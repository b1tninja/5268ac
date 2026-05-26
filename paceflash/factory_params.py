"""Parse Pace factory manufacturing key=value block from the **loader** MTD slice."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any

from boardfs.flash import flash_image_from_cmdline, flash_image_from_cmdline_bytes
from boardfs.flash_layout import FlashImage
from opentl.driver import TranslateMode
from opentl import nand_bootstrap
from unand.geometry import PACE_DEFAULT
from unand.mtd import DEFAULT_MTDPARTS

# First hit on PACE 5268AC logical dumps (see reference/board_params_nand.md)
DEFAULT_FACTORY_HINT_OFFSET = 0x1FF84

_FACTORY_ANCHOR = b"model="
_KEY_RE = re.compile(r"^[a-z0-9_]+$")

# Keys treated as secrets when --redact (values replaced in output)
_SENSITIVE_KEYS = frozenset(
    {
        "devkey",
        "authcode",
        "accesscode",
        "wifikey1",
        "wifikey2",
        "wifi5gkey1",
        "wifi5gkey2",
        "wifissid1",
        "wifissid2",
        "wifi5gssid1",
        "wifi5gssid2",
    }
)

_KNOWN_FACTORY_KEYS = frozenset(
    {
        "model",
        "sn",
        "mac",
        "devkey",
        "authcode",
        "accesscode",
        "wifissid1",
        "wifikey1",
        "wifi5gsn",
        "wifi5gpca",
        "wifi5gmodel",
        "wifi5gssid1",
        "wifi5gkey1",
        "wifi5gssid2",
        "wifi5gkey2",
        "pca",
        "maccount",
        "mfg_timestamp",
        "srom",
        "factory_mode",
        "trust_engcert",
    }
)

FACTORY_TRUST_ENGCERT_KEY = "trust_engcert"


def _physical_pace_envelope(file_size: int) -> bool:
    return file_size in (
        PACE_DEFAULT.full_inline_bytes,
        PACE_DEFAULT.full_flat_tail_bytes,
    )


def _cmdline_for_image_size(file_size: int, cmdline: str | None) -> str:
    """Use loader-only mtdparts when the file is just a carved loader slice."""
    if cmdline is not None:
        return cmdline
    if file_size == 524288:
        return "quiet rw mtdparts=mtd-0:-(loader)"
    return f"quiet rw {DEFAULT_MTDPARTS}"


def open_flash_for_loader(
    flash_path: str | Path,
    *,
    cmdline: str | None = None,
    nand_translate: bool = True,
    nand_translate_mode: TranslateMode = "inline-2112",
) -> tuple[FlashImage, list[str]]:
    """
    Return a :class:`FlashImage` suitable for ``read_partition("loader")``.

    Full-chip **physical** Pace dumps are logicalized in a temp dir when
    ``nand_translate`` is true (default).
    """
    warnings: list[str] = []
    p = Path(flash_path).expanduser().resolve()
    file_size = os.path.getsize(p)
    line = _cmdline_for_image_size(file_size, cmdline)
    if _physical_pace_envelope(file_size):
        if nand_translate:
            with tempfile.TemporaryDirectory() as td:
                spare_p = Path(td) / "flat_spare.bin"
                logical, man = nand_bootstrap.translate_physical_nand(
                    p, nand_translate_mode, spare_out=spare_p
                )
                for w in man.get("warnings") or []:
                    warnings.append(f"nand_translate: {w}")
                flash = flash_image_from_cmdline_bytes(
                    logical, line, display_path=str(p)
                )
        else:
            warnings.append(
                "physical NAND dump without --nand-translate: loader slice offsets "
                "may not match the logical plane (factory block ~0x1FF84)"
            )
            flash = flash_image_from_cmdline(p, line)
    else:
        flash = flash_image_from_cmdline(p, line)
    return flash, warnings


def find_factory_block_offset(
    loader_bytes: bytes,
    *,
    hint_offset: int | None = None,
) -> int | None:
    """Return offset of ``model=`` anchor, preferring ``hint_offset`` when valid."""
    if hint_offset is not None:
        off = int(hint_offset)
        if 0 <= off < len(loader_bytes) and loader_bytes[off : off + len(_FACTORY_ANCHOR)] == _FACTORY_ANCHOR:
            return off
    idx = loader_bytes.find(_FACTORY_ANCHOR)
    return idx if idx >= 0 else None


def _region_end(loader_bytes: bytes, start: int) -> int:
    """End of contiguous factory key=value blob (NUL-separated)."""
    n = len(loader_bytes)
    i = start
    ff_run = 0
    while i < n:
        b = loader_bytes[i]
        if b == 0xFF:
            ff_run += 1
            if ff_run >= 64:
                return i - ff_run
        else:
            ff_run = 0
        if b == 0 and i > start:
            # Allow NUL separators between keys; stop after long gap without '='
            j = i + 1
            while j < n and loader_bytes[j] in (0, 0xFF):
                j += 1
            if j >= n:
                # Trailing NUL/0xFF padding to EOF — end factory block here
                return i
            window = loader_bytes[i : min(i + 256, n)]
            if b"=" not in window and j - i > 4:
                return i
        i += 1
    return n


def parse_factory_params_from_loader(
    loader_bytes: bytes,
    *,
    hint_offset: int | None = DEFAULT_FACTORY_HINT_OFFSET,
) -> dict[str, Any]:
    """
    Parse manufacturing ``key=value`` pairs from the loader MTD bytes.

    Returns a dict with ``ok``, ``offset``, ``params``, ``unknown_keys``, ``warnings``.
    """
    warnings: list[str] = []
    off = find_factory_block_offset(loader_bytes, hint_offset=hint_offset)
    if off is None:
        return {
            "ok": False,
            "error": "factory anchor model= not found in loader partition",
            "hint_offset": hint_offset,
        }
    end = _region_end(loader_bytes, off)
    region = loader_bytes[off:end]
    params: dict[str, str] = {}
    unknown: list[str] = []
    for segment in region.split(b"\x00"):
        if not segment or b"=" not in segment:
            continue
        try:
            text = segment.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            warnings.append(f"non-ascii segment at loader+{off:#x}+{segment[:8]!r}")
            continue
        key, _, val = text.partition("=")
        key = key.strip().lower()
        if not key or not _KEY_RE.match(key):
            continue
        val = val.strip()
        if not val:
            continue
        params[key] = val
        if key not in _KNOWN_FACTORY_KEYS:
            unknown.append(key)
    if not params:
        return {
            "ok": False,
            "error": "no key=value pairs parsed after model= anchor",
            "offset": off,
            "region_bytes": len(region),
        }
    if "sn" not in params:
        warnings.append("parsed block has no sn= (unexpected for 5268AC factory)")
    return {
        "ok": True,
        "offset": off,
        "region_bytes": len(region),
        "params": params,
        "unknown_keys": sorted(set(unknown)),
        "warnings": warnings,
    }


def _redact_params(params: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in params.items():
        if k in _SENSITIVE_KEYS:
            if len(v) <= 8:
                out[k] = "***"
            else:
                out[k] = f"{v[:4]}…({len(v)} chars)"
        else:
            out[k] = v
    return out


def probe_factory_params(
    loader_bytes: bytes,
    *,
    hint_offset: int | None = DEFAULT_FACTORY_HINT_OFFSET,
    redact: bool = False,
) -> dict[str, Any]:
    """Probe wrapper adding partition size metadata."""
    parsed = parse_factory_params_from_loader(loader_bytes, hint_offset=hint_offset)
    parsed["loader_size_bytes"] = len(loader_bytes)
    parsed["hint_offset"] = hint_offset
    if parsed.get("ok") and redact and isinstance(parsed.get("params"), dict):
        parsed["params"] = _redact_params(parsed["params"])
        parsed["redacted"] = True
    return parsed


def patch_factory_trust_engcert(
    loader: bytearray,
    value: str,
    *,
    hint_offset: int | None = DEFAULT_FACTORY_HINT_OFFSET,
) -> dict[str, Any]:
    """
    Set ``trust_engcert`` in the loader manufacturing ``key=value`` block.

    Appends or updates the key in the factory defaults region (NAND **loader** MTD,
    not ``tlpart`` board_param). Intended to survive factory/hard reset paths that
    re-seed paramtool state from manufacturing data.
    """
    if value not in ("true", "false"):
        raise ValueError("trust_engcert value must be exactly 'true' or 'false'")

    parsed = parse_factory_params_from_loader(bytes(loader), hint_offset=hint_offset)
    if not parsed.get("ok"):
        return {
            "ok": False,
            "skipped": True,
            "error": parsed.get("error", "factory block not found"),
        }

    off = int(parsed["offset"])
    end = off + int(parsed["region_bytes"])
    params = dict(parsed["params"])
    old_val = params.get(FACTORY_TRUST_ENGCERT_KEY)

    if old_val == value:
        return {
            "ok": True,
            "unchanged": True,
            "offset": off,
            "region_bytes": parsed["region_bytes"],
            "value": value,
        }

    if old_val is not None:
        old_seg = f"{FACTORY_TRUST_ENGCERT_KEY}={old_val}".encode("ascii")
        new_seg = f"{FACTORY_TRUST_ENGCERT_KEY}={value}".encode("ascii")
        idx = loader.find(old_seg, off, end)
        if idx < 0:
            return {
                "ok": False,
                "error": f"{FACTORY_TRUST_ENGCERT_KEY} present in parse but segment not found",
            }
        if len(new_seg) != len(old_seg):
            return {
                "ok": False,
                "error": f"in-place factory patch length mismatch: {len(old_seg)} vs {len(new_seg)}",
            }
        loader[idx : idx + len(old_seg)] = new_seg
        return {
            "ok": True,
            "unchanged": False,
            "offset": off,
            "patch_offset": idx,
            "patch_length": len(new_seg),
            "old_value": old_val,
            "new_value": value,
        }

    insert = b"\x00" + f"{FACTORY_TRUST_ENGCERT_KEY}={value}".encode("ascii") + b"\x00"
    pad = 0
    while end + pad < len(loader) and loader[end + pad] in (0, 0xFF):
        pad += 1
        if pad > 512:
            break
    if len(insert) > pad:
        return {
            "ok": False,
            "error": f"factory block padding too small for {FACTORY_TRUST_ENGCERT_KEY} ({pad} B free)",
        }
    loader[end : end + len(insert)] = insert
    return {
        "ok": True,
        "unchanged": False,
        "offset": off,
        "patch_offset": end,
        "patch_length": len(insert),
        "old_value": old_val,
        "new_value": value,
        "region_bytes_after": int(parsed["region_bytes"]) + len(insert),
    }


def dump_factory_params(
    flash_path: str | Path,
    *,
    cmdline: str | None = None,
    nand_translate: bool = True,
    nand_translate_mode: TranslateMode = "inline-2112",
    hint_offset: int | None = DEFAULT_FACTORY_HINT_OFFSET,
    redact: bool = False,
) -> dict[str, Any]:
    """Read loader MTD from a flash dump and parse factory parameters."""
    flash, open_warnings = open_flash_for_loader(
        flash_path,
        cmdline=cmdline,
        nand_translate=nand_translate,
        nand_translate_mode=nand_translate_mode,
    )
    names = {p.name for p in flash.partitions}
    p = Path(flash_path).expanduser().resolve()
    file_size = os.path.getsize(p)
    resolved_cmdline = _cmdline_for_image_size(file_size, cmdline)
    out: dict[str, Any] = {
        "flash": str(p),
        "cmdline": resolved_cmdline,
        "nand_translate": nand_translate,
        "warnings": list(open_warnings),
    }
    loader_part = next((p for p in flash.partitions if p.name == "loader"), None)
    if loader_part is not None:
        out["loader_partition"] = {
            "index": loader_part.index,
            "offset": loader_part.offset,
            "size": loader_part.size,
        }
    if "loader" not in names:
        out["factory"] = {"ok": False, "error": "no loader partition in mtd layout"}
        return out
    try:
        blob = flash.read_partition("loader")
    except Exception as e:
        out["factory"] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        return out
    parsed = probe_factory_params(blob, hint_offset=hint_offset, redact=redact)
    out["factory"] = parsed
    for w in parsed.get("warnings") or []:
        out["warnings"].append(f"factory: {w}")
    return out
