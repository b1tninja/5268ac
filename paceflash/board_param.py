"""Offline ``paramtool`` / ``board_param_*`` store recovery from assembled ``tlpart``.

Mirrors Ghidra RE on **5268AC** 11.5.1.532678:

- ``/usr/bin/paramtool`` → ``board_param_open`` / ``board_param_get`` / ``board_param_show``
- ``libboard`` ``param_get`` @ ``0x00014040``: NUL-separated ``key=value`` records (prefix key match)
- On-flash persistence lives in the logical **``tlpart``** byte stream (``.board_param`` extension in
  strings); runtime ``board_param_open`` reads a CRC-prefixed file via a small index (paths are
  GP-relative — not required for offline text scan).

See ``reference/eapol_8021x_p12.md``, ``reference/boot_environment_trust_eng.md``.
"""

from __future__ import annotations

import hashlib
import re
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from boardfs import temporary_registry_from_physical_nand
from opentl.driver import TranslateMode
from unand.mtd import DEFAULT_MTDPARTS

from paceflash.eapol_cert import _param_tag

# libboard param_get: ASCII key prefix before '='
_PARAM_KEY_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_:.-]*$")

# Pace paramtool namespace (flash corpus)
_GW_LINE_RE = re.compile(rb"gw:[a-zA-Z0-9_.-]+=[^\x00\n\r]{0,512}")

# board_param on-disk: 4-byte CRC then payload; key scan starts at payload+1 (Ghidra +0x19 - +0x14)
_BOARD_PARAM_CRC_SKIP = 5

_SENSITIVE_SUFFIXES = ("_p12",)
_SENSITIVE_KEYS = frozenset(
    {
        "devkey",
        "authcode",
        "accesscode",
    }
)

DumpMode = Literal["show", "get"]

# U-Boot/OpenTL env copies on 532678 corpus are ~0x10800 bytes apart.
_ENV_COPY_SPACING = 0x10800
# Ghidra ``board_param_open`` trial window (see ``extract_board_params_from_tlpart``).
_CRC_BLOB_PROBE_BYTES = 512 * 1024

TRUST_ENGCERT_KEY = "gw:trust_engcert"
TRUST_ENGCERT_ANCHOR = b"gw:trust_engcert="


@dataclass(frozen=True, slots=True)
class BoardParamSite:
    """One CRC-prefixed ``board_param`` blob in assembled ``tlpart``."""

    offset: int
    blob_length: int
    crc_valid: bool
    role: str
    params: dict[str, str]
    stored_crc32: str


def uboot_crc32(data: bytes) -> int:
    """Same polynomial as ``libboard`` ``uboot_crc32`` (zlib CRC32)."""
    return zlib.crc32(data) & 0xFFFFFFFF


def parse_board_param_text(
    data: bytes,
    *,
    text_offset: int = 0,
) -> dict[str, str]:
    """
    Parse NUL-separated ``key=value`` records like ``libboard`` ``param_get``.

    ``param_get`` compares the sought key as a prefix of each record's key field up to ``=``.
    We store full keys as parsed before ``=``.
    """
    params: dict[str, str] = {}
    i = max(0, text_offset)
    n = len(data)
    while i < n:
        while i < n and data[i] == 0:
            i += 1
        if i >= n:
            break
        j = i
        while j < n and data[j] != 0:
            j += 1
        segment = data[i:j]
        if b"=" not in segment:
            i = j + 1
            continue
        try:
            text = segment.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            i = j + 1
            continue
        key, _, val = text.partition("=")
        key = key.strip()
        if not key or not _PARAM_KEY_RE.match(key):
            i = j + 1
            continue
        if not _is_plausible_param(key, val):
            i = j + 1
            continue
        # Last wins (same as iterating records in order)
        params[key] = val
        i = j + 1
    return params


def _is_plausible_param(key: str, val: str) -> bool:
    if not val:
        return False
    if key.endswith("_p12"):
        return len(val) >= 64 and re.fullmatch(r"[A-Za-z0-9+/=]+", val) is not None
    if key.startswith("gw:"):
        return len(val) <= 512
    if ":" in key:
        return len(val) <= 4096
    return len(val) <= 1024


def _redact_value(key: str, val: str) -> str:
    if key in _SENSITIVE_KEYS or any(key.endswith(s) for s in _SENSITIVE_SUFFIXES):
        if len(val) <= 12:
            return "***"
        return f"{val[:8]}…({len(val)} chars)"
    return val


def try_parse_crc_board_param_blob(blob: bytes) -> tuple[dict[str, str], dict[str, Any]] | None:
    """
    Validate ``board_param_open`` file layout: ``[crc32 LE][payload…]`` with text at payload+1.

    Returns (params, meta) or None if CRC does not match.
    """
    if len(blob) < _BOARD_PARAM_CRC_SKIP + 8:
        return None
    stored = int.from_bytes(blob[:4], "little")
    payload = blob[4:]
    # Ghidra stores scan pointer at puVar8+5 → skip one byte after CRC before key=value run
    calc = uboot_crc32(payload)
    if stored != calc:
        return None
    params = parse_board_param_text(blob, text_offset=_BOARD_PARAM_CRC_SKIP)
    if not params:
        return None
    return params, {
        "layout": "crc32_le_prefix",
        "stored_crc32": f"{stored:08x}",
        "calc_crc32": f"{calc:08x}",
        "blob_bytes": len(blob),
    }


def _record_order_from_blob(blob: bytes) -> list[str]:
    order: list[str] = []
    i = _BOARD_PARAM_CRC_SKIP
    n = len(blob)
    while i < n:
        while i < n and blob[i] == 0:
            i += 1
        if i >= n:
            break
        j = i
        while j < n and blob[j] != 0:
            j += 1
        segment = blob[i:j]
        if b"=" not in segment:
            i = j + 1
            continue
        try:
            text = segment.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            i = j + 1
            continue
        key, _, val = text.partition("=")
        key = key.strip()
        if key and _PARAM_KEY_RE.match(key) and _is_plausible_param(key, val):
            if key not in order:
                order.append(key)
        i = j + 1
    return order


def serialize_board_param_records(
    params: dict[str, str],
    *,
    order: list[str] | None = None,
) -> bytes:
    """NUL-separated ``key=value`` records (no leading NUL — caller adds for CRC payload)."""
    keys = order if order is not None else sorted(params.keys())
    parts: list[bytes] = []
    for key in keys:
        if key not in params:
            continue
        line = f"{key}={params[key]}".encode("ascii")
        parts.append(line)
    if not parts:
        return b""
    return b"\x00".join(parts) + b"\x00"


def build_crc_board_param_blob(
    params: dict[str, str],
    *,
    order: list[str] | None = None,
    payload_size: int | None = None,
) -> bytes:
    """
    Build ``[crc32 LE][payload…]`` with text starting at payload byte 1.

    When ``payload_size`` is set, pad the payload with trailing NULs (fixed env slot).
    """
    text = serialize_board_param_records(params, order=order)
    payload = b"\x00" + text
    if payload_size is not None:
        if len(payload) > payload_size:
            raise ValueError(
                f"board_param payload {len(payload)} B exceeds fixed slot {payload_size} B"
            )
        payload = payload + b"\x00" * (payload_size - len(payload))
    crc = uboot_crc32(payload)
    return struct.pack("<I", crc) + payload


def patch_board_param_key(
    blob: bytes,
    key: str,
    value: str,
    *,
    max_size: int | None = None,
) -> bytes:
    """
    Replace ``key`` in a CRC blob or append before trailing NUL run.

    Preserves record order and total blob size (``max_size`` or ``len(blob)``).
    """
    if not _PARAM_KEY_RE.match(key):
        raise ValueError(f"invalid board_param key: {key!r}")
    if not _is_plausible_param(key, value):
        raise ValueError(f"implausible value for key {key!r}")

    slot = max_size if max_size is not None else len(blob)
    if slot < _BOARD_PARAM_CRC_SKIP + 8:
        raise ValueError(f"board_param slot too small: {slot} B")

    parsed = try_parse_crc_board_param_blob(blob[:slot])
    if parsed is None:
        raise ValueError("source blob CRC invalid or empty")
    params, _meta = parsed
    order = _record_order_from_blob(blob[:slot])
    params = dict(params)
    if key in order:
        params[key] = value
    else:
        order.append(key)
        params[key] = value

    payload_size = slot - 4
    return build_crc_board_param_blob(params, order=order, payload_size=payload_size)


def _infer_crc_blob_length(tlpart: bytes, blob_start: int) -> int:
    """Env copy slot size — ``_ENV_COPY_SPACING`` unless tail of ``tlpart``."""
    return min(_ENV_COPY_SPACING, len(tlpart) - blob_start)


def _try_locate_crc_blob_at_anchor(
    tlpart: bytes,
    anchor_off: int,
    *,
    role: str,
) -> BoardParamSite | None:
    """Find CRC blob base by scanning backward from ``gw:trust_engcert=`` anchor."""
    search_lo = max(0, anchor_off - 4096)
    max_slot = min(_ENV_COPY_SPACING, len(tlpart))
    for bs in range(anchor_off, search_lo - 1, -1):
        room = len(tlpart) - bs
        if room < _BOARD_PARAM_CRC_SKIP + 8:
            continue
        # Prefer full env slot; fall back to shorter valid CRC windows (tests / partial dumps).
        for slot_len in (min(max_slot, room), min(65536, room), min(4096, room), room):
            if slot_len < _BOARD_PARAM_CRC_SKIP + 8:
                continue
            trial = tlpart[bs : bs + slot_len]
            parsed = try_parse_crc_board_param_blob(trial)
            if parsed is None:
                continue
            params, meta = parsed
            if TRUST_ENGCERT_KEY not in params:
                continue
            if not (bs + _BOARD_PARAM_CRC_SKIP <= anchor_off < bs + slot_len):
                continue
            stored = meta.get("stored_crc32", "")
            return BoardParamSite(
                offset=bs,
                blob_length=slot_len,
                crc_valid=True,
                role=role,
                params=dict(params),
                stored_crc32=str(stored),
            )
    return None


def locate_board_param_blobs(tlpart: bytes) -> list[BoardParamSite]:
    """
    Find CRC-valid ``board_param`` env blobs (primary + backup) in ``tlpart``.

    Uses ``gw:trust_engcert=`` anchors from the 532678 corpus layout.
    """
    anchors = [i for i in range(len(tlpart)) if tlpart.startswith(TRUST_ENGCERT_ANCHOR, i)]
    if not anchors:
        return []

    sites: list[BoardParamSite] = []
    roles = ("primary", "backup")
    for idx, anchor_off in enumerate(anchors[:2]):
        role = roles[idx] if idx < len(roles) else f"copy_{idx}"
        site = _try_locate_crc_blob_at_anchor(tlpart, anchor_off, role=role)
        if site is not None:
            sites.append(site)
    return sites


def patch_board_param_in_buffer(
    buf: bytearray,
    offset: int,
    blob: bytes,
    *,
    slot_length: int,
) -> None:
    if len(blob) > slot_length:
        raise ValueError(f"patched blob {len(blob)} B exceeds slot {slot_length} B")
    padded = blob + b"\x00" * (slot_length - len(blob))
    buf[offset : offset + slot_length] = padded


def patch_trust_engcert_inline_literals(
    tlpart: bytearray,
    value: str,
) -> dict[str, Any]:
    """
    Patch ``gw:trust_engcert=…`` NUL-terminated literals when CRC env blobs are absent.

    Used on captures where ``paramtool`` keys live in U-Boot-style env text without a
    valid CRC wrapper (common on 11.14.x lab dumps).
    """
    if value == "true":
        old_lit = b"gw:trust_engcert=false"
        new_lit = b"gw:trust_engcert=true\x00"
    else:
        old_lit = b"gw:trust_engcert=true"
        new_lit = b"gw:trust_engcert=false"
    if len(old_lit) != len(new_lit):
        raise ValueError(
            f"inline trust_engcert patch length mismatch: {len(old_lit)} vs {len(new_lit)}"
        )

    patched: list[dict[str, Any]] = []
    off = 0
    while off < len(tlpart):
        idx = tlpart.find(old_lit, off)
        if idx < 0:
            break
        tlpart[idx : idx + len(old_lit)] = new_lit
        patched.append(
            {
                "offset": idx,
                "role": "inline_literal",
                "unchanged": False,
                "old_value": "false" if value == "true" else "true",
                "new_value": value,
            }
        )
        off = idx + len(old_lit)

    if not patched:
        raise ValueError(
            f"no inline gw:trust_engcert literal matching {old_lit!r} found in tlpart"
        )

    return {
        "ok": True,
        "sites_patched": patched,
        "keys_changed": {TRUST_ENGCERT_KEY: (patched[0]["old_value"], value)},
        "site_count": len(patched),
        "patch_mode": "inline_literal",
    }


def patch_trust_engcert_in_tlpart(
    tlpart: bytearray,
    value: str,
) -> dict[str, Any]:
    """
    Patch ``gw:trust_engcert`` in every located CRC env copy inside ``tlpart``.

    Falls back to fixed-width inline literal replacement when CRC blobs are not found.

    ``value`` must be exactly ``true`` or ``false`` (paramtool convention).
    """
    if value not in ("true", "false"):
        raise ValueError("trust_engcert value must be exactly 'true' or 'false'")

    sites = locate_board_param_blobs(bytes(tlpart))
    if not sites:
        return patch_trust_engcert_inline_literals(tlpart, value)

    patched: list[dict[str, Any]] = []
    keys_changed: dict[str, tuple[str, str]] = {}
    for site in sites:
        old_val = site.params.get(TRUST_ENGCERT_KEY, "")
        if old_val == value:
            patched.append(
                {
                    "offset": site.offset,
                    "role": site.role,
                    "unchanged": True,
                    "old_value": old_val,
                    "new_value": value,
                }
            )
            continue
        start = site.offset
        slot = tlpart[start : start + site.blob_length]
        new_blob = patch_board_param_key(
            bytes(slot),
            TRUST_ENGCERT_KEY,
            value,
            max_size=site.blob_length,
        )
        patch_board_param_in_buffer(tlpart, start, new_blob, slot_length=site.blob_length)
        keys_changed[TRUST_ENGCERT_KEY] = (old_val, value)
        patched.append(
            {
                "offset": site.offset,
                "role": site.role,
                "unchanged": False,
                "old_value": old_val,
                "new_value": value,
                "blob_length": site.blob_length,
            }
        )

    return {
        "ok": True,
        "sites_patched": patched,
        "keys_changed": keys_changed,
        "site_count": len(sites),
        "patch_mode": "crc_blob",
    }


def scan_gw_param_lines(tlpart: bytes) -> dict[str, str]:
    """Find ``gw:…=…`` tokens (paramtool namespace) anywhere in ``tlpart``."""
    found: dict[str, str] = {}
    for m in _GW_LINE_RE.finditer(tlpart):
        try:
            line = m.group(0).decode("ascii", errors="strict")
        except UnicodeDecodeError:
            continue
        key, _, val = line.partition("=")
        if key:
            found[key] = val
    return found


def scan_p12_param_lines(tlpart: bytes) -> dict[str, str]:
    """``lightspeed_p12`` / ``device_p12`` base64 lines (WAN identity blobs)."""
    found: dict[str, str] = {}
    for cert in ("lightspeed", "device"):
        tag = _param_tag(cert)
        idx = tlpart.find(tag)
        if idx < 0:
            continue
        chunk = tlpart[idx : idx + 65536]
        end = len(chunk)
        for sep in (b"\n", b"\x00", b"\r"):
            j = chunk.find(sep)
            if j > 0:
                end = min(end, j)
        line = chunk[:end].decode("ascii", errors="replace")
        if "=" in line:
            key, b64 = line.split("=", 1)
            found[key.strip()] = b64.strip()
    return found


def find_param_region_around_anchor(
    tlpart: bytes,
    *,
    anchor: bytes = b"gw:trust_engcert=",
    back: int = 4096,
    forward: int = 256 * 1024,
) -> tuple[int, int] | None:
    """Window around a known param key for NUL-separated parsing."""
    idx = tlpart.find(anchor)
    if idx < 0:
        return None
    start = max(0, idx - back)
    end = min(len(tlpart), idx + forward)
    return start, end


def extract_board_params_from_tlpart(tlpart: bytes) -> dict[str, Any]:
    """
    Merge heuristics: ``gw:`` regex, ``*_p12`` lines, CRC blob at anchor, region parse.
    """
    warnings: list[str] = []
    merged: dict[str, str] = {}
    sources: dict[str, str] = {}
    out_extra: dict[str, Any] = {}

    for key, val in scan_gw_param_lines(tlpart).items():
        merged[key] = val
        sources[key] = "gw_regex"

    for key, val in scan_p12_param_lines(tlpart).items():
        merged[key] = val
        sources[key] = "p12_line"

    region = find_param_region_around_anchor(tlpart)
    if region is not None:
        start, end = region
        window = tlpart[start:end]
        for key, val in parse_board_param_text(window).items():
            if key not in merged:
                merged[key] = val
                sources[key] = "region_parse"
        # CRC blob aligned so anchor sits at offset+5 from blob base
        anchor_off = tlpart.find(b"gw:trust_engcert=")
        if anchor_off >= _BOARD_PARAM_CRC_SKIP:
            blob_start = anchor_off - (_BOARD_PARAM_CRC_SKIP - 1)
            # try a few alignments (Ghidra layout ambiguity)
            for delta in (0, -1, 1, -4, 4):
                bs = blob_start + delta
                if bs < 0 or bs >= len(tlpart):
                    continue
                trial = tlpart[bs : bs + min(512 * 1024, len(tlpart) - bs)]
                parsed = try_parse_crc_board_param_blob(trial)
                if parsed is not None:
                    crc_params, meta = parsed
                    for k, v in crc_params.items():
                        merged[k] = v
                        sources[k] = "crc_blob"
                    out_extra = {
                        "crc_meta": meta,
                        "region": {"start": start, "end": end, "anchor": anchor_off},
                    }
                    break

    if not merged:
        return {
            "ok": False,
            "error": "no board_param keys found in tlpart (expected gw:* or *_p12)",
            "warnings": warnings,
        }

    result: dict[str, Any] = {
        "ok": True,
        "params": merged,
        "sources": sources,
        "warnings": warnings,
    }
    result.update(out_extra)
    return result


def dump_paramtool(
    flash_path: str | Path,
    *,
    mode: DumpMode = "show",
    key: str | None = None,
    cmdline: str | None = None,
    nand_translate: bool = True,
    nand_translate_mode: TranslateMode = "inline-2112",
    redact: bool = False,
    include_p12_b64: bool = True,
) -> dict[str, Any]:
    """Read assembled ``tlpart`` and return paramtool-style board parameters."""
    p = Path(flash_path).expanduser().resolve()
    line = cmdline if cmdline is not None else f"quiet rw {DEFAULT_MTDPARTS}"
    warnings: list[str] = []
    out: dict[str, Any] = {
        "flash": str(p),
        "cmdline": line,
        "nand_translate": nand_translate,
        "mode": mode,
        "warnings": warnings,
    }
    if key is not None:
        out["key"] = key

    with temporary_registry_from_physical_nand(
        p, line, translate_mode=nand_translate_mode
    ) as (reg, man, _ot):
        if not nand_translate and man.get("warnings"):
            for w in man["warnings"]:
                warnings.append(str(w))
        try:
            tlpart = reg.flash.read_partition("tlpart")
        except Exception as e:
            out["ok"] = False
            out["error"] = f"tlpart read failed: {type(e).__name__}: {e}"
            return out

    extracted = extract_board_params_from_tlpart(tlpart)
    if not extracted.get("ok"):
        out["ok"] = False
        out["error"] = extracted.get("error", "extract failed")
        out["warnings"].extend(extracted.get("warnings") or [])
        return out

    params: dict[str, str] = dict(extracted["params"])
    if not include_p12_b64:
        params = {k: v for k, v in params.items() if not k.endswith("_p12")}

    out["param_count"] = len(params)
    out["sources"] = extracted.get("sources")
    if "crc_meta" in extracted:
        out["crc_meta"] = extracted["crc_meta"]
    if "region" in extracted:
        out["region"] = extracted["region"]
    out["warnings"].extend(extracted.get("warnings") or [])

    if mode == "get":
        if not key:
            out["ok"] = False
            out["error"] = "get requires a key name"
            return out
        if key not in params:
            out["ok"] = False
            out["error"] = f"key not found: {key}"
            out["known_keys"] = sorted(params.keys())
            return out
        val = params[key]
        out["ok"] = True
        out["value"] = _redact_value(key, val) if redact else val
        out["value_bytes"] = len(val.encode("ascii", errors="replace"))
        if key.endswith("_p12") and not redact:
            out["value_sha256"] = hashlib.sha256(val.encode()).hexdigest()
        return out

    # show
    display = params
    if redact:
        display = {k: _redact_value(k, v) for k, v in params.items()}
    out["ok"] = True
    out["params"] = display
    return out
