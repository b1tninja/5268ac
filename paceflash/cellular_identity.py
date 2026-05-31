"""Offline LTE modem identity (IMEI) from CMDB on a PACE flash dump.

QxDM passcode validation uses ``cmlegacy.fwll_cellular_intf.0.usim`` → ``IMEI``
(last six characters). That map is populated at runtime by ``fwlld`` from the
cellular module REST ``USIM`` endpoint — **not** from the factory loader block.

See ``reference/qxdm_passcode.md``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from boardfs.ext2_path import read_ext2_regular_file
from paceflash.flash_session import open_opentla4_ext2
from paceflash.http_auth import _CMDB_EXT2_PATHS, read_cmdb_xml_text_from_bytes

_USIM_OID = "cmlegacy.fwll_cellular_intf.0.usim"
_FIELD_S = re.compile(r'<S N="([^"]+)">([^<]*)</S>')
_IMEI_IN_CMDM_RE = re.compile(r'<S N="IMEI">([^<]*)</S>')
_IMEI_DIGITS_RE = re.compile(r"\b(\d{15})\b")
_TLPART_IMEI_CTX = re.compile(
    rb'IMEI[\x00\s"\']{0,8}(\d{15})',
    re.IGNORECASE,
)


def qxdm_passcode_from_imei(imei: str | None) -> str | None:
    """Last six characters of IMEI (Lua ``string.sub(imei, -6)``)."""
    if not imei:
        return None
    s = imei.strip()
    if len(s) < 6:
        return None
    return s[-6:]


def parse_usim_from_cmdb(text: str) -> dict[str, Any]:
    """
    Extract USIM map fields from CMDB XML text.

    Prefer ``<S N="IMEI">`` anywhere in the blob; also collect ICCID/IMSI when present.
    """
    fields: dict[str, str] = {}
    for m in _FIELD_S.finditer(text):
        name, value = m.group(1), m.group(2)
        if name in ("IMEI", "ICCID", "IMSI", "MSISDN", "SIMSTATE"):
            fields[name] = value.strip()
    imei = fields.get("IMEI") or None
    if not imei:
        m = _IMEI_IN_CMDM_RE.search(text)
        if m:
            imei = m.group(1).strip()
            fields.setdefault("IMEI", imei)
    passcode = qxdm_passcode_from_imei(imei)
    ok = bool(imei and len(imei) >= 6)
    note = None
    if not imei:
        note = (
            "IMEI not found in CMDB XML — modem may never have registered USIM data "
            "(empty module, no SIM, or fwlld never ran OWA REST USIM sync)"
        )
    elif len(imei) < 6:
        note = f"IMEI too short for QxDM passcode ({len(imei)} chars): {imei!r}"
    return {
        "ok": ok,
        "oid": _USIM_OID,
        "fields": fields,
        "imei": imei,
        "qxdm_passcode": passcode,
        "note": note,
    }


def scan_tlpart_for_imei(tlpart: bytes) -> list[dict[str, Any]]:
    """Heuristic: find 15-digit IMEI near ``IMEI`` marker in assembled tlpart."""
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for m in _TLPART_IMEI_CTX.finditer(tlpart):
        imei = m.group(1).decode("ascii", errors="replace")
        if imei in seen:
            continue
        seen.add(imei)
        found.append(
            {
                "source": "tlpart_embedded",
                "offset": m.start(),
                "imei": imei,
                "qxdm_passcode": qxdm_passcode_from_imei(imei),
            }
        )
    return found


def _read_cmdb_usim_from_ext2(
    flash_path: Path,
    *,
    cmdline: str | None,
    nand_translate: bool,
    nand_translate_mode: str,
    bbm_chain_aware: bool,
    paths: tuple[str, ...],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    with open_opentla4_ext2(
        flash_path,
        cmdline,
        nand_translate=nand_translate,
        nand_translate_mode=nand_translate_mode,  # type: ignore[arg-type]
        bbm_chain_aware=bbm_chain_aware,
    ) as vol:
        for rel in paths:
            entry: dict[str, Any] = {"path": rel, "source": "ext2_opentla4"}
            try:
                data = read_ext2_regular_file(
                    vol.slice_bytes,
                    rel,
                    sb_off=vol.sb_off,
                    access=vol.access,
                    cmdb_recover=True,
                )
            except FileNotFoundError:
                entry["ok"] = False
                entry["error"] = "not found"
                results.append(entry)
                continue
            except OSError as e:
                entry["ok"] = False
                entry["error"] = f"{type(e).__name__}: {e}"
                results.append(entry)
                continue
            if not data.strip().startswith(b"<?xml") and b"<CM" not in data[:4096]:
                entry["ok"] = False
                entry["error"] = "not CMDB XML"
                entry["bytes"] = len(data)
                results.append(entry)
                continue
            text, enc = read_cmdb_xml_text_from_bytes(data)
            usim = parse_usim_from_cmdb(text)
            entry["ok"] = usim["ok"]
            entry["encoding"] = enc
            entry["bytes"] = len(data)
            entry.update(usim)
            results.append(entry)
    return results


def dump_cellular_identity(
    flash_path: str | Path,
    *,
    cmdline: str | None = None,
    nand_translate: bool = True,
    nand_translate_mode: Literal["inline-2112", "flat-tail", "identity"] = "inline-2112",
    bbm_chain_aware: bool = False,
    include_tlpart_scan: bool = True,
    cmdb_paths: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Read IMEI / QxDM passcode candidates from CMDB (+ optional tlpart scan)."""
    p = Path(flash_path).expanduser().resolve()
    warnings: list[str] = []
    out: dict[str, Any] = {
        "flash": str(p),
        "ok": False,
        "warnings": warnings,
        "oid": _USIM_OID,
        "factory_has_imei": False,
        "note": (
            "IMEI is not in the factory loader block (sn/mac/accesscode only). "
            "It lives in CMDB usim map after modem registration."
        ),
    }

    paths = cmdb_paths if cmdb_paths is not None else _CMDB_EXT2_PATHS
    try:
        out["cmdb_ext2"] = _read_cmdb_usim_from_ext2(
            p,
            cmdline=cmdline,
            nand_translate=nand_translate,
            nand_translate_mode=nand_translate_mode,
            bbm_chain_aware=bbm_chain_aware,
            paths=paths,
        )
    except Exception as e:
        warnings.append(f"ext2 CMDB read: {type(e).__name__}: {e}")
        out["cmdb_ext2"] = []

    imei: str | None = None
    source: str | None = None
    for block in out.get("cmdb_ext2") or []:
        if block.get("ok") and block.get("imei"):
            imei = str(block["imei"])
            source = f"cmdb:{block.get('path')}"
            break
    if not imei:
        for block in out.get("cmdb_ext2") or []:
            if block.get("imei"):
                imei = str(block["imei"])
                source = f"cmdb_partial:{block.get('path')}"
                break

    if include_tlpart_scan:
        try:
            from boardfs import temporary_registry_from_physical_nand
            from unand.mtd import DEFAULT_MTDPARTS

            line = cmdline if cmdline is not None else f"quiet rw {DEFAULT_MTDPARTS}"
            with temporary_registry_from_physical_nand(
                p, line, translate_mode=nand_translate_mode
            ) as (reg, man, _ot):
                if not nand_translate and man.get("warnings"):
                    for w in man["warnings"]:
                        warnings.append(str(w))
                tlpart = reg.flash.read_partition("tlpart")
            out["tlpart_imei_hits"] = scan_tlpart_for_imei(tlpart)
            if not imei and out["tlpart_imei_hits"]:
                hit = out["tlpart_imei_hits"][0]
                imei = hit.get("imei")
                source = "tlpart_embedded"
        except Exception as e:
            warnings.append(f"tlpart IMEI scan: {type(e).__name__}: {e}")
            out["tlpart_imei_hits"] = []
    else:
        out["tlpart_imei_hits"] = []

    out["imei"] = imei
    out["qxdm_passcode"] = qxdm_passcode_from_imei(imei)
    out["source"] = source
    out["ok"] = bool(out["qxdm_passcode"])
    if not out["ok"]:
        if not any(b.get("bytes") for b in out.get("cmdb_ext2") or []):
            out["error"] = "no readable CMDB on flash"
        elif imei:
            out["error"] = f"IMEI present but too short for passcode: {imei!r}"
        else:
            out["error"] = (
                "IMEI not in CMDB — likely no LTE module registration on this dump "
                "(dev board, missing SIM, or modem never synced USIM to CM)"
            )
    return out
