"""Probe Pace 5268AC HTTP authentication: factory defaults, CMDB users, and realm map."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from boardfs.ext2_path import read_ext2_regular_file
from paceflash.factory_params import dump_factory_params
from paceflash.flash_session import open_opentla4_ext2

# HURL is *not* an HTTP auth realm — it maps broadband events → /xslt?PAGE=HURLnn.
# These are the configured HTTP authentication surfaces (webs_conf + soap_conf).
HTTP_AUTH_REALMS: tuple[dict[str, str], ...] = (
    {
        "surface": "main_ui",
        "auth_type": "session",
        "realm": "(app login / PAGE=login)",
        "backend": "tw_ulib_pwd_* + board_key_*",
        "notes": "home0 vhosts /xslt; subscriber code from libboard accesscode/systemcode",
    },
    {
        "surface": "mdc",
        "auth_type": "basic",
        "realm": "tech-write",
        "backend": "mdc",
        "vhost": "mdc0:0",
        "port": "50001",
        "notes": "Field/mobile diagnostics; gated by mdc feature flag",
    },
    {
        "surface": "tr064_soap",
        "auth_type": "digest",
        "realm": "TR-064",
        "backend": "dslf-config",
        "users": "dslf-config, dslf-reset",
        "notes": "soap_conf.xml mutating SOAP actions",
    },
    {
        "surface": "hurl",
        "auth_type": "(none on /hurl itself)",
        "realm": "N/A",
        "backend": "redirect only",
        "notes": "hurl_conf.xml → /xslt?PAGE=HURL*; auth applies on target XSLT pages",
    },
)

_FACTORY_HTTP_KEYS = frozenset(
    {
        "accesscode",
        "authcode",
        "sn",
        "mac",
        "wifissid1",
        "wifikey1",
        "wifi5gssid1",
        "wifi5gkey1",
        "wifi5gssid2",
        "wifi5gkey2",
    }
)

_CMDB_EXT2_PATHS = (
    "cm/cmlegacy.498",
    "cm/cmlegacy.203",
    "config/cmlegacy.203",
)

_ROW_RE = re.compile(r'<ROW N="(\d+)">(.*?)</ROW>', re.DOTALL)
_FIELD_S = re.compile(r'<S N="([^"]+)">([^<]*)</S>')
_TABLE_USER = re.compile(r'<TABLE N="user">(.*?)</TABLE>', re.DOTALL)
_TLPART_USER_CHUNK = re.compile(
    rb'<TABLE N="user">.{0,12000}?</TABLE>',
    re.DOTALL,
)


def _fields_from_row(row_xml: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in _FIELD_S.finditer(row_xml)}


def parse_cm_user_table(text: str) -> list[dict[str, str]]:
    """Parse CMDB ``<TABLE N="user">`` rows (adm, tech, wra, …)."""
    m = _TABLE_USER.search(text)
    if not m:
        return []
    users: list[dict[str, str]] = []
    for rm in _ROW_RE.finditer(m.group(1)):
        f = _fields_from_row(rm.group(2))
        name = f.get("user", "")
        if not name:
            continue
        users.append(
            {
                "id": f.get("id", rm.group(1)),
                "user": name,
                "password": f.get("password", ""),
                "groups": f.get("groups", ""),
                "hint": f.get("hint", ""),
                "fullname": f.get("fullname", ""),
            }
        )
    return users


def _redact_factory_http(params: dict[str, str], *, redact: bool) -> dict[str, str]:
    out = {k: params[k] for k in _FACTORY_HTTP_KEYS if k in params}
    if redact:
        for k in ("accesscode", "authcode", "wifikey1", "wifi5gkey1", "wifi5gkey2"):
            if k in out and out[k]:
                out[k] = out[k][:2] + "…" + f"({len(out[k])} chars)"
    return out


def _redact_user_password(u: dict[str, str], *, redact: bool, decode: bool) -> dict[str, Any]:
    row: dict[str, Any] = dict(u)
    pw = row.get("password") or ""
    if not pw:
        row["password_note"] = "empty"
        return row
    if pw.lower().startswith("base64:"):
        b64 = pw.split(":", 1)[1]
        row["password_format"] = "base64"
        if decode and not redact:
            import base64

            try:
                row["password_decoded_hex"] = base64.b64decode(b64).hex()
                row["password_decoded_len"] = len(base64.b64decode(b64))
            except Exception as e:
                row["password_decode_error"] = str(e)
        if redact:
            row["password"] = "base64:[REDACTED]"
        return row
    if redact and len(pw) > 4:
        row["password"] = pw[:2] + "…"
    return row


def scan_tlpart_user_tables(tlpart: bytes, *, redact: bool, decode: bool) -> list[dict[str, Any]]:
    """Find embedded CM ``user`` tables in assembled tlpart (rw CMDB mirrors)."""
    found: list[dict[str, Any]] = []
    for i, m in enumerate(_TLPART_USER_CHUNK.finditer(tlpart)):
        try:
            text = m.group().decode("utf-8", errors="replace")
        except Exception:
            continue
        users = parse_cm_user_table(text)
        if not users:
            continue
        found.append(
            {
                "source": "tlpart_embedded",
                "index": i,
                "offset": m.start(),
                "users": [_redact_user_password(u, redact=redact, decode=decode) for u in users],
            }
        )
    return found


def _try_read_cmdb_from_ext2(
    flash_path: Path,
    *,
    cmdline: str | None,
    nand_translate: bool,
    nand_translate_mode: str,
    bbm_chain_aware: bool,
    redact: bool,
    decode: bool,
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
            users = parse_cm_user_table(text)
            entry["ok"] = True
            entry["encoding"] = enc
            entry["bytes"] = len(data)
            entry["users"] = [
                _redact_user_password(u, redact=redact, decode=decode) for u in users
            ]
            results.append(entry)
    return results


def read_cmdb_xml_text_from_bytes(data: bytes) -> tuple[str, str]:
    from paceflash.cmdb_password import decode_cmdb_xml_bytes

    return decode_cmdb_xml_bytes(data)


def dump_http_auth(
    flash_path: str | Path,
    *,
    cmdline: str | None = None,
    nand_translate: bool = True,
    nand_translate_mode: Literal["inline-2112", "flat-tail", "identity"] = "inline-2112",
    bbm_chain_aware: bool = False,
    redact: bool = False,
    decode_password_hashes: bool = False,
    include_tlpart_scan: bool = True,
    cmdb_paths: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """
    Collect HTTP-related credentials: loader factory block, ext2 CMDB ``user`` table, tlpart mirrors.

    **accesscode** (factory) is the printed Device Access Code; CM **adm** stores a **base64**
    digest checked by ``tw_ulib_pwd_auth``. **tech** backs realm **tech-write** (MDC basic).
    **dslf-config** / **dslf-reset** map to TR-064 digest (realm **TR-064**).
    """
    p = Path(flash_path).expanduser().resolve()
    warnings: list[str] = []
    out: dict[str, Any] = {
        "flash": str(p),
        "ok": True,
        "warnings": warnings,
        "http_auth_realms": list(HTTP_AUTH_REALMS),
        "hurl_note": (
            "HURL (/hurl) is a redirect router, not an HTTP auth realm. "
            "Authenticated pages are /xslt?PAGE=… after login or digest on SOAP/MDC vhosts."
        ),
    }

    fac_doc = dump_factory_params(
        p,
        cmdline=cmdline,
        nand_translate=nand_translate,
        nand_translate_mode=nand_translate_mode,
        redact=redact,
    )
    out["factory"] = fac_doc.get("factory")
    fac = fac_doc.get("factory") or {}
    if fac.get("ok") and isinstance(fac.get("params"), dict):
        out["factory_http"] = _redact_factory_http(fac["params"], redact=redact)
        out["accesscode_hint"] = (
            "Printed Device Access Code (factory accesscode=); "
            "CM adm password is stored hashed (base64:…) — compare via tw_ulib_pwd_auth / libboard_key_accesscode RE."
        )
    else:
        warnings.append(f"factory block: {fac.get('error', 'failed')}")

    paths = cmdb_paths if cmdb_paths is not None else _CMDB_EXT2_PATHS
    try:
        out["cmdb_ext2"] = _try_read_cmdb_from_ext2(
            p,
            cmdline=cmdline,
            nand_translate=nand_translate,
            nand_translate_mode=nand_translate_mode,
            bbm_chain_aware=bbm_chain_aware,
            redact=redact,
            decode=decode_password_hashes,
            paths=paths,
        )
    except Exception as e:
        warnings.append(f"ext2 CMDB read: {type(e).__name__}: {e}")
        out["cmdb_ext2"] = []

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
            out["tlpart_user_tables"] = scan_tlpart_user_tables(
                tlpart, redact=redact, decode=decode_password_hashes
            )
        except Exception as e:
            warnings.append(f"tlpart user scan: {type(e).__name__}: {e}")
            out["tlpart_user_tables"] = []

    # Map realm → CM users (static groups table in firmware)
    out["realm_user_map"] = {
        "tech-write": ["tech (CM user; MDC basic)"],
        "TR-064": ["dslf-config", "dslf-reset (CM groups tr064/tr069)"],
        "main_ui": ["adm (CM user; hint: Device Access Code on label)"],
    }

    return out
