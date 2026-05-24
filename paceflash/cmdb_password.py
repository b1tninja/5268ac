"""Pace CMDB web password hashing (``tw_ulib_pwd_hash``) and offline verification."""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Iterable

# librgw_compat tw_ulib_pwd_hash @ 0xbf82c: MD5_Init; MD5_Update(salt); MD5_Update(password);
# MD5_Final → 16 bytes → nu_b64_ntop into output buffer (CM stores as ``base64:…``).
#
# tw_ulib_pwd_auth @ 0xc03dc: strcmp(user_typed_password, transformed_cm_field) — NOT memcmp
# on raw digest (MIPS disasm @ 0xc0914 → strcmp). So login compares strings, not binary MD5 out.

def decode_cmdb_xml_bytes(data: bytes) -> tuple[str, str]:
    if len(data) >= 2 and data[:2] == b"\xff\xfe":
        return data.decode("utf-16-le"), "utf-16-le"
    if len(data) >= 2 and data[:2] == b"\xfe\xff":
        return data.decode("utf-16-be"), "utf-16-be"
    return data.decode("utf-8", errors="replace"), "utf-8"


_TABLE_USER = re.compile(r'<TABLE N="user">(.*?)</TABLE>', re.DOTALL)
_ROW_RE = re.compile(r'<ROW N="(\d+)">(.*?)</ROW>', re.DOTALL)
_FIELD_S = re.compile(r'<S N="([^"]+)">([^<]*)</S>')


def tw_ulib_pwd_hash(salt: str | bytes, password: str | bytes) -> bytes:
    """MD5( salt_bytes ‖ password_bytes ) — two OpenSSL MD5_Update calls."""
    if isinstance(salt, str):
        salt = salt.encode("utf-8", errors="replace")
    if isinstance(password, str):
        password = password.encode("utf-8", errors="replace")
    h = hashlib.md5()
    h.update(salt)
    h.update(password)
    return h.digest()


def tw_ulib_pwd_hash_b64(salt: str | bytes, password: str | bytes) -> str:
    """Digest as standard base64 (matches CM ``password`` payload after ``base64:``)."""
    return base64.b64encode(tw_ulib_pwd_hash(salt, password)).decode("ascii")


def parse_password_field(value: str) -> tuple[str, bytes | None]:
    """
    Return (raw_field, decoded_digest_or_none).

    CM XML uses ``<S N="password">base64:…</S>``.
    """
    v = value.strip()
    if v.lower().startswith("base64:"):
        b64 = v[7:]
        try:
            return v, base64.b64decode(b64, validate=True)
        except Exception:
            return v, None
    if re.fullmatch(r"[A-Za-z0-9+/=]+", v):
        try:
            return v, base64.b64decode(v, validate=True)
        except Exception:
            pass
    return v, None


def cm_login_compare_strings(stored_password_field: str) -> list[str]:
    """
    Candidate strings for ``strcmp`` in ``tw_ulib_pwd_auth`` (transform usually keeps
    the CM ASCII form; on failure it prepends ``base64:`` again).
    """
    raw, digest = parse_password_field(stored_password_field)
    out: list[str] = []
    seen: set[str] = set()

    def add(s: str) -> None:
        if s and s not in seen:
            seen.add(s)
            out.append(s)

    add(raw)
    if raw.lower().startswith("base64:"):
        add(raw[7:])
    if digest:
        add(digest.hex())
    return out


def verify_password_candidates(
    stored_password_field: str,
    candidates: Iterable[str],
    *,
    extra_salts: Iterable[str | bytes] = (),
) -> list[dict[str, Any]]:
    """
    Test login/password strings against CM storage.

    Returns matches with ``kind``:
    - ``strcmp_candidate`` — string that would pass ``strcmp`` in ``tw_ulib_pwd_auth``
    - ``hash_preimage`` — ``tw_ulib_pwd_hash(salt, candidate)`` equals stored 16-byte digest
    """
    raw, digest = parse_password_field(stored_password_field)
    compare_set = set(cm_login_compare_strings(stored_password_field))
    matches: list[dict[str, Any]] = []

    for cand in candidates:
        if not cand:
            continue
        if cand in compare_set:
            matches.append(
                {
                    "kind": "strcmp_candidate",
                    "password": cand,
                    "note": "Exact CM/compare string (pass-the-hash style for web login)",
                }
            )
        if digest is not None:
            for salt in _salt_variants(extra_salts):
                if tw_ulib_pwd_hash(salt, cand) == digest:
                    matches.append(
                        {
                            "kind": "hash_preimage",
                            "password": cand,
                            "salt": salt if isinstance(salt, str) else salt.decode(
                                "utf-8", errors="replace"
                            ),
                            "digest_hex": digest.hex(),
                            "note": "tw_ulib_pwd_hash(salt, password) matches CM digest",
                        }
                    )
    return matches


def _salt_variants(extra: Iterable[str | bytes]) -> list[str | bytes]:
    base: list[str | bytes] = ["", "adm", "Administrator"]
    for s in extra:
        if s not in base:
            base.append(s)
    return base


def verify_user_from_table_xml(
    text: str,
    username: str,
    candidates: Iterable[str],
    *,
    extra_salts: Iterable[str | bytes] = (),
) -> dict[str, Any]:
    """Parse ``<TABLE N="user">`` and verify ``username`` row."""
    m = _TABLE_USER.search(text)
    if not m:
        return {"ok": False, "error": "no user table"}
    for rm in _ROW_RE.finditer(m.group(1)):
        fields = {m.group(1): m.group(2) for m in _FIELD_S.finditer(rm.group(2))}
        if fields.get("user") != username:
            continue
        pw = fields.get("password", "")
        matches = verify_password_candidates(
            pw, candidates, extra_salts=[username, *extra_salts]
        )
        return {
            "ok": True,
            "user": username,
            "stored_password": pw,
            "digest_hex": parse_password_field(pw)[1].hex()
            if parse_password_field(pw)[1]
            else None,
            "login_compare_candidates": cm_login_compare_strings(pw),
            "matches": matches,
        }
    return {"ok": False, "error": f"user {username!r} not found"}


def default_accesscode_candidates(
    factory_http: dict[str, str] | None,
    *,
    serial: str | None = None,
) -> list[str]:
    """Build guess list from factory block + common defaults."""
    out: list[str] = []
    if factory_http:
        ac = factory_http.get("accesscode")
        if ac:
            out.append(ac)
        for k in ("sn", "mac", "devkey", "authcode"):
            v = factory_http.get(k)
            if v:
                out.append(v)
    if serial:
        out.append(serial)
    out.extend(["", "password", "admin", "2wire"])
    dedup: list[str] = []
    seen: set[str] = set()
    for s in out:
        if s not in seen:
            seen.add(s)
            dedup.append(s)
    return dedup
