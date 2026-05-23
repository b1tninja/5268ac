"""
U-Boot **environment image v1** (``uint32_t crc`` + payload) — offline parse only.

The stored CRC is the IEEE polynomial CRC-32 over every byte **after** the CRC word,
exactly as ``crc32(0, blob + 4, len - 4)`` in U-Boot. Payload is NUL-separated
``key=value`` records, terminated by an extra NUL, then typically ``0xFF`` erase padding.

This module does **not** select offsets inside a flash dump; callers read a fixed slice
(e.g. from :mod:`unand.mtd` / partition layout) and pass the bytes here.

**Redundant env:** some builds store a ``flags`` byte immediately after the CRC word, still
included in the CRC span. If ``flags`` is non-zero, pass a slice that drops that byte (or
extend this module once a concrete image is validated).
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from uboot.cmdline import get_mtdparts_token, get_mtdparts_token_from_env_blob

CrcEndian = Literal["little", "big", "auto"]


@dataclass(frozen=True)
class ParsedUbootEnvV1:
    """Result of :func:`parse_uboot_env_v1`."""

    crc_stored: int
    crc_ok: bool
    crc_endian: Literal["little", "big"] | None
    payload: bytes
    variables: dict[str, str]
    mtdparts_token: str | None


def _crc32_uboot(data: bytes) -> int:
    return zlib.crc32(data, 0) & 0xFFFFFFFF


def _parse_kv_payload(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    i = 0
    n = len(data)
    while i < n:
        c = data[i]
        if c == 0:
            i += 1
            continue
        if c == 0xFF:
            while i < n and data[i] == 0xFF:
                i += 1
            continue
        end = data.find(b"\x00", i)
        if end == -1:
            if i < n:
                _add_kv_chunk(out, data[i:])
            break
        chunk = data[i:end]
        i = end + 1
        if not chunk:
            continue
        if len(chunk) == chunk.count(0xFF):
            break
        _add_kv_chunk(out, chunk)
    return out


def _add_kv_chunk(out: dict[str, str], chunk: bytes) -> None:
    text = chunk.decode("ascii", errors="replace")
    if "=" in text:
        k, _, v = text.partition("=")
        if k:
            out[k] = v
    elif text:
        out[text] = ""


def parse_uboot_env_v1(blob: bytes, *, crc_endian: CrcEndian = "little") -> ParsedUbootEnvV1:
    """
    Parse a raw v1 env image: first four bytes are CRC; remainder is the hashed payload.

    ``crc_endian``:
        * ``little`` / ``big`` — interpret the CRC word in that order.
        * ``auto`` — accept either endian if exactly one matches; if both match, little wins.
    """
    if len(blob) < 4:
        raise ValueError("env v1 blob shorter than 4-byte CRC field")

    body = blob[4:]
    crc_calc = _crc32_uboot(body)
    le = struct.unpack_from("<I", blob, 0)[0]
    be = struct.unpack_from(">I", blob, 0)[0]

    if crc_endian == "little":
        stored, endian, ok = le, "little", crc_calc == le
    elif crc_endian == "big":
        stored, endian, ok = be, "big", crc_calc == be
    else:
        le_ok, be_ok = crc_calc == le, crc_calc == be
        if le_ok and not be_ok:
            stored, endian, ok = le, "little", True
        elif be_ok and not le_ok:
            stored, endian, ok = be, "big", True
        elif le_ok and be_ok:
            stored, endian, ok = le, "little", True
        else:
            stored, endian, ok = le, None, False

    variables = _parse_kv_payload(body)
    mtd = _mtdparts_from_variables(variables, body)
    return ParsedUbootEnvV1(
        crc_stored=stored,
        crc_ok=ok,
        crc_endian=endian if ok else None,
        payload=body,
        variables=variables,
        mtdparts_token=mtd,
    )


def _mtdparts_from_variables(variables: dict[str, str], body: bytes) -> str | None:
    ba = variables.get("bootargs")
    if ba is not None:
        tok = get_mtdparts_token(ba)
        if tok is not None:
            return tok
    tok = get_mtdparts_token_from_env_blob(body)
    if tok is not None:
        return tok
    raw = variables.get("mtdparts")
    if raw is None:
        return None
    r = raw.strip()
    if r.lower().startswith("mtdparts="):
        return r
    return f"mtdparts={r}"


def read_uboot_env_v1_file(
    path: str | Path,
    offset: int,
    size: int,
    *,
    crc_endian: CrcEndian = "little",
) -> ParsedUbootEnvV1:
    """Read *exactly* ``size`` bytes at ``offset`` and :func:`parse_uboot_env_v1`."""
    p = Path(path)
    with p.open("rb") as f:
        f.seek(offset)
        blob = f.read(size)
    if len(blob) != size:
        raise ValueError(
            f"short read from {p!s}: wanted {size} bytes at offset {offset}, got {len(blob)}"
        )
    return parse_uboot_env_v1(blob, crc_endian=crc_endian)
