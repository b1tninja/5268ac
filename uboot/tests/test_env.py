"""Tests for :mod:`uboot.env` (U-Boot env v1 CRC + NUL-split pairs)."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

import pytest

from uboot.cmdline import get_mtdparts_token
from uboot.env import ParsedUbootEnvV1, parse_uboot_env_v1, read_uboot_env_v1_file


def _pack_le_crc(body: bytes) -> bytes:
    c = zlib.crc32(body, 0) & 0xFFFFFFFF
    return struct.pack("<I", c) + body


def _pack_be_crc(body: bytes) -> bytes:
    c = zlib.crc32(body, 0) & 0xFFFFFFFF
    return struct.pack(">I", c) + body


def test_parse_uboot_env_v1_le_crc_and_pairs() -> None:
    body = b"bootargs=quiet mtdparts=mtd-0:4096(a),-(b)\0serial#=abc\0\0" + b"\xff" * 8
    blob = _pack_le_crc(body)
    r = parse_uboot_env_v1(blob, crc_endian="little")
    assert isinstance(r, ParsedUbootEnvV1)
    assert r.crc_ok
    assert r.crc_endian == "little"
    assert r.variables["serial#"] == "abc"
    assert r.variables["bootargs"] == "quiet mtdparts=mtd-0:4096(a),-(b)"
    assert r.mtdparts_token == "mtdparts=mtd-0:4096(a),-(b)"
    assert get_mtdparts_token(r.variables["bootargs"]) == r.mtdparts_token


def test_parse_uboot_env_v1_standalone_mtdparts_variable() -> None:
    body = b"mtdparts=mtd-0:1m(foo)\0\0" + b"\xff" * 4
    r = parse_uboot_env_v1(_pack_le_crc(body))
    assert r.crc_ok
    assert r.mtdparts_token == "mtdparts=mtd-0:1m(foo)"


def test_parse_uboot_env_v1_mtdparts_value_without_prefix() -> None:
    body = b"mtdparts=mtd-0:64k@0(x)\0\0"
    r = parse_uboot_env_v1(_pack_le_crc(body))
    assert r.mtdparts_token == "mtdparts=mtd-0:64k@0(x)"


def test_parse_uboot_env_v1_big_endian_crc() -> None:
    body = b"a=1\0b=2\0\0"
    blob = _pack_be_crc(body)
    r = parse_uboot_env_v1(blob, crc_endian="big")
    assert r.crc_ok and r.crc_endian == "big"
    r_auto = parse_uboot_env_v1(blob, crc_endian="auto")
    assert r_auto.crc_ok and r_auto.crc_endian == "big"


def test_parse_uboot_env_v1_auto_little_endian() -> None:
    # ``auto`` should pick LE when it is the only matching CRC word.
    body = b"x=y\0\0"
    blob = _pack_le_crc(body)
    r = parse_uboot_env_v1(blob, crc_endian="auto")
    assert r.crc_ok and r.crc_endian == "little"


def test_parse_uboot_env_v1_crc_mismatch() -> None:
    body = b"a=b\0\0"
    blob = _pack_le_crc(body)
    bad = blob[:-1] + bytes([(blob[-1] ^ 0xFF) & 0xFF])
    r = parse_uboot_env_v1(bad, crc_endian="little")
    assert not r.crc_ok
    assert r.crc_endian is None
    assert r.variables.get("a") == "b"


def test_read_uboot_env_v1_file(tmp_path: Path) -> None:
    body = b"foo=bar\0\0"
    blob = _pack_le_crc(body)
    f = tmp_path / "env.bin"
    f.write_bytes(b"\x00" * 10 + blob)
    off = 10
    r = read_uboot_env_v1_file(f, offset=off, size=len(blob))
    assert r.crc_ok and r.variables["foo"] == "bar"


def test_read_uboot_env_v1_file_short_read_raises(tmp_path: Path) -> None:
    f = tmp_path / "short.bin"
    f.write_bytes(b"\x01\x02")
    with pytest.raises(ValueError, match="short read"):
        read_uboot_env_v1_file(f, offset=0, size=16)


def test_parse_uboot_env_v1_too_short_raises() -> None:
    with pytest.raises(ValueError, match="shorter than 4-byte"):
        parse_uboot_env_v1(b"\x01\x02")
