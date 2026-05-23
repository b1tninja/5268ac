"""Tests for :mod:`uboot.cmdline` and :mod:`uboot.mtdparts`."""

from __future__ import annotations

import pytest

from unand.geometry import PACE_DEFAULT
from unand.mtd import DEFAULT_MTDPARTS, parse_mtdparts

from uboot.cmdline import (
    env_blob_to_cmdline_like_string,
    get_mtdparts_token,
    get_mtdparts_token_from_env_blob,
    parse_bootargs,
)
from uboot.mtdparts import partition_table_from_bootargs


def test_env_blob_to_cmdline_like_string_nul_separated() -> None:
    blob = b"bootargs=quiet\0mtdparts=mtd-0:4096(a),-(b)\0other=x"
    s = env_blob_to_cmdline_like_string(blob)
    assert "mtdparts=mtd-0:4096(a),-(b)" in s.replace("  ", " ")
    tok = get_mtdparts_token_from_env_blob(blob)
    assert tok == "mtdparts=mtd-0:4096(a),-(b)"


def test_get_mtdparts_token_from_env_blob_matches_space_cmdline() -> None:
    cmd = f"quiet {DEFAULT_MTDPARTS} rw"
    blob = cmd.encode("ascii")
    assert get_mtdparts_token_from_env_blob(blob) == get_mtdparts_token(cmd)


def test_parse_bootargs_key_value_and_bare() -> None:
    m = parse_bootargs("foo=1 bar=baz=2 qux")
    assert m["foo"] == "1"
    assert m["bar"] == "baz=2"
    assert m["qux"] is None


def test_parse_bootargs_duplicate_last_wins() -> None:
    m = parse_bootargs("a=1 a=2")
    assert m["a"] == "2"


def test_get_mtdparts_token_isolated_from_trailing_params() -> None:
    cmd = (
        "console=ttyS0,115200 root=/dev/mtdblock2 "
        + DEFAULT_MTDPARTS
        + " mem=256M"
    )
    tok = get_mtdparts_token(cmd)
    assert tok == DEFAULT_MTDPARTS
    direct = parse_mtdparts(tok, logical_total=PACE_DEFAULT.logical_bytes)
    via = partition_table_from_bootargs(cmd, logical_total=PACE_DEFAULT.logical_bytes)
    assert via == direct


def test_partition_table_from_bootargs_default_geom_remainder() -> None:
    cmd = f"quiet {DEFAULT_MTDPARTS} rw"
    expected = parse_mtdparts(DEFAULT_MTDPARTS, logical_total=PACE_DEFAULT.logical_bytes)
    got = partition_table_from_bootargs(cmd)
    assert got == expected


def test_partition_table_from_bootargs_no_mtdparts_raises() -> None:
    with pytest.raises(ValueError, match="No mtdparts"):
        partition_table_from_bootargs("console=ttyS0")
