"""Tests for :mod:`uboot.bootcmd`."""

from __future__ import annotations

from unand.geometry import PACE_DEFAULT
from unand.mtd import DEFAULT_MTDPARTS

from uboot.bootcmd import (
    extract_bootargs_value_from_setenv,
    parse_bootcmd_segments,
    segments_with_setenv_bootargs,
)
from uboot.mtdparts import partition_table_from_bootargs


def test_parse_bootcmd_segments_splits_and_strips() -> None:
    s = "  echo start ; nand read ; bootm  "
    assert parse_bootcmd_segments(s) == ("echo start", "nand read", "bootm")


def test_segments_with_setenv_bootargs() -> None:
    segs = parse_bootcmd_segments("run foo; setenv bootargs bar=baz; bootm")
    hit = segments_with_setenv_bootargs(segs)
    assert hit == ("setenv bootargs bar=baz",)


def test_extract_bootargs_value_from_setenv() -> None:
    v = extract_bootargs_value_from_setenv("setenv bootargs quiet root=/dev/mtd2 rw")
    assert v == "quiet root=/dev/mtd2 rw"


def test_bootcmd_setenv_bootargs_mtdparts_round_trip() -> None:
    inner = f"quiet {DEFAULT_MTDPARTS} rw"
    seg = f"setenv bootargs {inner}"
    extracted = extract_bootargs_value_from_setenv(seg)
    assert extracted is not None
    parts = partition_table_from_bootargs(extracted)
    expected = partition_table_from_bootargs(inner, logical_total=PACE_DEFAULT.logical_bytes)
    assert parts == expected
