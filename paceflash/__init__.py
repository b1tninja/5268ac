"""Pace-class flash inventory CLI and library (MTD, TL disklabel, SquashFS probe, ext2, UBI hints, fstab)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from paceflash.fstab import (
    FstabEntry,
    parse_fstab,
    parse_fstab_from_extfs_image,
    read_fstab_text_from_extfs_image,
)
from paceflash.artifacts import iter_flash_corpus_artifacts

if TYPE_CHECKING:
    from paceflash.inventory import build_inventory

__all__ = [
    "FstabEntry",
    "build_inventory",
    "iter_flash_corpus_artifacts",
    "parse_fstab",
    "parse_fstab_from_extfs_image",
    "read_fstab_text_from_extfs_image",
]


def __getattr__(name: str):
    if name == "build_inventory":
        from paceflash.inventory import build_inventory

        return build_inventory
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
