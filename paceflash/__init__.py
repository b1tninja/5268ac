"""Pace-class flash inventory CLI and library (MTD, TL disklabel, SquashFS probe, ext2, UBI hints, fstab)."""

from __future__ import annotations

from paceflash.fstab import (
    FstabEntry,
    parse_fstab,
    parse_fstab_from_extfs_image,
    read_fstab_text_from_extfs_image,
)
from paceflash.inventory import build_inventory

__all__ = [
    "FstabEntry",
    "build_inventory",
    "parse_fstab",
    "parse_fstab_from_extfs_image",
    "read_fstab_text_from_extfs_image",
]
