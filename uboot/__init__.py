"""
U-Boot–adjacent **offline** parsing: ``bootcmd`` segments and Linux ``bootargs``.

This package does **not** talk to hardware. It helps turn strings found in dumps,
``/proc/cmdline`` style logs, or env extracts into inputs for :mod:`unand.mtd` (``mtdparts``)
and documents the boot chain in ``reference/boot_and_storage.md``.

**Kernel analogue:** bootloader / early env construction (strings only). NAND geometry and
the MTD **data plane** live in :mod:`unand`; partition tables from ``mtdparts=`` are parsed
by :mod:`unand.mtd`; OpenTL consumes partition-relative bytes in :mod:`opentl`.
"""

from __future__ import annotations

from uboot.bootcmd import (
    extract_bootargs_value_from_setenv,
    parse_bootcmd_segments,
    segments_with_setenv_bootargs,
)
from uboot.cmdline import (
    bootargs_mapping,
    env_blob_to_cmdline_like_string,
    get_mtdparts_token,
    get_mtdparts_token_from_env_blob,
    parse_bootargs,
)
from uboot.env import ParsedUbootEnvV1, parse_uboot_env_v1, read_uboot_env_v1_file
from uboot.mtdparts import partition_table_from_bootargs

__all__ = [
    "parse_bootargs",
    "bootargs_mapping",
    "get_mtdparts_token",
    "env_blob_to_cmdline_like_string",
    "get_mtdparts_token_from_env_blob",
    "parse_uboot_env_v1",
    "read_uboot_env_v1_file",
    "ParsedUbootEnvV1",
    "parse_bootcmd_segments",
    "segments_with_setenv_bootargs",
    "extract_bootargs_value_from_setenv",
    "partition_table_from_bootargs",
]
