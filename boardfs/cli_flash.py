"""Shared flash + OpenTL registry resolution for :mod:`boardfs.cli` (no user-facing entry point).

See ``reference/layers_unand_uboot_opentl_boardfs_paceflash.md`` for the full layer stack and Ghidra MCP hints.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from opentl.logutil import configure_opentl_stderr_logging
from opentl.logical_opentl_session import LogicalOpenTLSession
from opentl.nand_translate import TranslateMode

from boardfs.flash import flash_image_from_cmdline
from boardfs.registry import FsRegistry
from boardfs.bootstrap import temporary_registry_from_physical_nand
from unand.geometry import PACE_DEFAULT


def full_chip_physical_pace(file_size: int) -> bool:
    return file_size in (PACE_DEFAULT.full_inline_bytes, PACE_DEFAULT.full_flat_tail_bytes)


def apply_opentl_cli_env(*, debug_log: bool, tl_probe_report: bool) -> None:
    if debug_log:
        os.environ["OPENTL_DEBUG"] = "1"
        configure_opentl_stderr_logging()
    if tl_probe_report:
        os.environ["OPENTL_TLDISK_REPORT"] = "1"


@contextmanager
def open_fs_registry_for_cli(
    flash: Path,
    cmdline: str,
    *,
    nand_translate: bool,
    nand_mode: TranslateMode,
) -> Iterator[tuple[FsRegistry, dict[str, Any] | None, LogicalOpenTLSession | None]]:
    """
    Yield ``(FsRegistry, nand_translate_manifest | None, LogicalOpenTLSession | None)``.

    Full-chip Pace physical + ``nand_translate``: delegates to
    :func:`paceflash.nand_logicalize.temporary_registry_from_physical_nand`.
    Otherwise: linear flash image + empty registry (no BBM unless caller attached elsewhere).
    """
    p = flash.expanduser().resolve()
    nz = p.stat().st_size
    if nand_translate and full_chip_physical_pace(nz):
        with temporary_registry_from_physical_nand(p, cmdline, translate_mode=nand_mode) as (reg, man, ot):
            yield reg, man, ot
    else:
        img = flash_image_from_cmdline(p, cmdline)
        yield FsRegistry(flash=img, cmdline=cmdline), None, None


def build_flash_probe_parent() -> argparse.ArgumentParser:
    """Shared flags for ``virt-map`` / ``page-table`` (use with ``parents=[...]``)."""
    par = argparse.ArgumentParser(add_help=False)
    par.add_argument(
        "--debug-log",
        action="store_true",
        help="Set OPENTL_DEBUG and attach stderr logging for opentl loggers",
    )
    par.add_argument("--cmdline", type=str, default=None, help="Kernel cmdline with mtdparts=")
    par.add_argument(
        "--nand-translate",
        action="store_true",
        help="Logicalize full-chip Pace physical captures in RAM before probes (extracts spare for BBM)",
    )
    par.add_argument(
        "--nand-mode",
        type=str,
        choices=("inline-2112", "flat-tail", "identity"),
        default="inline-2112",
        help="NAND translate mode when --nand-translate is used (default inline-2112)",
    )
    par.add_argument(
        "--tl-probe-report",
        action="store_true",
        help="Set OPENTL_TLDISK_REPORT=1 for TL scans",
    )
    return par
