"""
Bridge ``bootargs`` / cmdline text → :mod:`unand.mtd` partition tuples.

Keeps :func:`unand.mtd.parse_mtdparts` as the **single parser of record** for layout math.
"""

from __future__ import annotations

from unand.geometry import NandGeometry, PACE_DEFAULT
from unand.mtd import MtdPart, parse_mtdparts

from uboot.cmdline import get_mtdparts_token


def partition_table_from_bootargs(
    cmdline: str,
    *,
    logical_total: int | None = None,
    geom: NandGeometry | None = None,
) -> tuple[MtdPart, ...]:
    """
    Parse ``mtdparts`` from a kernel command line (or fragment containing one token).

    * Extracts the space-delimited ``mtdparts=…`` token via :func:`uboot.cmdline.get_mtdparts_token`.
    * Passes ``logical_total`` to :func:`unand.mtd.parse_mtdparts` when the table uses ``-(name)``.

    If ``logical_total`` is ``None`` and a remainder partition exists, uses
    ``geom.logical_bytes`` (default :data:`unand.geometry.PACE_DEFAULT`).
    """
    g = geom or PACE_DEFAULT
    tok = get_mtdparts_token(cmdline)
    if tok is None:
        raise ValueError(f"No mtdparts= token in cmdline: {cmdline!r}")
    lt = logical_total if logical_total is not None else g.logical_bytes
    return parse_mtdparts(tok, logical_total=lt)
