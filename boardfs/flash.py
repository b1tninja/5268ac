"""Build :class:`~binwalker.extract.flash_layout.FlashImage` from ``mtdparts`` + dump size."""

from __future__ import annotations

import os
from pathlib import Path

from binwalker.extract.flash_layout import FlashImage, build_partitions_from_mtdparts, effective_mtd_reference_size
from unand.geometry import NandGeometry, PACE_DEFAULT


#region kernel_adjacent mtdparts_FlashImage (kernel MTD offset semantics on logical plane)
def flash_image_from_cmdline(
    flash_path: str | Path,
    cmdline: str,
    *,
    geom: NandGeometry = PACE_DEFAULT,
) -> FlashImage:
    """
    Parse ``mtdparts`` from ``cmdline`` and size partitions against the logical reference size
    of ``flash_path`` (Pace envelope mapping via :func:`effective_mtd_reference_size`).
    """
    p = Path(flash_path).expanduser().resolve()
    sz = os.path.getsize(p)
    ref = effective_mtd_reference_size(sz, geom=geom)
    layout = build_partitions_from_mtdparts(cmdline, image_size=ref)
    return FlashImage(path=str(p), partitions=layout.partitions)


def flash_image_from_cmdline_bytes(
    logical: bytes,
    cmdline: str,
    *,
    geom: NandGeometry = PACE_DEFAULT,
    display_path: str = "<memory>",
) -> FlashImage:
    """
    Same partition layout as :func:`flash_image_from_cmdline`, but the backing image is
    ``logical`` (already logical-plane bytes). ``display_path`` is stored as :attr:`FlashImage.path`
    for logging only; reads use ``logical_image``.
    """
    ref = len(logical)
    _ = effective_mtd_reference_size(ref, geom=geom)
    layout = build_partitions_from_mtdparts(cmdline, image_size=ref)
    return FlashImage(path=display_path, partitions=layout.partitions, logical_image=logical)


#endregion
