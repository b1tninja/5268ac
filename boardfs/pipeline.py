"""Construct :class:`~boardfs.registry.FsRegistry` from an OpenTL NAND pipeline."""

from __future__ import annotations

from pathlib import Path

from unand.geometry import NandGeometry, PACE_DEFAULT

from boardfs.flash import flash_image_from_cmdline
from boardfs.registry import FsRegistry
from opentl.nand_pipeline import NandPipeline


#region kernel_adjacent opentl_NandPipeline_to_boardfs_FsRegistry (see reference/layers_unand_uboot_opentl_boardfs_paceflash.md)
def fs_registry_from_nand_pipeline(
    pipeline: NandPipeline,
    cmdline: str,
    *,
    geom: NandGeometry = PACE_DEFAULT,
) -> FsRegistry:
    """
    Use the pipeline's **logical plane** file as the MTD backing image (same layout as
    ``mtdparts`` on full logical dumps).
    """
    lp = pipeline.logical_path
    if lp is None or not lp.is_file():
        raise ValueError("NandPipeline.logical_path must be set to an existing file")
    flash = flash_image_from_cmdline(Path(lp), cmdline, geom=geom)
    return FsRegistry(flash=flash, cmdline=cmdline, block_map=pipeline.bbm)


#endregion
