"""
Board filesystem orchestration: **MTD** layout, **cmdline** conventions, **UBI** hints,
and **BlockDev** slicing. **TL virtual replay** is implemented in :mod:`opentl`;
:class:`~boardfs.registry.FsRegistry` holds :class:`~opentl.driver.LogicalOpenTLSession`
after BBM attach.

Layer A: ``mtdparts`` / :class:`~binwalker.extract.flash_layout.FlashImage`.
Layer B: :mod:`opentl.tldisk` enumeration inside ``tlpart`` scan buffer.
Layer C: ``ubi.mtd=`` parsing + raw UBI VID header scan.
Layer D: :mod:`boardfs.squashfs_probe` for ``hsqs`` magic peek.
Ext2 dissect helpers: :mod:`boardfs.ext2_dissect`.
"""

from __future__ import annotations

from boardfs.block import AssembledBlockDev, BlockDev, BlockSlice
from boardfs.bootstrap import temporary_registry_from_physical_nand
from boardfs.ext2_dissect import (
    find_ext2_superblock_offsets,
    list_root_for_block_dev,
    list_root_for_block_dev_with_meta,
    resolve_mountable_ext2_superblock_offset,
)
from boardfs.ext2_path import list_ext2_directory, normalize_ext2_path, read_ext2_regular_file
from boardfs.flash import flash_image_from_cmdline, flash_image_from_cmdline_bytes
from boardfs.mount_spec import RootSpec, parse_root_from_cmdline
from boardfs.pipeline import fs_registry_from_nand_pipeline
from boardfs.registry import FsRegistry
from boardfs.squashfs_probe import SQUASHFS_MAGIC_LE, peek_squashfs_superblock_magic
from boardfs.tl_chain import (
    Opentla4VolumeResult,
    apply_chain_aware_virtual_tl_scan,
    assemble_opentla4_ntl_bytes,
    assemble_opentla4_volume,
    audit_tl_kernel_alignment_bytes,
    bbm_virtual_scan_summary,
    buffer_has_tl_disklabel_anchor,
    correlation_suggests_chain_aware,
    correlation_suggests_chain_aware_from_hits,
    flash_plane_sector0_prefix_bytes,
    infer_chain_aware_virtual_tl_scan,
    infer_ext2_opentla4_chain_aware,
    linear_opentla4_bytes,
    ntl_result_to_jsonable,
)
from boardfs.ubi_cmdline import UbiMtdAttachSpec, iter_ubi_mtd_attach_specs
from boardfs.ubi_scan import UbiVidHeaderHit, scan_ubi_vid_headers_in_bytes, scan_ubi_vid_headers_on_block_dev
from opentl.driver import (
    AssembledNTLResult,
    TranslateMode,
    configure_opentl_stderr_logging,
    infer_chain_aware_tl_scan,
)

__all__ = [
    "AssembledBlockDev",
    "AssembledNTLResult",
    "BlockDev",
    "BlockSlice",
    "FsRegistry",
    "Opentla4VolumeResult",
    "RootSpec",
    "SQUASHFS_MAGIC_LE",
    "UbiMtdAttachSpec",
    "UbiVidHeaderHit",
    "apply_chain_aware_virtual_tl_scan",
    "assemble_opentla4_ntl_bytes",
    "assemble_opentla4_volume",
    "audit_tl_kernel_alignment_bytes",
    "bbm_virtual_scan_summary",
    "buffer_has_tl_disklabel_anchor",
    "configure_opentl_stderr_logging",
    "correlation_suggests_chain_aware",
    "correlation_suggests_chain_aware_from_hits",
    "find_ext2_superblock_offsets",
    "list_ext2_directory",
    "normalize_ext2_path",
    "read_ext2_regular_file",
    "flash_image_from_cmdline",
    "flash_image_from_cmdline_bytes",
    "flash_plane_sector0_prefix_bytes",
    "fs_registry_from_nand_pipeline",
    "infer_chain_aware_virtual_tl_scan",
    "infer_ext2_opentla4_chain_aware",
    "iter_ubi_mtd_attach_specs",
    "linear_opentla4_bytes",
    "list_root_for_block_dev",
    "list_root_for_block_dev_with_meta",
    "ntl_result_to_jsonable",
    "parse_root_from_cmdline",
    "peek_squashfs_superblock_magic",
    "resolve_mountable_ext2_superblock_offset",
    "scan_ubi_vid_headers_in_bytes",
    "scan_ubi_vid_headers_on_block_dev",
    "temporary_registry_from_physical_nand",
    "TranslateMode",
]
