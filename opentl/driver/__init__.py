"""
Kernel-shaped OpenTL **driver** facade: BBM (virt→phys), hole semantics, logical-prefix virt read,
:class:`~opentl.logical_opentl_session.LogicalOpenTLSession` (canonical prefix + map + replace),
and constants aligned with the Linux ``drivers/mtd/opentl`` read path.

**Not** in this namespace: host orchestration (:mod:`opentl.nand_pipeline`), tl-mount inference
(:mod:`opentl.tl_mount`), nand-translate file I/O (:mod:`opentl.nand_translate`), host ext2 slide /
volume helpers (import ext2 tooling from your workspace stack as needed),
``mtd_scanner`` string heuristics — import those from their modules.

See ``README.md`` in this directory for the driver vs host split.
"""

from __future__ import annotations

from opentl.errors import IncompleteBBMInferenceError, VirtBlockHoleError
from opentl.logical_opentl_session import LogicalOpenTLSession
from opentl.open_tl import (
    EXT2_LE16_MAGIC,
    ExtractResult,
    KERNEL_SECTORS_PER_NAND_PAGE,
    OpenTL,
    OPENTLA4_EXT2_MAGIC_OFF,
    OPENTLA4_NUM_SECTORS,
    OPENTLA4_START_SECTOR,
    SECTOR_BYTES,
    extract_opentla4,
    extract_result_as_dict,
    extract_virtual_disk_bytes,
    extract_virtual_disk_bytes_chain_aware,
    layout_within_tl_erase_unit,
    opentla4_ext2_magic_le,
    partition_payload_ext2_magic,
    virt_global_byte_to_physical,
)
from opentl.virt_page_table import (
    PHYS_PAGE_BASE_HOLE,
    LazyChainAwareVirtNandPageTable,
    VirtNandPageTable,
    build_lazy_chain_aware_virt_nand_page_table,
    build_virt_nand_page_table,
    build_virt_nand_page_table_chain_aware,
    extract_virtual_disk_bytes_via_page_table,
)
from opentl.spare_chain_replay import tl_geometry_from_flat_spare
from opentl.bbm_kernel_replay import build_block_map_from_kernel_mount_replay
from opentl.tl_bbm import (
    SCHEMA_V1,
    BlockMapBuild,
    TLGeometry,
    TL_ERASE_BYTES_DEFAULT,
    TL_LOGICAL_PREFIX_DEFAULT,
    TL_PHYS_BLOCK_HOLE,
    TL_RAW_BLOCKS_DEFAULT,
    TL_VIRT_BLOCKS_DEFAULT,
    block_map_to_json_dict,
    geometry_boot_trace_dict,
    is_hole_phys_block,
    parse_block_map_dict,
    validate_virt_to_phys_block_entries,
)
from opentl.tl_chain_heuristic import (
    correlation_suggests_chain_aware_from_hits,
    infer_chain_aware_tl_scan,
)
from opentl.tlpart_bbm_assembly import virtual_tl_byte_stream_from_logical_plane
from opentl.spare_verify import (
    verify_page_all,
    verify_page_require_nand_page_length,
    verify_page_require_spare_xsum,
)
from opentl.tl_physical import (
    FLASH_5268_CLASS_SIZE,
    OOB_ENVELOPE,
    PAGE_DATA,
    PAGE_RAW,
    PAGE_SPARE,
    PURE_DATA_PLANE,
    TLPART_NAND_DATA_OFFSET_DEFAULT,
    infer_tl_mount_nand_logical_offset,
)
from opentl.ntl_rw import (
    PTYPE_NTL_RW,
    AssembledNTLResult,
    assemble_ntl_rw_slice,
    build_chain_head_cache,
    ntl_assembly_to_jsonable,
)
from opentl.nand_translate import TranslateMode, nand_translate_to_bytes
from opentl.tldisk import buffer_has_tl_disklabel_anchor
from opentl.tl_sector_audit import (
    audit_tl_kernel_alignment_bytes,
    flash_plane_sector0_prefix_bytes,
)
from opentl.logutil import configure_opentl_stderr_logging

__all__ = [
    "EXT2_LE16_MAGIC",
    "FLASH_5268_CLASS_SIZE",
    "IncompleteBBMInferenceError",
    "OOB_ENVELOPE",
    "PAGE_DATA",
    "PAGE_RAW",
    "PAGE_SPARE",
    "PURE_DATA_PLANE",
    "PHYS_PAGE_BASE_HOLE",
    "PTYPE_NTL_RW",
    "AssembledNTLResult",
    "LazyChainAwareVirtNandPageTable",
    "VirtNandPageTable",
    "BlockMapBuild",
    "ExtractResult",
    "KERNEL_SECTORS_PER_NAND_PAGE",
    "LogicalOpenTLSession",
    "OpenTL",
    "OPENTLA4_EXT2_MAGIC_OFF",
    "OPENTLA4_NUM_SECTORS",
    "OPENTLA4_START_SECTOR",
    "SCHEMA_V1",
    "SECTOR_BYTES",
    "TLPART_NAND_DATA_OFFSET_DEFAULT",
    "TLGeometry",
    "TL_ERASE_BYTES_DEFAULT",
    "TL_LOGICAL_PREFIX_DEFAULT",
    "TL_PHYS_BLOCK_HOLE",
    "TL_RAW_BLOCKS_DEFAULT",
    "TL_VIRT_BLOCKS_DEFAULT",
    "VirtBlockHoleError",
    "block_map_to_json_dict",
    "build_block_map_from_kernel_mount_replay",
    "build_lazy_chain_aware_virt_nand_page_table",
    "build_virt_nand_page_table",
    "build_virt_nand_page_table_chain_aware",
    "extract_opentla4",
    "extract_result_as_dict",
    "extract_virtual_disk_bytes",
    "extract_virtual_disk_bytes_chain_aware",
    "extract_virtual_disk_bytes_via_page_table",
    "geometry_boot_trace_dict",
    "infer_tl_mount_nand_logical_offset",
    "correlation_suggests_chain_aware_from_hits",
    "infer_chain_aware_tl_scan",
    "is_hole_phys_block",
    "layout_within_tl_erase_unit",
    "opentla4_ext2_magic_le",
    "assemble_ntl_rw_slice",
    "build_chain_head_cache",
    "ntl_assembly_to_jsonable",
    "parse_block_map_dict",
    "partition_payload_ext2_magic",
    "tl_geometry_from_flat_spare",
    "validate_virt_to_phys_block_entries",
    "verify_page_all",
    "verify_page_require_nand_page_length",
    "verify_page_require_spare_xsum",
    "virtual_tl_byte_stream_from_logical_plane",
    "virt_global_byte_to_physical",
    "TranslateMode",
    "nand_translate_to_bytes",
    "buffer_has_tl_disklabel_anchor",
    "audit_tl_kernel_alignment_bytes",
    "flash_plane_sector0_prefix_bytes",
    "configure_opentl_stderr_logging",
]
