"""Thin boardfs facades over :mod:`opentl` BBM / opentla4 volume helpers."""

from __future__ import annotations

from typing import Any

from boardfs.registry import FsRegistry
from opentl import registry_hooks
from opentl.driver import (
    LogicalOpenTLSession,
    audit_tl_kernel_alignment_bytes,
    buffer_has_tl_disklabel_anchor,
    correlation_suggests_chain_aware_from_hits,
    flash_plane_sector0_prefix_bytes,
)
from opentl.ext2_probe import buffer_has_ext2_signature, ext2_slice_has_mountable_root
from opentl.opentla4_volume import OPENTLA4_SLICE_NAME, Opentla4VolumeResult

bbm_virtual_scan_summary = registry_hooks.bbm_virtual_scan_summary_for_registry
infer_chain_aware_virtual_tl_scan = registry_hooks.infer_chain_aware_for_registry
apply_chain_aware_virtual_tl_scan = registry_hooks.apply_chain_aware_for_registry
assemble_opentla4_volume = registry_hooks.assemble_opentla4_volume_for_registry
assemble_opentla4_ntl_bytes = registry_hooks.assemble_opentla4_ntl_for_registry
infer_ext2_opentla4_chain_aware = registry_hooks.infer_ext2_opentla4_chain_aware_for_registry
linear_opentla4_bytes = registry_hooks.linear_opentla4_bytes
ntl_result_to_jsonable = registry_hooks.ntl_result_to_jsonable


def correlation_suggests_chain_aware(hits: list[Any]) -> bool:
    return correlation_suggests_chain_aware_from_hits(hits)


__all__ = [
    "OPENTLA4_SLICE_NAME",
    "buffer_has_ext2_signature",
    "ext2_slice_has_mountable_root",
    "FsRegistry",
    "LogicalOpenTLSession",
    "Opentla4VolumeResult",
    "apply_chain_aware_virtual_tl_scan",
    "assemble_opentla4_ntl_bytes",
    "assemble_opentla4_volume",
    "audit_tl_kernel_alignment_bytes",
    "bbm_virtual_scan_summary",
    "buffer_has_tl_disklabel_anchor",
    "correlation_suggests_chain_aware",
    "correlation_suggests_chain_aware_from_hits",
    "flash_plane_sector0_prefix_bytes",
    "infer_chain_aware_virtual_tl_scan",
    "infer_ext2_opentla4_chain_aware",
    "linear_opentla4_bytes",
    "ntl_result_to_jsonable",
]
