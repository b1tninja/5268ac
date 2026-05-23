"""FsRegistry-aware helpers (lazy :mod:`boardfs` import)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opentl import bbm_chain
from opentl import opentla4_volume as o4
from opentl.driver import (
    AssembledNTLResult,
    LogicalOpenTLSession,
    ntl_assembly_to_jsonable,
)

if TYPE_CHECKING:
    from boardfs.registry import FsRegistry

ntl_result_to_jsonable = ntl_assembly_to_jsonable


#region kernel_adjacent registry_hooks_boardfs_facade
def _tl_slice_view(reg: FsRegistry, slice_name: str) -> o4.TlSliceView:
    sl = reg.tl_slice_by_name(slice_name)
    return o4.TlSliceView(
        name=sl.name,
        ptype=int(sl.ptype),
        offset_bytes=int(sl.offset_bytes),
        length_bytes=int(sl.length_bytes),
    )


def resolve_flat_oob(reg: FsRegistry) -> bytes | None:
    session = getattr(reg, "attached_logical_opentl_session", None)
    oob = o4.resolve_flat_oob_from_session(session)
    if oob:
        return oob
    cache_oob = getattr(reg, "_flat_oob_cache", None)
    if cache_oob:
        return bytes(cache_oob)
    try:
        from unand.plane import LogicalPlane

        backing = getattr(reg, "backing_path", None)
        if backing is None:
            return None
        plane = LogicalPlane(backing)
        if plane.has_flat_spare_in_file:
            return plane.flat_spare_bytes()
    except (TypeError, ValueError, OSError):
        pass
    return None


def assemble_opentla4_ntl_for_registry(
    reg: FsRegistry,
    *,
    slice_name: str = o4.OPENTLA4_SLICE_NAME,
    flat_oob: bytes | None = None,
    max_assemble_bytes: int | None = None,
) -> AssembledNTLResult | None:
    m = getattr(reg, "attached_block_map", None)
    session = getattr(reg, "attached_logical_opentl_session", None)
    if m is None or session is None:
        return None
    if flat_oob is None:
        flat_oob = resolve_flat_oob(reg)
    if flat_oob is None:
        return None
    try:
        tl_slice = _tl_slice_view(reg, slice_name)
    except KeyError:
        return None
    return o4.assemble_opentla4_ntl_bytes(
        session=session,
        block_map=m,
        flat_oob=flat_oob,
        tl_slice=tl_slice,
        max_assemble_bytes=max_assemble_bytes,
    )


def linear_opentla4_bytes(reg: FsRegistry, *, slice_name: str = o4.OPENTLA4_SLICE_NAME) -> bytes | None:
    try:
        tl_slice = _tl_slice_view(reg, slice_name)
        tlp = reg.flash.read_partition("tlpart")
    except (KeyError, Exception):
        return None
    skip = int(getattr(reg, "_tl_mtd_skip", 0) or 0)
    return o4.linear_opentla4_mtd_window(tlp, tl_slice, mtd_skip=skip)


def infer_ext2_opentla4_chain_aware_for_registry(
    reg: FsRegistry,
    *,
    slice_name: str = o4.OPENTLA4_SLICE_NAME,
    linear_slice: bytes | None = None,
    virt_slice: bytes | None = None,
) -> bool:
    if linear_slice is None:
        linear_slice = linear_opentla4_bytes(reg, slice_name=slice_name)
    session = getattr(reg, "attached_logical_opentl_session", None)
    m = getattr(reg, "attached_block_map", None)
    if virt_slice is None and session is not None and m is not None:
        try:
            tl_slice = _tl_slice_view(reg, slice_name)
            virt_slice = o4.virt_opentla4_probe_bytes(session, m, tl_slice)
        except KeyError:
            virt_slice = None
    return o4.infer_ext2_opentla4_chain_aware(linear_slice=linear_slice, virt_slice=virt_slice)


def infer_chain_aware_for_registry(
    reg: FsRegistry,
    *,
    linear_tlpart: bytes | None = None,
    ot_session: LogicalOpenTLSession | None = None,
    tl_slice: str = o4.OPENTLA4_SLICE_NAME,
) -> bool:
    if linear_tlpart is None:
        try:
            linear_tlpart = reg.flash.read_partition("tlpart")
        except KeyError:
            linear_tlpart = None
    if ot_session is None:
        ot_session = getattr(reg, "attached_logical_opentl_session", None)

    def _ext2() -> bool:
        return infer_ext2_opentla4_chain_aware_for_registry(reg, slice_name=tl_slice)

    return bbm_chain.infer_chain_aware_virtual_tl_scan(
        tlpart_tl_scan_bytes=reg.tlpart_tl_scan_bytes,
        linear_tlpart=linear_tlpart,
        ot_session=ot_session,
        ext2_chain_infer=_ext2,
    )


def apply_chain_aware_for_registry(
    reg: FsRegistry,
    ot_session: LogicalOpenTLSession,
    flat_oob: bytes,
) -> None:
    bbm_chain.apply_chain_aware_to_session(ot_session, flat_oob)
    inner = reg._opentl_session
    if inner is not None and inner is not ot_session:
        inner.set_chain_aware_virt_reads(flat_oob)
    reg._flat_oob_cache = bytes(flat_oob)  # type: ignore[attr-defined]
    reg.invalidate_tl_cache()


def bbm_virtual_scan_summary_for_registry(
    reg: FsRegistry,
    ot_session: LogicalOpenTLSession | None,
    *,
    chain_aware_applied: bool = False,
) -> dict[str, Any]:
    return bbm_chain.bbm_virtual_scan_summary(
        getattr(reg, "attached_block_map", None),
        ot_session,
        reg.tlpart_tl_scan_bytes,
        chain_aware_applied=chain_aware_applied,
    )


def assemble_opentla4_volume_for_registry(
    reg: "FsRegistry",
    *,
    slice_name: str = o4.OPENTLA4_SLICE_NAME,
    max_assemble_bytes: int | None = None,
) -> o4.Opentla4VolumeResult:
    tl_slice = _tl_slice_view(reg, slice_name)
    tlpart: bytes | None = None
    try:
        tlpart = reg.flash.read_partition("tlpart")
    except KeyError:
        pass
    skip = int(getattr(reg, "_tl_mtd_skip", 0) or 0)
    bbm_bytes: bytes | None = None
    try:
        bbm_bytes = reg.block_dev_for_tl_slice(slice_name).read_slice()
    except Exception:
        pass
    return o4.assemble_opentla4_volume(
        tl_slice=tl_slice,
        tlpart_bytes=tlpart,
        mtd_skip=skip,
        session=getattr(reg, "attached_logical_opentl_session", None),
        block_map=getattr(reg, "attached_block_map", None),
        flat_oob=resolve_flat_oob(reg),
        bbm_slice_bytes=bbm_bytes,
        max_assemble_bytes=max_assemble_bytes,
    )
#endregion


__all__ = [
    "apply_chain_aware_for_registry",
    "assemble_opentla4_ntl_for_registry",
    "assemble_opentla4_volume_for_registry",
    "bbm_virtual_scan_summary_for_registry",
    "infer_chain_aware_for_registry",
    "infer_ext2_opentla4_chain_aware_for_registry",
    "linear_opentla4_bytes",
    "ntl_result_to_jsonable",
    "resolve_flat_oob",
]
