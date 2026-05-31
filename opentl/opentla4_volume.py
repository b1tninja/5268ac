"""Assemble ``opentla4`` rw slice bytes via NTL / linear MTD / BBM virt (no inventory dissect)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from opentl.driver import (
    AssembledNTLResult,
    BlockMapBuild,
    LogicalOpenTLSession,
    PTYPE_NTL_RW,
    assemble_ntl_rw_slice,
    ntl_assembly_to_jsonable,
    partition_payload_ext2_magic,
)
from opentl.ext2_probe import (
    buffer_has_ext2_signature,
    ext2_slice_has_mountable_root,
)

OPENTLA4_SLICE_NAME = "opentla4"
LAZY_ASSEMBLE_PROBE_BYTES = 512 * 1024
ntl_result_to_jsonable = ntl_assembly_to_jsonable


@dataclass
class TlSliceView:
    """Minimal TL child slice metadata for volume assembly."""

    name: str
    ptype: int
    offset_bytes: int
    length_bytes: int


@dataclass
class Opentla4VolumeResult:
    slice_name: str
    slice_bytes: bytes
    ext2_sb_offset: int | None = None
    ext2_magic_ok: bool = False
    recovery: str | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    read_model: str = "unknown"
    ntl_assembly: dict[str, Any] | None = None


def resolve_flat_oob_from_session(session: LogicalOpenTLSession | None) -> bytes | None:
    if session is not None:
        oob = getattr(session, "_flat_oob", None)
        if oob:
            return bytes(oob)
    return None


#region kernel: 0x80289170
def assemble_opentla4_ntl_bytes(
    *,
    session: LogicalOpenTLSession,
    block_map: BlockMapBuild,
    flat_oob: bytes,
    tl_slice: TlSliceView,
    max_assemble_bytes: int | None = None,
    collect_page_histogram: bool = False,
    parallel_vblk_workers: int | None = None,
) -> AssembledNTLResult | None:
    if tl_slice.ptype != PTYPE_NTL_RW:
        return None
    return assemble_ntl_rw_slice(
        logical_prefix=session.linear_prefix,
        block_map=block_map,
        flat_oob=flat_oob,
        virt_byte_start=int(tl_slice.offset_bytes),
        virt_byte_length=int(tl_slice.length_bytes),
        slice_name=tl_slice.name,
        max_assemble_bytes=max_assemble_bytes,
        collect_page_histogram=collect_page_histogram,
        parallel_vblk_workers=parallel_vblk_workers,
    )
#endregion


#region kernel_adjacent opentla4_linear_mtd_window
def linear_opentla4_mtd_window(
    tlpart_bytes: bytes,
    tl_slice: TlSliceView,
    *,
    mtd_skip: int = 0,
) -> bytes | None:
    start = mtd_skip + int(tl_slice.offset_bytes)
    end = start + int(tl_slice.length_bytes)
    if end > len(tlpart_bytes):
        return None
    return tlpart_bytes[start:end]


def virt_opentla4_probe_bytes(
    session: LogicalOpenTLSession,
    block_map: BlockMapBuild,
    tl_slice: TlSliceView,
) -> bytes | None:
    erase = int(block_map.geometry.erase_bytes)
    probe_len = min(int(tl_slice.length_bytes), erase * 2)
    if probe_len <= 0:
        return None
    try:
        data, _, _ = session.extract_virtual_disk_bytes(int(tl_slice.offset_bytes), probe_len)
        return data
    except Exception:
        return None
#endregion


#region kernel_adjacent infer_ext2_opentla4_chain_aware
def infer_ext2_opentla4_chain_aware(
    *,
    linear_slice: bytes | None,
    virt_slice: bytes | None,
) -> bool:
    if linear_slice is None or virt_slice is None:
        return False
    if not buffer_has_ext2_signature(linear_slice):
        return False
    lin_mount, _ = ext2_slice_has_mountable_root(linear_slice)
    virt_mount, _ = ext2_slice_has_mountable_root(virt_slice)
    if lin_mount and not virt_mount:
        return True
    lin_magic, _ = partition_payload_ext2_magic(linear_slice)
    virt_magic, _ = partition_payload_ext2_magic(virt_slice)
    if lin_magic and not virt_magic:
        return True
    if buffer_has_ext2_signature(linear_slice) and not buffer_has_ext2_signature(virt_slice):
        return True
    return False
#endregion


def resolve_mountable_superblock(slice_bytes: bytes) -> int | None:
    """First superblock offset where Dissect lists ``/`` (uses :mod:`opentl.ext2_probe`)."""
    ok, sb = ext2_slice_has_mountable_root(slice_bytes)
    return sb if ok else None


def resolve_lazy_assemble_cap(
    tl_slice: TlSliceView,
    block_map: BlockMapBuild | None,
    *,
    probe_bytes: int = LAZY_ASSEMBLE_PROBE_BYTES,
) -> int:
    """Bytes to bulk-assemble up front; inode/file I/O beyond uses NTL per block."""
    cap = int(probe_bytes)
    if block_map is not None:
        erase = int(block_map.geometry.erase_bytes)
        if erase > 0:
            cap = max(cap, erase * 2)
    return min(int(tl_slice.length_bytes), cap)


def _effective_max_assemble_bytes(
    tl_slice: TlSliceView,
    block_map: BlockMapBuild | None,
    *,
    max_assemble_bytes: int | None,
    lazy_assembly: bool,
) -> int | None:
    if max_assemble_bytes is not None:
        return max_assemble_bytes
    if lazy_assembly:
        return resolve_lazy_assemble_cap(tl_slice, block_map)
    return None


#region kernel_adjacent assemble_opentla4_volume
def assemble_opentla4_volume(
    *,
    tl_slice: TlSliceView,
    tlpart_bytes: bytes | None,
    mtd_skip: int,
    session: LogicalOpenTLSession | None,
    block_map: BlockMapBuild | None,
    flat_oob: bytes | None,
    bbm_slice_bytes: bytes | None = None,
    max_assemble_bytes: int | None = None,
    collect_page_histogram: bool = False,
    parallel_vblk_workers: int | None = None,
    lazy_assembly: bool = False,
) -> Opentla4VolumeResult:
    """Try NTL → linear ``tlpart`` → supplied BBM bytes; return mountable superblock when found."""
    out = Opentla4VolumeResult(slice_name=tl_slice.name, slice_bytes=b"")
    sb: int | None = None
    ntl_result: AssembledNTLResult | None = None
    assemble_cap = _effective_max_assemble_bytes(
        tl_slice,
        block_map,
        max_assemble_bytes=max_assemble_bytes,
        lazy_assembly=lazy_assembly,
    )

    if tl_slice.ptype == PTYPE_NTL_RW and session is not None and block_map is not None and flat_oob:
        ntl_result = assemble_opentla4_ntl_bytes(
            session=session,
            block_map=block_map,
            flat_oob=flat_oob,
            tl_slice=tl_slice,
            max_assemble_bytes=assemble_cap,
            collect_page_histogram=collect_page_histogram,
            parallel_vblk_workers=parallel_vblk_workers,
        )
        if ntl_result is not None:
            out.ntl_assembly = ntl_result_to_jsonable(ntl_result)
            out.slice_bytes = ntl_result.data
            if lazy_assembly and assemble_cap is not None and assemble_cap < int(tl_slice.length_bytes):
                out.read_model = "ntl_rw_chain_replay_lazy"
            else:
                out.read_model = "ntl_rw_chain_replay"
            sb = resolve_mountable_superblock(ntl_result.data)

    if sb is None and tlpart_bytes is not None:
        linear = linear_opentla4_mtd_window(tlpart_bytes, tl_slice, mtd_skip=mtd_skip)
        if linear is not None:
            out.slice_bytes = linear
            out.read_model = "linear_tlpart"
            sb = resolve_mountable_superblock(linear)

    if sb is None and bbm_slice_bytes is not None:
        out.slice_bytes = bbm_slice_bytes
        out.read_model = "bbm_virt"
        sb = resolve_mountable_superblock(bbm_slice_bytes)

    if not out.slice_bytes and bbm_slice_bytes is not None:
        out.slice_bytes = bbm_slice_bytes

    if not out.slice_bytes:
        out.error = "no opentla4 slice bytes assembled"
        return out

    out.ext2_magic_ok, _ = partition_payload_ext2_magic(out.slice_bytes)
    if not out.ext2_magic_ok:
        out.ext2_magic_ok = buffer_has_ext2_signature(out.slice_bytes)

    if sb is not None:
        out.ext2_sb_offset = sb
    elif out.ext2_magic_ok:
        out.recovery = "superblock_scan"
        parts = ["ext2 magic present but no mountable superblock after NTL/BBM/linear attempts"]
        if ntl_result is not None:
            parts.append(
                f"ntl unresolved_vpages={ntl_result.unresolved_vpages} "
                f"spare_xsum_failures={ntl_result.spare_xsum_failures}"
            )
        out.error = " — ".join(parts)
    else:
        out.error = "no ext2 container on opentla4 slice"

    return out
#endregion


__all__ = [
    "LAZY_ASSEMBLE_PROBE_BYTES",
    "OPENTLA4_SLICE_NAME",
    "Opentla4VolumeResult",
    "TlSliceView",
    "assemble_opentla4_ntl_bytes",
    "assemble_opentla4_volume",
    "infer_ext2_opentla4_chain_aware",
    "linear_opentla4_mtd_window",
    "ntl_result_to_jsonable",
    "resolve_flat_oob_from_session",
    "resolve_lazy_assemble_cap",
    "resolve_mountable_superblock",
    "virt_opentla4_probe_bytes",
    "buffer_has_ext2_signature",
]
