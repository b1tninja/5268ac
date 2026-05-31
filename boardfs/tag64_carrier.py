"""PACE tag-64 page+2048 and cross-erase ext2 read overlays (kernel_adjacent)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentl.ntl_rw import (
    _pages_per_erase,
    pace_tag64_spare,
    resolve_tag64_cross_erase_phys_page,
    tag64_spare_at_phys_page,
)
from opentl.open_tl import KERNEL_NAND_PAGE_BYTES
from opentl.spare_chain_replay import oob_page_spare

if TYPE_CHECKING:
    from boardfs.ext2_volume_io import Ext2VolumeAccess

PAGE_BYTES = int(KERNEL_NAND_PAGE_BYTES)


#region kernel_adjacent ext2_read_slice_block
def read_slice_block(access: Ext2VolumeAccess, block_num: int) -> bytes:
    """Assembled slice prefix or per-block NTL replay when lazy (no tag-64 overlay)."""
    from boardfs.ext2_volume_io import read_ext2_filesystem_block

    blksz = int(access.blksz)
    if block_num <= 0:
        return b"\x00" * blksz
    off = block_num * blksz
    if off + blksz <= len(access.slice_bytes):
        return bytes(access.slice_bytes[off : off + blksz])
    if access.ntl is not None:
        return read_ext2_filesystem_block(access.ntl, block_num=block_num, blksz=blksz)
    return b"\x00" * blksz


#endregion


#region kernel_adjacent ext2_tag64_spare_probe
def tag64_spare_at_page(access: Ext2VolumeAccess, phys_blk: int, ppage: int) -> bool:
    if access.ntl is None:
        return False
    return tag64_spare_at_phys_page(
        access.ntl.flat_oob,
        access.ntl.block_map.geometry,
        phys_blk,
        ppage,
    )


#endregion


#region kernel_adjacent ext2_tag64_bbm_plus_sites
def _bbm_plus_chunks_at_gvirt(
    access: Ext2VolumeAccess,
    gvirt: int,
) -> tuple[bytes, bytes, int, int] | None:
    """Return (bbm_chunk, plus_chunk, phys_blk, ppage) for one global virt byte offset."""
    if access.ntl is None:
        return None
    blksz = int(access.blksz)
    erase = int(access.ntl.block_map.geometry.erase_bytes)
    if erase <= 0:
        return None
    vb = gvirt // erase
    vo = gvirt % erase
    ppage = vo // PAGE_BYTES
    v2p = getattr(access.ntl.block_map, "virt_to_phys_block", None)
    if not v2p or vb < 0 or vb >= len(v2p):
        return None
    phys_blk = int(v2p[vb])
    if phys_blk <= 0:
        return None
    prefix = access.ntl.session.linear_prefix
    bbm_off = phys_blk * erase + vo
    if bbm_off + blksz > len(prefix):
        return None
    plus_off = bbm_off + PAGE_BYTES
    if plus_off + blksz > len(prefix):
        return None
    return (
        prefix[bbm_off : bbm_off + blksz],
        prefix[plus_off : plus_off + blksz],
        phys_blk,
        ppage,
    )


def tag64_plus2048_for_gvirt(
    access: Ext2VolumeAccess,
    gvirt: int,
    slice_chunk: bytes,
) -> bytes | None:
    """
    Page+2048 carrier at inode virt ``gvirt`` when tag-64 spare pairing applies.

    Compares ``slice_chunk`` (assembled opentla4 read) against BBM linear and +2048
    sites at ``gvirt`` — not against the fs block number used for the read (so shadow
    promotion can still overlay live-map NAND sites).
    """
    sites = _bbm_plus_chunks_at_gvirt(access, gvirt)
    if sites is None:
        return None
    _bbm_chunk, plus_chunk, phys_blk, ppage = sites
    if slice_chunk == plus_chunk:
        return None
    if not tag64_spare_at_phys_page(
        access.ntl.flat_oob,
        access.ntl.block_map.geometry,
        phys_blk,
        ppage,
    ):
        return None
    return plus_chunk


#endregion


#region kernel_adjacent ext2_tag64_cross_erase_overlay
def tag64_cross_erase_next_vblk_for_gvirt(
    access: Ext2VolumeAccess,
    gvirt: int,
    slice_chunk: bytes,
) -> bytes | None:
    """
    Cross-erase tag-64 overlay: last page of ``vblk`` → page 0 of ``vblk+1``.

    Uses the same BBM site resolver as :func:`opentl.ntl_rw._read_ppage_after_find_phy`.
    Kept as a safety net when ext2 reads bypass fresh NTL assembly or shadow promotion
    changed the fs block phys.
    """
    if access.ntl is None:
        return None
    blksz = int(access.blksz)
    erase = int(access.ntl.block_map.geometry.erase_bytes)
    if erase <= 0:
        return None
    ppe = int(_pages_per_erase(access.ntl.block_map))
    vb = gvirt // erase
    vo = gvirt % erase
    ppage = vo // PAGE_BYTES
    off_in_page = vo % PAGE_BYTES
    if ppage != ppe - 1:
        return None
    v2p = access.ntl.block_map.virt_to_phys_block
    if vb < 0 or vb >= len(v2p):
        return None
    phys_blk = int(v2p[vb])
    if phys_blk <= 0:
        return None
    if not tag64_spare_at_phys_page(
        access.ntl.flat_oob,
        access.ntl.block_map.geometry,
        phys_blk,
        ppage,
    ):
        return None
    cross = resolve_tag64_cross_erase_phys_page(
        access.ntl.block_map,
        vblk=int(vb),
        requested_ppage=int(ppage),
        pages_per_erase=ppe,
    )
    if cross is None:
        return None
    read_phys, _read_pp = cross
    prefix = access.ntl.session.linear_prefix
    cross_off = int(read_phys) * erase + off_in_page
    if cross_off + blksz > len(prefix):
        return None
    cross_chunk = prefix[cross_off : cross_off + blksz]
    if cross_chunk == slice_chunk:
        return None
    return cross_chunk


def tag64_plus2048_chunk_for_fs_block(access: Ext2VolumeAccess, block_num: int) -> bytes | None:
    """Tag-64 carrier keyed by opentla4 fs block number (live-map phys)."""
    if access.ntl is None or block_num <= 0:
        return None
    gvirt = int(access.ntl.virt_byte_start) + int(block_num) * int(access.blksz)
    return tag64_plus2048_for_gvirt(access, gvirt, read_slice_block(access, block_num))


def apply_tag64_carrier_overlay(access: Ext2VolumeAccess, block_num: int) -> bytes:
    """Legacy fs-block overlay (prefer block-map reads in :mod:`boardfs.ext2_extent_merge`)."""
    chunk = read_slice_block(access, block_num)
    if not getattr(access, "tag64_carrier_overlay", False):
        return chunk
    plus = tag64_plus2048_chunk_for_fs_block(access, block_num)
    if plus is None:
        return chunk
    stats = access.ntl._stats if access.ntl is not None else None
    if isinstance(stats, dict):
        stats["tag64_carrier_overlays"] = int(stats.get("tag64_carrier_overlays", 0)) + 1
    return plus


#endregion
