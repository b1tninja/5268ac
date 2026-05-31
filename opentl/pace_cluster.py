"""
PACE OpenTL cluster site geometry — content-neutral byte routing helpers.

Detects when an assembled opentla4 fs block reads the BBM linear site but not the
tag-64 ``+2048`` carrier at the same inode virt slot. Used by ext2 shadow promotion
and tag-64 overlays; no file-format or checksum knowledge.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentl.open_tl import KERNEL_NAND_PAGE_BYTES
from opentl.tl_bbm import BlockMapBuild

if TYPE_CHECKING:
    pass

PAGE_BYTES = int(KERNEL_NAND_PAGE_BYTES)


#region kernel_adjacent pace_cluster_bbm_plus_sites
def bbm_and_plus_chunks_at_gvirt(
    linear_prefix: bytes,
    block_map: BlockMapBuild,
    gvirt: int,
    *,
    blksz: int,
    page_bytes: int = PAGE_BYTES,
) -> tuple[bytes, bytes] | None:
    """Return ``(bbm_chunk, plus_chunk)`` at global virt byte ``gvirt``."""
    erase = int(block_map.geometry.erase_bytes)
    if erase <= 0 or blksz <= 0:
        return None
    vb = int(gvirt) // erase
    vo = int(gvirt) % erase
    v2p = block_map.virt_to_phys_block
    if vb < 0 or vb >= len(v2p):
        return None
    phys_blk = int(v2p[vb])
    if phys_blk <= 0:
        return None
    bbm_off = phys_blk * erase + vo
    if bbm_off + blksz > len(linear_prefix):
        return None
    plus_off = bbm_off + int(page_bytes)
    if plus_off + blksz > len(linear_prefix):
        return None
    return (
        linear_prefix[bbm_off : bbm_off + blksz],
        linear_prefix[plus_off : plus_off + blksz],
    )


#endregion


#region kernel_adjacent pace_cluster_stale_assembled
def stale_assembled_cluster_at_gvirt(
    *,
    assembled_chunk: bytes,
    linear_prefix: bytes,
    block_map: BlockMapBuild,
    gvirt: int,
    blksz: int,
) -> bool:
    """
    True when ``assembled_chunk`` matches BBM linear at ``gvirt`` but not ``+2048``.

    OpenTL stale-cluster signal for botched promote / wrong page routing on the
    assembled slice relative to prefix-plane carrier sites.
    """
    sites = bbm_and_plus_chunks_at_gvirt(
        linear_prefix,
        block_map,
        gvirt,
        blksz=blksz,
    )
    if sites is None:
        return False
    bbm_chunk, plus_chunk = sites
    return assembled_chunk == bbm_chunk and assembled_chunk != plus_chunk


def assembled_plus_divergent_at_gvirt(
    *,
    assembled_chunk: bytes,
    linear_prefix: bytes,
    block_map: BlockMapBuild,
    gvirt: int,
    blksz: int,
) -> bool:
    """
    True when tag-64 assembly disagrees with the prefix-plane ``+2048`` carrier chunk.

    Inverse of :func:`stale_assembled_cluster_at_gvirt`: BBM linear is wrong but the
    carrier plane at ``gvirt`` may still hold the routed payload (30151 uImage fb 2998+).
    """
    sites = bbm_and_plus_chunks_at_gvirt(
        linear_prefix,
        block_map,
        gvirt,
        blksz=blksz,
    )
    if sites is None:
        return False
    _bbm_chunk, plus_chunk = sites
    return assembled_chunk != plus_chunk


def stale_assembled_cluster_at_fs_block(
    *,
    assembled_chunk: bytes,
    linear_prefix: bytes,
    block_map: BlockMapBuild,
    virt_byte_start: int,
    fs_block_num: int,
    blksz: int,
) -> bool:
    """``stale_assembled_cluster_at_gvirt`` keyed by opentla4 filesystem block number."""
    if fs_block_num <= 0:
        return False
    gvirt = int(virt_byte_start) + int(fs_block_num) * int(blksz)
    return stale_assembled_cluster_at_gvirt(
        assembled_chunk=assembled_chunk,
        linear_prefix=linear_prefix,
        block_map=block_map,
        gvirt=gvirt,
        blksz=blksz,
    )


#endregion


__all__ = [
    "assembled_plus_divergent_at_gvirt",
    "bbm_and_plus_chunks_at_gvirt",
    "stale_assembled_cluster_at_fs_block",
    "stale_assembled_cluster_at_gvirt",
]
