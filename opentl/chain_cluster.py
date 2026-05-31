"""
NTL chain-routed 1 KiB cluster reads at a fixed inode virt site.

When BBM assembly mapped the wrong chain phys but spare/OOB still enumerates alternates
at the same ``(vblk, ppage)``, walk mode-2 candidates and return the carrier-aligned
chunk. Content-neutral: spare pairing, tag-64 ``+2048``, cross-erase only.
"""

from __future__ import annotations

from typing import Any

from opentl.ntl_rw import (
    PACE_SPARE_D_PAGE_TAG,
    _chain_head_for_vblk,
    _chain_slots_for_vblk,
    _find_phy_spare_matches,
    _pages_per_erase,
    _read_ppage_after_find_phy,
    tag64_spare_at_phys_page,
)
from opentl.open_tl import KERNEL_NAND_PAGE_BYTES
from opentl.pace_cluster import (
    assembled_plus_divergent_at_gvirt,
    bbm_and_plus_chunks_at_gvirt,
    stale_assembled_cluster_at_gvirt,
)
from opentl.spare_chain_replay import iter_ntl_read_page_phy_candidates, oob_page_spare
from opentl.tl_bbm import BlockMapBuild, TLGeometry
from opentl.virt_slot import chain_length_for_vblk

PAGE_BYTES = int(KERNEL_NAND_PAGE_BYTES)


def _chunk_from_page(page: bytes, *, off_in_page: int, blksz: int) -> bytes:
    start = int(off_in_page)
    end = start + int(blksz)
    if start < 0 or end > len(page):
        return page[start:start] if start < len(page) else b""
    return page[start:end]


def _score_chain_chunk(
    chunk: bytes,
    *,
    bbm_chunk: bytes,
    plus_chunk: bytes,
    tag64: bool,
) -> int:
    if tag64 and chunk == plus_chunk:
        return 3
    if chunk == plus_chunk:
        return 2
    if chunk != bbm_chunk:
        return 1
    return 0


#region kernel_adjacent chain_cluster_routed_read
def chain_routed_cluster_at_gvirt(
    *,
    linear_prefix: bytes,
    flat_oob: bytes,
    block_map: BlockMapBuild,
    gvirt: int,
    blksz: int,
    assembled_chunk: bytes,
    stats: dict[str, Any] | None = None,
) -> bytes | None:
    """
    Return a chain-routed or tag-64 carrier 1 KiB cluster at ``gvirt``.

    Handles stale BBM assembly (``assembled == bbm != plus``) via mode-2 chain walk,
    and tag-64 carrier divergence (``assembled != plus`` with tag-64 spare) via the
    prefix-plane ``+2048`` chunk. Returns ``None`` when already aligned.
    """
    geo: TLGeometry = block_map.geometry
    erase = int(geo.erase_bytes)
    if erase <= 0:
        return None
    vb = int(gvirt) // erase
    vo = int(gvirt) % erase
    ppage = vo // PAGE_BYTES
    off_in_page = vo % PAGE_BYTES
    v2p = block_map.virt_to_phys_block
    if vb < 0 or vb >= len(v2p):
        return None

    sites = bbm_and_plus_chunks_at_gvirt(
        linear_prefix,
        block_map,
        int(gvirt),
        blksz=int(blksz),
    )
    if sites is None:
        return None
    bbm_chunk, plus_chunk = sites

    stale = stale_assembled_cluster_at_gvirt(
        assembled_chunk=assembled_chunk,
        linear_prefix=linear_prefix,
        block_map=block_map,
        gvirt=int(gvirt),
        blksz=int(blksz),
    )
    plus_divergent = assembled_plus_divergent_at_gvirt(
        assembled_chunk=assembled_chunk,
        linear_prefix=linear_prefix,
        block_map=block_map,
        gvirt=int(gvirt),
        blksz=int(blksz),
    )
    if not stale and not plus_divergent:
        return None

    if plus_divergent and not stale:
        phys_blk = int(v2p[vb])
        if phys_blk > 0 and tag64_spare_at_phys_page(
            flat_oob,
            geo,
            phys_blk,
            int(ppage),
        ):
            if plus_chunk != assembled_chunk:
                return plus_chunk
        return None

    if not stale:
        return None
    work_stats: dict[str, Any] = stats if stats is not None else {}
    head_cache = work_stats.get("_chain_head")
    if not isinstance(head_cache, dict):
        head_cache = {}
        work_stats["_chain_head"] = head_cache
    head = _chain_head_for_vblk(flat_oob, block_map, vb, head_cache={"_chain_head": head_cache})
    head_phys = int(head) if head is not None else int(v2p[vb])
    chain_len = int(chain_length_for_vblk(flat_oob, block_map, vb, cache={}))
    slot_stats: dict[str, Any] = {"_chain_head": head_cache}
    slots, _cl = _chain_slots_for_vblk(
        slot_stats,
        flat_oob,
        block_map,
        geo,
        vblk=int(vb),
        head=int(head_phys),
    )
    ppe = int(_pages_per_erase(block_map))
    tries = iter_ntl_read_page_phy_candidates(
        slots,
        chain_len,
        requested_ppage=int(ppage),
        pages_per_erase=ppe,
    )
    best: bytes | None = None
    best_score = -1
    flags_by_phys = {int(s.phys): int(s.flags) for s in slots}
    for phys, try_ppage in tries:
        spare64 = oob_page_spare(flat_oob, geo, int(phys), int(try_ppage))
        if not _find_phy_spare_matches(
            spare64,
            vblk=int(vb),
            requested_ppage=int(ppage),
            slot_flags=int(flags_by_phys.get(int(phys), 0)),
        ):
            continue
        tag64 = (spare64[0xD] & 0xFF) == PACE_SPARE_D_PAGE_TAG or (
            try_ppage > 0
            and (oob_page_spare(flat_oob, geo, int(phys), int(try_ppage) - 1)[0xD] & 0xFF)
            == PACE_SPARE_D_PAGE_TAG
        )
        read_hit = _read_ppage_after_find_phy(
            linear_prefix,
            flat_oob,
            geo,
            block_map,
            vblk=int(vb),
            requested_ppage=int(ppage),
            phys=int(phys),
            spare64=spare64,
            slot_flags=int(flags_by_phys.get(int(phys), 0)),
            pages_per_erase=ppe,
            stats=work_stats,
            accept_page=None,
        )
        if read_hit is None:
            continue
        page, _rec_phys, _nand_pp = read_hit
        chunk = _chunk_from_page(page, off_in_page=off_in_page, blksz=int(blksz))
        if len(chunk) < int(blksz):
            continue
        score = _score_chain_chunk(
            chunk,
            bbm_chunk=bbm_chunk,
            plus_chunk=plus_chunk,
            tag64=bool(tag64),
        )
        if score > best_score:
            best_score = score
            best = chunk
    if best is None or best == assembled_chunk:
        return None
    return best


#endregion


__all__ = ["chain_routed_cluster_at_gvirt"]
