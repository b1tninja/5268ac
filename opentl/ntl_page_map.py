"""
Per–virtual-block page map (read-only port of ``ntl_build_page_map`` / ``ntl_lookup_page_map``).

Kernel: ``0x80284a20`` / ``0x80285248``. LRU freelists at ``remap+0x14f38`` are not modeled;
we keep an in-memory ``dict[vblk]``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from opentl.spare_chain_replay import Mode2ChainSlot, oob_page_spare
from opentl.spare_layout import SPARE_U32_ERASED_SENTINEL, map_page_state, parse_spare, spare_read_verify_ok
from opentl.tl_bbm import BlockMapBuild, TLGeometry

PAGE_MAP_MISS = 2
PAGE_MAP_HOLE = (-1, 0xFFFF)


@dataclass
class VblkPageMap:
    """Kernel cache node payload (no LRU links)."""

    vblk: int
    pages: dict[int, tuple[int, int]] = field(default_factory=dict)  # vpage -> (pblk, ppage)
    bitmap: list[int] = field(default_factory=lambda: [0, 0])  # up to 64 pages


@dataclass
class PageMapCache:
    """Lazy per-vblk maps for offline NTL reads."""

    _maps: dict[int, VblkPageMap] = field(default_factory=dict)

    def get(self, vblk: int) -> VblkPageMap | None:
        return self._maps.get(vblk)

    def put(self, m: VblkPageMap) -> None:
        self._maps[m.vblk] = m


#region kernel: 0x80284a20
def build_page_map(
    flat_oob: bytes,
    geo: TLGeometry,
    *,
    vblk: int,
    head_phys: int,
    chain_slots: list[Mode2ChainSlot],
    chain_length: int,
    pages_per_erase: int,
    large_page: bool = True,
) -> VblkPageMap:
    """
    Walk phys chain **tail page index → head page** on each erase unit (kernel
    ``ntl_build_page_map``), recording the first valid spare per ``vpage``.
    """
    m = VblkPageMap(vblk=vblk)
    if head_phys == 0xFFFFFFFF or chain_length < 1:
        return m

    chain_phys: list[int] = []
    for i in range(chain_length):
        if i < len(chain_slots):
            chain_phys.append(chain_slots[i].phys)
        elif i == 0:
            chain_phys.append(head_phys)
    if not chain_phys:
        chain_phys = [head_phys]

    chain_idx = 0
    phys = chain_phys[0]
    ppage = pages_per_erase - 1
    max_pages = pages_per_erase

    max_steps = pages_per_erase * max(chain_length, len(chain_phys), 1) + 1
    steps = 0
    while phys != 0xFFFFFFFF and 0 <= phys < geo.raw_blocks:
        steps += 1
        if steps > max_steps:
            break
        spare = oob_page_spare(flat_oob, geo, phys, ppage)
        if spare_read_verify_ok(spare, large_page=large_page, pages_per_erase=pages_per_erase):
            raw_st = spare[4] & 0xFF
            if raw_st == 0x24:
                sr = parse_spare(spare)
                if not sr.is_erased_like():
                    vtag = sr.virt_u32(large_page=large_page)
                    if vtag != SPARE_U32_ERASED_SENTINEL and vtag == (vblk & 0xFFFFFFFF):
                        flags_u16 = 0
                        if chain_idx < len(chain_slots):
                            flags_u16 = chain_slots[chain_idx].flags & 0xFF
                        if flags_u16 == 0:
                            vpage = ppage
                        else:
                            vpage = spare[0xD] & 0xFF
                        if vpage < max_pages and vpage not in m.pages:
                            m.pages[vpage] = (phys, ppage)

        if ppage > 0:
            ppage -= 1
        else:
            if chain_idx >= chain_length - 1:
                break
            chain_idx += 1
            if chain_idx >= len(chain_phys):
                break
            phys = chain_phys[chain_idx]
            ppage = pages_per_erase - 1

    return m


#endregion


#region kernel: 0x80285248
def lookup_page_map(m: VblkPageMap, vpage: int) -> tuple[int, int] | None:
    """
    ``ntl_lookup_page_map`` mode 0.

    Returns ``(pblk, ppage)`` when the bitmap bit is **clear** and an entry exists.
    Returns ``None`` when the bitmap bit is **set** (kernel hole sentinel — use chain walk).
    """
    if vpage < 0:
        return None
    word = vpage >> 5
    if word < len(m.bitmap) and (m.bitmap[word] & (1 << (vpage & 0x1F))) != 0:
        return None
    ent = m.pages.get(vpage)
    if ent is None:
        return None
    return ent


def lookup_or_build(
    cache: PageMapCache,
    flat_oob: bytes,
    geo: TLGeometry,
    *,
    vblk: int,
    head_phys: int,
    chain_slots: list[Mode2ChainSlot],
    chain_length: int,
    pages_per_erase: int,
) -> VblkPageMap:
    existing = cache.get(vblk)
    if existing is not None:
        return existing
    built = build_page_map(
        flat_oob,
        geo,
        vblk=vblk,
        head_phys=head_phys,
        chain_slots=chain_slots,
        chain_length=chain_length,
        pages_per_erase=pages_per_erase,
    )
    cache.put(built)
    return built


#endregion
