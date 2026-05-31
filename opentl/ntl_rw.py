"""
Kernel-faithful **NTL mode-2** (``opentl_rw`` / ``ptype`` 17) virtual-disk assembly.

Annotated with ``#region kernel: 0x…`` (see ``reference/kernel_python_regions.md``).

Public entry points: :func:`assemble_ntl_rw_slice`, :class:`AssembledNTLResult`,
:func:`ntl_assembly_to_jsonable`. Host tools (e.g. ``paceflash``) should import these via
``opentl`` / :mod:`opentl.driver`, not this module's internals.
"""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Literal

ReadSource = Literal["kernel_bounce", "prefix_plane"]
DEFAULT_READ_SOURCE: ReadSource = "kernel_bounce"

from opentl.open_tl import KERNEL_NAND_PAGE_BYTES
from opentl.ntl_ecc import verify_read_phy_page_bounce
from opentl.ntl_page_map import PageMapCache, VblkPageMap, build_page_map, lookup_page_map
from opentl.spare_chain_replay import (
    build_mode2_chain_slots,
    chain_page_map_fast_path,
    iter_ntl_read_page_phy_candidates,
    oob_page_spare,
    spare_blob_matches_geo,
)
from opentl.virt_slot import chain_length_for_vblk
from opentl.spare_layout import (
    SPARE_U32_ERASED_SENTINEL,
    map_page_state,
    parse_spare,
    spare_page_accept_for_read,
    spare_read_verify_ok,
    xsum_matches,
)
from opentl.tl_bbm import BlockMapBuild, TLGeometry, is_hole_phys_block

PTYPE_NTL_RW = 17

_HOLE_PAGE = b"\x00" * KERNEL_NAND_PAGE_BYTES

# Observed on PACE S34ML01G1@TSOP48: valid ``0x24`` pages tag ``spare[0xd]==64`` while payload
# for logical virt erase-page ``N`` sits on NAND page ``N+1`` (not mirror flag @ slot+4).
PACE_SPARE_D_PAGE_TAG = 64


#region kernel_adjacent pace_tag64_nand_ppage
def pace_tag64_spare(spare64: bytes) -> bool:
    """True when spare tag byte ``[0xd]`` is PACE tag 64 (field / MCP observation, not a Ghidra EA)."""
    return len(spare64) >= 0x0E and (spare64[0xD] & 0xFF) == PACE_SPARE_D_PAGE_TAG


def tag64_spare_at_phys_page(
    flat_oob: bytes,
    geo: TLGeometry,
    phys_blk: int,
    ppage: int,
) -> bool:
    """Tag 64 on spare@``ppage`` or ``ppage-1`` within one phys erase block."""
    if pace_tag64_spare(oob_page_spare(flat_oob, geo, phys_blk, ppage)):
        return True
    if ppage > 0 and pace_tag64_spare(oob_page_spare(flat_oob, geo, phys_blk, ppage - 1)):
        return True
    return False


def resolve_tag64_cross_erase_phys_page(
    block_map: BlockMapBuild,
    *,
    vblk: int,
    requested_ppage: int,
    pages_per_erase: int,
) -> tuple[int, int] | None:
    """
    When tag-64 applies at the last NAND page of virt erase block ``vblk``, payload is on
    page **0** of ``virt_to_phys_block[vblk+1]`` (5268AC BAK/13171 uImage tail blocks).

    Host inference from dump correlation — not yet tied to a single Ghidra EA; see
    ``work_corpus/nand_probe/tag64_ppage63_cross_erase_bak.md``.
    """
    if int(requested_ppage) != int(pages_per_erase) - 1:
        return None
    vb1 = int(vblk) + 1
    v2p = block_map.virt_to_phys_block
    if vb1 < 0 or vb1 >= len(v2p):
        return None
    phys_next = int(v2p[vb1])
    if phys_next <= 0 or is_hole_phys_block(phys_next):
        return None
    return phys_next, 0


def _nand_ppage_for_virt_read(
    virt_ppage: int,
    spare64: bytes,
    *,
    slot_flags: int,
    pages_per_erase: int,
) -> int:
    """
    NAND page index for ``prefix[phys*erase + ppage*2048]`` after ``ntl_find_phy`` match.

    Kernel mirror (flag 4): ``find_phy`` already gates on ``spare[0xd]==requested_ppage``;
    use the matched ``virt_ppage`` for the data read. PACE tag 64: payload is one physical
    page ahead of the linear virt page index inside the erase block (clamped at
    ``pages_per_erase-1``). When clamped, :func:`resolve_tag64_cross_erase_phys_page` selects
    page 0 of ``vblk+1`` instead (see ``_read_ppage_after_find_phy``).
    """
    if (slot_flags & 4) != 0:
        return int(virt_ppage)
    if pace_tag64_spare(spare64):
        return min(int(virt_ppage) + 1, pages_per_erase - 1)
    return int(virt_ppage)


#endregion


def _use_page_map_for_chain(slots: list, chain_len: int) -> bool:
    """
    Build ``ntl_page_map`` only for mirror-flag chains (kernel ``*(chain+5)==4`` gate).

    Do **not** enable for every ``chain_len >= 1`` — single-hop PACE tag-64 chains need
    ``iter_ntl_read_page_phy_candidates`` + ``_nand_ppage_for_virt_read`` per page; a stale
    page-map row keyed wrong caused slice assembly to read logical page N while payload
    sits on N+1 (see ``uimage_mismatch_explain`` pace_page_plus1 cohort).
    """
    if chain_len < 1 or not slots:
        return False
    return chain_page_map_fast_path(slots, chain_len)


#region kernel_adjacent pace_tag64_ecc_spare_pair
def _ecc_spare_ppage_for_data_page(
    flat_oob: bytes,
    geo: TLGeometry,
    *,
    phys: int,
    data_ppage: int,
    stats: dict[str, Any],
) -> int:
    """
    PACE tag 64: ``find_phy`` matches spare on page ``N``; payload is on ``N+1``.

    ECC syndromes in the bounce buffer must use spare from the tag page, not the data page.
    When both page ``N`` and ``N+1`` carry tag 64 in spare (common on field dumps), prefer the
    **previous** page: syndromes for data@``N+1`` live on spare@``N``.
    """
    if data_ppage <= 0:
        return int(data_ppage)
    spare_prev = oob_page_spare(flat_oob, geo, phys, data_ppage - 1)
    if pace_tag64_spare(spare_prev):
        stats["tag64_ecc_spare_fixes"] = int(stats.get("tag64_ecc_spare_fixes", 0)) + 1
        return int(data_ppage) - 1
    spare_data = oob_page_spare(flat_oob, geo, phys, data_ppage)
    if pace_tag64_spare(spare_data):
        return int(data_ppage)
    return int(data_ppage)


#endregion


def _read_source_from_stats(stats: dict[str, Any]) -> ReadSource:
    src = stats.get("_read_source", DEFAULT_READ_SOURCE)
    return src if src in ("kernel_bounce", "prefix_plane") else DEFAULT_READ_SOURCE


def _hole_pages(needed_ppages: set[int]) -> dict[int, bytes]:
    """``ntl_read_page`` hole path: ``memset(page, 0, page_size)`` when virt slot unmapped."""
    return {int(p): _HOLE_PAGE for p in needed_ppages}


#region kernel_adjacent AssembledNTLResult_ntl_telemetry
@dataclass
class AssembledNTLResult:
    """Flat virt byte stream for one TL slice (typically ``opentla4``)."""

    data: bytes
    slice_name: str
    pblk_count: int
    vblk_count: int
    chain_lengths: dict[int, int] = field(default_factory=dict)
    deleted_pblks: int = 0
    spare_xsum_failures: int = 0
    unresolved_vpages: int = 0
    page_map_hits: int = 0
    ecc_corrections: int = 0
    ecc_failures: int = 0
    tag64_ecc_spare_fixes: int = 0
    tag64_cross_erase_reads: int = 0
    chain_walk_calls: int = 0
    page_map_builds: int = 0
    page_state_histogram: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


#endregion


#region kernel_adjacent opentl_rw_pages_per_erase
def _pages_per_erase(m: BlockMapBuild) -> int:
    from unand.geometry import PACE_DEFAULT

    return max(1, int(m.geometry.erase_bytes) // PACE_DEFAULT.page_data)


#endregion




#region kernel_adjacent ntl_chain_head_cache
def build_chain_head_cache(flat_oob: bytes, m: BlockMapBuild) -> dict[int, int | None]:
    """One NAND scan → ``vblk → chain head phys``."""
    geo = m.geometry
    by_vblk: dict[int, list[int]] = {}
    sp0_by_pblk: dict[int, bytes] = {}
    for pblk in range(geo.raw_blocks):
        if is_hole_phys_block(pblk):
            continue
        sp0 = oob_page_spare(flat_oob, geo, pblk, 0)
        sp0_by_pblk[pblk] = sp0
        if sp0 == b"\xff" * 64:
            continue
        sr = parse_spare(sp0)
        if not sr.is_erased_like():
            vtag = sr.virt_u32(large_page=True)
            if vtag == SPARE_U32_ERASED_SENTINEL:
                continue
            if map_page_state(sp0[4]) == 0xB6:
                continue
            by_vblk.setdefault(vtag, []).append(pblk)
    out: dict[int, int | None] = {}
    for vb, candidates in by_vblk.items():
        pick: int | None = None
        for pblk in candidates:
            sp0 = sp0_by_pblk[pblk]
            if map_page_state(sp0[4]) == 0 and sp0[4] == 0:
                pick = pblk
                break
        if pick is None and candidates:
            pick = min(candidates)
        out[vb] = pick
    return out


def _chain_head_for_vblk(
    flat_oob: bytes,
    m: BlockMapBuild,
    vblk: int,
    *,
    head_cache: dict[int, int | None] | None = None,
) -> int | None:
    """
    Chain anchor phys for ``vblk`` — ``*(remap+8)[vblk]`` dword0 (current/tail mapping).

    ``ntl_put_chain_in_array`` starts here and walks **forward** via page-0 ``next_pblk``.
    Spare scan is fallback only when the BBM slot is a hole (``0xffffffff``).
    """
    head: int | None = None
    if vblk < len(m.virt_to_phys_block):
        pb = int(m.virt_to_phys_block[vblk])
        if not is_hole_phys_block(pb):
            head = pb
    if head is None and head_cache is not None and vblk in head_cache:
        head = head_cache[vblk]
    if head is None:
        head = _chain_head_from_spare_scan(flat_oob, m, vblk)
    if head_cache is not None:
        head_cache[vblk] = head
    return head


#region kernel_adjacent ntl_chain_head_spare_scan_fallback
def _chain_head_from_spare_scan(flat_oob: bytes, m: BlockMapBuild, vblk: int) -> int | None:
    """Fallback when ``virt_to_phys_block[vblk]`` is hole — scan page-0 spare virt tags."""
    geo = m.geometry
    candidates: list[int] = []
    for pblk in range(geo.raw_blocks):
        if is_hole_phys_block(pblk):
            continue
        sp0 = oob_page_spare(flat_oob, geo, pblk, 0)
        if sp0 == b"\xff" * 64:
            continue
        sr = parse_spare(sp0)
        if not sr.virt_u32_meaningful(large_page=True):
            continue
        if sr.virt_u32(large_page=True) != (vblk & 0xFFFFFFFF):
            continue
        if map_page_state(sp0[4]) == 0xB6:
            continue
        candidates.append(pblk)
    if not candidates:
        return None
    for pblk in candidates:
        sp0 = oob_page_spare(flat_oob, geo, pblk, 0)
        if map_page_state(sp0[4]) == 0 and sp0[4] == 0:
            return pblk
    return min(candidates)


#endregion


#endregion


#region kernel_adjacent opentl_rw_mount_scan_stats
def _histogram_page0_spare(
    flat_oob: bytes,
    m: BlockMapBuild,
    *,
    head_cache: dict[int, int | None] | None = None,
) -> tuple[int, dict[str, int]]:
    """Page-0 spare histogram; reuses ``head_cache`` scan when provided."""
    geo = m.geometry
    hist: Counter[str] = Counter()
    deleted = 0
    if head_cache is not None:
        for pblk in range(geo.raw_blocks):
            if is_hole_phys_block(pblk):
                continue
            sp0 = oob_page_spare(flat_oob, geo, pblk, 0)
            st = map_page_state(sp0[4])
            hist[f"state_0x{st:02x}"] += 1
            if st == 0xB6:
                deleted += 1
        return deleted, {k: int(v) for k, v in hist.items()}
    for pblk in range(geo.raw_blocks):
        if is_hole_phys_block(pblk):
            continue
        sp0 = oob_page_spare(flat_oob, geo, pblk, 0)
        st = map_page_state(sp0[4])
        hist[f"state_0x{st:02x}"] += 1
        if st == 0xB6:
            deleted += 1
    return deleted, {k: int(v) for k, v in hist.items()}


def _needed_vblk_pages(
    virt_byte_start: int,
    virt_byte_end: int,
    erase_bytes: int,
) -> dict[int, set[int]]:
    needed: dict[int, set[int]] = {}
    g = virt_byte_start
    while g < virt_byte_end:
        vb = g // erase_bytes
        vo = g % erase_bytes
        ppage = vo // KERNEL_NAND_PAGE_BYTES
        needed.setdefault(vb, set()).add(ppage)
        g += KERNEL_NAND_PAGE_BYTES - (vo % KERNEL_NAND_PAGE_BYTES)
    return needed


#endregion


#region kernel: 0x80288bd4
def _find_phy_spare_matches(
    spare64: bytes,
    *,
    vblk: int,
    requested_ppage: int,
    slot_flags: int,
    large_page: bool = True,
) -> bool:
    """
    ``ntl_find_phy`` spare acceptance before ``ntl_verify_read_phy_page``.

    Status must be ``$`` (0x24) only — Ghidra @ ``0x80288bd4``: ``cVar2 == '\\0'`` rejects the
    candidate (``return`` without filling ``param_10``); only ``'$'`` sets phys/page out.
    Virt tag must match ``vblk``. When the chain slot mirror flag (``4``) is set,
    ``spare[0xd]`` must equal ``requested_ppage``.
    """
    raw_st = spare64[4] & 0xFF
    if raw_st != 0x24:
        return False
    sr = parse_spare(spare64)
    if sr.is_erased_like():
        return False
    vtag = sr.virt_u32(large_page=large_page)
    if vtag == SPARE_U32_ERASED_SENTINEL or vtag != (vblk & 0xFFFFFFFF):
        return False
    if (slot_flags & 4) != 0 and (spare64[0xD] & 0xFF) != (requested_ppage & 0xFF):
        return False
    return True


def _slot_flags_for_phys(slots: list, phys: int) -> int:
    for s in slots:
        if int(s.phys) == int(phys):
            return int(s.flags) & 0xFF
    return 0


#endregion


#region kernel: 0x80288600
def _verify_read_phy_page(
    prefix: bytes,
    flat_oob: bytes,
    geo: TLGeometry,
    *,
    phys: int,
    ppage: int,
    pages_per_erase: int,
    stats: dict[str, Any],
    expected_vblk: int | None = None,
    accept_page: Callable[[int, int, bytes, bytes], bool] | None = None,
) -> bytes | None:
    """``ntl_verify_read_phy_page`` @ ``0x80288600`` — trailer-byte gate then optional ECC."""
    erase = int(geo.erase_bytes)
    base = phys * erase + ppage * KERNEL_NAND_PAGE_BYTES
    end = base + KERNEL_NAND_PAGE_BYTES
    if base < 0 or end > len(prefix):
        return None
    page_data = prefix[base:end]
    data_ppage = int(ppage)
    ecc_spare_ppage = _ecc_spare_ppage_for_data_page(
        flat_oob, geo, phys=phys, data_ppage=data_ppage, stats=stats
    )
    spare64 = oob_page_spare(flat_oob, geo, phys, ecc_spare_ppage)
    if (spare64[4] & 0xFF) != 0x24:
        return None
    state = map_page_state(spare64[4])
    if state != 0x24:
        return None
    if not spare_read_verify_ok(spare64, large_page=True, pages_per_erase=pages_per_erase):
        stats["spare_xsum_failures"] = int(stats.get("spare_xsum_failures", 0)) + 1
        return None
    trailer_idx = min(max(pages_per_erase, 1), 64) - 1
    read_src = _read_source_from_stats(stats)
    page_out = page_data
    # Kernel @ 0x80288600: printk on ECC failure, verify still returns 0; ntl_read_page memcpy's
    # param_6 (NAND bounce). Tag-64 rows pair data@N+1 with spare/ECC@N (see assembly_gap probe).
    if spare64[trailer_idx] == 0xFF:
        bounce = bytearray(page_data) + bytearray(spare64)
        out, corrected, ecc_hard_fail = verify_read_phy_page_bounce(
            bounce,
            page_size=KERNEL_NAND_PAGE_BYTES,
            pages_per_erase=pages_per_erase,
        )
        if corrected:
            stats["ecc_corrections"] = int(stats.get("ecc_corrections", 0)) + 1
        if ecc_hard_fail:
            stats["ecc_failures"] = int(stats.get("ecc_failures", 0)) + 1
        if read_src == "kernel_bounce" and out is not None:
            page_out = out
        # prefix_plane: keep captured prefix plane at data_ppage (forensic dump fidelity)
    if accept_page is not None and not accept_page(phys, data_ppage, page_out, spare64):
        return None
    return page_out


def _record_page_phys_base(
    stats: dict[str, Any],
    *,
    vblk: int,
    ppage: int,
    phys: int,
    nand_ppage: int,
    erase: int,
) -> None:
    bases = stats.get("_page_phys_base")
    if not isinstance(bases, dict):
        bases = {}
        stats["_page_phys_base"] = bases
    bases[(int(vblk), int(ppage))] = int(phys) * int(erase) + int(nand_ppage) * KERNEL_NAND_PAGE_BYTES


#endregion


def _lookup_or_build_counted(
    cache: PageMapCache,
    stats: dict[str, Any],
    flat_oob: bytes,
    geo: TLGeometry,
    *,
    vblk: int,
    head_phys: int,
    chain_slots: list,
    chain_length: int,
    pages_per_erase: int,
) -> VblkPageMap:
    existing = cache.get(vblk)
    if existing is not None:
        return existing
    stats["page_map_builds"] = int(stats.get("page_map_builds", 0)) + 1
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


def _chain_slots_for_vblk(
    stats: dict[str, Any],
    flat_oob: bytes,
    m: BlockMapBuild,
    geo: TLGeometry,
    *,
    vblk: int,
    head: int,
) -> tuple[list, int]:
    chain_lens = stats.get("_chain_len")
    if not isinstance(chain_lens, dict):
        chain_lens = {}
        stats["_chain_len"] = chain_lens
    chain_len = chain_lens.get(vblk)
    if chain_len is None:
        chain_len = chain_length_for_vblk(flat_oob, m, vblk, cache=chain_lens)
        chain_lens[vblk] = chain_len
    slot_cache = stats.get("_chain_slots")
    if not isinstance(slot_cache, dict):
        slot_cache = {}
        stats["_chain_slots"] = slot_cache
    slots = slot_cache.get(vblk)
    if slots is None:
        slots = build_mode2_chain_slots(
            flat_oob,
            geo,
            start_phys=int(head),
            chain_length=int(chain_len),
            page_size_is_0x200=False,
        )
        slot_cache[vblk] = slots
    return slots, int(chain_len)


#region kernel_adjacent tag64_cross_erase_vblk_read
def _read_ppage_after_find_phy(
    prefix: bytes,
    flat_oob: bytes,
    geo: TLGeometry,
    m: BlockMapBuild,
    *,
    vblk: int,
    requested_ppage: int,
    phys: int,
    spare64: bytes,
    slot_flags: int,
    pages_per_erase: int,
    stats: dict[str, Any],
    accept_page: Callable[[int, int, bytes, bytes], bool] | None,
) -> tuple[bytes, int, int] | None:
    """
    Load one 2 KiB virt page after ``ntl_find_phy`` matched spare on ``phys``.

    Applies PACE tag-64 page+2048 within the erase block, then cross-erase ``vblk+1`` page 0
    when ``requested_ppage`` is the last page index and tag-64 spare is present.
    """
    if tag64_spare_at_phys_page(flat_oob, geo, int(phys), int(requested_ppage)):
        cross = resolve_tag64_cross_erase_phys_page(
            m,
            vblk=int(vblk),
            requested_ppage=int(requested_ppage),
            pages_per_erase=int(pages_per_erase),
        )
        if cross is not None:
            read_phys, read_pp = cross
            page = _verify_read_phy_page(
                prefix,
                flat_oob,
                geo,
                phys=int(read_phys),
                ppage=int(read_pp),
                pages_per_erase=pages_per_erase,
                stats=stats,
                expected_vblk=int(vblk) + 1,
                accept_page=accept_page,
            )
            if page is not None:
                stats["tag64_cross_erase_reads"] = int(
                    stats.get("tag64_cross_erase_reads", 0)
                ) + 1
                return page, int(read_phys), int(read_pp)

    nand_pp = _nand_ppage_for_virt_read(
        int(requested_ppage),
        spare64,
        slot_flags=int(slot_flags),
        pages_per_erase=int(pages_per_erase),
    )
    page = _verify_read_phy_page(
        prefix,
        flat_oob,
        geo,
        phys=int(phys),
        ppage=int(nand_pp),
        pages_per_erase=pages_per_erase,
        stats=stats,
        expected_vblk=int(vblk),
        accept_page=accept_page,
    )
    if page is None:
        return None
    return page, int(phys), int(nand_pp)


#endregion


_NTL_STATS_COUNTER_KEYS = (
    "spare_xsum_failures",
    "page_map_hits",
    "ecc_corrections",
    "ecc_failures",
    "tag64_ecc_spare_fixes",
    "tag64_cross_erase_reads",
    "chain_walk_calls",
    "page_map_builds",
)


def _resolve_parallel_vblk_workers(requested: int | None, n_vblks: int) -> int:
    """Return thread-pool size; default serial (``0``) unless ``requested`` or env set."""
    if n_vblks <= 1:
        return 0
    if requested == 0:
        return 0
    env = os.environ.get("OPENTL_NTL_PARALLEL_VBLK", "").strip()
    if requested is None:
        if not env:
            return 0
        if env == "0":
            return 0
        try:
            requested = int(env)
        except ValueError:
            requested = min(8, os.cpu_count() or 4)
    if requested and int(requested) > 0:
        return min(int(requested), n_vblks, 8)
    return 0


def _merge_ntl_worker_stats(dst: dict[str, Any], src: dict[str, Any]) -> None:
    for key in _NTL_STATS_COUNTER_KEYS:
        if key in src:
            dst[key] = int(dst.get(key, 0)) + int(src[key])
    for nested in ("_page_phys_base", "_chain_len", "_chain_slots"):
        part = src.get(nested)
        if isinstance(part, dict):
            bucket = dst.setdefault(nested, {})
            bucket.update(part)


def _merge_page_map_cache(dst: PageMapCache, src: PageMapCache) -> None:
    for vb, pmap in src._maps.items():
        if dst.get(vb) is None:
            dst.put(pmap)


def _prefetch_vblk_pages(
    *,
    logical_prefix: bytes,
    flat_oob: bytes,
    m: BlockMapBuild,
    needed: dict[int, set[int]],
    stats: dict[str, Any],
    pages_per_erase: int,
    page_map_cache: PageMapCache,
    accept_page: Callable[[int, int, bytes, bytes], bool] | None,
    parallel_vblk_workers: int | None,
) -> None:
    """Load all ``needed`` virt blocks before the byte copy loop (optional thread pool)."""
    vblk_store = stats.get("_vblk_pages")
    if not isinstance(vblk_store, dict):
        vblk_store = {}
        stats["_vblk_pages"] = vblk_store
    pending = [(vb, ppages) for vb, ppages in needed.items() if vb not in vblk_store]
    if not pending:
        return
    workers = _resolve_parallel_vblk_workers(parallel_vblk_workers, len(pending))
    if workers <= 1:
        for vb, ppages in pending:
            _ensure_vblk_pages(
                logical_prefix,
                flat_oob,
                m,
                vblk=vb,
                needed_ppages=ppages,
                stats=stats,
                pages_per_erase=pages_per_erase,
                page_map_cache=page_map_cache,
                accept_page=accept_page,
            )
        return

    head_cache = stats.get("_chain_head")
    read_source = stats.get("_read_source")

    def _work(item: tuple[int, set[int]]) -> tuple[int, dict[int, bytes | None], dict[str, Any], PageMapCache]:
        vb, ppages = item
        worker_stats: dict[str, Any] = {
            "_read_source": read_source,
            "_chain_head": head_cache,
            "_chain_len": {},
            "_chain_slots": {},
        }
        worker_cache = PageMapCache()
        pages = _load_vblk_pages(
            logical_prefix,
            flat_oob,
            m,
            vblk=vb,
            needed_ppages=ppages,
            stats=worker_stats,
            pages_per_erase=pages_per_erase,
            page_map_cache=worker_cache,
            accept_page=accept_page,
        )
        return vb, pages, worker_stats, worker_cache

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for vb, pages, worker_stats, worker_cache in pool.map(_work, pending):
            vblk_store[vb] = pages
            _merge_ntl_worker_stats(stats, worker_stats)
            _merge_page_map_cache(page_map_cache, worker_cache)


#region kernel: 0x80288bd4
def _load_vblk_pages(
    prefix: bytes,
    flat_oob: bytes,
    m: BlockMapBuild,
    *,
    vblk: int,
    needed_ppages: set[int],
    stats: dict[str, Any],
    pages_per_erase: int,
    page_map_cache: PageMapCache,
    accept_page: Callable[[int, int, bytes, bytes], bool] | None = None,
) -> dict[int, bytes | None]:
    """Load all ``needed_ppages`` for ``vblk`` once (amortized chain walk)."""
    geo = m.geometry
    pages: dict[int, bytes | None] = {p: None for p in needed_ppages}
    head_cache = stats.get("_chain_head")
    if not isinstance(head_cache, dict):
        head_cache = {}
    if vblk < len(m.virt_to_phys_block) and is_hole_phys_block(int(m.virt_to_phys_block[vblk])):
        return _hole_pages(needed_ppages)

    head = _chain_head_for_vblk(flat_oob, m, vblk, head_cache=head_cache)
    if head is None:
        return _hole_pages(needed_ppages)

    slots, chain_len = _chain_slots_for_vblk(stats, flat_oob, m, geo, vblk=vblk, head=head)
    flags_by_phys = {int(s.phys): int(s.flags) & 0xFF for s in slots}

    use_page_map = _use_page_map_for_chain(slots, chain_len)
    if use_page_map:
        pmap = _lookup_or_build_counted(
            page_map_cache,
            stats,
            flat_oob,
            geo,
            vblk=vblk,
            head_phys=int(head),
            chain_slots=slots,
            chain_length=chain_len,
            pages_per_erase=pages_per_erase,
        )
        for ppage in list(needed_ppages):
            hit = lookup_page_map(pmap, ppage)
            if hit is None:
                continue
            phys, map_ppage = hit
            spare64 = oob_page_spare(flat_oob, geo, int(phys), int(map_ppage))
            if not _find_phy_spare_matches(
                spare64,
                vblk=vblk,
                requested_ppage=ppage,
                slot_flags=flags_by_phys.get(int(phys), 0),
            ):
                continue
            read_hit = _read_ppage_after_find_phy(
                prefix,
                flat_oob,
                geo,
                m,
                vblk=int(vblk),
                requested_ppage=int(ppage),
                phys=int(phys),
                spare64=spare64,
                slot_flags=flags_by_phys.get(int(phys), 0),
                pages_per_erase=pages_per_erase,
                stats=stats,
                accept_page=accept_page,
            )
            if read_hit is not None:
                page, rec_phys, nand_pp = read_hit
                pages[ppage] = page
                _record_page_phys_base(
                    stats,
                    vblk=vblk,
                    ppage=ppage,
                    phys=int(rec_phys),
                    nand_ppage=int(nand_pp),
                    erase=int(geo.erase_bytes),
                )
                stats["page_map_hits"] = int(stats.get("page_map_hits", 0)) + 1

    pending = {ppage for ppage in needed_ppages if pages.get(ppage) is None}
    if pending:
        for ppage in list(pending):
            stats["chain_walk_calls"] = int(stats.get("chain_walk_calls", 0)) + 1
            candidates = iter_ntl_read_page_phy_candidates(
                slots,
                chain_len,
                requested_ppage=ppage,
                pages_per_erase=pages_per_erase,
            )
            for phys, try_ppage in candidates:
                spare64 = oob_page_spare(flat_oob, geo, int(phys), int(try_ppage))
                if not _find_phy_spare_matches(
                    spare64,
                    vblk=vblk,
                    requested_ppage=ppage,
                    slot_flags=flags_by_phys.get(int(phys), 0),
                ):
                    continue
                read_hit = _read_ppage_after_find_phy(
                    prefix,
                    flat_oob,
                    geo,
                    m,
                    vblk=int(vblk),
                    requested_ppage=int(ppage),
                    phys=int(phys),
                    spare64=spare64,
                    slot_flags=flags_by_phys.get(int(phys), 0),
                    pages_per_erase=pages_per_erase,
                    stats=stats,
                    accept_page=accept_page,
                )
                if read_hit is not None:
                    page, rec_phys, nand_pp = read_hit
                    pages[ppage] = page
                    _record_page_phys_base(
                        stats,
                        vblk=vblk,
                        ppage=ppage,
                        phys=int(rec_phys),
                        nand_ppage=int(nand_pp),
                        erase=int(geo.erase_bytes),
                    )
                    break
            if pages.get(ppage) is None:
                pages[ppage] = _HOLE_PAGE

    return pages


def _ensure_vblk_pages(
    prefix: bytes,
    flat_oob: bytes,
    m: BlockMapBuild,
    *,
    vblk: int,
    needed_ppages: set[int],
    stats: dict[str, Any],
    pages_per_erase: int,
    page_map_cache: PageMapCache,
    accept_page: Callable[[int, int, bytes, bytes], bool] | None = None,
) -> dict[int, bytes | None]:
    vblk_store = stats.get("_vblk_pages")
    if not isinstance(vblk_store, dict):
        vblk_store = {}
        stats["_vblk_pages"] = vblk_store
    if vblk in vblk_store:
        return vblk_store[vblk]
    pages = _load_vblk_pages(
        prefix,
        flat_oob,
        m,
        vblk=vblk,
        needed_ppages=needed_ppages,
        stats=stats,
        pages_per_erase=pages_per_erase,
        page_map_cache=page_map_cache,
        accept_page=accept_page,
    )
    vblk_store[vblk] = pages
    return pages


def _read_virt_page_cached(
    prefix: bytes,
    flat_oob: bytes,
    m: BlockMapBuild,
    *,
    vblk: int,
    ppage: int,
    needed: dict[int, set[int]],
    stats: dict[str, Any],
    pages_per_erase: int,
    page_map_cache: PageMapCache,
    accept_page: Callable[[int, int, bytes, bytes], bool] | None = None,
) -> bytes | None:
    if vblk >= len(m.virt_to_phys_block):
        return None
    ppages = needed.get(vblk, {ppage})
    if ppage not in ppages:
        ppages = set(ppages)
        ppages.add(ppage)
    pages = _ensure_vblk_pages(
        prefix,
        flat_oob,
        m,
        vblk=vblk,
        needed_ppages=ppages,
        stats=stats,
        pages_per_erase=pages_per_erase,
        page_map_cache=page_map_cache,
        accept_page=accept_page,
    )
    return pages.get(ppage)


def _page_phys_base(stats: dict[str, Any], vblk: int, ppage: int) -> int | None:
    bases = stats.get("_page_phys_base")
    if not isinstance(bases, dict):
        return None
    base = bases.get((int(vblk), int(ppage)))
    return int(base) if isinstance(base, int) else None


#region kernel_adjacent extract_virt_byte_range_ntl_rw
def extract_virt_byte_range_ntl_rw(
    logical_prefix: bytes,
    block_map: BlockMapBuild,
    flat_oob: bytes,
    *,
    virt_byte_start: int,
    virt_byte_length: int,
    hole_fill_byte: int = 0,
    max_bytes: int | None = None,
    accept_page: Callable[[int, int, bytes, bytes], bool] | None = None,
    stats: dict[str, Any] | None = None,
    read_source: ReadSource = DEFAULT_READ_SOURCE,
    parallel_vblk_workers: int | None = None,
) -> tuple[bytes, int | None, int | None]:
    """
    Copy a virt byte range using :func:`_read_virt_page_cached` (``ntl_read_page`` semantics).

    Shared by :func:`assemble_ntl_rw_slice` and
    :func:`opentl.open_tl.extract_virtual_disk_bytes_chain_aware`.
    """
    m = block_map
    if not spare_blob_matches_geo(flat_oob, m.geometry):
        raise ValueError(
            f"flat_oob length {len(flat_oob)} does not match geometry raw_blocks={m.geometry.raw_blocks}"
        )

    local_stats: dict[str, Any] = stats if stats is not None else {}
    local_stats["_read_source"] = read_source
    page_map_cache = PageMapCache()
    pages_per_erase = _pages_per_erase(m)
    local_stats.setdefault("_chain_head", build_chain_head_cache(flat_oob, m))
    local_stats.setdefault("_chain_len", {})

    erase = int(m.geometry.erase_bytes)
    virt_start = int(virt_byte_start)
    virt_len = int(virt_byte_length)
    if max_bytes is not None:
        virt_len = min(virt_len, max(0, int(max_bytes)))
    virt_disk_bytes = int(m.geometry.virt_blocks) * erase
    if virt_start + virt_len > virt_disk_bytes:
        raise ValueError(
            f"slice past virtual disk end: {virt_start + virt_len} > {virt_disk_bytes}"
        )

    virt_end = virt_start + virt_len
    needed = _needed_vblk_pages(virt_start, virt_end, erase)
    _prefetch_vblk_pages(
        logical_prefix=logical_prefix,
        flat_oob=flat_oob,
        m=m,
        needed=needed,
        stats=local_stats,
        pages_per_erase=pages_per_erase,
        page_map_cache=page_map_cache,
        accept_page=accept_page,
        parallel_vblk_workers=parallel_vblk_workers,
    )
    out = bytearray(virt_len)
    fill = hole_fill_byte & 0xFF
    first_phys: int | None = None
    last_phys: int | None = None

    pos = 0
    gvirt = virt_start
    cur_vb = -1
    cur_ppage = -1
    cur_page: bytes | None = None
    while gvirt < virt_end and pos < virt_len:
        vb = gvirt // erase
        vo = gvirt % erase
        ppage = vo // KERNEL_NAND_PAGE_BYTES
        off_in_page = vo % KERNEL_NAND_PAGE_BYTES
        chunk = min(KERNEL_NAND_PAGE_BYTES - off_in_page, virt_end - gvirt, virt_len - pos)

        if vb != cur_vb or ppage != cur_ppage:
            cur_vb = vb
            cur_ppage = ppage
            cur_page = _read_virt_page_cached(
                logical_prefix,
                flat_oob,
                m,
                vblk=vb,
                ppage=ppage,
                needed=needed,
                stats=local_stats,
                pages_per_erase=pages_per_erase,
                page_map_cache=page_map_cache,
                accept_page=accept_page,
            )
            if cur_page is None:
                cur_page = _HOLE_PAGE

        page = cur_page

        phys_base = _page_phys_base(local_stats, vb, ppage)
        if phys_base is not None:
            used = phys_base + off_in_page
            if first_phys is None:
                first_phys = used
            last_phys = used + chunk - 1

        if page is _HOLE_PAGE or page is None:
            for i in range(chunk):
                out[pos + i] = fill
        else:
            out[pos : pos + chunk] = page[off_in_page : off_in_page + chunk]

        pos += chunk
        gvirt += chunk

    if stats is not None:
        stats.update(local_stats)

    return bytes(out), first_phys, last_phys


#endregion


#region kernel_adjacent assemble_ntl_rw_slice
def assemble_ntl_rw_slice(
    *,
    logical_prefix: bytes,
    block_map: BlockMapBuild,
    flat_oob: bytes,
    virt_byte_start: int,
    virt_byte_length: int,
    slice_name: str = "opentla4",
    max_assemble_bytes: int | None = None,
    read_source: ReadSource = DEFAULT_READ_SOURCE,
    collect_page_histogram: bool = False,
    parallel_vblk_workers: int | None = None,
) -> AssembledNTLResult | None:
    """
    Assemble a TL rw slice using NTL mode-2 chain replay (``ntl_read_page`` semantics).

    ``virt_byte_start`` / ``virt_byte_length`` are **global** offsets within the TL virt
    stream (same as disklabel slice ``offset_bytes`` / ``length_bytes``).

    ``max_assemble_bytes``: cap how many slice bytes to read (kernel reads on demand; use for
    smoke / superblock probes). ``None`` = full ``virt_byte_length``.

    ``collect_page_histogram``: when ``False`` (default), skip the full-chip page-0 spare scan
    used only for assembly telemetry.

    ``parallel_vblk_workers``: thread-pool size for bulk vblk page prefetch before the copy
    loop; ``None`` / ``0`` = serial (default). Set ``OPENTL_NTL_PARALLEL_VBLK=8`` or pass an
    explicit worker count to experiment (CPU-bound ECC under CPython may not speed up on all hosts).
    """
    m = block_map
    if not spare_blob_matches_geo(flat_oob, m.geometry):
        return None

    stats: dict[str, Any] = {"_read_source": read_source}
    head_cache = build_chain_head_cache(flat_oob, m)
    if collect_page_histogram:
        deleted, hist = _histogram_page0_spare(flat_oob, m, head_cache=head_cache)
    else:
        deleted, hist = 0, {}
    stats["_chain_head"] = head_cache
    stats["_chain_len"] = {}

    erase = int(m.geometry.erase_bytes)
    virt_start = int(virt_byte_start)
    virt_len = int(virt_byte_length)
    if max_assemble_bytes is not None:
        cap = max(0, int(max_assemble_bytes))
        virt_len = min(virt_len, cap)

    out, _, _ = extract_virt_byte_range_ntl_rw(
        logical_prefix,
        m,
        flat_oob,
        virt_byte_start=virt_start,
        virt_byte_length=virt_len,
        stats=stats,
        read_source=read_source,
        parallel_vblk_workers=parallel_vblk_workers,
    )

    vblk_seen: set[int] = set()
    g_end = virt_start + virt_len
    gvirt = virt_start
    while gvirt < g_end:
        vblk_seen.add(gvirt // erase)
        vo = gvirt % erase
        gvirt += min(
            KERNEL_NAND_PAGE_BYTES - (vo % KERNEL_NAND_PAGE_BYTES),
            g_end - gvirt,
        )

    chain_lengths = stats.get("_chain_len")
    if not isinstance(chain_lengths, dict):
        chain_lengths = {}

    return AssembledNTLResult(
        data=bytes(out),
        slice_name=slice_name,
        pblk_count=int(m.geometry.raw_blocks),
        vblk_count=len(vblk_seen),
        chain_lengths={int(k): int(v) for k, v in chain_lengths.items()},
        deleted_pblks=deleted,
        spare_xsum_failures=int(stats.get("spare_xsum_failures", 0)),
        unresolved_vpages=0,
        page_map_hits=int(stats.get("page_map_hits", 0)),
        ecc_corrections=int(stats.get("ecc_corrections", 0)),
        ecc_failures=int(stats.get("ecc_failures", 0)),
        tag64_ecc_spare_fixes=int(stats.get("tag64_ecc_spare_fixes", 0)),
        tag64_cross_erase_reads=int(stats.get("tag64_cross_erase_reads", 0)),
        chain_walk_calls=int(stats.get("chain_walk_calls", 0)),
        page_map_builds=int(stats.get("page_map_builds", 0)),
        page_state_histogram=hist,
    )


#endregion


#region kernel_adjacent ntl_assembly_to_jsonable
def ntl_assembly_to_jsonable(result: AssembledNTLResult) -> dict[str, Any]:
    return {
        "slice": result.slice_name,
        "slice_len_bytes": len(result.data),
        "assembled_bytes": len(result.data),
        "pblk_count": result.pblk_count,
        "vblk_count": result.vblk_count,
        "chain_lengths": {str(k): v for k, v in sorted(result.chain_lengths.items())},
        "deleted_pblks": result.deleted_pblks,
        "spare_xsum_failures": result.spare_xsum_failures,
        "unresolved_vpages": result.unresolved_vpages,
        "page_map_hits": result.page_map_hits,
        "ecc_corrections": result.ecc_corrections,
        "ecc_failures": result.ecc_failures,
        "tag64_ecc_spare_fixes": result.tag64_ecc_spare_fixes,
        "tag64_cross_erase_reads": result.tag64_cross_erase_reads,
        "chain_walk_calls": result.chain_walk_calls,
        "page_map_builds": result.page_map_builds,
        "page_state_histogram": result.page_state_histogram,
        "notes": result.notes,
        "warnings": result.warnings,
    }


#endregion
