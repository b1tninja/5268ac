"""
Offline replay of ``ntl_put_chain_in_array`` **mode 2** (*piVar10 == 2) chain hops, plus
:func:`iter_mode2_phys_chain_from_oob` to list **ordered physical candidates** along spare
``next`` links (see ``reference/ghidra_boardfs_bbm_readpath.md``).

Decompilation source: ``FUN_802888f8`` in
``att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_36645b10_kernel_load_80010000_ep_80458130.bin.c``
(address ``0x802888f8``, symbol ``ntl_put_chain_in_array``).

The kernel reads spare via ``FUN_80288750`` (``ntl_read_verify_phy_spare``) for each
physical erase unit on the chain, then parses **next physical unit** from the same
byte lanes ``ntl_prepare_wspare`` uses for **current** phys — **not** from the
virt id fields at ``spare[11:13]``.

``ntl_verify_chain_seqnum`` walks **RAM** ``rev_tab`` rows only (mount audit); it is
implemented separately as :func:`audit_rev_tab_chain_seqnum`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from unand.geometry import PACE_DEFAULT

from opentl.tl_bbm import TLGeometry, TL_VIRT_BLOCKS_DEFAULT, is_hole_phys_block


def oob_page_spare(oob: bytes, geo: TLGeometry, phys_block: int, page: int) -> bytes:
    """Return 64-byte spare for ``phys_block`` / ``page`` within a flat per-block spare slice."""
    if not (0 <= phys_block < geo.raw_blocks and 0 <= page < 64):
        raise IndexError("phys_block or page out of range")
    stride = 64 * PACE_DEFAULT.page_spare
    off = phys_block * stride + page * PACE_DEFAULT.page_spare
    return oob[off : off + PACE_DEFAULT.page_spare]


def tl_geometry_from_flat_spare(blob: bytes, *, pages_per_erase: int = 64) -> TLGeometry:
    """
    Derive **raw_blocks** from concatenated spare length (**64 pages × raw_blocks × 64 B**).

    For **production-sized** partitions (``raw_blocks > TL_VIRT_BLOCKS_DEFAULT``), set
    ``virt_blocks = raw_blocks - bb_reserved`` using default :class:`~opentl.tl_bbm.TLGeometry`
    ``bb_reserved`` (factory spare band). Smaller blobs (tests / toy maps) keep
    ``virt_blocks = min(raw_blocks, TL_VIRT_BLOCKS_DEFAULT)``.
    """
    if len(blob) % PACE_DEFAULT.page_spare:
        raise ValueError(f"spare length {len(blob)} not multiple of {PACE_DEFAULT.page_spare}")
    n_pages = len(blob) // PACE_DEFAULT.page_spare
    if n_pages % pages_per_erase:
        raise ValueError(
            f"spare page count {n_pages} not a multiple of pages_per_erase={pages_per_erase}"
        )
    rb = n_pages // pages_per_erase
    bb_r = TLGeometry().bb_reserved
    if rb > TL_VIRT_BLOCKS_DEFAULT:
        vb = max(0, rb - bb_r)
        return TLGeometry(raw_blocks=rb, virt_blocks=vb, bb_reserved=bb_r)
    vb = min(rb, TL_VIRT_BLOCKS_DEFAULT)
    return TLGeometry(raw_blocks=rb, virt_blocks=vb)


def spare_blob_matches_geo(blob: bytes, geo: TLGeometry, *, pages_per_erase: int = 64) -> bool:
    expected = geo.raw_blocks * pages_per_erase * PACE_DEFAULT.page_spare
    return len(blob) == expected


#region kernel: 0x802888f8
# ntl_put_chain_in_array — mode 2 spare chain step (MCP user-ghidra decompile_function @ 0x802888f8)
def next_phys_from_spare_chain_step(
    spare64: bytes,
    *,
    page_size_is_0x200: bool,
) -> tuple[int | None, int]:
    """
    Parse link target after ``ntl_read_verify_phy_spare`` (same layout as in ``FUN_802888f8``).

    Returns ``(next_phys, flags_u16)`` where ``flags_u16`` is ``spare[8] & 4`` (mirror bit).

    * **Small-page branch** (``*(ctx+0x10)==0x200``): next is LE16 @ bytes **9–10**;
      ``0xffff`` → ``None`` (terminator ``0xffffffff``).
    * **Large-page branch** (5268 NAND page **2048**): extends with bytes **16** and **17**
      as ``lo | (sp[16]<<16) | (sp[17]<<24)`` matching the decompiler expression (not the same
      as :meth:`opentl.spare_layout.SpareRecord.phys_u32`, which packs **<H** @ 16).
    """
    if len(spare64) != 64:
        raise ValueError("spare must be 64 bytes")
    sp = spare64
    flags_byte = sp[8]
    flags_u16 = flags_byte & 4
    lo = sp[9] | (sp[10] << 8)
    if page_size_is_0x200:
        if lo == 0xFFFF:
            return None, flags_u16
        return lo, flags_u16
    u32 = lo | (sp[16] << 16) | (sp[17] << 24)
    if u32 == 0xFFFFFFFF:
        return None, flags_u16
    return u32, flags_u16


@dataclass(frozen=True)
class ChainHop:
    """One ``(phys, spare_flags_bit4, next_phys)`` step."""

    phys: int
    spare_mirror_flag: int  # 0 or 4
    next_phys: int | None


def replay_put_chain_mode2_from_oob(
    oob: bytes,
    geo: TLGeometry,
    *,
    start_phys: int,
    chain_length: int,
    page_size_is_0x200: bool,
    page_in_block: int = 0,
    phys_hi_exclusive: int | None = None,
) -> tuple[list[ChainHop], list[str]]:
    """
    Simulate ``FUN_802888f8`` outer loop for ``*remap==2``: walk **chain_length** hops
    starting at ``start_phys``, reading **page_in_block** spare slice per phys.

    ``phys_hi_exclusive``: upper bound check uses ``piVar10[5]`` in-kernel; default
    ``geo.raw_blocks``.
    """
    notes: list[str] = []
    hi = phys_hi_exclusive if phys_hi_exclusive is not None else geo.raw_blocks
    out: list[ChainHop] = []
    cur: int | None = start_phys
    if chain_length == 0:
        return [], notes

    for _step in range(chain_length):
        if cur is None:
            notes.append("early terminator before chain_length reached")
            break
        if cur == 0xFFFFFFFF:
            notes.append("phys sentinel 0xffffffff mid-chain")
            break
        if not (0 <= cur < hi):
            notes.append(f"phys {cur} out of bounds (hi={hi})")
            break
        sp = oob_page_spare(oob, geo, cur, page_in_block)
        nxt, fl = next_phys_from_spare_chain_step(sp, page_size_is_0x200=page_size_is_0x200)
        out.append(ChainHop(phys=cur, spare_mirror_flag=fl, next_phys=nxt))
        cur = nxt

    return out, notes


#endregion


#region kernel_adjacent spare_chain_replay_pages_per_tl_erase
# Host: pages-per-erase from TLGeometry vs PACE page_data; must stay consistent with oob_page_spare's page bound.
def _pages_per_tl_erase(geo: TLGeometry) -> int:
    """Pages per TL erase unit (must match :func:`oob_page_spare` ``page`` bound)."""
    n = geo.erase_bytes // PACE_DEFAULT.page_data
    if n < 1:
        raise ValueError("TLGeometry.erase_bytes too small for page_data")
    return int(n)


#endregion


#region kernel: 0x802888f8
# ntl_put_chain_in_array — mode-2 spare walk enumerating phys candidates (same EA as next_phys parser)
def iter_mode2_phys_chain_from_oob(
    oob: bytes,
    geo: TLGeometry,
    *,
    start_phys: int,
    page_size_is_0x200: bool,
    spare_page: int = 0,
    max_hops: int = 0x46,
) -> list[int]:
    """
    Ordered physical erase units along a **mode-2** spare chain (``ntl_put_chain_in_array`` hop
    semantics via :func:`next_phys_from_spare_chain_step`).

    Walks from ``start_phys``, reading **64-byte** spare for ``(phys, spare_page)`` at each hop
    until the spare terminator (**``None``**) or ``max_hops`` or a **cycle** (revisited phys).
    See ``reference/ghidra_boardfs_bbm_readpath.md`` (``ntl_read_page`` verify loop).

    **Kernel:** ``ntl_put_chain_in_array`` calls ``ntl_read_verify_phy_spare(..., page=0)`` for every
  hop when building the chain — not the logical data page index. Pass ``spare_page=0`` (default).

    **Hole** start or ``start_phys`` out of ``[0, raw_blocks)`` returns ``[]``.
    """
    if is_hole_phys_block(start_phys) or start_phys < 0 or start_phys >= geo.raw_blocks:
        return []
    max_page = _pages_per_tl_erase(geo)
    if spare_page < 0 or spare_page >= max_page:
        raise ValueError(f"spare_page {spare_page} out of range for geometry (max {max_page})")

    out: list[int] = []
    cur: int | None = start_phys
    seen: set[int] = set()
    hops = 0
    while cur is not None and hops < max_hops:
        if cur in seen:
            break
        if cur < 0 or cur >= geo.raw_blocks:
            break
        seen.add(cur)
        out.append(cur)
        sp = oob_page_spare(oob, geo, cur, spare_page)
        nxt, _ = next_phys_from_spare_chain_step(sp, page_size_is_0x200=page_size_is_0x200)
        cur = nxt
        hops += 1
    return out


#endregion


#region kernel: 0x802888f8
# Mode-2 chain array slots (8 bytes each) for ntl_find_phy / ntl_build_page_map
@dataclass(frozen=True)
class Mode2ChainSlot:
    """One ``ntl_put_chain_in_array`` row: u32 phys @0, u16 flags @4 (spare[8]&4)."""

    phys: int
    flags: int


def build_mode2_chain_slots(
    oob: bytes,
    geo: TLGeometry,
    *,
    start_phys: int,
    chain_length: int,
    page_size_is_0x200: bool = False,
    page_in_block: int = 0,
) -> list[Mode2ChainSlot]:
    """Materialize the kernel chain array filled by ``ntl_put_chain_in_array``."""
    hops, _ = replay_put_chain_mode2_from_oob(
        oob,
        geo,
        start_phys=start_phys,
        chain_length=chain_length,
        page_size_is_0x200=page_size_is_0x200,
        page_in_block=page_in_block,
    )
    return [Mode2ChainSlot(phys=h.phys, flags=h.spare_mirror_flag) for h in hops]


#region kernel: 0x80288210
def ntl_prev_phy_location(
    slots: list[Mode2ChainSlot],
    chain_length: int,
    *,
    requested_ppage: int,
    chain_idx: int,
    phys_out: list[int],
    page_out: list[int],
    pages_per_erase: int,
) -> None:
    """
    ``ntl_prev_phy_location`` @ ``0x80288210`` — advance ``(phys, page)`` along the mode-2 chain.

    ``phys_out`` / ``page_out`` are single-element lists mutated in place (kernel ``param_6``).
    ``chain_idx`` is ``*param_5`` (index into ``slots``).
    """
    if not phys_out or not page_out:
        return
    i = int(chain_idx)
    if i < 0 or i >= chain_length:
        phys_out[0] = 0xFFFFFFFF
        page_out[0] = 0xFFFF
        return
    if i < len(slots) and (slots[i].flags & 4) != 0 and page_out[0] != 0:
        page_out[0] -= 1
        return
    if chain_length - 1 <= i:
        phys_out[0] = 0xFFFFFFFF
        page_out[0] = 0xFFFF
        return
    nxt = i + 1
    if nxt >= len(slots):
        phys_out[0] = 0xFFFFFFFF
        page_out[0] = 0xFFFF
        return
    phys_out[0] = int(slots[nxt].phys)
    if (slots[nxt].flags & 4) == 0:
        page_out[0] = int(requested_ppage)
    else:
        page_out[0] = int(pages_per_erase) - 1


def iter_ntl_read_page_phy_candidates(
    slots: list[Mode2ChainSlot],
    chain_length: int,
    *,
    requested_ppage: int,
    pages_per_erase: int,
    max_search: int | None = None,
) -> list[tuple[int, int]]:
    """
    Ordered ``(phys, ppage)`` tries for one ``ntl_read_page`` (``find_phy`` index loop + ``prev_phy``).

    Mirrors ``ntl_find_phy`` @ ``0x80288bd4`` with ``param_6 != 1`` (single-page read, not scan-all).
    """
    if chain_length < 1 or not slots:
        return []
    cap = max_search if max_search is not None else (chain_length * pages_per_erase + chain_length + 4)
    phys = int(slots[0].phys)
    page = int(requested_ppage)
    chain_idx = 0
    out: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    for _ in range(cap):
        if phys == 0xFFFFFFFF:
            break
        key = (phys, page)
        if key not in seen:
            seen.add(key)
            out.append(key)
        p_state = [phys]
        pg_state = [page]
        ntl_prev_phy_location(
            slots,
            chain_length,
            requested_ppage=requested_ppage,
            chain_idx=chain_idx,
            phys_out=p_state,
            page_out=pg_state,
            pages_per_erase=pages_per_erase,
        )
        phys = int(p_state[0])
        page = int(pg_state[0])
        if phys == 0xFFFFFFFF:
            break
        chain_idx += 1
        if chain_idx < len(slots) and int(slots[chain_idx].phys) != phys:
            for j, s in enumerate(slots):
                if int(s.phys) == phys:
                    chain_idx = j
                    break
    return out


#endregion


def chain_page_map_fast_path(slots: list[Mode2ChainSlot], chain_length: int) -> bool:
    """
    ``ntl_find_phy`` @ ``0x80288bd4`` fresh-search gate before ``ntl_lookup_page_map``.

    Decompiler: ``*(char *)(chain_array + 5) == 4`` on the first 8-byte chain slot. On **MIPS BE**
    the mirror ushort ``(spare[8] & 4)`` stored at slot **+4** appears as byte **+5** == ``0x04``.
    """
    if chain_length < 1 or not slots:
        return False
    return (int(slots[0].flags) & 0xFF) == 4 or (int(slots[0].flags) >> 8) & 0xFF == 4 or any(
        s.flags == 4 for s in slots
    )


#endregion


_MAX_SEQ_CHAIN = 0x45


#region kernel: 0x80289a30
# ntl_verify_chain_seqnum — RAM rev_tab audit
def audit_rev_tab_chain_seqnum(
    rows: Sequence[tuple[int, int, int]],
    head_idx: int,
    *,
    debug_printk_gt_zero: bool = True,
) -> tuple[bool, str]:
    """
    Approximate ``ntl_verify_chain_seqnum`` (``0x80289a30``) on **RAM** rows.

    Each row: ``(next_idx, seq_byte, flags_byte)`` for the **16-byte** record indexed by
    slot (kernel walks ``next = row[0]`` until ``-1``, compares ``row[12]`` to head seq).

    The kernel ORs ``flags_byte`` at offset **0xd** with **0x10** during the walk; this
    helper does not mutate rows — it only validates seq equality and hop count **≤ 0x45**.

    ``head_idx``: starting row index ``param_4`` (must not be ``-1``).

    Returns ``(ok, reason)``.
    """
    if head_idx == -1:
        return False, "head_idx is -1"
    if not (0 <= head_idx < len(rows)):
        return False, "head_idx out of rows range"
    head_next, head_seq, _hf = rows[head_idx]
    _ = head_next  # first hop starts from row content — kernel reads seq from head row byte 0xc
    u_var6 = head_seq
    i_var3 = head_idx
    hops = 0
    visited: set[int] = set()
    while True:
        if i_var3 in visited:
            return False, f"cycle detected at idx {i_var3}"
        visited.add(i_var3)
        if i_var3 < 0 or i_var3 >= len(rows):
            return False, f"idx {i_var3} out of range"
        next_i, seq_b, _fb = rows[i_var3]
        hops += 1
        if hops > _MAX_SEQ_CHAIN:
            msg = "chain_length_over_max"
            if debug_printk_gt_zero:
                return False, msg
            return False, "Hard_hart"
        if seq_b != u_var6:
            if debug_printk_gt_zero:
                return False, f"mismatch_seq_in_chain hop={hops} idx={i_var3} seq={seq_b}!={u_var6}"
            return False, "Hard_hart"
        if next_i == -1 or next_i == 0xFFFFFFFF:
            break
        i_var3 = next_i & 0xFFFFFFFF
    return True, f"ok hops={hops}"


#endregion
