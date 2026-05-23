"""
8-byte OpenTL virt erase-slot metadata (kernel ``*(remap+8) + vblk*8``).

Decompile ``ntl_put_chain_in_array`` @ ``0x802888f8``: byte at **+5** is chain hop count;
byte at **+5** == ``0`` means unmapped (``ntl_read_page`` hole). Offline we infer chain
length from spare replay when RAM table bytes are not captured.
"""

from __future__ import annotations

from dataclasses import dataclass

from opentl.spare_chain_replay import replay_put_chain_mode2_from_oob
from opentl.tl_bbm import BlockMapBuild, TL_PHYS_BLOCK_HOLE, is_hole_phys_block

_MAX_CHAIN_HOPS = 0x46


@dataclass(frozen=True)
class VirtSlot:
    """One ``*(remap+8)`` entry (8 bytes, only phys u32 required for linear reads)."""

    phys: int
    chain_length: int
    populated: bool


def infer_virt_chain_length(
    flat_oob: bytes,
    m: BlockMapBuild,
    vblk: int,
    *,
    max_hops: int = _MAX_CHAIN_HOPS,
) -> int:
    """
    Infer ``virt_entry+5`` chain length by replaying mode-2 spare hops from the BBM head phys.

    Returns ``0`` for holes / unmapped slots.
    """
    if vblk < 0 or vblk >= len(m.virt_to_phys_block):
        return 0
    head = int(m.virt_to_phys_block[vblk])
    if is_hole_phys_block(head) or head < 0 or head >= m.geometry.raw_blocks:
        return 0
    hops, _ = replay_put_chain_mode2_from_oob(
        flat_oob,
        m.geometry,
        start_phys=head,
        chain_length=max_hops,
        page_size_is_0x200=False,
    )
    return max(1, min(len(hops), max_hops)) if hops else 1


def build_virt_slots(
    flat_oob: bytes,
    m: BlockMapBuild,
    *,
    max_hops: int = _MAX_CHAIN_HOPS,
) -> tuple[VirtSlot, ...]:
    """Build per-vblk :class:`VirtSlot` rows (chain length inferred from spare)."""
    out: list[VirtSlot] = []
    for vblk in range(m.geometry.virt_blocks):
        phys = int(m.virt_to_phys_block[vblk])
        if is_hole_phys_block(phys):
            out.append(VirtSlot(phys=TL_PHYS_BLOCK_HOLE, chain_length=0, populated=False))
            continue
        clen = infer_virt_chain_length(flat_oob, m, vblk, max_hops=max_hops)
        out.append(VirtSlot(phys=phys, chain_length=clen, populated=True))
    return tuple(out)


def chain_length_for_vblk(
    flat_oob: bytes,
    m: BlockMapBuild,
    vblk: int,
    *,
    cache: dict[int, int] | None = None,
    max_hops: int = _MAX_CHAIN_HOPS,
) -> int:
    """Cached wrapper used by :mod:`opentl.ntl_rw`."""
    if cache is not None and vblk in cache:
        return cache[vblk]
    n = infer_virt_chain_length(flat_oob, m, vblk, max_hops=max_hops)
    if cache is not None:
        cache[vblk] = n
    return n
