"""
Derived **virtual NAND page → linear-plane offset** cache (host-only).

Kernel **ntl_read_page** @ ``0x80289170`` indexes **8-byte virt erase slots** at
``*(remap+8) + virt_block×8`` (see ``reference/ghidra_boardfs_bbm_readpath.md``). It does **not**
keep a full per–2048-byte-page RAM table. This module **precomputes** those page bases from
:class:`~opentl.tl_bbm.BlockMapBuild` (primary ``virt_to_phys_block`` per erase block) so offline
tools can ``memcpy`` / hole-``memset`` without a per-byte loop.
"""

from __future__ import annotations

from array import array
from dataclasses import dataclass, field
from typing import Callable, Optional, Union

from opentl.open_tl import KERNEL_NAND_PAGE_BYTES
from opentl.spare_chain_replay import (
    iter_mode2_phys_chain_from_oob,
    oob_page_spare,
    spare_blob_matches_geo,
)
from opentl.tl_bbm import BlockMapBuild, is_hole_phys_block

# Sentinel in phys_page_base[]: hole (kernel memset path analogue).
PHYS_PAGE_BASE_HOLE = -1


@dataclass(frozen=True, slots=True)
class VirtNandPageTable:
    """
    For each global virtual **2048-byte** NAND page index ``p``, ``phys_page_base[p]`` is the byte
    offset into the linear prefix for page ``p``, or :data:`PHYS_PAGE_BASE_HOLE`.
    """

    phys_page_base: tuple[int, ...]
    num_pages: int
    logical_prefix_len: int
    erase_bytes: int
    virt_blocks: int
    #: ``"primary"`` (from ``virt_to_phys_block`` only) or ``"chain_aware"`` (spare chain per page).
    mode: str = "primary"

    def phys_base_for_virt_byte(self, virt_byte: int) -> int:
        """Page-aligned phys base for the NAND page containing ``virt_byte``."""
        if virt_byte < 0:
            raise ValueError("virt_byte must be non-negative")
        page = virt_byte // KERNEL_NAND_PAGE_BYTES
        if page >= self.num_pages:
            raise ValueError(f"virt byte {virt_byte:#x} past table ({self.num_pages} pages)")
        return self.phys_page_base_at(page)

    def phys_page_base_at(self, page_idx: int) -> int:
        """Linear prefix offset for virtual NAND page ``page_idx``."""
        if page_idx < 0 or page_idx >= self.num_pages:
            raise IndexError(f"page_idx {page_idx} out of range [0, {self.num_pages})")
        return self.phys_page_base[page_idx]


def _phys_page_base_at_virt_page_start(
    m: BlockMapBuild,
    *,
    gvirt_page_start: int,
    logical_prefix_len: int,
) -> int:
    """Resolve linear prefix offset for the first byte of virtual NAND page at ``gvirt_page_start``."""
    geo = m.geometry
    erase = int(geo.erase_bytes)
    vb = gvirt_page_start // erase
    vo = gvirt_page_start % erase
    if vb >= len(m.virt_to_phys_block):
        return PHYS_PAGE_BASE_HOLE
    pb = m.virt_to_phys_block[vb]
    if is_hole_phys_block(pb):
        return PHYS_PAGE_BASE_HOLE
    phys_first = pb * erase + vo
    if phys_first < 0 or phys_first + KERNEL_NAND_PAGE_BYTES > logical_prefix_len:
        return PHYS_PAGE_BASE_HOLE
    return phys_first


#region kernel_adjacent build_virt_nand_page_table (derived from *(remap+8) erase-slot semantics)
def build_virt_nand_page_table(
    m: BlockMapBuild,
    *,
    logical_prefix_len: int,
    max_virt_bytes: int | None = None,
) -> VirtNandPageTable:
    """
  Build the page translation cache for the full virtual TL disk.

  ``logical_prefix_len`` must match the prefix passed to extract (same as
  :func:`~opentl.open_tl.virt_span_nand_page_rows`).
    """
    if logical_prefix_len < 0:
        raise ValueError("logical_prefix_len must be >= 0")
    geo = m.geometry
    erase = int(geo.erase_bytes)
    virt_disk_bytes = int(geo.virt_blocks) * erase
    if max_virt_bytes is not None:
        virt_disk_bytes = min(virt_disk_bytes, int(max_virt_bytes))
    if virt_disk_bytes <= 0:
        return VirtNandPageTable(
            phys_page_base=(),
            num_pages=0,
            logical_prefix_len=int(logical_prefix_len),
            erase_bytes=erase,
            virt_blocks=int(geo.virt_blocks),
            mode="primary",
        )
    num_pages = (virt_disk_bytes + KERNEL_NAND_PAGE_BYTES - 1) // KERNEL_NAND_PAGE_BYTES
    bases = array("i")
    for p in range(num_pages):
        gvirt = p * KERNEL_NAND_PAGE_BYTES
        bases.append(
            _phys_page_base_at_virt_page_start(
                m, gvirt_page_start=gvirt, logical_prefix_len=int(logical_prefix_len)
            )
        )
    return VirtNandPageTable(
        phys_page_base=tuple(bases),
        num_pages=num_pages,
        logical_prefix_len=int(logical_prefix_len),
        erase_bytes=erase,
        virt_blocks=int(geo.virt_blocks),
        mode="primary",
    )


#endregion


#region kernel_adjacent build_virt_nand_page_table_chain_aware
# ntl_put_chain_in_array @ 0x802888f8 — per (virt_block, page_in_block) candidate order
def _phys_page_base_chain_aware_at_virt_page_start(
    m: BlockMapBuild,
    logical_prefix: bytes,
    *,
    flat_oob: bytes,
    gvirt_page_start: int,
    page_size_is_0x200: bool,
    verify_page: Callable[[int, int, bytes, bytes], bool] | None,
) -> int:
    """First accepted spare-chain candidate for the 2048 B NAND page at ``gvirt_page_start``."""
    geo = m.geometry
    erase = int(geo.erase_bytes)
    lim = len(logical_prefix)
    vb = gvirt_page_start // erase
    vo = gvirt_page_start % erase
    page_in_block = vo // KERNEL_NAND_PAGE_BYTES
    if vb >= len(m.virt_to_phys_block):
        return PHYS_PAGE_BASE_HOLE
    pb = m.virt_to_phys_block[vb]
    if is_hole_phys_block(pb):
        return PHYS_PAGE_BASE_HOLE

    def default_verify(phys: int, pg_in_blk: int, page_data: bytes, spare64: bytes) -> bool:
        _ = phys, pg_in_blk, spare64
        return len(page_data) == KERNEL_NAND_PAGE_BYTES

    accept = verify_page if verify_page is not None else default_verify

    for phys in iter_mode2_phys_chain_from_oob(
        flat_oob,
        geo,
        start_phys=int(pb),
        page_size_is_0x200=page_size_is_0x200,
    ):
        base = phys * erase + page_in_block * KERNEL_NAND_PAGE_BYTES
        end = base + KERNEL_NAND_PAGE_BYTES
        if base < 0 or end > lim:
            continue
        page_data = logical_prefix[base:end]
        spare64 = oob_page_spare(flat_oob, geo, phys, page_in_block)
        if accept(phys, page_in_block, page_data, spare64):
            return base
    return PHYS_PAGE_BASE_HOLE


def build_virt_nand_page_table_chain_aware(
    m: BlockMapBuild,
    logical_prefix: bytes,
    *,
    flat_oob: bytes,
    page_size_is_0x200: bool = False,
    verify_page: Callable[[int, int, bytes, bytes], bool] | None = None,
) -> VirtNandPageTable:
    """
    Build a page table using mode-2 spare **chain** resolution per virtual NAND page.

    Same acceptance rules as :func:`~opentl.open_tl.extract_virtual_disk_bytes_chain_aware`
    (first in-range candidate that passes ``verify_page``, default: any full page window).
    """
    if not spare_blob_matches_geo(flat_oob, m.geometry):
        raise ValueError(
            f"flat_oob length {len(flat_oob)} does not match geometry raw_blocks={m.geometry.raw_blocks}"
        )
    lim = min(len(logical_prefix), int(m.logical_prefix_bytes))
    geo = m.geometry
    erase = int(geo.erase_bytes)
    virt_disk_bytes = int(geo.virt_blocks) * erase
    if virt_disk_bytes <= 0:
        return VirtNandPageTable(
            phys_page_base=(),
            num_pages=0,
            logical_prefix_len=lim,
            erase_bytes=erase,
            virt_blocks=int(geo.virt_blocks),
            mode="chain_aware",
        )
    num_pages = (virt_disk_bytes + KERNEL_NAND_PAGE_BYTES - 1) // KERNEL_NAND_PAGE_BYTES
    bases = array("i")
    for p in range(num_pages):
        gvirt = p * KERNEL_NAND_PAGE_BYTES
        bases.append(
            _phys_page_base_chain_aware_at_virt_page_start(
                m,
                logical_prefix[:lim],
                flat_oob=flat_oob,
                gvirt_page_start=gvirt,
                page_size_is_0x200=page_size_is_0x200,
                verify_page=verify_page,
            )
        )
    return VirtNandPageTable(
        phys_page_base=tuple(bases),
        num_pages=num_pages,
        logical_prefix_len=lim,
        erase_bytes=erase,
        virt_blocks=int(geo.virt_blocks),
        mode="chain_aware",
    )


@dataclass
class LazyChainAwareVirtNandPageTable:
    """
    On-demand chain-aware page bases (kernel ``ntl_read_page`` / ``ntl_find_phy`` per page).

    Avoids eager ``build_virt_nand_page_table_chain_aware`` over the full virtual disk.
    """

    block_map: BlockMapBuild
    logical_prefix: bytes
    flat_oob: bytes
    logical_prefix_len: int
    num_pages: int
    erase_bytes: int
    virt_blocks: int
    page_size_is_0x200: bool = False
    verify_page: Callable[[int, int, bytes, bytes], bool] | None = None
    mode: str = "chain_aware"
    _cache: dict[int, int] = field(default_factory=dict)

    def phys_page_base_at(self, page_idx: int) -> int:
        if page_idx < 0 or page_idx >= self.num_pages:
            raise IndexError(f"page_idx {page_idx} out of range [0, {self.num_pages})")
        cached = self._cache.get(page_idx)
        if cached is not None:
            return cached
        gvirt = page_idx * KERNEL_NAND_PAGE_BYTES
        lim = min(len(self.logical_prefix), self.logical_prefix_len)
        base = _phys_page_base_chain_aware_at_virt_page_start(
            self.block_map,
            self.logical_prefix[:lim],
            flat_oob=self.flat_oob,
            gvirt_page_start=gvirt,
            page_size_is_0x200=self.page_size_is_0x200,
            verify_page=self.verify_page,
        )
        self._cache[page_idx] = base
        return base

    def phys_base_for_virt_byte(self, virt_byte: int) -> int:
        if virt_byte < 0:
            raise ValueError("virt_byte must be non-negative")
        page = virt_byte // KERNEL_NAND_PAGE_BYTES
        return self.phys_page_base_at(page)


def build_lazy_chain_aware_virt_nand_page_table(
    m: BlockMapBuild,
    logical_prefix: bytes,
    *,
    flat_oob: bytes,
    page_size_is_0x200: bool = False,
    verify_page: Callable[[int, int, bytes, bytes], bool] | None = None,
) -> LazyChainAwareVirtNandPageTable:
    """Lazy chain-aware table (production default for :meth:`~opentl.logical_opentl_session.LogicalOpenTLSession.set_chain_aware_virt_reads`)."""
    if not spare_blob_matches_geo(flat_oob, m.geometry):
        raise ValueError(
            f"flat_oob length {len(flat_oob)} does not match geometry raw_blocks={m.geometry.raw_blocks}"
        )
    lim = min(len(logical_prefix), int(m.logical_prefix_bytes))
    geo = m.geometry
    erase = int(geo.erase_bytes)
    virt_disk_bytes = int(geo.virt_blocks) * erase
    num_pages = (
        (virt_disk_bytes + KERNEL_NAND_PAGE_BYTES - 1) // KERNEL_NAND_PAGE_BYTES
        if virt_disk_bytes > 0
        else 0
    )
    return LazyChainAwareVirtNandPageTable(
        block_map=m,
        logical_prefix=logical_prefix,
        flat_oob=flat_oob,
        logical_prefix_len=lim,
        num_pages=num_pages,
        erase_bytes=erase,
        virt_blocks=int(geo.virt_blocks),
        page_size_is_0x200=page_size_is_0x200,
        verify_page=verify_page,
    )


VirtNandPageTableLike = Union[VirtNandPageTable, LazyChainAwareVirtNandPageTable]


#endregion


#region kernel: 0x80289170
# ntl_read_page — page-granular memcpy / hole memset analogue
def extract_virtual_disk_bytes_via_page_table(
    logical_prefix: bytes,
    table: VirtNandPageTableLike,
    *,
    virt_byte_start: int,
    virt_byte_length: int,
    hole_fill_byte: int = 0,
) -> tuple[bytes, int | None, int | None]:
    """
    Same contract as :func:`~opentl.open_tl.extract_virtual_disk_bytes`, using a prebuilt
    :class:`VirtNandPageTable`.
    """
    if virt_byte_length < 0:
        raise ValueError("virt_byte_length must be >= 0")
    if len(logical_prefix) < table.logical_prefix_len:
        raise ValueError(
            f"logical_prefix length {len(logical_prefix)} < table.logical_prefix_len "
            f"{table.logical_prefix_len}"
        )
    virt_disk_bytes = table.virt_blocks * table.erase_bytes
    if virt_byte_start + virt_byte_length > virt_disk_bytes:
        raise ValueError(
            f"slice past virtual disk end: {virt_byte_start + virt_byte_length} > {virt_disk_bytes}"
        )

    out = bytearray(virt_byte_length)
    first_phys: Optional[int] = None
    last_phys: Optional[int] = None
    fill = hole_fill_byte & 0xFF
    gvirt = int(virt_byte_start)
    end = gvirt + int(virt_byte_length)
    out_pos = 0

    while gvirt < end:
        page_idx = gvirt // KERNEL_NAND_PAGE_BYTES
        off_in_page = gvirt % KERNEL_NAND_PAGE_BYTES
        chunk = min(KERNEL_NAND_PAGE_BYTES - off_in_page, end - gvirt)
        page_base = table.phys_page_base_at(page_idx)

        if page_base == PHYS_PAGE_BASE_HOLE:
            for i in range(chunk):
                out[out_pos + i] = fill
        else:
            phys = page_base + off_in_page
            if phys + chunk > len(logical_prefix):
                raise ValueError(
                    f"physical span [{phys:#x}, {phys + chunk:#x}) out of prefix len {len(logical_prefix)}"
                )
            out[out_pos : out_pos + chunk] = logical_prefix[phys : phys + chunk]
            if first_phys is None:
                first_phys = phys
            last_phys = phys + chunk - 1

        out_pos += chunk
        gvirt += chunk

    return bytes(out), first_phys, last_phys


#endregion


__all__ = [
    "PHYS_PAGE_BASE_HOLE",
    "LazyChainAwareVirtNandPageTable",
    "VirtNandPageTable",
    "VirtNandPageTableLike",
    "build_lazy_chain_aware_virt_nand_page_table",
    "build_virt_nand_page_table",
    "build_virt_nand_page_table_chain_aware",
    "extract_virtual_disk_bytes_via_page_table",
]
