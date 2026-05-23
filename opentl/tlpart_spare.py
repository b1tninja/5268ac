"""
**tlpart** logical bytes ↔ flat **64 B/spare-page** stream alignment.

After ``nand-translate`` on a 5268-class dump, ``--spare-out`` is often **65536 × 64 B** (one OOB
row per **128 MiB** logical page). ``tlpart.bin`` is only the OpenTL partition; spare page index
``i`` still refers to plane logical offset ``i * 2048``. Under canonical ``mtdparts``,
``tlpart`` begins at :data:`~opentl.tl_physical.TLPART_NAND_DATA_OFFSET_DEFAULT` in that plane.

If the spare file is already truncated to **1012 × 64 × 64 B** (``opentl.tl_mount.mount_flash_image`` / TL erase
coverage), spare page ``0`` lines up with ``tlpart`` byte ``0`` — no base offset.
"""

from __future__ import annotations

from typing import Any, Literal

from .nand_translate import NAND_PAGES_5268
from opentl.tl_bbm import TL_LOGICAL_PREFIX_DEFAULT
from opentl.tl_physical import PAGE_DATA, PAGE_SPARE, PURE_DATA_PLANE, TLPART_NAND_DATA_OFFSET_DEFAULT

SpareIndexMode = Literal["full_logical_plane", "tlpart_relative_spare_stream"]


def infer_flat_spare_indexing_mode(flat_spare_len: int, *, page_spare: int = PAGE_SPARE) -> SpareIndexMode:
    """
    Classify how ``flat_spare`` page indices map to **logical** byte offsets.

    * **full_logical_plane** — at least ``NAND_PAGES_5268`` pages (65536): page ``i`` → logical ``i * 2048``.
    * **tlpart_relative_spare_stream** — shorter stream: page ``i`` → ``tlpart``-relative ``i * 2048``.
    """
    if page_spare <= 0:
        raise ValueError("page_spare must be positive")
    if flat_spare_len % page_spare != 0:
        raise ValueError(f"flat spare length {flat_spare_len} not a multiple of {page_spare}")
    n_pages = flat_spare_len // page_spare
    if n_pages >= NAND_PAGES_5268:
        return "full_logical_plane"
    return "tlpart_relative_spare_stream"


def _tlpart_range_to_plane_logical_offsets(
    *,
    byte_start_in_tlpart: int,
    byte_end_inclusive_in_tlpart: int,
    mode: SpareIndexMode,
    nand_tlpart_base_logical: int,
) -> tuple[int, int]:
    if byte_start_in_tlpart < 0:
        raise ValueError("byte_start_in_tlpart must be >= 0")
    if byte_end_inclusive_in_tlpart < byte_start_in_tlpart:
        raise ValueError("byte_end_inclusive_in_tlpart must be >= byte_start_in_tlpart")
    if byte_end_inclusive_in_tlpart >= TL_LOGICAL_PREFIX_DEFAULT:
        raise ValueError(
            f"tlpart-relative end {byte_end_inclusive_in_tlpart} must be < "
            f"TL_LOGICAL_PREFIX_DEFAULT ({TL_LOGICAL_PREFIX_DEFAULT})"
        )
    if mode == "full_logical_plane":
        L0 = nand_tlpart_base_logical + byte_start_in_tlpart
        L1 = nand_tlpart_base_logical + byte_end_inclusive_in_tlpart
        if L1 >= PURE_DATA_PLANE:
            raise ValueError(
                f"logical range [{L0:#x}, {L1:#x}] extends past PURE_DATA_PLANE ({PURE_DATA_PLANE} B)"
            )
        return L0, L1
    L0 = byte_start_in_tlpart
    L1 = byte_end_inclusive_in_tlpart
    return L0, L1


def spare_page_indices_covering_logical_range(
    L0: int,
    L1: int,
    *,
    n_spare_pages: int,
    page_data: int = PAGE_DATA,
) -> tuple[int, int]:
    """Inclusive spare page index range ``(p0, p1)`` covering logical bytes ``[L0, L1]``."""
    if n_spare_pages <= 0:
        raise ValueError("n_spare_pages must be positive")
    p0 = max(0, L0 // page_data)
    p1 = min(n_spare_pages - 1, (L1 + page_data - 1) // page_data)
    if p0 > p1:
        raise ValueError(f"empty spare page range: L0={L0} L1={L1} n_pages={n_spare_pages}")
    return p0, p1


def slice_flat_spare_for_tlpart_logical_range(
    flat_spare: bytes,
    *,
    byte_start_in_tlpart: int = 0,
    byte_end_inclusive_in_tlpart: int | None = None,
    nand_tlpart_base_logical: int = int(TLPART_NAND_DATA_OFFSET_DEFAULT),
    page_data: int = PAGE_DATA,
    page_spare: int = PAGE_SPARE,
) -> tuple[bytes, dict[str, Any]]:
    """
    Return contiguous spare bytes for all pages overlapping a **tlpart-relative** logical range.

    If ``byte_end_inclusive_in_tlpart`` is ``None``, use the last byte of the standard **tlpart**
    OpenTL slice (**``TL_LOGICAL_PREFIX_DEFAULT - 1``**).
    """
    mode = infer_flat_spare_indexing_mode(len(flat_spare), page_spare=page_spare)
    n_pages = len(flat_spare) // page_spare
    end_tlp = (
        TL_LOGICAL_PREFIX_DEFAULT - 1
        if byte_end_inclusive_in_tlpart is None
        else byte_end_inclusive_in_tlpart
    )
    L0, L1 = _tlpart_range_to_plane_logical_offsets(
        byte_start_in_tlpart=byte_start_in_tlpart,
        byte_end_inclusive_in_tlpart=end_tlp,
        mode=mode,
        nand_tlpart_base_logical=nand_tlpart_base_logical,
    )
    p0, p1 = spare_page_indices_covering_logical_range(
        L0, L1, n_spare_pages=n_pages, page_data=page_data
    )
    out = flat_spare[p0 * page_spare : (p1 + 1) * page_spare]
    meta: dict[str, Any] = {
        "spare_index_mode": mode,
        "nand_tlpart_base_logical_hex": hex(nand_tlpart_base_logical),
        "tlpart_byte_range_hex": (hex(byte_start_in_tlpart), hex(end_tlp)),
        "plane_logical_byte_range_hex": (hex(L0), hex(L1)),
        "spare_page_first": p0,
        "spare_page_last": p1,
        "spare_slice_bytes": len(out),
        "flat_spare_total_pages": n_pages,
    }
    return out, meta


__all__ = [
    "infer_flat_spare_indexing_mode",
    "slice_flat_spare_for_tlpart_logical_range",
    "spare_page_indices_covering_logical_range",
]
