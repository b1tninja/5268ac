"""
P2 spare gates for :func:`~opentl.open_tl.extract_virtual_disk_bytes_chain_aware`.

Composes **reject-and-continue** behaviour (``ntl_find_phy`` / ``ntl_read_verify_phy_spare`` analogue):
each chain candidate can be rejected so the next phys is tried. Full §7.1 kernel skip list is not
replicated byte-for-byte — start with **xsum** (``ntl_compute_spare_xsum`` vs ``spare[0xf]``).
"""

from __future__ import annotations

from collections.abc import Callable

from opentl.open_tl import KERNEL_NAND_PAGE_BYTES
from opentl.spare_layout import xsum_matches


#region kernel_adjacent verify_page_require_nand_page_length
def verify_page_require_nand_page_length() -> Callable[[int, int, bytes, bytes], bool]:
    """Accept only when ``page_data`` is a full 2048-byte NAND page."""

    def _v(_phys: int, _page_in_block: int, page_data: bytes, _spare64: bytes) -> bool:
        return len(page_data) == KERNEL_NAND_PAGE_BYTES

    return _v


#endregion


#region kernel: 0x80288560
# ntl_compute_spare_xsum / ntl_xsum_read — reject-and-continue shape of ntl_find_phy @ 0x80288bd4
def verify_page_require_spare_xsum(*, large_page: bool = True) -> Callable[[int, int, bytes, bytes], bool]:
    """
    **P2:** ``ntl_compute_spare_xsum`` / stored byte @ ``spare[0xf]`` (see ``opentl.spare_layout``).

    Use as ``verify_page=…`` for :func:`~opentl.open_tl.extract_virtual_disk_bytes_chain_aware`
    to skip candidates whose sparerow fails checksum (kernel would read next phys from ``ntl_find_phy``).
    """

    def _v(_phys: int, _page_in_block: int, page_data: bytes, spare64: bytes) -> bool:
        if len(page_data) != KERNEL_NAND_PAGE_BYTES:
            return False
        return xsum_matches(spare64, large_page=large_page)

    return _v


#endregion


#region kernel_adjacent verify_page_all
def verify_page_all(
    *parts: Callable[[int, int, bytes, bytes], bool],
) -> Callable[[int, int, bytes, bytes], bool]:
    """Logical AND of verify predicates (short-circuit on first False)."""

    def _v(phys: int, page_in_block: int, page_data: bytes, spare64: bytes) -> bool:
        for p in parts:
            if not p(phys, page_in_block, page_data, spare64):
                return False
        return True

    return _v


#endregion


__all__ = [
    "verify_page_all",
    "verify_page_require_nand_page_length",
    "verify_page_require_spare_xsum",
]
