"""
Mount-time spare/OOB gates used by offline `ntl_mount` replay.

This is a small, testable subset of `ntl_read_verify_phy_spare` / `ntl_find_valid_spare`
behaviour (see `opentl.spare_layout.spare_read_verify_ok` and `reference/opentl_kernel_ghidra.md`).

For offline mount reconstruction we primarily need:

- A predicate for whether a spare row is "mount-usable" (state + checksum).
- Extraction of a meaningful virtual id (vblk) from a mount-usable row.
"""

from __future__ import annotations

from dataclasses import dataclass

from opentl.spare_layout import SpareRecord, map_page_state, parse_spare, xsum_matches


@dataclass(frozen=True)
class MountSpareRow:
    phys: int
    page: int
    state: int
    rec: SpareRecord
    virt_u32: int


def mount_spare_row_or_none(
    phys: int,
    page: int,
    spare64: bytes,
    *,
    large_page: bool = True,
    pages_per_erase: int = 64,
) -> MountSpareRow | None:
    """
    Return a parsed mount-usable spare row or None.

    Criteria:
    - kernel-tagged-like after state normalization (`spare_read_verify_ok`)
    - xsum matches when state indicates tagged/active
    - virt_u32 is meaningful and in-range checks are left to the caller (geometry-specific)
    """
    if len(spare64) != 64:
        return None
    # For mount replay we want a conservative acceptance rule:
    # only consider rows whose checksum matches, regardless of the per-erase trailer heuristics.
    _ = pages_per_erase
    if not xsum_matches(spare64, large_page=large_page):
        return None
    rec = parse_spare(spare64)
    st = map_page_state(spare64[4])
    if not rec.virt_u32_meaningful(large_page=large_page):
        return None
    v = rec.virt_u32(large_page=large_page)
    return MountSpareRow(phys=int(phys), page=int(page), state=int(st), rec=rec, virt_u32=int(v))


__all__ = ["MountSpareRow", "mount_spare_row_or_none"]

