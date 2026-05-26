"""Refresh flat spare/OOB rows after logical main-plane edits."""

from __future__ import annotations

from opentl.ntl_ecc import ntl_ecc_read, opentl_calculate_ecc
from opentl.spare_layout import compute_spare_xsum, map_page_state

from unand.geometry import NandGeometry, PACE_DEFAULT

_SLICE_BYTES = 512
_REFRESHABLE_STATES = (0, 0x24)
# OpenTL xsum operands (``spare[0xf]`` is the stored checksum itself).
_XSUM_OPERAND_BYTES = frozenset({8, 9, 10, 11, 12, 0xD, 0xE, 16, 17, 18, 19})


def pages_touched_by_spans(
    spans: list[tuple[int, int]],
    *,
    page_data: int,
) -> list[int]:
    """Return sorted NAND page indices overlapping ``(offset, length)`` spans."""
    touched: set[int] = set()
    for off, length in spans:
        if length <= 0:
            continue
        start_page = off // page_data
        end_page = (off + length - 1) // page_data
        for page in range(start_page, end_page + 1):
            touched.add(page)
    return sorted(touched)


def slices_touched_by_spans(
    spans: list[tuple[int, int]],
    *,
    page_data: int = 2048,
) -> dict[int, set[int]]:
    """Map NAND page index -> set of 512-byte ECC slice indices touched by ``spans``."""
    per_page: dict[int, set[int]] = {}
    for off, length in spans:
        if length <= 0:
            continue
        end = off + length
        start_page = off // page_data
        end_page = (end - 1) // page_data
        for page in range(start_page, end_page + 1):
            page_start = page * page_data
            page_end = page_start + page_data
            chunk_start = max(off, page_start)
            chunk_end = min(end, page_end)
            if chunk_start >= chunk_end:
                continue
            rel_start = chunk_start - page_start
            rel_end = chunk_end - page_start
            s0 = rel_start // _SLICE_BYTES
            s1 = (rel_end - 1) // _SLICE_BYTES
            per_page.setdefault(page, set()).update(range(s0, s1 + 1))
    return per_page


def _write_large_page_slice_syndromes(
    bounce: bytearray,
    slice_idx: int,
    *,
    page_size: int,
    spare_base: int,
    rewrite_shared: bool,
) -> set[int]:
    """
    Write ECC syndromes for one 512-byte slice; return spare byte indices changed.

    Only stores bytes whose computed syndrome differs from the current spare value.
    """
    half0 = slice_idx * 0x200
    calc_lo = opentl_calculate_ecc(bounce, half0)
    calc_hi = opentl_calculate_ecc(bounce, half0 + 0x100)
    changed: set[int] = set()

    def _put(rel_idx: int, value: int) -> None:
        abs_idx = spare_base + rel_idx
        if bounce[abs_idx] != value:
            bounce[abs_idx] = value
            changed.add(rel_idx)

    if slice_idx == 0:
        _put(2, calc_lo[2])
        _put(3, calc_hi[0])
        _put(6, calc_hi[1])
        _put(7, calc_hi[2])
        _put(0x16, calc_lo[0])
        _put(0x17, calc_lo[1])
        return changed
    if slice_idx == 1:
        _put(0x12, calc_lo[0])
        _put(0x13, calc_lo[1])
        _put(0x14, calc_lo[2])
        _put(0x15, calc_hi[0])
        if rewrite_shared:
            _put(0x16, calc_lo[0])
            _put(0x17, calc_lo[1])
        return changed
    off = 0x18 + 6 * (slice_idx - 2)
    for i, value in enumerate(calc_lo):
        _put(off + i, value)
    for i, value in enumerate(calc_hi):
        _put(off + 3 + i, value)
    return changed


def refresh_spare_ecc_for_pages(
    logical: bytes | bytearray,
    spare: bytearray,
    page_indices: list[int],
    *,
    geom: NandGeometry = PACE_DEFAULT,
    refresh_xsum: bool = True,
    spans: list[tuple[int, int]] | None = None,
) -> dict[str, object]:
    """
    Recompute OpenTL ECC lanes in ``spare`` for patched pages only.

    Requires ``spans`` (logical main-plane byte ranges that were edited). Only ECC
    slices intersecting those spans are rewritten; unmodified slices and all other
    pages are left untouched (preserving pre-existing correctable ECC drift elsewhere).

    Skips hole/erased rows (``spare[4]`` → ``0xff``) and non-programmed spare states.
    """
    if not spans:
        return {
            "pages_requested": len(page_indices),
            "pages_updated": 0,
            "rows": [],
            "skipped": "no patch spans supplied",
        }

    page_data = int(geom.page_data)
    page_spare = int(geom.page_spare)
    expected_spare = int(geom.pages_total) * page_spare
    if len(spare) != expected_spare:
        raise ValueError(f"spare length {len(spare)} != expected {expected_spare}")

    slice_map = slices_touched_by_spans(spans, page_data=page_data)

    rows: list[dict[str, object]] = []
    for page in page_indices:
        main_off = page * page_data
        spare_off = page * page_spare
        if main_off + page_data > len(logical):
            rows.append({"page": page, "skipped": True, "reason": "main past end"})
            continue

        touched_slices = slice_map.get(page)
        if not touched_slices:
            rows.append({"page": page, "skipped": True, "reason": "no patch bytes in page"})
            continue

        oob = bytearray(spare[spare_off : spare_off + page_spare])
        state = map_page_state(oob[4])
        if state == 0xFF:
            rows.append({"page": page, "skipped": True, "reason": "hole/erased spare"})
            continue
        if state not in _REFRESHABLE_STATES:
            rows.append(
                {
                    "page": page,
                    "skipped": True,
                    "reason": f"spare state {state:#x} not OpenTL-programmed",
                }
            )
            continue

        bounce = bytearray(logical[main_off : main_off + page_data]) + oob
        old_oob = bytes(oob)
        changed_indices: set[int] = set()
        rewrite_shared = 0 in touched_slices
        for slice_idx in sorted(touched_slices):
            changed_indices |= _write_large_page_slice_syndromes(
                bounce,
                slice_idx,
                page_size=page_data,
                spare_base=page_data,
                rewrite_shared=rewrite_shared,
            )

        if not changed_indices:
            rows.append(
                {
                    "page": page,
                    "logical_offset": main_off,
                    "spare_offset": spare_off,
                    "state": state,
                    "slices_updated": sorted(touched_slices),
                    "ecc_updated": False,
                    "reason": "ECC lanes already matched patched main",
                }
            )
            continue

        new_oob = bytearray(bounce[page_data:])
        spare[spare_off : spare_off + page_spare] = new_oob

        xsum_before = old_oob[0xF]
        xsum_after = new_oob[0xF]
        if refresh_xsum and changed_indices.intersection(_XSUM_OPERAND_BYTES):
            recomputed = compute_spare_xsum(new_oob, large_page=(page_data >= 2048))
            if new_oob[0xF] != recomputed:
                spare[spare_off + 0xF] = recomputed
                new_oob[0xF] = recomputed
                xsum_after = recomputed

        verify_bounce = bytearray(logical[main_off : main_off + page_data]) + new_oob
        st, corrected = ntl_ecc_read(page_data, verify_bounce)
        rows.append(
            {
                "page": page,
                "logical_offset": main_off,
                "spare_offset": spare_off,
                "state": state,
                "slices_updated": sorted(touched_slices),
                "spare_bytes_changed": sorted(changed_indices),
                "ecc_updated": True,
                "xsum_before": xsum_before,
                "xsum_after": xsum_after,
                "ecc_verify_status": st,
                "ecc_corrected": corrected,
            }
        )

    return {
        "pages_requested": len(page_indices),
        "pages_updated": sum(1 for r in rows if r.get("ecc_updated")),
        "rows": rows,
    }
