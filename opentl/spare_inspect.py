"""
Aggregate audit of a concatenated NAND spare stream (64 B × pages).

Pairs with :func:`opentl.nand_translate.extract_spare_only_to_file` / a flat spare sidecar workflow.
Decodes OpenTL fields via
:class:`opentl.spare_layout.SpareRecord` (kernel §7.4a–§7.4b).
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from opentl.spare_layout import SpareRecord, parse_spare, xsum_matches
from opentl.tl_bbm import TLGeometry
from opentl.tl_physical import PAGE_SPARE


def analyze_spare_stream(
    spare: bytes,
    *,
    geo: TLGeometry | None = None,
    large_page: bool = True,
    sample_limit: int = 8,
) -> dict[str, Any]:
    """
    Return JSON-serializable summary counts plus optional decoded samples.

    ``sample_limit``: max non-erased **OpenTL-tagged** rows (**kernel_tagged_like**)
    appended under ``samples`` (each includes global page index and phys block/page).
    """
    g = geo or TLGeometry()
    if len(spare) % PAGE_SPARE:
        raise ValueError(
            f"spare length {len(spare)} is not a multiple of {PAGE_SPARE}"
        )
    n_pages = len(spare) // PAGE_SPARE

    erased = 0
    bootcode_pages = 0
    tagged = 0
    tagged_xsum_ok = 0
    virt_in_range = 0
    mirror_flag_pages = 0

    samples: list[dict[str, Any]] = []

    for pi in range(n_pages):
        chunk = spare[pi * PAGE_SPARE : (pi + 1) * PAGE_SPARE]
        rec = parse_spare(chunk)
        if rec.is_erased_like():
            erased += 1
            continue
        if rec.has_bootcode_marker():
            bootcode_pages += 1
        if rec.mirror_duplicate_chain_flag:
            mirror_flag_pages += 1
        if rec.kernel_tagged_like():
            tagged += 1
            if xsum_matches(chunk, large_page=large_page):
                tagged_xsum_ok += 1
            v = rec.virt_u32(large_page=large_page)
            if 0 <= v < g.virt_blocks:
                virt_in_range += 1
            if sample_limit > 0 and len(samples) < sample_limit and rec.kernel_tagged_like():
                pb = pi // 64
                pg = pi % 64
                samples.append(
                    {
                        "global_page_index": pi,
                        "phys_block": pb,
                        "page_in_erase": pg,
                        "decoded": {
                            "status_4": rec.status,
                            "flags_8": rec.flags_byte8,
                            "phys_u32": rec.phys_u32(large_page=large_page),
                            "virt_u32": v,
                            "page_in_block_13": rec.page_in_block,
                            "xsum_ok": xsum_matches(chunk, large_page=large_page),
                            "mirror_duplicate_chain": rec.mirror_duplicate_chain_flag,
                        },
                    }
                )

    return {
        "schema": "opentl_spare_inspect_v1",
        "page_spare_bytes": PAGE_SPARE,
        "total_pages": n_pages,
        "geometry": asdict(g),
        "counts": {
            "erased_like": erased,
            "non_erased": n_pages - erased,
            "bootcode_substring_hits": bootcode_pages,
            "kernel_tagged_like_spare4": tagged,
            "kernel_tagged_xsum_ok": tagged_xsum_ok,
            "kernel_tagged_virt_in_range": virt_in_range,
            "spare8_mirror_bit_set": mirror_flag_pages,
        },
        "samples_openotl_tagged": samples,
    }
