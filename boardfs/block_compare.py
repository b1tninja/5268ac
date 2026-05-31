"""Block-aligned byte comparison for ext2 file read validation."""

from __future__ import annotations

import hashlib
from typing import Any

__all__ = ["block_diff_report", "md5_hex"]


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def block_diff_report(
    a: bytes,
    b: bytes,
    *,
    block_size: int = 4096,
    max_report: int = 32,
    label_a: str = "a",
    label_b: str = "b",
) -> dict[str, Any]:
    """
    Compare ``a`` and ``b`` in ``block_size`` chunks.

    Returns first differing block indices, per-block MD5 when they differ, and summary counts.
    """
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    nblocks = max(
        (len(a) + block_size - 1) // block_size,
        (len(b) + block_size - 1) // block_size,
    )
    mismatches: list[dict[str, Any]] = []
    match_blocks = 0
    for bi in range(nblocks):
        off = bi * block_size
        ca = a[off : off + block_size]
        cb = b[off : off + block_size]
        if ca == cb:
            if ca:
                match_blocks += 1
            continue
        entry: dict[str, Any] = {
            "block": bi,
            "offset": off,
            f"{label_a}_len": len(ca),
            f"{label_b}_len": len(cb),
        }
        if ca:
            entry[f"{label_a}_md5"] = md5_hex(ca)
        if cb:
            entry[f"{label_b}_md5"] = md5_hex(cb)
        mismatches.append(entry)
        if len(mismatches) >= max_report:
            break
    return {
        "block_size": block_size,
        "blocks_compared": nblocks,
        "matching_blocks": match_blocks,
        "mismatch_blocks": len(mismatches) if len(mismatches) < max_report else "truncated",
        "first_mismatch_offset": mismatches[0]["offset"] if mismatches else None,
        "mismatches": mismatches,
        "same_len": len(a) == len(b),
        "same_bytes": a == b,
    }
