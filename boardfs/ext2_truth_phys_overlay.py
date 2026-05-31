"""
Forensic read: patch kernel-exact file blocks with pkgstream clusters found in the slice.

When ``sys1/uImage`` inode maps stale ``kernel_phys`` but 533857 bytes exist elsewhere on
opentla4, ``slice.find(want_1k)`` yields ``truth_phys``. This overlay substitutes those
blocks via :class:`~boardfs.ext2_volume_io.Ext2VolumeAccess` — **analysis only**, not boot path.
"""

from __future__ import annotations

from typing import Any

from boardfs.ext2_dissect import (
    _ext2_addr_per_block_bits,
    _ext2_block_size,
    _ext2_fs_block,
    _ext2_last_block,
    _ext2_map_file_block,
    _ext2_read_file_bytes_kernel_exact,
)
from boardfs.ext2_volume_io import Ext2VolumeAccess

__all__ = [
    "build_truth_phys_overlay",
    "read_file_bytes_truth_phys_overlay",
    "overlay_summary",
]


def _find_block_anchors(haystack: bytes | bytearray, needle: bytes, *, limit: int = 8) -> list[int]:
    if not needle:
        return []
    anchors: list[int] = []
    start = 0
    while len(anchors) < limit:
        i = haystack.find(needle, start)
        if i < 0:
            break
        anchors.append(i)
        start = i + 1
    return anchors


def build_truth_phys_overlay(
    slice_buf: bytes | bytearray,
    sb_off: int,
    i_block: bytes,
    size: int,
    want_body: bytes,
    *,
    access: Ext2VolumeAccess | None = None,
    blksz: int | None = None,
) -> dict[int, int]:
    """
    Map file_block → truth_phys for blocks where kernel_exact read != ``want_body``.

    Uses first full-block anchor in ``slice_buf`` (same rule as ``ext2_bbm_gap_analysis``).
    """
    lb = _ext2_last_block(slice_buf, sb_off)
    if blksz is None:
        blksz = _ext2_block_size(slice_buf, sb_off)
    if lb is None or lb <= 0 or blksz <= 0 or size <= 0:
        return {}
    apb = _ext2_addr_per_block_bits(blksz)
    got = _ext2_read_file_bytes_kernel_exact(slice_buf, sb_off, i_block, size, access=access)
    nfb = (min(len(want_body), size) + blksz - 1) // blksz
    overlay: dict[int, int] = {}
    for fb in range(nfb):
        off = fb * blksz
        want = want_body[off : off + blksz]
        if got[off : off + blksz] == want:
            continue
        kernel_phys = _ext2_map_file_block(
            slice_buf,
            i_block,
            fb,
            last_block=lb,
            blksz=blksz,
            addr_per_block_bits=apb,
            access=access,
            kernel_exact=True,
        )
        anchors = _find_block_anchors(slice_buf, want, limit=8)
        if not anchors:
            continue
        truth_phys = anchors[0] // blksz
        if truth_phys > 0 and truth_phys != kernel_phys:
            overlay[fb] = truth_phys
    return overlay


def read_file_bytes_truth_phys_overlay(
    slice_buf: bytes | bytearray,
    sb_off: int,
    i_block: bytes,
    size: int,
    overlay: dict[int, int],
    *,
    access: Ext2VolumeAccess | None = None,
) -> bytes:
    """Kernel-exact read with selected file blocks replaced by ``overlay[fb]`` clusters."""
    blksz = _ext2_block_size(slice_buf, sb_off)
    if blksz <= 0:
        return b""
    body = bytearray(
        _ext2_read_file_bytes_kernel_exact(slice_buf, sb_off, i_block, size, access=access)
    )
    for fb, truth_phys in sorted(overlay.items()):
        off = int(fb) * blksz
        if off + blksz > len(body):
            continue
        chunk = _ext2_fs_block(slice_buf, int(truth_phys), access=access, blksz=blksz)
        body[off : off + blksz] = chunk[:blksz]
    return bytes(body)[:size]


def overlay_summary(
    slice_buf: bytes | bytearray,
    sb_off: int,
    i_block: bytes,
    size: int,
    want_body: bytes,
    overlay: dict[int, int],
    *,
    access: Ext2VolumeAccess | None = None,
) -> dict[str, Any]:
    """Counts for validation reports."""
    blksz = _ext2_block_size(slice_buf, sb_off)
    nfb = (min(len(want_body), size) + blksz - 1) // blksz if blksz > 0 else 0
    patched = read_file_bytes_truth_phys_overlay(
        slice_buf, sb_off, i_block, size, overlay, access=access
    )
    mism_after = 0
    if blksz > 0:
        for fb in range(nfb):
            off = fb * blksz
            if patched[off : off + blksz] != want_body[off : off + blksz]:
                mism_after += 1
    return {
        "overlay_blocks": len(overlay),
        "mismatch_1k_after_overlay": mism_after,
        "match_1k_after_overlay": nfb - mism_after,
        "eq_pkgstream": patched == want_body[:size],
    }
