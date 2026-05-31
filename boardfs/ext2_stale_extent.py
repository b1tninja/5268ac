"""
Recover stale document extents on PACE opentla4 captures.

When inode ``i_block[]`` points at mid-file payload (common on CMDB XML after
power-loss / promote skew), kernel-faithful reads return an ``i_size`` fragment
starting inside the document.  Scan near the inode's mapped physical blocks for
the real header block and read through ``</ROOT></CM>``.

Used automatically from :func:`~boardfs.ext2_dissect._ext2_read_file_bytes` on
PACE volumes (``s_inode_size == 0``); not a separate CLI flag.
"""

from __future__ import annotations

import stat
import struct

from boardfs.ext2_dissect import (
    _EXT2_NDIR_BLOCKS_KERNEL,
    _ext2_addr_per_block_bits,
    _ext2_block_size,
    _ext2_fs_block,
    _ext2_last_block,
    _ext2_map_file_block,
)
from boardfs.ext2_volume_io import Ext2VolumeAccess

_CMDB_HEADER_MARKERS = (b"<?xml", b"<?xll", b"<CM VERS")
_CMDB_XML_FOOTER = b"</ROOT></CM>"
_HEADER_SCAN_BACK = 128
_DEFAULT_SCAN_MARGIN = 512
_MAX_READ_BLOCKS = 4096

__all__ = ["recover_stale_document_extent"]


def _has_cmdb_xml_header(data: bytes) -> bool:
    return any(m in data[:4096] for m in _CMDB_HEADER_MARKERS)


def _looks_like_stale_cmdb_fragment(data: bytes) -> bool:
    """Kernel read started mid-document (XML field tags without prologue)."""
    if not data or _has_cmdb_xml_header(data):
        return False
    sample = data[:4096]
    if b"<?xml" in sample:
        return False
    return b"<" in sample and (
        b"</" in sample
        or b"CM VERS" in sample
        or b'N="' in sample
        or b'ame">' in sample
    )


def _header_block_backward(
    buf: bytes | bytearray,
    first_phys: int,
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
    max_back: int = _HEADER_SCAN_BACK,
) -> int:
    if first_phys <= 0 or blksz <= 0 or last_block <= 0:
        return 0
    for back in range(max_back):
        bn = first_phys - back
        if bn <= 0:
            break
        chunk = _ext2_fs_block(buf, bn, access=access, blksz=blksz)
        if any(m in chunk for m in _CMDB_HEADER_MARKERS):
            return bn
    return 0


def _scan_header_in_range(
    buf: bytes | bytearray,
    block_lo: int,
    block_hi: int,
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
) -> int:
    lo = max(1, int(block_lo))
    hi = min(int(block_hi), int(last_block))
    if lo > hi:
        return 0
    for bn in range(lo, hi + 1):
        chunk = _ext2_fs_block(buf, bn, access=access, blksz=blksz)
        if any(m in chunk for m in _CMDB_HEADER_MARKERS):
            return bn
    return 0


def _read_document_from_header_block(
    buf: bytes | bytearray,
    header_blk: int,
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
    max_blocks: int = _MAX_READ_BLOCKS,
) -> bytes:
    parts: list[bytes] = []
    for off in range(max_blocks):
        bn = header_blk + off
        if bn > last_block:
            break
        chunk = _ext2_fs_block(buf, bn, access=access, blksz=blksz)
        parts.append(chunk)
        if _CMDB_XML_FOOTER in chunk:
            blob = b"".join(parts)
            foot = blob.find(_CMDB_XML_FOOTER)
            return blob[: foot + len(_CMDB_XML_FOOTER)]
    return b"".join(parts)


def _kernel_mapped_phys_range(
    buf: bytes | bytearray,
    sb_off: int,
    i_block: bytes,
    *,
    size: int,
    access: Ext2VolumeAccess | None = None,
    max_fb: int = 512,
) -> tuple[int, int]:
    lb = _ext2_last_block(buf, sb_off)
    blksz = _ext2_block_size(buf, sb_off)
    if lb is None or lb <= 0 or blksz <= 0:
        return 0, 0
    apb = _ext2_addr_per_block_bits(blksz)
    want = (size + blksz - 1) // blksz if size > 0 else max_fb
    physs: list[int] = []
    for fb in range(min(max(1, want), max_fb)):
        phys = _ext2_map_file_block(
            buf,
            i_block,
            fb,
            last_block=lb,
            blksz=blksz,
            addr_per_block_bits=apb,
            access=access,
            kernel_exact=True,
        )
        if phys <= 0:
            if fb >= _EXT2_NDIR_BLOCKS_KERNEL:
                break
            continue
        physs.append(phys)
    if not physs:
        return 0, 0
    return min(physs), max(physs)


def recover_stale_document_extent(
    buf: bytes | bytearray,
    sb_off: int,
    i_block: bytes,
    body: bytes,
    *,
    size: int = 0,
    i_mode: int = 0,
    access: Ext2VolumeAccess | None = None,
    scan_margin_blocks: int = _DEFAULT_SCAN_MARGIN,
) -> bytes:
    """
    When *body* from a kernel read lacks ``<?xml`` but looks like mid-CMDB XML,
    locate the header on disk near inode anchor blocks and return the full document.
    """
    del size
    if not body or _has_cmdb_xml_header(body):
        return body
    if (i_mode & 0xF000) not in (0x8000, 0):  # regular file only
        return body
    if not _looks_like_stale_cmdb_fragment(body):
        return body

    lb = _ext2_last_block(buf, sb_off)
    blksz = _ext2_block_size(buf, sb_off)
    if lb is None or lb <= 0 or blksz <= 0:
        return body

    lo, hi = _kernel_mapped_phys_range(
        buf, sb_off, i_block, size=len(body), access=access
    )
    if lo <= 0:
        return body

    header = _header_block_backward(
        buf, lo, last_block=lb, blksz=blksz, access=access
    )
    if header <= 0:
        margin = int(scan_margin_blocks)
        for scan_lo, scan_hi in (
            (lo, hi + margin),
            (max(1, lo - margin), lo - 1),
        ):
            header = _scan_header_in_range(
                buf,
                scan_lo,
                scan_hi,
                last_block=lb,
                blksz=blksz,
                access=access,
            )
            if header > 0:
                break

    if header <= 0:
        return body

    recovered = _read_document_from_header_block(
        buf,
        header,
        last_block=lb,
        blksz=blksz,
        access=access,
    )
    if _has_cmdb_xml_header(recovered) and _CMDB_XML_FOOTER in recovered:
        return recovered
    return body
