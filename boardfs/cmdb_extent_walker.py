"""
Physical CMDB extent recovery for PACE opentla4 ext2 captures.

This module **does not** implement Linux ``ext2_get_block``. It walks on-disk payload
adjacency (lagged ``i_block[]``, in-band pointer-table pages, sparse indirect gaps) to
reconstruct CMDB XML when inode metadata is stale relative to the physical extent.

Use :func:`recover_cmdb_file_bytes` from ``paceflash cat --cmdb-recover``; default
:func:`~boardfs.ext2_dissect._ext2_read_file_bytes` follows stock kernel semantics.

Ghidra / empirical lag notes: ``reference/ghidra_ext2_pace_lag_investigation.md``.
"""

from __future__ import annotations

import struct

from boardfs.ext2_dissect import (
    _EXT2_NDIR_BLOCKS_KERNEL,
    _CMDB_HEADER_MARKERS,
    _CMDB_XML_FOOTER,
    _ext2_block_has_cmdb_header,
    _ext2_block_size,
    _ext2_fs_block,
    _ext2_last_block,
    _ext2_repair_block_ptr,
)

# PACE on-disk inode: 13 direct slots at 0..12, singly-indirect at 13 (not kernel 12/12).
_EXT2_ONDISK_EXTRA_DIRECT = 12
_EXT2_ONDISK_INDIRECT = 13
_PACE_INDIRECT_HDR_MAGIC = b"\xff\xac"
_PACE_CMDB_HEADER_SCAN_BACK = 128
from boardfs.ext2_volume_io import Ext2VolumeAccess

__all__ = [
    "recover_cmdb_file_bytes",
    "recover_cmdb_dir_data_block",
]


def _ext2_block_is_pace_inode_ptr_table(chunk: bytes) -> bool:
    """In-band page of tagged ``0x01xxxxxx`` ``__le32`` slots (copy of ``i_block[]``), not XML."""
    if len(chunk) < 32:
        return False
    tagged = 0
    for i in range(min(16, len(chunk) // 4)):
        raw = struct.unpack_from("<I", chunk, i * 4)[0]
        if raw == 0:
            break
        if ((raw >> 16) & 0xFF) == 0x01 and (raw & 0xFFFF) >= 0x8000:
            tagged += 1
        else:
            break
    return tagged >= 8


def _ext2_contiguous_data_run_phys(
    buf: bytes | bytearray,
    anchor_phys: int,
    run_index: int,
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
) -> int:
    """Nth payload block after ``anchor_phys``, skipping in-band pointer-table pages."""
    if anchor_phys <= 0 or run_index <= 0 or last_block <= 0 or blksz <= 0:
        return 0
    phys = anchor_phys
    found = 0
    while found < run_index and phys < last_block:
        phys += 1
        chunk = _ext2_fs_block(buf, phys, access=access, blksz=blksz)
        if _ext2_block_is_pace_inode_ptr_table(chunk[:256]):
            continue
        found += 1
    return phys if found == run_index and phys <= last_block else 0


def _ext2_cmdb_header_block_backward(
    buf: bytes | bytearray,
    first_decoded_blk: int,
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
    max_back: int = _PACE_CMDB_HEADER_SCAN_BACK,
) -> int:
    if first_decoded_blk <= 0 or blksz <= 0 or last_block <= 0:
        return 0
    for back in range(max_back):
        bn = first_decoded_blk - back
        if bn <= 0:
            break
        chunk = _ext2_fs_block(buf, bn, access=access, blksz=blksz)
        if _ext2_block_has_cmdb_header(chunk):
            return bn
    return 0


def _pace_pointer_lag_blocks(raw_blk: int, i_blocks: int, i_mode: int) -> int:
    """
    Lag **L** for ``0x01``-tagged ``i_block[]`` on opentla4 CMDB volumes.

    Regular file: **L** = ``i_blocks - 2 * NDIR`` (12). Directory: return ``-i_blocks``.
    """
    if raw_blk == 0 or ((raw_blk >> 16) & 0xFF) != 0x01:
        return 0
    if (i_mode & 0xF000) == 0x4000:
        return -int(i_blocks)
    if (i_mode & 0xF000) == 0x8000:
        return int(i_blocks) - 2 * _EXT2_NDIR_BLOCKS_KERNEL
    return 0


def _pace_inode_data_shift(
    buf: bytes | bytearray,
    i_block: bytes,
    *,
    last_block: int,
    blksz: int,
    i_blocks: int = 0,
    i_mode: int = 0,
    access: Ext2VolumeAccess | None = None,
) -> int:
    ib = struct.unpack_from("<15I", i_block.ljust(60, b"\x00")[:60])
    raw0 = int(ib[0])
    if raw0 == 0:
        return 0
    lag = _pace_pointer_lag_blocks(raw0, i_blocks, i_mode)
    if not _contiguous_direct13_inode(ib, last_block=last_block):
        return lag
    first = _ext2_repair_block_ptr(raw0, last_block)
    if first <= 0:
        return lag
    use_formula = lag != 0 and (i_mode & 0xF000) in (0x4000, 0x8000)
    if use_formula:
        start = first - lag
        if 0 < start <= last_block:
            chunk = _ext2_fs_block(buf, start, access=access, blksz=blksz)
            if _ext2_block_has_cmdb_header(chunk[:256]):
                return lag
    header = _ext2_cmdb_header_block_backward(
        buf, first, last_block=last_block, blksz=blksz, access=access
    )
    if 0 < header < first:
        return first - header
    # Do not apply formula lag when the shifted first block lacks a CMDB XML header.
    return 0


def _contiguous_direct13_inode(ib: tuple[int, ...], *, last_block: int) -> bool:
    direct = [
        _ext2_repair_block_ptr(int(ib[i]), last_block)
        for i in range(_EXT2_ONDISK_EXTRA_DIRECT + 1)
        if ib[i]
    ]
    if len(direct) < _EXT2_ONDISK_EXTRA_DIRECT + 1:
        return False
    if not all(b == a + 1 for a, b in zip(direct, direct[1:])):
        return False
    return ib[_EXT2_ONDISK_INDIRECT] == 0


def _read_indirect_ptrs_pace(
    buf: bytes | bytearray,
    ind_blk: int,
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
) -> list[int]:
    """PACE: ``ff ac`` header may place the ``__le32[]`` table in the next filesystem block."""
    page = _ext2_fs_block(buf, ind_blk, access=access, blksz=blksz)
    off = blksz if len(page) >= 2 and page[:2] == _PACE_INDIRECT_HDR_MAGIC else 0
    if off == blksz:
        page = _ext2_fs_block(buf, ind_blk + 1, access=access, blksz=blksz)
        off = 0
    ptrs: list[int] = []
    for i in range(blksz // 4):
        if off + i * 4 + 4 > len(page):
            break
        raw = struct.unpack_from("<I", page, off + i * 4)[0]
        if raw == 0:
            break
        blk = _ext2_repair_block_ptr(raw, last_block)
        if blk <= 0:
            break
        ptrs.append(blk)
    return ptrs


def _indirect_logical_block_pace(ptrs: list[int], logical: int, *, last_block: int) -> int:
    """Sparse indirect: fill implicit contiguous physical blocks between explicit pointers."""
    if logical < 0 or not ptrs or last_block <= 0:
        return 0
    pos = 0
    prev_phys = 0
    for i, p in enumerate(ptrs):
        p = _ext2_repair_block_ptr(int(p), last_block)
        if p <= 0:
            break
        if i > 0 and p > prev_phys + 1:
            for filler in range(prev_phys + 1, p):
                if pos == logical:
                    return filler
                pos += 1
        if pos == logical:
            return p
        pos += 1
        prev_phys = p
    return 0


def _map_file_block_pace_on_disk(
    buf: bytes | bytearray,
    ib: tuple[int, ...],
    file_blk: int,
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
) -> int:
    """PACE on-disk layout (13 direct + indirect at 13) without pointer lag."""
    if file_blk < 0:
        return 0

    def dec(raw: int) -> int:
        return _ext2_repair_block_ptr(int(raw), last_block)

    if file_blk <= _EXT2_ONDISK_EXTRA_DIRECT:
        raw = ib[file_blk]
        if not raw:
            return 0
        p = dec(raw)
        return p if 0 < p <= last_block else 0
    ind = dec(ib[_EXT2_ONDISK_INDIRECT])
    if ind > 0:
        ptrs = _read_indirect_ptrs_pace(
            buf, ind, last_block=last_block, blksz=blksz, access=access
        )
        if ptrs:
            logical = file_blk - (_EXT2_ONDISK_EXTRA_DIRECT + 1)
            phys = _indirect_logical_block_pace(ptrs, logical, last_block=last_block)
            if 0 < phys <= last_block:
                return phys
        return 0
    anchor = dec(ib[_EXT2_ONDISK_EXTRA_DIRECT])
    if anchor <= 0:
        return 0
    steps = file_blk - _EXT2_ONDISK_EXTRA_DIRECT
    if steps <= 0:
        return anchor
    return _ext2_contiguous_data_run_phys(
        buf,
        anchor,
        steps,
        last_block=last_block,
        blksz=blksz,
        access=access,
    )


def _map_file_block_pace(
    buf: bytes | bytearray,
    ib: tuple[int, ...],
    file_blk: int,
    *,
    pace_lag: int,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
) -> int:
    if file_blk < 0:
        return 0
    if pace_lag <= 0:
        return _map_file_block_pace_on_disk(
            buf, ib, file_blk, last_block=last_block, blksz=blksz, access=access
        )
    lag = pace_lag

    def dec(raw: int) -> int:
        return _ext2_repair_block_ptr(int(raw), last_block)

    if file_blk < _EXT2_NDIR_BLOCKS_KERNEL:
        raw = ib[file_blk]
        if not raw:
            return 0
        p = dec(raw) - lag
        return p if 0 < p <= last_block else 0
    if file_blk < lag:
        anchor = dec(ib[11]) - lag if ib[11] else 0
        if anchor <= 0 or file_blk < 12:
            return 0
        payload_start = anchor + 1
        if payload_start <= last_block:
            chunk = _ext2_fs_block(buf, payload_start, access=access, blksz=blksz)
            if _ext2_block_is_pace_inode_ptr_table(chunk[:256]):
                payload_start += 1
        phys = payload_start + (file_blk - 12)
        return phys if 0 < phys <= last_block else 0
    slot = file_blk - lag
    if slot < _EXT2_ONDISK_EXTRA_DIRECT + 1:
        raw = ib[slot]
        if not raw:
            return 0
        p = dec(raw)
        return p if 0 < p <= last_block else 0
    ind = dec(ib[_EXT2_ONDISK_INDIRECT])
    if ind > 0:
        ptrs = _read_indirect_ptrs_pace(
            buf, ind, last_block=last_block, blksz=blksz, access=access
        )
        if ptrs:
            logical = file_blk - (_EXT2_ONDISK_EXTRA_DIRECT + 1)
            phys = _indirect_logical_block_pace(ptrs, logical, last_block=last_block)
            if 0 < phys <= last_block:
                return phys
        return 0
    anchor = dec(ib[_EXT2_ONDISK_EXTRA_DIRECT])
    if anchor <= 0:
        return 0
    steps = file_blk - (lag + _EXT2_ONDISK_EXTRA_DIRECT)
    if steps <= 0:
        return anchor
    return _ext2_contiguous_data_run_phys(
        buf,
        anchor,
        steps,
        last_block=last_block,
        blksz=blksz,
        access=access,
    )


def _probe_mapped_span(
    buf: bytes | bytearray,
    i_block: bytes,
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
    pace_lag: int = 0,
    max_fb: int = 2048,
    stop_at_cmdb_footer: bool = False,
) -> int:
    ib = struct.unpack_from("<15I", i_block.ljust(60, b"\x00")[:60])
    span = 0
    for fb in range(max_fb):
        phys = _map_file_block_pace(
            buf,
            ib,
            fb,
            pace_lag=pace_lag,
            last_block=last_block,
            blksz=blksz,
            access=access,
        )
        if phys <= 0:
            break
        span = fb + 1
        if not stop_at_cmdb_footer:
            continue
        chunk = _ext2_fs_block(buf, phys, access=access, blksz=blksz)
        if _CMDB_XML_FOOTER in chunk:
            break
        if fb > 0 and _ext2_block_has_cmdb_header(chunk[:256]):
            span = fb
            break
    return span


def recover_cmdb_dir_data_block(
    buf: bytes | bytearray,
    raw_blk: int,
    *,
    dir_inum: int,
    last_block: int,
    blksz: int,
    inodes_count: int,
    i_blocks: int = 0,
    i_mode: int = 0,
) -> int:
    """Resolve directory data block (PACE ``+ i_blocks`` / ``+2`` fallbacks)."""
    from boardfs.ext2_dissect import (
        _ext2_dir_block_has_dot_entry,
        _ext2_dentry_inodes_cap,
    )

    blk = _ext2_repair_block_ptr(raw_blk, last_block)
    if blk <= 0 or blksz <= 0:
        return 0
    cap = _ext2_dentry_inodes_cap(inodes_count, hint_inum=dir_inum)

    def _has_dot(block_num: int) -> bool:
        if block_num <= 0 or block_num > last_block:
            return False
        off = block_num * blksz
        if off + blksz > len(buf):
            return False
        return _ext2_dir_block_has_dot_entry(
            buf[off : off + blksz], dir_inum, inodes_count=cap
        )

    lag = _pace_pointer_lag_blocks(raw_blk, i_blocks, i_mode)
    if lag != 0:
        adj = blk - lag
        if adj > 0 and _has_dot(adj):
            return adj
    if dir_inum > 0 and _has_dot(blk):
        return blk
    if dir_inum > 0 and ((raw_blk >> 16) & 0xFF) == 0x01:
        ahead = blk + 2
        if _has_dot(ahead):
            return ahead
    return blk if blk > 0 else 0


def _cmdb_output_has_xml_header(data: bytes) -> bool:
    return any(m in data[:4096] for m in _CMDB_HEADER_MARKERS)


def _collect_inode_anchor_phys_range(
    buf: bytes | bytearray,
    ib: tuple[int, ...],
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
    max_fb: int = 512,
) -> tuple[int, int]:
    """Min/max physical blocks referenced by on-disk ``i_block[]`` (no pointer lag)."""
    physs: list[int] = []
    for fb in range(max_fb):
        phys = _map_file_block_pace_on_disk(
            buf, ib, fb, last_block=last_block, blksz=blksz, access=access
        )
        if phys <= 0:
            if fb > _EXT2_ONDISK_EXTRA_DIRECT + 32:
                break
            continue
        physs.append(phys)
    if not physs:
        return 0, 0
    return min(physs), max(physs)


def _scan_cmdb_header_block_in_range(
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
        if _ext2_block_has_cmdb_header(chunk):
            return bn
    return 0


def _read_cmdb_xml_from_header_block(
    buf: bytes | bytearray,
    header_blk: int,
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
    max_blocks: int = 4096,
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


def recover_cmdb_near_inode_extent(
    buf: bytes | bytearray,
    i_block: bytes,
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
    scan_margin_blocks: int = 512,
) -> bytes:
    """
    When inode ``i_block[]`` points at stale mid-file blocks, find ``<?xml`` on disk
    near the anchor physical range and read through ``</ROOT></CM>``.
    """
    ib = struct.unpack_from("<15I", i_block.ljust(60, b"\x00")[:60])
    lo, hi = _collect_inode_anchor_phys_range(
        buf, ib, last_block=last_block, blksz=blksz, access=access
    )
    if lo <= 0:
        return b""
    margin = int(scan_margin_blocks)
    for scan_lo, scan_hi in (
        (lo, hi + margin),
        (max(1, lo - margin), lo - 1),
    ):
        header_blk = _scan_cmdb_header_block_in_range(
            buf,
            scan_lo,
            scan_hi,
            last_block=last_block,
            blksz=blksz,
            access=access,
        )
        if header_blk > 0:
            return _read_cmdb_xml_from_header_block(
                buf,
                header_blk,
                last_block=last_block,
                blksz=blksz,
                access=access,
            )
    return b""


def recover_cmdb_file_bytes(
    buf: bytes | bytearray,
    sb_off: int,
    i_block: bytes,
    size: int,
    *,
    i_blocks: int = 0,
    i_mode: int = 0,
    access: Ext2VolumeAccess | None = None,
) -> bytes:
    """
    Reconstruct a CMDB regular file by physical extent walk (not kernel ``ext2_get_block``).
    """
    lb = _ext2_last_block(buf, sb_off)
    blksz = _ext2_block_size(buf, sb_off)
    if lb is None or lb <= 0 or blksz <= 0:
        return b""
    pace_lag = _pace_inode_data_shift(
        buf,
        i_block,
        last_block=lb,
        blksz=blksz,
        i_blocks=i_blocks,
        i_mode=i_mode,
        access=access,
    )
    ib = struct.unpack_from("<15I", i_block.ljust(60, b"\x00")[:60])
    stop_footer = pace_lag > 0 and _contiguous_direct13_inode(ib, last_block=lb)
    if stop_footer and ib[0]:
        first = _ext2_repair_block_ptr(int(ib[0]), lb) - pace_lag
        if first > 0:
            chunk = _ext2_fs_block(buf, first, access=access, blksz=blksz)[:256]
            stop_footer = _ext2_block_has_cmdb_header(chunk)
    mapped_span = _probe_mapped_span(
        buf,
        i_block,
        last_block=lb,
        blksz=blksz,
        access=access,
        pace_lag=pace_lag,
        stop_at_cmdb_footer=stop_footer,
    )
    nblocks = mapped_span if mapped_span > 0 else 0
    if size > 0:
        nblocks = max(nblocks, (size + blksz - 1) // blksz)
    if i_blocks > 0:
        nblocks = max(nblocks, (i_blocks * 512 + blksz - 1) // blksz)
    if nblocks <= 0:
        return b""
    parts: list[bytes] = []
    for idx in range(nblocks):
        phys = _map_file_block_pace(
            buf,
            ib,
            idx,
            pace_lag=pace_lag,
            last_block=lb,
            blksz=blksz,
            access=access,
        )
        if phys <= 0:
            parts.append(b"\x00" * blksz)
            continue
        parts.append(_ext2_fs_block(buf, phys, access=access, blksz=blksz))
    out = b"".join(parts)
    if mapped_span > 0:
        out = out[: mapped_span * blksz]
    footer = out.find(_CMDB_XML_FOOTER)
    if footer >= 0:
        out = out[: footer + len(_CMDB_XML_FOOTER)]
    elif size > 0:
        out = out[:size]
    if not _cmdb_output_has_xml_header(out):
        near = recover_cmdb_near_inode_extent(
            buf,
            i_block,
            last_block=lb,
            blksz=blksz,
            access=access,
        )
        if _cmdb_output_has_xml_header(near) and _CMDB_XML_FOOTER in near:
            out = near
            if size > 0 and len(out) > size:
                foot = out.rfind(_CMDB_XML_FOOTER)
                end = foot + len(_CMDB_XML_FOOTER) if foot >= 0 else len(out)
                if end <= size:
                    out = out[:size]
    return out
