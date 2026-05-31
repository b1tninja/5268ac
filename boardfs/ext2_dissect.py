"""List ``/`` on a :class:`~boardfs.block.BlockSlice` via Dissect extfs (in-memory slice)."""

from __future__ import annotations

import io
import stat
import struct
from typing import Any

from boardfs.block import BlockSlice
from boardfs.ext2_volume_io import Ext2VolumeAccess
from opentl.driver import OPENTLA4_EXT2_MAGIC_OFF


def _ext2_fs_block(
    buf: bytes | bytearray,
    block_num: int,
    *,
    access: Ext2VolumeAccess | None,
    blksz: int,
) -> bytes:
    """Read one filesystem block (NTL replay when ``access.ntl`` is set)."""
    if block_num <= 0:
        return b"\x00" * blksz
    if access is not None:
        return access.read_block(block_num)
    off = block_num * blksz
    if off + blksz > len(buf):
        return b"\x00" * blksz
    return bytes(buf[off : off + blksz])

#region kernel_adjacent ext2_dissect_dissect_prepare
# PACE opentla4 capture: s_inode_size/s_first_ino zero, GD high-byte mask (not a single kernel EA).
_EXT2_MAGIC_LE = b"\x53\xef"
_EXT2_SB_MAGIC_OFF = 56
_EXT2_SB0_OFF = 1024
_EXT2_DEFAULT_INODE_SIZE = 128
_EXT2_DEFAULT_FIRST_INO = 11


def _ext2_io_view(data: bytes, sb_off: int) -> io.BytesIO:
    delta = sb_off - _EXT2_SB0_OFF
    if delta == 0:
        return io.BytesIO(data)
    if delta > 0:
        return io.BytesIO(data[delta:])
    return io.BytesIO(b"\x00" * (-delta) + data)


def _ext2_normalize_superblock_for_dissect(buf: bytearray, sb_off: int = _EXT2_SB0_OFF) -> bool:
    if sb_off + 90 > len(buf):
        return False
    if buf[sb_off + _EXT2_SB_MAGIC_OFF : sb_off + _EXT2_SB_MAGIC_OFF + 2] != _EXT2_MAGIC_LE:
        return False
    changed = False
    if struct.unpack_from("<H", buf, sb_off + 88)[0] == 0:
        buf[sb_off + 88 : sb_off + 90] = struct.pack("<H", _EXT2_DEFAULT_INODE_SIZE)
        changed = True
    if struct.unpack_from("<I", buf, sb_off + 84)[0] == 0:
        buf[sb_off + 84 : sb_off + 88] = struct.pack("<I", _EXT2_DEFAULT_FIRST_INO)
        changed = True
    ro_compat = struct.unpack_from("<I", buf, sb_off + 104)[0]
    if ro_compat > 0xFFFF:
        buf[sb_off + 104 : sb_off + 108] = b"\x00\x00\x00\x00"
        changed = True
    return changed


def _ext2_le32_block(raw: int) -> int:
    """
    Kernel ``ext2_get_branch`` / ``ext2_get_block``: ``bswap32`` on stored ``__le32``.

    On a little-endian host the on-disk little-endian word is used as-is.
    """
    return raw & 0xFFFFFFFF


def _ext2_branch_block_ptr_kernel_exact(raw: int) -> int:
    """Stock ``ext2_get_branch``: ``bswap32`` / raw ``__le32`` only; stop at zero."""
    blk = _ext2_le32_block(raw)
    return blk if blk > 0 else 0


def _ext2_branch_block_ptr(raw: int, last_block: int) -> int:
    """
    Pointer value for ``ext2_get_branch`` on a prepared dump volume.

    Uses kernel ``__le32`` semantics first; when the stored word cannot be a valid
    block number (corrupt tag / bit rot), apply :func:`_ext2_decode_block_ptr` so
    mapping matches scrubbed pointer pages in :func:`_ext2_prepare_kernel_block_read`.
    """
    blk = _ext2_le32_block(raw)
    if blk <= 0:
        return 0
    if last_block > 0 and blk > last_block:
        blk = _ext2_decode_block_ptr(raw, last_block)
    return blk if blk > 0 else 0


def _ext2_repair_block_ptr(value: int, last_block: int) -> int:
    """
    Offline dump repair for tagged/corrupt ``__le32`` pointers (GD rows, indirect tables).

    **Not** used on the kernel-faithful read path — only :func:`_ext2_sanitize_group_descriptors`
    and Dissect prep. Diverges from stock ``ext2_get_branch`` when MSB tag bytes are present.
    """
    value &= 0xFFFFFFFF
    if value == 0 or last_block <= 0:
        return value
    if value <= last_block:
        return value
    if ((value >> 16) & 0xFF) == 0x01:
        low16 = value & 0xFFFF
        if 0 < low16 <= last_block:
            return low16
    for mask in (0xFFFF, 0xFFFFFF):
        trimmed = value & mask
        if 0 < trimmed <= last_block:
            return trimmed
    return value


# Back-compat alias (repair path / tests / sanitize)
_ext2_decode_block_ptr = _ext2_repair_block_ptr
_ext2_mask_block_ptr = _ext2_repair_block_ptr


def _ext2_sanitize_group_descriptors(buf: bytearray, sb_off: int = _EXT2_SB0_OFF) -> bool:
    if sb_off + 128 > len(buf):
        return False
    sb = memoryview(buf)[sb_off : sb_off + 256]
    if sb[_EXT2_SB_MAGIC_OFF : _EXT2_SB_MAGIC_OFF + 2] != _EXT2_MAGIC_LE:
        return False
    blksz = 1024 << struct.unpack_from("<I", sb, 24)[0]
    if blksz <= 0:
        return False
    blocks_lo = struct.unpack_from("<I", sb, 4)[0]
    blocks_hi = struct.unpack_from("<I", sb, 72)[0]
    last_block = ((blocks_hi << 32) | blocks_lo) - 1
    if last_block <= 0:
        return False
    bpg = struct.unpack_from("<I", sb, 32)[0]
    if bpg == 0:
        return False
    first_data = struct.unpack_from("<I", sb, 20)[0]
    ngroups = (last_block - first_data + bpg) // bpg
    gd_off = _EXT2_SB0_OFF + blksz
    changed = False
    for g in range(int(ngroups) + 1):
        o = gd_off + g * 32
        if o + 12 > len(buf):
            break
        for fld in (0, 4, 8):
            v = struct.unpack_from("<I", buf, o + fld)[0]
            fixed = _ext2_decode_block_ptr(v, last_block)
            if fixed != v:
                struct.pack_into("<I", buf, o + fld, fixed)
                changed = True
    return changed


def _ext2_block_size(buf: bytes | bytearray, sb_off: int = _EXT2_SB0_OFF) -> int:
    log_bsz = struct.unpack_from("<I", buf, sb_off + 24)[0]
    return 1024 << log_bsz


def _ext2_last_block(buf: bytes | bytearray, sb_off: int = _EXT2_SB0_OFF) -> int | None:
    if sb_off + 76 > len(buf):
        return None
    if buf[sb_off + _EXT2_SB_MAGIC_OFF : sb_off + _EXT2_SB_MAGIC_OFF + 2] != _EXT2_MAGIC_LE:
        return None
    blocks_lo = struct.unpack_from("<I", buf, sb_off + 4)[0]
    blocks_hi = struct.unpack_from("<I", buf, sb_off + 72)[0]
    last_block = ((blocks_hi << 32) | blocks_lo) - 1
    return last_block if last_block > 0 else None


def _ext2_sanitize_pointer_block(
    buf: bytearray, block_num: int, *, last_block: int, blksz: int
) -> bool:
    """Mask MSB junk on ``uint32`` block pointers inside one filesystem block."""
    if block_num <= 0:
        return False
    off = block_num * blksz
    if off + blksz > len(buf):
        return False
    changed = False
    for i in range(0, blksz, 4):
        v = struct.unpack_from("<I", buf, off + i)[0]
        fixed = _ext2_decode_block_ptr(v, last_block)
        if fixed != v:
            struct.pack_into("<I", buf, off + i, fixed)
            changed = True
    return changed


def _ext2_maybe_sanitize_pointer_continuation(
    buf: bytearray,
    table_blk: int,
    *,
    last_block: int,
    blksz: int,
) -> None:
    """
    Scrub ``table_blk + 1`` only when it looks like a PACE indirect-table continuation.

    Kernel ``ext2_get_branch`` does not skip to ``ind_blk + 1``; on stock layouts the byte
    after a singly-indirect table is **file data** (e.g. uImage table @ 4628, data @ 4629).
    """
    if table_blk + 1 >= len(buf) // blksz:
        return
    page = _ext2_fs_block(buf, table_blk, access=None, blksz=blksz)
    if len(page) >= 2 and page[:2] == _PACE_INDIRECT_HDR_MAGIC:
        _ext2_sanitize_pointer_block(buf, table_blk + 1, last_block=last_block, blksz=blksz)


def _ext2_sanitize_singly_indirect_table(
    buf: bytearray,
    sind_blk: int,
    *,
    last_block: int,
    blksz: int,
) -> None:
    """Repair ``__le32[]`` data-pointer page(s) for one singly-indirect table block."""
    if sind_blk <= 0:
        return
    _ext2_sanitize_pointer_block(buf, sind_blk, last_block=last_block, blksz=blksz)
    _ext2_maybe_sanitize_pointer_continuation(
        buf, sind_blk, last_block=last_block, blksz=blksz
    )


def _ext2_sanitize_dind_pointer_page(
    buf: bytearray,
    dind_blk: int,
    *,
    last_block: int,
    blksz: int,
) -> None:
    """
    Kernel double-indirect: ``i_block[13]`` → dind page → singly-indirect tables → data.

    ``ext2_block_to_path`` paths ``[13, x, y]`` use ``ext2_get_branch`` on each level; scrub
    the dind page and every singly-indirect table it references (same as inode slot 12, but
    reached through dind).
    """
    if dind_blk <= 0 or dind_blk > last_block:
        return
    _ext2_sanitize_pointer_block(buf, dind_blk, last_block=last_block, blksz=blksz)
    _ext2_maybe_sanitize_pointer_continuation(
        buf, dind_blk, last_block=last_block, blksz=blksz
    )
    dind_off = dind_blk * blksz
    if dind_off + blksz > len(buf):
        return
    for i in range(0, blksz, 4):
        v = struct.unpack_from("<I", buf, dind_off + i)[0]
        if v == 0:
            continue
        sind = _ext2_decode_block_ptr(v, last_block)
        if sind != v:
            struct.pack_into("<I", buf, dind_off + i, sind)
        if 0 < sind <= last_block:
            _ext2_sanitize_singly_indirect_table(
                buf, sind, last_block=last_block, blksz=blksz
            )


def _ext2_sanitize_inode_indirect_chain(
    buf: bytearray, sb_off: int, i_block: bytes, *, last_block: int | None = None, blksz: int | None = None
) -> None:
    """
    Repair ``__le32`` pointer tables referenced by ``i_block[12..14]`` before kernel mapping.

    Ghidra ``ext2_get_branch`` @ ``0x8013cb50`` only does ``bswap32`` + zero check; it does not
    fix corrupt table cells. Offline dumps (and Dissect mount) need pointer **pages** scrubbed
    when a stored word is ``> last_block`` but decodes to a valid block (e.g. ``0x0100123d`` →
    block **4669**). This is dump repair, not PACE lag / sparse indirect / ``ff ac`` layout.
    """
    if len(i_block) < 60:
        return
    lb = last_block if last_block is not None else _ext2_last_block(buf, sb_off)
    if lb is None:
        return
    bs = blksz if blksz is not None else _ext2_block_size(buf, sb_off)
    blocks = struct.unpack_from("<15I", i_block[:60])
    if blocks[12]:
        sind = _ext2_decode_block_ptr(blocks[12], lb)
        if sind > 0:
            _ext2_sanitize_singly_indirect_table(buf, sind, last_block=lb, blksz=bs)
    if blocks[13]:
        dind = _ext2_decode_block_ptr(blocks[13], lb)
        if dind > 0:
            _ext2_sanitize_dind_pointer_page(buf, dind, last_block=lb, blksz=bs)
    if blocks[14]:
        tind = _ext2_decode_block_ptr(blocks[14], lb)
        if tind <= 0:
            return
        _ext2_sanitize_pointer_block(buf, tind, last_block=lb, blksz=bs)
        tind_off = tind * bs
        if tind_off + bs > len(buf):
            return
        for i in range(0, bs, 4):
            v = struct.unpack_from("<I", buf, tind_off + i)[0]
            if v == 0:
                continue
            dind = _ext2_decode_block_ptr(v, lb)
            if dind != v:
                struct.pack_into("<I", buf, tind_off + i, dind)
            if dind > 0:
                _ext2_sanitize_dind_pointer_page(buf, dind, last_block=lb, blksz=bs)


_EXT2_FT_TO_KIND = {
    1: "file",
    2: "dir",
    3: "link",
    4: "sock",
    5: "fifo",
    6: "other",
    7: "other",
}


def _ext2_direct_logical_block(raw_blk: int, *, last_block: int) -> int:
    """Kernel direct slot: stored ``__le32`` block number."""
    blk = _ext2_le32_block(raw_blk)
    if blk <= 0 or last_block <= 0 or blk > last_block:
        return 0
    return blk


# Ghidra ``ext2_block_to_path`` @ ``0x8013c9f0``: ``file_blk < 0xc`` → direct ``i_block[file_blk]``.
_EXT2_NDIR_BLOCKS_KERNEL = 12
_EXT2_FEATURE_INCOMPAT_HTREE = 0x2000000

# Exported for :mod:`boardfs.cmdb_extent_walker` (physical recovery, not kernel ext2).
_CMDB_HEADER_MARKERS = (b"<?xml", b"<?xll", b"<CM VERS")
_CMDB_XML_FOOTER = b"</ROOT></CM>"
_PACE_INDIRECT_HDR_MAGIC = b"\xff\xac"
_PACE_CMDB_HEADER_SCAN_BACK = 128


def _ext2_block_has_cmdb_header(chunk: bytes) -> bool:
    return any(m in chunk for m in _CMDB_HEADER_MARKERS)


def _ext2_addr_per_block_bits(blksz: int) -> int:
    """Kernel ``s_addr_per_block_bits`` = ``log2(ptrs_per_block)`` = ``log2(blksz/4)``."""
    ppb = blksz // 4
    if ppb <= 1:
        return 0
    return ppb.bit_length() - 1


def _ext2_block_to_path(
    file_blk: int,
    *,
    ptrs_per_block: int,
    addr_per_block_bits: int,
) -> tuple[list[int], int] | None:
    """
    Port of kernel ``ext2_block_to_path`` (532678 @ ``0x8013c9f0``).

    Uses ``s_addr_per_block_bits`` (``log2(ptrs_per_block)``), not ``s_log_block_size``.
    """
    if file_blk < 0 or ptrs_per_block <= 0:
        return None
    if file_blk < _EXT2_NDIR_BLOCKS_KERNEL:
        return ([file_blk], _EXT2_NDIR_BLOCKS_KERNEL - file_blk)
    n = file_blk - _EXT2_NDIR_BLOCKS_KERNEL
    if n < ptrs_per_block:
        return ([_EXT2_NDIR_BLOCKS_KERNEL, n], ptrs_per_block - n)
    n -= ptrs_per_block
    dind_span = 1 << ((addr_per_block_bits << 1) & 0x1F)
    if n < dind_span:
        return (
            [
                _EXT2_NDIR_BLOCKS_KERNEL + 1,
                n >> addr_per_block_bits,
                n & (ptrs_per_block - 1),
            ],
            dind_span - n,
        )
    n -= dind_span
    tind_span = ptrs_per_block * ptrs_per_block * ptrs_per_block
    if n < tind_span:
        return (
            [
                _EXT2_NDIR_BLOCKS_KERNEL + 2,
                n // (ptrs_per_block * ptrs_per_block),
                (n // ptrs_per_block) % ptrs_per_block,
                n % ptrs_per_block,
            ],
            tind_span - n,
        )
    return None


def _ext2_read_indirect_ptrs(
    buf: bytes | bytearray,
    ind_blk: int,
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
) -> list[int]:
    """Load single-indirect ``__le32[]`` from block start (kernel ``ext2_get_branch``)."""
    page = _ext2_fs_block(buf, ind_blk, access=access, blksz=blksz)
    ptrs: list[int] = []
    for i in range(blksz // 4):
        if i * 4 + 4 > len(page):
            break
        raw = struct.unpack_from("<I", page, i * 4)[0]
        if raw == 0:
            break
        blk = _ext2_branch_block_ptr(raw, last_block)
        if blk <= 0:
            break
        ptrs.append(blk)
    return ptrs


def _ext2_resolve_branch(
    buf: bytes | bytearray,
    ib: tuple[int, ...],
    path: list[int],
    *,
    last_block: int,
    blksz: int,
    access: Ext2VolumeAccess | None = None,
    kernel_exact: bool = False,
) -> int:
    """
    Walk ``ext2_get_branch`` (``0x8013cb50``): ``i_block[path[0]]`` then indirect slots.

    Ghidra: each level ``__bread`` uses ``bswap32`` on the stored ``__le32``; loop stops when
    the decoded pointer is **zero** only (no ``> last_block`` test in ``ext2_get_branch``).
    When ``kernel_exact`` is false, call :func:`_ext2_prepare_kernel_block_read` before
    mapping so scrubbed pointer pages match :func:`_ext2_branch_block_ptr` repair fallback.
    """
    if not path:
        return 0
    slot = path[0]
    if slot >= len(ib):
        return 0
    def _decode_ptr(raw: int) -> int:
        if kernel_exact:
            return _ext2_branch_block_ptr_kernel_exact(raw)
        return _ext2_branch_block_ptr(raw, last_block)

    block = _decode_ptr(int(ib[slot]))
    if block <= 0:
        return 0
    for idx in path[1:]:
        page = _ext2_fs_block(buf, block, access=access, blksz=blksz)
        off = idx * 4
        if off + 4 > len(page):
            return 0
        block = _decode_ptr(struct.unpack_from("<I", page, off)[0])
        if block <= 0:
            return 0
    return block


def _ext2_sanitize_i_block_bytes(i_block: bytes, *, last_block: int) -> bytes:
    """Repair tagged ``i_block[0..14]`` slot values (offline; not in ``ext2_get_branch``)."""
    ib = bytearray(i_block.ljust(60, b"\x00")[:60])
    for i in range(15):
        raw = struct.unpack_from("<I", ib, i * 4)[0]
        if not raw:
            continue
        fixed = _ext2_decode_block_ptr(raw, last_block)
        if fixed != raw:
            struct.pack_into("<I", ib, i * 4, fixed)
    return bytes(ib)


def _ext2_prepare_kernel_block_read(
    buf: bytes | bytearray,
    sb_off: int,
    i_block: bytes,
) -> tuple[bytearray, bytes]:
    """
    Mutable volume + repaired ``i_block`` for ``ext2_get_branch``.

    Returns ``(work, i_block_prepared)`` — map with ``i_block_prepared`` and read data
    from ``work`` (not ``Ext2VolumeAccess.slice_bytes``) so scrubbed tables are visible.
    """
    work = buf if isinstance(buf, bytearray) else bytearray(buf)
    lb = _ext2_last_block(work, sb_off)
    if lb is None or lb <= 0:
        return work, i_block
    ib_prep = _ext2_sanitize_i_block_bytes(i_block, last_block=lb)
    _ext2_sanitize_inode_indirect_chain(work, sb_off, ib_prep)
    return work, ib_prep


def _ext2_map_file_block(
    buf: bytes | bytearray,
    i_block: bytes,
    file_blk: int,
    *,
    last_block: int,
    blksz: int,
    addr_per_block_bits: int = 0,
    access: Ext2VolumeAccess | None = None,
    base_shift: int = 0,
    log_block_size: int = 0,
    kernel_exact: bool = False,
) -> int:
    """
    Map file-relative block index to a filesystem block (kernel ``ext2_get_block`` read path).

    ``base_shift`` / ``log_block_size`` are ignored (PACE recovery uses
    :mod:`boardfs.cmdb_extent_walker`).
    """
    del base_shift, log_block_size
    if file_blk < 0 or blksz <= 0 or last_block <= 0:
        return 0
    ib = struct.unpack_from("<15I", i_block.ljust(60, b"\x00")[:60])
    apb = addr_per_block_bits if addr_per_block_bits > 0 else _ext2_addr_per_block_bits(blksz)
    ptrs_per_block = blksz // 4
    path_result = _ext2_block_to_path(
        file_blk, ptrs_per_block=ptrs_per_block, addr_per_block_bits=apb
    )
    if path_result is None:
        return 0
    path, _ = path_result
    return _ext2_resolve_branch(
        buf,
        ib,
        path,
        last_block=last_block,
        blksz=blksz,
        access=access,
        kernel_exact=kernel_exact,
    )


def _ext2_read_file_bytes_kernel_exact(
    buf: bytes | bytearray,
    sb_off: int,
    i_block: bytes,
    size: int,
    *,
    access: Ext2VolumeAccess | None = None,
) -> bytes:
    """
    Read a regular file via stock kernel ``ext2_get_block`` (no sanitize/repair/PACE lag).

    Maps with raw on-disk ``i_block[]`` and indirect pages; uses :class:`Ext2VolumeAccess`
    for NTL chain replay when set.
    """
    lb = _ext2_last_block(buf, sb_off)
    blksz = _ext2_block_size(buf, sb_off)
    if lb is None or lb <= 0 or blksz <= 0 or size <= 0:
        return b""
    apb = _ext2_addr_per_block_bits(blksz)
    nblocks = (size + blksz - 1) // blksz
    parts: list[bytes] = []
    for idx in range(nblocks):
        bn = _ext2_map_file_block(
            buf,
            i_block,
            idx,
            last_block=lb,
            blksz=blksz,
            addr_per_block_bits=apb,
            access=access,
            kernel_exact=True,
        )
        if bn <= 0:
            parts.append(b"\x00" * blksz)
            continue
        parts.append(_ext2_fs_block(buf, bn, access=access, blksz=blksz))
    return b"".join(parts)[:size]


def _ext2_read_file_bytes(
    buf: bytes | bytearray,
    sb_off: int,
    i_block: bytes,
    size: int,
    *,
    i_blocks: int = 0,
    i_mode: int = 0,
    access: Ext2VolumeAccess | None = None,
    cmdb_recover: bool = False,
    extent_merge: bool = False,
    rel_path: str = "",
    live_inum: int = 0,
    oracle_body: bytes | None = None,
    shadow_promote: bool = False,
) -> bytes:
    """
    Read a regular file via kernel ``ext2_get_block`` mapping.

    Stops at ``i_size`` like ``generic_file_read``. Unmapped blocks are zero-filled (hole).
    Default path is :func:`_ext2_read_file_bytes_kernel_exact` (stock 12-direct + indirect,
    no sanitize/repair/13-direct PACE walker). ``cmdb_recover=True`` uses CMDB extent
    recovery; ``shadow_promote=True`` swaps stale live-map blocks from deleted orphan
    shadow inodes; ``extent_merge=True`` repairs stale install-image inode maps (pkgstream
    chunk oracle when ``oracle_body`` is set).
    """
    if cmdb_recover:
        from boardfs.cmdb_extent_walker import recover_cmdb_file_bytes

        return recover_cmdb_file_bytes(
            buf,
            sb_off,
            i_block,
            size,
            i_blocks=i_blocks,
            i_mode=i_mode,
            access=access,
        )
    if extent_merge and live_inum > 0:
        from boardfs.ext2_extent_merge import read_extent_merged_file_bytes

        return read_extent_merged_file_bytes(
            buf,
            sb_off,
            live_inum,
            i_block,
            size,
            rel_path=rel_path,
            i_blocks=i_blocks,
            i_mode=i_mode,
            access=access,
            oracle_body=oracle_body,
        )
    if shadow_promote and live_inum > 0:
        from boardfs.ext2_extent_merge import read_shadow_promoted_file_bytes

        return read_shadow_promoted_file_bytes(
            buf,
            sb_off,
            live_inum,
            i_block,
            size,
            access=access,
        )
    return _ext2_read_file_bytes_kernel_exact(
        buf, sb_off, i_block, size, access=access
    )


def ext2_file_map_report(
    buf: bytes | bytearray,
    sb_off: int,
    i_block: bytes,
    *,
    inum: int,
    rel_path: str,
    size: int,
    i_blocks: int = 0,
    max_blocks: int = 64,
) -> list[str]:
    """
    Human-readable block map (stock kernel ``ext2_get_block`` layout).

    Use from ``paceflash`` ``ext2map`` or tests. For CMDB physical recovery use
    ``paceflash cat --cmdb-recover`` / :mod:`boardfs.cmdb_extent_walker`.
    """
    lb = _ext2_last_block(buf, sb_off)
    blksz = _ext2_block_size(buf, sb_off)
    if lb is None or lb <= 0 or blksz <= 0:
        return [f"{rel_path}: invalid superblock"]
    apb = _ext2_addr_per_block_bits(blksz)
    ib = struct.unpack_from("<15I", i_block.ljust(60, b"\x00")[:60])
    nblocks = (size + blksz - 1) // blksz if size > 0 else 0
    lines: list[str] = [
        f"path={rel_path!r} inode={inum}",
        f"i_size={size} i_blocks={i_blocks} ({i_blocks * 512} byte sectors) "
        f"kernel_read_blocks={nblocks} blksz={blksz}",
        "layout: i_block[0..11] direct, [12] singly-indirect, [13] dind, [14] tind",
        "i_block on-disk (__le32 block numbers, kernel decode):",
    ]
    slot_names = (
        [f"direct[{i}]" for i in range(_EXT2_NDIR_BLOCKS_KERNEL)]
        + ["indirect[12]", "dind[13]", "tind[14]"]
    )
    for i, name in enumerate(slot_names):
        raw = ib[i] if i < len(ib) else 0
        dec = _ext2_le32_block(int(raw)) if raw else 0
        lines.append(f"  [{i:2d}] {name:16s} raw=0x{raw:08x} phys={dec}")
    ind = _ext2_le32_block(int(ib[12])) if ib[12] else 0
    if 0 < ind <= lb:
        ptrs = _ext2_read_indirect_ptrs(buf, ind, last_block=lb, blksz=blksz)
        lines.append(f"indirect table at phys {ind}: {len(ptrs)} pointers")
    show = min(nblocks, max(1, max_blocks)) if nblocks else max(1, max_blocks)
    if nblocks > show:
        lines.append(f"file blocks 0..{show - 1} (of {nblocks}; use ext2map -n {nblocks}):")
    else:
        lines.append(f"file blocks 0..{show - 1}:")
    markers = (b"<?xml", b"</CM>", b"</CM></ROOT>", b"scheduler0:days")
    for fb in range(show):
        phys = _ext2_map_file_block(
            buf,
            i_block,
            fb,
            last_block=lb,
            blksz=blksz,
            addr_per_block_bits=apb,
            kernel_exact=True,
        )
        flags: list[str] = []
        if phys <= 0:
            flags.append("hole")
        else:
            chunk = _ext2_fs_block(buf, phys, access=None, blksz=blksz)
            if sum(1 for b in chunk if b) < 32:
                flags.append("sparse")
            for m in markers:
                if m in chunk:
                    flags.append(m.decode(errors="replace"))
        role = "direct" if fb < _EXT2_NDIR_BLOCKS_KERNEL else f"indirect#{fb - _EXT2_NDIR_BLOCKS_KERNEL}"
        lines.append(
            f"  fb {fb:4d} ({role:12s}) -> phys {phys:6d}"
            + (f"  [{', '.join(flags)}]" if flags else "")
        )
    if size > 0:
        probe = _ext2_read_file_bytes(buf, sb_off, i_block, size)
        nz_end = len(probe.rstrip(b"\x00"))
        lines.append(
            f"kernel read: {len(probe)} bytes, last non-zero at offset {nz_end - 1 if nz_end else 0}"
        )
    return lines


def _ext2_dir_data_block_for_inode(
    buf: bytes | bytearray,
    raw_blk: int,
    *,
    dir_inum: int,
    last_block: int,
    blksz: int,
    inodes_count: int,
    i_blocks: int = 0,
    i_mode: int = 0,
    cmdb_recover: bool = False,
) -> int:
    """
    Resolve the filesystem block that holds a directory's ``.`` dentry.

    Starts from ``decode(i_block[0])``; if that block has no ``.`` → ``dir_inum``,
    applies lag / ``+2`` adjustment (same rules as :func:`recover_cmdb_dir_data_block`).
    """
    del cmdb_recover
    from boardfs.cmdb_extent_walker import recover_cmdb_dir_data_block

    return recover_cmdb_dir_data_block(
        buf,
        raw_blk,
        dir_inum=dir_inum,
        last_block=last_block,
        blksz=blksz,
        inodes_count=inodes_count,
        i_blocks=i_blocks,
        i_mode=i_mode,
    )


def _ext2_dir_blocks_bytes(
    slice_view: bytes,
    i_block: bytes,
    *,
    dir_size: int,
    last_block: int,
    blksz: int,
    dir_inum: int = 0,
    inodes_count: int = 0,
    i_blocks: int = 0,
    i_mode: int = 0,
    access: Ext2VolumeAccess | None = None,
    cmdb_recover: bool = False,
) -> bytes:
    """Read directory via kernel direct ``i_block[0..11]`` (``ext2_get_block``)."""
    ib = struct.unpack_from("<15I", i_block.ljust(60, b"\x00")[:60])
    parts: list[bytes] = []
    for raw_blk in ib[:_EXT2_NDIR_BLOCKS_KERNEL]:
        if raw_blk == 0:
            break
        if dir_inum > 0 and inodes_count > 0:
            blk = _ext2_dir_data_block_for_inode(
                slice_view,
                raw_blk,
                dir_inum=dir_inum,
                last_block=last_block,
                blksz=blksz,
                inodes_count=inodes_count,
                i_blocks=i_blocks,
                i_mode=i_mode,
                cmdb_recover=cmdb_recover,
            )
        else:
            blk = _ext2_direct_logical_block(raw_blk, last_block=last_block)
        if blk <= 0:
            continue
        parts.append(_ext2_fs_block(slice_view, blk, access=access, blksz=blksz))
    if not parts:
        return b""
    data = b"".join(parts)
    return data[:dir_size] if dir_size > 0 else data


def _ext2_dentry_inodes_cap(inodes_count: int, *, hint_inum: int = 0) -> int:
    """Inode ceiling for dentry scans (PACE sb may under-report ``s_inodes_count``)."""
    cap = inodes_count if inodes_count > 11 else 2**31 - 1
    if hint_inum > 0 and cap <= hint_inum:
        cap = hint_inum + 1
    return cap


def _ext2_dir_block_has_dot_entry(
    blk: bytes,
    inum: int,
    *,
    inodes_count: int,
) -> bool:
    """True when a directory block contains a ``.`` dentry for ``inum`` (any offset)."""
    if not blk or not any(blk):
        return False
    cap = _ext2_dentry_inodes_cap(inodes_count, hint_inum=inum)
    ents = _ext2_parse_dir_entry(blk, inodes_count=cap, cap=512, htree=False)
    return any(ino == inum and name == "." for ino, name, _ft in ents)


def _ext2_parse_dir_entry_2(
    data: bytes,
    *,
    inodes_count: int,
    cap: int = 4096,
) -> list[tuple[int, str, int]]:
    """Return ``(inode, name, file_type)`` from ext2_dir_entry_2 bytes."""
    out: list[tuple[int, str, int]] = []
    offset = 0
    limit = len(data)
    while offset + 8 <= limit and len(out) < cap:
        inode, rec_len, name_len, file_type = struct.unpack_from("<IHBB", data, offset)
        if rec_len == 0:
            break
        if rec_len < 8 or offset + rec_len > limit:
            break
        name = data[offset + 8 : offset + 8 + name_len].decode(errors="surrogateescape")
        if 0 < inode < inodes_count and name:
            out.append((inode, name, int(file_type)))
        offset += rec_len
    return out


def _ext2_feature_htree(buf: bytes | bytearray, sb_off: int = _EXT2_SB0_OFF) -> bool:
    """True when ``feature_incompat`` has ``EXT4_FEATURE_INCOMPAT_LARGEDIR`` (htree / dir_entry_2)."""
    if sb_off + 100 > len(buf):
        return False
    return bool(struct.unpack_from("<I", buf, sb_off + 96)[0] & _EXT2_FEATURE_INCOMPAT_HTREE)


def _ext2_parse_dir_entry(
    data: bytes,
    *,
    inodes_count: int,
    cap: int = 4096,
    htree: bool = False,
) -> list[tuple[int, str, int]]:
    """
    Parse directory bytes (``ext2_readdir`` @ ``0x8013a0d8``).

    When htree is off (this opentla4 volume), use classic ``ext2_dir_entry`` (v1). v2-first
    mis-parses block 66 root dirents where ``name_len`` is u16.
    """
    if htree:
        v2 = _ext2_parse_dir_entry_2(data, inodes_count=inodes_count, cap=cap)
        if (
            len(v2) >= 2
            and v2[0][0] == 2
            and v2[0][1] == "."
            and v2[1][0] == 2
            and v2[1][1] == ".."
        ):
            return v2
    out: list[tuple[int, str, int]] = []
    offset = 0
    limit = len(data)
    while offset + 8 <= limit and len(out) < cap:
        inode, rec_len = struct.unpack_from("<IH", data, offset)
        if rec_len == 0:
            break
        if rec_len < 8 or offset + rec_len > limit:
            break
        # ``ext2_readdir`` v1: ``name_len`` is u8 at +6, name at +8 (not u16 ``IHH``).
        name_len = data[offset + 6]
        name = data[offset + 8 : offset + 8 + name_len].decode(errors="surrogateescape")
        if 0 < inode < inodes_count and name:
            ft = 2 if name not in (".", "..") else 0
            out.append((inode, name, ft))
        offset += rec_len
    if out and out[0][1] in (".", ".."):
        return out
    if htree:
        v2 = _ext2_parse_dir_entry_2(data, inodes_count=inodes_count, cap=cap)
        return v2 if v2 else out
    return out


_EXT2_VALID_MODE_NIBBLES = frozenset(
    (0x1000, 0x2000, 0x4000, 0x6000, 0x8000, 0xA000, 0xC000)
)


def _ext2_valid_inode_mode(mode: int) -> bool:
    return (mode & 0xF000) in _EXT2_VALID_MODE_NIBBLES


def _ext2_volume_uses_pace_inode_layout(buf: bytes | bytearray, sb_off: int = _EXT2_SB0_OFF) -> bool:
    """
    True for opentla4 product captures where ``s_inode_size`` / ``s_first_ino`` are zero
    in the on-disk superblock (kernel substitutes 128 / 11 at mount).
    """
    if sb_off + 90 > len(buf):
        return False
    if buf[sb_off + _EXT2_SB_MAGIC_OFF : sb_off + _EXT2_SB_MAGIC_OFF + 2] != _EXT2_MAGIC_LE:
        return False
    return struct.unpack_from("<H", buf, sb_off + 88)[0] == 0


def _ext2_sb_fields(buf: bytes | bytearray, sb_off: int = _EXT2_SB0_OFF) -> dict[str, int]:
    first_ino = struct.unpack_from("<I", buf, sb_off + 84)[0]
    if first_ino == 0:
        first_ino = _EXT2_DEFAULT_FIRST_INO
    inode_size = struct.unpack_from("<H", buf, sb_off + 88)[0]
    if inode_size == 0:
        inode_size = _EXT2_DEFAULT_INODE_SIZE
    return {
        "first_ino": first_ino,
        "inodes_per_group": struct.unpack_from("<I", buf, sb_off + 40)[0],
        "inodes_count": struct.unpack_from("<I", buf, sb_off + 0)[0],
        "blksz": _ext2_block_size(buf, sb_off),
        "inode_size": inode_size,
        "last_block": _ext2_last_block(buf, sb_off) or 0,
    }


def _ext2_inode_table_entry(
    buf: bytes | bytearray,
    sb_off: int,
    inum: int,
) -> tuple[int, int, int, int] | None:
    """Return ``(itbl_block, index, inode_size, blksz)`` for inode ``inum``."""
    fields = _ext2_sb_fields(buf, sb_off)
    ipg = fields["inodes_per_group"]
    blksz = fields["blksz"]
    inode_size = fields["inode_size"]
    last_block = fields["last_block"]
    if ipg == 0 or last_block <= 0 or inum < 1:
        return None
    group = (inum - 1) // ipg
    index = (inum - 1) % ipg
    gd_off = _EXT2_SB0_OFF + blksz + group * 32
    if gd_off + 12 > len(buf):
        return None
    itbl = _ext2_decode_block_ptr(
        struct.unpack_from("<I", buf, gd_off + 8)[0], last_block
    )
    if itbl <= 0:
        return None
    return itbl, index, inode_size, blksz


def _ext2_inode_record_bytes(
    buf: bytes | bytearray,
    sb_off: int,
    inum: int,
    *,
    access: Ext2VolumeAccess | None = None,
) -> bytes | None:
    """Raw inode record (``inode_size`` bytes) via assembled slice or ``access`` block I/O."""
    entry = _ext2_inode_table_entry(buf, sb_off, inum)
    if entry is None:
        return None
    itbl, index, inode_size, blksz = entry
    linear_off = itbl * blksz + index * inode_size

    def _read_at(linear: int, n: int) -> bytes | None:
        block_num = linear // blksz
        off_in = linear % blksz
        if access is not None:
            chunk = _ext2_fs_block(buf, block_num, access=access, blksz=blksz)
        else:
            off = block_num * blksz
            if off + blksz > len(buf):
                return None
            chunk = bytes(buf[off : off + blksz])
        if off_in + n <= len(chunk):
            return chunk[off_in : off_in + n]
        head = chunk[off_in:]
        tail = _read_at((block_num + 1) * blksz, n - len(head))
        if tail is None:
            return None
        return head + tail

    if access is None and linear_off + inode_size > len(buf):
        return None
    return _read_at(linear_off, inode_size)


def _ext2_inode_byte_offset(
    buf: bytes | bytearray,
    sb_off: int,
    inum: int,
) -> int | None:
    """
    Byte offset of inode ``inum`` in the assembled slice (``ext2_get_inode`` layout).

    Group = ``(inode - 1) // inodes_per_group``; index = ``(inode - 1) % inodes_per_group``;
    table block = ``bg_inode_table`` at GD offset **+8** (not ``+0``).
    """
    entry = _ext2_inode_table_entry(buf, sb_off, inum)
    if entry is None:
        return None
    itbl, index, inode_size, blksz = entry
    off = itbl * blksz + index * inode_size
    if off + 60 > len(buf):
        return None
    return off


def _ext2_read_inode_fields(
    buf: bytes | bytearray,
    sb_off: int,
    inum: int,
    *,
    access: Ext2VolumeAccess | None = None,
) -> tuple[int, int, bytes] | None:
    """Return ``(i_mode, i_size, i_block[:60])`` for ``inum`` (Linux ``ext2_get_inode``)."""
    rec = _ext2_inode_record_bytes(buf, sb_off, inum, access=access)
    if rec is None:
        return None
    mode = struct.unpack_from("<H", rec, 0)[0]
    if not _ext2_valid_inode_mode(mode):
        return None
    size = struct.unpack_from("<I", rec, 4)[0]
    if size > 0x10000000:
        return None
    i_block = bytes(rec[40:100])
    fields = _ext2_sb_fields(buf, sb_off)
    blk0 = struct.unpack_from("<I", i_block, 0)[0]
    if blk0 and _ext2_decode_block_ptr(blk0, fields["last_block"]) <= 0:
        return None
    return mode, size, i_block


def _ext2_read_inode_i_blocks(
    buf: bytes | bytearray,
    sb_off: int,
    inum: int,
    *,
    access: Ext2VolumeAccess | None = None,
) -> int:
    rec = _ext2_inode_record_bytes(buf, sb_off, inum, access=access)
    if rec is None or len(rec) < 32:
        return 0
    return int(struct.unpack_from("<I", rec, 28)[0])


def _ext2_dir_data_opaque(data: bytes, *, htree: bool = False) -> bool:
    """True when a directory block has payload but no valid ``ext2_dir_entry`` chain."""
    if not data or not any(data):
        return False
    if _ext2_parse_dir_entry(data[:4096], inodes_count=2**31 - 1, cap=4, htree=htree):
        return False
    return True


def _ext2_prepare_volume(buf: bytearray, sb_off: int = _EXT2_SB0_OFF) -> None:
    _ext2_normalize_superblock_for_dissect(buf, sb_off)
    _ext2_sanitize_group_descriptors(buf, sb_off)


def _ext2_open_dissect(data: bytes, sb_off: int):
    from dissect.extfs import ExtFS

    delta = sb_off - _EXT2_SB0_OFF
    if delta == 0:
        work = bytearray(data)
    elif delta > 0:
        work = bytearray(data[delta:])
    else:
        work = bytearray(b"\x00" * (-delta) + data)
    _ext2_prepare_volume(work, _EXT2_SB0_OFF)
    return ExtFS(io.BytesIO(bytes(work)))
#endregion


#region hypothesis_only ext2_ef53_signature_grep
def find_ext2_superblock_offsets(data: bytes, *, max_hits: int = 16) -> list[int]:
    out: list[int] = []
    pos = 0
    while len(out) < max_hits:
        idx = data.find(_EXT2_MAGIC_LE, pos)
        if idx < 0:
            break
        sb = idx - _EXT2_SB_MAGIC_OFF
        if sb >= 0 and sb + _EXT2_SB0_OFF + 2 <= len(data):
            if sb not in out:
                out.append(sb)
        pos = idx + 1
    return sorted(out)
#endregion


#region kernel_adjacent opentla4_product_superblock_offsets
# Product layout: s_magic @ OPENTLA4_EXT2_MAGIC_OFF (0x438), primary sb @ 1024; see reference/opentl.md.
def _ext2_mounts_at(data: bytes, sb_off: int) -> bool:
    try:
        fs = _ext2_open_dissect(data, sb_off)
        if not stat.S_ISDIR(fs.root.inode.i_mode):
            return False
        names = [n for n in fs.root.listdir() if n not in (".", "..")]
        return bool(names)
    except Exception:
        return False


def ext2_superblock_try_offsets(data: bytes) -> list[int]:
    sb0 = OPENTLA4_EXT2_MAGIC_OFF - _EXT2_SB_MAGIC_OFF
    product = [
        sb0 if sb0 != _EXT2_SB0_OFF else _EXT2_SB0_OFF,
        0,
    ]
    if sb0 != _EXT2_SB0_OFF and _EXT2_SB0_OFF not in product:
        product.insert(1, _EXT2_SB0_OFF)
    out: list[int] = []
    seen: set[int] = set()
    for off in product:
        if off < 0 or off in seen:
            continue
        if off + _EXT2_SB_MAGIC_OFF + 2 > len(data):
            continue
        seen.add(off)
        out.append(off)
    return out
#endregion


def resolve_mountable_ext2_superblock_offset(data: bytes) -> int | None:
    for off in ext2_superblock_try_offsets(data):
        if _ext2_mounts_at(data, off):
            return off
    return None


#region kernel_adjacent ext2_dissect_mount
def list_root_for_block_dev_with_meta(
    dev: BlockSlice, *, cap: int = 50, sb_off: int | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    data = dev.read_slice()
    last_err: Exception | None = None
    candidates = [sb_off] if sb_off is not None else ext2_superblock_try_offsets(data)
    for off in candidates:
        if off is None or off < 0:
            continue
        try:
            fs = _ext2_open_dissect(data, off)
            root = fs.root
            if not stat.S_ISDIR(root.inode.i_mode):
                continue
            rows: list[dict[str, Any]] = []
            for name, node in sorted(root.listdir().items(), key=lambda kv: kv[0]):
                if name in (".", ".."):
                    continue
                rows.append(
                    {
                        "name": name,
                        "inode": node.inum,
                        "file_type": stat.filemode(node.inode.i_mode),
                    }
                )
                if len(rows) >= cap:
                    break
            return rows, {"ext2_superblock_offset": off}
        except Exception as e:
            last_err = e
            continue
    if last_err is not None:
        raise last_err
    raise ValueError("Not a valid ExtFS filesystem (magic mismatch)")


def list_root_for_block_dev(dev: BlockSlice, *, cap: int = 50) -> list[dict[str, Any]]:
    rows, _meta = list_root_for_block_dev_with_meta(dev, cap=cap)
    return rows
#endregion
