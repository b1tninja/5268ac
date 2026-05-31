"""
Shadow-inode promotion for stale PACE opentla4 ext2 reads.

When a botched deferred promote leaves correct payload clusters on disk but the
linked dentry inode still maps stale phys blocks, prefer deleted-orphan shadow
inode phys blocks where the live map reads a stale assembled OpenTL cluster.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Any

from boardfs.ext2_dissect import (
    _EXT2_NDIR_BLOCKS_KERNEL,
    _ext2_addr_per_block_bits,
    _ext2_block_size,
    _ext2_fs_block,
    _ext2_last_block,
    _ext2_map_file_block,
    _ext2_prepare_kernel_block_read,
    _ext2_read_inode_fields,
    _ext2_sb_fields,
)
from boardfs.ext2_volume_io import Ext2VolumeAccess

__all__ = [
    "read_shadow_promoted_file_bytes",
    "stale_assembled_live_block",
]

# PACE opentla4 captures store the post-unlink timestamp at ``i_mtime`` (off +20);
# ``debugfs stat`` labels the same field ``dtime`` on deleted orphans (inode 993).
_PACE_DELETED_TIME_OFF = 20


@dataclass(frozen=True)
class _InodeMap:
    inum: int
    size: int
    mtime: int
    links: int
    i_block: bytes


def _inode_meta(buf: bytes | bytearray, sb_off: int, inum: int) -> _InodeMap | None:
    off = _ext2_inode_byte_offset(buf, sb_off, inum)
    if off is None:
        return None
    fields = _ext2_read_inode_fields(buf, sb_off, inum)
    if fields is None:
        return None
    mode, size, i_block = fields
    if (mode & 0xF000) != 0x8000:
        return None
    links = struct.unpack_from("<H", buf, off + 26)[0]
    mtime = struct.unpack_from("<I", buf, off + 20)[0]
    return _InodeMap(
        inum=inum,
        size=size,
        mtime=mtime,
        links=links,
        i_block=i_block,
    )


def _ext2_inode_byte_offset(buf: bytes | bytearray, sb_off: int, inum: int) -> int | None:
    from boardfs.ext2_dissect import _ext2_inode_byte_offset as _off

    return _off(buf, sb_off, inum)


def _inode_deleted_time(buf: bytes | bytearray, sb_off: int, inum: int) -> int:
    off = _ext2_inode_byte_offset(buf, sb_off, inum)
    if off is None:
        return 0
    return int(struct.unpack_from("<I", buf, off + _PACE_DELETED_TIME_OFF)[0])


def _promote_split_detected(live_i_block: bytes, shadow_i_block: bytes) -> bool:
    live_direct = struct.unpack_from("<12I", live_i_block.ljust(48, b"\x00")[:48])
    shadow_direct = struct.unpack_from("<12I", shadow_i_block.ljust(48, b"\x00")[:48])
    return live_direct != shadow_direct


def _live_phys_invalid(phys: int, last_block: int) -> bool:
    return phys <= 0 or phys > last_block


def _fs_block_stale(
    access: Ext2VolumeAccess,
    *,
    fs_block_num: int,
    assembled_chunk: bytes | None = None,
    gvirt: int | None = None,
) -> bool:
    """Content-neutral stale cluster check at an inode virt site (defaults to *fs_block_num*)."""
    from boardfs.tag64_carrier import read_slice_block
    from opentl.pace_cluster import (
        stale_assembled_cluster_at_fs_block,
        stale_assembled_cluster_at_gvirt,
    )

    if access.ntl is None or fs_block_num <= 0:
        return False
    chunk = (
        assembled_chunk
        if assembled_chunk is not None
        else read_slice_block(access, fs_block_num)
    )
    if gvirt is not None:
        return stale_assembled_cluster_at_gvirt(
            assembled_chunk=chunk,
            linear_prefix=access.ntl.session.linear_prefix,
            block_map=access.ntl.block_map,
            gvirt=int(gvirt),
            blksz=int(access.blksz),
        )
    return stale_assembled_cluster_at_fs_block(
        assembled_chunk=chunk,
        linear_prefix=access.ntl.session.linear_prefix,
        block_map=access.ntl.block_map,
        virt_byte_start=int(access.ntl.virt_byte_start),
        fs_block_num=int(fs_block_num),
        blksz=int(access.blksz),
    )


def _live_direct_run_skip(
    live_i_block: bytes,
    *,
    access: Ext2VolumeAccess | None,
    last_block: int,
    live_gvirt_for_fb0: int | None = None,
) -> int:
    """
    Leading junk direct slots before the real file-block-0 cluster (botched promote).

    Walk live ``direct[]`` against the tag-64 BBM/+2048 carrier sites at the **live
    inode** virt for file block 0 — same gvirt key used by read overlays. Skip past
    stale-assembled slots and unrelated clusters until the assembled chunk matches
    the ``+2048`` carrier at that site.
    """
    from boardfs.ext2_dissect import _ext2_le32_block
    from boardfs.tag64_carrier import read_slice_block
    from opentl.pace_cluster import bbm_and_plus_chunks_at_gvirt

    direct = [_ext2_le32_block(int(raw)) for raw in struct.unpack_from("<12I", live_i_block.ljust(48, b"\x00")[:48])]
    if access is None or access.ntl is None or live_gvirt_for_fb0 is None:
        return 0
    gvirt0 = int(live_gvirt_for_fb0)
    sites = bbm_and_plus_chunks_at_gvirt(
        access.ntl.session.linear_prefix,
        access.ntl.block_map,
        gvirt0,
        blksz=int(access.blksz),
    )
    if sites is None:
        return 0
    bbm_chunk, plus_chunk = sites
    for skip in range(_EXT2_NDIR_BLOCKS_KERNEL):
        if skip >= len(direct):
            break
        phys = direct[skip]
        if _live_phys_invalid(phys, last_block):
            continue
        chunk = read_slice_block(access, phys)
        if chunk == plus_chunk:
            return skip
        if chunk == bbm_chunk and chunk != plus_chunk:
            continue
        if skip == 0:
            return 0
        continue
    return 0


def _live_direct_anchor_phys(
    live_i_block: bytes,
    *,
    access: Ext2VolumeAccess | None,
    last_block: int,
    live_gvirt_for_fb0: int | None = None,
) -> int | None:
    """First cluster in the live direct run after a botched-promote skip prefix."""
    from boardfs.ext2_dissect import _ext2_le32_block

    skip = _live_direct_run_skip(
        live_i_block,
        access=access,
        last_block=last_block,
        live_gvirt_for_fb0=live_gvirt_for_fb0,
    )
    if skip <= 0:
        head = _ext2_le32_block(int(struct.unpack_from("<I", live_i_block.ljust(48, b"\x00")[:48], 0)[0]))
        return head if not _live_phys_invalid(head, last_block) else None
    direct = [_ext2_le32_block(int(raw)) for raw in struct.unpack_from("<12I", live_i_block.ljust(48, b"\x00")[:48])]
    phys = direct[skip]
    return phys if not _live_phys_invalid(phys, last_block) else None


def _apply_direct_run_skip(
    merged: list[int],
    live_i_block: bytes,
    *,
    access: Ext2VolumeAccess | None,
    last_block: int,
    live_gvirt_for_fb0: int | None = None,
) -> None:
    """Remap direct file blocks through the detected live ``i_block`` skip prefix."""
    from boardfs.ext2_dissect import _ext2_le32_block

    skip = _live_direct_run_skip(
        live_i_block,
        access=access,
        last_block=last_block,
        live_gvirt_for_fb0=live_gvirt_for_fb0,
    )
    if skip <= 0:
        return
    direct = [_ext2_le32_block(int(raw)) for raw in struct.unpack_from("<12I", live_i_block.ljust(48, b"\x00")[:48])]
    for fb in range(min(_EXT2_NDIR_BLOCKS_KERNEL - skip, len(merged))):
        phys = direct[fb + skip]
        if _live_phys_invalid(phys, last_block):
            continue
        merged[fb] = phys


def _invalid_live_shadow_promoted_fbs(
    live_map: list[int],
    shadow_map: list[int],
    merged: list[int],
    *,
    last_block: int,
) -> list[int]:
    out: list[int] = []
    for fb, (live_phys, shadow_phys) in enumerate(zip(live_map, shadow_map)):
        if shadow_phys <= 0 or live_phys == shadow_phys:
            continue
        if not _live_phys_invalid(live_phys, last_block):
            continue
        if merged[fb] == shadow_phys:
            out.append(fb)
    return out


def _refine_invalid_live_shadow_phys(
    merged: list[int],
    *,
    live_map: list[int],
    shadow_map: list[int],
    invalid_live_promoted: list[int],
    anchor_phys: int | None,
    access: Ext2VolumeAccess,
    last_block: int,
    blksz: int,
) -> None:
    """
    Fix shadow indirect single-slot skew against the live direct anchor run.

    When the assembled slice holds the same cluster bytes at ``shadow_phys`` and
    ``anchor + fb - 1`` but tag-64 overlays keyed on each fs block disagree, prefer
    the anchor-run phys (correct inode virt site). Singly-indirect shadow slots that
    already read correctly are left unchanged.
    """
    from boardfs.tag64_carrier import read_slice_block

    if anchor_phys is None or not invalid_live_promoted:
        return
    del blksz, live_map
    anchor = int(anchor_phys)
    for fb in invalid_live_promoted:
        shadow_phys = int(shadow_map[fb])
        if shadow_phys <= 0 or shadow_phys > last_block:
            continue
        alt = anchor + int(fb) - 1
        if _live_phys_invalid(alt, last_block):
            continue
        if _fs_block_stale(access, fs_block_num=alt):
            continue
        shadow_asm = read_slice_block(access, shadow_phys)
        alt_asm = read_slice_block(access, alt)
        prefix = 0
        for left, right in zip(shadow_asm, alt_asm):
            if left != right:
                break
            prefix += 1
        if prefix < len(shadow_asm) // 2:
            continue
        shadow_read = _read_by_block_map(
            access.slice_bytes,
            [shadow_phys],
            size=len(shadow_asm),
            blksz=len(shadow_asm),
            access=access,
            live_phys_per_fb=[shadow_phys],
            tag64_carrier=True,
            last_block=last_block,
        )
        alt_read = _read_by_block_map(
            access.slice_bytes,
            [alt],
            size=len(alt_asm),
            blksz=len(alt_asm),
            access=access,
            live_phys_per_fb=[alt],
            tag64_carrier=True,
            last_block=last_block,
        )
        if shadow_read != alt_read:
            merged[fb] = int(alt)


def stale_assembled_live_block(
    *,
    access: Ext2VolumeAccess,
    linear_prefix: bytes,
    block_map: Any,
    virt_byte_start: int,
    kernel_phys: int,
) -> bool:
    """Backward-compatible wrapper around :mod:`opentl.pace_cluster`."""
    from boardfs.tag64_carrier import read_slice_block
    from opentl.pace_cluster import stale_assembled_cluster_at_fs_block

    if kernel_phys <= 0 or access.ntl is None:
        return False
    return stale_assembled_cluster_at_fs_block(
        assembled_chunk=read_slice_block(access, kernel_phys),
        linear_prefix=linear_prefix,
        block_map=block_map,
        virt_byte_start=int(virt_byte_start),
        fs_block_num=int(kernel_phys),
        blksz=int(access.blksz),
    )


def _merge_shadow_promote_block_map(
    live_map: list[int],
    shadow_map: list[int],
    *,
    buf: bytes | bytearray,
    sb_off: int,
    live_i_block: bytes,
    shadow_i_block: bytes,
    shadow_inum: int,
    access: Ext2VolumeAccess | None,
    last_block: int | None = None,
) -> list[int]:
    """Prefer deleted-orphan shadow phys blocks where live map hits a stale assembled cluster."""
    lb = last_block
    if lb is None:
        lb = _ext2_last_block(buf, sb_off)
    if lb is None or lb <= 0:
        lb = 0
    merged = list(live_map)
    if access is None or access.ntl is None:
        for fb, (live_phys, shadow_phys) in enumerate(zip(live_map, shadow_map)):
            if shadow_phys <= 0 or live_phys == shadow_phys:
                continue
            if _live_phys_invalid(live_phys, lb) and 0 < shadow_phys <= lb:
                merged[fb] = shadow_phys
        return merged

    shadow_ok = (
        _promote_split_detected(live_i_block, shadow_i_block)
        and _inode_deleted_time(buf, sb_off, shadow_inum) != 0
    )
    off = _ext2_inode_byte_offset(buf, sb_off, shadow_inum)
    if shadow_ok and off is not None and struct.unpack_from("<H", buf, off + 26)[0] == 0:
        linear_prefix = access.ntl.session.linear_prefix
        block_map = access.ntl.block_map
        virt_start = int(access.ntl.virt_byte_start)
        for fb, (live_phys, shadow_phys) in enumerate(zip(live_map, shadow_map)):
            if shadow_phys <= 0 or live_phys == shadow_phys:
                continue
            from boardfs.tag64_carrier import (
                _bbm_plus_chunks_at_gvirt,
                read_slice_block,
                tag64_spare_at_page,
            )

            live_raw = read_slice_block(access, live_phys)
            shadow_raw = read_slice_block(access, shadow_phys)
            gvirt = virt_start + live_phys * int(access.blksz)
            sites = _bbm_plus_chunks_at_gvirt(access, gvirt)
            if sites is not None:
                _bbm, plus_chunk, phys_blk, ppage = sites
                tag64 = tag64_spare_at_page(access, phys_blk, ppage) or (
                    ppage > 0 and tag64_spare_at_page(access, phys_blk, ppage - 1)
                )
                if tag64 and shadow_raw == plus_chunk and live_raw != shadow_raw:
                    merged[fb] = shadow_phys
                    continue
            from opentl.pace_cluster import stale_assembled_cluster_at_gvirt

            live_gvirt = virt_start + int(live_map[fb]) * int(access.blksz)
            if stale_assembled_cluster_at_gvirt(
                assembled_chunk=live_raw,
                linear_prefix=linear_prefix,
                block_map=block_map,
                gvirt=live_gvirt,
                blksz=int(access.blksz),
            ):
                merged[fb] = shadow_phys
                continue

    for fb, (live_phys, shadow_phys) in enumerate(zip(live_map, shadow_map)):
        if shadow_phys <= 0 or live_phys == shadow_phys:
            continue
        if _live_phys_invalid(live_phys, lb) and 0 < shadow_phys <= lb:
            merged[fb] = shadow_phys
    return merged


def _shadow_inodes(
    buf: bytes | bytearray,
    sb_off: int,
    *,
    live_inum: int,
    live_size: int,
) -> list[_InodeMap]:
    """Unlinked regular files in the same size class (``dtime`` may be 0 after boot ``e2fsck``)."""
    fields = _ext2_sb_fields(buf, sb_off)
    cap = int(fields.get("inodes_count") or 0)
    if cap <= 1:
        return []
    tol = max(4096, live_size // 512)
    shadows: list[_InodeMap] = []
    for inum in range(1, cap):
        if inum == live_inum:
            continue
        meta = _inode_meta(buf, sb_off, inum)
        if meta is None:
            continue
        if meta.links != 0:
            continue
        if abs(meta.size - live_size) > tol:
            continue
        shadows.append(meta)
    shadows.sort(
        key=lambda m: (_inode_deleted_time(buf, sb_off, m.inum), m.mtime, m.inum),
        reverse=True,
    )
    return shadows


def _map_all_file_blocks(
    work: bytearray,
    sb_off: int,
    i_block: bytes,
    nblocks: int,
    *,
    blksz: int,
    lb: int,
    kernel_exact: bool = False,
    access: Ext2VolumeAccess | None = None,
) -> list[int]:
    if kernel_exact:
        ib = i_block
    else:
        _, ib = _ext2_prepare_kernel_block_read(work, sb_off, i_block)
    apb = _ext2_addr_per_block_bits(blksz)
    out: list[int] = []
    for fb in range(nblocks):
        bn = _ext2_map_file_block(
            work,
            ib,
            fb,
            last_block=lb,
            blksz=blksz,
            addr_per_block_bits=apb,
            access=access,
            kernel_exact=kernel_exact,
        )
        out.append(bn)
    return out


def _path_to_file_block(path: list[int], *, ptrs_per_block: int) -> int | None:
    """Inverse of kernel ``ext2_block_to_path`` (direct + singly/doubly/triply indirect)."""
    if not path:
        return None
    if len(path) == 1 and path[0] < _EXT2_NDIR_BLOCKS_KERNEL:
        return path[0]
    if len(path) == 2 and path[0] == _EXT2_NDIR_BLOCKS_KERNEL:
        return _EXT2_NDIR_BLOCKS_KERNEL + path[1]
    if len(path) == 3 and path[0] == _EXT2_NDIR_BLOCKS_KERNEL + 1:
        return _EXT2_NDIR_BLOCKS_KERNEL + ptrs_per_block + path[1] * ptrs_per_block + path[2]
    if len(path) == 4 and path[0] == _EXT2_NDIR_BLOCKS_KERNEL + 2:
        tind_span = ptrs_per_block * ptrs_per_block * ptrs_per_block
        n = path[3] + path[2] * ptrs_per_block + path[1] * ptrs_per_block * ptrs_per_block
        return _EXT2_NDIR_BLOCKS_KERNEL + ptrs_per_block + ptrs_per_block * ptrs_per_block + n
    return None


def _read_by_block_map(
    buf: bytes | bytearray,
    phys_per_fb: list[int],
    *,
    size: int,
    blksz: int,
    access: Ext2VolumeAccess | None,
    live_phys_per_fb: list[int] | None = None,
    tag64_carrier: bool = False,
    last_block: int | None = None,
) -> bytes:
    from boardfs.tag64_carrier import (
        read_slice_block,
        tag64_cross_erase_next_vblk_for_gvirt,
        tag64_plus2048_for_gvirt,
    )

    parts: list[bytes] = []
    stats = access.ntl._stats if access is not None and access.ntl is not None else None
    lb = int(last_block) if last_block is not None and last_block > 0 else 0
    for fb, phys in enumerate(phys_per_fb):
        if phys <= 0:
            parts.append(b"\x00" * blksz)
            continue
        if access is not None:
            chunk = read_slice_block(access, phys)
        else:
            chunk = _ext2_fs_block(buf, phys, access=access, blksz=blksz)
        if (
            tag64_carrier
            and access is not None
            and access.ntl is not None
            and live_phys_per_fb is not None
            and fb < len(live_phys_per_fb)
        ):
            live_p = live_phys_per_fb[fb]
            gvirt_p = live_p
            if lb > 0 and (live_p <= 0 or live_p > lb):
                gvirt_p = phys
            if gvirt_p > 0:
                gvirt = int(access.ntl.virt_byte_start) + int(gvirt_p) * blksz
                from opentl.chain_cluster import chain_routed_cluster_at_gvirt

                routed = chain_routed_cluster_at_gvirt(
                    linear_prefix=access.ntl.session.linear_prefix,
                    flat_oob=access.ntl.flat_oob,
                    block_map=access.ntl.block_map,
                    gvirt=int(gvirt),
                    blksz=int(blksz),
                    assembled_chunk=chunk,
                    stats=stats if isinstance(stats, dict) else None,
                )
                if routed is not None:
                    chunk = routed
                    if isinstance(stats, dict):
                        stats["chain_cluster_overlays"] = int(
                            stats.get("chain_cluster_overlays", 0)
                        ) + 1
                if phys == live_p:
                    plus = tag64_plus2048_for_gvirt(access, gvirt, chunk)
                    if plus is not None:
                        chunk = plus
                        if isinstance(stats, dict):
                            stats["tag64_carrier_overlays"] = int(
                                stats.get("tag64_carrier_overlays", 0)
                            ) + 1
                cross = tag64_cross_erase_next_vblk_for_gvirt(access, gvirt, chunk)
                if cross is not None:
                    chunk = cross
                    if isinstance(stats, dict):
                        stats["tag64_cross_erase_overlays"] = int(
                            stats.get("tag64_cross_erase_overlays", 0)
                        ) + 1
        parts.append(chunk)
    out = b"".join(parts)
    return out[:size]


def _validate_uimage_ih_dcrc(data: bytes) -> bool:
    """U-Boot ``imi`` outer payload CRC (``ih_dcrc`` over ``ih_size`` bytes)."""
    if len(data) < 64:
        return False
    from uboot.uimage import parse_uimage_header

    hdr = parse_uimage_header(data[:64])
    if hdr is None:
        return False
    payload = data[64 : 64 + int(hdr.ih_size)]
    if len(payload) != int(hdr.ih_size):
        return False
    return (zlib.crc32(payload) & 0xFFFFFFFF) == (int(hdr.ih_dcrc) & 0xFFFFFFFF)


def read_shadow_promoted_file_bytes(
    buf: bytes | bytearray,
    sb_off: int,
    live_inum: int,
    i_block: bytes,
    size: int,
    *,
    access: Ext2VolumeAccess | None = None,
) -> bytes:
    """
    Deleted-orphan shadow inode promotion for stale PACE opentla4 captures.

    Content-neutral policy only: invalid live phys, stale assembled clusters,
    tag-64 carrier sites at live inode virt, direct-anchor block 0, and anchor-run
    refinement for corrupt live indirect maps.
    """
    lb = _ext2_last_block(buf, sb_off)
    blksz = _ext2_block_size(buf, sb_off)
    if lb is None or lb <= 0 or blksz <= 0 or size <= 0:
        return b""
    work = buf if isinstance(buf, bytearray) else bytearray(buf)
    nblocks = (size + blksz - 1) // blksz
    live_map = _map_all_file_blocks(
        work,
        sb_off,
        i_block,
        nblocks,
        blksz=blksz,
        lb=lb,
        kernel_exact=True,
        access=access,
    )
    shadows = _shadow_inodes(work, sb_off, live_inum=live_inum, live_size=size)
    if not shadows:
        return _read_by_block_map(
            buf,
            live_map,
            size=size,
            blksz=blksz,
            access=access,
            live_phys_per_fb=live_map,
            tag64_carrier=True,
            last_block=lb,
        )
    best = shadows[0]
    shadow_map = _map_all_file_blocks(
        work,
        sb_off,
        best.i_block,
        nblocks,
        blksz=blksz,
        lb=lb,
        kernel_exact=True,
        access=access,
    )
    merged = _merge_shadow_promote_block_map(
        live_map,
        shadow_map,
        buf=buf,
        sb_off=sb_off,
        live_i_block=i_block,
        shadow_i_block=best.i_block,
        shadow_inum=best.inum,
        access=access,
        last_block=lb,
    )
    if access is not None and access.ntl is not None and live_map:
        live_gvirt_for_fb0 = int(access.ntl.virt_byte_start) + int(live_map[0]) * blksz
        anchor_phys = _live_direct_anchor_phys(
            i_block,
            access=access,
            last_block=lb,
            live_gvirt_for_fb0=live_gvirt_for_fb0,
        )
        _apply_direct_run_skip(
            merged,
            i_block,
            access=access,
            last_block=lb,
            live_gvirt_for_fb0=live_gvirt_for_fb0,
        )
        invalid_live_promoted = _invalid_live_shadow_promoted_fbs(
            live_map,
            shadow_map,
            merged,
            last_block=lb,
        )
        _refine_invalid_live_shadow_phys(
            merged,
            live_map=live_map,
            shadow_map=shadow_map,
            invalid_live_promoted=invalid_live_promoted,
            anchor_phys=anchor_phys,
            access=access,
            last_block=lb,
            blksz=blksz,
        )
    return _read_by_block_map(
        buf,
        merged,
        size=size,
        blksz=blksz,
        access=access,
        live_phys_per_fb=live_map,
        tag64_carrier=True,
        last_block=lb,
    )
