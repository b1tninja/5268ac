"""
Recover install-image bytes on PACE opentla4 when the linked inode map is stale.

After a botched deferred promote, new payload clusters remain on disk but are wired only
through polluted indirect metadata (and unlinked inodes). Stock ``ext2_get_block`` on the
linked dentry inode returns **stale** phys blocks; the correct clusters are selected by
matching each 1 KiB file block against a **pkgstream chunk oracle** (per-block MD5), with
metadata-candidate phys and slice anchor fallback.
"""

from __future__ import annotations

import gzip
import hashlib
import re
import struct
import zlib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from boardfs.ext2_dissect import (
    _EXT2_NDIR_BLOCKS_KERNEL,
    _ext2_addr_per_block_bits,
    _ext2_block_size,
    _ext2_branch_block_ptr,
    _ext2_branch_block_ptr_kernel_exact,
    _ext2_fs_block,
    _ext2_last_block,
    _ext2_map_file_block,
    _ext2_prepare_kernel_block_read,
    _ext2_read_inode_fields,
    _ext2_sb_fields,
)
from boardfs.ext2_volume_io import Ext2VolumeAccess

__all__ = [
    "build_incremental_md5_prefix_oracle",
    "load_uimage_oracle_from_pkgstream",
    "read_extent_merged_file_bytes",
    "read_shadow_promoted_file_bytes",
    "register_uimage_oracle_loader",
    "stale_assembled_live_block",
    "validate_install_image_bytes",
]

# PACE opentla4 captures store the post-unlink timestamp at ``i_mtime`` (off +20);
# ``debugfs stat`` labels the same field ``dtime`` on deleted orphans (inode 993).
_PACE_DELETED_TIME_OFF = 20
_KERNEL_PAGE_BYTES = 2048

_SQUASHFS_MAGIC = b"hsqs"
_MAX_INDEX_VISITS = 2048
_MAX_ALTS_PER_BLOCK = 24
_MAX_REPAIR_TRIALS = 4096
_uimage_oracle_loader: Callable[[], bytes | None] | None = None


def register_uimage_oracle_loader(fn: Callable[[], bytes | None] | None) -> None:
    """Optional hook for ``paceflash`` to supply pkgstream uImage bytes without hard paths here."""
    global _uimage_oracle_loader
    _uimage_oracle_loader = fn


def load_uimage_oracle_from_pkgstream(pkgstream_path: Path | str) -> bytes:
    """Extract ``sys1/uImage`` FILE payload bytes from a carrier ``.pkgstream``."""
    from lib2spy.native_pkgstream import load_pkgstream_bytes, try_decompress_bzip2_prefix
    from lib2spy.pkgstream_verify import verify_pkgstream

    path = Path(pkgstream_path).expanduser().resolve()
    body, _ = try_decompress_bzip2_prefix(load_pkgstream_bytes(path))
    for rec in verify_pkgstream(path).file_records:
        base = rec.path.rsplit("/", 1)[-1]
        if base == "uImage":
            return body[rec.payload_offset : rec.payload_end]
    raise ValueError(f"uImage FILE not found in pkgstream: {path}")


def _resolve_uimage_oracle_body(oracle_body: bytes | None) -> bytes | None:
    if oracle_body is not None and len(oracle_body) > 0:
        return oracle_body
    if _uimage_oracle_loader is not None:
        try:
            loaded = _uimage_oracle_loader()
        except OSError:
            loaded = None
        if loaded:
            return loaded
    return None


def _oracle_block_chunk(want_body: bytes, fb: int, *, blksz: int) -> bytes | None:
    off = fb * blksz
    if off >= len(want_body):
        return None
    end = min(off + blksz, len(want_body))
    chunk = want_body[off:end]
    if len(chunk) < blksz:
        chunk = chunk.ljust(blksz, b"\x00")
    return chunk


def build_incremental_md5_prefix_oracle(
    want_body: bytes,
    *,
    blksz: int,
    nblocks: int,
) -> tuple[list[str | None], list[bytes | None]]:
    """
    Pkgstream oracle: for each file block ``fb``, the MD5 hex digest after
    ``hashlib.md5().update()`` over file blocks ``0..fb`` inclusive (1 KiB each).
    """
    prefix_hex: list[str | None] = []
    chunk_want: list[bytes | None] = []
    hasher = hashlib.md5()
    for fb in range(nblocks):
        chunk = _oracle_block_chunk(want_body, fb, blksz=blksz)
        if chunk is None:
            prefix_hex.append(None)
            chunk_want.append(None)
            continue
        hasher.update(chunk)
        prefix_hex.append(hasher.hexdigest())
        chunk_want.append(chunk)
    return prefix_hex, chunk_want


def _incremental_md5_matches(base: hashlib._Hash, chunk: bytes, target_hex: str, *, blksz: int) -> bool:
    trial = base.copy()
    body = chunk if len(chunk) >= blksz else chunk.ljust(blksz, b"\x00")
    trial.update(body[:blksz])
    return trial.hexdigest() == target_hex


def _find_slice_phys_for_chunk(
    slice_buf: bytes | bytearray,
    want: bytes,
    *,
    blksz: int,
    limit: int = 8,
) -> list[int]:
    if not want:
        return []
    phys: list[int] = []
    start = 0
    while len(phys) < limit:
        i = slice_buf.find(want, start)
        if i < 0:
            break
        if i % blksz == 0:
            phys.append(i // blksz)
        start = i + 1
    return phys


def _read_fs_block_cached(
    buf: bytes | bytearray,
    phys: int,
    *,
    blksz: int,
    access: Ext2VolumeAccess | None,
    cache: dict[int, bytes],
) -> bytes:
    if phys <= 0:
        return b"\x00" * blksz
    hit = cache.get(phys)
    if hit is None:
        hit = _ext2_fs_block(buf, phys, access=access, blksz=blksz)
        cache[phys] = hit
    return hit



def _alt_phys_universe(
    live_map: list[int],
    candidates: list[set[int]],
) -> set[int]:
    """Every filesystem block number seen in live/shadow/metadata candidate sets."""
    pool: set[int] = set()
    for phys in live_map:
        if phys > 0:
            pool.add(phys)
    for cset in candidates:
        pool |= {p for p in cset if p > 0}
    return pool


def _pick_extent_by_incremental_md5(
    base: hashlib._Hash,
    target_hex: str,
    phys_choices: list[int],
    *,
    buf: bytes | bytearray,
    blksz: int,
    access: Ext2VolumeAccess | None,
    block_cache: dict[int, bytes],
    skip_phys: int = 0,
) -> tuple[int, bytes | None]:
    """
    Compare the pkgstream oracle prefix MD5 at this file block against each 1 KiB
    extent choice: ``base.copy().update(sector)`` vs ``target_hex``.
    """
    for phys in phys_choices:
        if phys <= 0 or phys == skip_phys:
            continue
        cand = _read_fs_block_cached(
            buf, phys, blksz=blksz, access=access, cache=block_cache
        )
        if _incremental_md5_matches(base, cand, target_hex, blksz=blksz):
            return phys, cand
    return 0, None


def _repair_map_with_incremental_md5_oracle(
    buf: bytes | bytearray,
    live_map: list[int],
    candidates: list[set[int]],
    oracle_body: bytes,
    *,
    size: int,
    blksz: int,
    access: Ext2VolumeAccess | None,
) -> tuple[list[int], dict[str, int]]:
    """
    Walk file blocks in order with a running ``hashlib.md5().update`` per 1 KiB sector.

    At file block ``fb`` the pkgstream oracle supplies ``prefix_md5[fb]`` — the MD5
    after blocks ``0..fb`` inclusive.  Each candidate phys extent is O(1) to test:
    ``running.copy().update(read(phys)) == prefix_md5[fb]`` without re-hashing the
    whole uImage.  That is the selection rule for stale inode / fragmented extents.
    """
    nblocks = len(live_map)
    prefix_md5, chunk_want = build_incremental_md5_prefix_oracle(
        oracle_body, blksz=blksz, nblocks=nblocks
    )
    out = list(live_map)
    alt_phys = sorted(_alt_phys_universe(live_map, candidates))
    stats = {
        "incremental_blocks": 0,
        "live_ok": 0,
        "candidate_hits": 0,
        "slice_hits": 0,
        "extent_scan_hits": 0,
        "unresolved": 0,
        "resync_rebuilds": 0,
    }
    block_cache: dict[int, bytes] = {}
    running = hashlib.md5()
    prefix_synced = True

    for fb in range(nblocks):
        target = prefix_md5[fb]
        if target is None:
            continue
        stats["incremental_blocks"] += 1

        if not prefix_synced:
            running = hashlib.md5()
            for j in range(fb):
                if chunk_want[j] is None:
                    continue
                running.update(
                    _read_fs_block_cached(
                        buf, out[j], blksz=blksz, access=access, cache=block_cache
                    )[:blksz]
                )
            stats["resync_rebuilds"] += 1
            prefix_synced = True

        base = running.copy()
        live_chunk = _read_fs_block_cached(
            buf, out[fb], blksz=blksz, access=access, cache=block_cache
        )
        if _incremental_md5_matches(base, live_chunk, target, blksz=blksz):
            running.update(live_chunk[:blksz])
            stats["live_ok"] += 1
            continue

        picked_phys = 0
        picked_chunk: bytes | None = None

        tried: set[int] = {out[fb]}
        ordered_meta = sorted(candidates[fb] - tried)
        picked_phys, picked_chunk = _pick_extent_by_incremental_md5(
            base,
            target,
            ordered_meta,
            buf=buf,
            blksz=blksz,
            access=access,
            block_cache=block_cache,
            skip_phys=out[fb],
        )
        if picked_phys > 0:
            stats["candidate_hits"] += 1
        else:
            tried |= set(ordered_meta)

        if picked_phys <= 0 and chunk_want[fb] is not None:
            for truth_phys in _find_slice_phys_for_chunk(
                buf, chunk_want[fb], blksz=blksz
            ):
                if truth_phys in tried:
                    continue
                cand = _read_fs_block_cached(
                    buf, truth_phys, blksz=blksz, access=access, cache=block_cache
                )
                if _incremental_md5_matches(base, cand, target, blksz=blksz):
                    picked_phys = truth_phys
                    picked_chunk = cand
                    stats["slice_hits"] += 1
                    break

        if picked_phys <= 0:
            scan_pool = [p for p in alt_phys if p not in tried]
            picked_phys, picked_chunk = _pick_extent_by_incremental_md5(
                base,
                target,
                scan_pool,
                buf=buf,
                blksz=blksz,
                access=access,
                block_cache=block_cache,
            )
            if picked_phys > 0:
                stats["extent_scan_hits"] += 1

        if picked_chunk is not None:
            out[fb] = picked_phys
            running.update(picked_chunk[:blksz])
            continue

        stats["unresolved"] += 1
        running.update(live_chunk[:blksz])
        prefix_synced = False

    return out, stats


# Back-compat alias for tests/tools
_repair_map_with_chunk_oracle = _repair_map_with_incremental_md5_oracle
_build_chunk_md5_oracle = build_incremental_md5_prefix_oracle


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


def stale_assembled_live_block(
    *,
    access: Ext2VolumeAccess,
    linear_prefix: bytes,
    block_map: Any,
    virt_byte_start: int,
    kernel_phys: int,
) -> bool:
    """
    OpenTL stale-cluster signal without pkgstream: assembled slice matches BBM linear
    bytes at the inode virt slot but not the page+2048 carrier within the same erase block.
    """
    if kernel_phys <= 0 or access.ntl is None:
        return False
    from boardfs.tag64_carrier import read_slice_block

    blksz = int(access.blksz)
    assembled = read_slice_block(access, kernel_phys)
    gvirt = int(virt_byte_start) + int(kernel_phys) * blksz
    erase = int(block_map.geometry.erase_bytes)
    if erase <= 0:
        return False
    vb = gvirt // erase
    vo = gvirt % erase
    v2p = block_map.virt_to_phys_block
    if vb < 0 or vb >= len(v2p):
        return False
    phys_blk = int(v2p[vb])
    if phys_blk <= 0:
        return False
    bbm_off = phys_blk * erase + vo
    if bbm_off + blksz > len(linear_prefix):
        return False
    bbm_chunk = linear_prefix[bbm_off : bbm_off + blksz]
    plus_off = bbm_off + _KERNEL_PAGE_BYTES
    if plus_off + blksz > len(linear_prefix):
        return False
    plus_chunk = linear_prefix[plus_off : plus_off + blksz]
    return assembled == bbm_chunk and assembled != plus_chunk


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
) -> list[int]:
    """Prefer deleted-orphan shadow phys blocks where live map hits a stale assembled cluster."""
    if access is None or access.ntl is None:
        return list(live_map)
    if not _promote_split_detected(live_i_block, shadow_i_block):
        return list(live_map)
    if _inode_deleted_time(buf, sb_off, shadow_inum) == 0:
        return list(live_map)
    off = _ext2_inode_byte_offset(buf, sb_off, shadow_inum)
    if off is None or struct.unpack_from("<H", buf, off + 26)[0] != 0:
        return list(live_map)

    linear_prefix = access.ntl.session.linear_prefix
    block_map = access.ntl.block_map
    virt_start = int(access.ntl.virt_byte_start)
    merged = list(live_map)
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
        if stale_assembled_live_block(
            access=access,
            linear_prefix=linear_prefix,
            block_map=block_map,
            virt_byte_start=virt_start,
            kernel_phys=live_phys,
        ):
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


def _decode_branch_ptr(raw: int, *, lb: int, kernel_exact: bool) -> int:
    if kernel_exact:
        return _ext2_branch_block_ptr_kernel_exact(raw)
    return _ext2_branch_block_ptr(raw, lb)


def _harvest_metadata_pointer_map(
    buf: bytes | bytearray,
    i_block: bytes,
    *,
    lb: int,
    blksz: int,
    access: Ext2VolumeAccess | None,
    kernel_exact: bool = True,
) -> dict[int, set[int]]:
    """
    Map file_block → phys for every data pointer reachable from ``i_block[]`` metadata.

    Walks indirect/dind/tind pages (including orphan pollution not on the live branch path).
    """
    ib = struct.unpack_from("<15I", i_block.ljust(60, b"\x00")[:60])
    ptrs_per_block = blksz // 4
    out: dict[int, set[int]] = defaultdict(set)
    visited: set[int] = set()
    queue: list[tuple[int, list[int]]] = []

    for slot in range(_EXT2_NDIR_BLOCKS_KERNEL):
        phys = _decode_branch_ptr(int(ib[slot]), lb=lb, kernel_exact=kernel_exact)
        if phys > 0:
            out[slot].add(phys)

    for slot in (_EXT2_NDIR_BLOCKS_KERNEL, _EXT2_NDIR_BLOCKS_KERNEL + 1, _EXT2_NDIR_BLOCKS_KERNEL + 2):
        branch = _decode_branch_ptr(int(ib[slot]), lb=lb, kernel_exact=kernel_exact)
        if branch > 0:
            queue.append((branch, [slot]))

    visits = 0
    while queue and visits < _MAX_INDEX_VISITS:
        blk, prefix = queue.pop()
        if blk in visited or blk <= 0:
            continue
        visited.add(blk)
        visits += 1
        page = _ext2_fs_block(buf, blk, access=access, blksz=blksz)
        if _index_page_score(page, lb=lb, blksz=blksz) >= 8:
            for i in range(ptrs_per_block):
                raw = struct.unpack_from("<I", page, i * 4)[0]
                if raw == 0:
                    break
                child = _decode_branch_ptr(raw, lb=lb, kernel_exact=kernel_exact)
                if child <= 0:
                    break
                queue.append((child, prefix + [i]))
            continue
        for i in range(ptrs_per_block):
            raw = struct.unpack_from("<I", page, i * 4)[0]
            if raw == 0:
                break
            phys = _decode_branch_ptr(raw, lb=lb, kernel_exact=kernel_exact)
            if phys <= 0:
                break
            fb = _path_to_file_block(prefix + [i], ptrs_per_block=ptrs_per_block)
            if fb is not None:
                out[fb].add(phys)
    return dict(out)


def _collect_uimage_block_candidates(
    buf: bytes | bytearray,
    work: bytearray,
    sb_off: int,
    i_block: bytes,
    nblocks: int,
    *,
    live_inum: int,
    live_size: int,
    lb: int,
    blksz: int,
    access: Ext2VolumeAccess | None,
) -> list[set[int]]:
    """Per file_block candidate phys: live map, shadow maps, metadata forest."""
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
    candidates: list[set[int]] = [set() for _ in range(nblocks)]
    for fb, phys in enumerate(live_map):
        if phys > 0:
            candidates[fb].add(phys)

    sources = [i_block]
    for meta in _shadow_inodes(work, sb_off, live_inum=live_inum, live_size=live_size):
        sources.append(meta.i_block)
        smap = _map_all_file_blocks(
            work,
            sb_off,
            meta.i_block,
            nblocks,
            blksz=blksz,
            lb=lb,
            kernel_exact=True,
            access=access,
        )
        for fb, phys in enumerate(smap):
            if phys > 0:
                candidates[fb].add(phys)

    pointer_maps: dict[int, set[int]] = defaultdict(set)
    for ib_src in sources:
        for fb, phys_set in _harvest_metadata_pointer_map(
            buf, ib_src, lb=lb, blksz=blksz, access=access
        ).items():
            pointer_maps[fb] |= phys_set

    for fb in range(nblocks):
        candidates[fb] |= pointer_maps.get(fb, set())

    return candidates


def _index_page_score(page: bytes, *, lb: int, blksz: int) -> int:
    hits = 0
    for i in range(blksz // 4):
        raw = struct.unpack_from("<I", page, i * 4)[0]
        if raw == 0:
            break
        if _ext2_branch_block_ptr(raw, lb) > 0:
            hits += 1
    return hits


def _harvest_metadata_phys(
    buf: bytes | bytearray,
    i_block: bytes,
    *,
    lb: int,
    blksz: int,
    access: Ext2VolumeAccess | None,
) -> set[int]:
    """
    Collect every filesystem block number referenced from indirect/dind pages reachable
    from ``i_block[]`` (includes orphan pointers not visible to ``ext2_map_file_block``).
    """
    ib = struct.unpack_from("<15I", i_block.ljust(60, b"\x00")[:60])
    phys: set[int] = set()
    visited: set[int] = set()
    queue: list[int] = []
    for slot in ib:
        p = _ext2_branch_block_ptr(int(slot), lb)
        if p > 0:
            queue.append(p)
    visits = 0
    while queue and visits < _MAX_INDEX_VISITS:
        blk = queue.pop()
        if blk in visited or blk <= 0:
            continue
        visited.add(blk)
        visits += 1
        page = _ext2_fs_block(buf, blk, access=access, blksz=blksz)
        if _index_page_score(page, lb=lb, blksz=blksz) < 8:
            continue
        for i in range(blksz // 4):
            raw = struct.unpack_from("<I", page, i * 4)[0]
            if raw == 0:
                break
            child = _ext2_branch_block_ptr(raw, lb)
            if child <= 0:
                break
            phys.add(child)
            if child not in visited:
                queue.append(child)
    return phys


def _read_by_block_map(
    buf: bytes | bytearray,
    phys_per_fb: list[int],
    *,
    size: int,
    blksz: int,
    access: Ext2VolumeAccess | None,
    live_phys_per_fb: list[int] | None = None,
    tag64_carrier: bool = False,
) -> bytes:
    from boardfs.tag64_carrier import (
        read_slice_block,
        tag64_cross_erase_next_vblk_for_gvirt,
        tag64_plus2048_for_gvirt,
    )

    parts: list[bytes] = []
    stats = access.ntl._stats if access is not None and access.ntl is not None else None
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
            if live_p > 0:
                gvirt = int(access.ntl.virt_byte_start) + int(live_p) * blksz
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


def _uimage_member0_block_range(data: bytes, blksz: int) -> tuple[int, int] | None:
    from uboot.uimage import extract_all_members, parse_uimage_header

    if len(data) < 64 or parse_uimage_header(data[:64]) is None:
        return None
    try:
        _, parts = extract_all_members(data)
    except (ValueError, OSError):
        return None
    if not parts:
        return None
    # Member0 gzip payload starts immediately after the 64-byte outer header on these images.
    start_b = 64 // blksz
    end_b = (64 + len(parts[0]) + blksz - 1) // blksz
    return start_b, end_b


def _validate_uimage(data: bytes) -> bool:
    if len(data) < 64:
        return False
    from uboot.uimage import (
        carve_uimage_member_body,
        extract_all_members,
        parse_uimage_header,
        uimage_header_crc_ok,
    )

    hdr = parse_uimage_header(data[:64])
    if hdr is None or not uimage_header_crc_ok(data[:64]):
        return False
    try:
        outer, parts = extract_all_members(data)
        plain = carve_uimage_member_body(parts[0], outer)
        gzip.decompress(plain)
    except (OSError, EOFError, zlib.error, ValueError):
        return False
    return True


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


def _read_md5sums_expected(
    buf: bytes | bytearray,
    sb_off: int,
    basename: str,
    *,
    access: Ext2VolumeAccess | None,
) -> str | None:
    """On-disk ``sys1/md5sums.txt`` entry for ``basename`` (promote intent, not inode map)."""
    from boardfs.ext2_path import read_ext2_regular_file

    try:
        text = read_ext2_regular_file(
            buf, "sys1/md5sums.txt", sb_off=sb_off, access=access, extent_merge=False
        ).decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return None
    for line in text.splitlines():
        m = re.match(r"^([0-9a-fA-F]{32})\s+(\S+)", line.strip())
        if m and m.group(2) == basename:
            return m.group(1).lower()
    return None


def _member0_gzip_decompresses(data: bytes) -> bool:
    if len(data) < 64:
        return False
    from uboot.uimage import (
        carve_uimage_member_body,
        extract_all_members,
        parse_uimage_header,
    )

    hdr = parse_uimage_header(data[:64])
    if hdr is None:
        return False
    try:
        outer, parts = extract_all_members(data)
        plain = carve_uimage_member_body(parts[0], outer)
        gzip.decompress(plain)
    except (OSError, EOFError, zlib.error, ValueError):
        return False
    return True


def _repair_gzip_guided_map(
    buf: bytes | bytearray,
    out: list[int],
    candidates: list[set[int]],
    *,
    size: int,
    blksz: int,
    access: Ext2VolumeAccess | None,
    md5_oracle: str | None,
    max_trials: int,
) -> tuple[list[int], int]:
    """
    Walk member0 gzip failures: at each stale file block try metadata alternates until
    ``gzip.decompress(member0)`` succeeds or trial budget is exhausted.
    """
    trials = 0

    def _read(m: list[int]) -> bytes:
        return _read_by_block_map(buf, m, size=size, blksz=blksz, access=access)

    def _done(data: bytes) -> bool:
        if md5_oracle and hashlib.md5(data).hexdigest() == md5_oracle:
            return True
        return validate_install_image_bytes("sys1/uImage", data)

    data = _read(out)
    span = _uimage_member0_block_range(data, blksz)
    if span is None:
        return out, trials

    start_b, end_b = span
    live_phys = {p for p in out if p > 0}
    global_alts = sorted(
        p for cset in candidates for p in cset if p > 0 and p not in live_phys
    )[: _MAX_ALTS_PER_BLOCK * 16]

    while trials < max_trials:
        data = _read(out)
        if _done(data):
            return out, trials
        if _member0_gzip_decompresses(data):
            if md5_oracle is None:
                return out, trials
            if hashlib.md5(data).hexdigest() == md5_oracle:
                return out, trials

        fixed = False
        for fb in range(start_b, min(end_b + 1, len(out))):
            alts = sorted(
                candidates[fb] | set(global_alts),
                key=lambda p: (p == out[fb], p),
            )
            for phys in alts[: _MAX_ALTS_PER_BLOCK]:
                if phys <= 0 or phys == out[fb]:
                    continue
                trial = list(out)
                trial[fb] = phys
                trial_data = _read(trial)
                trials += 1
                if _member0_gzip_decompresses(trial_data) or _done(trial_data):
                    out = trial
                    fixed = True
                    break
                if trials >= max_trials:
                    break
            if fixed or trials >= max_trials:
                break
        if not fixed:
            break

    return out, trials


def _repair_uimage_block_map(
    buf: bytes | bytearray,
    live_map: list[int],
    candidates: list[set[int]],
    *,
    size: int,
    blksz: int,
    access: Ext2VolumeAccess | None,
    md5_oracle: str | None = None,
) -> list[int]:
    """
    Greedy per-block repair using format-native checks (``ih_dcrc``, gzip member0).

    Tries shadow/metadata candidates before orphan-cluster alts; stops early when
    :func:`validate_install_image_bytes` succeeds.
    """
    out = list(live_map)
    nblocks = len(out)

    def _read(m: list[int]) -> bytes:
        return _read_by_block_map(buf, m, size=size, blksz=blksz, access=access)

    def _ok(data: bytes) -> bool:
        if md5_oracle and hashlib.md5(data).hexdigest() != md5_oracle:
            return False
        return validate_install_image_bytes("sys1/uImage", data)

    def _better(data: bytes) -> bool:
        if md5_oracle:
            return hashlib.md5(data).hexdigest() == md5_oracle
        return _validate_uimage_ih_dcrc(data)

    data = _read(out)
    if _ok(data):
        return out

    suspect = [
        fb
        for fb in range(nblocks)
        if any(p != live_map[fb] for p in candidates[fb] if p > 0)
    ]
    trials = 0
    for fb in suspect:
        ordered = sorted(
            candidates[fb],
            key=lambda p: (p != out[fb], p),
        )
        for phys in ordered[: _MAX_ALTS_PER_BLOCK]:
            if phys <= 0 or phys == out[fb]:
                continue
            trial = list(out)
            trial[fb] = phys
            trial_data = _read(trial)
            trials += 1
            if _ok(trial_data):
                return trial
            if _better(trial_data):
                out[fb] = phys
            if trials >= _MAX_REPAIR_TRIALS:
                break
        if trials >= _MAX_REPAIR_TRIALS:
            break

    if _ok(_read(out)):
        return out

    span = _uimage_member0_block_range(_read(out), blksz)
    if span is not None and trials < _MAX_REPAIR_TRIALS:
        start_b, end_b = span
        for fb in range(start_b, min(end_b + 1, nblocks)):
            for phys in sorted(candidates[fb], key=lambda p: (p != out[fb], p))[
                : _MAX_ALTS_PER_BLOCK
            ]:
                if phys <= 0 or phys == out[fb]:
                    continue
                trial = list(out)
                trial[fb] = phys
                trial_data = _read(trial)
                trials += 1
                if _ok(trial_data):
                    return trial
                if _better(trial_data):
                    out[fb] = phys
                if trials >= _MAX_REPAIR_TRIALS:
                    break
            if trials >= _MAX_REPAIR_TRIALS:
                break

    if _ok(_read(out)):
        return out

    if not _validate_uimage_ih_dcrc(_read(out)) and trials < _MAX_REPAIR_TRIALS:
        live_phys = {p for p in out if p > 0}
        orphan_alts = sorted(
            p
            for cset in candidates
            for p in cset
            if p > 0 and p not in live_phys
        )[: _MAX_ALTS_PER_BLOCK * 8]
        span = _uimage_member0_block_range(_read(out), blksz)
        fb_range = range(nblocks)
        if span is not None:
            fb_range = range(span[0], min(span[1] + 1, nblocks))
        for fb in fb_range:
            for phys in orphan_alts:
                if phys in candidates[fb] or phys == out[fb]:
                    continue
                trial = list(out)
                trial[fb] = phys
                trials += 1
                if _ok(_read(trial)):
                    return trial
                if _better(_read(trial)):
                    out[fb] = phys
                if trials >= _MAX_REPAIR_TRIALS:
                    break
            if trials >= _MAX_REPAIR_TRIALS:
                break

    out, gzip_trials = _repair_gzip_guided_map(
        buf,
        out,
        candidates,
        size=size,
        blksz=blksz,
        access=access,
        md5_oracle=md5_oracle,
        max_trials=max(0, _MAX_REPAIR_TRIALS - trials),
    )
    trials += gzip_trials

    return out


def _validate_squashfs_image(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == _SQUASHFS_MAGIC


def validate_install_image_bytes(rel_path: str, data: bytes) -> bool:
    """Format-native integrity check (no carrier hashes)."""
    base = rel_path.rsplit("/", 1)[-1]
    if base == "uImage":
        return _validate_uimage(data)
    if base.endswith(".img"):
        return _validate_squashfs_image(data)
    return len(data) > 0


def _repair_map_with_gzip_evidence(
    buf: bytes | bytearray,
    live_map: list[int],
    alt_phys: set[int],
    *,
    size: int,
    blksz: int,
    access: Ext2VolumeAccess | None,
    candidates: list[set[int]] | None = None,
    md5_oracle: str | None = None,
) -> list[int]:
    """Legacy entry point; delegates to :func:`_repair_uimage_block_map`."""
    if candidates is None:
        candidates = [set() for _ in live_map]
        for fb, phys in enumerate(live_map):
            if phys > 0:
                candidates[fb].add(phys)
        live_phys = {p for p in live_map if p > 0}
        for p in alt_phys:
            if p > 0 and p not in live_phys:
                for fb in range(len(live_map)):
                    candidates[fb].add(p)
    return _repair_uimage_block_map(
        buf,
        live_map,
        candidates,
        size=size,
        blksz=blksz,
        access=access,
        md5_oracle=md5_oracle,
    )


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
    Kernel-faithful uImage read with deleted-orphan shadow inode promotion.

    When dentry/live direct blocks differ from a deleted same-size shadow inode,
    swap in shadow phys blocks only where the live map reads a stale assembled
    OpenTL cluster (assembled == BBM linear, != page+2048 carrier).
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
    )
    return _read_by_block_map(
        buf,
        merged,
        size=size,
        blksz=blksz,
        access=access,
        live_phys_per_fb=live_map,
        tag64_carrier=True,
    )


def read_extent_merged_file_bytes(
    buf: bytes | bytearray,
    sb_off: int,
    live_inum: int,
    i_block: bytes,
    size: int,
    *,
    rel_path: str = "",
    i_blocks: int = 0,
    i_mode: int = 0,
    access: Ext2VolumeAccess | None = None,
    oracle_body: bytes | None = None,
) -> bytes:
    """
    Read install image bytes, repairing stale inode maps.

    When ``oracle_body`` (pkgstream uImage) is supplied, uses incremental MD5
    (``hashlib.md5().update`` per 1 KiB file block) to pick the correct phys extent.
    """
    del i_blocks, i_mode
    lb = _ext2_last_block(buf, sb_off)
    blksz = _ext2_block_size(buf, sb_off)
    if lb is None or lb <= 0 or blksz <= 0 or size <= 0:
        return b""
    work = buf if isinstance(buf, bytearray) else bytearray(buf)
    nblocks = (size + blksz - 1) // blksz
    base = rel_path.rsplit("/", 1)[-1]

    if base == "uImage":
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
        candidates = _collect_uimage_block_candidates(
            buf,
            work,
            sb_off,
            i_block,
            nblocks,
            live_inum=live_inum,
            live_size=size,
            lb=lb,
            blksz=blksz,
            access=access,
        )
        oracle = _resolve_uimage_oracle_body(oracle_body)
        if oracle is not None:
            repaired_map, _stats = _repair_map_with_incremental_md5_oracle(
                buf,
                live_map,
                candidates,
                oracle,
                size=size,
                blksz=blksz,
                access=access,
            )
            return _read_by_block_map(
                buf, repaired_map, size=size, blksz=blksz, access=access
            )

        md5_oracle = _read_md5sums_expected(buf, sb_off, "uImage", access=access)
        alt_phys: set[int] = set()
        for cset in candidates:
            alt_phys |= cset
        repaired_map = _repair_map_with_gzip_evidence(
            buf,
            live_map,
            alt_phys,
            size=size,
            blksz=blksz,
            access=access,
            candidates=candidates,
            md5_oracle=md5_oracle,
        )
        return _read_by_block_map(
            buf, repaired_map, size=size, blksz=blksz, access=access
        )

    live_map = _map_all_file_blocks(work, sb_off, i_block, nblocks, blksz=blksz, lb=lb)
    shadows = _shadow_inodes(work, sb_off, live_inum=live_inum, live_size=size)
    merged = list(live_map)
    for meta in shadows:
        smap = _map_all_file_blocks(
            work, sb_off, meta.i_block, nblocks, blksz=blksz, lb=lb
        )
        for fb in range(nblocks):
            ps = smap[fb]
            pl = merged[fb]
            if ps > 0 and ps != pl and meta.mtime >= 0:
                merged[fb] = ps

    data = _read_by_block_map(buf, merged, size=size, blksz=blksz, access=access)
    if rel_path and validate_install_image_bytes(rel_path, data):
        return data
    return _read_by_block_map(buf, live_map, size=size, blksz=blksz, access=access)
