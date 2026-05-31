"""Extract SquashFS image files stored inside an ext2 volume on a TL slice (e.g. opentla4)."""

from __future__ import annotations

import hashlib
import stat
from typing import Any

from boardfs.block import BlockSlice
from boardfs.squashfs_probe import SQUASHFS_MAGIC_LE
from lib2spy.native_pkgstream import squashfs_le_span_at

from boardfs.ext2_dissect import resolve_mountable_ext2_superblock_offset
from boardfs.ext2_volume_io import Ext2VolumeAccess

# Typical post-promote layout on opentla4 (see firmware_upgrade_process.md §5).
DEFAULT_SQUASH_IMAGE_PATHS: tuple[str, ...] = (
    "sys1/rootimage.img",
    "sys2/rootimage.img",
    "rootimage.img",
    "sys1/ui.img",
    "sys2/ui.img",
    "ui.img")

# Install/recovery kernel on opentla4 (U-Boot ``ext2load opentl 0:5 … /sys1/uImage``).
DEFAULT_UIMAGE_PATHS: tuple[str, ...] = (
    "sys1/uImage",
    "sys2/uImage")

_EMBEDDED_ROW_BASE: dict[str, Any] = {
    "content_kind": "squashfs",
    "container": "ext2",
    "read_model": "ext2_file_extract",
}


def _open_extfs_at_superblock(data: bytes, sb_off: int):
    from boardfs.ext2_dissect import _ext2_open_dissect

    return _ext2_open_dissect(data, sb_off)


def extract_ext2_file(
    slice_data: bytes,
    path: str,
    *,
    sb_off: int | None = None,
    access: Ext2VolumeAccess | None = None) -> tuple[bytes | None, dict[str, Any]]:
    """
    Read one embedded ``.img`` path from the ext2 **container** (file bytes are usually SquashFS).

    Returns ``(file_bytes, meta)``; ``file_bytes is None`` when the ext2 volume is unmounted or path missing.
    """
    meta: dict[str, Any] = {
        "path": path,
        **_EMBEDDED_ROW_BASE,
        "ext2_superblock_offset": sb_off,
    }
    sb = sb_off if sb_off is not None else resolve_mountable_ext2_superblock_offset(slice_data)
    if sb is None:
        meta["error"] = "ext2 container not mounted (no superblock offset)"
        meta["status"] = "ext2_unmounted"
        return None, meta
    rel = path.lstrip("/")
    try:
        fs = _open_extfs_at_superblock(slice_data, sb)
        node = fs.get(rel)
        if not stat.S_ISREG(node.inode.i_mode):
            meta["error"] = "not a regular file in ext2"
            meta["status"] = "missing_or_not_file"
            return None, meta
        with node.open() as fh:
            body = fh.read()
        meta["read_model"] = "ext2_file_extract"
        meta["ext2_superblock_offset"] = sb
        meta["size"] = len(body)
        meta["status"] = "ok"
        if len(body) >= 4 and body[:4] == SQUASHFS_MAGIC_LE:
            meta["hsqs_at_file_start"] = True
            span = squashfs_le_span_at(body, 0)
            if span is not None:
                _, slen = span
                meta["strict_squash_len"] = slen
                meta["strict_squash_sha256"] = hashlib.sha256(body[:slen]).hexdigest()
        return body, meta
    except Exception as e:
        meta["dissect_error"] = f"{type(e).__name__}: {e}"

    # Lab NAND dumps: Dissect dentry miss; fall back to inode-faithful PACE read (not CMDB recovery).
    try:
        from boardfs.ext2_path import read_ext2_regular_file

        rel = path.lstrip("/")
        body = read_ext2_regular_file(
            slice_data,
            rel,
            sb_off=sb,
            access=access,
        )
    except Exception as e:
        meta["error"] = f"{type(e).__name__}: {e}"
        meta["status"] = "read_failed"
        return None, meta
    meta["read_model"] = "ext2_file_extract+pace_inode"
    meta["ext2_superblock_offset"] = sb
    meta["size"] = len(body)
    meta["status"] = "ok"
    if len(body) >= 4 and body[:4] == SQUASHFS_MAGIC_LE:
        meta["hsqs_at_file_start"] = True
        span = squashfs_le_span_at(body, 0)
        if span is not None:
            _, slen = span
            meta["strict_squash_len"] = slen
            meta["strict_squash_sha256"] = hashlib.sha256(body[:slen]).hexdigest()
    return body, meta


def probe_embedded_squash_images(
    slice_data: bytes,
    paths: tuple[str, ...] = DEFAULT_SQUASH_IMAGE_PATHS,
    *,
    sb_off: int | None = None) -> list[dict[str, Any]]:
    """Probe known ``.img`` paths (SquashFS payloads inside ext2, not ext2 volumes themselves)."""
    sb = sb_off if sb_off is not None else resolve_mountable_ext2_superblock_offset(slice_data)
    rows: list[dict[str, Any]] = []
    for path in paths:
        body, meta = extract_ext2_file(slice_data, path, sb_off=sb)
        row: dict[str, Any] = {**meta}
        row["ok"] = body is not None
        if body is not None:
            row["sha256_head16"] = hashlib.sha256(body[: min(len(body), 65536)]).hexdigest()[:16]
        rows.append(row)
    return rows


# Back-compat alias used by inventory correlation.
probe_ext2_squash_files = probe_embedded_squash_images


def ext2_file_sources_from_block_dev(
    dev: BlockSlice,
    paths: tuple[str, ...] = DEFAULT_SQUASH_IMAGE_PATHS,
    *,
    access: Ext2VolumeAccess | None = None) -> tuple[list[tuple[str, bytes]], list[dict[str, Any]], int | None]:
    """
    Return ``(correlation_sources, probe_rows, ext2_sb_off)``.

    ``correlation_sources`` entries are ``(source_label, file_bytes)`` with labels like
    ``ext2_file:sys1/rootimage.img``.
    """
    data = dev.read_slice()
    sb = resolve_mountable_ext2_superblock_offset(data)
    probe_rows = probe_embedded_squash_images(data, paths, sb_off=sb)
    sources: list[tuple[str, bytes]] = []
    if sb is not None:
        for path in paths:
            body, _ = extract_ext2_file(data, path, sb_off=sb, access=access)
            if body is not None:
                sources.append((f"ext2_file:{path}", body))
    return sources, probe_rows, sb


def try_dissect_ext2_file_root(
    dev: BlockSlice,
    *,
    paths: tuple[str, ...] = ("sys1/rootimage.img", "sys2/rootimage.img", "rootimage.img")) -> dict[str, Any] | None:
    """First embedded ``.img`` whose bytes dissect as SquashFS ``/`` (for inventory squash block)."""
    from paceflash.squashfs_dissect import list_squashfs_root_entries_with_meta

    data = dev.read_slice()
    sb = resolve_mountable_ext2_superblock_offset(data)
    if sb is None:
        return None
    for path in paths:
        body, meta = extract_ext2_file(data, path, sb_off=sb)
        if body is None:
            continue
        try:
            rows, sq_meta = list_squashfs_root_entries_with_meta(body, cap=32, prefer_offsets=[0])
            return {
                "path": path,
                "content_kind": "squashfs",
                "container": "ext2",
                "root_ls": rows,
                "source": "ext2_file_extract",
                "read_model": "ext2_file_extract",
                "ext2_superblock_offset": sb,
                "squashfs_superblock_offset": sq_meta.get("squashfs_superblock_offset", 0),
                "squashfs_image_bytes": sq_meta.get("squashfs_image_bytes", len(body)),
            }
        except Exception as e:
            meta["dissect_error"] = f"{type(e).__name__}: {e}"
            if "LZMA" in type(e).__name__:
                meta["failure_class"] = "misaligned_or_not_squashfs"
            continue
    return None
