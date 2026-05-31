"""List directories and read files on an in-memory ext2 volume (kernel inode layout)."""

from __future__ import annotations

import io
import stat
import struct
from typing import Any

from dissect.extfs import ExtFS

from boardfs.ext2_dissect import (
    _EXT2_FT_TO_KIND,
    _EXT2_SB0_OFF,
    _ext2_dir_blocks_bytes,
    _ext2_dir_data_opaque,
    _ext2_feature_htree,
    _ext2_io_view,
    _ext2_last_block,
    _ext2_open_dissect,
    _ext2_parse_dir_entry,
    ext2_file_map_report,
    _ext2_inode_byte_offset,
    _ext2_read_file_bytes,
    _ext2_read_inode_fields,
    _ext2_read_inode_i_blocks,
    _ext2_volume_uses_pace_inode_layout,
    resolve_mountable_ext2_superblock_offset,
)
from boardfs.ext2_volume_io import Ext2VolumeAccess


class Ext2DirectoryOpaqueError(OSError):
    """Directory data block has no parseable ``ext2_dir_entry`` chain (see ``ext2_readdir``)."""


#region kernel_adjacent ext2_path_io
def normalize_ext2_path(path: str | None) -> str:
    """Return a path relative to volume root (no leading slash); ``''`` is ``/``."""
    if path is None or path in ("", "/", "."):
        return ""
    p = path.strip()
    while p.startswith("./"):
        p = p[2:]
    return p.strip("/")


def _ext2_dir_entries_from_inode(
    work: bytes,
    i_block: bytes,
    *,
    dir_size: int,
    sb_off: int,
    dir_inum: int = 0,
    access: Ext2VolumeAccess | None = None,
    cap: int = 4096,
) -> list[tuple[int, str, int]]:
    """Parse directory blocks from inode ``i_block`` (``ext2_readdir`` / ``ext2_get_page``)."""
    last_block = _ext2_last_block(work, sb_off=sb_off)
    if last_block is None:
        return []
    blksz = 1024 << struct.unpack_from("<I", work, sb_off + 24)[0]
    inodes_count = struct.unpack_from("<I", work, sb_off)[0]
    i_blocks = 0
    i_mode = 0
    if dir_inum > 0:
        fields = _ext2_read_inode_fields(work, sb_off, dir_inum, access=access)
        if fields is not None:
            i_mode, _, _ = fields
            ino_off = _ext2_inode_byte_offset(work, sb_off, dir_inum)
            if ino_off is not None:
                i_blocks = struct.unpack_from("<I", work, ino_off + 28)[0]
            else:
                i_blocks = _ext2_read_inode_i_blocks(work, sb_off, dir_inum, access=access)
    data = _ext2_dir_blocks_bytes(
        work,
        i_block,
        dir_size=dir_size,
        last_block=last_block,
        blksz=blksz,
        dir_inum=dir_inum,
        inodes_count=inodes_count,
        i_blocks=i_blocks,
        i_mode=i_mode,
        access=access,
    )
    return _ext2_parse_dir_entry(
        data,
        inodes_count=inodes_count,
        cap=cap,
        htree=_ext2_feature_htree(work, sb_off),
    )


def _ext2_resolve_path_inum(
    work: bytes,
    sb_off: int,
    rel: str,
    *,
    root_i_block: bytes,
    root_mode: int,
    root_size: int,
    access: Ext2VolumeAccess | None = None,
) -> tuple[int, int, bytes, int]:
    """
    Walk ``rel`` under ``/`` using kernel inode table + ``ext2_dir_entry`` parsing.
    """
    parts = [p for p in rel.split("/") if p and p != "."]
    inum = 2
    mode = root_mode
    i_block = root_i_block
    size = root_size

    for idx, part in enumerate(parts):
        is_last = idx == len(parts) - 1
        entries = _ext2_dir_entries_from_inode(
            work,
            i_block,
            dir_size=size,
            sb_off=sb_off,
            dir_inum=inum,
            access=access,
        )
        match = next((e for e in entries if e[1] == part), None)
        if match is None:
            raise FileNotFoundError(rel)
        inum, _, _ft = match
        fields = _ext2_read_inode_fields(work, sb_off, inum, access=access)
        if fields is None:
            raise FileNotFoundError(f"{rel} (inode {inum})")
        mode, size, i_block = fields
        if is_last:
            if not stat.S_ISDIR(mode) and not stat.S_ISREG(mode):
                raise FileNotFoundError(f"{rel} (inode {inum})")
            break
        if not stat.S_ISDIR(mode):
            raise NotADirectoryError(f"{rel}: {part!r} (inode {inum}) is not a directory")
    return inum, mode, i_block, size


def list_ext2_directory(
    slice_data: bytes,
    path: str = "",
    *,
    sb_off: int | None = None,
    cap: int = 4096,
    include_dot: bool = False,
    access: Ext2VolumeAccess | None = None,
) -> list[dict[str, Any]]:
    """
    List one directory on the ext2 volume.

    Each row has ``name``, ``inode``, ``file_type`` (``stat.filemode``), and ``kind``
    (``dir``, ``file``, ``link``, or ``other``).
    """
    rel = normalize_ext2_path(path)
    sb = sb_off if sb_off is not None else resolve_mountable_ext2_superblock_offset(slice_data)
    if sb is None:
        raise ValueError("ext2 volume not mountable (no superblock offset)")
    work_view = _ext2_io_view(slice_data, sb).getvalue()
    fs = _ext2_open_dissect(slice_data, sb)
    root_ino = fs.root.inode
    root_mode = int(root_ino.i_mode)
    root_size = int(getattr(root_ino, "size", 0) or getattr(root_ino, "i_size_lo", 0) or 0)
    root_i_block = bytes(root_ino.i_block[:48])

    if rel:
        try:
            _inum, mode, i_block, dir_size = _ext2_resolve_path_inum(
                work_view,
                sb,
                rel,
                root_i_block=root_i_block,
                root_mode=root_mode,
                root_size=root_size,
                access=access,
            )
        except NotADirectoryError:
            raise NotADirectoryError(rel or "/")
        if not stat.S_ISDIR(mode):
            raise NotADirectoryError(rel or "/")
    else:
        mode = root_mode
        i_block = root_i_block
        dir_size = root_size
        _inum = 2

    inodes_count = struct.unpack_from("<I", work_view, sb)[0]
    i_blocks = 0
    ino_off = _ext2_inode_byte_offset(work_view, sb, _inum)
    if ino_off is not None:
        i_blocks = struct.unpack_from("<I", work_view, ino_off + 28)[0]
    entries = _ext2_dir_entries_from_inode(
        work_view,
        i_block,
        dir_size=dir_size,
        sb_off=sb,
        dir_inum=_inum,
        access=access,
        cap=cap,
    )
    is_dir = stat.S_ISDIR(mode)
    htree = _ext2_feature_htree(work_view, sb)
    last_block = _ext2_last_block(work_view, sb_off=_EXT2_SB0_OFF) or 0
    blksz = 1024 << struct.unpack_from("<I", work_view, _EXT2_SB0_OFF + 24)[0]
    dir_data = _ext2_dir_blocks_bytes(
        work_view,
        i_block,
        dir_size=dir_size,
        last_block=last_block,
        blksz=blksz,
        dir_inum=_inum,
        inodes_count=inodes_count,
        i_blocks=i_blocks,
        i_mode=mode,
        access=access,
    )
    if not entries and _ext2_dir_data_opaque(dir_data, htree=htree):
        raise Ext2DirectoryOpaqueError(
            f"{rel or '/'}: no valid ext2_dir_entry chain in directory data block "
            "(kernel would reject with bad/zero-length directory entry)"
        )
    if not is_dir and not entries:
        raise NotADirectoryError(rel or "/")

    rows: list[dict[str, Any]] = []
    for inum, name, ft in entries:
        if not include_dot and name in (".", ".."):
            continue
        kind = _EXT2_FT_TO_KIND.get(ft, "other")
        if ft == 2:
            kind = "dir"
        elif ft == 1:
            kind = "file"
        file_type = "?" + kind
        rows.append(
            {
                "name": name,
                "inode": inum,
                "file_type": file_type,
                "kind": kind,
            }
        )
    rows.sort(key=lambda r: r["name"])
    return rows


def default_shadow_promote_for_path(path: str) -> bool:
    """Deprecated — PACE capture reads enable shadow promotion via volume layout."""
    del path
    return False


def read_ext2_regular_file(
    slice_data: bytes,
    path: str,
    *,
    sb_off: int | None = None,
    access: Ext2VolumeAccess | None = None,
    shadow_promote: bool | None = None,
) -> bytes:
    """Read a regular file from the ext2 volume; raises if missing or not a file."""
    rel = normalize_ext2_path(path)
    if rel == "":
        raise IsADirectoryError("/")
    sb = sb_off if sb_off is not None else resolve_mountable_ext2_superblock_offset(slice_data)
    if sb is None:
        raise ValueError("ext2 volume not mountable (no superblock offset)")
    work_view = _ext2_io_view(slice_data, sb).getvalue()
    fs = _ext2_open_dissect(slice_data, sb)
    root_ino = fs.root.inode
    root_mode = int(root_ino.i_mode)
    root_size = int(getattr(root_ino, "size", 0) or getattr(root_ino, "i_size_lo", 0) or 0)
    root_i_block = bytes(root_ino.i_block[:48])
    try:
        _inum, mode, i_block, inode_size = _ext2_resolve_path_inum(
            work_view,
            sb,
            rel,
            root_i_block=root_i_block,
            root_mode=root_mode,
            root_size=root_size,
            access=access,
        )
    except NotADirectoryError as e:
        raise IsADirectoryError(rel) from e
    if stat.S_ISDIR(mode):
        raise IsADirectoryError(rel)
    if not stat.S_ISREG(mode):
        raise OSError(f"not a regular file: {rel!r}")
    i_blocks = _ext2_read_inode_i_blocks(work_view, sb, _inum, access=access)
    if shadow_promote is None:
        shadow_promote = default_shadow_promote_for_path(rel)
    data = _ext2_read_file_bytes(
        work_view,
        sb,
        i_block,
        inode_size,
        i_blocks=i_blocks,
        i_mode=mode,
        access=access,
        rel_path=rel,
        live_inum=_inum,
        shadow_promote=shadow_promote,
    )
    pace = _ext2_volume_uses_pace_inode_layout(work_view, sb)
    if not pace and inode_size and len(data) < inode_size:
        raise OSError(
            f"ext2 read short for {rel!r}: got {len(data)} bytes, inode size {inode_size}"
        )
    return data


def read_ext2_regular_file_by_inum(
    slice_data: bytes,
    inum: int,
    *,
    sb_off: int | None = None,
    access: Ext2VolumeAccess | None = None,
) -> bytes:
    """Read a regular file by inode number (forensic / orphan-inode probes)."""
    sb = sb_off if sb_off is not None else resolve_mountable_ext2_superblock_offset(slice_data)
    if sb is None:
        raise ValueError("ext2 volume not mountable (no superblock offset)")
    work_view = _ext2_io_view(slice_data, sb).getvalue()
    fields = _ext2_read_inode_fields(work_view, sb, inum, access=access)
    if fields is None:
        raise FileNotFoundError(f"inode {inum}")
    mode, inode_size, i_block = fields
    if not stat.S_ISREG(mode):
        raise OSError(f"inode {inum} is not a regular file (mode={mode:#o})")
    i_blocks = _ext2_read_inode_i_blocks(work_view, sb, inum, access=access)
    return _ext2_read_file_bytes(
        work_view,
        sb,
        i_block,
        inode_size,
        i_blocks=i_blocks,
        i_mode=mode,
        access=access,
        rel_path=f"inode:{inum}",
        live_inum=inum,
    )


def ext2_file_map_report_for_path(
    slice_data: bytes,
    path: str,
    *,
    sb_off: int | None = None,
    max_blocks: int = 64,
) -> list[str]:
    """Resolve ``path`` and return :func:`~boardfs.ext2_dissect.ext2_file_map_report` lines."""
    rel = normalize_ext2_path(path)
    if rel == "":
        raise IsADirectoryError("/")
    sb = sb_off if sb_off is not None else resolve_mountable_ext2_superblock_offset(slice_data)
    if sb is None:
        raise ValueError("ext2 volume not mountable (no superblock offset)")
    work_view = _ext2_io_view(slice_data, sb).getvalue()
    fs = _ext2_open_dissect(slice_data, sb)
    root_ino = fs.root.inode
    root_mode = int(root_ino.i_mode)
    root_size = int(getattr(root_ino, "size", 0) or getattr(root_ino, "i_size_lo", 0) or 0)
    root_i_block = bytes(root_ino.i_block[:48])
    inum, mode, i_block, inode_size = _ext2_resolve_path_inum(
        work_view,
        sb,
        rel,
        root_i_block=root_i_block,
        root_mode=root_mode,
        root_size=root_size,
    )
    if stat.S_ISDIR(mode):
        raise IsADirectoryError(rel)
    if not stat.S_ISREG(mode):
        raise OSError(f"not a regular file: {rel!r}")
    i_blocks = 0
    ino_off = _ext2_inode_byte_offset(work_view, sb, inum)
    if ino_off is not None:
        i_blocks = struct.unpack_from("<I", work_view, ino_off + 28)[0]
    return ext2_file_map_report(
        work_view,
        sb,
        i_block,
        inum=inum,
        rel_path=rel,
        size=inode_size,
        i_blocks=i_blocks,
        max_blocks=max_blocks,
    )
#endregion
