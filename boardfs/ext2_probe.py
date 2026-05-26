"""
Read-only **ext2 / ext3 / ext4** access for carved ``opentla4`` raw images.

Uses the **`ext4`** PyPI package (`python-ext4`, read-only). Install::

    pip install ext4

Requires **Python 3.11+** (constraint from ``ext4``).

For a quick magic check **without** dependencies, use :func:`peek_ext2_magic_at_438`.
"""

from __future__ import annotations

import io
import posixpath
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

# Standard primary superblock offset for ext2/ext4 (1024); ``s_magic`` at +0x38 → absolute 0x438.
EXT2_MAGIC_FILE_OFFSET = 0x438
EXT2_MAGIC_LE = 0xEF53


def peek_ext2_magic_at_438(path: str | Path) -> tuple[bool, int]:
    """
    Read **uint16 LE** at offset **0x438** (``s_magic`` in the primary superblock).

    Returns ``(matches_expected, value)`` — does **not** validate the full filesystem.
    """
    p = Path(path)
    with p.open("rb") as f:
        f.seek(EXT2_MAGIC_FILE_OFFSET)
        raw = f.read(2)
    if len(raw) < 2:
        return False, 0
    val = raw[0] | (raw[1] << 8)
    return val == EXT2_MAGIC_LE, val


def _require_ext4() -> Any:
    try:
        import ext4  # type: ignore[import-untyped]
    except ImportError as e:
        raise ImportError(
            "ext2/ext4 parsing requires the optional 'ext4' package. "
            "Install with: pip install ext4 (Python 3.11+)."
        ) from e
    return ext4


@contextmanager
def open_ext2_volume(
    path: str | Path,
    *,
    ignore_magic: bool = False,
    ignore_checksum: bool = False,
    ignore_flags: bool = False,
) -> Iterator[Any]:
    """
    Open a **raw partition image** (e.g. ``tl-extract`` output) as :class:`ext4.Volume`.

    The file must stay open for the lifetime of the volume; this context manager
    owns the handle.
    """
    ext4 = _require_ext4()
    p = Path(path)
    f = p.open("rb", buffering=io.DEFAULT_BUFFER_SIZE)
    try:
        if not hasattr(f, "peek"):
            f = io.BufferedReader(f)  # type: ignore[assignment]
        vol = ext4.Volume(
            f,
            offset=0,
            ignore_flags=ignore_flags,
            ignore_magic=ignore_magic,
            ignore_checksum=ignore_checksum,
        )
        yield vol
    finally:
        f.close()


def superblock_summary(vol: Any) -> dict[str, Any]:
    """Serialize key superblock fields for JSON / CLI."""
    sb = vol.superblock
    name = bytes(sb.s_volume_name).split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    last_mounted = bytes(sb.s_last_mounted).split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return {
        "s_magic": int(sb.s_magic),
        "s_magic_hex": f"{int(sb.s_magic):#06x}",
        "block_size": int(vol.block_size),
        "s_blocks_count_lo": int(sb.s_blocks_count_lo),
        "s_inodes_count": int(sb.s_inodes_count),
        "s_free_blocks_count_lo": int(sb.s_free_blocks_count_lo),
        "s_free_inodes_count": int(sb.s_free_inodes_count),
        "s_volume_name": name,
        "s_last_mounted": last_mounted,
        "s_rev_level": int(sb.s_rev_level),
    }


def list_dir(vol: Any, dir_path: str = "/") -> list[dict[str, Any]]:
    """Non-recursive directory listing; ``dir_path`` is POSIX (e.g. ``/sys1``)."""
    ext4 = _require_ext4()
    node = vol.inode_at(dir_path)
    if not isinstance(node, ext4.Directory):
        raise NotADirectoryError(dir_path)
    out: list[dict[str, Any]] = []
    for dirent, ft in node.opendir():
        nm = dirent.name_bytes.decode("utf-8", errors="replace")
        if nm in (".", ".."):
            continue
        ino = int(dirent.inode)
        out.append({"name": nm, "inode": ino, "file_type": str(ft)})
    out.sort(key=lambda x: x["name"])
    return out


def read_file(vol: Any, file_path: str, *, _depth: int = 0) -> bytes:
    """Read full file contents for a regular file path (follows symlinks with a depth cap)."""
    if _depth > 40:
        raise OSError("symlink recursion depth exceeded")
    ext4 = _require_ext4()
    node = vol.inode_at(file_path)
    if isinstance(node, ext4.File):
        return node.open().read()
    if isinstance(node, ext4.SymbolicLink):
        raw_target = node.readlink()
        ts = raw_target.decode("utf-8", errors="surrogateescape")
        if ts.startswith("/"):
            next_path = posixpath.normpath(ts)
        else:
            parent = posixpath.dirname(file_path.rstrip("/")) or "/"
            next_path = posixpath.normpath(posixpath.join(parent, ts))
        return read_file(vol, next_path, _depth=_depth + 1)
    raise OSError(f"not a regular file: {file_path}")


def probe_cli_report(path: str | Path) -> dict[str, Any]:
    """Combine magic peek + optional full probe for ``tl-ext2-probe --json``."""
    p = Path(path)
    ok, mag = peek_ext2_magic_at_438(p)
    out: dict[str, Any] = {
        "path": str(p.resolve()),
        "size": p.stat().st_size,
        "magic_0x438_ok": ok,
        "magic_0x438": f"{mag:#06x}",
    }
    try:
        _require_ext4()
    except ImportError as e:
        out["error"] = str(e)
        return out
    try:
        with open_ext2_volume(p) as vol:
            out["superblock"] = superblock_summary(vol)
            out["root_ls"] = list_dir(vol, "/")[:50]
    except Exception as e:
        out["parse_error"] = f"{type(e).__name__}: {e}"
    return out
