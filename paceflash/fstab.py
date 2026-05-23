"""Parse ``/etc/fstab`` after a root filesystem image is available (ext2/3/4 via Dissect)."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class FstabEntry:
    """One non-comment line in ``fstab`` (six fields, ``#`` starts a comment)."""

    fs_spec: str
    mount_point: str
    vfs_type: str
    mntops: str
    freq: int
    passno: int


_WS = re.compile(r"\s+")


def parse_fstab(text: str) -> tuple[FstabEntry, ...]:
    """
    Parse ``fstab`` text (POSIX-ish: ``#`` comments, blank lines ignored).

    Does not validate paths or filesystem types.
    """
    out: list[FstabEntry] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
        parts = _WS.split(line)
        if len(parts) < 6:
            continue
        fs_spec, mount_point, vfs_type, mntops, freq_s, pass_s = parts[:6]
        out.append(
            FstabEntry(
                fs_spec=fs_spec,
                mount_point=mount_point,
                vfs_type=vfs_type,
                mntops=mntops,
                freq=int(freq_s, 0),
                passno=int(pass_s, 0),
            )
        )
    return tuple(out)


def _read_regular_via_symlinks(fs: object, posix_path: str, *, max_depth: int = 40) -> bytes:
    """Resolve symlinks (relative targets) and return a regular file's raw bytes."""
    from dissect.extfs.exceptions import FileNotFoundError as ExtFileNotFoundError

    path = posix_path
    depth = 0
    while depth < max_depth:
        try:
            node = fs.get(path)
        except ExtFileNotFoundError as e:
            raise OSError(f"missing {path!r}") from e
        if node.filetype == stat.S_IFLNK:
            target = node.link
            if target.startswith("/"):
                path = os.path.normpath(target)
            else:
                parent = os.path.dirname(path.rstrip("/")) or "/"
                path = os.path.normpath(os.path.join(parent, target))
            depth += 1
            continue
        if node.filetype != stat.S_IFREG:
            raise OSError(f"not a regular file: {path!r} (mode {node.filetype:#o})")
        return node.open().read()
    raise OSError("symlink recursion depth exceeded")


def read_fstab_text_from_extfs_image(image_path: str | Path) -> str:
    """
    Read ``/etc/fstab`` from an ext2/3/4 **disk image file** (carved slice or full volume).

    Requires ``dissect.extfs``. Follows symlinks on the volume like a typical rootfs.
    """
    from dissect.extfs import ExtFS

    p = Path(image_path).expanduser().resolve()
    with p.open("rb") as fh:
        fs = ExtFS(fh)
        raw = _read_regular_via_symlinks(fs, "/etc/fstab")
    return raw.decode("utf-8", errors="replace")


def parse_fstab_from_extfs_image(image_path: str | Path) -> tuple[FstabEntry, ...]:
    """Convenience: :func:`read_fstab_text_from_extfs_image` then :func:`parse_fstab`."""
    return parse_fstab(read_fstab_text_from_extfs_image(image_path))


__all__ = [
    "FstabEntry",
    "parse_fstab",
    "parse_fstab_from_extfs_image",
    "read_fstab_text_from_extfs_image",
]
