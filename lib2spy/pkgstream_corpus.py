"""
Slice artifacts from a carrier ``.pkgstream`` via :mod:`lib2spy.native_pkgstream` (magic scan).
Also write SHA-256 manifests for extracted blobs or an unpacked directory tree.
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from lib2spy.native_pkgstream import extract_slices_native

DEFAULT_EXTRACT_NAMES: Set[str] = frozenset({"squashfs", "uimage"})


def extract_squashfs_dissect_tree(squashfs_path: str | Path, out_root: str | Path) -> Dict[str, Any]:
    """
    Extract a SquashFS **4.x little-endian** image to a normal directory tree using
    `dissect.squashfs <https://pypi.org/project/dissect.squashfs/>`_ (optional dependency;
    install with ``pip install dissect.squashfs`` or ``pip install -e ".[dissect]"``).

    Skips symlinks and non-regular inodes. Returns ``{"ok", "files_written", ...}``.
    """
    try:
        from dissect.squashfs import SquashFS  # type: ignore[import-untyped]
    except ImportError as e:
        return {
            "ok": False,
            "error": f"dissect.squashfs not installed ({e}); pip install dissect.squashfs",
            "files_written": 0,
            "out_root": str(Path(out_root).resolve()),
        }

    src = Path(squashfs_path).resolve()
    root = Path(out_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    written = 0

    def walk(inode: Any, rel: str) -> None:
        nonlocal written
        if inode.is_symlink():
            return
        if inode.is_file():
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            stream = inode.open()
            try:
                data = stream.read()
            finally:
                stream.close()
            dest.write_bytes(data)
            written += 1
        elif inode.is_dir():
            for ch in inode.iterdir():
                sub = f"{rel}/{ch.name}".strip("/") if rel else ch.name
                walk(ch, sub)

    try:
        with src.open("rb") as fh:
            fs = SquashFS(fh)
            walk(fs.root, "")
        return {"ok": True, "files_written": written, "out_root": str(root), "squashfs_path": str(src)}
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "files_written": written,
            "out_root": str(root),
            "squashfs_path": str(src),
        }


def iter_squashfs_files(squashfs_path: str | Path) -> Iterator[Tuple[str, bytes]]:
    """
    Yield ``(relative_posix_path, file_bytes)`` for each regular file in a SquashFS image
    via ``dissect.squashfs``. Symlinks are skipped.

    Requires ``pip install dissect.squashfs``. Raises ``ImportError`` if unavailable.
    """
    from dissect.squashfs import SquashFS  # type: ignore[import-untyped]

    src = Path(squashfs_path).resolve()

    def walk(inode: Any, rel: str) -> Iterator[Tuple[str, bytes]]:
        if inode.is_symlink():
            return
        if inode.is_file():
            stream = inode.open()
            try:
                data = stream.read()
            finally:
                stream.close()
            norm = rel.replace("\\", "/").lstrip("/")
            yield (norm, data)
        elif inode.is_dir():
            for ch in inode.iterdir():
                sub = f"{rel}/{ch.name}".strip("/") if rel else ch.name
                yield from walk(ch, sub)

    with src.open("rb") as fh:
        fs = SquashFS(fh)
        yield from walk(fs.root, "")


def iter_squashfs_files_from_bytes(data: bytes) -> Iterator[Tuple[str, bytes]]:
    """
    Yield ``(relative_posix_path, file_bytes)`` for each regular file in an in-memory
    SquashFS image via ``dissect.squashfs``. Symlinks are skipped.
    """
    from dissect.squashfs import SquashFS  # type: ignore[import-untyped]

    def walk(inode: Any, rel: str) -> Iterator[Tuple[str, bytes]]:
        if inode.is_symlink():
            return
        if inode.is_file():
            stream = inode.open()
            try:
                body = stream.read()
            finally:
                stream.close()
            yield (rel.replace("\\", "/").lstrip("/"), body)
        elif inode.is_dir():
            for ch in inode.iterdir():
                sub = f"{rel}/{ch.name}".strip("/") if rel else ch.name
                yield from walk(ch, sub)

    fs = SquashFS(io.BytesIO(data))
    yield from walk(fs.root, "")


def unsquash_pkgstream_carves_dissect(
    manifest_rows: Sequence[Dict[str, Any]],
    dissect_out_dir: str | Path,
) -> Dict[str, Any]:
    """
    For each carved row with ``signature_name == "squashfs"``, extract under
    ``dissect_out_dir/<carve_stem>/`` via :func:`extract_squashfs_dissect_tree`.
    """
    base = Path(dissect_out_dir).resolve()
    base.mkdir(parents=True, exist_ok=True)
    trees: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for row in manifest_rows:
        if row.get("signature_name") != "squashfs":
            continue
        carved = Path(row["path"]).resolve()
        sub = base / carved.stem
        res = extract_squashfs_dissect_tree(carved, sub)
        entry = {"carved_path": str(carved), "extract_root": str(sub), **res}
        if res.get("ok"):
            trees.append(entry)
        else:
            errors.append(entry)

    return {
        "dissect_out_dir": str(base),
        "trees_ok": len(trees),
        "trees_failed": len(errors),
        "trees": trees,
        "errors": errors,
    }


def extract_pkgstream_slices(
    pkgstream_path: str | Path,
    out_dir: str | Path,
    *,
    names: Optional[Sequence[str]] = None,
    write_manifest: bool = True,
    unsquash_dissect_out: Optional[str] = None,
    strict_uimage_decompress: bool = False,
) -> Dict[str, Any]:
    """
    Carve SquashFS / uImage from ``pkgstream_path`` using :func:`lib2spy.native_pkgstream.scan_embedded_images`
    (magic / superblock scan; optional outer bzip2 decompression). Filenames match
    the native embedded-image scanner. Optionally writes ``corpus_manifest.json``.

    Returns a summary dict suitable for JSON serialization.
    """
    want: Optional[Set[str]] = set(names) if names is not None else None
    summary = extract_slices_native(
        str(Path(pkgstream_path).resolve()),
        str(Path(out_dir).resolve()),
        names=want,
        write_manifest=write_manifest,
        strict_uimage_decompress=strict_uimage_decompress,
    )
    manifest_rows: List[Dict[str, Any]] = summary.pop("manifest_rows", [])
    if unsquash_dissect_out and manifest_rows:
        summary["unsquash_dissect"] = unsquash_pkgstream_carves_dissect(
            manifest_rows, unsquash_dissect_out
        )
        summary["unsquash_dissect_note"] = (
            "Corpus tree(s) for tl-crc-index (and optional corpus string search) live under dissect_out_dir; "
            "dissect.squashfs is AGPL-3.0 — see https://pypi.org/project/dissect.squashfs/"
        )
    return summary


def extract_pkgstream_slices_native(
    pkgstream_path: str,
    out_dir: str,
    *,
    names: Optional[Sequence[str]] = None,
    write_manifest: bool = True,
    unsquash_dissect_out: Optional[str] = None,
    strict_uimage_decompress: bool = False,
) -> Dict[str, Any]:
    """Alias for :func:`extract_pkgstream_slices` (kept for older call sites)."""
    return extract_pkgstream_slices(
        pkgstream_path,
        out_dir,
        names=names,
        write_manifest=write_manifest,
        unsquash_dissect_out=unsquash_dissect_out,
        strict_uimage_decompress=strict_uimage_decompress,
    )


def write_directory_manifest(
    root_dir: str,
    out_json_path: str,
    *,
    max_hash_bytes: int = 4 * 1024 * 1024,
    skip_suffixes: Sequence[str] = (".pyc", ".pyo"),
) -> Dict[str, Any]:
    """
    Walk ``root_dir`` (e.g. unsquashed SquashFS tree), record path relative to root,
    size, and SHA-256 of first ``max_hash_bytes`` bytes per file.
    """
    root = Path(root_dir).resolve()
    out: List[Dict[str, Any]] = []
    for fp in sorted(root.rglob("*")):
        if not fp.is_file():
            continue
        if any(str(fp).endswith(s) for s in skip_suffixes):
            continue
        rel = fp.relative_to(root).as_posix()
        sz = fp.stat().st_size
        read_n = min(sz, max_hash_bytes)
        data = fp.read_bytes()[:read_n] if read_n else b""
        h = hashlib.sha256(data).hexdigest()
        out.append(
            {
                "relative_path": rel,
                "size": sz,
                "sha256_prefix": h,
                "hashed_bytes": read_n,
            }
        )
    payload = {"root": str(root), "file_count": len(out), "files": out}
    Path(out_json_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload
