"""Resolve corpus refs to file bytes (``corpus cat`` / ``corpus locate``)."""

from __future__ import annotations

import hashlib
import re
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from corpus.index_db import (
    collection_image_filter_sql,
    collection_image_prefix,
    collection_slug_for_fs,
    collection_slug_from_image_path,
    lookup_blob_by_md5,
    lookup_blob_by_sha1,
    resolve_collection_slug_arg,
)
from corpus.paths import repo_root_from_module, work_corpus_dir
from corpus.ref import CorpusRef, collection_prefix_for_scope, parse_ref

_REPO = repo_root_from_module()


@dataclass
class LocateResult:
    ref: str
    scope: str
    file_path: str
    image_path: str
    image_id: str
    file_md5: Optional[str]
    on_disk: Optional[Path]
    cache_path: Optional[Path]
    resolver: str


def extract_cache_dir(repo_root: Optional[Path] = None) -> Path:
    root = repo_root if repo_root is not None else _REPO
    path = work_corpus_dir(root) / "extract_cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def cache_path_for_ref(ref: str, repo_root: Optional[Path] = None) -> Path:
    digest = hashlib.sha256(ref.encode("utf-8")).hexdigest()[:32]
    return extract_cache_dir(repo_root) / digest


def locate_ref(
    conn: sqlite3.Connection,
    ref: str,
    *,
    repo_root: Optional[Path] = None,
) -> LocateResult:
    parsed = parse_ref(ref)
    if parsed.scope == "@unknown":
        if not parsed.image_id:
            raise LookupError(f"ambiguous @unknown ref {ref!r}; use @unknown/<image-id>/path")
        rows = _lookup_file_rows_by_image_prefix(
            conn, parsed.file_path, parsed.image_id
        )
        if not rows:
            raise LookupError(f"no indexed file for ref {ref!r}")
        row = rows[0]
        image_path = str(row["image_path"])
        file_path = str(row["file_path"])
        on_disk = _find_materialized_file(repo_root, "@unknown", image_path, file_path)
        cache = cache_path_for_ref(ref, repo_root)
        return LocateResult(
            ref=ref,
            scope="@unknown",
            file_path=file_path,
            image_path=image_path,
            image_id=str(row["image_md5"])[:12],
            file_md5=str(row["file_md5"]) if row["file_md5"] is not None else None,
            on_disk=on_disk,
            cache_path=cache if cache.is_file() else None,
            resolver="image_id",
        )

    if parsed.scope.startswith("@"):
        digest = parsed.scope[1:].lower()
        row = None
        resolver = "md5"
        if len(digest) == 32:
            row = conn.execute(
                "SELECT f.path, f.md5, cb.sha1, i.path AS image_path, i.md5 AS image_md5 "
                "FROM files f JOIN images i ON f.image_id = i.id "
                "LEFT JOIN content_blobs cb ON cb.md5 = f.md5 "
                "WHERE f.md5 = ? LIMIT 1",
                (digest,),
            ).fetchone()
        elif len(digest) == 40:
            resolver = "sha1"
            row = conn.execute(
                "SELECT f.path, f.md5, cb.sha1, i.path AS image_path, i.md5 AS image_md5 "
                "FROM files f JOIN images i ON f.image_id = i.id "
                "JOIN content_blobs cb ON cb.md5 = f.md5 "
                "WHERE cb.sha1 = ? LIMIT 1",
                (digest,),
            ).fetchone()
        if row is None:
            raise LookupError(f"no file with digest {digest}")
        image_path = str(row["image_path"])
        file_path = str(row["path"])
        scope = collection_slug_from_image_path(image_path) or parsed.scope
        on_disk = _find_materialized_file(repo_root, scope, image_path, file_path)
        cache = cache_path_for_ref(ref, repo_root)
        image_id_src = row["image_md5"] or row["md5"] or digest
        return LocateResult(
            ref=ref,
            scope=scope,
            file_path=file_path,
            image_path=image_path,
            image_id=str(image_id_src)[:12],
            file_md5=str(row["md5"]),
            on_disk=on_disk,
            cache_path=cache if cache.is_file() else None,
            resolver=resolver,
        )

    scope = resolve_collection_slug_arg(parsed.scope)
    rows = _lookup_file_rows(conn, scope, parsed.file_path, parsed.image_id)
    if not rows:
        raise LookupError(f"no indexed file for ref {ref!r}")
    if len(rows) > 1 and not parsed.image_id:
        scopes = {r["image_path"] for r in rows}
        raise LookupError(
            f"ambiguous ref {ref!r} ({len(rows)} files); retry with image-id, e.g. "
            f"{format_ref_with_image_id(scope, parsed.file_path, str(rows[0]['image_md5'])[:12])}"
        )
    row = rows[0]
    image_path = str(row["image_path"])
    file_path = str(row["file_path"])
    on_disk = _find_materialized_file(repo_root, scope, image_path, file_path)
    cache = cache_path_for_ref(ref, repo_root)
    return LocateResult(
        ref=ref,
        scope=scope,
        file_path=file_path,
        image_path=image_path,
        image_id=str(row["image_md5"])[:12],
        file_md5=str(row["file_md5"]) if row["file_md5"] is not None else None,
        on_disk=on_disk,
        cache_path=cache if cache.is_file() else None,
        resolver="index",
    )


def format_ref_with_image_id(scope: str, file_path: str, image_id: str) -> str:
    from corpus.ref import format_ref

    return format_ref(scope, file_path, image_id=image_id)


def _indexed_file_size_bytes(
    conn: sqlite3.Connection,
    image_path: str,
    file_path: str,
) -> Optional[int]:
    file_path = file_path.replace("\\", "/").lstrip("/")
    row = conn.execute(
        "SELECT f.size_bytes FROM files f JOIN images i ON f.image_id = i.id "
        "WHERE i.path = ? AND f.path = ? LIMIT 1",
        (image_path, file_path),
    ).fetchone()
    if row is None:
        return None
    return int(row["size_bytes"])


def fetch_bytes(
    conn: sqlite3.Connection,
    ref: str,
    *,
    repo_root: Optional[Path] = None,
) -> bytes:
    loc = locate_ref(conn, ref, repo_root=repo_root)
    cache = cache_path_for_ref(ref, repo_root)
    if cache.is_file():
        return cache.read_bytes()
    indexed_size = _indexed_file_size_bytes(conn, loc.image_path, loc.file_path)
    if indexed_size == 0:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(b"")
        return b""
    if loc.on_disk is not None and loc.on_disk.is_file():
        data = loc.on_disk.read_bytes()
        cache.write_bytes(data)
        return data
    sbom_path = _sbom_materialized_file(loc.image_path, loc.file_path, repo_root=repo_root)
    if sbom_path is not None and sbom_path.is_file():
        data = sbom_path.read_bytes()
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(data)
        return data
    try:
        data = _extract_from_image(conn, loc.image_path, loc.file_path, repo_root=repo_root)
    except LookupError as exc:
        indexed = _fetch_text_lines_from_index(conn, loc.image_path, loc.file_path)
        if indexed is not None:
            data = indexed
        elif indexed_size == 0:
            data = b""
        else:
            raise
    except Exception as exc:
        indexed = _fetch_text_lines_from_index(conn, loc.image_path, loc.file_path)
        if indexed is not None:
            data = indexed
        elif indexed_size == 0:
            data = b""
        else:
            raise LookupError(
                f"extract failed for {loc.file_path!r} from {loc.image_path}: {exc}"
            ) from exc
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(data)
    return data


def apply_query_slice(data: bytes, query: Dict[str, str]) -> bytes:
    if not query:
        return data
    if "offset" in query or "len" in query:
        off = int(query.get("offset", "0"))
        ln = int(query["len"]) if "len" in query else len(data) - off
        return data[off : off + ln]
    if "line" in query:
        line_no = int(query["line"])
        lines = data.splitlines(keepends=True)
        if line_no < 1 or line_no > len(lines):
            raise LookupError(f"line {line_no} out of range (1..{len(lines)})")
        return lines[line_no - 1]
    return data


def _lookup_file_rows_by_image_prefix(
    conn: sqlite3.Connection,
    file_path: str,
    image_id_prefix: str,
) -> List[sqlite3.Row]:
    file_path = file_path.replace("\\", "/").lstrip("/")
    prefix = image_id_prefix.lower()
    sql = (
        "SELECT f.path AS file_path, f.md5 AS file_md5, cb.sha1 AS file_sha1, "
        "i.path AS image_path, i.md5 AS image_md5 "
        "FROM files f JOIN images i ON f.image_id = i.id "
        "LEFT JOIN content_blobs cb ON cb.md5 = f.md5 "
        "WHERE f.path = ? AND LOWER(COALESCE(i.md5, i.sha1, '')) LIKE ?"
    )
    return list(conn.execute(sql, (file_path, f"{prefix}%")))


def _lookup_file_rows(
    conn: sqlite3.Connection,
    scope: str,
    file_path: str,
    image_id: Optional[str],
) -> List[sqlite3.Row]:
    file_path = file_path.replace("\\", "/").lstrip("/")
    coll_sql, coll_args = collection_image_filter_sql(scope, image_alias="i")
    sql = (
        "SELECT f.path AS file_path, f.md5 AS file_md5, cb.sha1 AS file_sha1, "
        "i.path AS image_path, i.md5 AS image_md5 "
        "FROM files f JOIN images i ON f.image_id = i.id "
        "LEFT JOIN content_blobs cb ON cb.md5 = f.md5 "
        f"WHERE f.path = ?{coll_sql}"
    )
    rows = list(conn.execute(sql, (file_path,) + coll_args))
    if image_id:
        rows = [r for r in rows if str(r["image_md5"]).startswith(image_id)]
    return rows


def _repo_resolve_path(path_str: str, repo_root: Optional[Path]) -> Path:
    p = Path(path_str)
    if p.is_file():
        return p.resolve()
    root = repo_root if repo_root is not None else _REPO
    q = (root / path_str).resolve()
    return q if q.is_file() else p


def _sbom_materialized_file(
    image_path: str,
    file_path: str,
    *,
    repo_root: Optional[Path] = None,
) -> Optional[Path]:
    from corpus.sbom import safe_sbom_name

    root = repo_root if repo_root is not None else _REPO
    file_path_norm = file_path.replace("\\", "/").lstrip("/")
    tree_name = safe_sbom_name(image_path, suffix="")
    sbom_root = work_corpus_dir(root) / "sbom"
    if not sbom_root.is_dir():
        return None
    for sources in sbom_root.glob("*/sources"):
        candidate = sources / tree_name / file_path_norm
        if candidate.is_file():
            return candidate
    return None


def _fetch_text_lines_from_index(
    conn: sqlite3.Connection,
    image_path: str,
    file_path: str,
) -> Optional[bytes]:
    """Rebuild a text file from per-line index rows when SquashFS extract is unavailable."""
    file_path = file_path.replace("\\", "/").lstrip("/")
    rows = conn.execute(
        "SELECT t.line_no, t.text FROM blob_text_lines t "
        "JOIN files f ON f.md5 = t.content_md5 "
        "JOIN images i ON f.image_id = i.id "
        "WHERE i.path = ? AND f.path = ? ORDER BY t.line_no",
        (image_path, file_path),
    ).fetchall()
    if not rows:
        return None
    parts: List[str] = []
    for row in rows:
        text = str(row["text"] or "")
        if text and not text.endswith("\n"):
            text += "\n"
        parts.append(text)
    return "".join(parts).encode("utf-8")


def _find_materialized_file(
    repo_root: Optional[Path],
    scope: str,
    image_path: str,
    file_path: str,
) -> Optional[Path]:
    root = repo_root if repo_root is not None else _REPO
    file_path_norm = file_path.replace("\\", "/").lstrip("/")
    candidates: List[Path] = []

    sbom_hit = _sbom_materialized_file(image_path, file_path_norm, repo_root=root)
    if sbom_hit is not None:
        return sbom_hit

    fs_seg = collection_slug_for_fs(scope)
    for base_name in (
        "pkgstream_corpus_by_version",
        "pkgstream_corpus",
        "flash_corpus",
    ):
        base = work_corpus_dir(root) / base_name
        if not base.is_dir():
            continue
        for staging in base.glob(f"*{fs_seg}*"):
            if staging.is_dir():
                for path in staging.rglob(file_path_norm.split("/")[-1]):
                    if path.is_file() and path.as_posix().endswith(file_path_norm):
                        candidates.append(path)

    squash_m = re.search(r":squash_embedded:([^:]+)", image_path)
    if squash_m:
        offset = squash_m.group(1)
        for staging in (work_corpus_dir(root) / "pkgstream_corpus_by_version").glob(f"**/*{offset}*"):
            pass

    for candidate in candidates:
        if candidate.is_file():
            rel_try = candidate.as_posix()
            if rel_try.endswith(file_path_norm):
                return candidate

    if ":squash_embedded:" in image_path or image_path.endswith(".squashfs"):
        return None
    carrier = _squashfs_blob_path(image_path, repo_root=root)
    if carrier is not None:
        joined = carrier.parent / file_path_norm
        if joined.is_file():
            return joined
    return candidates[0] if candidates else None


def _unsquashfs_read_file(blob: Path, inner_path: str) -> Optional[bytes]:
    exe = shutil.which("unsquashfs")
    if not exe:
        return None
    inner_path = inner_path.replace("\\", "/").lstrip("/")
    try:
        proc = subprocess.run(
            [exe, "-f", "-c", str(blob.resolve()), inner_path],
            capture_output=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _read_squashfs_inner_file(blob: Path, inner_path: str) -> bytes:
    from lib2spy.pkgstream_corpus import iter_squashfs_files

    inner_path = inner_path.replace("\\", "/").lstrip("/")
    try:
        for rel, data in iter_squashfs_files(blob):
            if rel.replace("\\", "/").lstrip("/") == inner_path:
                return data
    except Exception as dissect_err:
        unsquash = _unsquashfs_read_file(blob, inner_path)
        if unsquash is not None:
            return unsquash
        raise LookupError(
            f"dissect failed on {blob} ({dissect_err}); install unsquashfs or use corpus-runtime Docker"
        ) from dissect_err
    raise LookupError(f"{inner_path!r} not in squashfs {blob}")


def _extract_from_image(
    conn: sqlite3.Connection,
    image_path: str,
    file_path: str,
    *,
    repo_root: Optional[Path] = None,
) -> bytes:
    blob = _squashfs_blob_path(image_path, repo_root=repo_root)
    if blob is None:
        raise LookupError(f"cannot resolve carrier for {image_path}")
    return _read_squashfs_inner_file(blob, file_path)


def _squashfs_blob_path(image_path: str, *, repo_root: Optional[Path] = None) -> Optional[Path]:
    m = re.search(r":squash_embedded:([^:]+)", image_path)
    if not m:
        resolved = _repo_resolve_path(image_path, repo_root)
        if resolved.is_file():
            return resolved
        return None
    token = m.group(1)
    root = repo_root if repo_root is not None else _REPO
    work = work_corpus_dir(root)
    for base in work.rglob("*"):
        if base.is_file() and token.replace("0x", "") in base.name:
            return base
    pkg_m = re.search(r":pkgstream:([^:]+\\.pkgstream)", image_path, re.I)
    if pkg_m:
        pkg = Path(pkg_m.group(1))
        if pkg.is_file():
            side = pkg.parent / f"{pkg.name}.sidecars" / f"squash_{token}.bin"
            if side.is_file():
                return side
    return None
