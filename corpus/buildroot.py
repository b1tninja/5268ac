"""
Buildroot reference indexing and stock vs manufacturer file classification.

A Buildroot ``target/`` (or staged firmware sysroot used as reference) is indexed with
image key ``buildroot:<profile>`` (e.g. ``buildroot:2011.11``). Firmware pkgstream
collections use ``collection:<slug>:…`` keys. Compare by relative path and SHA-256.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from corpus.index_db import (
    build_index_for_extracted_tree,
    collection_image_prefix,
    normalize_collection_slug,
)

Origin = Literal["stock", "vendor_modified", "vendor_path", "buildroot_only", "unknown"]

_BUILDROOT_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def normalize_buildroot_profile(profile: str) -> str:
    """Filesystem-safe profile id (Buildroot version tag, e.g. ``2011.11``)."""
    s = profile.strip().replace("\\", "/").strip("/")
    if not s:
        return "default"
    s = s.replace("/", "_").replace(":", "_")
    if not _BUILDROOT_PROFILE_RE.match(s):
        raise ValueError(f"invalid buildroot profile: {profile!r}")
    return s


def format_buildroot_image_key(profile: str) -> str:
    return f"buildroot:{normalize_buildroot_profile(profile)}"


def build_index_for_buildroot(
    conn: sqlite3.Connection,
    target_root: Path,
    profile: str,
    *,
    max_file_bytes: int = 32 * 1024 * 1024,
    skip_suffixes: bool = True,
    symtab: bool = False,
    min_string_len: int = 4,
    max_strings_per_file: int = 2000,
    dwarf: bool = False,
    progress: Optional[Any] = None,
) -> Dict[str, Any]:
    """Index a Buildroot ``target/`` tree (or compatible rootfs) under ``buildroot:<profile>``."""
    key = format_buildroot_image_key(profile)
    result = build_index_for_extracted_tree(
        conn,
        target_root,
        image_key=key,
        max_file_bytes=max_file_bytes,
        skip_suffixes=skip_suffixes,
        symtab=symtab,
        min_string_len=min_string_len,
        max_strings_per_file=max_strings_per_file,
        dwarf=dwarf,
        progress=progress,
    )
    if result.get("ok"):
        result["buildroot_profile"] = normalize_buildroot_profile(profile)
        result["buildroot_image_key"] = key
    return result


def list_buildroot_profiles(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT path, file_count, indexed_at FROM images WHERE path LIKE 'buildroot:%' ORDER BY path"
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for row in rows:
        path = str(row["path"])
        out.append(
            {
                "profile": path.split(":", 1)[1] if ":" in path else path,
                "image_key": path,
                "file_count": row["file_count"],
                "indexed_at": row["indexed_at"],
            }
        )
    return out


def _file_map_for_image(conn: sqlite3.Connection, image_key: str) -> Dict[str, str]:
    row = conn.execute("SELECT id FROM images WHERE path = ?", (image_key,)).fetchone()
    if row is None:
        return {}
    image_id = int(row["id"])
    cur = conn.execute(
        "SELECT path, sha256 FROM files WHERE image_id = ?",
        (image_id,),
    )
    return {str(r["path"]): str(r["sha256"]) for r in cur}


def _firmware_files_for_collection(
    conn: sqlite3.Connection,
    collection_slug: str,
) -> List[Dict[str, str]]:
    prefix = collection_image_prefix(collection_slug)
    rows = conn.execute(
        "SELECT f.path, f.sha256, i.path AS image_key "
        "FROM files f JOIN images i ON f.image_id = i.id "
        "WHERE substr(i.path, 1, length(?)) = ? "
        "ORDER BY f.path, i.path",
        (prefix, prefix),
    ).fetchall()
    return [
        {
            "path": str(r["path"]),
            "sha256": str(r["sha256"]),
            "image_key": str(r["image_key"]),
        }
        for r in rows
    ]


def classify_origin(
    rel_path: str,
    firmware_sha256: str,
    buildroot_by_path: Dict[str, str],
) -> Origin:
    br_sha = buildroot_by_path.get(rel_path)
    if br_sha is None:
        return "vendor_path"
    if br_sha == firmware_sha256:
        return "stock"
    return "vendor_modified"


@dataclass
class BuildrootFileRow:
    path: str
    sha256: str
    image_key: str
    origin: Origin
    buildroot_sha256: Optional[str] = None


@dataclass
class BuildrootDiffReport:
    buildroot_profile: str
    buildroot_image_key: str
    collection: str
    stock: int
    vendor_modified: int
    vendor_path: int
    buildroot_only: int
    rows: List[BuildrootFileRow]
    buildroot_only_paths: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "buildroot_profile": self.buildroot_profile,
            "buildroot_image_key": self.buildroot_image_key,
            "collection": self.collection,
            "counts": {
                "stock": self.stock,
                "vendor_modified": self.vendor_modified,
                "vendor_path": self.vendor_path,
                "buildroot_only": self.buildroot_only,
            },
            "buildroot_only_paths": self.buildroot_only_paths[:200],
            "samples": {
                "vendor_path": [r.path for r in self.rows if r.origin == "vendor_path"][:50],
                "vendor_modified": [r.path for r in self.rows if r.origin == "vendor_modified"][:50],
                "stock": [r.path for r in self.rows if r.origin == "stock"][:20],
            },
        }


def diff_collection_vs_buildroot(
    conn: sqlite3.Connection,
    collection_slug: str,
    buildroot_profile: str,
    *,
    limit_rows: int = 0,
) -> BuildrootDiffReport:
    """
    Compare every indexed firmware file in *collection_slug* against ``buildroot:<profile>``.

    * **stock** — same relative path and SHA-256 as Buildroot reference.
    * **vendor_modified** — path exists in Buildroot but content differs (vendor patch).
    * **vendor_path** — path only on firmware (manufacturer addition).
    * **buildroot_only** — path only in Buildroot reference (not in this collection).
    """
    profile = normalize_buildroot_profile(buildroot_profile)
    br_key = format_buildroot_image_key(profile)
    br_map = _file_map_for_image(conn, br_key)
    if not br_map:
        raise LookupError(
            f"no indexed Buildroot reference for profile {profile!r} "
            f"(image key {br_key!r}); run: python -m corpus --build-index --buildroot TARGET/ "
            f"--buildroot-profile {profile}"
        )

    collection = normalize_collection_slug(collection_slug)
    fw_files = _firmware_files_for_collection(conn, collection)
    if not fw_files:
        raise LookupError(
            f"no indexed files for collection {collection!r}; "
            "index pkgstream or squashfs with --collection first"
        )

    rows: List[BuildrootFileRow] = []
    counts = {"stock": 0, "vendor_modified": 0, "vendor_path": 0}
    fw_paths: set[str] = set()

    for item in fw_files:
        rel = item["path"]
        fw_paths.add(rel)
        origin = classify_origin(rel, item["sha256"], br_map)
        counts[origin] += 1
        rows.append(
            BuildrootFileRow(
                path=rel,
                sha256=item["sha256"],
                image_key=item["image_key"],
                origin=origin,
                buildroot_sha256=br_map.get(rel),
            )
        )
        if limit_rows and len(rows) >= limit_rows:
            break

    br_only = sorted(set(br_map) - fw_paths)
    return BuildrootDiffReport(
        buildroot_profile=profile,
        buildroot_image_key=br_key,
        collection=collection,
        stock=counts["stock"],
        vendor_modified=counts["vendor_modified"],
        vendor_path=counts["vendor_path"],
        buildroot_only=len(br_only),
        rows=rows,
        buildroot_only_paths=br_only,
    )


def lookup_path_origin(
    conn: sqlite3.Connection,
    collection_slug: str,
    rel_path: str,
    buildroot_profile: str,
) -> Dict[str, Any]:
    """Classify one firmware path (first match in collection) vs Buildroot."""
    profile = normalize_buildroot_profile(buildroot_profile)
    br_key = format_buildroot_image_key(profile)
    br_map = _file_map_for_image(conn, br_key)
    if not br_map:
        raise LookupError(f"Buildroot profile not indexed: {profile}")

    rel = rel_path.replace("\\", "/").lstrip("./")
    prefix = collection_image_prefix(collection_slug)
    row = conn.execute(
        "SELECT f.path, f.sha256, i.path AS image_key "
        "FROM files f JOIN images i ON f.image_id = i.id "
        "WHERE substr(i.path, 1, length(?)) = ? AND f.path = ? LIMIT 1",
        (prefix, prefix, rel),
    ).fetchone()
    if row is None:
        return {
            "path": rel,
            "collection": normalize_collection_slug(collection_slug),
            "buildroot_profile": profile,
            "origin": "unknown",
            "detail": "path not found in collection index",
        }

    fw_sha = str(row["sha256"])
    origin = classify_origin(rel, fw_sha, br_map)
    return {
        "path": rel,
        "collection": normalize_collection_slug(collection_slug),
        "buildroot_profile": profile,
        "buildroot_image_key": br_key,
        "origin": origin,
        "firmware_sha256": fw_sha,
        "buildroot_sha256": br_map.get(rel),
        "image_key": str(row["image_key"]),
    }


def default_buildroot_target_candidates(repo_root: Path) -> List[Path]:
    """Common ``target/`` paths from ``cross/buildroot`` workflows."""
    base = repo_root / "work_corpus" / "toolchain"
    return [
        p
        for p in (
            base / "output" / "target",
            base / "output-2013.05" / "target",
            base / "output-2011.11" / "target",
        )
        if p.is_dir()
    ]
