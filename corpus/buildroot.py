"""
Buildroot reference indexing and stock vs manufacturer file classification.

A Buildroot ``target/`` (or staged firmware sysroot used as reference) is indexed with
image key ``buildroot:<profile>`` (e.g. ``buildroot:2011.11``). Firmware pkgstream
collections use ``collection:<slug>:…`` keys. Compare by relative path and MD5.
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
    collection_image_filter_sql,
    collection_image_prefix,
    image_collection_prefix_from_path,
    normalize_collection_slug,
)

Origin = Literal["stock", "vendor_modified", "vendor_path", "buildroot_only", "unknown"]

_BUILDROOT_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_GCC_BUILDROOT_RE = re.compile(
    r"GCC:\s*\(Buildroot\s+([^)]+)\)\s+(\d+\.\d+\.\d+)",
    re.IGNORECASE,
)


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
        "SELECT path, md5 FROM files WHERE image_id = ?",
        (image_id,),
    )
    return {str(r["path"]): str(r["md5"]) for r in cur}


def _firmware_files_for_collection(
    conn: sqlite3.Connection,
    collection_slug: str,
) -> List[Dict[str, str]]:
    coll_sql, coll_args = collection_image_filter_sql(
        collection_slug, leading_where=True
    )
    rows = conn.execute(
        "SELECT f.path, f.md5, i.path AS image_key "
        "FROM files f JOIN images i ON f.image_id = i.id "
        + coll_sql
        + " ORDER BY f.path, i.path",
        coll_args,
    ).fetchall()
    return [
        {
            "path": str(r["path"]),
            "md5": str(r["md5"]),
            "image_key": str(r["image_key"]),
        }
        for r in rows
    ]


def classify_origin(
    rel_path: str,
    firmware_md5: str,
    buildroot_by_path: Dict[str, str],
) -> Origin:
    br_md5 = buildroot_by_path.get(rel_path)
    if br_md5 is None:
        return "vendor_path"
    if br_md5 == firmware_md5:
        return "stock"
    return "vendor_modified"


@dataclass
class BuildrootFileRow:
    path: str
    md5: str
    image_key: str
    origin: Origin
    buildroot_md5: Optional[str] = None


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

    * **stock** — same relative path and MD5 as Buildroot reference.
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
        origin = classify_origin(rel, item["md5"], br_map)
        counts[origin] += 1
        rows.append(
            BuildrootFileRow(
                path=rel,
                md5=item["md5"],
                image_key=item["image_key"],
                origin=origin,
                buildroot_md5=br_map.get(rel),
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
    coll_sql, coll_args = collection_image_filter_sql(
        collection_slug, leading_where=True
    )
    row = conn.execute(
        "SELECT f.path, f.md5, i.path AS image_key "
        "FROM files f JOIN images i ON f.image_id = i.id "
        + coll_sql
        + " AND f.path = ? LIMIT 1",
        coll_args + (rel,),
    ).fetchone()
    if row is None:
        return {
            "path": rel,
            "collection": normalize_collection_slug(collection_slug),
            "buildroot_profile": profile,
            "origin": "unknown",
            "detail": "path not found in collection index",
        }

    fw_md5 = str(row["md5"])
    origin = classify_origin(rel, fw_md5, br_map)
    return {
        "path": rel,
        "collection": normalize_collection_slug(collection_slug),
        "buildroot_profile": profile,
        "buildroot_image_key": br_key,
        "origin": origin,
        "firmware_md5": fw_md5,
        "buildroot_md5": br_map.get(rel),
        "image_key": str(row["image_key"]),
    }


_COLLECTION_CARRIER_MARKERS = (
    ":pkgstream:",
    ":paceflash:",
    ":squash_embedded:",
    ":squash:",
    ":kernel_elf:",
    ":tlv:",
)
_VERSION_COLLECTION_SLUG_RE = re.compile(
    r"^(version:\d{1,2}\.\d{1,2}\.\d{1,6}(?:\.\d{1,6})?)"
)
_STAGING_VERSION_SEGMENT_RE = re.compile(
    r"(?:^|[/\\])version_(\d{1,2}\.\d{1,2}\.\d{1,6}(?:\.\d{1,6})?)(?:[/\\]|$)"
)


def collection_slug_from_image_path(image_path: str) -> Optional[str]:
    """Extract collection slug from a ``collection:…`` or staging-tree image key."""
    from corpus.index_db import collection_slug_from_image_path as _slug_from_key

    slug = _slug_from_key(image_path)
    if slug:
        m = _VERSION_COLLECTION_SLUG_RE.match(slug)
        if m:
            return m.group(1)
        return slug

    norm = image_path.replace("\\", "/")
    staging = _STAGING_VERSION_SEGMENT_RE.search(norm)
    if staging:
        return f"version:{staging.group(1)}"

    prefix = image_collection_prefix_from_path(image_path)
    if prefix:
        slug = prefix[len("collection:") :].rstrip(":")
        return slug or None
    if not image_path.startswith("collection:"):
        return None
    rest = image_path[len("collection:") :]
    cut = len(rest)
    for marker in _COLLECTION_CARRIER_MARKERS:
        pos = rest.find(marker)
        if pos > 0:
            cut = min(cut, pos)
    slug = rest[:cut].rstrip(":")
    m = _VERSION_COLLECTION_SLUG_RE.match(slug)
    if m:
        return m.group(1)
    return slug or None


def list_firmware_collections(conn: sqlite3.Connection) -> List[str]:
    """Distinct firmware collection slugs present in the index."""
    rows = conn.execute("SELECT path FROM images ORDER BY path").fetchall()
    seen: set[str] = set()
    out: List[str] = []
    for row in rows:
        slug = collection_slug_from_image_path(str(row["path"]))
        if slug and slug not in seen:
            seen.add(slug)
            out.append(slug)
    return sorted(out, key=_collection_sort_key)


def list_collection_details(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Per-collection summary: slug, indexed images, total file_count, metadata."""
    from corpus.index_db import get_collection_metadata

    rows = conn.execute(
        "SELECT path, file_count, indexed_at FROM images ORDER BY path"
    ).fetchall()
    by_slug: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        image_key = str(row["path"])
        slug = collection_slug_from_image_path(image_key)
        if not slug:
            continue
        entry = by_slug.setdefault(
            slug,
            {"collection": slug, "images": [], "file_count": 0},
        )
        fc = int(row["file_count"] or 0)
        entry["images"].append(
            {
                "image_key": image_key,
                "file_count": fc,
                "indexed_at": row["indexed_at"],
            }
        )
        entry["file_count"] += fc
    for slug, entry in by_slug.items():
        meta = get_collection_metadata(conn, slug)
        if meta:
            entry["release_path"] = meta.get("release_path")
            entry["firmware_version"] = meta.get("firmware_version")
            entry["component_version"] = meta.get("component_version")
            entry["channel"] = meta.get("channel")
            entry["install_pkgstream"] = meta.get("install_pkgstream")
    return [by_slug[s] for s in sorted(by_slug, key=_collection_sort_key)]


def _collection_sort_key(slug: str) -> Tuple[Any, ...]:
    """Sort ``version:`` / ``pkgstream:`` slugs with stable comparable keys."""
    from corpus.index_db import firmware_version_sort_key

    if slug.startswith("version:"):
        ver = slug.split(":", 1)[1]
        return (0, firmware_version_sort_key(ver), slug)
    if slug.startswith("pkgstream:"):
        tail = slug.split(":", 1)[1]
        m = re.search(r"(\d{1,2}\.\d{1,2}\.\d{1,6}(?:\.\d{1,6})?)", tail)
        ver_key = firmware_version_sort_key(m.group(1)) if m else (0,)
        return (0, ver_key, slug)
    if slug.startswith("nand:"):
        return (1, slug)
    if slug.startswith("buildroot:"):
        return (2, slug)
    return (3, slug)


def _carrier_rank(image_key: str) -> int:
    key = image_key.lower()
    if "0001_" in key:
        return 0
    if "install" in key:
        return 1
    return 2


def _pick_preferred_carrier(rows: List[Dict[str, Any]]) -> Optional[str]:
    if not rows:
        return None
    ranked = sorted(
        rows,
        key=lambda r: (
            _carrier_rank(str(r.get("image_key", ""))),
            -float(r.get("confidence") or 0),
            str(r.get("image_key", "")),
        ),
    )
    return str(ranked[0]["image_key"])


def _normalize_buildroot_tag(tag: Optional[str]) -> Optional[str]:
    if not tag:
        return None
    return tag.strip().split("-")[0]


def metadata_mismatch(
    os_release_version_id: Optional[str],
    gcc_buildroot: Optional[str],
) -> Tuple[bool, Optional[str]]:
    """True when claimed os-release Buildroot tag disagrees with ELF gcc branding."""
    os_tag = _normalize_buildroot_tag(os_release_version_id)
    gcc_tag = _normalize_buildroot_tag(gcc_buildroot)
    if not os_tag or not gcc_tag:
        return False, None
    if os_tag == gcc_tag:
        return False, None
    return True, f"os-release VERSION_ID={os_tag!r} vs gcc Buildroot {gcc_tag!r}"


def os_release_fields(
    conn: sqlite3.Connection,
    collection_slug: str,
) -> Dict[str, Any]:
    """Release-file keys for ``etc/os-release`` (preferred install carrier)."""
    coll_sql, coll_args = collection_image_filter_sql(
        collection_slug, leading_where=True
    )
    rows = conn.execute(
        "SELECT i.path AS image_key, v.key, v.value, v.confidence "
        "FROM file_versions v JOIN images i ON v.image_id = i.id "
        + coll_sql
        + " AND v.path LIKE '%os-release' AND v.source = 'release_file' "
        "ORDER BY i.path, v.key",
        coll_args,
    ).fetchall()
    if not rows:
        return {"fields": {}, "image_key": None}

    by_carrier: Dict[str, List[Any]] = {}
    for row in rows:
        ik = str(row["image_key"])
        by_carrier.setdefault(ik, []).append(row)

    pick_from = [
        {"image_key": ik, "confidence": max(float(r["confidence"] or 0) for r in grp)}
        for ik, grp in by_carrier.items()
    ]
    chosen = _pick_preferred_carrier(pick_from)
    assert chosen is not None

    fields = {
        str(r["key"]): str(r["value"])
        for r in by_carrier[chosen]
    }
    return {"fields": fields, "image_key": chosen}


def elf_toolchain_comment(
    conn: sqlite3.Connection,
    collection_slug: str,
    elf_path: str = "bin/busybox",
) -> Dict[str, Any]:
    """Parse gcc / Buildroot identity from ``.comment`` on a canonical ELF."""
    coll_sql, coll_args = collection_image_filter_sql(
        collection_slug, leading_where=True
    )
    rows = conn.execute(
        "SELECT i.path AS image_key, s.text "
        "FROM elf_strings s JOIN images i ON s.image_id = i.id "
        + coll_sql
        + " AND s.path = ? AND s.section = '.comment' "
        "ORDER BY i.path",
        coll_args + (elf_path,),
    ).fetchall()
    if not rows:
        return {
            "image_key": None,
            "comment_lines": [],
            "gcc_buildroot": None,
            "gcc_version": None,
        }

    by_carrier: Dict[str, List[str]] = {}
    for row in rows:
        ik = str(row["image_key"])
        by_carrier.setdefault(ik, []).append(str(row["text"]))

    chosen = _pick_preferred_carrier(
        [{"image_key": ik, "confidence": 0} for ik in by_carrier]
    )
    assert chosen is not None
    lines = by_carrier[chosen]
    gcc_buildroot: Optional[str] = None
    gcc_version: Optional[str] = None
    for line in lines:
        m = _GCC_BUILDROOT_RE.search(line)
        if m:
            gcc_buildroot = m.group(1).strip()
            gcc_version = m.group(2).strip()
            break

    return {
        "image_key": chosen,
        "comment_lines": lines,
        "gcc_buildroot": gcc_buildroot,
        "gcc_version": gcc_version,
    }


@dataclass
class BuildrootCollectionRow:
    collection: str
    os_release_image_key: Optional[str]
    version_id: Optional[str]
    version: Optional[str]
    pretty_name: Optional[str]
    busybox_image_key: Optional[str]
    gcc_buildroot: Optional[str]
    gcc_version: Optional[str]
    comment_lines: List[str]
    metadata_mismatch: bool
    mismatch_reason: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collection": self.collection,
            "os_release_image_key": self.os_release_image_key,
            "os_release": {
                "VERSION_ID": self.version_id,
                "VERSION": self.version,
                "PRETTY_NAME": self.pretty_name,
            },
            "busybox_image_key": self.busybox_image_key,
            "gcc_buildroot": self.gcc_buildroot,
            "gcc_version": self.gcc_version,
            "comment_lines": self.comment_lines,
            "metadata_mismatch": self.metadata_mismatch,
            "mismatch_reason": self.mismatch_reason,
        }


@dataclass
class BuildrootVersionsReport:
    collections: List[BuildrootCollectionRow]
    warnings: List[str]
    diffs: Dict[str, Dict[str, Dict[str, int]]]
    elf_path: str
    buildroot_profiles: List[str]

    def to_dict(self) -> Dict[str, Any]:
        mismatched = [r.collection for r in self.collections if r.metadata_mismatch]
        os_ids = sorted({r.version_id for r in self.collections if r.version_id})
        gcc_tags = sorted({r.gcc_buildroot for r in self.collections if r.gcc_buildroot})
        return {
            "elf_path": self.elf_path,
            "buildroot_profiles": self.buildroot_profiles,
            "warnings": self.warnings,
            "summary": {
                "collection_count": len(self.collections),
                "distinct_os_release_version_id": os_ids,
                "distinct_gcc_buildroot": gcc_tags,
                "metadata_mismatch_collections": mismatched,
            },
            "collections": [r.to_dict() for r in self.collections],
            "diffs": self.diffs,
        }


def buildroot_versions_report(
    conn: sqlite3.Connection,
    *,
    elf_path: str = "bin/busybox",
    collections: Optional[List[str]] = None,
    buildroot_profiles: Optional[List[str]] = None,
) -> BuildrootVersionsReport:
    """
    Scan indexed firmware collections: ``etc/os-release`` vs canonical ELF ``.comment``.

    Optionally include stock/vendor counts per ``buildroot:<profile>`` reference.
    """
    slugs = collections if collections is not None else list_firmware_collections(conn)
    warnings: List[str] = []
    if not slugs:
        warnings.append(
            "no firmware collections in index "
            "(expected collection:* keys or pkgstream_corpus_by_version/version_* paths)"
        )

    profiles: List[str] = []
    if buildroot_profiles:
        for raw in buildroot_profiles:
            try:
                profiles.append(normalize_buildroot_profile(raw.strip()))
            except ValueError as exc:
                warnings.append(str(exc))

    rows_out: List[BuildrootCollectionRow] = []
    diffs: Dict[str, Dict[str, Dict[str, int]]] = {}

    for slug in slugs:
        os_data = os_release_fields(conn, slug)
        fields = os_data.get("fields") or {}
        tc = elf_toolchain_comment(conn, slug, elf_path=elf_path)
        version_id = fields.get("VERSION_ID")
        gcc_br = tc.get("gcc_buildroot")
        mismatch, reason = metadata_mismatch(version_id, gcc_br)

        rows_out.append(
            BuildrootCollectionRow(
                collection=slug,
                os_release_image_key=os_data.get("image_key"),
                version_id=version_id,
                version=fields.get("VERSION"),
                pretty_name=fields.get("PRETTY_NAME"),
                busybox_image_key=tc.get("image_key"),
                gcc_buildroot=gcc_br,
                gcc_version=tc.get("gcc_version"),
                comment_lines=list(tc.get("comment_lines") or []),
                metadata_mismatch=mismatch,
                mismatch_reason=reason,
            )
        )

        if profiles:
            diffs[slug] = {}
            for profile in profiles:
                try:
                    rep = diff_collection_vs_buildroot(conn, slug, profile)
                    diffs[slug][profile] = {
                        "stock": rep.stock,
                        "vendor_modified": rep.vendor_modified,
                        "vendor_path": rep.vendor_path,
                        "buildroot_only": rep.buildroot_only,
                    }
                except LookupError as exc:
                    warnings.append(f"{slug} vs buildroot:{profile}: {exc}")

    return BuildrootVersionsReport(
        collections=rows_out,
        warnings=warnings,
        diffs=diffs,
        elf_path=elf_path,
        buildroot_profiles=profiles,
    )


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
