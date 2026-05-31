"""
SQLite index for SquashFS images (via dissect) or **already-extracted** rootfs trees:
text lines, ELF symbols, ELF section strings, plus **DT_SONAME** / **DT_NEEDED** from
``.dynamic`` for linker-resolution queries.

Used by ``python -m corpus`` (default DB: ``work_corpus/corpus/index.sqlite``).
Blob ingest requires ``dissect.squashfs``; extracted-tree ingest needs only ``pyelftools``.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

ELF_MAGIC = b"\x7fELF"

_BOARD_PARAM_SENSITIVE_SUFFIXES = ("_p12",)
_BOARD_PARAM_SENSITIVE_KEYS = frozenset({"devkey", "authcode", "accesscode"})

# Repo root (.../5268ac) so sibling packages import when PYTHONPATH is unset.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpus.blob_index import (
    BlobWriteCallbacks,
    carrier_digests_for_path,
    clone_image_file_memberships,
    completed_image_blob_analysis,
    create_v3_schema,
    get_blob_transform_dst,
    index_blob_payload,
    lookup_blob_by_md5,
    lookup_blob_by_sha1,
    mark_image_blob_analysis_completed,
    record_blob_transform,
    sync_image_elf_dynamic_from_blob,
    upsert_content_blob,
    upsert_install_md5sums,
)
from corpus.content_hash import ContentDigests, digest_bytes, digest_file, parse_md5sums_txt
from corpus.vmlinux_elf import try_vmlinux_to_elf

# Sections scanned for printable strings (loaded segments only).
ELF_STRING_SECTIONS = frozenset({".rodata", ".data", ".dynstr", ".comment"})
DEFAULT_MAX_STRINGS_PER_FILE = 2000
ANALYSIS_VERSION = "corpus-index-v3"
DEFAULT_INDEX_COMMIT_BATCH = 100

# lib2spy carrier JSON artifacts (``iter_pkgstream_artifacts``) — not rootfs ``files`` rows.
CARRIER_METADATA_KINDS = frozenset({"pkgstream_metadata", "certificate_metadata"})
CARRIER_METADATA_FILENAMES = frozenset(
    {"pkgstream_metadata.json", "certificate_metadata.json"}
)

# Shared libraries / kernel modules (.so, .ko) are ELF — never listed here; handled via ELF path.
SKIP_SUFFIXES = {
    ".bin",
    ".gz",
    ".bz2",
    ".xz",
    ".lzma",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".ico",
    ".mp3",
    ".wav",
    ".ttf",
    ".woff",
    ".woff2",
}

# Default ``corpus grep`` categories (includes carrier JSON; SCRIPT TLV lines once indexed).
DEFAULT_SEARCH_KINDS = frozenset(
    {"text", "strings", "symbol", "rodata", "carrier_meta"}
)

# CLI / MCP ``--kind`` choices (``tlv_*`` filter pkgstream prefix TLV artifacts).
SEARCH_KIND_CHOICES = (
    "text",
    "strings",
    "symbol",
    "rodata",
    "soname",
    "needed",
    "board_param",
    "carrier_meta",
    "tlv_script",
    "tlv_file",
)

# ``corpus find --kind`` — list indexed artifacts by pkgstream / carrier type (no path glob required).
FIND_KIND_CHOICES = (
    "tlv_script",
    "tlv_file",
    "squashfs",
    "carrier_meta",
    "uimage",
)


def normalize_collection_slug(slug: str) -> str:
    """
    Normalize a release / firmware-tree label for ``collection:…`` image keys.

    Example: ``firmware_11.5.1.532678/11.5.1.532678`` (slashes OK inside the slug).
  Preserves ``pkgstream:``, ``nand:``, ``buildroot:`` scope prefixes.
    """
    s = slug.strip().replace("\\", "/")
    while "//" in s:
        s = s.replace("//", "/")
    for prefix in ("pkgstream:", "nand:", "buildroot:", "version:"):
        if s.startswith(prefix):
            body = s[len(prefix) :].strip("/")
            return f"{prefix}{body}" if body else prefix.rstrip(":")
    s = s.strip("/")
    return s or "default"


def resolve_collection_slug_arg(slug: str) -> str:
    """
    Normalize a CLI ``--collection`` value to a corpus collection slug.

    Accepts ``pkgstream:00D09E/11.14.1.533857-PROD``, legacy ``version:11.14.1.533857``,
    bare dotted firmware versions, or partial release paths (``11.14.1.533857-PROD``).
    """
    s = slug.strip()
    if not s:
        return "default"
    if s.startswith(("pkgstream:", "nand:", "buildroot:", "version:")):
        return normalize_collection_slug(s)
    if _looks_like_firmware_version(s):
        return s
    if "/" in s or re.search(r"-(PROD|LAB|ALPHA|BETA|DEV)\b", s, re.I):
        return f"pkgstream:{normalize_collection_slug(s)}"
    return normalize_collection_slug(s)


_RELEASE_CHANNEL_RE = re.compile(
    r"-(PROD|LAB|ALPHA|BETA|DEV|STAGING)(?:[/\\]|$)",
    re.IGNORECASE,
)


def parse_release_channel(release_path: str) -> Optional[str]:
    """Parse ``-PROD`` / ``-LAB`` / … from a mirror release directory path."""
    m = _RELEASE_CHANNEL_RE.search(release_path.replace("\\", "/"))
    return m.group(1).upper() if m else None


def pkgstream_release_path(root: Path, pkgstream_path: Path) -> str:
    """Mirror-relative release directory key for one ``.pkgstream`` carrier."""
    return _pkgstream_release_group_key(root, pkgstream_path)


def pkgstream_collection_slug_from_release(release_path: str) -> str:
    return f"pkgstream:{normalize_collection_slug(release_path)}"


def flash_collection_slug(flash_path: str | Path) -> str:
    """
    Default collection for a lab NAND dump: ``nand:@<flash-basename>``.

    Example: ``PACE 5268AC S34ML01G1@TSOP48.BIN`` →
    ``nand:@PACE 5268AC S34ML01G1@TSOP48.BIN``.
    """
    name = Path(flash_path).expanduser().resolve().name
    return f"nand:@{name}"


def resolve_flash_collection_slug(
    flash_path: str | Path,
    explicit: str | None = None,
) -> str:
    """Use *explicit* when provided; otherwise ``flash_collection_slug``."""
    if explicit:
        return normalize_collection_slug(explicit)
    return flash_collection_slug(flash_path)


def collection_image_prefix(collection_slug: str) -> str:
    """Prefix for ``images.path`` rows belonging to a collection."""
    return f"collection:{normalize_collection_slug(collection_slug)}:"


def collection_slug_for_fs(slug: str) -> str:
    """Filesystem-safe directory segment derived from a collection slug."""
    n = normalize_collection_slug(slug)
    return n.replace("/", "__").replace("\\", "__").replace(":", "_")


def collection_image_filter_sql(
    collection_slug: str,
    *,
    image_alias: str = "i",
    leading_where: bool = False,
) -> Tuple[str, Tuple[Any, ...]]:
    """
    SQL fragment restricting ``images.path`` to one firmware collection.

    Matches ``collection:<slug>:…`` keys, legacy ``collection:version:<ver>:…``,
    staging trees, and (for bare dotted versions) rows tied via ``collections``.
    """
    slug = resolve_collection_slug_arg(collection_slug)
    if slug.startswith("version:"):
        ver = slug.split(":", 1)[1]
        return _firmware_version_filter_sql(ver, image_alias=image_alias, leading_where=leading_where)
    if _looks_like_firmware_version(slug) and not slug.startswith(("pkgstream:", "nand:", "buildroot:")):
        return _firmware_version_filter_sql(slug, image_alias=image_alias, leading_where=leading_where)

    prefix = collection_image_prefix(slug)
    fs_seg = collection_slug_for_fs(slug)
    staging_like = f"%/{fs_seg}/%"
    legacy_ver = ""
    if slug.startswith("pkgstream:"):
        ver_parts = firmware_versions_from_path(slug.split(":", 1)[1])
        if ver_parts:
            legacy_ver = ver_parts[0]
    parts = [
        f"substr({image_alias}.path, 1, length(?)) = ?",
        f"{image_alias}.path LIKE ?",
    ]
    args: List[Any] = [prefix, prefix, staging_like]
    if legacy_ver:
        legacy_prefix = collection_image_prefix(f"version:{legacy_ver}")
        parts.append(f"substr({image_alias}.path, 1, length(?)) = ?")
        args.extend([legacy_prefix, legacy_prefix])
        parts.append(f"{image_alias}.path LIKE ?")
        args.append(f"%/version_{legacy_ver}/%")
    expr = "(" + " OR ".join(parts) + ")"
    if leading_where:
        return f" WHERE {expr}", tuple(args)
    return f" AND {expr}", tuple(args)


def _firmware_version_filter_sql(
    firmware_version: str,
    *,
    image_alias: str = "i",
    leading_where: bool = False,
) -> Tuple[str, Tuple[Any, ...]]:
    """Match all collections that share a dotted firmware version (may be ambiguous)."""
    legacy_prefix = collection_image_prefix(f"version:{firmware_version}")
    expr = (
        f"(substr({image_alias}.path, 1, length(?)) = ? "
        f"OR {image_alias}.path LIKE ? "
        f"OR {image_alias}.path LIKE ? "
        f"OR EXISTS (SELECT 1 FROM collections c WHERE c.firmware_version = ? "
        f"AND substr({image_alias}.path, 1, length('collection:' || c.slug || ':')) = "
        f"'collection:' || c.slug || ':'))"
    )
    args: Tuple[Any, ...] = (
        legacy_prefix,
        legacy_prefix,
        f"%/{firmware_version}/%",
        f"%{firmware_version}%",
        firmware_version,
    )
    if leading_where:
        return f" WHERE {expr}", args
    return f" AND {expr}", args


def completed_images_filter_sql(
    *,
    image_alias: str = "i",
    leading_where: bool = False,
) -> Tuple[str, Tuple[Any, ...]]:
    """
    SQL fragment excluding images with an in-progress ``analysis_status`` row.

    Legacy rows with no ``analysis_status`` entry remain visible.
    """
    expr = (
        f"NOT EXISTS (SELECT 1 FROM analysis_status a "
        f"WHERE a.image_path = {image_alias}.path "
        f"AND a.analysis_version = ? AND a.status = 'running')"
    )
    args: Tuple[Any, ...] = (ANALYSIS_VERSION,)
    if leading_where:
        return f" WHERE {expr}", args
    return f" AND {expr}", args


def compose_image_filters(
    *,
    collection_slug: Optional[str] = None,
    completed_only: bool = False,
    leading_where: bool = False,
) -> Tuple[str, Tuple[Any, ...]]:
    """Merge collection and completed-only restrictions for ``images`` queries."""
    parts: List[str] = []
    args_list: List[Any] = []
    if collection_slug:
        frag, frag_args = collection_image_filter_sql(collection_slug, leading_where=False)
        parts.append(frag[5:] if frag.startswith(" AND ") else frag)
        args_list.extend(frag_args)
    if completed_only:
        frag, frag_args = completed_images_filter_sql(leading_where=False)
        parts.append(frag[5:] if frag.startswith(" AND ") else frag)
        args_list.extend(frag_args)
    if not parts:
        return "", ()
    joined = " AND ".join(parts)
    if leading_where:
        return f" WHERE {joined}", tuple(args_list)
    return f" AND {joined}", tuple(args_list)


def list_collection_slugs_for_firmware_version(
    conn: sqlite3.Connection,
    firmware_version: str,
) -> List[str]:
    """Return collection slugs (from ``collections`` or image keys) for a firmware version."""
    seen: set[str] = set()
    out: List[str] = []
    for row in conn.execute(
        "SELECT slug FROM collections WHERE firmware_version = ? ORDER BY slug",
        (firmware_version,),
    ):
        slug = str(row["slug"])
        if slug not in seen:
            seen.add(slug)
            out.append(slug)
    frag, args = _firmware_version_filter_sql(firmware_version, leading_where=True)
    for row in conn.execute(f"SELECT i.path FROM images i {frag}", args):
        slug = collection_slug_from_image_path(str(row["path"]))
        if slug and slug not in seen:
            seen.add(slug)
            out.append(slug)
    return sorted(out, key=lambda s: s.lower())


def count_collections_for_firmware_version(
    conn: sqlite3.Connection,
    firmware_version: str,
) -> int:
    return len(list_collection_slugs_for_firmware_version(conn, firmware_version))


_PKGSTREAM_FIRMWARE_VERSION_RE = re.compile(
    rb"(?<!\d)(\d{1,2}\.\d{1,2}\.\d{1,6}\.\d{1,6})(?!\d)"
)
_PATH_FIRMWARE_VERSION_RE = re.compile(
    r"(?<!\d)(\d{1,2}\.\d{1,2}\.\d{1,6}\.\d{1,6})(?!\d)"
)
_IGNORED_VERSION_STRINGS = {"0.0.0.0", "10.0.0.0"}


def _looks_like_firmware_version(version: str) -> bool:
    """Reject IP addresses, null placeholders, and broad library/protocol versions."""
    if version in _IGNORED_VERSION_STRINGS:
        return False
    try:
        parts = [int(x) for x in version.split(".")]
    except ValueError:
        return False
    if len(parts) != 4:
        return False
    if parts[0] <= 0 or parts[0] > 20:
        return False
    if parts[-1] == 0:
        return False
    return True


def firmware_version_candidates_from_pkgstream(pkgstream_path: Path) -> List[Tuple[str, int]]:
    """
    Return firmware-looking dotted versions found inside a pkgstream, ranked by frequency.

    This intentionally ignores common placeholders and IP-address-shaped values so release
    grouping favors strings like ``11.5.1.532678``.
    """
    data = Path(pkgstream_path).read_bytes()
    counts: Counter[str] = Counter()
    for match in _PKGSTREAM_FIRMWARE_VERSION_RE.finditer(data):
        version = match.group(1).decode("ascii", errors="replace")
        if _looks_like_firmware_version(version):
            counts[version] += 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def firmware_versions_from_path(path: Path | str) -> List[str]:
    """Return firmware-looking versions embedded in a path string."""
    out: List[str] = []
    for match in _PATH_FIRMWARE_VERSION_RE.finditer(str(path).replace("\\", "/")):
        version = match.group(1)
        if _looks_like_firmware_version(version) and version not in out:
            out.append(version)
    return out


@dataclass(frozen=True)
class PkgstreamCollectionPlan:
    path: Path
    relative_path: str
    collection_slug: str
    release_path: str
    channel: Optional[str]
    version: str
    version_source: str
    internal_candidates: List[Tuple[str, int]]

    def to_json(self) -> Dict[str, Any]:
        return {
            "path": str(self.path),
            "relative_path": self.relative_path,
            "collection": self.collection_slug,
            "release_path": self.release_path,
            "channel": self.channel,
            "version": self.version,
            "version_source": self.version_source,
            "internal_candidates": self.internal_candidates,
        }


def classify_pkgstream_collection(
    pkgstream_path: Path,
    *,
    root: Optional[Path] = None,
    collection_prefix: str = "pkgstream:",
    unknown_version: str = "unknown",
) -> PkgstreamCollectionPlan:
    """
    Classify one pkgstream into a path-primary collection.

    The collection slug is ``pkgstream:<release-path>`` (mirror-relative release
    directory). *version* / *version_source* retain firmware version metadata for
    filters and ``collections`` rows; they do not alone define the slug.
    """
    pkg = Path(pkgstream_path).resolve()
    base = Path(root).resolve() if root is not None else pkg.parent
    try:
        rel = pkg.relative_to(base).as_posix()
    except ValueError:
        rel = pkg.name

    release_path = pkgstream_release_path(base, pkg)
    channel = parse_release_channel(release_path)
    if collection_prefix == "pkgstream:":
        collection_slug = pkgstream_collection_slug_from_release(release_path)
    else:
        collection_slug = f"{collection_prefix}{release_path}"

    internal = firmware_version_candidates_from_pkgstream(pkg)
    if internal:
        version = internal[0][0]
        source = "internal"
    else:
        path_versions = firmware_versions_from_path(rel)
        if path_versions:
            version = path_versions[0]
            source = "path-fallback"
        else:
            version = unknown_version
            source = "unknown"
    return PkgstreamCollectionPlan(
        path=pkg,
        relative_path=rel,
        collection_slug=collection_slug,
        release_path=release_path,
        channel=channel,
        version=version,
        version_source=source,
        internal_candidates=internal[:8],
    )


def iter_pkgstreams_under(
    root: Path,
    *,
    path_substrings: Optional[Sequence[str]] = None,
) -> Iterator[Path]:
    """Yield all ``*.pkgstream`` files under *root*, sorted by relative path.

    When *path_substrings* is set, only paths whose mirror-relative POSIX path
    contains at least one substring (case-sensitive) are included.
    """
    root = Path(root).resolve()
    filters = [s for s in (path_substrings or []) if s]
    paths: List[Path] = []
    for dirpath, _dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        for name in filenames:
            if name.lower().endswith(".pkgstream"):
                path = Path(dirpath) / name
                if filters:
                    rel = path.relative_to(root).as_posix()
                    if not any(sub in rel for sub in filters):
                        continue
                paths.append(path)
    paths.sort(key=lambda p: p.relative_to(root).as_posix().lower())
    yield from paths


def plan_pkgstream_collections(
    root: Path,
    *,
    collection_prefix: str = "pkgstream:",
    unknown_version: str = "unknown",
    path_substrings: Optional[Sequence[str]] = None,
) -> List[PkgstreamCollectionPlan]:
    """Plan all pkgstream collection slugs under a mirror/root directory.

    The mirror commonly stores one install carrier plus config/cert carriers in
    the same release directory. Treat that directory as the release bundle so
    config/cert carriers inherit the install carrier's firmware collection even
    if their own payloads contain unrelated version-looking strings.
    """
    root = Path(root).resolve()
    raw = [
        classify_pkgstream_collection(
            p,
            root=root,
            collection_prefix=collection_prefix,
            unknown_version=unknown_version,
        )
        for p in iter_pkgstreams_under(root, path_substrings=path_substrings)
    ]
    groups: dict[str, list[PkgstreamCollectionPlan]] = {}
    for item in raw:
        groups.setdefault(_pkgstream_release_group_key(root, item.path), []).append(item)

    out: list[PkgstreamCollectionPlan] = []
    for items in groups.values():
        bundle = min(items, key=_pkgstream_bundle_plan_priority)
        for item in items:
            if bundle.version != unknown_version and item.collection_slug != bundle.collection_slug:
                item = PkgstreamCollectionPlan(
                    path=item.path,
                    relative_path=item.relative_path,
                    collection_slug=bundle.collection_slug,
                    release_path=bundle.release_path,
                    channel=bundle.channel,
                    version=bundle.version,
                    version_source=f"release-bundle:{bundle.version_source}",
                    internal_candidates=item.internal_candidates,
                )
            elif bundle.version != unknown_version and _is_pkgstream_sidecar(item.path) and item.path != bundle.path:
                item = PkgstreamCollectionPlan(
                    path=item.path,
                    relative_path=item.relative_path,
                    collection_slug=bundle.collection_slug,
                    release_path=bundle.release_path,
                    channel=bundle.channel,
                    version=bundle.version,
                    version_source=f"release-bundle:{bundle.version_source}",
                    internal_candidates=item.internal_candidates,
                )
            out.append(item)
    out.sort(key=lambda item: item.relative_path.lower())
    return out


def sort_pkgstream_plan(
    plan: List[PkgstreamCollectionPlan],
    *,
    version_order: str = "path",
) -> List[PkgstreamCollectionPlan]:
    """Reorder a pkgstream plan (``path`` = lexicographic relative path, default)."""
    if version_order not in ("path", "asc", "desc"):
        raise ValueError(f"unsupported pkgstream version order: {version_order!r}")
    if version_order == "path":
        return plan

    def version_key(item: PkgstreamCollectionPlan) -> Tuple[int, ...]:
        if item.version == "unknown":
            # Desc: process known releases first; asc: unknowns last.
            return (0,) * 8 if version_order == "desc" else (10**9,) * 8
        return firmware_version_sort_key(item.version)

    ordered = list(plan)
    ordered.sort(key=lambda item: item.relative_path.lower())
    ordered.sort(key=version_key, reverse=version_order == "desc")
    return ordered


def _is_pkgstream_sidecar(path: Path) -> bool:
    name = path.name.lower()
    return any(token in name for token in ("config", "cert", "eapol", "cms"))


def _pkgstream_release_group_key(root: Path, path: Path) -> str:
    """Return the release directory key for a pkgstream path relative to *root*."""
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        return path.parent.as_posix()
    dirs = rel.parts[:-1]
    if not dirs:
        return "."
    for i in range(len(dirs)):
        prefix = "/".join(dirs[: i + 1])
        if firmware_versions_from_path(prefix):
            return prefix
    return "/".join(dirs)


def _pkgstream_bundle_plan_priority(item: PkgstreamCollectionPlan) -> tuple[int, str]:
    sidecar = _is_pkgstream_sidecar(item.path)
    if item.version == "unknown":
        tier = 9
    elif item.version_source == "internal" and not sidecar:
        tier = 0
    elif item.version_source == "path-fallback" and not sidecar:
        tier = 1
    elif item.version_source == "internal":
        tier = 2
    elif item.version_source == "path-fallback":
        tier = 3
    else:
        tier = 4
    return (tier, item.relative_path.lower())


def format_pkgstream_image_key(
    collection_slug: Optional[str],
    pkgstream_resolved: Path,
    segment: str,
) -> str:
    """
    Stable logical key for pkgstream-derived images.

    *segment* examples: ``tlv``, ``squash_embedded:0xab0c``, ``kernel_elf:0x1ae4b7e``.
    Without *collection_slug*, matches the legacy ``pkgstream:<abs>:…`` shape.
    """
    pkg_abs = str(Path(pkgstream_resolved).resolve())
    core = f"pkgstream:{pkg_abs}:{segment}"
    if collection_slug:
        return f"{collection_image_prefix(collection_slug)}{core}"
    return core


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _sqlite_journal_mode() -> str:
    mode = os.environ.get("CORPUS_SQLITE_JOURNAL", "wal").strip().lower()
    if mode in ("wal", "delete", "truncate", "memory"):
        return mode
    return "wal"


def _wal_passive_checkpoint(conn: sqlite3.Connection) -> None:
    try:
        row = conn.execute("PRAGMA journal_mode").fetchone()
        if row is not None and str(row[0]).lower() == "wal":
            conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
    except sqlite3.Error:
        pass


def _apply_sqlite_connection_pragmas(conn: sqlite3.Connection, *, readonly: bool) -> None:
    """Tune SQLite for long-running index writes + concurrent readonly grep/find."""
    conn.execute("PRAGMA foreign_keys=ON")
    busy_ms = _env_int("CORPUS_SQLITE_BUSY_MS", 120_000)
    conn.execute(f"PRAGMA busy_timeout={busy_ms}")
    mmap = os.environ.get("CORPUS_SQLITE_MMAP", "0").strip().lower()
    if mmap in ("0", "off", "false", "no", ""):
        conn.execute("PRAGMA mmap_size=0")
    else:
        conn.execute(f"PRAGMA mmap_size={int(mmap)}")
    if readonly:
        conn.execute("PRAGMA query_only=ON")
        return
    journal = _sqlite_journal_mode()
    conn.execute(f"PRAGMA journal_mode={journal}")
    sync = "FULL" if journal == "delete" else "NORMAL"
    conn.execute(f"PRAGMA synchronous={sync}")


class _IndexBatchCommitter:
    """Periodic commit during one image ingest so readonly queries can progress."""

    __slots__ = ("_conn", "_batch_size", "_pending")

    def __init__(self, conn: sqlite3.Connection, *, batch_size: Optional[int] = None) -> None:
        self._conn = conn
        self._batch_size = (
            _env_int("CORPUS_INDEX_BATCH_FILES", DEFAULT_INDEX_COMMIT_BATCH)
            if batch_size is None
            else batch_size
        )
        self._pending = 0
        conn.execute("BEGIN")

    def tick(self, n: int = 1) -> None:
        self._pending += n
        if self._batch_size > 0 and self._pending >= self._batch_size:
            self.flush()

    def flush(self) -> None:
        if self._pending <= 0:
            return
        self._conn.commit()
        _wal_passive_checkpoint(self._conn)
        self._conn.execute("BEGIN")
        self._pending = 0

    def finish(self) -> None:
        self._conn.commit()
        _wal_passive_checkpoint(self._conn)
        self._pending = 0


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS images (
          id INTEGER PRIMARY KEY,
          path TEXT NOT NULL UNIQUE,
          md5 TEXT,
          sha1 TEXT,
          size_bytes INTEGER NOT NULL,
          file_count INTEGER NOT NULL DEFAULT 0,
          indexed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_images_md5 ON images(md5);

        -- Per-image ELF dynamic metadata (rebuilt from blob_* on membership insert).
        CREATE TABLE IF NOT EXISTS elf_symbols (
          id INTEGER PRIMARY KEY,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          scope TEXT NOT NULL,
          sym_type TEXT,
          bind TEXT,
          name TEXT NOT NULL,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_elf_sym_image ON elf_symbols(image_id);
        CREATE INDEX IF NOT EXISTS idx_elf_sym_name ON elf_symbols(name);

        CREATE TABLE IF NOT EXISTS elf_strings (
          id INTEGER PRIMARY KEY,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          section TEXT NOT NULL,
          text TEXT NOT NULL,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_elf_strings_image ON elf_strings(image_id);

        CREATE TABLE IF NOT EXISTS elf_soname (
          id INTEGER PRIMARY KEY,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          soname TEXT NOT NULL,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE,
          UNIQUE(image_id, path)
        );
        CREATE INDEX IF NOT EXISTS idx_elf_soname_image ON elf_soname(image_id);
        CREATE INDEX IF NOT EXISTS idx_elf_soname_name ON elf_soname(soname);

        CREATE TABLE IF NOT EXISTS elf_needed (
          id INTEGER PRIMARY KEY,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          needed TEXT NOT NULL,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_elf_needed_image ON elf_needed(image_id);
        CREATE INDEX IF NOT EXISTS idx_elf_needed_needed ON elf_needed(needed);

        CREATE TABLE IF NOT EXISTS files (
          id INTEGER PRIMARY KEY,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          size_bytes INTEGER NOT NULL,
          md5 TEXT NOT NULL,
          content_class TEXT NOT NULL,
          suffix TEXT,
          indexed_at TEXT NOT NULL,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE,
          UNIQUE(image_id, path)
        );
        CREATE INDEX IF NOT EXISTS idx_files_image ON files(image_id);
        CREATE INDEX IF NOT EXISTS idx_files_md5 ON files(md5);
        CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);

        CREATE TABLE IF NOT EXISTS secret_findings (
          id INTEGER PRIMARY KEY,
          image_id INTEGER NOT NULL,
          file_id INTEGER,
          path TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          severity TEXT NOT NULL,
          line_no INTEGER,
          byte_offset INTEGER NOT NULL,
          snippet TEXT NOT NULL,
          fingerprint TEXT NOT NULL,
          indexed_at TEXT NOT NULL,
          UNIQUE(image_id, fingerprint),
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE,
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_secret_findings_image ON secret_findings(image_id);
        CREATE INDEX IF NOT EXISTS idx_secret_findings_rule ON secret_findings(rule_id);

        CREATE TABLE IF NOT EXISTS file_versions (
          id INTEGER PRIMARY KEY,
          file_id INTEGER NOT NULL,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          source TEXT NOT NULL,
          key TEXT NOT NULL,
          value TEXT NOT NULL,
          confidence REAL NOT NULL,
          evidence TEXT,
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_file_versions_file ON file_versions(file_id);
        CREATE INDEX IF NOT EXISTS idx_file_versions_value ON file_versions(value);

        CREATE TABLE IF NOT EXISTS binary_formats (
          id INTEGER PRIMARY KEY,
          file_id INTEGER NOT NULL,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          content_class TEXT NOT NULL,
          file_type TEXT,
          file_mime TEXT,
          file_mime_encoding TEXT,
          magic_hex TEXT,
          suffix TEXT,
          elf_class INTEGER,
          endian TEXT,
          machine TEXT,
          abi TEXT,
          elf_type TEXT,
          entry_point INTEGER,
          interpreter TEXT,
          build_id TEXT,
          section_count INTEGER,
          segment_count INTEGER,
          stripped INTEGER,
          has_debug INTEGER,
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE,
          UNIQUE(file_id)
        );
        CREATE INDEX IF NOT EXISTS idx_binary_formats_image ON binary_formats(image_id);
        CREATE INDEX IF NOT EXISTS idx_binary_formats_class ON binary_formats(content_class);
        -- Added later (auto-migrated for existing DBs): file_type, file_mime, file_mime_encoding

        CREATE TABLE IF NOT EXISTS elf_symbol_refs (
          id INTEGER PRIMARY KEY,
          file_id INTEGER NOT NULL,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          scope TEXT NOT NULL,
          sym_type TEXT,
          bind TEXT,
          name TEXT NOT NULL,
          version TEXT,
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_elf_symbol_refs_file ON elf_symbol_refs(file_id);
        CREATE INDEX IF NOT EXISTS idx_elf_symbol_refs_name ON elf_symbol_refs(name);

        CREATE TABLE IF NOT EXISTS elf_library_edges (
          id INTEGER PRIMARY KEY,
          image_id INTEGER NOT NULL,
          consumer_path TEXT NOT NULL,
          needed TEXT NOT NULL,
          provider_image_id INTEGER,
          provider_path TEXT,
          provider_soname TEXT,
          resolution TEXT NOT NULL,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE,
          FOREIGN KEY(provider_image_id) REFERENCES images(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_elf_library_edges_image ON elf_library_edges(image_id);
        CREATE INDEX IF NOT EXISTS idx_elf_library_edges_needed ON elf_library_edges(needed);

        CREATE TABLE IF NOT EXISTS dwarf_units (
          id INTEGER PRIMARY KEY,
          file_id INTEGER NOT NULL,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          offset INTEGER,
          producer TEXT,
          language TEXT,
          comp_dir TEXT,
          name TEXT,
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_dwarf_units_file ON dwarf_units(file_id);

        CREATE TABLE IF NOT EXISTS dwarf_functions (
          id INTEGER PRIMARY KEY,
          unit_id INTEGER NOT NULL,
          file_id INTEGER NOT NULL,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          name TEXT NOT NULL,
          low_pc INTEGER,
          high_pc INTEGER,
          FOREIGN KEY(unit_id) REFERENCES dwarf_units(id) ON DELETE CASCADE,
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_dwarf_functions_name ON dwarf_functions(name);

        CREATE TABLE IF NOT EXISTS dwarf_types (
          id INTEGER PRIMARY KEY,
          unit_id INTEGER NOT NULL,
          file_id INTEGER NOT NULL,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          tag TEXT NOT NULL,
          name TEXT NOT NULL,
          FOREIGN KEY(unit_id) REFERENCES dwarf_units(id) ON DELETE CASCADE,
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_dwarf_types_name ON dwarf_types(name);

        CREATE TABLE IF NOT EXISTS dwarf_sources (
          id INTEGER PRIMARY KEY,
          unit_id INTEGER NOT NULL,
          file_id INTEGER NOT NULL,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          source_path TEXT NOT NULL,
          FOREIGN KEY(unit_id) REFERENCES dwarf_units(id) ON DELETE CASCADE,
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_dwarf_sources_path ON dwarf_sources(source_path);

        CREATE TABLE IF NOT EXISTS artifact_edges (
          id INTEGER PRIMARY KEY,
          parent_image_path TEXT NOT NULL,
          parent_path TEXT,
          child_image_path TEXT NOT NULL,
          child_path TEXT,
          relationship TEXT NOT NULL,
          metadata_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_artifact_edges_parent ON artifact_edges(parent_image_path);
        CREATE INDEX IF NOT EXISTS idx_artifact_edges_child ON artifact_edges(child_image_path);

        CREATE TABLE IF NOT EXISTS carrier_metadata (
          id INTEGER PRIMARY KEY,
          image_id INTEGER NOT NULL,
          kind TEXT NOT NULL,
          sha256 TEXT NOT NULL,
          size_bytes INTEGER NOT NULL,
          json_text TEXT NOT NULL,
          indexed_at TEXT NOT NULL,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE,
          UNIQUE(image_id, kind)
        );
        CREATE INDEX IF NOT EXISTS idx_carrier_metadata_kind ON carrier_metadata(kind);

        CREATE TABLE IF NOT EXISTS analysis_status (
          image_path TEXT NOT NULL,
          md5 TEXT NOT NULL,
          size_bytes INTEGER NOT NULL,
          analysis_version TEXT NOT NULL,
          options_hash TEXT NOT NULL,
          status TEXT NOT NULL,
          started_at TEXT,
          completed_at TEXT,
          metrics_json TEXT,
          error TEXT,
          PRIMARY KEY(image_path, analysis_version, options_hash)
        );
        CREATE INDEX IF NOT EXISTS idx_analysis_status_lookup
          ON analysis_status(md5, analysis_version, options_hash, status);

        CREATE TABLE IF NOT EXISTS ingest_status (
          ingest_key TEXT NOT NULL,
          md5 TEXT NOT NULL,
          analysis_version TEXT NOT NULL,
          options_hash TEXT NOT NULL,
          status TEXT NOT NULL,
          started_at TEXT,
          completed_at TEXT,
          metrics_json TEXT,
          error TEXT,
          PRIMARY KEY (ingest_key, analysis_version, options_hash)
        );
        CREATE INDEX IF NOT EXISTS idx_ingest_status_lookup
          ON ingest_status(ingest_key, md5, analysis_version, options_hash, status);

        CREATE TABLE IF NOT EXISTS collections (
          slug TEXT PRIMARY KEY,
          release_path TEXT NOT NULL,
          firmware_version TEXT,
          component_version TEXT,
          channel TEXT,
          install_pkgstream TEXT,
          pkgstream_root TEXT,
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_collections_firmware
          ON collections(firmware_version);

        CREATE TABLE IF NOT EXISTS board_params (
          id INTEGER PRIMARY KEY,
          image_id INTEGER NOT NULL,
          collection_slug TEXT,
          source TEXT NOT NULL,
          indexed_at TEXT NOT NULL,
          UNIQUE(image_id, source),
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_board_params_image ON board_params(image_id);
        CREATE INDEX IF NOT EXISTS idx_board_params_collection ON board_params(collection_slug);

        CREATE TABLE IF NOT EXISTS board_param_kv (
          id INTEGER PRIMARY KEY,
          board_params_id INTEGER NOT NULL,
          image_id INTEGER NOT NULL,
          key TEXT NOT NULL,
          value TEXT NOT NULL,
          value_len INTEGER NOT NULL,
          is_sensitive INTEGER NOT NULL,
          source TEXT,
          fingerprint TEXT NOT NULL,
          FOREIGN KEY(board_params_id) REFERENCES board_params(id) ON DELETE CASCADE,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE,
          UNIQUE(board_params_id, key)
        );
        CREATE INDEX IF NOT EXISTS idx_board_param_kv_image_key ON board_param_kv(image_id, key);
        CREATE INDEX IF NOT EXISTS idx_board_param_kv_key ON board_param_kv(key);
        CREATE INDEX IF NOT EXISTS idx_board_param_kv_fingerprint ON board_param_kv(fingerprint);
        """
    )
    create_v3_schema(conn)
    _migrate_binary_formats_file_columns(conn)
    _migrate_board_param_tables(conn)
    _migrate_v3_columns(conn)
    conn.commit()


def _migrate_binary_formats_file_columns(conn: sqlite3.Connection) -> None:
    """
    Add ``file(1)`` columns to ``binary_formats`` for older DBs.

    Cursor's test DBs are created fresh, but user DBs persist under work_corpus/.
    """
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(binary_formats)").fetchall()}
    for name in ("file_type", "file_mime", "file_mime_encoding"):
        if name not in cols:
            conn.execute(f"ALTER TABLE binary_formats ADD COLUMN {name} TEXT")
    # best-effort index creation (works even if already exists)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_binary_formats_file_type ON binary_formats(file_type)")


def _migrate_board_param_tables(conn: sqlite3.Connection) -> None:
    """
    Ensure board_param tables exist on older DBs.
    (CREATE TABLE IF NOT EXISTS already runs, but keep for symmetry / future ALTERs.)
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS board_params ("
        "id INTEGER PRIMARY KEY, "
        "image_id INTEGER NOT NULL, "
        "collection_slug TEXT, "
        "source TEXT NOT NULL, "
        "indexed_at TEXT NOT NULL, "
        "UNIQUE(image_id, source), "
        "FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_board_params_image ON board_params(image_id)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS board_param_kv ("
        "id INTEGER PRIMARY KEY, "
        "board_params_id INTEGER NOT NULL, "
        "image_id INTEGER NOT NULL, "
        "key TEXT NOT NULL, "
        "value TEXT NOT NULL, "
        "value_len INTEGER NOT NULL, "
        "is_sensitive INTEGER NOT NULL, "
        "source TEXT, "
        "fingerprint TEXT NOT NULL, "
        "FOREIGN KEY(board_params_id) REFERENCES board_params(id) ON DELETE CASCADE, "
        "FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE, "
        "UNIQUE(board_params_id, key))"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_board_param_kv_image_key ON board_param_kv(image_id, key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_board_param_kv_key ON board_param_kv(key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_board_param_kv_fingerprint ON board_param_kv(fingerprint)")


def _migrate_v3_columns(conn: sqlite3.Connection) -> None:
    """Best-effort ALTER for DBs created before corpus-index-v3."""
    img_cols = {row["name"] for row in conn.execute("PRAGMA table_info(images)").fetchall()}
    if "md5" not in img_cols:
        conn.execute("ALTER TABLE images ADD COLUMN md5 TEXT")
    if "sha1" not in img_cols:
        conn.execute("ALTER TABLE images ADD COLUMN sha1 TEXT")
    file_cols = {row["name"] for row in conn.execute("PRAGMA table_info(files)").fetchall()}
    if "md5" not in file_cols:
        conn.execute("ALTER TABLE files ADD COLUMN md5 TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_md5 ON files(md5)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_images_md5 ON images(md5)")


def file_digests(path: Path) -> ContentDigests:
    return digest_file(path)


def file_md5(path: Path) -> str:
    """Return MD5 hex digest for a file on disk."""
    return digest_file(path).md5


def file_sha256(path: Path) -> str:
    """Deprecated alias for :func:`file_md5` (v3 indexes MD5, not SHA-256)."""
    return file_md5(path)


def collection_slug_from_image_path(image_path: str) -> Optional[str]:
    """Extract collection slug from a ``collection:…`` image key."""
    if not image_path.startswith("collection:"):
        return None
    if image_path.startswith("collection:pkgstream:"):
        rest = image_path[len("collection:pkgstream:") :]
        carrier_markers = (":pkgstream:", ":squash_embedded:", ":paceflash:", ":squash:", ":kernel_elf:", ":tlv:")
        cut = len(rest)
        for marker in carrier_markers:
            pos = rest.find(marker)
            if pos > 0:
                cut = min(cut, pos)
        slug_body = rest[:cut].rstrip(":")
        if slug_body:
            return f"pkgstream:{slug_body}"
    prefix = image_collection_prefix_from_path(image_path)
    if prefix:
        return prefix[len("collection:") :].rstrip(":")
    rest = image_path[len("collection:") :]
    for marker in (":pkgstream:", ":paceflash:", ":squash_embedded:", ":squash:", ":kernel_elf:", ":tlv:"):
        pos = rest.find(marker)
        if pos > 0:
            return rest[:pos].rstrip(":")
    return rest.rstrip(":") or None


def upsert_collection_metadata(
    conn: sqlite3.Connection,
    *,
    slug: str,
    release_path: str,
    firmware_version: Optional[str] = None,
    component_version: Optional[str] = None,
    channel: Optional[str] = None,
    install_pkgstream: Optional[str] = None,
    pkgstream_root: Optional[str] = None,
) -> None:
    conn.execute(
        "INSERT INTO collections("
        "slug, release_path, firmware_version, component_version, channel, "
        "install_pkgstream, pkgstream_root, updated_at"
        ") VALUES (?,?,?,?,?,?,?,?) "
        "ON CONFLICT(slug) DO UPDATE SET "
        "release_path=excluded.release_path, "
        "firmware_version=COALESCE(excluded.firmware_version, collections.firmware_version), "
        "component_version=COALESCE(excluded.component_version, collections.component_version), "
        "channel=COALESCE(excluded.channel, collections.channel), "
        "install_pkgstream=COALESCE(excluded.install_pkgstream, collections.install_pkgstream), "
        "pkgstream_root=COALESCE(excluded.pkgstream_root, collections.pkgstream_root), "
        "updated_at=excluded.updated_at",
        (
            normalize_collection_slug(slug),
            release_path,
            firmware_version,
            component_version,
            channel,
            install_pkgstream,
            pkgstream_root,
            _utc_now(),
        ),
    )
    conn.commit()


def get_collection_metadata(
    conn: sqlite3.Connection,
    slug: str,
) -> Optional[Dict[str, Any]]:
    row = conn.execute(
        "SELECT * FROM collections WHERE slug = ?",
        (normalize_collection_slug(slug),),
    ).fetchone()
    return dict(row) if row else None


def query_component_version_from_index(
    conn: sqlite3.Connection,
    collection_slug: str,
) -> Optional[str]:
    """Read ``sys1/component.txt`` (or similar) from indexed text lines in *collection_slug*."""
    prefix = collection_image_prefix(collection_slug)
    row = conn.execute(
        "SELECT t.text FROM blob_text_lines t "
        "JOIN files f ON f.md5 = t.content_md5 "
        "JOIN images i ON f.image_id = i.id "
        "WHERE substr(i.path, 1, length(?)) = ? "
        "AND (f.path LIKE '%sys1/component.txt' OR f.path LIKE '%/component.txt') "
        "ORDER BY CASE WHEN f.path LIKE '%sys1/component.txt' THEN 0 ELSE 1 END, length(t.text) "
        "LIMIT 1",
        (prefix, prefix),
    ).fetchone()
    if row is None:
        return None
    text = str(row["text"]).strip()
    return text or None


def index_board_params_from_tlpart(
    conn: sqlite3.Connection,
    *,
    image_id: int,
    collection_slug: Optional[str],
    tlpart_bytes: bytes,
) -> Dict[str, Any]:
    """
    Extract board_param key/value records from assembled tlpart bytes and store as typed index rows.

    This is intentionally *not* represented as a synthetic file path in ``files``.
    """
    from paceflash.board_param import extract_board_params_from_tlpart

    extracted = extract_board_params_from_tlpart(tlpart_bytes)
    if not extracted.get("ok"):
        return {"ok": False, "error": extracted.get("error"), "warnings": extracted.get("warnings") or []}
    params = extracted.get("params") or {}
    sources = extracted.get("sources") or {}
    if not isinstance(params, dict) or not params:
        return {"ok": False, "error": "no params dict"}

    cur = conn.execute(
        "INSERT OR REPLACE INTO board_params(image_id, collection_slug, source, indexed_at) "
        "VALUES (?,?,?,?)",
        (int(image_id), normalize_collection_slug(collection_slug) if collection_slug else None, "tlpart", _utc_now()),
    )
    board_params_id = cur.lastrowid
    # SQLite INSERT OR REPLACE does not always preserve lastrowid for replace; fetch id
    row = conn.execute(
        "SELECT id FROM board_params WHERE image_id = ? AND source = ?",
        (int(image_id), "tlpart"),
    ).fetchone()
    board_params_id = int(row["id"]) if row else int(board_params_id or 0)

    written = 0
    for key, val in sorted(params.items(), key=lambda kv: str(kv[0])):
        k = str(key)
        v = str(val)
        is_sensitive = 1 if (k in _BOARD_PARAM_SENSITIVE_KEYS or any(k.endswith(s) for s in _BOARD_PARAM_SENSITIVE_SUFFIXES)) else 0
        fingerprint = hashlib.sha256((k + "\x00" + v).encode("utf-8", errors="replace")).hexdigest()
        conn.execute(
            "INSERT OR REPLACE INTO board_param_kv("
            "board_params_id, image_id, key, value, value_len, is_sensitive, source, fingerprint"
            ") VALUES (?,?,?,?,?,?,?,?)",
            (
                board_params_id,
                int(image_id),
                k,
                v,
                len(v),
                is_sensitive,
                str(sources.get(k) or ""),
                fingerprint,
            ),
        )
        written += 1
    conn.commit()
    return {"ok": True, "keys": written, "warnings": extracted.get("warnings") or []}


def sync_pkgstream_collection_metadata(
    conn: sqlite3.Connection,
    root: Path,
    plans: Sequence[PkgstreamCollectionPlan],
) -> None:
    """Upsert ``collections`` rows after indexing a pkgstream mirror root."""
    by_slug: Dict[str, List[PkgstreamCollectionPlan]] = {}
    for item in plans:
        by_slug.setdefault(item.collection_slug, []).append(item)
    for slug, items in by_slug.items():
        install = min(items, key=_pkgstream_bundle_plan_priority)
        component = query_component_version_from_index(conn, slug)
        sample = items[0]
        upsert_collection_metadata(
            conn,
            slug=slug,
            release_path=sample.release_path,
            firmware_version=sample.version if sample.version != "unknown" else None,
            component_version=component,
            channel=sample.channel,
            install_pkgstream=install.relative_path,
            pkgstream_root=str(root.resolve()),
        )


def seed_test_text_membership(
    conn: sqlite3.Connection,
    image_path: str,
    file_path: str,
    text: str,
    *,
    options_hash: str = "test-options",
) -> tuple[int, str]:
    """Insert minimal v3 rows for unit tests (image + file + blob text lines)."""
    from corpus.content_hash import digest_bytes

    data = text.encode("utf-8")
    d = digest_bytes(data)
    upsert_content_blob(conn, d, len(data), content_class="text")
    conn.execute(
        "INSERT OR REPLACE INTO images(path, md5, sha1, size_bytes, file_count, indexed_at) "
        "VALUES (?,?,?,?,?,?)",
        (image_path, d.md5, d.sha1, len(data), 1, _utc_now()),
    )
    image_id = int(
        conn.execute("SELECT id FROM images WHERE path = ?", (image_path,)).fetchone()[0]
    )
    file_id = insert_file_row(conn, image_id, file_path, data, digests=d, content_class="text")
    index_text_lines_blob(conn, d.md5, options_hash, data)
    conn.commit()
    return file_id, d.md5


def connect_db(path: str | Path, *, readonly: bool = False) -> sqlite3.Connection:
    p = Path(path).resolve()
    if readonly:
        if not p.is_file():
            raise FileNotFoundError(f"corpus index not found: {p}")
        conn = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True, isolation_level=None)
        conn.row_factory = sqlite3.Row
        _apply_sqlite_connection_pragmas(conn, readonly=True)
        return conn
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), isolation_level=None)
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    _apply_sqlite_connection_pragmas(conn, readonly=False)
    return conn


def _safe_artifact_relpath(path: str) -> Path:
    rel = Path(path.replace("\\", "/").lstrip("/"))
    if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        digest = hashlib.sha256(path.encode("utf-8", errors="replace")).hexdigest()[:16]
        return Path("_unsafe") / f"artifact_{digest}.bin"
    return rel


def _display_path(path: Path, *, base: Optional[Path] = None) -> str:
    p = Path(path).resolve()
    bases = [b for b in (base, Path.cwd(), _REPO_ROOT) if b is not None]
    for candidate in bases:
        try:
            return p.relative_to(Path(candidate).resolve()).as_posix()
        except ValueError:
            continue
    return str(p)


def _write_bytes_if_needed(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and path.stat().st_size == len(data):
        return "reused"
    path.write_bytes(data)
    return "written"


def _analysis_options_hash(
    *,
    max_file_bytes: int,
    skip_suffixes: bool,
    symtab: bool,
    string_sections: frozenset[str],
    min_string_len: int,
    max_strings_per_file: int,
    dwarf: bool,
    scan_secrets: bool = False,
) -> str:
    payload = {
        "max_file_bytes": max_file_bytes,
        "skip_suffixes": skip_suffixes,
        "symtab": symtab,
        "string_sections": sorted(string_sections),
        "min_string_len": min_string_len,
        "max_strings_per_file": max_strings_per_file,
        "dwarf": dwarf,
        "scan_secrets": scan_secrets,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _completed_analysis_row(
    conn: sqlite3.Connection,
    *,
    image_path: str,
    md5: str,
    size_bytes: int,
    options_hash: str,
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM analysis_status "
        "WHERE image_path = ? AND md5 = ? AND size_bytes = ? "
        "AND analysis_version = ? AND options_hash = ? AND status = 'completed'",
        (image_path, md5, size_bytes, ANALYSIS_VERSION, options_hash),
    ).fetchone()


def _mark_analysis_started(
    conn: sqlite3.Connection,
    *,
    image_path: str,
    md5: str,
    size_bytes: int,
    options_hash: str,
) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO analysis_status("
        "image_path, md5, size_bytes, analysis_version, options_hash, status, started_at, completed_at, metrics_json, error"
        ") VALUES (?,?,?,?,?,?,?,?,?,?)",
        (image_path, md5, size_bytes, ANALYSIS_VERSION, options_hash, "running", _utc_now(), None, None, None),
    )
    conn.commit()


def _index_run_options_hash(
    *,
    max_file_bytes: int,
    skip_suffixes: bool,
    symtab: bool,
    string_sections: frozenset[str],
    min_string_len: int,
    max_strings_per_file: int,
    dwarf: bool,
) -> str:
    """Hash of indexing options for pkgstream-carrier resume (index only; SBOM is separate)."""
    payload = {
        "max_file_bytes": max_file_bytes,
        "skip_suffixes": skip_suffixes,
        "symtab": symtab,
        "string_sections": sorted(string_sections),
        "min_string_len": min_string_len,
        "max_strings_per_file": max_strings_per_file,
        "dwarf": dwarf,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _completed_ingest_row(
    conn: sqlite3.Connection,
    *,
    ingest_key: str,
    md5: str,
    options_hash: str,
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM ingest_status "
        "WHERE ingest_key = ? AND md5 = ? "
        "AND analysis_version = ? AND options_hash = ? AND status = 'completed'",
        (ingest_key, md5, ANALYSIS_VERSION, options_hash),
    ).fetchone()


def _mark_ingest_completed(
    conn: sqlite3.Connection,
    *,
    ingest_key: str,
    md5: str,
    options_hash: str,
    metrics: dict[str, Any],
) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO ingest_status("
        "ingest_key, md5, analysis_version, options_hash, status, started_at, completed_at, metrics_json, error"
        ") VALUES (?,?,?,?,?,?,?,?,?)",
        (
            ingest_key,
            md5,
            ANALYSIS_VERSION,
            options_hash,
            "completed",
            None,
            _utc_now(),
            json.dumps(metrics, sort_keys=True, default=str),
            None,
        ),
    )
    conn.commit()


def pkgstream_ingest_key(pkgstream_path: Path, collection_slug: Optional[str] = None) -> str:
    base = str(Path(pkgstream_path).resolve())
    if collection_slug:
        return f"{collection_image_prefix(collection_slug)}pkgstream_file:{base}"
    return f"pkgstream_file:{base}"


def _analysis_skip_result(
    conn: sqlite3.Connection,
    *,
    image_path: str,
    md5: str,
    size_bytes: int,
    options_hash: str,
    progress: Optional[Callable[[str], None]] = None,
    label: str = "artifact",
) -> Optional[Dict[str, Any]]:
    row = _completed_analysis_row(
        conn,
        image_path=image_path,
        md5=md5,
        size_bytes=size_bytes,
        options_hash=options_hash,
    )
    if row is None:
        return None
    metrics = json.loads(row["metrics_json"] or "{}")
    if progress:
        progress(
            f"# {label} index skip completed {image_path} "
            f"analysis={ANALYSIS_VERSION} options={options_hash[:12]}"
        )
    return {
        "ok": True,
        "skipped": True,
        "reason": "analysis_completed",
        "analysis_version": ANALYSIS_VERSION,
        "options_hash": options_hash,
        "path": image_path,
        **metrics,
    }


def index_progress_summary(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Resume-oriented counts from ``analysis_status`` and ``ingest_status``."""
    row = conn.execute(
        "SELECT "
        "(SELECT COUNT(*) FROM images) AS images, "
        "(SELECT COUNT(*) FROM analysis_status WHERE status = 'completed') AS analyses_completed, "
        "(SELECT COUNT(*) FROM analysis_status WHERE status = 'running') AS analyses_running, "
        "(SELECT COUNT(*) FROM ingest_status WHERE status = 'completed') AS pkgstreams_completed, "
        "(SELECT COUNT(*) FROM ingest_status WHERE status = 'running') AS pkgstreams_running"
    ).fetchone()
    return dict(row) if row is not None else {}


def _mark_analysis_completed(
    conn: sqlite3.Connection,
    *,
    image_path: str,
    md5: str,
    size_bytes: int,
    options_hash: str,
    metrics: dict[str, Any],
) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO analysis_status("
        "image_path, md5, size_bytes, analysis_version, options_hash, status, started_at, completed_at, metrics_json, error"
        ") VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            image_path,
            md5,
            size_bytes,
            ANALYSIS_VERSION,
            options_hash,
            "completed",
            None,
            _utc_now(),
            json.dumps(metrics, sort_keys=True, default=str),
            None,
        ),
    )
    conn.commit()


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def _materialize_artifact_payload(
    artifact: Any,
    work_root: Optional[Path],
    data: bytes,
) -> tuple[Optional[Path], str]:
    if work_root is None:
        return None, "disabled"
    logical_path = str(getattr(artifact, "logical_path"))
    dst = Path(work_root) / _safe_artifact_relpath(logical_path)
    return dst, _write_bytes_if_needed(dst, data)


_GENERIC_VERSION_RE = re.compile(
    r"(?<![A-Za-z0-9])v?(\d+(?:\.\d+){1,5}(?:[-_+][A-Za-z0-9][A-Za-z0-9._+-]*)?)(?![A-Za-z0-9])"
)


def content_class_for(rel_path: str, data: bytes) -> str:
    """Coarse file class used for query summaries and format triage."""
    lower = rel_path.lower()
    if data[:4] == ELF_MAGIC:
        return "elf"
    if data[:4] == b"hsqs":
        return "squashfs"
    if lower.endswith((".sh", ".py", ".pl", ".lua", ".js", ".xml", ".conf", ".cfg", ".ini")):
        return "text"
    if is_probably_binary(data[:8192]):
        return "binary"
    return "text"


def insert_file_row(
    conn: sqlite3.Connection,
    image_id: int,
    rel_path: str,
    data: bytes,
    *,
    digests: Optional[ContentDigests] = None,
    content_class: Optional[str] = None,
) -> int:
    """Insert one file membership row and return its row id."""
    d = digests or digest_bytes(data)
    cls = content_class or content_class_for(rel_path, data)
    cur = conn.execute(
        "INSERT OR REPLACE INTO files(image_id, path, size_bytes, md5, content_class, suffix, indexed_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (
            image_id,
            rel_path,
            len(data),
            d.md5,
            cls,
            Path(rel_path).suffix.lower() or None,
            _utc_now(),
        ),
    )
    file_id = cur.lastrowid
    if file_id is None:
        row = conn.execute(
            "SELECT id FROM files WHERE image_id = ? AND path = ?", (image_id, rel_path)
        ).fetchone()
        assert row is not None
        file_id = int(row["id"])
    conn.execute(
        "UPDATE content_blobs SET ref_count = ref_count + 1 WHERE md5 = ?",
        (d.md5,),
    )
    return int(file_id)


def _truncate_text(value: str, limit: int = 4000) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def iter_ascii_strings(data: bytes, min_len: int) -> Iterator[Tuple[int, str]]:
    printable = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for match in printable.finditer(data):
        yield match.start(), match.group(0).decode("ascii", errors="replace")


def iter_utf16le_strings(data: bytes, min_len: int) -> Iterator[Tuple[int, str]]:
    # ASCII-range UTF-16LE strings are common in firmware config blobs.
    pattern = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % min_len))
    for match in pattern.finditer(data):
        raw = match.group(0)
        try:
            text = raw.decode("utf-16le")
        except UnicodeDecodeError:
            continue
        yield match.start(), text


def index_file_strings_blob(
    conn: sqlite3.Connection,
    content_md5: str,
    options_hash: str,
    data: bytes,
    *,
    min_string_len: int,
    max_strings_per_file: int,
) -> int:
    """Index bounded printable strings into shared ``blob_file_strings``."""
    if max_strings_per_file <= 0:
        return 0
    written = 0
    for encoding, iterator in (
        ("ascii", iter_ascii_strings(data, min_string_len)),
        ("utf16le", iter_utf16le_strings(data, min_string_len)),
    ):
        for offset, text in iterator:
            if not text:
                continue
            conn.execute(
                "INSERT OR IGNORE INTO blob_file_strings("
                "content_md5, options_hash, offset, encoding, source, text, length"
                ") VALUES (?,?,?,?,?,?,?)",
                (
                    content_md5,
                    options_hash,
                    offset,
                    encoding,
                    "raw",
                    _truncate_text(text),
                    len(text),
                ),
            )
            written += 1
            if written >= max_strings_per_file:
                return written
    return written


def index_file_strings(
    conn: sqlite3.Connection,
    file_id: int,
    image_id: int,
    rel_path: str,
    data: bytes,
    *,
    min_string_len: int,
    max_strings_per_file: int,
    options_hash: str = "",
) -> int:
    """Legacy wrapper — writes shared blob strings keyed by content md5."""
    d = digest_bytes(data)
    upsert_content_blob(conn, d, len(data))
    return index_file_strings_blob(
        conn,
        d.md5,
        options_hash,
        data,
        min_string_len=min_string_len,
        max_strings_per_file=max_strings_per_file,
    )


def _insert_version(
    conn: sqlite3.Connection,
    file_id: int,
    image_id: int,
    rel_path: str,
    *,
    source: str,
    key: str,
    value: str,
    confidence: float,
    evidence: Optional[str] = None,
) -> int:
    if not value:
        return 0
    conn.execute(
        "INSERT INTO file_versions(file_id, image_id, path, source, key, value, confidence, evidence) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (
            file_id,
            image_id,
            rel_path,
            source,
            key,
            value[:512],
            confidence,
            _truncate_text(evidence or value, 1000),
        ),
    )
    return 1


def index_version_evidence(
    conn: sqlite3.Connection,
    file_id: int,
    image_id: int,
    rel_path: str,
    data: bytes,
) -> int:
    """Collect lightweight version evidence from paths and textual payloads."""
    n = 0
    seen: set[Tuple[str, str, str]] = set()

    def add(source: str, key: str, value: str, confidence: float, evidence: Optional[str] = None) -> None:
        nonlocal n
        item = (source, key, value)
        if item in seen:
            return
        seen.add(item)
        n += _insert_version(
            conn,
            file_id,
            image_id,
            rel_path,
            source=source,
            key=key,
            value=value,
            confidence=confidence,
            evidence=evidence,
        )

    for version in firmware_versions_from_path(rel_path):
        add("path", "firmware_version", version, 0.8, rel_path)

    text = data[:512 * 1024].decode("utf-8", errors="replace")
    lower_path = rel_path.lower()
    if lower_path.endswith(("os-release", "openwrt_release", "version", "release")):
        for line in text.splitlines()[:200]:
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'\"")
            if key and value and ("version" in key.lower() or key in {"DISTRIB_RELEASE", "BUILD_ID"}):
                add("release_file", key, value, 0.95, line)

    for match in _GENERIC_VERSION_RE.finditer(text):
        value = match.group(1)
        if value.count(".") >= 1:
            add("string", "version", value, 0.35, match.group(0))
            if len(seen) > 128:
                break
    return n


def delete_image_by_path(conn: sqlite3.Connection, image_path: str) -> None:
    conn.execute("DELETE FROM images WHERE path = ?", (image_path,))
    conn.execute(
        "DELETE FROM artifact_edges WHERE parent_image_path = ? OR child_image_path = ?",
        (image_path, image_path),
    )
    conn.commit()


def ensure_image_row_for_large_artifact(
    conn: sqlite3.Connection,
    image_key: str,
    data: bytes,
) -> int:
    """
    Create/replace an ``images`` row for a large artifact without ingesting its bytes into ``files``.

    Used for huge containers like ``mtd/tlpart.bin`` where storing every byte as a file row would
    be both misleading and expensive, but we still want a stable ``image_id`` anchor for typed
    indexes (e.g. board_param_kv).
    """
    digests = digest_bytes(data)
    size_b = len(data)
    delete_image_by_path(conn, image_key)
    cur = conn.execute(
        "INSERT INTO images(path, md5, sha1, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?,?)",
        (image_key, digests.md5, digests.sha1, size_b, 0, _utc_now()),
    )
    image_id = int(cur.lastrowid or 0)
    conn.commit()
    return image_id


def record_artifact_edge(
    conn: sqlite3.Connection,
    child_image_path: str,
    child_path: str,
    metadata: Dict[str, Any],
) -> int:
    """Record optional parent/child artifact provenance emitted by artifact iterators."""
    parent = metadata.get("parent_source_key")
    if not parent:
        return 0
    relationship = str(metadata.get("relationship") or "contains")
    parent_path = metadata.get("parent_logical_path")
    meta = {
        k: v
        for k, v in metadata.items()
        if k not in {"parent_source_key", "parent_logical_path", "relationship"}
    }
    conn.execute(
        "INSERT INTO artifact_edges(parent_image_path, parent_path, child_image_path, child_path, relationship, metadata_json) "
        "VALUES (?,?,?,?,?,?)",
        (
            str(parent),
            str(parent_path) if parent_path is not None else None,
            child_image_path,
            child_path,
            relationship,
            json.dumps(meta, sort_keys=True, default=str),
        ),
    )
    return 1


def _strip_elf_enum(prefix: str, val: Any) -> str:
    if hasattr(val, "name"):
        s = val.name
    else:
        s = str(val)
    if s.startswith(prefix):
        return s[len(prefix) :].lower()
    return s.lower()


def _sym_type_str(sym: Any) -> str:
    return _strip_elf_enum("STT_", sym.entry["st_info"]["type"])


def _bind_str(sym: Any) -> str:
    return _strip_elf_enum("STB_", sym.entry["st_info"]["bind"]).upper()


def _is_undef(sym: Any) -> bool:
    shndx = sym.entry["st_shndx"]
    if shndx == "SHN_UNDEF":
        return True
    if isinstance(shndx, int) and shndx == 0:
        return True
    return False


def _dynamic_tag_name(tag: Any) -> str:
    dt = tag.entry["d_tag"]
    if hasattr(dt, "name"):
        return str(dt.name)
    return str(dt)


def _elf_header_value(value: Any) -> str:
    if hasattr(value, "name"):
        return str(value.name)
    return str(value)


def _section_has_debug(ef: Any) -> bool:
    return any(getattr(sec, "name", "").startswith(".debug") for sec in ef.iter_sections())


def _elf_interpreter(ef: Any) -> Optional[str]:
    sec = ef.get_section_by_name(".interp")
    if sec is None:
        return None
    try:
        return sec.data().split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    except Exception:
        return None


def _elf_build_id(ef: Any) -> Optional[str]:
    for sec in ef.iter_sections():
        if not getattr(sec, "name", "").startswith(".note"):
            continue
        try:
            for note in sec.iter_notes():
                n_type = note.get("n_type")
                if str(n_type) in {"NT_GNU_BUILD_ID", "3"}:
                    desc = note.get("n_desc")
                    if isinstance(desc, bytes):
                        return desc.hex()
                    return str(desc)
        except Exception:
            continue
    return None


def index_binary_format(
    conn: sqlite3.Connection,
    file_id: int,
    image_id: int,
    rel_path: str,
    data: bytes,
    *,
    content_class: str,
    ef: Any | None = None,
) -> int:
    """Record normalized file/binary format facts."""
    ft = detect_file_type(rel_path, data)
    kwargs: Dict[str, Any] = {
        "elf_class": None,
        "endian": None,
        "machine": None,
        "abi": None,
        "elf_type": None,
        "entry_point": None,
        "interpreter": None,
        "build_id": None,
        "section_count": None,
        "segment_count": None,
        "stripped": None,
        "has_debug": None,
    }
    if ef is not None:
        kwargs.update(
            {
                "elf_class": int(getattr(ef, "elfclass", 0) or 0),
                "endian": "little" if getattr(ef, "little_endian", False) else "big",
                "machine": _elf_header_value(ef.header["e_machine"]),
                "abi": _elf_header_value(ef.header["e_ident"]["EI_OSABI"]),
                "elf_type": _elf_header_value(ef.header["e_type"]),
                "entry_point": int(ef.header["e_entry"]),
                "interpreter": _elf_interpreter(ef),
                "build_id": _elf_build_id(ef),
                "section_count": int(ef.num_sections()),
                "segment_count": int(ef.num_segments()),
                "stripped": 1 if ef.get_section_by_name(".symtab") is None else 0,
                "has_debug": 1 if _section_has_debug(ef) else 0,
            }
        )
    conn.execute(
        "INSERT OR REPLACE INTO binary_formats("
        "file_id, image_id, path, content_class, file_type, file_mime, file_mime_encoding, "
        "magic_hex, suffix, elf_class, endian, machine, abi, elf_type, entry_point, interpreter, build_id, "
        "section_count, segment_count, stripped, has_debug"
        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            file_id,
            image_id,
            rel_path,
            content_class,
            ft.get("type"),
            ft.get("mime"),
            ft.get("mime_encoding"),
            data[:16].hex(),
            Path(rel_path).suffix.lower() or None,
            kwargs["elf_class"],
            kwargs["endian"],
            kwargs["machine"],
            kwargs["abi"],
            kwargs["elf_type"],
            kwargs["entry_point"],
            kwargs["interpreter"],
            kwargs["build_id"],
            kwargs["section_count"],
            kwargs["segment_count"],
            kwargs["stripped"],
            kwargs["has_debug"],
        ),
    )
    return 1


def _file_tool_available(name: str = "file") -> bool:
    try:
        res = subprocess.run([name, "--version"], capture_output=True, text=True, timeout=2)
        return res.returncode == 0
    except Exception:
        return False


def detect_file_type(rel_path: str, data: bytes, *, file_bin: str = "file") -> Dict[str, Any]:
    """
    Best-effort libmagic classification using external ``file(1)``.

    Returns keys: type, mime, mime_encoding, ok, error.
    """
    out: Dict[str, Any] = {"ok": False, "type": None, "mime": None, "mime_encoding": None}
    if not _file_tool_available(file_bin):
        out["error"] = "file tool not available"
        return out
    try:
        with tempfile.NamedTemporaryFile(prefix="corpus_file_", suffix=Path(rel_path).suffix, delete=True) as tmp:
            tmp.write(data)
            tmp.flush()
            r_type = subprocess.run(
                [file_bin, "--brief", "--no-pad", tmp.name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            r_mime = subprocess.run(
                [file_bin, "--brief", "--no-pad", "--mime", tmp.name],
                capture_output=True,
                text=True,
                timeout=5,
            )
        if r_type.returncode == 0:
            out["type"] = (r_type.stdout or "").strip()[:400]
        if r_mime.returncode == 0:
            mime = (r_mime.stdout or "").strip()
            # typically: "application/x-executable; charset=binary"
            if ";" in mime:
                left, right = mime.split(";", 1)
                out["mime"] = left.strip()[:200]
                m = re.search(r"charset=([A-Za-z0-9._+-]+)", right)
                out["mime_encoding"] = m.group(1) if m else right.strip()[:100]
            else:
                out["mime"] = mime[:200]
        out["ok"] = bool(out["type"] or out["mime"])
        return out
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out


def index_elf_dynamic(
    conn: sqlite3.Connection,
    image_id: int,
    rel_path: str,
    ef: Any,
) -> Tuple[int, int]:
    """
    Record DT_SONAME / DT_NEEDED from ``.dynamic`` for linker-resolution queries.

    Returns ``(n_soname_rows, n_needed_rows)``.
    """
    from elftools.elf.dynamic import DynamicSection

    sec = ef.get_section_by_name(".dynamic")
    if sec is None or not isinstance(sec, DynamicSection):
        return 0, 0

    ns = 0
    nn = 0
    soname_written = False
    for tag in sec.iter_tags():
        name = _dynamic_tag_name(tag)
        if name == "DT_NULL":
            break
        if name == "DT_SONAME":
            sn = tag.soname
            if sn and not soname_written:
                conn.execute(
                    "INSERT OR REPLACE INTO elf_soname(image_id, path, soname) VALUES (?,?,?)",
                    (image_id, rel_path, sn),
                )
                ns += 1
                soname_written = True
        elif name == "DT_NEEDED":
            nd = tag.needed
            if nd:
                conn.execute(
                    "INSERT INTO elf_needed(image_id, path, needed) VALUES (?,?,?)",
                    (image_id, rel_path, nd),
                )
                nn += 1
    return ns, nn


def index_elf_dynamic_blob(
    conn: sqlite3.Connection,
    content_md5: str,
    options_hash: str,
    ef: Any,
) -> Tuple[int, int]:
    """Record DT_SONAME / DT_NEEDED into shared blob tables."""
    from elftools.elf.dynamic import DynamicSection

    sec = ef.get_section_by_name(".dynamic")
    if sec is None or not isinstance(sec, DynamicSection):
        return 0, 0

    ns = 0
    nn = 0
    soname_written = False
    for tag in sec.iter_tags():
        name = _dynamic_tag_name(tag)
        if name == "DT_NULL":
            break
        if name == "DT_SONAME":
            sn = tag.soname
            if sn and not soname_written:
                conn.execute(
                    "INSERT OR REPLACE INTO blob_elf_soname(content_md5, options_hash, soname) "
                    "VALUES (?,?,?)",
                    (content_md5, options_hash, sn),
                )
                ns += 1
                soname_written = True
        elif name == "DT_NEEDED":
            nd = tag.needed
            if nd:
                conn.execute(
                    "INSERT OR IGNORE INTO blob_elf_needed(content_md5, options_hash, needed) "
                    "VALUES (?,?,?)",
                    (content_md5, options_hash, nd),
                )
                nn += 1
    return ns, nn


def iter_elf_dynamic_lines(ef: Any) -> Iterator[str]:
    """Yield ``SONAME:…`` / ``NEEDED:…`` lines for filesystem grep parity with the DB."""
    from elftools.elf.dynamic import DynamicSection

    sec = ef.get_section_by_name(".dynamic")
    if sec is None or not isinstance(sec, DynamicSection):
        return
    soname_emitted = False
    for tag in sec.iter_tags():
        name = _dynamic_tag_name(tag)
        if name == "DT_NULL":
            break
        if name == "DT_SONAME":
            sn = tag.soname
            if sn and not soname_emitted:
                yield f"SONAME:{sn}"
                soname_emitted = True
        elif name == "DT_NEEDED":
            nd = tag.needed
            if nd:
                yield f"NEEDED:{nd}"


def index_elf_payload(
    conn: sqlite3.Connection,
    image_id: int,
    file_id: int,
    rel_path: str,
    data: bytes,
    *,
    symtab: bool,
    string_sections: frozenset[str],
    min_string_len: int,
    dwarf: bool = False,
    progress: Optional[Callable[[str], None]] = None,
) -> Tuple[int, int, int, int, int, int, int, int]:
    """Insert ELF metadata rows. Returns symbol/string/dynamic/DWARF counters."""
    from elftools.elf.elffile import ELFFile

    started = time.monotonic()
    n_sym = 0
    n_str = 0
    n_fmt = 0
    n_ver = 0
    n_du = 0
    n_df = 0
    n_dt = 0
    bio = io.BytesIO(data)
    ef = ELFFile(bio)
    if progress:
        progress(
            f"# elf index start {rel_path} size={len(data)}B "
            f"sections={ef.num_sections()} symtab={symtab} dwarf={dwarf}"
        )
    n_fmt += index_binary_format(
        conn,
        file_id,
        image_id,
        rel_path,
        data,
        content_class="elf",
        ef=ef,
    )

    def ins_sym(scope: str, st: str, bd: str, name: str) -> None:
        nonlocal n_sym
        conn.execute(
            "INSERT INTO elf_symbols(image_id, path, scope, sym_type, bind, name) VALUES (?,?,?,?,?,?)",
            (image_id, rel_path, scope, st, bd, name),
        )
        conn.execute(
            "INSERT INTO elf_symbol_refs(file_id, image_id, path, scope, sym_type, bind, name, version) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (file_id, image_id, rel_path, scope, st, bd, name, None),
        )
        n_sym += 1

    sec = ef.get_section_by_name(".dynsym")
    if sec is not None:
        if progress:
            progress(f"# elf dynsym start {rel_path}")
        for sym in sec.iter_symbols():
            name = sym.name
            if not name:
                continue
            st = _sym_type_str(sym)
            bd = _bind_str(sym)
            if _is_undef(sym):
                ins_sym("dynsym_import", st, bd, name)
            elif bd in ("GLOBAL", "WEAK"):
                ins_sym("dynsym_export", st, bd, name)
        if progress:
            progress(f"# elf dynsym done {rel_path} symbols={n_sym} elapsed={_format_duration(time.monotonic() - started)}")

    if symtab:
        stsec = ef.get_section_by_name(".symtab")
        if stsec is not None:
            if progress:
                progress(f"# elf symtab start {rel_path}")
            symtab_started = time.monotonic()
            last_progress = symtab_started
            seen: set[str] = set()
            for sym in stsec.iter_symbols():
                name = sym.name
                if not name or name in seen:
                    continue
                seen.add(name)
                st = _sym_type_str(sym)
                bd = _bind_str(sym)
                ins_sym("symtab", st, bd, name)
                now = time.monotonic()
                if progress and (len(seen) % 5000 == 0 or now - last_progress >= 10):
                    last_progress = now
                    progress(
                        f"# elf symtab progress {rel_path} seen={len(seen)} total_symbols={n_sym} "
                        f"elapsed={_format_duration(now - symtab_started)}"
                    )
            if progress:
                progress(
                    f"# elf symtab done {rel_path} seen={len(seen)} total_symbols={n_sym} "
                    f"elapsed={_format_duration(time.monotonic() - symtab_started)}"
                )

    printable = re.compile(rb"[\x20-\x7e]{%d,}" % min_string_len)
    if progress:
        progress(f"# elf strings start {rel_path}")
    strings_started = time.monotonic()
    for s in ef.iter_sections():
        sec_name = s.name
        if sec_name not in string_sections:
            continue
        hdr = s.header
        if hdr["sh_type"] != "SHT_PROGBITS":
            continue
        try:
            blob = s.data()
        except Exception:
            continue
        for m in printable.finditer(blob):
            try:
                txt = m.group(0).decode("ascii")
            except UnicodeDecodeError:
                continue
            conn.execute(
                "INSERT INTO elf_strings(image_id, path, section, text) VALUES (?,?,?,?)",
                (image_id, rel_path, sec_name, txt),
            )
            n_str += 1
            if sec_name == ".comment":
                n_ver += _insert_version(
                    conn,
                    file_id,
                    image_id,
                    rel_path,
                    source="elf_section",
                    key=".comment",
                    value=txt,
                    confidence=0.7,
                    evidence=txt,
                )

    ns, nn = index_elf_dynamic(conn, image_id, rel_path, ef)
    if progress:
        progress(
            f"# elf strings/dynamic done {rel_path} strings={n_str} soname={ns} needed={nn} "
            f"elapsed={_format_duration(time.monotonic() - strings_started)}"
        )
    soname_row = conn.execute(
        "SELECT soname FROM elf_soname WHERE image_id = ? AND path = ?",
        (image_id, rel_path),
    ).fetchone()
    if soname_row is not None:
        n_ver += _insert_version(
            conn,
            file_id,
            image_id,
            rel_path,
            source="elf_dynamic",
            key="DT_SONAME",
            value=str(soname_row["soname"]),
            confidence=0.85,
            evidence=str(soname_row["soname"]),
        )

    if dwarf:
        if progress:
            progress(f"# elf dwarf start {rel_path}")
        dwarf_started = time.monotonic()
        du, df, dt = index_dwarf_payload(conn, file_id, image_id, rel_path, ef)
        n_du += du
        n_df += df
        n_dt += dt
        if progress:
            progress(
                f"# elf dwarf done {rel_path} units={du} funcs={df} types={dt} "
                f"elapsed={_format_duration(time.monotonic() - dwarf_started)}"
            )
    if progress:
        progress(
            f"# elf index done {rel_path} symbols={n_sym} strings={n_str} "
            f"elapsed={_format_duration(time.monotonic() - started)}"
        )
    return n_sym, n_str, ns, nn, n_fmt, n_ver, n_du, n_df + n_dt


def index_elf_payload_blob(
    conn: sqlite3.Connection,
    content_md5: str,
    options_hash: str,
    image_id: int,
    file_id: int,
    rel_path: str,
    data: bytes,
    *,
    symtab: bool,
    string_sections: frozenset[str],
    min_string_len: int,
    dwarf: bool = False,
    progress: Optional[Callable[[str], None]] = None,
) -> dict[str, int]:
    """Insert shared ELF blob rows; path-local refs stay on ``file_id``."""
    from elftools.elf.elffile import ELFFile

    counts = {
        "elf_sym": 0,
        "elf_str": 0,
        "elf_soname": 0,
        "elf_needed": 0,
        "binary_formats": 0,
        "file_versions": 0,
        "dwarf_units": 0,
        "dwarf_entries": 0,
    }
    bio = io.BytesIO(data)
    ef = ELFFile(bio)
    counts["binary_formats"] += index_binary_format(
        conn,
        file_id,
        image_id,
        rel_path,
        data,
        content_class="elf",
        ef=ef,
    )

    def ins_sym(scope: str, st: str, bd: str, name: str) -> None:
        conn.execute(
            "INSERT OR IGNORE INTO blob_elf_symbols("
            "content_md5, options_hash, scope, sym_type, bind, name"
            ") VALUES (?,?,?,?,?,?)",
            (content_md5, options_hash, scope, st, bd, name),
        )
        conn.execute(
            "INSERT INTO elf_symbol_refs(file_id, image_id, path, scope, sym_type, bind, name, version) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (file_id, image_id, rel_path, scope, st, bd, name, None),
        )
        counts["elf_sym"] += 1

    sec = ef.get_section_by_name(".dynsym")
    if sec is not None:
        for sym in sec.iter_symbols():
            name = sym.name
            if not name:
                continue
            st = _sym_type_str(sym)
            bd = _bind_str(sym)
            if _is_undef(sym):
                ins_sym("dynsym_import", st, bd, name)
            elif bd in ("GLOBAL", "WEAK"):
                ins_sym("dynsym_export", st, bd, name)

    if symtab:
        stsec = ef.get_section_by_name(".symtab")
        if stsec is not None:
            seen: set[str] = set()
            for sym in stsec.iter_symbols():
                name = sym.name
                if not name or name in seen:
                    continue
                seen.add(name)
                ins_sym("symtab", _sym_type_str(sym), _bind_str(sym), name)

    printable = re.compile(rb"[\x20-\x7e]{%d,}" % min_string_len)
    for s in ef.iter_sections():
        sec_name = s.name
        if sec_name not in string_sections:
            continue
        hdr = s.header
        if hdr["sh_type"] != "SHT_PROGBITS":
            continue
        try:
            blob = s.data()
        except Exception:
            continue
        for m in printable.finditer(blob):
            try:
                txt = m.group(0).decode("ascii")
            except UnicodeDecodeError:
                continue
            conn.execute(
                "INSERT OR IGNORE INTO blob_elf_strings(content_md5, options_hash, section, text) "
                "VALUES (?,?,?,?)",
                (content_md5, options_hash, sec_name, txt),
            )
            counts["elf_str"] += 1
            if sec_name == ".comment":
                counts["file_versions"] += _insert_version(
                    conn,
                    file_id,
                    image_id,
                    rel_path,
                    source="elf_section",
                    key=".comment",
                    value=txt,
                    confidence=0.7,
                    evidence=txt,
                )

    ns, nn = index_elf_dynamic_blob(conn, content_md5, options_hash, ef)
    counts["elf_soname"] += ns
    counts["elf_needed"] += nn

    if dwarf:
        n_du, n_df, n_dt = index_dwarf_payload(conn, file_id, image_id, rel_path, ef)
        counts["dwarf_units"] += n_du
        counts["dwarf_entries"] += n_df + n_dt

    return counts


def _die_attr_text(die: Any, name: str) -> Optional[str]:
    attr = die.attributes.get(name)
    if attr is None:
        return None
    value = attr.value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _die_attr_int(die: Any, name: str) -> Optional[int]:
    attr = die.attributes.get(name)
    if attr is None:
        return None
    try:
        return int(attr.value)
    except Exception:
        return None


def _dwarf_high_pc(die: Any, low_pc: Optional[int]) -> Optional[int]:
    attr = die.attributes.get("DW_AT_high_pc")
    if attr is None:
        return None
    try:
        value = int(attr.value)
    except Exception:
        return None
    if low_pc is not None and getattr(attr, "form", "") not in {"DW_FORM_addr", "DW_FORM_GNU_addr_index"}:
        return low_pc + value
    return value


def index_dwarf_payload(
    conn: sqlite3.Connection,
    file_id: int,
    image_id: int,
    rel_path: str,
    ef: Any,
) -> Tuple[int, int, int]:
    """Index lightweight DWARF compile unit, function, and type metadata."""
    try:
        if not ef.has_dwarf_info():
            return 0, 0, 0
        dwarfinfo = ef.get_dwarf_info()
    except Exception:
        return 0, 0, 0

    n_units = 0
    n_funcs = 0
    n_types = 0
    type_tags = {
        "DW_TAG_base_type",
        "DW_TAG_typedef",
        "DW_TAG_structure_type",
        "DW_TAG_union_type",
        "DW_TAG_enumeration_type",
        "DW_TAG_class_type",
    }
    for cu in dwarfinfo.iter_CUs():
        try:
            top = cu.get_top_DIE()
        except Exception:
            continue
        cur = conn.execute(
            "INSERT INTO dwarf_units(file_id, image_id, path, offset, producer, language, comp_dir, name) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                file_id,
                image_id,
                rel_path,
                int(cu.cu_offset),
                _die_attr_text(top, "DW_AT_producer"),
                _die_attr_text(top, "DW_AT_language"),
                _die_attr_text(top, "DW_AT_comp_dir"),
                _die_attr_text(top, "DW_AT_name"),
            ),
        )
        unit_id = int(cur.lastrowid)
        n_units += 1

        try:
            lineprog = dwarfinfo.line_program_for_CU(cu)
        except Exception:
            lineprog = None
        if lineprog is not None:
            header = lineprog.header
            file_entries = (
                header.get("file_entry", [])
                if hasattr(header, "get")
                else getattr(header, "file_entry", [])
            )
            for entry in file_entries or []:
                name = getattr(entry, "name", b"")
                if isinstance(name, bytes):
                    source_path = name.decode("utf-8", errors="replace")
                else:
                    source_path = str(name)
                if source_path:
                    conn.execute(
                        "INSERT INTO dwarf_sources(unit_id, file_id, image_id, path, source_path) "
                        "VALUES (?,?,?,?,?)",
                        (unit_id, file_id, image_id, rel_path, source_path),
                    )

        for die in cu.iter_DIEs():
            name = _die_attr_text(die, "DW_AT_name")
            if not name:
                continue
            if die.tag == "DW_TAG_subprogram":
                low_pc = _die_attr_int(die, "DW_AT_low_pc")
                conn.execute(
                    "INSERT INTO dwarf_functions(unit_id, file_id, image_id, path, name, low_pc, high_pc) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (
                        unit_id,
                        file_id,
                        image_id,
                        rel_path,
                        name,
                        low_pc,
                        _dwarf_high_pc(die, low_pc),
                    ),
                )
                n_funcs += 1
            elif die.tag in type_tags:
                conn.execute(
                    "INSERT INTO dwarf_types(unit_id, file_id, image_id, path, tag, name) "
                    "VALUES (?,?,?,?,?,?)",
                    (unit_id, file_id, image_id, rel_path, die.tag, name),
                )
                n_types += 1
    return n_units, n_funcs, n_types


def iter_elf_matching_lines(
    data: bytes,
    compiled: Sequence[re.Pattern[str]],
    *,
    symtab: bool = False,
    string_sections: Optional[frozenset[str]] = None,
    min_string_len: int = 4,
) -> Iterator[str]:
    """
    Yield display lines for dynsym/symtab symbols and ELF section strings that match any of
    ``compiled`` regexes (same semantics as index + search).
    """
    from elftools.elf.elffile import ELFFile

    sections = string_sections if string_sections is not None else ELF_STRING_SECTIONS
    bio = io.BytesIO(data)
    ef = ELFFile(bio)

    sec = ef.get_section_by_name(".dynsym")
    if sec is not None:
        for sym in sec.iter_symbols():
            name = sym.name
            if not name:
                continue
            st = _sym_type_str(sym)
            bd = _bind_str(sym)
            if _is_undef(sym):
                scope = "dynsym_import"
            elif bd in ("GLOBAL", "WEAK"):
                scope = "dynsym_export"
            else:
                continue
            disp = f"SYMBOL:{scope}:{st}:{bd}:{name}"
            if pattern_matches_line(compiled, disp):
                yield disp

    if symtab:
        stsec = ef.get_section_by_name(".symtab")
        if stsec is not None:
            seen: set[str] = set()
            for sym in stsec.iter_symbols():
                name = sym.name
                if not name or name in seen:
                    continue
                seen.add(name)
                st = _sym_type_str(sym)
                bd = _bind_str(sym)
                disp = f"SYMBOL:symtab:{st}:{bd}:{name}"
                if pattern_matches_line(compiled, disp):
                    yield disp

    for dyn_line in iter_elf_dynamic_lines(ef):
        if pattern_matches_line(compiled, dyn_line):
            yield dyn_line

    printable = re.compile(rb"[\x20-\x7e]{%d,}" % min_string_len)
    for s in ef.iter_sections():
        sec_name = s.name
        if sec_name not in sections:
            continue
        hdr = s.header
        if hdr["sh_type"] != "SHT_PROGBITS":
            continue
        try:
            blob = s.data()
        except Exception:
            continue
        for m in printable.finditer(blob):
            try:
                txt = m.group(0).decode("ascii")
            except UnicodeDecodeError:
                continue
            disp = f"RODATA[{sec_name}]:{txt}"
            if pattern_matches_line(compiled, disp):
                yield disp


def is_probably_binary(sample: bytes) -> bool:
    if len(sample) >= 8192:
        sample = sample[:8192]
    return b"\x00" in sample


def index_text_lines_blob(
    conn: sqlite3.Connection,
    content_md5: str,
    options_hash: str,
    data: bytes,
) -> int:
    n = 0
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    line_no = 0
    for line in text.splitlines():
        line_no += 1
        conn.execute(
            "INSERT OR IGNORE INTO blob_text_lines(content_md5, options_hash, line_no, text) "
            "VALUES (?,?,?,?)",
            (content_md5, options_hash, line_no, line),
        )
        n += 1
    return n


def index_text_lines(
    conn: sqlite3.Connection,
    image_id: int,
    rel_path: str,
    data: bytes,
    *,
    options_hash: str = "",
) -> int:
    """Legacy wrapper — writes shared blob lines keyed by content md5."""
    d = digest_bytes(data)
    upsert_content_blob(conn, d, len(data))
    return index_text_lines_blob(conn, d.md5, options_hash, data)


def _scan_secrets_callback(
    conn: sqlite3.Connection,
    *,
    image_id: int,
    file_id: int,
    path: str,
    data: bytes,
    enabled: bool,
) -> int:
    if not enabled:
        return 0
    from corpus.secrets import scan_and_index_file_secrets

    return scan_and_index_file_secrets(
        conn,
        image_id=image_id,
        file_id=file_id,
        path=path,
        data=data,
    )


def _blob_callbacks(
    *,
    skip_suffixes: bool,
    min_string_len: int,
    max_strings_per_file: int,
    symtab: bool,
    string_sections: frozenset[str],
    dwarf: bool,
    scan_secrets: bool,
) -> BlobWriteCallbacks:
    def _elf_blob(
        conn: sqlite3.Connection,
        content_md5: str,
        options_hash: str,
        image_id: int,
        file_id: int,
        rel_path: str,
        data: bytes,
        progress: Optional[Callable[[str], None]] = None,
    ) -> dict[str, int]:
        return index_elf_payload_blob(
            conn,
            content_md5,
            options_hash,
            image_id,
            file_id,
            rel_path,
            data,
            symtab=symtab,
            string_sections=string_sections,
            min_string_len=min_string_len,
            dwarf=dwarf,
            progress=progress,
        )

    def _strings_blob(
        conn: sqlite3.Connection,
        content_md5: str,
        options_hash: str,
        data: bytes,
    ) -> int:
        return index_file_strings_blob(
            conn,
            content_md5,
            options_hash,
            data,
            min_string_len=min_string_len,
            max_strings_per_file=max_strings_per_file,
        )

    def _secrets(
        conn: sqlite3.Connection,
        *,
        image_id: int,
        file_id: int,
        path: str,
        data: bytes,
    ) -> int:
        return _scan_secrets_callback(
            conn,
            image_id=image_id,
            file_id=file_id,
            path=path,
            data=data,
            enabled=scan_secrets,
        )

    return BlobWriteCallbacks(
        index_text_lines_blob=index_text_lines_blob,
        index_file_strings_blob=_strings_blob,
        index_elf_payload_blob=_elf_blob,
        index_binary_format=index_binary_format,
        index_version_evidence=index_version_evidence,
        content_class_for=content_class_for,
        is_probably_binary=is_probably_binary,
        is_pkgstream_script_tlv_path=is_pkgstream_script_tlv_path,
        skip_suffixes=SKIP_SUFFIXES if skip_suffixes else set(),
        scan_secrets=_secrets,
    )


def iter_index_file(
    conn: sqlite3.Connection,
    image_id: int,
    rel_path: str,
    data: bytes,
    *,
    max_file_bytes: int,
    skip_suffixes: bool,
    symtab: bool,
    string_sections: frozenset[str],
    min_string_len: int,
    max_strings_per_file: int = DEFAULT_MAX_STRINGS_PER_FILE,
    dwarf: bool = False,
    scan_secrets: bool = False,
    progress: Optional[Callable[[str], None]] = None,
    options_hash: Optional[str] = None,
) -> Dict[str, int]:
    """Return counters text_lines, elf_sym, elf_str, elf_soname, elf_needed."""
    oh = options_hash or _analysis_options_hash(
        max_file_bytes=max_file_bytes,
        skip_suffixes=skip_suffixes,
        symtab=symtab,
        string_sections=string_sections,
        min_string_len=min_string_len,
        max_strings_per_file=max_strings_per_file,
        dwarf=dwarf,
        scan_secrets=scan_secrets,
    )
    return index_blob_payload(
        conn,
        image_id,
        rel_path,
        data,
        analysis_version=ANALYSIS_VERSION,
        options_hash=oh,
        max_file_bytes=max_file_bytes,
        skip_suffixes=skip_suffixes,
        callbacks=_blob_callbacks(
            skip_suffixes=skip_suffixes,
            min_string_len=min_string_len,
            max_strings_per_file=max_strings_per_file,
            symtab=symtab,
            string_sections=string_sections,
            dwarf=dwarf,
            scan_secrets=scan_secrets,
        ),
        insert_file_row_fn=insert_file_row,
        progress=progress,
    )


def _rows_as_dicts(conn: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(f"SELECT * FROM {table}")]


def _analyze_file_worker(
    args: tuple[str, bytes, int, bool, bool, tuple[str, ...], int, int, bool, bool],
) -> dict[str, Any]:
    """Analyze one file payload in a private in-memory DB for parent-side insertion."""
    (
        rel_path,
        data,
        max_file_bytes,
        skip_suffixes,
        symtab,
        string_sections_raw,
        min_string_len,
        max_strings_per_file,
        dwarf,
        scan_secrets,
    ) = args
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        "INSERT INTO images(path, sha256, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?)",
        ("worker:image", hashlib.sha256(data).hexdigest(), len(data), 1, _utc_now()),
    )
    image_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    counts = iter_index_file(
        conn,
        image_id,
        rel_path,
        data,
        max_file_bytes=max_file_bytes,
        skip_suffixes=skip_suffixes,
        symtab=symtab,
        string_sections=frozenset(string_sections_raw),
        min_string_len=min_string_len,
        max_strings_per_file=max_strings_per_file,
        dwarf=dwarf,
        scan_secrets=scan_secrets,
        progress=None,
    )
    conn.commit()
    tables = (
        "files",
        "file_strings",
        "file_versions",
        "binary_formats",
        "elf_symbols",
        "elf_strings",
        "elf_soname",
        "elf_needed",
        "elf_symbol_refs",
        "dwarf_units",
        "dwarf_functions",
        "dwarf_types",
        "dwarf_sources",
    )
    if scan_secrets:
        tables = tables + ("secret_findings",)
    rows = {table: _rows_as_dicts(conn, table) for table in tables}
    conn.close()
    return {"path": rel_path, "counts": counts, "rows": rows}


def _insert_worker_file_result(
    conn: sqlite3.Connection,
    image_id: int,
    result: dict[str, Any],
) -> dict[str, int]:
    """Insert worker-returned rows into the real DB, remapping worker ids."""
    rows = result["rows"]
    file_id_map: dict[int, int] = {}
    for row in rows["files"]:
        cur = conn.execute(
            "INSERT OR REPLACE INTO files(image_id, path, size_bytes, sha256, content_class, suffix, indexed_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                image_id,
                row["path"],
                row["size_bytes"],
                row["sha256"],
                row["content_class"],
                row["suffix"],
                row["indexed_at"],
            ),
        )
        new_id = cur.lastrowid
        if new_id is None:
            existing = conn.execute(
                "SELECT id FROM files WHERE image_id = ? AND path = ?",
                (image_id, row["path"]),
            ).fetchone()
            assert existing is not None
            new_id = int(existing["id"])
        file_id_map[int(row["id"])] = int(new_id)

    def fid(old: Any) -> int:
        return file_id_map[int(old)]

    for row in rows["file_strings"]:
        conn.execute(
            "INSERT INTO file_strings(file_id, image_id, path, offset, encoding, source, text, length) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (fid(row["file_id"]), image_id, row["path"], row["offset"], row["encoding"], row["source"], row["text"], row["length"]),
        )
    for row in rows["file_versions"]:
        conn.execute(
            "INSERT INTO file_versions(file_id, image_id, path, source, key, value, confidence, evidence) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (fid(row["file_id"]), image_id, row["path"], row["source"], row["key"], row["value"], row["confidence"], row["evidence"]),
        )
    for row in rows["binary_formats"]:
        conn.execute(
            "INSERT OR REPLACE INTO binary_formats("
            "file_id, image_id, path, content_class, magic_hex, suffix, elf_class, endian, machine, abi, "
            "elf_type, entry_point, interpreter, build_id, section_count, segment_count, stripped, has_debug"
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                fid(row["file_id"]),
                image_id,
                row["path"],
                row["content_class"],
                row["magic_hex"],
                row["suffix"],
                row["elf_class"],
                row["endian"],
                row["machine"],
                row["abi"],
                row["elf_type"],
                row["entry_point"],
                row["interpreter"],
                row["build_id"],
                row["section_count"],
                row["segment_count"],
                row["stripped"],
                row["has_debug"],
            ),
        )
    for row in rows["elf_symbols"]:
        conn.execute(
            "INSERT INTO elf_symbols(image_id, path, scope, sym_type, bind, name) VALUES (?,?,?,?,?,?)",
            (image_id, row["path"], row["scope"], row["sym_type"], row["bind"], row["name"]),
        )
    for row in rows["elf_symbol_refs"]:
        conn.execute(
            "INSERT INTO elf_symbol_refs(file_id, image_id, path, scope, sym_type, bind, name, version) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (fid(row["file_id"]), image_id, row["path"], row["scope"], row["sym_type"], row["bind"], row["name"], row["version"]),
        )
    for row in rows["elf_strings"]:
        conn.execute(
            "INSERT INTO elf_strings(image_id, path, section, text) VALUES (?,?,?,?)",
            (image_id, row["path"], row["section"], row["text"]),
        )
    for row in rows["elf_soname"]:
        conn.execute(
            "INSERT OR REPLACE INTO elf_soname(image_id, path, soname) VALUES (?,?,?)",
            (image_id, row["path"], row["soname"]),
        )
    for row in rows["elf_needed"]:
        conn.execute(
            "INSERT INTO elf_needed(image_id, path, needed) VALUES (?,?,?)",
            (image_id, row["path"], row["needed"]),
        )

    unit_id_map: dict[int, int] = {}
    for row in rows["dwarf_units"]:
        cur = conn.execute(
            "INSERT INTO dwarf_units(file_id, image_id, path, offset, producer, language, comp_dir, name) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                fid(row["file_id"]),
                image_id,
                row["path"],
                row["offset"],
                row["producer"],
                row["language"],
                row["comp_dir"],
                row["name"],
            ),
        )
        unit_id_map[int(row["id"])] = int(cur.lastrowid)
    for row in rows["dwarf_functions"]:
        conn.execute(
            "INSERT INTO dwarf_functions(unit_id, file_id, image_id, path, name, low_pc, high_pc) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                unit_id_map[int(row["unit_id"])],
                fid(row["file_id"]),
                image_id,
                row["path"],
                row["name"],
                row["low_pc"],
                row["high_pc"],
            ),
        )
    for row in rows["dwarf_types"]:
        conn.execute(
            "INSERT INTO dwarf_types(unit_id, file_id, image_id, path, tag, name) VALUES (?,?,?,?,?,?)",
            (unit_id_map[int(row["unit_id"])], fid(row["file_id"]), image_id, row["path"], row["tag"], row["name"]),
        )
    for row in rows["dwarf_sources"]:
        conn.execute(
            "INSERT INTO dwarf_sources(unit_id, file_id, image_id, path, source_path) VALUES (?,?,?,?,?)",
            (unit_id_map[int(row["unit_id"])], fid(row["file_id"]), image_id, row["path"], row["source_path"]),
        )
    for row in rows.get("secret_findings", []):
        conn.execute(
            "INSERT OR IGNORE INTO secret_findings("
            "image_id, file_id, path, rule_id, severity, line_no, byte_offset, snippet, fingerprint, indexed_at"
            ") VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                image_id,
                fid(row["file_id"]) if row.get("file_id") is not None else None,
                row["path"],
                row["rule_id"],
                row["severity"],
                row["line_no"],
                row["byte_offset"],
                row["snippet"],
                row["fingerprint"],
                row["indexed_at"],
            ),
        )
    out = dict(result["counts"])
    if "secrets" not in out:
        out["secrets"] = len(rows.get("secret_findings", []))
    return out


def _add_counts(target: dict[str, int], counts: dict[str, int]) -> None:
    for k, v in counts.items():
        if k in target:
            target[k] += int(v)


def _export_secrets_after_image_index(
    conn: sqlite3.Connection,
    *,
    image_id: int,
    image_key: str,
    secrets_dir: Optional[Path],
    scan_secrets: bool,
) -> None:
    if not scan_secrets or secrets_dir is None:
        return
    from corpus.buildroot import collection_slug_from_image_path
    from corpus.secrets import write_image_secrets_artifacts

    slug = collection_slug_from_image_path(image_key)
    write_image_secrets_artifacts(
        conn,
        image_id=image_id,
        image_key=image_key,
        secrets_dir=secrets_dir,
        collection_slug=slug,
    )


def build_index_for_image(
    conn: sqlite3.Connection,
    squashfs_path: Path,
    *,
    image_key: Optional[str] = None,
    max_file_bytes: int = 32 * 1024 * 1024,
    skip_suffixes: bool = True,
    symtab: bool = False,
    string_sections: Optional[frozenset[str]] = None,
    min_string_len: int = 4,
    max_strings_per_file: int = DEFAULT_MAX_STRINGS_PER_FILE,
    dwarf: bool = False,
    jobs: int = 1,
    scan_secrets: bool = False,
    secrets_dir: Optional[Path] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    Index one SquashFS **file** on disk (carved blob or ``.squashfs``), reading files via
    :func:`lib2spy.pkgstream_corpus.iter_squashfs_files` (dissect).

    ``image_key`` overrides the stored ``images.path`` (default: absolute path to the blob).
    """
    from lib2spy.pkgstream_corpus import iter_squashfs_files

    sections = string_sections if string_sections is not None else ELF_STRING_SECTIONS
    src = squashfs_path.resolve()
    if not src.is_file():
        return {"ok": False, "error": f"not a file: {src}"}

    carrier = carrier_digests_for_path(src)
    size_b = src.stat().st_size
    ipath = image_key if image_key else str(src)
    options_hash = _analysis_options_hash(
        max_file_bytes=max_file_bytes,
        skip_suffixes=skip_suffixes,
        symtab=symtab,
        string_sections=sections,
        min_string_len=min_string_len,
        max_strings_per_file=max_strings_per_file,
        dwarf=dwarf,
        scan_secrets=scan_secrets,
    )

    img_cached = completed_image_blob_analysis(
        conn,
        carrier.md5,
        analysis_version=ANALYSIS_VERSION,
        options_hash=options_hash,
    )
    if img_cached is not None and img_cached["canonical_image_id"]:
        delete_image_by_path(conn, ipath)
        cur = conn.execute(
            "INSERT INTO images(path, md5, sha1, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?,?)",
            (ipath, carrier.md5, carrier.sha1, size_b, 0, _utc_now()),
        )
        image_id = int(cur.lastrowid)
        n = clone_image_file_memberships(
            conn,
            canonical_image_id=int(img_cached["canonical_image_id"]),
            target_image_id=image_id,
            options_hash=options_hash,
        )
        resolve_elf_library_edges(conn, image_id=image_id)
        metrics = json.loads(img_cached["metrics_json"] or "{}")
        result = {
            "ok": True,
            "skipped": True,
            "reason": "image_blob_dedup",
            "image_id": image_id,
            "path": ipath,
            "files_cloned": n,
            **metrics,
        }
        _mark_analysis_completed(
            conn,
            image_path=ipath,
            md5=carrier.md5,
            size_bytes=size_b,
            options_hash=options_hash,
            metrics=result,
        )
        if progress:
            progress(f"# squashfs image dedup {ipath} md5={carrier.md5} cloned={n}")
        return result

    skipped = _analysis_skip_result(
        conn,
        image_path=ipath,
        md5=carrier.md5,
        size_bytes=size_b,
        options_hash=options_hash,
        progress=progress,
        label="squashfs",
    )
    if skipped is not None:
        return skipped

    delete_image_by_path(conn, ipath)
    upsert_content_blob(conn, carrier, size_b, content_class="squashfs")
    _mark_analysis_started(
        conn,
        image_path=ipath,
        md5=carrier.md5,
        size_bytes=size_b,
        options_hash=options_hash,
    )
    cur = conn.execute(
        "INSERT INTO images(path, md5, sha1, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?,?)",
        (ipath, carrier.md5, carrier.sha1, size_b, 0, _utc_now()),
    )
    image_id = cur.lastrowid
    assert image_id is not None

    totals = {
        "text_lines": 0,
        "elf_sym": 0,
        "elf_str": 0,
        "files_seen": 0,
        "file_strings": 0,
        "file_versions": 0,
        "binary_formats": 0,
        "dwarf_units": 0,
        "secrets": 0,
    }

    def log(msg: str) -> None:
        if progress:
            progress(msg)

    started = time.monotonic()
    last_progress = started
    worker_jobs = 1  # v3 content dedup requires shared DB; parallel workers disabled
    log(f"# squashfs index start {ipath} size={size_b}B jobs={worker_jobs} secrets={scan_secrets}")

    def report(now: Optional[float] = None, *, pending: int = 0) -> None:
        nonlocal last_progress
        now = time.monotonic() if now is None else now
        if progress and (totals["files_seen"] % 100 == 0 or now - last_progress >= 10):
            last_progress = now
            log(
                f"# squashfs index progress {ipath} files={totals['files_seen']} "
                f"lines={totals['text_lines']} elf_sym={totals['elf_sym']} "
                f"elapsed={_format_duration(now - started)}"
            )

    batch = _IndexBatchCommitter(conn)
    try:
        for rel, data in iter_squashfs_files(src):
            totals["files_seen"] += 1
            c = iter_index_file(
                conn,
                image_id,
                rel,
                data,
                max_file_bytes=max_file_bytes,
                skip_suffixes=skip_suffixes,
                symtab=symtab,
                string_sections=sections,
                min_string_len=min_string_len,
                max_strings_per_file=max_strings_per_file,
                dwarf=dwarf,
                scan_secrets=scan_secrets,
                progress=progress,
                options_hash=options_hash,
            )
            _add_counts(totals, c)
            batch.tick()
            report()

        conn.execute(
            "UPDATE images SET file_count = ? WHERE id = ?", (totals["files_seen"], image_id)
        )
        batch.finish()
    except Exception:
        conn.rollback()
        raise
    resolve_elf_library_edges(conn, image_id=image_id)
    _export_secrets_after_image_index(
        conn,
        image_id=image_id,
        image_key=ipath,
        secrets_dir=secrets_dir,
        scan_secrets=scan_secrets,
    )
    log(
        f"indexed image id={image_id} files={totals['files_seen']} "
        f"lines={totals['text_lines']} elf_sym={totals['elf_sym']} elf_str={totals['elf_str']} "
        f"secrets={totals.get('secrets', 0)} "
        f"elapsed={_format_duration(time.monotonic() - started)}"
    )
    result = {"ok": True, "image_id": image_id, **totals, "path": ipath}
    mark_image_blob_analysis_completed(
        conn,
        carrier.md5,
        analysis_version=ANALYSIS_VERSION,
        options_hash=options_hash,
        canonical_image_id=image_id,
        metrics=result,
    )
    _mark_analysis_completed(
        conn,
        image_path=ipath,
        md5=carrier.md5,
        size_bytes=size_b,
        options_hash=options_hash,
        metrics=result,
    )
    return result


def build_index_for_squashfs_bytes(
    conn: sqlite3.Connection,
    image_key: str,
    data: bytes,
    *,
    max_file_bytes: int = 32 * 1024 * 1024,
    skip_suffixes: bool = True,
    symtab: bool = False,
    string_sections: Optional[frozenset[str]] = None,
    min_string_len: int = 4,
    max_strings_per_file: int = DEFAULT_MAX_STRINGS_PER_FILE,
    dwarf: bool = False,
    scan_secrets: bool = False,
    secrets_dir: Optional[Path] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Index one in-memory SquashFS image, reading files via ``dissect.squashfs``."""
    from lib2spy.pkgstream_corpus import iter_squashfs_files_from_bytes

    sections = string_sections if string_sections is not None else ELF_STRING_SECTIONS
    carrier = digest_bytes(data)
    options_hash = _analysis_options_hash(
        max_file_bytes=max_file_bytes,
        skip_suffixes=skip_suffixes,
        symtab=symtab,
        string_sections=sections,
        min_string_len=min_string_len,
        max_strings_per_file=max_strings_per_file,
        dwarf=dwarf,
        scan_secrets=scan_secrets,
    )
    img_cached = completed_image_blob_analysis(
        conn,
        carrier.md5,
        analysis_version=ANALYSIS_VERSION,
        options_hash=options_hash,
    )
    if img_cached is not None and img_cached["canonical_image_id"]:
        delete_image_by_path(conn, image_key)
        cur = conn.execute(
            "INSERT INTO images(path, md5, sha1, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?,?)",
            (image_key, carrier.md5, carrier.sha1, len(data), 0, _utc_now()),
        )
        image_id = int(cur.lastrowid)
        n = clone_image_file_memberships(
            conn,
            canonical_image_id=int(img_cached["canonical_image_id"]),
            target_image_id=image_id,
            options_hash=options_hash,
        )
        resolve_elf_library_edges(conn, image_id=image_id)
        if progress:
            progress(f"# squashfs bytes image dedup {image_key} md5={carrier.md5} cloned={n}")
        return {
            "ok": True,
            "skipped": True,
            "reason": "image_blob_dedup",
            "image_id": image_id,
            "files_cloned": n,
            "path": image_key,
        }

    delete_image_by_path(conn, image_key)
    upsert_content_blob(conn, carrier, len(data), content_class="squashfs")
    cur = conn.execute(
        "INSERT INTO images(path, md5, sha1, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?,?)",
        (image_key, carrier.md5, carrier.sha1, len(data), 0, _utc_now()),
    )
    image_id = cur.lastrowid
    assert image_id is not None
    totals = {
        "text_lines": 0,
        "elf_sym": 0,
        "elf_str": 0,
        "files_seen": 0,
        "file_strings": 0,
        "file_versions": 0,
        "binary_formats": 0,
        "dwarf_units": 0,
        "secrets": 0,
    }
    started = time.monotonic()
    last_progress = started
    if progress:
        progress(f"# squashfs bytes index start {image_key} size={len(data)}B secrets={scan_secrets}")
    batch = _IndexBatchCommitter(conn)
    try:
        for rel, payload in iter_squashfs_files_from_bytes(data):
            totals["files_seen"] += 1
            c = iter_index_file(
                conn,
                image_id,
                rel,
                payload,
                max_file_bytes=max_file_bytes,
                skip_suffixes=skip_suffixes,
                symtab=symtab,
                string_sections=sections,
                min_string_len=min_string_len,
                max_strings_per_file=max_strings_per_file,
                dwarf=dwarf,
                scan_secrets=scan_secrets,
                progress=progress,
                options_hash=options_hash,
            )
            for k in (
                "text_lines",
                "elf_sym",
                "elf_str",
                "file_strings",
                "file_versions",
                "binary_formats",
                "dwarf_units",
                "secrets",
            ):
                totals[k] += c[k]
            batch.tick()
            now = time.monotonic()
            if progress and (totals["files_seen"] % 100 == 0 or now - last_progress >= 10):
                last_progress = now
                progress(
                    f"# squashfs bytes progress {image_key} files={totals['files_seen']} "
                    f"lines={totals['text_lines']} elf_sym={totals['elf_sym']} "
                    f"elapsed={_format_duration(now - started)}"
                )
        conn.execute("UPDATE images SET file_count = ? WHERE id = ?", (totals["files_seen"], image_id))
        batch.finish()
    except Exception:
        conn.rollback()
        raise
    resolve_elf_library_edges(conn, image_id=image_id)
    _export_secrets_after_image_index(
        conn,
        image_id=image_id,
        image_key=image_key,
        secrets_dir=secrets_dir,
        scan_secrets=scan_secrets,
    )
    if progress:
        progress(
            f"indexed squashfs artifact id={image_id} files={totals['files_seen']} "
            f"lines={totals['text_lines']} elf_sym={totals['elf_sym']} elf_str={totals['elf_str']} "
            f"secrets={totals.get('secrets', 0)} "
            f"elapsed={_format_duration(time.monotonic() - started)}"
        )
    result = {"ok": True, "image_id": image_id, **totals, "path": image_key}
    mark_image_blob_analysis_completed(
        conn,
        carrier.md5,
        analysis_version=ANALYSIS_VERSION,
        options_hash=options_hash,
        canonical_image_id=image_id,
        metrics=result,
    )
    return result


def default_pkgstream_dissect_roots(repo_root: Path) -> List[Path]:
    """Subdirectories of extracted pkgstream corpus roots."""
    roots: list[Path] = []
    for base in (
        repo_root / "work_corpus" / "pkgstream_dissect_corpus",
        repo_root / "work_tl_crc" / "pkgstream_dissect_corpus",
    ):
        if base.is_dir():
            roots.extend(sorted(p for p in base.iterdir() if p.is_dir()))
    return roots


def iter_extracted_tree_files(root: Path) -> Iterator[Tuple[str, bytes]]:
    """Yield ``(posix_path_relative_to_root, data)`` for regular files under ``root``."""
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            p = Path(dirpath) / name
            try:
                if not p.is_file():
                    continue
                rel = p.relative_to(root).as_posix()
                yield rel, p.read_bytes()
            except OSError:
                continue


def _ensure_repo_on_path() -> None:
    r = str(_REPO_ROOT)
    if r not in sys.path:
        sys.path.insert(0, r)


def index_single_blob_as_image(
    conn: sqlite3.Connection,
    image_key: str,
    rel_path: str,
    data: bytes,
    *,
    max_file_bytes: int,
    skip_suffixes: bool,
    symtab: bool,
    string_sections: Optional[frozenset[str]] = None,
    min_string_len: int = 4,
    max_strings_per_file: int = DEFAULT_MAX_STRINGS_PER_FILE,
    dwarf: bool = False,
    scan_secrets: bool = False,
    secrets_dir: Optional[Path] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    One ``images`` row and a single virtual path (e.g. ``vmlinux.elf``) for **raw bytes**.
    """
    sections = string_sections if string_sections is not None else ELF_STRING_SECTIONS
    eff_max = 10**15 if max_file_bytes <= 0 else max_file_bytes
    if len(data) > eff_max:
        return {"ok": False, "error": f"blob {len(data)} B exceeds --max-file-mb limit"}

    digests = digest_bytes(data)
    size_b = len(data)
    options_hash = _analysis_options_hash(
        max_file_bytes=max_file_bytes,
        skip_suffixes=skip_suffixes,
        symtab=symtab,
        string_sections=sections,
        min_string_len=min_string_len,
        max_strings_per_file=max_strings_per_file,
        dwarf=dwarf,
        scan_secrets=scan_secrets,
    )
    skipped = _analysis_skip_result(
        conn,
        image_path=image_key,
        md5=digests.md5,
        size_bytes=size_b,
        options_hash=options_hash,
        progress=progress,
        label="blob",
    )
    if skipped is not None:
        return skipped

    delete_image_by_path(conn, image_key)
    upsert_content_blob(conn, digests, size_b)
    cur = conn.execute(
        "INSERT INTO images(path, md5, sha1, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?,?)",
        (image_key, digests.md5, digests.sha1, size_b, 0, _utc_now()),
    )
    image_id = cur.lastrowid
    assert image_id is not None
    c = iter_index_file(
        conn,
        image_id,
        rel_path,
        data,
        max_file_bytes=eff_max,
        skip_suffixes=skip_suffixes,
        symtab=symtab,
        string_sections=sections,
        min_string_len=min_string_len,
        max_strings_per_file=max_strings_per_file,
        dwarf=dwarf,
        scan_secrets=scan_secrets,
        progress=progress,
        options_hash=options_hash,
    )
    conn.execute(
        "UPDATE images SET md5 = ?, sha1 = ?, file_count = ? WHERE id = ?",
        (digests.md5, digests.sha1, 1, image_id),
    )
    conn.commit()
    resolve_elf_library_edges(conn, image_id=image_id)
    _export_secrets_after_image_index(
        conn,
        image_id=image_id,
        image_key=image_key,
        secrets_dir=secrets_dir,
        scan_secrets=scan_secrets,
    )
    if progress:
        progress(
            f"indexed {image_key} ::{rel_path} lines={c['text_lines']} "
            f"elf_sym={c['elf_sym']} elf_str={c['elf_str']} secrets={c.get('secrets', 0)}"
        )
    result = {"ok": True, "image_id": image_id, "path": image_key, **c}
    _mark_analysis_completed(
        conn,
        image_path=image_key,
        md5=digests.md5,
        size_bytes=size_b,
        options_hash=options_hash,
        metrics=result,
    )
    return result


def index_carrier_metadata_artifact(
    conn: sqlite3.Connection,
    image_key: str,
    kind: str,
    data: bytes,
    *,
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    Index pkgstream/certificate carrier JSON as ``carrier_metadata`` (not ``files``).

    Search with ``corpus grep --kind carrier_meta``; omit from ``corpus find`` paths.
    """
    digests = digest_bytes(data)
    size_b = len(data)
    try:
        json_text = data.decode("utf-8")
    except UnicodeDecodeError:
        json_text = data.decode("utf-8", errors="replace")

    delete_image_by_path(conn, image_key)
    upsert_content_blob(conn, digests, size_b, content_class="carrier_metadata")
    cur = conn.execute(
        "INSERT INTO images(path, md5, sha1, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?,?)",
        (image_key, digests.md5, digests.sha1, size_b, 0, _utc_now()),
    )
    image_id = cur.lastrowid
    assert image_id is not None
    conn.execute(
        "INSERT OR REPLACE INTO carrier_metadata(image_id, kind, sha256, size_bytes, json_text, indexed_at) "
        "VALUES (?,?,?,?,?,?)",
        (image_id, kind, digests.md5, size_b, json_text, _utc_now()),
    )
    conn.commit()
    if progress:
        progress(f"# carrier_metadata indexed kind={kind} path={image_key} size={size_b}B")
    return {
        "ok": True,
        "path": image_key,
        "image_id": image_id,
        "kind": kind,
        "carrier_metadata": True,
        "size_bytes": size_b,
    }


def build_index_for_extracted_tree(
    conn: sqlite3.Connection,
    root: Path,
    *,
    image_key: Optional[str] = None,
    max_file_bytes: int = 32 * 1024 * 1024,
    skip_suffixes: bool = True,
    symtab: bool = False,
    string_sections: Optional[frozenset[str]] = None,
    min_string_len: int = 4,
    max_strings_per_file: int = DEFAULT_MAX_STRINGS_PER_FILE,
    dwarf: bool = False,
    scan_secrets: bool = False,
    secrets_dir: Optional[Path] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    Index files under an extracted rootfs directory (same classification as blob ingest).
    Stored ``images.path`` defaults to ``extracted:<absolute_root>`` unless ``image_key`` is set.
    """
    sections = string_sections if string_sections is not None else ELF_STRING_SECTIONS
    root = root.resolve()
    if not root.is_dir():
        return {"ok": False, "error": f"not a directory: {root}"}

    ipath = image_key if image_key else f"extracted:{root}"

    delete_image_by_path(conn, ipath)
    cur = conn.execute(
        "INSERT INTO images(path, md5, sha1, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?,?)",
        (ipath, None, None, 0, 0, _utc_now()),
    )
    image_id = cur.lastrowid
    assert image_id is not None

    totals = {
        "text_lines": 0,
        "elf_sym": 0,
        "elf_str": 0,
        "files_seen": 0,
        "file_strings": 0,
        "file_versions": 0,
        "binary_formats": 0,
        "dwarf_units": 0,
        "secrets": 0,
    }

    def log(msg: str) -> None:
        if progress:
            progress(msg)

    for rel, data in iter_extracted_tree_files(root):
        totals["files_seen"] += 1
        c = iter_index_file(
            conn,
            image_id,
            rel,
            data,
            max_file_bytes=max_file_bytes,
            skip_suffixes=skip_suffixes,
            symtab=symtab,
            string_sections=sections,
            min_string_len=min_string_len,
            max_strings_per_file=max_strings_per_file,
            dwarf=dwarf,
            scan_secrets=scan_secrets,
            progress=progress,
        )
        for k in (
            "text_lines",
            "elf_sym",
            "elf_str",
            "file_strings",
            "file_versions",
            "binary_formats",
            "dwarf_units",
            "secrets",
        ):
            totals[k] += c[k]

    conn.execute(
        "UPDATE images SET file_count = ? WHERE id = ?", (totals["files_seen"], image_id)
    )
    conn.commit()
    resolve_elf_library_edges(conn, image_id=image_id)
    _export_secrets_after_image_index(
        conn,
        image_id=image_id,
        image_key=ipath,
        secrets_dir=secrets_dir,
        scan_secrets=scan_secrets,
    )
    log(
        f"indexed extracted tree id={image_id} root={root} files={totals['files_seen']} "
        f"lines={totals['text_lines']} elf_sym={totals['elf_sym']} elf_str={totals['elf_str']} "
        f"secrets={totals.get('secrets', 0)}"
    )
    return {"ok": True, "image_id": image_id, **totals, "path": ipath}


def _peel_uimage_kernel_member(
    full_image: bytes,
    *,
    member_index: int = 0,
) -> Tuple[Any, bytes, bytes]:
    """
    Split MULTI/single uImage and decompress member *member_index* per U-Boot rules.

    Returns ``(outer_header, raw_member, plain_member)`` where *plain_member* is suitable
    for :func:`corpus.vmlinux_elf.try_vmlinux_to_elf`.
    """
    from paceflash.uimage_kernel import peel_uimage_kernel_member

    peel = peel_uimage_kernel_member(full_image, member_index=member_index)
    return peel.header, peel.member_raw, peel.kernel_inner


def _index_embedded_uimage(
    conn: sqlite3.Connection,
    pkgstream_path: Path,
    body: bytes,
    hit: Dict[str, Any],
    carved_dir: Path,
    *,
    collection_slug: Optional[str] = None,
    max_file_bytes: int,
    skip_suffixes: bool,
    symtab: bool,
    string_sections: Optional[frozenset[str]],
    min_string_len: int,
    progress: Optional[Callable[[str], None]],
) -> Dict[str, Any]:
    """
    Carve uImage, peel kernel member (:func:`uboot.uimage.carve_uimage_member_body`),
    run **vmlinux-to-elf** when available, index the resulting ELF (or fallback: inner ``.bin``).
    """
    _ensure_repo_on_path()
    try:
        from uboot.uimage import carve_uimage_member_body  # noqa: F401 — import check
    except ImportError as e:
        return {"kind": "uimage", "error": f"uboot.uimage import failed ({e})"}

    off = int(hit["offset"])
    sz = int(hit["size"])
    uimg_full = body[off : off + sz]
    stem = f"uimage_{off:#010x}_{sz}"
    upath = carved_dir / f"{stem}.bin"
    upath.write_bytes(uimg_full)
    if progress:
        progress(f"# carved uImage @{off:#x} len={sz} → {upath.name}")

    out: Dict[str, Any] = {
        "kind": "uimage",
        "offset": off,
        "raw_carve": str(upath),
    }

    try:
        _h, member_raw, inner = _peel_uimage_kernel_member(uimg_full, member_index=0)
        kbin = carved_dir / f"{stem}_kernel_inner.bin"
        kbin.write_bytes(inner)
        out["kernel_inner"] = str(kbin)
        out["member_decompressed"] = inner != member_raw
    except Exception as e:
        out["error"] = str(e)
        if progress:
            progress(f"# WARN uImage @{off:#x} kernel extract: {e}")
        return out

    ok, err, elf_bytes = try_vmlinux_to_elf(kbin, None)
    pkg_abs = pkgstream_path.resolve()
    eff_max = max_file_bytes

    if ok and elf_bytes is not None:
        out["vmlinux_elf"] = None
        ik = format_pkgstream_image_key(
            collection_slug, pkg_abs, f"kernel_elf:{off:#x}"
        )
        data = elf_bytes
        r = index_single_blob_as_image(
            conn,
            ik,
            "vmlinux.elf",
            data,
            max_file_bytes=eff_max,
            skip_suffixes=skip_suffixes,
            symtab=symtab,
            string_sections=string_sections,
            min_string_len=min_string_len,
            progress=progress,
        )
        out["elf_index"] = r
        if not r.get("ok"):
            out["elf_index_error"] = r.get("error")
    else:
        out["vmlinux_to_elf_error"] = err
        if progress:
            progress(f"# WARN vmlinux-to-elf @{off:#x}: {err[:300]}")
        ik2 = format_pkgstream_image_key(
            collection_slug, pkg_abs, f"kernel_inner:{off:#x}"
        )
        r2 = index_single_blob_as_image(
            conn,
            ik2,
            "kernel_inner.bin",
            inner,
            max_file_bytes=eff_max,
            skip_suffixes=skip_suffixes,
            symtab=symtab,
            string_sections=string_sections,
            min_string_len=min_string_len,
            progress=progress,
        )
        out["fallback_index"] = r2

    return out


def _index_uimage_artifact(
    conn: sqlite3.Connection,
    image_key: str,
    data: bytes,
    *,
    sidecar_dir: Optional[Path] = None,
    display_base: Optional[Path] = None,
    max_file_bytes: int,
    skip_suffixes: bool,
    symtab: bool,
    string_sections: Optional[frozenset[str]],
    min_string_len: int,
    max_strings_per_file: int = DEFAULT_MAX_STRINGS_PER_FILE,
    dwarf: bool = False,
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Peel one uImage artifact and index vmlinux ELF when conversion succeeds."""
    out: Dict[str, Any] = {"kind": "uimage", "path": image_key}
    uimg_d = digest_bytes(data)
    upsert_content_blob(conn, uimg_d, len(data), content_class="uimage")
    transform_opts = "vmlinux_to_elf:v1"
    cached_elf_md5 = get_blob_transform_dst(conn, uimg_d.md5, "vmlinux_to_elf", transform_opts)
    if cached_elf_md5:
        out["transform_cache_hit"] = True
        out["elf_md5"] = cached_elf_md5
        if progress:
            progress(f"# uImage transform cache hit {image_key} md5={uimg_d.md5} elf={cached_elf_md5}")
        return out

    with tempfile.TemporaryDirectory() as td:
        sidecars = Path(sidecar_dir) if sidecar_dir is not None else Path(td)
        sidecars.mkdir(parents=True, exist_ok=True)
        kbin = sidecars / "kernel_inner.bin"
        try:
            _h, member_raw, inner = _peel_uimage_kernel_member(data, member_index=0)
            _write_bytes_if_needed(kbin, inner)
            out["kernel_inner"] = _display_path(kbin, base=display_base)
            out["member_decompressed"] = inner != member_raw
            inner_d = digest_bytes(inner)
            upsert_content_blob(conn, inner_d, len(inner), content_class="kernel_inner")
        except Exception as e:
            out["error"] = str(e)
            if progress:
                progress(f"# WARN uImage artifact {image_key}: {e}")
            return out

        if progress:
            progress(f"# uImage convert start {image_key}: vmlinux-to-elf")
        convert_started = time.monotonic()
        ok, err, elf_bytes = try_vmlinux_to_elf(kbin, None)
        if progress:
            status = "ok" if ok and elf_bytes is not None else "fallback"
            progress(
                f"# uImage convert {status} {image_key} "
                f"elapsed={_format_duration(time.monotonic() - convert_started)}"
            )
        if ok and elf_bytes is not None:
            elf_d = digest_bytes(elf_bytes)
            upsert_content_blob(conn, elf_d, len(elf_bytes), content_class="elf")
            record_blob_transform(conn, uimg_d.md5, "vmlinux_to_elf", transform_opts, elf_d.md5)
            elf_path = sidecars / "vmlinux.elf"
            _write_bytes_if_needed(elf_path, elf_bytes)
            elf_image_key = _display_path(elf_path, base=display_base)
            r = index_single_blob_as_image(
                conn,
                elf_image_key,
                "vmlinux.elf",
                elf_bytes,
                max_file_bytes=max_file_bytes,
                skip_suffixes=skip_suffixes,
                symtab=symtab,
                string_sections=string_sections,
                min_string_len=min_string_len,
                max_strings_per_file=max_strings_per_file,
                dwarf=dwarf,
                progress=progress,
            )
            out["elf_index"] = r
            out["elf_md5"] = elf_d.md5
        else:
            out["vmlinux_to_elf_error"] = err
            kernel_image_key = _display_path(kbin, base=display_base)
            r = index_single_blob_as_image(
                conn,
                kernel_image_key,
                "kernel_inner.bin",
                inner,
                max_file_bytes=max_file_bytes,
                skip_suffixes=skip_suffixes,
                symtab=symtab,
                string_sections=string_sections,
                min_string_len=min_string_len,
                max_strings_per_file=max_strings_per_file,
                dwarf=dwarf,
                progress=progress,
            )
            out["fallback_index"] = r
    return out


def index_artifact(
    conn: sqlite3.Connection,
    artifact: Any,
    *,
    work_root: Optional[Path] = None,
    display_base: Optional[Path] = None,
    max_file_bytes: int = 32 * 1024 * 1024,
    skip_suffixes: bool = True,
    symtab: bool = False,
    string_sections: Optional[frozenset[str]] = None,
    min_string_len: int = 4,
    max_strings_per_file: int = DEFAULT_MAX_STRINGS_PER_FILE,
    dwarf: bool = False,
    jobs: int = 1,
    sbom_dir: Optional[Path] = None,
    sbom_source: str = "auto",
    sbom_mount_root: Optional[Path] = None,
    syft_bin: str = "syft",
    sbom_format: str = "syft-json",
    scan_secrets: bool = False,
    secrets_dir: Optional[Path] = None,
    secrets_gitleaks: bool = False,
    gitleaks_bin: str = "gitleaks",
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Index one artifact yielded by ``lib2spy`` or ``paceflash`` public APIs."""
    kind = str(getattr(artifact, "kind"))
    logical_path = str(getattr(artifact, "logical_path"))
    metadata = dict(getattr(artifact, "metadata", {}) or {})
    data = artifact.read_bytes() if hasattr(artifact, "read_bytes") else bytes(getattr(artifact, "data"))
    artifact_path, materialize_status = _materialize_artifact_payload(artifact, work_root, data)
    # Keep a stable logical key (collection:...:pkgstream:/... / collection:...:paceflash:/...)
    # even when we materialize the artifact bytes to disk under work_root.
    source_key = getattr(artifact, "source_key", None)
    image_key = str(source_key) if source_key else _display_path(artifact_path, base=display_base)
    started = time.monotonic()
    if progress:
        progress(
            f"# artifact start kind={kind} path={logical_path} size={len(data)}B "
            f"stored={image_key} materialize={materialize_status}"
        )
    if kind == "squashfs":
        if artifact_path is not None:
            result = build_index_for_image(
                conn,
                artifact_path,
                image_key=image_key,
                max_file_bytes=max_file_bytes,
                skip_suffixes=skip_suffixes,
                symtab=symtab,
                string_sections=string_sections,
                min_string_len=min_string_len,
                max_strings_per_file=max_strings_per_file,
                dwarf=dwarf,
                jobs=jobs,
                scan_secrets=scan_secrets,
                secrets_dir=secrets_dir,
                progress=progress,
            )
        else:
            result = build_index_for_squashfs_bytes(
                conn,
                image_key,
                data,
                max_file_bytes=max_file_bytes,
                skip_suffixes=skip_suffixes,
                symtab=symtab,
                string_sections=string_sections,
                min_string_len=min_string_len,
                max_strings_per_file=max_strings_per_file,
                dwarf=dwarf,
                scan_secrets=scan_secrets,
                secrets_dir=secrets_dir,
                progress=progress,
            )
        result["artifact_path"] = image_key
        result["materialized"] = materialize_status
        record_artifact_edge(conn, image_key, logical_path, metadata)
        if sbom_dir is not None:
            from corpus.sbom import materialize_files, safe_sbom_name
            from lib2spy.pkgstream_corpus import iter_squashfs_files, iter_squashfs_files_from_bytes

            mode = sbom_source if sbom_source in {"auto", "mount", "materialize"} else "auto"
            carrier_md5_row = conn.execute(
                "SELECT md5 FROM images WHERE path = ?", (image_key,)
            ).fetchone()
            carrier_md5 = str(carrier_md5_row["md5"]) if carrier_md5_row and carrier_md5_row["md5"] else None
            tree_dir = Path(sbom_dir) / "sources" / safe_sbom_name(image_key, suffix="", carrier_md5=carrier_md5)
            sbom_path = Path(sbom_dir) / safe_sbom_name(image_key, carrier_md5=carrier_md5)
            mount_sbom_path = Path(sbom_dir) / "mounted" / safe_sbom_name(image_key, carrier_md5=carrier_md5)
            if result.get("skipped"):
                cached_sbom = mount_sbom_path if mount_sbom_path.is_file() else sbom_path
                if cached_sbom.is_file() and cached_sbom.stat().st_size > 0:
                    if progress:
                        progress(f"# syft SBOM skip cached {image_key}")
                    result["sbom"] = {
                        "ok": True,
                        "cached": True,
                        "path": str(cached_sbom),
                        "grype_hint": f"grype sbom:{cached_sbom}",
                    }
                    if progress:
                        progress(
                            f"# artifact done kind={kind} path={logical_path} "
                            f"elapsed={_format_duration(time.monotonic() - started)}"
                        )
                    return result
            mount_root = (
                Path(sbom_mount_root)
                if sbom_mount_root is not None
                else Path(sbom_dir) / "mounts"
            )
            try:
                from corpus.sbom import (
                    open_squashfs_mount_tree,
                    run_syft,
                    run_syft_squashfs_archive,
                )

                sbom_result: Dict[str, Any] = {
                    "ok": False,
                    "error": "sbom not run",
                    "source_mode": mode,
                }
                gitleaks_tree: Optional[Path] = None
                if mode == "materialize":
                    if progress:
                        progress(
                            f"# syft materialize start {image_key} -> "
                            f"{_display_path(tree_dir, base=display_base)}"
                        )
                    sbom_started = time.monotonic()
                    files = (
                        iter_squashfs_files(artifact_path)
                        if artifact_path is not None
                        else iter_squashfs_files_from_bytes(data)
                    )
                    materialized = materialize_files(files, tree_dir)
                    if progress:
                        progress(
                            f"# syft materialize done {image_key} "
                            f"written={materialized.get('files_written')} reused={materialized.get('files_reused')} "
                            f"elapsed={_format_duration(time.monotonic() - sbom_started)}"
                        )
                    syft_started = time.monotonic()
                    sbom_result = run_syft(
                        tree_dir,
                        sbom_path,
                        syft_bin=syft_bin,
                        output_format=sbom_format,
                        source_type="materialized-dir",
                    )
                    sbom_result["materialized"] = materialized
                    sbom_result["source_mode"] = "materialize"
                    gitleaks_tree = tree_dir
                elif mode in {"auto", "mount"} and artifact_path is not None:
                    if progress:
                        progress(
                            f"# syft mount start {image_key} -> "
                            f"{_display_path(mount_sbom_path, base=display_base)}"
                        )
                    with open_squashfs_mount_tree(
                        artifact_path,
                        mount_root,
                        name_hint=mount_sbom_path.stem,
                        allow_fuse=True,
                    ) as (mount_tree, tree_mode):
                        if mount_tree is not None:
                            syft_started = time.monotonic()
                            sbom_result = run_syft(
                                mount_tree,
                                mount_sbom_path,
                                syft_bin=syft_bin,
                                output_format=sbom_format,
                                source_type="squashfs-mount",
                            )
                            sbom_result["source_image"] = str(artifact_path)
                            sbom_result["source_mode"] = tree_mode
                            if progress and sbom_result.get("ok"):
                                cache = " cached" if sbom_result.get("cached") else ""
                                progress(
                                    f"# syft {tree_mode} run done{cache} {image_key} "
                                    f"elapsed={_format_duration(time.monotonic() - syft_started)}"
                                )
                            gitleaks_tree = mount_tree
                        elif mode == "mount":
                            sbom_result = {
                                "ok": False,
                                "error": "squashfs mount required (--sbom-source mount) but kernel and squashfuse failed",
                                "source_mode": "mount",
                            }
                            gitleaks_tree = None
                        else:
                            if progress:
                                progress(
                                    f"# syft squashfs: archive scan {image_key} "
                                    f"(mount/squashfuse unavailable)"
                                )
                            syft_started = time.monotonic()
                            sbom_result = run_syft_squashfs_archive(
                                artifact_path,
                                mount_sbom_path,
                                syft_bin=syft_bin,
                                output_format=sbom_format,
                            )
                            if progress and sbom_result.get("ok"):
                                cache = " cached" if sbom_result.get("cached") else ""
                                progress(
                                    f"# syft squashfs-file run done{cache} {image_key} "
                                    f"elapsed={_format_duration(time.monotonic() - syft_started)}"
                                )
                            gitleaks_tree = None
                else:
                    gitleaks_tree = None

                if (
                    scan_secrets
                    and secrets_gitleaks
                    and secrets_dir is not None
                    and gitleaks_tree is not None
                    and Path(gitleaks_tree).is_dir()
                    and result.get("image_id")
                ):
                    from corpus.secrets import (
                        GITLEAKS_REPORT_SUFFIX,
                        ingest_gitleaks_report_into_db,
                        run_gitleaks_directory,
                    )

                    gl_report = (
                        Path(secrets_dir)
                        / "gitleaks"
                        / safe_sbom_name(image_key, suffix=GITLEAKS_REPORT_SUFFIX)
                    )
                    if progress:
                        progress(f"# gitleaks start {image_key} -> {gl_report}")
                    gl_res = run_gitleaks_directory(
                        Path(gitleaks_tree), gl_report, gitleaks_bin=gitleaks_bin
                    )
                    if gl_res.get("ok"):
                        n_gl = ingest_gitleaks_report_into_db(
                            conn,
                            image_id=int(result["image_id"]),
                            image_key=image_key,
                            report_path=Path(str(gl_res["path"])),
                        )
                        gl_res["ingested"] = n_gl
                        _export_secrets_after_image_index(
                            conn,
                            image_id=int(result["image_id"]),
                            image_key=image_key,
                            secrets_dir=secrets_dir,
                            scan_secrets=True,
                        )
                    result["gitleaks"] = gl_res
            except Exception as e:
                sbom_result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            result["sbom"] = sbom_result
            if sbom_result.get("ok") and sbom_result.get("path"):
                from corpus.vuln import append_sbom_catalog

                append_sbom_catalog(
                    Path(sbom_dir),
                    image_key=image_key,
                    sbom_path=Path(str(sbom_result["path"])),
                    source_mode=str(sbom_result.get("source_mode") or ""),
                    package_count=sbom_result.get("package_count"),
                )
            if progress:
                status = "ok" if sbom_result.get("ok") else f"failed: {sbom_result.get('error')}"
                progress(f"# syft SBOM {image_key}: {status}")
        if progress:
            progress(f"# artifact done kind={kind} path={logical_path} elapsed={_format_duration(time.monotonic() - started)}")
        return result
    if kind == "uimage":
        sidecar_dir = (
            artifact_path.with_name(f"{artifact_path.name}.sidecars")
            if artifact_path is not None
            else None
        )
        result = _index_uimage_artifact(
            conn,
            image_key,
            data,
            sidecar_dir=sidecar_dir,
            display_base=display_base,
            max_file_bytes=max_file_bytes,
            skip_suffixes=skip_suffixes,
            symtab=symtab,
            string_sections=string_sections,
            min_string_len=min_string_len,
            max_strings_per_file=max_strings_per_file,
            dwarf=dwarf,
            progress=progress,
        )
        result["artifact_path"] = image_key
        result["materialized"] = materialize_status
        record_artifact_edge(conn, image_key, logical_path, metadata)
        if progress:
            progress(
                f"# artifact done kind={kind} path={logical_path} "
                f"elapsed={_format_duration(time.monotonic() - started)}"
            )
        return result
    if kind in CARRIER_METADATA_KINDS:
        result = index_carrier_metadata_artifact(
            conn,
            image_key,
            kind,
            data,
            progress=progress,
        )
        result["artifact_path"] = image_key
        result["materialized"] = materialize_status
        record_artifact_edge(conn, image_key, logical_path, metadata)
        if progress:
            progress(
                f"# artifact done kind={kind} path={logical_path} "
                f"elapsed={_format_duration(time.monotonic() - started)}"
            )
        return result
    if kind in {"mtd_partition", "ext2_file"}:
        # Pace install kernel is normally ``/sys1/uImage`` on assembled opentla4 ext2 (paceflash
        # emits kind=uimage). If an ext2 file begins with uImage magic, peel via
        # :func:`_peel_uimage_kernel_member` and run vmlinux-to-elf.
        # If this payload begins with a legacy uImage header, treat it as a uImage so we
        try:
            from uboot.uimage import parse_uimage_header
        except Exception:
            parse_uimage_header = None  # type: ignore[assignment]
        if parse_uimage_header is not None and parse_uimage_header(data[:64]) is not None:
            sidecar_dir = (
                artifact_path.with_name(f"{artifact_path.name}.sidecars")
                if artifact_path is not None
                else None
            )
            result = _index_uimage_artifact(
                conn,
                image_key,
                data,
                sidecar_dir=sidecar_dir,
                display_base=display_base,
                max_file_bytes=max_file_bytes,
                skip_suffixes=skip_suffixes,
                symtab=symtab,
                string_sections=string_sections,
                min_string_len=min_string_len,
                max_strings_per_file=max_strings_per_file,
                dwarf=dwarf,
                progress=progress,
            )
            result["artifact_path"] = image_key
            result["materialized"] = materialize_status
            record_artifact_edge(conn, image_key, logical_path, metadata)
            if progress:
                progress(
                    f"# artifact done kind={kind} path={logical_path} elapsed={_format_duration(time.monotonic() - started)}"
                )
            return result
    if kind == "mtd_partition" and str(metadata.get("partition") or "") == "tlpart":
        # tlpart is a huge container; do not index it as an image/file.
        # We still *walk* it to derive typed indexes (e.g. board_param) in build_index_from_flash.
        result = {
            "ok": True,
            "path": image_key,
            "skipped": True,
            "reason": "container_walk_only",
            "size_bytes": len(data),
        }
        record_artifact_edge(conn, image_key, logical_path, metadata)
        if progress:
            progress(
                f"# artifact done kind={kind} path={logical_path} elapsed={_format_duration(time.monotonic() - started)}"
            )
        return result
    result = index_single_blob_as_image(
        conn,
        image_key,
        logical_path,
        data,
        max_file_bytes=max_file_bytes,
        skip_suffixes=skip_suffixes,
        symtab=symtab,
        string_sections=string_sections,
        min_string_len=min_string_len,
        max_strings_per_file=max_strings_per_file,
        dwarf=dwarf,
        scan_secrets=scan_secrets,
        secrets_dir=secrets_dir,
        progress=progress,
    )
    result["artifact_path"] = image_key
    result["materialized"] = materialize_status
    record_artifact_edge(conn, image_key, logical_path, metadata)
    if progress:
        progress(f"# artifact done kind={kind} path={logical_path} elapsed={_format_duration(time.monotonic() - started)}")
    return result


def build_index_from_pkgstream(
    conn: sqlite3.Connection,
    pkgstream_path: Path,
    work_root: Path,
    *,
    collection_slug: Optional[str] = None,
    max_file_bytes: int = 32 * 1024 * 1024,
    skip_suffixes: bool = True,
    symtab: bool = False,
    string_sections: Optional[frozenset[str]] = None,
    min_string_len: int = 4,
    max_strings_per_file: int = DEFAULT_MAX_STRINGS_PER_FILE,
    dwarf: bool = False,
    jobs: int = 1,
    sbom_dir: Optional[Path] = None,
    sbom_source: str = "auto",
    sbom_mount_root: Optional[Path] = None,
    syft_bin: str = "syft",
    sbom_format: str = "syft-json",
    scan_secrets: bool = False,
    secrets_dir: Optional[Path] = None,
    secrets_gitleaks: bool = False,
    gitleaks_bin: str = "gitleaks",
    display_base: Optional[Path] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    Full pkgstream corpus ingest through ``lib2spy``'s public artifact iterator.

    With *collection_slug*, logical keys are prefixed so several carriers (install + conf/certs)
    can load into one DB as a release bundle:
    ``collection:<slug>:pkgstream:<abs_pkg>:tlv``, ``…:squash_embedded:<offset>``, etc.

    Without it, keys stay ``pkgstream:<abs_pkg>:…`` (legacy).
    """
    from lib2spy.artifacts import iter_pkgstream_artifacts

    sections = string_sections if string_sections is not None else ELF_STRING_SECTIONS
    pkgstream_path = pkgstream_path.resolve()
    work_root = work_root.resolve()
    display_base = Path(display_base).resolve() if display_base is not None else _REPO_ROOT
    work_root.mkdir(parents=True, exist_ok=True)
    ingest_key = pkgstream_ingest_key(pkgstream_path, collection_slug)
    pkg_md5 = file_md5(pkgstream_path)
    run_options_hash = _index_run_options_hash(
        max_file_bytes=max_file_bytes,
        skip_suffixes=skip_suffixes,
        symtab=symtab,
        string_sections=sections,
        min_string_len=min_string_len,
        max_strings_per_file=max_strings_per_file,
        dwarf=dwarf,
    )

    def log(msg: str) -> None:
        if progress:
            progress(msg)

    completed_ingest = _completed_ingest_row(
        conn,
        ingest_key=ingest_key,
        md5=pkg_md5,
        options_hash=run_options_hash,
    )
    if completed_ingest is not None:
        metrics = json.loads(completed_ingest["metrics_json"] or "{}")
        log(
            f"# pkgstream ingest skip completed {_display_path(pkgstream_path, base=display_base)} "
            f"artifacts={metrics.get('artifact_count')} skipped_squashfs={metrics.get('squashfs_skipped')}"
        )
        return {
            "ok": True,
            "skipped": True,
            "reason": "ingest_completed",
            "pkgstream_path": _display_path(pkgstream_path, base=display_base),
            "work_root": _display_path(work_root, base=display_base),
            "collection_slug": collection_slug,
            **metrics,
        }

    parts: List[Dict[str, Any]] = []
    log(f"# pkgstream artifact ingest -> {work_root}")
    squashfs_skipped = 0
    try:
        artifacts = iter_pkgstream_artifacts(pkgstream_path, collection=collection_slug)
        for artifact in artifacts:
            try:
                result = index_artifact(
                    conn,
                    artifact,
                    work_root=work_root,
                    display_base=display_base,
                    max_file_bytes=max_file_bytes,
                    skip_suffixes=skip_suffixes,
                    symtab=symtab,
                    string_sections=sections,
                    min_string_len=min_string_len,
                    max_strings_per_file=max_strings_per_file,
                    dwarf=dwarf,
                    jobs=jobs,
                    sbom_dir=sbom_dir,
                    sbom_source=sbom_source,
                    sbom_mount_root=sbom_mount_root,
                    syft_bin=syft_bin,
                    sbom_format=sbom_format,
                    scan_secrets=scan_secrets,
                    secrets_dir=secrets_dir,
                    secrets_gitleaks=secrets_gitleaks,
                    gitleaks_bin=gitleaks_bin,
                    progress=progress,
                )
            except Exception as e:
                result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                log(f"# WARN artifact {artifact.source_key}: {result['error']}")
            if isinstance(result, dict) and result.get("skipped") and str(artifact.kind) == "squashfs":
                squashfs_skipped += 1
            parts.append(
                {
                    "kind": artifact.kind,
                    "path": artifact.logical_path,
                    "source_key": artifact.source_key,
                    "artifact_path": result.get("artifact_path") if isinstance(result, dict) else None,
                    "result": result,
                }
            )
    except Exception as e:
        return {"ok": False, "error": f"iter_pkgstream_artifacts: {e}", "parts": parts}

    ingest_metrics = {
        "artifact_count": len(parts),
        "squashfs_skipped": squashfs_skipped,
        "collection_slug": collection_slug,
    }
    _mark_ingest_completed(
        conn,
        ingest_key=ingest_key,
        md5=pkg_md5,
        options_hash=run_options_hash,
        metrics=ingest_metrics,
    )
    return {
        "ok": True,
        "pkgstream_path": _display_path(pkgstream_path, base=display_base),
        "work_root": _display_path(work_root, base=display_base),
        "collection_slug": collection_slug,
        "parts": parts,
        **ingest_metrics,
    }


def build_index_from_pkgstream_root(
    conn: sqlite3.Connection,
    root: Path,
    work_base: Path,
    *,
    group_by_version: bool = True,
    collection_slug: Optional[str] = None,
    collection_prefix: str = "version:",
    max_file_bytes: int = 32 * 1024 * 1024,
    skip_suffixes: bool = True,
    symtab: bool = False,
    string_sections: Optional[frozenset[str]] = None,
    min_string_len: int = 4,
    max_strings_per_file: int = DEFAULT_MAX_STRINGS_PER_FILE,
    dwarf: bool = False,
    jobs: int = 1,
    sbom_dir: Optional[Path] = None,
    sbom_source: str = "auto",
    sbom_mount_root: Optional[Path] = None,
    syft_bin: str = "syft",
    sbom_format: str = "syft-json",
    scan_secrets: bool = False,
    secrets_dir: Optional[Path] = None,
    secrets_gitleaks: bool = False,
    gitleaks_bin: str = "gitleaks",
    display_base: Optional[Path] = None,
    pkgstream_version_order: str = "path",
    pkgstream_path_substrings: Optional[Sequence[str]] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Index every pkgstream under a root directory, optionally grouping by detected version."""
    root = Path(root).resolve()
    work_base = Path(work_base).resolve()
    display_base = Path(display_base).resolve() if display_base is not None else _REPO_ROOT
    path_filters = [s for s in (pkgstream_path_substrings or []) if s]
    if group_by_version:
        plan = plan_pkgstream_collections(
            root,
            collection_prefix=collection_prefix,
            path_substrings=path_filters or None,
        )
    else:
        slug = collection_slug or root.name
        norm_slug = normalize_collection_slug(slug)
        plan = [
            PkgstreamCollectionPlan(
                path=p.resolve(),
                relative_path=p.relative_to(root).as_posix(),
                collection_slug=norm_slug,
                release_path=norm_slug.split(":", 1)[-1] if ":" in norm_slug else norm_slug,
                channel=parse_release_channel(norm_slug),
                version=slug,
                version_source="explicit-root",
                internal_candidates=[],
            )
            for p in iter_pkgstreams_under(root, path_substrings=path_filters or None)
        ]

    if not plan:
        detail = f"no .pkgstream files under {root}"
        if path_filters:
            detail += f" matching path substring(s): {', '.join(path_filters)!r}"
        return {"ok": False, "error": detail, "parts": []}

    plan = sort_pkgstream_plan(plan, version_order=pkgstream_version_order)

    def log(msg: str) -> None:
        if progress:
            progress(msg)

    results: List[Dict[str, Any]] = []
    failures = 0
    root_started = time.monotonic()
    for index, item in enumerate(plan, 1):
        item_started = time.monotonic()
        collection = item.collection_slug
        work = (
            work_base
            / collection_slug_for_fs(collection)
            / f"{index:04d}_{re.sub(r'[^A-Za-z0-9_.-]+', '_', item.path.stem)[:80]}"
        )
        log(
            f"# pkgstream root index {index}/{len(plan)} "
            f"collection={collection} source={item.version_source} {item.relative_path}"
        )
        res = build_index_from_pkgstream(
            conn,
            item.path,
            work,
            collection_slug=collection,
            max_file_bytes=max_file_bytes,
            skip_suffixes=skip_suffixes,
            symtab=symtab,
            string_sections=string_sections,
            min_string_len=min_string_len,
            max_strings_per_file=max_strings_per_file,
            dwarf=dwarf,
            jobs=jobs,
            sbom_dir=(
                Path(sbom_dir) / collection_slug_for_fs(collection)
                if sbom_dir is not None
                else None
            ),
            sbom_source=sbom_source,
            sbom_mount_root=sbom_mount_root,
            syft_bin=syft_bin,
            sbom_format=sbom_format,
            scan_secrets=scan_secrets,
            secrets_dir=secrets_dir,
            secrets_gitleaks=secrets_gitleaks,
            gitleaks_bin=gitleaks_bin,
            display_base=display_base,
            progress=progress,
        )
        ok = bool(res.get("ok"))
        if not ok:
            failures += 1
        sboms = [
            {
                "source_key": part.get("source_key"),
                "artifact_path": part.get("artifact_path"),
                "logical_path": part.get("path"),
                "sbom": (part.get("result") or {}).get("sbom"),
            }
            for part in (res.get("parts", []) or [])
            if isinstance(part, dict)
            and isinstance(part.get("result"), dict)
            and (part.get("result") or {}).get("sbom")
        ]
        results.append(
            {
                **item.to_json(),
                "ok": ok,
                "error": res.get("error"),
                "parts": len(res.get("parts", []) or []),
                "sboms": sboms,
            }
        )
        elapsed = time.monotonic() - root_started
        avg = elapsed / index
        eta = avg * (len(plan) - index)
        skip_note = ""
        if res.get("skipped"):
            skip_note = " skipped=ingest"
        log(
            f"# pkgstream root progress {index}/{len(plan)} ok={ok} failures={failures}{skip_note} "
            f"item_elapsed={_format_duration(time.monotonic() - item_started)} "
            f"elapsed={_format_duration(elapsed)} avg={_format_duration(avg)} eta={_format_duration(eta)}"
        )

    if group_by_version:
        sync_pkgstream_collection_metadata(conn, root, plan)

    log("# resolving ELF library edges for full corpus …")
    resolve_elf_library_edges(conn)

    summary = index_progress_summary(conn)
    log(
        f"# index resume summary images={summary.get('images')} "
        f"analyses_completed={summary.get('analyses_completed')} "
        f"pkgstreams_completed={summary.get('pkgstreams_completed')}"
    )

    return {
        "ok": failures == 0,
        "root": _display_path(root, base=display_base),
        "work_base": _display_path(work_base, base=display_base),
        "group_by_version": group_by_version,
        "pkgstream_count": len(plan),
        "failures": failures,
        "parts": results,
        "summary": summary,
    }


def build_index_from_flash(
    conn: sqlite3.Connection,
    flash_path: Path,
    *,
    collection_slug: Optional[str] = None,
    work_root: Optional[Path] = None,
    cmdline: Optional[str] = None,
    max_file_bytes: int = 32 * 1024 * 1024,
    skip_suffixes: bool = True,
    symtab: bool = False,
    string_sections: Optional[frozenset[str]] = None,
    min_string_len: int = 4,
    max_strings_per_file: int = DEFAULT_MAX_STRINGS_PER_FILE,
    dwarf: bool = False,
    sbom_dir: Optional[Path] = None,
    sbom_source: str = "auto",
    sbom_mount_root: Optional[Path] = None,
    syft_bin: str = "syft",
    sbom_format: str = "syft-json",
    scan_secrets: bool = False,
    secrets_dir: Optional[Path] = None,
    secrets_gitleaks: bool = False,
    gitleaks_bin: str = "gitleaks",
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Index artifacts from a Pace NAND/logical flash dump through ``paceflash``."""
    import os

    # Corpus walks entire ext2 trees; bulk NTL assembly beats per-block lazy replay.
    os.environ.setdefault("OPENTL_FULL_ASSEMBLY", "1")

    from paceflash.artifacts import iter_flash_corpus_artifacts

    flash_resolved = Path(flash_path).expanduser().resolve()
    collection_slug = resolve_flash_collection_slug(flash_resolved, collection_slug)
    # Cleanup: older versions indexed a synthetic board_param export as a fake file path.
    try:
        prefix = collection_image_prefix(collection_slug)
        conn.execute(
            "DELETE FROM images WHERE path LIKE ? AND path LIKE ?",
            (prefix + "%", "%:board_param:%"),
        )
        conn.execute(
            "DELETE FROM images WHERE path LIKE ? AND path LIKE ?",
            (prefix + "%", "%/board_param/keys.txt"),
        )
        # Older DBs stored synthetic reports under the materialized on-disk path (not under collection:*).
        conn.execute(
            "DELETE FROM images WHERE path LIKE ? AND path LIKE ?",
            (f"%nand_@{normalize_collection_slug(collection_slug).split('@',1)[-1]}%", "%/board_param/keys.txt"),
        )
        conn.commit()
    except Exception:
        pass
    if work_root is not None:
        work_root = Path(work_root).resolve()
        work_root.mkdir(parents=True, exist_ok=True)

    sections = string_sections if string_sections is not None else ELF_STRING_SECTIONS
    parts: List[Dict[str, Any]] = []
    tlpart_bytes: Optional[bytes] = None
    anchor_image_id: Optional[int] = None
    try:
        for artifact in iter_flash_corpus_artifacts(
            flash_resolved,
            collection=collection_slug,
            cmdline=cmdline,
        ):
            kind = str(getattr(artifact, "kind", ""))
            meta = dict(getattr(artifact, "metadata", {}) or {})
            # Capture tlpart bytes for board_param extraction (even if analysis is skipped).
            if kind == "mtd_partition" and str(meta.get("partition") or "") == "tlpart":
                try:
                    tlpart_bytes = (
                        artifact.read_bytes()  # type: ignore[attr-defined]
                        if hasattr(artifact, "read_bytes")
                        else bytes(getattr(artifact, "data"))
                    )
                except Exception:
                    tlpart_bytes = None
            try:
                result = index_artifact(
                    conn,
                    artifact,
                    work_root=work_root,
                    max_file_bytes=max_file_bytes,
                    skip_suffixes=skip_suffixes,
                    symtab=symtab,
                    string_sections=sections,
                    min_string_len=min_string_len,
                    max_strings_per_file=max_strings_per_file,
                    dwarf=dwarf,
                    sbom_dir=sbom_dir,
                    sbom_source=sbom_source,
                    sbom_mount_root=sbom_mount_root,
                    syft_bin=syft_bin,
                    sbom_format=sbom_format,
                    scan_secrets=scan_secrets,
                    secrets_dir=secrets_dir,
                    secrets_gitleaks=secrets_gitleaks,
                    gitleaks_bin=gitleaks_bin,
                    progress=progress,
                )
            except Exception as e:
                result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                if progress:
                    progress(f"# WARN flash artifact {artifact.source_key}: {result['error']}")
            # Pick an anchor image_id for typed indexes (small, already indexed artifact).
            if anchor_image_id is None and kind in ("flash_metadata", "opentla4_metadata") and isinstance(result, dict):
                if result.get("image_id") is not None:
                    anchor_image_id = int(result["image_id"])
            parts.append(
                {
                    "kind": artifact.kind,
                    "path": artifact.logical_path,
                    "source_key": artifact.source_key,
                    "result": result,
                }
            )
    except Exception as e:
        return {"ok": False, "error": f"iter_flash_corpus_artifacts: {e}", "parts": parts}
    if tlpart_bytes is not None and anchor_image_id is not None:
        bp = index_board_params_from_tlpart(
            conn,
            image_id=anchor_image_id,
            collection_slug=collection_slug,
            tlpart_bytes=tlpart_bytes,
        )
        parts.append({"kind": "board_param_index", "path": "tlpart:board_param", "source_key": None, "result": bp})
    resolve_elf_library_edges(conn)
    return {
        "ok": True,
        "flash_path": str(flash_resolved),
        "collection_slug": collection_slug,
        "parts": parts,
    }


_IDENT_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


def ident_pattern_regex(token: str) -> str:
    """
    Turn a C-style identifier into a regex that also matches common variants.

    ``lightspeed_p12`` matches ``lightspeed_p12`` and ``lightspeed p12`` (board
  param keys vs comments). Underscores in the query are ``[\\s_]``, not regex ``.``.
    """
    parts = token.split("_")
    if len(parts) < 2:
        return re.escape(token)
    return r"[\s_]".join(re.escape(part) for part in parts if part != "")


def compile_patterns(
    patterns: Sequence[str],
    fixed: bool,
    ignore_case: bool,
) -> List[re.Pattern[str]]:
    flags = re.MULTILINE
    if ignore_case:
        flags |= re.IGNORECASE
    out: List[re.Pattern[str]] = []
    for p in patterns:
        if fixed:
            out.append(re.compile(re.escape(p), flags))
        elif _IDENT_TOKEN_RE.match(p) and "_" in p:
            out.append(re.compile(ident_pattern_regex(p), flags))
        else:
            out.append(re.compile(p, flags))
    return out


def pattern_matches_line(patterns: Sequence[re.Pattern[str]], line: str) -> bool:
    return any(c.search(line) for c in patterns)


def image_collection_prefix_from_path(image_path: str) -> Optional[str]:
    """Return ``collection:<slug>:`` prefix from an image key when present."""
    if not image_path.startswith("collection:"):
        return None
    markers = [":pkgstream:", ":paceflash:"]
    positions = [image_path.find(m) for m in markers if image_path.find(m) > 0]
    if not positions:
        return None
    return image_path[: min(positions) + 1]


def resolve_elf_library_edges(
    conn: sqlite3.Connection,
    *,
    image_id: Optional[int] = None,
) -> int:
    """Resolve DT_NEEDED rows to in-corpus DT_SONAME providers."""
    if image_id is None:
        conn.execute("DELETE FROM elf_library_edges")
        needed_rows = conn.execute(
            "SELECT n.image_id, i.path AS image_path, n.path AS consumer_path, n.needed "
            "FROM elf_needed n JOIN images i ON n.image_id = i.id"
        ).fetchall()
    else:
        conn.execute("DELETE FROM elf_library_edges WHERE image_id = ?", (image_id,))
        needed_rows = conn.execute(
            "SELECT n.image_id, i.path AS image_path, n.path AS consumer_path, n.needed "
            "FROM elf_needed n JOIN images i ON n.image_id = i.id WHERE n.image_id = ?",
            (image_id,),
        ).fetchall()

    n = 0
    for row in needed_rows:
        consumer_image_id = int(row["image_id"])
        needed = str(row["needed"])
        provider = conn.execute(
            "SELECT s.image_id, i.path AS image_path, s.path AS provider_path, s.soname "
            "FROM elf_soname s JOIN images i ON s.image_id = i.id "
            "WHERE s.soname = ? AND s.image_id = ? LIMIT 1",
            (needed, consumer_image_id),
        ).fetchone()
        resolution = "same_image"
        if provider is None:
            prefix = image_collection_prefix_from_path(str(row["image_path"]))
            if prefix:
                provider = conn.execute(
                    "SELECT s.image_id, i.path AS image_path, s.path AS provider_path, s.soname "
                    "FROM elf_soname s JOIN images i ON s.image_id = i.id "
                    "WHERE s.soname = ? AND substr(i.path, 1, length(?)) = ? LIMIT 1",
                    (needed, prefix, prefix),
                ).fetchone()
                resolution = "collection"
        if provider is None:
            provider = conn.execute(
                "SELECT s.image_id, i.path AS image_path, s.path AS provider_path, s.soname "
                "FROM elf_soname s JOIN images i ON s.image_id = i.id "
                "WHERE s.soname = ? LIMIT 1",
                (needed,),
            ).fetchone()
            resolution = "global"
        if provider is None:
            resolution = "unresolved"
        conn.execute(
            "INSERT INTO elf_library_edges("
            "image_id, consumer_path, needed, provider_image_id, provider_path, provider_soname, resolution"
            ") VALUES (?,?,?,?,?,?,?)",
            (
                consumer_image_id,
                row["consumer_path"],
                needed,
                int(provider["image_id"]) if provider is not None else None,
                provider["provider_path"] if provider is not None else None,
                provider["soname"] if provider is not None else None,
                resolution,
            ),
        )
        n += 1
    conn.commit()
    return n


@dataclass
class SearchHit:
    kind: str
    image_path: str
    path: str
    detail: Dict[str, Any]

    def to_ref(self, conn: sqlite3.Connection, *, image_id: Optional[str] = None) -> str:
        from corpus.ref import format_ref_for_hit

        return format_ref_for_hit(conn, self, image_id=image_id)

    def display_line(self, conn: sqlite3.Connection) -> str:
        meta = get_collection_metadata(
            conn, collection_slug_from_image_path(self.image_path) or ""
        )
        parts: List[str] = []
        if meta and meta.get("channel"):
            parts.append(str(meta["channel"]))
        if meta and meta.get("component_version"):
            parts.append(f"component={meta['component_version']}")
        preview = self._preview_text()
        if preview:
            parts.append(preview)
        display = " ".join(parts) if parts else self.format_line()
        return display

    def _preview_text(self) -> str:
        if self.kind == "text_line":
            return str(self.detail.get("text", ""))[:120]
        if self.kind == "elf_symbol":
            return str(self.detail.get("name", ""))
        if self.kind == "elf_string":
            return str(self.detail.get("text", ""))[:120]
        if self.kind == "elf_soname":
            return str(self.detail.get("soname", ""))
        if self.kind == "elf_needed":
            return str(self.detail.get("needed", ""))
        if self.kind == "file_string":
            return str(self.detail.get("text", ""))[:120]
        if self.kind == "secret":
            return str(self.detail.get("snippet", ""))[:80]
        if self.kind == "carrier_metadata":
            return str(self.detail.get("text", ""))[:120]
        return ""

    def to_json_dict(self, conn: sqlite3.Connection) -> Dict[str, Any]:
        slug = collection_slug_from_image_path(self.image_path)
        meta = get_collection_metadata(conn, slug) if slug else None
        payload: Dict[str, Any] = {
            "kind": self.kind,
            "ref": self.to_ref(conn),
            "scope": slug or "",
            "image": self.image_path,
            "path": self.path,
            **self.detail,
        }
        if meta:
            payload["firmware_version"] = meta.get("firmware_version")
            payload["component_version"] = meta.get("component_version")
            payload["channel"] = meta.get("channel")
            payload["release_path"] = meta.get("release_path")
        if self.kind == "text_line":
            payload["preview"] = self.detail.get("text", "")
        elif self.kind == "elf_symbol":
            payload["preview"] = self.detail.get("name", "")
        elif self.kind in ("elf_string", "file_string", "carrier_metadata"):
            payload["preview"] = self.detail.get("text", "")
        return payload

    def format_line(self) -> str:
        if self.kind == "text_line":
            ln = self.detail["line_no"]
            return f"{self.image_path}::{self.path}:{ln}:{self.detail['text']}"
        if self.kind == "elf_symbol":
            return (
                f"{self.image_path}::{self.path}:SYMBOL:"
                f"{self.detail['scope']}:{self.detail['sym_type']}:{self.detail['bind']}:{self.detail['name']}"
            )
        if self.kind == "elf_string":
            sec = self.detail["section"]
            return f"{self.image_path}::{self.path}:RODATA[{sec}]:{self.detail['text']}"
        if self.kind == "elf_soname":
            return f"{self.image_path}::{self.path}:SONAME:{self.detail['soname']}"
        if self.kind == "elf_needed":
            return f"{self.image_path}::{self.path}:NEEDED:{self.detail['needed']}"
        if self.kind == "file_string":
            off = self.detail.get("offset", 0)
            return (
                f"{self.image_path}::{self.path}:STRING@{off}:"
                f"{self.detail.get('text', '')}"
            )
        if self.kind == "secret":
            off = self.detail.get("byte_offset", 0)
            return (
                f"{self.image_path}::{self.path}:SECRET[{self.detail.get('rule_id')}]:"
                f"@{off}:{self.detail.get('snippet', '')}"
            )
        if self.kind == "carrier_metadata":
            return (
                f"{self.image_path}::{self.path}:CARRIER_META[{self.detail.get('kind', '')}]:"
                f"{self.detail.get('text', '')[:120]}"
            )
        return repr(self.__dict__)


def search_index(
    conn: sqlite3.Connection,
    patterns: Sequence[str],
    *,
    fixed: bool,
    ignore_case: bool,
    kinds: Optional[frozenset[str]] = None,
    limit: int = 0,
    collection_slug: Optional[str] = None,
    completed_only: bool = False,
) -> Iterator[SearchHit]:
    """
    kinds: subset of :data:`SEARCH_KIND_CHOICES` — default :data:`DEFAULT_SEARCH_KINDS`.

    ``tlv_script`` / ``tlv_file`` search line-oriented text and extracted strings but
    only under pkgstream prefix TLV artifact keys (``…:tlv_script:…`` / ``…:tlv_file:…``).

    When *collection_slug* is set, only ``images.path`` rows under that collection
    prefix are searched (see :func:`format_pkgstream_image_key`).

    When *completed_only* is true, skip images with ``analysis_status.status='running'``
    (safe for concurrent reads while indexing).
    """
    compiled = compile_patterns(list(patterns), fixed=fixed, ignore_case=ignore_case)
    raw = kinds or DEFAULT_SEARCH_KINDS
    allowed = _expand_search_kinds(raw)
    tlv_script_only = "tlv_script" in raw and "text" not in raw and "strings" not in raw
    tlv_file_only = "tlv_file" in raw and "text" not in raw and "strings" not in raw
    n = 0

    coll_sql, coll_args = compose_image_filters(
        collection_slug=collection_slug,
        completed_only=completed_only,
    )

    if "text" in allowed:
        cur = conn.execute(
            "SELECT i.path AS ip, f.path AS fp, t.line_no, t.text, f.md5, cb.sha1 "
            "FROM blob_text_lines t "
            "JOIN files f ON f.md5 = t.content_md5 "
            "JOIN content_blobs cb ON cb.md5 = f.md5 "
            "JOIN images i ON f.image_id = i.id"
            + coll_sql,
            coll_args,
        )
        for row in cur:
            fp = str(row["fp"] or "")
            ip = str(row["ip"] or "")
            if is_carrier_metadata_filename(fp) or is_carrier_metadata_image_key(ip):
                continue
            if tlv_script_only and not is_pkgstream_script_tlv_hit(ip, fp):
                continue
            if tlv_file_only and not is_pkgstream_tlv_file_hit(ip, fp):
                continue
            if pattern_matches_line(compiled, row["text"]):
                yield SearchHit(
                    "text_line",
                    row["ip"],
                    row["fp"],
                    {
                        "line_no": row["line_no"],
                        "text": row["text"],
                        "content_md5": row["md5"],
                        "content_sha1": row["sha1"],
                    },
                )
                n += 1
                if limit and n >= limit:
                    return

    if "strings" in allowed:
        cur = conn.execute(
            "SELECT i.path AS ip, f.path AS fp, fs.offset, fs.source, fs.text, f.md5 "
            "FROM blob_file_strings fs "
            "JOIN files f ON f.md5 = fs.content_md5 "
            "JOIN images i ON f.image_id = i.id"
            + coll_sql,
            coll_args,
        )
        for row in cur:
            fp = str(row["fp"] or "")
            ip = str(row["ip"] or "")
            if is_carrier_metadata_filename(fp) or is_carrier_metadata_image_key(ip):
                continue
            if tlv_script_only and not is_pkgstream_script_tlv_hit(ip, fp):
                continue
            if tlv_file_only and not is_pkgstream_tlv_file_hit(ip, fp):
                continue
            txt = row["text"]
            if pattern_matches_line(compiled, txt):
                yield SearchHit(
                    "file_string",
                    row["ip"],
                    row["fp"],
                    {
                        "offset": row["offset"],
                        "source": row["source"],
                        "text": txt,
                    },
                )
                n += 1
                if limit and n >= limit:
                    return

    if "carrier_meta" in allowed or "carrier_metadata" in allowed:
        cur = conn.execute(
            "SELECT i.path AS ip, c.kind, c.json_text "
            "FROM carrier_metadata c JOIN images i ON c.image_id = i.id"
            + coll_sql,
            coll_args,
        )
        for row in cur:
            txt = str(row["json_text"] or "")
            if pattern_matches_line(compiled, txt):
                kind = str(row["kind"])
                yield SearchHit(
                    "carrier_metadata",
                    row["ip"],
                    carrier_metadata_virtual_path(kind),
                    {"kind": kind, "text": txt},
                )
                n += 1
                if limit and n >= limit:
                    return

    if "symbol" in allowed:
        cur = conn.execute(
            "SELECT i.path AS ip, f.path AS fp, e.scope, e.sym_type, e.bind, e.name, f.md5 "
            "FROM blob_elf_symbols e "
            "JOIN files f ON f.md5 = e.content_md5 "
            "JOIN images i ON f.image_id = i.id"
            + coll_sql,
            coll_args,
        )
        for row in cur:
            name = row["name"]
            if pattern_matches_line(compiled, name):
                yield SearchHit(
                    "elf_symbol",
                    row["ip"],
                    row["fp"],
                    {
                        "scope": row["scope"],
                        "sym_type": row["sym_type"],
                        "bind": row["bind"],
                        "name": name,
                    },
                )
                n += 1
                if limit and n >= limit:
                    return

    if "rodata" in allowed:
        cur = conn.execute(
            "SELECT i.path AS ip, f.path AS fp, s.section, s.text "
            "FROM blob_elf_strings s "
            "JOIN files f ON f.md5 = s.content_md5 "
            "JOIN images i ON f.image_id = i.id"
            + coll_sql,
            coll_args,
        )
        for row in cur:
            txt = row["text"]
            if pattern_matches_line(compiled, txt):
                yield SearchHit(
                    "elf_string",
                    row["ip"],
                    row["fp"],
                    {"section": row["section"], "text": txt},
                )
                n += 1
                if limit and n >= limit:
                    return

    if "soname" in allowed:
        cur = conn.execute(
            "SELECT i.path AS ip, s.path AS fp, s.soname "
            "FROM elf_soname s JOIN images i ON s.image_id = i.id"
            + coll_sql,
            coll_args,
        )
        for row in cur:
            sn = row["soname"]
            if pattern_matches_line(compiled, sn):
                yield SearchHit(
                    "elf_soname",
                    row["ip"],
                    row["fp"],
                    {"soname": sn},
                )
                n += 1
                if limit and n >= limit:
                    return

    if "needed" in allowed:
        cur = conn.execute(
            "SELECT i.path AS ip, n.path AS fp, n.needed "
            "FROM elf_needed n JOIN images i ON n.image_id = i.id"
            + coll_sql,
            coll_args,
        )
        for row in cur:
            nd = row["needed"]
            if pattern_matches_line(compiled, nd):
                yield SearchHit(
                    "elf_needed",
                    row["ip"],
                    row["fp"],
                    {"needed": nd},
                )
                n += 1
                if limit and n >= limit:
                    return

    if "secret" in allowed:
        cur = conn.execute(
            "SELECT i.path AS ip, s.path AS fp, s.rule_id, s.severity, s.line_no, "
            "s.byte_offset, s.snippet "
            "FROM secret_findings s JOIN images i ON s.image_id = i.id"
            + coll_sql,
            coll_args,
        )
        for row in cur:
            blob = f"{row['rule_id']} {row['snippet']}"
            if pattern_matches_line(compiled, blob):
                yield SearchHit(
                    "secret",
                    row["ip"],
                    row["fp"],
                    {
                        "rule_id": row["rule_id"],
                        "severity": row["severity"],
                        "line_no": row["line_no"],
                        "byte_offset": row["byte_offset"],
                        "snippet": row["snippet"],
                    },
                )
                n += 1
                if limit and n >= limit:
                    return

    if "board_param" in allowed:
        # Typed board params from tlpart extraction (not a file row).
        coll_sql = ""
        coll_args: Tuple[Any, ...] = ()
        if collection_slug:
            # board_params.collection_slug stores normalized slug directly.
            coll_sql = " AND p.collection_slug = ?"
            coll_args = (normalize_collection_slug(collection_slug),)
        cur = conn.execute(
            "SELECT p.collection_slug AS scope, k.key, k.value, k.value_len, k.is_sensitive, k.source "
            "FROM board_param_kv k JOIN board_params p ON k.board_params_id = p.id "
            "WHERE 1=1" + coll_sql,
            coll_args,
        )
        for row in cur:
            blob = f"{row['key']}={row['value']} {row['source']}"
            if pattern_matches_line(compiled, blob):
                scope = str(row["scope"] or "")
                yield SearchHit(
                    "board_param",
                    f"collection:{scope}:board_params",
                    f"board_param:{row['key']}",
                    {
                        "key": row["key"],
                        "value_preview": (str(row["value"])[:120] if not int(row["is_sensitive"] or 0) else "***"),
                        "value_len": int(row["value_len"] or 0),
                        "is_sensitive": int(row["is_sensitive"] or 0),
                        "source": row["source"],
                    },
                )
                n += 1
                if limit and n >= limit:
                    return


def explain_library_links(
    conn: sqlite3.Connection,
    lib_name: str,
    *,
    collection_slug: Optional[str] = None,
) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """
    Resolve *lib_name* as a DT_NEEDED string (e.g. ``libcm_server.so.0``).

    Returns ``(providers, consumers)`` where each item is ``(image_path, elf_path)``:

    - **providers**: ELFs whose **DT_SONAME** equals *lib_name* (the shared object that
      satisfies the NEEDED entry).
    - **consumers**: ELFs that list *lib_name* in **DT_NEEDED**.
    """
    coll_sql = ""
    coll_args: Tuple[Any, ...] = ()
    if collection_slug:
        coll_sql, coll_args = collection_image_filter_sql(collection_slug)

    cur = conn.execute(
        "SELECT i.path AS ip, s.path AS fp FROM elf_soname s "
        "JOIN images i ON s.image_id = i.id WHERE s.soname = ?" + coll_sql,
        (lib_name,) + coll_args,
    )
    providers = [(row["ip"], row["fp"]) for row in cur]

    cur = conn.execute(
        "SELECT i.path AS ip, n.path AS fp FROM elf_needed n "
        "JOIN images i ON n.image_id = i.id WHERE n.needed = ?" + coll_sql,
        (lib_name,) + coll_args,
    )
    consumers = [(row["ip"], row["fp"]) for row in cur]
    return providers, consumers


def duplicate_files(
    conn: sqlite3.Connection,
    *,
    collection_slug: Optional[str] = None,
    limit: int = 0,
) -> List[Dict[str, Any]]:
    coll_sql = ""
    coll_args: Tuple[Any, ...] = ()
    if collection_slug:
        coll_sql, coll_args = collection_image_filter_sql(
            collection_slug, leading_where=True
        )
    rows = conn.execute(
        "SELECT f.md5, f.size_bytes, COUNT(*) AS count "
        "FROM files f JOIN images i ON f.image_id = i.id"
        + coll_sql
        + " GROUP BY f.md5, f.size_bytes HAVING COUNT(*) > 1 "
        "ORDER BY count DESC, f.size_bytes DESC"
        + (" LIMIT ?" if limit else ""),
        coll_args + ((limit,) if limit else ()),
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for row in rows:
        blob = lookup_blob_by_md5(conn, str(row["md5"]))
        members = conn.execute(
            "SELECT i.path AS image, f.path, f.content_class FROM files f JOIN images i ON f.image_id = i.id "
            "WHERE f.md5 = ? ORDER BY i.path, f.path",
            (row["md5"],),
        ).fetchall()
        out.append(
            {
                "md5": row["md5"],
                "sha1": blob["sha1"] if blob is not None else None,
                "size_bytes": row["size_bytes"],
                "count": row["count"],
                "members": [dict(m) for m in members],
            }
        )
    return out


def file_info(conn: sqlite3.Connection, term: str, *, limit: int = 50) -> List[Dict[str, Any]]:
    like = f"%{term}%"
    rows = conn.execute(
        "SELECT f.*, i.path AS image, cb.sha1 AS content_sha1 "
        "FROM files f JOIN images i ON f.image_id = i.id "
        "LEFT JOIN content_blobs cb ON cb.md5 = f.md5 "
        "WHERE f.md5 = ? OR cb.sha1 = ? OR f.path LIKE ? ORDER BY f.size_bytes DESC LIMIT ?",
        (term.lower(), term.lower(), like, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def is_pkgstream_tlv_file_hit(image_path: str, file_path: str) -> bool:
    return ":tlv_file:" in image_path.replace("\\", "/")


def is_squashfs_rootfs_hit(image_path: str, file_path: str) -> bool:
    ip = image_path.replace("\\", "/")
    if ":tlv_script:" in ip or ":tlv_file:" in ip:
        return False
    return ":squashfs:" in ip or ":squash_embedded:" in ip


def is_uimage_artifact_hit(image_path: str, file_path: str) -> bool:
    ip = image_path.replace("\\", "/")
    return ":uimage:" in ip or file_path.endswith("uImage") or "/uImage" in normalize_index_path(file_path)


def image_matches_find_kind(image_path: str, file_path: str, kind: str) -> bool:
    if kind == "tlv_script":
        return is_pkgstream_script_tlv_hit(image_path, file_path)
    if kind == "tlv_file":
        return is_pkgstream_tlv_file_hit(image_path, file_path)
    if kind == "squashfs":
        return is_squashfs_rootfs_hit(image_path, file_path)
    if kind == "uimage":
        return is_uimage_artifact_hit(image_path, file_path)
    if kind in ("carrier_meta", "carrier_metadata"):
        return is_carrier_metadata_image_key(image_path) or is_carrier_metadata_virtual_path(file_path)
    return True


def find_files(
    conn: sqlite3.Connection,
    path_globs: Sequence[str],
    *,
    kinds: Optional[Sequence[str]] = None,
    collection_slug: Optional[str] = None,
    limit: int = 0,
    completed_only: bool = False,
) -> Iterator[Dict[str, Any]]:
    """
    Enumerate indexed files whose *files.path* matches any glob in *path_globs*.

    Globs use ``fnmatch`` semantics and match against normalized POSIX-style paths
    (``\\`` → ``/``).  When *kinds* is set, only rows whose image key matches
    :func:`image_matches_find_kind` are returned (``tlv_script``, ``tlv_file``,
    ``squashfs``, ``uimage``).  Use ``carrier_meta`` alone to list
    ``carrier_metadata`` JSON rows (virtual ``@carrier/…`` paths).

    Either *path_globs* or *kinds* must be non-empty.  Kind-only finds default
    the path glob to ``*``.
    """
    import fnmatch

    kind_set = [k for k in (kinds or []) if k]
    globs = [g.replace("\\", "/") for g in (path_globs or []) if g]
    if not globs and kind_set:
        globs = ["*"]
    if not globs and not kind_set:
        raise ValueError("find_files requires at least one path glob or --kind")

    want_carrier = any(k in ("carrier_meta", "carrier_metadata") for k in kind_set)
    file_kinds = [k for k in kind_set if k not in ("carrier_meta", "carrier_metadata")]

    coll_sql, coll_args = compose_image_filters(
        collection_slug=collection_slug,
        completed_only=completed_only,
        leading_where=True,
    )

    n = 0

    if want_carrier:
        cur = conn.execute(
            "SELECT i.path AS image_path, c.kind AS carrier_kind, c.md5, c.size_bytes "
            "FROM carrier_metadata c JOIN images i ON c.image_id = i.id"
            + coll_sql
            + " ORDER BY i.path, c.kind",
            coll_args,
        )
        for row in cur:
            ck = str(row["carrier_kind"])
            fp = carrier_metadata_virtual_path(ck)
            yield {
                "image_path": row["image_path"],
                "file_path": fp,
                "md5": row["md5"],
                "size_bytes": row["size_bytes"],
                "content_class": "carrier_metadata",
                "artifact_kind": "carrier_meta",
            }
            n += 1
            if limit and n >= limit:
                return

    cur = conn.execute(
        "SELECT i.path AS image_path, f.path AS file_path, f.md5, cb.sha1, f.size_bytes, f.content_class "
        "FROM files f JOIN images i ON f.image_id = i.id "
        "LEFT JOIN content_blobs cb ON cb.md5 = f.md5"
        + coll_sql
        + " ORDER BY i.path, f.path",
        coll_args,
    )

    for row in cur:
        fp = str(row["file_path"] or "").replace("\\", "/")
        ip = str(row["image_path"] or "")
        if is_carrier_metadata_filename(fp):
            continue
        if file_kinds and not any(image_matches_find_kind(ip, fp, k) for k in file_kinds):
            continue
        if not any(fnmatch.fnmatch(fp, g) for g in globs):
            continue
        artifact_kind = None
        for k in file_kinds or FIND_KIND_CHOICES:
            if image_matches_find_kind(ip, fp, k):
                artifact_kind = k
                break
        yield {
            "image_path": row["image_path"],
            "file_path": row["file_path"],
            "md5": row["md5"],
            "sha1": row["sha1"],
            "size_bytes": row["size_bytes"],
            "content_class": row["content_class"],
            "artifact_kind": artifact_kind,
        }
        n += 1
        if limit and n >= limit:
            return


def normalize_index_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("/")


def is_pkgstream_script_tlv_path(rel_path: str) -> bool:
    """``lib2spy`` SCRIPT TLV virtual paths under ``_scripts/script_*`` (``.sh``; legacy ``.bin``)."""
    p = normalize_index_path(rel_path)
    if not p.startswith("_scripts/script_"):
        return False
    return p.endswith(".sh") or p.endswith(".bin")


def is_pkgstream_script_tlv_hit(image_path: str, file_path: str) -> bool:
    ip = image_path.replace("\\", "/")
    fp = normalize_index_path(file_path)
    return ":tlv_script:" in ip or is_pkgstream_script_tlv_path(fp)


def is_pkgstream_tlv_file_hit(image_path: str, file_path: str) -> bool:
    return ":tlv_file:" in image_path.replace("\\", "/")


def _expand_search_kinds(kinds: frozenset[str]) -> frozenset[str]:
    """Map CLI kind aliases (``tlv_script``, ``carrier_metadata``) to index tables."""
    expanded = set(kinds)
    if "tlv_script" in kinds or "tlv_file" in kinds:
        expanded.update({"text", "strings"})
    if "carrier_metadata" in kinds:
        expanded.add("carrier_meta")
    return frozenset(expanded)


def carrier_metadata_virtual_path(kind: str) -> str:
    return f"@carrier/{kind}"


def is_carrier_metadata_filename(path: str) -> bool:
    return Path(path.replace("\\", "/")).name in CARRIER_METADATA_FILENAMES


def is_carrier_metadata_image_key(image_path: str) -> bool:
    norm = image_path.replace("\\", "/")
    return any(norm.endswith(f"/{name}") or norm.endswith(name) for name in CARRIER_METADATA_FILENAMES)


def is_carrier_metadata_virtual_path(path: str) -> bool:
    return normalize_index_path(path).startswith("@carrier/")


def firmware_version_sort_key(version: str) -> Tuple[int, ...]:
    """Sort key for dotted firmware version strings (e.g. ``10.5.3.527157``)."""
    parts: List[int] = []
    for seg in version.split("."):
        try:
            parts.append(int(seg))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def resolve_image_collection_context(
    conn: sqlite3.Connection,
    image_path: str,
) -> Dict[str, Optional[str]]:
    """
    Resolve collection slug and firmware/component metadata for one indexed image key.
    """
    from corpus.ref import legacy_version_scope_from_image_path, scope_from_image_path

    scope = scope_from_image_path(image_path)
    slug: Optional[str] = scope
    firmware_version: Optional[str] = None
    component_version: Optional[str] = None
    channel: Optional[str] = None

    if scope and scope.startswith("version:"):
        firmware_version = scope.split(":", 1)[1]
    elif scope:
        meta = get_collection_metadata(conn, scope)
        if meta:
            slug = str(meta.get("slug") or scope)
            firmware_version = meta.get("firmware_version")
            component_version = meta.get("component_version")
            channel = meta.get("channel")
        if not firmware_version:
            vers = firmware_versions_from_path(scope)
            if vers:
                firmware_version = vers[-1]
    if not firmware_version:
        leg = legacy_version_scope_from_image_path(image_path)
        if leg:
            slug = slug or leg
            if leg.startswith("version:"):
                firmware_version = leg.split(":", 1)[1]
    if not firmware_version:
        vers = firmware_versions_from_path(image_path)
        if vers:
            firmware_version = vers[-1]

    return {
        "collection_slug": slug,
        "firmware_version": firmware_version,
        "component_version": component_version,
        "channel": channel,
    }


def _preview_text_line(
    conn: sqlite3.Connection,
    image_id: int,
    file_path: str,
) -> Optional[str]:
    row = conn.execute(
        "SELECT t.text FROM blob_text_lines t "
        "JOIN files f ON f.md5 = t.content_md5 "
        "WHERE f.image_id = ? AND f.path = ? ORDER BY t.line_no LIMIT 1",
        (image_id, file_path),
    ).fetchone()
    if row is None:
        return None
    return str(row["text"] or "").rstrip("\n")


def file_path_history(
    conn: sqlite3.Connection,
    path: str,
    *,
    collection_slug: Optional[str] = None,
    path_glob: bool = False,
    limit: int = 0,
    preview: bool = False,
) -> List[Dict[str, Any]]:
    """
    Group indexed copies of *path* by content hash and summarize firmware/collection coverage.

    Memberships are deduped by ``(md5, firmware_version)`` so duplicate index or grep
    rows for the same release do not inflate counts.
    """
    import fnmatch

    path_norm = normalize_index_path(path)
    use_glob = path_glob or ("*" in path_norm) or ("?" in path_norm)

    coll_sql = ""
    coll_args: Tuple[Any, ...] = ()
    if collection_slug:
        coll_sql, coll_args = collection_image_filter_sql(collection_slug, leading_where=True)

    rows = conn.execute(
        "SELECT f.id AS file_id, f.image_id, f.path AS file_path, f.md5, f.size_bytes, "
        "f.content_class, i.path AS image_path, cb.sha1 AS content_sha1 "
        "FROM files f JOIN images i ON f.image_id = i.id "
        "LEFT JOIN content_blobs cb ON cb.md5 = f.md5"
        + coll_sql
        + " ORDER BY f.md5, i.path",
        coll_args,
    ).fetchall()

    groups: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        fp = normalize_index_path(str(row["file_path"] or ""))
        if is_carrier_metadata_filename(fp):
            continue
        if use_glob:
            if not fnmatch.fnmatch(fp, path_norm):
                continue
        elif fp != path_norm:
            continue

        md5 = str(row["md5"])
        ctx = resolve_image_collection_context(conn, str(row["image_path"]))
        fw = ctx.get("firmware_version") or "unknown"

        if md5 not in groups:
            groups[md5] = {
                "query": path_norm,
                "path_glob": use_glob,
                "md5": md5,
                "sha1": row["content_sha1"],
                "size_bytes": int(row["size_bytes"]),
                "content_class": str(row["content_class"] or ""),
                "matched_paths": set(),
                "image_ids": set(),
                "seen_fw": set(),
                "firmware_versions": [],
                "collections": {},
                "preview": None,
                "_preview_image_id": None,
            }
        g = groups[md5]
        g["matched_paths"].add(fp)
        g["image_ids"].add(int(row["image_id"]))
        if fw in g["seen_fw"]:
            continue
        g["seen_fw"].add(fw)
        g["firmware_versions"].append(fw)
        slug = ctx.get("collection_slug")
        if slug and slug not in g["collections"]:
            g["collections"][slug] = {
                "slug": slug,
                "firmware_version": ctx.get("firmware_version"),
                "component_version": ctx.get("component_version"),
                "channel": ctx.get("channel"),
            }
        if preview and g["preview"] is None:
            g["_preview_image_id"] = int(row["image_id"])
            g["_preview_file_path"] = fp

    out: List[Dict[str, Any]] = []
    for md5, g in groups.items():
        fw_sorted = sorted(g["firmware_versions"], key=firmware_version_sort_key)
        if preview and g.get("_preview_image_id") is not None:
            g["preview"] = _preview_text_line(
                conn,
                int(g["_preview_image_id"]),
                str(g.get("_preview_file_path") or path_norm),
            )
        coll_list = sorted(g["collections"].values(), key=lambda c: str(c.get("slug") or ""))
        paths_sorted = sorted(g["matched_paths"])
        payload: Dict[str, Any] = {
            "query": g["query"],
            "path_glob": g["path_glob"],
            "path": paths_sorted[0] if len(paths_sorted) == 1 else g["query"],
            "paths": paths_sorted,
            "md5": md5,
            "sha1": g.get("sha1"),
            "size_bytes": g["size_bytes"],
            "content_class": g["content_class"],
            "image_count": len(g["image_ids"]),
            "firmware_versions": fw_sorted,
            "firmware_version_count": len(fw_sorted),
            "firmware_min": fw_sorted[0] if fw_sorted else None,
            "firmware_max": fw_sorted[-1] if fw_sorted else None,
            "collection_count": len(coll_list),
            "collections": coll_list,
        }
        if preview:
            payload["preview"] = g.get("preview")
        out.append(payload)

    out.sort(
        key=lambda r: (
            firmware_version_sort_key(str(r["firmware_max"] or "")),
            str(r["md5"]),
        ),
        reverse=True,
    )
    if limit and limit > 0:
        out = out[:limit]
    return out


def version_rows(conn: sqlite3.Connection, *, limit: int = 200) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT i.path AS image, v.path, v.source, v.key, v.value, v.confidence, v.evidence "
        "FROM file_versions v JOIN images i ON v.image_id = i.id "
        "ORDER BY v.confidence DESC, v.value LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def dependency_rows(conn: sqlite3.Connection, term: str, *, limit: int = 200) -> List[Dict[str, Any]]:
    like = f"%{term}%"
    rows = conn.execute(
        "SELECT i.path AS image, e.consumer_path, e.needed, e.provider_path, e.provider_soname, e.resolution "
        "FROM elf_library_edges e JOIN images i ON e.image_id = i.id "
        "WHERE e.needed LIKE ? OR e.consumer_path LIKE ? OR COALESCE(e.provider_path, '') LIKE ? "
        "ORDER BY e.resolution, e.needed LIMIT ?",
        (like, like, like, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def format_summary(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT content_class, COALESCE(machine, '') AS machine, COALESCE(elf_type, '') AS elf_type, "
        "COUNT(*) AS count FROM binary_formats GROUP BY content_class, machine, elf_type "
        "ORDER BY count DESC, content_class"
    ).fetchall()
    return [dict(row) for row in rows]


def dwarf_rows(conn: sqlite3.Connection, term: str, *, limit: int = 200) -> List[Dict[str, Any]]:
    like = f"%{term}%"
    rows = conn.execute(
        "SELECT 'function' AS kind, i.path AS image, d.path, d.name, d.low_pc, d.high_pc "
        "FROM dwarf_functions d JOIN images i ON d.image_id = i.id "
        "WHERE d.path LIKE ? OR d.name LIKE ? "
        "UNION ALL "
        "SELECT 'type' AS kind, i.path AS image, t.path, t.name, NULL AS low_pc, NULL AS high_pc "
        "FROM dwarf_types t JOIN images i ON t.image_id = i.id "
        "WHERE t.path LIKE ? OR t.name LIKE ? "
        "LIMIT ?",
        (like, like, like, like, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def child_edges(conn: sqlite3.Connection, term: str, *, limit: int = 200) -> List[Dict[str, Any]]:
    like = f"%{term}%"
    rows = conn.execute(
        "SELECT parent_image_path, parent_path, child_image_path, child_path, relationship, metadata_json "
        "FROM artifact_edges WHERE parent_image_path LIKE ? OR child_image_path LIKE ? "
        "OR COALESCE(parent_path, '') LIKE ? OR COALESCE(child_path, '') LIKE ? "
        "ORDER BY parent_image_path, child_image_path LIMIT ?",
        (like, like, like, like, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def guess_squashfs_files(paths: Sequence[str]) -> List[Path]:
    """Expand explicit paths; treat directories as recursive *.squashfs + legacy carve names."""
    from glob import glob as glob_fn

    out: List[Path] = []
    for raw in paths:
        expanded = Path(raw).expanduser()
        if expanded.is_file():
            out.append(expanded.resolve())
            continue
        if expanded.is_dir():
            out.extend(sorted(expanded.rglob("*.squashfs")))
            out.extend(sorted(expanded.rglob("*.sqsh")))
            out.extend(sorted(expanded.rglob("*_squashfs_*.bin")))
            continue
        matches = glob_fn(str(expanded))
        if matches:
            for g in matches:
                gp = Path(g)
                if gp.is_file():
                    out.append(gp.resolve())
    # dedupe preserve order
    seen: set[str] = set()
    uniq: List[Path] = []
    for x in out:
        k = str(x.resolve())
        if k not in seen:
            seen.add(k)
            uniq.append(x)
    return uniq
