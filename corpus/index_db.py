"""
SQLite index for SquashFS images (via dissect) or **already-extracted** rootfs trees:
text lines, ELF symbols, ELF section strings, plus **DT_SONAME** / **DT_NEEDED** from
``.dynamic`` for linker-resolution queries.

Used by ``python -m corpus`` with ``--db`` / ``--build-index``.
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

# Repo root (.../5268ac) so sibling packages import when PYTHONPATH is unset.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpus.vmlinux_elf import try_vmlinux_to_elf

# Sections scanned for printable strings (loaded segments only).
ELF_STRING_SECTIONS = frozenset({".rodata", ".data", ".dynstr", ".comment"})
DEFAULT_MAX_STRINGS_PER_FILE = 2000
ANALYSIS_VERSION = "corpus-index-v2"

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


def normalize_collection_slug(slug: str) -> str:
    """
    Normalize a release / firmware-tree label for ``collection:…`` image keys.

    Example: ``firmware_11.5.1.532678/11.5.1.532678`` (slashes OK inside the slug).
    """
    s = slug.strip().replace("\\", "/")
    while "//" in s:
        s = s.replace("//", "/")
    s = s.strip("/")
    return s or "default"


def collection_image_prefix(collection_slug: str) -> str:
    """Prefix for ``images.path`` rows belonging to a collection."""
    return f"collection:{normalize_collection_slug(collection_slug)}:"


def collection_slug_for_fs(slug: str) -> str:
    """Filesystem-safe directory segment derived from a collection slug."""
    n = normalize_collection_slug(slug)
    return n.replace("/", "__").replace("\\", "__").replace(":", "_")


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
    version: str
    version_source: str
    internal_candidates: List[Tuple[str, int]]

    def to_json(self) -> Dict[str, Any]:
        return {
            "path": str(self.path),
            "relative_path": self.relative_path,
            "collection": self.collection_slug,
            "version": self.version,
            "version_source": self.version_source,
            "internal_candidates": self.internal_candidates,
        }


def classify_pkgstream_collection(
    pkgstream_path: Path,
    *,
    root: Optional[Path] = None,
    collection_prefix: str = "version:",
    unknown_version: str = "unknown",
) -> PkgstreamCollectionPlan:
    """
    Classify one pkgstream into a collection by version information.

    Policy:
    1. Prefer firmware-looking versions found inside the pkgstream bytes.
    2. Fall back to the version in the relative path so config/cert carriers share
       their install carrier's release collection.
    3. Use ``version:unknown`` when neither source has a version.
    """
    pkg = Path(pkgstream_path).resolve()
    base = Path(root).resolve() if root is not None else pkg.parent
    try:
        rel = pkg.relative_to(base).as_posix()
    except ValueError:
        rel = pkg.name

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
        collection_slug=f"{collection_prefix}{version}",
        version=version,
        version_source=source,
        internal_candidates=internal[:8],
    )


def iter_pkgstreams_under(root: Path) -> Iterator[Path]:
    """Yield all ``*.pkgstream`` files under *root*, sorted by relative path."""
    root = Path(root).resolve()
    paths: List[Path] = []
    for dirpath, _dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        for name in filenames:
            if name.lower().endswith(".pkgstream"):
                paths.append(Path(dirpath) / name)
    paths.sort(key=lambda p: p.relative_to(root).as_posix().lower())
    yield from paths


def plan_pkgstream_collections(
    root: Path,
    *,
    collection_prefix: str = "version:",
    unknown_version: str = "unknown",
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
        for p in iter_pkgstreams_under(root)
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
                    version=bundle.version,
                    version_source=f"release-bundle:{bundle.version_source}",
                    internal_candidates=item.internal_candidates,
                )
            elif bundle.version != unknown_version and _is_pkgstream_sidecar(item.path) and item.path != bundle.path:
                item = PkgstreamCollectionPlan(
                    path=item.path,
                    relative_path=item.relative_path,
                    collection_slug=bundle.collection_slug,
                    version=bundle.version,
                    version_source=f"release-bundle:{bundle.version_source}",
                    internal_candidates=item.internal_candidates,
                )
            out.append(item)
    out.sort(key=lambda item: item.relative_path.lower())
    return out


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


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS images (
          id INTEGER PRIMARY KEY,
          path TEXT NOT NULL UNIQUE,
          sha256 TEXT NOT NULL,
          size_bytes INTEGER NOT NULL,
          file_count INTEGER NOT NULL DEFAULT 0,
          indexed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS text_lines (
          id INTEGER PRIMARY KEY,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          line_no INTEGER NOT NULL,
          text TEXT NOT NULL,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_text_lines_image ON text_lines(image_id);

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
          sha256 TEXT NOT NULL,
          content_class TEXT NOT NULL,
          suffix TEXT,
          indexed_at TEXT NOT NULL,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE,
          UNIQUE(image_id, path)
        );
        CREATE INDEX IF NOT EXISTS idx_files_image ON files(image_id);
        CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);
        CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);

        CREATE TABLE IF NOT EXISTS file_strings (
          id INTEGER PRIMARY KEY,
          file_id INTEGER NOT NULL,
          image_id INTEGER NOT NULL,
          path TEXT NOT NULL,
          offset INTEGER NOT NULL,
          encoding TEXT NOT NULL,
          source TEXT NOT NULL,
          text TEXT NOT NULL,
          length INTEGER NOT NULL,
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
          FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_file_strings_file ON file_strings(file_id);
        CREATE INDEX IF NOT EXISTS idx_file_strings_image ON file_strings(image_id);

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

        CREATE TABLE IF NOT EXISTS analysis_status (
          image_path TEXT NOT NULL,
          sha256 TEXT NOT NULL,
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
          ON analysis_status(image_path, sha256, analysis_version, options_hash, status);
        """
    )
    conn.commit()


def connect_db(path: str | Path) -> sqlite3.Connection:
    p = Path(path).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), isolation_level=None)
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    # FK enforcement (sqlite defaults off)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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
) -> str:
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


def _completed_analysis_row(
    conn: sqlite3.Connection,
    *,
    image_path: str,
    sha256: str,
    size_bytes: int,
    options_hash: str,
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM analysis_status "
        "WHERE image_path = ? AND sha256 = ? AND size_bytes = ? "
        "AND analysis_version = ? AND options_hash = ? AND status = 'completed'",
        (image_path, sha256, size_bytes, ANALYSIS_VERSION, options_hash),
    ).fetchone()


def _mark_analysis_started(
    conn: sqlite3.Connection,
    *,
    image_path: str,
    sha256: str,
    size_bytes: int,
    options_hash: str,
) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO analysis_status("
        "image_path, sha256, size_bytes, analysis_version, options_hash, status, started_at, completed_at, metrics_json, error"
        ") VALUES (?,?,?,?,?,?,?,?,?,?)",
        (image_path, sha256, size_bytes, ANALYSIS_VERSION, options_hash, "running", _utc_now(), None, None, None),
    )
    conn.commit()


def _mark_analysis_completed(
    conn: sqlite3.Connection,
    *,
    image_path: str,
    sha256: str,
    size_bytes: int,
    options_hash: str,
    metrics: dict[str, Any],
) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO analysis_status("
        "image_path, sha256, size_bytes, analysis_version, options_hash, status, started_at, completed_at, metrics_json, error"
        ") VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            image_path,
            sha256,
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
    content_class: Optional[str] = None,
) -> int:
    """Insert one file identity row and return its row id."""
    cls = content_class or content_class_for(rel_path, data)
    cur = conn.execute(
        "INSERT OR REPLACE INTO files(image_id, path, size_bytes, sha256, content_class, suffix, indexed_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (
            image_id,
            rel_path,
            len(data),
            hashlib.sha256(data).hexdigest(),
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


def index_file_strings(
    conn: sqlite3.Connection,
    file_id: int,
    image_id: int,
    rel_path: str,
    data: bytes,
    *,
    min_string_len: int,
    max_strings_per_file: int,
) -> int:
    """Index bounded printable strings from any file payload."""
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
                "INSERT INTO file_strings(file_id, image_id, path, offset, encoding, source, text, length) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    file_id,
                    image_id,
                    rel_path,
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
        "file_id, image_id, path, content_class, magic_hex, suffix, elf_class, endian, machine, abi, "
        "elf_type, entry_point, interpreter, build_id, section_count, segment_count, stripped, has_debug"
        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            file_id,
            image_id,
            rel_path,
            content_class,
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


def index_text_lines(
    conn: sqlite3.Connection,
    image_id: int,
    rel_path: str,
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
            "INSERT INTO text_lines(image_id, path, line_no, text) VALUES (?,?,?,?)",
            (image_id, rel_path, line_no, line),
        )
        n += 1
    return n


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
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, int]:
    """Return counters text_lines, elf_sym, elf_str, elf_soname, elf_needed."""
    counts = {
        "files": 0,
        "file_strings": 0,
        "file_versions": 0,
        "binary_formats": 0,
        "text_lines": 0,
        "elf_sym": 0,
        "elf_str": 0,
        "elf_soname": 0,
        "elf_needed": 0,
        "dwarf_units": 0,
        "dwarf_entries": 0,
    }
    if len(data) > max_file_bytes:
        return counts
    suf = Path(rel_path).suffix.lower()
    cls = content_class_for(rel_path, data)
    file_id = insert_file_row(conn, image_id, rel_path, data, content_class=cls)
    counts["files"] = 1
    counts["file_strings"] += index_file_strings(
        conn,
        file_id,
        image_id,
        rel_path,
        data,
        min_string_len=min_string_len,
        max_strings_per_file=max_strings_per_file,
    )
    counts["file_versions"] += index_version_evidence(conn, file_id, image_id, rel_path, data)

    # ELF first (includes .so, .ko, extensionless, and ``.bin`` carves that are ELFs).
    if data[:4] == ELF_MAGIC:
        es, estr, sns, nds, nfmt, nver, ndu, ndwarf = index_elf_payload(
            conn,
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
        counts["elf_sym"] += es
        counts["elf_str"] += estr
        counts["elf_soname"] += sns
        counts["elf_needed"] += nds
        counts["binary_formats"] += nfmt
        counts["file_versions"] += nver
        counts["dwarf_units"] += ndu
        counts["dwarf_entries"] += ndwarf
        return counts

    counts["binary_formats"] += index_binary_format(
        conn,
        file_id,
        image_id,
        rel_path,
        data,
        content_class=cls,
    )

    if skip_suffixes and suf in SKIP_SUFFIXES:
        return counts
    if is_probably_binary(data):
        return counts
    counts["text_lines"] += index_text_lines(conn, image_id, rel_path, data)
    return counts


def _rows_as_dicts(conn: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(f"SELECT * FROM {table}")]


def _analyze_file_worker(args: tuple[str, bytes, int, bool, bool, tuple[str, ...], int, int, bool]) -> dict[str, Any]:
    """Analyze one file payload in a private in-memory DB for parent-side insertion."""
    rel_path, data, max_file_bytes, skip_suffixes, symtab, string_sections_raw, min_string_len, max_strings_per_file, dwarf = args
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
        progress=None,
    )
    conn.commit()
    rows = {
        table: _rows_as_dicts(conn, table)
        for table in (
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
    }
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
    return dict(result["counts"])


def _add_counts(target: dict[str, int], counts: dict[str, int]) -> None:
    for k, v in counts.items():
        if k in target:
            target[k] += int(v)


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

    sha = file_sha256(src)
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
    )
    completed = _completed_analysis_row(
        conn,
        image_path=ipath,
        sha256=sha,
        size_bytes=size_b,
        options_hash=options_hash,
    )
    if completed is not None:
        metrics = json.loads(completed["metrics_json"] or "{}")
        if progress:
            progress(
                f"# squashfs index skip completed {ipath} "
                f"analysis={ANALYSIS_VERSION} options={options_hash[:12]} files={metrics.get('files_seen')}"
            )
        return {
            "ok": True,
            "skipped": True,
            "reason": "analysis_completed",
            "analysis_version": ANALYSIS_VERSION,
            "options_hash": options_hash,
            "path": ipath,
            **metrics,
        }

    delete_image_by_path(conn, ipath)
    _mark_analysis_started(
        conn,
        image_path=ipath,
        sha256=sha,
        size_bytes=size_b,
        options_hash=options_hash,
    )
    cur = conn.execute(
        "INSERT INTO images(path, sha256, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?)",
        (ipath, sha, size_b, 0, _utc_now()),
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
    }

    def log(msg: str) -> None:
        if progress:
            progress(msg)

    started = time.monotonic()
    last_progress = started
    worker_jobs = max(1, int(jobs or 1))
    log(f"# squashfs index start {ipath} size={size_b}B jobs={worker_jobs}")

    def report(now: Optional[float] = None, *, pending: int = 0) -> None:
        nonlocal last_progress
        now = time.monotonic() if now is None else now
        if progress and (totals["files_seen"] % 100 == 0 or now - last_progress >= 10):
            last_progress = now
            log(
                f"# squashfs index progress {ipath} files={totals['files_seen']} "
                f"lines={totals['text_lines']} elf_sym={totals['elf_sym']} pending_elves={pending} "
                f"elapsed={_format_duration(now - started)}"
            )

    def finish_future(fut: Any) -> None:
        result = fut.result()
        c = _insert_worker_file_result(conn, image_id, result)
        _add_counts(totals, c)
        if progress:
            log(
                f"# elf worker done {result['path']} symbols={c.get('elf_sym', 0)} "
                f"strings={c.get('elf_str', 0)} elapsed={_format_duration(time.monotonic() - started)}"
            )

    conn.execute("BEGIN")
    try:
        if worker_jobs > 1:
            pending: set[Any] = set()
            with ProcessPoolExecutor(max_workers=worker_jobs) as pool:
                for rel, data in iter_squashfs_files(src):
                    totals["files_seen"] += 1
                    if len(data) <= max_file_bytes and data[:4] == ELF_MAGIC:
                        if progress:
                            log(f"# elf worker submit {rel} size={len(data)}B")
                        pending.add(
                            pool.submit(
                                _analyze_file_worker,
                                (
                                    rel,
                                    data,
                                    max_file_bytes,
                                    skip_suffixes,
                                    symtab,
                                    tuple(sorted(sections)),
                                    min_string_len,
                                    max_strings_per_file,
                                    dwarf,
                                ),
                            )
                        )
                        while len(pending) >= worker_jobs * 4:
                            done, pending = wait(pending, timeout=10, return_when=FIRST_COMPLETED)
                            for fut in done:
                                finish_future(fut)
                            report(pending=len(pending))
                        report(pending=len(pending))
                        continue
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
                        progress=progress,
                    )
                    _add_counts(totals, c)
                    report(pending=len(pending))
                while pending:
                    done, pending = wait(pending, timeout=10, return_when=FIRST_COMPLETED)
                    for fut in done:
                        finish_future(fut)
                    report(pending=len(pending))
        else:
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
                    progress=progress,
                )
                _add_counts(totals, c)
                report()

        conn.execute(
            "UPDATE images SET file_count = ? WHERE id = ?", (totals["files_seen"], image_id)
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    resolve_elf_library_edges(conn, image_id=image_id)
    log(
        f"indexed image id={image_id} files={totals['files_seen']} "
        f"lines={totals['text_lines']} elf_sym={totals['elf_sym']} elf_str={totals['elf_str']} "
        f"elapsed={_format_duration(time.monotonic() - started)}"
    )
    result = {"ok": True, "image_id": image_id, **totals, "path": ipath}
    _mark_analysis_completed(
        conn,
        image_path=ipath,
        sha256=sha,
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
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Index one in-memory SquashFS image, reading files via ``dissect.squashfs``."""
    from lib2spy.pkgstream_corpus import iter_squashfs_files_from_bytes

    sections = string_sections if string_sections is not None else ELF_STRING_SECTIONS
    delete_image_by_path(conn, image_key)
    sha = hashlib.sha256(data).hexdigest()
    cur = conn.execute(
        "INSERT INTO images(path, sha256, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?)",
        (image_key, sha, len(data), 0, _utc_now()),
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
    }
    started = time.monotonic()
    last_progress = started
    if progress:
        progress(f"# squashfs bytes index start {image_key} size={len(data)}B")
    conn.execute("BEGIN")
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
                progress=progress,
            )
            for k in ("text_lines", "elf_sym", "elf_str", "file_strings", "file_versions", "binary_formats", "dwarf_units"):
                totals[k] += c[k]
            now = time.monotonic()
            if progress and (totals["files_seen"] % 100 == 0 or now - last_progress >= 10):
                last_progress = now
                progress(
                    f"# squashfs bytes progress {image_key} files={totals['files_seen']} "
                    f"lines={totals['text_lines']} elf_sym={totals['elf_sym']} "
                    f"elapsed={_format_duration(now - started)}"
                )
        conn.execute("UPDATE images SET file_count = ? WHERE id = ?", (totals["files_seen"], image_id))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    resolve_elf_library_edges(conn, image_id=image_id)
    if progress:
        progress(
            f"indexed squashfs artifact id={image_id} files={totals['files_seen']} "
            f"lines={totals['text_lines']} elf_sym={totals['elf_sym']} elf_str={totals['elf_str']} "
            f"elapsed={_format_duration(time.monotonic() - started)}"
        )
    return {"ok": True, "image_id": image_id, **totals, "path": image_key}


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
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    One ``images`` row and a single virtual path (e.g. ``vmlinux.elf``) for **raw bytes**.
    """
    sections = string_sections if string_sections is not None else ELF_STRING_SECTIONS
    eff_max = 10**15 if max_file_bytes <= 0 else max_file_bytes
    if len(data) > eff_max:
        return {"ok": False, "error": f"blob {len(data)} B exceeds --max-file-mb limit"}

    delete_image_by_path(conn, image_key)
    sha = hashlib.sha256(data).hexdigest()
    cur = conn.execute(
        "INSERT INTO images(path, sha256, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?)",
        (image_key, sha, len(data), 0, _utc_now()),
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
        progress=progress,
    )
    conn.execute("UPDATE images SET file_count = ? WHERE id = ?", (1, image_id))
    conn.commit()
    resolve_elf_library_edges(conn, image_id=image_id)
    if progress:
        progress(
            f"indexed {image_key} ::{rel_path} lines={c['text_lines']} "
            f"elf_sym={c['elf_sym']} elf_str={c['elf_str']}"
        )
    return {"ok": True, "image_id": image_id, "path": image_key, **c}


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
    sha = hashlib.sha256(ipath.encode("utf-8")).hexdigest()

    delete_image_by_path(conn, ipath)
    cur = conn.execute(
        "INSERT INTO images(path, sha256, size_bytes, file_count, indexed_at) VALUES (?,?,?,?,?)",
        (ipath, sha, 0, 0, _utc_now()),
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
            progress=progress,
        )
        for k in ("text_lines", "elf_sym", "elf_str", "file_strings", "file_versions", "binary_formats", "dwarf_units"):
            totals[k] += c[k]

    conn.execute(
        "UPDATE images SET file_count = ? WHERE id = ?", (totals["files_seen"], image_id)
    )
    conn.commit()
    resolve_elf_library_edges(conn, image_id=image_id)
    log(
        f"indexed extracted tree id={image_id} root={root} files={totals['files_seen']} "
        f"lines={totals['text_lines']} elf_sym={totals['elf_sym']} elf_str={totals['elf_str']}"
    )
    return {"ok": True, "image_id": image_id, **totals, "path": ipath}


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
    Carve uImage, peel kernel member (:func:`uboot.uimage.extract_kernel_blob` + gzip),
    run **vmlinux-to-elf** when available, index the resulting ELF (or fallback: inner ``.bin``).
    """
    _ensure_repo_on_path()
    try:
        from uboot.uimage import extract_kernel_blob, gunzip_if_gzip
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
        _h, member_raw = extract_kernel_blob(uimg_full, member_index=0)
        inner, did_gunzip = gunzip_if_gzip(member_raw)
        kbin = carved_dir / f"{stem}_kernel_inner.bin"
        kbin.write_bytes(inner)
        out["kernel_inner"] = str(kbin)
        out["gunzip_inner"] = did_gunzip
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
    from uboot.uimage import extract_kernel_blob, gunzip_if_gzip

    out: Dict[str, Any] = {"kind": "uimage", "path": image_key}
    with tempfile.TemporaryDirectory() as td:
        sidecars = Path(sidecar_dir) if sidecar_dir is not None else Path(td)
        sidecars.mkdir(parents=True, exist_ok=True)
        kbin = sidecars / "kernel_inner.bin"
        try:
            _h, member_raw = extract_kernel_blob(data, member_index=0)
            inner, did_gunzip = gunzip_if_gzip(member_raw)
            _write_bytes_if_needed(kbin, inner)
            out["kernel_inner"] = _display_path(kbin, base=display_base)
            out["gunzip_inner"] = did_gunzip
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
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Index one artifact yielded by ``lib2spy`` or ``paceflash`` public APIs."""
    kind = str(getattr(artifact, "kind"))
    logical_path = str(getattr(artifact, "logical_path"))
    metadata = dict(getattr(artifact, "metadata", {}) or {})
    data = artifact.read_bytes() if hasattr(artifact, "read_bytes") else bytes(getattr(artifact, "data"))
    artifact_path, materialize_status = _materialize_artifact_payload(artifact, work_root, data)
    image_key = (
        _display_path(artifact_path, base=display_base)
        if artifact_path is not None
        else str(getattr(artifact, "source_key"))
    )
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
                progress=progress,
            )
        result["artifact_path"] = image_key
        result["materialized"] = materialize_status
        record_artifact_edge(conn, image_key, logical_path, metadata)
        if sbom_dir is not None:
            from corpus.sbom import (
                materialize_files,
                run_syft,
                run_syft_from_squashfs_mount,
                safe_sbom_name,
            )
            from lib2spy.pkgstream_corpus import iter_squashfs_files, iter_squashfs_files_from_bytes

            mode = sbom_source if sbom_source in {"auto", "mount", "materialize"} else "auto"
            tree_dir = Path(sbom_dir) / "sources" / safe_sbom_name(image_key, suffix="")
            sbom_path = Path(sbom_dir) / safe_sbom_name(image_key)
            mount_sbom_path = Path(sbom_dir) / "mounted" / safe_sbom_name(image_key)
            mount_root = (
                Path(sbom_mount_root)
                if sbom_mount_root is not None
                else Path(sbom_dir) / "mounts"
            )
            try:
                sbom_result: Dict[str, Any]
                mount_error: Optional[str] = None
                if mode in {"auto", "mount"} and artifact_path is not None:
                    if progress:
                        progress(
                            f"# syft mount start {image_key} -> "
                            f"{_display_path(mount_sbom_path, base=display_base)}"
                        )
                    syft_started = time.monotonic()
                    sbom_result = run_syft_from_squashfs_mount(
                        artifact_path,
                        mount_sbom_path,
                        mount_root=mount_root,
                        syft_bin=syft_bin,
                        output_format=sbom_format,
                    )
                    if sbom_result.get("ok") or mode == "mount":
                        if progress:
                            cache = " cached" if sbom_result.get("cached") else ""
                            progress(
                                f"# syft mount run done{cache} {image_key} "
                                f"elapsed={_format_duration(time.monotonic() - syft_started)}"
                            )
                    else:
                        mount_error = str(sbom_result.get("error") or "mount unavailable")
                        if progress:
                            progress(f"# syft mount unavailable {image_key}: {mount_error}")
                elif mode == "mount":
                    sbom_result = {
                        "ok": False,
                        "error": "squashfs mount requires a materialized image path",
                        "source_mode": "mount",
                    }
                else:
                    sbom_result = {"ok": False, "error": "materialize fallback pending"}

                if not sbom_result.get("ok") and mode != "mount":
                    if progress:
                        progress(f"# syft materialize start {image_key} -> {_display_path(tree_dir, base=display_base)}")
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
                        progress(f"# syft run start {image_key} -> {_display_path(sbom_path, base=display_base)}")
                    syft_started = time.monotonic()
                    sbom_result = run_syft(
                        tree_dir,
                        sbom_path,
                        syft_bin=syft_bin,
                        output_format=sbom_format,
                        source_type="materialized-dir",
                    )
                    if progress:
                        cache = " cached" if sbom_result.get("cached") else ""
                        progress(
                            f"# syft run done{cache} {image_key} "
                            f"elapsed={_format_duration(time.monotonic() - syft_started)}"
                        )
                    sbom_result["materialized"] = materialized
                    sbom_result["source_mode"] = "materialize"
                    if mount_error:
                        sbom_result["mount_error"] = mount_error
            except Exception as e:
                sbom_result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            result["sbom"] = sbom_result
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
            progress(f"# artifact done kind={kind} path={logical_path} elapsed={_format_duration(time.monotonic() - started)}")
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

    def log(msg: str) -> None:
        if progress:
            progress(msg)

    parts: List[Dict[str, Any]] = []
    log(f"# pkgstream artifact ingest -> {work_root}")
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
                    progress=progress,
                )
            except Exception as e:
                result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                log(f"# WARN artifact {artifact.source_key}: {result['error']}")
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

    resolve_elf_library_edges(conn)
    return {
        "ok": True,
        "pkgstream_path": _display_path(pkgstream_path, base=display_base),
        "work_root": _display_path(work_root, base=display_base),
        "collection_slug": collection_slug,
        "parts": parts,
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
    display_base: Optional[Path] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Index every pkgstream under a root directory, optionally grouping by detected version."""
    root = Path(root).resolve()
    work_base = Path(work_base).resolve()
    display_base = Path(display_base).resolve() if display_base is not None else _REPO_ROOT
    if group_by_version:
        plan = plan_pkgstream_collections(root, collection_prefix=collection_prefix)
    else:
        slug = collection_slug or root.name
        plan = [
            PkgstreamCollectionPlan(
                path=p.resolve(),
                relative_path=p.relative_to(root).as_posix(),
                collection_slug=slug,
                version=slug,
                version_source="explicit-root",
                internal_candidates=[],
            )
            for p in iter_pkgstreams_under(root)
        ]

    if not plan:
        return {"ok": False, "error": f"no .pkgstream files under {root}", "parts": []}

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
        log(
            f"# pkgstream root progress {index}/{len(plan)} ok={ok} failures={failures} "
            f"item_elapsed={_format_duration(time.monotonic() - item_started)} "
            f"elapsed={_format_duration(elapsed)} avg={_format_duration(avg)} eta={_format_duration(eta)}"
        )

    return {
        "ok": failures == 0,
        "root": _display_path(root, base=display_base),
        "work_base": _display_path(work_base, base=display_base),
        "group_by_version": group_by_version,
        "pkgstream_count": len(plan),
        "failures": failures,
        "parts": results,
    }


def build_index_from_flash(
    conn: sqlite3.Connection,
    flash_path: Path,
    *,
    collection_slug: Optional[str] = None,
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
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Index artifacts from a Pace NAND/logical flash dump through ``paceflash``."""
    from paceflash.artifacts import iter_flash_corpus_artifacts

    sections = string_sections if string_sections is not None else ELF_STRING_SECTIONS
    parts: List[Dict[str, Any]] = []
    try:
        for artifact in iter_flash_corpus_artifacts(
            flash_path,
            collection=collection_slug,
            cmdline=cmdline,
        ):
            try:
                result = index_artifact(
                    conn,
                    artifact,
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
                    progress=progress,
                )
            except Exception as e:
                result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                if progress:
                    progress(f"# WARN flash artifact {artifact.source_key}: {result['error']}")
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
    resolve_elf_library_edges(conn)
    return {
        "ok": True,
        "flash_path": str(Path(flash_path).resolve()),
        "collection_slug": collection_slug,
        "parts": parts,
    }


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
) -> Iterator[SearchHit]:
    """
    kinds: subset of {'text','symbol','rodata','soname','needed'} — default all.

    When *collection_slug* is set, only ``images.path`` rows under that collection
    prefix are searched (see :func:`format_pkgstream_image_key`).
    """
    compiled = compile_patterns(list(patterns), fixed=fixed, ignore_case=ignore_case)
    allowed = kinds or frozenset({"text", "symbol", "rodata"})
    n = 0

    coll_sql = ""
    coll_args: Tuple[Any, ...] = ()
    if collection_slug:
        pf = collection_image_prefix(collection_slug)
        coll_sql = " AND substr(i.path, 1, length(?)) = ?"
        coll_args = (pf, pf)

    if "text" in allowed:
        cur = conn.execute(
            "SELECT i.path AS ip, t.path AS fp, t.line_no, t.text "
            "FROM text_lines t JOIN images i ON t.image_id = i.id"
            + coll_sql,
            coll_args,
        )
        for row in cur:
            if pattern_matches_line(compiled, row["text"]):
                yield SearchHit(
                    "text_line",
                    row["ip"],
                    row["fp"],
                    {"line_no": row["line_no"], "text": row["text"]},
                )
                n += 1
                if limit and n >= limit:
                    return

    if "symbol" in allowed:
        cur = conn.execute(
            "SELECT i.path AS ip, e.path AS fp, e.scope, e.sym_type, e.bind, e.name "
            "FROM elf_symbols e JOIN images i ON e.image_id = i.id"
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
            "SELECT i.path AS ip, s.path AS fp, s.section, s.text "
            "FROM elf_strings s JOIN images i ON s.image_id = i.id"
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
        pf = collection_image_prefix(collection_slug)
        coll_sql = " AND substr(i.path, 1, length(?)) = ?"
        coll_args = (pf, pf)

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
        pf = collection_image_prefix(collection_slug)
        coll_sql = " WHERE substr(i.path, 1, length(?)) = ?"
        coll_args = (pf, pf)
    rows = conn.execute(
        "SELECT f.sha256, f.size_bytes, COUNT(*) AS count "
        "FROM files f JOIN images i ON f.image_id = i.id"
        + coll_sql
        + " GROUP BY f.sha256, f.size_bytes HAVING COUNT(*) > 1 "
        "ORDER BY count DESC, f.size_bytes DESC"
        + (" LIMIT ?" if limit else ""),
        coll_args + ((limit,) if limit else ()),
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for row in rows:
        members = conn.execute(
            "SELECT i.path AS image, f.path, f.content_class FROM files f JOIN images i ON f.image_id = i.id "
            "WHERE f.sha256 = ? ORDER BY i.path, f.path",
            (row["sha256"],),
        ).fetchall()
        out.append(
            {
                "sha256": row["sha256"],
                "size_bytes": row["size_bytes"],
                "count": row["count"],
                "members": [dict(m) for m in members],
            }
        )
    return out


def file_info(conn: sqlite3.Connection, term: str, *, limit: int = 50) -> List[Dict[str, Any]]:
    like = f"%{term}%"
    rows = conn.execute(
        "SELECT f.*, i.path AS image FROM files f JOIN images i ON f.image_id = i.id "
        "WHERE f.sha256 = ? OR f.path LIKE ? ORDER BY f.size_bytes DESC LIMIT ?",
        (term, like, limit),
    ).fetchall()
    return [dict(row) for row in rows]


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
