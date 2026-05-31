"""
Content-addressed blob analysis storage (corpus-index-v3).

Shared grep targets (text lines, strings, ELF symbols) live in ``blob_*`` tables
keyed by ``(content_md5, options_hash)``. ``files`` holds membership only.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from corpus.content_hash import ContentDigests, digest_bytes, digest_file

V3_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS content_blobs (
  md5 TEXT NOT NULL CHECK(length(md5) = 32),
  sha1 TEXT NOT NULL CHECK(length(sha1) = 40),
  size_bytes INTEGER NOT NULL,
  content_class TEXT,
  first_seen_at TEXT NOT NULL,
  ref_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (md5)
) WITHOUT ROWID;
CREATE UNIQUE INDEX IF NOT EXISTS idx_content_blobs_sha1 ON content_blobs(sha1);

CREATE TABLE IF NOT EXISTS blob_analysis (
  md5 TEXT NOT NULL,
  analysis_version TEXT NOT NULL,
  options_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  metrics_json TEXT,
  completed_at TEXT,
  PRIMARY KEY (md5, analysis_version, options_hash),
  FOREIGN KEY (md5) REFERENCES content_blobs(md5)
);
CREATE INDEX IF NOT EXISTS idx_blob_analysis_completed
  ON blob_analysis(md5, options_hash) WHERE status = 'completed';

CREATE TABLE IF NOT EXISTS image_blob_analysis (
  carrier_md5 TEXT NOT NULL,
  analysis_version TEXT NOT NULL,
  options_hash TEXT NOT NULL,
  canonical_image_id INTEGER,
  status TEXT NOT NULL,
  metrics_json TEXT,
  completed_at TEXT,
  PRIMARY KEY (carrier_md5, analysis_version, options_hash),
  FOREIGN KEY (carrier_md5) REFERENCES content_blobs(md5)
);
CREATE INDEX IF NOT EXISTS idx_image_blob_analysis_completed
  ON image_blob_analysis(carrier_md5, options_hash) WHERE status = 'completed';

CREATE TABLE IF NOT EXISTS blob_transforms (
  src_md5 TEXT NOT NULL,
  transform TEXT NOT NULL,
  options_hash TEXT NOT NULL,
  dst_md5 TEXT NOT NULL,
  PRIMARY KEY (src_md5, transform, options_hash),
  FOREIGN KEY (src_md5) REFERENCES content_blobs(md5),
  FOREIGN KEY (dst_md5) REFERENCES content_blobs(md5)
);

CREATE TABLE IF NOT EXISTS install_md5sums (
  collection_slug TEXT NOT NULL,
  basename TEXT NOT NULL,
  md5 TEXT NOT NULL,
  PRIMARY KEY (collection_slug, basename),
  FOREIGN KEY (md5) REFERENCES content_blobs(md5)
);
CREATE INDEX IF NOT EXISTS idx_install_md5sums_md5 ON install_md5sums(md5);

CREATE TABLE IF NOT EXISTS blob_text_lines (
  content_md5 TEXT NOT NULL,
  options_hash TEXT NOT NULL,
  line_no INTEGER NOT NULL,
  text TEXT NOT NULL,
  PRIMARY KEY (content_md5, options_hash, line_no),
  FOREIGN KEY (content_md5) REFERENCES content_blobs(md5)
);
CREATE INDEX IF NOT EXISTS idx_blob_text_lines_text ON blob_text_lines(text);
CREATE INDEX IF NOT EXISTS idx_blob_text_lines_md5
  ON blob_text_lines(content_md5, options_hash, line_no);

CREATE TABLE IF NOT EXISTS blob_file_strings (
  content_md5 TEXT NOT NULL,
  options_hash TEXT NOT NULL,
  offset INTEGER NOT NULL,
  encoding TEXT NOT NULL,
  source TEXT NOT NULL,
  text TEXT NOT NULL,
  length INTEGER NOT NULL,
  PRIMARY KEY (content_md5, options_hash, offset, encoding),
  FOREIGN KEY (content_md5) REFERENCES content_blobs(md5)
);
CREATE INDEX IF NOT EXISTS idx_blob_file_strings_text
  ON blob_file_strings(text, content_md5);

CREATE TABLE IF NOT EXISTS blob_elf_symbols (
  content_md5 TEXT NOT NULL,
  options_hash TEXT NOT NULL,
  scope TEXT NOT NULL,
  sym_type TEXT,
  bind TEXT,
  name TEXT NOT NULL,
  PRIMARY KEY (content_md5, options_hash, scope, name),
  FOREIGN KEY (content_md5) REFERENCES content_blobs(md5)
);
CREATE INDEX IF NOT EXISTS idx_blob_elf_symbols_name
  ON blob_elf_symbols(name, content_md5);

CREATE TABLE IF NOT EXISTS blob_elf_strings (
  content_md5 TEXT NOT NULL,
  options_hash TEXT NOT NULL,
  section TEXT NOT NULL,
  text TEXT NOT NULL,
  PRIMARY KEY (content_md5, options_hash, section, text),
  FOREIGN KEY (content_md5) REFERENCES content_blobs(md5)
);

CREATE TABLE IF NOT EXISTS blob_elf_soname (
  content_md5 TEXT NOT NULL,
  options_hash TEXT NOT NULL,
  soname TEXT NOT NULL,
  PRIMARY KEY (content_md5, options_hash),
  FOREIGN KEY (content_md5) REFERENCES content_blobs(md5)
);
CREATE INDEX IF NOT EXISTS idx_blob_elf_soname_name ON blob_elf_soname(soname);

CREATE TABLE IF NOT EXISTS blob_elf_needed (
  content_md5 TEXT NOT NULL,
  options_hash TEXT NOT NULL,
  needed TEXT NOT NULL,
  PRIMARY KEY (content_md5, options_hash, needed),
  FOREIGN KEY (content_md5) REFERENCES content_blobs(md5)
);
CREATE INDEX IF NOT EXISTS idx_blob_elf_needed_needed ON blob_elf_needed(needed);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def create_v3_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(V3_SCHEMA_SQL)


def upsert_content_blob(
    conn: sqlite3.Connection,
    digests: ContentDigests,
    size_bytes: int,
    *,
    content_class: Optional[str] = None,
) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO content_blobs(md5, sha1, size_bytes, content_class, first_seen_at, ref_count) "
        "VALUES (?,?,?,?,?,0)",
        (digests.md5, digests.sha1, size_bytes, content_class, utc_now()),
    )
    if content_class:
        conn.execute(
            "UPDATE content_blobs SET content_class = COALESCE(content_class, ?) WHERE md5 = ?",
            (content_class, digests.md5),
        )


def lookup_blob_by_md5(conn: sqlite3.Connection, md5: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM content_blobs WHERE md5 = ?", (md5.lower(),)).fetchone()


def lookup_blob_by_sha1(conn: sqlite3.Connection, sha1: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM content_blobs WHERE sha1 = ?", (sha1.lower(),)).fetchone()


def completed_blob_analysis(
    conn: sqlite3.Connection,
    md5: str,
    *,
    analysis_version: str,
    options_hash: str,
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM blob_analysis "
        "WHERE md5 = ? AND analysis_version = ? AND options_hash = ? AND status = 'completed'",
        (md5, analysis_version, options_hash),
    ).fetchone()


def mark_blob_analysis_completed(
    conn: sqlite3.Connection,
    md5: str,
    *,
    analysis_version: str,
    options_hash: str,
    metrics: dict[str, Any],
) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO blob_analysis("
        "md5, analysis_version, options_hash, status, metrics_json, completed_at"
        ") VALUES (?,?,?,?,?,?)",
        (md5, analysis_version, options_hash, "completed", json.dumps(metrics, sort_keys=True), utc_now()),
    )


def mark_blob_analysis_running(
    conn: sqlite3.Connection,
    md5: str,
    *,
    analysis_version: str,
    options_hash: str,
) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO blob_analysis("
        "md5, analysis_version, options_hash, status, metrics_json, completed_at"
        ") VALUES (?,?,?,?,?,?)",
        (md5, analysis_version, options_hash, "running", None, None),
    )


def completed_image_blob_analysis(
    conn: sqlite3.Connection,
    carrier_md5: str,
    *,
    analysis_version: str,
    options_hash: str,
) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM image_blob_analysis "
        "WHERE carrier_md5 = ? AND analysis_version = ? AND options_hash = ? AND status = 'completed'",
        (carrier_md5, analysis_version, options_hash),
    ).fetchone()


def mark_image_blob_analysis_completed(
    conn: sqlite3.Connection,
    carrier_md5: str,
    *,
    analysis_version: str,
    options_hash: str,
    canonical_image_id: int,
    metrics: dict[str, Any],
) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO image_blob_analysis("
        "carrier_md5, analysis_version, options_hash, canonical_image_id, status, metrics_json, completed_at"
        ") VALUES (?,?,?,?,?,?,?)",
        (
            carrier_md5,
            analysis_version,
            options_hash,
            canonical_image_id,
            "completed",
            json.dumps(metrics, sort_keys=True),
            utc_now(),
        ),
    )


def get_blob_transform_dst(
    conn: sqlite3.Connection,
    src_md5: str,
    transform: str,
    options_hash: str,
) -> Optional[str]:
    row = conn.execute(
        "SELECT dst_md5 FROM blob_transforms WHERE src_md5 = ? AND transform = ? AND options_hash = ?",
        (src_md5, transform, options_hash),
    ).fetchone()
    return str(row["dst_md5"]) if row else None


def record_blob_transform(
    conn: sqlite3.Connection,
    src_md5: str,
    transform: str,
    options_hash: str,
    dst_md5: str,
) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO blob_transforms(src_md5, transform, options_hash, dst_md5) "
        "VALUES (?,?,?,?)",
        (src_md5, transform, options_hash, dst_md5),
    )


def sync_image_elf_dynamic_from_blob(
    conn: sqlite3.Connection,
    image_id: int,
    rel_path: str,
    content_md5: str,
    options_hash: str,
) -> None:
    """Copy blob SONAME/NEEDED into per-image tables for library edge resolution."""
    soname = conn.execute(
        "SELECT soname FROM blob_elf_soname WHERE content_md5 = ? AND options_hash = ?",
        (content_md5, options_hash),
    ).fetchone()
    if soname is not None:
        conn.execute(
            "INSERT OR REPLACE INTO elf_soname(image_id, path, soname) VALUES (?,?,?)",
            (image_id, rel_path, soname["soname"]),
        )
    conn.execute("DELETE FROM elf_needed WHERE image_id = ? AND path = ?", (image_id, rel_path))
    for row in conn.execute(
        "SELECT needed FROM blob_elf_needed WHERE content_md5 = ? AND options_hash = ?",
        (content_md5, options_hash),
    ):
        conn.execute(
            "INSERT INTO elf_needed(image_id, path, needed) VALUES (?,?,?)",
            (image_id, rel_path, row["needed"]),
        )


def clone_image_file_memberships(
    conn: sqlite3.Connection,
    *,
    canonical_image_id: int,
    target_image_id: int,
    options_hash: str,
) -> int:
    """
    Clone ``files`` rows from canonical image to target; sync ELF dynamic tables from blobs.
    Returns number of files cloned.
    """
    rows = conn.execute(
        "SELECT path, size_bytes, md5, content_class, suffix, indexed_at FROM files WHERE image_id = ?",
        (canonical_image_id,),
    ).fetchall()
    n = 0
    for row in rows:
        conn.execute(
            "INSERT OR REPLACE INTO files(image_id, path, size_bytes, md5, content_class, suffix, indexed_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                target_image_id,
                row["path"],
                row["size_bytes"],
                row["md5"],
                row["content_class"],
                row["suffix"],
                row["indexed_at"],
            ),
        )
        sync_image_elf_dynamic_from_blob(
            conn, target_image_id, str(row["path"]), str(row["md5"]), options_hash
        )
        n += 1
    conn.execute(
        "UPDATE images SET file_count = (SELECT COUNT(*) FROM files WHERE image_id = ?) WHERE id = ?",
        (target_image_id, target_image_id),
    )
    return n


def upsert_install_md5sums(
    conn: sqlite3.Connection,
    collection_slug: str,
    entries: dict[str, str],
) -> None:
    for basename, md5_hex in entries.items():
        if "/" in basename:
            continue
        conn.execute(
            "INSERT OR REPLACE INTO install_md5sums(collection_slug, basename, md5) VALUES (?,?,?)",
            (collection_slug, basename, md5_hex.lower()),
        )


@dataclass
class BlobWriteCallbacks:
    """Hooks into index_db extractors (avoids circular imports at module load)."""

    index_text_lines_blob: Callable[..., int]
    index_file_strings_blob: Callable[..., int]
    index_elf_payload_blob: Callable[..., dict[str, int]]
    index_binary_format: Callable[..., int]
    index_version_evidence: Callable[..., int]
    content_class_for: Callable[..., str]
    is_probably_binary: Callable[[bytes], bool]
    is_pkgstream_script_tlv_path: Callable[[str], bool]
    skip_suffixes: set[str]
    scan_secrets: Callable[..., int] = field(default=lambda *a, **k: 0)


def metrics_from_counts(counts: dict[str, int]) -> dict[str, int]:
    return {k: int(v) for k, v in counts.items()}


def index_blob_payload(
    conn: sqlite3.Connection,
    image_id: int,
    rel_path: str,
    data: bytes,
    *,
    analysis_version: str,
    options_hash: str,
    max_file_bytes: int,
    skip_suffixes: bool,
    callbacks: BlobWriteCallbacks,
    insert_file_row_fn: Callable[..., int],
    progress: Optional[Callable[[str], None]] = None,
) -> dict[str, int]:
    """
    Index one file payload with content-addressed dedup.

    Shared ``blob_*`` rows are written once per ``(md5, options_hash)``; ``files`` always updated.
    """
    counts: dict[str, int] = {
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
        "secrets": 0,
        "blob_cache_hit": 0,
    }

    if len(data) > max_file_bytes:
        return counts

    digests = digest_bytes(data)
    cls = callbacks.content_class_for(rel_path, data)
    upsert_content_blob(conn, digests, len(data), content_class=cls)
    file_id = insert_file_row_fn(
        conn, image_id, rel_path, data, digests=digests, content_class=cls
    )
    counts["files"] = 1

    cached = completed_blob_analysis(
        conn, digests.md5, analysis_version=analysis_version, options_hash=options_hash
    )
    if cached is not None:
        counts["blob_cache_hit"] = 1
        metrics = json.loads(cached["metrics_json"] or "{}")
        for k in (
            "text_lines",
            "file_strings",
            "elf_sym",
            "elf_str",
            "elf_soname",
            "elf_needed",
            "binary_formats",
            "dwarf_units",
            "dwarf_entries",
        ):
            counts[k] = int(metrics.get(k, 0))
        counts["file_versions"] += callbacks.index_version_evidence(
            conn, file_id, image_id, rel_path, data
        )
        counts["secrets"] += callbacks.scan_secrets(
            conn, image_id=image_id, file_id=file_id, path=rel_path, data=data
        )
        sync_image_elf_dynamic_from_blob(conn, image_id, rel_path, digests.md5, options_hash)
        return counts

    mark_blob_analysis_running(
        conn, digests.md5, analysis_version=analysis_version, options_hash=options_hash
    )

    counts["file_strings"] += callbacks.index_file_strings_blob(
        conn,
        digests.md5,
        options_hash,
        data,
    )
    counts["file_versions"] += callbacks.index_version_evidence(
        conn, file_id, image_id, rel_path, data
    )

    elf_magic = b"\x7fELF"
    if data[:4] == elf_magic:
        elf_counts = callbacks.index_elf_payload_blob(
            conn,
            digests.md5,
            options_hash,
            image_id,
            file_id,
            rel_path,
            data,
            progress=progress,
        )
        for k, v in elf_counts.items():
            counts[k] = counts.get(k, 0) + int(v)
        counts["secrets"] += callbacks.scan_secrets(
            conn, image_id=image_id, file_id=file_id, path=rel_path, data=data
        )
        sync_image_elf_dynamic_from_blob(conn, image_id, rel_path, digests.md5, options_hash)
        mark_blob_analysis_completed(
            conn,
            digests.md5,
            analysis_version=analysis_version,
            options_hash=options_hash,
            metrics=metrics_from_counts(counts),
        )
        return counts

    counts["binary_formats"] += callbacks.index_binary_format(
        conn,
        file_id,
        image_id,
        rel_path,
        data,
        content_class=cls,
    )

    suf = Path(rel_path).suffix.lower()
    index_as_text = callbacks.is_pkgstream_script_tlv_path(rel_path)
    if skip_suffixes and suf in callbacks.skip_suffixes and not index_as_text:
        counts["secrets"] += callbacks.scan_secrets(
            conn, image_id=image_id, file_id=file_id, path=rel_path, data=data
        )
        mark_blob_analysis_completed(
            conn,
            digests.md5,
            analysis_version=analysis_version,
            options_hash=options_hash,
            metrics=metrics_from_counts(counts),
        )
        return counts
    if callbacks.is_probably_binary(data) and not index_as_text:
        counts["secrets"] += callbacks.scan_secrets(
            conn, image_id=image_id, file_id=file_id, path=rel_path, data=data
        )
        mark_blob_analysis_completed(
            conn,
            digests.md5,
            analysis_version=analysis_version,
            options_hash=options_hash,
            metrics=metrics_from_counts(counts),
        )
        return counts

    counts["text_lines"] += callbacks.index_text_lines_blob(
        conn, digests.md5, options_hash, data
    )
    counts["secrets"] += callbacks.scan_secrets(
        conn, image_id=image_id, file_id=file_id, path=rel_path, data=data
    )
    mark_blob_analysis_completed(
        conn,
        digests.md5,
        analysis_version=analysis_version,
        options_hash=options_hash,
        metrics=metrics_from_counts(counts),
    )
    sync_image_elf_dynamic_from_blob(conn, image_id, rel_path, digests.md5, options_hash)
    return counts


def carrier_digests_for_path(path: Path) -> ContentDigests:
    return digest_file(path)
