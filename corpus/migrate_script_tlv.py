"""One-off migration: rename indexed pkgstream SCRIPT TLV paths ``.bin`` → ``.sh``."""

from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from corpus.fetch import _find_materialized_file
from corpus.index_db import (
    content_class_for,
    index_text_lines,
    is_pkgstream_script_tlv_path,
    normalize_index_path,
)
from corpus.paths import repo_root_from_module, work_corpus_dir
from corpus.ref import scope_from_image_path

_SCRIPT_BIN_RE = re.compile(r"^(_scripts/script_\d{2}_@\d{7})\.bin$")

_PATH_TABLES = (
    "text_lines",
    "file_strings",
    "elf_symbols",
    "elf_strings",
    "elf_soname",
    "elf_needed",
    "secret_findings",
)


def script_tlv_sh_path(file_path: str) -> Optional[str]:
    """Return ``.sh`` path for a legacy SCRIPT TLV ``.bin`` virtual path, else ``None``."""
    if not is_pkgstream_script_tlv_path(file_path) or not file_path.endswith(".bin"):
        return None
    m = _SCRIPT_BIN_RE.match(normalize_index_path(file_path))
    if not m:
        return None
    return f"{m.group(1)}.sh"


def script_tlv_image_path(image_path: str, old_file_path: str, new_file_path: str) -> str:
    ip = image_path.replace("\\", "/")
    old = normalize_index_path(old_file_path)
    new = normalize_index_path(new_file_path)
    if ip.endswith(old):
        return ip[: -len(old)] + new
    token = f":tlv_script:{old}"
    if token in ip:
        return ip.replace(token, f":tlv_script:{new}", 1)
    return ip


def _rename_on_disk(
    repo_root: Path,
    old_file_path: str,
    new_file_path: str,
    *,
    dry_run: bool,
) -> List[str]:
    old_name = Path(old_file_path).name
    new_name = Path(new_file_path).name
    actions: List[str] = []
    wc = work_corpus_dir(repo_root)
    for sub in ("pkgstream_corpus_by_version", "pkgstream_corpus", "sbom"):
        base = wc / sub
        if not base.is_dir():
            continue
        for src in base.glob(f"**/_scripts/{old_name}"):
            if not src.is_file():
                continue
            dst = src.with_name(new_name)
            actions.append(f"rename {src} -> {dst}")
            if not dry_run:
                dst.parent.mkdir(parents=True, exist_ok=True)
                if dst.exists():
                    dst.unlink()
                src.rename(dst)
    return actions


def _update_image_path_refs(conn: sqlite3.Connection, old_ip: str, new_ip: str) -> None:
    conn.execute("UPDATE analysis_status SET image_path = ? WHERE image_path = ?", (new_ip, old_ip))
    conn.execute(
        "UPDATE artifact_edges SET parent_image_path = ? WHERE parent_image_path = ?",
        (new_ip, old_ip),
    )
    conn.execute(
        "UPDATE artifact_edges SET child_image_path = ? WHERE child_image_path = ?",
        (new_ip, old_ip),
    )


def _backfill_text_lines(
    conn: sqlite3.Connection,
    *,
    repo_root: Path,
    image_id: int,
    image_path: str,
    file_path: str,
    file_id: int,
) -> int:
    existing = conn.execute(
        "SELECT 1 FROM text_lines WHERE image_id = ? LIMIT 1", (image_id,)
    ).fetchone()
    if existing is not None:
        return 0

    scope = scope_from_image_path(image_path) or "@unknown"
    on_disk = _find_materialized_file(repo_root, scope, image_path, file_path)
    if on_disk is None or not on_disk.is_file():
        return 0
    data = on_disk.read_bytes()
    n = index_text_lines(conn, image_id, file_path, data)
    cls = content_class_for(file_path, data)
    conn.execute(
        "UPDATE files SET content_class = ?, suffix = ? WHERE id = ?",
        (cls, Path(file_path).suffix.lower() or None, file_id),
    )
    return n


def migrate_script_tlv_suffixes(
    conn: sqlite3.Connection,
    *,
    repo_root: Optional[Path] = None,
    dry_run: bool = False,
    backfill_text: bool = True,
    verbose: bool = False,
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    Rename legacy ``_scripts/script_*@….bin`` rows to ``.sh`` and fix ``images.path`` keys.

    Safe to run while indexing is idle. Re-run is a no-op once no ``.bin`` script rows remain.
    """
    root = repo_root if repo_root is not None else repo_root_from_module()
    log = progress or (lambda _msg: None)

    rows = conn.execute(
        "SELECT f.id AS file_id, f.path AS file_path, f.image_id, i.path AS image_path "
        "FROM files f JOIN images i ON f.image_id = i.id "
        "WHERE f.path LIKE '_scripts/script_%' AND f.path LIKE '%.bin' "
        "AND i.path LIKE '%:tlv_script:%' "
        "ORDER BY i.path, f.path"
    ).fetchall()

    stats: Dict[str, Any] = {
        "candidates": len(rows),
        "migrated": 0,
        "disk_renames": 0,
        "text_lines_added": 0,
        "skipped": 0,
        "errors": [],
    }
    disk_done: Set[str] = set()

    for row in rows:
        old_fp = str(row["file_path"])
        new_fp = script_tlv_sh_path(old_fp)
        if new_fp is None:
            stats["skipped"] += 1
            continue

        image_id = int(row["image_id"])
        file_id = int(row["file_id"])
        old_ip = str(row["image_path"])
        new_ip = script_tlv_image_path(old_ip, old_fp, new_fp)

        if old_fp == new_fp and old_ip == new_ip:
            stats["skipped"] += 1
            continue

        conflict = conn.execute("SELECT 1 FROM images WHERE path = ? AND id != ?", (new_ip, image_id)).fetchone()
        if conflict is not None:
            stats["errors"].append(f"image path conflict: {new_ip!r}")
            continue

        if verbose:
            log(f"{'dry-run ' if dry_run else ''}migrate {old_fp} -> {new_fp}")
        elif stats["migrated"] and stats["migrated"] % 500 == 0:
            log(f"… {stats['migrated']} index rows processed")

        if dry_run:
            stats["migrated"] += 1
            if old_fp not in disk_done:
                disk_actions = _rename_on_disk(root, old_fp, new_fp, dry_run=True)
                stats["disk_renames"] += len(disk_actions)
                disk_done.add(old_fp)
                if verbose:
                    for action in disk_actions:
                        log(f"  {action}")
            continue

        for tbl in _PATH_TABLES:
            conn.execute(
                f"UPDATE {tbl} SET path = ? WHERE image_id = ? AND path = ?",
                (new_fp, image_id, old_fp),
            )
        conn.execute(
            "UPDATE files SET path = ?, suffix = '.sh' WHERE id = ?",
            (new_fp, file_id),
        )
        _update_image_path_refs(conn, old_ip, new_ip)
        conn.execute("UPDATE images SET path = ? WHERE id = ?", (new_ip, image_id))

        if old_fp not in disk_done:
            disk_actions = _rename_on_disk(root, old_fp, new_fp, dry_run=False)
            stats["disk_renames"] += len(disk_actions)
            disk_done.add(old_fp)
            if verbose:
                for action in disk_actions:
                    log(f"  {action}")

        if backfill_text:
            stats["text_lines_added"] += _backfill_text_lines(
                conn,
                repo_root=root,
                image_id=image_id,
                image_path=new_ip,
                file_path=new_fp,
                file_id=file_id,
            )

        stats["migrated"] += 1

    if not dry_run and stats["migrated"]:
        conn.commit()

    return stats


def cmd_migrate_script_tlv(repo_root: Path, args) -> int:
    from corpus.index_db import connect_db

    db_path = Path(args.db)
    conn = connect_db(db_path)
    try:
        stats = migrate_script_tlv_suffixes(
            conn,
            repo_root=repo_root,
            dry_run=bool(args.dry_run),
            backfill_text=not bool(args.no_backfill_text),
            verbose=bool(getattr(args, "verbose", False)),
            progress=print,
        )
    finally:
        conn.close()

    print(
        f"# migrate-script-tlv: candidates={stats['candidates']} "
        f"migrated={stats['migrated']} disk_renames={stats['disk_renames']} "
        f"text_lines_added={stats['text_lines_added']} skipped={stats['skipped']}"
    )
    for err in stats.get("errors") or []:
        print(f"ERROR: {err}", file=sys.stderr)
    return 1 if stats.get("errors") else 0
