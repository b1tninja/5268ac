#!/usr/bin/env python3
"""
Recursive grep over dissected squashfs trees, OR search / build a SQLite index from
raw SquashFS **images** read with ``dissect.squashfs`` (no extracted tree on disk).

Filesystem mode (default):
  - Walk ``work_corpus/pkgstream_dissect_corpus/*/`` or ``--roots``
  - Patterns are regex unless ``-F``

Index mode:
  - ``pip install dissect.squashfs pyelftools``
  - ``--build-index --db PATH --pkgstream FILE.pkgstream`` (repeat ``--pkgstream`` for several carriers)
    and optional ``--collection SLUG`` — TLV extract + embedded SquashFS + uImage carve ->
    ``vmlinux-to-elf`` on ``PATH`` (see ``tools.md``).
  - ``--build-index --db PATH --pkgstream-root DIR`` — walk a mirror/tree and group carriers
    into version collections derived from pkgstream bytes, falling back to versioned paths.
  - ``--build-index --db PATH --flash FLASH.bin`` — Pace NAND via paceflash; default collection ``nand:@<basename>``.
  - ``--build-index --db PATH --image CARVED.bin`` — raw SquashFS blob(s) via dissect.
  - ``--build-index --from-extracted`` — already-unpacked trees under ``pkgstream_dissect_corpus/``.
  - ``--build-index --buildroot TARGET/ --buildroot-profile 2011.11`` — stock Buildroot ``target/`` reference.
  - ``--buildroot-diff --collection version:…`` — stock vs manufacturer paths (needs indexed Buildroot + firmware).
  - ``--buildroot-origin PATH --collection version:…`` — classify one file.
  - ``--buildroot-versions-report`` — os-release vs busybox ``.comment`` per collection.
  - ``--list-collections`` — firmware ``collection:*`` slugs in ``--db``.
  - ``--db PATH patterns…`` — grep the index (text + symbols + rodata strings).

Examples:
  python -m corpus rwdata /rwdata/cm mount tmpfs
  python -m corpus --build-index --db cm.sqlite \\
      --collection firmware_11.5.1.532678/11.5.1.532678 \\
      --pkgstream firmware/.../install.pkgstream \\
      --pkgstream firmware/.../conf.pkgstream
  python -m corpus --build-index --db cm.sqlite \\
      --image carve/tlpart_squashfs_0x03ff5080_8a358306.bin
  python -m corpus --db cm.sqlite -i rwdata cmd
  python -m corpus --buildroot-versions-report --jsonl
  python -m corpus --buildroot-versions-report --buildroot-profiles 2011.11,2013.05
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple  # noqa: F401


DEFAULT_MAX_BYTES = 32 * 1024 * 1024

# .so / .ko are ELF — scanned via pyelftools, not skipped.
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


def default_corpus_roots(repo_root: Path) -> List[Path]:
    bases = [
        repo_root / "work_corpus" / "pkgstream_dissect_corpus",
        repo_root / "work_tl_crc" / "pkgstream_dissect_corpus",
    ]
    roots: list[Path] = []
    for base in bases:
        if base.is_dir():
            roots.extend(sorted(p for p in base.iterdir() if p.is_dir()))
    return roots


def is_probably_binary(sample: bytes) -> bool:
    if b"\x00" in sample[:8192]:
        return True
    return False


def iter_lines_from_file(
    path: Path,
    max_bytes: int,
    binary: bool,
) -> Iterator[Tuple[int, str]]:
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size > max_bytes and not binary:
        return
    try:
        data = path.read_bytes()
    except OSError:
        return
    if not binary and is_probably_binary(data[:8192]):
        return
    if binary:
        text = data.decode("utf-8", errors="replace")
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="replace")
    line_no = 0
    for line in text.splitlines(keepends=True):
        line_no += 1
        yield line_no, line.rstrip("\r\n")


def compile_patterns(
    patterns: List[str],
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


def match_line(
    line: str,
    compiled: List[re.Pattern[str]],
) -> Optional[re.Match[str]]:
    for c in compiled:
        m = c.search(line)
        if m:
            return m
    return None


def walk_files(roots: Iterable[Path], skip_suffixes: bool) -> Iterator[Path]:
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if not d.startswith(".git")]
            for name in filenames:
                p = Path(dirpath) / name
                if skip_suffixes and p.suffix.lower() in SKIP_SUFFIXES:
                    continue
                try:
                    if p.is_file():
                        yield p
                except OSError:
                    continue


def iter_text_lines_from_bytes(data: bytes, binary: bool) -> Iterator[Tuple[int, str]]:
    if not binary and is_probably_binary(data[:8192]):
        return
    if binary:
        text = data.decode("utf-8", errors="replace")
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="replace")
    line_no = 0
    for line in text.splitlines():
        line_no += 1
        yield line_no, line


def cmd_fs_grep(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    roots: List[Path]
    if args.roots:
        roots = [Path(r).resolve() for r in args.roots]
    else:
        roots = default_corpus_roots(repo)
        if not roots:
            print(
                "No default corpus under work_tl_crc/pkgstream_dissect_corpus; pass --roots.",
                file=sys.stderr,
            )
            return 2

    max_bytes = int(args.max_file_mb * 1024 * 1024) if args.max_file_mb > 0 else 10**15
    compiled = compile_patterns(list(args.patterns), fixed=args.fixed_strings, ignore_case=args.ignore_case)
    skip_suffix = not args.no_skip_suffixes

    total = 0
    elftools_warned = False
    for path in walk_files(roots, skip_suffixes=skip_suffix):
        try:
            rel = path.relative_to(repo)
            disp = str(rel).replace("\\", "/")
        except ValueError:
            disp = str(path)

        try:
            sz = path.stat().st_size
            if sz > max_bytes:
                continue
            data = path.read_bytes()
        except OSError:
            continue

        if data[:4] == idx.ELF_MAGIC:
            try:
                elf_line = 0
                for eline in idx.iter_elf_matching_lines(
                    data,
                    compiled,
                    symtab=args.symtab,
                    min_string_len=args.min_string_len,
                ):
                    elf_line += 1
                    total += 1
                    if args.jsonl:
                        print(
                            json.dumps(
                                {
                                    "path": disp,
                                    "line": elf_line,
                                    "kind": "elf",
                                    "text": eline[:4000],
                                },
                                ensure_ascii=False,
                            ),
                            flush=True,
                        )
                    else:
                        print(f"{disp}:ELF:{eline}")
                    if args.limit and total >= args.limit:
                        return 0
            except ImportError:
                if not elftools_warned:
                    print(
                        "Install pyelftools to search ELF (.so/.ko): pip install pyelftools",
                        file=sys.stderr,
                    )
                    elftools_warned = True
            continue

        for line_no, line in iter_text_lines_from_bytes(data, binary=args.binary):
            if match_line(line, compiled):
                total += 1
                if args.jsonl:
                    print(
                        json.dumps(
                            {
                                "path": disp,
                                "line": line_no,
                                "text": line[:4000],
                            },
                            ensure_ascii=False,
                        ),
                        flush=True,
                    )
                else:
                    print(f"{disp}:{line_no}:{line}")
                if args.limit and total >= args.limit:
                    return 0
    return 0


def cmd_explain_library(repo: Path, args: argparse.Namespace) -> int:
    """Print DT_SONAME providers vs DT_NEEDED consumers for one NEEDED / SONAME string."""
    from corpus import index_db as idx

    conn = _connect_query_db(args)
    coll = getattr(args, "collection", None)
    prov, cons = idx.explain_library_links(
        conn,
        args.explain_library,
        collection_slug=coll,
    )
    conn.close()

    lib = args.explain_library
    print(f"# library resolution for NEEDED / SONAME: {lib}", file=sys.stderr)
    print(f"## providers (ELF files with DT_SONAME == {lib})")
    if not prov:
        print("(none in index)")
    else:
        for ip, fp in prov:
            print(f"{ip}::{fp}")
    print(f"## consumers (ELF files listing DT_NEEDED == {lib})")
    if not cons:
        print("(none in index)")
    else:
        for ip, fp in cons:
            print(f"{ip}::{fp}")
    return 0


def _print_rows(rows: list[dict[str, object]], *, jsonl: bool) -> None:
    for row in rows:
        if jsonl:
            print(json.dumps(row, ensure_ascii=False), flush=True)
        else:
            print(json.dumps(row, ensure_ascii=False, sort_keys=True))


def cmd_duplicates(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    conn = _connect_query_db(args)
    rows = idx.duplicate_files(
        conn,
        collection_slug=getattr(args, "collection", None),
        limit=args.limit or 0,
    )
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def cmd_file_info(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    conn = _connect_query_db(args)
    rows = idx.file_info(conn, args.file_info, limit=args.limit or 50)
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def cmd_versions(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    conn = _connect_query_db(args)
    rows = idx.version_rows(conn, limit=args.limit or 200)
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def _format_firmware_span(row: Dict[str, Any]) -> str:
    fw_min = row.get("firmware_min")
    fw_max = row.get("firmware_max")
    n = int(row.get("firmware_version_count") or 0)
    if not fw_min and not fw_max:
        return "unknown"
    if fw_min == fw_max:
        return f"{fw_min} ({n} version{'s' if n != 1 else ''})"
    return f"{fw_min} – {fw_max} ({n} versions)"


def _format_paths_field(row: Dict[str, Any]) -> str:
    paths = row.get("paths") or []
    if not paths:
        return f"path={row.get('path') or row.get('query') or '?'}"
    if len(paths) == 1 and not row.get("path_glob"):
        return f"path={paths[0]}"
    return f"paths={','.join(paths)}"


def _print_file_history(rows: List[Dict[str, Any]], *, jsonl: bool, preview: bool, verbose: bool) -> None:
    if jsonl:
        for row in rows:
            print(json.dumps(row, ensure_ascii=False), flush=True)
        return
    if not rows:
        return
    any_glob = any(row.get("path_glob") for row in rows)
    if any_glob:
        all_paths = sorted({p for row in rows for p in (row.get("paths") or [])})
        query = rows[0].get("query") or "?"
        print(f"# query {query!r}: {len(all_paths)} matching path(s)", file=sys.stderr)
        for p in all_paths:
            print(f"#   {p}", file=sys.stderr)
    for row in rows:
        sha_short = str(row.get("md5") or "")[:12]
        size_b = row.get("size_bytes")
        images = row.get("image_count")
        fw_span = _format_firmware_span(row)
        coll_n = row.get("collection_count")
        parts = [
            f"{sha_short}",
            _format_paths_field(row),
            f"size={size_b}",
            f"images={images}",
            f"firmware={fw_span}",
            f"collections={coll_n}",
        ]
        if preview and row.get("preview"):
            prev = str(row["preview"]).replace("\n", "\\n")
            if len(prev) > 72:
                prev = prev[:69] + "..."
            parts.append(f"preview={prev}")
        print("\t".join(parts), flush=True)
        if verbose:
            for coll in row.get("collections") or []:
                slug = coll.get("slug", "")
                ch = coll.get("channel") or ""
                fv = coll.get("firmware_version") or ""
                cv = coll.get("component_version") or ""
                extra = f" channel={ch}" if ch else ""
                if cv and cv != fv:
                    extra += f" component={cv}"
                print(f"  {slug}\tfirmware={fv}{extra}", flush=True)


def cmd_file_history(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    if _require_db_file(repo, args) != 0:
        return 2
    path = getattr(args, "path", None)
    if not path:
        print("corpus file-history requires PATH", file=sys.stderr)
        return 2

    conn = _connect_query_db(args)
    rows = idx.file_path_history(
        conn,
        path,
        collection_slug=_collection_arg(args),
        path_glob=bool(getattr(args, "glob", False)),
        limit=int(getattr(args, "limit", 0) or 0),
        preview=bool(getattr(args, "preview", False)),
    )
    conn.close()
    _print_file_history(
        rows,
        jsonl=bool(getattr(args, "jsonl", False)),
        preview=bool(getattr(args, "preview", False)),
        verbose=bool(getattr(args, "verbose", False)),
    )
    return 0 if rows else 1


def cmd_index_status(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    conn = _connect_query_db(args)
    summary = idx.index_progress_summary(conn)
    recent = conn.execute(
        "SELECT ingest_key, md5, completed_at, metrics_json "
        "FROM ingest_status WHERE status = 'completed' "
        "ORDER BY completed_at DESC LIMIT ?",
        (args.limit or 25,),
    ).fetchall()
    conn.close()
    row = {"db": args.db, **summary, "recent_pkgstream_ingests": [dict(r) for r in recent]}
    if args.jsonl:
        print(json.dumps(row, ensure_ascii=False), flush=True)
    else:
        print(json.dumps(row, indent=2, sort_keys=True))
    return 0


def cmd_deps(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    conn = _connect_query_db(args)
    rows = idx.dependency_rows(conn, args.deps, limit=args.limit or 200)
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def cmd_format_summary(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    conn = _connect_query_db(args)
    rows = idx.format_summary(conn)
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def cmd_dwarf(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    term = args.dwarf or ""
    conn = _connect_query_db(args)
    rows = idx.dwarf_rows(conn, term, limit=args.limit or 200)
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def cmd_children(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    conn = _connect_query_db(args)
    rows = idx.child_edges(conn, args.children, limit=args.limit or 200)
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def _sbom_root(repo: Path, args: argparse.Namespace) -> Path:
    from corpus.paths import default_sbom_dir

    if getattr(args, "sbom_dir", None):
        return Path(args.sbom_dir).expanduser().resolve()
    return default_sbom_dir(repo)


def _resolve_db_path(repo: Path, args: argparse.Namespace) -> Path:
    from corpus.paths import resolve_corpus_db_path

    return resolve_corpus_db_path(repo, getattr(args, "db", None))


def _connect_query_db(args: argparse.Namespace):
    """Open the corpus index read-only (safe while another process is indexing)."""
    from corpus import index_db as idx

    return idx.connect_db(args.db, readonly=True)


def _connect_write_db(args: argparse.Namespace):
    """Open the corpus index for writes (--build-index, migrations)."""
    from corpus import index_db as idx

    return idx.connect_db(args.db, readonly=False)


def _require_db_file(repo: Path, args: argparse.Namespace) -> int:
    from corpus.paths import LEGACY_CORPUS_DB_RELATIVE, preferred_corpus_db_path

    path = _resolve_db_path(repo, args)
    args.db = str(path)
    if path.is_file():
        return 0
    print(f"Corpus database not found: {path}", file=sys.stderr)
    print(f"  Expected default: {preferred_corpus_db_path(repo)}", file=sys.stderr)
    print(f"  Legacy path:      {repo / LEGACY_CORPUS_DB_RELATIVE}", file=sys.stderr)
    print(
        "  Build: python -m corpus --build-index --pkgstream-root gateway.c01.sbcglobal.net",
        file=sys.stderr,
    )
    return 2


def _uses_index_db(args: argparse.Namespace) -> bool:
    if args.build_index:
        return True
    if getattr(args, "explain_library", None):
        return True
    if getattr(args, "duplicates", False):
        return True
    if getattr(args, "file_info", None):
        return True
    if getattr(args, "versions", False):
        return True
    if getattr(args, "index_status", False):
        return True
    if getattr(args, "deps", None):
        return True
    if getattr(args, "format_summary", False):
        return True
    if getattr(args, "dwarf", None) not in (None, ""):
        return True
    if getattr(args, "children", None):
        return True
    if getattr(args, "sbom_for", None):
        return True
    if getattr(args, "buildroot_diff", False):
        return True
    if getattr(args, "buildroot_origin", None):
        return True
    if getattr(args, "list_buildroot", False):
        return True
    if getattr(args, "list_collections", False):
        return True
    if getattr(args, "buildroot_versions_report", False):
        return True
    if args.patterns:
        return True
    return False


def _collection_arg(args: argparse.Namespace) -> Optional[str]:
    from corpus import vuln

    return vuln.resolve_collection_slug_arg(getattr(args, "collection", None))


def _secrets_dir(repo: Path, args: argparse.Namespace) -> Optional[Path]:
    if not getattr(args, "secrets", False):
        return None
    if getattr(args, "secrets_dir", None):
        return Path(args.secrets_dir).expanduser().resolve()
    from corpus.paths import default_secrets_dir

    return default_secrets_dir(repo)


def _index_secret_kwargs(repo: Path, args: argparse.Namespace) -> dict[str, object]:
    return {
        "scan_secrets": bool(getattr(args, "secrets", False)),
        "secrets_dir": _secrets_dir(repo, args),
        "secrets_gitleaks": bool(getattr(args, "secrets_gitleaks", False)),
        "gitleaks_bin": getattr(args, "gitleaks_bin", "gitleaks"),
    }


def cmd_list_secrets(repo: Path, args: argparse.Namespace) -> int:
    from corpus import secrets as sec

    secrets_root = (
        Path(args.secrets_dir).expanduser().resolve()
        if getattr(args, "secrets_dir", None)
        else _secrets_dir(repo, args) or (repo / "work_corpus" / "secrets")
    )
    coll = _collection_arg(args)
    entries = list(
        sec.iter_secret_report_entries(
            secrets_root,
            collection_slug=coll,
            term=getattr(args, "secrets_term", None),
        )
    )
    if not entries:
        conn = None
        if getattr(args, "db", None):
            from corpus import index_db as idx

            conn = _connect_query_db(args)
            coll_sql = ""
            coll_args: tuple = ()
            if coll:
                coll_sql, coll_args = idx.collection_image_filter_sql(coll, leading_where=True)
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM secret_findings s JOIN images i ON s.image_id = i.id"
                + coll_sql,
                coll_args,
            ).fetchone()
            conn.close()
            if row and int(row["n"]) > 0:
                print(
                    f"# {row['n']} finding(s) in DB; export with: "
                    "python -m corpus --secrets-export --secrets",
                    file=sys.stderr,
                )
                return 0
        print(f"# no secret reports under {secrets_root}", file=sys.stderr)
        return 1

    if args.jsonl:
        for ent in entries:
            print(
                json.dumps(
                    {
                        "report": str(ent.path),
                        "image_key": ent.image_key,
                        "finding_count": ent.finding_count,
                        "by_severity": ent.by_severity,
                        "source_mode": ent.source_mode,
                    },
                    ensure_ascii=False,
                )
            )
        return 0

    for ent in entries:
        sev = ",".join(f"{k}={v}" for k, v in sorted(ent.by_severity.items()))
        print(f"{ent.path.name}\tfindings={ent.finding_count}\t{sev}\t{ent.image_key or ''}")
    print(f"# {len(entries)} report(s)", file=sys.stderr)
    return 0


def cmd_secrets_summary(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    coll = _collection_arg(args)
    conn = _connect_query_db(args)
    coll_sql = ""
    coll_args: tuple = ()
    if coll:
        coll_sql, coll_args = idx.collection_image_filter_sql(coll, leading_where=True)
    rows = conn.execute(
        "SELECT rule_id, severity, COUNT(*) AS n FROM secret_findings s "
        "JOIN images i ON s.image_id = i.id"
        + coll_sql
        + " GROUP BY rule_id, severity ORDER BY n DESC",
        coll_args,
    ).fetchall()
    conn.close()
    if not rows:
        print("# no secret findings in index (build with --secrets)", file=sys.stderr)
        return 1
    if args.jsonl:
        for row in rows:
            print(json.dumps(dict(row), ensure_ascii=False))
        return 0
    for row in rows:
        print(f"{row['rule_id']}\t{row['severity']}\t{row['n']}")
    return 0


def cmd_secrets_export(repo: Path, args: argparse.Namespace) -> int:
    from corpus import secrets as sec

    secrets_root = _secrets_dir(repo, args)
    if secrets_root is None:
        print("--secrets-export requires --secrets or prior --build-index --secrets", file=sys.stderr)
        return 2
    from corpus import index_db as idx

    conn = _connect_query_db(args)

    def prog(msg: str) -> None:
        print(msg, file=sys.stderr)

    res = sec.scan_secrets_for_database(
        conn,
        collection_slug=_collection_arg(args),
        secrets_dir=secrets_root,
        progress=prog,
    )
    conn.close()
    if args.jsonl:
        print(json.dumps(res, ensure_ascii=False))
    else:
        print(f"# exported {res.get('images_exported', 0)} image report(s) -> {secrets_root}")
    return 0 if res.get("ok") else 1


def cmd_list_sboms(repo: Path, args: argparse.Namespace) -> int:
    from corpus import vuln

    sbom_root = _sbom_root(repo, args)
    coll = _collection_arg(args)
    entries = list(
        vuln.iter_sbom_entries(
            sbom_root,
            collection_slug=coll,
            term=getattr(args, "sbom_term", None),
        )
    )
    rows = vuln.entries_to_rows(entries, repo_root=repo)
    if not rows:
        print(f"# no SBOMs under {sbom_root}", file=sys.stderr)
        if coll:
            print(f"# collection filter: {coll}", file=sys.stderr)
        return 1
    _print_rows(rows, jsonl=args.jsonl)
    if not args.jsonl:
        print(f"# {len(rows)} SBOM(s); scan with: python -m corpus --grype --grype-sbom <path>", file=sys.stderr)
    return 0


def _resolve_grype_sbom_paths(repo: Path, args: argparse.Namespace) -> List[Path]:
    from corpus import index_db as idx
    from corpus import vuln

    sbom_root = _sbom_root(repo, args)
    coll = _collection_arg(args)
    explicit = [Path(p).expanduser().resolve() for p in (getattr(args, "grype_sbom", None) or [])]

    paths: List[Path] = []
    seen: set[str] = set()

    def add(path: Path) -> None:
        key = str(path.resolve())
        if path.is_file() and key not in seen:
            seen.add(key)
            paths.append(path.resolve())

    for p in explicit:
        add(p)

    sbom_for = getattr(args, "sbom_for", None)
    if sbom_for:
        conn = _connect_query_db(args)
        like = f"%{sbom_for}%"
        if coll:
            prefix = idx.collection_image_prefix(coll)
            rows = conn.execute(
                "SELECT path FROM images WHERE path LIKE ? AND path LIKE ?",
                (like, f"{prefix}%"),
            ).fetchall()
        else:
            rows = conn.execute("SELECT path FROM images WHERE path LIKE ?", (like,)).fetchall()
        conn.close()
        for row in rows:
            for p in vuln.sbom_paths_for_image_keys([str(row["path"])], sbom_root, collection_slug=coll):
                add(p)

    if getattr(args, "grype_all", False):
        for ent in vuln.iter_sbom_entries(sbom_root, collection_slug=coll, term=getattr(args, "sbom_term", None)):
            add(ent.path)

    return paths


def cmd_grype(repo: Path, args: argparse.Namespace) -> int:
    from corpus import vuln

    sbom_root = _sbom_root(repo, args)
    coll = _collection_arg(args)

    if getattr(args, "grype_summary", False):
        entries = list(
            vuln.iter_sbom_entries(
                sbom_root,
                collection_slug=coll,
                term=getattr(args, "sbom_term", None),
            )
        )
        rows = []
        for ent in entries:
            if ent.grype_report is None or not ent.grype_report.is_file():
                continue
            summary = ent.grype_summary or vuln.summarize_grype_report(ent.grype_report)
            rows.append(
                {
                    "sbom": str(ent.path),
                    "grype_report": str(ent.grype_report),
                    "collection": ent.collection_slug,
                    "source_hint": ent.source_hint,
                    **summary,
                }
            )
        if not rows:
            print("# no Grype reports found (.grype.json beside .syft.json)", file=sys.stderr)
            return 1
        _print_rows(rows, jsonl=args.jsonl)
        return 0

    try:
        sbom_paths = _resolve_grype_sbom_paths(repo, args)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    if not sbom_paths:
        print(
            "No SBOM files matched; use --grype-sbom PATH, --sbom-for TERM (with --db), "
            "or --collection version:X with --grype-all.",
            file=sys.stderr,
        )
        return 2

    report_dir = (
        Path(args.grype_report_dir).expanduser().resolve()
        if getattr(args, "grype_report_dir", None)
        else None
    )
    rc = 0
    for sbom_path in sbom_paths:
        report_path = None
        if report_dir is not None:
            report_path = report_dir / (sbom_path.stem.replace(".syft", "") + ".grype.json")
        elif getattr(args, "grype_report", None):
            report_path = Path(args.grype_report).expanduser().resolve()
            if len(sbom_paths) > 1:
                report_path = report_path.parent / f"{sbom_path.stem}.grype.json"
        else:
            ent = vuln.SbomEntry(path=sbom_path)
            report_path = ent.default_grype_report_path()

        result = vuln.run_grype(
            sbom_path,
            grype_bin=args.grype_bin,
            output_format=args.grype_output,
            report_path=report_path if args.grype_output == "json" else None,
            fail_on=args.grype_fail_on or None,
            db_update=getattr(args, "grype_db_update", False),
            quiet=getattr(args, "grype_quiet", False),
            only_fixed=getattr(args, "grype_only_fixed", False),
            skip_existing=getattr(args, "grype_skip_existing", False),
            timeout_s=int(getattr(args, "grype_timeout", 900)),
        )
        if args.jsonl:
            print(json.dumps(result, ensure_ascii=False), flush=True)
        else:
            print(f"# grype {sbom_path.name}", file=sys.stderr)
            if result.get("table"):
                print(result["table"], end="" if str(result["table"]).endswith("\n") else "\n")
            elif result.get("summary"):
                print(json.dumps(result["summary"], indent=2, sort_keys=True))
            elif result.get("error"):
                print(result["error"], file=sys.stderr)
        if not result.get("ok"):
            rc = 1
    return rc


def cmd_index_search(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    kinds = frozenset(args.kinds or list(idx.DEFAULT_SEARCH_KINDS))
    conn = _connect_query_db(args)
    total = 0
    coll = _collection_arg(args)
    raw_coll = getattr(args, "collection", None)
    if (
        raw_coll
        and idx._looks_like_firmware_version(raw_coll.strip())
        and "/" not in raw_coll
        and not raw_coll.strip().startswith(("pkgstream:", "nand:", "buildroot:", "version:"))
    ):
        ver = raw_coll.strip()
        n = idx.count_collections_for_firmware_version(conn, ver)
        if n > 1:
            slugs = idx.list_collection_slugs_for_firmware_version(conn, ver)
            print(
                f"warning: firmware version {ver!r} matches {n} collections; "
                f"prefer a release path (e.g. {slugs[0]!r})",
                file=sys.stderr,
            )
    refs_only = getattr(args, "refs_only", False)
    null_sep = getattr(args, "null", False)
    file_type_sub = getattr(args, "file_type", None)
    path_globs = getattr(args, "path_glob", None) or []
    for hit in idx.search_index(
        conn,
        args.patterns,
        fixed=args.fixed_strings,
        ignore_case=args.ignore_case,
        kinds=kinds,
        limit=args.limit or 0,
        collection_slug=coll,
        completed_only=True,
    ):
        if path_globs and not _path_glob_match(hit.path, path_globs):
            continue
        if file_type_sub and not _hit_file_type_match(conn, hit.image_path, hit.path, file_type_sub):
            continue
        total += 1
        ref = hit.to_ref(conn)
        if args.jsonl:
            print(
                json.dumps(hit.to_json_dict(conn), ensure_ascii=False),
                flush=True,
            )
        elif refs_only:
            end = "\0" if null_sep else "\n"
            sys.stdout.write(ref + end)
            sys.stdout.flush()
        else:
            display = hit.display_line(conn)
            print(f"{ref}\t{display}")
    conn.close()
    if total == 0 and args.patterns and not args.fixed_strings:
        for p in args.patterns:
            if "_" in p and p.replace("_", "").replace(".", "").isalnum():
                print(
                    f"hint: pattern {p!r} uses regex rules (_ is a literal underscore); "
                    "matched board-param names also appear as 'lightspeed p12' in scripts — "
                    "retry as lightspeed.p12 or use -F for an exact byte match",
                    file=sys.stderr,
                )
                break
    return 0


def _path_glob_match(path: str, globs: List[str]) -> bool:
    import fnmatch

    p = path.replace("\\", "/")
    return any(fnmatch.fnmatch(p, g) for g in globs)


def _hit_file_type_match(
    conn: sqlite3.Connection,
    image_path: str,
    file_path: str,
    needle: str,
) -> bool:
    """
    Match substring against stored ``file(1)`` output for this file.

    Best-effort: if we can't find a binary_formats row, don't match.
    """
    import sqlite3 as _sqlite3

    try:
        row = conn.execute(
            "SELECT b.file_type, b.file_mime, b.file_mime_encoding "
            "FROM binary_formats b JOIN files f ON b.file_id = f.id "
            "JOIN images i ON f.image_id = i.id "
            "WHERE i.path = ? AND f.path = ? LIMIT 1",
            (image_path, file_path),
        ).fetchone()
    except _sqlite3.Error:
        return False
    if row is None:
        return False
    blob = " ".join(str(row[k] or "") for k in ("file_type", "file_mime", "file_mime_encoding")).lower()
    return needle.lower() in blob


def parse_ref_from_pipe_line(line: str) -> Optional[str]:
    """
    Extract a corpus ref from one line of piped CLI output.

    Accepts plain ``--refs-only`` lines or default ``find``/``grep`` rows::
    ``<ref>\\t<image>::<path>``.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "\t" in line:
        return line.split("\t", 1)[0].strip()
    if line.startswith("ref="):
        return line[4:].strip()
    return line


def parse_refs_from_stdin_data(data: str, *, null_sep: bool = False) -> List[str]:
    """Split piped ``--refs-only`` (or tab-separated find/grep) output into refs."""
    if null_sep:
        parts = [p.strip() for p in data.split("\0") if p.strip()]
    else:
        parts = []
        for ln in data.splitlines():
            ref = parse_ref_from_pipe_line(ln)
            if ref:
                parts.append(ref)
        return parts
    out: List[str] = []
    for p in parts:
        ref = parse_ref_from_pipe_line(p)
        if ref:
            out.append(ref)
    return out


def refs_from_stdin(*, null_sep: bool = False) -> List[str]:
    if sys.stdin.isatty():
        return []
    return parse_refs_from_stdin_data(sys.stdin.read(), null_sep=null_sep)


def _refs_from_args(args: argparse.Namespace) -> List[str]:
    ref = getattr(args, "ref", None)
    if ref:
        refs = [ref.strip()]
    else:
        refs = refs_from_stdin(null_sep=bool(getattr(args, "null", False)))
    max_count = int(getattr(args, "max_count", 0) or 0)
    if max_count > 0:
        refs = refs[:max_count]
    return refs


def _add_stdin_ref_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "-0",
        "--null",
        action="store_true",
        dest="null",
        help="Refs on stdin are NUL-separated (match ``grep/find --refs-only -0``).",
    )
    ap.add_argument(
        "-n",
        "--max-count",
        type=int,
        default=0,
        metavar="N",
        help="Process at most N refs from stdin (0 = all).",
    )
    ap.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Skip refs that fail lookup/extract; exit 1 if any were skipped.",
    )


def _cat_refs(
    conn: Any,
    repo: Path,
    refs: Sequence[str],
    *,
    delimiter: bool,
    continue_on_error: bool,
) -> int:
    from corpus.fetch import apply_query_slice, fetch_bytes
    from corpus.ref import parse_ref

    rc = 0
    for i, ref in enumerate(refs):
        if delimiter and i:
            sys.stdout.buffer.write(b"\n")
        if delimiter:
            sys.stdout.buffer.write(f"==> {ref}\n".encode("utf-8", errors="replace"))
        try:
            parsed = parse_ref(ref)
            data = fetch_bytes(conn, ref, repo_root=repo)
            if parsed.query:
                data = apply_query_slice(data, parsed.query)
            sys.stdout.buffer.write(data)
        except (LookupError, OSError, ValueError) as exc:
            print(f"{ref}: {exc}", file=sys.stderr)
            rc = 1
            if not continue_on_error:
                return rc
        except Exception as exc:
            print(f"{ref}: {type(exc).__name__}: {exc}", file=sys.stderr)
            rc = 1
            if not continue_on_error:
                return rc
    return rc


def _locate_refs(
    conn: Any,
    repo: Path,
    refs: Sequence[str],
    *,
    jsonl: bool,
    continue_on_error: bool,
) -> int:
    from corpus.fetch import locate_ref

    rc = 0
    for ref in refs:
        try:
            loc = locate_ref(conn, ref, repo_root=repo)
        except LookupError as exc:
            print(f"{ref}: {exc}", file=sys.stderr)
            rc = 1
            if not continue_on_error:
                return rc
            continue
        if jsonl:
            print(
                json.dumps(
                    {
                        "ref": loc.ref,
                        "scope": loc.scope,
                        "path": loc.file_path,
                        "image_path": loc.image_path,
                        "image_id": loc.image_id,
                        "file_md5": loc.file_md5,
                        "on_disk": str(loc.on_disk) if loc.on_disk else None,
                        "cache_path": str(loc.cache_path) if loc.cache_path else None,
                        "resolver": loc.resolver,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
        else:
            print(
                f"ref={loc.ref}\n"
                f"scope={loc.scope}\n"
                f"path={loc.file_path}\n"
                f"image={loc.image_path}\n"
                f"image_id={loc.image_id}",
                flush=True,
            )
    return rc


def cmd_cat(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    if _require_db_file(repo, args) != 0:
        return 2
    refs = _refs_from_args(args)
    if not refs:
        print(
            "corpus cat requires REF (or pipe refs from corpus grep/find --refs-only, or find/grep tab output)",
            file=sys.stderr,
        )
        return 2
    use_delimiter = bool(getattr(args, "delimiter", False)) or (
        len(refs) > 1 and not getattr(args, "raw", False)
    )
    conn = _connect_query_db(args)
    try:
        rc = _cat_refs(
            conn,
            repo,
            refs,
            delimiter=use_delimiter,
            continue_on_error=bool(getattr(args, "continue_on_error", False)),
        )
    finally:
        conn.close()
    return rc


def cmd_xargs(repo: Path, args: argparse.Namespace) -> int:
    """Run ``cat`` or ``locate`` once per ref on stdin (xargs-style)."""
    from corpus import index_db as idx

    if _require_db_file(repo, args) != 0:
        return 2
    refs = _refs_from_args(args)
    if not refs:
        print(
            "corpus xargs requires refs on stdin (pipe from corpus grep/find --refs-only, or find/grep tab output)",
            file=sys.stderr,
        )
        return 2
    action = getattr(args, "action", "cat")
    conn = _connect_query_db(args)
    try:
        if action == "cat":
            rc = _cat_refs(
                conn,
                repo,
                refs,
                delimiter=not getattr(args, "raw", False),
                continue_on_error=bool(getattr(args, "continue_on_error", False)),
            )
        elif action == "locate":
            rc = _locate_refs(
                conn,
                repo,
                refs,
                jsonl=bool(getattr(args, "jsonl", False)),
                continue_on_error=bool(getattr(args, "continue_on_error", False)),
            )
        else:
            print(f"unknown xargs action {action!r}", file=sys.stderr)
            rc = 2
    finally:
        conn.close()
    return rc


def cmd_locate(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx
    from corpus.fetch import locate_ref

    if _require_db_file(repo, args) != 0:
        return 2
    ref = getattr(args, "ref", None)
    if not ref:
        print("corpus locate requires REF", file=sys.stderr)
        return 2
    conn = _connect_query_db(args)
    try:
        loc = locate_ref(conn, ref, repo_root=repo)
    except LookupError as exc:
        print(str(exc), file=sys.stderr)
        conn.close()
        return 1
    conn.close()
    if args.jsonl:
        print(
            json.dumps(
                {
                    "ref": loc.ref,
                    "scope": loc.scope,
                    "path": loc.file_path,
                    "image_path": loc.image_path,
                    "image_id": loc.image_id,
                    "file_md5": loc.file_md5,
                    "on_disk": str(loc.on_disk) if loc.on_disk else None,
                    "cache_path": str(loc.cache_path) if loc.cache_path else None,
                    "resolver": loc.resolver,
                },
                ensure_ascii=False,
            )
        )
    else:
        print(f"ref={loc.ref}")
        print(f"scope={loc.scope}")
        print(f"path={loc.file_path}")
        print(f"image={loc.image_path}")
        print(f"image_id={loc.image_id}")
        if loc.on_disk:
            print(f"on_disk={loc.on_disk}")
        if loc.cache_path:
            print(f"cache={loc.cache_path}")
    return 0


def cmd_find(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx
    from corpus.ref import format_ref, image_short_id, scope_from_image_path

    if _require_db_file(repo, args) != 0:
        return 2

    globs = getattr(args, "globs", None) or []
    kinds = getattr(args, "kinds", None) or []
    if not globs and not kinds:
        print("corpus find requires GLOB pattern(s) and/or --kind", file=sys.stderr)
        return 2

    coll = _collection_arg(args)
    refs_only = bool(getattr(args, "refs_only", False))
    null_sep = bool(getattr(args, "null", False))
    file_type_sub = getattr(args, "file_type", None)

    conn = _connect_query_db(args)
    total = 0
    try:
        for row in idx.find_files(
            conn,
            globs,
            kinds=kinds or None,
            collection_slug=coll,
            limit=int(getattr(args, "limit", 0) or 0),
            completed_only=True,
        ):
            image_path = str(row["image_path"])
            file_path = str(row["file_path"])
            if file_type_sub and not _hit_file_type_match(conn, image_path, file_path, file_type_sub):
                continue

            scope = scope_from_image_path(image_path) or "@unknown"
            iid = image_short_id(conn, image_path)
            ref = format_ref(scope, file_path, image_id=iid)

            total += 1
            if args.jsonl:
                print(
                    json.dumps(
                        {
                            "ref": ref,
                            "image_path": image_path,
                            "file_path": file_path,
                            "md5": row.get("md5"),
                            "size_bytes": row.get("size_bytes"),
                            "content_class": row.get("content_class"),
                            "artifact_kind": row.get("artifact_kind"),
                            "collection": coll,
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
            elif refs_only:
                end = "\0" if null_sep else "\n"
                sys.stdout.write(ref + end)
                sys.stdout.flush()
            else:
                kind_tag = row.get("artifact_kind")
                prefix = f"[{kind_tag}] " if kind_tag else ""
                print(f"{prefix}{ref}\t{image_path}::{file_path}")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        conn.close()
        return 2
    finally:
        conn.close()

    return 0 if total else 1


def cmd_buildroot_diff(repo: Path, args: argparse.Namespace) -> int:
    from corpus import buildroot as br
    from corpus import index_db as idx

    if not args.collection:
        print("--buildroot-diff requires --collection", file=sys.stderr)
        return 2
    profile = args.buildroot_profile or "2011.11"
    conn = _connect_query_db(args)
    try:
        report = br.diff_collection_vs_buildroot(conn, args.collection, profile)
    except LookupError as exc:
        print(str(exc), file=sys.stderr)
        conn.close()
        return 1
    conn.close()
    if args.jsonl:
        print(json.dumps(report.to_dict(), ensure_ascii=False))
    else:
        c = report.to_dict()["counts"]
        print(
            f"buildroot:{report.buildroot_profile} vs collection:{report.collection}\n"
            f"  stock: {c['stock']}\n"
            f"  vendor_modified: {c['vendor_modified']}\n"
            f"  vendor_path: {c['vendor_path']}\n"
            f"  buildroot_only: {c['buildroot_only']}"
        )
        samples = report.to_dict()["samples"]
        for label in ("vendor_path", "vendor_modified", "stock"):
            paths = samples.get(label) or []
            if paths:
                print(f"\n=== {label} (sample) ===")
                for p in paths[:20]:
                    print(f"  {p}")
    return 0


def cmd_buildroot_origin(repo: Path, args: argparse.Namespace) -> int:
    from corpus import buildroot as br
    from corpus import index_db as idx

    if not args.collection:
        print("--buildroot-origin requires --collection", file=sys.stderr)
        return 2
    profile = args.buildroot_profile or "2011.11"
    conn = _connect_query_db(args)
    try:
        payload = br.lookup_path_origin(
            conn, args.collection, args.buildroot_origin, profile
        )
    except LookupError as exc:
        print(str(exc), file=sys.stderr)
        conn.close()
        return 1
    conn.close()
    if args.jsonl:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print(
            f"{payload['path']}: {payload['origin']} "
            f"(collection:{payload['collection']} buildroot:{payload['buildroot_profile']})"
        )
        if payload.get("firmware_md5"):
            print(f"  firmware md5: {payload['firmware_md5']}")
        if payload.get("buildroot_md5"):
            print(f"  buildroot md5: {payload['buildroot_md5']}")
    return 0


def _parse_buildroot_profiles_arg(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


def cmd_buildroot_versions_report(repo: Path, args: argparse.Namespace) -> int:
    from corpus import buildroot as br
    from corpus import index_db as idx

    conn = _connect_query_db(args)
    collections = None
    if getattr(args, "collection", None):
        collections = [idx.normalize_collection_slug(args.collection)]
    elf_path = getattr(args, "buildroot_elf", None) or "bin/busybox"
    profiles = _parse_buildroot_profiles_arg(getattr(args, "buildroot_profiles", None))

    report = br.buildroot_versions_report(
        conn,
        elf_path=elf_path,
        collections=collections,
        buildroot_profiles=profiles or None,
    )
    conn.close()

    if not report.collections and not report.warnings:
        print("No collection data in index.", file=sys.stderr)
        return 1

    if args.jsonl:
        print(json.dumps(report.to_dict(), ensure_ascii=False))
        return 0

    for w in report.warnings:
        print(f"warning: {w}", file=sys.stderr)

    print(f"elf_path={report.elf_path}  collections={len(report.collections)}")
    print(
        f"{'collection':<28} {'VERSION_ID':<12} {'gcc_BR':<12} {'gcc':<8} mismatch"
    )
    for row in report.collections:
        flag = "!" if row.metadata_mismatch else ""
        print(
            f"{row.collection:<28} "
            f"{(row.version_id or '-'):<12} "
            f"{(row.gcc_buildroot or '-'):<12} "
            f"{(row.gcc_version or '-'):<8} "
            f"{flag}"
        )
        if row.metadata_mismatch and row.mismatch_reason:
            print(f"  -> {row.mismatch_reason}")

    if report.diffs:
        print("\n=== diff counts (collection x buildroot profile) ===")
        for coll, by_prof in sorted(report.diffs.items()):
            for prof, counts in sorted(by_prof.items()):
                print(
                    f"  {coll} vs buildroot:{prof}  "
                    f"stock={counts['stock']} "
                    f"vendor_modified={counts['vendor_modified']} "
                    f"vendor_path={counts['vendor_path']} "
                    f"buildroot_only={counts['buildroot_only']}"
                )

    summary = report.to_dict()["summary"]
    print(
        f"\ndistinct VERSION_ID: {summary['distinct_os_release_version_id']}\n"
        f"distinct gcc Buildroot: {summary['distinct_gcc_buildroot']}\n"
        f"metadata mismatches: {len(summary['metadata_mismatch_collections'])}"
    )
    return 0


def _collection_only_query(args: argparse.Namespace) -> bool:
    """True when --collection is the sole query (no patterns or other index modes)."""
    if not getattr(args, "collection", None):
        return False
    if args.patterns:
        return False
    if args.build_index:
        return False
    for attr in (
        "explain_library",
        "file_info",
        "deps",
        "dwarf",
        "children",
        "buildroot_origin",
        "sbom_for",
    ):
        if getattr(args, attr, None):
            return False
    for flag in (
        "duplicates",
        "versions",
        "index_status",
        "format_summary",
        "buildroot_diff",
        "list_buildroot",
        "list_collections",
        "buildroot_versions_report",
        "list_sboms",
        "list_secrets",
        "secrets_summary",
        "secrets_export",
        "grype",
        "grype_summary",
    ):
        if getattr(args, flag, False):
            return False
    return True


def cmd_collection_show(repo: Path, args: argparse.Namespace) -> int:
    from corpus import buildroot as br
    from corpus import index_db as idx

    coll = _collection_arg(args)
    if not coll:
        print("--collection requires a slug", file=sys.stderr)
        return 2

    conn = _connect_query_db(args)
    rows = [r for r in br.list_collection_details(conn) if r["collection"] == coll]
    conn.close()

    if not rows:
        print(
            f"No indexed data for collection {coll!r} "
            "(try --list-collections; slug is version:x.y.z.w).",
            file=sys.stderr,
        )
        return 1

    row = rows[0]
    if args.jsonl:
        print(json.dumps(row, ensure_ascii=False))
        return 0

    print(f"collection={row['collection']}  images={len(row['images'])}  files={row['file_count']}")
    for key in (
        "release_path",
        "firmware_version",
        "component_version",
        "channel",
        "install_pkgstream",
    ):
        if row.get(key):
            print(f"  {key}={row[key]}")
    for img in row["images"]:
        print(
            f"  {img['image_key']}\tfiles={img['file_count']}\tindexed={img['indexed_at']}"
        )
    print(
        "\nSearch this collection:  python -m corpus grep --collection "
        f"{coll} PATTERN",
        file=sys.stderr,
    )
    return 0


def cmd_list_collections(repo: Path, args: argparse.Namespace) -> int:
    from corpus import buildroot as br
    from corpus import index_db as idx

    conn = _connect_query_db(args)
    rows = br.list_collection_details(conn)
    conn.close()

    if args.jsonl:
        for row in rows:
            print(json.dumps(row, ensure_ascii=False))
        return 0

    if not rows:
        print(
            "No firmware collections in index "
            "(no collection:* keys and no work_corpus/pkgstream_corpus_by_version/version_* paths).",
            file=sys.stderr,
        )
        print(
            "  Build: python -m corpus --build-index --pkgstream-root gateway.c01.sbcglobal.net",
            file=sys.stderr,
        )
        return 1

    for row in rows:
        carriers = len(row["images"])
        print(f"{row['collection']}\timages={carriers}\tfiles={row['file_count']}")
        if getattr(args, "verbose", False):
            for img in row["images"]:
                print(
                    f"  {img['image_key']}\tfiles={img['file_count']}\t"
                    f"indexed={img['indexed_at']}"
                )
    return 0


def cmd_list_buildroot(repo: Path, args: argparse.Namespace) -> int:
    from corpus import buildroot as br
    from corpus import index_db as idx

    conn = _connect_query_db(args)
    rows = br.list_buildroot_profiles(conn)
    conn.close()
    if args.jsonl:
        for row in rows:
            print(json.dumps(row, ensure_ascii=False))
    elif not rows:
        print("No buildroot:* images in index (use --build-index --buildroot TARGET/)")
    else:
        for row in rows:
            print(
                f"{row['image_key']}\tfiles={row['file_count']}\tindexed={row['indexed_at']}"
            )
    return 0


def cmd_build_index(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    buildroot_list = getattr(args, "buildroot", None) or []
    pkg_list = getattr(args, "pkgstream", None) or []
    pkg_root_list = getattr(args, "pkgstream_root", None) or []
    flash_list = getattr(args, "flash", None) or []
    from_extracted = getattr(args, "from_extracted", False)
    collection_raw = getattr(args, "collection", None)
    sbom_dir = None
    if getattr(args, "sbom", False):
        sbom_dir = (
            Path(args.sbom_dir).expanduser().resolve()
            if getattr(args, "sbom_dir", None)
            else (repo / "work_corpus" / "sbom").resolve()
        )
    secret_kw = _index_secret_kwargs(repo, args)

    if getattr(args, "fresh", False):
        dbp = Path(args.db).expanduser().resolve()
        for p in (dbp, Path(str(dbp) + "-wal"), Path(str(dbp) + "-shm")):
            try:
                p.unlink()
            except FileNotFoundError:
                pass

    if buildroot_list:
        try:
            import elftools  # noqa: F401
        except ImportError:
            print("Missing pyelftools — pip install pyelftools.", file=sys.stderr)
            return 2
        if pkg_list or pkg_root_list or from_extracted or flash_list:
            print(
                "Use --buildroot without --pkgstream, --pkgstream-root, --flash, or --from-extracted.",
                file=sys.stderr,
            )
            return 2
        from corpus import buildroot as br

        conn = _connect_write_db(args)
        symtab = getattr(args, "symtab", False)
        max_bytes = int(args.max_file_mb * 1024 * 1024) if args.max_file_mb > 0 else 10**15
        profile = args.buildroot_profile or "2011.11"

        def prog_br(msg: str) -> None:
            print(msg, file=sys.stderr)

        failures = 0
        for br_arg in buildroot_list:
            target = Path(br_arg).expanduser().resolve()
            if not target.is_dir():
                print(f"Not a directory: {target}", file=sys.stderr)
                conn.close()
                return 2
            prog_br(f"# buildroot index profile={profile} root={target}")
            res = br.build_index_for_buildroot(
                conn,
                target,
                profile,
                max_file_bytes=max_bytes,
                skip_suffixes=not args.no_skip_suffixes,
                symtab=symtab,
                min_string_len=args.min_string_len,
                max_strings_per_file=args.max_strings_per_file,
                dwarf=getattr(args, "dwarf", None) is not None,
                progress=prog_br,
            )
            if not res.get("ok"):
                prog_br(f"FAILED: {res.get('error')}")
                failures += 1
            else:
                prog_br(
                    f"# indexed {res.get('buildroot_image_key')} "
                    f"files={res.get('files_seen', 0)}"
                )
        conn.close()
        prog_br(f"# database {args.db}")
        return 1 if failures else 0

    if pkg_root_list:
        if pkg_list or from_extracted or args.image or flash_list or buildroot_list:
            print(
                "Use --pkgstream-root without --pkgstream, --from-extracted, --image, or --flash.",
                file=sys.stderr,
            )
            return 2
        try:
            import dissect.squashfs  # noqa: F401
        except ImportError:
            print(
                "Missing dissect.squashfs — pip install dissect.squashfs (AGPL-3.0).",
                file=sys.stderr,
            )
            return 2
        try:
            import elftools  # noqa: F401
        except ImportError:
            print("Missing pyelftools — pip install pyelftools.", file=sys.stderr)
            return 2

        conn = _connect_write_db(args)

        def prog_root(msg: str) -> None:
            print(msg, file=sys.stderr)

        symtab = getattr(args, "symtab", False)
        max_bytes = int(args.max_file_mb * 1024 * 1024) if args.max_file_mb > 0 else 10**15
        report: dict[str, object] = {"roots": []}
        failures = 0
        for root_arg in pkg_root_list:
            root = Path(root_arg).expanduser().resolve()
            if not root.is_dir():
                print(f"Not a directory: {root}", file=sys.stderr)
                conn.close()
                return 2
            group_by_version = not getattr(args, "no_pkgstream_version_collections", False)
            if not group_by_version and not collection_raw:
                collection_raw = root.name
            work_base = (
                Path(args.pkgstream_work).expanduser().resolve()
                if getattr(args, "pkgstream_work", None)
                else (repo / "work_corpus" / "pkgstream_corpus_by_version")
            )
            prog_root(f"# pkgstream root corpus index: {root}")
            prog_root(f"# staging base: {work_base}")
            if group_by_version:
                prog_root(
                    "# collections: pkgstream:<release-path> (mirror dir; PROD/LAB disambiguation)"
                )
            else:
                prog_root(f"# collection: {idx.normalize_collection_slug(collection_raw or root.name)}")

            res = idx.build_index_from_pkgstream_root(
                conn,
                root,
                work_base,
                group_by_version=group_by_version,
                collection_slug=collection_raw,
                max_file_bytes=max_bytes,
                skip_suffixes=not args.no_skip_suffixes,
                symtab=symtab,
                min_string_len=args.min_string_len,
                max_strings_per_file=args.max_strings_per_file,
                dwarf=getattr(args, "dwarf", None) is not None,
                jobs=max(1, int(getattr(args, "jobs", 1) or 1)),
                sbom_dir=sbom_dir,
                sbom_source=args.sbom_source,
                sbom_mount_root=(
                    Path(args.sbom_mount_root).expanduser().resolve()
                    if getattr(args, "sbom_mount_root", None)
                    else None
                ),
                syft_bin=args.syft_bin,
                sbom_format=args.sbom_format,
                display_base=repo,
                pkgstream_version_order=getattr(args, "pkgstream_version_order", "path"),
                progress=prog_root,
                **secret_kw,
            )
            failures += int(res.get("failures", 0) or (0 if res.get("ok") else 1))
            report["roots"].append(res)

        conn.close()
        if getattr(args, "pkgstream_report_json", None):
            out = Path(args.pkgstream_report_json).expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(report, indent=2), encoding="utf-8")
            prog_root(f"# report: {out}")
        prog_root(f"# database {args.db}")
        return 1 if failures else 0

    if pkg_list:
        if from_extracted or args.image or flash_list:
            print(
                "Use --pkgstream without --from-extracted, --image, or --flash.",
                file=sys.stderr,
            )
            return 2
        try:
            import dissect.squashfs  # noqa: F401
        except ImportError:
            print(
                "Missing dissect.squashfs — pip install dissect.squashfs (AGPL-3.0).",
                file=sys.stderr,
            )
            return 2
        try:
            import elftools  # noqa: F401
        except ImportError:
            print("Missing pyelftools — pip install pyelftools.", file=sys.stderr)
            return 2

        conn = _connect_write_db(args)

        def prog_pkg(msg: str) -> None:
            print(msg, file=sys.stderr)

        symtab = getattr(args, "symtab", False)
        max_bytes = int(args.max_file_mb * 1024 * 1024) if args.max_file_mb > 0 else 10**15

        explicit_work = getattr(args, "pkgstream_work", None)
        multi = len(pkg_list) > 1

        for pkgstream_arg in pkg_list:
            pkg = Path(pkgstream_arg).expanduser().resolve()
            if not pkg.is_file():
                print(f"Not a file: {pkg}", file=sys.stderr)
                conn.close()
                return 2

            if explicit_work:
                wb = Path(explicit_work).expanduser().resolve()
                work = (wb / pkg.stem).resolve() if multi else wb.resolve()
            else:
                base = repo / "work_corpus" / "pkgstream_corpus"
                if collection_raw:
                    work = (
                        base / idx.collection_slug_for_fs(collection_raw) / pkg.stem
                    ).resolve()
                else:
                    work = (base / pkg.stem).resolve()

            prog_pkg(f"# pkgstream corpus index: {pkg}")
            prog_pkg(f"# staging: {work}")
            if collection_raw:
                prog_pkg(
                    f"# collection: {idx.normalize_collection_slug(collection_raw)}"
                )

            res = idx.build_index_from_pkgstream(
                conn,
                pkg,
                work,
                collection_slug=collection_raw,
                max_file_bytes=max_bytes,
                skip_suffixes=not args.no_skip_suffixes,
                symtab=symtab,
                min_string_len=args.min_string_len,
                max_strings_per_file=args.max_strings_per_file,
                dwarf=getattr(args, "dwarf", None) is not None,
                jobs=max(1, int(getattr(args, "jobs", 1) or 1)),
                sbom_dir=(
                    sbom_dir / idx.collection_slug_for_fs(collection_raw)
                    if sbom_dir is not None and collection_raw
                    else sbom_dir
                ),
                sbom_source=args.sbom_source,
                sbom_mount_root=(
                    Path(args.sbom_mount_root).expanduser().resolve()
                    if getattr(args, "sbom_mount_root", None)
                    else None
                ),
                syft_bin=args.syft_bin,
                sbom_format=args.sbom_format,
                display_base=repo,
                progress=prog_pkg,
                **secret_kw,
            )
            if not res.get("ok"):
                prog_pkg(f"# FAILED {pkg.name}: {res.get('error')}")
                conn.close()
                return 1

        conn.close()
        prog_pkg(f"# database {args.db}")
        return 0

    if flash_list:
        if from_extracted or args.image:
            print("Use --flash without --from-extracted or --image.", file=sys.stderr)
            return 2
        conn = _connect_write_db(args)

        def prog_flash(msg: str) -> None:
            print(msg, file=sys.stderr)

        symtab = getattr(args, "symtab", False)
        max_bytes = int(args.max_file_mb * 1024 * 1024) if args.max_file_mb > 0 else 10**15
        for flash_arg in flash_list:
            flash = Path(flash_arg).expanduser().resolve()
            if not flash.is_file():
                print(f"Not a file: {flash}", file=sys.stderr)
                conn.close()
                return 2
            flash_coll = idx.resolve_flash_collection_slug(flash, collection_raw)
            prog_flash(f"# paceflash corpus index: {flash}")
            prog_flash(f"# collection {flash_coll}")
            flash_secret_kw = dict(secret_kw)
            if flash_secret_kw.get("secrets_dir") is not None:
                flash_secret_kw["secrets_dir"] = (
                    Path(flash_secret_kw["secrets_dir"])
                    / idx.collection_slug_for_fs(flash_coll)
                )
            flash_work = (
                repo / "work_corpus" / "flash_corpus" / idx.collection_slug_for_fs(flash_coll)
            )
            res = idx.build_index_from_flash(
                conn,
                flash,
                collection_slug=flash_coll,
                work_root=flash_work,
                max_file_bytes=max_bytes,
                skip_suffixes=not args.no_skip_suffixes,
                symtab=symtab,
                min_string_len=args.min_string_len,
                max_strings_per_file=args.max_strings_per_file,
                dwarf=getattr(args, "dwarf", None) is not None,
                sbom_dir=(
                    sbom_dir / idx.collection_slug_for_fs(flash_coll)
                    if sbom_dir is not None
                    else sbom_dir
                ),
                sbom_source=args.sbom_source,
                sbom_mount_root=(
                    Path(args.sbom_mount_root).expanduser().resolve()
                    if getattr(args, "sbom_mount_root", None)
                    else None
                ),
                syft_bin=args.syft_bin,
                sbom_format=args.sbom_format,
                progress=prog_flash,
                **flash_secret_kw,
            )
            if not res.get("ok"):
                prog_flash(f"# FAILED {flash.name}: {res.get('error')}")
                conn.close()
                return 1
        conn.close()
        prog_flash(f"# database {args.db}")
        return 0

    if from_extracted:
        try:
            import elftools  # noqa: F401
        except ImportError:
            print("Missing pyelftools — pip install pyelftools.", file=sys.stderr)
            return 2

        if args.image:
            roots = [Path(x).expanduser().resolve() for x in args.image]
        else:
            roots = idx.default_pkgstream_dissect_roots(repo)
        roots = [r for r in roots if r.is_dir()]
        if not roots:
            print(
                "No extracted corpus roots; pass --image DIR or add dirs under "
                "work_corpus/pkgstream_dissect_corpus/.",
                file=sys.stderr,
            )
            return 2

        conn = _connect_write_db(args)

        def prog_extracted(msg: str) -> None:
            print(msg, file=sys.stderr)

        symtab = getattr(args, "symtab", False)
        max_bytes = int(args.max_file_mb * 1024 * 1024) if args.max_file_mb > 0 else 10**15

        for root in roots:
            prog_extracted(f"# indexing extracted tree {root} …")
            res = idx.build_index_for_extracted_tree(
                conn,
                root,
                max_file_bytes=max_bytes,
                skip_suffixes=not args.no_skip_suffixes,
                symtab=symtab,
                min_string_len=args.min_string_len,
                max_strings_per_file=args.max_strings_per_file,
                dwarf=getattr(args, "dwarf", None) is not None,
                progress=prog_extracted,
                **secret_kw,
            )
            if not res.get("ok"):
                prog_extracted(f"FAILED {root}: {res.get('error')}")
        conn.close()
        prog_extracted(f"# database {args.db}")
        return 0

    try:
        import dissect.squashfs  # noqa: F401
    except ImportError:
        print(
            "Missing dissect.squashfs — pip install dissect.squashfs (AGPL-3.0).",
            file=sys.stderr,
        )
        return 2
    try:
        import elftools  # noqa: F401
    except ImportError:
        print("Missing pyelftools — pip install pyelftools.", file=sys.stderr)
        return 2

    images = idx.guess_squashfs_files(args.image)
    if not images:
        print("No input images resolved from --image; pass files or directories.", file=sys.stderr)
        return 2

    conn = _connect_write_db(args)

    def prog(msg: str) -> None:
        print(msg, file=sys.stderr)

    symtab = getattr(args, "symtab", False)
    max_bytes = int(args.max_file_mb * 1024 * 1024) if args.max_file_mb > 0 else 10**15

    for img in images:
        prog(f"# indexing {img} …")
        res = idx.build_index_for_image(
            conn,
            img,
            max_file_bytes=max_bytes,
            skip_suffixes=not args.no_skip_suffixes,
            symtab=symtab,
            min_string_len=args.min_string_len,
            max_strings_per_file=args.max_strings_per_file,
            dwarf=getattr(args, "dwarf", None) is not None,
            jobs=max(1, int(getattr(args, "jobs", 1) or 1)),
            progress=prog,
            **secret_kw,
        )
        if not res.get("ok"):
            prog(f"FAILED {img}: {res.get('error')}")
    conn.close()
    prog(f"# database {args.db}")
    return 0


_SUBCOMMANDS = frozenset(
    {
        "grep",
        "cat",
        "locate",
        "find",
        "file-history",
        "index",
        "fs-grep",
        "collection",
        "xargs",
        "migrate-script-tlv",
    }
)
_INDEX_ONLY_FLAGS = frozenset(
    {
        "--build-index",
        "--migrate-db",
        "--list-collections",
        "--list-buildroot",
        "--list-secrets",
        "--secrets-summary",
        "--secrets-export",
        "--list-sboms",
        "--buildroot-diff",
        "--buildroot-versions-report",
        "--buildroot-origin",
        "--grype",
        "--grype-summary",
        "--explain-library",
        "--duplicates",
        "--file-info",
        "--versions",
        "--index-status",
        "--deps",
        "--format-summary",
        "--children",
        "--from-extracted",
    }
)


def _normalize_cli_argv(argv: List[str]) -> Tuple[Optional[str], List[str]]:
    """Return optional subcommand and argv for the main parser."""
    if not argv:
        return None, argv
    if argv[0] in _SUBCOMMANDS:
        return argv[0], argv[1:]
    if argv[0].startswith("-"):
        return "grep", argv
    if any(flag in argv for flag in _INDEX_ONLY_FLAGS):
        return None, argv
    if any(a.endswith(".pkgstream") for a in argv):
        return None, argv
    return "grep", argv


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    if str(repo) not in sys.path:
        sys.path.insert(0, str(repo))

    raw_argv = sys.argv[1:]
    subcmd, argv = _normalize_cli_argv(raw_argv)

    if subcmd == "cat":
        cat_ap = argparse.ArgumentParser(
            prog="corpus cat",
            description="Print file bytes for one or more corpus refs (pipe from grep/find --refs-only).",
        )
        cat_ap.add_argument("ref", nargs="?", help="Corpus ref; omit when piping refs on stdin.")
        cat_ap.add_argument("--db", metavar="PATH", default=None)
        _add_stdin_ref_args(cat_ap)
        cat_ap.add_argument(
            "--delimiter",
            action="store_true",
            help="With multiple stdin refs, print ``==> ref`` before each payload (default when N>1).",
        )
        cat_ap.add_argument(
            "--raw",
            action="store_true",
            help="Concatenate multiple files with no ``==>`` headers (binary-safe only if you know the content).",
        )
        args = cat_ap.parse_args(argv)
        args.db = str(_resolve_db_path(repo, args))
        return cmd_cat(repo, args)

    if subcmd == "xargs":
        xargs_ap = argparse.ArgumentParser(
            prog="corpus xargs",
            description="Run cat or locate once per ref on stdin (pipe from grep/find --refs-only).",
        )
        xargs_ap.add_argument(
            "action",
            nargs="?",
            default="cat",
            choices=("cat", "locate"),
            help="Per-ref action (default: cat).",
        )
        xargs_ap.add_argument("--db", metavar="PATH", default=None)
        _add_stdin_ref_args(xargs_ap)
        xargs_ap.add_argument(
            "--raw",
            action="store_true",
            help="For cat: no ``==> ref`` headers between files.",
        )
        xargs_ap.add_argument("--jsonl", action="store_true", help="For locate: JSON lines.")
        args = xargs_ap.parse_args(argv)
        args.db = str(_resolve_db_path(repo, args))
        return cmd_xargs(repo, args)

    if subcmd == "locate":
        loc_ap = argparse.ArgumentParser(prog="corpus locate", description="Resolve a corpus ref to paths.")
        loc_ap.add_argument("ref", help="Corpus ref from corpus grep.")
        loc_ap.add_argument("--db", metavar="PATH", default=None)
        loc_ap.add_argument("--jsonl", action="store_true")
        args = loc_ap.parse_args(argv)
        args.db = str(_resolve_db_path(repo, args))
        return cmd_locate(repo, args)

    if subcmd == "find":
        from corpus import index_db as idx

        find_ap = argparse.ArgumentParser(
            prog="corpus find",
            description="List indexed files by artifact kind and/or path glob.",
        )
        find_ap.add_argument(
            "globs",
            nargs="*",
            metavar="GLOB",
            help="Optional fnmatch path glob(s). Omit when using --kind alone.",
        )
        find_ap.add_argument(
            "--kind",
            action="append",
            choices=idx.FIND_KIND_CHOICES,
            dest="kinds",
            help="Filter by artifact type: tlv_script, tlv_file, squashfs, carrier_meta, uimage.",
        )
        find_ap.add_argument("--db", metavar="PATH", default=None)
        find_ap.add_argument("--collection", metavar="SLUG", default=None, help="Restrict to one collection (pkgstream:/nand:/buildroot:).")
        find_ap.add_argument("--file-type", default=None, metavar="SUBSTR", help="Require stored `file(1)` output to contain SUBSTR.")
        find_ap.add_argument("--limit", type=int, default=0, help="Stop after N matches (0 = unlimited).")
        find_ap.add_argument("--jsonl", action="store_true", help="JSON lines output.")
        find_ap.add_argument(
            "--refs-only",
            action="store_true",
            help="Print one corpus ref per line (pipe to ``corpus xargs cat`` or ``corpus cat``).",
        )
        find_ap.add_argument("-0", "--null", action="store_true", dest="null", help="With --refs-only: NUL-terminated refs.")
        args = find_ap.parse_args(argv)
        args.db = str(_resolve_db_path(repo, args))
        return cmd_find(repo, args)

    if subcmd == "file-history":
        fh_ap = argparse.ArgumentParser(
            prog="corpus file-history",
            description="Group indexed copies of a path by content hash and show firmware/collection coverage.",
        )
        fh_ap.add_argument("path", help="File path inside rootfs (e.g. etc/shadow); fnmatch if --glob or * in PATH.")
        fh_ap.add_argument("--db", metavar="PATH", default=None)
        fh_ap.add_argument(
            "--collection",
            metavar="SLUG",
            default=None,
            help="Restrict to one collection or bare firmware version.",
        )
        fh_ap.add_argument("--glob", action="store_true", help="Treat PATH as an fnmatch glob.")
        fh_ap.add_argument("--limit", type=int, default=0, help="Max distinct content hashes (0 = all).")
        fh_ap.add_argument("--preview", action="store_true", help="Include first indexed text line per variant.")
        fh_ap.add_argument(
            "--verbose",
            action="store_true",
            help="After each row, list collection slugs in that variant.",
        )
        fh_ap.add_argument("--jsonl", action="store_true", help="JSON lines (one object per content hash).")
        args = fh_ap.parse_args(argv)
        args.db = str(_resolve_db_path(repo, args))
        return cmd_file_history(repo, args)

    if subcmd == "migrate-script-tlv":
        from corpus.migrate_script_tlv import cmd_migrate_script_tlv

        mig_ap = argparse.ArgumentParser(
            prog="corpus migrate-script-tlv",
            description=(
                "One-off: rename indexed pkgstream SCRIPT TLV paths from legacy "
                "``_scripts/script_*@….bin`` to ``.sh`` and backfill text_lines."
            ),
        )
        mig_ap.add_argument("--db", metavar="PATH", default=None)
        mig_ap.add_argument(
            "--dry-run",
            action="store_true",
            help="Print planned renames without updating the index or on-disk files.",
        )
        mig_ap.add_argument(
            "--no-backfill-text",
            action="store_true",
            help="Skip text_lines backfill for scripts that had zero indexed lines.",
        )
        mig_ap.add_argument(
            "--verbose",
            action="store_true",
            help="Print every index row and on-disk rename (default: summary only).",
        )
        args = mig_ap.parse_args(argv)
        args.db = str(_resolve_db_path(repo, args))
        return cmd_migrate_script_tlv(repo, args)

    from corpus import index_db as idx

    ap = argparse.ArgumentParser(
        description="Grep dissect corpus dirs or SQLite index built from SquashFS images (dissect)."
    )
    ap.add_argument(
        "patterns",
        nargs="*",
        default=[],
        help="Search patterns (regex unless -F). Required unless --build-index.",
    )
    ap.add_argument(
        "--db",
        metavar="PATH",
        default=None,
        help="SQLite index path (default: work_corpus/corpus/index.sqlite; "
        "falls back to work_corpus/corpus_index.sqlite if only legacy exists).",
    )
    ap.add_argument(
        "--migrate-db",
        action="store_true",
        help="Move work_corpus/corpus_index.sqlite to work_corpus/corpus/index.sqlite and exit.",
    )
    ap.add_argument(
        "--build-index",
        action="store_true",
        help="Populate --db from --pkgstream, SquashFS --image(s), or --from-extracted trees.",
    )
    ap.add_argument(
        "--fresh",
        action="store_true",
        help="With --build-index: delete --db plus SQLite WAL/SHM files before indexing.",
    )
    ap.add_argument(
        "--from-extracted",
        action="store_true",
        help="With --build-index: index unpacked rootfs dirs (each --image or default "
        "work_corpus/pkgstream_dissect_corpus/*). Does not require dissect.squashfs.",
    )
    ap.add_argument(
        "--buildroot",
        metavar="TARGET",
        action="append",
        default=[],
        help="With --build-index: index a Buildroot target/ tree as buildroot:<profile> reference "
        "(repeatable). Use with --buildroot-profile (default 2011.11).",
    )
    ap.add_argument(
        "--buildroot-profile",
        metavar="PROFILE",
        default=None,
        help="Buildroot reference tag for --buildroot / --buildroot-diff (e.g. 2011.11, 2013.05).",
    )
    ap.add_argument(
        "--buildroot-diff",
        action="store_true",
        help="Compare --collection firmware files to indexed buildroot:<profile> by path and md5.",
    )
    ap.add_argument(
        "--buildroot-origin",
        metavar="PATH",
        default=None,
        help="Classify one firmware path (e.g. bin/busybox) vs Buildroot; requires --collection.",
    )
    ap.add_argument(
        "--list-buildroot",
        action="store_true",
        help="List indexed buildroot:* images in --db.",
    )
    ap.add_argument(
        "--list-collections",
        action="store_true",
        help="List firmware collection slugs (collection:*) in --db; use --jsonl for image keys.",
    )
    ap.add_argument(
        "--buildroot-versions-report",
        action="store_true",
        help="Per-collection table: etc/os-release vs ELF .comment (default bin/busybox).",
    )
    ap.add_argument(
        "--buildroot-profiles",
        metavar="PROFILE[,PROFILE…]",
        default=None,
        help="With --buildroot-versions-report: also diff each collection vs buildroot profiles.",
    )
    ap.add_argument(
        "--buildroot-elf",
        metavar="PATH",
        default="bin/busybox",
        help="Canonical ELF path for gcc/Buildroot .comment (default bin/busybox).",
    )
    ap.add_argument(
        "--pkgstream",
        metavar="PATH",
        action="append",
        default=[],
        help="With --build-index: ingest one or more .pkgstream carriers (install + conf/certs). "
        "Repeat the flag. TLV extract + embedded SquashFS/uImage; optional --collection groups "
        "keys in one DB. Staging: see --pkgstream-work.",
    )
    ap.add_argument(
        "--pkgstream-root",
        metavar="DIR",
        action="append",
        default=[],
        help="With --build-index: recursively ingest every .pkgstream under DIR. By default, "
        "carriers are grouped into collection slugs like version:11.5.1.532678 from internal "
        "version strings, with path-version fallback for config/cert carriers.",
    )
    ap.add_argument(
        "--no-pkgstream-version-collections",
        action="store_true",
        help="With --pkgstream-root: do not derive version collections; use --collection or the root directory name.",
    )
    ap.add_argument(
        "--pkgstream-report-json",
        metavar="PATH",
        default=None,
        help="With --pkgstream-root: write a JSON report containing version classification and indexing results.",
    )
    ap.add_argument(
        "--pkgstream-version-order",
        choices=("path", "asc", "desc"),
        default="path",
        help="With --pkgstream-root: order carriers before indexing. "
        "desc = highest firmware version first (Z→A); default = lexicographic relative path.",
    )
    ap.add_argument(
        "--sbom",
        action="store_true",
        help="With --build-index: generate Syft SBOM JSON for indexed SquashFS roots when syft is available.",
    )
    ap.add_argument(
        "--sbom-dir",
        metavar="DIR",
        default=None,
        help="With --sbom: directory for SBOM JSON, temporary mounts, and materialized fallback trees "
        "(default work_corpus/sbom).",
    )
    ap.add_argument(
        "--sbom-source",
        choices=("auto", "mount", "materialize"),
        default="auto",
        help="With --sbom: auto tries kernel mount, then squashfuse, then syft squashfs:PATH "
        "(no full rootfs extract). mount requires a mounted tree; materialize forces dissect extract.",
    )
    ap.add_argument(
        "--sbom-mount-root",
        metavar="DIR",
        default=None,
        help="With --sbom-source auto/mount: temporary mountpoint parent "
        "(default <sbom-dir>/mounts). Requires container mount privileges.",
    )
    ap.add_argument(
        "--syft-bin",
        metavar="PATH",
        default="syft",
        help="With --sbom: Syft executable name/path (default syft).",
    )
    ap.add_argument(
        "--sbom-format",
        metavar="FORMAT",
        default="syft-json",
        help="With --sbom: Syft output format (default syft-json; Grype can read it via sbom:PATH).",
    )
    ap.add_argument(
        "--secrets",
        action="store_true",
        help="With --build-index: run firmware-aware secret rules on each indexed file; "
        "store hits in secret_findings and write work_corpus/secrets/*.secrets.json.",
    )
    ap.add_argument(
        "--secrets-dir",
        metavar="DIR",
        default=None,
        help="With --secrets: report directory (default work_corpus/secrets).",
    )
    ap.add_argument(
        "--secrets-gitleaks",
        action="store_true",
        help="With --secrets: run gitleaks on mounted SquashFS trees (kernel or squashfuse; not squashfs: archive-only).",
    )
    ap.add_argument(
        "--gitleaks-bin",
        metavar="PATH",
        default="gitleaks",
        help="Gitleaks executable (default gitleaks).",
    )
    ap.add_argument(
        "--list-secrets",
        action="store_true",
        help="List per-image .secrets.json reports under --secrets-dir.",
    )
    ap.add_argument(
        "--secrets-summary",
        action="store_true",
        help="Summarize secret_findings rows in --db (by rule and severity).",
    )
    ap.add_argument(
        "--secrets-export",
        action="store_true",
        help="Write .secrets.json reports from DB secret_findings (after --build-index --secrets).",
    )
    ap.add_argument(
        "--secrets-term",
        metavar="TEXT",
        default=None,
        help="With --list-secrets: filter report filenames / image keys.",
    )
    ap.add_argument(
        "--flash",
        metavar="PATH",
        action="append",
        default=[],
        help="With --build-index: ingest Pace NAND/logical flash via paceflash. "
        "Default collection per file: nand:@<basename> (override with --collection).",
    )
    ap.add_argument(
        "--collection",
        metavar="SLUG",
        default=None,
        help="Collection slug (version:11.14.1.533857, nand:@FLASH.bin, …). "
        "Alone: summarize indexed carriers; with PATTERNs: search only that collection. "
        "Pkgstream build: groups carriers; --flash defaults to nand:@<basename> when omitted.",
    )
    ap.add_argument(
        "--pkgstream-work",
        metavar="DIR",
        default=None,
        help="Staging directory for --pkgstream (default work_corpus/pkgstream_corpus/<stem>).",
    )
    ap.add_argument(
        "--image",
        action="append",
        default=[],
        metavar="PATH",
        help="SquashFS blob / glob / carve dir (blob mode), or extracted rootfs dir (--from-extracted). Repeatable.",
    )
    ap.add_argument(
        "--roots",
        nargs="*",
        default=None,
        help="Filesystem corpus roots (dissect trees). Default: pkgstream_dissect_corpus subdirs.",
    )
    ap.add_argument(
        "-i",
        "--ignore-case",
        action="store_true",
        help="Case-insensitive match.",
    )
    ap.add_argument(
        "-F",
        "--fixed-strings",
        action="store_true",
        help="Treat patterns as literal strings.",
    )
    ap.add_argument(
        "--binary",
        action="store_true",
        help="(Filesystem mode) scan binary-ish files as UTF-8 replacement.",
    )
    ap.add_argument(
        "--max-file-mb",
        type=float,
        default=32.0,
        help="Max file size for indexing / filesystem scan (default 32; 0 = unlimited).",
    )
    ap.add_argument(
        "--no-skip-suffixes",
        action="store_true",
        help="Treat skipped suffixes (.bin, archives, images, etc.) as UTF-8 text in filesystem mode "
        "(ELF .so/.ko are always parsed via pyelftools). Index mode: include non-ELF ``.bin`` as text.",
    )
    ap.add_argument(
        "--jsonl",
        action="store_true",
        help="JSON lines output.",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Stop after N matches (0 = unlimited).",
    )
    ap.add_argument(
        "--refs-only",
        action="store_true",
        help="With index grep: print one corpus ref per line (pipe to ``corpus xargs cat``).",
    )
    ap.add_argument(
        "-0",
        "--null",
        action="store_true",
        dest="null",
        help="With --refs-only: NUL-terminated refs.",
    )
    ap.add_argument(
        "--symtab",
        action="store_true",
        help="Also index (with --build-index) or scan (filesystem mode, ELF files) ``.symtab`` names; large.",
    )
    ap.add_argument(
        "--min-string-len",
        type=int,
        default=4,
        metavar="N",
        help="Minimum printable run length for ELF section strings (default 4).",
    )
    ap.add_argument(
        "--max-strings-per-file",
        type=int,
        default=2000,
        metavar="N",
        help="With --build-index: cap raw printable strings stored per file (default 2000; 0 disables).",
    )
    ap.add_argument(
        "--dwarf",
        nargs="?",
        const="",
        default=None,
        metavar="PATH_OR_SYMBOL",
        help="With --build-index: index DWARF metadata. With --db: query indexed DWARF names/paths.",
    )
    ap.add_argument(
        "--jobs",
        type=int,
        default=1,
        metavar="N",
        help="With --build-index: parallel worker processes for ELF analysis inside SquashFS images (default 1).",
    )
    ap.add_argument(
        "--kind",
        action="append",
        choices=idx.SEARCH_KIND_CHOICES,
        dest="kinds",
        help="Limit index search to categories (repeatable). Default: text+strings+symbol+rodata+carrier_meta. "
        "Use tlv_script / tlv_file for pkgstream prefix TLV install scripts and FILE records; "
        "carrier_meta for pkgstream_metadata.json.",
    )
    ap.add_argument(
        "--path-glob",
        action="append",
        default=[],
        metavar="GLOB",
        help="Index-grep filter: only hits whose file path matches this glob (repeatable), "
        "e.g. --path-glob 'opentla4/sys1/*.txt' or --path-glob 'usr/lib/*.so*'.",
    )
    ap.add_argument(
        "--file-type",
        default=None,
        metavar="SUBSTR",
        help="Index-grep filter: require stored `file(1)` output to contain SUBSTR "
        "(case-insensitive), e.g. 'ELF 32-bit' or 'gzip compressed'.",
    )
    ap.add_argument(
        "--explain-library",
        metavar="NAME",
        default=None,
        help="With --db only: print which indexed ELFs provide this DT_SONAME and which "
        "list it as DT_NEEDED (e.g. libcm_server.so.0). Does not use search patterns.",
    )
    ap.add_argument(
        "--duplicates",
        action="store_true",
        help="With --db only: list duplicate files grouped by SHA-256.",
    )
    ap.add_argument(
        "--file-info",
        metavar="PATH_OR_SHA",
        default=None,
        help="With --db only: show file identity rows matching a path substring or SHA-256.",
    )
    ap.add_argument(
        "--versions",
        action="store_true",
        help="With --db only: list indexed version evidence.",
    )
    ap.add_argument(
        "--index-status",
        action="store_true",
        help="With --db only: show resume counters (completed pkgstreams, squashfs analyses, images).",
    )
    ap.add_argument(
        "--deps",
        metavar="LIB_OR_PATH",
        default=None,
        help="With --db only: query resolved DT_NEEDED dependency edges.",
    )
    ap.add_argument(
        "--format-summary",
        action="store_true",
        help="With --db only: summarize indexed binary/file formats.",
    )
    ap.add_argument(
        "--children",
        metavar="PATH_OR_SHA",
        default=None,
        help="With --db only: show artifact parent/child edges such as ext2 file -> SquashFS sysimage.",
    )
    ap.add_argument(
        "--list-sboms",
        action="store_true",
        help="List Syft SBOM JSON files under --sbom-dir (default work_corpus/sbom). "
        "Use with --collection and/or --sbom-term.",
    )
    ap.add_argument(
        "--sbom-term",
        metavar="TEXT",
        default=None,
        help="Filter --list-sboms / --grype targets by substring in SBOM filename or source hint.",
    )
    ap.add_argument(
        "--sbom-for",
        metavar="IMAGE_SUBSTR",
        default=None,
        help="Resolve SBOM file(s) for corpus image path(s) matching this substring "
        "(e.g. squashfs_0x00368538). Uses the default corpus DB unless --db is set.",
    )
    ap.add_argument(
        "--grype",
        action="store_true",
        help="Run grype against one or more SBOMs (--grype-sbom, --sbom-for, or --collection --grype-all).",
    )
    ap.add_argument(
        "--grype-all",
        action="store_true",
        help="With --grype: scan every SBOM in the selected --collection (or entire --sbom-dir).",
    )
    ap.add_argument(
        "--grype-sbom",
        action="append",
        default=[],
        metavar="PATH",
        help="With --grype: explicit .syft.json path (repeatable).",
    )
    ap.add_argument(
        "--grype-summary",
        action="store_true",
        help="Summarize existing .grype.json reports (no scan). Filter with --collection / --sbom-term.",
    )
    ap.add_argument(
        "--grype-bin",
        metavar="PATH",
        default="grype",
        help="Grype executable (default grype).",
    )
    ap.add_argument(
        "--grype-output",
        choices=("table", "json", "cyclonedx-json"),
        default="table",
        help="Grype output format (default table). Use json to write --grype-report / sidecar .grype.json.",
    )
    ap.add_argument(
        "--grype-report",
        metavar="PATH",
        default=None,
        help="With --grype-output json: write Grype JSON report (single SBOM only unless multiple .grype.json names are derived).",
    )
    ap.add_argument(
        "--grype-report-dir",
        metavar="DIR",
        default=None,
        help="With --grype-output json and multiple SBOMs: directory for per-SBOM .grype.json files.",
    )
    ap.add_argument(
        "--grype-fail-on",
        choices=("none", "negligible", "low", "medium", "high", "critical"),
        default=None,
        help="Pass --fail-on to grype (non-zero exit when matching vulns are present).",
    )
    ap.add_argument(
        "--grype-db-update",
        action="store_true",
        help="Pass --db-update to grype before scanning.",
    )
    ap.add_argument(
        "--grype-only-fixed",
        action="store_true",
        help="Pass --only-fixed to grype.",
    )
    ap.add_argument(
        "--grype-skip-existing",
        action="store_true",
        help="Skip grype when a .grype.json report exists and is newer than the SBOM.",
    )
    ap.add_argument(
        "--grype-quiet",
        action="store_true",
        help="Pass -q to grype.",
    )
    ap.add_argument(
        "--grype-timeout",
        type=int,
        default=900,
        metavar="SEC",
        help="Grype subprocess timeout per SBOM (default 900).",
    )

    args = ap.parse_args(argv)

    if getattr(args, "migrate_db", False):
        from corpus.paths import migrate_legacy_corpus_db

        dest = migrate_legacy_corpus_db(repo)
        print(str(dest))
        return 0

    if _uses_index_db(args) or _collection_only_query(args):
        from corpus.paths import ensure_corpus_db_parent

        db_path = _resolve_db_path(repo, args)
        args.db = str(db_path)
        if args.build_index:
            ensure_corpus_db_parent(db_path)
        elif _require_db_file(repo, args) != 0:
            return 2

    if _collection_only_query(args):
        return cmd_collection_show(repo, args)

    if args.build_index:
        need_image = (
            not (getattr(args, "pkgstream", None) or [])
            and not (getattr(args, "pkgstream_root", None) or [])
            and not (getattr(args, "flash", None) or [])
            and not (getattr(args, "buildroot", None) or [])
            and not args.from_extracted
        )
        if need_image and not args.image:
            print(
                "--build-index requires --image unless --pkgstream, --pkgstream-root, --flash, "
                "--buildroot, or --from-extracted is set.",
                file=sys.stderr,
            )
            return 2
        return cmd_build_index(repo, args)

    if _uses_index_db(args) and args.patterns:
        return cmd_index_search(repo, args)

    if _uses_index_db(args) and not args.patterns:
        if getattr(args, "explain_library", None):
            return cmd_explain_library(repo, args)
        if getattr(args, "duplicates", False):
            return cmd_duplicates(repo, args)
        if getattr(args, "file_info", None):
            return cmd_file_info(repo, args)
        if getattr(args, "versions", False):
            return cmd_versions(repo, args)
        if getattr(args, "index_status", False):
            return cmd_index_status(repo, args)
        if getattr(args, "deps", None):
            return cmd_deps(repo, args)
        if getattr(args, "format_summary", False):
            return cmd_format_summary(repo, args)
        if getattr(args, "dwarf", None) not in (None, ""):
            return cmd_dwarf(repo, args)
        if getattr(args, "children", None):
            return cmd_children(repo, args)
        if getattr(args, "list_collections", False):
            return cmd_list_collections(repo, args)
        if getattr(args, "list_buildroot", False):
            return cmd_list_buildroot(repo, args)
        if getattr(args, "buildroot_diff", False):
            return cmd_buildroot_diff(repo, args)
        if getattr(args, "buildroot_origin", None):
            return cmd_buildroot_origin(repo, args)
        if getattr(args, "buildroot_versions_report", False):
            return cmd_buildroot_versions_report(repo, args)

    if getattr(args, "list_sboms", False):
        return cmd_list_sboms(repo, args)
    if getattr(args, "list_secrets", False):
        return cmd_list_secrets(repo, args)
    if getattr(args, "secrets_summary", False):
        return cmd_secrets_summary(repo, args)
    if getattr(args, "secrets_export", False):
        return cmd_secrets_export(repo, args)
    if getattr(args, "grype", False) or getattr(args, "grype_summary", False):
        return cmd_grype(repo, args)

    if not args.patterns:
        print(
            "Provide patterns (``python -m corpus grep PATTERN``), or use --build-index.",
            file=sys.stderr,
        )
        return 2

    return cmd_fs_grep(repo, args)


if __name__ == "__main__":
    raise SystemExit(main())
