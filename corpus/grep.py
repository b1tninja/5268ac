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
  - ``--build-index --db PATH --flash FLASH.bin`` — Pace NAND/logical flash via paceflash.
  - ``--build-index --db PATH --image CARVED.bin`` — raw SquashFS blob(s) via dissect.
  - ``--build-index --from-extracted`` — already-unpacked trees under ``pkgstream_dissect_corpus/``.
  - ``--db PATH patterns…`` — grep the index (text + symbols + rodata strings).

Examples:
  python tools/squashfs_corpus_grep.py rwdata /rwdata/cm mount tmpfs
  python tools/squashfs_corpus_grep.py --build-index --db cm.sqlite \\
      --collection firmware_11.5.1.532678/11.5.1.532678 \\
      --pkgstream firmware/.../install.pkgstream \\
      --pkgstream firmware/.../conf.pkgstream
  python tools/squashfs_corpus_grep.py --build-index --db cm.sqlite \\
      --image carve/tlpart_squashfs_0x03ff5080_8a358306.bin
  python tools/squashfs_corpus_grep.py --db cm.sqlite -i rwdata cmd
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple


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

    conn = idx.connect_db(args.db)
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

    conn = idx.connect_db(args.db)
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

    conn = idx.connect_db(args.db)
    rows = idx.file_info(conn, args.file_info, limit=args.limit or 50)
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def cmd_versions(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    conn = idx.connect_db(args.db)
    rows = idx.version_rows(conn, limit=args.limit or 200)
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def cmd_deps(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    conn = idx.connect_db(args.db)
    rows = idx.dependency_rows(conn, args.deps, limit=args.limit or 200)
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def cmd_format_summary(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    conn = idx.connect_db(args.db)
    rows = idx.format_summary(conn)
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def cmd_dwarf(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    term = args.dwarf or ""
    conn = idx.connect_db(args.db)
    rows = idx.dwarf_rows(conn, term, limit=args.limit or 200)
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def cmd_children(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    conn = idx.connect_db(args.db)
    rows = idx.child_edges(conn, args.children, limit=args.limit or 200)
    conn.close()
    _print_rows(rows, jsonl=args.jsonl)
    return 0


def cmd_index_search(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

    kinds = frozenset(args.kinds or ["text", "symbol", "rodata"])
    conn = idx.connect_db(args.db)
    total = 0
    coll = getattr(args, "collection", None)
    for hit in idx.search_index(
        conn,
        args.patterns,
        fixed=args.fixed_strings,
        ignore_case=args.ignore_case,
        kinds=kinds,
        limit=args.limit or 0,
        collection_slug=coll,
    ):
        total += 1
        if args.jsonl:
            print(
                json.dumps(
                    {
                        "kind": hit.kind,
                        "image": hit.image_path,
                        "path": hit.path,
                        **hit.detail,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
        else:
            print(hit.format_line())
    conn.close()
    return 0


def cmd_build_index(repo: Path, args: argparse.Namespace) -> int:
    from corpus import index_db as idx

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

    if getattr(args, "fresh", False):
        dbp = Path(args.db).expanduser().resolve()
        for p in (dbp, Path(str(dbp) + "-wal"), Path(str(dbp) + "-shm")):
            try:
                p.unlink()
            except FileNotFoundError:
                pass

    if pkg_root_list:
        if pkg_list or from_extracted or args.image or flash_list:
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

        conn = idx.connect_db(args.db)

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
                prog_root("# collections: detected firmware versions (internal, path fallback, then version:unknown)")
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
                syft_bin=args.syft_bin,
                sbom_format=args.sbom_format,
                display_base=repo,
                progress=prog_root,
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

        conn = idx.connect_db(args.db)

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
                syft_bin=args.syft_bin,
                sbom_format=args.sbom_format,
                display_base=repo,
                progress=prog_pkg,
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
        conn = idx.connect_db(args.db)

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
            prog_flash(f"# paceflash corpus index: {flash}")
            res = idx.build_index_from_flash(
                conn,
                flash,
                collection_slug=collection_raw,
                max_file_bytes=max_bytes,
                skip_suffixes=not args.no_skip_suffixes,
                symtab=symtab,
                min_string_len=args.min_string_len,
                max_strings_per_file=args.max_strings_per_file,
                dwarf=getattr(args, "dwarf", None) is not None,
                sbom_dir=(
                    sbom_dir / idx.collection_slug_for_fs(collection_raw)
                    if sbom_dir is not None and collection_raw
                    else sbom_dir
                ),
                syft_bin=args.syft_bin,
                sbom_format=args.sbom_format,
                progress=prog_flash,
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

        conn = idx.connect_db(args.db)

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

    conn = idx.connect_db(args.db)

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
        )
        if not res.get("ok"):
            prog(f"FAILED {img}: {res.get('error')}")
    conn.close()
    prog(f"# database {args.db}")
    return 0


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    if str(repo) not in sys.path:
        sys.path.insert(0, str(repo))

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
        help="SQLite index path (search or --build-index).",
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
        "--sbom",
        action="store_true",
        help="With --build-index: generate Syft SBOM JSON for indexed SquashFS roots when syft is available.",
    )
    ap.add_argument(
        "--sbom-dir",
        metavar="DIR",
        default=None,
        help="With --sbom: directory for materialized rootfs trees and SBOM JSON "
        "(default work_corpus/sbom).",
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
        "--flash",
        metavar="PATH",
        action="append",
        default=[],
        help="With --build-index: ingest one or more Pace NAND/logical flash dumps through paceflash.",
    )
    ap.add_argument(
        "--collection",
        metavar="SLUG",
        default=None,
        help="Release / bundle label for the corpus (e.g. firmware_11.5.1.532678/11.5.1.532678). "
        "Build: prefixes image keys so multiple --pkgstream files share one --db. "
        "Search: limit hits to that collection.",
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
        choices=("text", "symbol", "rodata", "soname", "needed"),
        dest="kinds",
        help="Limit index search to categories (repeatable). Default: text+symbol+rodata. "
        "Use soname/needed for DT_SONAME / DT_NEEDED (after rebuild-index).",
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

    args = ap.parse_args()

    if args.build_index:
        if not args.db:
            print("--build-index requires --db", file=sys.stderr)
            return 2
        need_image = (
            not (getattr(args, "pkgstream", None) or [])
            and not (getattr(args, "pkgstream_root", None) or [])
            and not (getattr(args, "flash", None) or [])
            and not args.from_extracted
        )
        if need_image and not args.image:
            print(
                "--build-index requires --image unless --pkgstream, --pkgstream-root, --flash, "
                "or --from-extracted is set.",
                file=sys.stderr,
            )
            return 2
        return cmd_build_index(repo, args)

    if args.db:
        if getattr(args, "explain_library", None):
            return cmd_explain_library(repo, args)
        if getattr(args, "duplicates", False):
            return cmd_duplicates(repo, args)
        if getattr(args, "file_info", None):
            return cmd_file_info(repo, args)
        if getattr(args, "versions", False):
            return cmd_versions(repo, args)
        if getattr(args, "deps", None):
            return cmd_deps(repo, args)
        if getattr(args, "format_summary", False):
            return cmd_format_summary(repo, args)
        if getattr(args, "dwarf", None) not in (None, ""):
            return cmd_dwarf(repo, args)
        if getattr(args, "children", None):
            return cmd_children(repo, args)
        if not args.patterns:
            print(
                "Search mode requires at least one pattern or an inspection flag.",
                file=sys.stderr,
            )
            return 2
        return cmd_index_search(repo, args)

    if not args.patterns:
        print("Provide patterns, or use --build-index with --db and --image.", file=sys.stderr)
        return 2

    return cmd_fs_grep(repo, args)


if __name__ == "__main__":
    raise SystemExit(main())
