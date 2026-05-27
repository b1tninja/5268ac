#!/usr/bin/env python3
"""Mirror known gateway firmware URLs from the repository ``pkgstreams`` list."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


DEFAULT_HOST = "gateway.c01.sbcglobal.net"


@dataclass(frozen=True)
class MirrorEntry:
    source: str
    rel_path: str
    url: str
    is_pkgstream: bool


def clean_line(line: str) -> str:
    line = line.strip()
    if not line or line.startswith("#"):
        return ""
    if "|" in line and line.split("|", 1)[0].strip().isdigit():
        line = line.split("|", 1)[1].strip()
    return line


def url_for_source(source: str, *, scheme: str) -> str:
    if source.startswith(("http://", "https://")):
        return quote(source, safe=":/?&=%#[]@!$&'()*+,;")
    return f"{scheme}://{quote(source, safe='/:')}"


def iter_entries(
    pkgstreams_path: Path,
    *,
    host: str = DEFAULT_HOST,
    scheme: str = "https",
    only_pkgstream: bool = True,
) -> Iterable[MirrorEntry]:
    seen: set[str] = set()
    for raw in pkgstreams_path.read_text(encoding="utf-8").splitlines():
        source = clean_line(raw)
        if not source:
            continue
        without_scheme = source.split("://", 1)[1] if "://" in source else source
        if not without_scheme.startswith(f"{host}/"):
            continue
        rel_path = without_scheme[len(host) + 1 :]
        is_pkgstream = rel_path.lower().endswith(".pkgstream")
        if only_pkgstream and not is_pkgstream:
            continue
        if rel_path in seen:
            continue
        seen.add(rel_path)
        yield MirrorEntry(
            source=source,
            rel_path=rel_path,
            url=url_for_source(source, scheme=scheme),
            is_pkgstream=is_pkgstream,
        )


def download_one(
    entry: MirrorEntry,
    out_root: Path,
    *,
    timeout_s: float,
    retries: int,
    force: bool,
    seed_root: Path | None = None,
) -> dict[str, object]:
    dst = out_root / entry.rel_path
    if dst.is_file() and dst.stat().st_size > 0 and not force:
        return {
            "status": "skipped",
            "reason": "exists",
            "url": entry.url,
            "path": str(dst),
            "bytes": dst.stat().st_size,
        }
    dst.parent.mkdir(parents=True, exist_ok=True)
    if seed_root is not None and not force:
        seeded = seed_root / entry.rel_path
        if seeded.is_file() and seeded.stat().st_size > 0:
            shutil.copy2(seeded, dst)
            return {
                "status": "seeded",
                "url": entry.url,
                "path": str(dst),
                "seed": str(seeded),
                "bytes": dst.stat().st_size,
            }
    tmp = dst.with_name(dst.name + ".part")
    last_error = ""
    for attempt in range(1, retries + 2):
        try:
            req = Request(entry.url, headers={"User-Agent": "5268ac-corpus-runtime/1"})
            with urlopen(req, timeout=timeout_s) as resp, tmp.open("wb") as f:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
            tmp.replace(dst)
            return {
                "status": "downloaded",
                "url": entry.url,
                "path": str(dst),
                "bytes": dst.stat().st_size,
            }
        except (HTTPError, URLError, TimeoutError, OSError) as e:
            last_error = f"{type(e).__name__}: {e}"
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            if attempt <= retries:
                time.sleep(min(2**attempt, 10))
    return {"status": "failed", "url": entry.url, "path": str(dst), "error": last_error}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Mirror known gateway firmware URLs.")
    ap.add_argument("--pkgstreams", type=Path, default=Path("pkgstreams"), help="URL list file.")
    ap.add_argument(
        "--out",
        type=Path,
        default=Path(DEFAULT_HOST),
        help=f"Mirror root for paths below {DEFAULT_HOST}.",
    )
    ap.add_argument("--host", default=DEFAULT_HOST, help="Host prefix expected in pkgstreams.")
    ap.add_argument("--scheme", default="https", choices=("https", "http"), help="Download URL scheme.")
    ap.add_argument(
        "--all-files",
        action="store_true",
        help="Mirror every listed firmware URL, not only entries ending in .pkgstream.",
    )
    ap.add_argument("--dry-run", action="store_true", help="Print planned entries without downloading.")
    ap.add_argument("--force", action="store_true", help="Redownload even when destination exists.")
    ap.add_argument(
        "--seed",
        type=Path,
        default=None,
        help="Existing mirror root to copy from before downloading missing files.",
    )
    ap.add_argument("--limit", type=int, default=0, help="Limit entries, useful for smoke tests.")
    ap.add_argument("--timeout-s", type=float, default=60.0, help="Per-request timeout.")
    ap.add_argument("--retries", type=int, default=2, help="Retries after the first failure.")
    ap.add_argument("--jsonl", action="store_true", help="Emit JSON lines.")
    args = ap.parse_args(argv)

    entries = list(
        iter_entries(
            args.pkgstreams,
            host=args.host,
            scheme=args.scheme,
            only_pkgstream=not args.all_files,
        )
    )
    if args.limit:
        entries = entries[: args.limit]

    if args.dry_run:
        for entry in entries:
            row = {
                "url": entry.url,
                "path": str(args.out / entry.rel_path),
                "is_pkgstream": entry.is_pkgstream,
            }
            print(json.dumps(row, ensure_ascii=False) if args.jsonl else f"{row['url']} -> {row['path']}")
        print(f"# planned {len(entries)} entries", file=sys.stderr)
        return 0

    failures = 0
    for entry in entries:
        row = download_one(
            entry,
            args.out,
            timeout_s=args.timeout_s,
            retries=args.retries,
            force=args.force,
            seed_root=args.seed,
        )
        if row["status"] == "failed":
            failures += 1
        print(json.dumps(row, ensure_ascii=False) if args.jsonl else f"{row['status']}: {row['path']}")
    print(f"# mirrored {len(entries) - failures}/{len(entries)} entries to {args.out}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
