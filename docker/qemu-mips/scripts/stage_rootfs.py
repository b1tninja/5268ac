#!/usr/bin/env python3
"""
Stage a minimal MIPS sysroot from an indexed SquashFS carve for qemu-user (-L).

Example (inside qemu-mips container):
  python3 docker/qemu-mips/scripts/stage_rootfs.py \\
    --collection version:11.14.1.533857 \\
    --paths bin/busybox usr/lib/libdhcp.so.0.0.0 lib \\
    --out work_corpus/qemu_mips/sysroots/version_11.14.1.533857
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from corpus.index_db import collection_slug_for_fs
from lib2spy.pkgstream_corpus import extract_squashfs_dissect_tree, iter_squashfs_files

REPO = Path(__file__).resolve().parents[3]


def _squashfs_for_collection(collection: str) -> Path:
    """Pick the install-carrier SquashFS carve under pkgstream_corpus_by_version."""
    base = REPO / "work_corpus" / "pkgstream_corpus_by_version" / collection_slug_for_fs(collection)
    if not base.is_dir():
        raise SystemExit(
            f"Staged corpus tree missing: {base}\n"
            "  Run pkgstream ingest / index-release first (see reference/tools.md)."
        )
    candidates = sorted(base.glob("*/embedded/squashfs_*.bin"))
    if not candidates:
        raise SystemExit(f"No squashfs_*.bin under {base}/*/embedded/")
    for pref in ("0001_", "install"):
        for p in candidates:
            if pref in p.parents[1].name:
                return p
    return candidates[0]


def _prefix_ok(rel: str, prefixes: tuple[str, ...]) -> bool:
    if not prefixes:
        return True
    for pref in prefixes:
        if rel == pref or rel.startswith(pref.rstrip("/") + "/"):
            return True
    return False


def stage_from_squashfs(
    squashfs: Path,
    out_root: Path,
    *,
    paths: tuple[str, ...],
    full_tree: bool,
) -> dict:
    out_root.mkdir(parents=True, exist_ok=True)
    if full_tree:
        return extract_squashfs_dissect_tree(squashfs, out_root)

    written = 0
    for rel, data in iter_squashfs_files(squashfs):
        if not _prefix_ok(rel, paths):
            continue
        dest = out_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        written += 1
    return {
        "ok": True,
        "mode": "selective",
        "files_written": written,
        "out_root": str(out_root.resolve()),
        "squashfs_path": str(squashfs.resolve()),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--collection", required=True, help="e.g. version:11.14.1.533857")
    ap.add_argument(
        "--squashfs",
        type=Path,
        default=None,
        help="Override SquashFS carve path (skip corpus lookup)",
    )
    ap.add_argument(
        "--paths",
        nargs="*",
        default=("bin", "lib", "usr/lib", "etc/ld.so.cache"),
        help="Path prefixes to copy (selective mode)",
    )
    ap.add_argument(
        "--full-tree",
        action="store_true",
        help="Extract entire SquashFS (slow; use for broad testing)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Sysroot output dir (default: work_corpus/qemu_mips/sysroots/<slug>)",
    )
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    slug = args.collection.replace(":", "_")
    out = args.out or (REPO / "work_corpus" / "qemu_mips" / "sysroots" / slug)
    sq = args.squashfs or _squashfs_for_collection(args.collection)

    result = stage_from_squashfs(
        sq,
        out,
        paths=tuple(args.paths),
        full_tree=args.full_tree,
    )
    default_link = REPO / "work_corpus" / "qemu_mips" / "sysroots" / "default"
    default_marker = REPO / "work_corpus" / "qemu_mips" / "sysroots" / "default.txt"
    default_link.parent.mkdir(parents=True, exist_ok=True)
    try:
        if default_link.is_symlink() or (
            default_link.exists() and not default_link.is_dir()
        ):
            default_link.unlink(missing_ok=True)
        if not default_link.exists():
            default_link.symlink_to(out.name, target_is_directory=True)
        default_ref = str(default_link)
    except OSError:
        default_marker.write_text(str(out.resolve()) + "\n", encoding="utf-8")
        default_ref = str(default_marker)

    payload = {**result, "collection": args.collection, "default_sysroot": default_ref}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"staged {payload.get('files_written', '?')} files -> {out}")
        print(f"default sysroot -> {default_ref}")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
