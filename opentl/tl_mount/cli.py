"""Command-line interface for :func:`~opentl.tl_mount.mount_flash_image`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence


def populate_tl_mount_arguments(p: argparse.ArgumentParser) -> None:
    """Attach tl-mount flags to ``p`` (standalone parser or shared subparser)."""
    p.add_argument(
        "flash_file",
        type=str,
        help="Logical NAND plane image, or full-chip Pace raw dump (inline / flat-tail) for auto-spare",
    )
    p.add_argument(
        "--out-bbm",
        required=False,
        default=None,
        metavar="PATH",
        help="Optional: write TL BBM map JSON (schema from opentl.tl_bbm.SCHEMA_V1) to this path (otherwise use --json for stdout)",
    )
    p.add_argument(
        "--logical-prefix-bytes",
        type=lambda x: int(x, 0),
        default=None,
        metavar="N",
        help="Cap logical prefix read (default: min(1012*128KiB, file size after nand offset))",
    )
    p.add_argument(
        "--nand-logical-offset",
        type=lambda x: int(x, 0),
        default=None,
        metavar="N",
        help=(
            "Byte offset in this file where the linear logical-plane read starts for BBM (default: 0). "
            "kernel_replay virt→phys uses chip-linear indices into the prefix buffer; use a nonzero "
            "offset only when file byte 0 is not plane byte 0 (exotic layouts). Must match how the "
            "paired --spare stream was built."
        ),
    )
    p.add_argument(
        "--spare",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Optional flat spare/OOB stream (raw_blocks×64×64 B). Omit for full-chip Pace-class "
            "raw dumps (inline 2048+64 or flat-tail): spare is extracted via unand LogicalPlane."
        ),
    )
    p.add_argument("--json", action="store_true", help="Print map JSON to stdout")


def register_tl_mount_subparser(sub: Any) -> argparse.ArgumentParser:
    """Register ``tl-mount`` on an ``argparse`` subparser group."""
    p = sub.add_parser(
        "tl-mount",
        help="OpenTL offline BBM JSON (kernel_replay_v1: logical + spare, or raw dump with auto-spare)",
    )
    populate_tl_mount_arguments(p)
    return p


def run_tl_mount_from_args(args: argparse.Namespace) -> int:
    """Run tl-mount from a parsed namespace (exit code: 0 ok, 1 error)."""
    from opentl.open_tl import OpenTL
    from opentl.tl_bbm import block_map_to_json_dict
    from opentl.tl_mount import mount_flash_image, resolve_nand_logical_offset_for_mount

    ot_keep: OpenTL | None = None
    try:
        flash_path = Path(args.flash_file).expanduser().resolve()
        if args.spare:
            spare_blob = Path(args.spare).expanduser().resolve().read_bytes()
            nand_off = resolve_nand_logical_offset_for_mount(flash_path, args.nand_logical_offset)
            bmap = mount_flash_image(
                str(flash_path),
                logical_prefix_bytes=args.logical_prefix_bytes,
                nand_logical_offset=nand_off,
                spare_bytes=spare_blob,
            )
        else:
            ot_keep = OpenTL.from_flash_path_for_tl_mount(
                str(flash_path),
                spare_path=None,
                nand_logical_offset=args.nand_logical_offset,
                logical_prefix_bytes=args.logical_prefix_bytes,
            )
            bmap = ot_keep.block_map
            bmap.notes.append("tl-mount: auto spare via unand LogicalPlane")
    except Exception as e:
        print(f"tl-mount: {e}", file=sys.stderr)
        return 1
    payload = block_map_to_json_dict(bmap)
    if args.out_bbm:
        outp = Path(args.out_bbm)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Wrote {outp}", file=sys.stderr)
    if args.json:
        print(json.dumps(payload, indent=2))
    elif not args.out_bbm:
        print(f"tl-mount: mode={bmap.mode} virt_blocks={len(bmap.virt_to_phys_block)}")
        for n in bmap.notes[:12]:
            note = n.encode("ascii", errors="replace").decode("ascii")
            print(f"  note: {note}")
        print("  (pass --json for full map, or --out-bbm PATH to write JSON)", file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """
    Standalone entry: ``python -m opentl tl-mount …`` or ``python -m opentl.tl_mount …``.

    ``argv`` defaults to ``sys.argv[1:]`` (no script name).
    """
    if argv is None:
        argv = sys.argv[1:]
    ap = argparse.ArgumentParser(
        prog="python -m opentl tl-mount",
        description=(
            "OpenTL offline BBM JSON via kernel_replay_v1. "
            "Pass a logical-plane image plus --spare, or a full-chip Pace raw dump (inline / flat-tail) "
            "and omit --spare to extract OOB via unand LogicalPlane."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    populate_tl_mount_arguments(ap)
    args = ap.parse_args(list(argv))
    return run_tl_mount_from_args(args)


__all__ = [
    "main",
    "populate_tl_mount_arguments",
    "register_tl_mount_subparser",
    "run_tl_mount_from_args",
]
