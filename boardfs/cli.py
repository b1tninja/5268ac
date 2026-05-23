"""``python -m boardfs`` — virtual BBM introspection (virt map + NAND page table rows)."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from opentl.logical_opentl_session import LogicalOpenTLSession
from opentl.tl_bbm import TL_PHYS_BLOCK_HOLE

from boardfs.cli_flash import apply_opentl_cli_env, build_flash_probe_parent, open_fs_registry_for_cli
from boardfs.registry import FsRegistry, read_linear_plane_prefix
from unand.mtd import DEFAULT_MTDPARTS


def _virt_map_dict(reg: FsRegistry) -> dict[str, Any]:
    m = reg.attached_block_map
    out: dict[str, Any] = {
        "has_attached_block_map": m is not None,
        "memory_backed": reg.flash.logical_image is not None,
    }
    if m is None:
        return out
    holes = sum(1 for pb in m.virt_to_phys_block if pb == TL_PHYS_BLOCK_HOLE)
    blob = reg.tlpart_tl_scan_bytes
    head_hash: str | None = None
    if blob:
        head_hash = hashlib.sha256(blob[:4096]).hexdigest()[:16]
    vb = int(m.geometry.virt_blocks)
    n_head = min(32, vb)
    tail_from = max(0, vb - 8)
    pairs_head = [{"virt": i, "phys": m.virt_to_phys_block[i]} for i in range(n_head)]
    pairs_tail = [{"virt": i, "phys": m.virt_to_phys_block[i]} for i in range(tail_from, vb) if i >= n_head]
    out.update(
        {
            "bbm_mode": m.mode,
            "logical_prefix_bytes": m.logical_prefix_bytes,
            "nand_logical_offset": m.nand_logical_offset,
            "virt_blocks": vb,
            "erase_bytes": m.geometry.erase_bytes,
            "hole_erase_blocks": holes,
            "tlpart_tl_scan_bytes_len": len(blob or b""),
            "tlpart_tl_scan_head_sha256_16": head_hash,
            "virt_to_phys_head": pairs_head,
            "virt_to_phys_tail": pairs_tail,
        }
    )
    return out


def cmd_virt_map(args: argparse.Namespace) -> int:
    apply_opentl_cli_env(debug_log=args.debug_log, tl_probe_report=args.tl_probe_report)
    cmd = args.cmdline or f"quiet rw {DEFAULT_MTDPARTS}"
    p = Path(args.flash).expanduser().resolve()
    man_out: dict[str, Any] | None = None
    with open_fs_registry_for_cli(
        p,
        cmd,
        nand_translate=args.nand_translate,
        nand_mode=args.nand_mode,
    ) as (reg, man, _ot):
        if man is not None:
            man_out = dict(man)
        d = _virt_map_dict(reg)
        if man and man.get("tl_bbm_attach_error") and not man.get("tl_bbm_attached"):
            d["tl_bbm_attach_error"] = man["tl_bbm_attach_error"]
    if man_out is not None:
        d["nand_translate_manifest"] = man_out
    if args.json:
        print(json.dumps(d, indent=2, default=str))
    else:
        for k, v in d.items():
            print(f"{k}: {v}")
    return 0


def cmd_page_table(args: argparse.Namespace) -> int:
    apply_opentl_cli_env(debug_log=args.debug_log, tl_probe_report=args.tl_probe_report)
    cmd = args.cmdline or f"quiet rw {DEFAULT_MTDPARTS}"
    p = Path(args.flash).expanduser().resolve()
    with open_fs_registry_for_cli(
        p,
        cmd,
        nand_translate=args.nand_translate,
        nand_mode=args.nand_mode,
    ) as (reg, man, ot_session):
        if reg.attached_block_map is None:
            if man:
                err = man.get("tl_bbm_attach_error", "unknown")
                print(
                    f"error: no BBM attached after NAND translate ({err}). "
                    "Check flat spare from nand-translate, or supply BlockMapBuild.from_dict(...) "
                    "and attach via FsRegistry(block_map=...) / attach_open_tl_bbm.",
                    file=sys.stderr,
                )
            else:
                print(
                    "error: no BBM attached (use --nand-translate on a full-chip dump with spare extraction, "
                    "or construct FsRegistry with block_map= in Python)",
                    file=sys.stderr,
                )
            return 2
        return _emit_page_table(reg, args, ot_session=ot_session)


def _emit_page_table(
    reg: FsRegistry,
    args: argparse.Namespace,
    *,
    ot_session: LogicalOpenTLSession | None = None,
) -> int:
    m = reg.attached_block_map
    if m is None:
        print("error: no attached BlockMapBuild", file=sys.stderr)
        return 2
    if ot_session is not None and ot_session.block_map is m:
        rows = ot_session.nand_page_rows(
            int(args.virt_start),
            int(args.virt_len),
            max_rows=int(args.max_rows),
        )
    else:
        lim = int(m.logical_prefix_bytes)
        prefix = read_linear_plane_prefix(reg.flash, lim)
        session = LogicalOpenTLSession.from_linear_prefix_bytes(prefix, m)
        rows = session.nand_page_rows(
            int(args.virt_start),
            int(args.virt_len),
            max_rows=int(args.max_rows),
        )
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "virt_byte": r.virt_byte,
                        "virt_byte_span": r.virt_byte_span,
                        "virt_block": r.virt_block,
                        "offset_in_erase": r.offset_in_erase,
                        "nand_page_index": r.nand_page_index,
                        "sector_in_page": r.sector_in_page,
                        "byte_in_sector": r.byte_in_sector,
                        "hole": r.hole,
                        "phys_byte": r.phys_byte,
                    }
                    for r in rows
                ],
                indent=2,
            )
        )
        return 0
    hdr = f"{'virt':>10} {'span':>5} {'vblk':>5} {'pg':>4} {'hole':>5} {'phys':>12}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        phys = "—" if r.phys_byte is None else f"{r.phys_byte:#010x}"
        print(
            f"{r.virt_byte:#010x} {r.virt_byte_span:5d} {r.virt_block:5d} {r.nand_page_index:4d} "
            f"{str(r.hole):>5} {phys:>12}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    flash_parent = build_flash_probe_parent()
    ap = argparse.ArgumentParser(prog="boardfs", description="Boardfs / OpenTL BBM CLI tools")
    sub = ap.add_subparsers(dest="command", required=True)

    vm = sub.add_parser(
        "virt-map",
        parents=[flash_parent],
        help="Print virt→phys BBM summary (and optional TL scan hash)",
    )
    vm.add_argument("flash", type=str, help="Flash image path")
    vm.add_argument("--json", action="store_true", help="Emit JSON")
    vm.set_defaults(func=cmd_virt_map)

    pt = sub.add_parser(
        "page-table",
        parents=[flash_parent],
        help="Print NAND page rows for a virtual byte span",
    )
    pt.add_argument("flash", type=str, help="Flash image path")
    pt.add_argument("--virt-start", type=int, default=0, help="Virtual TL disk byte offset (default 0)")
    pt.add_argument(
        "--virt-len",
        type=int,
        default=8192,
        metavar="N",
        help="Span length in virtual bytes (default 8192)",
    )
    pt.add_argument("--max-rows", type=int, default=64, help="Max table rows (default 64)")
    pt.add_argument("--json", action="store_true", help="Emit JSON array of rows")
    pt.set_defaults(func=cmd_page_table)

    args = ap.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
