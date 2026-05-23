"""``python -m unand`` — translate + inspect NAND dumps."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from unand.geometry import PACE_DEFAULT
from unand.io import normalize_to_logical, sha256_logical_plane
from unand.layout import RawDumpLayout, detect_layout_file
from unand.mtd import DEFAULT_MTDPARTS, parse_mtdparts

_LAYOUT_CHOICES: dict[str, RawDumpLayout] = {
    "inline_2048_64": RawDumpLayout.INLINE_2048_64,
    "flat_tail_2048_64": RawDumpLayout.FLAT_TAIL_2048_64,
    "logical_only": RawDumpLayout.LOGICAL_ONLY,
}


def _parse_layout(s: str) -> RawDumpLayout:
    k = s.strip().lower().replace("-", "_")
    if k not in _LAYOUT_CHOICES:
        raise argparse.ArgumentTypeError(
            f"unknown layout {s!r}; expected one of: {', '.join(sorted(_LAYOUT_CHOICES))}"
        )
    return _LAYOUT_CHOICES[k]


def _cmd_translate(args: argparse.Namespace) -> int:
    used = normalize_to_logical(
        args.input,
        args.output,
        args.spare_out,
        layout=args.layout,
    )
    print(f"layout={used.value}")
    if args.print_mtd:
        parts = parse_mtdparts(DEFAULT_MTDPARTS, logical_total=PACE_DEFAULT.logical_bytes)
        for p in parts:
            print(f"{p.name}\t0x{p.offset:x}\t{p.size}\t0x{p.size:x}")
    return 0


def _cmd_layout_detect(args: argparse.Namespace) -> int:
    """Offline heuristic report only (not used by translate defaults)."""
    resolved = detect_layout_file(str(args.input), geom=PACE_DEFAULT)
    print(f"layout={resolved.value}")
    return 0


def _cmd_sha256(args: argparse.Namespace) -> int:
    hx = sha256_logical_plane(args.input, layout=args.layout)
    print(f"layout={args.layout.value}")
    print(hx)
    return 0


def _cmd_hexdump(args: argparse.Namespace) -> int:
    """Print NAND pages/blocks/sectors in hexdump format with metadata.

    Uses :func:`hexdump_page` from ``unand.hexdump`` with
    :class:`PageIterator` for true streaming output — each page's hexdump
    is printed immediately as it's read, no full-file buffering.

    Addresses shown are relative to the **data plane** (logical offset):
    data starts at page_idx × page_data, spare starts at page_data + page_idx × page_data.
    """
    import sys as _sys

    from unand.hexdump import hexdump_page
    from unand.page_view import PageIterator
    from unand.reader import NandPageReader
    from unand.s34ml import S34ML01G1

    chip = S34ML01G1()
    geom = chip.geometry

    pages_per_block = geom.erase_bytes // geom.page_data
    total_pages = geom.pages_total

    if args.page_range is None:
        start_page = 0
        end_page = total_pages - 1
    else:
        start_page = args.page_range[0]
        end_page = args.page_range[1]

    start_page = max(0, start_page)
    end_page = min(end_page, total_pages - 1)

    _sys.stdout.flush()

    prev_block = -1

    with NandPageReader(args.input, geom=geom, page_range=(start_page, end_page)) as reader:
        source = PageIterator(reader, geom, layout="inline")
        page_idx = 0

        for page in source:
            cur_block = page_idx // pages_per_block

            if cur_block != prev_block:
                prev_block = cur_block
                spare = page.spare or b""
                erased = all(b == 0xFF for b in spare)
                bad_block = spare[2] == 0x00 if len(spare) > 2 else False
                status_parts = []
                if erased:
                    status_parts.append("erased")
                if bad_block:
                    status_parts.append("bad-block")
                if not status_parts:
                    status_parts.append("good")
                status = ",".join(status_parts)
                print(
                    f"\n=== Block {cur_block} (pages {page_idx}-{page_idx + pages_per_block - 1}) "
                    f"status={status} ==="
                )

            lines = hexdump_page(
                page,
                geom,
                chip=chip,
                width=16,
                show_spare=args.spare,
                show_labels=True,
                address_mode="cumulative",
                page_idx=page_idx,
            )
            print(lines)
            page_idx += 1

    return 0


def _cmd_block(args: argparse.Namespace) -> int:
    """Read a specific block in hexdump format."""
    from unand.s34ml import S34ML01G1

    chip = S34ML01G1()
    geom = chip.geometry
    pages_per_block = geom.erase_bytes // geom.page_data
    block_size = geom.erase_bytes

    with open(args.input, "rb") as f:
        offset = args.block * block_size
        f.seek(offset)
        data = f.read(block_size)

        if len(data) < block_size:
            print(f"Error: block {args.block} extends beyond image", flush=True)
            return 1

        print(f"=== Block {args.block} (offset 0x{offset:x}, {block_size:,} bytes) ===")
        print()

        for page_in_block in range(pages_per_block):
            page_offset = page_in_block * geom.page_data
            page_data = data[page_offset : page_offset + geom.page_data]
            page_spare = data[
                page_offset + geom.page_data : page_offset + geom.page_data + geom.page_spare
            ]

            if args.data:
                print(f"  Page {page_in_block} (data):")
                for row in range(0, min(len(page_data), 128), 16):
                    chunk = page_data[row : row + 16]
                    hex_part = "  ".join(f"{b:02x}" for b in chunk)
                    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                    print(f"    {row:04x}: {hex_part:<48s} |{ascii_part}|")
                    if row >= 128 - 16:
                        break

            if args.spare and page_spare:
                spare_hex = " ".join(f"{b:02x}" for b in page_spare)
                print(f"  Page {page_in_block} (spare): {spare_hex}")

                decoded = chip.decode_spare(page_spare)
                print(
                    f"    tag={decoded.get('tag_str', 'N/A')} "
                    f"phys_blk={decoded.get('physical_block_address', 'N/A')} "
                    f"virt_blk={decoded.get('virtual_block_id', 'N/A')} "
                    f"xsum={'OK' if decoded.get('xsum_ok') else 'FAIL'}"
                )

            print()

    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m unand",
        epilog="MTD vs spare, page vs OpenTL sector: see unand/README.md in the repo.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("translate", help="Normalize raw dump to logical (+ optional spare)")
    t.add_argument("input", type=Path)
    t.add_argument("--output", "-o", type=Path, required=True)
    t.add_argument("--spare-out", type=Path, default=None)
    t.add_argument(
        "--layout",
        type=_parse_layout,
        required=True,
        metavar="LAYOUT",
        help="Packing: inline_2048_64 | flat_tail_2048_64 | logical_only (required)",
    )
    t.add_argument("--print-mtd", action="store_true", help=f"Print {DEFAULT_MTDPARTS!r} slices")
    t.set_defaults(func=_cmd_translate)

    ld = sub.add_parser(
        "layout-detect",
        help="Offline heuristic layout guess (report only; do not use as a silent default)",
    )
    ld.add_argument("input", type=Path)
    ld.set_defaults(func=_cmd_layout_detect)

    s = sub.add_parser("sha256-logical", help="SHA-256 of the logical data plane")
    s.add_argument("input", type=Path)
    s.add_argument(
        "--layout",
        type=_parse_layout,
        required=True,
        metavar="LAYOUT",
        help="How to read the logical plane from this file (required)",
    )
    s.set_defaults(func=_cmd_sha256)

    h = sub.add_parser("hexdump", help="Hexdump NAND pages with metadata (default: all pages)")
    h.add_argument("input", type=Path)
    h.add_argument("--data", action="store_true", default=True, help="Include data hex (first 64 bytes)")
    h.add_argument(
        "--spare",
        action="store_true",
        default=True,
        help="Include spare hex and metadata",
    )
    h.add_argument(
        "--range",
        dest="page_range",
        type=int,
        nargs=2,
        metavar=("START", "END"),
        default=None,
        help="Page range to dump (default: print all)",
    )
    h.set_defaults(func=_cmd_hexdump)

    b = sub.add_parser("block", help="Hexdump a specific NAND block")
    b.add_argument("input", type=Path)
    b.add_argument("--block", "-b", type=int, required=True, help="Block number to read")
    b.add_argument("--data", action="store_true", help="Include data hexdump")
    b.add_argument("--spare", action="store_true", help="Include spare hexdump")
    b.set_defaults(func=_cmd_block)

    q = sub.add_parser("q", help="Quick hexdump of first 10 pages (shortcut for hexdump)")
    q.add_argument("input", type=Path)
    q.set_defaults(func=_cmd_hexdump)

    ns = p.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())
