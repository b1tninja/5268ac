"""OpenTL hexdump — hexdumpy with **OpenTL-specific** spare decoding.

This module wraps **``hexdumpy.hexdump_page``** with OpenTL spare decode.
It remains **unaware** of the manufacturer-specific spare layout — that
lives in ``unand.hexdump``.

The hexdump output shows addresses relative to the **data plane** (logical
address):
- Data region: ``page_idx × page_data``
- Spare region: ``page_idx × page_data + page_data``

Usage::

    from opentl.hexdump import hexdump_page

    # Format a single page with OpenTL spare decode
    lines = hexdump_page(page, geom)
    print(lines)

CLI::

    python -m opentl.hexdump path_to_nand_dump.bin [--spare] [--range START END]
"""

from __future__ import annotations

import argparse
import sys
from typing import Iterator, Optional

from hexdumpy import PageView, hexdump_page as _core_hexdump_page, print_hexdump_page as _core_print

from unand.geometry import NandGeometry, PACE_DEFAULT
from unand.page_view import PageIterator
from unand.reader import NandPageReader


def _opentl_decode(spare: bytes) -> Optional[str]:
    """Format OpenTL spare decode as a text block.

    Returns None if the spare is empty or too short.
    """
    if not spare or len(spare) < 64:
        return None
    try:
        from opentl.spare_layout import parse_spare, xsum_matches

        rec = parse_spare(spare)
        virt = rec.virt_u32() if rec.virt_u32_meaningful() else "N/A"
        phys = rec.phys_u32() if rec.phys_u32_meaningful() else "N/A"
        tag = rec.status
        xsum_ok = xsum_matches(spare)

        lines = []
        lines.append("=== Spare Area — OpenTL ===")
        lines.append("")
        lines.append(f"  {'offset':>5s}  {'field':>18s}  {'value':>10s}  {'description'}")
        lines.append(f"  {'-----':>5s}  {'-----':>18s}  {'-----':>10s}  {'-----------'}")
        lines.append(f"  02h     {'Tag / Status':>18s}  {tag:02x}{'':>10s}  Spare tag / status")
        lines.append(f"  09-0Ch  {'Physical Blk':>18s}  {phys}{'':>10s}  Physical block address")
        lines.append(f"  0D-10h  {'Virtual Blk':>18s}  {virt}{'':>10s}  Virtual block ID")
        lines.append(f"  60-63h  {'XSUM':>18s}  {'OK' if xsum_ok else 'FAIL':>10s}  Checksum validation")
        return "\n".join(lines)
    except Exception:
        return None


def hexdump_page(
    page: PageView,
    geom: NandGeometry,
    *,
    width: int = 16,
    show_spare: bool = True,
    show_labels: bool = True,
    address_mode: str = "cumulative",
    page_idx: int = 0,
) -> str:
    """Format a single NAND page as hexdump with OpenTL spare decode.

    Parameters
    ----------
    page : PageView
        Page with data and spare bytes.
    geom : NandGeometry
        NAND geometry.
    width : int — bytes per line
    show_spare : bool — include spare hexdump
    show_labels : bool — insert section labels
    address_mode : str — ``"cumulative"`` or ``"relative"``
    page_idx : int — page index in dump

    Returns
    -------
    str — formatted hexdump lines with OpenTL spare decode appended
    """
    lines = _core_hexdump_page(
        page, geom, width=width, show_spare=show_spare,
        show_labels=show_labels, address_mode=address_mode, page_idx=page_idx,
    )

    # Append OpenTL spare decode
    if page.spare:
        decoded = _opentl_decode(page.spare)
        if decoded:
            lines += "\n" + decoded

    return lines


def print_hexdump_page(
    page: PageView,
    geom: NandGeometry,
    *,
    width: int = 16,
    show_spare: bool = True,
    show_labels: bool = True,
    address_mode: str = "cumulative",
    page_idx: int = 0,
) -> None:
    """Print a single NAND page hexdump with OpenTL decode, flushed immediately."""
    _core_print(
        page, geom, width=width, show_spare=show_spare,
        show_labels=show_labels, address_mode=address_mode, page_idx=page_idx,
    )
    # Append OpenTL spare decode
    if page.spare:
        decoded = _opentl_decode(page.spare)
        if decoded:
            print(decoded)


# ---------------------------------------------------------------------------
# CLI entry point: python -m opentl.hexdump
# ---------------------------------------------------------------------------

def _cmd_hexdump(args: argparse.Namespace) -> int:
    """Print NAND pages/blocks/sectors in hexdump format with OpenTL metadata."""
    import sys

    chip = None
    geom = PACE_DEFAULT
    pages_per_block = geom.erase_bytes // geom.page_data

    start_page = 0
    end_page = geom.pages_total - 1
    if args.page_range:
        start_page = args.page_range[0]
        end_page = args.page_range[1]

    # Clamp to valid range
    start_page = max(0, start_page)
    end_page = min(end_page, geom.pages_total - 1)

    sys.stdout.flush()

    prev_block = -1

    with NandPageReader(args.input, geom=geom, page_range=(start_page, end_page)) as reader:
        source = PageIterator(reader, geom, layout="inline")
        page_idx = 0

        for page in source:
            cur_block = page_idx // pages_per_block

            # Block boundary header
            if cur_block != prev_block:
                prev_block = cur_block
                spare = page.spare or b""
                erased = all(b == 0xFF for b in spare)
                from unand.s34ml import factory_bbi_bad_from_spare

                factory_bad = factory_bbi_bad_from_spare(spare, 0) is True
                status_parts = []
                if erased:
                    status_parts.append("erased")
                if factory_bad:
                    status_parts.append("factory-bad")
                if not status_parts:
                    status_parts.append("good")
                status = ",".join(status_parts)
                print(f"\n=== Block {cur_block} (pages {page_idx}-{page_idx + pages_per_block - 1}) status={status} ===")

            # Format hexdump for this page with OpenTL decode
            lines = hexdump_page(
                page, geom,
                width=16,
                show_spare=args.spare,
                show_labels=True,
                address_mode="cumulative",
                page_idx=page_idx,
            )
            print(lines)
            page_idx += 1

    return 0


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        prog="python -m opentl.hexdump",
        description="Hexdump NAND pages with OpenTL spare decode",
    )
    p.add_argument("input", type=str, help="Path to NAND dump file")
    p.add_argument("--spare", action="store_true", default=True,
                   help="Include spare hex and metadata")
    p.add_argument("--range", dest="page_range", type=int, nargs=2,
                   metavar=("START", "END"), default=None,
                   help="Page range to dump")

    ns = p.parse_args(argv)

    # Validate input file
    import os
    if not os.path.isfile(ns.input):
        print(f"Error: {ns.input} not found", file=sys.stderr)
        raise SystemExit(1)

    raise SystemExit(_cmd_hexdump(ns))


if __name__ == "__main__":
    main()