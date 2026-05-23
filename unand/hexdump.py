"""NAND hexdump with **manufacturer-defined** spare decoding.

This module wraps **``hexdumpy.hexdump_page``** with manufacturer-specific
spare decode.  It remains **unaware** of OpenTL — the OpenTL-specific
wrapper lives in ``opentl.hexdump``.

The hexdump output shows addresses relative to the **data plane** (logical
address):
- Data region: ``page_idx × page_data``
- Spare region: ``page_idx × page_data + page_data``
- For inline 2048+64, page 1 data starts at 0x0800 (not 0x0840)
- For flat-tail, data and spare share the same logical offset

Usage::

    from unand.hexdump import hexdump_page, print_hexdump_page
    from unand.page_view import PageIterator
    from unand.reader import NandPageReader

    chip = S34ML01G1()
    with NandPageReader(path, geom=geom) as reader:
        source = PageIterator(reader, geom, layout="inline")
        for idx, page in enumerate(source):
            # Format hexdump
            lines = hexdump_page(page, geom, page_idx=idx)
            # Append manufacturer spare decode
            if page.spare:
                lines += chip.render_spare_table(page.spare, idx, geom)
            print(lines)
"""

from __future__ import annotations

from typing import Iterator, Optional

from hexdumpy import PageView, hexdump_page as _core_hexdump_page, print_hexdump_page as _core_print
from unand.geometry import NandGeometry, PACE_DEFAULT
from unand.page_view import PageIterator
from unand.s34ml import S34ML, S34ML01G1
from unand.reader import NandPageReader


def hexdump_page(
    page: PageView,
    geom: NandGeometry,
    *,
    chip: Optional[S34ML] = None,
    width: int = 16,
    show_spare: bool = True,
    show_labels: bool = True,
    address_mode: str = "cumulative",
    page_idx: int = 0,
) -> str:
    """Format a single NAND page as hexdump with manufacturer spare decode.

    Parameters
    ----------
    page : PageView
        Page with data and spare bytes.
    geom : NandGeometry
        NAND geometry.
    chip : S34ML instance (optional, appends spare table)
    width : int — bytes per line
    show_spare : bool — include spare hexdump
    show_labels : bool — insert section labels
    address_mode : str — ``"cumulative"`` or ``"relative"``
    page_idx : int — page index in dump

    Returns
    -------
    str — formatted hexdump lines (caller can append manufacturer decode)
    """
    if chip is None:
        chip = S34ML01G1()

    lines = _core_hexdump_page(
        page, geom, width=width, show_spare=show_spare,
        show_labels=show_labels, address_mode=address_mode, page_idx=page_idx,
    )

    # Append manufacturer spare decode
    if page.spare:
        decoded = chip.decode_spare(page.spare)
        tag = decoded.get("tag_str", "N/A")
        bad_block = decoded.get("bad_block", False)
        erased = decoded.get("erased", False)
        lines += f"\n  --- Decoded Spare (S34ML01G1): tag={tag} bad_block={bad_block} erased={erased} ---"

    return lines


def print_hexdump_page(
    page: PageView,
    geom: NandGeometry,
    *,
    chip: Optional[S34ML] = None,
    width: int = 16,
    show_spare: bool = True,
    show_labels: bool = True,
    address_mode: str = "cumulative",
    page_idx: int = 0,
) -> None:
    """Print a single NAND page hexdump, flushed immediately."""
    if chip is None:
        chip = S34ML01G1()

    _core_print(
        page, geom, width=width, show_spare=show_spare,
        show_labels=show_labels, address_mode=address_mode, page_idx=page_idx,
    )


# ---------------------------------------------------------------------------
# Convenience: CLI entry point
# ---------------------------------------------------------------------------

def dump_file(
    path: str,
    *,
    geom: NandGeometry = None,
    chip: S34ML = None,
    layout: str = "inline",
    width: int = 16,
    show_spare: bool = True,
    show_labels: bool = True,
    page_range: tuple = None,
    address_mode: str = "cumulative",
) -> None:
    """Stream hexdump from a NAND dump file with proper data-plane addressing.

    Parameters
    ----------
    path : str — path to the raw NAND dump
    geom : NandGeometry — geometry for offset arithmetic
    chip : S34ML — chip for spare decode
    layout : str — ``"inline"``, ``"flat_tail"``, ``"logical"``
    width : int — bytes per hexdump line
    show_spare : bool — include spare hexdump
    show_labels : bool — insert section labels
    page_range : tuple — ``(start_page, end_page)`` inclusive
    address_mode : str — ``"cumulative"`` or ``"relative"``
    """
    import sys

    if geom is None:
        geom = PACE_DEFAULT
    if chip is None:
        chip = S34ML01G1()

    start_page = 0
    end_page = geom.pages_total - 1
    if page_range:
        start_page = page_range[0]
        end_page = page_range[1]

    # Flush stdout so hexdump appears immediately
    sys.stdout.flush()

    pages_per_block = geom.erase_bytes // geom.page_data
    prev_block = -1

    with NandPageReader(path, geom=geom, page_range=(start_page, end_page)) as reader:
        source = PageIterator(reader, geom, layout=layout)
        page_idx = 0

        for page in source:
            cur_block = page_idx // pages_per_block

            # Block boundary header
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
                print(f"\n=== Block {cur_block} (pages {page_idx}-{page_idx + pages_per_block - 1}) status={status} ===")

            # Format and print page
            lines = _core_hexdump_page(
                page, geom, width=width, show_spare=show_spare,
                show_labels=show_labels, address_mode=address_mode, page_idx=page_idx,
            )

            # Append manufacturer spare decode
            if page.spare:
                decoded = chip.decode_spare(page.spare)
                tag = decoded.get("tag_str", "N/A")
                bad_block = decoded.get("bad_block", False)
                erased = decoded.get("erased", False)
                lines += f"\n  --- Decoded Spare (S34ML01G1): tag={tag} bad_block={bad_block} erased={erased} ---"

            print(lines)
            page_idx += 1


# ---------------------------------------------------------------------------
# Legacy backward-compat
# ---------------------------------------------------------------------------

def hexdump(
    data: bytes,
    *,
    geom: NandGeometry = None,
    show_spare: bool = False,
    show_labels: bool = True,
) -> str:
    """Produce a hexdump string for raw byte data.

    Parameters
    ----------
    data : bytes
        Raw NAND data (page + spare interleaved or flat).
    geom : NandGeometry | None
        If set, produces page-aware output.
    show_spare : bool
        Interleave spare bytes.
    show_labels : bool
        Insert page labels.
    """
    if geom is None:
        from hexdumpy.geometry import NandGeometry as HG
        geom = HG(page_data=2048, page_spare=64, erase_bytes=131072, num_blocks=1024)

    buf = []
    width = 16
    total = len(data)
    i = 0
    page_idx = 0

    while i < total:
        buf.append(f"\n{'=' * 66}")
        if show_spare:
            buf.append(f"  Page {page_idx:04d}  data=0x{geom.page_data:04x}  spare=0x{geom.page_spare:02x}")
        else:
            buf.append(f"  Page {page_idx:04d}  data=0x{geom.page_data:04x}")
        buf.append(f"{'=' * 66}")
        buf.append("  offset   |                hex bytes                | ascii")
        buf.append("  " + "-" * 66)

        if show_spare:
            data_end = min(i + geom.page_data, total)
            spare_start = i + geom.page_data
            spare_end = min(spare_start + geom.page_spare, total)

            if data_end > i:
                buf.append(f"  --- data (0x{data_end - i:04x} bytes) ---")
                for base in range(i, data_end, width):
                    chunk = data[base: base + width]
                    buf.append("    " + f"{base:08x}" + "  |" + "  ".join(f"{b:02x}" for b in chunk[:4]) + "  " + "  ".join(f"{b:02x}" for b in chunk[4:8]) + "|" + "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk[:16]).ljust(16))

            if spare_end > spare_start:
                buf.append(f"  --- spare (0x{spare_end - spare_start:04x} bytes) ---")
                for base in range(spare_start, spare_end, width):
                    chunk = data[base: base + width]
                    buf.append("    " + f"{base:08x}" + "  |" + "  ".join(f"{b:02x}" for b in chunk[:4]) + "  " + "  ".join(f"{b:02x}" for b in chunk[4:8]) + "|" + "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk[:16]).ljust(16))

            i = spare_end
        else:
            end = min(i + geom.page_data, total)
            for base in range(i, end, width):
                chunk = data[base: base + width]
                buf.append("    " + f"{base:08x}" + "  |" + "  ".join(f"{b:02x}" for b in chunk[:4]) + "  " + "  ".join(f"{b:02x}" for b in chunk[4:8]) + "|" + "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk[:16]).ljust(16))
            i = end

        page_idx += 1

    return "\n".join(buf)


def page_hexdump(
    path: str,
    *,
    geom: NandGeometry = None,
    show_spare: bool = True,
    page_range: tuple[int, int] = None,
) -> str:
    """Quick hexdump from file path with manufacturer spare decode."""
    if geom is None:
        geom = PACE_DEFAULT
    if page_range is None:
        page_range = (0, 9)

    start_page, end_page = page_range
    pages_per_block = geom.erase_bytes // geom.page_data
    chip = S34ML01G1()

    buf = []

    # Block status headers
    with NandPageReader(path, geom=geom, page_range=(start_page, end_page)) as reader:
        for pidx, _data, spare in reader:
            if pidx % pages_per_block == 0:
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
                blk = pidx // pages_per_block
                buf.append(f"=== Block {blk} (pages {pidx}-{pidx + pages_per_block - 1}) status={status} ===")

    for page_idx in range(start_page, end_page + 1):
        with NandPageReader(path, geom=geom, page_range=(page_idx, page_idx)) as reader:
            for _pidx, data, spare in reader:
                page = PageView(
                    data=data, spare=spare,
                    logical_offset=page_idx * geom.page_data,
                    absolute_offset=page_idx * geom.page_phys,
                    page_data_size=len(data),
                    page_spare_size=len(spare),
                )
                lines = _core_hexdump_page(
                    page, geom, width=16, show_spare=show_spare,
                    show_labels=True, address_mode="cumulative", page_idx=page_idx,
                )
                if spare:
                    decoded = chip.decode_spare(spare)
                    lines += f"\n  --- Decoded Spare (S34ML01G1): tag={decoded.get('tag_str', 'N/A')} ---"
                buf.append(lines)

    return "\n".join(buf)