"""hexdumpy — simple hexdump formatter for NAND pages.

This module is **domain-agnostic**: it knows nothing about ``unand`` or ``opentl``.
It provides a single function to format a page as a hexdump string.  The caller
iterates pages and passes each one to the formatter, then appends any extra
decoded sections (manufacturer spare table, OpenTL metadata, etc.).

The core data type is :class:`PageView` — a named tuple carrying both the raw
page bytes **and** their address offsets.  Consumers create ``PageView`` objects
from whatever packing layout they understand (inline 2048+64, flat-tail,
logical-only, etc.) and hexdumpy uses the offsets for correct address labels.

Usage::

    from hexdumpy import hexdump_page, PageView

    # Format a single page
    page = PageView(
        data=data_bytes,
        spare=spare_bytes,
        logical_offset=0x0800,   # page_idx × page_data in data plane
        absolute_offset=0x0840,  # page_idx × (page_data + page_spare) in file
        page_data_size=2048,     # raw data area bytes
        page_spare_size=64,      # spare/OOB bytes
    )

    print(hexdump_page(page, geom, address_mode="cumulative"))
"""

from __future__ import annotations

from collections import namedtuple
from typing import Optional

from .geometry import NandGeometry

#: Page view carrying raw bytes and address offsets.
#:   - **data**: main data area (e.g. 2048 bytes)
#:   - **spare**: OOB/spare area (e.g. 64 bytes)
#:   - **logical_offset**: page index × page_data — data-plane address
#:   - **absolute_offset**: page index × page_phys — raw-file address
#:   - **page_data_size**: raw data area bytes (2048, 4096, etc.)
#:   - **page_spare_size**: OOB/spare bytes (64, 128, etc.)
PageView = namedtuple(
    "PageView",
    ("data", "spare", "logical_offset", "absolute_offset", "page_data_size", "page_spare_size"),
)


def _hexdump_row(addr: int, chunk: bytes, width: int = 16) -> str:
    """Format a single line of a hexdump table."""
    addr_str = f"{addr:08x}"

    hex_parts = [f"{b:02x}" for b in chunk]
    groups = []
    for i in range(0, len(hex_parts), 4):
        groups.append(hex_parts[i: i + 4])
    hex_str = "  ".join(" ".join(g) for g in groups)

    if len(chunk) < width:
        hex_str = hex_str + "   " * (width - len(chunk))

    ascii_repr = "".join(
        chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk
    )
    ascii_repr = ascii_repr.ljust(width)

    return f"  {addr_str}  |{hex_str}| {ascii_repr}\n"


def _compute_addr(page, base: int, address_mode: str, page_data_size: int) -> int:
    """Compute the address for a hexdump row.

    Parameters
    ----------
    page : PageView
    base : int — byte offset within the data or spare region
    address_mode : str — ``"cumulative"`` or ``"relative"``
    page_data_size : int — data area bytes for the page

    Returns
    -------
    int — formatted address for the hexdump row
    """
    if address_mode == "relative":
        return base

    # Cumulative: use the PageView's stored logical offset
    logical = page.logical_offset
    # If base is past the data region, add to logical offset for spare addressing
    if base >= page_data_size:
        logical += page_data_size
    return logical + base


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
    """Format a single page as a hexdump string.

    Parameters
    ----------
    page : PageView
        Page with data and spare bytes, plus address offsets.
    geom : NandGeometry
        Geometry for reference (data sizes).
    width : int
        Bytes per hex line (default 16).
    show_spare : bool
        Include spare hexdump section.
    show_labels : bool
        Insert section labels.
    address_mode : str
        ``"cumulative"`` uses stored offsets; ``"relative"`` resets to zero.
    page_idx : int
        Page index in the dump (used for page heading).

    Returns
    -------
    str
        Formatted hexdump lines.  Caller can append extra decoded sections.

    Example::

        from unand.s34ml import S34ML01G1
        from hexdumpy import hexdump_page

        chip = S34ML01G1()
        lines = hexdump_page(page, geom)
        if page.spare:
            lines += chip.render_spare_table(page.spare, page_idx, geom)
        print(lines)
    """
    data_chunk = page.data
    spare_chunk = page.spare
    page_data_size = page.page_data_size
    page_spare_size = page.page_spare_size

    lines = []

    # Page heading
    if show_labels:
        lines.append("")
        lines.append("=" * 66)
        if show_spare and spare_chunk:
            lines.append(f"  Page {page_idx:04d}  data=0x{page_data_size:04x}  spare=0x{page_spare_size:02x}")
        else:
            lines.append(f"  Page {page_idx:04d}  data=0x{page_data_size:04x}")
        lines.append("=" * 66)

    lines.append("  offset   |                hex bytes                | ascii")
    lines.append("  " + "-" * 66)

    # Data region
    if show_spare and spare_chunk:
        lines.append(f"  --- data ({len(data_chunk):04x} bytes) ---")
        for base in range(0, len(data_chunk), width):
            addr = _compute_addr(page, base, address_mode, page_data_size)
            lines.append(_hexdump_row(addr, data_chunk[base: base + width], width))

        # Spare region
        lines.append(f"  --- spare ({len(spare_chunk):04x} bytes) ---")
        for base in range(0, len(spare_chunk), width):
            spare_base = len(data_chunk) + base if address_mode == "cumulative" else base
            addr = _compute_addr(page, spare_base, address_mode, page_data_size)
            lines.append(_hexdump_row(addr, spare_chunk[base: base + width], width))
    else:
        lines.append(f"  --- data ({len(data_chunk):04x} bytes) ---")
        for base in range(0, len(data_chunk), width):
            addr = _compute_addr(page, base, address_mode, page_data_size)
            lines.append(_hexdump_row(addr, data_chunk[base: base + width], width))

    return "\n".join(lines)


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
    """Print a single page hexdump with ``flush=True``.

    All parameters are the same as :func:`hexdump_page`.
    """
    print(hexdump_page(
        page, geom, width=width, show_spare=show_spare,
        show_labels=show_labels, address_mode=address_mode, page_idx=page_idx,
    ), end="", flush=True)