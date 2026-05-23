"""Smoke tests for generic hexdump formatting."""

from __future__ import annotations

from hexdumpy import PageView, hexdump_page
from hexdumpy.geometry import NandGeometry


def test_hexdump_page_single_data_line() -> None:
    g = NandGeometry(page_data=16, page_spare=8, erase_bytes=32 * 1024, num_blocks=8)
    page = PageView(
        data=b"abcdefghijklmnop",
        spare=b"",
        logical_offset=0,
        absolute_offset=0,
        page_data_size=16,
        page_spare_size=8,
    )
    out = hexdump_page(page, g, show_spare=False, show_labels=False, address_mode="relative")
    assert "61 62 63 64" in out
    assert "ascii" in out or "|" in out
