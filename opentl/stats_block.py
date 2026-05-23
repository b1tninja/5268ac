"""
OpenTL **stats** RAM image layout — derived from live Ghidra decompilation of the 5268 kernel
(``att-5268-11.5.1.532678…-kernel.elf``, ``image_base=0x80010000``).

The driver does **not** store stats as a standalone file; it allocates ``remap+0x150cc``,
sizes it from ``remap[0x5432]`` (byte length = ``ntl_initialize_memory`` formula), and
loads/writes that window via ``ntl_access_pages`` at the **tail** of the virtual TL range.

Use :mod:`unand` only at call sites that need **NAND plane** addressing (see
:func:`nand_logical_slice_for_stats_tail`); this module stays layout-pure.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import Any, Optional

#region kernel: 0x8028a938
# also ntl_initialize_memory:0x80289610, ntl_load_stat_table:0x8028aab0 (opentl_kernel_ghidra.md)
# ntl_reset_stat_table — confirmed @ 8028a938 (May 2026 MCP decompile)
STATS_MAGIC_WORD0: int = 0x0001_0000  # little-endian u32 @ offset 0
STATS_MAGIC_WORD1: int = 0xDEAD1001  # u32 @ offset 4 (kernel writes literal 0xdead1001)
# Third u32 @ offset 8 is copied from remap[5] at reset time (phys span / bookkeeping word).


def stats_buffer_byte_count(phys_span: int, *, alignment: int = 4) -> int:
    """
    Bytes reserved for the stats arena — mirrors ``ntl_initialize_memory``:

        ``puVar3[0x5432] = align_up((phys_span + 0xc) * 4, param_1[4])``

    where ``phys_span = inner[1] - inner[0]`` (last minus first physical unit index).
    """
    if phys_span < 0:
        raise ValueError("phys_span must be non-negative")
    if alignment <= 0 or (alignment & (alignment - 1)) != 0:
        raise ValueError("alignment must be a positive power of two")
    raw = (phys_span + 0xC) * 4
    return (raw + alignment - 1) & ~(alignment - 1)


def stats_region_virt_block_count(
    stats_buffer_bytes: int,
    *,
    page_bytes: int = 2048,
    pages_per_block: int = 64,
) -> int:
    """
    Virtual erase-block count for the stats window — mirrors ``ntl_load_stat_table``:

    * ``page_count = ceil(stats_buffer_bytes / page_bytes)``
    * ``virt_blocks = ceil(page_count / pages_per_block)``
    """
    if stats_buffer_bytes <= 0:
        return 0
    pages = math.ceil(stats_buffer_bytes / page_bytes)
    return math.ceil(pages / pages_per_block)


def stats_region_linear_page_span(
    stats_buffer_bytes: int,
    *,
    page_bytes: int = 2048,
    pages_per_block: int = 64,
    total_virt_blocks: int,
) -> tuple[int, int]:
    """
    ``(start_linear_page, page_count)`` for ``ntl_access_pages`` on stats I/O.

    ``start_linear_page = (total_virt_blocks - virt_stats_blocks) * pages_per_block``
    """
    vb = stats_region_virt_block_count(
        stats_buffer_bytes, page_bytes=page_bytes, pages_per_block=pages_per_block
    )
    if vb > total_virt_blocks:
        raise ValueError("stats region larger than total_virt_blocks")
    pages = math.ceil(stats_buffer_bytes / page_bytes)
    # Kernel: start_linear_page = (remap[4] - virt_stats_blocks) * pages_per_block
    start = (total_virt_blocks - vb) * pages_per_block
    return start, pages


def stats_tail_virtual_disk_bytes(
    stats_buffer_bytes: int,
    *,
    erase_bytes: int = 131_072,
    page_bytes: int = 2048,
    pages_per_block: int = 64,
) -> int:
    """Byte length of the **virtual TL disk** tail occupied by stats (whole erase blocks)."""
    vb = stats_region_virt_block_count(
        stats_buffer_bytes, page_bytes=page_bytes, pages_per_block=pages_per_block
    )
    return vb * erase_bytes


@dataclass(frozen=True)
class StatsHeaderView:
    """First 12 bytes of the stats buffer after ``ntl_reset_stat_table``."""

    word0: int
    word1: int
    word2: int

    @classmethod
    def unpack(cls, buf: bytes) -> StatsHeaderView:
        if len(buf) < 12:
            raise ValueError("need at least 12 bytes for stats header")
        w0, w1, w2 = struct.unpack_from("<III", buf, 0)
        return cls(w0, w1, w2)

    def magic_ok(self) -> bool:
        return self.word0 == STATS_MAGIC_WORD0 and self.word1 == STATS_MAGIC_WORD1


def validate_stats_header(
    buf: bytes,
    *,
    word2_expected: Optional[int] = None,
) -> tuple[bool, list[str]]:
    """
    Return ``(ok, notes)`` — when ``word2_expected`` is ``None``, word2 is not checked
    (driver-specific bookkeeping; equals ``remap[5]`` at reset in the 5268 image).
    """
    notes: list[str] = []
    if len(buf) < 12:
        return False, ["buffer shorter than 12 bytes"]
    h = StatsHeaderView.unpack(buf)
    if not h.magic_ok():
        return False, [f"bad magic got ({h.word0:#x},{h.word1:#x})"]
    if word2_expected is not None and h.word2 != (word2_expected & 0xFFFF_FFFF):
        return False, [f"word2 mismatch got {h.word2:#x} expected {word2_expected:#x}"]
    notes.append("stats magic pair OK (0x10000, 0xDEAD1001)")
    return True, notes


#endregion


def slice_stats_tail_from_virtual_tl_disk(
    tl_disk: bytes,
    *,
    phys_span: int,
    total_virt_blocks: int,
    erase_bytes: int = 131_072,
    page_bytes: int = 2048,
    pages_per_block: int = 64,
    alignment: int = 4,
) -> bytes:
    """
    Return the **tail** ``virt_blocks * erase_bytes`` slice from a linearized whole-TL disk
    image (identity virt→phys). For real remaps, assemble the virtual disk first.
    """
    sz = stats_buffer_byte_count(phys_span, alignment=alignment)
    tail = stats_tail_virtual_disk_bytes(
        sz,
        erase_bytes=erase_bytes,
        page_bytes=page_bytes,
        pages_per_block=pages_per_block,
    )
    if len(tl_disk) < tail:
        raise ValueError(f"tl_disk len {len(tl_disk)} < stats tail {tail}")
    return tl_disk[-tail:]


def nand_logical_slice_for_stats_tail(
    *,
    tlpart_byte_offset: int,
    phys_span: int,
    total_virt_blocks: int,
    erase_bytes: int = 131_072,
    page_bytes: int = 2048,
    pages_per_block: int = 64,
    alignment: int = 4,
) -> tuple[int, int]:
    """
    ``(byte_start, byte_length)`` into **NAND logical** ``tlpart`` (main data, no OOB interleave)
    for the stats tail, assuming **identity** virt→phys so virtual tail == physical tail.

    Callers pass ``tlpart_byte_offset`` from :mod:`opentl.nand_translate` / ``unand`` carve
    (often ``0`` for a ``tlpart.bin`` that starts at erase 0).
    """
    sz = stats_buffer_byte_count(phys_span, alignment=alignment)
    tail = stats_tail_virtual_disk_bytes(
        sz,
        erase_bytes=erase_bytes,
        page_bytes=page_bytes,
        pages_per_block=pages_per_block,
    )
    # Whole TL data bytes for virt layer (identity): total_virt_blocks * erase_bytes
    whole = total_virt_blocks * erase_bytes
    start = tlpart_byte_offset + (whole - tail)
    return start, tail
