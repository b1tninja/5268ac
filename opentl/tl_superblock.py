"""
Kernel **OpenTL TL superblock** on logical page 0 (`ntl_mount` mode 3), att-5268 class.

Magic ``0xBA51CDEF``, major byte at offset 4, a bounded u16 at offset 6, then TLV records
starting at byte 8. Each record: **big-endian** u16 type, u16 length, then ``length`` payload
bytes; type **4** terminates the header (see ``ntl_mount`` / ``parse_tl_header`` strings).

This module only implements the **single-buffer** case where the full header fits in the
first ``page_data`` bytes (no ``ntl_access_pages`` refill). Returns ``None`` if the buffer
does not contain a recognizable valid header.
"""

from __future__ import annotations

import struct

#region kernel: 0x8028ac28
# parse_tl_header / ntl_mount mode 3 — TL superblock on logical page 0
# MIPS BE wire order matches ``*puVar18 != 0xba51cdef`` in kernel .bin.c
TL_SUPER_MAGIC_BE = 0xBA51CDEF
TL_SUPER_MAJOR = 1
TL_SUPER_MAX_U16_AT_6 = 100
TL_TLV_MAX_LENGTH = 0x400
_MAX_TLV_RECORDS = 128


def tl_superblock_skip_bytes(data: bytes, *, page_data: int = 0x800) -> int | None:
    """
    If ``data`` begins with a valid TL superblock and TLV stream ending in type 4, return the
    **exclusive** byte offset immediately after that stream (suitable as ``mtd_skip`` for
    disklabel enumeration). Otherwise return ``None``.

    The entire TLV stream through the terminating type-4 record must fit within
    ``data[:min(len(data), page_data)]`` (v1 does not simulate ``ntl_access_pages`` page refills).
    """
    if len(data) < 8:
        return None
    (magic,) = struct.unpack_from(">I", data, 0)
    if magic != TL_SUPER_MAGIC_BE:
        return None
    if data[4] != TL_SUPER_MAJOR:
        return None
    (u16_at_6,) = struct.unpack_from(">H", data, 6)
    if u16_at_6 > TL_SUPER_MAX_U16_AT_6:
        return None

    ptr = 8
    window = min(len(data), page_data)
    for _ in range(_MAX_TLV_RECORDS):
        if ptr + 4 > window:
            return None
        (rtype, rlen) = struct.unpack_from(">HH", data, ptr)
        if rlen > TL_TLV_MAX_LENGTH:
            return None
        payload_at = ptr + 4
        if payload_at + rlen > len(data) or payload_at + rlen > window:
            return None
        if rtype == 4:
            return payload_at + rlen
        ptr = payload_at + rlen
    return None


#endregion


__all__ = [
    "TL_SUPER_MAGIC_BE",
    "TL_SUPER_MAJOR",
    "tl_superblock_skip_bytes",
]
