"""
MBR sector-0 helpers mirroring kernel ``msdos_partition`` → FreeBSD slice (type ``0xA5``).

Used when a buffer begins with a **PC MBR** (e.g. full logical-plane image) so TL disklabel
enumeration can start at ``LBA_start * 512`` like ``read_dev_sector``-driven parsers.
"""

from __future__ import annotations

import struct

MBR_BOOT_SIGNATURE_OFFSET = 0x1FE
MBR_PARTITION_TABLE = 0x1BE
PARTITION_ENTRY_LEN = 16
PARTITION_TYPE_OFFSET = 4
PARTITION_LBA_OFFSET = 8
PTYPE_FREEBSD_A5 = 0xA5
SECTOR_BYTES = 512


def mbr_boot_signature_ok(sector0: bytes) -> bool:
    """True if ``sector0`` has length ≥ 512 and bytes ``0x1FE..0x1FF`` are ``55 AA``."""
    return (
        len(sector0) >= 512
        and sector0[MBR_BOOT_SIGNATURE_OFFSET] == 0x55
        and sector0[MBR_BOOT_SIGNATURE_OFFSET + 1] == 0xAA
    )


def mbr_first_a5_slice_byte_offset(data: bytes, *, require_fits_buffer: bool = True) -> int | None:
    """
    If ``data`` starts with a valid MBR boot signature and a **primary** slot has type ``0xA5``,
    return ``LBA_start * 512`` for the **first** such slot (kernel ``parse_freebsd`` entry path).

    Returns ``None`` if no MBR, no ``0xA5`` entry, or ``LBA * 512 == 0`` (would recurse on the same
    sector-0 view).

    When ``require_fits_buffer`` is True (default), the offset must satisfy ``0 < off < len(data)``
    so callers can safely slice ``data[off:]``. When False, only the first 512 bytes are consulted
    for the partition table; offsets may exceed ``len(data)`` (diagnostic / audit use).
    """
    if not mbr_boot_signature_ok(data):
        return None
    for slot in range(4):
        base = MBR_PARTITION_TABLE + slot * PARTITION_ENTRY_LEN
        if base + PARTITION_ENTRY_LEN > len(data):
            break
        if data[base + PARTITION_TYPE_OFFSET] != PTYPE_FREEBSD_A5:
            continue
        lba_start = struct.unpack_from("<I", data, base + PARTITION_LBA_OFFSET)[0]
        off = lba_start * SECTOR_BYTES
        if off == 0:
            continue
        if require_fits_buffer and off >= len(data):
            continue
        return int(off)
    return None
