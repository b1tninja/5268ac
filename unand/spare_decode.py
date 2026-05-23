"""Spare (OOB) byte decoding for S34ML large-page NAND.

Parses the **64-byte** spare row into structured fields: EDC / ECC bytes,
Status Register 1 & 2, tag, block/page address, and checksum validation.

Usage::

    from unand import S34MLFamily

    reader = S34MLFamily.from_chip("TSOP48.BIN")
    oob = reader.read_oob(0)          # 64 bytes for page 0
    decoded = decode_spare_oob(oob)
    print(decoded)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional


# ---------------------------------------------------------------------------
# Status Register bitmasks (per S34ML01G1 datasheet)
# ---------------------------------------------------------------------------

# Status Register 1 (bitmasks)
SR1_PROGRAM_STATUS   = 0x01      # 0=complete, 1=in progress
SR1_ERASE_STATUS     = 0x02      # 0=complete, 1=in progress
SR1_PROGRAM_FAIL     = 0x08      # 0=pass, 1=fail
SR1_ERASE_FAIL       = 0x10      # 0=pass, 1=fail
SR1_ECC_UNCOR        = 0x20      # 0=no uncorrectable, 1=uncorrectable
SR1_CCE              = 0x40      # Command/Control Error
SR1_PREVIOUS_STATUS  = 0x80      # Mirror of bit 2 (previous op status)

# Status Register 2 (bitmasks)
SR2_BAD_BLOCK        = 0x04      # 0=bad, 1=good
SR2_RBn              = 0x10      # Ready/Busy n
SR2_PROTECTION_FAIL  = 0x20      # Write protection fail
SR2_WRITE_FAIL       = 0x40      # Write fail
SR2_TOGGLE           = 0x80      # Toggle status


@dataclass
class SpareDecoded:
    """Parsed 64-byte spare / OOB row."""

    #: ECC / EDC syndrome bytes (bytes 0–2 of spare)
    edc_bytes: bytes

    #: Status / class byte (spare[3])
    status_class: int

    #: Tag byte (spare[4]): ``0x00`` = tagged, ``0x24`` = ``'$'``, ``0xFF`` = erased
    tag: int

    #: Tag string representation
    tag_str: str

    #: Chain/mirror flag nibble (spare[8])
    chain_flag: int

    #: Physical block address (LE16 from spare[9:10])
    phys_block: int

    #: Virtual block ID (LE16 from spare[11:12])
    virt_id: int

    #: Page index within erase block (spare[13])
    page_in_block: int

    #: Checksum base (spare[14])
    xsum_base: int

    #: Stored checksum (spare[15])
    xsum_stored: int

    #: Physical address high bytes (LE16 from spare[16:17])
    phys_high: int

    #: Virtual address high bytes (LE16 from spare[18:19])
    virt_high: int

    #: Full 64-byte spare as raw bytes (for reference)
    raw: bytes

    #: Computed checksum over relevant spare bytes
    xsum_computed: int

    #: Checksum match?
    xsum_ok: bool

    #: Status Register 1 decoded (from spare[3])
    sr1_flags: int

    #: Status Register 1 human-readable
    sr1_str: str

    #: Status Register 2 decoded (from spare[8] or spare[3] bit 8+)
    sr2_flags: int

    #: Status Register 2 human-readable
    sr2_str: str

    #: Bad block? (from SR2 bit 2)
    bad_block: bool

    #: ECC / uncorrectable error? (from SR1 bit 5)
    ecc_uncorrectable: bool

    #: Erased / unprogrammed? (spare[4] == 0xFF and most bytes 0xFF)
    erased: bool


def _status_str(flags: int, masks: dict[str, int]) -> str:
    """Build a comma-separated status string from flag bits."""
    parts = []
    for name, bit in masks.items():
        if flags & bit:
            parts.append(name)
    return ",".join(parts) if parts else "OK"


def decode_spare_oob(raw: bytes) -> SpareDecoded:
    """Decode a **64-byte** spare/OOB row into ``SpareDecoded``.

    Parameters
    ----------
    raw : bytes
        Exactly 64 bytes from ``spare_stream()`` or ``read_oob(page_index)``.

    Returns
    -------
    SpareDecoded

    Raises
    ------
    ValueError
        If ``len(raw) != 64``.
    """
    if len(raw) != 64:
        raise ValueError(f"spare row must be 64 bytes, got {len(raw)}")

    # EDC / ECC bytes (first 3 bytes)
    edc_bytes = raw[0:3]

    # Status / class byte
    status_class = raw[3]

    # Tag byte
    tag = raw[4]
    tag_byte = chr(tag) if 0x20 <= tag <= 0x7E else ""
    tag_str = tag_byte if tag_byte else (
        "erased" if tag == 0xFF else f"0x{tag:02x}"
    )

    # Chain / mirror flag (bit 4 of spare[8] is duplicate/mirror marker)
    chain_flag = raw[8] & 0x0F

    # Physical block address (LE16)
    phys_block = struct.unpack_from("<H", raw, 9)[0]

    # Virtual block ID (LE16)
    virt_id = struct.unpack_from("<H", raw, 11)[0]

    # Page index within erase block
    page_in_block = raw[13]

    # Checksum
    xsum_base = raw[14]
    xsum_stored = raw[15]

    # High bytes (32-bit extension)
    phys_high = struct.unpack_from("<H", raw, 16)[0]
    virt_high = struct.unpack_from("<H", raw, 18)[0]

    # Compute checksum (matches ntl_compute_spare_xsum in kernel)
    # Sum of key spare bytes as signed int8
    def i8(b: int) -> int:
        return b if b < 128 else b - 256

    partial = i8(raw[9]) + i8(raw[10]) + i8(raw[11]) + i8(raw[12])
    # Large page: include high bytes
    partial += i8(raw[16]) + i8(raw[17])
    xsum_computed = i8(raw[8]) + i8(raw[13]) + i8(raw[14]) + partial
    xsum_computed = xsum_computed & 0xFF  # mask to byte
    xsum_ok = (xsum_computed & 0xFF) == xsum_stored

    # Status Register 1 (from spare[3] — status_class byte)
    sr1_flags = status_class & 0x7F  # lower 7 bits
    sr1_masks = {
        "PROGRAM": SR1_PROGRAM_STATUS,
        "ERASE": SR1_ERASE_STATUS,
        "PGRM_FAIL": SR1_PROGRAM_FAIL,
        "ERASE_FAIL": SR1_ERASE_FAIL,
        "ECC_UNC": SR1_ECC_UNCOR,
        "CCE": SR1_CCE,
    }
    sr1_str = _status_str(sr1_flags, sr1_masks)

    # Status Register 2 (often in spare[3] upper bits or spare[8])
    sr2_raw = (status_class >> 7) | (raw[8] & 0x80)  # combine for SR2
    sr2_masks = {
        "BAD_BLOCK": SR2_BAD_BLOCK,
        "PROT_FAIL": SR2_PROTECTION_FAIL,
        "WR_FAIL": SR2_WRITE_FAIL,
        "TOGGLE": SR2_TOGGLE,
    }
    sr2_str = _status_str(sr2_raw, sr2_masks)

    bad_block = bool(sr2_raw & SR2_BAD_BLOCK)
    ecc_unc = bool(sr1_flags & SR1_ECC_UNCOR)

    # Erased check: most bytes should be 0xFF
    ff_count = sum(1 for b in raw if b == 0xFF)
    erased = ff_count > 50  # >78% FF = likely erased

    return SpareDecoded(
        edc_bytes=edc_bytes,
        status_class=status_class,
        tag=tag,
        tag_str=tag_str,
        chain_flag=chain_flag,
        phys_block=phys_block,
        virt_id=virt_id,
        page_in_block=page_in_block,
        xsum_base=xsum_base,
        xsum_stored=xsum_stored,
        phys_high=phys_high,
        virt_high=virt_high,
        raw=raw,
        xsum_computed=xsum_computed,
        xsum_ok=xsum_ok,
        sr1_flags=sr1_flags,
        sr1_str=sr1_str,
        sr2_flags=sr2_raw,
        sr2_str=sr2_str,
        bad_block=bad_block,
        ecc_uncorrectable=ecc_unc,
        erased=erased,
    )


def decode_spare_stream(spare_bytesio) -> List[SpareDecoded]:
    """Decode an entire spare sidecar (``BytesIO``) into a list of ``SpareDecoded``.

    Parameters
    ----------
    spare_bytesio : io.BytesIO
        The output of ``reader.spare_stream()`` — 4 MiB for S34ML01G1.

    Returns
    -------
    list[SpareDecoded]
        One entry per NAND page, in chip order.
    """
    spare_bytesio.seek(0)
    raw_data = spare_bytesio.read()
    n_pages = len(raw_data) // 64
    result = []
    for i in range(n_pages):
        chunk = raw_data[i * 64 : (i + 1) * 64]
        result.append(decode_spare_oob(chunk))
    return result


def summary(decoded: List[SpareDecoded]) -> str:
    """Print a compact summary of decoded spare rows.

    Columns: page, tag, phys_block, virt_id, page_in_block, xsum_ok,
    bad_block, ecc_unc, erased.
    """
    lines = [f"{'pg':>6} {'tag':>5} {'pb':>5} {'vid':>5} {'ppb':>3} "
             f"{'cksum':>5} {'bad':>4} {'ecc':>4} {'erased':>6}"]
    lines.append("-" * len(lines[0]))
    for d in decoded:
        lines.append(
            f"{d.phys_block * 64 + d.page_in_block:>6} "
            f"{d.tag_str:>5} "
            f"{d.phys_block:>5} "
            f"{d.virt_id:>5} "
            f"{d.page_in_block:>3} "
            f"{'OK' if d.xsum_ok else 'FAIL':>5} "
            f"{'Y' if d.bad_block else '-':>4} "
            f"{'Y' if d.ecc_uncorrectable else '-':>4} "
            f"{'Y' if d.erased else 'N':>6}"
        )
    return "\n".join(lines)