"""Spansion / Catalyst **S34ML** NAND chip family.

Implements the :class:`~unand.chip.NandChip` ABC with spare/OOB decoding
specific to the S34ML large-page format (2048 B data + 64 B spare).

All S34ML models share a common base class **S34ML** — geometry is computed
from a ``DENSITY`` multiplier (``1024 * DENSITY`` erase blocks, each 128 KiB).

Usage::

    from unand.s34ml import S34ML, S34ML01G1, S34MLFamily

    # Chip identity with spare decoding
    chip = S34ML01G1()                    # S34ML01G1 — 128 MiB
    print(chip.geometry)                  # num_blocks=1024

    # Create reader from path / bytes / handle
    reader = S34ML01G1.from_path("TSOP48.B1IN")
    reader = S34ML01G1.from_bytes(raw_nand_bin)
    with open("dump.bin", "rb") as fh:
        reader = S34ML01G1.from_handle(fh)

    # Decode spare/OOB data
    oob = b'\\x00' * 64
    decoded = chip.decode_spare(oob)
    print(decoded['tag'], decoded['phys_block'])

    # Auto-detect from dump size
    chip = S34MLFamily.from_chip("TSOP48.BIN")

--------

Datasheet reference: S34ML01G1 Data Sheet (Micron/Spansion)

**Read Enable bus operation** — Data is serially shifted out on DQ0–DQ7 when:
    RE#   (Read Enable) is toggled low/high
    CE#   (Chip Enable) is low
    WE#   (Write Enable) is high
    ALE#  (Address Latch Enable) is low
    CLE#  (Command Latch Enable) is low

This mode outputs data from the memory array, Status Register content,
EDC (Error Detection Code) register content, and ID register data.

**Status Register 1** (read via Command 70h):
    Bit 0 — Program/Encode Operation Status (0=complete, 1=in progress)
    Bit 1 — Erase Status (0=complete, 1=in progress)
    Bit 2 — Reserved
    Bit 3 — Program Fail Status (0=pass, 1=fail)
    Bit 4 — Erase Fail Status  (0=pass, 1=fail)
    Bit 5 — ECC Status         (0=no uncorrectable errors, 1=uncorrectable)
    Bit 6 — CCE Status (Command/Control Error)
    Bit 7 — Previous Operation Status (mirror of bit 2)

**Status Register 2** (read via Command 71h):
    Bit 0 — Reserved
    Bit 1 — Reserved
    Bit 2 — Bad Block Indicator (0=bad, 1=good)
    Bit 3 — Reserved
    Bit 4 — RBn Status
    Bit 5 — Protection Fail Status
    Bit 6 — Write Fail Status
    Bit 7 — Toggle Status

**ECC/EDC in Spare (OOB) bytes:**
    For the S34ML large-page format (2048 B data + 64 B spare):
      spare[0:3]  — ECC / EDC syndrome bytes
      spare[3]    — Status / class byte (Status Register 1)
      spare[4]    — Tag byte: '\\0' (0x00) or '$' (0x24) = tagged
                   0xFF = erased / not yet programmed
      spare[8]    — Chain/mirror flag bit (bit 4 = duplicate marker)
      spare[9:10] — Physical block address (LE16)
      spare[11:12] — Virtual block ID (LE16)
      spare[13]   — Page index within erase block
      spare[14]   — Checksum / xsum base
      spare[15]   — Stored checksum (must match computed over spare bytes)
      spare[16:17] — Physical address high bytes (32-bit extension)
      spare[18:19] — Virtual address high bytes (32-bit extension)

--------

See also: ``reference/spare64_bbm_field_map.md`` (OpenTL field map),
``opentl/spare_layout.py`` (spare record parsing + checksum),
``opentl/spare_chain_replay.py`` (bad-block chain walk).
"""

from __future__ import annotations

import struct
from abc import ABC
from typing import List

from .chip import NandChip

# ---------------------------------------------------------------------------
# Shared geometry constants for all S34ML models
# ---------------------------------------------------------------------------

#: Data bytes per NAND page
_PAGE_DATA: int = 2048
#: Spare / OOB bytes per NAND page
_PAGE_SPARE: int = 64
#: Erase block size (same for all S34ML)
_ERASE_BYTES: int = 131072  # 128 KiB
#: Pages per erase block (same for all S34ML)
_PAGES_PER_BLOCK: int = 64
#: Base number of erase blocks (multiplied by DENSITY)
_BASE_BLOCKS: int = 1024

# ---------------------------------------------------------------------------
# Status Register bitmasks (per S34ML01G1 datasheet)
# ---------------------------------------------------------------------------

SR1_PROGRAM_STATUS = 0x01  # 0=complete, 1=in progress
SR1_ERASE_STATUS = 0x02  # 0=complete, 1=in progress
SR1_PROGRAM_FAIL = 0x08  # 0=pass, 1=fail
SR1_ERASE_FAIL = 0x10  # 0=pass, 1=fail
SR1_ECC_UNCOR = 0x20  # 0=no uncorrectable, 1=uncorrectable
SR1_CCE = 0x40  # Command/Control Error
SR1_PREVIOUS_STATUS = 0x80  # Mirror of bit 2 (previous op status)

SR2_BAD_BLOCK = 0x04  # 0=bad, 1=good
SR2_RBn = 0x10  # Ready/Busy n
SR2_PROTECTION_FAIL = 0x20  # Write protection fail
SR2_WRITE_FAIL = 0x40  # Write fail
SR2_TOGGLE = 0x80  # Toggle status


def _status_str(flags: int, masks: dict[str, int]) -> str:
    """Build a comma-separated status string from flag bits."""
    parts = []
    for name, bit in masks.items():
        if flags & bit:
            parts.append(name)
    return ",".join(parts) if parts else "OK"


# ---------------------------------------------------------------------------
# Base class: S34ML — all geometry derived from DENSITY
# ---------------------------------------------------------------------------

class S34ML(NandChip):
    """Base class for all Spansion / Catalyst NAND chips.

    Geometry is computed from three class attributes:

    Attributes
    ----------
    FAMILY : str
        Technology family, e.g. ``"S34ML"``.
    DENSITY : str
        Density code, e.g. ``"01G"``, ``"02G"``, ``"04G"``.
    DENSITY_MULT : int
        Integer multiplier for base blocks.  ``num_blocks = 1024 * DENSITY_MULT``.
        A multiplier of 1 → 128 MiB, 2 → 256 MiB, 4 → 512 MiB, etc.
    TECHNOLOGY : str
        Technology name, e.g. ``"NAND Revision 1"``.

    The ``MODEL`` attribute is auto-computed as ``"{FAMILY}{DENSITY}{REVISION}"``
    where ``REVISION`` defaults to 1.

    Usage::

        class S34ML01G1(S34ML):
            FAMILY   = "S34ML"
            DENSITY  = "01G"
            DENSITY_MULT = 1
            TECHNOLOGY = "NAND Revision 1"

        chip = S34ML01G1()
        print(chip.model)       # "S34ML01G1"
        print(chip.geometry)   # num_blocks=1024
    """

    #: Technology family (e.g. "S34ML")
    FAMILY: str = "S34ML"

    #: Density code (e.g. "01G", "02G", "04G") — override in subclass
    DENSITY: str = ""

    #: Multiplier for base block count (num_blocks = 1024 * DENSITY_MULT)
    DENSITY_MULT: int = 1

    #: Technology name (e.g. "NAND Revision 1")
    TECHNOLOGY: str = "NAND Revision 1"

    #: Flash version / revision (defaults to "1")
    REVISION: str = "1"

    #: Model name (e.g. "S34ML01G1") — set explicitly on each subclass
    MODEL: str | None = None

    #: Flash ID
    FLASH_ID: int = 0x01F1

    def __init__(self) -> None:
        super().__init__(
            manufacturer="Spansion",
            model=self.MODEL,
            geometry=NandGeometry(
                model=self.MODEL,
                page_data=_PAGE_DATA,
                page_spare=_PAGE_SPARE,
                erase_bytes=_ERASE_BYTES,
                num_blocks=_BASE_BLOCKS * self.DENSITY_MULT,
            ),
            flash_id=self.FLASH_ID,
        )

    # ------------------------------------------------------------------
    # Spare decoding — NAND-specific fields only
    #
    # OpenTL-specific decoding (virtual/phys block addresses, checksum,
    # chain replay) lives in opentl/spare_layout.py and opentl/spare_chain_replay.py.
    # ------------------------------------------------------------------

    def render_spare_table(self, raw: bytes, page_idx: int, geom) -> str:
        """Render the spare area as a datasheet-accurate table (per Table 9.1).

        Parameters
        ----------
        raw : bytes
            Raw 64-byte spare row.
        page_idx : int
            Page index in the raw dump.
        geom : NandGeometry
            Geometry for logical_offset computation.

        Returns
        -------
        str
            Formatted spare table with field offsets and values.
        """
        if len(raw) < 64:
            raise ValueError(f"Spare must be 64 bytes, got {len(raw)}")

        # Compute data-plane address
        logical_offset = page_idx * geom.page_data
        data_plane_spare_addr = logical_offset + geom.page_data

        lines = []
        lines.append(f"=== Spare Area — Spansion S34ML01G1 (2048+64) ===")
        lines.append(f"")
        lines.append(f"  {'offset':>5s}  {'field':>18s}  {'value':>10s}  {'description'}")
        lines.append(f"  {'-----':>5s}  {'-----':>18s}  {'-----':>10s}  {'-----------'}")

        # Byte 0-2: ECC Syndrome
        ecc0, ecc1, ecc2 = raw[0], raw[1], raw[2]
        lines.append(f"  00h     {'ECC syndrome':>18s}  {ecc0:02x}{ecc1:02x}{ecc2:02x}{'':>6s}  ECC/EDC syndrome bytes (data integrity)")

        # Byte 0: Tag (also in spare[4])
        tag = raw[4]
        if tag == 0xFF:
            tag_desc = "0xFF       erased / not programmed"
        elif 0x20 <= tag <= 0x7E:
            tag_desc = f"0x{tag:02x}      '{chr(tag)}' (printable tag)"
        else:
            tag_desc = f"0x{tag:02x}      non-printable tag"
        lines.append(f"  04h     {'Tag':>18s}  {tag:02x}{'':>12s}  {tag_desc}")

        # Byte 1: Status
        status = raw[3]
        lines.append(f"  03h     {'Status (SR1)':>18s}  {status:02x}{'':>10s}  Status Register 1")

        # Byte 2: Bad Block Indicator
        bbi = raw[2]
        if bbi == 0x00:
            bbi_desc = "0x00       BAD block"
        elif bbi == 0xFF:
            bbi_desc = "0xFF       good block"
        else:
            bbi_desc = f"0x{bbi:02x}      unknown"
        lines.append(f"  02h     {'Bad Block Ind.':>18s}  {bbi:02x}{'':>10s}  {bbi_desc}")

        # Byte 3-4: Physical Block Number (LE16)
        if len(raw) >= 10:
            phys_lo = raw[9] if raw[9] is not None else 0
            phys_hi = raw[10] if raw[10] is not None else 0
            phys_blk = phys_lo | (phys_hi << 8)
            lines.append(f"  09-0Ah  {'Physical Blk':>18s}  {phys_blk:04x}{'':>10s}  Physical block address (LE16)")

        # Byte 5: Additional Spare Data
        lines.append(f"  05h     {'Spare Data':>18s}  {raw[5]:02x}{'':>12s}  Reserved / spare data")

        # Byte 6: XOR Checksum
        lines.append(f"  06h     {'XOR Checksum':>18s}  {raw[6]:02x}{'':>10s}  XOR checksum of first bytes")

        # Bytes 7-5F: Reserved
        lines.append(f"  07-5Fh  {'Reserved':>18s}  {'-':>10s}  Reserved (unused)")

        # Byte 60-63: Page Address
        if len(raw) >= 64:
            page_addr = raw[60] | (raw[61] << 8) | (raw[62] << 16) | (raw[63] << 24) if all(b is not None for b in raw[60:64]) else 0
            lines.append(f"  60-63h  {'Page Address':>18s}  {page_addr:08x}{'':>10s}  Page address in block (LE32)")

        # Summary
        lines.append(f"")
        lines.append(f"  Data-plane address: 0x{data_plane_spare_addr:08x}")
        lines.append(f"  Logical offset:     0x{logical_offset:08x}")

        return "\n".join(lines)

    def decode_spare(self, raw: bytes) -> dict:
        """Decode NAND-specific fields from a 64-byte spare row.

        Returns only datasheet-defined fields:
        - Status registers (SR1, SR2)
        - Bad block indicator (spare[2])
        - ECC syndrome bytes (spare[0:3])
        - Tag byte (spare[4])
        - Chain/mirror flag (spare[8])
        - Raw spare bytes

        For OpenTL-specific decoding (virtual block addresses, checksum),
        use :func:`opentl.spare_layout.parse_spare` → :class:`SpareRecord`.
        """
        if len(raw) != 64:
            raise ValueError(f"S34ML spare must be 64 bytes, got {len(raw)}")

        # Status Register 1 (spare[3])
        sr1 = raw[3]
        sr1_flags = sr1 & 0x7F

        # Bad block indicator (spare[2]) — per datasheet Table 9.1
        bad_block = raw[2] == 0x00  # 0x00 = bad, 0x01 = good

        # ECC syndrome bytes
        ecc0, ecc1, ecc2 = raw[0], raw[1], raw[2]

        # Tag byte (spare[4])
        tag = raw[4]
        tag_str = ""
        if 0x20 <= tag <= 0x7E:
            tag_str = chr(tag)
        elif tag == 0xFF:
            tag_str = "erased"
        else:
            tag_str = f"0x{tag:02x}"

        # Chain/mirror flag (bit 2 of spare[8])
        chain_flag = raw[8] & 0x04

        # Status Register 2 (combine SR1 high bit + spare[8])
        sr2 = (sr1 >> 7) | (raw[8] & 0x80)

        # Erased check
        erased = sum(1 for b in raw if b == 0xFF) > 50

        return dict(
            raw=raw,
            status_register_1=sr1,
            status_register_1_flags=sr1_flags,
            status_register_2=sr2,
            bad_block=bad_block,
            ecc_bytes=(ecc0, ecc1, ecc2),
            tag=tag,
            tag_str=tag_str,
            chain_flag=chain_flag,
            erased=erased,
        )

    def decode_spare_stream(self, raw_all: bytes) -> List[dict]:
        """Decode an entire spare sidecar (all pages) into a list of dicts."""
        n_pages = len(raw_all) // 64
        return [self.decode_spare(raw_all[i * 64:(i + 1) * 64]) for i in range(n_pages)]


# ---------------------------------------------------------------------------
# Concrete chip classes — each sets MODEL + DENSITY
# ---------------------------------------------------------------------------

class S34ML01G1(S34ML):
    """S34ML01G1 — Spansion 128 MiB NAND (2048 B data + 64 B spare, 1024 blocks)."""

    MODEL = "S34ML01G1"
    DENSITY = "01G"
    DENSITY_MULT = 1
    TECHNOLOGY = "NAND Revision 1"


class S34ML02G1(S34ML):
    """S34ML02G1 — Spansion 256 MiB NAND (2048 B data + 64 B spare, 2048 blocks)."""

    MODEL = "S34ML02G1"
    DENSITY = "02G"
    DENSITY_MULT = 2
    TECHNOLOGY = "NAND Revision 1"


class S34ML04G1(S34ML):
    """S34ML04G1 — Spansion 512 MiB NAND (2048 B data + 64 B spare, 4096 blocks)."""

    MODEL = "S34ML04G1"
    DENSITY = "04G"
    DENSITY_MULT = 4
    TECHNOLOGY = "NAND Revision 1"


# ---------------------------------------------------------------------------
# Family: auto-detect from dump size (map built lazily at runtime)
# ---------------------------------------------------------------------------

from .geometry import NandGeometry
from pathlib import Path
from typing import BinaryIO, Union


class S34MLFamily(ABC):
    """Factory for Spansion/Catalyst S34ML chip family.

    Provides ``from_chip()`` that auto-selects the correct chip from
    the size of the input (file path, bytes, or file handle).

    The density map is built lazily at call time from all registered
    chip classes (subclasses of S34ML that have MODEL and DENSITY).
    Add a new model by subclassing S34ML with MODEL + DENSITY — no
    manual map editing needed.
    """

    @staticmethod
    def _density_map() -> dict[int, tuple[str, NandGeometry]]:
        """Build density map from all concrete S34ML subclasses."""
        result = {}
        for cls in S34ML.__subclasses__():
            for subcls in cls.__subclasses__():
                if (hasattr(subcls, "MODEL") and subcls.MODEL
                        and hasattr(subcls, "DENSITY") and subcls.DENSITY):
                    result[subcls.DENSITY] = (subcls.MODEL, subcls().geometry)
            if (hasattr(cls, "MODEL") and cls.MODEL
                    and hasattr(cls, "DENSITY") and cls.DENSITY):
                if cls.__name__ not in ("S34ML",):  # skip base class
                    result[cls.DENSITY] = (cls.MODEL, cls().geometry)
        return result

    @classmethod
    def from_chip(cls, data: Union[str, Path, bytes, BinaryIO]) -> NandChip:
        """Auto-detect the S34ML chip model from input size.

        Parameters
        ----------
        data : str | Path | bytes | BinaryIO
            File path, raw bytes, or a seekable file handle.

        Returns
        -------
        NandChip
            The detected chip identity (model + geometry).
        """
        if isinstance(data, (str, Path)):
            size = Path(data).stat().st_size
        elif isinstance(data, bytes):
            size = len(data)
        else:
            pos = data.tell()
            data.seek(0, 2)
            size = data.tell()
            data.seek(pos)

        map_ = cls._density_map()

        # Match by logical size first
        for density, (model, geom) in map_.items():
            if size == geom.logical_bytes:
                break
        else:
            # Fallback: match by expected inline size
            for density, (model, geom) in map_.items():
                expected_inline = geom.pages_total * geom.page_phys
                if abs(size - expected_inline) < 0.05 * expected_inline:
                    break
            else:
                raise ValueError(
                    f"Size {size} does not match any known S34ML chip. "
                    f"Expected logical sizes: {[g.logical_bytes for _, (_, g) in map_.items()]}"
                )

        return cls._make_chip(model, density)

    @classmethod
    def _make_chip(cls, model: str, density: int) -> NandChip:
        """Create a NandChip instance."""
        for cls in [S34ML01G1, S34ML02G1, S34ML04G1]:
            if cls.MODEL == model:
                return cls()
        raise ValueError(model)

    @classmethod
    def get_default(cls) -> NandChip:
        """Return the default / most common chip for this family."""
        map_ = cls._density_map()
        smallest_density = min(map_)
        model, _ = map_[smallest_density]
        return cls._make_chip(model, smallest_density)


__all__ = [
    "S34ML",
    "S34ML01G1",
    "S34ML02G1",
    "S34ML04G1",
    "S34MLFamily",
    # Status Register bitmasks
    "SR1_ECC_UNCOR",
    "SR1_ERASE_FAIL",
    "SR1_PROGRAM_FAIL",
    "SR2_BAD_BLOCK",
    "SR2_PROTECTION_FAIL",
    "SR2_WRITE_FAIL",
    # Shared constants
    "_PAGE_DATA",
    "_PAGE_SPARE",
    "_ERASE_BYTES",
    "_PAGES_PER_BLOCK",
    "_BASE_BLOCKS",
]
