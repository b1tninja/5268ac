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

**Factory bad-block (datasheet §9.2, ``reference/pdfs/S34ML01G1.PDF`` p.69):**
    On the **1st and 2nd page** of each erase block (0-based **0**, **1**), ``spare[0] != 0xFF``
    marks a factory bad block. This is **not** ``spare[2]`` (ECC2 on programmed pages).
    Runtime failures use Status Register pass/fail (§9.1), not factory spare markers.

**528-byte EDC units (datasheet Table 3.3 / 3.4):**
    Each page = four **512 + 16** byte groups (main + spare tail per sector).
    ``spare[0:2]`` are the ECC syndromes for **sector A** only; §9.2 reuses ``spare[0]`` on pages 0–1.

**Spare bytes often overlaid by OpenTL on Pace dumps** (virt/phys, xsum at ``spare[0x0F]``, tag at ``spare[4]``).
    Use :func:`opentl.spare_layout.parse_spare` for runtime fields; ``decode_spare`` here is chip/datasheet view.

--------

See also: ``reference/spare64_bbm_field_map.md`` (OpenTL field map),
``opentl/spare_layout.py`` (spare record parsing + checksum),
``opentl/spare_chain_replay.py`` (bad-block chain walk).
"""

from __future__ import annotations

from abc import ABC
from pathlib import Path
from typing import BinaryIO, List, Union

from .chip import NandChip
from .geometry import NandGeometry

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

#: Datasheet §9.2 — factory bad-block marker pages (1st and 2nd page, 0-based).
#: ``spare[0]`` on either page must be ``0xFF`` for a good factory block.
FACTORY_BBI_MARKER_PAGES: tuple[int, ...] = (0, 1)

#: EDC unit size per datasheet Table 3.3 (512 B main + 16 B spare per sector).
EDC_UNIT_DATA_BYTES: int = 512
EDC_UNIT_SPARE_BYTES: int = 16
EDC_UNITS_PER_PAGE: int = 4


def factory_bbi_marker_page(page_in_block: int) -> bool:
    """True if ``page_in_block`` is a datasheet §9.2 factory BBI marker page."""
    return page_in_block in FACTORY_BBI_MARKER_PAGES


def factory_bbi_bad_from_spare(spare: bytes, page_in_block: int) -> bool | None:
    """Factory bad-block flag from one spare row (§9.2).

    Returns ``None`` when ``page_in_block`` is not a marker page (1st / 2nd).
    Returns ``True`` when ``spare[0] != 0xFF`` (factory-marked bad).
    """
    if page_in_block not in FACTORY_BBI_MARKER_PAGES:
        return None
    if len(spare) < 1:
        return None
    return spare[0] != 0xFF


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


def _sr1_status_str(sr1: int) -> str:
    masks = {
        "PROG": SR1_PROGRAM_STATUS,
        "ERS": SR1_ERASE_STATUS,
        "PFAIL": SR1_PROGRAM_FAIL,
        "EFAIL": SR1_ERASE_FAIL,
        "ECC_UNCOR": SR1_ECC_UNCOR,
        "CCE": SR1_CCE,
        "PREV": SR1_PREVIOUS_STATUS,
    }
    return _status_str(sr1, masks)


def edc_unit_spare_offset(unit_index: int) -> int:
    """Byte offset within a 64-byte spare row for EDC unit ``unit_index`` (0..3).

    Sector A spare starts at 0; B/C/D at 16/32/48 (Table 3.4 column 2048–2111).
    """
    if not 0 <= unit_index < EDC_UNITS_PER_PAGE:
        raise ValueError(f"unit_index must be 0..{EDC_UNITS_PER_PAGE - 1}, got {unit_index}")
    return unit_index * EDC_UNIT_SPARE_BYTES


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

    def erase_block_factory_bad(self, marker_spares: dict[int, bytes]) -> bool:
        """True if any §9.2 marker page in the block has ``spare[0] != 0xFF``.

        Parameters
        ----------
        marker_spares : dict[int, bytes]
            Spare rows keyed by ``page_in_block`` (typically keys ``0``, ``1``).
        """
        for pinb in FACTORY_BBI_MARKER_PAGES:
            sp = marker_spares.get(pinb)
            if sp is not None and factory_bbi_bad_from_spare(sp, pinb):
                return True
        return False

    def marker_spare_rows_for_block(self, image: bytes, block: int) -> dict[int, bytes]:
        """Return §9.2 marker spare rows for erase block ``block`` (inline 2048+64)."""
        g = self.geometry
        pages_per_block = g.erase_bytes // g.page_data
        if not 0 <= block < g.num_blocks:
            raise IndexError(f"block {block} out of range 0..{g.num_blocks - 1}")
        out: dict[int, bytes] = {}
        for pinb in FACTORY_BBI_MARKER_PAGES:
            page = block * pages_per_block + pinb
            spare_off = page * g.page_phys + g.page_data
            end = spare_off + g.page_spare
            if end > len(image):
                raise ValueError(
                    f"image too short for block {block} page {pinb}: need {end} bytes, have {len(image)}"
                )
            out[pinb] = image[spare_off:end]
        return out

    def scan_factory_bad_blocks(self, image: bytes) -> list[int]:
        """Return erase-block indices factory-marked bad (inline 2048+64 layout)."""
        g = self.geometry
        pages_per_block = g.erase_bytes // g.page_data
        bad: list[int] = []
        for block in range(g.num_blocks):
            for pinb in FACTORY_BBI_MARKER_PAGES:
                page = block * pages_per_block + pinb
                spare_off = page * g.page_phys + g.page_data
                if spare_off + 1 > len(image):
                    return bad
                if image[spare_off] != 0xFF:
                    bad.append(block)
                    break
        return bad

    def factory_bbi_bad_from_block_spares(self, marker_spares: dict[int, bytes]) -> bool:
        """True if §9.2 marks the erase block factory-bad (any marker page ``spare[0] != 0xFF``)."""
        return self.erase_block_factory_bad(marker_spares)

    def render_spare_table(
        self, raw: bytes, page_idx: int, geom, *, page_in_block: int | None = None
    ) -> str:
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

        pinb = page_in_block if page_in_block is not None else (page_idx % _PAGES_PER_BLOCK)
        ecc0, ecc1, ecc2 = raw[0], raw[1], raw[2]
        ecc_note = "ECC/EDC syndrome (bytes 0-2)"
        if factory_bbi_marker_page(pinb):
            if ecc0 == 0xFF:
                ecc_note += "; §9.2 factory BBI good (spare[0]==FF)"
            else:
                ecc_note += f"; §9.2 FACTORY BAD (spare[0]={ecc0:02x})"
        lines.append(
            f"  00-02h  {'ECC / factory BBI':>18s}  {ecc0:02x}{ecc1:02x}{ecc2:02x}{'':>6s}  {ecc_note}"
        )

        # Tag (spare[4])
        tag = raw[4]
        if tag == 0xFF:
            tag_desc = "0xFF       erased / not programmed"
        elif 0x20 <= tag <= 0x7E:
            tag_desc = f"0x{tag:02x}      '{chr(tag)}' (printable tag)"
        else:
            tag_desc = f"0x{tag:02x}      non-printable tag"
        lines.append(f"  04h     {'Tag':>18s}  {tag:02x}{'':>12s}  {tag_desc}")

        status = raw[3]
        lines.append(f"  03h     {'Spare byte 3':>18s}  {status:02x}{'':>10s}  May mirror SR1 (70h) when programmed")

        if len(raw) >= 20:
            phys_blk = raw[9] | (raw[10] << 8)
            virt_blk = raw[11] | (raw[12] << 8)
            lines.append(
                f"  09-0Ah  {'OpenTL phys lo':>18s}  {phys_blk:04x}{'':>10s}  Runtime overlay (not §9.2 factory BBI)"
            )
            lines.append(
                f"  0B-0Ch  {'OpenTL virt lo':>18s}  {virt_blk:04x}{'':>10s}  Runtime overlay"
            )
            lines.append(
                f"  0Dh     {'Page in block':>18s}  {raw[13]:02x}{'':>10s}  OpenTL page index"
            )
            lines.append(
                f"  0Fh     {'OpenTL xsum':>18s}  {raw[15]:02x}{'':>10s}  Stored checksum (opentl/spare_layout)"
            )

        lines.append(f"  05-07h  {'Reserved/vendor':>18s}  {'-':>10s}  Vendor / padding")

        # Summary
        lines.append(f"")
        lines.append(f"  Data-plane address: 0x{data_plane_spare_addr:08x}")
        lines.append(f"  Logical offset:     0x{logical_offset:08x}")

        return "\n".join(lines)

    def decode_spare(self, raw: bytes, *, page_in_block: int | None = None) -> dict:
        """Decode NAND-specific fields from a 64-byte spare row.

        Returns only datasheet-defined fields:
        - Factory bad-block indicator (§9.2: ``spare[0]`` on marker pages 0 and 1)
        - ECC syndrome bytes for EDC unit A (``spare[0:3]``; byte 2 is not factory BBI)
        - Spare byte 3 (may mirror SR1 when programmed — not authoritative on OpenTL dumps)
        - Tag byte (``spare[4]``, often OpenTL class on Pace images)
        - Chain/mirror flag (``spare[8]`` bit 2)

        Pass ``page_in_block`` (0..63) to populate ``factory_bbi_bad``; otherwise it
        is ``None`` (unknown — do not infer factory status from spare[2]).

        For OpenTL-specific decoding (virtual block addresses, checksum),
        use :func:`opentl.spare_layout.parse_spare` → :class:`SpareRecord`.
        """
        if len(raw) != 64:
            raise ValueError(f"S34ML spare must be 64 bytes, got {len(raw)}")

        # Spare byte 3 — on fresh status reads mirrors SR1 (cmd 70h); on dumps often OpenTL data.
        sr1 = raw[3]
        sr1_flags = sr1 & 0x7F

        factory_bbi_bad = (
            factory_bbi_bad_from_spare(raw, page_in_block)
            if page_in_block is not None
            else None
        )

        # ECC syndromes for EDC unit A (large-page Table 3.3)
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

        # Chain/mirror flag (bit 2 of spare[8]) — OpenTL uses bit 4 for duplicate hop
        chain_flag = raw[8] & 0x04

        erased = sum(1 for b in raw if b == 0xFF) > 50

        return dict(
            raw=raw,
            status_register_1=sr1,
            status_register_1_flags=sr1_flags,
            status_register_1_str=_sr1_status_str(sr1),
            program_fail=bool(sr1 & SR1_PROGRAM_FAIL),
            erase_fail=bool(sr1 & SR1_ERASE_FAIL),
            ecc_uncorrectable=bool(sr1 & SR1_ECC_UNCOR),
            factory_bbi_bad=factory_bbi_bad,
            factory_bbi_marker=(
                factory_bbi_marker_page(page_in_block)
                if page_in_block is not None
                else None
            ),
            ecc_bytes=(ecc0, ecc1, ecc2),
            edc_unit_a_spare=(raw[0:16] if len(raw) >= 16 else raw[0:3]),
            tag=tag,
            tag_str=tag_str,
            chain_flag=chain_flag,
            erased=erased,
        )

    def decode_spare_stream(self, raw_all: bytes) -> List[dict]:
        """Decode an entire spare sidecar (all pages) into a list of dicts."""
        n_pages = len(raw_all) // 64
        pages_per_block = self.geometry.erase_bytes // self.geometry.page_data
        return [
            self.decode_spare(
                raw_all[i * 64 : (i + 1) * 64],
                page_in_block=i % pages_per_block,
            )
            for i in range(n_pages)
        ]


# ---------------------------------------------------------------------------
# Concrete chip classes — each sets MODEL + DENSITY
# ---------------------------------------------------------------------------

class S34ML01G1(S34ML):
    """S34ML01G1 — Spansion 128 MiB NAND (2048 B data + 64 B spare, 1024 blocks).

    Datasheet: ``reference/pdfs/S34ML01G1.PDF`` — 1-bit ECC per 528 B, §9.2 factory BBI on
    erase-block pages 0–1, Read ID ``0x01F1`` (matches ``fwupgrade.txt`` ``id 0x01f1``).
    """

    MODEL = "S34ML01G1"
    DENSITY = "01G"
    DENSITY_MULT = 1
    TECHNOLOGY = "NAND Revision 1"
    FLASH_ID = 0x01F1


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
    def _density_map() -> dict[str, tuple[str, NandGeometry]]:
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
    def _make_chip(cls, model: str, density: str) -> NandChip:
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
    "FACTORY_BBI_MARKER_PAGES",
    "factory_bbi_marker_page",
    "factory_bbi_bad_from_spare",
    "edc_unit_spare_offset",
    "EDC_UNIT_DATA_BYTES",
    "EDC_UNIT_SPARE_BYTES",
    "EDC_UNITS_PER_PAGE",
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
