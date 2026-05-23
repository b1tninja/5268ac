"""
5268-class Pace / BCM large-page NAND geometry (clean-room from reference docs).

Each **page** is **page_data** bytes of main (MTD/logical) plus **page_spare** bytes of
OOB for that same page — not per 512-byte OpenTL sector. See package ``README.md``.
"""

from __future__ import annotations

from dataclasses import dataclass


#region kernel_adjacent Pace5268_NandGeometry (issue.md dump layout; printk-class constants)
@dataclass(frozen=True, slots=True)
class NandGeometry:
    """NAND flash device identity + geometry metadata (replaces SpareInfo).

    Parameters
    ----------
    model : str
        Part number, e.g. ``"S34ML01G1"``.
    page_data : int
        Main data bytes per NAND page (e.g. 2048).
    page_spare : int
        OOB / spare bytes per NAND page (e.g. 64).
    erase_bytes : int
        Erase block size in bytes (e.g. 131072 = 128 KiB).
    num_blocks : int
        Total erase blocks on the chip.
    """

    model: str = ""
    page_data: int = 2048
    page_spare: int = 64
    erase_bytes: int = 131072  # 128 KiB
    num_blocks: int = 1024

    @property
    def page_phys(self) -> int:
        """Total bytes per NAND page including spare (page_data + page_spare)."""
        return self.page_data + self.page_spare

    @property
    def pages_per_block(self) -> int:
        """Pages per erase block = erase_bytes // page_data."""
        return self.erase_bytes // self.page_data

    @property
    def pages_total(self) -> int:
        """Total NAND pages = num_blocks × pages_per_block."""
        return self.num_blocks * self.pages_per_block

    @property
    def logical_bytes(self) -> int:
        """MTD data-plane size = pages_total × page_data."""
        return self.pages_total * self.page_data

    @property
    def oob_total_bytes(self) -> int:
        """Total spare / OOB bytes = pages_total × page_spare."""
        return self.pages_total * self.page_spare

    @property
    def spare_total_bytes(self) -> int:
        """Alias for :py:attr:`oob_total_bytes`."""
        return self.oob_total_bytes

    @property
    def full_inline_bytes(self) -> int:
        """Full chip image with inline data+spare packing (2112 B × pages)."""
        return self.pages_total * self.page_phys

    @property
    def full_flat_tail_bytes(self) -> int:
        """Full chip image with flat data-then-spare packing."""
        return self.logical_bytes + self.oob_total_bytes


PACE_DEFAULT = NandGeometry()

#endregion


#region kernel_adjacent FLASH_ID_Pace5268 (fwupgrade.txt + hardware.md)
# Observed on Pace 5268 capture (fwupgrade.txt + hardware.md)
FLASH_ID_PACE = 0x01F1


def assert_full_dump_size(geom: NandGeometry, size: int) -> None:
    if size not in (geom.logical_bytes, geom.full_inline_bytes, geom.full_flat_tail_bytes):
        raise ValueError(
            f"Unexpected dump size {size}; expected one of "
            f"{geom.logical_bytes}, {geom.full_inline_bytes}, {geom.full_flat_tail_bytes}"
        )


#endregion


def effective_mtd_reference_size(file_size: int, *, geom: NandGeometry = PACE_DEFAULT) -> int:
    """
    Byte length used as ``image_size`` / ``logical_total`` when laying out ``mtdparts``.

    Pace-class full-chip dumps pack spare after (or interleaved with) the main plane;
    ``mtdparts`` byte offsets apply only to the **logical** MTD-sized region
    (``geom.logical_bytes``, e.g. 128 MiB).
    """
    if file_size == geom.logical_bytes:
        return file_size
    if file_size in (geom.full_inline_bytes, geom.full_flat_tail_bytes):
        return geom.logical_bytes
    return file_size
