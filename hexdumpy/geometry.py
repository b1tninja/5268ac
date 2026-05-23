"""Minimal NAND geometry dataclass for hexdumpy.

Replaces the dependency on ``unand.geometry.NandGeometry`` so that
hexdumpy is fully domain-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class NandGeometry:
    """NAND geometry for hexdumpy.

    Parameters
    ----------
    page_data : int
        Main data area bytes per page (e.g. 2048).
    page_spare : int
        Spare/OOB bytes per page (e.g. 64).
    erase_bytes : int
        Erase block size in bytes (e.g. 131072).
    num_blocks : int
        Total number of erase blocks.
    """

    page_data: int
    page_spare: int
    erase_bytes: int
    num_blocks: int

    @property
    def page_phys(self) -> int:
        """Total page + spare bytes (data + OOB)."""
        return self.page_data + self.page_spare

    @property
    def pages_per_block(self) -> int:
        """Pages per erase block."""
        return self.erase_bytes // self.page_data

    @property
    def pages_total(self) -> int:
        """Total NAND pages."""
        return self.num_blocks * self.pages_per_block

    @property
    def logical_bytes(self) -> int:
        """Data plane only (no OOB)."""
        return self.num_blocks * self.erase_bytes

    def __repr__(self) -> str:
        return (
            f"NandGeometry(page_data={self.page_data}, "
            f"page_spare={self.page_spare}, "
            f"erase_bytes={self.erase_bytes}, "
            f"num_blocks={self.num_blocks})"
        )


#: Default preset for Pace 5268AC class NAND.
PACE_DEFAULT = NandGeometry(
    page_data=2048,
    page_spare=64,
    erase_bytes=131072,
    num_blocks=1024,
)