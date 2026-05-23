"""NAND chip identity and geometry metadata — with spare/OOB decoding.

The ``NandChip`` class carries device identity **and** defines an interface
for decoding the 64-byte spare/OOB rows.  Concrete chip families
(``S34MLFamily``, etc.) implement the spare-decoding methods so
the correct field map is used for each device.

Usage::

    from unand import S34ML01G1, S34MLFamily

    # Chip identity
    print(S34ML01G1)                # NandChip(Spansion S34ML01G1)
    print(S34ML01G1.geometry)       # NandGeometry with page_spare=64

    # Create a concrete chip preset via family factory
    chip = S34MLFamily.from_chip("TSOP48.BIN")
    print(chip.geometry)            # NandGeometry(S34ML01G1, ...)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import BinaryIO, List


class NandChip(ABC):
    """Abstract class: NAND flash device identity + spare/OOB decoding.

    Subclasses provide:
      - **Identity** — manufacturer, model, geometry, flash ID
      - **Spare info** — how spare rows are laid out
      - **Decoding** — parse spare bytes into structured fields (ECC, status,
        tag, block/page address, checksum)
    """

    __slots__ = ("manufacturer", "model", "geometry", "flash_id")

    def __init__(
        self,
        manufacturer: str,
        model: str,
        geometry: "NandGeometry" = None,  # type: ignore[assignment]
        flash_id: int | None = None,
    ) -> None:
        self.manufacturer = manufacturer
        self.model = model
        self.geometry = geometry
        self.flash_id = flash_id

    # ------------------------------------------------------------------
    # Abstract: spare information
    # ------------------------------------------------------------------

    @property
    def spare_info(self) -> "NandGeometry":
        """Return the geometry metadata for this chip model.

        Override in subclasses to provide chip-specific spare info, or
        just return ``self.geometry`` when geometry covers the needed data.
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement spare_info")

    # ------------------------------------------------------------------
    # Abstract: spare decoding
    # ------------------------------------------------------------------

    @abstractmethod
    def decode_spare(self, raw: bytes) -> dict:
        """Decode a single **64-byte** spare row into a dict (or dataclass).

        Parameters
        ----------
        raw : bytes
            Exactly ``spare_info.page_spare`` bytes.

        Returns
        -------
        dict / dataclass
            Parsed spare fields: ECC, Status Register, tag, address,
            page index, checksum, etc.

        Raises
        ------
        ValueError
            If ``len(raw) != spare_info.page_spare``.
        """

    @abstractmethod
    def decode_spare_stream(self, raw_all: bytes) -> List[dict]:
        """Decode an entire spare sidecar (all pages).

        Parameters
        ----------
        raw_all : bytes
            Raw spare bytes for all pages: ``pages_total × page_spare`` bytes.

        Returns
        -------
        list[dict]
            One decoded spare entry per NAND page, in chip order.
        """

    # ------------------------------------------------------------------
    # Concrete helpers
    # ------------------------------------------------------------------

    @property
    def pages_total(self) -> int:
        """Total NAND pages on this chip."""
        g = self.geometry
        return g.num_blocks * (g.erase_bytes // g.page_data)

    def __repr__(self) -> str:
        return f"NandChip({self.manufacturer} {self.model})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NandChip):
            return False
        return (
            self.manufacturer == other.manufacturer
            and self.model == other.model
            and self.geometry == other.geometry
        )

    def __hash__(self) -> int:
        return hash((self.manufacturer, self.model, self.geometry))

    # ------------------------------------------------------------------
    # Factory: create NANDReader from path / bytes / handle
    # (Import is lazy to avoid circular import with reader module)
    # ------------------------------------------------------------------

    @classmethod
    def from_path(cls, path: str | Path) -> "NANDReader":
        """Return ``NANDReader`` for *path*, preset with this chip's geometry."""
        from .reader import NANDReader
        return NANDReader.from_path(path, chip=cls())  # type: ignore[return-value]

    @classmethod
    def from_bytes(cls, data: bytes) -> "NANDReader":
        """Return ``NANDReader`` from raw NAND dump bytes."""
        from .reader import NANDReader
        return NANDReader.from_bytes(data, chip=cls())  # type: ignore[return-value]

    @classmethod
    def from_handle(cls, handle: BinaryIO) -> "NANDReader":
        """Return ``NANDReader`` from a seekable file handle."""
        from .reader import NANDReader
        return NANDReader.from_handle(handle, chip=cls())  # type: ignore[return-value]