"""Byte-range view of a slice inside a backing file or in-memory flash image."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias


@dataclass(frozen=True, slots=True)
class AssembledBlockDev:
    """
    Read-only slice whose bytes were **already** assembled (e.g. OpenTL virt→phys for a TL child).

    Use :class:`BlockDev` for a contiguous range on linear flash; use this when the payload does not
    map to a single ``(offset, size)`` on the backing image.
    """

    label: str
    size: int
    data: bytes

    def read_slice(self) -> bytes:
        if len(self.data) != self.size:
            raise RuntimeError(f"AssembledBlockDev {self.label!r}: size {self.size} != len(data) {len(self.data)}")
        return self.data


@dataclass(frozen=True, slots=True)
class BlockDev:
    """Read-only slice ``[offset, offset+size)`` in ``backing`` (path or whole-image ``bytes``)."""

    backing: Path | bytes
    offset: int
    size: int
    label: str

    @property
    def backing_path(self) -> Path:
        """Disk path when ``backing`` is a :class:`pathlib.Path`; raises for in-memory backings."""
        if not isinstance(self.backing, Path):
            raise TypeError("BlockDev is memory-backed; use read_slice() instead of backing_path")
        return self.backing

    def read_slice(self) -> bytes:
        if isinstance(self.backing, Path):
            with self.backing.open("rb") as f:
                f.seek(self.offset)
                data = f.read(self.size)
            if len(data) != self.size:
                raise ValueError(
                    f"short read on {self.backing} at {self.offset:#x}: need {self.size} got {len(data)}"
                )
            return data
        mv = memoryview(self.backing)
        end = self.offset + self.size
        if self.offset < 0 or end > len(self.backing):
            raise ValueError(
                f"slice [{self.offset:#x}, {end:#x}) exceeds backing length {len(self.backing)}"
            )
        return bytes(mv[self.offset : end])


BlockSlice: TypeAlias = BlockDev | AssembledBlockDev
