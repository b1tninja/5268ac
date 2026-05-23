"""Lazy byte sequences over NAND dump buffers — zero-copy virtual planes.

A :class:`VirtualPlane` wraps a subset of the raw dump buffer and provides
``bytes``-like access (slicing, iteration) without materializing the data in
memory.  Call ``.to_bytesio()`` or ``bytes(vp)`` when you need a full copy.

Usage::

    from unand import NANDReader

    reader = NANDReader.from_path("dump.bin", chip=chip)

    # Lazy views — no memory copy
    logical = reader.logical_plane()    # VirtualPlane
    spare   = reader.spare_stream()     # VirtualPlane | None

    # Slice without copying (returns small bytes object)
    page0_data = logical[0:2048]

    # Iterate one byte at a time
    for byte in logical:
        ...

    # Materialize when needed
    bio = logical.to_bytesio()          # BytesIO
    full = bytes(logical)               # bytes (full materialization)
"""

from __future__ import annotations

import io
from typing import Iterator


class VirtualPlane:
    """Zero-copy lazy view over a **contiguous** region of the raw NAND dump.

    Parameters
    ----------
    source : bytes
        The underlying buffer (reference, not a copy).
    offset : int
        Starting position in *source*.
    length : int
        Number of bytes to expose.

    Example::

        logical = VirtualPlane(data, offset=0, length=134217728)
        bio = logical.to_bytesio()   # materialize on demand
        slice_ = logical[0x1000:0x2000]  # small slice — returns bytes
    """

    __slots__ = ("_source", "_offset", "_length")

    def __init__(self, source: bytes, offset: int, length: int) -> None:
        self._source = source
        self._offset = offset
        self._length = length

    # ------------------------------------------------------------------
    # Protocol
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        """Number of bytes in this plane."""
        return self._length

    def __getitem__(self, key):
        """Return a bytes object from the underlying buffer.

        Supports integer indexing and slicing.  Raises ``IndexError`` for
        out-of-bounds access.
        """
        source = self._source
        base = self._offset
        length = self._length

        if isinstance(key, int):
            idx = key if key >= 0 else length + key
            if idx < 0 or idx >= length:
                raise IndexError(f"VirtualPlane index {key} out of range [{length}]")
            return bytes(source[base + idx])

        if isinstance(key, slice):
            start, stop, step = key.indices(length)
            if start >= length or stop <= 0 or start >= stop:
                return b""
            abs_start = base + start
            abs_stop = base + stop
            return bytes(source[abs_start:abs_stop:step])

        raise TypeError(f"VirtualPlane indices must be integers or slices, got {type(key).__name__}")

    def __bytes__(self) -> bytes:
        """Materialize the entire plane as bytes."""
        return bytes(self._source[self._offset : self._offset + self._length])

    def __iter__(self) -> Iterator[int]:
        """Iterate one **integer** byte at a time."""
        src = self._source
        base = self._offset
        length = self._length
        for i in range(length):
            yield src[base + i]

    def __repr__(self) -> str:
        return f"VirtualPlane(length={self._length}, offset={self._offset})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, VirtualPlane):
            return (
                self._source is other._source
                and self._offset == other._offset
                and self._length == other._length
            )
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self._source, self._offset, self._length))

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def to_bytesio(self) -> "io.BytesIO":
        """Materialize and return a ``BytesIO``.

        This is the only operation that copies data — use lazy slicing or
        iteration when possible.
        """
        return io.BytesIO(bytes(self))

    def chunk_iter(self, chunk_size: int) -> Iterator[bytes]:
        """Yield *chunk_size*-byte segments from this plane.

        Parameters
        ----------
        chunk_size : int
            Number of bytes per chunk.  The final chunk may be smaller.

        Example::

            for chunk in logical.chunk_iter(1024 * 1024):
                # process 1 MiB at a time
                ...
        """
        src = self._source
        base = self._offset
        length = self._length
        end = base + length
        pos = base
        while pos < end:
            take = min(chunk_size, end - pos)
            yield bytes(src[pos : pos + take])
            pos += take

    def read(self, offset: int, length: int) -> bytes:
        """Read *length* bytes starting at *offset* (convenience alias)."""
        if offset < 0 or length < 0 or offset + length > self._length:
            raise IndexError((offset, length))
        return bytes(self._source[self._offset + offset : self._offset + offset + length])


# ---------------------------------------------------------------------------
# Scattered-access VirtualPlane subclass for INLINE layout
# ---------------------------------------------------------------------------

class _InlineScattered(VirtualPlane):
    """VirtualPlane that reads from **scattered** (interleaved) offsets.

    Used for NAND dumps with INLINE (data+spare alternating) packing.
    The offset/length in the parent class track logical layout; actual
    buffer reads compute page-relative source offsets on the fly.
    """

    __slots__ = ("_page_phys", "_unit_size")

    def __init__(
        self,
        source: bytes,
        logical_length: int,
        page_phys: int,
        unit_size: int,
    ) -> None:
        """
        Parameters
        ----------
        source : bytes
            Raw dump buffer.
        logical_length : int
            Total logical bytes (pages × unit_size).
        page_phys : int
            Total bytes per NAND page including OOB (e.g. 2112).
        unit_size : int
            Bytes per page we expose (main data or spare, e.g. 2048 or 64).
        """
        super().__init__(source, 0, logical_length)
        self._page_phys = page_phys
        self._unit_size = unit_size

    def _src_off(self, logical_idx: int) -> int:
        """Map logical index → actual source buffer offset."""
        page = logical_idx // self._unit_size
        off_in_page = logical_idx % self._unit_size
        return page * self._page_phys + off_in_page

    def __getitem__(self, key):
        source = self._source
        length = self._length
        unit = self._unit_size

        if isinstance(key, int):
            idx = key if key >= 0 else length + key
            if idx < 0 or idx >= length:
                raise IndexError(f"VirtualPlane index {key} out of range [{length}]")
            return bytes(source[self._src_off(idx)])

        if isinstance(key, slice):
            start, stop, step = key.indices(length)
            if start >= length or stop <= 0 or start >= stop:
                return b""
            result = bytearray()
            idx = start
            while idx < stop:
                result.append(source[self._src_off(idx)])
                idx += step if step != 0 else 1
            return bytes(result)

        raise TypeError(f"VirtualPlane indices must be integers or slices, got {type(key).__name__}")

    def __bytes__(self) -> bytes:
        result = bytearray()
        for i in range(self._length):
            result.append(self._source[self._src_off(i)])
        return bytes(result)

    def chunk_iter(self, chunk_size: int) -> Iterator[bytes]:
        """Yield chunk_size bytes from scattered plane."""
        result = bytearray()
        remaining = self._length
        while remaining > 0:
            take = min(chunk_size, remaining)
            end_logical = take  # relative to current chunk start
            for i in range(end_logical):
                result.append(self._source[self._src_off(i)])
            yield bytes(result)
            result.clear()
            remaining -= take