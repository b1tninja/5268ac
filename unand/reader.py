"""Stream a NAND dump page-by-page using data+spare page pairs.

Usage::

    from unand.reader import NandPageReader
    from unand.geometry import PACE_DEFAULT

    with NandPageReader("dump.bin", geom=PACE_DEFAULT) as reader:
        for page_idx, data, spare in reader:
            print(page_idx, len(data), len(spare))

    # Range-limited iteration (no seeking)
    with NandPageReader("dump.bin", geom=PACE_DEFAULT,
                        page_range=(100, 199)) as reader:
        for page_idx, data, spare in reader:
            print(page_idx)
"""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, Iterator, Optional, Tuple

from unand.geometry import NandGeometry, PACE_DEFAULT


class NANDReader:
    """In-memory NAND reader (deprecated: use NandPageReader for streaming).

    This class loads the entire file into memory and provides page-level
    access by index.  For large dumps, prefer :class:`NandPageReader` which
    streams page-by-page without full-file memory load.
    """

    def __init__(
        self,
        path: str | Path,
        geom: NandGeometry = PACE_DEFAULT,
        page_range: Optional[Tuple[int, int]] = None,
    ):
        self._path = Path(path)
        self._geom = geom
        self._page_range = page_range
        self._raw = bytearray()
        self._load()

    def _load(self) -> None:
        with open(self._path, "rb") as f:
            self._raw.extend(f.read())

    @property
    def geom(self) -> NandGeometry:
        return self._geom

    def data_page(self, idx: int) -> bytes:
        """Return data region bytes for page *idx*."""
        geom = self._geom
        start = idx * (geom.page_data + geom.page_spare)
        end = start + geom.page_data
        return bytes(self._raw[start:end])

    def spare_page(self, idx: int) -> bytes:
        """Return spare region bytes for page *idx*."""
        geom = self._geom
        data_start = idx * (geom.page_data + geom.page_spare)
        spare_start = data_start + geom.page_data
        spare_end = spare_start + geom.page_spare
        return bytes(self._raw[spare_start:spare_end])

    def page(self, idx: int) -> Tuple[bytes, bytes]:
        """Return ``(data, spare)`` for page *idx*."""
        return self.data_page(idx), self.spare_page(idx)

    def total_pages(self) -> int:
        """Total pages in the file."""
        return len(self._raw) // (self._geom.page_data + self._geom.page_spare)

    def __len__(self) -> int:
        return self.total_pages()

    def __repr__(self) -> str:
        return f"NANDReader({self._path!r}, pages={self.total_pages()})"


class NandPageReader:
    """Stream a raw NAND dump page-by-page (data + spare pairs).

    This class uses **sequential iteration only** -- no ``seek``/``tell``.
    It reads pages in order from the file, making it compatible with any
    stream type (files, pipes, sockets, etc.).

    Parameters
    ----------
    path : str | Path
        Path to the raw NAND dump file.
    geom : NandGeometry
        NAND geometry describing page/erase sizes. Defaults to PACE_DEFAULT.
    page_range : tuple[int, int] | None
        (start_page, end_page) inclusive.  Pages before *start_page* are
        skipped sequentially (no seeking).  Only pages within the range
        are yielded by the iterator.  If *None*, all pages from 0 through
        ``geom.pages_total - 1`` are yielded.
    """

    def __init__(
        self,
        path: str | Path,
        geom: NandGeometry = PACE_DEFAULT,
        page_range: Optional[Tuple[int, int]] = None,
    ):
        self._path = Path(path)
        self._geom = geom

        # Determine which pages to yield
        start_page: int
        end_page: int
        if page_range is not None:
            start_page = page_range[0]
            end_page = page_range[1]
        else:
            start_page = 0
            end_page = geom.pages_total - 1

        self._yield_from = max(0, start_page)
        self._yield_until = min(end_page, geom.pages_total - 1)
        self._total_yield = max(0, self._yield_until - self._yield_from + 1)

    @property
    def geom(self) -> NandGeometry:
        return self._geom

    def __enter__(self) -> "NandPageReader":
        self._fp: Optional[BinaryIO] = open(self._path, "rb")
        return self

    def __exit__(self, *args) -> None:
        fp = self._fp
        if fp is not None:
            fp.close()
            self._fp = None

    def __iter__(self) -> Iterator[Tuple[int, bytes, bytes]]:
        """Yield ``(page_index, data_bytes, spare_bytes)`` for each page
        within the configured *page_range*.  Pages before the range are
        skipped sequentially (no seeking).
        """
        fp = self._fp
        if fp is None:
            fp = open(self._path, "rb")
            close_after = True
        else:
            close_after = False

        try:
            geom = self._geom
            page_data = geom.page_data
            page_spare = geom.page_spare
            page_phys = page_data + page_spare

            # Total bytes to read (all pages from 0 to end)
            total_bytes = (geom.pages_total) * page_phys

            skipped = 0          # pages skipped before range
            yielded = 0          # pages yielded so far

            while yielded < self._total_yield and skipped < geom.pages_total:
                # Bytes for one full page (data + spare)
                read_bytes = min(page_phys, total_bytes - skipped * page_phys)
                chunk = fp.read(read_bytes)
                if len(chunk) < read_bytes:
                    break  # EOF

                page_idx = skipped

                if skipped < self._yield_from:
                    # Before range: skip this page
                    skipped += 1
                    continue

                # Within range: extract data + spare from chunk
                data = chunk[:page_data]
                spare = chunk[page_data:page_data + page_spare]

                # Pad if partial read (last page may be short)
                if len(data) < page_data:
                    data = data + bytes(b'\xff' for _ in range(page_data - len(data)))
                if len(spare) < page_spare:
                    spare = spare + bytes(b'\xff' for _ in range(page_spare - len(spare)))

                yield page_idx, data, spare
                yielded += 1
                skipped += 1

        finally:
            if close_after:
                fp.close()