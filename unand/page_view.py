"""PageView generation for NAND dumps — converts raw page pairs to offset-aware views.

This module sits between :class:`unand.reader.NandPageReader` and **hexdumpy**.
It produces :class:`hexdumpy.PageView` named tuples with correct
``logical_offset`` (data-plane address) and ``absolute_offset`` (raw-file
address) for each packing layout.

Usage::

    from unand.page_view import PageIterator

    with NandPageReader(path, geom=geom) as reader:
        for page in PageIterator(reader, layout="inline"):
            print(f"Page {page.page_idx}: data={len(page.data)}, "
                  f"logical=0x{page.logical_offset:x}, "
                  f"absolute=0x{page.absolute_offset:x}")
"""

from __future__ import annotations

from typing import Iterator, Optional

from hexdumpy import PageView
from unand.reader import NandPageReader

PagePair = tuple[int, bytes, bytes]  # (page_idx, data, spare)


class PageIterator:
    """Transforms :class:`NandPageReader` output into :class:`PageView` objects.

    Parameters
    ----------
    reader : NandPageReader
        The raw page reader (yields ``(page_idx, data, spare)`` tuples).
    geom : NandGeometry
        NAND geometry for offset arithmetic.
    layout : str
        The packing layout:

        - **``"inline"``** — data and spare interleaved per page:
          ``[data0][spare0][data1][spare1]...``
          File address = page_idx × (page_data + page_spare)
        - **``"flat_tail"``** — all data pages first, then all spare pages:
          ``[all_data][all_spare]``
          File address = page_idx × page_data (spare is at end)
        - **``"logical"``** — data plane only, no spare:
          File address = page_idx × page_data, spare = empty
    """

    def __init__(
        self,
        reader: NandPageReader,
        geom,
        *,
        layout: str = "inline",
    ):
        self.reader = reader
        self.geom = geom
        self.layout = layout

    def __iter__(self) -> Iterator[PageView]:
        """Yield :class:`PageView` for each page with correct offsets."""
        for page_idx, data, spare in self.reader:
            if self.layout == "flat_tail":
                # In flat-tail, the reader already returns data from the
                # flat region. The file address equals the logical address
                # because all pages are contiguous data.
                logical_offset = page_idx * self.geom.page_data
                absolute_offset = page_idx * self.geom.page_data
                # In flat-tail, spare may come from a separate area of the file.
                # If spare is None or empty, it means the spare data is
                # appended after all data pages in the file — we still
                # track it correctly.
                if spare and len(spare) > 0:
                    page_spare_size = len(spare)
                else:
                    page_spare_size = self.geom.page_spare

                yield PageView(
                    data=data,
                    spare=spare if spare else b"",
                    logical_offset=logical_offset,
                    absolute_offset=absolute_offset,
                    page_data_size=len(data),
                    page_spare_size=page_spare_size,
                )

            elif self.layout == "logical":
                # Data plane only — no spare bytes
                yield PageView(
                    data=data,
                    spare=b"",
                    logical_offset=page_idx * self.geom.page_data,
                    absolute_offset=page_idx * self.geom.page_data,
                    page_data_size=len(data),
                    page_spare_size=0,
                )

            else:  # "inline" (default)
                # data and spare are interleaved per page in the file.
                logical_offset = page_idx * self.geom.page_data
                absolute_offset = page_idx * self.geom.page_phys
                yield PageView(
                    data=data,
                    spare=spare,
                    logical_offset=logical_offset,
                    absolute_offset=absolute_offset,
                    page_data_size=self.geom.page_data,
                    page_spare_size=self.geom.page_spare,
                )


class PageIteratorFactory:
    """Creates a PageIterator with the correct layout for a given path.

    Parameters
    ----------
    path : str
        Path to the NAND dump file.
    geom : NandGeometry
        NAND geometry.
    """

    def __init__(self, path: str, geom):
        self.path = path
        self.geom = geom

    def from_layout(self, layout: str) -> PageIterator:
        """Create a PageIterator with the specified layout."""
        reader = NandPageReader(self.path, geom=self.geom)
        return PageIterator(reader, self.geom, layout=layout)