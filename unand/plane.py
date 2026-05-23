"""
Random access on the **128 MiB MTD data plane** (main bytes only) plus per-page OOB.

``read`` / ``read_page`` use **logical** main offsets (same namespace as ``mtdparts``).
``read_oob_page`` returns the **64** spare bytes for that **NAND page index**, not for a
512-byte OpenTL sector. See package ``README.md``.

**Kernel RE:** Python sources that mirror driver behavior use ``#region kernel: 0x…`` comments;
host-side helpers use ``#region kernel_adjacent``. See ``reference/kernel_python_regions.md``.
"""

from __future__ import annotations

import mmap
from pathlib import Path

from unand.geometry import NandGeometry, PACE_DEFAULT
from unand.layout import LayoutDetectionError, RawDumpLayout, detect_layout_file


class LogicalPlane:
    """
    Random-access view of the **128 MiB** MTD **main** plane plus per-page **64**-byte OOB.

    Use this as the stable façade when a path may be **LOGICAL_ONLY**, **INLINE_2048_64**, or
    **FLAT_TAIL_2048_64**: :meth:`open_file` runs layout detection; :meth:`flat_spare_bytes` returns
    the full **4 MiB** flat spare when OOB is in-file; :meth:`materialize_logical_plane` writes a
    contiguous logical image for tools that cannot read interleaved raw dumps. OpenTL **tl-mount**
    and :meth:`opentl.open_tl.OpenTL.from_flash_path_for_tl_mount` build on these methods so callers
    need not import :mod:`unand.io` / :mod:`unand.layout` directly for that flow.

    For **INLINE** / **FLAT_TAIL** sources, :meth:`read` / :meth:`read_page` hit the backing file on
    demand without materializing a second 128 MiB buffer. For **LOGICAL_ONLY**, optional ``use_mmap``
    maps the file read-only.
    """

    __slots__ = ("_path", "_geom", "_layout", "_mm")

    @classmethod
    def open_file(
        cls,
        path: str | Path,
        *,
        geom: NandGeometry = PACE_DEFAULT,
        use_mmap: bool = True,
    ) -> LogicalPlane:
        """
        Open ``path`` using :func:`~unand.layout.detect_layout_file` (Pace-class file sizes + ELF peek).

        Returns a :class:`LogicalPlane` with the resolved :class:`~unand.layout.RawDumpLayout`. On
        failure, raises ``ValueError`` with prefix ``LogicalPlane.open_file:`` so callers (e.g.
        :mod:`opentl`) do not need to import :exc:`~unand.layout.LayoutDetectionError`.
        """
        p = Path(path).expanduser().resolve()
        try:
            layout = detect_layout_file(str(p), geom=geom)
        except LayoutDetectionError as e:
            raise ValueError(
                "LogicalPlane.open_file: could not detect NAND dump layout from file size/peek; "
                f"expected Pace-class logical or full-chip raw. ({e})"
            ) from e
        return cls(p, geom=geom, layout=layout, use_mmap=use_mmap)

    def __init__(
        self,
        path: str | Path,
        *,
        geom: NandGeometry = PACE_DEFAULT,
        layout: RawDumpLayout,
        use_mmap: bool = True,
    ) -> None:
        """Attach to ``path`` with an explicit ``layout`` (use :meth:`open_file` for auto-detect)."""
        self._path = Path(path)
        self._geom = geom
        self._layout = layout
        self._mm: mmap.mmap | None = None
        if use_mmap and self._layout == RawDumpLayout.LOGICAL_ONLY:
            f = open(self._path, "rb")
            self._mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            f.close()

    def close(self) -> None:
        if self._mm is not None:
            self._mm.close()
            self._mm = None

    def __enter__(self) -> LogicalPlane:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def layout(self) -> RawDumpLayout:
        return self._layout

    @property
    def backing_path(self) -> Path:
        """Filesystem path of the opened dump (raw inline/flat-tail or logical-only image)."""
        return self._path

    @property
    def has_flat_spare_in_file(self) -> bool:
        """True when INLINE or FLAT_TAIL so OOB exists in-file for :meth:`flat_spare_bytes`."""
        return self._layout in (RawDumpLayout.INLINE_2048_64, RawDumpLayout.FLAT_TAIL_2048_64)

    def flat_spare_bytes(self) -> bytes:
        """
        Return the full **flat spare** stream: ``pages_total × page_spare`` bytes (typically **4 MiB**).

        Byte order matches :func:`unand.io.extract_spare_bytes` (one **64**-byte row per NAND page in
        chip order). Only valid for **INLINE_2048_64** and **FLAT_TAIL_2048_64**; for **LOGICAL_ONLY**
        there is no in-file OOB—raise ``ValueError``. Callers that already have a sidecar spare file
        should pass it into OpenTL (e.g. :meth:`opentl.open_tl.OpenTL.from_logical_with_flat_spare`)
        instead of calling this method.
        """
        if not self.has_flat_spare_in_file:
            raise ValueError(
                "LogicalPlane: logical-plane-only image has no in-file OOB; pass a flat spare stream "
                "from the same capture (e.g. nand-translate spare_out)."
            )
        from unand.io import extract_spare_bytes

        return extract_spare_bytes(self._path, layout=self._layout, geom=self._geom)

    def materialize_logical_plane(self, dest: Path) -> None:
        """
        Write only the **128 MiB** logical **main** plane to ``dest`` (no spare file).

        For **LOGICAL_ONLY**, the backing file already *is* that plane—raises ``ValueError``; use
        :attr:`backing_path` (or copy the file yourself) for OpenTL / tl-mount.

        For **INLINE** / **FLAT_TAIL**, delegates to :func:`unand.io.normalize_to_logical` with
        ``spare_out=None`` (streaming strip of inline pages, or skip of the data prefix on flat-tail).
        """
        if self._layout == RawDumpLayout.LOGICAL_ONLY:
            raise ValueError(
                "LogicalPlane.materialize_logical_plane: LOGICAL_ONLY source is already the logical "
                "plane; use backing_path for OpenTL / tl-mount."
            )
        from unand.io import normalize_to_logical

        normalize_to_logical(self._path, dest, spare_out=None, layout=self._layout, geom=self._geom)

    def read(self, offset: int, length: int) -> bytes:
        """Read ``length`` main-plane bytes starting at MTD-relative ``offset``."""
        if offset < 0 or length < 0 or offset + length > self._geom.logical_bytes:
            raise IndexError((offset, length))
        if self._mm is not None:
            return bytes(self._mm[offset : offset + length])
        return self._read_file(offset, length)

    def _read_file(self, offset: int, length: int) -> bytes:
        g = self._geom
        if self._layout in (RawDumpLayout.LOGICAL_ONLY, RawDumpLayout.FLAT_TAIL_2048_64):
            with open(self._path, "rb") as f:
                f.seek(offset)
                return f.read(length)
        if self._layout != RawDumpLayout.INLINE_2048_64:
            raise RuntimeError(self._layout)
        out = bytearray()
        pos = offset
        end = offset + length
        with open(self._path, "rb") as f:
            while pos < end:
                page, o = divmod(pos, g.page_data)
                chunk = min(g.page_data - o, end - pos)
                f.seek(page * g.page_phys + o)
                out.extend(f.read(chunk))
                pos += chunk
        return bytes(out)

    def read_page(self, page_index: int) -> bytes:
        """Return ``page_data`` main bytes for zero-based NAND page ``page_index``."""
        if page_index < 0 or page_index >= self._geom.pages_total:
            raise IndexError(page_index)
        base = page_index * self._geom.page_data
        return self.read(base, self._geom.page_data)

    def read_oob_page(self, page_index: int) -> bytes:
        """
        Return the **64**-byte spare row for NAND main page ``page_index``.

        Indexing matches ``read_page(page_index)`` (one row per **2048**-byte main page,
        not per 512-byte OpenTL sector). Meaning of bytes is driver-specific; see
        ``reference/spare64_bbm_field_map.md`` and ``opentl``.
        """
        if page_index < 0 or page_index >= self._geom.pages_total:
            raise IndexError(page_index)
        g = self._geom
        with open(self._path, "rb") as f:
            if self._layout == RawDumpLayout.INLINE_2048_64:
                f.seek(page_index * g.page_phys + g.page_data)
                return f.read(g.page_spare)
            if self._layout == RawDumpLayout.FLAT_TAIL_2048_64:
                f.seek(g.logical_bytes + page_index * g.page_spare)
                return f.read(g.page_spare)
            raise ValueError("OOB not defined for LOGICAL_ONLY without spare sidecar")