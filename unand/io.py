"""
Streaming normalize: raw dump → logical data plane + optional flat spare stream.

``logical_out`` is the **MTD-sized** main image. ``spare_out`` (if given) is a **4 MiB**
sidecar: spare row for page **0**, then page **1**, … — an offline convenience, **not**
a kernel MTD partition. See package ``README.md``.
"""

from __future__ import annotations

import io
import shutil
from contextlib import ExitStack, nullcontext
from pathlib import Path
from typing import BinaryIO, cast

from unand.geometry import NandGeometry, PACE_DEFAULT
from unand.layout import RawDumpLayout


def _coerce_path(p: str | Path) -> Path:
    return Path(p) if not isinstance(p, Path) else p


def _open_wb_sink(sink: Path | BinaryIO):
    """Writable stream for logical or spare output."""
    if isinstance(sink, Path):
        sink.parent.mkdir(parents=True, exist_ok=True)
        return open(sink, "wb")
    return nullcontext(sink)


#region kernel_adjacent normalize_to_logical (opentl.nand_translate / unand.io seam; see reference/layers_unand_uboot_opentl_boardfs_paceflash.md)
def normalize_to_logical(
    raw_path: str | Path,
    logical_out: str | Path | BinaryIO,
    spare_out: str | Path | BinaryIO | None = None,
    *,
    geom: NandGeometry = PACE_DEFAULT,
    layout: RawDumpLayout,
) -> RawDumpLayout:
    """
    Read a full-chip image and write the **128 MiB** logical (main) stream and
    optionally the **4 MiB** spare sidecar (see package ``README.md``).

    ``logical_out`` / ``spare_out`` may be :class:`pathlib.Path` (files on disk) or
    binary streams (e.g. :class:`io.BytesIO`) for in-memory output.

    ``layout`` must be explicit (``INLINE_2048_64``, ``FLAT_TAIL_2048_64``, or ``LOGICAL_ONLY``);
    there is no ``auto`` detection here — use :func:`unand.layout.detect_layout_file` in a
    separate probe step if you need a hint.

    Returns the layout that was applied.
    """

    raw_path = Path(raw_path)
    logical_sink: Path | BinaryIO = _coerce_path(logical_out) if isinstance(logical_out, (str, Path)) else logical_out
    spare_sink: Path | BinaryIO | None
    if spare_out is None:
        spare_sink = None
    elif isinstance(spare_out, (str, Path)):
        spare_sink = _coerce_path(spare_out)
    else:
        spare_sink = spare_out

    resolved = layout
    if resolved == RawDumpLayout.LOGICAL_ONLY:
        if spare_sink is not None:
            raise ValueError("spare_out not applicable for LOGICAL_ONLY input")
        if isinstance(logical_sink, Path):
            shutil.copyfile(raw_path, logical_sink)
        else:
            with open(raw_path, "rb") as inp:
                shutil.copyfileobj(inp, cast(BinaryIO, logical_sink))
        return resolved

    with ExitStack() as stack:
        lout = stack.enter_context(_open_wb_sink(logical_sink))
        spare_fp: BinaryIO | None = (
            stack.enter_context(_open_wb_sink(spare_sink)) if spare_sink is not None else None
        )
        with open(raw_path, "rb") as inp:
            if resolved == RawDumpLayout.INLINE_2048_64:
                _stream_inline_to_logical(inp, lout, spare_fp, geom)
            elif resolved == RawDumpLayout.FLAT_TAIL_2048_64:
                _stream_flat_tail_to_logical(inp, lout, spare_fp, geom)
            else:
                raise ValueError(resolved)
    return resolved


def _stream_inline_to_logical(inp: BinaryIO, lout: BinaryIO, spare_fp: BinaryIO | None, geom: NandGeometry) -> None:
    page_main = geom.page_data
    page_oob = geom.page_spare
    for _ in range(geom.pages_total):
        main = inp.read(page_main)
        oob = inp.read(page_oob)
        if len(main) != page_main or len(oob) != page_oob:
            raise ValueError("unexpected EOF in inline stream")
        lout.write(main)
        if spare_fp is not None:
            spare_fp.write(oob)


def _stream_flat_tail_to_logical(inp: BinaryIO, lout: BinaryIO, spare_fp: BinaryIO | None, geom: NandGeometry) -> None:
    n_data = geom.logical_bytes
    n_oob = geom.oob_total_bytes
    remain = n_data
    chunk = 1024 * 1024
    while remain > 0:
        take = min(chunk, remain)
        buf = inp.read(take)
        if len(buf) != take:
            raise ValueError("unexpected EOF in flat data region")
        lout.write(buf)
        remain -= take
    if spare_fp is None:
        inp.seek(n_oob, 1)
        return
    remain = n_oob
    while remain > 0:
        take = min(chunk, remain)
        buf = inp.read(take)
        if len(buf) != take:
            raise ValueError("unexpected EOF in flat spare region")
        spare_fp.write(buf)
        remain -= take


#endregion


#region kernel_adjacent denormalize_logical_to_physical (inverse of normalize_to_logical)
def denormalize_logical_to_physical(
    logical_in: str | Path | BinaryIO,
    physical_out: str | Path | BinaryIO,
    *,
    layout: RawDumpLayout,
    spare_in: str | Path | BinaryIO | None = None,
    geom: NandGeometry = PACE_DEFAULT,
) -> RawDumpLayout:
    """
    Write a physical dump from a **128 MiB** logical main plane (+ optional spare sidecar).

    Inverse of :func:`normalize_to_logical` for **INLINE_2048_64** and **FLAT_TAIL_2048_64**.
    **LOGICAL_ONLY** input is copied verbatim to ``physical_out``.
    """
    logical_path: Path | None
    logical_fp: BinaryIO | None
    if isinstance(logical_in, (str, Path)):
        logical_path = _coerce_path(logical_in)
        logical_fp = None
    else:
        logical_path = None
        logical_fp = logical_in

    physical_sink: Path | BinaryIO = (
        _coerce_path(physical_out) if isinstance(physical_out, (str, Path)) else physical_out
    )
    spare_src: Path | BinaryIO | None
    if spare_in is None:
        spare_src = None
    elif isinstance(spare_in, (str, Path)):
        spare_src = _coerce_path(spare_in)
    else:
        spare_src = spare_in

    if layout == RawDumpLayout.LOGICAL_ONLY:
        if spare_src is not None:
            raise ValueError("spare_in not applicable for LOGICAL_ONLY output")
        if logical_path is not None:
            if isinstance(physical_sink, Path):
                shutil.copyfile(logical_path, physical_sink)
            else:
                with open(logical_path, "rb") as inp:
                    shutil.copyfileobj(inp, cast(BinaryIO, physical_sink))
        else:
            assert logical_fp is not None
            logical_fp.seek(0)
            shutil.copyfileobj(logical_fp, cast(BinaryIO, physical_sink))
        return layout

    with ExitStack() as stack:
        pout = stack.enter_context(_open_wb_sink(physical_sink))
        spare_fp: BinaryIO | None = None
        if spare_src is not None:
            if isinstance(spare_src, Path):
                spare_fp = stack.enter_context(open(spare_src, "rb"))
            else:
                spare_src.seek(0)
                spare_fp = spare_src

        if logical_path is not None:
            lin_fp = stack.enter_context(open(logical_path, "rb"))
        else:
            assert logical_fp is not None
            logical_fp.seek(0)
            lin_fp = logical_fp

        if layout == RawDumpLayout.INLINE_2048_64:
            _stream_logical_to_inline(lin_fp, pout, spare_fp, geom)
        elif layout == RawDumpLayout.FLAT_TAIL_2048_64:
            _stream_logical_to_flat_tail(lin_fp, pout, spare_fp, geom)
        else:
            raise ValueError(layout)
    return layout


def _stream_logical_to_inline(
    lin: BinaryIO,
    pout: BinaryIO,
    spare_fp: BinaryIO | None,
    geom: NandGeometry,
) -> None:
    page_main = geom.page_data
    page_oob = geom.page_spare
    for _ in range(geom.pages_total):
        main = lin.read(page_main)
        if len(main) != page_main:
            raise ValueError("unexpected EOF in logical stream")
        pout.write(main)
        if spare_fp is not None:
            oob = spare_fp.read(page_oob)
            if len(oob) != page_oob:
                raise ValueError("unexpected EOF in spare sidecar")
            pout.write(oob)
        else:
            pout.write(b"\x00" * page_oob)


def _stream_logical_to_flat_tail(
    lin: BinaryIO,
    pout: BinaryIO,
    spare_fp: BinaryIO | None,
    geom: NandGeometry,
) -> None:
    n_data = geom.logical_bytes
    chunk = 1024 * 1024
    remain = n_data
    while remain > 0:
        take = min(chunk, remain)
        buf = lin.read(take)
        if len(buf) != take:
            raise ValueError("unexpected EOF in logical stream")
        pout.write(buf)
        remain -= take
    if spare_fp is None:
        pout.write(b"\x00" * geom.oob_total_bytes)
        return
    remain = geom.oob_total_bytes
    while remain > 0:
        take = min(chunk, remain)
        buf = spare_fp.read(take)
        if len(buf) != take:
            raise ValueError("unexpected EOF in spare sidecar")
        pout.write(buf)
        remain -= take


def patch_logical_bytes(
    logical: bytearray,
    patches: list[tuple[int, bytes]],
) -> None:
    """Apply in-place byte patches to a logical main plane buffer."""
    total = len(logical)
    for off, data in patches:
        if off < 0 or off + len(data) > total:
            raise IndexError((off, len(data), total))
        logical[off : off + len(data)] = data


def patch_physical_pages(
    input_path: str | Path,
    output_path: str | Path,
    modified_pages: dict[int, tuple[bytes, bytes]],
    *,
    layout: RawDumpLayout,
    geom: NandGeometry = PACE_DEFAULT,
) -> None:
    """
    Copy ``input_path`` to ``output_path`` and overwrite only listed NAND pages.

    Each ``modified_pages`` entry is ``page_index -> (main_2048, spare_64)``.
    All other pages (including bad-block chain rows and hole fillers) pass through
    bit-identically from the source dump.
    """
    src = Path(input_path)
    dst = Path(output_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    if not modified_pages:
        return

    page_data = geom.page_data
    page_spare = geom.page_spare
    page_phys = geom.page_phys

    with open(dst, "r+b") as out:
        if layout == RawDumpLayout.INLINE_2048_64:
            for page_idx, (main, oob) in sorted(modified_pages.items()):
                if len(main) != page_data or len(oob) != page_spare:
                    raise ValueError(
                        f"page {page_idx}: expected ({page_data}, {page_spare}) "
                        f"got ({len(main)}, {len(oob)})"
                    )
                out.seek(page_idx * page_phys)
                out.write(main)
                out.write(oob)
            return
        if layout == RawDumpLayout.FLAT_TAIL_2048_64:
            for page_idx, (main, oob) in sorted(modified_pages.items()):
                if len(main) != page_data or len(oob) != page_spare:
                    raise ValueError(
                        f"page {page_idx}: expected ({page_data}, {page_spare}) "
                        f"got ({len(main)}, {len(oob)})"
                    )
                out.seek(page_idx * page_data)
                out.write(main)
                out.seek(geom.logical_bytes + page_idx * page_spare)
                out.write(oob)
            return
        raise ValueError(f"patch_physical_pages unsupported for layout {layout!r}")


#endregion


def sha256_logical_plane(
    raw_path: str | Path,
    *,
    layout: RawDumpLayout,
    geom: NandGeometry = PACE_DEFAULT,
) -> str:
    """Single-pass SHA-256 of the logical data plane (no spare), for golden tests."""

    import hashlib

    raw_path = Path(raw_path)
    h = hashlib.sha256()
    if layout == RawDumpLayout.LOGICAL_ONLY:
        with open(raw_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    with open(raw_path, "rb") as f:
        if layout == RawDumpLayout.INLINE_2048_64:
            for _ in range(geom.pages_total):
                h.update(f.read(geom.page_data))
                f.seek(geom.page_spare, 1)
        else:
            h.update(f.read(geom.logical_bytes))
    return h.hexdigest()


#region kernel_adjacent extract_spare_sidecar (flat spare stream; not kernel MTD partition)
def _extract_spare_raw_stream(
    inp: BinaryIO,
    out: BinaryIO,
    *,
    layout: RawDumpLayout,
    geom: NandGeometry,
    logical_cut_bytes: int | None,
) -> None:
    """Copy flat spare bytes from a raw dump open at ``inp`` to ``out`` (INLINE or FLAT_TAIL only)."""
    if layout == RawDumpLayout.LOGICAL_ONLY:
        raise ValueError(
            "logical-only image has no separate spare region; use inline or flat-tail raw dump"
        )
    page_main = geom.page_data
    page_oob = geom.page_spare
    chunk = 1024 * 1024

    if layout == RawDumpLayout.INLINE_2048_64:
        while True:
            main = inp.read(page_main)
            if not main:
                break
            if len(main) != page_main:
                raise ValueError("unexpected EOF in inline main region")
            oob = inp.read(page_oob)
            if len(oob) != page_oob:
                raise ValueError("unexpected EOF in inline spare region")
            out.write(oob)
        return
    if layout == RawDumpLayout.FLAT_TAIL_2048_64:
        cut = logical_cut_bytes if logical_cut_bytes is not None else geom.logical_bytes
        remain = cut
        while remain > 0:
            take = min(chunk, remain)
            buf = inp.read(take)
            if len(buf) != take:
                raise ValueError("unexpected EOF skipping flat logical region")
            remain -= take
        while True:
            buf = inp.read(chunk)
            if not buf:
                break
            out.write(buf)
        return
    raise ValueError(layout)


def extract_spare_bytes(
    raw_path: str | Path,
    *,
    layout: RawDumpLayout,
    geom: NandGeometry = PACE_DEFAULT,
    logical_cut_bytes: int | None = None,
) -> bytes:
    """
    Return the flat spare/OOB stream (same bytes as :func:`extract_spare_to_file` would write).

    * **INLINE** — ``page_spare`` bytes per NAND page, in linear page order.
    * **FLAT_TAIL** — bytes after the logical prefix; ``logical_cut_bytes`` defaults to
      ``geom.logical_bytes``.

    Raises ``ValueError`` for **LOGICAL_ONLY** input.
    """
    raw_path = Path(raw_path)
    out = io.BytesIO()
    with open(raw_path, "rb") as inp:
        _extract_spare_raw_stream(
            inp, out, layout=layout, geom=geom, logical_cut_bytes=logical_cut_bytes
        )
    return out.getvalue()


def extract_spare_to_file(
    raw_path: str | Path,
    dst: str | Path,
    *,
    geom: NandGeometry = PACE_DEFAULT,
    layout: RawDumpLayout,
    logical_cut_bytes: int | None = None,
) -> RawDumpLayout:
    """
    Write only the flat spare/OOB stream (no logical-plane file).

    * **INLINE** — ``page_spare`` bytes per NAND page, in linear page order.
    * **FLAT_TAIL** — bytes after the logical prefix; ``logical_cut_bytes`` defaults to
      ``geom.logical_bytes`` for a full-chip flat-tail image.

    Raises ``ValueError`` for **LOGICAL_ONLY** input (no separate spare region).

    ``layout`` must be explicit (no ``auto``).
    """
    raw_path = Path(raw_path)
    dst = Path(dst)
    if layout == RawDumpLayout.LOGICAL_ONLY:
        raise ValueError(
            "logical-only image has no separate spare region; use inline or flat-tail raw dump"
        )

    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(raw_path, "rb") as inp, open(dst, "wb") as spout:
        _extract_spare_raw_stream(
            inp, spout, layout=layout, geom=geom, logical_cut_bytes=logical_cut_bytes
        )
    return layout


#endregion
