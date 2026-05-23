"""
NAND dump → logical data-plane translation for carved scanners (Binwalk, etc.).

5268-class captures often ship as either:

* **flat logical data + appended OOB tail** (128 MiB data then ~4 MiB spare) — ``mtdparts`` byte offsets apply directly;
* **inline 2048+64** — each NAND page is ``PAGE_RAW`` bytes; parsers see garbage every 2 KiB unless stripped.

Packing is selected explicitly via :class:`unand.layout.RawDumpLayout` / :data:`opentl.nand_translate.TranslateMode` (no ``auto`` inference in translate paths).
"""

from __future__ import annotations

import io
import shutil
from pathlib import Path
from typing import BinaryIO, Literal, cast

from unand.geometry import NandGeometry, PACE_DEFAULT
from unand.io import extract_spare_to_file, normalize_to_logical
from unand.layout import RawDumpLayout

from opentl.tl_physical import (
    FLASH_5268_CLASS_SIZE,
    OOB_ENVELOPE,
    PAGE_DATA,
    PAGE_RAW,
    PAGE_SPARE,
    PURE_DATA_PLANE,
)

# 5268-class single-plane linear read: 1024 erase blocks x 64 pages (see ``issue.md``).
NAND_PAGES_5268 = 1024 * 64

TranslateMode = Literal["flat-tail", "inline-2112", "identity"]

# Carve/router policy: ``auto`` = infer logical vs padded dump; ``always`` = always run nand-translate pipeline.
NandCarveTranslatePolicy = Literal["auto", "always", "never"]


#region kernel_adjacent nand_translate_unand_seam (mode resolution, carve plan, partial streams; see reference/layers_unand_uboot_opentl_boardfs_paceflash.md)
def _geom() -> NandGeometry:
    return PACE_DEFAULT


def _mode_to_raw_layout(mode: str) -> RawDumpLayout:
    if mode == "identity":
        raise ValueError("identity has no RawDumpLayout")
    if mode == "inline-2112":
        return RawDumpLayout.INLINE_2048_64
    if mode == "flat-tail":
        return RawDumpLayout.FLAT_TAIL_2048_64
    raise ValueError(f"unknown translate mode: {mode!r}")


def resolve_translate_mode(
    path: Path,
    explicit: TranslateMode,
) -> tuple[str, None]:
    """
    Validate ``explicit`` translate mode against ``path`` size (no layout inference).

    * ``identity`` — always allowed (byte-for-byte copy path).
    * ``inline-2112`` — requires length multiple of ``PAGE_RAW``, or full-chip inline size.
    * ``flat-tail`` — requires full flat-tail chip size, or a partial tail strip with a
      compatible size for :func:`logical_bytes_for_flat_tail`.

    Raises ``ValueError`` when the file size does not match the selected packing (e.g. full
    inline-sized dump with ``flat-tail``, or logical-sized image with ``inline-2112``).
    """
    sz = path.stat().st_size
    g = _geom()
    if explicit == "identity":
        return "identity", None
    if explicit == "inline-2112":
        if sz == g.logical_bytes:
            raise ValueError(
                "inline-2112 requested but file is already logical-plane size "
                f"({g.logical_bytes} B); use identity"
            )
        if sz == g.full_inline_bytes:
            return "inline-2112", None
        if sz >= PAGE_RAW and sz % PAGE_RAW == 0:
            return "inline-2112", None
        raise ValueError(
            f"inline-2112 requires full inline chip ({g.full_inline_bytes} B) or "
            f"length multiple of {PAGE_RAW} B, got {sz}"
        )
    if explicit == "flat-tail":
        if sz == g.logical_bytes:
            raise ValueError(
                "flat-tail requested but file is logical-plane size only "
                f"({g.logical_bytes} B); use identity or a dump with OOB tail"
            )
        if sz == g.full_flat_tail_bytes:
            return "flat-tail", None
        if sz == g.full_inline_bytes:
            raise ValueError(
                f"file is full inline packed size ({g.full_inline_bytes} B); "
                "use inline-2112, not flat-tail"
            )
        if g.logical_bytes < sz < g.full_flat_tail_bytes:
            return "flat-tail", None
        if sz > g.full_flat_tail_bytes:
            raise ValueError(
                f"file size {sz} exceeds full flat-tail chip ({g.full_flat_tail_bytes} B)"
            )
        raise ValueError(
            f"flat-tail mode incompatible with file size {sz}; expected full flat-tail "
            f"({g.full_flat_tail_bytes} B) or a dump larger than logical ({g.logical_bytes} B) "
            "with appended spare"
        )
    raise RuntimeError(f"unexpected translate mode {explicit!r}")


def nand_carve_translate_plan(
    flash: Path,
    *,
    nand_translate: NandCarveTranslatePolicy,
    nand_mode: str,
) -> tuple[bool, TranslateMode | None]:
    """
    Decide whether flash carving should invoke the nand-translate pipeline before Binwalk.

    Returns ``(run_translate, effective_mode)``.
    ``run_translate=False`` ⇒ pass ``nand_data_mode=\"none\"`` into the caller's flash-carve layer
    (whatever module orchestrates Binwalk + nand-translate for that workspace).
    ``run_translate=True`` ⇒ pass ``nand_data_mode=effective_mode`` where ``effective_mode`` is
    one of ``inline-2112`` / ``flat-tail`` / ``identity`` (never inferred here — caller must
    pass an explicit ``nand_mode`` when translation may run).
    """
    mode_req = nand_mode.strip()
    if nand_translate == "never":
        return False, None
    if nand_translate == "always":
        if mode_req not in ("flat-tail", "inline-2112", "identity"):
            raise ValueError(f"unsupported nand_mode: {nand_mode!r}")
        resolved, _ = resolve_translate_mode(flash, mode_req)  # type: ignore[arg-type]
        return True, resolved  # type: ignore[return-value]

    # nand_translate == "auto" (policy: still infer *whether* to translate from explicit mode + size)
    if mode_req not in ("flat-tail", "inline-2112", "identity"):
        raise ValueError(f"unsupported nand_mode: {nand_mode!r}")

    resolved, _ = resolve_translate_mode(flash, mode_req)  # type: ignore[arg-type]
    if resolved == "identity":
        return False, None
    return True, resolved  # type: ignore[return-value]


def logical_bytes_for_flat_tail(
    file_size: int,
    *,
    override: int | None,
) -> int:
    """Effective cut point for flat-tail strip."""
    if override is not None:
        return override
    if file_size == FLASH_5268_CLASS_SIZE:
        return PURE_DATA_PLANE
    return file_size


def preview_logical_size(
    path: Path,
    mode: TranslateMode,
    *,
    logical_bytes: int | None = None,
) -> tuple[int, str, None]:
    """Byte length of logical output without reading page payloads (for carve dry-run stubs)."""
    resolved, layout = resolve_translate_mode(path, mode)
    sz = path.stat().st_size
    if resolved == "identity":
        return sz, resolved, layout
    if resolved == "inline-2112":
        if sz % PAGE_RAW != 0:
            raise ValueError(
                f"inline-2112 requires file length multiple of {PAGE_RAW}, got {sz}"
            )
        return (sz // PAGE_RAW) * PAGE_DATA, resolved, layout
    if resolved == "flat-tail":
        lb = logical_bytes_for_flat_tail(sz, override=logical_bytes)
        return lb, resolved, layout
    raise RuntimeError(f"unexpected resolved mode {resolved!r}")


def write_zero_stub(path: Path, size: int) -> None:
    """Create a sparse-ish zero file of ``size`` bytes (for dry-run sizing only)."""
    if size < 0:
        raise ValueError("size must be non-negative")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        if size > 0:
            f.seek(size - 1)
            f.write(b"\x00")


def _stream_partial_inline_to_files(
    src: Path,
    logical_out: Path,
    spare_out: Path | None,
    *,
    geom: NandGeometry,
) -> None:
    page_main = geom.page_data
    page_oob = geom.page_spare
    logical_out.parent.mkdir(parents=True, exist_ok=True)
    spare_fp: BinaryIO | None = None
    if spare_out is not None:
        spare_out = Path(spare_out)
        spare_out.parent.mkdir(parents=True, exist_ok=True)
        spare_fp = spare_out.open("wb")
    try:
        with src.open("rb") as inp, logical_out.open("wb") as lout:
            while True:
                main = inp.read(page_main)
                if not main:
                    break
                if len(main) != page_main:
                    raise ValueError("unexpected EOF in inline main region")
                oob = inp.read(page_oob)
                if len(oob) != page_oob:
                    raise ValueError("unexpected EOF in inline spare region")
                lout.write(main)
                if spare_fp is not None:
                    spare_fp.write(oob)
    finally:
        if spare_fp is not None:
            spare_fp.close()


def _stream_partial_flat_tail_to_files(
    src: Path,
    logical_out: Path,
    spare_out: Path | None,
    *,
    logical_cut: int,
    geom: NandGeometry,
) -> None:
    chunk = 1024 * 1024
    logical_out.parent.mkdir(parents=True, exist_ok=True)
    spare_fp: BinaryIO | None = None
    if spare_out is not None:
        spare_out = Path(spare_out)
        spare_out.parent.mkdir(parents=True, exist_ok=True)
        spare_fp = spare_out.open("wb")
    try:
        with src.open("rb") as inp, logical_out.open("wb") as lout:
            remain = logical_cut
            while remain > 0:
                take = min(chunk, remain)
                buf = inp.read(take)
                if len(buf) != take:
                    raise ValueError("unexpected EOF in flat logical region")
                lout.write(buf)
                remain -= take
            if spare_fp is None:
                while inp.read(chunk):
                    pass
                return
            while True:
                buf = inp.read(chunk)
                if not buf:
                    break
                spare_fp.write(buf)
    finally:
        if spare_fp is not None:
            spare_fp.close()


#endregion


#region kernel_adjacent nand_translate_to_file_public_api (nand_translate_to_bytes / nand_translate_to_file)
def nand_translate_to_bytes(
    path: Path,
    mode: TranslateMode,
    *,
    logical_bytes: int | None = None,
    spare_out: Path | None = None,
) -> tuple[bytes, dict]:
    """
    Read ``path`` and return ``(logical_data, manifest_dict)`` (loads logical into RAM).

    Streams through an in-memory buffer (no temporary logical-plane file). If ``spare_out`` is set,
    spare bytes are still written to that path when applicable.
    """
    buf = io.BytesIO()
    man = nand_translate_to_file(path, buf, mode, logical_bytes=logical_bytes, spare_out=spare_out)
    return buf.getvalue(), man


def nand_translate_to_file(
    src: Path,
    dst: Path | BinaryIO,
    mode: TranslateMode,
    *,
    logical_bytes: int | None = None,
    spare_out: Path | None = None,
) -> dict:
    """Translate ``src`` → ``dst`` (path or writable binary stream); return manifest dict."""
    resolved, _ = resolve_translate_mode(src, mode)
    sz = src.stat().st_size
    g = _geom()
    manifest: dict = {
        "source": str(src.resolve()),
        "source_size": sz,
        "requested_mode": mode,
        "resolved_mode": resolved,
    }

    if resolved == "identity":
        if isinstance(dst, Path):
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        else:
            with src.open("rb") as inp:
                shutil.copyfileobj(inp, cast(BinaryIO, dst))
        manifest["logical_size"] = sz
        if spare_out is not None:
            spare_out = Path(spare_out)
            spare_out.parent.mkdir(parents=True, exist_ok=True)
            spare_out.write_bytes(b"")
            manifest["spare_out"] = str(spare_out.resolve())
            manifest["spare_bytes_written"] = 0
        manifest["dest"] = str(dst.resolve()) if isinstance(dst, Path) else "<memory>"
        return manifest

    if resolved == "inline-2112":
        if sz == g.full_inline_bytes:
            used = normalize_to_logical(src, dst, spare_out, geom=g, layout=RawDumpLayout.INLINE_2048_64)
            manifest["unand_layout"] = used.value
        else:
            if not isinstance(dst, Path):
                raise ValueError("partial inline NAND translate requires a Path destination")
            _stream_partial_inline_to_files(src, dst, spare_out, geom=g)
            manifest["unand_layout"] = "partial_inline"
        if isinstance(dst, Path):
            manifest["logical_size"] = dst.stat().st_size
            manifest["dest"] = str(dst.resolve())
        else:
            manifest["logical_size"] = int(dst.tell())
            manifest["dest"] = "<memory>"
        if spare_out is not None and Path(spare_out).is_file():
            manifest["spare_out"] = str(Path(spare_out).resolve())
            manifest["spare_bytes_written"] = Path(spare_out).stat().st_size
        return manifest

    if resolved == "flat-tail":
        lb = logical_bytes_for_flat_tail(sz, override=logical_bytes)
        manifest["logical_bytes"] = lb
        if sz == g.full_flat_tail_bytes:
            used = normalize_to_logical(src, dst, spare_out, geom=g, layout=RawDumpLayout.FLAT_TAIL_2048_64)
            manifest["unand_layout"] = used.value
        else:
            if not isinstance(dst, Path):
                raise ValueError("partial flat-tail NAND translate requires a Path destination")
            _stream_partial_flat_tail_to_files(src, dst, spare_out, logical_cut=lb, geom=g)
            manifest["unand_layout"] = "partial_flat_tail"
        if isinstance(dst, Path):
            manifest["logical_size"] = dst.stat().st_size
            manifest["dest"] = str(dst.resolve())
        else:
            manifest["logical_size"] = int(dst.tell())
            manifest["dest"] = "<memory>"
        if spare_out is not None and Path(spare_out).is_file():
            spo = Path(spare_out)
            manifest["spare_out"] = str(spo.resolve())
            manifest["spare_bytes_written"] = spo.stat().st_size
            manifest["oob_tail_bytes"] = manifest["spare_bytes_written"]
        return manifest

    raise RuntimeError(f"unexpected resolved mode {resolved!r}")


#endregion


#region kernel_adjacent nand_translate_spare_sidecar (extract_spare_only, inline strip helpers)
def extract_spare_only_to_file(
    src: Path,
    dst: Path,
    mode: TranslateMode,
    *,
    logical_bytes: int | None = None,
) -> dict:
    """
    Write **only** concatenated OOB/spare bytes (no logical-plane image).

    * **flat-tail** — bytes after the logical cut (typically the last **~4 MiB** of a 138 412 032 dump).
    * **inline-2112** — 64-byte spare slices per page, in linear page order.

    Indexing: spare for global page ``p`` (0-based, chip-linear order) is
    ``dst[p * PAGE_SPARE : (p + 1) * PAGE_SPARE]`` when ``len(spare) % PAGE_SPARE == 0``.
    """
    resolved, _ = resolve_translate_mode(src, mode)
    if resolved == "identity":
        raise ValueError(
            "identity layout has no separate spare region; use flat-tail or inline-2112, "
            "or pass a full raw dump with OOB."
        )

    sz = src.stat().st_size
    g = _geom()
    manifest: dict = {
        "source": str(src.resolve()),
        "source_size": sz,
        "requested_mode": mode,
        "resolved_mode": resolved,
        "page_data": PAGE_DATA,
        "page_spare": PAGE_SPARE,
    }

    dst.parent.mkdir(parents=True, exist_ok=True)

    raw_layout = _mode_to_raw_layout(resolved)  # type: ignore[arg-type]
    cut: int | None = None
    if resolved == "flat-tail":
        cut = logical_bytes_for_flat_tail(sz, override=logical_bytes)
        manifest["logical_cut_bytes"] = cut
        manifest["spare_layout"] = "appended_tail"
    elif resolved == "inline-2112":
        manifest["spare_layout"] = "inline_per_page"

    used = extract_spare_to_file(
        src,
        dst,
        geom=g,
        layout=raw_layout,
        logical_cut_bytes=cut,
    )
    manifest["unand_layout"] = used.value
    spare_blob_len = dst.stat().st_size
    manifest["spare_bytes"] = spare_blob_len
    manifest["spare_pages_implied"] = (
        spare_blob_len // PAGE_SPARE if spare_blob_len % PAGE_SPARE == 0 else None
    )
    manifest["dest"] = str(dst.resolve())

    if sz == FLASH_5268_CLASS_SIZE and manifest["spare_pages_implied"] == NAND_PAGES_5268:
        manifest["note_5268"] = (
            f"matches {NAND_PAGES_5268} pages x {PAGE_SPARE} B spare = {OOB_ENVELOPE} B envelope"
        )

    return manifest


def strip_inline_oob(raw: bytes, *, page_data: int = PAGE_DATA, page_spare: int = PAGE_SPARE) -> bytes:
    """Concatenate only data regions from an inline ``page_data + page_spare`` byte stream."""
    page = page_data + page_spare
    if len(raw) % page != 0:
        raise ValueError(f"length {len(raw)} not multiple of page size {page}")
    out = bytearray()
    for i in range(0, len(raw), page):
        out.extend(raw[i : i + page_data])
    return bytes(out)


def extract_inline_oob_stream(
    raw: bytes,
    *,
    page_data: int = PAGE_DATA,
    page_spare: int = PAGE_SPARE,
) -> bytes:
    """Concatenate only spare/OOB regions from an inline ``page_data + page_spare`` byte stream."""
    page = page_data + page_spare
    if len(raw) % page != 0:
        raise ValueError(f"length {len(raw)} not multiple of page size {page}")
    out = bytearray()
    for i in range(0, len(raw), page):
        out.extend(raw[i + page_data : i + page])
    return bytes(out)


def strip_oob_tail(payload: bytes, logical_bytes: int) -> tuple[bytes, bytes]:
    """Split ``payload`` into ``(logical_prefix, tail)`` at ``logical_bytes``."""
    if logical_bytes < 0 or logical_bytes > len(payload):
        raise ValueError("logical_bytes out of range")
    return payload[:logical_bytes], payload[logical_bytes:]


#endregion


__all__ = [
    "NAND_PAGES_5268",
    "NandCarveTranslatePolicy",
    "TranslateMode",
    "extract_inline_oob_stream",
    "extract_spare_only_to_file",
    "logical_bytes_for_flat_tail",
    "nand_carve_translate_plan",
    "nand_translate_to_bytes",
    "nand_translate_to_file",
    "preview_logical_size",
    "resolve_translate_mode",
    "strip_inline_oob",
    "strip_oob_tail",
    "write_zero_stub",
]
