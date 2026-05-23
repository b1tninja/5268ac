"""
Raw TSOP dump layout: inline 2048+64 vs flat-tail vs already-logical.

Detection uses the **logical main** view (MTD-sized), not spare. See package ``README.md``.
"""

from __future__ import annotations

from enum import Enum

from unand.geometry import NandGeometry, PACE_DEFAULT


#region kernel_adjacent physical_envelope_detection (handoff to unand.io.normalize_to_logical)
class RawDumpLayout(Enum):
    """How a full-chip image packs main + OOB."""

    LOGICAL_ONLY = "logical_only"  # 134217728 B: data plane only
    INLINE_2048_64 = "inline_2048_64"  # 2112 B per page in NAND order
    FLAT_TAIL_2048_64 = "flat_tail_2048_64"  # 128 MiB data || 4 MiB spare


class LayoutDetectionError(ValueError):
    pass


def _read_logical_inline(data: bytes | memoryview, geom: NandGeometry, logical_offset: int) -> bytes:
    if logical_offset < 0 or logical_offset >= geom.logical_bytes:
        raise IndexError(logical_offset)
    page, off = divmod(logical_offset, geom.page_data)
    file_off = page * geom.page_phys + off
    end = file_off + 4
    if end > len(data):
        raise IndexError(file_off)
    return bytes(data[file_off:end])


def _read_logical_flat(data: bytes | memoryview, geom: NandGeometry, logical_offset: int) -> bytes:
    if logical_offset < 0 or logical_offset >= geom.logical_bytes:
        raise IndexError(logical_offset)
    end = logical_offset + 4
    if end > len(data):
        raise IndexError(logical_offset)
    return bytes(data[logical_offset:end])


def _elf_magic(b4: bytes) -> bool:
    return len(b4) >= 4 and b4[:4] == b"\x7fELF"


def detect_layout(
    file_size: int,
    *,
    geom: NandGeometry = PACE_DEFAULT,
    peek: bytes | None = None,
    tail_slab: bytes | None = None,
) -> RawDumpLayout:
    """
    Decide how `peek` (leading bytes of the file) is packed.

    Uses weak ELF anchors on the **MTD data plane**. For PACE TSOP48.BIN (inline),
    the first ``\\x7fELF`` sits at **logical 0x20000**; a naive **flat** view shows
    ELF at **file offset 0x21000** (logical 0x21000 under flat), so we score both.

    For the Pace-class envelope where **flat-tail** and **inline** share the same total
    length, pass ``tail_slab`` = bytes from **file offset** ``geom.logical_bytes`` (the
    flat spare seam); see :func:`detect_layout_file`.
    """

    if file_size == geom.logical_bytes:
        return RawDumpLayout.LOGICAL_ONLY
    if file_size != geom.full_inline_bytes:
        raise LayoutDetectionError(
            f"Unsupported size {file_size}; expected {geom.logical_bytes} or {geom.full_inline_bytes}"
        )
    if peek is None or len(peek) < min(file_size, 0x22090):
        raise LayoutDetectionError(
            "detect_layout for a 138412032 B file requires `peek` covering at least ~0x22090 bytes"
        )
    mv = memoryview(peek)
    anchors = tuple(a for a in (0x20000, 0x21000, 0) if a < geom.logical_bytes)
    if not anchors:
        raise LayoutDetectionError("logical plane too small for ELF-anchor detection")
    inline_hits = sum(1 for a in anchors if _elf_magic(_read_logical_inline(mv, geom, a)))
    flat_hits = sum(1 for a in anchors if _elf_magic(_read_logical_flat(mv, geom, a)))
    if inline_hits > flat_hits:
        return RawDumpLayout.INLINE_2048_64
    if flat_hits > inline_hits:
        return RawDumpLayout.FLAT_TAIL_2048_64
    if 0x20000 < geom.logical_bytes and _elf_magic(_read_logical_inline(mv, geom, 0x20000)):
        return RawDumpLayout.INLINE_2048_64
    if 0x21000 < geom.logical_bytes and _elf_magic(_read_logical_flat(mv, geom, 0x21000)):
        return RawDumpLayout.FLAT_TAIL_2048_64
    # Pace-class envelope: flat-tail vs inline share the same total byte length.
    # When ELF anchors are absent/tied, use a weak probe at the start of the flat spare tail:
    # printable dmesg text there usually means interleaved inline packing; all-zero / idle
    # spare tail leans toward flat-tail (matches carve dry-run stubs and sparse captures).
    if (
        file_size == geom.full_flat_tail_bytes == geom.full_inline_bytes
        and tail_slab is not None
        and len(tail_slab) >= 8
    ):
        printable = sum(32 <= b < 127 for b in tail_slab)
        if printable >= 24:
            return RawDumpLayout.INLINE_2048_64
        if max(tail_slab) == 0:
            return RawDumpLayout.FLAT_TAIL_2048_64
    raise LayoutDetectionError(
        "Could not disambiguate inline vs flat-tail (ELF anchors tied or absent); "
        "pass layout=RawDumpLayout.INLINE_2048_64 or FLAT_TAIL_2048_64 explicitly"
    )


def read_logical_plane_interval(
    path: str,
    logical_start: int,
    length: int,
    *,
    layout: RawDumpLayout,
    geom: NandGeometry = PACE_DEFAULT,
) -> bytes:
    """
    Read a contiguous byte range on the MTD logical data plane (0 … ``geom.logical_bytes``).

    * ``LOGICAL_ONLY`` / ``FLAT_TAIL_2048_64`` — the first ``logical_bytes`` of the file are
      contiguous logical bytes (flat-tail stores data then spare; only the data prefix is
      mapped here).
    * ``INLINE_2048_64`` — logical addresses map through 2048+64 page pairs.
    """
    if logical_start < 0 or length < 0:
        raise ValueError("logical_start and length must be non-negative")
    if logical_start + length > geom.logical_bytes:
        raise ValueError(
            f"interval [{logical_start:#x}, {logical_start + length:#x}) "
            f"extends past logical plane end {geom.logical_bytes:#x}"
        )
    if layout in (RawDumpLayout.LOGICAL_ONLY, RawDumpLayout.FLAT_TAIL_2048_64):
        with open(path, "rb") as f:
            f.seek(logical_start)
            data = f.read(length)
        if len(data) != length:
            raise ValueError(
                f"short read at logical {logical_start:#x}: got {len(data)}, wanted {length}"
            )
        return data
    if layout == RawDumpLayout.INLINE_2048_64:
        out = bytearray()
        remain = length
        pos = logical_start
        page_data = geom.page_data
        page_phys = geom.page_phys
        with open(path, "rb") as f:
            while remain > 0:
                page, off = divmod(pos, page_data)
                file_off = page * page_phys + off
                take = min(remain, page_data - off)
                f.seek(file_off)
                chunk = f.read(take)
                if len(chunk) != take:
                    raise ValueError(
                        f"short read at logical {pos:#x} (file {file_off:#x}): "
                        f"got {len(chunk)}, wanted {take}"
                    )
                out.extend(chunk)
                remain -= take
                pos += take
        return bytes(out)
    raise ValueError(f"unsupported layout {layout!r}")


def detect_layout_file(path: str, *, geom: NandGeometry = PACE_DEFAULT) -> RawDumpLayout:
    import os

    st = os.stat(path)
    need = min(st.st_size, max(0x22090, geom.page_phys * 70))
    tail_slab: bytes | None = None
    with open(path, "rb") as f:
        peek = f.read(need)
        if st.st_size == geom.full_flat_tail_bytes == geom.full_inline_bytes:
            lb = geom.logical_bytes
            if lb + 8 <= st.st_size:
                f.seek(lb)
                tail_slab = f.read(min(256, st.st_size - lb))
    return detect_layout(st.st_size, geom=geom, peek=peek, tail_slab=tail_slab)


#endregion
