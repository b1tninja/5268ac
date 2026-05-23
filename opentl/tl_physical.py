"""
OpenTL physical-layer helpers: flash dump layout heuristics and TL disklabel scans.

Grounded in 5268AC-class captures (see repo ``issue.md`` / ``fwupgrade.txt``).
"""

from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


from uboot import partition_table_from_bootargs

from unand.geometry import PACE_DEFAULT
from unand.mtd import DEFAULT_MTDPARTS, part_by_name

from opentl.errors import VirtBlockHoleError
from opentl.tl_bbm import is_hole_phys_block

# NAND page geometry — same as :data:`unand.geometry.PACE_DEFAULT` (BCMNAND printk: 2048+64).
PAGE_DATA = PACE_DEFAULT.page_data
PAGE_SPARE = PACE_DEFAULT.page_spare
PAGE_RAW = PACE_DEFAULT.page_phys

# Typical full-chip dump envelope (inline 2112 × pages).
FLASH_5268_CLASS_SIZE = PACE_DEFAULT.full_inline_bytes
PURE_DATA_PLANE = PACE_DEFAULT.logical_bytes
OOB_ENVELOPE = PACE_DEFAULT.oob_total_bytes

# ``tlpart`` start on the logical data plane from default ``mtdparts=`` (via :mod:`uboot` → :mod:`unand.mtd`).
TLPART_NAND_DATA_OFFSET_DEFAULT = part_by_name(
    partition_table_from_bootargs(DEFAULT_MTDPARTS),
    "tlpart",
).offset

ELF_MAGIC = b"\x7fELF"
SQUASHFS_MAGIC_LE = b"hsqs"  # SquashFS little-endian magic at superblock start


#region kernel: 0x80286c30
# opentl_add_mtd — tlpart base in full plane (TLPART_NAND_DATA_OFFSET_DEFAULT) vs BBM prefix origin
def infer_tl_mount_nand_logical_offset(*, logical_image_size: int) -> int:
    """
    Default ``nand_logical_offset`` for :func:`~opentl.tl_mount.mount_flash_image` / :class:`~opentl.open_tl.OpenTL`
    when the caller omits an explicit offset.

    **kernel_replay_v1** virt→phys uses **chip-linear** byte indices ``pb * erase_bytes + …`` into the
    logical NAND plane (see :func:`~opentl.open_tl.virt_global_byte_to_physical`). The prefix buffer
    passed to :func:`~opentl.open_tl.extract_virtual_disk_bytes` is indexed by those same offsets, so
    for a file whose byte ``0`` is plane byte ``0`` (full translate output or tlpart-only carve), the
    mount read must start at **offset 0**. A nonzero skip (e.g. ``tlpart`` at ``0x180000`` on the
    full plane — :data:`TLPART_NAND_DATA_OFFSET_DEFAULT`) was incorrect for BBM assembly: it left
    ``len(prefix)`` too short while the table still referenced bytes past the slice.

    ``logical_image_size`` is retained for API compatibility; exotic layouts should pass an explicit
    ``nand_logical_offset``. For ``tlpart`` payload only, use a carve whose file offset ``0`` is
    already that region (or pass ``--nand-logical-offset`` on the CLI).
    """
    _ = logical_image_size
    return 0


#endregion

# ``parse_bsd`` / U-Boot disklabel printk (sectors as hex, type hex)
TL_DISKLABEL_PARTITIONS_LE: tuple[tuple[int, int, int], ...] = (
    (0x00000008, 0x00000080, 0x0000001D),
    (0x00000088, 0x00000080, 0x0000001D),
    (0x00000108, 0x00000078, 0x0000001C),
    (0x00000180, 0x0003C080, 0x00000011),
)


def _pack_triple_le(start: int, length: int, ptype: int) -> bytes:
    return struct.pack("<III", start & 0xFFFFFFFF, length & 0xFFFFFFFF, ptype & 0xFFFFFFFF)


DISKLABEL_CHAIN_PATTERN = b"".join(_pack_triple_le(*t) for t in TL_DISKLABEL_PARTITIONS_LE)

# Whole-disk slice from U-Boot printk: Partition(2) start 0 / length 0x3c200 (BSD ``c``); type byte not printed.
TL_DISKLABEL_WHOLE_DISK_START_LE = struct.pack("<II", 0, 0x0003_C200)
DISKLABEL_CHAIN5_TAIL_LEN = len(DISKLABEL_CHAIN_PATTERN)
DISKLABEL_CHAIN5_TOTAL_LEN = 12 + DISKLABEL_CHAIN5_TAIL_LEN

# BSD disklabel magic at start of ``disklabel`` structure (little-endian).
BSD_DISKLABEL_MAGIC_LE = struct.pack("<I", 0x82564557)


@dataclass
class LayoutDetectResult:
    file_size: int
    size_matches_5268_oob_model: bool
    pure_data_plane_bytes: int | None
    oob_envelope_bytes: int | None
    hsqs_offset: int | None
    hsqs_magic_ok: bool
    hsqs_offset_mod_page_raw: int | None
    interleaved_page_stride_ruled_out: bool | None
    elf_offset: int
    elf_magic_ok: bool
    recommended_logical_data_end: int | None
    recommendation: str
    notes: list[str] = field(default_factory=list)


def discover_hsqs_for_stride_test(path: str | Path, *, scan_limit: int | None = None) -> tuple[int | None, bool | None]:
    """
    Find a SquashFS superblock magic ``hsqs`` in ``path`` for the 2112-byte stride heuristic.

    Prefer the **first** occurrence whose offset is **not** a multiple of ``PAGE_RAW`` so the
    stride test can rule out uniform 2048+64 interleaving. If every hit is aligned, returns the
    first hit and ``False`` for ``interleaved_ruled_out``.
    """
    p = Path(path)
    size = p.stat().st_size
    limit = scan_limit if scan_limit is not None else min(size, PURE_DATA_PLANE if size >= PURE_DATA_PLANE else size)

    with p.open("rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            pos = 0
            first_aligned: int | None = None
            while pos < limit:
                idx = mm.find(SQUASHFS_MAGIC_LE, pos)
                if idx == -1 or idx >= limit:
                    break
                if idx % PAGE_RAW != 0:
                    return idx, True
                if first_aligned is None:
                    first_aligned = idx
                pos = idx + 1
            if first_aligned is not None:
                return first_aligned, False
            return None, None
        finally:
            mm.close()


def analyze_tl_layout(
    path: str | Path,
    *,
    elf_offset: int = 0x21000,
    hsqs_offset: int | None = None,
    logical_data_end: int | None = None,
    auto_hsqs: bool = True,
) -> LayoutDetectResult:
    """
    Heuristic: distinguish flat logical data (+ optional OOB tail) vs inline 2048+64 interleaving.

    Strong signal: SquashFS ``hsqs`` at an offset that is **not** a multiple of ``PAGE_RAW`` implies
    the dump is **not** uniformly interleaved on a 2112-byte stride (see ``issue.md``).
    """
    p = Path(path)
    size = p.stat().st_size
    notes: list[str] = []

    matches_oob_model = size == FLASH_5268_CLASS_SIZE
    pure = PURE_DATA_PLANE if matches_oob_model else None
    oob_env = OOB_ENVELOPE if matches_oob_model else None

    discovered_ruled_out: bool | None = None
    if hsqs_offset is None and auto_hsqs:
        hsqs_offset, discovered_ruled_out = discover_hsqs_for_stride_test(p)
        if hsqs_offset is not None:
            notes.append(
                f"Auto-selected hsqs@{hsqs_offset:#x} for stride test "
                f"(misaligned={'yes' if discovered_ruled_out else 'no'})."
            )
    elif hsqs_offset is None and not auto_hsqs:
        hsqs_offset = None

    hsqs_magic_ok = False
    hsqs_mod: int | None = None
    ruled_out: bool | None = None

    if hsqs_offset is not None and 0 <= hsqs_offset <= size - 4:
        with p.open("rb") as f:
            f.seek(hsqs_offset)
            hsqs_magic_ok = f.read(4) == SQUASHFS_MAGIC_LE
        hsqs_mod = hsqs_offset % PAGE_RAW
        if hsqs_magic_ok:
            ruled_out = hsqs_mod != 0
            if discovered_ruled_out is not None:
                ruled_out = discovered_ruled_out
            if ruled_out:
                notes.append(
                    f"hsqs@{hsqs_offset:#x} mod {PAGE_RAW} == {hsqs_mod} "
                    f"→ inline {PAGE_RAW}-byte interleaving unlikely if magic is genuine."
                )
            else:
                notes.append(
                    f"hsqs@{hsqs_offset:#x} is aligned on {PAGE_RAW}-byte stride; "
                    "cannot rule out interleaving from this test alone."
                )
        else:
            notes.append(f"No SquashFS magic at hsqs_offset={hsqs_offset:#x}; skipping stride test.")
            ruled_out = None

    elf_magic_ok = False
    if 0 <= elf_offset <= size - 4:
        with p.open("rb") as f:
            f.seek(elf_offset)
            elf_magic_ok = f.read(4) == ELF_MAGIC
        elf_align = elf_offset % PAGE_RAW == 0
        notes.append(
            f"ELF magic at {elf_offset:#x}: {'ok' if elf_magic_ok else 'missing'} "
            + (
                f"(offset on {PAGE_RAW}-byte boundary; ELF span alone does not disprove interleaving)."
                if elf_align
                else "(ELF span alone does not disprove interleaving)."
            )
        )

    if logical_data_end is None:
        logical_data_end = PURE_DATA_PLANE if matches_oob_model else None

    if matches_oob_model and hsqs_magic_ok and ruled_out:
        recommendation = "flat_logical_data_with_appended_oob_tail"
    elif matches_oob_model and hsqs_magic_ok and ruled_out is False:
        recommendation = (
            "flat_logical_data_with_appended_oob_tail_probable_misaligned_hsqs_not_found"
        )
    elif matches_oob_model and not hsqs_magic_ok:
        recommendation = "flat_logical_data_with_appended_oob_tail_probable_no_hsqs_magic"
    elif not matches_oob_model:
        recommendation = "unknown_size_run_hsqs_and_partition_checks"
    else:
        recommendation = "insufficient_evidence"

    return LayoutDetectResult(
        file_size=size,
        size_matches_5268_oob_model=matches_oob_model,
        pure_data_plane_bytes=pure,
        oob_envelope_bytes=oob_env,
        hsqs_offset=hsqs_offset,
        hsqs_magic_ok=hsqs_magic_ok,
        hsqs_offset_mod_page_raw=hsqs_mod,
        interleaved_page_stride_ruled_out=ruled_out,
        elf_offset=elf_offset,
        elf_magic_ok=elf_magic_ok,
        recommended_logical_data_end=logical_data_end,
        recommendation=recommendation,
        notes=notes,
    )


def layout_result_as_dict(r: LayoutDetectResult) -> dict:
    return {
        "file_size": r.file_size,
        "size_matches_5268_oob_model": r.size_matches_5268_oob_model,
        "pure_data_plane_bytes": r.pure_data_plane_bytes,
        "oob_envelope_bytes": r.oob_envelope_bytes,
        "hsqs_offset": r.hsqs_offset,
        "hsqs_magic_ok": r.hsqs_magic_ok,
        "hsqs_offset_mod_page_raw": r.hsqs_offset_mod_page_raw,
        "interleaved_page_stride_ruled_out": r.interleaved_page_stride_ruled_out,
        "elf_offset": r.elf_offset,
        "elf_magic_ok": r.elf_magic_ok,
        "recommended_logical_data_end": r.recommended_logical_data_end,
        "recommendation": r.recommendation,
        "notes": list(r.notes),
    }


@dataclass(frozen=True)
class DisklabelHit:
    offset: int
    match_kind: str  # "chain" | "chain4" | "first_triple" | "bsd_magic"


def _scan_tl_disklabel_seq(buf: Any, *, max_hits: int) -> list[DisklabelHit]:
    """
    Shared scanner for ``mmap`` or ``bytes``-like buffers supporting ``.find`` and length.

    ``max_hits`` is applied **per match kind** (chain5, chain4, first_triple, bsd_magic), not as
    one shared pool — so a flood of spurious ``chain4`` substring hits cannot starve ``bsd_magic``
    collection at higher offsets.
    """
    seen_anchor: set[int] = set()
    mm_len = len(buf)

    def room_for_chain5(idx: int) -> bool:
        return idx + DISKLABEL_CHAIN5_TOTAL_LEN <= mm_len

    chain5_hits: list[DisklabelHit] = []
    pos = 0
    while len(chain5_hits) < max_hits:
        idx = buf.find(TL_DISKLABEL_WHOLE_DISK_START_LE, pos)
        if idx == -1:
            break
        if room_for_chain5(idx):
            tail_from = idx + 12
            if buf[tail_from : tail_from + DISKLABEL_CHAIN5_TAIL_LEN] == DISKLABEL_CHAIN_PATTERN:
                if idx not in seen_anchor:
                    chain5_hits.append(DisklabelHit(offset=idx, match_kind="chain"))
                    seen_anchor.add(idx)
        pos = idx + 1

    chain4_hits: list[DisklabelHit] = []
    pos = 0
    while len(chain4_hits) < max_hits:
        idx = buf.find(DISKLABEL_CHAIN_PATTERN, pos)
        if idx == -1:
            break
        if idx not in seen_anchor:
            chain4_hits.append(DisklabelHit(offset=idx, match_kind="chain4"))
            seen_anchor.add(idx)
        pos = idx + 1

    first = _pack_triple_le(*TL_DISKLABEL_PARTITIONS_LE[0])
    triple_hits: list[DisklabelHit] = []
    pos = 0
    while len(triple_hits) < max_hits:
        idx = buf.find(first, pos)
        if idx == -1:
            break
        if idx not in seen_anchor:
            triple_hits.append(DisklabelHit(offset=idx, match_kind="first_triple"))
            seen_anchor.add(idx)
        pos = idx + 1

    bsd_hits: list[DisklabelHit] = []
    seen_bsd: set[int] = set()
    pos = 0
    while len(bsd_hits) < max_hits:
        idx = buf.find(BSD_DISKLABEL_MAGIC_LE, pos)
        if idx == -1:
            break
        if idx not in seen_bsd:
            bsd_hits.append(DisklabelHit(offset=idx, match_kind="bsd_magic"))
            seen_bsd.add(idx)
        pos = idx + 1

    hits = chain5_hits + chain4_hits + triple_hits + bsd_hits
    hits.sort(key=lambda h: h.offset)
    return hits


def scan_tl_disklabel_bytes(data: bytes | bytearray, *, max_hits: int = 50) -> list[DisklabelHit]:
    """
    Same semantics as :func:`scan_tl_disklabel`, but scans an in-memory buffer (no mmap).

    ``max_hits`` limits each of chain5, chain4, ``first_triple``, and ``bsd_magic`` independently
    (up to ``4 * max_hits`` hits total, sorted by offset).
    """
    return _scan_tl_disklabel_seq(data, max_hits=max_hits)


def scan_tl_disklabel(path: str | Path, *, max_hits: int = 50) -> list[DisklabelHit]:
    """
    Search raw image for little-endian (start, length, type) tuples matching ``parse_bsd`` printk.

    * ``chain`` — whole-disk triple ``(0, 0x3c200, *)`` followed by the four known slices (type of whole-disk ignored).
    * ``chain4`` — legacy contiguous four-tuple chain only.
    * ``first_triple`` — first env slice triple only.
    * ``bsd_magic`` — BSD ``disklabel`` magic ``0x82564557`` (LE).

    ``max_hits`` limits each match kind independently (see :func:`scan_tl_disklabel_bytes`).
    """
    p = Path(path)
    with p.open("rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        return _scan_tl_disklabel_seq(mm, max_hits=max_hits)
    finally:
        mm.close()


def disklabel_hits_as_dicts(hits: Iterable[DisklabelHit]) -> list[dict]:
    return [{"offset": h.offset, "offset_hex": f"{h.offset:#x}", "match_kind": h.match_kind} for h in hits]


def summarize_tl_physical_probe(path: str | Path, *, hsqs_offset: int | None = None) -> dict:
    """One-shot summary for CLI / JSON: layout + disklabel (no env string scan)."""
    layout = analyze_tl_layout(path, hsqs_offset=hsqs_offset)
    dhits = scan_tl_disklabel(path)
    return {
        "layout": layout_result_as_dict(layout),
        "disklabel_hits": disklabel_hits_as_dicts(dhits[:20]),
        "disklabel_hit_count": len(dhits),
    }


# --- OpenTL erase-block geometry (5268-class; fwupgrade.txt / kernel RE) ---

TL_ERASE_BYTES_DEFAULT = 131072  # 128 KiB
TL_RAW_BLOCKS_DEFAULT = 1012
TL_VIRT_BLOCKS_DEFAULT = 982
TL_LOGICAL_PREFIX_DEFAULT = TL_RAW_BLOCKS_DEFAULT * TL_ERASE_BYTES_DEFAULT  # 132644864


@dataclass(frozen=True)
class TLGeometry:
    """5268-class TL virtual/raw block counts and boot-trace invariants (kernel printk corroboration)."""

    erase_bytes: int = TL_ERASE_BYTES_DEFAULT
    raw_blocks: int = TL_RAW_BLOCKS_DEFAULT
    virt_blocks: int = TL_VIRT_BLOCKS_DEFAULT
    stats_blocks: int = 1
    bb_reserved: int = 30
    head_pages: int = 1
    media_pages: int = 64768
    spares_field: int = 85
    cap_sectors: int = 251132
    geometry_wasted_sectors: int = 252
    sectors_per_unit: int = 256


@dataclass
class BlockMapBuild:
    """Virt→physical erase-block indices (kernel table shape; load via JSON or explicit construction)."""

    geometry: TLGeometry
    mode: str
    logical_prefix_bytes: int
    virt_to_phys_block: list[int]
    stats_physical_block_index: int | None = None
    heuristic_score: float | None = None
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    source_path: str | None = None
    input_sha256_prefix: str | None = None
    nand_logical_offset: int = 0

    def virt_to_phys_block_index(self, virt_block: int) -> int:
        """Physical erase-block index for virtual block ``virt_block`` (raises if unmapped hole)."""
        if virt_block < 0 or virt_block >= len(self.virt_to_phys_block):
            raise IndexError(
                f"virt_block {virt_block} out of range for map length {len(self.virt_to_phys_block)}"
            )
        pb = self.virt_to_phys_block[virt_block]
        if is_hole_phys_block(pb):
            raise VirtBlockHoleError(
                f"virt_block {virt_block} is an unmapped hole (phys_unit 0xffffffff); no physical erase index"
            )
        return pb


def geometry_boot_trace_dict(g: TLGeometry) -> dict[str, Any]:
    """Constants corroborating fwupgrade.txt OpenTL / nand_geom printks."""
    return {
        "head_pages": g.head_pages,
        "media_pages": g.media_pages,
        "spares_field": g.spares_field,
        "cap_sectors": g.cap_sectors,
        "geometry_wasted_sectors": g.geometry_wasted_sectors,
        "sectors_per_unit": g.sectors_per_unit,
    }

