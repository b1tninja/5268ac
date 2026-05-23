"""
Offline enumeration of **TL disklabel** slices inside ``tlpart`` (kernel ``parse_bsd`` / ``tldisk_partition`` analogue).

Uses the same printk-corroborated tuple chain as :mod:`opentl.tl_physical` but returns **named byte ranges**
(``opentla1`` … ``opentla4``) suitable for filesystem tooling. Does not call the kernel.

- :func:`enumerate_tl_slices_from_bytes` — raw buffer only (no TL superblock handling).
- :func:`enumerate_tl_slices_from_tlpart_mtd_bytes` — **MTD ``tlpart`` image**: optional kernel
  TL superblock prefix (:mod:`opentl.tl_superblock`) then disklabel scan; returns ``mtd_skip``
  for tools that map slice sectors to flash bytes.

Import explicitly (not re-exported from :mod:`opentl` root)::

    from opentl.tldisk import enumerate_tl_slices, enumerate_tl_slices_from_tlpart_mtd_bytes, TLDiskSlice
"""

from __future__ import annotations

import json
import logging
import os
import struct
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path

from opentl.tl_physical import DisklabelHit

from opentl.open_tl import OPENTLA4_NUM_SECTORS, OPENTLA4_START_SECTOR, SECTOR_BYTES
from opentl.tl_physical import (
    BSD_DISKLABEL_MAGIC_LE,
    DISKLABEL_CHAIN5_TAIL_LEN,
    DISKLABEL_CHAIN5_TOTAL_LEN,
    DISKLABEL_CHAIN_PATTERN,
    TL_DISKLABEL_PARTITIONS_LE,
    TL_DISKLABEL_WHOLE_DISK_START_LE,
    scan_tl_disklabel_bytes,
)
from opentl.tl_mbr_slice import mbr_first_a5_slice_byte_offset
from opentl.tl_superblock import tl_superblock_skip_bytes

_LOG = logging.getLogger(__name__)

# Whole-disk ``c`` slice: start 0, length 0x3c200 sectors (see tl_physical / U-Boot printk).
_WHOLE_DISK_NUM_SECTORS = 0x3C200

_PRINTK_PARTITION_TOTAL = 8

#region kernel: 0x8020ec1c parse_bsd disklabel sector (FUN_8020ec1c / read_dev_sector)
# Ghidra: d_magic @0, d_npartitions BE u16 @0x8a, 16-byte entries @0x94 (start/length BE, ptype @+0xc).
DISKLABEL_SECTOR_BYTES = SECTOR_BYTES
DISKLABEL_D_MAGIC_OFF = 0
DISKLABEL_D_NPARTITIONS_OFF = 0x8A
DISKLABEL_D_PARTITIONS_OFF = 0x94
DISKLABEL_D_PARTITION_STRIDE = 16
DISKLABEL_D_PARTITION_PTYPE_OFF = 0xC
DISKLABEL_MAX_PARTITIONS = 0x10
# Pace-class virt cap from fwupgrade / tldisk_partition printk (~0x3d4fc sectors).
DISKLABEL_MAX_START_SECTOR = 0x0040_0000
DISKLABEL_MAX_LENGTH_SECTORS = 0x0040_0000
#endregion

@dataclass(frozen=True, slots=True)
class TLDiskSlice:
    """One TL child slice (``opentla1`` … ``opentla4``) or whole-disk ``opentla0`` when chain5 is present."""

    name: str
    index: int
    start_sector: int
    num_sectors: int
    ptype: int
    offset_bytes: int
    length_bytes: int


@dataclass
class TLDiskEnumerationResult:
    """Result of :func:`enumerate_tl_slices` / :func:`enumerate_tl_slices_from_bytes`."""

    slices: tuple[TLDiskSlice, ...]
    anchor_offset: int
    anchor_kind: str  # "chain5" | "chain4" | "manual_chain5" | "manual_chain4"
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    enumerate_log: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class TlpartTlEnumeration:
    """
    Result of :func:`enumerate_tl_slices_from_tlpart_mtd_bytes` — TL disklabel slices plus
    ``mtd_skip`` so MTD-backed tools can map virtual sector 0 to ``tlpart`` byte ``mtd_skip``.
    """

    result: TLDiskEnumerationResult
    mtd_skip: int


@dataclass(frozen=True, slots=True)
class TLDiskProbeReport:
    """Structured counts for TL disklabel auto-scan failures (``OPENTL_TLDISK_REPORT=1``)."""

    buffer_len: int
    hit_counts: dict[str, int]
    bsd_magic_offsets: tuple[int, ...]
    chain_like_hits: int
    anchors_tried: int
    bsd_window_search_tried: bool
    global_bsd_chain_search_tried: bool
    mbr_a5_slice_fallback_attempted: bool
    last_anchor_offset: int | None
    nearest_bsd_delta: int | None
    last_error: str | None


def _tl_probe_report_env_enabled() -> bool:
    v = os.environ.get("OPENTL_TLDISK_REPORT", "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _emit_tl_disk_probe_report(report: TLDiskProbeReport) -> None:
    if not _tl_probe_report_env_enabled():
        return
    log = logging.getLogger("opentl.tldisk.probe")
    payload = {
        "buffer_len": report.buffer_len,
        "hit_counts": report.hit_counts,
        "bsd_magic_offsets_hex": [f"{o:#x}" for o in report.bsd_magic_offsets],
        "chain_like_hits": report.chain_like_hits,
        "anchors_tried": report.anchors_tried,
        "bsd_window_search_tried": report.bsd_window_search_tried,
        "global_bsd_chain_search_tried": report.global_bsd_chain_search_tried,
        "mbr_a5_slice_fallback_attempted": report.mbr_a5_slice_fallback_attempted,
        "last_anchor_offset_hex": None
        if report.last_anchor_offset is None
        else f"{report.last_anchor_offset:#x}",
        "nearest_bsd_delta": report.nearest_bsd_delta,
        "last_error": report.last_error,
    }
    log.info("TLDiskProbeReport %s", json.dumps(payload, sort_keys=True))


def enumerate_tl_slices_from_tlpart_mtd_bytes(blob: bytes) -> TlpartTlEnumeration:
    """
    Enumerate TL disklabel slices for a **raw ``tlpart`` MTD byte image**.

    If a kernel TL superblock (:mod:`opentl.tl_superblock`) is present, tries disklabel
    enumeration on ``blob[skip:]`` **first** (``skip`` from :func:`tl_superblock_skip_bytes`),
    then falls back to the full ``blob``. :attr:`TlpartTlEnumeration.mtd_skip` is ``skip`` when
    the suffix path wins, else ``0``. :attr:`~TLDiskEnumerationResult.anchor_offset` is always
    expressed relative to the **start of the full** ``blob``.

    For a plain byte buffer that is already ``tlpart``-relative with no TL header, use
    :func:`enumerate_tl_slices_from_bytes` directly.
    """
    skip = tl_superblock_skip_bytes(blob) or 0
    if skip > 0:
        try:
            inner = enumerate_tl_slices_from_bytes(blob[skip:])
            out = replace(
                inner,
                anchor_offset=inner.anchor_offset + skip,
                notes=[
                    *inner.notes,
                    f"opentl: tlpart enumeration used TL superblock skip {skip:#x}",
                ],
            )
            return TlpartTlEnumeration(result=out, mtd_skip=skip)
        except ValueError:
            pass
    full = enumerate_tl_slices_from_bytes(blob)
    notes = list(full.notes)
    if skip > 0:
        notes.append(
            "opentl: tlpart enumeration fell back to full buffer "
            "(TL superblock skip did not yield a valid disklabel)"
        )
    return TlpartTlEnumeration(result=replace(full, notes=notes), mtd_skip=0)


def read_virtual_sector(virt_stream: bytes, sector_index: int) -> bytes:
    """Return one 512-byte logical sector from a materialized virt→phys byte stream."""
    if sector_index < 0:
        raise ValueError(f"sector_index must be non-negative, got {sector_index}")
    start = sector_index * DISKLABEL_SECTOR_BYTES
    end = start + DISKLABEL_SECTOR_BYTES
    if end > len(virt_stream):
        return virt_stream[start:] + bytes(end - len(virt_stream))
    return virt_stream[start:end]


def parse_bsd_disklabel_sector(sector: bytes) -> tuple[TLDiskSlice, ...] | None:
    """
    Parse one kernel ``read_dev_sector`` disklabel buffer (``FUN_8020ec1c`` @ ``0x8020ec1c``).

    Returns ``opentla1`` … slices for each partition entry with non-zero ``ptype``, or ``None`` if the
    sector fails magic / ``d_npartitions`` / sanity checks. See
    ``reference/ghidra_parse_bsd_disklabel_layout.md``.
    """
    if len(sector) < DISKLABEL_D_PARTITIONS_OFF + DISKLABEL_D_PARTITION_STRIDE:
        return None
    if sector[DISKLABEL_D_MAGIC_OFF : DISKLABEL_D_MAGIC_OFF + 4] != BSD_DISKLABEL_MAGIC_LE:
        return None
    nparts = struct.unpack_from(">H", sector, DISKLABEL_D_NPARTITIONS_OFF)[0]
    if nparts == 0 or nparts > DISKLABEL_MAX_PARTITIONS:
        return None
    out: list[TLDiskSlice] = []
    slot = 0
    for i in range(nparts):
        base = DISKLABEL_D_PARTITIONS_OFF + i * DISKLABEL_D_PARTITION_STRIDE
        if base + DISKLABEL_D_PARTITION_STRIDE > len(sector):
            break
        start_sec = struct.unpack_from(">I", sector, base)[0]
        num_sec = struct.unpack_from(">I", sector, base + 4)[0]
        ptype = sector[base + DISKLABEL_D_PARTITION_PTYPE_OFF]
        if ptype == 0:
            continue
        if start_sec >= DISKLABEL_MAX_START_SECTOR or num_sec >= DISKLABEL_MAX_LENGTH_SECTORS:
            return None
        if num_sec == 0:
            continue
        slot += 1
        out.append(
            TLDiskSlice(
                name=f"opentla{slot}",
                index=slot,
                start_sector=start_sec,
                num_sectors=num_sec,
                ptype=ptype,
                offset_bytes=start_sec * SECTOR_BYTES,
                length_bytes=num_sec * SECTOR_BYTES,
            )
        )
    return tuple(out) if out else None
#endregion


def buffer_has_tl_disklabel_anchor(data: bytes) -> bool:
    """True if ``data`` has a chain anchor, valid BSD disklabel sector, or ``bsd_magic``."""
    if not data:
        return False
    raw = scan_tl_disklabel_bytes(data, max_hits=30)
    if any(h.match_kind in ("chain", "chain4") for h in raw):
        return True
    bsd_list = [h.offset for h in raw if h.match_kind == "bsd_magic"]
    if _try_enumerate_bsd_disklabel_sectors(data, bsd_list) is not None:
        return True
    return bool(bsd_list)


def _sector_aligned_bsd_offsets(data: bytes, bsd_offsets: list[int]) -> list[int]:
    """Prefer ``bsd_magic`` at 512-byte sector boundaries (kernel ``read_dev_sector`` view)."""
    n = len(data)
    aligned: list[int] = []
    for off in sorted(set(bsd_offsets)):
        if off % DISKLABEL_SECTOR_BYTES == 0 and off + DISKLABEL_SECTOR_BYTES <= n:
            aligned.append(off)
    return aligned


def _try_enumerate_bsd_disklabel_sectors(
    data: bytes, bsd_offsets: list[int]
) -> TLDiskEnumerationResult | None:
    """Try kernel ``parse_bsd`` sector layout at each sector-aligned ``bsd_magic`` offset."""
    warnings: list[str] = []
    for off in _sector_aligned_bsd_offsets(data, bsd_offsets):
        sector = data[off : off + DISKLABEL_SECTOR_BYTES]
        slices_list = parse_bsd_disklabel_sector(sector)
        if slices_list is None:
            continue
        notes = [
            f"auto-selected BSD disklabel sector at {off:#x} "
            "(kernel parse_bsd layout, reference/ghidra_parse_bsd_disklabel_layout.md)"
        ]
        log = ["tldisk_partition: going to enumerate"]
        for i, _s in enumerate(slices_list, start=1):
            log.append(f"parse_bsd: adding tldisk partition at {i}/{_PRINTK_PARTITION_TOTAL}")
        _validate_opentla4(slices_list, warnings)
        return TLDiskEnumerationResult(
            slices=slices_list,
            anchor_offset=off,
            anchor_kind="bsd_disklabel_sector",
            warnings=warnings,
            notes=notes,
            enumerate_log=log,
        )
    return None


def _triple_at(buf: bytes, off: int) -> tuple[int, int, int] | None:
    if off < 0 or off + 12 > len(buf):
        return None
    a, b, c = struct.unpack_from("<III", buf, off)
    return (a & 0xFFFFFFFF, b & 0xFFFFFFFF, c & 0xFFFFFFFF)


# After ``bsd_magic``, Pace-class dumps often store printk triples non-contiguously (not ``DISKLABEL_CHAIN_PATTERN``).
_SCATTERED_BSD_SEARCH_WINDOW = 0x400
_SCATTERED_BSD_STRIDE = 4


def _partition_triple_matches(
    triple: tuple[int, int, int], expected: tuple[int, int, int]
) -> bool:
    """True if ``triple`` is ``(start, length, ptype)`` or ``(ptype, length, start)`` for ``expected``."""
    if triple == expected:
        return True
    s, ln, pt = expected
    return triple == (pt, ln, s)


def _find_scattered_partition_offsets(buf: bytes, win_start: int, win_end: int) -> tuple[int, ...] | None:
    """Return increasing byte offsets of all four printk partitions inside ``[win_start, win_end)``."""
    n = len(buf)
    win_start = max(0, win_start)
    win_end = min(n, win_end)
    if win_end - win_start < 12:
        return None
    cands: list[list[int]] = [[] for _ in range(len(TL_DISKLABEL_PARTITIONS_LE))]
    for off in range(win_start, win_end - 11, _SCATTERED_BSD_STRIDE):
        t = _triple_at(buf, off)
        if t is None:
            continue
        for i, exp in enumerate(TL_DISKLABEL_PARTITIONS_LE):
            if _partition_triple_matches(t, exp):
                cands[i].append(off)

    def pick_chain(idx: int, min_off: int) -> list[int] | None:
        if idx >= len(TL_DISKLABEL_PARTITIONS_LE):
            return []
        for off in cands[idx]:
            if off > min_off:
                rest = pick_chain(idx + 1, off)
                if rest is not None:
                    return [off, *rest]
        return None

    if any(not c for c in cands):
        return None
    chain = pick_chain(0, win_start - 1)
    if chain is None or len(chain) != len(TL_DISKLABEL_PARTITIONS_LE):
        return None
    return tuple(chain)


def _build_slices_from_scattered_partitions(
    buf: bytes, part_offsets: tuple[int, ...]
) -> tuple[tuple[TLDiskSlice, ...], list[str]]:
    out: list[TLDiskSlice] = []
    log: list[str] = ["tldisk_partition: going to enumerate"]
    for i, (ss, slen, pt) in enumerate(TL_DISKLABEL_PARTITIONS_LE):
        t = _triple_at(buf, part_offsets[i])
        if t is None or not _partition_triple_matches(t, (ss, slen, pt)):
            raise ValueError(f"scattered triple {i} mismatch at {part_offsets[i]:#x}")
        out.append(
            TLDiskSlice(
                name=f"opentla{i + 1}",
                index=i + 1,
                start_sector=ss,
                num_sectors=slen,
                ptype=pt,
                offset_bytes=ss * SECTOR_BYTES,
                length_bytes=slen * SECTOR_BYTES,
            )
        )
        log.append(f"parse_bsd: adding tldisk partition at {i + 1}/{_PRINTK_PARTITION_TOTAL}")
    return tuple(out), log


def _pace_tl_disklabel_header_signature(buf: bytes, bsd_off: int) -> bool:
    """True when bytes after ``bsd_magic`` look like the vendor ``opentl`` / ``tldisk`` label header."""
    n = len(buf)
    if bsd_off < 0 or bsd_off + 4 > n:
        return False
    if buf[bsd_off : bsd_off + 4] != BSD_DISKLABEL_MAGIC_LE:
        return False
    win = buf[bsd_off : min(n, bsd_off + 0x80)]
    return b"opentl" in win and b"tldisk" in win


#region kernel_adjacent tldisk_printk_constants_fallback
def _build_slices_from_printk_constants() -> tuple[tuple[TLDiskSlice, ...], list[str]]:
    """Build opentla1..4 from :data:`TL_DISKLABEL_PARTITIONS_LE` (U-Boot ``parse_bsd`` printk)."""
    out: list[TLDiskSlice] = []
    log: list[str] = ["tldisk_partition: going to enumerate"]
    for i, (ss, slen, pt) in enumerate(TL_DISKLABEL_PARTITIONS_LE):
        out.append(
            TLDiskSlice(
                name=f"opentla{i + 1}",
                index=i + 1,
                start_sector=ss,
                num_sectors=slen,
                ptype=pt,
                offset_bytes=ss * SECTOR_BYTES,
                length_bytes=slen * SECTOR_BYTES,
            )
        )
        log.append(f"parse_bsd: adding tldisk partition at {i + 1}/{_PRINTK_PARTITION_TOTAL}")
    return tuple(out), log


def _try_enumerate_printk_constants_near_bsd(
    data: bytes, bsd_offsets: list[int]
) -> TLDiskEnumerationResult | None:
    """
    When chain/scattered parsing fails but ``bsd_magic`` is followed by ``opentl``/``tldisk`` strings
    (Pace-class vendor label header), use printk-corroborated geometry from :mod:`opentl.tl_physical`.
    """
    for bsd in sorted(set(bsd_offsets)):
        if not _pace_tl_disklabel_header_signature(data, bsd):
            continue
        slices_list, log = _build_slices_from_printk_constants()
        warnings = [
            "opentl: TL disklabel partition geometry taken from printk constants "
            "(on-image tuples missing or corrupt; verify against capture)"
        ]
        notes = [
            f"auto-selected printk-constant partitions near vendor header at bsd_magic {bsd:#x}"
        ]
        _validate_opentla4(slices_list, warnings)
        return TLDiskEnumerationResult(
            slices=slices_list,
            anchor_offset=bsd,
            anchor_kind="bsd_printk_constants",
            warnings=warnings,
            notes=notes,
            enumerate_log=log,
        )
    return None


def _try_enumerate_scattered_bsd_partitions(
    data: bytes, bsd_offsets: list[int]
) -> TLDiskEnumerationResult | None:
    """When chain5/chain4 substrings are absent, match printk triples near ``bsd_magic``."""
    n = len(data)
    seen: set[int] = set()
    for bsd in sorted(set(bsd_offsets)):
        if bsd in seen:
            continue
        seen.add(bsd)
        win_end = min(n, bsd + _SCATTERED_BSD_SEARCH_WINDOW)
        part_offs = _find_scattered_partition_offsets(data, bsd, win_end)
        if part_offs is None:
            continue
        slices_list, log = _build_slices_from_scattered_partitions(data, part_offs)
        notes = [
            f"auto-selected scattered TL partitions near bsd_magic at {bsd:#x} "
            f"(offsets {[f'{o:#x}' for o in part_offs]})"
        ]
        warnings: list[str] = []
        _validate_opentla4(slices_list, warnings)
        return TLDiskEnumerationResult(
            slices=slices_list,
            anchor_offset=part_offs[0],
            anchor_kind="bsd_scattered",
            warnings=warnings,
            notes=notes,
            enumerate_log=log,
        )
    return None


def _layout_at_anchor(buf: bytes, anchor: int) -> tuple[str, int]:
    """
    Return ``(kind, first_triple_offset)`` where ``kind`` is chain5 or chain4, or raise ValueError.
    ``first_triple_offset`` is byte offset of ``TL_DISKLABEL_PARTITIONS_LE[0]`` within ``buf``.
    """
    n = len(buf)
    if anchor < 0 or anchor >= n:
        raise ValueError(f"anchor_offset {anchor} out of range for buffer length {n}")

    if anchor + 12 + DISKLABEL_CHAIN5_TAIL_LEN <= n:
        if buf[anchor : anchor + 8] == TL_DISKLABEL_WHOLE_DISK_START_LE:
            tail_from = anchor + 12
            if buf[tail_from : tail_from + DISKLABEL_CHAIN5_TAIL_LEN] == DISKLABEL_CHAIN_PATTERN:
                return ("chain5", anchor + 12)

    if anchor + DISKLABEL_CHAIN5_TAIL_LEN <= n:
        if buf[anchor : anchor + DISKLABEL_CHAIN5_TAIL_LEN] == DISKLABEL_CHAIN_PATTERN:
            return ("chain4", anchor)

    raise ValueError(
        f"no TL disklabel chain at anchor {anchor:#x}: need chain5 (whole-disk + 4 tuples) or chain4"
    )


def _build_slices(buf: bytes, anchor: int) -> tuple[tuple[TLDiskSlice, ...], str, list[str]]:
    kind, triple0 = _layout_at_anchor(buf, anchor)
    out: list[TLDiskSlice] = []
    log: list[str] = []
    log.append("tldisk_partition: going to enumerate")

    if kind == "chain5":
        wd = _triple_at(buf, anchor)
        if wd is None:
            raise ValueError("chain5: truncated buffer at whole-disk triple")
        ws, wlen, wtype = wd
        if ws != 0 or wlen != _WHOLE_DISK_NUM_SECTORS:
            raise ValueError(f"chain5: unexpected whole-disk triple {(ws, wlen, wtype)!r}")
        out.append(
            TLDiskSlice(
                name="opentla0",
                index=0,
                start_sector=ws,
                num_sectors=wlen,
                ptype=wtype,
                offset_bytes=ws * SECTOR_BYTES,
                length_bytes=wlen * SECTOR_BYTES,
            )
        )
        log.append(f"parse_bsd: adding tldisk partition at 1/{_PRINTK_PARTITION_TOTAL}")
        base_idx = 1
        part_base = triple0
        slot0 = 2
    else:
        base_idx = 1
        part_base = triple0
        slot0 = 1

    for i, (ss, slen, pt) in enumerate(TL_DISKLABEL_PARTITIONS_LE):
        off = part_base + i * 12
        t = _triple_at(buf, off)
        if t is None:
            raise ValueError(f"truncated buffer reading triple {i} at {off:#x}")
        ss2, slen2, pt2 = t
        if (ss2, slen2, pt2) != (ss, slen, pt):
            raise ValueError(
                f"triple mismatch at {off:#x}: disk has {(ss2, slen2, pt2)!r} expected {(ss, slen, pt)!r}"
            )
        name = f"opentla{base_idx + i}"
        out.append(
            TLDiskSlice(
                name=name,
                index=base_idx + i,
                start_sector=ss,
                num_sectors=slen,
                ptype=pt,
                offset_bytes=ss * SECTOR_BYTES,
                length_bytes=slen * SECTOR_BYTES,
            )
        )
        log.append(
            f"parse_bsd: adding tldisk partition at {slot0 + i}/{_PRINTK_PARTITION_TOTAL}"
        )

    return tuple(out), kind, log


def _shift_enumeration_slice_offsets(r: TLDiskEnumerationResult, delta: int) -> TLDiskEnumerationResult:
    """Shift :attr:`~TLDiskSlice.offset_bytes` and :attr:`~TLDiskEnumerationResult.anchor_offset` by ``delta``."""
    shifted = tuple(
        replace(s, offset_bytes=s.offset_bytes + delta, length_bytes=s.length_bytes) for s in r.slices
    )
    return replace(r, slices=shifted, anchor_offset=r.anchor_offset + delta)


_BSD_OFFSET_LOG_CAP = 8

# When linear ``chain``/``chain4`` hits are absent but ``bsd_magic`` appears (kernel ``parse_bsd``
# path over a block buffer), the TL tuple block may sit within a few KiB of the label magic.
# Wider than a single erase block so disklabel magic can precede/follow the tuple block by >16 KiB.
_CHAIN_NEAR_BSD_HALF_WINDOW = 65536

# When ``bsd_magic`` exists but no chain sits in the near window, scan the whole buffer for
# chain5/chain4 and try anchors sorted by distance to ``bsd_magic`` (layout skew / sparse scan).
_GLOBAL_BSD_CHAIN_MAX_CHAIN5 = 120
_GLOBAL_BSD_CHAIN_MAX_CHAIN4 = 500
_GLOBAL_BSD_CHAIN_TRY_CAP = 450


#region kernel_adjacent tldisk_offline_chain_anchor_search
def _min_abs_dist(anchor: int, refs: list[int]) -> int:
    return min(abs(anchor - r) for r in refs)


def _collect_global_chain_anchor_offsets(
    data: bytes,
    *,
    max_chain5: int,
    max_chain4: int,
) -> list[int]:
    """All valid chain5 / chain4 anchor offsets in ``data`` (capped for very noisy images)."""
    n = len(data)
    seen: set[int] = set()
    out: list[int] = []

    pos = 0
    c5 = 0
    while c5 < max_chain5:
        idx = data.find(TL_DISKLABEL_WHOLE_DISK_START_LE, pos)
        if idx == -1:
            break
        if idx + DISKLABEL_CHAIN5_TOTAL_LEN <= n:
            tail_from = idx + 12
            if data[tail_from : tail_from + DISKLABEL_CHAIN5_TAIL_LEN] == DISKLABEL_CHAIN_PATTERN:
                if idx not in seen:
                    seen.add(idx)
                    out.append(idx)
                    c5 += 1
        pos = idx + 1

    pos = 0
    c4 = 0
    lp = len(DISKLABEL_CHAIN_PATTERN)
    while c4 < max_chain4:
        idx = data.find(DISKLABEL_CHAIN_PATTERN, pos)
        if idx == -1:
            break
        if idx not in seen:
            seen.add(idx)
            out.append(idx)
            c4 += 1
        pos = idx + 1

    return out


def _sort_anchor_offsets_by_bsd_distance(anchors: list[int], bsd_offsets: list[int]) -> list[int]:
    bs = sorted(set(bsd_offsets))
    if not bs:
        return sorted(set(anchors))
    return sorted(set(anchors), key=lambda a: min(abs(a - b) for b in bs))
#endregion


def _anchors_near_bsd_magic_sorted(
    data: bytes,
    bsd_offsets: list[int],
    *,
    half_window: int,
    skip: set[int],
) -> list[int]:
    """Unique chain5/chain4 anchor offsets within ``half_window`` of any ``bsd_offsets``."""
    n = len(data)
    bsds = sorted(set(bsd_offsets))
    if not bsds:
        return []
    lp = len(DISKLABEL_CHAIN_PATTERN)
    found: set[int] = set()
    for bsd in bsds:
        lo = max(0, bsd - half_window)
        hi5 = min(n - DISKLABEL_CHAIN5_TOTAL_LEN, bsd + half_window)
        hi4 = min(n - lp, bsd + half_window)
        for a in range(lo, hi5 + 1):
            if a in skip or a in found:
                continue
            if data[a : a + 8] == TL_DISKLABEL_WHOLE_DISK_START_LE:
                tf = a + 12
                if data[tf : tf + DISKLABEL_CHAIN5_TAIL_LEN] == DISKLABEL_CHAIN_PATTERN:
                    found.add(a)
        for a in range(lo, hi4 + 1):
            if a in skip or a in found:
                continue
            if data[a : a + lp] == DISKLABEL_CHAIN_PATTERN:
                found.add(a)
    return sorted(found, key=lambda a: (_min_abs_dist(a, bsds), a))


def _log_tl_enumeration_failure_diagnostics(
    raw_hits: list[DisklabelHit],
    *,
    last_err: Exception | None,
    bsd_window_search_tried: bool = False,
    global_bsd_chain_search_tried: bool = False,
) -> None:
    bsd = [h.offset for h in raw_hits if h.match_kind == "bsd_magic"]
    n_triple = sum(1 for h in raw_hits if h.match_kind == "first_triple")
    lines: list[str] = []
    if bsd:
        head = bsd[:_BSD_OFFSET_LOG_CAP]
        tail = len(bsd) - len(head)
        suf = f" (+{tail} more)" if tail else ""
        lines.append(
            "scan: bsd_magic (0x82564557) at offsets: "
            + ", ".join(f"{o:#x}" for o in head)
            + suf
        )
    else:
        lines.append("scan: no bsd_magic hits among scan_tl_disklabel_bytes results")
    lines.append(f"scan: first_triple hit count: {n_triple}")
    lines.append(
        "hint: kernel parse_bsd reads 512-byte sectors via read_dev_sector (see "
        "reference/ghidra_parse_bsd_disklabel_layout.md); legacy scan also tries contiguous "
        "printk tuple chains and BSD disklabel sectors at sector-aligned bsd_magic."
    )
    if bsd_window_search_tried:
        lines.append(
            f"also searched ±{_CHAIN_NEAR_BSD_HALF_WINDOW:#x} bytes around each bsd_magic for "
            "chain5/chain4 — no valid anchor."
        )
    if global_bsd_chain_search_tried:
        lines.append(
            "also searched the full buffer for chain5/chain4 (capped), trying anchors closest to "
            "each bsd_magic first — no valid anchor."
        )
    if last_err is not None:
        lines.append(f"last chain/chain4 anchor attempt: {last_err}")
    _LOG.debug("TL disklabel auto-enumeration failed.\n%s", "\n".join(lines))


def _make_tl_probe_report_from_failure(
    data: bytes,
    raw_hits: list[DisklabelHit],
    *,
    tried_anchors: set[int],
    bsd_window_search_tried: bool,
    global_bsd_chain_search_tried: bool,
    mbr_a5_slice_fallback_attempted: bool,
    last_anchor_attempt: int | None,
    last_err: Exception | None,
) -> TLDiskProbeReport:
    bsd_all = sorted({h.offset for h in raw_hits if h.match_kind == "bsd_magic"})
    bsd_show = tuple(bsd_all[:32])
    near: int | None = None
    if last_anchor_attempt is not None and bsd_all:
        near = min(abs(last_anchor_attempt - b) for b in bsd_all)
    return TLDiskProbeReport(
        buffer_len=len(data),
        hit_counts=dict(Counter(h.match_kind for h in raw_hits)),
        bsd_magic_offsets=bsd_show,
        chain_like_hits=sum(1 for h in raw_hits if h.match_kind in ("chain", "chain4")),
        anchors_tried=len(tried_anchors),
        bsd_window_search_tried=bsd_window_search_tried,
        global_bsd_chain_search_tried=global_bsd_chain_search_tried,
        mbr_a5_slice_fallback_attempted=mbr_a5_slice_fallback_attempted,
        last_anchor_offset=last_anchor_attempt,
        nearest_bsd_delta=near,
        last_error=repr(last_err) if last_err else None,
    )


def enumerate_tl_slices_from_bytes(
    data: bytes,
    *,
    anchor_offset: int | None = None,
    mbr_a5_slice_fallback: bool = True,
) -> TLDiskEnumerationResult:
    """
    Enumerate TL disklabel slices from a **tlpart-relative** byte buffer.

    If ``anchor_offset`` is ``None``, scans for ``chain`` / ``chain4`` hits (same as
    :func:`~opentl.tl_physical.scan_tl_disklabel_bytes`) and tries each candidate in
    printk-like order until :func:`_build_slices` succeeds — not only the first substring match.

    If that fails but ``bsd_magic`` hits exist, performs a bounded scan for chain5/chain4
    within :data:`_CHAIN_NEAR_BSD_HALF_WINDOW` bytes of each magic (disklabel-relative layout).

    If that still fails, scans the **whole buffer** for chain5/chain4 (hit caps apply) and tries
    anchors in order of increasing distance to the nearest ``bsd_magic`` (handles tuple blocks
    farther than the near window).

    When ``mbr_a5_slice_fallback`` is true (default) and the buffer begins with a PC MBR whose
    first primary **FreeBSD slice** (type ``0xA5``) has ``LBA_start * 512 > 0``, a final attempt
    scans from that byte offset (kernel ``msdos_partition`` → ``parse_freebsd`` analogue); see
    :mod:`opentl.tl_mbr_slice`.

    On failure (no usable anchor), emits forensic detail at :data:`logging.DEBUG` under
    ``opentl.tldisk`` (enable via ``OPENTL_DEBUG`` or ``OPENTL_LOG_LEVEL=DEBUG`` on the
    ``opentl`` logger; see :mod:`opentl.logutil`). When ``OPENTL_TLDISK_REPORT=1`` (or ``true`` /
    ``yes`` / ``on``), also emits one **INFO** JSON line on logger ``opentl.tldisk.probe`` with
    hit counts and anchor attempt summary.
    """
    warnings: list[str] = []
    notes: list[str] = []

    if anchor_offset is None:
        raw_hits = scan_tl_disklabel_bytes(data, max_hits=50)
        hits_ordered = sorted(
            (h for h in raw_hits if h.match_kind in ("chain", "chain4")),
            key=lambda h: (0 if h.match_kind == "chain" else 1, h.offset),
        )
        last_err: Exception | None = None
        tried_anchors: set[int] = set()
        last_anchor_attempt: int | None = None
        mbr_a5_fb_attempted = False
        for h in hits_ordered:
            tried_anchors.add(h.offset)
            try:
                slices_list, kind, log = _build_slices(data, h.offset)
            except ValueError as e:
                last_err = e
                last_anchor_attempt = h.offset
                continue
            anchor = h.offset
            notes.append(f"auto-selected anchor at {anchor:#x} (match_kind={h.match_kind})")
            anchor_kind = kind
            _validate_opentla4(slices_list, warnings)
            return TLDiskEnumerationResult(
                slices=slices_list,
                anchor_offset=anchor,
                anchor_kind=anchor_kind,
                warnings=warnings,
                notes=notes,
                enumerate_log=log,
            )

        bsd_window_tried = False
        global_bsd_chain_tried = False
        bsd_list = [h.offset for h in raw_hits if h.match_kind == "bsd_magic"]
        if bsd_list:
            bsd_window_tried = True
            for anchor in _anchors_near_bsd_magic_sorted(
                data,
                bsd_list,
                half_window=_CHAIN_NEAR_BSD_HALF_WINDOW,
                skip=tried_anchors,
            ):
                tried_anchors.add(anchor)
                try:
                    slices_list, kind, log = _build_slices(data, anchor)
                except ValueError as e:
                    last_err = e
                    last_anchor_attempt = anchor
                    continue
                notes.append(
                    f"auto-selected anchor at {anchor:#x} (chain near bsd_magic within "
                    f"±{_CHAIN_NEAR_BSD_HALF_WINDOW:#x})"
                )
                anchor_kind = kind
                _validate_opentla4(slices_list, warnings)
                return TLDiskEnumerationResult(
                    slices=slices_list,
                    anchor_offset=anchor,
                    anchor_kind=anchor_kind,
                    warnings=warnings,
                    notes=notes,
                    enumerate_log=log,
                )

            global_bsd_chain_tried = True
            global_anchors = _collect_global_chain_anchor_offsets(
                data,
                max_chain5=_GLOBAL_BSD_CHAIN_MAX_CHAIN5,
                max_chain4=_GLOBAL_BSD_CHAIN_MAX_CHAIN4,
            )
            for anchor in _sort_anchor_offsets_by_bsd_distance(global_anchors, bsd_list)[
                : _GLOBAL_BSD_CHAIN_TRY_CAP
            ]:
                if anchor in tried_anchors:
                    continue
                tried_anchors.add(anchor)
                try:
                    slices_list, kind, log = _build_slices(data, anchor)
                except ValueError as e:
                    last_err = e
                    last_anchor_attempt = anchor
                    continue
                notes.append(
                    f"auto-selected anchor at {anchor:#x} (full-buffer chain search ordered by "
                    "bsd_magic distance)"
                )
                anchor_kind = kind
                _validate_opentla4(slices_list, warnings)
                return TLDiskEnumerationResult(
                    slices=slices_list,
                    anchor_offset=anchor,
                    anchor_kind=anchor_kind,
                    warnings=warnings,
                    notes=notes,
                    enumerate_log=log,
                )

            sector_r = _try_enumerate_bsd_disklabel_sectors(data, bsd_list)
            if sector_r is not None:
                return sector_r

            scattered = _try_enumerate_scattered_bsd_partitions(data, bsd_list)
            if scattered is not None:
                return scattered

            printk_fb = _try_enumerate_printk_constants_near_bsd(data, bsd_list)
            if printk_fb is not None:
                return printk_fb

        if mbr_a5_slice_fallback:
            mb = mbr_first_a5_slice_byte_offset(data)
            if mb is not None and mb < len(data):
                mbr_a5_fb_attempted = True
                try:
                    inner_r = enumerate_tl_slices_from_bytes(
                        data[mb:],
                        anchor_offset=None,
                        mbr_a5_slice_fallback=False,
                    )
                    out_r = _shift_enumeration_slice_offsets(inner_r, mb)
                    notes_m = list(out_r.notes)
                    notes_m.insert(
                        0,
                        f"opentl: TL disklabel from MBR primary type 0xA5 slice at byte {mb:#x}",
                    )
                    return TLDiskEnumerationResult(
                        slices=out_r.slices,
                        anchor_offset=out_r.anchor_offset,
                        anchor_kind=out_r.anchor_kind,
                        warnings=list(inner_r.warnings),
                        notes=notes_m,
                        enumerate_log=list(inner_r.enumerate_log),
                    )
                except ValueError:
                    pass

        rp = _make_tl_probe_report_from_failure(
            data,
            raw_hits,
            tried_anchors=tried_anchors,
            bsd_window_search_tried=bsd_window_tried,
            global_bsd_chain_search_tried=global_bsd_chain_tried,
            mbr_a5_slice_fallback_attempted=mbr_a5_fb_attempted,
            last_anchor_attempt=last_anchor_attempt,
            last_err=last_err,
        )
        _emit_tl_disk_probe_report(rp)
        _log_tl_enumeration_failure_diagnostics(
            raw_hits,
            last_err=last_err,
            bsd_window_search_tried=bsd_window_tried,
            global_bsd_chain_search_tried=global_bsd_chain_tried,
        )
        if last_err is not None:
            raise ValueError("no TL disklabel chain5/chain4 pattern found in buffer") from last_err
        raise ValueError("no TL disklabel chain5/chain4 pattern found in buffer")

    anchor = anchor_offset
    slices_list, kind, log = _build_slices(data, anchor)
    anchor_kind = f"manual_{kind}"

    _validate_opentla4(slices_list, warnings)

    return TLDiskEnumerationResult(
        slices=slices_list,
        anchor_offset=anchor,
        anchor_kind=anchor_kind,
        warnings=warnings,
        notes=notes,
        enumerate_log=log,
    )


def _validate_opentla4(slices: tuple[TLDiskSlice, ...], warnings: list[str]) -> None:
    for s in slices:
        if s.name != "opentla4":
            continue
        if s.start_sector != OPENTLA4_START_SECTOR or s.num_sectors != OPENTLA4_NUM_SECTORS:
            warnings.append(
                f"opentla4 slice {(s.start_sector, s.num_sectors)} differs from "
                f"open_tl constants ({OPENTLA4_START_SECTOR}, {OPENTLA4_NUM_SECTORS})"
            )
        return
    warnings.append("no opentla4 slice in enumeration — cannot cross-check open_tl constants")


def enumerate_tl_slices(
    path: str | Path,
    *,
    anchor_offset: int | None = None,
    mbr_a5_slice_fallback: bool = True,
) -> TLDiskEnumerationResult:
    """
    Enumerate TL disklabel slices from a **tlpart-relative** file (or image whose start is tlpart).
    """
    p = Path(path)
    with p.open("rb") as f:
        data = f.read()
    r = enumerate_tl_slices_from_bytes(
        data,
        anchor_offset=anchor_offset,
        mbr_a5_slice_fallback=mbr_a5_slice_fallback,
    )
    if not r.notes:
        r.notes.append(f"source={p.resolve()}")
    else:
        r.notes.append(f"source={p.resolve()}")
    return r


def enumerate_tl_slices_auto_file(
    path: str | Path,
    *,
    max_hits: int = 8,
    mbr_a5_slice_fallback: bool = True,
) -> TLDiskEnumerationResult:
    """
    Scan a possibly **full logical-plane** file: same multi-hit strategy as
    :func:`enumerate_tl_slices_from_bytes` on the whole image.
    """
    p = Path(path)
    with p.open("rb") as f:
        data = f.read()
    r = enumerate_tl_slices_from_bytes(data, mbr_a5_slice_fallback=mbr_a5_slice_fallback)
    r.notes.append(f"source={p.resolve()}")
    return r


__all__ = [
    "TLDiskProbeReport",
    "TLDiskSlice",
    "TLDiskEnumerationResult",
    "TlpartTlEnumeration",
    "enumerate_tl_slices",
    "enumerate_tl_slices_from_bytes",
    "enumerate_tl_slices_from_tlpart_mtd_bytes",
    "enumerate_tl_slices_auto_file",
]
