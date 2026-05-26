"""
MTD partition table from mtdparts / printk ranges and mmap-backed slicing of flash dumps.
"""

from __future__ import annotations

import json
import mmap
import os
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

from uboot import get_mtdparts_token
from uboot.env import parse_uboot_env_v1

from unand.geometry import NandGeometry, PACE_DEFAULT, effective_mtd_reference_size
from unand.layout import RawDumpLayout, read_logical_plane_interval


def parse_flash_raw_layout_cli(s: str) -> RawDumpLayout:
    """CLI string → :class:`RawDumpLayout` for ``build_layout_interactive`` / carve flags."""
    k = s.strip().lower().replace("-", "_")
    table: dict[str, RawDumpLayout] = {
        "logical_only": RawDumpLayout.LOGICAL_ONLY,
        "inline_2048_64": RawDumpLayout.INLINE_2048_64,
        "flat_tail_2048_64": RawDumpLayout.FLAT_TAIL_2048_64,
    }
    if k not in table:
        raise ValueError(
            f"unknown flash raw layout {s!r}; expected one of: {', '.join(sorted(table))}"
        )
    return table[k]
from unand.mtd import MtdPart, parse_mtdparts

from opentl.mtd_scanner import (
    MtdFinding,
    MtdScanResult,
    MtdScanner,
    parse_mtdparts_value,
    parse_partition_range,
)
from opentl.tl_physical import TLPART_NAND_DATA_OFFSET_DEFAULT


@dataclass
class MtdPartition:
    index: int
    name: str
    offset: int
    size: int
    remainder: bool


@dataclass
class LayoutBuildResult:
    partitions: List[MtdPartition]
    warnings: List[str] = field(default_factory=list)


def _normalize_mtdparts_input(
    parsed_or_string: Union[str, bytes, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if isinstance(parsed_or_string, dict):
        return parsed_or_string
    if isinstance(parsed_or_string, bytes):
        text = parsed_or_string.decode("ascii", errors="replace")
    else:
        text = parsed_or_string
    tok = get_mtdparts_token(text)
    if tok:
        parsed = parse_mtdparts_value(tok.encode("ascii", errors="replace"))
        if parsed and parsed.get("partitions"):
            return parsed
    raw = parsed_or_string
    if isinstance(raw, str):
        raw = raw.encode("ascii", errors="replace")
    return parse_mtdparts_value(raw)


# Typical U-Boot CONFIG_ENV_SIZE candidates (image length including 4-byte CRC).
UBOOT_ENV_IMAGE_SIZES: Tuple[int, ...] = (
    0x2000,
    0x4000,
    0x8000,
    0x10000,
    0x20000,
    0x40000,
    0x80000,
)

# First OpenTL env slice in TL BSD disklabel (`parse_bsd` printk): start sector 8, 512 B/sector.
TL_DISKLABEL_ENV_START_BYTES = 8 * 512


def build_partitions_from_mtdparts(
    parsed_or_string: Union[str, bytes, Dict[str, Any]],
    *,
    image_size: int,
) -> LayoutBuildResult:
    """
    Lay out partitions sequentially from offset 0. The last ``-(name)`` entry fills
    ``image_size - offset`` (remainder).
    """
    warnings: List[str] = []
    parsed = _normalize_mtdparts_input(parsed_or_string)
    if not parsed or not parsed.get("partitions"):
        raise ValueError("invalid or empty mtdparts")

    specs = parsed["partitions"]
    remainder_count = sum(1 for p in specs if p.get("remainder"))
    if remainder_count > 1:
        raise ValueError("mtdparts has more than one remainder partition")
    if remainder_count == 1 and not specs[-1].get("remainder"):
        raise ValueError("remainder partition must be last in mtdparts")

    line = mtdparts_parsed_to_cmdline(parsed)
    unand_parts: tuple[MtdPart, ...] | None
    try:
        unand_parts = parse_mtdparts(line, logical_total=image_size)
    except ValueError as e:
        msg = str(e)
        if remainder_count == 1 and (
            "remainder negative" in msg or "exceed logical_total" in msg.lower()
        ):
            fixed_end = sum(
                int(s["size_bytes"])
                for s in specs
                if not s.get("remainder") and s.get("size_bytes") is not None
            )
            raise ValueError(
                f"image_size {image_size} too small for fixed partitions ending at {fixed_end}"
            ) from e
        unand_parts = None

    if unand_parts is not None and len(unand_parts) == len(specs):
        out_un: List[MtdPartition] = [
            MtdPartition(
                index=i,
                name=p.name,
                offset=p.offset,
                size=p.size,
                remainder=bool(specs[i].get("remainder")),
            )
            for i, p in enumerate(unand_parts)
        ]
        if out_un[-1].remainder and out_un[-1].size == 0:
            warnings.append(f"remainder partition {out_un[-1].name!r} has size 0")
        offset_end = out_un[-1].offset + out_un[-1].size
        if remainder_count == 0 and offset_end != image_size:
            if offset_end > image_size:
                raise ValueError(
                    f"sum of partition sizes {offset_end} exceeds image_size {image_size}"
                )
            warnings.append(
                f"fixed partitions sum to {offset_end}, image_size is {image_size} (gap or mismatch)"
            )
        _validate_contiguous(out_un, image_size, warnings)
        return LayoutBuildResult(partitions=out_un, warnings=warnings)

    out: List[MtdPartition] = []
    offset = 0
    for i, spec in enumerate(specs):
        name = str(spec.get("name", "?"))
        if spec.get("remainder"):
            size = image_size - offset
            if size < 0:
                raise ValueError(
                    f"image_size {image_size} too small for fixed partitions ending at {offset}"
                )
            if size == 0:
                warnings.append(f"remainder partition {name!r} has size 0")
            out.append(
                MtdPartition(
                    index=i, name=name, offset=offset, size=size, remainder=True
                )
            )
            offset += size
            break

        sz = spec.get("size_bytes")
        if sz is None:
            raise ValueError(f"partition {name!r} has no size")
        out.append(
            MtdPartition(
                index=i, name=name, offset=offset, size=int(sz), remainder=False
            )
        )
        offset += int(sz)

    if offset != image_size:
        # Fixed-only layout: must fit exactly; remainder layout: already matched
        if remainder_count == 0:
            if offset > image_size:
                raise ValueError(
                    f"sum of partition sizes {offset} exceeds image_size {image_size}"
                )
            warnings.append(
                f"fixed partitions sum to {offset}, image_size is {image_size} (gap or mismatch)"
            )

    _validate_contiguous(out, image_size, warnings)
    return LayoutBuildResult(partitions=out, warnings=warnings)


def _validate_contiguous(
    parts: List[MtdPartition], image_size: int, warnings: List[str]
) -> None:
    if not parts:
        return
    if parts[0].offset != 0:
        warnings.append(f"first partition offset is {parts[0].offset}, expected 0")
    for a, b in zip(parts, parts[1:]):
        if a.offset + a.size != b.offset:
            warnings.append(
                f"gap or overlap between {a.name!r} end {a.offset + a.size} "
                f"and {b.name!r} start {b.offset}"
            )
    last = parts[-1]
    end = last.offset + last.size
    if end != image_size:
        warnings.append(
            f"last partition ends at {end}, image_size is {image_size} "
            f"(partial dump or layout mismatch)"
        )


def merge_printk_ranges(
    findings: Sequence[MtdFinding],
) -> List[Dict[str, Any]]:
    """
    Dedupe kernel printk partition ranges ``0x....-0x.... : "name"``.
    """
    seen: set = set()
    merged: List[Dict[str, Any]] = []
    for f in findings:
        if f.kind != "partition_range_printk":
            continue
        p = f.parsed if isinstance(f.parsed, dict) else None
        if not p:
            raw = f.text.encode("ascii", errors="replace")
            p = parse_partition_range(raw)
        if not p:
            continue
        key = (p.get("start"), p.get("end"), p.get("name"))
        if key in seen:
            continue
        seen.add(key)
        merged.append(p)
    merged.sort(key=lambda x: (x.get("start", 0), x.get("name", "")))
    return merged


def validate_against_printk_ranges(
    partitions: Sequence[MtdPartition],
    printk_ranges: Sequence[Dict[str, Any]],
) -> List[str]:
    """Return warning strings for name/offset/size mismatches vs printk lines."""
    issues: List[str] = []
    by_name = {p.name: p for p in partitions}
    for pr in printk_ranges:
        name = pr.get("name")
        if name not in by_name:
            continue
        p = by_name[name]
        if pr.get("start") != p.offset:
            issues.append(
                f'printk range start for "{name}" is {pr.get("start")}, '
                f"mtdparts layout has {p.offset}"
            )
        exp_len = pr.get("length")
        if exp_len is not None and exp_len != p.size:
            issues.append(
                f'printk length for "{name}" is {exp_len}, mtdparts layout has size {p.size}'
            )
    return issues


def select_mtdparts_parsed(scan: MtdScanResult, *, image_size: int) -> Dict[str, Any]:
    """
    Choose one mtdparts table from an MTD scan: tables must lay out cleanly against
    ``image_size`` (rejects corrupted strings with duplicate ``-(…)`` remainders, etc.),
    then prefer loader/mtdoops/tlpart and more segments.
    """
    candidates = list(scan.mtdparts_parsed)
    if not candidates:
        raise ValueError("no mtdparts tables found in scan; pass --mtdparts explicitly")

    viable: List[Dict[str, Any]] = []
    for d in candidates:
        try:
            build_partitions_from_mtdparts(d, image_size=image_size)
            viable.append(d)
        except ValueError:
            continue

    if not viable:
        raise ValueError(
            "no mtdparts table in scan lays out cleanly for this image size; "
            "pass --mtdparts explicitly (e.g. mtd-0:524288(loader),1048576(mtdoops),-(tlpart))"
        )

    def score(d: Dict[str, Any]) -> Tuple[int, int]:
        parts = d.get("partitions") or []
        names = {str(p.get("name", "")) for p in parts}
        bonus = 0
        if {"loader", "mtdoops", "tlpart"}.issubset(names):
            bonus = 100
        return (bonus + len(parts), len(parts))

    viable.sort(key=score, reverse=True)
    return viable[0]


def try_mtdparts_from_uboot_env(
    flash_path: str,
    *,
    ref_size: int,
    geom: NandGeometry = PACE_DEFAULT,
    layout: RawDumpLayout,
) -> Optional[Tuple[Dict[str, Any], str, List[str]]]:
    """
    Read fixed-size U-Boot env v1 candidates on the logical plane, verify CRC, extract
    ``mtdparts``, and validate layout against ``ref_size``.

    ``layout`` must describe how ``flash_path`` packs main vs spare (``LOGICAL_ONLY``,
    ``INLINE_2048_64``, or ``FLAT_TAIL_2048_64``). There is no inference here — use
    ``python -m unand layout-detect`` when unsure.

    Probes (in order): logical start of **loader** (0); OpenTL **disklabel env** slice
    at ``TLPART_NAND_DATA_OFFSET_DEFAULT + TL_DISKLABEL_ENV_START_BYTES`` (heuristic when
    ``tlpart`` matches default ``mtdparts`` placement).

    Returns ``(parsed_dict, display_token, notes)`` or ``None``.
    """

    tlpart_env_base = TLPART_NAND_DATA_OFFSET_DEFAULT + TL_DISKLABEL_ENV_START_BYTES
    bases: List[Tuple[int, str]] = [
        (0, "loader"),
        (tlpart_env_base, "tlpart-disklabel-env"),
    ]
    for base, label in bases:
        if base < 0 or base >= geom.logical_bytes:
            continue
        for sz in UBOOT_ENV_IMAGE_SIZES:
            if base + sz > geom.logical_bytes:
                continue
            try:
                blob = read_logical_plane_interval(
                    flash_path, base, sz, layout=layout, geom=geom
                )
            except ValueError:
                continue
            r = parse_uboot_env_v1(blob, crc_endian="auto")
            if not r.crc_ok or not r.mtdparts_token:
                continue
            parsed = _normalize_mtdparts_input(r.mtdparts_token)
            if not parsed:
                continue
            try:
                build_partitions_from_mtdparts(parsed, image_size=ref_size)
            except ValueError:
                continue
            line = r.mtdparts_token.strip()
            notes = [
                f"U-Boot env v1 at {label} logical {base:#x} size {sz:#x}; "
                f"CRC endian {r.crc_endian!r}"
            ]
            return parsed, line, notes
    return None


def mtdparts_parsed_to_cmdline(parsed: Dict[str, Any]) -> str:
    """Reconstruct ``mtdparts=mtd-0:...`` for display / JSON."""
    mtd_id = parsed.get("mtd_id") or "mtd-0"
    specs = parsed.get("partitions") or []
    chunks: List[str] = []
    for s in specs:
        if s.get("remainder"):
            chunks.append(f"-({s.get('name')})")
        else:
            chunks.append(f"{s['size_bytes']}({s['name']})")
    return f"mtdparts={mtd_id}:{','.join(chunks)}"


@dataclass
class FlashImage:
    """
    Read-only view of a flash file sliced by MTD partition names.

    Offsets are **linear file byte offsets** (same as logical MTD offsets on a
    **LOGICAL_ONLY** or already-normalized image). Raw **INLINE_2048_64** full-chip files
    still require a logical-plane normalize step before extraction via this class.

    When ``logical_image`` is set, reads use that in-memory buffer instead of ``path``
    (``path`` is still used for display / manifests).
    """

    path: str
    partitions: List[MtdPartition]
    logical_image: Optional[bytes] = None

    def __post_init__(self) -> None:
        if self.logical_image is not None:
            self.size = len(self.logical_image)
        else:
            self.size = os.path.getsize(self.path)

    def _by_name(self, name: str) -> MtdPartition:
        for p in self.partitions:
            if p.name == name:
                return p
        raise KeyError(f"no partition named {name!r}")

    def slice_bytes(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        if offset + length > self.size:
            raise ValueError(
                f"read [{offset:#x}, {offset + length:#x}) exceeds file size {self.size}"
            )
        if self.logical_image is not None:
            mv = memoryview(self.logical_image)
            return bytes(mv[offset : offset + length])
        with open(self.path, "rb") as f:
            f.seek(offset)
            return f.read(length)

    def read_partition(self, name: str) -> bytes:
        p = self._by_name(name)
        return self.slice_bytes(p.offset, p.size)

    def extract_partition(self, name: str, out_path: str) -> None:
        data = self.read_partition(name)
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "wb") as out:
            out.write(data)

    @contextmanager
    def mmap_open(self) -> Iterator[mmap.mmap]:
        if self.logical_image is not None:
            raise NotImplementedError("FlashImage.mmap_open requires an on-disk path (no logical_image)")
        with open(self.path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                yield mm
            finally:
                mm.close()


def safe_extract_filename(name: str) -> str:
    """Filesystem-safe stem for a partition name."""
    s = re.sub(r"[^\w.\-]+", "_", name.strip())
    return s or "partition"


def write_partition_manifest(
    flash_path: str,
    image_size: int,
    mtdparts_line: str,
    partitions: Sequence[MtdPartition],
    out_json_path: str,
    *,
    opentl_pipeline: Optional[Dict[str, Any]] = None,
    layout_source: Optional[str] = None,
    layout_notes: Optional[Sequence[str]] = None,
) -> None:
    payload: Dict[str, Any] = {
        "flash_file": os.path.abspath(flash_path),
        "image_size": image_size,
        "mtdparts": mtdparts_line,
        "partitions": [
            {
                "index": p.index,
                "name": p.name,
                "offset": p.offset,
                "offset_hex": f"{p.offset:#x}",
                "size": p.size,
                "size_hex": f"{p.size:#x}",
                "remainder": p.remainder,
                "end": p.offset + p.size,
                "end_hex": f"{p.offset + p.size:#x}",
            }
            for p in partitions
        ],
    }
    if opentl_pipeline is not None:
        payload["opentl_pipeline"] = opentl_pipeline
    if layout_source is not None:
        payload["layout_source"] = layout_source
    if layout_notes:
        payload["layout_notes"] = list(layout_notes)
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def build_layout_interactive(
    flash_path: str,
    *,
    mtdparts: Optional[str] = None,
    geom: NandGeometry = PACE_DEFAULT,
    flash_raw_layout: RawDumpLayout = RawDumpLayout.LOGICAL_ONLY,
) -> Tuple[LayoutBuildResult, Dict[str, Any], str, Optional[MtdScanResult], Dict[str, Any]]:
    """
    Resolve MTD layout from ``--mtdparts``, U-Boot env v1 on the logical plane, or
    :class:`MtdScanner` on ``flash_path``.

    ``flash_raw_layout`` selects how env blobs are read from ``flash_path`` when the
    U-Boot env path runs (``LOGICAL_ONLY`` for a 128 MiB logical image; ``INLINE_2048_64``
    / ``FLAT_TAIL_2048_64`` for full-chip physical dumps — no auto-detection).

    Returns ``(layout_result, parsed_dict, mtdparts_display_line, scan_or_none, meta)``.
    ``meta`` has keys ``source`` (``explicit`` | ``uboot-env`` | ``mtd-scan``) and
    ``notes`` (list of str). ``scan_or_none`` is set when layout came from an MTD string
    scan (printk validation); it is ``None`` for explicit or env-derived layout.

    ``FlashImage`` / remainder sizing use :func:`effective_mtd_reference_size` so Pace
    full-chip envelopes map to the logical MTD plane length.
    """
    file_size = os.path.getsize(flash_path)
    ref_size = effective_mtd_reference_size(file_size, geom=geom)
    parsed: Optional[Dict[str, Any]] = None
    line = ""
    scan: Optional[MtdScanResult] = None
    meta: Dict[str, Any] = {"source": "mtd-scan", "notes": []}

    if mtdparts:
        meta["source"] = "explicit"
        parsed = _normalize_mtdparts_input(mtdparts)
        if not parsed:
            raise ValueError("could not parse --mtdparts")
        line = mtdparts.strip()
        if not line.startswith("mtdparts="):
            line = mtdparts_parsed_to_cmdline(parsed)
    else:
        env_hit = try_mtdparts_from_uboot_env(
            flash_path, ref_size=ref_size, geom=geom, layout=flash_raw_layout
        )
        if env_hit is not None:
            parsed, line, env_notes = env_hit
            meta["source"] = "uboot-env"
            meta["notes"] = list(env_notes)
            scan = None
        else:
            scanner = MtdScanner()
            scan = scanner.scan(flash_path)
            parsed = select_mtdparts_parsed(scan, image_size=ref_size)
            line = mtdparts_parsed_to_cmdline(parsed)
            meta["source"] = "mtd-scan"

    assert parsed is not None
    layout = build_partitions_from_mtdparts(parsed, image_size=ref_size)
    return layout, parsed, line, scan, meta


def format_partition_table(partitions: Sequence[MtdPartition]) -> str:
    lines = [
        f"{'#':>3}  {'name':<12}  {'start_hex':>14}  {'end_hex':>14}  {'size':>12}  {'size_hex':>12}",
        "-" * 72,
    ]
    for p in partitions:
        end = p.offset + p.size
        lines.append(
            f"{p.index:>3}  {p.name:<12}  {p.offset:#016x}  {end:#016x}  "
            f"{p.size:>12}  {p.size:#012x}"
        )
    return "\n".join(lines)
