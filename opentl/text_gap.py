"""
Scan NAND / flash dumps for printable runs interrupted by binary gaps; histogram gap lengths
and modulo residuals vs candidate strides (512 / 2048 / 2112 / 128KiB).

Schema id for JSON output: :data:`TEXT_GAP_SCHEMA_V1` (historical on-disk string; see module constant).
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Optional

# Historical ``schema`` field value for text-gap JSON reports.
TEXT_GAP_SCHEMA_V1 = "opentl_tl_text_gap_v1"

# Syslog-like prefix (RFC3164-ish month day time)
_SYSLOG_MONTH = rb"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
# RFC3164-style: "Feb 10 10:57:08 hostname …" (no year); avoid requiring a 4-digit year.
RE_SYSLOG_ANCHOR = re.compile(
    _SYSLOG_MONTH + rb"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S",
    re.MULTILINE,
)
RE_DMESG_BRACKET = re.compile(rb"\[\s*\d+\.\d+\]")
RE_FW_MAC_LINE = re.compile(
    rb"SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+DST=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.MULTILINE,
)

DEFAULT_LOGICAL_PREFIX = 128 * 1024 * 1024
DEFAULT_STRIDES = (512, 2048, 2112, 4096, 131072)


def is_printable_byte(b: int) -> bool:
    return (0x20 <= b <= 0x7E) or b in (0x09, 0x0A, 0x0B, 0x0C, 0x0D)


def classify_printable_runs(buf: bytes) -> tuple[list[tuple[int, int]], list[int]]:
    """
    Return (list of (start, end) exclusive-end printable runs, list of gap lengths between runs).
    Ignores leading/trailing non-printable as gaps only between runs.
    """
    n = len(buf)
    if n == 0:
        return [], []

    runs: list[tuple[int, int]] = []
    gaps: list[int] = []

    i = 0
    while i < n:
        while i < n and not is_printable_byte(buf[i]):
            i += 1
        if i >= n:
            break
        start = i
        i += 1
        while i < n and is_printable_byte(buf[i]):
            i += 1
        runs.append((start, i))
        # gap until next printable start
        gap_start = i
        while i < n and not is_printable_byte(buf[i]):
            i += 1
        if i > gap_start:
            gaps.append(i - gap_start)

    return runs, gaps


def _histogram_modulo(values: Iterable[int], strides: tuple[int, ...]) -> dict[str, dict[int, int]]:
    out: dict[str, dict[int, int]] = {}
    for s in strides:
        ctr: Counter[int] = Counter()
        for v in values:
            ctr[v % s] += 1
        # JSON keys must be strings for portability
        out[str(s)] = dict(sorted(ctr.items()))
    return out


def _gap_histogram(gaps: list[int], *, max_bucket: int = 65536) -> dict[str, int]:
    """Raw gap length counts for lengths <= max_bucket; overflow in '__overflow__'."""
    ctr: Counter[str] = Counter()
    for g in gaps:
        if g <= max_bucket:
            ctr[str(g)] += 1
        else:
            ctr["__overflow__"] += 1

    def _sort_key(kv: tuple[str, int]) -> tuple[int, int]:
        k, _ = kv
        if k == "__overflow__":
            return (2, 0)
        return (0, int(k))

    return dict(sorted(ctr.items(), key=_sort_key))


def _find_split_mac_candidates(buf: bytes, runs: list[tuple[int, int]], max_samples: int = 100) -> list[dict[str, Any]]:
    """
    Detect firewall-style lines split by a binary gap: tail before gap looks like MAC= partial,
    head after gap continues with colon-hex then SRC=.
    """
    samples: list[dict[str, Any]] = []
    # Iterate gaps implied by consecutive runs
    for i in range(len(runs) - 1):
        if len(samples) >= max_samples:
            break
        (_, end_a) = runs[i]
        (start_b, _) = runs[i + 1]
        gap_len = start_b - end_a
        if gap_len < 4 or gap_len > 262144:
            continue
        tail = buf[max(0, end_a - 96) : end_a].decode("latin-1", errors="replace")
        head = buf[start_b : min(len(buf), start_b + 160)].decode("latin-1", errors="replace")
        if "MAC=" not in tail or "SRC=" not in head:
            continue
        head_stripped = head.lstrip()
        # Continuation after gap: hex octets then SRC/DST (firewall log line)
        if not re.match(r"^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:", head_stripped[:18]):
            continue
        after_mac = tail.rsplit("MAC=", 1)[-1]
        # Broken line: MAC field interrupted — tail after MAC= is incomplete (no 5 colons before gap)
        octets_before = after_mac.count(":")
        if octets_before >= 5:
            continue
        mods = {str(s): gap_len % s for s in DEFAULT_STRIDES}
        samples.append(
            {
                "gap_start_offset": end_a,
                "gap_end_offset": start_b,
                "gap_length": gap_len,
                "gap_length_hex": hex(gap_len),
                "gap_mod_stride": mods,
                "tail_preview": tail[-72:].replace("\n", "\\n"),
                "head_preview": head[:120].replace("\n", "\\n"),
            }
        )
    return samples


def _dst_pair_deltas(buf: bytes, max_pairs: int = 500) -> list[dict[str, Any]]:
    """Repeated DST= same IP: deltas between match offsets (same-layer duplicates / splits)."""
    matches = list(RE_FW_MAC_LINE.finditer(buf))
    out: list[dict[str, Any]] = []
    by_dst: dict[str, list[int]] = {}
    for m in matches:
        dst = m.group(2).decode("ascii", errors="replace")
        by_dst.setdefault(dst, []).append(m.start())
    for dst, offs in by_dst.items():
        offs.sort()
        for i in range(len(offs) - 1):
            if len(out) >= max_pairs:
                return out
            dlt = offs[i + 1] - offs[i]
            if dlt < 16:
                continue
            out.append(
                {
                    "dst_ip": dst,
                    "delta": dlt,
                    "delta_hex": hex(dlt),
                    "mod_stride": {str(s): dlt % s for s in DEFAULT_STRIDES},
                    "first_offset": offs[i],
                    "second_offset": offs[i + 1],
                }
            )
    return out


def analyze_text_gap_file(
    image_path: str | Path,
    *,
    logical_prefix_bytes: Optional[int] = None,
    strides: tuple[int, ...] = DEFAULT_STRIDES,
    syslog_samples: int = 80,
    dmesg_samples: int = 40,
    min_gap_bytes: int = 16,
) -> dict[str, Any]:
    """
    Read logical prefix, classify printable runs / gaps, anchor syslog/dmesg hits,
    emit a dict whose ``schema`` is :data:`TEXT_GAP_SCHEMA_V1`.
    """
    path = Path(image_path)
    size = path.stat().st_size
    lim = logical_prefix_bytes if logical_prefix_bytes is not None else min(size, DEFAULT_LOGICAL_PREFIX)
    lim = min(lim, size)

    with path.open("rb") as f:
        buf = f.read(lim)

    runs, gaps = classify_printable_runs(buf)
    gaps_stride = [g for g in gaps if g >= min_gap_bytes]
    gap_mod_histogram = _histogram_modulo(gaps_stride, strides)
    gap_raw_top = Counter(gaps_stride).most_common(40)

    syslog_matches = list(RE_SYSLOG_ANCHOR.finditer(buf))
    dmesg_matches = list(RE_DMESG_BRACKET.finditer(buf))

    syslog_offsets = [
        {
            "offset": m.start(),
            "offset_hex": hex(m.start()),
            "preview": m.group()[:64].decode("latin-1", errors="replace"),
        }
        for m in syslog_matches[:syslog_samples]
    ]
    dmesg_offsets = [
        {
            "offset": m.start(),
            "offset_hex": hex(m.start()),
            "preview": m.group()[:32].decode("latin-1", errors="replace"),
        }
        for m in dmesg_matches[:dmesg_samples]
    ]

    split_candidates = _find_split_mac_candidates(buf, runs)
    dst_pairs = _dst_pair_deltas(buf)

    layout_note: Optional[dict[str, Any]] = None
    try:
        from opentl.tl_physical import analyze_tl_layout, layout_result_as_dict

        layout = analyze_tl_layout(str(path), elf_offset=0x21000, hsqs_offset=None, logical_data_end=None)
        layout_note = layout_result_as_dict(layout)
    except Exception as e:
        layout_note = {"error": str(e)}

    cross_check = _cross_check_vs_geometry(layout_note, gap_mod_histogram, strides, min_gap_bytes=min_gap_bytes)

    return {
        "schema": TEXT_GAP_SCHEMA_V1,
        "source_path": str(path.resolve()),
        "logical_prefix_bytes": lim,
        "min_gap_bytes_for_stride_analysis": min_gap_bytes,
        "printable_run_count": len(runs),
        "gap_count_all": len(gaps),
        "gap_count_stride_filtered": len(gaps_stride),
        "gap_length_top40": [{"length": a, "count": b} for a, b in gap_raw_top],
        "gap_length_histogram_small": _gap_histogram(gaps_stride, max_bucket=65536),
        "gap_modulo_histogram": gap_mod_histogram,
        "strides_used": list(strides),
        "syslog_anchor_count": len(syslog_matches),
        "syslog_anchor_samples": syslog_offsets,
        "dmesg_bracket_count": len(dmesg_matches),
        "dmesg_bracket_samples": dmesg_offsets,
        "split_mac_gap_candidates": split_candidates,
        "dst_repeat_deltas": dst_pairs[:200],
        "tl_layout_detect": layout_note,
        "geometry_cross_check": cross_check,
    }


def _cross_check_vs_geometry(
    layout_dict: Optional[dict[str, Any]],
    gap_mod_hist: dict[str, dict[int, int]],
    strides: tuple[int, ...],
    *,
    min_gap_bytes: int,
) -> dict[str, Any]:
    """Compare dominant gap residues with tl-layout-detect recommendation and OpenTL page size."""
    out: dict[str, Any] = {
        "open_tl_page_bytes": 2048,
        "erase_bytes": 131072,
        "min_gap_bytes_for_stride_analysis": min_gap_bytes,
        "interpretation_notes": [],
    }
    if layout_dict and "error" not in layout_dict:
        out["layout_recommendation"] = layout_dict.get("recommendation")
        out["layout_flat_logical_end"] = layout_dict.get("recommended_logical_data_end")
        out["layout_interleaved_ruled_out"] = layout_dict.get("interleaved_page_stride_ruled_out")

    # Pick modal residue for 2048 from gap_mod_histogram
    mod2048 = gap_mod_hist.get("2048") or {}
    if mod2048:
        best_res, best_cnt = max(mod2048.items(), key=lambda kv: kv[1])
        out["modal_gap_mod_2048"] = {"residue": best_res, "count": best_cnt}
        if best_res == 0:
            out["interpretation_notes"].append(
                "Most gap lengths are multiples of 2048 — consistent with OpenTL 2048-byte page boundaries in logical space."
            )
        else:
            out["interpretation_notes"].append(
                f"Dominant gap length mod 2048 is {best_res} (not 0); interruptions may include sector alignment, metadata, or mixed volumes."
            )

    mod2112 = gap_mod_hist.get("2112") or {}
    if mod2112:
        br, bc = max(mod2112.items(), key=lambda kv: kv[1])
        out["modal_gap_mod_2112"] = {"residue": br, "count": bc}
        top2048 = max(mod2048.values()) if mod2048 else 0
        if br == 0 and bc >= top2048 and bc > 10:
            out["interpretation_notes"].append(
                "Strong 2112-byte periodicity would suggest interleaved 2048+64 OOB in that region — reconcile with tl-layout-detect flat model."
            )

    return out


def write_text_gap_json(data: dict[str, Any], path: str | Path) -> None:
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
