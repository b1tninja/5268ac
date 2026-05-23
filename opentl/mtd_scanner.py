#!/usr/bin/env python3
"""
Scan flash dumps or strings files for MTD-related strings: mtdparts,
kernel-printed partition ranges, bcmnand/tldisk hints, UBI printk lines.

Uses mmap like FlashScanner for large inputs.
"""

from __future__ import annotations

import mmap
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# Max stored hits per regex kind after dedupe (mirrored flash copies).
DEFAULT_MAX_PER_KIND = 128


def _ascii_safe(s: Optional[str]) -> str:
    """Safe for dumb Windows consoles (cp1252): drop non-Latin-1 extras."""
    if s is None:
        return "?"
    return "".join(c if ord(c) < 128 else "?" for c in str(s))


def _ascii_display(data: bytes, max_len: int = 500) -> str:
    """Decode fragment for printing; truncate long blobs."""
    s = data.decode("ascii", errors="replace").strip()
    s = "".join(c if ord(c) < 128 else "?" for c in s)
    s = re.sub(r"\s+", " ", s)
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


@dataclass
class MtdFinding:
    kind: str
    offset: int
    text: str
    parsed: Optional[Dict[str, Any]] = None


@dataclass
class MtdScanResult:
    """Container returned by MtdScanner.scan()."""

    findings: List[MtdFinding] = field(default_factory=list)
    mtdparts_parsed: List[Dict[str, Any]] = field(default_factory=list)
    bcmnand_geometry_parsed: List[Dict[str, Any]] = field(default_factory=list)


def parse_mtdparts_value(value: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse a mtdparts blob (may include leading 'mtdparts=').

    Expected form: mtd-id:524288(name),...(restname)
    Sizes are decimal bytes; '-' means remainder of device.
    """
    if not isinstance(value, (bytes, bytearray)):
        return None
    s = bytes(value).decode("ascii", errors="replace").strip()

    if s.startswith("mtdparts="):
        s = s[9:]
    idx = s.find(":")
    if idx < 0:
        return None

    mtd_id = s[:idx].strip()
    rest = s[idx + 1 :]

    partitions: List[Dict[str, Any]] = []

    pat = re.compile(r"-\(([^)]+)\)|(\d+)\(([^)]+)\)")
    # Also allow @offset in specs (best-effort — capture extra as raw_tail)
    for m in pat.finditer(rest):
        if m.group(1) is not None:
            partitions.append(
                {"name": m.group(1), "sizespec": "-", "size_bytes": None, "remainder": True}
            )
        else:
            partitions.append(
                {
                    "name": m.group(3),
                    "sizespec": m.group(2),
                    "size_bytes": int(m.group(2)),
                    "remainder": False,
                }
            )

    if not partitions:
        return {"mtd_id": mtd_id, "partitions": [], "raw_tail": rest}

    return {"mtd_id": mtd_id, "partitions": partitions}


def parse_partition_range(text: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse printk line 0x....-0x.... : \"name\".
    """
    m = re.match(
        rb'\s*(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)\s*:\s*"([^"]+)"',
        text.strip(),
    )
    if not m:
        return None
    start = int(m.group(1), 16)
    end = int(m.group(2), 16)
    name = m.group(3).decode("ascii", errors="replace")
    return {
        "name": name,
        "start_hex": m.group(1).decode(),
        "end_hex": m.group(2).decode(),
        "start": start,
        "end": end,
        "length": end - start,
    }


def parse_cmdline_mt_line(text: bytes) -> Optional[Dict[str, Any]]:
    """Kernel lines: Creating N MTD partitions on \"mtd-X\"."""
    m = re.search(
        rb'Creating\s+(\d+)\s+MTD\s+partitions\s+on\s+"([^"]+)"', text
    )
    if not m:
        return None
    return {"count": int(m.group(1)), "mtd_id": m.group(2).decode("ascii", errors="replace")}


def parse_mtd_partition_offset_line(text: bytes) -> Optional[Dict[str, Any]]:
    """BCM-style: MTD partition(n) offset=0 size=N num=…"""
    m = re.search(
        rb'MTD\s+partition\s*\(\s*(\d+)\s*\)\s+offset\s*=\s*(\d+)\s+size\s*=\s*(\d+)',
        text,
        re.I,
    )
    if not m:
        return None
    return {
        "index": int(m.group(1)),
        "offset": int(m.group(2)),
        "size": int(m.group(3)),
    }


# Expanded printk BCMNAND: size=128MB, block=128KB, page=2048B, spare=64 (5268-class dumps).
BCMNAND_GEOMETRY_BYTES = (
    rb"BCMNAND:\s*size\s*=\s*(\d+)\s*"
    rb"(MB|MiB|MIB|GB|GiB|GIB)"
    rb"\s*,\s*block\s*=\s*(\d+)\s*"
    rb"(KB|KiB|KIB|MB|MiB|MIB)"
    rb"\s*,\s*page\s*=\s*(\d+)\s*B"
    rb"\s*,\s*spare\s*=\s*(\d+)"
)
_BCMNAND_GEOMETRY_RE = re.compile(BCMNAND_GEOMETRY_BYTES, re.I)


def _chip_capacity_mib(size_n: int, size_unit_upper: str) -> float:
    """Best-effort chip capacity in MiB from printk size=… units."""
    u = size_unit_upper.strip().upper()
    if u.startswith("G"):
        return float(size_n) * 1024.0
    return float(size_n)


def _erase_bytes(block_n: int, block_unit_raw: str) -> Tuple[int, str]:
    u = block_unit_raw.strip().upper()
    if u.startswith("M"):
        eb = block_n * (1024 * 1024)
        return eb, f"{block_n} MiB erase block ({eb} bytes)"
    eb = block_n * 1024
    return eb, f"{block_n} KiB erase block ({eb} bytes)"


def parse_bcmnand_geometry(frag: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse BCM NAND geometry printk (vendor brcmnand style).

    Typical: BCMNAND: size=128MB, block=128KB, page=2048B, spare=64

    Adds normalized hints for mtd-utils / image tooling comparisons.
    """
    m = _BCMNAND_GEOMETRY_RE.search(frag)
    if not m:
        return None

    sz_n = int(m.group(1))
    sz_unit = m.group(2).decode("ascii", errors="replace").strip()
    sz_u = sz_unit.upper()

    bk_n = int(m.group(3))
    bk_unit = m.group(4).decode("ascii", errors="replace")

    pg = int(m.group(5))
    spare = int(m.group(6))

    mib = _chip_capacity_mib(sz_n, sz_u)
    eb_bytes, eb_human = _erase_bytes(bk_n, bk_unit)

    raw = m.group(0).decode("ascii", errors="replace").strip()

    return {
        "raw": raw,
        "chip_capacity_mib": round(mib, 9),
        "chip_capacity_human": f"~{mib:g} MiB - raw size={sz_n}{sz_unit.strip()}",
        "erase_block_bytes": eb_bytes,
        "erase_block_human": eb_human,
        "page_bytes": pg,
        "oob_spare_bytes": spare,
    }


# (kind, compiled_bytes_regex, description for docs)
_REGEX_SPECS: List[Tuple[str, bytes]] = [
    (
        "mtdparts_token",
        rb"mtdparts=[^\x00-\x08\x0b\x0c\x0e-\x1f]{20,768}",
    ),
    (
        "mtdids",
        rb"mtdids=[^\x00-\x08\x0b\x0c\x0e-\x1f]{5,512}",
    ),
    (
        "mtdoops_console",
        rb"mtdoops\.mtddev[^\x00-\x1f]{0,200}",
    ),
    (
        "mtdoops_record",
        rb"mtdoops\.record_size[^\x00-\x1f]{0,160}",
    ),
    ("ubi_mtd", rb"ubi\.mtd\s*=\s*[^\x00-\x1f\s,]{0,64}"),
    ("mtdblock_root", rb"root[^\x00-\x1f]{0,200}mtdblock\s*\d+"),
    (
        "rootfstype_hint",
        rb"rootfstype\s*=\s*(jffs2|ubifs|squashfs)",
    ),
    (
        "cmdlinepart_notice",
        rb"[0-9]+\s+cmdlinepart\s+partitions\s+found[^\x00-\x1f]{0,120}",
    ),
    (
        "creating_mtd_partitions",
        rb'Creating\s+\d+\s+MTD\s+partitions\s+on\s+"[^\x00"]+"',
    ),
    (
        "partition_range_printk",
        rb'0x[0-9a-f]+\s*-\s*0x[0-9a-f]+\s*:\s*"[^"]+"',
    ),
    ("mtdoops_attached", rb"mtdoops:\s+(?:Attached to MTD device|ready)[^\x00-\x1f]{0,80}"),
    (
        "mtd_partition_offsets",
        rb"MTD\s+partition\s*\(\s*\d+\s*\)\s+offset\s*=\s*\d+\s+size\s*=\s*\d+[^\x00-\x1f]{0,40}",
    ),
    (
        "bcmnand_geometry",
        BCMNAND_GEOMETRY_BYTES,
    ),
    (
        "bcmnand",
        rb"BCMNAND:[^\x00-\x1f\x22]{1,280}",
    ),
    ("tlpart_kw", rb"tlpart|Tldisk|opentla|tldisk_partition"),
    (
        "tldisk_partition_printk",
        rb"tldisk_partition\s*:\s*[^\x00-\x1f]{0,260}",
    ),
    (
        "parse_bsd_printk",
        rb"parse_bsd\s*:[^\x00-\x1f]{0,320}",
    ),
    ("ubi_phy_erase", rb"UBI:[\x20-\x7e]{0,320}"),
    ("ubi_attach", rb"ubiattach[\x20-\x7e]{0,200}"),
]

def _build_compiled_patterns() -> List[Tuple[str, re.Pattern]]:
    out: List[Tuple[str, re.Pattern]] = []
    for kind, pat in _REGEX_SPECS:
        if kind == "bcmnand_geometry":
            out.append((kind, _BCMNAND_GEOMETRY_RE))
        else:
            out.append((kind, re.compile(pat, re.I)))
    return out


_COMPILED_PATTERNS: List[Tuple[str, re.Pattern]] = _build_compiled_patterns()


class MtdScanner:
    """Scan binary data for MTD-related strings."""

    def __init__(self, max_per_kind: int = DEFAULT_MAX_PER_KIND):
        self.max_per_kind = max_per_kind
        self._findings: List[MtdFinding] = []
        self._mtdparts_parsed: List[Dict[str, Any]] = []
        self._bcmnand_geometry_parsed: List[Dict[str, Any]] = []

    def scan(self, file_path: str) -> MtdScanResult:
        """Memory-map file and run all MTD patterns."""
        self._findings = []
        self._mtdparts_parsed = []
        self._bcmnand_geometry_parsed = []
        mtdparts_sig_seen: Set[str] = set()
        bcmnand_geo_sig_seen: Set[str] = set()

        with open(file_path, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                for kind, pat in _COMPILED_PATTERNS:
                    seen_signature: Set[str] = set()
                    kind_count = 0
                    for match in pat.finditer(mm):
                        if kind_count >= self.max_per_kind:
                            break
                        frag = bytes(mm[match.start() : match.end()])
                        text = _ascii_display(frag)
                        sig = kind + ":" + text[:400]
                        if sig in seen_signature:
                            continue
                        seen_signature.add(sig)
                        kind_count += 1

                        parsed = MtdScanner._enrich(kind, frag)

                        if kind == "mtdparts_token" and parsed:
                            mtd_key = repr(
                                (parsed.get("mtd_id"), parsed.get("partitions"))
                            )
                            if mtd_key not in mtdparts_sig_seen:
                                mtdparts_sig_seen.add(mtd_key)
                                self._mtdparts_parsed.append(parsed)

                        if kind == "bcmnand_geometry" and parsed:
                            geo_key = repr(
                                (
                                    parsed.get("chip_capacity_mib"),
                                    parsed.get("erase_block_bytes"),
                                    parsed.get("page_bytes"),
                                    parsed.get("oob_spare_bytes"),
                                )
                            )
                            if geo_key not in bcmnand_geo_sig_seen:
                                bcmnand_geo_sig_seen.add(geo_key)
                                self._bcmnand_geometry_parsed.append(parsed)

                        self._findings.append(
                            MtdFinding(kind, match.start(), text, parsed=parsed)
                        )

        self._dedupe_near_identical()

        return MtdScanResult(
            findings=sorted(self._findings, key=lambda x: (x.kind, x.offset)),
            mtdparts_parsed=list(self._mtdparts_parsed),
            bcmnand_geometry_parsed=list(self._bcmnand_geometry_parsed),
        )

    def scan_strings_file(self, file_path: str) -> MtdScanResult:
        """Alias: pre-extracted `strings` output uses the same mmap scan."""
        return self.scan(file_path)

    def _dedupe_near_identical(self) -> None:
        """Remove duplicate findings with same kind+text (common in mirrored flash)."""
        uniq: List[MtdFinding] = []
        seen: Set[Tuple[str, str]] = set()
        for f in sorted(self._findings, key=lambda x: x.offset):
            key = (f.kind, f.text[:300])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(f)
        self._findings = uniq

    @staticmethod
    def _enrich(kind: str, frag: bytes) -> Optional[Dict[str, Any]]:
        if kind == "partition_range_printk":
            return parse_partition_range(frag)
        if kind == "creating_mtd_partitions":
            return parse_cmdline_mt_line(frag)
        if kind == "mtd_partition_offsets":
            return parse_mtd_partition_offset_line(frag)
        if kind == "mtdparts_token":
            return parse_mtdparts_value(frag)
        if kind == "bcmnand_geometry":
            return parse_bcmnand_geometry(frag)
        return None


def print_report(result: MtdScanResult) -> None:
    """Print human-readable sections for CLI output."""
    print("\n" + "=" * 70)
    print("MTD LAYOUT / PARTITION STRINGS")
    print("=" * 70)

    if result.mtdparts_parsed:
        print("\n--- Parsed mtdparts (best-effort) ---")
        for i, table in enumerate(result.mtdparts_parsed, 1):
            mid = _ascii_safe(str(table.get("mtd_id", "?")))
            print(f"  Table {i}: mtd_id={mid!r}")
            for p in table.get("partitions", []):
                name = _ascii_safe(p.get("name", "?"))
                if p.get("remainder"):
                    print(f"    - {name}  (remainder of device)")
                else:
                    sz = p.get("size_bytes")
                    print(f"    - {name}  size={sz} bytes")

    if result.bcmnand_geometry_parsed:
        print("\n--- BCM NAND reported geometry (from printk) ---")
        for i, geo in enumerate(result.bcmnand_geometry_parsed, 1):
            print(f"  Snapshot {i}:")
            print(f"    capacity: {_ascii_safe(str(geo.get('chip_capacity_human')))}")
            print(f"    erase: {_ascii_safe(str(geo.get('erase_block_human')))}")
            pb = geo.get("page_bytes")
            sp = geo.get("oob_spare_bytes")
            print(f"    page_bytes={pb}  spare/OOB_hint={sp}")
            rw = geo.get("raw", "")
            if rw and len(rw) > 160:
                rw = rw[:157] + "..."
            print(f"    raw: {_ascii_safe(str(rw))}")

    ranges = [f for f in result.findings if f.kind == "partition_range_printk" and f.parsed]
    if ranges:
        print("\n--- Kernel-printed partition ranges ---")
        seen_r: Set[str] = set()
        for f in ranges:
            p = f.parsed or {}
            pname = _ascii_safe(p.get("name"))
            shr = _ascii_safe(str(p.get("start_hex")))
            ehr = _ascii_safe(str(p.get("end_hex")))
            label = f"{pname}:{shr}-{ehr}"
            if label in seen_r:
                continue
            seen_r.add(label)
            print(
                f"  {pname}: {shr} - {ehr} "
                f"(len {p.get('length')})"
            )

    offset_lines = [
        f for f in result.findings if f.kind == "mtd_partition_offsets" and f.parsed
    ]
    if offset_lines:
        print("\n--- MTD partition offset/size lines (driver debug) ---")
        seen_o: Set[str] = set()
        for f in offset_lines:
            p = f.parsed or {}
            key = f"{p.get('index')}:{p.get('offset')}:{p.get('size')}"
            if key in seen_o:
                continue
            seen_o.add(key)
            print(
                f"  part[{p.get('index')}] offset={p.get('offset')} "
                f"size={p.get('size')} bytes"
            )

    tl_printk = [
        f
        for f in result.findings
        if f.kind in ("tldisk_partition_printk", "parse_bsd_printk")
    ]
    if tl_printk:
        print("\n--- TL disk vendor printk (sample) ---")
        seen_tl: Set[str] = set()
        for f in tl_printk[:20]:
            t = f.text[:200] + ("..." if len(f.text) > 200 else "")
            if t in seen_tl:
                continue
            seen_tl.add(t)
            print(f"  [{f.kind}] @0x{f.offset:x}  {_ascii_safe(t)}")
        if len(tl_printk) > 20:
            print(f"  ... ({len(tl_printk) - 20} more lines suppressed)")

    print("\n--- Other MTD / U-Boot / flash cues (deduped) ---")
    by_kind: Dict[str, List[MtdFinding]] = defaultdict(list)
    for f in result.findings:
        if f.kind in (
            "partition_range_printk",
            "mtd_partition_offsets",
            "mtdparts_token",
            "bcmnand_geometry",
            "tldisk_partition_printk",
            "parse_bsd_printk",
        ):
            continue
        by_kind[f.kind].append(f)

    for kind in sorted(by_kind.keys()):
        items = by_kind[kind][:12]
        print(f"\n  [{kind}] ({len(by_kind[kind])} hit(s))")
        for f in items[:5]:
            t = f.text[:180] + ("..." if len(f.text) > 180 else "")
            print(f"    @0x{f.offset:x}  {_ascii_safe(t)}")
        if len(by_kind[kind]) > 5:
            print(f"    ... ({len(by_kind[kind]) - 5} more)")

    print("\n--- Summary ---")
    print(f"  Total unique findings: {len(result.findings)}")
    print(f"  Distinct mtdparts tables: {len(result.mtdparts_parsed)}")
    print(f"  Distinct BCM NAND geometry snapshots: {len(result.bcmnand_geometry_parsed)}")
    print("=" * 70 + "\n")
