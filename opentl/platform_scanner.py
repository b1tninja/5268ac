#!/usr/bin/env python3
"""
mmap scan for Linux / boot / CPU identity strings embedded in dumps
(Linux version printk, kernel command line, BMIPS CPU printk, BRCMNAND bootstrap lines).
"""

from __future__ import annotations

import mmap
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from opentl.mtd_scanner import DEFAULT_MAX_PER_KIND


def _ascii_display(data: bytes, max_len: int = 4096) -> str:
    s = data.decode("ascii", errors="replace").strip()
    s = "".join(c if ord(c) < 128 else "?" for c in s)
    s = re.sub(r"\s+", " ", s)
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


@dataclass
class PlatformFinding:
    kind: str
    offset: int
    text: str
    parsed: Optional[Dict[str, Any]] = None


@dataclass
class PlatformScanResult:
    findings: List[PlatformFinding] = field(default_factory=list)
    linux_versions: List[Dict[str, Any]] = field(default_factory=list)
    kernel_cmdlines: List[Dict[str, Any]] = field(default_factory=list)


LINUX_VERSION_CORE = re.compile(
    rb"Linux\s+version\s+"
    rb"(\d+\.\d+(?:\.\d+)?)"  # 3.4.11
    rb"(-[a-zA-Z0-9._+-]+)?"  # -rt19 (optional)
    rb"\s*\(",
    re.I,
)


def parse_linux_version(frag: bytes) -> Optional[Dict[str, Any]]:
    """Extract Linux release, local suffix, gcc/Buildroot hints if present."""
    m = LINUX_VERSION_CORE.search(frag)
    if not m:
        m = re.search(
            rb"Linux\s+version\s+(\d+\.\d+(?:\.\d+)?)(-[a-zA-Z0-9._+-]+)?",
            frag,
            re.I,
        )
    if not m:
        return None
    ver = m.group(1).decode("ascii", errors="replace")
    loc_grp = m.group(2)
    loc = loc_grp.decode("ascii", errors="replace") if loc_grp else ""
    full_version = ver + loc

    raw = frag.decode("ascii", errors="replace").strip()

    gcc = None
    buildroot = None
    mg = re.search(
        rb"gcc\s+version\s+([\d.]+).*?Buildroot\s+([0-9.]+)",
        frag,
        re.I | re.DOTALL,
    )
    if mg:
        gcc = mg.group(1).decode("ascii", errors="replace")
        buildroot = mg.group(2).decode("ascii", errors="replace")
    else:
        mg2 = re.search(rb"gcc\s+version\s+([\d.]+)", frag, re.I)
        if mg2:
            gcc = mg2.group(1).decode("ascii", errors="replace")

    host = None
    mh = re.search(rb"\(([^@)]*@[^)]+)\)", frag)
    if mh:
        host = mh.group(1).decode("ascii", errors="replace")

    return {
        "version": full_version,
        "release": ver,
        "localversion": (loc.lstrip("-") if loc else None),
        "gcc": gcc,
        "buildroot": buildroot,
        "build_host_hint": host,
        "raw": raw[:1500],
    }


def parse_kernel_cmdline(frag: bytes) -> Optional[Dict[str, Any]]:
    """
    Text after 'Kernel command line:' plus a few high-signal parameters.
    """
    m = re.search(rb"Kernel\s+command\s+line:\s*(.+)", frag, re.I | re.DOTALL)
    if not m:
        return None
    raw_cmd = m.group(1).decode("ascii", errors="replace").strip()
    # Stop at repeated syslog noise (second timestamp) if any
    raw_cmd = raw_cmd.split(" left=")[0].strip()

    out: Dict[str, Any] = {"full": raw_cmd}

    mp = re.search(r"mtdparts=\S+", raw_cmd)
    if mp:
        out["mtdparts"] = mp.group(0)

    cons = re.search(r"console=\S+", raw_cmd)
    if cons:
        out["console"] = cons.group(0)

    init = re.search(r"\binit=\S+", raw_cmd)
    if init:
        out["init"] = init.group(0)

    for key in ("rd_start=", "rd_size=", "memsize="):
        if key in raw_cmd:
            mv = re.search(re.escape(key) + r"\S*", raw_cmd)
            if mv:
                out[key.rstrip("=")] = mv.group(0)

    um = re.search(r"ubi\.mtd=\S+", raw_cmd)
    if um:
        out["ubi.mtd"] = um.group(0)

    return out


def parse_uboot_passthrough(frag: bytes) -> Dict[str, Any]:
    """
    U-boot passed args … — often duplicates bootargs echoed before kernel parses them.
    """
    raw = frag.decode("ascii", errors="replace").strip()
    out: Dict[str, Any] = {"raw": raw[:8192]}
    mp = re.search(rb"mtdparts=\S+", frag)
    if mp:
        out["mtdparts"] = mp.group(0).decode("ascii", errors="replace").strip()
    cons = re.search(rb"console=\S+", frag)
    if cons:
        out["console"] = cons.group(0).decode("ascii", errors="replace").strip()
    return out


def parse_brcmnand_device(frag: bytes) -> Optional[Dict[str, Any]]:
    """BRCMNAND device: block: N page: M name: foo"""
    m = re.search(
        rb"block:\s*(\d+)\s+page:\s*(\d+)\s+name:\s*(\S+)",
        frag,
        re.I,
    )
    if not m:
        return None
    return {
        "block_bytes": int(m.group(1)),
        "page_bytes": int(m.group(2)),
        "name": m.group(3).decode("ascii", errors="replace"),
        "raw": frag.decode("ascii", errors="replace").strip()[:400],
    }


def parse_bcmnand_bootcfg(frag: bytes) -> Optional[Dict[str, Any]]:
    """
    BCMNAND: Bootcfg=... Cfg=... CsAndNor=... Base=... Acc=... Id=...
    """
    raw = frag.decode("ascii", errors="replace").strip()
    return {"raw": raw[:500]}


_PLATFORM_REGEX_SPECS: List[Tuple[str, bytes]] = [
    (
        "linux_version_printk",
        rb"Linux\s+version\s+\d+\.\d+(?:\.\d+)?[\x20-\x7e]{20,900}",
    ),
    (
        "kernel_command_line",
        rb"Kernel\s+command\s+line:\s*[\x20-\x7e]{30,8192}",
    ),
    (
        "cpu_bmips_printk",
        rb"CPU\s+revision\s+is:\s*[\x20-\x7e]{10,400}",
    ),
    (
        "uboot_passthrough",
        rb"(?:U-|u-)[Bb]oot\s+passed\s+args\s+[\x20-\x7e]{30,8192}",
    ),
    (
        "found_arg",
        rb"Found\s+arg\s+[\x20-\x7e]{10,700}",
    ),
    (
        "found_env",
        rb"Found\s+env\s+[\x20-\x7e]{6,500}",
    ),
    (
        "brcmnand_device",
        rb"BRCMNAND\s+device\s*:[\x20-\x7e]{10,400}",
    ),
    (
        "bcmnand_bootcfg",
        rb"BCMNAND:\s*Bootcfg=[\x20-\x7e]{10,500}",
    ),
]

_COMPILED_PLATFORM: List[Tuple[str, re.Pattern]] = [
    (k, re.compile(p, re.I)) for k, p in _PLATFORM_REGEX_SPECS
]


class PlatformScanner:
    """Scan flash dumps for kernel / boot identity strings."""

    def __init__(self, max_per_kind: int = DEFAULT_MAX_PER_KIND):
        self.max_per_kind = max_per_kind
        self._findings: List[PlatformFinding] = []
        self._linux_versions: List[Dict[str, Any]] = []
        self._kernel_cmdlines: List[Dict[str, Any]] = []

    def scan(self, file_path: str) -> PlatformScanResult:
        self._findings = []
        self._linux_versions = []
        self._kernel_cmdlines = []
        linux_seen: Set[str] = set()
        cmdline_seen: Set[str] = set()

        with open(file_path, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                for kind, pat in _COMPILED_PLATFORM:
                    seen_signature: Set[str] = set()
                    kind_count = 0
                    for match in pat.finditer(mm):
                        if kind_count >= self.max_per_kind:
                            break
                        frag = bytes(mm[match.start() : match.end()])
                        text = _ascii_display(frag, max_len=3000)
                        sig = kind + ":" + text[:500]
                        if sig in seen_signature:
                            continue
                        seen_signature.add(sig)
                        kind_count += 1

                        parsed = PlatformScanner._enrich(kind, frag)

                        if kind == "linux_version_printk" and parsed:
                            lk = repr(
                                (
                                    parsed.get("version"),
                                    parsed.get("gcc"),
                                    parsed.get("buildroot"),
                                )
                            )
                            if lk not in linux_seen:
                                linux_seen.add(lk)
                                self._linux_versions.append(parsed)

                        if kind == "kernel_command_line" and parsed and "full" in parsed:
                            ck = parsed.get("full", "")[:2000]
                            if ck and ck not in cmdline_seen:
                                cmdline_seen.add(ck)
                                self._kernel_cmdlines.append(parsed)

                        self._findings.append(
                            PlatformFinding(kind, match.start(), text, parsed=parsed)
                        )

        self._dedupe_near_identical()

        return PlatformScanResult(
            findings=sorted(self._findings, key=lambda x: (x.kind, x.offset)),
            linux_versions=list(self._linux_versions),
            kernel_cmdlines=list(self._kernel_cmdlines),
        )

    def scan_strings_file(self, file_path: str) -> PlatformScanResult:
        return self.scan(file_path)

    def _dedupe_near_identical(self) -> None:
        uniq: List[PlatformFinding] = []
        seen: Set[Tuple[str, str]] = set()
        for f in sorted(self._findings, key=lambda x: x.offset):
            key = (f.kind, f.text[:400])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(f)
        self._findings = uniq

    @staticmethod
    def _enrich(kind: str, frag: bytes) -> Optional[Dict[str, Any]]:
        if kind == "linux_version_printk":
            return parse_linux_version(frag)
        if kind == "kernel_command_line":
            return parse_kernel_cmdline(frag)
        if kind == "uboot_passthrough":
            return parse_uboot_passthrough(frag)
        if kind == "brcmnand_device":
            return parse_brcmnand_device(frag)
        if kind == "bcmnand_bootcfg":
            return parse_bcmnand_bootcfg(frag)
        return None


def print_platform_report(result: PlatformScanResult) -> None:
    print("\n" + "=" * 70)
    print("KERNEL / PLATFORM / BOOT STRINGS")
    print("=" * 70)

    if result.linux_versions:
        print("\n--- Linux version (printk) ---")
        for i, lv in enumerate(result.linux_versions, 1):
            print(f"  [{i}] {lv.get('version')}")
            if lv.get("gcc"):
                print(f"      gcc: {lv.get('gcc')}")
            if lv.get("buildroot"):
                print(f"      Buildroot: {lv.get('buildroot')}")
            if lv.get("build_host_hint"):
                print(f"      host hint: {lv.get('build_host_hint')}")
            raw = lv.get("raw", "")
            if len(raw) > 240:
                raw = raw[:237] + "..."
            print(f"      raw: {raw}")

    if result.kernel_cmdlines:
        print("\n--- Kernel command line (deduped) ---")
        for i, kc in enumerate(result.kernel_cmdlines, 1):
            print(f"  [{i}]")
            full = kc.get("full", "")
            if len(full) > 500:
                print(f"      full: {full[:497]}...")
            else:
                print(f"      full: {full}")
            for key in sorted(k for k in kc if k != "full"):
                print(f"      {key}: {kc[key]}")

    cpu_hits = [f for f in result.findings if f.kind == "cpu_bmips_printk"]
    if cpu_hits:
        print("\n--- CPU printk ---")
        seen_c: Set[str] = set()
        for f in cpu_hits:
            if f.text not in seen_c:
                seen_c.add(f.text)
                print(f"  {f.text[:260]}")

    passthrough = [
        f for f in result.findings if f.kind in ("found_arg", "found_env")
    ]
    ub = [f for f in result.findings if f.kind == "uboot_passthrough"]
    if passthrough or ub:
        print("\n--- Bootloader passthrough snippets ---")
        for f in (ub + passthrough)[:40]:
            t = f.text[:300] + ("..." if len(f.text) > 300 else "")
            print(f"  [{f.kind}] @0x{f.offset:x}  {t}")
        extra = len(ub + passthrough) - 40
        if extra > 0:
            print(f"  ... ({extra} additional lines suppressed)")

    nand_x = [
        f
        for f in result.findings
        if f.kind in ("brcmnand_device", "bcmnand_bootcfg") and f.parsed
    ]
    if nand_x:
        print("\n--- BCM / BRCMNAND bootstrap printk ---")
        seen_n: Set[str] = set()
        for f in nand_x:
            key = str(f.parsed.get("raw", f.text))[:180]
            if key in seen_n:
                continue
            seen_n.add(key)
            if f.kind == "brcmnand_device" and f.parsed:
                p = f.parsed
                print(
                    f"  BRCMNAND device: block={p.get('block_bytes')} "
                    f"page={p.get('page_bytes')} name={p.get('name')}"
                )
            else:
                print(f"  {f.text[:300]}")

    print("\n--- Other platform hits ---")
    by_kind: Dict[str, List[PlatformFinding]] = defaultdict(list)
    skip_k = frozenset(
        {
            "linux_version_printk",
            "kernel_command_line",
            "cpu_bmips_printk",
            "found_arg",
            "found_env",
            "uboot_passthrough",
            "brcmnand_device",
            "bcmnand_bootcfg",
        }
    )
    for f in result.findings:
        if f.kind not in skip_k:
            by_kind[f.kind].append(f)

    if not by_kind:
        print("  (none)")
    else:
        for kind in sorted(by_kind.keys()):
            print(f"  [{kind}] {len(by_kind[kind])} hit(s)")

    print("\n--- Summary ---")
    print(f"  Linux version signatures: {len(result.linux_versions)}")
    print(f"  Deduped kernel cmdlines: {len(result.kernel_cmdlines)}")
    print(f"  Total findings (deduped): {len(result.findings)}")
    print("=" * 70 + "\n")

