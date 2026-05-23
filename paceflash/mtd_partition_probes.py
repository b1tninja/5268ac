"""Linear MTD partition probes: U-Boot env in ``loader``, mtdoops panic ring."""

from __future__ import annotations

import re
import struct
from typing import Any

from binwalker.extract.flash_layout import UBOOT_ENV_IMAGE_SIZES
from uboot.env import parse_uboot_env_v1

# fwupgrade.txt default for 5268-class captures
DEFAULT_MTDOOPS_RECORD_SIZE = 131072

_ASCII_RUN_RE = re.compile(rb"[\x20-\x7e\r\n\t]{20,}")


def probe_loader_env(loader_bytes: bytes) -> dict[str, Any]:
    """
    Try U-Boot env v1 images at the start of the **loader** MTD slice (offset 0).
    """
    best: dict[str, Any] | None = None
    for sz in UBOOT_ENV_IMAGE_SIZES:
        if sz > len(loader_bytes):
            continue
        blob = loader_bytes[:sz]
        r = parse_uboot_env_v1(blob, crc_endian="auto")
        if not r.crc_ok:
            continue
        entry: dict[str, Any] = {
            "env_size": sz,
            "crc_ok": True,
            "crc_endian": r.crc_endian,
            "mtdparts_token": r.mtdparts_token,
            "variables": dict(r.variables),
        }
        if best is None or sz > best.get("env_size", 0):
            best = entry
    if best is None:
        return {"ok": False, "error": "no CRC-valid U-Boot env v1 at loader base"}
    warnings: list[str] = []
    vars_ = best.get("variables") or {}
    for key in ("bootcmd", "bootdelay", "serial#", "ver", "version"):
        if key in vars_:
            best[f"highlight_{key}"] = vars_[key]
    if best.get("mtdparts_token"):
        warnings.append(f"loader env mtdparts: {best['mtdparts_token']}")
    return {"ok": True, "env": best, "warnings": warnings}


def probe_mtdoops(
    mtdoops_bytes: bytes,
    *,
    record_size: int = DEFAULT_MTDOOPS_RECORD_SIZE,
) -> dict[str, Any]:
    """
    Summarize the **mtdoops** MTD slice: erase fill ratio, record slots, ASCII oops text.
    """
    n = len(mtdoops_bytes)
    if n == 0:
        return {"ok": False, "error": "empty mtdoops slice"}
    if record_size < 4096 or (record_size & 0xFFF) != 0:
        return {"ok": False, "error": f"invalid record_size {record_size}"}
    ff_count = sum(1 for b in mtdoops_bytes if b == 0xFF)
    erased_ratio = ff_count / n
    slot_count = n // record_size
    used_slots: list[dict[str, Any]] = []
    for i in range(slot_count):
        off = i * record_size
        chunk = mtdoops_bytes[off : off + record_size]
        if not chunk or all(b == 0xFF for b in chunk):
            continue
        head = chunk[:8]
        if len(head) >= 4:
            counter = struct.unpack(">I", head[:4])[0]
        else:
            counter = None
        if counter == 0xFFFFFFFF:
            continue
        used_slots.append(
            {
                "slot_index": i,
                "offset": off,
                "counter_be_u32": f"{counter:08x}" if counter is not None else None,
            }
        )
    runs: list[dict[str, Any]] = []
    for m in _ASCII_RUN_RE.finditer(mtdoops_bytes):
        text = m.group().decode("ascii", errors="replace")
        if len(text.strip()) < 20:
            continue
        runs.append(
            {
                "offset": m.start(),
                "length": m.end() - m.start(),
                "preview": text[:240].replace("\n", "\\n"),
            }
        )
    warnings: list[str] = []
    if erased_ratio > 0.95:
        warnings.append(
            "mtdoops slice is mostly 0xFF (erased or cleared — expected after upgrade scrub)"
        )
    elif not used_slots and not runs:
        warnings.append("mtdoops has non-FF data but no recognized record headers or ASCII oops")
    elif used_slots:
        warnings.append(
            f"mtdoops has {len(used_slots)} non-empty record slot(s) of {slot_count} "
            f"(record_size={record_size})"
        )
    return {
        "ok": True,
        "size_bytes": n,
        "record_size": record_size,
        "slot_count": slot_count,
        "erased_byte_ratio": round(erased_ratio, 4),
        "used_slots": used_slots[:32],
        "ascii_runs": runs[:16],
        "ascii_run_count": len(runs),
        "warnings": warnings,
    }


def run_mtd_partition_probes(
    flash: Any,
    *,
    probe_loader: bool = True,
    probe_mtdoops_flag: bool = True,
    mtdoops_record_size: int = DEFAULT_MTDOOPS_RECORD_SIZE,
) -> dict[str, Any]:
    """
    Run probes on ``flash`` (:class:`~binwalker.extract.flash_layout.FlashImage`).
    """
    out: dict[str, Any] = {"warnings": []}
    names = {p.name for p in flash.partitions}
    if probe_loader:
        if "loader" not in names:
            out["loader"] = {"ok": False, "error": "no loader partition in mtd layout"}
        else:
            try:
                blob = flash.read_partition("loader")
                out["loader"] = probe_loader_env(blob)
            except Exception as e:
                out["loader"] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        if isinstance(out.get("loader"), dict):
            for w in out["loader"].get("warnings") or []:
                out["warnings"].append(f"loader: {w}")
    if probe_mtdoops_flag:
        if "mtdoops" not in names:
            out["mtdoops"] = {"ok": False, "error": "no mtdoops partition in mtd layout"}
        else:
            try:
                blob = flash.read_partition("mtdoops")
                out["mtdoops"] = probe_mtdoops(blob, record_size=mtdoops_record_size)
            except Exception as e:
                out["mtdoops"] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        if isinstance(out.get("mtdoops"), dict):
            for w in out["mtdoops"].get("warnings") or []:
                out["warnings"].append(f"mtdoops: {w}")
    return out
