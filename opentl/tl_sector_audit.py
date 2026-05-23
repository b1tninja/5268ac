"""
Offline **sector / MBR / scan** audit for TL disklabel debugging (Ghidra-backed assumptions).

Complements :mod:`opentl.tldisk` by summarizing whether an MBR ``0xA5`` slice offset could apply,
how ``bsd_magic`` hits align to 512-byte sectors, and whether chain-pattern substrings appear
near disklabel-related hits (observational counts only — not a virt→phys mapping strategy).
"""

from __future__ import annotations

from typing import Any

from opentl.tl_mbr_slice import mbr_boot_signature_ok, mbr_first_a5_slice_byte_offset
from opentl.tl_physical import DISKLABEL_CHAIN_PATTERN, scan_tl_disklabel_bytes


def flash_plane_sector0_prefix_bytes(flash: object) -> bytes | None:
    """
    First 512 bytes of a flash backing object exposing ``logical_image`` or ``path`` (duck-typed).

    Works with in-memory logical planes or path-backed images without importing MTD layout packages.
    """
    li = getattr(flash, "logical_image", None)
    if li is not None and isinstance(li, (bytes, bytearray)) and len(li) >= 512:
        return bytes(li[:512])
    path = getattr(flash, "path", None)
    if isinstance(path, str):
        try:
            with open(path, "rb") as f:
                return f.read(512)
        except OSError:
            return None
    return None


def audit_tl_kernel_alignment_bytes(
    tlpart_bytes: bytes,
    *,
    plane_sector0_prefix: bytes | None = None,
) -> dict[str, Any]:
    """
    Build a JSON-friendly report for ``tlpart`` bytes plus optional **full-plane** first sector.

    ``plane_sector0_prefix`` should be the first 512 bytes of the **logical flash** (offset 0)
    when available (e.g. in-memory logicalized image) so MBR fields are reported even when
    ``tlpart_bytes`` is only the MTD slice.
    """
    if plane_sector0_prefix is not None and len(plane_sector0_prefix) >= 512:
        mbr_view = plane_sector0_prefix[:512]
    else:
        mbr_view = tlpart_bytes[:512]
    mbr_ok = mbr_boot_signature_ok(mbr_view)
    a5_off = (
        mbr_first_a5_slice_byte_offset(mbr_view, require_fits_buffer=False) if mbr_ok else None
    )

    raw = scan_tl_disklabel_bytes(tlpart_bytes, max_hits=50)
    chains = [h for h in raw if h.match_kind in ("chain", "chain4")]
    bsds = [h.offset for h in raw if h.match_kind == "bsd_magic"]

    nearest: int | None = None
    pos = tlpart_bytes.find(DISKLABEL_CHAIN_PATTERN)
    if pos >= 0 and bsds:
        nearest = min(abs(pos - b) for b in bsds)

    return {
        "mbr_boot_signature_ok": mbr_ok,
        "mbr_a5_slice_byte_offset": a5_off,
        "tlpart_chain_hits": len(chains),
        "tlpart_first_chain_offset": chains[0].offset if chains else None,
        "tlpart_bsd_magic_count": len(bsds),
        "tlpart_bsd_magic_offsets_hex": [f"{o:#x}" for o in bsds[:12]],
        "tlpart_bsd_magic_mod512": [b % 512 for b in bsds[:12]],
        "tlpart_substring_chain4_offset": pos if pos >= 0 else None,
        "tlpart_nearest_chain4_to_bsd_bytes": nearest,
    }
