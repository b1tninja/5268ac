"""
Assemble ``opentla4`` (ext2) from a logical ``tlpart`` image + BBM map.

Uses :class:`opentl.open_tl.OpenTL` for virt-to-phys assembly (no ``tl_bbm`` imports here).
Optional uImage verification uses :mod:`uboot.uimage`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from opentl.open_tl import ExtractResult, OpenTL, extract_opentla4 as _extract_opentla4_core
from uboot.uimage import parse_uimage_header


def verify_uimage_in_extract(ext2_img: bytes, reference_uimage_path: str | Path) -> dict:
    """Compare first legacy uImage header in ``ext2_img`` to header at offset 0 of reference file."""
    ref = Path(reference_uimage_path).read_bytes()
    ref_h = parse_uimage_header(ref[:64], offset_in_file=0)
    out: dict = {"reference_ok": ref_h is not None, "candidate_offset": None, "match": False}
    if ref_h is None:
        out["error"] = "reference is not a uImage at offset 0"
        return out

    magic_be = b"\x27\x05\x19\x56"
    start = 0
    while True:
        idx = ext2_img.find(magic_be, start)
        if idx == -1:
            break
        cand = parse_uimage_header(ext2_img[idx : idx + 64], offset_in_file=idx)
        if cand is not None:
            out["candidate_offset"] = idx
            out["match"] = (
                cand.ih_size == ref_h.ih_size
                and cand.ih_name == ref_h.ih_name
                and cand.ih_dcrc == ref_h.ih_dcrc
            )
            out["candidate"] = cand.as_dict()
            out["reference"] = ref_h.as_dict()
            return out
        start = idx + 1

    out["error"] = "no uImage magic found in extracted image"
    return out


def extract_opentla4(
    image_path: str | Path,
    *,
    block_map: Any,
    out_path: Optional[str | Path] = None,
    dry_run: bool = False,
    logical_prefix_bytes: Optional[int] = None,
    nand_logical_offset: Optional[int] = None,
    verify_uimage_path: Optional[str | Path] = None,
) -> ExtractResult:
    """Build ``opentla4`` with optional ``verify_uimage_path`` (carve / validation helper)."""
    verify_path = Path(verify_uimage_path) if verify_uimage_path is not None else None

    def _verify(payload: bytes) -> dict:
        assert verify_path is not None
        return verify_uimage_in_extract(payload, verify_path)

    verify_fn = _verify if verify_path is not None else None
    return _extract_opentla4_core(
        image_path,
        block_map=block_map,
        out_path=out_path,
        dry_run=dry_run,
        logical_prefix_bytes=logical_prefix_bytes,
        nand_logical_offset=nand_logical_offset,
        verify=verify_fn,
    )


__all__ = ["ExtractResult", "OpenTL", "extract_opentla4", "verify_uimage_in_extract"]
