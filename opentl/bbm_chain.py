"""BBM virtual-scan and spare-chain inference (host layer on :mod:`opentl.driver`)."""

from __future__ import annotations

import hashlib
from typing import Any

from opentl.driver import (
    BlockMapBuild,
    LogicalOpenTLSession,
    TL_PHYS_BLOCK_HOLE,
    infer_chain_aware_tl_scan,
)


#region kernel_adjacent bbm_virtual_scan_summary
def bbm_virtual_scan_summary(
    block_map: BlockMapBuild | None,
    ot_session: LogicalOpenTLSession | None,
    tlpart_tl_scan_bytes: bytes | None,
    *,
    chain_aware_applied: bool = False,
) -> dict[str, Any]:
    """JSON-friendly BBM / virtual TL scan stats when a session is attached."""
    if block_map is None or ot_session is None:
        return {"attached": False}
    holes = sum(1 for pb in block_map.virt_to_phys_block if pb == TL_PHYS_BLOCK_HOLE)
    blob = tlpart_tl_scan_bytes
    head_hash: str | None = None
    if blob:
        head_hash = hashlib.sha256(blob[:4096]).hexdigest()[:16]
    table = ot_session.virt_nand_page_table
    return {
        "attached": True,
        "bbm_mode": block_map.mode,
        "logical_prefix_bytes": int(block_map.logical_prefix_bytes),
        "nand_logical_offset": int(block_map.nand_logical_offset),
        "virt_blocks": int(block_map.geometry.virt_blocks),
        "erase_bytes": int(block_map.geometry.erase_bytes),
        "hole_erase_blocks": holes,
        "virt_nand_page_table_mode": table.mode,
        "virt_nand_page_table_pages": table.num_pages,
        "tlpart_tl_scan_bytes_len": len(blob or b""),
        "tlpart_tl_scan_head_sha256_16": head_hash,
        "chain_aware_virtual_scan": bool(chain_aware_applied),
    }


#endregion


#region kernel_adjacent infer_chain_aware_virtual_tl_scan
def infer_chain_aware_virtual_tl_scan(
    *,
    tlpart_tl_scan_bytes: bytes | None,
    linear_tlpart: bytes | None,
    ot_session: LogicalOpenTLSession | None = None,
    ext2_chain_infer: Any = None,
) -> bool:
    """
    Heuristic for auto-applying spare-chain BBM rebuild when linear ``tlpart`` still carries payload.

    ``ext2_chain_infer`` is an optional callable ``() -> bool`` (e.g. registry ext2 mismatch probe).
    """
    if infer_chain_aware_tl_scan(
        tlpart_tl_scan_bytes=tlpart_tl_scan_bytes,
        linear_tlpart=linear_tlpart,
    ):
        return True
    if (
        linear_tlpart is not None
        and b"hsqs" in linear_tlpart
        and ot_session is not None
        and ot_session.virt_nand_page_table.mode == "primary"
    ):
        return True
    if ext2_chain_infer is not None:
        try:
            if ext2_chain_infer():
                return True
        except Exception:
            pass
    return False


#endregion


#region kernel: 0x80289170
def apply_chain_aware_to_session(ot_session: LogicalOpenTLSession, flat_oob: bytes) -> None:
    """Enable spare-chain page resolution on ``ot_session`` (lazy; no full virtual-disk memcpy)."""
    ot_session.apply_chain_aware_flat_oob(flat_oob)


#endregion


__all__ = [
    "apply_chain_aware_to_session",
    "bbm_virtual_scan_summary",
    "infer_chain_aware_virtual_tl_scan",
]
