"""Physical NAND → logical plane + OpenTL BBM attach helpers (paths owned by caller)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentl.driver import LogicalOpenTLSession, OpenTL, infer_tl_mount_nand_logical_offset
from opentl.nand_translate import TranslateMode, nand_translate_to_bytes
from opentl.tl_bbm import BlockMapBuild
from opentl.tl_mount import mount_flash_image_from_bytes


#region kernel_adjacent nand_bootstrap_translate_attach
def translate_physical_nand(
    raw_path: Path,
    translate_mode: TranslateMode,
    *,
    spare_out: Path,
) -> tuple[bytes, dict[str, Any]]:
    """Stream logical plane bytes; write flat spare to ``spare_out``."""
    return nand_translate_to_bytes(raw_path, translate_mode, spare_out=spare_out)


def attach_open_tl_block_map_from_bytes(
    logical: bytes,
    spare_bytes: bytes,
) -> tuple[BlockMapBuild, dict[str, Any]]:
    """Build BBM map from in-memory logical plane + flat spare (no temp logical file)."""
    off = infer_tl_mount_nand_logical_offset(logical_image_size=len(logical))
    block_map = mount_flash_image_from_bytes(
        logical,
        spare_bytes=spare_bytes,
        nand_logical_offset=off,
        logical_prefix_bytes=None,
    )
    meta: dict[str, Any] = {
        "tl_bbm_attached": True,
        "tl_bbm_mode": block_map.mode,
        "flat_spare_bytes": len(spare_bytes),
        "logical_prefix_bytes": int(block_map.logical_prefix_bytes),
        "block_map": block_map,
    }
    return block_map, meta


def attach_open_tl_from_paths(
    logical_path: Path,
    spare_path: Path,
) -> tuple[OpenTL, LogicalOpenTLSession, dict[str, Any]]:
    """Build :class:`~opentl.driver.OpenTL` from on-disk logical plane + flat spare."""
    meta: dict[str, Any] = {}
    nand_off = infer_tl_mount_nand_logical_offset(logical_image_size=logical_path.stat().st_size)
    ot = OpenTL.from_logical_with_flat_spare(
        logical_path,
        spare_path=spare_path,
        nand_logical_offset=nand_off,
    )
    session = LogicalOpenTLSession.from_open_tl(ot)
    meta["tl_bbm_attached"] = True
    meta["tl_bbm_mode"] = ot.block_map.mode
    meta["flat_spare_path"] = str(spare_path.resolve())
    meta["flat_spare_bytes"] = spare_path.stat().st_size
    return ot, session, meta
#endregion


__all__ = [
    "attach_open_tl_block_map_from_bytes",
    "attach_open_tl_from_paths",
    "translate_physical_nand",
]
