"""Physical NAND → logical plane + OpenTL BBM attach helpers (paths owned by caller)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentl.driver import LogicalOpenTLSession, OpenTL, infer_tl_mount_nand_logical_offset
from opentl.nand_translate import TranslateMode, nand_translate_to_bytes


#region kernel_adjacent nand_bootstrap_translate_attach
def translate_physical_nand(
    raw_path: Path,
    translate_mode: TranslateMode,
    *,
    spare_out: Path,
) -> tuple[bytes, dict[str, Any]]:
    """Stream logical plane bytes; write flat spare to ``spare_out``."""
    return nand_translate_to_bytes(raw_path, translate_mode, spare_out=spare_out)


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
    "attach_open_tl_from_paths",
    "translate_physical_nand",
]
