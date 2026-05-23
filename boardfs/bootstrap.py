"""Build :class:`~boardfs.registry.FsRegistry` from a physical Pace NAND dump."""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from boardfs.flash import flash_image_from_cmdline_bytes
from boardfs.registry import FsRegistry
from opentl import nand_bootstrap
from opentl.driver import LogicalOpenTLSession, TranslateMode
from unand.geometry import NandGeometry, PACE_DEFAULT


#region kernel_adjacent boardfs_temporary_registry_from_physical_nand
@contextmanager
def temporary_registry_from_physical_nand(
    raw_path: Path,
    cmdline: str,
    *,
    geom: NandGeometry = PACE_DEFAULT,
    translate_mode: TranslateMode = "inline-2112",
) -> Iterator[tuple[FsRegistry, dict[str, Any], LogicalOpenTLSession | None]]:
    """
    Logicalize NAND in RAM, attach OpenTL when flat spare exists, yield ``FsRegistry``.

    Yields ``(FsRegistry, translate_manifest, opentl_session)``.
    """
    _ = geom
    raw = raw_path.expanduser().resolve()
    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        spare_p = td_p / "flat_spare.bin"
        logical, man = nand_bootstrap.translate_physical_nand(
            raw, translate_mode, spare_out=spare_p
        )
        flash = flash_image_from_cmdline_bytes(
            logical,
            cmdline,
            geom=geom,
            display_path=str(raw),
        )
        reg = FsRegistry(flash=flash, cmdline=cmdline)
        man_out: dict[str, Any] = dict(man)
        ot_session: LogicalOpenTLSession | None = None
        if spare_p.is_file() and spare_p.stat().st_size > 0:
            log_p = td_p / "logical_plane.bin"
            log_p.write_bytes(logical)
            try:
                ot, ot_session, attach_meta = nand_bootstrap.attach_open_tl_from_paths(
                    log_p, spare_p
                )
                reg.attach_open_tl(ot)
                man_out.update(attach_meta)
            except Exception as e:
                man_out["tl_bbm_attach_error"] = f"{type(e).__name__}: {e}"
                man_out["tl_bbm_attached"] = False
        else:
            man_out["tl_bbm_attach_error"] = "no flat spare bytes from nand_translate (spare_out empty)"
            man_out["tl_bbm_attached"] = False
        try:
            yield reg, man_out, ot_session
        finally:
            pass
#endregion
