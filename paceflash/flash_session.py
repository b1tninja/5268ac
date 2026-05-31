"""Open a :class:`~boardfs.registry.FsRegistry` from a Pace flash dump (logical or physical NAND)."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from boardfs import (
    FsRegistry,
    Opentla4VolumeResult,
    apply_chain_aware_virtual_tl_scan,
    assemble_opentla4_volume,
    flash_image_from_cmdline,
    infer_chain_aware_virtual_tl_scan,
    infer_ext2_opentla4_chain_aware,
    temporary_registry_from_physical_nand,
)
from boardfs.ext2_dissect import _EXT2_SB0_OFF, resolve_mountable_ext2_superblock_offset
from boardfs.ext2_volume_io import Ext2VolumeAccess, ext2_volume_access_from_assembly
from opentl.registry_hooks import _tl_slice_view, resolve_flat_oob
from opentl.driver import TranslateMode
from unand.geometry import PACE_DEFAULT
from unand.mtd import DEFAULT_MTDPARTS


#region kernel_adjacent paceflash_flash_session
def physical_pace_envelope(file_size: int) -> bool:
    return file_size in (PACE_DEFAULT.full_inline_bytes, PACE_DEFAULT.full_flat_tail_bytes)


def _apply_chain_aware_bbm_if_needed(
    reg: FsRegistry,
    man: dict,
    ot_session,
    *,
    bbm_chain_aware: bool,
    tl_slice: str,
) -> None:
    if ot_session is None or not man.get("tl_bbm_attached"):
        return
    spare_p = man.get("flat_spare_path")
    if not isinstance(spare_p, str) or not Path(spare_p).is_file():
        return
    try:
        linear_tlp = reg.flash.read_partition("tlpart")
    except KeyError:
        return
    infer_ext2_o4 = infer_ext2_opentla4_chain_aware(reg, slice_name=tl_slice)
    want_chain = bbm_chain_aware or infer_chain_aware_virtual_tl_scan(
        reg, linear_tlpart=linear_tlp, ot_session=ot_session, tl_slice=tl_slice
    ) or infer_ext2_o4
    if want_chain:
        apply_chain_aware_virtual_tl_scan(reg, ot_session, Path(spare_p).read_bytes())


@contextmanager
def open_flash_registry(
    flash_path: str | Path,
    cmdline: str | None = None,
    *,
    nand_translate: bool = True,
    nand_translate_mode: TranslateMode = "inline-2112",
    bbm_chain_aware: bool = False,
    tl_slice: str = "opentla4",
) -> Iterator[FsRegistry]:
    """Yield a registry with the same NAND translate + optional chain-aware BBM as ``build_inventory``."""
    p = Path(flash_path).expanduser().resolve()
    line = cmdline if cmdline is not None else f"quiet rw {DEFAULT_MTDPARTS}"
    file_size = os.path.getsize(p)

    if physical_pace_envelope(file_size) and nand_translate:
        with temporary_registry_from_physical_nand(
            p, line, translate_mode=nand_translate_mode
        ) as (reg, man, ot_session):
            _apply_chain_aware_bbm_if_needed(
                reg, man, ot_session, bbm_chain_aware=bbm_chain_aware, tl_slice=tl_slice
            )
            yield reg
    else:
        flash = flash_image_from_cmdline(p, line)
        yield FsRegistry(flash=flash, cmdline=line)


@dataclass(frozen=True, slots=True)
class Opentla4Ext2Volume:
    slice_bytes: bytes
    sb_off: int
    read_model: str
    slice_name: str
    access: Ext2VolumeAccess
    ntl_assembly: dict | None = None


@contextmanager
def open_opentla4_ext2(
    flash_path: str | Path,
    cmdline: str | None = None,
    *,
    slice_name: str = "opentla4",
    nand_translate: bool = True,
    nand_translate_mode: TranslateMode = "inline-2112",
    bbm_chain_aware: bool = False,
    lazy_assembly: bool = True,
) -> Iterator[Opentla4Ext2Volume]:
    """Assemble the TL slice and yield mountable ext2 bytes + superblock offset.

    Default ``lazy_assembly=True`` bulk-assembles only the ext2 probe prefix (~512 KiB);
    file blocks beyond that use per-block NTL replay (kernel ``__bread`` shape).
    Set ``lazy_assembly=False`` or ``OPENTL_FULL_ASSEMBLY=1`` for full ~120 MiB materialization.
    """
    if os.environ.get("OPENTL_FULL_ASSEMBLY", "").strip() in ("1", "true", "yes"):
        lazy_assembly = False
    with open_flash_registry(
        flash_path,
        cmdline,
        nand_translate=nand_translate,
        nand_translate_mode=nand_translate_mode,
        bbm_chain_aware=bbm_chain_aware,
        tl_slice=slice_name,
    ) as reg:
        vol = assemble_opentla4_volume(reg, slice_name=slice_name, lazy_assembly=lazy_assembly)
        if not vol.slice_bytes:
            raise RuntimeError(vol.error or "no opentla4 slice bytes assembled")
        sb = vol.ext2_sb_offset
        if sb is None:
            sb = resolve_mountable_ext2_superblock_offset(vol.slice_bytes)
        if sb is None:
            raise RuntimeError(vol.error or "no mountable ext2 on opentla4 slice")
        yield Opentla4Ext2Volume(
            slice_bytes=vol.slice_bytes,
            sb_off=sb,
            read_model=vol.read_model,
            slice_name=slice_name,
            access=_opentla4_volume_access(reg, vol, slice_name=slice_name, flat_oob=None),
            ntl_assembly=vol.ntl_assembly,
        )


def _opentla4_volume_access(
    reg: FsRegistry,
    assembled: Opentla4VolumeResult,
    *,
    slice_name: str,
    flat_oob: bytes | None = None,
    sb_off: int | None = None,
) -> Ext2VolumeAccess:
    sb = sb_off if sb_off is not None else assembled.ext2_sb_offset
    if sb is None:
        sb = resolve_mountable_ext2_superblock_offset(assembled.slice_bytes) or _EXT2_SB0_OFF
    tl = _tl_slice_view(reg, slice_name)
    oob = flat_oob if flat_oob is not None else resolve_flat_oob(reg)
    return ext2_volume_access_from_assembly(
        slice_bytes=assembled.slice_bytes,
        sb_off=sb,
        read_model=assembled.read_model or "linear",
        reg_block_map=reg.attached_block_map,
        reg_session=reg.attached_logical_opentl_session,
        flat_oob=oob,
        virt_byte_start=int(tl.offset_bytes),
    )
#endregion
