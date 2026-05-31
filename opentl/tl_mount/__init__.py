"""
Offline **virt→phys** helpers for OpenTL logical-plane images.

Kernel (att-5268 ``ntl_read_page``): virtual block *i* maps through **``*(remap+8) + i*8``** —
populated during **``ntl_mount``** / **``ntl_load_stat_table``** from spare chains, not from
prefix-side alternate mapping strategies.

:func:`mount_flash_image` derives :class:`~opentl.tl_bbm.TLGeometry` from flat spare when present,
reads the logical prefix (cap from spare ``raw_blocks×erase`` when no explicit cap), then delegates to
:func:`opentl.bbm_kernel_replay.build_block_map_from_kernel_mount_replay` (mode **kernel_replay_v1**:
full flat spare required). Raises :class:`ValueError` if spare is missing, wrong size, or has no
mappable tagged rows.

CLI: ``python -m opentl tl-mount …`` (``python -m opentl.tl_mount`` is equivalent).

**Ghidra anchors:** this package’s Python sources use ``#region kernel: 0x…`` / ``#endregion`` comments
tied to MIPS load addresses for ``ntl_read_page``, ``ntl_mount``, and related paths; see
``reference/kernel_python_regions.md``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opentl.tl_bbm import BlockMapBuild

from opentl.spare_chain_replay import tl_geometry_from_flat_spare
from opentl.tl_bbm import TL_LOGICAL_PREFIX_DEFAULT, TLGeometry
from opentl.tl_physical import infer_tl_mount_nand_logical_offset

KERNEL_READ_PAGE_NOTE = (
    "Kernel ntl_read_page: entry at *(remap+8)+virt*8 (see ntl_mount / ntl_load_stat_table); "
    "offline kernel_replay_v1 fills uint32 phys indices from flat spare (see reference/ntl_mount_virt_table_fill.md)."
)


#region kernel_adjacent tl_mount_prefix_read (resolve offset + logical prefix bytes for ntl_mount replay)
def resolve_nand_logical_offset_for_mount(
    flash_file: str | Path,
    nand_logical_offset: int | None,
) -> int:
    """
    Resolve ``nand_logical_offset`` for the tl-mount CLI (``python -m opentl tl-mount``).

    Same rule as :func:`~opentl.tl_physical.infer_tl_mount_nand_logical_offset` when ``None``.
    """
    if nand_logical_offset is not None:
        return int(nand_logical_offset)
    sz = Path(flash_file).expanduser().resolve().stat().st_size
    return infer_tl_mount_nand_logical_offset(logical_image_size=sz)


def _read_logical_prefix(
    flash_file: str | Path,
    *,
    nand_logical_offset: int,
    logical_prefix_bytes: int | None,
) -> bytes:
    p = Path(flash_file).expanduser().resolve()
    sz = p.stat().st_size
    if nand_logical_offset < 0 or nand_logical_offset >= sz:
        raise ValueError(f"nand_logical_offset {nand_logical_offset:#x} past file end ({sz} B)")
    avail = sz - nand_logical_offset
    lim = (
        logical_prefix_bytes
        if logical_prefix_bytes is not None
        else min(avail, TL_LOGICAL_PREFIX_DEFAULT)
    )
    lim = min(int(lim), avail)
    with p.open("rb") as f:
        f.seek(nand_logical_offset)
        return f.read(lim)


def _read_logical_prefix_from_bytes(
    logical: bytes,
    *,
    nand_logical_offset: int,
    logical_prefix_bytes: int | None,
) -> bytes:
    sz = len(logical)
    if nand_logical_offset < 0 or nand_logical_offset >= sz:
        raise ValueError(f"nand_logical_offset {nand_logical_offset:#x} past buffer end ({sz} B)")
    avail = sz - nand_logical_offset
    lim = (
        logical_prefix_bytes
        if logical_prefix_bytes is not None
        else min(avail, TL_LOGICAL_PREFIX_DEFAULT)
    )
    lim = min(int(lim), avail)
    return logical[nand_logical_offset : nand_logical_offset + lim]


def _mount_block_map_from_prefix(
    prefix: bytes,
    *,
    flash_file: str | Path | None,
    source_path: str,
    nand_logical_offset: int,
    spare_bytes: bytes | None,
    replay_mode: str,
    notes: list[str],
    warnings: list[str],
    geo: TLGeometry,
) -> "BlockMapBuild":
    from opentl.bbm_kernel_replay import build_block_map_from_kernel_mount_replay
    from opentl.tl_mount.replay import build_virt_to_phys_from_mount_replay

    if replay_mode == "kernel_replay_v2_chain_tail":
        if flash_file is None:
            raise ValueError("kernel_replay_v2_chain_tail requires flash_file")
        bmap = build_block_map_from_kernel_mount_replay(
            flash_file,
            logical_prefix_bytes=len(prefix),
            spare_bytes=spare_bytes,
            nand_logical_offset=int(nand_logical_offset),
            geometry=geo,
            collision_strategy="v2_chain_tail",
        )
    elif replay_mode == "mount_v2":
        if spare_bytes is None:
            raise ValueError("mount_v2 replay requires non-empty spare_bytes")
        table, n2, w2, _debug = build_virt_to_phys_from_mount_replay(spare_bytes, geo)
        from opentl.tl_bbm import BlockMapBuild

        bmap = BlockMapBuild(
            geometry=geo,
            mode="kernel_replay_mount_v2",
            logical_prefix_bytes=len(prefix),
            virt_to_phys_block=table,
            stats_physical_block_index=None,
            warnings=w2,
            notes=n2,
            source_path=source_path,
            nand_logical_offset=int(nand_logical_offset),
        )
    else:
        if flash_file is None:
            raise ValueError(f"{replay_mode!r} replay requires flash_file")
        bmap = build_block_map_from_kernel_mount_replay(
            flash_file,
            logical_prefix_bytes=len(prefix),
            spare_bytes=spare_bytes,
            nand_logical_offset=int(nand_logical_offset),
            geometry=geo,
            collision_strategy="v2_chain_tail",
        )
    bmap.notes.extend(notes)
    bmap.warnings.extend(warnings)
    return bmap


def _prepare_mount_geometry(
    spare_bytes: bytes | None,
) -> tuple[TLGeometry, bool, list[str], list[str], int | None]:
    notes: list[str] = []
    warnings: list[str] = []
    geo = TLGeometry()
    spare_geom_ok = False
    effective_prefix_lim: int | None = None
    if spare_bytes is not None and len(spare_bytes) > 0:
        try:
            geo = tl_geometry_from_flat_spare(spare_bytes)
            spare_geom_ok = True
            notes.append(
                f"geometry from flat spare: raw_blocks={geo.raw_blocks} virt_blocks={geo.virt_blocks}"
            )
            effective_prefix_lim = int(geo.raw_blocks) * int(geo.erase_bytes)
            notes.append(
                f"prefix read cap from spare geometry: {effective_prefix_lim} B (raw_blocks×erase)"
            )
        except ValueError as e:
            warnings.append(f"flat spare geometry: {e}")
    return geo, spare_geom_ok, notes, warnings, effective_prefix_lim


#endregion


#region kernel: 0x8028ac28
# ntl_mount — symtab ~0x8028adac; see reference/ntl_mount_virt_table_fill.md + ghidra_boardfs_bbm_readpath.md
def mount_flash_image(
    flash_file: str | Path,
    *,
    logical_prefix_bytes: int | None,
    nand_logical_offset: int,
    spare_bytes: bytes | None,
    replay_mode: str = "mount_v2",
) -> "BlockMapBuild":
    """
    Attempt kernel-faithful :class:`~opentl.tl_bbm.BlockMapBuild` from ``flash_file``.

    Non-empty ``spare_bytes`` set :class:`~opentl.tl_bbm.TLGeometry` from flat spare length and
    drive :mod:`opentl.bbm_kernel_replay` **kernel_replay_v1** virt→phys table construction.

    When ``logical_prefix_bytes`` is ``None`` and spare-derived geometry succeeds, the logical
    prefix read is capped at ``raw_blocks * erase_bytes`` (full linear chip layout for that spare
    geometry), not :data:`~opentl.tl_bbm.TL_LOGICAL_PREFIX_DEFAULT` alone. The historical default
    (1012 erase blocks) is shorter than a full 1024-block PACE logical plane, which made
    ``virt→phys`` assembly index past ``len(prefix)`` on full dumps.
    """
    geo, spare_geom_ok, notes, warnings, spare_prefix_lim = _prepare_mount_geometry(spare_bytes)
    effective_prefix_lim = logical_prefix_bytes
    if effective_prefix_lim is None and spare_geom_ok:
        effective_prefix_lim = spare_prefix_lim

    p = Path(flash_file).expanduser().resolve()
    prefix = _read_logical_prefix(
        p,
        nand_logical_offset=nand_logical_offset,
        logical_prefix_bytes=effective_prefix_lim,
    )
    return _mount_block_map_from_prefix(
        prefix,
        flash_file=p,
        source_path=str(p.resolve()),
        nand_logical_offset=nand_logical_offset,
        spare_bytes=spare_bytes,
        replay_mode=replay_mode,
        notes=notes,
        warnings=warnings,
        geo=geo,
    )


def mount_flash_image_from_bytes(
    logical: bytes,
    *,
    logical_prefix_bytes: int | None = None,
    nand_logical_offset: int = 0,
    spare_bytes: bytes | None = None,
    replay_mode: str = "mount_v2",
) -> "BlockMapBuild":
    """
    Same as :func:`mount_flash_image` but the logical plane is already in memory.

    Avoids writing a temp logical-plane file during physical NAND bootstrap.
    """
    geo, spare_geom_ok, notes, warnings, spare_prefix_lim = _prepare_mount_geometry(spare_bytes)
    effective_prefix_lim = logical_prefix_bytes
    if effective_prefix_lim is None and spare_geom_ok:
        effective_prefix_lim = spare_prefix_lim

    prefix = _read_logical_prefix_from_bytes(
        logical,
        nand_logical_offset=nand_logical_offset,
        logical_prefix_bytes=effective_prefix_lim,
    )
    return _mount_block_map_from_prefix(
        prefix,
        flash_file=None,
        source_path="<memory>",
        nand_logical_offset=nand_logical_offset,
        spare_bytes=spare_bytes,
        replay_mode=replay_mode,
        notes=notes,
        warnings=warnings,
        geo=geo,
    )


#endregion


__all__ = [
    "KERNEL_READ_PAGE_NOTE",
    "mount_flash_image",
    "mount_flash_image_from_bytes",
    "resolve_nand_logical_offset_for_mount",
]
