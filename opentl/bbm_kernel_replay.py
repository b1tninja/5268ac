"""
Kernel-faithful virt→phys BBM: replay ``ntl_mount`` table fill at ``*(remap + 8)``.

The Linux OpenTL driver allocates the remap object, points the **8-byte-per-slot** virt table
through ``*(remap + 8)``, initializes slots to ``0xffffffff``, then fills live mappings from
**NAND spare-chain** walks — not from a dense array at a fixed offset inside ``tlpart.bin``.

Offline implementation: :func:`build_block_map_from_kernel_mount_replay` (**``kernel_replay_v1``**)
scans a **full flat spare** stream and derives ``virt_to_phys_block`` from OpenTL-tagged,
xsum-valid spare rows (see :doc:`reference/ntl_mount_virt_table_fill.md`).

For a captured kernel table JSON, use :class:`~opentl.tl_bbm.BlockMapBuild`.from_dict
(``schema`` = :data:`~opentl.tl_bbm.SCHEMA_V1`).
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path

from opentl.spare_chain_replay import oob_page_spare, spare_blob_matches_geo, tl_geometry_from_flat_spare
from opentl.spare_layout import parse_spare, xsum_matches
from opentl.tl_bbm import (
    TL_PHYS_BLOCK_HOLE,
    BlockMapBuild,
    TLGeometry,
    validate_virt_to_phys_block_entries,
)

_PAGES_PER_ERASE = 64


def _input_sha256_prefix(path: Path, *, max_read: int = 4096) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        h.update(f.read(max_read))
    return h.hexdigest()[:16]


def _pick_phys_for_virt(rows: list[tuple[int, int, bool]]) -> tuple[int, bool]:
    """
    Given candidates (phys_block, page_in_erase, mirror_duplicate_chain_flag), return
    (chosen_phys, had_phys_collision).

    When several phys blocks tag the same virt, prefer the erase unit with the **most**
    tagged spare rows (payload block). Otherwise tie-break: no mirror bit, lower page,
    lower phys (``spare_inspect`` / ``SpareRecord.mirror_duplicate_chain_flag``).
    """
    uniq_pb = {r[0] for r in rows}
    collision = len(uniq_pb) > 1
    if collision:
        by_pb: dict[int, list[tuple[int, int, bool]]] = defaultdict(list)
        for pb, pg, mir in rows:
            by_pb[pb].append((pb, pg, mir))
        best_pb = max(by_pb.keys(), key=lambda pb: len(by_pb[pb]))
        sub = by_pb[best_pb]
        sub_sorted = sorted(sub, key=lambda r: (1 if r[2] else 0, r[1], r[0]))
        return sub_sorted[0][0], True
    rows_sorted = sorted(rows, key=lambda r: (1 if r[2] else 0, r[1], r[0]))
    return rows_sorted[0][0], collision


def _virt_table_from_flat_spare(blob: bytes, geo: TLGeometry) -> tuple[list[int], list[str], list[str]]:
    """
    Build ``virt_to_phys_block`` (length ``geo.virt_blocks``) from full-chip flat spare.

    Returns ``(table, notes, warnings)``.
    """
    notes: list[str] = []
    warnings: list[str] = []
    cand: dict[int, list[tuple[int, int, bool]]] = defaultdict(list)

    for pb in range(geo.raw_blocks):
        for pg in range(_PAGES_PER_ERASE):
            sp = oob_page_spare(blob, geo, pb, pg)
            rec = parse_spare(sp)
            if not rec.kernel_tagged_like():
                continue
            if not xsum_matches(sp, large_page=True):
                continue
            if not rec.virt_u32_meaningful(large_page=True):
                continue
            v = rec.virt_u32(large_page=True)
            if v < 0 or v >= geo.virt_blocks:
                continue
            cand[v].append((pb, pg, rec.mirror_duplicate_chain_flag))

    table = [TL_PHYS_BLOCK_HOLE] * geo.virt_blocks
    collisions = 0
    for v in range(geo.virt_blocks):
        rows = cand.get(v)
        if not rows:
            continue
        pb, coll = _pick_phys_for_virt(rows)
        table[v] = pb
        if coll:
            collisions += 1

    if collisions:
        warnings.append(
            f"virt slots with multiple distinct phys in spare scan: {collisions} "
            f"(resolved with mirror/page/phys tie-break; see reference/ntl_mount_virt_table_fill.md)"
        )

    n_mapped = sum(1 for x in table if x != TL_PHYS_BLOCK_HOLE)
    n_holes = geo.virt_blocks - n_mapped
    notes.append(
        f"kernel_replay_v1: mapped {n_mapped} / {geo.virt_blocks} virt slots from spare "
        f"({n_holes} holes); scan raw_blocks={geo.raw_blocks} pages_per_erase={_PAGES_PER_ERASE}"
    )

    if n_mapped == 0:
        raise ValueError(
            "kernel BBM replay found no kernel-tagged xsum-valid spare rows with in-range virt_u32; "
            "check spare capture alignment or supply BlockMapBuild.from_dict JSON"
        )

    validate_virt_to_phys_block_entries(table, geo)
    return table, notes, warnings


#region kernel: 0x8028ac28
# ntl_mount — symtab ~0x8028adac; legacy FUN export; see reference/ntl_mount_virt_table_fill.md
def build_block_map_from_kernel_mount_replay(
    image_path: str | Path,
    *,
    logical_prefix_bytes: int | None = None,
    spare_path: str | Path | None = None,
    spare_bytes: bytes | None = None,
    nand_logical_offset: int = 0,
    geometry: TLGeometry | None = None,
) -> BlockMapBuild:
    """
    Build a :class:`~opentl.tl_bbm.BlockMapBuild` by offline replay of the virt table at
    ``*(remap+8)`` from a **full flat spare** image (``kernel_replay_v1``).

    **Requires** non-empty spare bytes whose length matches ``geometry.raw_blocks`` erase bands
    × 64 pages × 64-byte spare per page. Pass ``--spare`` from ``tl-mount`` / nand translate output.

    Raises :class:`ValueError` if spare is missing, wrong length, or contains no mappable
    virt observations.
    """
    img = Path(image_path).expanduser().resolve()
    blob: bytes | None = spare_bytes
    if blob is None and spare_path is not None:
        blob = Path(spare_path).expanduser().resolve().read_bytes()
    if blob is None or len(blob) == 0:
        raise ValueError(
            "kernel BBM replay requires non-empty flat spare_bytes or readable spare_path "
            "(full-chip spare stream matching TLGeometry.raw_blocks)"
        )

    geo = geometry if geometry is not None else tl_geometry_from_flat_spare(blob)
    if not spare_blob_matches_geo(blob, geo):
        expected = geo.raw_blocks * _PAGES_PER_ERASE * 64  # PACE 64 B spare; see spare_chain_replay
        raise ValueError(
            f"spare length {len(blob)} does not match geometry: expected {expected} bytes "
            f"(raw_blocks={geo.raw_blocks} × {_PAGES_PER_ERASE} × 64)"
        )

    table, notes, warnings = _virt_table_from_flat_spare(blob, geo)
    prefix_len = int(logical_prefix_bytes or 0)
    sha_pre = _input_sha256_prefix(img) if img.is_file() else ""

    return BlockMapBuild(
        geometry=geo,
        mode="kernel_replay_v1",
        logical_prefix_bytes=prefix_len,
        virt_to_phys_block=table,
        stats_physical_block_index=None,
        warnings=warnings,
        notes=notes,
        source_path=str(img),
        input_sha256_prefix=sha_pre or None,
        nand_logical_offset=int(nand_logical_offset),
    )


#endregion
