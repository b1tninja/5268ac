"""
OpenTL **virt→physical** erase-block map types and JSON I/O for captured virt→phys tables.

There are **no** heuristic or identity-map builders in this module. The kernel fills an
8-byte table at ``*(remap + 8)`` during ``ntl_mount`` from NAND spare-chain walks — see
``reference/opentl_kernel_ghidra.md`` §5–11 and ``reference/ghidra_boardfs_bbm_readpath.md``.
Offline assembly of that table is :func:`opentl.bbm_kernel_replay.build_block_map_from_kernel_mount_replay`
(**``kernel_replay_v1``** — full flat spare scan; see ``reference/ntl_mount_virt_table_fill.md``).

**Loading maps:** use :func:`parse_block_map_dict` / :meth:`BlockMapBuild.from_dict` on existing
JSON whose top-level ``schema`` matches :data:`SCHEMA_V1`, or construct :class:`BlockMapBuild` explicitly for tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from opentl.errors import VirtBlockHoleError

#region kernel: 0x80289610
# ntl_initialize_memory (+ FUN_802893a0 remap RAM); virt table base *(remap+8); §11 opentl_kernel_ghidra.md
TL_ERASE_BYTES_DEFAULT = 131072  # 128 KiB
TL_RAW_BLOCKS_DEFAULT = 1012
TL_VIRT_BLOCKS_DEFAULT = 982
TL_LOGICAL_PREFIX_DEFAULT = TL_RAW_BLOCKS_DEFAULT * TL_ERASE_BYTES_DEFAULT  # 132644864

TL_PHYS_BLOCK_HOLE: int = 0xFFFFFFFF


def is_hole_phys_block(pb: int) -> bool:
    """True if ``pb`` is the kernel unmapped / hole sentinel (no NAND read for that virt erase)."""
    return pb == TL_PHYS_BLOCK_HOLE


#endregion


def validate_virt_to_phys_block_entries(virt_to_phys: list[int], geo: TLGeometry) -> None:
    """Ensure each entry is either :data:`TL_PHYS_BLOCK_HOLE` or a valid physical block index."""
    rb = geo.raw_blocks
    for i, pb in enumerate(virt_to_phys):
        if is_hole_phys_block(pb):
            if pb != TL_PHYS_BLOCK_HOLE:
                raise ValueError(
                    f"virt_to_phys_block[{i}] must be exactly {TL_PHYS_BLOCK_HOLE:#x} for a hole, got {pb}"
                )
            continue
        if pb < 0 or pb >= rb:
            raise ValueError(f"virt_to_phys_block[{i}] physical {pb} out of range for raw_blocks={rb}")


# Historical ``schema`` string on disk for virt→phys map JSON (changing breaks existing files).
SCHEMA_V1 = "opentl_tl_bbm_v1"


@dataclass(frozen=True)
class TLGeometry:
    erase_bytes: int = TL_ERASE_BYTES_DEFAULT
    raw_blocks: int = TL_RAW_BLOCKS_DEFAULT
    virt_blocks: int = TL_VIRT_BLOCKS_DEFAULT
    stats_blocks: int = 1
    bb_reserved: int = 30
    head_pages: int = 1
    media_pages: int = 64768
    spares_field: int = 85
    cap_sectors: int = 251132
    geometry_wasted_sectors: int = 252
    sectors_per_unit: int = 256


@dataclass
class BlockMapBuild:
    """
    Virt→phys erase-block map (kernel-filled table shape; load via JSON or explicit construction).

    **Read-path parity:**

    - **Primary only:** :class:`BlockMapBuild` + logical prefix → one physical erase index per
      virtual block via ``virt_to_phys_block`` (no spare-chain walk). Used by
      :func:`opentl.open_tl.extract_virtual_disk_bytes` and primary :class:`~opentl.virt_page_table.VirtNandPageTable`.
    - **Chain-aware:** same map + **flat spare** (OOB) → use :func:`opentl.open_tl.extract_virtual_disk_bytes_chain_aware`, or :meth:`opentl.logical_opentl_session.LogicalOpenTLSession.apply_chain_aware_flat_oob` / ``set_chain_aware_virt_reads`` then :meth:`~opentl.logical_opentl_session.LogicalOpenTLSession.extract_virtual_disk_bytes_chain_aware_path`. Optional :mod:`opentl.spare_verify` predicates implement **P2** spare gates (e.g. xsum).

    A separate ``VirtBlockReadModel`` type is intentionally **not** required — the split is
    **(BlockMapBuild, optional flat OOB, optional verify_page)** as documented above.
    """

    geometry: TLGeometry
    mode: str
    logical_prefix_bytes: int
    virt_to_phys_block: list[int]
    stats_physical_block_index: Optional[int] = None
    heuristic_score: Optional[float] = None
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    source_path: Optional[str] = None
    input_sha256_prefix: Optional[str] = None
    nand_logical_offset: int = 0
    stats_on_disk: Optional[dict[str, Any]] = None


def geometry_boot_trace_dict(g: TLGeometry) -> dict[str, Any]:
    """Constants corroborating fwupgrade.txt OpenTL / nand_geom printks (research metadata)."""
    return {
        "head_pages": g.head_pages,
        "media_pages": g.media_pages,
        "spares_field": g.spares_field,
        "cap_sectors": g.cap_sectors,
        "geometry_wasted_sectors": g.geometry_wasted_sectors,
        "sectors_per_unit": g.sectors_per_unit,
    }


def block_map_to_json_dict(b: BlockMapBuild) -> dict[str, Any]:
    return {
        "schema": SCHEMA_V1,
        "mode": b.mode,
        "geometry": {
            "erase_bytes": b.geometry.erase_bytes,
            "raw_blocks": b.geometry.raw_blocks,
            "virt_blocks": b.geometry.virt_blocks,
            "stats_blocks": b.geometry.stats_blocks,
            "bb_reserved": b.geometry.bb_reserved,
            "head_pages": b.geometry.head_pages,
            "media_pages": b.geometry.media_pages,
            "spares_field": b.geometry.spares_field,
            "cap_sectors": b.geometry.cap_sectors,
            "geometry_wasted_sectors": b.geometry.geometry_wasted_sectors,
            "sectors_per_unit": b.geometry.sectors_per_unit,
        },
        "boot_trace_invariants": geometry_boot_trace_dict(b.geometry),
        "logical_prefix_bytes": b.logical_prefix_bytes,
        "virt_to_phys_block": b.virt_to_phys_block,
        "stats_physical_block_index": b.stats_physical_block_index,
        "warnings": list(b.warnings),
        "notes": list(b.notes),
        "source_path": b.source_path,
        "input_sha256_logical_prefix": b.input_sha256_prefix,
        "nand_logical_offset": b.nand_logical_offset,
        "stats_on_disk": b.stats_on_disk,
    }


def parse_block_map_dict(data: dict[str, Any]) -> BlockMapBuild:
    """
    Construct :class:`BlockMapBuild` from a map dictionary (``schema`` must equal :data:`SCHEMA_V1`).

    Prefer this (or :meth:`BlockMapBuild.from_dict`) when the payload is already in memory.
    """
    if data.get("schema") != SCHEMA_V1:
        raise ValueError(f"unsupported map schema: {data.get('schema')}")
    g = data["geometry"]
    geo = TLGeometry(
        erase_bytes=int(g["erase_bytes"]),
        raw_blocks=int(g["raw_blocks"]),
        virt_blocks=int(g["virt_blocks"]),
        stats_blocks=int(g.get("stats_blocks", 1)),
        bb_reserved=int(g.get("bb_reserved", 30)),
        head_pages=int(g.get("head_pages", 1)),
        media_pages=int(g.get("media_pages", 64768)),
        spares_field=int(g.get("spares_field", 85)),
        cap_sectors=int(g.get("cap_sectors", 251132)),
        geometry_wasted_sectors=int(g.get("geometry_wasted_sectors", 252)),
        sectors_per_unit=int(g.get("sectors_per_unit", 256)),
    )
    virt_to_phys = [int(x) for x in data["virt_to_phys_block"]]
    if len(virt_to_phys) != geo.virt_blocks:
        raise ValueError("virt_to_phys_block length mismatch vs geometry.virt_blocks")
    validate_virt_to_phys_block_entries(virt_to_phys, geo)
    stats_idx = data.get("stats_physical_block_index")
    return BlockMapBuild(
        geometry=geo,
        mode=str(data.get("mode", "imported")),
        logical_prefix_bytes=int(data.get("logical_prefix_bytes", 0)),
        virt_to_phys_block=virt_to_phys,
        stats_physical_block_index=int(stats_idx) if stats_idx is not None else None,
        heuristic_score=data.get("heuristic_score"),
        warnings=list(data.get("warnings") or []),
        notes=list(data.get("notes") or []),
        source_path=data.get("source_path"),
        input_sha256_prefix=data.get("input_sha256_logical_prefix"),
        nand_logical_offset=int(data.get("nand_logical_offset", 0)),
        stats_on_disk=data.get("stats_on_disk"),
    )


def _attach_block_map_build_methods() -> None:
    """Bind JSON interop helpers onto :class:`BlockMapBuild` (defined above)."""

    def to_dict(self: BlockMapBuild) -> dict[str, Any]:
        """Map dictionary (same shape as :func:`block_map_to_json_dict`; ``schema`` is :data:`SCHEMA_V1`)."""
        return block_map_to_json_dict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BlockMapBuild:
        """Parse map dict; equivalent to :func:`parse_block_map_dict`."""
        return parse_block_map_dict(data)

    def virt_to_phys_block_index(self: BlockMapBuild, virt_block: int) -> int:
        """Physical erase-block index for virtual block ``virt_block`` (raises if unmapped hole)."""
        if virt_block < 0 or virt_block >= len(self.virt_to_phys_block):
            raise IndexError(f"virt_block {virt_block} out of range for map length {len(self.virt_to_phys_block)}")
        pb = self.virt_to_phys_block[virt_block]
        if is_hole_phys_block(pb):
            raise VirtBlockHoleError(
                f"virt_block {virt_block} is an unmapped hole (phys_unit 0xffffffff); no physical erase index"
            )
        return pb

    def phys_block_index_or_hole(self: BlockMapBuild, virt_block: int) -> int | None:
        """Physical erase-block index, or ``None`` if this virt slot is a kernel-style hole."""
        if virt_block < 0 or virt_block >= len(self.virt_to_phys_block):
            raise IndexError(f"virt_block {virt_block} out of range for map length {len(self.virt_to_phys_block)}")
        pb = self.virt_to_phys_block[virt_block]
        return None if is_hole_phys_block(pb) else pb

    BlockMapBuild.to_dict = to_dict  # type: ignore[method-assign, assignment]
    BlockMapBuild.from_dict = from_dict  # type: ignore[method-assign, assignment]
    BlockMapBuild.virt_to_phys_block_index = virt_to_phys_block_index  # type: ignore[method-assign, assignment]
    BlockMapBuild.phys_block_index_or_hole = phys_block_index_or_hole  # type: ignore[method-assign, assignment]


_attach_block_map_build_methods()
