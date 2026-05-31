"""
Mount handle for OpenTL logical NAND + BBM: virt→phys assembly without exposing ``tl_bbm`` wiring.

Library callers assembling ``opentla4`` should prefer :class:`~opentl.nand_pipeline.NandPipeline`
(``.extract_opentla4()``), :meth:`OpenTL.from_logical_with_flat_spare` when you have a logical image
+ flat spare only, :mod:`opentl.driver` for a **driver-only** import graph, or pass a
``verify`` callable to :meth:`~opentl.open_tl.OpenTL.extract_opentla4` when uImage checks are needed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from opentl.errors import VirtBlockHoleError
from opentl.spare_chain_replay import (
    iter_mode2_phys_chain_from_oob,
    oob_page_spare,
    spare_blob_matches_geo,
)
from opentl.tl_bbm import BlockMapBuild, is_hole_phys_block

# Disklabel slice for ``opentla4`` (see issue.md): start sector 0x180, length 0x3C080 sectors
OPENTLA4_START_SECTOR = 0x180
OPENTLA4_NUM_SECTORS = 0x3C080

#region kernel: 0x8020ac20
# read_dev_sector — 512B logical sectors in 2048B NAND pages (see reference/ghidra_boardfs_bbm_readpath.md)
KERNEL_LOGICAL_SECTOR_BYTES = 512
KERNEL_NAND_PAGE_BYTES = 2048
KERNEL_SECTORS_PER_NAND_PAGE = KERNEL_NAND_PAGE_BYTES // KERNEL_LOGICAL_SECTOR_BYTES
SECTOR_BYTES = KERNEL_LOGICAL_SECTOR_BYTES
#endregion


#region kernel_adjacent open_tl_layout_within_tl_erase_unit
# Host: NAND page / 512B sector split within one TL erase (uses KERNEL_* constants from read_dev_sector region above).
def layout_within_tl_erase_unit(offset_within_erase: int, *, erase_bytes: int) -> tuple[int, int, int, int]:
    """
    Within one TL erase unit (typically 128 KiB), split a byte offset the same way the kernel
    splits sector I/O across 2048-byte NAND pages.

    Returns ``(page_index, sector_within_page, byte_within_sector, offset_within_page)``.
    """
    if offset_within_erase < 0 or offset_within_erase >= erase_bytes:
        raise ValueError(f"offset_within_erase {offset_within_erase} not in [0, {erase_bytes})")
    page = offset_within_erase // KERNEL_NAND_PAGE_BYTES
    within_page = offset_within_erase - page * KERNEL_NAND_PAGE_BYTES
    sec_in_page = within_page // KERNEL_LOGICAL_SECTOR_BYTES
    byte_in_sec = within_page % KERNEL_LOGICAL_SECTOR_BYTES
    return page, sec_in_page, byte_in_sec, within_page


#endregion


@dataclass(frozen=True)
class ExtractResult:
    partition: str
    virt_byte_start: int
    virt_byte_length: int
    bytes_written: int
    dry_run: bool
    first_physical_abs_off: Optional[int] = None
    last_physical_abs_off: Optional[int] = None
    nand_logical_offset: int = 0
    verify_uimage: Optional[dict] = None
    ext2_magic_ok: bool = False
    ext2_magic_le16: int = 0


#region kernel: 0x80289170
# ntl_read_page — virt BBM + hole memset / memcpy analogue
def extract_virtual_disk_bytes(
    logical_prefix: bytes,
    m: BlockMapBuild,
    *,
    virt_byte_start: int,
    virt_byte_length: int,
    hole_fill_byte: int = 0,
) -> tuple[bytes, int | None, int | None]:
    """
    Copy a contiguous range from the **virtual** TL disk into a linear byte string.

    Uses **one primary phys index** per virtual block from ``m.virt_to_phys_block`` (no
    ``ntl_find_phy`` chain walk, no ``ntl_verify_read_phy_page``). For kernel-shaped
    substitute-on-verify-failure parity, see **Offline parity roadmap** in
    ``reference/ghidra_boardfs_bbm_readpath.md``.

    For virt blocks mapped to hole (**``0xffffffff``** in the BBM table), each output byte is set
    to ``hole_fill_byte & 0xff`` (default **0**), matching kernel ``ntl_read_page`` ``memset`` to
    zero on hole / failed spare walk (see repo ``reference/ghidra_boardfs_bbm_readpath.md``).
    """
    geo = m.geometry
    erase = geo.erase_bytes
    out = bytearray(virt_byte_length)
    first_phys: Optional[int] = None
    last_phys: Optional[int] = None

    virt_disk_bytes = geo.virt_blocks * erase
    if virt_byte_start + virt_byte_length > virt_disk_bytes:
        raise ValueError(
            f"slice past virtual disk end: {virt_byte_start + virt_byte_length} > {virt_disk_bytes}"
        )

    gvirt = int(virt_byte_start)
    end = gvirt + int(virt_byte_length)
    out_pos = 0
    fill = hole_fill_byte & 0xFF

    while gvirt < end:
        vb = gvirt // erase
        vo = gvirt % erase
        off_in_page = vo % KERNEL_NAND_PAGE_BYTES
        chunk = min(KERNEL_NAND_PAGE_BYTES - off_in_page, end - gvirt)

        if vb >= len(m.virt_to_phys_block):
            raise ValueError(f"virt block index {vb} out of map range")
        pb = m.virt_to_phys_block[vb]
        if is_hole_phys_block(pb):
            for i in range(chunk):
                out[out_pos + i] = fill
        else:
            phys = pb * erase + vo
            if phys < 0 or phys + chunk > len(logical_prefix):
                raise ValueError(
                    f"physical span [{phys:#x}, {phys + chunk:#x}) out of prefix len {len(logical_prefix)}"
                )
            out[out_pos : out_pos + chunk] = logical_prefix[phys : phys + chunk]
            if first_phys is None:
                first_phys = phys
            last_phys = phys + chunk - 1

        out_pos += chunk
        gvirt += chunk

    return bytes(out), first_phys, last_phys


#endregion


#region kernel_adjacent extract_virtual_disk_bytes_chain_aware
def extract_virtual_disk_bytes_chain_aware(
    logical_prefix: bytes,
    m: BlockMapBuild,
    *,
    flat_oob: bytes,
    virt_byte_start: int,
    virt_byte_length: int,
    hole_fill_byte: int = 0,
    page_size_is_0x200: bool = False,
    verify_page: Callable[[int, int, bytes, bytes], bool] | None = None,
) -> tuple[bytes, int | None, int | None]:
    """
    Virtual-disk extract with **NTL mode-2** chain replay (``ntl_read_page`` / ``ntl_find_phy``).

    Delegates to :func:`opentl.ntl_rw.extract_virt_byte_range_ntl_rw` — the same implementation as
    :func:`~opentl.ntl_rw.assemble_ntl_rw_slice`. Optional ``verify_page`` is applied **after**
    kernel spare/ECC gates as an extra reject-and-continue predicate (P2 xsum helpers compose here).

    ``page_size_is_0x200`` is accepted for API compatibility; chain slot layout uses the same
    large-page path as :mod:`opentl.ntl_rw`.
    """
    _ = page_size_is_0x200
    from opentl.ntl_rw import extract_virt_byte_range_ntl_rw

    return extract_virt_byte_range_ntl_rw(
        logical_prefix,
        m,
        flat_oob,
        virt_byte_start=int(virt_byte_start),
        virt_byte_length=int(virt_byte_length),
        hole_fill_byte=int(hole_fill_byte),
        accept_page=verify_page,
    )


#endregion


@dataclass(frozen=True, slots=True)
class NandPageSpanRow:
    """One contiguous span within a virtual TL disk range, aligned to a 2048-byte NAND page boundary."""

    virt_byte: int
    virt_byte_span: int
    virt_block: int
    offset_in_erase: int
    nand_page_index: int
    sector_in_page: int
    byte_in_sector: int
    hole: bool
    phys_byte: int | None


#region kernel: 0x80289170
# ntl_read_page — NAND page decomposition within TL erase unit
def virt_span_nand_page_rows(
    m: BlockMapBuild,
    *,
    logical_prefix_len: int,
    virt_byte_start: int,
    virt_byte_length: int,
    max_rows: int = 256,
) -> list[NandPageSpanRow]:
    """
    Decompose ``[virt_byte_start, virt_byte_start + virt_byte_length)`` into **2048-byte NAND page**
    steps (same page layout as :func:`layout_within_tl_erase_unit`).

    ``logical_prefix_len`` bounds valid physical byte indices (same convention as
    :func:`extract_virtual_disk_bytes`). Rows with ``hole=True`` have ``phys_byte=None``.
    """
    if virt_byte_length < 0:
        raise ValueError("virt_byte_length must be >= 0")
    if max_rows < 1:
        raise ValueError("max_rows must be >= 1")
    geo = m.geometry
    erase = int(geo.erase_bytes)
    virt_end = virt_byte_start + virt_byte_length
    virt_disk = int(geo.virt_blocks) * erase
    if virt_end > virt_disk:
        raise ValueError(f"virt range ends past virtual disk: {virt_end} > {virt_disk}")

    rows: list[NandPageSpanRow] = []
    gvirt = int(virt_byte_start)
    end = virt_end
    while gvirt < end and len(rows) < max_rows:
        vb = gvirt // erase
        vo = gvirt % erase
        if vb >= len(m.virt_to_phys_block):
            raise ValueError(f"virt block {vb} out of map range")
        pb = m.virt_to_phys_block[vb]
        hole = is_hole_phys_block(pb)
        page, sec_in_page, byte_in_sec, offset_within_page = layout_within_tl_erase_unit(vo, erase_bytes=erase)
        tail = erase - vo
        page_remain = KERNEL_NAND_PAGE_BYTES - (vo % KERNEL_NAND_PAGE_BYTES)
        chunk = min(page_remain, end - gvirt, tail)
        phys_first: int | None = None
        if not hole:
            phys_first = pb * erase + vo
            if phys_first < 0 or phys_first + chunk > logical_prefix_len:
                raise ValueError(
                    f"physical span [{phys_first:#x}, {phys_first + chunk:#x}) out of prefix len {logical_prefix_len}"
                )
        rows.append(
            NandPageSpanRow(
                virt_byte=gvirt,
                virt_byte_span=chunk,
                virt_block=vb,
                offset_in_erase=vo,
                nand_page_index=page,
                sector_in_page=sec_in_page,
                byte_in_sector=byte_in_sec,
                hole=hole,
                phys_byte=phys_first,
            )
        )
        gvirt += chunk
        if chunk <= 0:
            break
    return rows


#endregion


#region kernel_adjacent opentla4_ext2_magic_at_438
# Pace opentla4: ext2 s_magic le16 @ 0x438 within partition payload (see reference/opentl.md).
OPENTLA4_EXT2_MAGIC_OFF = 0x438
EXT2_LE16_MAGIC = 0xEF53


def partition_payload_ext2_magic(payload: bytes) -> tuple[bool, int]:
    """Return ``(matches_EF53, le16)`` for ext2 primary superblock ``s_magic`` at **0x438**."""
    off = OPENTLA4_EXT2_MAGIC_OFF
    if len(payload) < off + 2:
        return False, 0
    le16 = struct.unpack_from("<H", payload, off)[0]
    return le16 == EXT2_LE16_MAGIC, le16


def virt_global_byte_to_physical(
    m: BlockMapBuild,
    virt_global: int,
    *,
    logical_prefix_len: int,
) -> int:
    """Map a **virtual** byte index on the TL disk to a **physical** offset into the flat prefix."""
    geo = m.geometry
    erase = geo.erase_bytes
    if virt_global < 0:
        raise ValueError("virt_global must be non-negative")
    vb = virt_global // erase
    vo = virt_global % erase
    if vb >= len(m.virt_to_phys_block):
        raise ValueError("virt block out of map range")
    pb = m.virt_to_phys_block[vb]
    if is_hole_phys_block(pb):
        raise VirtBlockHoleError(
            f"virt byte {virt_global} lies in virt erase block {vb} (unmapped hole; no physical offset)"
        )
    phys = pb * erase + vo
    if phys < 0 or phys + 2 > logical_prefix_len:
        raise ValueError("physical offset out of logical prefix")
    return phys


def opentla4_ext2_magic_le(
    logical_prefix: bytes,
    m: BlockMapBuild,
) -> tuple[bool, int, int | None]:
    """Return whether ext2 **s_magic** (le16 **0xEF53**) is present at **0x438** within the opentla4 slice."""
    lim = len(logical_prefix)
    v0 = OPENTLA4_START_SECTOR * SECTOR_BYTES + OPENTLA4_EXT2_MAGIC_OFF
    try:
        phys = virt_global_byte_to_physical(m, v0, logical_prefix_len=lim)
    except (ValueError, VirtBlockHoleError):
        return False, 0, None
    b0 = logical_prefix[phys]
    b1 = logical_prefix[phys + 1]
    le16 = b0 | (b1 << 8)
    return le16 == EXT2_LE16_MAGIC, le16, phys
#endregion


def extract_result_as_dict(r: ExtractResult) -> dict:
    d = {
        "partition": r.partition,
        "virt_byte_start": r.virt_byte_start,
        "virt_byte_start_hex": f"{r.virt_byte_start:#x}",
        "virt_byte_length": r.virt_byte_length,
        "bytes_written": r.bytes_written,
        "dry_run": r.dry_run,
        "first_physical_abs_off": r.first_physical_abs_off,
        "last_physical_abs_off": r.last_physical_abs_off,
        "nand_logical_offset": r.nand_logical_offset,
    }
    if r.verify_uimage is not None:
        d["verify_uimage"] = r.verify_uimage
    d["ext2_magic_ok"] = r.ext2_magic_ok
    d["ext2_magic_le16"] = r.ext2_magic_le16
    d["ext2_magic_le16_hex"] = f"{r.ext2_magic_le16:#06x}"
    return d


class OpenTL:
    """
    Logical ``tlpart`` (or prefix) image + BBM map: read prefix slices and assemble ``opentla4``.

    Construct with ``block_map=``, or use :meth:`from_logical_with_flat_spare` / :meth:`from_flash_path_for_tl_mount`
    to build the map from spare (``kernel_replay_v1`` — same path as ``tl-mount``).

    ``nand_logical_offset`` defaults from the map when absent on direct construction.
    """

    __slots__ = (
        "_path",
        "_block_map",
        "_nand_default",
        "_logical_prefix_bytes_default",
        "_mount_material_tempdir",
    )

    def __init__(
        self,
        image_path: str | Path,
        *,
        block_map: BlockMapBuild,
        nand_logical_offset: int | None = None,
        logical_prefix_bytes: int | None = None,
        _mount_material_tempdir: Any = None,
    ) -> None:
        m = block_map

        self._path = Path(image_path)
        self._block_map = m
        self._nand_default = int(nand_logical_offset) if nand_logical_offset is not None else int(m.nand_logical_offset)
        self._logical_prefix_bytes_default = logical_prefix_bytes
        self._mount_material_tempdir = _mount_material_tempdir

    @classmethod
    def from_logical_with_flat_spare(
        cls,
        image_path: str | Path,
        *,
        spare_path: str | Path | None = None,
        spare_bytes: bytes | None = None,
        nand_logical_offset: int | None = None,
        logical_prefix_bytes: int | None = None,
    ) -> OpenTL:
        """
        Build ``block_map`` via :func:`~opentl.tl_mount.mount_flash_image` (``kernel_replay_v1``)
        and return a file-backed :class:`OpenTL`.

        Pass exactly one of ``spare_path`` or ``spare_bytes`` (non-empty). When ``nand_logical_offset``
        is ``None``, it is inferred from the logical image size (same rule as :class:`~opentl.nand_pipeline.NandPipeline`).
        """
        from opentl.tl_mount import mount_flash_image
        from opentl.tl_physical import infer_tl_mount_nand_logical_offset

        p = Path(image_path).expanduser().resolve()
        blob = spare_bytes
        if blob is None and spare_path is not None:
            blob = Path(spare_path).expanduser().resolve().read_bytes()
        off = int(nand_logical_offset) if nand_logical_offset is not None else infer_tl_mount_nand_logical_offset(
            logical_image_size=p.stat().st_size
        )
        bmap = mount_flash_image(
            p,
            logical_prefix_bytes=logical_prefix_bytes,
            nand_logical_offset=off,
            spare_bytes=blob,
        )
        return cls(
            p,
            block_map=bmap,
            nand_logical_offset=off,
            logical_prefix_bytes=logical_prefix_bytes,
            _mount_material_tempdir=None,
        )

    @classmethod
    def from_flash_path_for_tl_mount(
        cls,
        image_path: str | Path,
        *,
        spare_path: str | Path | None = None,
        nand_logical_offset: int | None = None,
        logical_prefix_bytes: int | None = None,
    ) -> OpenTL:
        """
        Build BBM from a dump path using :class:`unand.plane.LogicalPlane` (layout detect + OOB).

        For full-chip **INLINE** / **FLAT_TAIL** raw captures, materializes a temp logical-plane file
        and keeps it alive on this instance via ``_mount_material_tempdir``. For **LOGICAL_ONLY**,
        pass ``spare_path`` when OOB lives in a sidecar.

        When ``spare_path`` is omitted, spare bytes come from the file only when OOB is in-band
        (INLINE / FLAT_TAIL).
        """
        import tempfile

        from unand.plane import LogicalPlane

        from opentl.tl_mount import mount_flash_image
        from opentl.tl_physical import infer_tl_mount_nand_logical_offset

        src = Path(image_path).expanduser().resolve()
        plane = LogicalPlane.open_file(src)
        if spare_path is not None:
            spare_blob = Path(spare_path).expanduser().resolve().read_bytes()
        else:
            spare_blob = plane.flat_spare_bytes()

        td: tempfile.TemporaryDirectory | None = None
        if plane.has_flat_spare_in_file:
            td = tempfile.TemporaryDirectory()
            log_p = Path(td.name) / "logical_plane.bin"
            plane.materialize_logical_plane(log_p)
            mount_p = log_p
        else:
            mount_p = plane.backing_path

        off = (
            int(nand_logical_offset)
            if nand_logical_offset is not None
            else infer_tl_mount_nand_logical_offset(logical_image_size=mount_p.stat().st_size)
        )
        bmap = mount_flash_image(
            mount_p,
            logical_prefix_bytes=logical_prefix_bytes,
            nand_logical_offset=off,
            spare_bytes=spare_blob,
        )
        return cls(
            mount_p,
            block_map=bmap,
            nand_logical_offset=off,
            logical_prefix_bytes=logical_prefix_bytes,
            _mount_material_tempdir=td,
        )

    @property
    def image_path(self) -> Path:
        return self._path

    @property
    def block_map(self) -> BlockMapBuild:
        return self._block_map

    @property
    def nand_logical_offset(self) -> int:
        """Byte offset in ``image_path`` where the OpenTL logical prefix starts."""
        return self._nand_default

    @property
    def default_logical_prefix_bytes(self) -> int | None:
        """Optional cap passed to :meth:`read_logical_prefix` / extract when not overridden per call."""
        return self._logical_prefix_bytes_default

    def read_logical_prefix(
        self,
        *,
        nand_logical_offset: int | None = None,
        logical_prefix_bytes: int | None = None,
    ) -> bytes:
        """Read the linear logical prefix from ``image_path`` at ``nand_logical_offset``."""
        off = int(nand_logical_offset) if nand_logical_offset is not None else self._nand_default
        if off < 0:
            raise ValueError("nand_logical_offset must be >= 0")

        lim_src = logical_prefix_bytes if logical_prefix_bytes is not None else self._logical_prefix_bytes_default
        lim = lim_src if lim_src is not None else self._block_map.logical_prefix_bytes
        if lim <= 0:
            lim = self._path.stat().st_size - off

        sz = self._path.stat().st_size
        if off >= sz:
            raise ValueError(f"nand_logical_offset {off:#x} past end of image ({sz} bytes)")
        available = sz - off
        with self._path.open("rb") as f:
            f.seek(off)
            return f.read(min(available, lim))

    def nand_page_table(
        self,
        virt_byte_start: int,
        virt_byte_length: int,
        *,
        nand_logical_offset: int | None = None,
        logical_prefix_bytes: int | None = None,
        max_rows: int = 256,
    ) -> list[NandPageSpanRow]:
        """See :func:`virt_span_nand_page_rows` using this image's linear prefix."""
        off = int(nand_logical_offset) if nand_logical_offset is not None else self._nand_default
        prefix = self.read_logical_prefix(
            nand_logical_offset=off,
            logical_prefix_bytes=logical_prefix_bytes,
        )
        return virt_span_nand_page_rows(
            self._block_map,
            logical_prefix_len=len(prefix),
            virt_byte_start=virt_byte_start,
            virt_byte_length=virt_byte_length,
            max_rows=max_rows,
        )

    def assemble_ntl_rw_slice(
        self,
        *,
        virt_byte_start: int,
        virt_byte_length: int,
        flat_oob: bytes,
        slice_name: str = "opentla4",
    ):
        """
        NTL mode-2 per-page assembly (ptype 17 rw volumes).

        Returns :class:`~opentl.ntl_rw.AssembledNTLResult` or ``None`` when spare/geo mismatch.
        """
        from opentl.ntl_rw import assemble_ntl_rw_slice as _assemble_ntl_rw_slice

        off = self._nand_default
        prefix = self.read_logical_prefix(
            nand_logical_offset=off,
            logical_prefix_bytes=self._logical_prefix_bytes_default,
        )
        return _assemble_ntl_rw_slice(
            logical_prefix=prefix,
            block_map=self._block_map,
            flat_oob=flat_oob,
            virt_byte_start=virt_byte_start,
            virt_byte_length=virt_byte_length,
            slice_name=slice_name,
        )

    def extract_opentla4(
        self,
        *,
        out_path: Optional[str | Path] = None,
        dry_run: bool = False,
        nand_logical_offset: int | None = None,
        verify: Callable[[bytes], dict] | None = None,
    ) -> ExtractResult:
        """
        Build ``opentla4`` ext2 raw slice. Optional ``verify`` is called with the assembled payload
        (e.g. uImage compare — pass a ``verify`` callable that inspects the assembled bytes).
        """
        off = int(nand_logical_offset) if nand_logical_offset is not None else self._nand_default
        prefix = self.read_logical_prefix(nand_logical_offset=off, logical_prefix_bytes=self._logical_prefix_bytes_default)

        virt_start = OPENTLA4_START_SECTOR * SECTOR_BYTES
        virt_len = OPENTLA4_NUM_SECTORS * SECTOR_BYTES

        payload, first_p, last_p = extract_virtual_disk_bytes(
            prefix, self._block_map, virt_byte_start=virt_start, virt_byte_length=virt_len
        )
        ext2_ok, ext2_le = partition_payload_ext2_magic(payload)

        verify_out: Optional[dict] = None
        if verify is not None:
            verify_out = verify(payload)

        if not dry_run and out_path:
            Path(out_path).write_bytes(payload)

        return ExtractResult(
            partition="opentla4",
            virt_byte_start=virt_start,
            virt_byte_length=virt_len,
            bytes_written=0 if dry_run else len(payload),
            dry_run=dry_run,
            first_physical_abs_off=first_p,
            last_physical_abs_off=last_p,
            nand_logical_offset=off,
            verify_uimage=verify_out,
            ext2_magic_ok=ext2_ok,
            ext2_magic_le16=ext2_le,
        )


def extract_opentla4(
    image_path: str | Path,
    *,
    block_map: BlockMapBuild,
    out_path: Optional[str | Path] = None,
    dry_run: bool = False,
    logical_prefix_bytes: Optional[int] = None,
    nand_logical_offset: Optional[int] = None,
    verify: Callable[[bytes], dict] | None = None,
) -> ExtractResult:
    """
    Build ``opentla4`` ext2 raw slice from ``tlpart`` binary and a BBM map.

    Prefer :class:`~opentl.nand_pipeline.NandPipeline` (``.extract_opentla4()``), :meth:`OpenTL.from_logical_with_flat_spare`
    when building the map from spare, :mod:`opentl.driver`, or pass
    ``verify=`` when uImage verification is required.
    """
    ot = OpenTL(
        image_path,
        block_map=block_map,
        nand_logical_offset=nand_logical_offset,
        logical_prefix_bytes=logical_prefix_bytes,
    )
    return ot.extract_opentla4(
        out_path=out_path,
        dry_run=dry_run,
        nand_logical_offset=nand_logical_offset,
        verify=verify,
    )


__all__ = [
    "EXT2_LE16_MAGIC",
    "ExtractResult",
    "KERNEL_SECTORS_PER_NAND_PAGE",
    "NandPageSpanRow",
    "OpenTL",
    "OPENTLA4_EXT2_MAGIC_OFF",
    "OPENTLA4_NUM_SECTORS",
    "OPENTLA4_START_SECTOR",
    "SECTOR_BYTES",
    "extract_opentla4",
    "extract_result_as_dict",
    "extract_virtual_disk_bytes",
    "extract_virtual_disk_bytes_chain_aware",
    "layout_within_tl_erase_unit",
    "opentla4_ext2_magic_le",
    "partition_payload_ext2_magic",
    "virt_global_byte_to_physical",
    "virt_span_nand_page_rows",
]
