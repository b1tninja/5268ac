"""Registry: flash image + TL disklabel enumeration + block slice resolution."""

from __future__ import annotations

import os
from dataclasses import InitVar, dataclass, field
from pathlib import Path

from binwalker.extract.flash_layout import FlashImage, MtdPartition

from boardfs.block import AssembledBlockDev, BlockDev, BlockSlice
from boardfs.mount_spec import parse_root_from_cmdline
from boardfs.ubi_cmdline import UbiMtdAttachSpec, iter_ubi_mtd_attach_specs
from opentl.logical_opentl_session import LogicalOpenTLSession
from opentl.open_tl import OpenTL
from opentl.tl_bbm import BlockMapBuild
from opentl.tldisk import (
    TLDiskEnumerationResult,
    TLDiskSlice,
    buffer_has_tl_disklabel_anchor,
    enumerate_tl_slices_from_tlpart_mtd_bytes,
)


#region kernel_adjacent read_linear_plane_prefix (BlockMapBuild physical indices vs mtdparts plane)
def read_linear_plane_prefix(flash: FlashImage, max_bytes: int) -> bytes:
    """
    Read the first ``min(file_size, max_bytes)`` bytes of the flash backing from **linear offset 0**.

    :class:`~opentl.logical_opentl_session.LogicalOpenTLSession` (BBM replay) indexes this prefix
    the same way the kernel-built map does (logical plane byte 0 = prefix byte 0).
    """
    n = max(0, int(max_bytes))
    if n == 0:
        return b""
    li = flash.logical_image
    if li is not None:
        return bytes(li[: min(len(li), n)])
    p = Path(flash.path)
    sz = os.path.getsize(p)
    with p.open("rb") as f:
        return f.read(min(sz, n))


#endregion


_TLPART_BBM_SCAN_CAP_BYTES = 2 * 1024 * 1024


def _tl_scan_cap_for_flash(flash: FlashImage) -> int:
    """Bytes of primary virt stream to materialize at BBM attach (disklabel anchor, not full virt disk)."""
    try:
        tlp = flash.read_partition("tlpart")
        return min(len(tlp), _TLPART_BBM_SCAN_CAP_BYTES)
    except KeyError:
        return _TLPART_BBM_SCAN_CAP_BYTES


@dataclass
class FsRegistry:
    """
    Holds a :class:`~binwalker.extract.flash_layout.FlashImage` and lazily enumerates TL slices
    inside ``tlpart`` via :func:`opentl.tldisk.enumerate_tl_slices_from_tlpart_mtd_bytes` (kernel
    TL superblock prefix + disklabel). Caches ``mtd_skip`` so :meth:`block_dev_for_tl_slice` maps
    virtual slice offsets to bytes correctly. A failed first parse is cached and re-raised on
    subsequent calls without re-reading or re-parsing ``tlpart``.

    When :attr:`tlpart_tl_scan_bytes` is set manually, TL disklabel enumeration uses that buffer
    instead of :meth:`~binwalker.extract.flash_layout.FlashImage.read_partition`.

    When :meth:`attach_open_tl_bbm` or :meth:`attach_open_tl` has been called with a
    :class:`~opentl.tl_bbm.BlockMapBuild` or :class:`~opentl.open_tl.OpenTL`,
    ``tlpart_tl_scan_bytes`` is filled from :meth:`LogicalOpenTLSession.virtual_tl_byte_stream`
    (primary BBM assembly) and :meth:`block_dev_for_tl_slice` returns
    :class:`~boardfs.block.AssembledBlockDev` payloads from the same OpenTL session.

    The façade for BBM-backed reads is :attr:`attached_logical_opentl_session`;
    boardfs orchestrates flash and disklabel probing only — it does not implement virt→phys replay.

    The same attachment can be done at construction with ``block_map=`` and optional
    ``bbm_linear_prefix=`` (see :meth:`attach_open_tl_bbm`).
    """

    flash: FlashImage
    cmdline: str
    block_map: InitVar[BlockMapBuild | None] = None
    bbm_linear_prefix: InitVar[bytes | None] = None
    _tl_enum: TLDiskEnumerationResult | None = field(default=None, repr=False)
    _tl_mtd_skip: int = field(default=0, repr=False)
    #: Set when the first :meth:`enumerate_tlpart_tl` attempt raised (so later calls reuse the same failure).
    _tl_enum_error: BaseException | None = field(default=None, repr=False)
    #: Optional kernel-faithful ``tlpart`` scan buffer (assembled virtual TL disk prefix).
    tlpart_tl_scan_bytes: bytes | None = field(default=None, repr=False)
    _block_map: BlockMapBuild | None = field(default=None, repr=False)
    _bbm_linear_prefix: bytes | None = field(default=None, repr=False)
    _tl_virt_slice_cache: dict[str, bytes] = field(default_factory=dict, repr=False)
    #: Set by :meth:`attach_open_tl_bbm` / :meth:`attach_open_tl`; cleared at the start of a BBM re-attach.
    _opentl_session: LogicalOpenTLSession | None = field(default=None, repr=False)

    def __post_init__(self, block_map: BlockMapBuild | None, bbm_linear_prefix: bytes | None) -> None:
        if bbm_linear_prefix is not None and block_map is None:
            raise ValueError("bbm_linear_prefix requires block_map")
        if block_map is not None:
            self.attach_open_tl_bbm(block_map, linear_prefix=bbm_linear_prefix)

    @property
    def backing_path(self) -> Path:
        """On-disk flash path. Raises when the image is memory-backed (``FlashImage.logical_image``)."""
        if self.flash.logical_image is not None:
            raise TypeError(
                "FsRegistry is memory-backed (FlashImage.logical_image); "
                "use BlockDev.read_slice() or FlashImage.read_partition()"
            )
        return Path(self.flash.path)

    @property
    def attached_block_map(self) -> BlockMapBuild | None:
        """The OpenTL :class:`~opentl.tl_bbm.BlockMapBuild` when BBM is attached; else ``None``."""
        return self._block_map

    @property
    def attached_logical_opentl_session(self) -> LogicalOpenTLSession | None:
        """Prefix + :class:`~opentl.tl_bbm.BlockMapBuild` session when BBM is attached; else ``None``."""
        return self._opentl_session

    def _flash_backing(self) -> Path | bytes:
        if self.flash.logical_image is not None:
            return self.flash.logical_image
        return Path(self.flash.path)

    #region kernel: 0x80289170
    # ntl_read_page — assemble virtual tlpart for TL disklabel path
    def attach_open_tl_bbm(self, block_map: BlockMapBuild, *, linear_prefix: bytes | None = None) -> None:
        """
        Attach an OpenTL BBM map: build :class:`~opentl.logical_opentl_session.LogicalOpenTLSession`,
        assemble virtual ``tlpart`` scan bytes, and resolve TL slices via the session.

        ``linear_prefix`` must be at least ``block_map.logical_prefix_bytes`` long when provided;
        otherwise bytes are read from :attr:`flash` starting at offset **0** (full logical plane).
        """
        self._tl_virt_slice_cache.clear()
        self._block_map = block_map
        lim = int(block_map.logical_prefix_bytes)
        if linear_prefix is not None:
            if len(linear_prefix) < lim:
                raise ValueError(
                    f"linear_prefix length {len(linear_prefix)} < block_map.logical_prefix_bytes {lim}"
                )
            self._bbm_linear_prefix = bytes(linear_prefix[:lim])
        else:
            self._bbm_linear_prefix = read_linear_plane_prefix(self.flash, lim)
        self._opentl_session = LogicalOpenTLSession.from_linear_prefix_bytes(
            self._bbm_linear_prefix,
            block_map,
        )
        self.tlpart_tl_scan_bytes = self._opentl_session.virtual_tl_byte_stream(
            max_virt_bytes=_tl_scan_cap_for_flash(self.flash)
        )
        self.invalidate_tl_cache()

    def attach_open_tl(self, ot: OpenTL, *, linear_prefix: bytes | None = None) -> None:
        """
        Attach BBM using a kernel-shaped :class:`~opentl.open_tl.OpenTL` (no spare parameters).

        When ``linear_prefix`` is ``None``, uses :meth:`opentl.open_tl.OpenTL.read_logical_prefix`.
        """
        use_ot_session = linear_prefix is None
        if use_ot_session:
            linear_prefix = ot.read_logical_prefix()
        self.attach_open_tl_bbm(ot.block_map, linear_prefix=linear_prefix)
        if use_ot_session:
            self._opentl_session = LogicalOpenTLSession.from_open_tl(ot)
            self.tlpart_tl_scan_bytes = self._opentl_session.virtual_tl_byte_stream(
                max_virt_bytes=_tl_scan_cap_for_flash(self.flash)
            )

    #endregion

    def partition_by_mtd_index(self, mtd_index: int) -> MtdPartition:
        """``mtdblockN`` / ``mtdN`` index matches :attr:`MtdPartition.index`."""
        for p in self.flash.partitions:
            if p.index == mtd_index:
                return p
        raise KeyError(f"no MTD partition with index {mtd_index}")

    def partition_by_name(self, name: str) -> MtdPartition:
        for p in self.flash.partitions:
            if p.name == name:
                return p
        raise KeyError(f"no MTD partition named {name!r}")

    def block_dev_for_mtd_index(self, mtd_index: int) -> BlockDev:
        p = self.partition_by_mtd_index(mtd_index)
        return BlockDev(
            backing=self._flash_backing(),
            offset=p.offset,
            size=p.size,
            label=f"mtdblock{p.index}:{p.name}",
        )

    def block_dev_for_mtd_named(self, name: str) -> BlockDev:
        """MTD slice by partition name from ``mtdparts`` (e.g. ``tlpart``)."""
        p = self.partition_by_name(name)
        return BlockDev(
            backing=self._flash_backing(),
            offset=p.offset,
            size=p.size,
            label=f"mtdblock{p.index}:{p.name}",
        )

    def ubi_mtd_attach_specs(self) -> tuple[UbiMtdAttachSpec, ...]:
        """All ``ubi.mtd=`` tokens on this registry's command line."""
        return iter_ubi_mtd_attach_specs(self.cmdline)

    def block_dev_for_ubi_mtd_attach(self, spec: UbiMtdAttachSpec) -> BlockDev:
        """
        Map one ``ubi.mtd=`` attachment to a :class:`BlockDev` over the **underlying MTD**
        region (the bytes UBI will attach — not decoded UBI volumes).

        ``mtd_ref`` may be a decimal ``mtdparts`` index or a partition name. Optional
        ``mtd_sub_offset`` selects a sub-range starting at that byte within the MTD slice.
        """
        ref = spec.mtd_ref.strip()
        if ref.isdigit():
            p = self.partition_by_mtd_index(int(ref, 10))
        else:
            p = self.partition_by_name(ref)
        sub = spec.mtd_sub_offset or 0
        if sub < 0 or sub > p.size:
            raise ValueError(f"mtd_sub_offset {sub} invalid for partition {p.name!r} size {p.size}")
        size = p.size - sub
        return BlockDev(
            backing=self._flash_backing(),
            offset=p.offset + sub,
            size=size,
            label=f"ubi.mtd->{ref}",
        )

    def first_ubi_backing_block_dev(self) -> BlockDev | None:
        """First ``ubi.mtd=`` attachment as a :class:`BlockDev`, or ``None`` if absent."""
        specs = self.ubi_mtd_attach_specs()
        if not specs:
            return None
        return self.block_dev_for_ubi_mtd_attach(specs[0])

    #region kernel_adjacent enumerate_tlpart_tl (tlpart MTD bytes → opentl.tldisk TL slices)
    def enumerate_tlpart_tl(self) -> TLDiskEnumerationResult:
        """Parse TL disklabel inside the ``tlpart`` MTD slice (cached).

        When :attr:`tlpart_tl_scan_bytes` is the BBM-assembled virtual stream and parsing it fails,
        retries on **linear** ``tlpart`` partition bytes, then on the **full** :attr:`_bbm_linear_prefix`
        (chip offset 0) when that is larger than the ``tlpart`` slice — some captures expose the
        disklabel only in the full-plane view. Slice ``offset_bytes`` remain kernel sector addresses.
        """
        if self._tl_enum_error is not None:
            raise self._tl_enum_error
        if self._tl_enum is not None:
            return self._tl_enum
        blob, blob_source = self._tlpart_enumeration_bytes_and_source()
        try:
            pack = enumerate_tl_slices_from_tlpart_mtd_bytes(blob)
            if blob_source == "linear_tlpart" and self.tlpart_tl_scan_bytes is not None:
                pack.result.notes.append(
                    "opentl: TL disklabel enumerated from linear MTD ``tlpart`` "
                    "(BBM virtual stream had no disklabel anchor; kernel label may only appear "
                    "after virt→phys assembly or on linear plane)"
                )
        except Exception as e:
            if self.tlpart_tl_scan_bytes is None:
                self._tl_enum_error = e
                raise
            linear = self.flash.read_partition("tlpart")
            full = self._bbm_linear_prefix
            pack = None
            fallback_source: str | None = None
            last_fb_err: BaseException | None = None
            for label, candidate in (
                ("linear_tlpart", linear),
                ("full_linear_prefix", full),
            ):
                if candidate is None:
                    continue
                if label == "full_linear_prefix" and len(candidate) <= len(linear):
                    continue
                try:
                    pack = enumerate_tl_slices_from_tlpart_mtd_bytes(candidate)
                    fallback_source = label
                    break
                except Exception as e2:
                    last_fb_err = e2
            if pack is None:
                self._tl_enum_error = e
                if last_fb_err is not None:
                    raise e from last_fb_err
                raise e
            if fallback_source == "linear_tlpart":
                pack.result.notes.append(
                    "opentl: TL disklabel enumerated from linear MTD ``tlpart`` (BBM virtual stream had no valid anchor); "
                    "slice ``offset_bytes`` are still kernel sector addresses for virt→phys assembly."
                )
            else:
                pack.result.notes.append(
                    "opentl: TL disklabel enumerated from full linear NAND plane at chip offset 0 "
                    "(BBM virtual stream and MTD ``tlpart`` slice had no valid anchor); "
                    "slice ``offset_bytes`` are still kernel sector addresses for virt→phys assembly."
                )
        self._tl_enum = pack.result
        self._tl_mtd_skip = pack.mtd_skip
        return self._tl_enum

    def invalidate_tl_cache(self) -> None:
        self._tl_enum = None
        self._tl_mtd_skip = 0
        self._tl_enum_error = None
        self._tl_virt_slice_cache.clear()

    def clear_virt_slice_cache(self) -> None:
        """Drop cached TL slice payloads (virtual BBM assemblies); TL disklabel enum cache unaffected."""
        self._tl_virt_slice_cache.clear()

    def _tlpart_enumeration_bytes_and_source(self) -> tuple[bytes, str]:
        """
        Pick bytes for :func:`~opentl.tldisk.enumerate_tl_slices_from_tlpart_mtd_bytes`.

        When BBM virtual assembly is attached but has no disklabel anchor (zeroed holes /
        wrong primary map) while linear ``tlpart`` still shows ``bsd_magic`` or a valid sector,
        enumerate on **linear** ``tlpart`` first — matching kernel ``read_dev_sector`` vs raw
        plane grep separation (see ``reference/ghidra_parse_bsd_disklabel_layout.md``).
        """
        linear = self.flash.read_partition("tlpart")
        virt = self.tlpart_tl_scan_bytes
        if virt is None:
            return linear, "linear_tlpart"
        if buffer_has_tl_disklabel_anchor(virt):
            return virt, "virt_bbm"
        if buffer_has_tl_disklabel_anchor(linear):
            return linear, "linear_tlpart"
        return virt, "virt_bbm"

    #endregion

    #region kernel_adjacent FsRegistry_replace_open_tl_block_map
    # Registry orchestration: swap BlockMapBuild, refresh virtual tlpart scan bytes, clear TL caches.
    def replace_open_tl_block_map(self, block_map: BlockMapBuild) -> None:
        """
        Swap the attached :class:`~opentl.tl_bbm.BlockMapBuild` while keeping the same linear prefix.

        Requires a prior :meth:`attach_open_tl_bbm` (or constructor ``block_map=``). When the prefix
        is non-empty, ``block_map.logical_prefix_bytes`` must equal ``len`` of the stored prefix.
        """
        if self._opentl_session is None:
            raise ValueError(
                "replace_open_tl_block_map requires BBM attach; "
                "call attach_open_tl_bbm or construct FsRegistry with block_map="
            )
        lim = len(self._bbm_linear_prefix or b"")
        if lim > 0 and int(block_map.logical_prefix_bytes) != lim:
            raise ValueError(
                f"block_map.logical_prefix_bytes {block_map.logical_prefix_bytes} must match "
                f"attached linear prefix length {lim}"
            )
        self._opentl_session.replace_block_map(block_map)
        self._block_map = block_map
        self.tlpart_tl_scan_bytes = self._opentl_session.virtual_tl_byte_stream(
            max_virt_bytes=_tl_scan_cap_for_flash(self.flash)
        )
        self.invalidate_tl_cache()

    #endregion

    def tl_slice_by_name(self, slice_name: str) -> TLDiskSlice:
        r = self.enumerate_tlpart_tl()
        for s in r.slices:
            if s.name == slice_name:
                return s
        raise KeyError(f"no TL slice named {slice_name!r}")

    def block_dev_for_cmdline_root(self) -> BlockDev | None:
        """
        If ``root=/dev/mtdblockN`` is present, return that MTD slice.

        ``root=ubiN:…`` is **not** a raw MTD slice; use :meth:`first_ubi_backing_block_dev`
        for the ``ubi.mtd=`` backing region, then UBI/UBIFS tooling.
        """
        spec = parse_root_from_cmdline(self.cmdline)
        if spec is None or spec.kind != "mtdblock" or spec.index is None:
            return None
        return self.block_dev_for_mtd_index(spec.index)

    #region kernel: 0x80289170
    # ntl_read_page — TL child slice payloads (BBM: LogicalOpenTLSession.extract_virtual_disk_bytes)
    def block_dev_for_tl_slice(self, slice_name: str) -> BlockSlice:
        """
        Byte range for a TL child slice.

        Without OpenTL BBM: contiguous range on :attr:`flash` (``tlpart`` MTD offset + ``mtd_skip`` + slice).

        With BBM (see :meth:`attach_open_tl_bbm`): :class:`~boardfs.block.AssembledBlockDev`
        via :meth:`LogicalOpenTLSession.extract_virtual_disk_bytes`.
        """
        sl = self.tl_slice_by_name(slice_name)
        if self._block_map is None or self._bbm_linear_prefix is None:
            tlp = self.partition_by_name("tlpart")
            return BlockDev(
                backing=self._flash_backing(),
                offset=tlp.offset + self._tl_mtd_skip + sl.offset_bytes,
                size=sl.length_bytes,
                label=slice_name,
            )
        if slice_name not in self._tl_virt_slice_cache:
            if self._opentl_session is None:
                raise RuntimeError("BBM attached but LogicalOpenTLSession missing; corrupt registry state")
            payload, _, _ = self._opentl_session.extract_virtual_disk_bytes(
                sl.offset_bytes,
                sl.length_bytes,
            )
            self._tl_virt_slice_cache[slice_name] = payload
        data = self._tl_virt_slice_cache[slice_name]
        return AssembledBlockDev(label=slice_name, size=sl.length_bytes, data=data)

    #endregion
