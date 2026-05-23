"""Ext2 filesystem block I/O — linear assembled slice or per-block NTL replay (kernel ``bread`` path)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from opentl.driver import LogicalOpenTLSession
from opentl.ntl_rw import _read_virt_page_cached
from opentl.open_tl import KERNEL_NAND_PAGE_BYTES
from opentl.ntl_page_map import PageMapCache
from opentl.tl_bbm import BlockMapBuild


@dataclass
class Ext2NtlContext:
    """Inputs for :func:`read_ext2_filesystem_block` (``ntl_rw_chain_replay``)."""

    session: LogicalOpenTLSession
    block_map: BlockMapBuild
    flat_oob: bytes
    virt_byte_start: int
    _stats: dict[str, Any] | None = None
    _page_map_cache: PageMapCache | None = None

    def __post_init__(self) -> None:
        if self._stats is None:
            self._stats = {}
        if self._page_map_cache is None:
            self._page_map_cache = PageMapCache()


@dataclass
class Ext2VolumeAccess:
    """
    Read ext2 blocks by filesystem block number.

    When ``ntl`` is set, each read uses the same virt→phys path as
    :func:`opentl.ntl_rw.assemble_ntl_rw_slice` (kernel ``__bread`` on ``opentla4``).
    Otherwise uses the pre-assembled ``slice_bytes`` only.
    """

    slice_bytes: bytes | bytearray
    blksz: int
    ntl: Ext2NtlContext | None = None
    read_model: str = "linear"

    def read_block(self, block_num: int) -> bytes:
        if block_num <= 0:
            return b"\x00" * self.blksz
        off = block_num * self.blksz
        if off + self.blksz <= len(self.slice_bytes):
            return bytes(self.slice_bytes[off : off + self.blksz])
        if self.ntl is not None:
            return read_ext2_filesystem_block(
                self.ntl,
                block_num=block_num,
                blksz=self.blksz,
            )
        return b"\x00" * self.blksz


def read_ext2_filesystem_block(
    ctx: Ext2NtlContext,
    *,
    block_num: int,
    blksz: int,
) -> bytes:
    """Map ext2 block ``block_num`` → global virt bytes → ``ntl_read_page`` (512 B pages)."""
    erase = int(ctx.block_map.geometry.erase_bytes)
    pages_per_erase = erase // KERNEL_NAND_PAGE_BYTES
    page_bytes = int(KERNEL_NAND_PAGE_BYTES)
    gvirt = int(ctx.virt_byte_start) + int(block_num) * int(blksz)
    end = gvirt + int(blksz)
    parts: list[bytes] = []
    cur = gvirt
    while cur < end:
        vblk = cur // erase
        vo = cur % erase
        ppage = vo // page_bytes
        off_in_page = vo % page_bytes
        page = _read_virt_page_cached(
            ctx.session.linear_prefix,
            ctx.flat_oob,
            ctx.block_map,
            vblk=vblk,
            ppage=ppage,
            needed={},
            stats=ctx._stats or {},
            pages_per_erase=pages_per_erase,
            page_map_cache=ctx._page_map_cache or PageMapCache(),
        )
        take = min(end - cur, page_bytes - off_in_page)
        if page is None:
            parts.append(b"\x00" * take)
        else:
            parts.append(page[off_in_page : off_in_page + take])
        cur += take
    return b"".join(parts)


def ext2_volume_access_from_assembly(
    *,
    slice_bytes: bytes,
    sb_off: int,
    read_model: str,
    reg_block_map: BlockMapBuild | None = None,
    reg_session: LogicalOpenTLSession | None = None,
    flat_oob: bytes | None = None,
    virt_byte_start: int | None = None,
) -> Ext2VolumeAccess:
    """Build block access for :mod:`boardfs.ext2_path` from an assembled opentla4 volume."""
    import struct

    from boardfs.ext2_dissect import _EXT2_SB0_OFF

    blksz = 1024 << struct.unpack_from("<I", slice_bytes, sb_off + 24)[0]
    ntl: Ext2NtlContext | None = None
    if (
        read_model == "ntl_rw_chain_replay"
        and reg_session is not None
        and reg_block_map is not None
        and flat_oob is not None
        and virt_byte_start is not None
    ):
        ntl = Ext2NtlContext(
            session=reg_session,
            block_map=reg_block_map,
            flat_oob=flat_oob,
            virt_byte_start=int(virt_byte_start),
        )
    return Ext2VolumeAccess(
        slice_bytes=slice_bytes,
        blksz=blksz,
        ntl=ntl,
        read_model=read_model,
    )


__all__ = [
    "Ext2NtlContext",
    "Ext2VolumeAccess",
    "ext2_volume_access_from_assembly",
    "read_ext2_filesystem_block",
]
