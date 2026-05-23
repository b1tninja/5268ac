"""
Stable read-model for logical-plane OpenTL + BBM after :class:`~opentl.tl_bbm.BlockMapBuild` exists.

**Public façade:** :class:`LogicalOpenTLSession` is the supported object for **prefix bytes +
:class:`~opentl.logical_opentl_session.LogicalOpenTLSession` + :class:`~opentl.tl_bbm.BlockMapBuild` + :meth:`replace_block_map` (host read-model). Virt→phys replay stays in :mod:`opentl.open_tl` / :mod:`opentl.virt_page_table`; **callers** (:mod:`boardfs`, :mod:`paceflash`) assemble virtual TL bytes via this session or :mod:`opentl.driver` helpers only.

Higher layers use :class:`LogicalOpenTLSession` instead of composing
:func:`~opentl.open_tl.virt_span_nand_page_rows` + prefix reads + :class:`~opentl.open_tl.OpenTL`
manually. After :meth:`opentl.open_tl.OpenTL.from_logical_with_flat_spare`, use :meth:`from_open_tl`.
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path
from typing import Any

from opentl.open_tl import (
    NandPageSpanRow,
    OpenTL,
    extract_virtual_disk_bytes,
    extract_virtual_disk_bytes_chain_aware,
    virt_span_nand_page_rows,
)
from opentl.tl_bbm import BlockMapBuild
from opentl.virt_page_table import (
    LazyChainAwareVirtNandPageTable,
    VirtNandPageTable,
    VirtNandPageTableLike,
    build_lazy_chain_aware_virt_nand_page_table,
    build_virt_nand_page_table,
    extract_virtual_disk_bytes_via_page_table,
)


#region kernel_adjacent LogicalOpenTLSession_read_model (aligns with boardfs.registry.read_linear_plane_prefix)
class LogicalOpenTLSession:
    """
    **Canonical public object** for linear-plane **prefix** (file or buffer) +
    :class:`~opentl.tl_bbm.BlockMapBuild` + cached reads + :meth:`replace_block_map`.

    File-backed extract and full ``OpenTL`` I/O use :meth:`open_tl` (same kernel-shaped path as
    :class:`~opentl.open_tl.OpenTL`). Prefix length follows ``min(backing_size, logical_prefix_bytes)``
    at linear offset **0**, matching :func:`boardfs.registry.read_linear_plane_prefix`.
    """

    def __init__(
        self,
        block_map: BlockMapBuild,
        *,
        logical_path: Path | None = None,
        prefix_buffer: bytes | None = None,
        nand_logical_offset: int | None = None,
        logical_prefix_bytes_override: int | None = None,
    ) -> None:
        has_path = logical_path is not None
        has_buf = prefix_buffer is not None
        if has_path == has_buf:
            raise ValueError("exactly one of logical_path or prefix_buffer must be set")
        self._block_map = block_map
        self._logical_path = Path(logical_path).resolve() if logical_path is not None else None
        self._prefix_buffer = prefix_buffer
        self._nand_logical_offset = nand_logical_offset
        self._logical_prefix_bytes_override = logical_prefix_bytes_override
        self._flat_oob: bytes | None = None
        self._virt_page_table_override: VirtNandPageTableLike | None = None

    @classmethod
    def from_paths(
        cls,
        logical_path: str | Path,
        block_map: BlockMapBuild,
        *,
        nand_logical_offset: int | None = None,
        logical_prefix_bytes: int | None = None,
    ) -> LogicalOpenTLSession:
        """File-backed logical plane (same layout as :class:`~opentl.open_tl.OpenTL` ``image_path``)."""
        return cls(
            block_map,
            logical_path=Path(logical_path).expanduser().resolve(),
            prefix_buffer=None,
            nand_logical_offset=nand_logical_offset,
            logical_prefix_bytes_override=logical_prefix_bytes,
        )

    @classmethod
    def from_open_tl(cls, ot: OpenTL) -> LogicalOpenTLSession:
        """Session aligned with ``ot`` (same nand offset and optional prefix cap as :class:`~opentl.open_tl.OpenTL`)."""
        return cls.from_paths(
            ot.image_path,
            ot.block_map,
            nand_logical_offset=ot.nand_logical_offset,
            logical_prefix_bytes=ot.default_logical_prefix_bytes,
        )

    @classmethod
    def from_linear_prefix_bytes(
        cls,
        prefix_bytes: bytes,
        block_map: BlockMapBuild,
    ) -> LogicalOpenTLSession:
        """
        Prefix-only session: :meth:`linear_prefix` / :meth:`nand_page_rows` / :meth:`pages` work.

        :meth:`open_tl` is unavailable (raises ``TypeError``) — use :meth:`from_paths` when an
        on-disk image is required for extract.
        """
        return cls(block_map, logical_path=None, prefix_buffer=bytes(prefix_bytes))

    @classmethod
    def from_nand_pipeline(cls, pipe: Any) -> LogicalOpenTLSession:
        from opentl.nand_pipeline import NandPipeline

        if not isinstance(pipe, NandPipeline):
            raise TypeError(f"expected NandPipeline, got {type(pipe).__name__}")
        if pipe.logical_path is None or not pipe.logical_path.is_file():
            raise ValueError("NandPipeline.logical_path must be set to an existing file")
        if pipe.bbm is None:
            raise ValueError("NandPipeline.bbm is None; call build_bbm() first")
        m = pipe.bbm
        return cls.from_paths(
            pipe.logical_path,
            m,
            nand_logical_offset=int(m.nand_logical_offset),
        )

    #region kernel_adjacent LogicalOpenTLSession_replace_block_map
    # BBM map swap (host glue): invalidate caches; virt replay stays on session (@ 0x80289170 / 0x802888f8).
    def _invalidate_cached_properties(self) -> None:
        for k in ("linear_prefix", "open_tl", "default_nand_page_rows", "virt_nand_page_table"):
            self.__dict__.pop(k, None)

    def replace_block_map(
        self,
        block_map: BlockMapBuild,
        *,
        logical_prefix_bytes_override: int | None = None,
        nand_logical_offset: int | None = None,
    ) -> None:
        """
        Swap in a new ``block_map`` while keeping the same backing prefix (path or buffer).

        Invalidates :func:`functools.cached_property` caches so :meth:`linear_prefix`, :meth:`open_tl`,
        and :meth:`default_nand_page_rows` reflect the new map. Pass ``logical_prefix_bytes_override``
        or ``nand_logical_offset`` only when those should change; ``None`` leaves them unchanged.
        """
        self._block_map = block_map
        if logical_prefix_bytes_override is not None:
            self._logical_prefix_bytes_override = int(logical_prefix_bytes_override)
        if nand_logical_offset is not None:
            self._nand_logical_offset = int(nand_logical_offset)
        self.clear_chain_aware_virt_reads()
        self._invalidate_cached_properties()

    #endregion

    #region kernel: 0x802888f8
    # ntl_put_chain_in_array — mode-2 spare chain VirtNandPageTable (delegates to virt_page_table)
    def set_chain_aware_virt_reads(
        self,
        flat_oob: bytes,
        *,
        verify_page: Any | None = None,
        page_size_is_0x200: bool = False,
    ) -> LazyChainAwareVirtNandPageTable:
        """
        Install lazy mode-2 spare chain page resolution (``spare_page=0`` per ``ntl_put_chain_in_array``).

        Does **not** walk the full virtual disk up front — pages resolve on first read via
        :meth:`~opentl.virt_page_table.LazyChainAwareVirtNandPageTable.phys_page_base_at`.
        """
        self._flat_oob = bytes(flat_oob)
        table = build_lazy_chain_aware_virt_nand_page_table(
            self._block_map,
            self.linear_prefix,
            flat_oob=self._flat_oob,
            page_size_is_0x200=page_size_is_0x200,
            verify_page=verify_page,
        )
        self._virt_page_table_override = table
        self.__dict__.pop("virt_nand_page_table", None)
        return table

    def clear_chain_aware_virt_reads(self) -> None:
        self._flat_oob = None
        self._virt_page_table_override = None
        self.__dict__.pop("virt_nand_page_table", None)

    #endregion

    #region kernel: 0x80289170
    # virtual_tl_byte_stream — contiguous virtual TL disk (primary BBM slots only)
    def virtual_tl_byte_stream(self, *, max_virt_bytes: int | None = None) -> bytes:
        """
        Materialize contiguous virtual TL bytes ``[0, virt_disk)``.

        Uses the **primary** :class:`~opentl.tl_bbm.BlockMapBuild` page table only (derived from
        ``virt_to_phys_block``), **not** a chain-aware spare override — so TL disklabel scan bytes stay
        stable unless the caller also applies chain-aware reads for slice probing.

        Matches :func:`~opentl.tlpart_bbm_assembly.virtual_tl_byte_stream_from_logical_plane`.
        """
        lim = min(len(self.linear_prefix), int(self._block_map.logical_prefix_bytes))
        if lim <= 0:
            raise ValueError("logical prefix empty or block_map.logical_prefix_bytes is 0")
        prefix = self.linear_prefix[:lim]
        geo = self._block_map.geometry
        virt_total = int(geo.virt_blocks) * int(geo.erase_bytes)
        if virt_total <= 0:
            raise ValueError("virtual TL disk size is 0 (check BlockMapBuild.geometry)")
        if max_virt_bytes is not None:
            mv = int(max_virt_bytes)
            if mv < 0:
                raise ValueError("max_virt_bytes must be >= 0")
            virt_total = min(virt_total, mv)
        table = build_virt_nand_page_table(
            self._block_map,
            logical_prefix_len=lim,
            max_virt_bytes=virt_total if max_virt_bytes is not None else None,
        )
        out, _, _ = extract_virtual_disk_bytes_via_page_table(
            prefix,
            table,
            virt_byte_start=0,
            virt_byte_length=virt_total,
        )
        return bytes(out)

    #endregion

    #region kernel: 0x80289170
    # Chain-aware spare attach (lazy page table; no full-disk materialization)
    def apply_chain_aware_flat_oob(
        self,
        flat_oob: bytes,
        *,
        verify_page: Any | None = None,
        page_size_is_0x200: bool = False,
    ) -> bytes:
        """
        Enable chain-aware reads via lazy :class:`~opentl.virt_page_table.LazyChainAwareVirtNandPageTable`.

        Returns ``b\"\"`` — callers must not expect a materialized full virtual TL stream here.
        Use :meth:`extract_virtual_disk_bytes` / :func:`~opentl.ntl_rw.assemble_ntl_rw_slice` for ranges.
        """
        self.set_chain_aware_virt_reads(
            flat_oob, verify_page=verify_page, page_size_is_0x200=page_size_is_0x200
        )
        return b""

    #endregion

    def _effective_prefix_limit(self) -> int:
        lim_src = self._logical_prefix_bytes_override
        if lim_src is not None:
            return int(lim_src)
        return int(self._block_map.logical_prefix_bytes)

    @cached_property
    def linear_prefix(self) -> bytes:
        """First ``min(backing_size, logical_prefix_bytes)`` bytes at linear offset **0**."""
        lim = self._effective_prefix_limit()
        if lim <= 0:
            return b""
        if self._prefix_buffer is not None:
            p = self._prefix_buffer
            return p if len(p) <= lim else bytes(p[:lim])
        assert self._logical_path is not None
        sz = self._logical_path.stat().st_size
        n = min(sz, lim)
        with self._logical_path.open("rb") as f:
            return f.read(n)

    @cached_property
    def open_tl(self) -> OpenTL:
        """Kernel-shaped :class:`~opentl.open_tl.OpenTL` handle (file-backed sessions only)."""
        if self._logical_path is None:
            raise TypeError(
                "open_tl requires a file-backed session; use from_paths(...) "
                "or from_nand_pipeline(...). Prefix-only sessions support nand_page_rows / pages only."
            )
        off = (
            int(self._nand_logical_offset)
            if self._nand_logical_offset is not None
            else int(self._block_map.nand_logical_offset)
        )
        return OpenTL(
            self._logical_path,
            block_map=self._block_map,
            nand_logical_offset=off,
            logical_prefix_bytes=self._logical_prefix_bytes_override,
        )

    #region kernel: 0x80289170
    # Virt span decomposition + memcpy/hole-fill (virt_span_nand_page_rows / page table / extract)
    def nand_page_rows(
        self,
        virt_byte_start: int,
        virt_byte_length: int,
        *,
        max_rows: int = 256,
    ) -> list[NandPageSpanRow]:
        """NAND page decomposition for a virtual TL byte span (uses cached :meth:`linear_prefix` length)."""
        return virt_span_nand_page_rows(
            self._block_map,
            logical_prefix_len=len(self.linear_prefix),
            virt_byte_start=int(virt_byte_start),
            virt_byte_length=int(virt_byte_length),
            max_rows=int(max_rows),
        )

    @cached_property
    def default_nand_page_rows(self) -> list[NandPageSpanRow]:
        """Default window matching ``boardfs page-table`` CLI defaults (0, 8192, max_rows 64)."""
        return self.nand_page_rows(0, 8192, max_rows=64)

    @cached_property
    def virt_nand_page_table(self) -> VirtNandPageTable:
        """Derived per–2048 B page → linear prefix offset table (see :mod:`opentl.virt_page_table`)."""
        if self._virt_page_table_override is not None:
            return self._virt_page_table_override
        return build_virt_nand_page_table(
            self._block_map,
            logical_prefix_len=len(self.linear_prefix),
        )

    def extract_virtual_disk_bytes(
        self,
        virt_byte_start: int,
        virt_byte_length: int,
        *,
        hole_fill_byte: int = 0,
        use_page_table: bool = True,
    ) -> tuple[bytes, int | None, int | None]:
        """
        Virtual TL byte range via page table (default) or byte loop fallback.

        Uses :func:`~opentl.virt_page_table.extract_virtual_disk_bytes_via_page_table` when
        ``use_page_table`` is true.
        """
        prefix = self.linear_prefix
        if use_page_table:
            return extract_virtual_disk_bytes_via_page_table(
                prefix,
                self.virt_nand_page_table,
                virt_byte_start=int(virt_byte_start),
                virt_byte_length=int(virt_byte_length),
                hole_fill_byte=int(hole_fill_byte),
            )
        return extract_virtual_disk_bytes(
            prefix,
            self._block_map,
            virt_byte_start=int(virt_byte_start),
            virt_byte_length=int(virt_byte_length),
            hole_fill_byte=int(hole_fill_byte),
        )

    def extract_virtual_disk_bytes_chain_aware_path(
        self,
        virt_byte_start: int,
        virt_byte_length: int,
        *,
        hole_fill_byte: int = 0,
        page_size_is_0x200: bool = False,
        verify_page: Any | None = None,
    ) -> tuple[bytes, int | None, int | None]:
        """
        Like :func:`opentl.open_tl.extract_virtual_disk_bytes_chain_aware` using this session's
        prefix, :class:`~opentl.tl_bbm.BlockMapBuild`, and attached **flat spare** (from
        :meth:`set_chain_aware_virt_reads` or :meth:`apply_chain_aware_flat_oob`).

        Raises ``ValueError`` if no flat OOB was set on this session.
        """
        if self._flat_oob is None:
            raise ValueError(
                "chain-aware extract requires flat OOB; call set_chain_aware_virt_reads "
                "or apply_chain_aware_flat_oob first"
            )
        return extract_virtual_disk_bytes_chain_aware(
            self.linear_prefix,
            self._block_map,
            flat_oob=self._flat_oob,
            virt_byte_start=int(virt_byte_start),
            virt_byte_length=int(virt_byte_length),
            hole_fill_byte=int(hole_fill_byte),
            page_size_is_0x200=page_size_is_0x200,
            verify_page=verify_page,
        )

    @property
    def pages(self) -> list[NandPageSpanRow]:
        """Alias for :meth:`default_nand_page_rows` (fixed window; not full-disk enumeration)."""
        return self.default_nand_page_rows

    #endregion

    @property
    def block_map(self) -> BlockMapBuild:
        return self._block_map


#endregion


__all__ = ["LogicalOpenTLSession"]
