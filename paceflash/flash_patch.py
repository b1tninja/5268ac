"""Immutable NAND flash patch orchestration (copy-on-write)."""

from __future__ import annotations

import hashlib
import io
import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from unand.geometry import PACE_DEFAULT
from unand.io import (
    denormalize_logical_to_physical,
    extract_spare_bytes,
    normalize_to_logical,
    patch_logical_bytes,
    patch_physical_pages,
)
from unand.spare_patch import pages_touched_by_spans, refresh_spare_ecc_for_pages
from unand.layout import RawDumpLayout, detect_layout_file
from unand.mtd import DEFAULT_MTDPARTS, parse_mtdparts, part_by_name

from paceflash.board_param import TRUST_ENGCERT_KEY, patch_trust_engcert_in_tlpart
from paceflash.factory_params import patch_factory_trust_engcert


@dataclass
class LogicalPatch:
    """One contiguous patch on the MTD logical main plane."""

    offset: int
    data: bytes
    label: str = ""


@dataclass
class FlashPatchSession:
    """
    Copy-on-write session: input flash is never modified.

    Holds logical main plane + spare sidecar + layout metadata for patch application.
    """

    input_path: Path
    layout: RawDumpLayout
    logical: bytearray
    spare: bytes | bytearray | None
    cmdline: str = f"quiet rw {DEFAULT_MTDPARTS}"
    patches: list[LogicalPatch] = field(default_factory=list)
    modified_pages: dict[int, tuple[bytes, bytes]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def open(
        cls,
        input_path: str | Path,
        *,
        cmdline: str | None = None,
    ) -> FlashPatchSession:
        p = Path(input_path).expanduser().resolve()
        if not p.is_file():
            raise FileNotFoundError(p)
        layout = detect_layout_file(str(p), geom=PACE_DEFAULT)
        line = cmdline if cmdline is not None else f"quiet rw {DEFAULT_MTDPARTS}"

        if layout == RawDumpLayout.LOGICAL_ONLY:
            logical = bytearray(p.read_bytes())
            spare = None
        else:
            logical_io = tempfile.SpooledTemporaryFile(max_size=256 * 1024 * 1024)
            spare_io = tempfile.SpooledTemporaryFile(max_size=16 * 1024 * 1024)
            normalize_to_logical(p, logical_io, spare_io, layout=layout, geom=PACE_DEFAULT)
            logical_io.seek(0)
            spare_io.seek(0)
            logical = bytearray(logical_io.read())
            spare = bytearray(spare_io.read())

        return cls(
            input_path=p,
            layout=layout,
            logical=logical,
            spare=spare,
            cmdline=line,
            metadata={"input_sha256": _sha256_file(p)},
        )

    def read_tlpart(self) -> bytes:
        parts = parse_mtdparts(self.cmdline, logical_total=len(self.logical))
        tlp = part_by_name(parts, "tlpart")
        end = tlp.offset + tlp.size
        return bytes(self.logical[tlp.offset : end])

    def read_tlpart_mutable(self) -> tuple[bytearray, int]:
        parts = parse_mtdparts(self.cmdline, logical_total=len(self.logical))
        tlp = part_by_name(parts, "tlpart")
        return self.logical, tlp.offset

    def apply_patches(self, patches: list[LogicalPatch]) -> dict[str, Any] | None:
        spare_refresh: dict[str, Any] | None = None
        spans = [(p.offset, len(p.data)) for p in patches]
        for patch in patches:
            patch_logical_bytes(self.logical, [(patch.offset, patch.data)])
            self.patches.append(patch)
        if self.spare is not None and patches:
            pages = pages_touched_by_spans(spans, page_data=PACE_DEFAULT.page_data)
            spare_refresh = refresh_spare_ecc_for_pages(
                self.logical,
                self.spare,
                pages,
                geom=PACE_DEFAULT,
                spans=spans,
            )
            page_data = PACE_DEFAULT.page_data
            page_spare = PACE_DEFAULT.page_spare
            for page in pages:
                main_off = page * page_data
                spare_off = page * page_spare
                self.modified_pages[page] = (
                    bytes(self.logical[main_off : main_off + page_data]),
                    bytes(self.spare[spare_off : spare_off + page_spare]),
                )
        elif patches and self.layout == RawDumpLayout.LOGICAL_ONLY:
            for patch in patches:
                page = patch.offset // PACE_DEFAULT.page_data
                main_off = page * PACE_DEFAULT.page_data
                self.modified_pages[page] = (
                    bytes(self.logical[main_off : main_off + PACE_DEFAULT.page_data]),
                    b"",
                )
        return spare_refresh

    def _record_modified_pages(self, spans: list[tuple[int, int]]) -> None:
        if self.spare is None:
            return
        page_data = PACE_DEFAULT.page_data
        page_spare = PACE_DEFAULT.page_spare
        for page in pages_touched_by_spans(spans, page_data=page_data):
            main_off = page * page_data
            spare_off = page * page_spare
            self.modified_pages[page] = (
                bytes(self.logical[main_off : main_off + page_data]),
                bytes(self.spare[spare_off : spare_off + page_spare]),
            )

    def patch_trust_engcert(self, value: str) -> dict[str, Any]:
        """Patch ``gw:trust_engcert`` in board_param env copies + factory defaults."""
        parts = parse_mtdparts(self.cmdline, logical_total=len(self.logical))
        loader_part = part_by_name(parts, "loader")
        factory_result: dict[str, Any] | None = None
        factory_patches: list[LogicalPatch] = []
        if self.layout != RawDumpLayout.LOGICAL_ONLY:
            loader_off = loader_part.offset
            loader_end = loader_off + loader_part.size
            loader_buf = bytearray(self.logical[loader_off:loader_end])
            factory_result = patch_factory_trust_engcert(loader_buf, value)
            if factory_result.get("ok") and not factory_result.get("unchanged"):
                po = int(factory_result["patch_offset"])
                pl = int(factory_result["patch_length"])
                self.logical[loader_off:loader_end] = loader_buf
                factory_patches.append(
                    LogicalPatch(
                        offset=loader_off + po,
                        data=bytes(loader_buf[po : po + pl]),
                        label=f"factory trust_engcert={value}@{po:#x}",
                    )
                )

        logical, tlp_off = self.read_tlpart_mutable()
        tlp = part_by_name(parts, "tlpart")
        tlpart = bytearray(logical[tlp_off : tlp_off + tlp.size])
        result = patch_trust_engcert_in_tlpart(tlpart, value)

        logical_patches: list[LogicalPatch] = list(factory_patches)
        for site in result.get("sites_patched") or []:
            if site.get("unchanged"):
                continue
            rel = int(site["offset"])
            if result.get("patch_mode") == "crc_blob":
                span = int(site["blob_length"])
            else:
                span = 22
            logical_patches.append(
                LogicalPatch(
                    offset=tlp_off + rel,
                    data=bytes(tlpart[rel : rel + span]),
                    label=f"trust_engcert={value}@{rel:#x}",
                )
            )
        spare_refresh: dict[str, Any] | None = None
        if logical_patches:
            spans = [(p.offset, len(p.data)) for p in logical_patches]
            for patch in logical_patches:
                patch_logical_bytes(self.logical, [(patch.offset, patch.data)])
                self.patches.append(patch)
            if self.spare is not None:
                pages = pages_touched_by_spans(spans, page_data=PACE_DEFAULT.page_data)
                spare_refresh = refresh_spare_ecc_for_pages(
                    self.logical,
                    self.spare,
                    pages,
                    geom=PACE_DEFAULT,
                    spans=spans,
                )
                self._record_modified_pages(spans)
            elif factory_patches:
                self._record_modified_pages(spans)

        result["key"] = TRUST_ENGCERT_KEY
        result["value"] = value
        if factory_result is not None:
            result["factory_trust_engcert"] = factory_result
        if spare_refresh is not None:
            result["spare_refresh"] = spare_refresh
        return result

    def materialize_output(
        self,
        out_path: str | Path,
        *,
        manifest_path: str | Path | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        out = Path(out_path).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        if self.layout == RawDumpLayout.LOGICAL_ONLY:
            out.write_bytes(self.logical)
        elif self.modified_pages:
            patch_physical_pages(
                self.input_path,
                out,
                self.modified_pages,
                layout=self.layout,
                geom=PACE_DEFAULT,
            )
        else:
            logical_tmp = tempfile.NamedTemporaryFile(delete=False)
            try:
                logical_tmp.write(self.logical)
                logical_tmp.flush()
                logical_tmp.close()
                if self.spare is not None:
                    spare_in: str | Path | io.BytesIO = io.BytesIO(bytes(self.spare))
                else:
                    spare_in = io.BytesIO(
                        extract_spare_bytes(
                            self.input_path, layout=self.layout, geom=PACE_DEFAULT
                        )
                    )
                denormalize_logical_to_physical(
                    logical_tmp.name,
                    out,
                    layout=self.layout,
                    spare_in=spare_in,
                    geom=PACE_DEFAULT,
                )
            finally:
                Path(logical_tmp.name).unlink(missing_ok=True)

        manifest: dict[str, Any] = {
            "input": str(self.input_path),
            "output": str(out),
            "input_sha256": self.metadata.get("input_sha256"),
            "output_sha256": _sha256_file(out),
            "layout": self.layout.name,
            "cmdline": self.cmdline,
            "patches": [
                {"offset": p.offset, "length": len(p.data), "label": p.label}
                for p in self.patches
            ],
            "modified_pages": sorted(self.modified_pages.keys()),
        }
        if extra:
            manifest.update(extra)

        if manifest_path is not None:
            mp = Path(manifest_path).expanduser().resolve()
            mp.parent.mkdir(parents=True, exist_ok=True)
            mp.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        manifest["manifest_path"] = str(manifest_path) if manifest_path else None
        return manifest


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def patch_trust_engcert_flash(
    flash_path: str | Path,
    *,
    value: str,
    out_path: str | Path,
    manifest_path: str | Path | None = None,
    cmdline: str | None = None,
) -> dict[str, Any]:
    """
    Immutable patch: set ``gw:trust_engcert`` in board_param env copies.

    Never modifies ``flash_path``; writes ``out_path`` (+ optional manifest JSON).
    """
    session = FlashPatchSession.open(flash_path, cmdline=cmdline)
    patch_result = session.patch_trust_engcert(value)
    manifest = session.materialize_output(
        out_path,
        manifest_path=manifest_path,
        extra={"trust_engcert": patch_result},
    )
    return {"ok": True, "patch": patch_result, "manifest": manifest}
