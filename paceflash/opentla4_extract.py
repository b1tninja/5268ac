"""
Inventory-oriented ``opentla4`` extract: volume bytes from :mod:`boardfs`, Dissect listing in paceflash.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from boardfs.block import AssembledBlockDev, BlockSlice
from boardfs.ext2_dissect import (
    list_root_for_block_dev_with_meta,
    resolve_mountable_ext2_superblock_offset,
)
from boardfs.ext2_volume_io import Ext2VolumeAccess
from boardfs.registry import FsRegistry
from boardfs.tl_chain import (
    OPENTLA4_SLICE_NAME,
    Opentla4VolumeResult,
    assemble_opentla4_volume,
    buffer_has_ext2_signature,
    ext2_slice_has_mountable_root,
    infer_ext2_opentla4_chain_aware,
    linear_opentla4_bytes,
)

from paceflash.ext2_file_extract import (
    DEFAULT_SQUASH_IMAGE_PATHS,
    DEFAULT_UIMAGE_PATHS,
    ext2_file_sources_from_block_dev,
    probe_embedded_squash_images,
    try_dissect_ext2_file_root,
)

@dataclass
class Opentla4ExtractResult:
    slice_name: str
    slice_bytes: bytes
    ext2_sb_offset: int | None = None
    root_ls: list[dict[str, Any]] | None = None
    embedded_squash_images: list[dict[str, Any]] = field(default_factory=list)
    squash_file_probe: list[dict[str, Any]] = field(default_factory=list)
    extracted_files: dict[str, bytes] = field(default_factory=dict)
    ext2_magic_ok: bool = False
    recovery: str | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    read_model: str = "ext2_file_extract"
    ntl_assembly: dict[str, Any] | None = None
    access: Ext2VolumeAccess | None = None


def _volume_to_extract(vol: Opentla4VolumeResult) -> Opentla4ExtractResult:
    return Opentla4ExtractResult(
        slice_name=vol.slice_name,
        slice_bytes=vol.slice_bytes,
        ext2_sb_offset=vol.ext2_sb_offset,
        ext2_magic_ok=vol.ext2_magic_ok,
        recovery=vol.recovery,
        error=vol.error,
        warnings=list(vol.warnings),
        read_model=vol.read_model,
        ntl_assembly=vol.ntl_assembly,
    )


def extract_opentla4_filesystem(
    reg: FsRegistry,
    *,
    slice_name: str = OPENTLA4_SLICE_NAME,
    paths: tuple[str, ...] = DEFAULT_SQUASH_IMAGE_PATHS,
    uimage_paths: tuple[str, ...] = DEFAULT_UIMAGE_PATHS,
    probe_embedded_squash: bool = True,
    collect_ntl_telemetry: bool = False,
    lazy_assembly: bool = False,
) -> Opentla4ExtractResult:
    """Mount ext2 on assembled slice bytes; extract known image paths.

    Corpus indexing and bulk inventory passes ``lazy_assembly=False`` (full ~120 MiB
    NTL materialization). Interactive ``paceflash cat`` uses lazy assembly by default.
    """
    vol = assemble_opentla4_volume(
        reg,
        slice_name=slice_name,
        collect_page_histogram=collect_ntl_telemetry,
        lazy_assembly=lazy_assembly,
    )
    out = _volume_to_extract(vol)
    if out.error and not out.slice_bytes:
        return out

    sb = out.ext2_sb_offset
    if sb is None and out.slice_bytes:
        sb = resolve_mountable_ext2_superblock_offset(out.slice_bytes)
        if sb is not None:
            out.ext2_sb_offset = sb

    dev: BlockSlice = AssembledBlockDev(
        label=slice_name, size=len(out.slice_bytes), data=out.slice_bytes
    )

    if sb is not None:
        try:
            rows, meta = list_root_for_block_dev_with_meta(dev, cap=50, sb_off=sb)
            out.root_ls = rows
            if isinstance(meta.get("ext2_superblock_offset"), int):
                out.ext2_sb_offset = meta["ext2_superblock_offset"]
        except Exception as e:
            out.error = f"{type(e).__name__}: {e}"
    elif out.ext2_magic_ok and out.error:
        out.recovery = out.recovery or "superblock_scan"
    elif not out.error:
        out.error = "no ext2 container on opentla4 slice"

    if sb is not None:
        from paceflash.flash_session import _opentla4_volume_access

        out.access = _opentla4_volume_access(reg, vol, slice_name=slice_name, sb_off=sb)
        if probe_embedded_squash:
            probe_rows = probe_embedded_squash_images(out.slice_bytes, paths, sb_off=sb)
            out.embedded_squash_images = probe_rows
            out.squash_file_probe = probe_rows
        try:
            all_paths = tuple(dict.fromkeys((*paths, *uimage_paths)))
            sources, _, sb2 = ext2_file_sources_from_block_dev(
                dev, all_paths, access=out.access
            )
            if sb2 is not None:
                out.ext2_sb_offset = sb2
            for label, body in sources:
                path = label.split(":", 1)[-1] if ":" in label else label
                out.extracted_files[path] = body
        except Exception as e:
            out.warnings.append(f"embedded ext2 file extract failed: {type(e).__name__}: {e}")

    return out


def opentla4_extract_to_jsonable(result: Opentla4ExtractResult) -> dict[str, Any]:
    files_meta: list[dict[str, Any]] = []
    for path, body in sorted(result.extracted_files.items()):
        row: dict[str, Any] = {
            "path": path,
            "size": len(body),
            "sha256_head16": hashlib.sha256(body[: min(len(body), 65536)]).hexdigest()[:16],
        }
        if len(body) >= 4:
            from lib2spy.native_pkgstream import squashfs_le_span_at

            if body[:4] == b"hsqs":
                span = squashfs_le_span_at(body, 0)
                if span is not None:
                    _, slen = span
                    row["strict_squash_len"] = slen
                    row["strict_squash_sha256"] = hashlib.sha256(body[:slen]).hexdigest()
        files_meta.append(row)
    return {
        "slice": result.slice_name,
        "slice_len_bytes": len(result.slice_bytes),
        "ext2_magic_ok": result.ext2_magic_ok,
        "ext2_superblock_offset": result.ext2_sb_offset,
        "root_ls": result.root_ls,
        "embedded_squash_images": result.embedded_squash_images,
        "squash_file_probe": result.squash_file_probe,
        "extracted_file_paths": sorted(result.extracted_files),
        "extracted_files": files_meta,
        "recovery": result.recovery,
        "error": result.error,
        "warnings": result.warnings,
        "read_model": result.read_model,
        "ntl_assembly": result.ntl_assembly,
    }


def write_opentla4_ext2_image(result: Opentla4ExtractResult, out_path: Path) -> dict[str, Any]:
    p = out_path.expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(result.slice_bytes)
    return {
        "path": str(p),
        "bytes_written": len(result.slice_bytes),
        "kind": "opentla4_ext2_partition",
        "ext2_magic_ok": result.ext2_magic_ok,
    }


def write_extracted_ext2_files(
    result: Opentla4ExtractResult,
    out_dir: Path,
) -> dict[str, Any]:
    root = out_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    written: list[dict[str, Any]] = []
    for path, body in sorted(result.extracted_files.items()):
        dest = root.joinpath(*Path(path).parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body)
        entry: dict[str, Any] = {"path": path, "dest": str(dest), "size": len(body)}
        if len(body) >= 4 and body[:4] == b"hsqs":
            from lib2spy.native_pkgstream import squashfs_le_span_at

            span = squashfs_le_span_at(body, 0)
            if span is not None:
                _, slen = span
                entry["strict_squash_sha256"] = hashlib.sha256(body[:slen]).hexdigest()
        written.append(entry)
    manifest = {
        "slice": result.slice_name,
        "ext2_superblock_offset": result.ext2_sb_offset,
        "files": written,
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "dir": str(root),
        "manifest": str(manifest_path),
        "files_written": len(written),
        "files": written,
    }


def ext2_block_from_extract(result: Opentla4ExtractResult) -> dict[str, Any]:
    block: dict[str, Any] = {
        "slice": result.slice_name,
        "root_ls": result.root_ls,
        "error": result.error,
        "ext2_superblock_offset": result.ext2_sb_offset,
        "embedded_squash_images": result.embedded_squash_images,
        "squash_file_probe": result.squash_file_probe,
        "read_model": result.read_model,
        "ext2_magic_ok": result.ext2_magic_ok,
        "ntl_assembly": result.ntl_assembly,
        "recovery": result.recovery,
        "extracted_file_paths": sorted(result.extracted_files),
    }
    for w in result.warnings:
        if block.get("error"):
            block["error"] = f"{block['error']}; {w}"
        else:
            block.setdefault("notes", []).append(w)
    return block


def squash_block_from_ext2_extract(
    result: Opentla4ExtractResult,
) -> dict[str, Any] | None:
    dev = AssembledBlockDev(
        label=result.slice_name, size=len(result.slice_bytes), data=result.slice_bytes
    )
    sq = try_dissect_ext2_file_root(dev)
    if sq is not None:
        return {"slice": result.slice_name, "error": None, **sq}
    return None


_linear_tlpart_slice_bytes = linear_opentla4_bytes
