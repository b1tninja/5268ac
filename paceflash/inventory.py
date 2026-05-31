"""Assemble a JSON-serializable flash inventory from ``boardfs``, ``unand``, and optional ``dissect.extfs``."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from typing import Any

from boardfs import (
    FsRegistry,
    TranslateMode,
    apply_chain_aware_virtual_tl_scan,
    audit_tl_kernel_alignment_bytes,
    bbm_virtual_scan_summary,
    buffer_has_tl_disklabel_anchor,
    flash_image_from_cmdline,
    flash_plane_sector0_prefix_bytes,
    infer_chain_aware_tl_scan,
    infer_chain_aware_virtual_tl_scan,
    list_root_for_block_dev_with_meta,
    scan_ubi_vid_headers_on_block_dev,
    temporary_registry_from_physical_nand,
)
from boardfs.ubi_cmdline import UbiMtdAttachSpec
from paceflash.squashfs_dissect import find_squashfs_superblock_offsets
from paceflash.mtd_partition_probes import run_mtd_partition_probes
from paceflash.ext2_file_extract import (
    ext2_file_sources_from_block_dev,
    try_dissect_ext2_file_root,
)
from boardfs.tl_chain import buffer_has_ext2_signature
from paceflash.opentla4_extract import (
    Opentla4ExtractResult,
    ext2_block_from_extract,
    extract_opentla4_filesystem,
    opentla4_extract_to_jsonable,
    squash_block_from_ext2_extract,
    write_extracted_ext2_files,
    write_opentla4_ext2_image,
)
from paceflash.upgrade_correlation import (
    load_carrier_refs,
    load_carrier_refs_collection,
    run_correlation_with_ext2_files,
)
from unand.geometry import PACE_DEFAULT, effective_mtd_reference_size
from unand.mtd import DEFAULT_MTDPARTS

_ROOT_LS_CAP = 50

_PHYSICAL_SKIP_MSG = (
    "Physical full-chip NAND dump: mtdparts offsets refer to the logical data plane, "
    "but this file is still packed as data+spare per page (or logical+oob tail). "
    "Run nand-translate or use a logicalized image before TL disklabel, ext2, or UBI VID scans."
)

_SQUASH_EXT2_ONLY_MSG = (
    "SquashFS on this product lives in ext2 files (e.g. sys1/rootimage.img), not as a raw TL partition. "
    "Mount ext2 on the opentla4 slice (--extract-ext2-dir or opentla4_extract), then dissect the embedded .img file."
)


def _warn(warnings: list[str], msg: str, *, debug: bool, debug_only: bool = False) -> None:
    """Append to inventory warnings; skip ``debug_only`` messages unless ``debug`` is true."""
    if debug_only and not debug:
        return
    warnings.append(msg)


def _physical_pace_envelope(file_size: int) -> bool:
    """True when ``file_size`` matches a full-chip Pace physical dump (inline or flat-tail)."""
    return file_size in (
        PACE_DEFAULT.full_inline_bytes,
        PACE_DEFAULT.full_flat_tail_bytes,
    )


def _slice_as_dict(s: Any) -> dict[str, Any]:
    return {
        "name": s.name,
        "index": s.index,
        "start_sector": s.start_sector,
        "num_sectors": s.num_sectors,
        "ptype": s.ptype,
        "offset_bytes": s.offset_bytes,
        "length_bytes": s.length_bytes,
    }


def _ubi_spec_as_dict(s: UbiMtdAttachSpec) -> dict[str, Any]:
    return {
        "raw_token": s.raw_token,
        "mtd_ref": s.mtd_ref,
        "mtd_sub_offset": s.mtd_sub_offset,
    }


def _jsonable_fields(d: dict[str, object]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[str(k)] = v
        elif isinstance(v, bytes):
            out[str(k)] = v.hex()
        else:
            out[str(k)] = repr(v)
    return out


def _squash_block_from_ext2_layer(
    reg: FsRegistry,
    tl_slice: str,
    *,
    opentla4_extract_result: Opentla4ExtractResult | None,
    ext2_block: dict[str, Any] | None,
    debug: bool = False,
) -> dict[str, Any]:
    """SquashFS inventory via ext2-embedded files only (no partition-level ``hsqs`` scan)."""
    block: dict[str, Any] = {
        "slice": tl_slice,
        "root_ls": None,
        "error": None,
        "read_model": "ext2_file_extract",
    }
    if opentla4_extract_result is not None:
        ext2_sq = squash_block_from_ext2_extract(opentla4_extract_result)
        if ext2_sq is not None:
            block.update(ext2_sq)
            return block
        if opentla4_extract_result.extracted_files:
            for path, body in opentla4_extract_result.extracted_files.items():
                if len(body) < 4:
                    continue
                try:
                    from paceflash.squashfs_dissect import list_squashfs_root_entries_with_meta

                    rows, meta_sq = list_squashfs_root_entries_with_meta(
                        body, cap=_ROOT_LS_CAP, prefer_offsets=[0]
                    )
                    block.update(
                        {
                            "root_ls": rows,
                            "path": path,
                            "source": f"ext2_file:{path}",
                            "squashfs_superblock_offset": meta_sq.get(
                                "squashfs_superblock_offset", 0
                            ),
                            "squashfs_image_bytes": meta_sq.get(
                                "squashfs_image_bytes", len(body)
                            ),
                        }
                    )
                    block["error"] = None
                    return block
                except Exception:
                    continue
    ext2_has_root = (
        isinstance(ext2_block, dict)
        and ext2_block.get("root_ls")
        and not ext2_block.get("error")
    )
    if ext2_has_root:
        try:
            dev_sq = reg.block_dev_for_tl_slice(tl_slice)
            ext2_sq = try_dissect_ext2_file_root(dev_sq)
            if ext2_sq is not None:
                block.update(ext2_sq)
                block["error"] = None
                return block
        except Exception as e:
            block["error"] = f"{type(e).__name__}: {e}"
            return block
    if isinstance(ext2_block, dict) and ext2_block.get("error"):
        block["error"] = (
            f"{ext2_block['error']} — {_SQUASH_EXT2_ONLY_MSG}"
            if debug
            else str(ext2_block["error"])
        )
    elif debug:
        block["error"] = _SQUASH_EXT2_ONLY_MSG
    else:
        block["error"] = "ext2 root listing unavailable"
    return block


def _nand_translate_summary(
    *,
    ran: bool,
    manifest: dict[str, Any] | None = None,
    error: str | None = None,
    skipped: bool = False,
) -> dict[str, Any]:
    out: dict[str, Any] = {"ran": ran}
    if skipped:
        out["skipped"] = True
    if error:
        out["error"] = error
        return out
    if manifest:
        for k in ("resolved_mode", "logical_size", "requested_mode", "unand_layout", "source_size"):
            if k in manifest:
                out[k] = manifest[k]
    return out


def _probe_fs_layers(
    reg: FsRegistry,
    ubi_specs: list[UbiMtdAttachSpec],
    *,
    include_ext2_root: bool,
    include_squashfs_root: bool,
    tl_slice: str,
    ubi_erase_bytes: int,
    debug: bool = False,
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    dict[str, Any] | None,
    dict[str, Any] | None,
    list[dict[str, Any]],
    Opentla4ExtractResult | None,
]:
    try:
        tlp_blob = (
            reg.tlpart_tl_scan_bytes
            if reg.tlpart_tl_scan_bytes is not None
            else reg.flash.read_partition("tlpart")
        )
    except KeyError:
        sector_audit: dict[str, Any] = {"error": "no mtd partition named tlpart"}
        tl_block: dict[str, Any] = {"ok": False, "sector_audit": sector_audit}
        squash_rows: list[dict[str, Any]] = []
        tl_block["error"] = "no tlpart partition"
        ext2_block: dict[str, Any] | None = None
        if include_ext2_root:
            ext2_block = {"slice": tl_slice, "root_ls": None, "error": "no tlpart partition"}
        squash_block: dict[str, Any] | None = None
        if include_squashfs_root:
            squash_block = {"slice": tl_slice, "root_ls": None, "error": "no tlpart partition"}
        ubi_scans: list[dict[str, Any]] = []
        for spec in ubi_specs:
            ubi_scans.append(
                {
                    "mtd_ref": spec.mtd_ref,
                    "mtd_sub_offset": spec.mtd_sub_offset,
                    "error": "no tlpart partition",
                    "vid_hits": [],
                }
            )
        return tl_block, squash_rows, ext2_block, squash_block, ubi_scans, None

    plane512 = flash_plane_sector0_prefix_bytes(reg.flash)
    sector_audit = audit_tl_kernel_alignment_bytes(tlp_blob, plane_sector0_prefix=plane512)
    tl_block: dict[str, Any] = {"ok": False, "sector_audit": sector_audit}
    squash_rows: list[dict[str, Any]] = []
    try:
        tl_enum = reg.enumerate_tlpart_tl()
        tl_block = {
            "ok": True,
            "anchor_offset": tl_enum.anchor_offset,
            "anchor_kind": tl_enum.anchor_kind,
            "warnings": list(tl_enum.warnings),
            "notes": list(tl_enum.notes),
            "slices": [_slice_as_dict(s) for s in tl_enum.slices],
            "sector_audit": sector_audit,
        }
    except Exception as e:
        tl_block = {"ok": False, "error": f"{type(e).__name__}: {e}", "sector_audit": sector_audit}

    ext2_block: dict[str, Any] | None = None
    opentla4_extract_result: Opentla4ExtractResult | None = None
    if include_ext2_root:
        #region kernel_adjacent inventory_tl_scan_opentla4_extract
        try:
            opentla4_extract_result = extract_opentla4_filesystem(
                reg,
                slice_name=tl_slice,
                probe_embedded_squash=debug,
            )
            ext2_block = ext2_block_from_extract(opentla4_extract_result)
            if debug and opentla4_extract_result.error and opentla4_extract_result.recovery:
                ext2_block["error"] = (
                    f"{opentla4_extract_result.error} (recovery={opentla4_extract_result.recovery})"
                )
                if opentla4_extract_result.extracted_files:
                    ext2_block["error"] = None
            slice_data = opentla4_extract_result.slice_bytes
            if debug and ext2_block.get("error") and buffer_has_ext2_signature(slice_data):
                ext2_block["error"] = (
                    f"{ext2_block['error']} — {tl_slice!r} has ext2 signature at 0x438; "
                    f"{_SQUASH_EXT2_ONLY_MSG}"
                )
                if opentla4_extract_result.extracted_files:
                    ext2_block["error"] = None
        except ImportError as e:
            ext2_block = {"slice": tl_slice, "root_ls": None, "error": str(e)}
        except Exception as e:
            ext2_block = {"slice": tl_slice, "root_ls": None, "error": f"{type(e).__name__}: {e}"}
        #endregion

    squash_block: dict[str, Any] | None = None
    if include_squashfs_root:
        try:
            squash_block = _squash_block_from_ext2_layer(
                reg,
                tl_slice,
                opentla4_extract_result=opentla4_extract_result,
                ext2_block=ext2_block,
                debug=debug,
            )
        except ImportError as e:
            squash_block = {"slice": tl_slice, "root_ls": None, "error": str(e)}
        except Exception as e:
            squash_block = {
                "slice": tl_slice,
                "root_ls": None,
                "error": f"{type(e).__name__}: {e}",
                "read_model": "ext2_file_extract",
            }

    ubi_scans: list[dict[str, Any]] = []
    for spec in ubi_specs:
        try:
            bd = reg.block_dev_for_ubi_mtd_attach(spec)
            hits = scan_ubi_vid_headers_on_block_dev(bd, erase_bytes=ubi_erase_bytes)
            ubi_scans.append(
                {
                    "mtd_ref": spec.mtd_ref,
                    "mtd_sub_offset": spec.mtd_sub_offset,
                    "backing_label": bd.label,
                    "backing_offset": bd.offset,
                    "backing_size": bd.size,
                    "vid_hits": [
                        {"vid_offset": h.vid_offset, "fields": _jsonable_fields(dict(h.fields))}
                        for h in hits
                    ],
                }
            )
        except Exception as e:
            ubi_scans.append(
                {
                    "mtd_ref": spec.mtd_ref,
                    "mtd_sub_offset": spec.mtd_sub_offset,
                    "error": f"{type(e).__name__}: {e}",
                    "vid_hits": [],
                }
            )

    return tl_block, squash_rows, ext2_block, squash_block, ubi_scans, opentla4_extract_result


def _physical_skip_blocks(
    ubi_specs: list[UbiMtdAttachSpec],
    *,
    include_ext2_root: bool,
    include_squashfs_root: bool,
    tl_slice: str,
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
    dict[str, Any] | None,
    dict[str, Any] | None,
    list[dict[str, Any]],
    Opentla4ExtractResult | None,
]:
    tl_block = {
        "ok": False,
        "error": _PHYSICAL_SKIP_MSG,
        "sector_audit": {"skipped": True, "reason": "physical_nand_skip_or_translate_failed"},
    }
    squash_rows: list[dict[str, Any]] = []
    ext2_block: dict[str, Any] | None = None
    if include_ext2_root:
        ext2_block = {"slice": tl_slice, "root_ls": None, "error": _PHYSICAL_SKIP_MSG}
    squash_block: dict[str, Any] | None = None
    if include_squashfs_root:
        squash_block = {"slice": tl_slice, "root_ls": None, "error": _PHYSICAL_SKIP_MSG}
    ubi_scans = [
        {
            "mtd_ref": spec.mtd_ref,
            "mtd_sub_offset": spec.mtd_sub_offset,
            "error": _PHYSICAL_SKIP_MSG,
            "vid_hits": [],
        }
        for spec in ubi_specs
    ]
    return tl_block, squash_rows, ext2_block, squash_block, ubi_scans, None


def _merge_ext2_into_correlation(
    reg: FsRegistry,
    tl_slice: str,
    carrier_refs: list[Any],
    report: dict[str, Any] | None,
    *,
    extract_result: Opentla4ExtractResult | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Re-run / extend carrier correlation with ext2-extracted image file bytes."""
    merge_warnings: list[str] = []
    try:
        if extract_result is not None and extract_result.extracted_files:
            ext2_sources = [
                (f"ext2_file:{path}", body)
                for path, body in extract_result.extracted_files.items()
            ]
            probe_rows = extract_result.squash_file_probe
        else:
            dev = reg.block_dev_for_tl_slice(tl_slice)
            ext2_sources, probe_rows, _sb = ext2_file_sources_from_block_dev(dev)
        if ext2_sources:
            _, merged = run_correlation_with_ext2_files(
                [],
                ext2_sources,
                carrier_refs,
                ext2_probe_rows=probe_rows,
            )
            return merged, merge_warnings
        merge_warnings.append(
            f"no ext2 file sources extracted from {tl_slice!r} for carrier correlation"
        )
    except Exception as e:
        merge_warnings.append(
            f"ext2 correlation merge failed ({type(e).__name__}: {e})"
        )
    return report, merge_warnings


def _dump_tl_slice_outputs(
    reg: FsRegistry,
    tl_slice: str,
    warnings: list[str],
    *,
    full_out: str | Path | None = None,
) -> dict[str, Any] | None:
    """Write assembled TL child partition bytes (ext2 container; not a raw SquashFS partition)."""
    if full_out is None:
        return None
    try:
        blob = reg.block_dev_for_tl_slice(tl_slice).read_slice()
    except Exception as e:
        warnings.append(f"paceflash: TL slice read failed for dump: {type(e).__name__}: {e}")
        return None
    try:
        outp_f = Path(full_out).expanduser().resolve()
        outp_f.parent.mkdir(parents=True, exist_ok=True)
        outp_f.write_bytes(blob)
        return {
            "path": str(outp_f),
            "slice": tl_slice,
            "bytes_written": len(blob),
            "kind": "full_tl_partition",
        }
    except Exception as e:
        warnings.append(f"paceflash: TL slice dump failed: {type(e).__name__}: {e}")
        return None


def build_inventory(
    flash_path: str | Path,
    *,
    cmdline: str | None = None,
    include_ext2_root: bool = True,
    include_squashfs_root: bool = True,
    tl_slice: str = "opentla4",
    ubi_erase_bytes: int = 131072,
    nand_translate: bool = True,
    nand_translate_mode: TranslateMode = "inline-2112",
    bbm_chain_aware: bool = False,
    dump_tl_slice_out: str | Path | None = None,
    lib2spy_json: str | Path | None = None,
    pkgstream_path: str | Path | None = None,
    firmware_collection: str | Path | None = None,
    carrier_index_json: str | Path | None = None,
    probe_loader_env: bool = False,
    probe_mtdoops: bool = False,
    mtdoops_record_size: int = 131072,
    dump_opentla4_ext2: str | Path | None = None,
    extract_ext2_dir: str | Path | None = None,
    debug: bool = False,
) -> dict[str, Any]:
    """
    Build a dict describing MTD layout, TL slices, optional dissect.extfs / embedded SquashFS in ext2 files
    for ``tl_slice``, and ``ubi.mtd=`` attachments with VID header hits on each backing region.

    SquashFS is **not** scanned at the TL partition level (no ``hsqs`` grep on ``opentla4`` slice bytes).
    Use ``squashfs`` / ``opentla4_extract.embedded_squash_images`` after ext2 mounts and
    ``--extract-ext2-dir`` to obtain ``sys1/rootimage.img`` payloads.

    For full-chip Pace **physical** envelope sizes (inline or flat-tail packed), when ``nand_translate`` is
    true (default), the image is logicalized in memory (``nand_translate_to_bytes``) before TL / ext2 / UBI scans.

    When ``dump_tl_slice_out`` is set, writes the assembled ``tl_slice`` ext2 container bytes (not a SquashFS carve).
    """
    #region kernel_adjacent build_inventory_nand_junction (paceflash ↔ boardfs ↔ opentl via temporary_registry_from_physical_nand; see reference/layers_unand_uboot_opentl_boardfs_paceflash.md)
    p = Path(flash_path).expanduser().resolve()
    file_size = os.path.getsize(p)
    logical_ref = effective_mtd_reference_size(file_size, geom=PACE_DEFAULT)

    line = cmdline if cmdline is not None else f"quiet rw {DEFAULT_MTDPARTS}"

    warnings: list[str] = []
    if file_size == PACE_DEFAULT.full_inline_bytes:
        _warn(
            warnings,
            "file size matches full inline NAND dump (data+spare per page); "
            "use logicalized image or nand-translate before mtdparts offsets match kernel MTD",
            debug=debug,
            debug_only=True,
        )
    elif file_size == PACE_DEFAULT.full_flat_tail_bytes:
        _warn(
            warnings,
            "file size matches full flat-tail NAND dump (logical+oob); "
            "logicalize or nand-translate for mtdparts-relative tooling",
            debug=debug,
            debug_only=True,
        )

    flash = flash_image_from_cmdline(p, line)
    reg_base = FsRegistry(flash=flash, cmdline=line)
    reg_active: FsRegistry = reg_base

    mtd: list[dict[str, Any]] = []
    for part in flash.partitions:
        mtd.append(
            {
                "index": part.index,
                "name": part.name,
                "offset": part.offset,
                "size": part.size,
                "remainder": part.remainder,
            }
        )

    physical_full_nand = _physical_pace_envelope(file_size)

    ubi_specs = list(reg_base.ubi_mtd_attach_specs())
    ubi_list = [_ubi_spec_as_dict(s) for s in ubi_specs]

    nand_meta: dict[str, Any]
    bbm_scan: dict[str, Any] | None = None
    tl_slice_dump_info: dict[str, Any] | None = None
    upgrade_nand_correlation: dict[str, Any] | None = None
    mtd_partition_probes: dict[str, Any] | None = None
    opentla4_extract_block: dict[str, Any] | None = None
    opentla4_ext2_dump_info: dict[str, Any] | None = None
    opentla4_files_dump_info: dict[str, Any] | None = None
    opentla4_extract_result: Opentla4ExtractResult | None = None
    carrier_refs = None
    if firmware_collection is not None:
        try:
            index_path = (
                Path(carrier_index_json).expanduser()
                if carrier_index_json is not None
                else None
            )
            carrier_refs = load_carrier_refs_collection(
                Path(firmware_collection),
                carrier_index_json=index_path,
            )
        except Exception as e:
            warnings.append(
                f"paceflash: 00D09E carrier collection failed ({type(e).__name__}: {e})"
            )
    elif lib2spy_json is not None:
        try:
            carrier_refs = load_carrier_refs(
                Path(lib2spy_json),
                Path(pkgstream_path) if pkgstream_path is not None else None,
            )
        except Exception as e:
            warnings.append(
                f"paceflash: upgrade carrier refs failed ({type(e).__name__}: {e})"
            )

    if physical_full_nand and nand_translate:
        bbm_chain_infer_outer: dict[str, Any] | None = None
        try:
            with temporary_registry_from_physical_nand(
                p, line, geom=PACE_DEFAULT, translate_mode=nand_translate_mode
            ) as (reg, man, ot_session):
                reg_active = reg
                chain_applied = False
                infer_tl_heuristic = False
                infer_ext2_o4 = False
                infer_primary_while_linear_hsqs = False
                want_chain = False
                virt_mode_before: str | None = None
                spare_path_ok = False
                linear_has_hsqs_flag = False
                pre_virt_has_hsqs_flag = False
                pre_virt_len: int | None = None
                if ot_session is not None and man.get("tl_bbm_attached"):
                    spare_p = man.get("flat_spare_path")
                    spare_path_ok = isinstance(spare_p, str) and Path(spare_p).is_file()
                    virt_mode_before = ot_session.virt_nand_page_table.mode
                    linear_tlp: bytes | None = None
                    try:
                        linear_tlp = reg.flash.read_partition("tlpart")
                    except KeyError:
                        linear_tlp = None
                    pre_virt_tl_scan = reg.tlpart_tl_scan_bytes
                    pre_virt_len = len(pre_virt_tl_scan) if pre_virt_tl_scan is not None else None
                    linear_has_hsqs_flag = linear_tlp is not None and b"hsqs" in linear_tlp
                    pre_virt_has_hsqs_flag = (
                        pre_virt_tl_scan is not None and b"hsqs" in pre_virt_tl_scan
                    )
                    infer_tl_heuristic = infer_chain_aware_tl_scan(
                        tlpart_tl_scan_bytes=pre_virt_tl_scan,
                        linear_tlpart=linear_tlp,
                    )
                    infer_ext2_o4 = False
                    if tl_slice == "opentla4":
                        try:
                            from boardfs import infer_ext2_opentla4_chain_aware

                            infer_ext2_o4 = infer_ext2_opentla4_chain_aware(reg)
                        except Exception:
                            infer_ext2_o4 = False
                    infer_primary_while_linear_hsqs = (
                        not infer_tl_heuristic
                        and linear_tlp is not None
                        and b"hsqs" in linear_tlp
                        and ot_session.virt_nand_page_table.mode == "primary"
                    )
                    want_chain = bbm_chain_aware or (
                        not bbm_chain_aware
                        and (
                            infer_chain_aware_virtual_tl_scan(
                                reg,
                                linear_tlpart=linear_tlp,
                                ot_session=ot_session,
                                tl_slice=tl_slice,
                            )
                            or infer_ext2_o4
                        )
                    )
                    if want_chain and not spare_path_ok:
                        _warn(
                            warnings,
                            "paceflash: chain-aware BBM was inferred/recommended but flat spare "
                            "path is missing or unreadable — TL reads stay primary VirtNandPageTable-only",
                            debug=debug,
                            debug_only=True,
                        )
                    if want_chain and isinstance(spare_p, str) and Path(spare_p).is_file():
                        apply_chain_aware_virtual_tl_scan(
                            reg,
                            ot_session,
                            Path(spare_p).read_bytes(),
                        )
                        chain_applied = True
                        if not bbm_chain_aware:
                            pre = pre_virt_tl_scan
                            detail = (
                                "virt stream head was zeroed but linear tlpart has payload"
                            )
                            if (
                                linear_tlp is not None
                                and pre is not None
                                and buffer_has_tl_disklabel_anchor(linear_tlp)
                                and not buffer_has_tl_disklabel_anchor(pre)
                            ):
                                detail = (
                                    "linear ``tlpart`` has TL disklabel anchor but primary BBM virt "
                                    "stream did not; spare-chain replay aligns with kernel ntl_read_page"
                                )
                            elif (
                                linear_tlp is not None
                                and pre is not None
                                and b"hsqs" in linear_tlp
                                and b"hsqs" not in pre
                            ):
                                detail = (
                                    "linear ``tlpart`` contains squash magic but BBM virt scan stream "
                                    "did not; spare-chain replay may restore omitted virt pages"
                                )
                            elif infer_ext2_o4:
                                detail = (
                                    "linear opentla4 has ext2 signature but BBM-assembled slice did not "
                                    "mount; spare-chain replay may restore ext2 file layout"
                                )
                            elif infer_primary_while_linear_hsqs:
                                detail = (
                                    "VirtNandPageTable was primary while linear ``tlpart`` has squash "
                                    "magic; spare-chain replay matches kernel ntl_read_page substitution"
                                )
                            elif pre is not None and len(pre) >= 64 and pre[:64] == b"\x00" * 64:
                                detail = (
                                    "virt stream head was zeroed but linear tlpart has payload"
                                )
                            _warn(
                                warnings,
                                "paceflash: applied chain-aware BBM virtual scan automatically "
                                f"({detail})",
                                debug=debug,
                                debug_only=True,
                            )
                    virt_mode_after = ot_session.virt_nand_page_table.mode
                    bbm_chain_infer_outer = {
                        "virt_nand_page_table_mode_before_apply": virt_mode_before,
                        "virt_nand_page_table_mode_after_decision": virt_mode_after,
                        "infer_tl_heuristic": infer_tl_heuristic,
                        "infer_ext2_opentla4": infer_ext2_o4,
                        "infer_primary_while_linear_hsqs": infer_primary_while_linear_hsqs,
                        "want_chain": want_chain,
                        "chain_applied": chain_applied,
                        "flat_spare_path_ok": spare_path_ok,
                        "linear_has_hsqs": linear_has_hsqs_flag,
                        "pre_virt_tl_scan_has_hsqs": pre_virt_has_hsqs_flag,
                        "pre_virt_tl_scan_len": pre_virt_len,
                        "bbm_chain_aware_cli": bool(bbm_chain_aware),
                    }
                if ot_session is not None and man.get("tl_bbm_attached"):
                    bbm_scan = bbm_virtual_scan_summary(
                        reg, ot_session, chain_aware_applied=chain_applied
                    )
                tl_block, squash_rows, ext2_block, squash_block, ubi_scans, opentla4_extract_result = (
                    _probe_fs_layers(
                        reg,
                        ubi_specs,
                        include_ext2_root=include_ext2_root,
                        include_squashfs_root=include_squashfs_root,
                        tl_slice=tl_slice,
                        ubi_erase_bytes=ubi_erase_bytes,
                        debug=debug,
                    )
                )
                if dump_tl_slice_out is not None:
                    tl_slice_dump_info = _dump_tl_slice_outputs(
                        reg,
                        tl_slice,
                        warnings,
                        full_out=dump_tl_slice_out,
                    )
                if probe_loader_env or probe_mtdoops:
                    try:
                        mtd_partition_probes = run_mtd_partition_probes(
                            reg.flash,
                            probe_loader=probe_loader_env,
                            probe_mtdoops_flag=probe_mtdoops,
                            mtdoops_record_size=mtdoops_record_size,
                        )
                        for w in mtd_partition_probes.get("warnings") or []:
                            warnings.append(f"paceflash: {w}")
                    except Exception as e:
                        warnings.append(
                            f"paceflash: mtd partition probes failed ({type(e).__name__}: {e})"
                        )
            nand_meta = _nand_translate_summary(ran=True, manifest=man)
            if man.get("tl_bbm_attached"):
                nand_meta["tl_bbm_attached"] = True
                if "tl_bbm_mode" in man:
                    nand_meta["tl_bbm_mode"] = man["tl_bbm_mode"]
            elif man.get("tl_bbm_attach_error"):
                err = str(man["tl_bbm_attach_error"])
                nand_meta["tl_bbm_attach_error"] = err
                warnings.append(f"TL BBM not attached: {err}")
            if bbm_chain_infer_outer is not None:
                nand_meta["bbm_chain_infer"] = bbm_chain_infer_outer
            if debug and (
                isinstance(squash_block, dict)
                and squash_block.get("error")
                and bbm_chain_infer_outer is not None
                and bbm_chain_infer_outer.get("want_chain")
                and not bbm_chain_infer_outer.get("chain_applied")
            ):
                ci = bbm_chain_infer_outer
                squash_block["error"] = (
                    f"{squash_block['error']} — BBM chain-aware was inferred/recommended but did not run "
                    f"(flat_spare_path_ok={ci.get('flat_spare_path_ok')}, "
                    f"virt_table_before={ci.get('virt_nand_page_table_mode_before_apply')!r}). "
                    "Inspect nand_translate.bbm_chain_infer (paceflash ls --json)."
                )
            if isinstance(tl_block, dict) and not tl_block.get("ok"):
                _warn(
                    warnings,
                    "TL disklabel enumeration failed after NAND translate; if this is a flat-tail "
                    "physical capture mis-detected as inline, retry with --nand-mode flat-tail",
                    debug=debug,
                    debug_only=True,
                )
            if debug:
                print(
                    "paceflash: logicalized raw NAND dump in memory for TL/ext2/UBI scans",
                    file=sys.stderr,
                )
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            tl_block, squash_rows, ext2_block, squash_block, ubi_scans, opentla4_extract_result = (
                _physical_skip_blocks(
                    ubi_specs,
                    include_ext2_root=include_ext2_root,
                    include_squashfs_root=include_squashfs_root,
                    tl_slice=tl_slice,
                )
            )
            nand_meta = _nand_translate_summary(ran=True, error=err)
            warnings.append(f"nand_translate failed: {err}")
            if dump_tl_slice_out is not None:
                warnings.append("paceflash: --dump-tl-slice skipped (nand_translate failed)")
    elif physical_full_nand:
        tl_block, squash_rows, ext2_block, squash_block, ubi_scans, opentla4_extract_result = (
            _physical_skip_blocks(
                ubi_specs,
                include_ext2_root=include_ext2_root,
                include_squashfs_root=include_squashfs_root,
                tl_slice=tl_slice,
            )
        )
        nand_meta = _nand_translate_summary(ran=False, skipped=True)
        if dump_tl_slice_out is not None:
            warnings.append(
                "paceflash: --dump-tl-slice needs in-memory nand_translate on physical Pace dumps "
                "(omit --no-nand-translate)"
            )
    else:
        tl_block, squash_rows, ext2_block, squash_block, ubi_scans, opentla4_extract_result = (
            _probe_fs_layers(
                reg_base,
                ubi_specs,
                include_ext2_root=include_ext2_root,
                include_squashfs_root=include_squashfs_root,
                tl_slice=tl_slice,
                ubi_erase_bytes=ubi_erase_bytes,
                debug=debug,
            )
        )
        nand_meta = _nand_translate_summary(ran=False)
        if dump_tl_slice_out is not None:
            tl_slice_dump_info = _dump_tl_slice_outputs(
                reg_base,
                tl_slice,
                warnings,
                full_out=dump_tl_slice_out,
            )

    if (probe_loader_env or probe_mtdoops) and mtd_partition_probes is None:
        try:
            mtd_partition_probes = run_mtd_partition_probes(
                reg_base.flash,
                probe_loader=probe_loader_env,
                probe_mtdoops_flag=probe_mtdoops,
                mtdoops_record_size=mtdoops_record_size,
            )
            for w in mtd_partition_probes.get("warnings") or []:
                warnings.append(f"paceflash: {w}")
        except Exception as e:
            warnings.append(
                f"paceflash: mtd partition probes failed ({type(e).__name__}: {e})"
            )

    #region kernel_adjacent build_inventory_opentla4_extract
    if include_ext2_root and tl_slice == "opentla4":
        try:
            if opentla4_extract_result is None:
                opentla4_extract_result = extract_opentla4_filesystem(
                    reg_active,
                    slice_name=tl_slice,
                    probe_embedded_squash=debug,
                    collect_ntl_telemetry=debug,
                )
            opentla4_extract_block = opentla4_extract_to_jsonable(opentla4_extract_result)
            if debug:
                for w in opentla4_extract_result.warnings:
                    warnings.append(f"paceflash: opentla4: {w}")
            if dump_opentla4_ext2 is not None:
                opentla4_ext2_dump_info = write_opentla4_ext2_image(
                    opentla4_extract_result, Path(dump_opentla4_ext2)
                )
            if extract_ext2_dir is not None:
                opentla4_files_dump_info = write_extracted_ext2_files(
                    opentla4_extract_result, Path(extract_ext2_dir)
                )
        except Exception as e:
            warnings.append(
                f"paceflash: opentla4 extract failed ({type(e).__name__}: {e})"
            )
    #endregion

    if carrier_refs is not None:
        merged, merge_warns = _merge_ext2_into_correlation(
            reg_active,
            tl_slice,
            carrier_refs,
            upgrade_nand_correlation,
            extract_result=opentla4_extract_result,
        )
        if merged is not None:
            upgrade_nand_correlation = merged
            for w in merged.get("warnings") or []:
                tag = f"paceflash: {w}"
                if tag not in warnings:
                    warnings.append(tag)
        for w in merge_warns:
            tag = f"paceflash: {w}"
            if tag not in warnings:
                warnings.append(tag)

    #endregion
    return {
        "flash_path": str(p),
        "file_size_bytes": file_size,
        "logical_reference_bytes": logical_ref,
        "cmdline": line,
        "warnings": warnings,
        "mtd": mtd,
        "tl": tl_block,
        "squashfs": squash_block,
        "ext2": ext2_block,
        "ubi_attach": ubi_list,
        "ubi_vid_scans": ubi_scans,
        "nand_translate": nand_meta,
        "bbm_virtual_scan": bbm_scan,
        "tl_slice_dump": tl_slice_dump_info,
        "upgrade_nand_correlation": upgrade_nand_correlation,
        "mtd_partition_probes": mtd_partition_probes,
        "opentla4_extract": opentla4_extract_block,
        "opentla4_ext2_dump": opentla4_ext2_dump_info,
        "opentla4_files_dump": opentla4_files_dump_info,
    }
