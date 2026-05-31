"""Public corpus-facing artifacts for Pace NAND / OpenTL flash dumps."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from boardfs.ext2_dissect import resolve_mountable_ext2_superblock_offset
from boardfs.ext2_path import list_ext2_directory, read_ext2_regular_file
from corpus.artifacts import CorpusArtifact
from paceflash.ext2_file_extract import DEFAULT_SQUASH_IMAGE_PATHS, DEFAULT_UIMAGE_PATHS
from paceflash.squashfs_carve import carve_dissectable_squash_blob
from paceflash.flash_session import _opentla4_volume_access, open_flash_registry
from paceflash.mtd_partition_probes import run_mtd_partition_probes
from paceflash.opentla4_extract import extract_opentla4_filesystem, opentla4_extract_to_jsonable
from paceflash.uimage_kernel import uimage_to_vmlinux_elf
from unand.mtd import DEFAULT_MTDPARTS

# ext2 directory trees corpus walks when indexing lab NAND dumps.
_CORPUS_EXT2_WALK_ROOTS: tuple[str, ...] = ("sys1", "sys2", "cm", "config")


def _source_prefix(flash_path: Path, collection: str | None) -> str:
    core = f"paceflash:{flash_path.resolve()}"
    if collection:
        return f"collection:{collection.strip().strip('/')}:{core}"
    return core


def _source_key(prefix: str, kind: str, logical_path: str) -> str:
    return f"{prefix}:{kind}:{logical_path}"


def _artifact(
    prefix: str,
    kind: str,
    logical_path: str,
    data: bytes,
    **metadata: object) -> CorpusArtifact:
    return CorpusArtifact(
        source_key=_source_key(prefix, kind, logical_path),
        kind=kind,
        logical_path=logical_path,
        data=data,
        metadata=dict(metadata))


def _corpus_ext2_static_paths() -> tuple[str, ...]:
    """Paths to pull from opentla4 for corpus text / CMDB / squash carriers."""
    from paceflash.board_info import _VERSION_EXT2_CANDIDATES
    from paceflash.http_auth import _CMDB_EXT2_PATHS

    version_paths = [path for path, _role in _VERSION_EXT2_CANDIDATES]
    return tuple(
        dict.fromkeys(
            (
                *DEFAULT_SQUASH_IMAGE_PATHS,
                *DEFAULT_UIMAGE_PATHS,
                *version_paths,
                *_CMDB_EXT2_PATHS)
        )
    )


def corpus_extracted_files_from_ext2(
    slice_bytes: bytes,
    *,
    sb_off: int | None,
    access: object | None = None,
    max_file_bytes: int = 32 * 1024 * 1024,
    walk_roots: tuple[str, ...] = _CORPUS_EXT2_WALK_ROOTS) -> dict[str, bytes]:
    """
    Read indexable files from an assembled opentla4 ext2 slice.

    Uses kernel-faithful ext2 reads so CMDB / sys1 paths resolve on lab dumps where
    directory entries are opaque to plain dissect walks.
    """
    sb = sb_off if sb_off is not None else resolve_mountable_ext2_superblock_offset(slice_bytes)
    if sb is None:
        return {}

    out: dict[str, bytes] = {}

    def _add(path: str) -> None:
        if path in out:
            return
        try:
            body = read_ext2_regular_file(
                slice_bytes,
                path,
                sb_off=sb,
                access=access,  # type: ignore[arg-type]
            )
        except (FileNotFoundError, OSError, ValueError):
            return
        if 0 < len(body) <= max_file_bytes:
            out[path] = body

    for path in _corpus_ext2_static_paths():
        _add(path)

    queue = list(walk_roots)
    while queue:
        rel = queue.pop(0)
        try:
            rows = list_ext2_directory(
                slice_bytes,
                rel,
                sb_off=sb,
                access=access,  # type: ignore[arg-type]
                cap=256,
            )
        except (OSError, ValueError):
            continue
        for row in rows:
            name = str(row.get("name") or "")
            if not name or name in (".", ".."):
                continue
            child = f"{rel}/{name}" if rel else name
            if row.get("kind") == "dir":
                queue.append(child)
            elif row.get("kind") == "file":
                _add(child)
    return out


def _squashfs_carve_bytes(data: bytes, off: int) -> bytes | None:
    """Return carved bytes at *off* without Dissect verification (legacy helper)."""
    from paceflash.squashfs_carve import squashfs_carve_bytes

    return squashfs_carve_bytes(data, off)


def _uimage_payload(data: bytes) -> bool:
    try:
        from uboot.uimage import parse_uimage_header
    except Exception:
        return False
    return parse_uimage_header(data[:64]) is not None


def _squashfs_offsets(data: bytes, *, max_hits: int = 8) -> list[int]:
    """Find plausible SquashFS magic offsets in an ext2 file (LE hsqs, BE sqsh)."""
    out: list[int] = []
    for needle in (b"hsqs", b"sqsh"):
        start = 0
        while len(out) < max_hits:
            off = data.find(needle, start)
            if off < 0:
                break
            # Keep the raw magic offsets for callers/tests; carving/validation happens at emit time.
            out.append(off)
            start = off + 4
        if len(out) >= max_hits:
            break
    return out


def iter_flash_corpus_artifacts(
    flash_path: str | Path,
    *,
    collection: str | None = None,
    cmdline: str | None = None,
    tl_slice: str = "opentla4",
    nand_translate: bool = True,
    nand_translate_mode: str = "inline-2112",
    bbm_chain_aware: bool = False,
    include_mtd: bool = True,
    include_ext2: bool = True,
    include_squashfs: bool = True,
    include_uimage: bool = True,
    lazy_assembly: bool = False,
) -> Iterator[CorpusArtifact]:
    """
    Yield normalized corpus artifacts from a Pace flash dump.

    Paceflash owns NAND logicalization, MTD slicing, BBM/TL assembly, ext2 extraction,
    and embedded SquashFS discovery. Corpus should only decide how to index these bytes.

    Default ``lazy_assembly=False``: full opentla4 NTL assembly before walking all ext2
    files (corpus reads the whole tree, not single-file ``cat`` paths).
    """
    src = Path(flash_path).expanduser().resolve()
    prefix = _source_prefix(src, collection)
    line = cmdline if cmdline is not None else f"quiet rw {DEFAULT_MTDPARTS}"

    with open_flash_registry(
        src,
        line,
        nand_translate=nand_translate,
        nand_translate_mode=nand_translate_mode,  # type: ignore[arg-type]
        bbm_chain_aware=bbm_chain_aware,
        tl_slice=tl_slice) as reg:
        mtd_rows = [
            {
                "index": p.index,
                "name": p.name,
                "offset": p.offset,
                "size": p.size,
                "remainder": p.remainder,
            }
            for p in reg.flash.partitions
        ]
        meta = {
            "flash_path": str(src),
            "cmdline": line,
            "tl_slice": tl_slice,
            "nand_translate": nand_translate,
            "nand_translate_mode": nand_translate_mode,
            "bbm_chain_aware": bbm_chain_aware,
            "mtd": mtd_rows,
        }
        yield _artifact(
            prefix,
            "flash_metadata",
            "flash_metadata.json",
            json.dumps(meta, indent=2).encode("utf-8"),
            **meta)

        if include_mtd:
            probes = run_mtd_partition_probes(reg.flash)
            yield _artifact(
                prefix,
                "mtd_probe_metadata",
                "mtd_probe_metadata.json",
                json.dumps(probes, indent=2).encode("utf-8"),
                probe_loader=True,
                probe_mtdoops=True)
            tlpart_bytes: bytes | None = None
            for name in ("loader", "mtdoops", "tlpart"):
                try:
                    part = reg.partition_by_name(name)
                    blob = reg.flash.read_partition(name)
                except Exception:
                    continue
                if name == "tlpart":
                    tlpart_bytes = blob
                yield _artifact(
                    prefix,
                    "mtd_partition",
                    f"mtd/{name}.bin",
                    blob,
                    partition=name,
                    offset=part.offset,
                    size=part.size)
            # NOTE: board_param is indexed as a first-class typed record in corpus (see corpus.index_db),
            # not as a synthetic file path (e.g. board_param/keys.txt) that suggests it existed on-device.

        if not include_ext2:
            return

        result = extract_opentla4_filesystem(
            reg,
            slice_name=tl_slice,
            probe_embedded_squash=include_squashfs,
            lazy_assembly=lazy_assembly)
        extract_meta = opentla4_extract_to_jsonable(result)
        yield _artifact(
            prefix,
            "opentla4_metadata",
            f"{tl_slice}/metadata.json",
            json.dumps(extract_meta, indent=2).encode("utf-8"),
            slice=tl_slice,
            read_model=result.read_model,
            ext2_superblock_offset=result.ext2_sb_offset)
        ext2_source_key = _source_key(prefix, "tl_ext2", f"{tl_slice}/{tl_slice}.ext2")
        if result.slice_bytes:
            yield _artifact(
                prefix,
                "tl_ext2",
                f"{tl_slice}/{tl_slice}.ext2",
                result.slice_bytes,
                slice=tl_slice,
                read_model=result.read_model,
                ext2_superblock_offset=result.ext2_sb_offset)
        corpus_files = corpus_extracted_files_from_ext2(
            result.slice_bytes,
            sb_off=result.ext2_sb_offset,
            access=result.access)
        merged_files = {**result.extracted_files, **corpus_files}
        for rel, data in sorted(merged_files.items()):
            ext2_logical_path = f"{tl_slice}/{rel}"
            ext2_file_source_key = _source_key(prefix, "ext2_file", ext2_logical_path)
            yield _artifact(
                prefix,
                "ext2_file",
                ext2_logical_path,
                data,
                slice=tl_slice,
                ext2_path=rel,
                parent_source_key=ext2_source_key,
                parent_logical_path=f"{tl_slice}/{tl_slice}.ext2",
                relationship="ext2_contains_file")
            if include_uimage and _uimage_payload(data):
                yield _artifact(
                    prefix,
                    "uimage",
                    f"{tl_slice}/uimage/{rel}",
                    data,
                    slice=tl_slice,
                    ext2_path=rel,
                    parent_source_key=ext2_file_source_key,
                    parent_logical_path=ext2_logical_path,
                    relationship="ext2_file_is_uimage")
                conv = uimage_to_vmlinux_elf(data)
                if conv.ok and conv.elf_bytes:
                    yield _artifact(
                        prefix,
                        "kernel_elf",
                        f"{tl_slice}/kernel_elf/{rel}.elf",
                        conv.elf_bytes,
                        slice=tl_slice,
                        ext2_path=rel,
                        parent_source_key=_source_key(prefix, "uimage", f"{tl_slice}/uimage/{rel}"),
                        parent_logical_path=f"{tl_slice}/uimage/{rel}",
                        relationship="uimage_converted_to_elf",
                        ih_load=conv.peel.header.ih_load,
                        ih_ep=conv.peel.header.ih_ep,
                        kernel_inner_len=len(conv.peel.kernel_inner),
                        member_decompressed=conv.peel.member_decompressed)
            if include_squashfs:
                carved = carve_dissectable_squash_blob(
                    data,
                    prefer_offsets=_squashfs_offsets(data),
                )
                squash_meta: dict[str, object] = {}
                squash_off = 0
                squash_bytes: bytes | None = None
                if carved is not None:
                    squash_off, squash_bytes, squash_meta = carved
            else:
                squash_bytes = None
                squash_meta = {}
            if squash_bytes is not None:
                logical = (
                    f"{tl_slice}/squashfs/{rel}"
                    if squash_off == 0
                    else f"{tl_slice}/squashfs/{rel}@0x{squash_off:x}"
                )
                squash_extra = {
                    k: v for k, v in squash_meta.items() if k not in {"ext2_path"}
                }
                yield _artifact(
                    prefix,
                    "squashfs",
                    logical,
                    squash_bytes,
                    slice=tl_slice,
                    ext2_path=rel,
                    squashfs_offset=squash_off,
                    parent_source_key=ext2_file_source_key,
                    parent_logical_path=ext2_logical_path,
                    relationship="ext2_file_contains_squashfs",
                    **squash_extra,
                )


__all__ = [
    "corpus_extracted_files_from_ext2",
    "iter_flash_corpus_artifacts",
]
