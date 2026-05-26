"""Public corpus-facing artifacts for Pace NAND / OpenTL flash dumps."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from corpus.artifacts import CorpusArtifact
from paceflash.flash_session import open_flash_registry
from paceflash.mtd_partition_probes import run_mtd_partition_probes
from paceflash.opentla4_extract import extract_opentla4_filesystem, opentla4_extract_to_jsonable
from unand.mtd import DEFAULT_MTDPARTS


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
    **metadata: object,
) -> CorpusArtifact:
    return CorpusArtifact(
        source_key=_source_key(prefix, kind, logical_path),
        kind=kind,
        logical_path=logical_path,
        data=data,
        metadata=dict(metadata),
    )


def _squashfs_offsets(data: bytes, *, max_hits: int = 8) -> list[int]:
    """Find plausible little-endian SquashFS magic offsets in an ext2 file."""
    out: list[int] = []
    start = 0
    while len(out) < max_hits:
        off = data.find(b"hsqs", start)
        if off < 0:
            break
        out.append(off)
        start = off + 4
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
) -> Iterator[CorpusArtifact]:
    """
    Yield normalized corpus artifacts from a Pace flash dump.

    Paceflash owns NAND logicalization, MTD slicing, BBM/TL assembly, ext2 extraction,
    and embedded SquashFS discovery. Corpus should only decide how to index these bytes.
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
        tl_slice=tl_slice,
    ) as reg:
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
            **meta,
        )

        if include_mtd:
            probes = run_mtd_partition_probes(reg.flash)
            yield _artifact(
                prefix,
                "mtd_probe_metadata",
                "mtd_probe_metadata.json",
                json.dumps(probes, indent=2).encode("utf-8"),
                probe_loader=True,
                probe_mtdoops=True,
            )
            for name in ("loader", "mtdoops", "tlpart"):
                try:
                    part = reg.partition_by_name(name)
                    blob = reg.flash.read_partition(name)
                except Exception:
                    continue
                yield _artifact(
                    prefix,
                    "mtd_partition",
                    f"mtd/{name}.bin",
                    blob,
                    partition=name,
                    offset=part.offset,
                    size=part.size,
                )

        if not include_ext2:
            return

        result = extract_opentla4_filesystem(
            reg,
            slice_name=tl_slice,
            probe_embedded_squash=include_squashfs,
        )
        extract_meta = opentla4_extract_to_jsonable(result)
        yield _artifact(
            prefix,
            "opentla4_metadata",
            f"{tl_slice}/metadata.json",
            json.dumps(extract_meta, indent=2).encode("utf-8"),
            slice=tl_slice,
            read_model=result.read_model,
            ext2_superblock_offset=result.ext2_sb_offset,
        )
        ext2_source_key = _source_key(prefix, "tl_ext2", f"{tl_slice}/{tl_slice}.ext2")
        if result.slice_bytes:
            yield _artifact(
                prefix,
                "tl_ext2",
                f"{tl_slice}/{tl_slice}.ext2",
                result.slice_bytes,
                slice=tl_slice,
                read_model=result.read_model,
            )
        for rel, data in sorted(result.extracted_files.items()):
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
                relationship="ext2_contains_file",
            )
            if include_squashfs:
                offsets = _squashfs_offsets(data)
            else:
                offsets = []
            for off in offsets:
                logical = (
                    f"{tl_slice}/squashfs/{rel}"
                    if off == 0
                    else f"{tl_slice}/squashfs/{rel}@0x{off:x}"
                )
                yield _artifact(
                    prefix,
                    "squashfs",
                    logical,
                    data[off:],
                    slice=tl_slice,
                    ext2_path=rel,
                    squashfs_offset=off,
                    parent_source_key=ext2_file_source_key,
                    parent_logical_path=ext2_logical_path,
                    relationship="ext2_file_contains_squashfs",
                )


__all__ = ["iter_flash_corpus_artifacts"]
