"""
UBI / UBIFS carving helpers for raw ``tlpart`` / NAND linear dumps.

Linux MTD uses **UBI erase-counter headers** whose magic is ``0x55424923``
(ASCII ``UBI#`` on big-endian wire order) and **volume ID headers** ``0x55424921``
(ASCII ``UBI!``). UBIFS nodes carry magic ``0x06101831`` (**little-endian** bytes
``31 18 10 06`` at the start of each node) — see ``include/mtd/ubi-media.h`` and
``fs/ubifs/ubifs-media.h`` in the kernel tree.

Carving produces ``.bin`` slices; **decode** them with :mod:`boardfs.ubifs_decode`
(optional ``ubi_reader``) or ``decode_carved_slices`` below after :func:`scan_ubifs_image`.

Example::

    from pathlib import Path
    from boardfs.ubi_carve import decode_carved_slices, scan_ubifs_image, carve_span

    r = scan_ubifs_image(Path(\"output/carved_flash/tlpart.bin\"))
    print(r.ubi_ec_offsets[:10], r.summary())
    if r.suggested_carves:
        carve_span(Path(\"tlpart.bin\"), r.suggested_carves[0], Path(\"ubi_slice.bin\"))

CLI carve + optional ubireader decode::

    python -m boardfs.ubi_carve --image tlpart.bin --out-json report.json --decode-dir work/dec
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional


# --- Kernel-equivalent magic bytes (documented for grep / hex editors)

UBI_EC_HDR_MAGIC_UINT32: int = 0x55424923  # "UBI#" as BE uint32
UBI_VID_HDR_MAGIC_UINT32: int = 0x55424921  # "UBI!" as BE uint32
UBIFS_NODE_MAGIC_UINT32: int = 0x06101831

# On-wire ASCII (typical NOR/NAND images match this literal sequence)
UBI_EC_MAGIC_ASCII: bytes = b"UBI#"
UBI_VID_MAGIC_ASCII: bytes = b"UBI!"
# UBIFS node magic as stored LE on medium (common case for MIPS/ARM LE UBIFS)
UBIFS_NODE_MAGIC_LE_BYTES: bytes = struct.pack("<I", UBIFS_NODE_MAGIC_UINT32)

# ``include/mtd/ubi-media.h``: EC + VID headers are 64 bytes each; VID follows EC in the PEB.
UBI_EC_HDR_LEN: int = 64
UBI_VID_HDR_LEN: int = 64


def _find_all(haystack: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        i = haystack.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def scan_magic_offsets(
    data: bytes,
    *,
    include_ubifs_nodes: bool = True,
) -> tuple[list[int], list[int], list[int]]:
    """
    Return ``(ubi_ec_offsets, ubi_vid_offsets, ubifs_node_offsets)`` for fixed needles.

    EC / VID use ASCII ``UBI#`` / ``UBI!``. UBIFS uses LE ``31 18 10 06``.
    """
    ec = _find_all(data, UBI_EC_MAGIC_ASCII)
    vid = _find_all(data, UBI_VID_MAGIC_ASCII)
    ubifs: list[int] = []
    if include_ubifs_nodes:
        ubifs = _find_all(data, UBIFS_NODE_MAGIC_LE_BYTES)
    return ec, vid, ubifs


def audit_ubi_vid_offset(
    data: bytes,
    vid_off: int,
    *,
    erase_bytes: int,
) -> dict[str, Any]:
    """
    Explain whether ``vid_off`` looks like a real **volume ID header** (``UBI!``).

    In a normal UBI PEB, byte ``0`` is the EC header (``UBI#``) and byte ``64`` is the
    VID header (``UBI!``), both inside one erase block aligned to ``erase_bytes``.
    Literal ``UBI!`` substrings elsewhere are usually compressed/log noise.
    """
    imax = len(data)
    peb_candidate = vid_off - UBI_EC_HDR_LEN
    aligned = peb_candidate >= 0 and peb_candidate % erase_bytes == 0
    ec_ok = False
    if 0 <= peb_candidate <= imax - 4:
        ec_ok = data[peb_candidate : peb_candidate + 4] == UBI_EC_MAGIC_ASCII
    mod_peb = vid_off % erase_bytes if erase_bytes else -1
    plausible = bool(aligned and ec_ok and vid_off + 4 <= imax)
    return {
        "vid_offset": vid_off,
        "vid_offset_hex": f"{vid_off:#x}",
        "peb_start_candidate": peb_candidate if peb_candidate >= 0 else None,
        "peb_erase_aligned": aligned,
        "ec_magic_at_peb": ec_ok,
        "vid_offset_mod_peb": mod_peb,
        "expect_vid_mod_peb": UBI_EC_HDR_LEN,
        "plausible_ubi_vid_header": plausible,
    }


def plausible_ubi_vid_offsets(
    data: bytes,
    vid_offsets: Iterable[int],
    *,
    erase_bytes: int,
) -> list[int]:
    """Keep only ``UBI!`` offsets that sit in a ``UBI#`` + 64 layout on an erase boundary."""
    out: list[int] = []
    for vo in vid_offsets:
        a = audit_ubi_vid_offset(data, vo, erase_bytes=erase_bytes)
        if a["plausible_ubi_vid_header"]:
            out.append(vo)
    return out


def parse_ubi_vid_hdr_fields(data: bytes, vid_off: int) -> Optional[dict[str, Any]]:
    """
    If ``data[vid_off:vid_off+4]`` is ``UBI!``, decode a few big-endian VID header fields.

    Matches Linux ``struct ubi_vid_hdr`` layout (magic, version, vol_type, …).
    Does **not** verify hdr_crc — use for inspection only.
    """
    if vid_off < 0 or vid_off + 28 > len(data):
        return None
    if data[vid_off : vid_off + 4] != UBI_VID_MAGIC_ASCII:
        return None
    magic, version, vol_type, copy_flag, compat, data_pad, data_crc, used_ebs, data_size, lnum = (
        struct.unpack(">IIBBBBIIII", data[vid_off : vid_off + 28])
    )
    return {
        "magic_hex": f"{magic:08x}",
        "version": version,
        "vol_type": vol_type,
        "copy_flag": copy_flag,
        "compat": compat,
        "data_pad": data_pad,
        "data_crc": data_crc,
        "used_ebs": used_ebs,
        "data_size": data_size,
        "lnum": lnum,
    }


def cluster_ranges(
    offsets: Iterable[int],
    *,
    max_interior_gap: int,
    image_len: int,
) -> list[tuple[int, int]]:
    """
    Sort offsets and merge into **[start, end)** half-open spans such that adjacent
    offsets farther than ``max_interior_gap`` start a new span.

    Each span covers from **first offset in cluster** through **last offset + 1**
    (minimal hull). Caller may extend ``end``.
    """
    offs = sorted(set(offsets))
    if not offs:
        return []
    spans: list[tuple[int, int]] = []
    cur_a = offs[0]
    cur_b = offs[0]
    for x in offs[1:]:
        if x - cur_b <= max_interior_gap:
            cur_b = x
        else:
            spans.append((cur_a, cur_b + 1))
            cur_a = cur_b = x
    spans.append((cur_a, cur_b + 1))
    # Clamp
    out: list[tuple[int, int]] = []
    for a, b in spans:
        a = max(0, min(a, image_len))
        b = max(a, min(b, image_len))
        if b > a:
            out.append((a, b))
    return out


def extend_span_to_erase_alignment(
    start: int,
    end: int,
    *,
    erase_bytes: int,
    image_len: int,
    extend_end_by_erase: int = 1,
) -> tuple[int, int]:
    """Align ``start`` down and extend ``end`` by ``extend_end_by_erase * erase_bytes`` (clamped)."""
    a = (start // erase_bytes) * erase_bytes
    b = end + extend_end_by_erase * erase_bytes
    b = min(image_len, b)
    a = max(0, min(a, image_len))
    if b < a:
        b = a
    return a, b


@dataclass
class UbifsCarveScan:
    """Result of scanning an image for UBI / UBIFS signatures."""

    image_path: str
    image_size: int
    ubi_ec_offsets: list[int] = field(default_factory=list)
    ubi_vid_offsets: list[int] = field(default_factory=list)
    ubifs_node_offsets: list[int] = field(default_factory=list)
    #: Proposed **[start, end)** byte spans (half-open) for carving UBI regions.
    suggested_carves: list[tuple[int, int]] = field(default_factory=list)
    erase_bytes_assumed: int = 131072
    #: Per-hit classification for every ``UBI!`` substring (see :func:`audit_ubi_vid_offset`).
    vid_hit_audit: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> dict:
        plausible_vid = sum(
            1 for a in self.vid_hit_audit if a.get("plausible_ubi_vid_header")
        )
        return {
            "image_size": self.image_size,
            "ubi_ec_count": len(self.ubi_ec_offsets),
            "ubi_vid_count": len(self.ubi_vid_offsets),
            "ubi_vid_plausible_count": plausible_vid,
            "ubifs_node_magic_count": len(self.ubifs_node_offsets),
            "suggested_carves": [
                {"start": a, "end": b, "length": b - a, "start_hex": f"{a:#x}", "end_hex": f"{b:#x}"}
                for a, b in self.suggested_carves
            ],
            "erase_bytes_assumed": self.erase_bytes_assumed,
        }


def scan_ubifs_image(
    image_path: str | Path,
    *,
    erase_bytes: int = 131072,
    cluster_gap_multiple: float = 4.0,
    extend_carves: bool = True,
    include_ubifs_nodes: bool = True,
) -> UbifsCarveScan:
    """
    Read ``image_path`` entirely and populate :class:`UbifsCarveScan`.

    **Clustering:** merge EC header offsets whose gaps are ≤ ``cluster_gap_multiple * erase_bytes``.
    **Carves:** one half-open span per cluster; optionally extend end by one erase block and
    align start down to erase boundary.

    If **no** EC headers are found, falls back to clustering UBIFS node magic only.

    **Note:** A genuine ``UBI!`` VID header always sits at ``peb + 64`` with ``UBI#`` at
    ``peb`` on an erase boundary — so it is already picked up as an EC hit. Literal
    ``UBI!`` without that layout is not UBI (see :func:`audit_ubi_vid_offset`).
    """
    path = Path(image_path)
    data = path.read_bytes()
    imax = len(data)
    ec, vid, ubifs = scan_magic_offsets(data, include_ubifs_nodes=include_ubifs_nodes)
    vid_audit = [audit_ubi_vid_offset(data, v, erase_bytes=erase_bytes) for v in vid]

    max_gap = int(cluster_gap_multiple * erase_bytes)
    clusters = cluster_ranges(ec, max_interior_gap=max_gap, image_len=imax)

    suggested: list[tuple[int, int]] = []
    for a, b in clusters:
        if extend_carves:
            a2, b2 = extend_span_to_erase_alignment(
                a,
                b,
                erase_bytes=erase_bytes,
                image_len=imax,
                extend_end_by_erase=1,
            )
            suggested.append((a2, b2))
        else:
            suggested.append((a, b))

    # If EC empty but UBIFS nodes present, cluster UBIFS offsets as weak fallback regions
    if not suggested and ubifs:
        clusters_u = cluster_ranges(ubifs, max_interior_gap=max_gap * 2, image_len=imax)
        for a, b in clusters_u:
            if extend_carves:
                a2, b2 = extend_span_to_erase_alignment(
                    a,
                    b,
                    erase_bytes=erase_bytes,
                    image_len=imax,
                    extend_end_by_erase=2,
                )
                suggested.append((a2, b2))
            else:
                suggested.append((a, b))

    return UbifsCarveScan(
        image_path=str(path.resolve()),
        image_size=imax,
        ubi_ec_offsets=ec,
        ubi_vid_offsets=vid,
        ubifs_node_offsets=ubifs,
        suggested_carves=suggested,
        erase_bytes_assumed=erase_bytes,
        vid_hit_audit=vid_audit,
    )


def carve_span(
    image_path: str | Path,
    span: tuple[int, int],
    out_path: str | Path,
    *,
    dry_run: bool = False,
) -> int:
    """
    Write bytes **[start, end)** from ``image_path`` to ``out_path``.

    Returns number of bytes written (``0`` if ``dry_run``).
    """
    start, end = span
    path = Path(image_path)
    data = path.read_bytes()
    if start < 0 or end > len(data) or start >= end:
        raise ValueError(f"bad span {(start, end)} for image length {len(data)}")
    slice_ = data[start:end]
    out = Path(out_path)
    if not dry_run:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(slice_)
    return 0 if dry_run else len(slice_)


def carve_all_suggested(
    scan: UbifsCarveScan,
    out_dir: str | Path,
    *,
    prefix: str = "ubi_carve",
    dry_run: bool = False,
) -> list[tuple[str, int]]:
    """
    Carve each span in ``scan.suggested_carves`` to ``out_dir/{prefix}_i_{start:x}_{end:x}.bin``.

    Returns list of ``(path, bytes_written)``.
    """
    out_dir = Path(out_dir)
    ip = Path(scan.image_path)
    results: list[tuple[str, int]] = []
    for i, span in enumerate(scan.suggested_carves):
        a, b = span
        name = f"{prefix}_{i}_{a:08x}_{b:08x}.bin"
        dst = out_dir / name
        n = carve_span(ip, span, dst, dry_run=dry_run)
        results.append((str(dst.resolve()), n))
    return results


def decode_carved_slices(
    scan: UbifsCarveScan,
    output_parent: str | Path,
    *,
    verbose_ubireader: bool = False,
    extract_kw: Optional[dict[str, Any]] = None,
) -> list:
    """
    Run :func:`boardfs.ubifs_decode.extract_ubifs_image` on each span in
    ``scan.suggested_carves`` (requires optional ``ubi_reader``).

    Writes temporary slices under ``output_parent`` and extraction trees under
    ``output_parent / decoded_<i>/``. Returns list of
    :class:`boardfs.ubifs_decode.UbifsExtractResult` (import lazily).

    ``extract_kw`` is passed through to each ``extract_ubifs_image`` call (e.g.
    ``peb_size``, ``leb_size``, ``warn_only_block_read_errors``). Per-slice
    ``start_offset`` defaults to ``0`` unless overridden in ``extract_kw``.
    """
    from boardfs.ubifs_decode import UbifsExtractResult, extract_ubifs_image

    out_parent = Path(output_parent)
    out_parent.mkdir(parents=True, exist_ok=True)
    src = Path(scan.image_path)
    results: list[UbifsExtractResult] = []
    extra = dict(extract_kw) if extract_kw else {}
    for i, span in enumerate(scan.suggested_carves):
        slice_bin = out_parent / f"_slice_{i}_{span[0]:08x}_{span[1]:08x}.bin"
        carve_span(src, span, slice_bin)
        dest = out_parent / f"decoded_{i}"
        dest.mkdir(parents=True, exist_ok=True)
        kw: dict[str, Any] = {
            "start_offset": extra.get("start_offset", 0),
            "end_offset": extra.get("end_offset"),
            "guess_offset": extra.get("guess_offset", 0),
            "peb_size": extra.get("peb_size"),
            "leb_size": extra.get("leb_size"),
            "warn_only_block_read_errors": extra.get(
                "warn_only_block_read_errors", False
            ),
            "ignore_block_header_errors": extra.get(
                "ignore_block_header_errors", False
            ),
            "uboot_fix": extra.get("uboot_fix", False),
            "master_key_path": extra.get("master_key_path"),
            "keep_permissions": extra.get("keep_permissions", False),
            "verbose_ubireader": verbose_ubireader,
        }
        # Drop None end_offset / peb / leb / master_key_path for cleaner calls
        call_kw = {k: v for k, v in kw.items() if v is not None}
        r = extract_ubifs_image(slice_bin, dest, **call_kw)
        results.append(r)
    return results


def write_scan_json(scan: UbifsCarveScan, path: str | Path) -> None:
    """Serialize :meth:`UbifsCarveScan.summary` plus raw offset lists (truncated in JSON optional)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "image_path": scan.image_path,
        **scan.summary(),
        "ubi_ec_offsets_sample": scan.ubi_ec_offsets[:500],
        "ubi_ec_offsets_total": len(scan.ubi_ec_offsets),
        "ubi_vid_offsets_sample": scan.ubi_vid_offsets[:500],
        "ubi_vid_offsets_total": len(scan.ubi_vid_offsets),
        "ubifs_node_offsets_sample": scan.ubifs_node_offsets[:500],
        "ubifs_node_offsets_total": len(scan.ubifs_node_offsets),
        "vid_hit_audit": scan.vid_hit_audit,
    }
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", type=Path, required=True, help="Raw flash/tlpart dump")
    ap.add_argument("--erase-bytes", type=int, default=131072, help="NAND erase unit (default 128 KiB)")
    ap.add_argument(
        "--cluster-gap-multiple",
        type=float,
        default=4.0,
        help="Merge EC hits when gap ≤ this multiple of erase-bytes",
    )
    ap.add_argument("--no-extend-carves", action="store_true", help="Disable erase-aligned extension")
    ap.add_argument("--no-ubifs-nodes", action="store_true", help="Skip UBIFS node magic scan")
    ap.add_argument("--out-json", type=Path, default=None, help="Write scan JSON report")
    ap.add_argument("--carve-dir", type=Path, default=None, help="If set, write carve bins here")
    ap.add_argument(
        "--decode-dir",
        type=Path,
        default=None,
        help=(
            "Run ubireader extraction per suggested carve into this directory "
            "(requires pip install ubi_reader). Writes slice binaries and decoded_* trees here."
        ),
    )
    ap.add_argument(
        "--decode-verbose",
        action="store_true",
        help="Verbose ubireader logging when using --decode-dir",
    )
    ap.add_argument(
        "--decode-peb-size",
        type=int,
        default=None,
        help="Optional PEB size forwarded to extract_ubifs_image",
    )
    ap.add_argument(
        "--decode-leb-size",
        type=int,
        default=None,
        help="Optional LEB size forwarded to extract_ubifs_image",
    )
    ap.add_argument(
        "--audit-vid",
        action="store_true",
        help="Print JSON classification for each literal UBI! offset (PEB alignment + EC anchor)",
    )
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    scan = scan_ubifs_image(
        args.image,
        erase_bytes=args.erase_bytes,
        cluster_gap_multiple=args.cluster_gap_multiple,
        extend_carves=not args.no_extend_carves,
        include_ubifs_nodes=not args.no_ubifs_nodes,
    )
    print(json.dumps(scan.summary(), indent=2))
    if args.audit_vid:
        print(json.dumps(scan.vid_hit_audit, indent=2))
    if args.out_json:
        write_scan_json(scan, args.out_json)
        print("wrote", args.out_json)
    if args.carve_dir:
        carved = carve_all_suggested(scan, args.carve_dir, dry_run=args.dry_run)
        for path, n in carved:
            print("carved", n, "bytes ->", path)
    if args.decode_dir:
        if args.dry_run:
            print("decode-dir: skipped (--dry-run)", file=sys.stderr)
        else:
            dec_kw: dict[str, Any] = {}
            if args.decode_peb_size is not None:
                dec_kw["peb_size"] = args.decode_peb_size
            if args.decode_leb_size is not None:
                dec_kw["leb_size"] = args.decode_leb_size
            results = decode_carved_slices(
                scan,
                args.decode_dir,
                verbose_ubireader=args.decode_verbose,
                extract_kw=dec_kw or None,
            )
            for i, r in enumerate(results):
                print(
                    json.dumps(
                        {
                            "slice_index": i,
                            "success": r.success,
                            "kind": r.kind,
                            "output_dirs": r.output_dirs,
                            "error": r.error,
                        },
                        indent=2,
                    )
                )


if __name__ == "__main__":
    main()
