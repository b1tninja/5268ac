"""
Native ``.pkgstream`` / 2SP container parsing and embedded-artifact discovery **without** Binwalk.

The on-wire layout is reverse-engineered from the gateway's ``/usr/lib/lib2sp.so`` (2WIRE / LIB2SP
stack): 24-byte big-endian header, a sequence of ``(type, length, payload)`` TLV records, optional
**bzip2** outer compression (``BZh``), and **bzip2**-compressed members inside the state machine
(used at runtime by ``lib2sp_install_data`` but not required to *locate* well-known child images).

This module **does not** reimplement the full installer or signature chain (PKCS#7).  It provides:

- strict header + TLV walking for the **metadata prefix**;
- **magic / superblock** scans for SquashFS (LE ``hsqs``) and legacy **uImage** (``0x27051956``),
  matching the same offsets a Binwalk ``file_map`` would report for those families.
"""

from __future__ import annotations

import bz2
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, Union

# Legacy uImage big-endian magic (``IH_MAGIC = 0x27051956``).  Inlined here so the ``opentl``
# Defined once in U-Boot and never changes; mirrors :data:`binwalker.extract.uimage.UIMAGE_MAGIC_BE`.
UIMAGE_MAGIC_BE = 0x27051956

# --- 2SP / carrier header (see demarshall_2sp_header in lib2sp.so) ---

MAGIC_2WIRE_SP = b"2WIRE_SP"
HEADER_FORMAT = struct.Struct(">8sIIII")
HEADER_SIZE = 24  # 8 + 4*4
TLV_HEADER = struct.Struct(">II")
# SquashFS 4.x little-endian on these images — ``bytes_used`` is at +40 (see ``squashfs_super_block``)
SQUASHFS_LE_MAGIC = 0x73717368  # b"hsqs" as little-endian 32-bit word
SQ_BYTES_USED_OFF = 40

# lib2sp ``lib2sp_do_payload_tlv`` / demarshall entry points (not exhaustive)
TLV_TYPE_FILE_1 = 0x1
TLV_TYPE_FILE_3 = 0x3
TLV_TYPE_SCRIPT = 0x26
TLV_TYPE_PATH_FILE = 0x2F
TLV_TYPE_DPI_SIG = 0x3E8  # 1000

PathLike = Union[str, Path]


@dataclass(frozen=True)
class Header2SP:
    """24-byte 2WIRE / 2SP outer header (big-endian u32 fields after 8-byte label)."""

    magic: bytes
    u32_0: int
    u32_1: int
    u32_2: int
    u32_3: int
    file_offset: int = 0

    @property
    def is_supported_magic(self) -> bool:
        return self.magic == MAGIC_2WIRE_SP


@dataclass(frozen=True)
class TlvRecord:
    """One TLV: big-endian type + length, payload follows immediately."""

    type: int
    length: int
    absolute_offset: int
    payload: bytes

    @property
    def end_offset(self) -> int:
        return self.absolute_offset + 8 + self.length


def parse_2sp_header(data: bytes, file_offset: int = 0) -> Header2SP:
    if len(data) < HEADER_SIZE:
        raise ValueError("need at least 24 bytes for 2SP header")
    magic, a, b, c, d = HEADER_FORMAT.unpack(data[:HEADER_SIZE])
    return Header2SP(magic, a, b, c, d, file_offset)


def try_decompress_bzip2_prefix(data: bytes) -> Tuple[bytes, bool]:
    """
    If the stream starts with bzip2 ``BZh[1-9]`` (same magic ``lib2sp_install_data`` checks before
    calling ``BZ2_bzDecompressInit``), return the fully decompressed buffer; else ``(data, False)``.
    """
    if len(data) >= 4 and data[:3] == b"BZh" and data[3:4] in b"123456789":
        try:
            return bz2.decompress(data), True
        except OSError:
            pass
    return data, False


def iter_tlvs(
    data: bytes,
    start: int = 0,
    *,
    max_length: int = 256 * 1024 * 1024,
    max_payload: int = 1024 * 1024 * 1024,
) -> Iterator[TlvRecord]:
    """
    Walk a linear sequence of TLVs. Stops at end of buffer or the first record that would
    run past ``len(data)`` or exceed ``max_payload`` (defensive; mirrors installer limits).
    """
    pos = start
    n = len(data)
    while pos + 8 <= n:
        t, lg = TLV_HEADER.unpack(data[pos : pos + 8])
        if lg > max_payload or lg < 0:
            break
        if pos + 8 + lg > n:
            break
        pay = data[pos + 8 : pos + 8 + lg]
        yield TlvRecord(t, lg, pos, pay)
        pos += 8 + lg
        if pos - start > max_length and start == 0:
            # avoid accidentally scanning gigabytes as TLV if caller misaligned
            pass


def iter_tlvs_prefix_only(
    data: bytes,
    *,
    start: int = HEADER_SIZE,
) -> List[TlvRecord]:
    """
    Collect TLVs from ``start`` until the sequence breaks (non-linear remainder may hold PKCS#7,
    raw FILE payloads concatenated with scripts, etc.).
    """
    out: List[TlvRecord] = []
    pos = start
    n = len(data)
    while pos + 8 <= n:
        t, lg = TLV_HEADER.unpack(data[pos : pos + 8])
        if lg > 1024 * 1024 * 1024 or lg < 0:
            break
        if pos + 8 + lg > n:
            break
        pay = data[pos + 8 : pos + 8 + lg]
        out.append(TlvRecord(t, lg, pos, pay))
        pos += 8 + lg
    return out


def squashfs_le_span_at(data: bytes, offset: int) -> Optional[Tuple[int, int]]:
    """
    If ``offset`` looks like a little-endian SquashFS 4 superblock, return (offset, length).
    """
    if offset < 0 or offset + 120 > len(data):
        return None
    if struct.unpack("<I", data[offset : offset + 4])[0] != SQUASHFS_LE_MAGIC:
        return None
    bytes_used = struct.unpack("<I", data[offset + SQ_BYTES_USED_OFF : offset + SQ_BYTES_USED_OFF + 4])[0]
    if bytes_used < 64 or bytes_used > len(data) - offset:
        return None
    return offset, bytes_used


def uimage_span_at(data: bytes, offset: int) -> Optional[Tuple[int, int]]:
    """
    Legacy uImage: total size = 64 + ih_size (big-endian u32 at header + 12).
    """
    if offset < 0 or offset + 64 > len(data):
        return None
    magic = struct.unpack(">I", data[offset : offset + 4])[0]
    if magic != UIMAGE_MAGIC_BE:
        return None
    ih_size = struct.unpack(">I", data[offset + 12 : offset + 16])[0]
    if ih_size == 0 or ih_size > len(data) - offset:
        return None
    total = 64 + ih_size
    if offset + total > len(data):
        return None
    return offset, total


def scan_embedded_images(data: bytes) -> List[Dict[str, Any]]:
    """
    Find SquashFS (``hsqs``) and uImage blobs by magic / superblock — same class of hits Binwalk
    ``file_map`` records for ``squashfs`` / ``uimage`` names.
    """
    hits: List[Dict[str, Any]] = []
    seen_sq: Set[int] = set()
    seen_ui: Set[int] = set()

    # SquashFS LE — scan for raw magic bytes (avoid overlapping spans)
    needle = b"hsqs"
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        sp = squashfs_le_span_at(data, i)
        if sp and sp[0] not in seen_sq:
            off, ln = sp
            seen_sq.add(off)
            hits.append({"offset": off, "size": ln, "name": "squashfs"})
        start = i + 1

    # uImage — search for big-endian magic bytes
    magic_be = struct.pack(">I", UIMAGE_MAGIC_BE)
    start = 0
    while True:
        i = data.find(magic_be, start)
        if i < 0:
            break
        sp = uimage_span_at(data, i)
        if sp and sp[0] not in seen_ui:
            off, ln = sp
            seen_ui.add(off)
            hits.append({"offset": off, "size": ln, "name": "uimage"})
        start = i + 1

    hits.sort(key=lambda r: r["offset"])
    return hits


def load_pkgstream_bytes(path: PathLike) -> bytes:
    p = Path(path)
    return p.read_bytes()


def analyze_pkgstream(path: PathLike, *, verify: bool = False) -> Dict[str, Any]:
    """
    Return header fields, TLV summary, and embedded-image scan for one ``.pkgstream`` file.

    :param path: pkgstream file path.
    :param verify: when True, additionally runs :func:`pkgstream_verify.verify_pkgstream`
        and includes the structured integrity report (PKCS#7, per-FILE/SCRIPT digests,
        RSA verification) under the ``"verify"`` key.
    """
    raw = load_pkgstream_bytes(path)
    body, was_bz2 = try_decompress_bzip2_prefix(raw)
    header = parse_2sp_header(body)
    tlvs = iter_tlvs_prefix_only(body, start=HEADER_SIZE)
    scans = scan_embedded_images(body)
    result: Dict[str, Any] = {
        "path": str(Path(path).resolve()),
        "outer_bzip2": was_bz2,
        "header": {
            "magic": header.magic.decode("ascii", "replace"),
            "u32": [header.u32_0, header.u32_1, header.u32_2, header.u32_3],
        },
        "tlv_count": len(tlvs),
        "tlv_types_preview": [x.type for x in tlvs[:30]],
        "embedded_images": scans,
        "raw_size": len(raw),
        "parsed_body_size": len(body),
    }
    if verify:
        # Late import — verifier optionally pulls in ``cryptography`` for RSA checks.
        from lib2spy.pkgstream_verify import verify_pkgstream

        report = verify_pkgstream(path)
        result["verify"] = report.to_json()
    return result


def extract_slices_native(
    pkgstream_path: str,
    out_dir: str,
    *,
    names: Optional[Set[str]] = None,
    write_manifest: bool = True,
    strict_uimage_decompress: bool = False,
) -> Dict[str, Any]:
    """
    Carve SquashFS / uImage blobs using :func:`scan_embedded_images` only (no Binwalk JSON).

    Filenames follow the same convention as :func:`extract_pkgstream_slices`.
    """
    from binwalker.carved import Pkgstream

    want = names if names is not None else {"squashfs", "uimage"}
    src = Path(pkgstream_path).resolve()
    out = Path(out_dir).resolve()

    pc = Pkgstream(
        src,
        names=sorted(want),
        strict_uimage_decompress=strict_uimage_decompress,
    )
    used: Set[str] = set()
    written: List[str] = []
    manifest_rows: List[Dict[str, Any]] = []
    for art, er in pc.save_all(out, used_filenames=used):
        written.append(str(er.path))
        manifest_rows.append(art.manifest_entry(er))
    body = pc._native_body
    assert body is not None
    rows = scan_embedded_images(body)

    summary: Dict[str, Any] = {
        "pkgstream_path": str(src),
        "outer_bzip2": pc.outer_bzip2,
        "out_dir": str(out),
        "extracted_count": len(written),
        "extracted_files": written,
        "rows_considered": len(rows),
        "extract_names": sorted(want),
        "strict_uimage_decompress": strict_uimage_decompress,
    }
    if write_manifest:
        man_path = out / "corpus_manifest.json"
        man_path.write_text(json.dumps(manifest_rows, indent=2), encoding="utf-8")
        summary["corpus_manifest_path"] = str(man_path)

    summary["manifest_rows"] = manifest_rows
    return summary
