"""
Legacy U-Boot ``uImage`` header (``image_header`` from ``include/image.h``).

All multi-byte fields are **big-endian** on the wire (typical for MIPS-class images).
Payload layout for ``IH_TYPE_MULTI``: see ``parse_legacy_multi_size_list`` / ``extract_kernel_blob``; U-Boot ``dumpimage`` remains a useful cross-check.
"""

from __future__ import annotations

import bz2
import gzip
import logging
import lzma
import struct
import zlib
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

# IH_MAGIC in U-Boot (big-endian bytes 27 05 19 56)
UIMAGE_MAGIC_BE = 0x27051956

_UIMAGE_STRUCT = struct.Struct(">IIIIIIIBBBB32s")

# Denx U-Boot include/image.h — IH_OS_*
IH_OS_NAMES: Dict[int, str] = {
    0: "invalid",
    1: "OpenBSD",
    2: "NetBSD",
    3: "FreeBSD",
    4: "4_4BSD",
    5: "Linux",
    6: "SVR4",
    7: "Esix",
    8: "Solaris",
    9: "Irix",
    10: "SCO",
    11: "Dell",
    12: "macOS",
    13: "Windows",
    14: "pSOS",
    15: "QNX",
    16: "U-Boot",
    17: "RTEMS",
    18: "VxWorks",
    19: "OSBD",
}

# IH_ARCH_*
IH_ARCH_NAMES: Dict[int, str] = {
    0: "invalid",
    1: "Alpha",
    2: "ARM",
    3: "I386",
    4: "IA64",
    5: "MIPS",
    6: "MIPS64",
    7: "PPC",
    8: "S390",
    9: "SuperH",
    10: "SPARC",
    11: "SPARC64",
    12: "M68K",
    13: "Microblaze",
    14: "Nios-II",
    15: "Blackfin",
    16: "AVR32",
    17: "ST200",
    18: "Sandbox",
    19: "ARC",
    20: "NDS32",
    21: "RISCV",
    22: "ARC64",
}

# IH_TYPE_*
IH_TYPE_NAMES: Dict[int, str] = {
    0: "invalid",
    1: "standalone",
    2: "kernel",
    3: "ramdisk",
    4: "multi",
    5: "firmware",
    6: "script",
    7: "filesystem",
    8: "flat_dt",
    9: "fpga",
    10: "appcode",
    11: "loadable",
}

# IH_COMP_*
IH_COMP_NAMES: Dict[int, str] = {
    0: "none",
    1: "gzip",
    2: "bzip2",
    3: "lzma",
    4: "lzo",
    5: "lz4",
    6: "zstd",
}


def _enum_label(names: Dict[int, str], code: int) -> str:
    if code in names:
        return names[code]
    return f"unknown (0x{code:02x})"


@dataclass(frozen=True)
class UImageHeader:
    """Parsed legacy ``image_header`` (64 bytes)."""

    offset_in_file: int
    ih_magic: int
    ih_hcrc: int
    ih_time: int
    ih_size: int
    ih_load: int
    ih_ep: int
    ih_dcrc: int
    ih_os: int
    ih_arch: int
    ih_type: int
    ih_comp: int
    ih_name: str

    def as_dict(self) -> dict:
        """Plain dict for JSON serialization."""
        return {
            "offset_in_file": self.offset_in_file,
            "ih_magic": self.ih_magic,
            "ih_hcrc": self.ih_hcrc,
            "ih_time": self.ih_time,
            "ih_size": self.ih_size,
            "ih_load": self.ih_load,
            "ih_ep": self.ih_ep,
            "ih_dcrc": self.ih_dcrc,
            "ih_os": self.ih_os,
            "ih_arch": self.ih_arch,
            "ih_type": self.ih_type,
            "ih_comp": self.ih_comp,
            "ih_name": self.ih_name,
        }


def parse_uimage_header(data: bytes, *, offset_in_file: int = 0) -> Optional[UImageHeader]:
    """
    Parse a legacy uImage header at the start of ``data``.
    Returns ``None`` if buffer too short or magic mismatch.
    """
    if len(data) < _UIMAGE_STRUCT.size:
        return None
    unpacked = _UIMAGE_STRUCT.unpack_from(data, 0)
    magic = unpacked[0]
    if magic != UIMAGE_MAGIC_BE:
        return None
    raw_name = unpacked[11]
    name = raw_name.split(b"\x00", 1)[0].decode("utf-8", "replace")
    return UImageHeader(
        offset_in_file=offset_in_file,
        ih_magic=magic,
        ih_hcrc=unpacked[1],
        ih_time=unpacked[2],
        ih_size=unpacked[3],
        ih_load=unpacked[4],
        ih_ep=unpacked[5],
        ih_dcrc=unpacked[6],
        ih_os=unpacked[7],
        ih_arch=unpacked[8],
        ih_type=unpacked[9],
        ih_comp=unpacked[10],
        ih_name=name,
    )


def uimage_header_crc_ok(header: bytes) -> bool:
    """
    Whether ``ih_hcrc`` matches U-Boot's header CRC (zlib CRC32 over bytes 4..63 with the
    CRC field zeroed).

    Vendor images often diverge on tail padding; treat ``False`` as weak signal and prefer
    ``ih_dcrc`` over the payload when validating assembled bytes.
    """
    if len(header) < 64:
        return False
    h = bytearray(header[:64])
    stored = struct.unpack_from(">I", h, 4)[0]
    h[4:8] = b"\x00\x00\x00\x00"
    calc = zlib.crc32(bytes(h[4:64])) & 0xFFFFFFFF
    return calc == stored


IH_TYPE_KERNEL = 2
IH_TYPE_MULTI = 4

# IH_COMP_* (subset — matches ``IH_COMP_NAMES`` indices)
IH_COMP_NONE = 0
IH_COMP_GZIP = 1
IH_COMP_BZIP2 = 2
IH_COMP_LZMA = 3

_logger = logging.getLogger(__name__)


def align4_uimage(n: int) -> int:
    """Round ``n`` up to a multiple of 4 (legacy multi-image padding between members)."""
    return (n + 3) & ~3


def parse_legacy_multi_size_list(payload_after_header: bytes) -> Tuple[List[int], int]:
    """
    Parse the legacy ``IH_TYPE_MULTI`` size table (U-Boot ``include/image.h``):
    big-endian ``uint32_t`` sizes until a zero word; image bytes follow immediately.

    Returns ``(sizes, data_offset)`` where ``data_offset`` is the byte index **within**
    ``payload_after_header`` where the first member starts.
    """
    idx = 0
    sizes: List[int] = []
    while True:
        if idx + 4 > len(payload_after_header):
            raise ValueError("unterminated legacy multi size list (truncated before zero word)")
        (word,) = struct.unpack_from(">I", payload_after_header, idx)
        idx += 4
        if word == 0:
            return sizes, idx
        sizes.append(int(word))


def split_legacy_multi_images(
    full_image: bytes,
    sizes: List[int],
    data_start: int,
    *,
    extent_end: Optional[int] = None,
) -> List[bytes]:
    """
    Slice each multi member out of ``full_image``. ``data_start`` is an absolute offset
    into ``full_image``. Between members, advance by ``align4_uimage(len)`` except after
    the last member (U-Boot: last file is not padded for alignment).
    """
    if extent_end is not None and data_start > extent_end:
        raise ValueError("multi data_start past extent_end")
    cursor = data_start
    out: List[bytes] = []
    for i, sz in enumerate(sizes):
        if sz < 0:
            raise ValueError(f"negative multi member size {sz}")
        if cursor + sz > len(full_image):
            raise ValueError("multi member extends past end of image")
        if extent_end is not None and cursor + sz > extent_end:
            raise ValueError("multi member extends past declared ih_size extent")
        out.append(full_image[cursor : cursor + sz])
        step = align4_uimage(sz) if i < len(sizes) - 1 else sz
        cursor += step
    return out


def _trailing_uniform_byte_run(blob: bytes) -> tuple[int, int]:
    """``(count, byte)`` for a trailing run of identical bytes; ``(0, 0)`` if not ``00``/``FF``."""
    if not blob:
        return 0, 0
    last = blob[-1]
    if last not in (0, 0xFF):
        return 0, 0
    n = 0
    for b in reversed(blob):
        if b != last:
            break
        n += 1
    return n, last


def _try_gzip_after_strip_uniform_suffix(blob: bytes) -> tuple[bytes, bool]:
    """
    Carved uImage members sometimes include **NAND padding** (``0xFF`` or ``0x00``) after the
    gzip trailer. :func:`gzip.decompress` rejects that; strip a uniform tail (≥4 bytes) and
    retry, with a few bytes of slack in case the deflate stream legitimately ended on ``FF``.
    """
    run, _b = _trailing_uniform_byte_run(blob)
    if run < 4:
        return blob, False
    for slack in range(0, 5):
        cut = run - slack
        if cut < 4:
            break
        try:
            return gzip.decompress(blob[:-cut]), True
        except (OSError, EOFError, zlib.error):
            continue
    return blob, False


def gunzip_if_gzip(blob: bytes) -> Tuple[bytes, bool]:
    """If ``blob`` looks like gzip, decompress; else return ``(blob, False)``."""
    if len(blob) >= 2 and blob[0] == 0x1F and blob[1] == 0x8B:
        try:
            return gzip.decompress(blob), True
        except (OSError, EOFError, zlib.error):
            stripped, ok = _try_gzip_after_strip_uniform_suffix(blob)
            if ok:
                return stripped, True
            return blob, False
    return blob, False


def decompress_by_ih_comp(payload: bytes, ih_comp: int) -> bytes:
    """
    Decompress ``payload`` according to U-Boot ``IH_COMP_*``.

    Returns ``payload`` unchanged when ``ih_comp`` is ``IH_COMP_NONE``, unsupported, or
    decompression fails (corrupt stream).
    """
    if ih_comp == IH_COMP_NONE:
        return payload
    if ih_comp == IH_COMP_GZIP:
        out, ok = gunzip_if_gzip(payload)
        if ok:
            return out
        if len(payload) >= 2 and payload[0] == 0x1F and payload[1] == 0x8B:
            _logger.warning(
                "gzip decompress failed (%d bytes, head %s) after uniform 0x00/0xFF suffix "
                "strip retry; leaving payload unchanged (truncated gzip, wrong ih_comp, or "
                "non-padding trailing bytes)",
                len(payload),
                payload[:8].hex(),
            )
        return payload
    if ih_comp == IH_COMP_BZIP2:
        try:
            return bz2.decompress(payload)
        except OSError:
            return payload
    if ih_comp == IH_COMP_LZMA:
        try:
            return lzma.decompress(payload)
        except lzma.LZMAError:
            return payload
    return payload


def compression_sidecar_suffix(ih_comp: int) -> Optional[str]:
    """
    Extra filename suffix for the **wire-format** compressed member when ``ih_comp`` is one
    of gzip / bzip2 / lzma (see ``IH_COMP_*``). Other codes return ``None``.
    """
    if ih_comp == IH_COMP_GZIP:
        return ".gz"
    if ih_comp == IH_COMP_BZIP2:
        return ".bz2"
    if ih_comp == IH_COMP_LZMA:
        return ".lzma"
    return None


def uimage_member_carve_split(
    member_blob: bytes, outer: UImageHeader
) -> Tuple[Optional[int], bytes, bytes]:
    """
    Split one MULTI member (or standalone kernel payload plus outer ``image_header`` context)
    into ``(declared_ih_comp_or_None, compressed_wire_bytes, plain_bytes)``.

    ``compressed_wire_bytes`` is only populated when ``declared_ih_comp`` is set (nested
    compressed inner or outer compression); otherwise it is empty and ``plain_bytes`` is the
    full ``member_blob``.

    Sidecar writers emit ``plain_bytes`` to ``…-{role}.bin`` always, and when
    :func:`compression_sidecar_suffix` is non-none for ``declared_ih_comp``, also emit
    ``compressed_wire_bytes`` to ``…-{role}.bin`` + that suffix (``.gz``, ``.bz2``, ``.lzma``).
    """
    if len(member_blob) >= 64:
        inner = parse_uimage_header(member_blob[:64])
        if inner is not None:
            if inner.ih_comp == IH_COMP_NONE:
                return None, b"", member_blob
            pay_end = min(len(member_blob), 64 + inner.ih_size)
            inner_payload = member_blob[64:pay_end]
            plain = decompress_by_ih_comp(inner_payload, inner.ih_comp)
            return inner.ih_comp, inner_payload, plain
    if outer.ih_comp == IH_COMP_NONE:
        return None, b"", member_blob
    plain = decompress_by_ih_comp(member_blob, outer.ih_comp)
    return outer.ih_comp, member_blob, plain


def carve_uimage_member_body(member_blob: bytes, outer: UImageHeader) -> bytes:
    """
    MULTI member slice as written to sidecar files: decompress using the member's nested
    ``image_header.ih_comp`` when **IH_MAGIC** is present and ``ih_comp != none``; otherwise
    use the **outer** MULTI ``ih_comp`` on the raw member bytes.

    When a nested header exists and ``ih_comp`` is ``IH_COMP_NONE``, returns the full member
    unchanged so gzip-looking payloads are not peeled unless the header declares gzip
    (matches U-Boot ``dumpimage`` semantics for undeclared compression).
    """
    _, _, plain = uimage_member_carve_split(member_blob, outer)
    return plain


def extract_outer_payload(full_image: bytes) -> Tuple[UImageHeader, bytes]:
    """
    Validate header and return ``(header, payload)`` where ``payload`` is the ``ih_size``
    bytes immediately after the 64-byte ``image_header``.
    """
    if len(full_image) < 64:
        raise ValueError("buffer too short for uImage header")
    h = parse_uimage_header(full_image[:64])
    if h is None:
        raise ValueError("not a legacy uImage (bad IH_MAGIC)")
    end = 64 + h.ih_size
    if len(full_image) < end:
        raise ValueError(f"truncated uImage: need {end} bytes, have {len(full_image)}")
    return h, full_image[64:end]


def extract_all_members(full_image: bytes) -> Tuple[UImageHeader, List[bytes]]:
    """
    Return the outer header and **every** raw member blob (before inner gunzip).

    For ``IH_TYPE_KERNEL`` the list has length **1**. For ``IH_TYPE_MULTI`` it has
    one entry per size-table member.
    """
    h, payload = extract_outer_payload(full_image)
    if h.ih_type == IH_TYPE_KERNEL:
        return h, [payload]
    if h.ih_type == IH_TYPE_MULTI:
        sizes, rel_in_payload = parse_legacy_multi_size_list(payload)
        if not sizes:
            raise ValueError("IH_TYPE_MULTI has empty size list")
        data_start = 64 + rel_in_payload
        extent_end = 64 + h.ih_size
        parts = split_legacy_multi_images(
            full_image, sizes, data_start, extent_end=extent_end
        )
        return h, parts
    raise ValueError(
        f"unsupported ih_type {h.ih_type} ({_enum_label(IH_TYPE_NAMES, h.ih_type)}); "
        "expected kernel (2) or multi (4)"
    )


def extract_kernel_blob(full_image: bytes, *, member_index: int = 0) -> Tuple[UImageHeader, bytes]:
    """
    Return the outer header and raw bytes for one member: either the full payload of a
    single ``IH_TYPE_KERNEL`` image, or one slice of an ``IH_TYPE_MULTI`` image.
    """
    if member_index < 0:
        raise ValueError("member_index must be non-negative")
    h, parts = extract_all_members(full_image)
    if h.ih_type == IH_TYPE_KERNEL and member_index != 0:
        raise ValueError("IH_TYPE_KERNEL has only one member (index 0)")
    if member_index >= len(parts):
        raise ValueError(f"multi member_index {member_index} out of range (0..{len(parts)-1})")
    return h, parts[member_index]


# Ghidra / offline RE: map uImage members to load addresses and extracted files.
UIMAGE_GHIDRA_MANIFEST_FORMAT = "uboot-uimage-ghidra-v1"

# Default Ghidra language/compiler IDs when importing **raw** MIPS binaries (BMIPS uImages).
GHIDRA_LANGUAGE_BY_IH_ARCH: Dict[int, str] = {
    2: "x86:LE:32:default",
    5: "MIPS:BE:32:default",
    6: "MIPS:BE:64:default",
}


@dataclass(frozen=True)
class GhidraExportSegment:
    """One extracted member + where to map it in Ghidra."""

    member_index: int
    role: str
    filename: str
    image_base: Optional[int]
    size: int
    gzip_inner_applied: bool
    entry_point: Optional[int]


def multi_member_role(member_index: int, member_count: int) -> str:
    """
    Fallback labels when an ``IH_TYPE_MULTI`` member does **not** start with a nested
    legacy ``image_header`` (typical raw gzip kernel / cpio ramdisk slices).

    Two-member images use ``kernel`` / ``ramdisk`` by member index; larger bundles use
    ``multi_<n>``. Prefer :func:`multi_member_roles` for carve/export filenames, which
    reads inner ``ih_type`` when present.
    """
    if member_count == 2 and member_index == 0:
        return "kernel"
    if member_count == 2 and member_index == 1:
        return "ramdisk"
    return f"multi_{member_index}"


def _ih_type_role_slug(ih_type: int) -> str:
    """Lowercase filesystem-ish token from ``IH_TYPE_*`` (nested member header)."""
    raw = IH_TYPE_NAMES.get(ih_type, f"type_{ih_type}")
    slug = raw.lower().replace(" ", "_").replace("-", "_")
    out: List[str] = []
    for ch in slug:
        if ch.isalnum() or ch == "_":
            out.append(ch)
        elif ch in "./":
            out.append("_")
        else:
            out.append("_")
    s = "".join(out).strip("_")
    return s if s else f"type_{ih_type}"


def multi_member_roles(parts: Sequence[bytes]) -> List[str]:
    """
    Role string for each MULTI member blob.

    If the member begins with a valid nested ``image_header`` (**IH_MAGIC**), the role is
    derived from that header's ``ih_type`` (e.g. ``kernel``, ``ramdisk``, ``flat_dt``).
    Otherwise uses :func:`multi_member_role` (two-part heuristic or ``multi_<n>``).

    When inner-header inference yields duplicate slugs, names are disambiguated with
    ``_1``, ``_2``, … (first keeps an unsuffixed base).
    """
    n = len(parts)
    inferred: List[str] = []
    for i, blob in enumerate(parts):
        label: Optional[str] = None
        if len(blob) >= 64:
            inner = parse_uimage_header(blob[:64])
            if inner is not None:
                label = _ih_type_role_slug(inner.ih_type)
        if label is None:
            label = multi_member_role(i, n)
        inferred.append(label)

    counts = Counter(inferred)
    tallies: Dict[str, int] = {}
    out_labels: List[str] = []
    for label in inferred:
        if counts[label] == 1:
            out_labels.append(label)
            continue
        k = tallies.get(label, 0)
        tallies[label] = k + 1
        out_labels.append(label if k == 0 else f"{label}_{k}")
    return out_labels


def resolve_member_image_base(
    member_index: int,
    member_count: int,
    header: UImageHeader,
    *,
    ramdisk_base: Optional[int] = None,
    member_base_overrides: Optional[Mapping[int, int]] = None,
) -> Optional[int]:
    """
    Virtual address (KSEG0 style) to use when loading the **decompressed** member in Ghidra.

    Member **0** always uses ``ih_load`` from the uImage header. Further members are not
    present in the legacy header; use ``ramdisk_base`` (typical: U-Boot ``rd_start`` from
    ``/proc/iomem`` or boot logs) or ``member_base_overrides``.
    """
    if member_index == 0:
        return header.ih_load
    overrides = member_base_overrides or {}
    if member_index in overrides:
        return overrides[member_index]
    if member_index == 1 and member_count >= 2 and ramdisk_base is not None:
        return ramdisk_base
    return None


def parse_member_base_specs(items: Sequence[str]) -> Dict[int, int]:
    """
    Parse ``--member-base`` values such as ``1:0x80a9a000`` (index before colon, hex or dec).
    """
    out: Dict[int, int] = {}
    for item in items:
        s = item.strip()
        if ":" not in s:
            raise ValueError(f"member-base must be INDEX:ADDRESS, got {item!r}")
        left, _, right = s.partition(":")
        idx = int(left.strip(), 0)
        addr = int(right.strip(), 0)
        out[idx] = addr
    return out


def build_uimage_ghidra_manifest(
    *,
    uimage_path: str,
    out_dir: str,
    header: UImageHeader,
    segments: Sequence[GhidraExportSegment],
) -> dict:
    """JSON-serializable manifest consumed by ``ghidra_load_uimage_manifest.py``."""
    lang = GHIDRA_LANGUAGE_BY_IH_ARCH.get(header.ih_arch)
    seg_dicts: List[dict] = []
    for s in segments:
        seg_dicts.append(
            {
                "member_index": s.member_index,
                "role": s.role,
                "output_file": s.filename,
                "image_base": s.image_base,
                "size": s.size,
                "gzip_inner_applied": s.gzip_inner_applied,
                "entry_point": s.entry_point,
            }
        )
    return {
        "format": UIMAGE_GHIDRA_MANIFEST_FORMAT,
        "uimage_source": uimage_path,
        "output_dir": out_dir,
        "header": header.as_dict(),
        "ghidra_language_hint": lang,
        "segments": seg_dicts,
    }


def uimage_carve_health_lines(full_image: bytes) -> List[str]:
    """
    Markdown bullets for ``carve_summary.md`` when the container bytes look unhealthy or
    zlib cannot honor ``ih_comp`` (so sidecars may stay gzip-shaped even though the header
    declares gzip).
    """
    lines: List[str] = []
    try:
        h, payload = extract_outer_payload(full_image)
    except ValueError:
        return lines

    payload_crc = zlib.crc32(payload) & 0xFFFFFFFF
    if payload_crc != (h.ih_dcrc & 0xFFFFFFFF):
        lines.append(
            "- **Payload CRC:** `ih_dcrc` does **not** match zlib CRC32 of the `ih_size` bytes "
            f"after the header (`ih_dcrc=0x{h.ih_dcrc:08x}`, `crc32(payload)=0x{payload_crc:08x}`). "
            "Expect carve/decompression problems if the dump or header metadata is inconsistent."
        )

    try:
        h2, parts = extract_all_members(full_image)
    except ValueError:
        return lines

    def _is_gzip_head(b: bytes) -> bool:
        return len(b) >= 2 and b[0] == 0x1F and b[1] == 0x8B

    if h2.ih_type == IH_TYPE_MULTI and parts:
        raw_k = parts[0]
        cooked_k = carve_uimage_member_body(raw_k, h2)
        if _is_gzip_head(raw_k) and _is_gzip_head(cooked_k) and raw_k == cooked_k:
            lines.append(
                "- **Decompression:** First MULTI member is still gzip-shaped after applying "
                "`ih_comp` / nested-header rules - Python zlib rejected the deflate stream. "
                "Sidecar ``*-kernel.bin`` may remain compressed even though **`ih_comp`** "
                "reports gzip."
            )
    elif h2.ih_type == IH_TYPE_KERNEL and len(parts) == 1:
        raw = parts[0]
        cooked = decompress_by_ih_comp(raw, h2.ih_comp)
        if (
            h2.ih_comp != IH_COMP_NONE
            and _is_gzip_head(raw)
            and raw == cooked
        ):
            lines.append(
                "- **Decompression:** Kernel payload still looks gzip-compressed after applying "
                "`ih_comp` - zlib could not decompress it."
            )
    return lines


def format_uimage_header_markdown(
    h: UImageHeader,
    *,
    title: Optional[str] = None,
    extra_bullets: Sequence[str] = (),
) -> str:
    """Human-readable markdown fragment (bullets + optional multi-image note)."""
    lines = []
    if title:
        lines.append(f"### {title}")
        lines.append("")
    lines.extend(
        [
            f"- **ih_magic:** `{h.ih_magic:#010x}` (`IH_MAGIC`)",
            f"- **ih_hcrc:** `{h.ih_hcrc:#010x}`",
            f"- **ih_time:** `{h.ih_time:#010x}` ({h.ih_time})",
            f"- **ih_size:** `{h.ih_size:#010x}` ({h.ih_size} bytes payload after header)",
            f"- **ih_load:** `{h.ih_load:#010x}`",
            f"- **ih_ep:** `{h.ih_ep:#010x}`",
            f"- **ih_dcrc:** `{h.ih_dcrc:#010x}`",
            f"- **ih_os:** {h.ih_os} ({_enum_label(IH_OS_NAMES, h.ih_os)})",
            f"- **ih_arch:** {h.ih_arch} ({_enum_label(IH_ARCH_NAMES, h.ih_arch)})",
            f"- **ih_type:** {h.ih_type} ({_enum_label(IH_TYPE_NAMES, h.ih_type)})",
            f"- **ih_comp:** {h.ih_comp} ({_enum_label(IH_COMP_NAMES, h.ih_comp)})",
            f"- **ih_name:** `{h.ih_name}`",
        ]
    )
    if h.ih_type == 4:
        lines.append(
            "- **Note:** Type **multi** — size table + members per **`include/image.h`**; "
            "extract with **`dumpimage`** (U-Boot) or your toolchain's uImage unpacker."
        )
    lines.extend(extra_bullets)
    return "\n".join(lines)
