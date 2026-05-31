"""Peel uImage kernel members and convert decompressed vmlinux to analyzable ELF."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from uboot.uimage import UImageHeader, parse_uimage_header


@dataclass(frozen=True, slots=True)
class UImagePeelResult:
    header: UImageHeader
    member_raw: bytes
    kernel_inner: bytes
    member_decompressed: bool


@dataclass(frozen=True, slots=True)
class UImageVmlinuxElfResult:
    peel: UImagePeelResult
    ok: bool
    error: str
    elf_bytes: bytes | None


def is_uimage_payload(data: bytes) -> bool:
    return len(data) >= 64 and parse_uimage_header(data[:64]) is not None


def peel_uimage_kernel_member(
    full_image: bytes,
    *,
    member_index: int = 0,
) -> UImagePeelResult:
    """Split MULTI/single uImage and gunzip (etc.) member *member_index* per U-Boot rules."""
    from uboot.uimage import carve_uimage_member_body, extract_kernel_blob

    header, member_raw = extract_kernel_blob(full_image, member_index=member_index)
    inner = carve_uimage_member_body(member_raw, header)
    return UImagePeelResult(
        header=header,
        member_raw=member_raw,
        kernel_inner=inner,
        member_decompressed=inner != member_raw,
    )


def uimage_to_vmlinux_elf(
    uimage: bytes,
    *,
    member_index: int = 0,
    timeout_s: int = 600,
) -> UImageVmlinuxElfResult:
    """Peel kernel member 0 and run **marin-m/vmlinux-to-elf** (gzip-aware decompress)."""
    from corpus.vmlinux_elf import try_vmlinux_to_elf

    peel = peel_uimage_kernel_member(uimage, member_index=member_index)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        kbin = Path(tmp.name)
        kbin.write_bytes(peel.kernel_inner)
    try:
        ok, err, elf_bytes = try_vmlinux_to_elf(kbin, None, timeout_s=timeout_s)
    finally:
        kbin.unlink(missing_ok=True)
    return UImageVmlinuxElfResult(peel=peel, ok=ok, error=err, elf_bytes=elf_bytes)


def uimage_peel_to_jsonable(result: UImagePeelResult) -> dict[str, Any]:
    from uboot.uimage import IH_ARCH_NAMES, IH_COMP_NAMES, IH_OS_NAMES, IH_TYPE_NAMES, _enum_label

    h = result.header
    return {
        **h.as_dict(),
        "ih_os_name": _enum_label(IH_OS_NAMES, h.ih_os),
        "ih_arch_name": _enum_label(IH_ARCH_NAMES, h.ih_arch),
        "ih_type_name": _enum_label(IH_TYPE_NAMES, h.ih_type),
        "ih_comp_name": _enum_label(IH_COMP_NAMES, h.ih_comp),
        "member_raw_len": len(result.member_raw),
        "kernel_inner_len": len(result.kernel_inner),
        "member_decompressed": result.member_decompressed,
    }


__all__ = [
    "UImagePeelResult",
    "UImageVmlinuxElfResult",
    "is_uimage_payload",
    "peel_uimage_kernel_member",
    "uimage_peel_to_jsonable",
    "uimage_to_vmlinux_elf",
]
