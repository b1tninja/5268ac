"""Hydrate dissectable SquashFS bytes from install pkgstreams when NAND ext2 reads fail Dissect."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from lib2spy.native_pkgstream import squashfs_le_span_at

from paceflash.board_info import parse_dotted_version_quad
from paceflash.ext2_file_extract import DEFAULT_SQUASH_IMAGE_PATHS, DEFAULT_UIMAGE_PATHS
from paceflash.squashfs_carve import carve_dissectable_squash_blob
from paceflash.upgrade_correlation import load_carrier_refs_from_pkgstream

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_GATEWAY = _REPO_ROOT / "gateway.c01.sbcglobal.net"

_EXT2_TO_CARRIER_PATH: dict[str, str] = {
    "sys1/rootimage.img": "/rwdata/tmp/sys2/rootimage.img",
    "sys2/rootimage.img": "/rwdata/tmp/sys2/rootimage.img",
    "rootimage.img": "/rwdata/tmp/sys2/rootimage.img",
    "sys1/ui.img": "/rwdata/tmp/sys2/ui.img",
    "sys2/ui.img": "/rwdata/tmp/sys2/ui.img",
    "ui.img": "/rwdata/tmp/sys2/ui.img",
}


def firmware_release_from_ext2_files(files: dict[str, bytes]) -> str | None:
    """Derive a gateway release directory name like ``11.14.1.533857-PROD`` from version files."""
    for path in ("sys1/component.txt", "sys2/component.txt", "sys1/version.txt", "sys2/version.txt"):
        body = files.get(path)
        if not body:
            continue
        text = body.decode("utf-8", errors="replace")
        parsed = parse_dotted_version_quad(text)
        if not parsed.get("ok"):
            continue
        nums = parsed["digits_array"]
        channel = "PROD"
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) >= 4:
            tail = lines[3].lower()
            if "lab" in tail:
                channel = "LAB"
            elif "alpha" in tail:
                channel = "ALPHA"
        return f"{nums[0]}.{nums[1]}.{nums[2]}.{nums[3]}-{channel}"
    return None


def find_install_pkgstream_for_release(
    gateway_root: Path,
    release_label: str,
) -> Path | None:
    """Locate an install ``.pkgstream`` for one release under the 00D09E mirror trees."""
    root = gateway_root.expanduser().resolve()
    candidates = [
        root / "firmware" / "00D09E" / release_label,
        root / "firmware" / "ALPHA" / "00D09E" / release_label,
        root / "firmware" / "lab" / "00D09E" / release_label,
    ]
    for directory in candidates:
        if not directory.is_dir():
            continue
        for pkg in sorted(directory.glob("*.pkgstream")):
            low = pkg.name.lower()
            if "install" not in low or "cert" in low or low.startswith("att_config"):
                continue
            return pkg
    return None


def carrier_file_bytes_for_ext2_path(
    pkgstream_path: Path,
    ext2_rel_path: str,
) -> tuple[bytes, dict[str, Any]] | None:
    """Extract one install FILE payload that corresponds to an ext2 ``sys*/…img`` path."""
    carrier_path = _EXT2_TO_CARRIER_PATH.get(ext2_rel_path.lstrip("/"))
    if carrier_path is None:
        return None
    refs = load_carrier_refs_from_pkgstream(
        pkgstream_path,
        release_label=pkgstream_path.parent.name,
    )
    ref = next((r for r in refs if r.path == carrier_path), None)
    if ref is None:
        return None
    body = pkgstream_path.read_bytes()
    start = ref.pkgstream_payload_offset
    end = start + ref.file_payload_len
    if end > len(body):
        return None
    payload = body[start:end]
    meta: dict[str, Any] = {
        "carrier_path": carrier_path,
        "pkgstream_path": str(pkgstream_path),
        "release_label": pkgstream_path.parent.name,
        "file_payload_len": ref.file_payload_len,
    }
    if ref.strict_squash_len is not None:
        sb = ref.strict_sb_offset_in_payload
        end_sq = sb + ref.strict_squash_len
        if end_sq <= len(payload):
            meta["strict_squash_len"] = ref.strict_squash_len
            meta["strict_squash_sha256"] = ref.strict_squash_sha256
            span = squashfs_le_span_at(payload, sb)
            if span is not None:
                _, slen = span
                payload = payload[sb : sb + slen]
                meta["squashfs_superblock_offset"] = sb
                meta["squashfs_image_bytes"] = len(payload)
    return payload, meta


def hydrate_dissectable_squash_from_carrier(
    ext2_rel_path: str,
    release_label: str,
    *,
    gateway_root: Path | str | None = None,
) -> tuple[int, bytes, dict[str, Any]] | None:
    """
    Load install-carrier SquashFS bytes for ``ext2_rel_path`` when on-flash bytes fail Dissect.

    Returns ``(offset, carved_bytes, meta)`` with ``read_model=carrier_hydrate``.
    """
    if ext2_rel_path.lstrip("/") not in {*DEFAULT_SQUASH_IMAGE_PATHS, *DEFAULT_UIMAGE_PATHS}:
        return None
    gateway = Path(gateway_root or _DEFAULT_GATEWAY).expanduser().resolve()
    pkg = find_install_pkgstream_for_release(gateway, release_label)
    if pkg is None:
        return None
    extracted = carrier_file_bytes_for_ext2_path(pkg, ext2_rel_path)
    if extracted is None:
        return None
    payload, carrier_meta = extracted
    carved = carve_dissectable_squash_blob(payload, prefer_offsets=[0])
    if carved is None:
        return None
    off, image, carve_meta = carved
    meta = {
        **carrier_meta,
        **carve_meta,
        "read_model": "carrier_hydrate",
        "hydrate_reason": "nand_dissect_failed",
        "ext2_path": ext2_rel_path,
        "firmware_release": release_label,
    }
    return off, image, meta
