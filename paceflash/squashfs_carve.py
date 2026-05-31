"""Dissect-verified SquashFS carving from ext2 file bytes or other blobs."""

from __future__ import annotations

from typing import Any

from lib2spy.native_pkgstream import squashfs_le_span_at

from paceflash.squashfs_dissect import (
    find_squashfs_superblock_offsets,
    first_dissect_verified_strict_squash_carve,
    iter_squashfs_image_candidates,
    list_squashfs_root_entries_with_meta,
)


def _verify_dissect_root(image: bytes, *, prefer_offset: int = 0) -> dict[str, Any] | None:
    try:
        _rows, meta = list_squashfs_root_entries_with_meta(
            image,
            cap=1,
            prefer_offsets=[prefer_offset],
        )
    except Exception:
        return None
    return dict(meta)


def carve_dissectable_squash_blob(
    data: bytes,
    *,
    prefer_offsets: list[int] | None = None,
) -> tuple[int, bytes, dict[str, Any]] | None:
    """
    Return ``(superblock_offset, carved_bytes, meta)`` only when Dissect can list ``/``.

    Tries strict ``bytes_used`` spans first, then relaxed EOF-tail candidates.
    """
    strict = first_dissect_verified_strict_squash_carve(data)
    if strict is not None:
        off, image = strict
        meta = _verify_dissect_root(image, prefer_offset=0)
        if meta is not None:
            meta["carve_model"] = "strict_dissect_verified"
            return off, image, meta

    seen: set[int] = set()
    ordered: list[int] = []
    for off in prefer_offsets or []:
        if 0 <= off < len(data) and off not in seen:
            seen.add(off)
            ordered.append(off)
    for off in find_squashfs_superblock_offsets(data):
        if off not in seen:
            seen.add(off)
            ordered.append(off)

    for off in ordered:
        for sb_off, image in iter_squashfs_image_candidates(
            data,
            prefer_offsets=[off],
            allow_eof_tail=True,
        ):
            meta = _verify_dissect_root(image, prefer_offset=0)
            if meta is None:
                continue
            meta["carve_model"] = "dissect_verified"
            meta["requested_offset"] = off
            return sb_off, image, meta
    return None


def squashfs_carve_bytes(data: bytes, off: int) -> bytes | None:
    """Legacy span-only carve (no Dissect verify). Prefer :func:`carve_dissectable_squash_blob`."""
    if off < 0 or off + 4 > len(data) or data[off : off + 4] not in (b"hsqs", b"sqsh"):
        return None
    span = squashfs_le_span_at(data, off)
    if span is not None:
        start, slen = span
        carved = data[start : start + slen]
        return carved if carved[:4] in (b"hsqs", b"sqsh") else None
    if off == 0 and data[:4] == b"hsqs":
        return data
    return None
