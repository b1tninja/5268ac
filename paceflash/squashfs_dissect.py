"""Non-recursive ``/`` listing for SquashFS in a byte buffer via ``dissect.squashfs``."""

from __future__ import annotations

import io
from typing import Any, Iterator

from boardfs.squashfs_probe import SQUASHFS_MAGIC_LE
from lib2spy.native_pkgstream import squashfs_le_span_at


def find_squashfs_superblock_offsets(data: bytes, *, max_hits: int = 32) -> list[int]:
    """Return byte offsets where little-endian SquashFS magic ``hsqs`` appears (possible superblock start)."""
    out: list[int] = []
    pos = 0
    while len(out) < max_hits:
        i = data.find(SQUASHFS_MAGIC_LE, pos)
        if i < 0:
            break
        if i not in out:
            out.append(i)
        pos = i + 1
    return sorted(out)


def iter_squashfs_image_candidates(
    data: bytes,
    *,
    prefer_offsets: list[int] | None = None,
    allow_eof_tail: bool = True,
) -> Iterator[tuple[int, bytes]]:
    """
    Yield ``(superblock_offset, image_bytes)`` for each plausible SquashFS image in ``data``.

    Uses ``bytes_used`` from the superblock when valid (:func:`lib2spy.native_pkgstream.squashfs_le_span_at`).

    When ``allow_eof_tail`` is True (default, dissect compatibility), offsets where ``bytes_used`` would extend
    past ``data`` still yield ``data[off:]`` so Dissect can try best-effort. External tools such as
    ``unsquashfs`` require file length to match ``bytes_used`` — call with ``allow_eof_tail=False`` for exports.
    """
    seen: set[int] = set()
    ordered: list[int] = []
    if prefer_offsets:
        for o in prefer_offsets:
            if 0 <= o < len(data) and o not in seen:
                seen.add(o)
                ordered.append(o)
    for o in find_squashfs_superblock_offsets(data):
        if o not in seen:
            seen.add(o)
            ordered.append(o)

    # Prefer superblocks whose `bytes_used` validates in-buffer (tier 0) over raw
    # `hsqs` + EOF tail slices (tier 1). Within a tier, use increasing offset (stable).
    def _candidate_sort_key(o: int) -> tuple[int, int]:
        if squashfs_le_span_at(data, o) is not None:
            return (0, o)
        if o + 4 <= len(data) and data[o : o + 4] == SQUASHFS_MAGIC_LE:
            return (1, o)
        return (2, o)

    ordered.sort(key=_candidate_sort_key)

    for off in ordered:
        span = squashfs_le_span_at(data, off)
        if span is not None:
            sb_off, length = span
            image = data[sb_off : sb_off + length]
            yield sb_off, image
        elif (
            allow_eof_tail
            and off + 4 <= len(data)
            and data[off : off + 4] == SQUASHFS_MAGIC_LE
        ):
            image = data[off:]
            yield off, image


def first_dissect_verified_strict_squash_carve(data: bytes) -> tuple[int, bytes] | None:
    """
    First strict-span image (:func:`iter_squashfs_image_candidates` with ``allow_eof_tail=False``)
    for which :func:`list_squashfs_root_entries_with_meta` succeeds — same bar as inventory's dissect
    listing (not just ``SquashFS`` construction / ``root.is_dir()``).
    """
    for sb_off, image in iter_squashfs_image_candidates(data, allow_eof_tail=False):
        try:
            list_squashfs_root_entries_with_meta(image, cap=32)
        except Exception:
            continue
        else:
            return sb_off, image
    return None


def _squash_kind(node: Any) -> str:
    if getattr(node, "is_symlink", lambda: False)():
        return "symlink"
    if getattr(node, "is_dir", lambda: False)():
        return "dir"
    if getattr(node, "is_file", lambda: False)():
        return "reg"
    return "other"


def list_squashfs_root_entries_with_meta(
    data: bytes,
    *,
    cap: int = 50,
    prefer_offsets: list[int] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    List top-level SquashFS directory entries via Dissect.

    ``meta`` may include ``squashfs_superblock_offset`` and ``squashfs_image_bytes``.
    """
    from dissect.squashfs import SquashFS

    last_err: Exception | None = None
    for sb_off, image in iter_squashfs_image_candidates(
        data, prefer_offsets=prefer_offsets, allow_eof_tail=True
    ):
        try:
            fs = SquashFS(io.BytesIO(image))
            root = fs.root
            if not root.is_dir():
                continue
            rows: list[dict[str, Any]] = []
            for ch in sorted(root.iterdir(), key=lambda n: n.name):  # type: ignore[attr-defined]
                name = getattr(ch, "name", "?")
                rows.append({"name": name, "kind": _squash_kind(ch)})
                if len(rows) >= cap:
                    break
            return rows, {
                "squashfs_superblock_offset": sb_off,
                "squashfs_image_bytes": len(image),
            }
        except Exception as e:
            last_err = e
            continue

    if last_err is not None:
        raise last_err
    raise ValueError("Not a SquashFS image (no valid hsqs superblock parsed)")


def list_squashfs_root_entries(
    data: bytes, *, cap: int = 50, prefer_offsets: list[int] | None = None
) -> list[dict[str, Any]]:
    rows, _m = list_squashfs_root_entries_with_meta(data, cap=cap, prefer_offsets=prefer_offsets)
    return rows
