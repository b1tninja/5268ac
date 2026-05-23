"""
Scan a raw **UBI-on-MTD** byte image for plausible **volume ID** headers (``UBI!``).

This is **not** a full UBI volume table (no volume names, no LEB map). It reuses
:class:`binwalker.ubi_carve` heuristics for offline triage. Named volumes require
``ubinfo`` / ``ubi_reader`` / kernel attach (see :mod:`binwalker.extract.ubifs_decode`).
"""

from __future__ import annotations

from dataclasses import dataclass

from boardfs.block import BlockDev, BlockSlice

from binwalker.ubi_carve import (
    parse_ubi_vid_hdr_fields,
    plausible_ubi_vid_offsets,
    scan_magic_offsets,
)


@dataclass(frozen=True, slots=True)
class UbiVidHeaderHit:
    """Decoded fields from one plausible ``struct ubi_vid_hdr`` (PEB-aligned with ``UBI#``)."""

    vid_offset: int
    fields: dict[str, object]


def scan_ubi_vid_headers_in_bytes(
    data: bytes,
    *,
    erase_bytes: int = 131072,
) -> tuple[UbiVidHeaderHit, ...]:
    """
    Return decoded VID headers at offsets that pass :func:`~binwalker.ubi_carve.plausible_ubi_vid_offsets`.

    ``erase_bytes`` must match the MTD erase block size for the UBI device (Pace OpenTL
    TL erase unit default is 128 KiB).
    """
    _ec, vid, _ubifs = scan_magic_offsets(data, include_ubifs_nodes=False)
    good = plausible_ubi_vid_offsets(data, vid, erase_bytes=erase_bytes)
    hits: list[UbiVidHeaderHit] = []
    for off in good:
        d = parse_ubi_vid_hdr_fields(data, off)
        if d is not None:
            hits.append(UbiVidHeaderHit(vid_offset=off, fields=d))
    return tuple(hits)


def scan_ubi_vid_headers_on_block_dev(
    dev: BlockSlice,
    *,
    erase_bytes: int = 131072,
) -> tuple[UbiVidHeaderHit, ...]:
    """Read ``dev`` entirely into memory and run :func:`scan_ubi_vid_headers_in_bytes`."""
    if dev.size < 0:
        raise ValueError("negative BlockDev.size")
    data = dev.read_slice()
    return scan_ubi_vid_headers_in_bytes(data, erase_bytes=erase_bytes)


__all__ = ["UbiVidHeaderHit", "scan_ubi_vid_headers_in_bytes", "scan_ubi_vid_headers_on_block_dev"]
