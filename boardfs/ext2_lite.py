"""
Lightweight checks on ext2 **primary superblock** bytes (no full FS validation).

Partition layout: primary superblock at byte offset **1024** (`0x400`); ``s_magic`` at superblock + **0x38**
→ partition offset **0x438** (same convention as **opentl.open_tl** / **opentl.driver** for opentla4 magic checks).
"""

from __future__ import annotations

import struct
from typing import Any

# Primary superblock starts at block 1 when block size is 1024 B (classic layout).
EXT2_SB_OFFSET = 1024  # 0x400

# Within struct ext2_super_block (Linux fs/ext2/ext2.h)
_EXT2_OFF_INODES_COUNT = 0x00
_EXT2_OFF_BLOCKS_COUNT = 0x04
_EXT2_OFF_LOG_BLOCK_SIZE = 0x18
_EXT2_OFF_MAGIC = 0x38
_EXT2_OFF_STATE = 0x3A
# Linux ``struct ext2_super_block``: ``s_creator_os`` / ``s_rev_level`` follow
# ``s_lastcheck`` / ``s_checkinterval`` at **0x40** / **0x44**.
_EXT2_OFF_CREATOR_OS = 0x48
_EXT2_OFF_REV_LEVEL = 0x4C

EXT2_MAGIC_LE = 0xEF53

# opentla4 slice is ~120 MiB — loose upper bound for sanity (bytes)
_MAX_PLAUSIBLE_VOLUME_BYTES = 256 * 1024 * 1024


def ext2_primary_superblock_sanity(partition_head: bytes) -> tuple[float, dict[str, Any]]:
    """
    Score **0.0 … 50.0** based on parsable primary superblock fields.

    ``partition_head`` must cover bytes from the **start of the ext2 partition** (opentla4 extract),
    at least through **0x43A** for magic; more length improves optional field checks.
    """
    detail: dict[str, Any] = {"ext2_lite_ok": False}
    need = EXT2_SB_OFFSET + _EXT2_OFF_MAGIC + 2
    if len(partition_head) < need:
        detail["reason"] = "partition_head_too_short"
        return 0.0, detail

    sb_base = EXT2_SB_OFFSET
    magic = struct.unpack_from("<H", partition_head, sb_base + _EXT2_OFF_MAGIC)[0]
    detail["s_magic"] = f"{magic:#06x}"
    if magic != EXT2_MAGIC_LE:
        detail["reason"] = "bad_magic"
        return 0.0, detail

    if len(partition_head) < sb_base + _EXT2_OFF_REV_LEVEL + 4:
        detail["reason"] = "truncated_after_magic"
        return 0.0, detail

    inodes = struct.unpack_from("<I", partition_head, sb_base + _EXT2_OFF_INODES_COUNT)[0]
    blocks = struct.unpack_from("<I", partition_head, sb_base + _EXT2_OFF_BLOCKS_COUNT)[0]
    log_bs = struct.unpack_from("<I", partition_head, sb_base + _EXT2_OFF_LOG_BLOCK_SIZE)[0]

    detail["s_inodes_count"] = inodes
    detail["s_blocks_count"] = blocks
    detail["s_log_block_size"] = log_bs

    score = 0.0

    if log_bs > 16:
        detail["reason"] = "s_log_block_size_absurd"
        detail["ext2_lite_ok"] = False
        return 0.0, detail

    try:
        block_size = 1024 << log_bs
    except OverflowError:
        detail["reason"] = "s_log_block_size_overflow"
        return 0.0, detail

    if block_size < 512 or block_size > 65536 or (block_size & (block_size - 1)) != 0:
        detail["reason"] = "block_size_implausible"
        detail["computed_block_size"] = block_size
        return 0.0, detail

    detail["computed_block_size"] = block_size
    score += 15.0

    if inodes == 0 or blocks == 0:
        detail["reason"] = "zero_inodes_or_blocks"
        return score * 0.3, detail

    vol_bytes = blocks * block_size
    detail["approx_volume_bytes"] = vol_bytes
    if vol_bytes > _MAX_PLAUSIBLE_VOLUME_BYTES:
        detail["reason"] = "volume_too_large"
        return min(score, 10.0), detail

    # Loose plausibility for opentla4-sized volumes
    if vol_bytes < block_size * 8:
        detail["reason"] = "volume_too_small"
        return min(score, 10.0), detail

    score += 15.0

    ratio = inodes / max(blocks, 1)
    detail["inodes_per_block"] = round(ratio, 6)
    if 0.01 <= ratio <= 8.0:
        score += 10.0
    elif ratio <= 16.0:
        score += 5.0

    state = struct.unpack_from("<H", partition_head, sb_base + _EXT2_OFF_STATE)[0]
    detail["s_state"] = state
    if 1 <= state <= 4:
        score += 5.0

    creator = struct.unpack_from("<I", partition_head, sb_base + _EXT2_OFF_CREATOR_OS)[0]
    detail["s_creator_os"] = creator
    if creator <= 7:
        score += 2.5

    rev = struct.unpack_from("<I", partition_head, sb_base + _EXT2_OFF_REV_LEVEL)[0]
    detail["s_rev_level"] = rev
    if rev <= 2:
        score += 2.5

    score = min(score, 50.0)
    detail["ext2_lite_ok"] = True
    detail["lite_score"] = score
    return score, detail


def scan_ext2_primary_superblock_slides(
    image: bytes,
    *,
    step: int = 512,
    scan_limit: int | None = None,
    require_volume_fits: bool = True,
) -> list[dict[str, Any]]:
    """
    Slide a hypothetical **ext2 partition start** through ``image`` (step bytes).

    Each candidate starts primary superblock at ``slide + EXT2_SB_OFFSET``. When
    ``require_volume_fits`` is True, reject hits where ``s_blocks_count * block_size``
    exceeds ``len(image) - slide`` — excluding bogus ``0xEF53`` that sit mid-file but
    describe a volume as large as the **whole** image from offset 0.
    """
    lim = len(image) if scan_limit is None else min(len(image), scan_limit)
    out: list[dict[str, Any]] = []
    slide = 0
    while slide + EXT2_SB_OFFSET + _EXT2_OFF_MAGIC + 2 <= lim:
        chunk = image[slide : slide + 65536]
        score, detail = ext2_primary_superblock_sanity(chunk)
        if score <= 0.0 or not detail.get("ext2_lite_ok"):
            slide += step
            continue
        sb = slide + EXT2_SB_OFFSET
        blocks = struct.unpack_from("<I", image, sb + _EXT2_OFF_BLOCKS_COUNT)[0]
        log_bs = struct.unpack_from("<I", image, sb + _EXT2_OFF_LOG_BLOCK_SIZE)[0]
        try:
            bs = 1024 << log_bs if log_bs <= 16 else 0
        except OverflowError:
            bs = 0
        vol = blocks * bs if bs else 0
        remainder = len(image) - slide
        fits = vol > 0 and vol <= remainder
        row = {
            "slide_offset": slide,
            "slide_hex": f"{slide:#x}",
            "lite_score": score,
            "approx_volume_bytes": vol,
            "remainder_bytes": remainder,
            "volume_fits_image": fits,
            **{k: v for k, v in detail.items() if k != "ext2_lite_ok"},
        }
        if not require_volume_fits or fits:
            out.append(row)
        slide += step
    return out


__all__ = [
    "EXT2_SB_OFFSET",
    "EXT2_MAGIC_LE",
    "ext2_primary_superblock_sanity",
    "scan_ext2_primary_superblock_slides",
]
