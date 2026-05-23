"""Minimal ext2 mount probes for chain-aware inference (not full inventory dissect)."""

from __future__ import annotations

import io
import stat
import struct

from opentl.driver import OPENTLA4_EXT2_MAGIC_OFF, partition_payload_ext2_magic

#region kernel_adjacent ext2_probe_dissect_prepare
# Same PACE superblock/GD fixes as boardfs.ext2_dissect (host Dissect mount path).
_EXT2_MAGIC_LE = b"\x53\xef"
_EXT2_SB_MAGIC_OFF = 56
_EXT2_SB0_OFF = 1024
_EXT2_DEFAULT_INODE_SIZE = 128
_EXT2_DEFAULT_FIRST_INO = 11


def _ext2_io_view(data: bytes, sb_off: int) -> io.BytesIO:
    delta = sb_off - _EXT2_SB0_OFF
    if delta == 0:
        return io.BytesIO(data)
    if delta > 0:
        return io.BytesIO(data[delta:])
    return io.BytesIO(b"\x00" * (-delta) + data)


def _ext2_normalize_superblock_for_dissect(buf: bytearray, sb_off: int = _EXT2_SB0_OFF) -> bool:
    if sb_off + 90 > len(buf):
        return False
    if buf[sb_off + _EXT2_SB_MAGIC_OFF : sb_off + _EXT2_SB_MAGIC_OFF + 2] != _EXT2_MAGIC_LE:
        return False
    changed = False
    if struct.unpack_from("<H", buf, sb_off + 88)[0] == 0:
        buf[sb_off + 88 : sb_off + 90] = struct.pack("<H", _EXT2_DEFAULT_INODE_SIZE)
        changed = True
    if struct.unpack_from("<I", buf, sb_off + 84)[0] == 0:
        buf[sb_off + 84 : sb_off + 88] = struct.pack("<I", _EXT2_DEFAULT_FIRST_INO)
        changed = True
    ro_compat = struct.unpack_from("<I", buf, sb_off + 104)[0]
    if ro_compat > 0xFFFF:
        buf[sb_off + 104 : sb_off + 108] = b"\x00\x00\x00\x00"
        changed = True
    return changed


def _ext2_mask_block_ptr(value: int, last_block: int) -> int:
    if value <= last_block:
        return value
    for mask in (0xFFFF, 0xFFFFFF):
        trimmed = value & mask
        if trimmed <= last_block:
            return trimmed
    return value


def _ext2_sanitize_group_descriptors(buf: bytearray, sb_off: int = _EXT2_SB0_OFF) -> bool:
    if sb_off + 128 > len(buf):
        return False
    sb = memoryview(buf)[sb_off : sb_off + 256]
    if sb[_EXT2_SB_MAGIC_OFF : _EXT2_SB_MAGIC_OFF + 2] != _EXT2_MAGIC_LE:
        return False
    blksz = 1024 << struct.unpack_from("<I", sb, 24)[0]
    if blksz <= 0:
        return False
    blocks_lo = struct.unpack_from("<I", sb, 4)[0]
    blocks_hi = struct.unpack_from("<I", sb, 72)[0]
    last_block = ((blocks_hi << 32) | blocks_lo) - 1
    if last_block <= 0:
        return False
    bpg = struct.unpack_from("<I", sb, 32)[0]
    if bpg == 0:
        return False
    first_data = struct.unpack_from("<I", sb, 20)[0]
    ngroups = (last_block - first_data + bpg) // bpg
    gd_off = _EXT2_SB0_OFF + blksz
    changed = False
    for g in range(int(ngroups) + 1):
        o = gd_off + g * 32
        if o + 12 > len(buf):
            break
        for fld in (0, 4, 8):
            v = struct.unpack_from("<I", buf, o + fld)[0]
            fixed = _ext2_mask_block_ptr(v, last_block)
            if fixed != v:
                struct.pack_into("<I", buf, o + fld, fixed)
                changed = True
    return changed


def _ext2_open_dissect(data: bytes, sb_off: int):
    from dissect.extfs import ExtFS

    delta = sb_off - _EXT2_SB0_OFF
    if delta == 0:
        work = bytearray(data)
    elif delta > 0:
        work = bytearray(data[delta:])
    else:
        work = bytearray(b"\x00" * (-delta) + data)
    _ext2_normalize_superblock_for_dissect(work, _EXT2_SB0_OFF)
    _ext2_sanitize_group_descriptors(work, _EXT2_SB0_OFF)
    return ExtFS(io.BytesIO(bytes(work)))
#endregion


#region kernel_adjacent opentla4_ext2_signature_and_mount
def buffer_has_ext2_signature(payload: bytes) -> bool:
    ok, _ = partition_payload_ext2_magic(payload)
    return ok


def ext2_slice_has_mountable_root(slice_data: bytes) -> tuple[bool, int | None]:
    """Return whether Dissect can list ``/`` on ``slice_data`` and the superblock offset used."""
    sb0 = OPENTLA4_EXT2_MAGIC_OFF - _EXT2_SB_MAGIC_OFF
    candidates = [
        sb0 if sb0 != _EXT2_SB0_OFF else _EXT2_SB0_OFF,
        0,
        _EXT2_SB0_OFF,
    ]
    seen: set[int] = set()
    for off in candidates:
        if off in seen or off < 0:
            continue
        seen.add(off)
        if off + _EXT2_SB_MAGIC_OFF + 2 > len(slice_data):
            continue
        try:
            fs = _ext2_open_dissect(slice_data, off)
            if not stat.S_ISDIR(fs.root.inode.i_mode):
                continue
            names = [n for n in fs.root.listdir() if n not in (".", "..")]
            if names:
                return True, off
        except Exception:
            continue
    return False, None
#endregion


__all__ = [
    "buffer_has_ext2_signature",
    "ext2_slice_has_mountable_root",
]
