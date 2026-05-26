"""
Software ECC helpers ported from OpenTL NAND driver (att-5268 kernel @ KSEG0).

* ``get_word`` / ``opentl_calculate_ecc`` @ ``0x80284358``
* ``opentl_correct_data`` @ ``0x80284740``
* ``ntl_ecc_read`` @ ``0x80288388``
"""

from __future__ import annotations

from typing import Tuple

PAGE_MAP_HOLE = (-1, 0xFFFF)


#region kernel: 0x80284330
def get_word_u32_be(buf: bytes, byte_offset: int) -> int:
    """``get_word``: 4-byte big-endian load (MIPS BE ``memcpy`` + return u32)."""
    return int.from_bytes(buf[byte_offset : byte_offset + 4], "big")


#endregion


#region kernel: 0x80284358
def opentl_calculate_ecc(data: bytes, offset: int = 0) -> tuple[int, int, int]:
    """
    Compute 3-byte syndrome for one 256-byte lane (8×32 B ``get_word`` columns).

    ``data`` must hold at least ``offset + 256`` bytes.
    """
    u15 = 0
    u10 = 0
    u11 = 0
    u12 = 0
    local_40 = 0
    b1 = False
    u14 = 0
    pos = offset
    while True:
        while True:
            u2 = get_word_u32_be(data, pos)
            u3 = get_word_u32_be(data, pos + 4)
            u4 = get_word_u32_be(data, pos + 8)
            u5 = get_word_u32_be(data, pos + 12)
            u6 = get_word_u32_be(data, pos + 16)
            u7 = get_word_u32_be(data, pos + 20)
            u8 = get_word_u32_be(data, pos + 24)
            u9 = get_word_u32_be(data, pos + 28)
            u13 = u3 ^ u2 ^ u4 ^ u5 ^ u6 ^ u7 ^ u8 ^ u9
            u2f = u13 >> 16 ^ u13
            u2f = u2f >> 8 ^ u2f
            u2f = u2f >> 4 ^ u2f
            pos += 32
            u10 ^= u5 ^ u3 ^ u7 ^ u9
            u11 ^= u5 ^ u4 ^ u8 ^ u9
            u12 ^= u7 ^ u6 ^ u8 ^ u9
            u15 ^= u13
            if ((u2f >> 2 ^ u2f) & 3) - 1 < 2:
                break
            u14 += 1
            if u14 == 8:
                break
        if u14 == 8:
            break
        local_40 ^= u14
        b1 = not b1
        u14 += 1
        if u14 == 8:
            break

    u12 = u12 >> 16 ^ u12
    u4w = ((u15 & 0xF0F0F0F0) << 16) ^ (u15 & 0xF0F0F0F0)
    u11 = u11 >> 16 ^ u11
    u3w = ((u15 & 0xAAAAAAAA) << 16) ^ (u15 & 0xAAAAAAAA)
    u12 = u12 << 8 ^ u12
    u4w = u4w >> 8 ^ u4w
    u3w = u3w >> 8 ^ u3w
    u10 = u10 >> 16 ^ u10
    u11 = u11 >> 8 ^ u11
    u12 = u12 >> 4 ^ u12
    u10 = u10 >> 8 ^ u10
    u4w = u4w << 2 ^ u4w
    u2w = u15 >> 24 ^ u15 >> 16
    u3w = u3w >> 4 ^ u3w
    u14w = ((u15 & 0xFF00FF00) >> 16) ^ (u15 & 0xFF00FF00)
    u11 = u11 << 4 ^ u11
    u10 = u10 << 4 ^ u10
    u15w = ((u15 & 0xCCCCCCCC) << 16) ^ (u15 & 0xCCCCCCCC)
    u2w = u2w >> 4 ^ u2w
    u12 = u12 >> 2 ^ u12
    u11 = u11 << 2 ^ u11
    u15w = u15w >> 8 ^ u15w
    u10 = u10 >> 2 ^ u10
    u14w = u14w >> 12 ^ u14w >> 8
    u2w = u2w << 2 ^ u2w
    u14w = u14w >> 2 ^ u14w
    u15w = (u15w << 4 ^ u15w) >> 2
    u11pack = (
        (local_40 & 2) << 12
        | (local_40 & 1) << 11
        | (local_40 & 4) << 13
        | (local_40 & 8) << 14
        | (u4w << 1 ^ u4w) & 0x800000
        | (u3w << 2 ^ u3w) & 0x80000
        | (u12 << 1 ^ u12) & 0x200
        | (u11 << 1 ^ u11) & 0x80
        | (u10 << 1 ^ u10) & 0x20
        | (u2w << 1 ^ u2w) & 8
        | (u14w << 1 ^ u14w) & 2
        | (u15w << 1 ^ u15w) & 0x200000
    )
    u10out = u11pack
    if b1:
        u10out = u11pack ^ 0xAAAAAA
    u10out = ~(u10out >> 1 | u11pack) & 0xFFFFFF
    return (u10out & 0xFF, (u10out >> 8) & 0xFF, (u10out >> 16) & 0xFF)


#endregion


def _syndrome_match(calc: tuple[int, int, int], stored: bytes) -> bool:
    return calc[0] == stored[0] and calc[1] == stored[1] and calc[2] == stored[2]


#region kernel: 0x80284740
def opentl_correct_data(page: bytearray, calc: bytes, stored: bytes) -> int:
    """
    Hamming-decode single-byte correction (``opentl_correct_data`` @ ``0x80284740``).

    ``calc`` / ``stored`` are the 3-byte syndromes from ``opentl_calculate_ecc`` and spare
    (``param_4`` / ``param_5`` in the decompiler — **not** page bytes).

    Returns ``0`` ok, ``1`` corrected, ``2`` hard failure.
    """
    if len(calc) < 3 or len(stored) < 3 or len(page) < 1:
        return 2
    p4 = bytearray(calc[:3])
    p5 = bytearray(stored[:3])
    p5[0] = (~p5[0]) & 0xFF
    p4[0] = (~p4[0]) & 0xFF
    p5[1] = (~p5[1]) & 0xFF
    u8 = p4[0]
    b7 = (~p4[1]) & 0xFF
    p4[1] = b7
    b1 = p5[0]
    u6 = p4[2]
    b2 = (p5[2] ^ p4[2]) & 0xFF
    u3 = (b2 << 16) | ((p5[1] ^ b7) << 8) | (b1 ^ p4[0])
    weight = sum((u3 >> i) & 1 for i in range(24))
    if weight == 1:
        return 2
    if weight == 0:
        return 0
    if weight != 12:
        return 2
    u4 = (u8 ^ (u8 >> 1)) & 1
    if (((b1 ^ (b1 >> 1)) & 1) == u4):
        return 2
    u4mix = (
        (u3 >> 9 & 0x100)
        + (u3 >> 8 & 0x80)
        + (u3 >> 1 & 1)
        + (u3 >> 7 & 0x40)
        + (u3 >> 6 & 0x20)
        + (u3 >> 5 & 0x10)
        + (u3 >> 4 & 8)
        + (u3 >> 3 & 4)
        + (u3 >> 2 & 2)
    )
    u5 = (~u4mix) & 3 | u4mix & 0xFFFFFFFC
    u4b = (b2 >> 4) & 2
    bitpos = (b2 >> 7) * 4 + u4b + ((b2 >> 3) & 1)
    if u5 >= len(page):
        return 2
    page[u5] = (page[u5] ^ (1 << bitpos)) & 0xFF
    return 1


#endregion


#region kernel: 0x80288388
def ntl_ecc_read(page_size: int, bounce: bytearray) -> tuple[int, bool]:
    """
    Verify/correct ECC on ``bounce`` (page data || OOB/meta tail).

    Mutates ``bounce[:page_size]`` in place. Returns ``(status, corrected_occurred)``
    — ``status==0`` success, ``1`` hard fail.
    """
    if page_size not in (512, 2048):
        raise ValueError(f"unsupported page_size {page_size}")
    if len(bounce) < page_size + 64:
        raise ValueError("bounce must be page_size + spare/meta bytes")
    pb = bounce[page_size : page_size + 64]
    slices = page_size >> 9
    corrected = False
    ecc_stream = page_size + 0x12
    page_off = 0
    for idx in range(slices):
        half0 = page_off
        half1 = page_off + 0x100
        calc_lo = opentl_calculate_ecc(bounce, half0)
        calc_hi = opentl_calculate_ecc(bounce, half1)
        if idx == 0:
            if page_size == 0x200:
                # ``local_38`` / ``local_35`` stack layout @ ``0x80288388`` (512 B page).
                stored_lo = bytes([pb[0], pb[1], pb[2]])
                stored_hi = bytes([pb[3], pb[6], pb[7]])
            else:
                # Large page: lo syndrome ``&local_38`` → ``pb[0x16,0x17,2]``; hi ``&local_35`` → ``pb[3,6,7]``.
                stored_lo = bytes([pb[0x16], pb[0x17], pb[2]])
                stored_hi = bytes([pb[3], pb[6], pb[7]])
        else:
            chunk = bounce[ecc_stream : ecc_stream + 6]
            stored_lo = bytes(chunk[0:3])
            stored_hi = bytes(chunk[3:6])
            ecc_stream += 6
        slice_mut = bytearray(bounce[half0 : half0 + 0x200])
        if not _syndrome_match(calc_lo, stored_lo[:3]):
            r = opentl_correct_data(slice_mut, bytes(calc_lo), stored_lo[:3])
            if r == 2:
                return 1, corrected
            if r == 1:
                corrected = True
        if not _syndrome_match(calc_hi, stored_hi[:3]):
            r = opentl_correct_data(slice_mut, bytes(calc_hi), stored_hi[:3])
            if r == 2:
                return 1, corrected
            if r == 1:
                corrected = True
        bounce[half0 : half0 + 0x200] = slice_mut
        page_off += 0x200
    return 0, corrected


#endregion


#region kernel: 0x80288388 write path (inverse of ntl_ecc_read)
def _pack_large_page_ecc_syndromes(
    bounce: bytearray,
    *,
    page_size: int,
    spare_base: int,
    syndromes: list[tuple[tuple[int, int, int], tuple[int, int, int]]],
) -> None:
    """
    Pack precomputed slice syndromes into the large-page spare ECC layout.

    Slice 0 uses scattered lanes ``[0x16,0x17,2]`` / ``[3,6,7]``. Slice 1 starts at
    spare ``0x12`` and shares bytes ``0x16`` / ``0x17`` with slice-0 lo[0:2].
    """
    s0_lo, s0_hi = syndromes[0]
    s1_lo, s1_hi = syndromes[1]
    bounce[spare_base + 2] = s0_lo[2]
    bounce[spare_base + 3] = s0_hi[0]
    bounce[spare_base + 6] = s0_hi[1]
    bounce[spare_base + 7] = s0_hi[2]
    bounce[spare_base + 0x12] = s1_lo[0]
    bounce[spare_base + 0x13] = s1_lo[1]
    bounce[spare_base + 0x14] = s1_lo[2]
    bounce[spare_base + 0x15] = s1_hi[0]
    bounce[spare_base + 0x16] = s0_lo[0]
    bounce[spare_base + 0x17] = s0_lo[1]
    for idx in range(2, len(syndromes)):
        lo, hi = syndromes[idx]
        off = spare_base + 0x18 + 6 * (idx - 2)
        bounce[off : off + 3] = bytes(lo)
        bounce[off + 3 : off + 6] = bytes(hi)


def ntl_ecc_write(page_size: int, bounce: bytearray) -> None:
    """
    Store ECC syndromes for ``bounce`` (page data || 64-byte spare).

    Mirrors ``ntl_ecc_read`` placement: first 512 B slice in spare tail lanes,
    further slices at ``bounce[page_size + 0x12 + 6*(idx-1)]``.
    """
    if page_size not in (512, 2048):
        raise ValueError(f"unsupported page_size {page_size}")
    if len(bounce) < page_size + 64:
        raise ValueError("bounce must be page_size + spare/meta bytes")
    spare_base = page_size
    slices = page_size >> 9
    if page_size == 0x200:
        half0 = 0
        half1 = 0x100
        calc_lo = opentl_calculate_ecc(bounce, half0)
        calc_hi = opentl_calculate_ecc(bounce, half1)
        bounce[spare_base + 0] = calc_lo[0]
        bounce[spare_base + 1] = calc_lo[1]
        bounce[spare_base + 2] = calc_lo[2]
        bounce[spare_base + 3] = calc_hi[0]
        bounce[spare_base + 6] = calc_hi[1]
        bounce[spare_base + 7] = calc_hi[2]
        return

    syndromes: list[tuple[tuple[int, int, int], tuple[int, int, int]]] = []
    for idx in range(slices):
        half0 = idx * 0x200
        calc_lo = opentl_calculate_ecc(bounce, half0)
        calc_hi = opentl_calculate_ecc(bounce, half0 + 0x100)
        syndromes.append((calc_lo, calc_hi))
    _pack_large_page_ecc_syndromes(
        bounce, page_size=page_size, spare_base=spare_base, syndromes=syndromes
    )


#endregion


#region kernel: 0x80288600
def verify_read_phy_page_bounce(
    bounce: bytearray,
    *,
    page_size: int = 2048,
    pages_per_erase: int = 64,
    trailer_spare_index: int | None = None,
) -> tuple[bytes | None, bool, bool]:
    """
    Offline ``ntl_verify_read_phy_page``: spare xsum gate + ``ntl_ecc_read`` when state ``0x24``.

    ``bounce`` layout: ``[0:page_size]`` data, ``[page_size:page_size+64]`` spare.

    Returns ``(page_bytes, corrected, ecc_hard_fail)``. Page bytes are still returned when
    ``ecc_hard_fail`` (kernel ``ntl_verify_read_phy_page`` returns success after ECC printk).
    """
    from opentl.spare_layout import map_page_state, spare_read_verify_ok, xsum_matches

    spare = bytes(bounce[page_size : page_size + 64])
    state = map_page_state(spare[4])
    if state == 0xFF:
        return None, False, False
    trailer = pages_per_erase - 1 if trailer_spare_index is None else trailer_spare_index
    corrected = False
    ecc_hard_fail = False
    if bounce[page_size + trailer] == 0xFF and spare_read_verify_ok(
        spare, large_page=True, pages_per_erase=pages_per_erase
    ):
        bounce[page_size + 4] = state & 0xFF
        if state == 0x24:
            st, corrected = ntl_ecc_read(page_size, bounce)
            if st != 0:
                corrected = False
                ecc_hard_fail = True
    elif state in (0, 0x24):
        bounce[page_size + 4] = state & 0xFF
    return bytes(bounce[:page_size]), corrected, ecc_hard_fail


#endregion
