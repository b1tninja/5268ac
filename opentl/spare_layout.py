"""
Decode 64-byte NAND spare/OOB for OpenTL large-page (2048 B data) geometry.

Layout follows ``opentl_kernel_ghidra.md`` §7.4b / §7.4a (``ntl_prepare_wspare``,
``ntl_compute_spare_xsum``). Byte indices are **absolute** within the 64-byte spare.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Sequence

# Kernel branch uses *(ctx+0x10) != 0x200 for "large page" spare extensions.
PAGE_SMALL = 0x200

# When spare[9:11] and spare[16:18] are still erased (0xFF), phys_u32() == 0xFFFFFFFF.
# Same pattern for virt at 11–12 and 18–19. This is **not** a real block index.
SPARE_U32_ERASED_SENTINEL = 0xFFFFFFFF


#region kernel: 0x8028c5d0
# also ntl_compute_spare_xsum:0x80288560 (§7.4a–7.4b opentl_kernel_ghidra.md)
@dataclass(frozen=True)
class SpareRecord:
    """Parsed spare view for BBM / mount simulation."""

    raw: bytes

    def __post_init__(self) -> None:
        if len(self.raw) != 64:
            raise ValueError("spare must be 64 bytes")

    @property
    def status(self) -> int:
        """Normalized status nibble area — spare[4] in docs (may be param_7 write path)."""
        return self.raw[4]

    @property
    def flags_byte8(self) -> int:
        """Merged flags written to spare[8] on programming path (§7.4b)."""
        return self.raw[8]

    @property
    def mirror_duplicate_chain_flag(self) -> bool:
        """
        True when **bit 4** of **spare[8]** is set — duplicate/mirror chain hop
        (**``ntl_put_chain_in_array``** tests ``(byte & 4)``, Ghidra on ``puVar9`` spare buffer).

        Offline tie-break (**``chain_v1``**) prefers observations **without** this bit when
        resolving multiple ``(phys_block, page)`` rows that decode to the same virt id.
        """
        return (self.flags_byte8 & 4) != 0

    @property
    def page_in_block(self) -> int:
        return self.raw[0xD]

    def phys_low16(self) -> int:
        return struct.unpack_from("<H", self.raw, 9)[0]

    def virt_low16(self) -> int:
        return struct.unpack_from("<H", self.raw, 11)[0]

    def phys_u32(self, *, large_page: bool = True) -> int:
        """
        Phys id as laid out by ``ntl_prepare_wspare`` (**§7.4b**): low **LE16** @ **9–10** plus
        **LE16** @ **16–17** as the high half.

        When those four bytes are still **erased** (**0xFF**), the value is **0xFFFFFFFF**
        (:data:`SPARE_U32_ERASED_SENTINEL`) — treat as **unassigned**, not a physical index.

        **Not** always identical to **chain-step** parsing in ``ntl_put_chain_in_array`` mode **2**,
        which ORs **single bytes** ``raw[16]<<16 | raw[17]<<24``; see ``opentl.spare_chain_replay``.
        """
        lo = self.phys_low16()
        if not large_page:
            return lo & 0xFFFF
        hi = struct.unpack_from("<H", self.raw, 16)[0]
        return (hi << 16) | lo

    def virt_u32(self, *, large_page: bool = True) -> int:
        """
        Virtual block id: low **LE16** @ **11–12**, high **LE16** @ **18–19** (large page).

        When those four bytes are still **erased** (**0xFF**), the value is **0xFFFFFFFF**
        (:data:`SPARE_U32_ERASED_SENTINEL`) — not a valid virtual index.
        """
        lo = self.virt_low16()
        if not large_page:
            return lo & 0xFFFF
        hi = struct.unpack_from("<H", self.raw, 18)[0]
        return (hi << 16) | lo

    def phys_u32_meaningful(self, *, large_page: bool = True) -> bool:
        """True when ``phys_u32()`` is not the erased pattern and the row is not all ``0xFF``."""
        if self.is_erased_like():
            return False
        return self.phys_u32(large_page=large_page) != SPARE_U32_ERASED_SENTINEL

    def virt_u32_meaningful(self, *, large_page: bool = True) -> bool:
        """True when ``virt_u32()`` is usable for decode (not erased / unset sentinels)."""
        if self.is_erased_like():
            return False
        v = self.virt_u32(large_page=large_page)
        if v == 0:
            return False
        return v != SPARE_U32_ERASED_SENTINEL

    def xsum_stored(self) -> int:
        """Checksum byte at spare[0xf] (see §7.4a — stored vs computed at 0xf)."""
        return self.raw[0xF]

    #region kernel_adjacent SpareRecord_erased_bootcode_heuristics
    def is_erased_like(self) -> bool:
        """Heuristic: factory-erased spare often reads 0xFF across user fields."""
        return self.raw == b"\xff" * 64

    def has_bootcode_marker(self) -> bool:
        """BCMNAND early-block vendor tag ``BootCode`` (see ``fwupgrade.txt`` ``OOB[n/…]`` lines)."""
        return b"BootCode" in self.raw

    #endregion

    def kernel_tagged_like(self) -> bool:
        """
        Read-side markers ``ntl_find_phy`` accepts after ``ntl_map_page_state`` normalization:
        **NUL** or **``$``** (**0x24**) at spare[**4**] enable virtual-block decode (**§7.3**).
        """
        return self.status in (0, 0x24)


#endregion


def parse_spare(spare64: bytes | Sequence[int]) -> SpareRecord:
    """Parse **64** raw spare bytes into :class:`SpareRecord`."""
    if isinstance(spare64, (bytes, bytearray, memoryview)):
        b = bytes(spare64)
    else:
        b = bytes(spare64)
    return SpareRecord(b)


#region kernel: 0x80288560
# ntl_compute_spare_xsum (§7.4a)
def compute_spare_xsum(spare64: bytes | Sequence[int], *, large_page: bool = True) -> int:
    """
    mirrors ``ntl_compute_spare_xsum`` (§7.4a): int8 wrapping sum; compare to ``spare[0xf]``.
    """
    s = bytes(spare64)
    if len(s) != 64:
        raise ValueError("spare must be 64 bytes")

    partial = _i8(s[9]) + _i8(s[10]) + _i8(s[11]) + _i8(s[12])
    if large_page:
        partial += _i8(s[16]) + _i8(s[17]) + _i8(s[18]) + _i8(s[19])

    total = _i8(s[8]) + _i8(s[0xD]) + _i8(s[0xE]) + partial
    return total & 0xFF


#endregion


def _i8(x: int) -> int:
    """Interpret byte as signed int8."""
    x &= 0xFF
    if x >= 0x80:
        return x - 0x100
    return x


def xsum_matches(spare64: bytes | Sequence[int], *, large_page: bool = True) -> bool:
    s = bytes(spare64)
    if len(s) != 64:
        return False
    return (s[0xF] & 0xFF) == compute_spare_xsum(s, large_page=large_page)


#region kernel: 0x802882a4
# ntl_map_page_state — Hamming vote on spare[4] before read-side tag checks
def map_page_state(page_state_byte: int) -> int:
    """
    Normalize spare status byte (``ntl_map_page_state`` @ ``0x802882a4``).

    Returns ``0x00`` valid, ``0x24`` in-chain, ``0xb6`` deleted, or ``0xff`` free/erased.
    """
    u = page_state_byte & 0xFF
    i_ff = i_24 = i_b6 = i_00 = 0
    for bit in range(8):
        mask = 1 << bit
        if (mask & ~u) != 0:
            i_ff += 1
        if (mask & u) != 0:
            i_00 += 1
        if (mask & (u ^ 0x24)) != 0:
            i_24 += 1
        if (mask & (u ^ 0xB6)) != 0:
            i_b6 += 1
    if i_ff < i_00:
        return 0xFF
    if i_24 < i_b6:
        if i_24 <= i_00:
            return 0x24
        return 0
    if i_b6 <= i_00:
        return 0xB6
    return 0


#endregion


#region kernel: 0x80288750
# ntl_read_verify_phy_spare — checksum gate before data read (§7.1)
def spare_read_verify_ok(
    spare64: bytes,
    *,
    large_page: bool = True,
    pages_per_erase: int = 64,
) -> bool:
    """
    ``ntl_read_verify_phy_spare`` acceptance (checksum + state normalization).

    When mapped state is not ``0xff`` and the per-erase trailer byte is still erased (``0xff``),
    require :func:`xsum_matches`.
    """
    if len(spare64) != 64:
        return False
    state = map_page_state(spare64[4])
    trailer_idx = min(max(pages_per_erase, 1), 64) - 1
    if state != 0xFF and spare64[trailer_idx] == 0xFF:
        if not xsum_matches(spare64, large_page=large_page):
            return False
    return True


#endregion


#region kernel: 0x80288600
# ntl_verify_read_phy_page spare path only — ECC @ 0x80288388 not implemented offline
def spare_page_accept_for_read(
    spare64: bytes,
    *,
    expected_vblk: int | None = None,
    large_page: bool = True,
    pages_per_erase: int = 64,
) -> bool:
    """
    ``ntl_verify_read_phy_page`` spare gate after ``ntl_map_page_state``.

    Accept when normalized state is ``0x00`` or ``0x24`` and read-verify passes; optional
    ``expected_vblk`` must match :meth:`SpareRecord.virt_u32` when the tag is kernel-like.
    """
    if not spare_read_verify_ok(
        spare64, large_page=large_page, pages_per_erase=pages_per_erase
    ):
        return False
    state = map_page_state(spare64[4])
    if state not in (0, 0x24):
        return False
    sr = parse_spare(spare64)
    if expected_vblk is not None and sr.kernel_tagged_like() and sr.virt_u32_meaningful():
        if sr.virt_u32(large_page=large_page) != (expected_vblk & 0xFFFFFFFF):
            return False
    return True


#endregion
