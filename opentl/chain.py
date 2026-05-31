"""
Doubly-linked physical-block chains used by OpenTL mount / allocator.

Kernel references (see ``reference/opentl_kernel_ghidra.md`` §11):

- ``tl_init_chain`` seeds a pool header and a per-physical-unit record table.
- ``tl_add_chain`` / ``tl_delete_chain`` splice/unlink **physical unit indices** into a pool.
- The pool is guarded by a **LE16** magic ``0xD00D`` and tracks **head**, **tail**, **count**.

This module provides a kernel-shaped in-memory model intended for offline mount replay.
It does **not** attempt to reproduce printk/debug verbosity or every ancillary helper.
"""

from __future__ import annotations

from dataclasses import dataclass, field

CHAIN_HEADER_BYTES = 0x38
CHAIN_MAGIC_LE16 = 0xD00D  # bytes b'\\x0d\\xd0' at offset 0x20 LE


@dataclass
class ChainHeader:
    """In-memory image of the first 0x38 bytes (tag string + magic + book-keeping)."""

    tag: str = "bad_links"
    forward_ptr: int = 0xFFFFFFFF
    _reserved_tail: bytes = field(default_factory=lambda: b"\xff" * 8)

    def pack(self) -> bytes:
        buf = bytearray(CHAIN_HEADER_BYTES)
        tag_b = self.tag.encode("ascii", errors="replace") + b"\x00"
        if len(tag_b) > 0x20:
            tag_b = tag_b[:0x20]
        buf[0 : len(tag_b)] = tag_b
        buf[0x20:0x22] = CHAIN_MAGIC_LE16.to_bytes(2, "little")
        buf[0x2C:0x34] = self.forward_ptr.to_bytes(4, "little") + self._reserved_tail[:4]
        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> ChainHeader:
        if len(data) < CHAIN_HEADER_BYTES:
            raise ValueError("chain header too short")
        magic = int.from_bytes(data[0x20:0x22], "little")
        if magic != CHAIN_MAGIC_LE16:
            raise ValueError(f"bad chain magic {magic:#x}")
        nul = data.find(b"\x00", 0, 0x20)
        tag = data[0:nul].decode("ascii", errors="replace") if nul != -1 else ""
        fwd = int.from_bytes(data[0x2C:0x30], "little")
        return cls(tag=tag, forward_ptr=fwd, _reserved_tail=data[0x30:0x38])


@dataclass
class PhysRemapSlot:
    """Placeholder for kernel **16-byte** virt/phys slot (§11); use :class:`ChainLink` for edits."""

    phys: int
    prev_idx: int = -1
    next_idx: int = -1
    flags: int = 0


@dataclass
class ChainLink:
    """One physical erase-block slot in the remap table (16-byte records in-kernel)."""

    prev: int  # phys index or -1
    next: int
    #: Intended for ``ntl_verify_chain_seqnum`` / mount-order parity (not wired from ``parse_spare`` yet).
    seq_or_aux: int = 0
    flags: int = 0


class ChainError(ValueError):
    pass


@dataclass
class ChainPoolHeader:
    """
    Kernel-shaped pool header metadata.

    Indices use ``-1`` for "none" (kernel uses ``0xffffffff``); this keeps Python ergonomic.
    """

    magic: int = CHAIN_MAGIC_LE16
    head: int = -1
    tail: int = -1
    count: int = 0
    max_phys: int = -1  # inclusive upper bound for valid phys indices


class ChainPool:
    """Kernel-shaped pool of physical indices with tl_add_chain/tl_delete_chain semantics."""

    def __init__(self, raw_blocks: int) -> None:
        if raw_blocks <= 0:
            raise ValueError("raw_blocks must be positive")
        self.raw_blocks = int(raw_blocks)
        self.hdr = ChainPoolHeader(max_phys=self.raw_blocks - 1)
        self.links: dict[int, ChainLink] = {}

    def tl_init_chain(self, header: ChainHeader | None = None) -> bytes:
        """Return packed header bytes (for tests)."""
        return (header or ChainHeader()).pack()

    def contains(self, phys: int) -> bool:
        return phys in self.links

    def _check_magic(self) -> None:
        if self.hdr.magic != CHAIN_MAGIC_LE16:
            raise ChainError(f"bad chain magic {self.hdr.magic:#x}")

    def _check_phys(self, phys: int) -> int:
        self._check_magic()
        p = int(phys)
        if p < 0 or p > self.hdr.max_phys:
            raise ChainError(f"phys {p} out of range (max {self.hdr.max_phys})")
        return p

    def tl_in_chain(self, phys: int) -> bool:
        """Kernel `tl_in_chain`: membership test."""
        try:
            p = self._check_phys(phys)
        except ChainError:
            return False
        return p in self.links

    def tl_chain_in(self, phys: int, prev: int, next_: int, *, flags: int = 0) -> None:
        p = self._check_phys(phys)
        self.links[p] = ChainLink(prev=int(prev), next=int(next_), flags=int(flags))

    def tl_follow(self, head: int) -> list[int]:
        """Walk ``next`` pointers until -1 / missing."""
        out: list[int] = []
        p = int(head)
        seen: set[int] = set()
        while p != -1 and p not in seen:
            seen.add(p)
            out.append(p)
            link = self.links.get(p)
            if link is None:
                break
            p = link.next
        return out

    def tl_add_chain(self, pos: int, phys: int) -> None:
        """
        Kernel `tl_add_chain(pool, phys, pos)` where pos is 0=head, 1=tail.
        """
        p = self._check_phys(phys)
        if self.tl_in_chain(p):
            raise ChainError(f"phys {p} already in chain")
        if pos not in (0, 1):
            raise ChainError(f"unknown_pos {pos}")

        if self.hdr.count == 0:
            self.links[p] = ChainLink(prev=-1, next=-1)
            self.hdr.head = self.hdr.tail = p
            self.hdr.count = 1
            return

        if pos == 0:
            old_head = self.hdr.head
            self.links[p] = ChainLink(prev=-1, next=old_head)
            if old_head in self.links:
                self.links[old_head].prev = p
            self.hdr.head = p
            self.hdr.count += 1
            return

        old_tail = self.hdr.tail
        self.links[p] = ChainLink(prev=old_tail, next=-1)
        if old_tail in self.links:
            self.links[old_tail].next = p
        self.hdr.tail = p
        self.hdr.count += 1

    def tl_delete_chain(self, phys: int) -> None:
        p = self._check_phys(phys)
        if not self.tl_in_chain(p):
            raise ChainError(f"phys {p} not in chain")
        lk = self.links.pop(p)

        if self.hdr.count == 1:
            self.hdr.head = -1
            self.hdr.tail = -1
            self.hdr.count = 0
            return

        if lk.prev != -1 and lk.prev in self.links:
            self.links[lk.prev].next = lk.next
        if lk.next != -1 and lk.next in self.links:
            self.links[lk.next].prev = lk.prev
        if self.hdr.head == p:
            self.hdr.head = lk.next
        if self.hdr.tail == p:
            self.hdr.tail = lk.prev
        self.hdr.count -= 1
