"""
Doubly-linked physical-block chains used by OpenTL mount / allocator.

Mirrors ``tl_init_chain`` seeding (``opentl_kernel_ghidra.md`` §11): **0x38**-byte
header with **uint16** tag **0xD00D** at offset **0x20** (bytes **0x0D, 0xD0**
in LE order), tail pointers initialized to **0xffffffff**.

This module provides **Python-level** chain primitives for tests and light-weight
simulation — not a byte-for-byte reproduction of every ``tl_*`` helper.
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


class ChainPool:
    """tl_add_chain / tl_delete_chain style operations on phys indices."""

    def __init__(self, raw_blocks: int) -> None:
        self.raw_blocks = raw_blocks
        self.links: dict[int, ChainLink] = {}

    def tl_init_chain(self, header: ChainHeader | None = None) -> bytes:
        """Return packed header bytes (for tests)."""
        return (header or ChainHeader()).pack()

    def contains(self, phys: int) -> bool:
        return phys in self.links

    def tl_chain_in(self, phys: int, prev: int, next_: int, *, flags: int = 0) -> None:
        self.links[phys] = ChainLink(prev=prev, next=next_, flags=flags)

    def tl_follow(self, head: int) -> list[int]:
        """Walk ``next`` pointers until -1 / missing."""
        out: list[int] = []
        p = head
        seen: set[int] = set()
        while p != -1 and p not in seen:
            seen.add(p)
            out.append(p)
            link = self.links.get(p)
            if link is None:
                break
            p = link.next
        return out

    def tl_add_chain(self, head_list: int, phys: int, after: int | None = None) -> None:
        """
        Insert **phys** into a simple chain rooted at conceptual **head_list**
        (we only track explicit links dict — caller maintains head index).
        """
        if after is None:
            self.links[phys] = ChainLink(prev=-1, next=-1)
            return
        dest = self.links.get(after)
        nxt = -1 if dest is None else dest.next
        self.links[phys] = ChainLink(prev=after, next=nxt)
        if dest is not None:
            dest.next = phys
        if nxt != -1 and nxt in self.links:
            self.links[nxt].prev = phys

    def tl_delete_chain(self, phys: int) -> None:
        lk = self.links.pop(phys, None)
        if lk is None:
            return
        if lk.prev != -1 and lk.prev in self.links:
            self.links[lk.prev].next = lk.next
        if lk.next != -1 and lk.next in self.links:
            self.links[lk.next].prev = lk.prev
