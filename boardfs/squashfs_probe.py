"""SquashFS superblock magic probe on a :class:`~boardfs.block.BlockSlice` (stdlib only)."""

from __future__ import annotations

from pathlib import Path

from boardfs.block import AssembledBlockDev, BlockDev, BlockSlice

SQUASHFS_MAGIC_LE = b"hsqs"


def peek_squashfs_superblock_magic(dev: BlockSlice) -> bool:
    """
    Return True if ``dev`` looks like it contains SquashFS.

    For normal :class:`~boardfs.block.BlockDev` slices this is **only** magic ``hsqs`` at
    the slice start (offset 0 in the slice).

    For :class:`~boardfs.block.AssembledBlockDev` (BBM-assembled virt slices), only magic at
    offset **0** counts — embedded ``hsqs`` inside ext2 file payloads is not partition-level SquashFS.
    """
    if isinstance(dev, AssembledBlockDev):
        data = dev.read_slice()
        return len(data) >= 4 and data[:4] == SQUASHFS_MAGIC_LE
    if isinstance(dev, BlockDev):
        b = dev.backing
        off = dev.offset
        if isinstance(b, Path):
            with b.open("rb") as f:
                f.seek(off)
                head = f.read(4)
        else:
            mv = memoryview(b)
            if off >= len(b) or off < 0:
                return False
            head = bytes(mv[off : min(len(b), off + 4)])
        return head == SQUASHFS_MAGIC_LE
    raise TypeError(f"unsupported block slice type: {type(dev)!r}")
