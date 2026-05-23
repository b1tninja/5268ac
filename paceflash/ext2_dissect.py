"""Deprecated: use :mod:`boardfs.ext2_dissect`.

``find_ext2_superblock_offsets`` is hypothesis-only (EF53 grep); not used by paceflash CLI/shell.
"""

from boardfs.ext2_dissect import (
    _ext2_io_view,
    _ext2_normalize_superblock_for_dissect,
    _ext2_open_dissect,
    _ext2_sanitize_group_descriptors,
    find_ext2_superblock_offsets,
    list_root_for_block_dev,
    list_root_for_block_dev_with_meta,
    resolve_mountable_ext2_superblock_offset,
)

__all__ = [
    "find_ext2_superblock_offsets",
    "list_root_for_block_dev",
    "list_root_for_block_dev_with_meta",
    "resolve_mountable_ext2_superblock_offset",
]
