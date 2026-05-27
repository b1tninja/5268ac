"""
``corpus`` — SQLite-backed index and grep over dissected SquashFS trees / ELF symbols.

CLI: ``python -m corpus`` — index, search, and pkgstream-root ingest.
"""

from __future__ import annotations

from corpus.artifacts import CorpusArtifact
from corpus.index_db import (
    build_index_from_flash,
    build_index_from_pkgstream,
    build_index_for_image,
    build_index_for_squashfs_bytes,
    connect_db,
    index_artifact,
    search_index,
)

__all__ = [
    "CorpusArtifact",
    "build_index_from_flash",
    "build_index_from_pkgstream",
    "build_index_for_image",
    "build_index_for_squashfs_bytes",
    "connect_db",
    "index_artifact",
    "search_index",
]
