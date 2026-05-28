"""
``corpus`` — SQLite-backed index and grep over dissected SquashFS trees / ELF symbols.

CLI: ``python -m corpus`` — index, search, and pkgstream-root ingest.
"""

from __future__ import annotations

from corpus.artifacts import CorpusArtifact
from corpus.paths import (
    CORPUS_DB_RELATIVE,
    default_corpus_db_path,
    default_pkgstream_staging_dir,
    default_sbom_dir,
)
from corpus.buildroot import (
    build_index_for_buildroot,
    diff_collection_vs_buildroot,
    format_buildroot_image_key,
    list_buildroot_profiles,
    lookup_path_origin,
)
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
    "build_index_for_buildroot",
    "diff_collection_vs_buildroot",
    "format_buildroot_image_key",
    "list_buildroot_profiles",
    "lookup_path_origin",
    "CORPUS_DB_RELATIVE",
    "CorpusArtifact",
    "default_corpus_db_path",
    "default_pkgstream_staging_dir",
    "default_sbom_dir",
    "build_index_from_flash",
    "build_index_from_pkgstream",
    "build_index_for_image",
    "build_index_for_squashfs_bytes",
    "connect_db",
    "index_artifact",
    "search_index",
]
