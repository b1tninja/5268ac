"""
``corpus`` — SQLite-backed index and grep over dissected SquashFS trees / ELF symbols.

CLI: ``python -m corpus`` — index, search, and pkgstream-root ingest.
"""

from __future__ import annotations

from corpus.artifacts import CorpusArtifact
from corpus.client import CorpusClient, FindResult, GrepHit
from corpus.paths import (
    CORPUS_DB_RELATIVE,
    default_corpus_db_path,
    default_pkgstream_staging_dir,
    default_sbom_dir,
)
from corpus.buildroot import (
    build_index_for_buildroot,
    buildroot_versions_report,
    diff_collection_vs_buildroot,
    format_buildroot_image_key,
    list_buildroot_profiles,
    list_collection_details,
    list_firmware_collections,
    lookup_path_origin,
)
from corpus.index_db import (
    build_index_from_flash,
    build_index_from_pkgstream,
    build_index_for_image,
    build_index_for_squashfs_bytes,
    connect_db,
    flash_collection_slug,
    index_artifact,
    resolve_flash_collection_slug,
    search_index,
)

__all__ = [
    "CorpusClient",
    "FindResult",
    "GrepHit",
    "build_index_for_buildroot",
    "buildroot_versions_report",
    "diff_collection_vs_buildroot",
    "format_buildroot_image_key",
    "list_buildroot_profiles",
    "list_collection_details",
    "list_firmware_collections",
    "lookup_path_origin",
    "CORPUS_DB_RELATIVE",
    "CorpusArtifact",
    "default_corpus_db_path",
    "default_pkgstream_staging_dir",
    "default_sbom_dir",
    "build_index_from_flash",
    "build_index_from_pkgstream",
    "flash_collection_slug",
    "resolve_flash_collection_slug",
    "build_index_for_image",
    "build_index_for_squashfs_bytes",
    "connect_db",
    "index_artifact",
    "search_index",
]
