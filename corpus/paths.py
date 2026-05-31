"""Standard paths under ``work_corpus/`` (Docker volume mount at ``/work/work_corpus``)."""

from __future__ import annotations

import shutil
from pathlib import Path

WORK_CORPUS_DIRNAME = "work_corpus"

# SQLite index (primary layout).
CORPUS_DB_RELATIVE = Path(WORK_CORPUS_DIRNAME) / "corpus" / "index.sqlite"

# Pre-standardization location (still read when present).
LEGACY_CORPUS_DB_RELATIVE = Path(WORK_CORPUS_DIRNAME) / "corpus_index.sqlite"

PKGSTREAM_BY_VERSION_RELATIVE = Path(WORK_CORPUS_DIRNAME) / "pkgstream_corpus_by_version"
SBOM_DIR_RELATIVE = Path(WORK_CORPUS_DIRNAME) / "sbom"
SECRETS_DIR_RELATIVE = Path(WORK_CORPUS_DIRNAME) / "secrets"
GHIDRA_IMPORT_RELATIVE = Path(WORK_CORPUS_DIRNAME) / "ghidra_import"


def repo_root_from_module() -> Path:
    return Path(__file__).resolve().parents[1]


def work_corpus_dir(repo_root: Path | None = None) -> Path:
    root = repo_root if repo_root is not None else repo_root_from_module()
    return (root / WORK_CORPUS_DIRNAME).resolve()


def preferred_corpus_db_path(repo_root: Path | None = None) -> Path:
    root = repo_root if repo_root is not None else repo_root_from_module()
    return (root / CORPUS_DB_RELATIVE).resolve()


def legacy_corpus_db_path(repo_root: Path | None = None) -> Path:
    root = repo_root if repo_root is not None else repo_root_from_module()
    return (root / LEGACY_CORPUS_DB_RELATIVE).resolve()


def default_corpus_db_path(repo_root: Path | None = None) -> Path:
    """
  Return the corpus SQLite path to use.

  Prefer ``work_corpus/corpus/index.sqlite``. If only the legacy
  ``work_corpus/corpus_index.sqlite`` exists, use that until migrated.
  """
    preferred = preferred_corpus_db_path(repo_root)
    legacy = legacy_corpus_db_path(repo_root)
    if preferred.is_file():
        return preferred
    if legacy.is_file():
        return legacy
    return preferred


def resolve_corpus_db_path(
    repo_root: Path,
    explicit: str | Path | None = None,
) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    return default_corpus_db_path(repo_root)


def ensure_corpus_db_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def migrate_legacy_corpus_db(repo_root: Path | None = None, *, force: bool = False) -> Path:
    """
    Move ``work_corpus/corpus_index.sqlite`` (+ WAL/SHM) to ``work_corpus/corpus/index.sqlite``.

    No-op when the preferred file already exists unless *force* is set.
    """
    preferred = preferred_corpus_db_path(repo_root)
    legacy = legacy_corpus_db_path(repo_root)
    if preferred.is_file() and not force:
        return preferred
    if not legacy.is_file():
        return preferred
    ensure_corpus_db_parent(preferred)
    shutil.move(str(legacy), str(preferred))
    for suffix in ("-wal", "-shm"):
        side = Path(str(legacy) + suffix)
        if side.is_file():
            shutil.move(str(side), str(preferred) + suffix)
    return preferred


def default_sbom_dir(repo_root: Path | None = None) -> Path:
    root = repo_root if repo_root is not None else repo_root_from_module()
    return (root / SBOM_DIR_RELATIVE).resolve()


def default_secrets_dir(repo_root: Path | None = None) -> Path:
    root = repo_root if repo_root is not None else repo_root_from_module()
    return (root / SECRETS_DIR_RELATIVE).resolve()


def default_pkgstream_staging_dir(repo_root: Path | None = None) -> Path:
    root = repo_root if repo_root is not None else repo_root_from_module()
    return (root / PKGSTREAM_BY_VERSION_RELATIVE).resolve()


__all__ = [
    "CORPUS_DB_RELATIVE",
    "GHIDRA_IMPORT_RELATIVE",
    "LEGACY_CORPUS_DB_RELATIVE",
    "PKGSTREAM_BY_VERSION_RELATIVE",
    "SBOM_DIR_RELATIVE",
    "SECRETS_DIR_RELATIVE",
    "WORK_CORPUS_DIRNAME",
    "default_corpus_db_path",
    "default_pkgstream_staging_dir",
    "default_sbom_dir",
    "default_secrets_dir",
    "ensure_corpus_db_parent",
    "legacy_corpus_db_path",
    "migrate_legacy_corpus_db",
    "preferred_corpus_db_path",
    "resolve_corpus_db_path",
    "work_corpus_dir",
]
