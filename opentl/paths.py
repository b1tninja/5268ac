"""Canonical repo paths and generated artifact root (default ``output/``)."""

from __future__ import annotations

import os
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]


def repo_root() -> Path:
    return _REPO_ROOT


def output_dir() -> Path:
    """
    Root directory for tool-generated artifacts.

    Override with environment variable ``OUTPUT_DIR`` (absolute path, or relative to
    the current working directory).
    """
    raw = os.environ.get("OUTPUT_DIR", "").strip()
    if raw:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = (Path.cwd() / p).resolve()
        else:
            p = p.resolve()
        return p
    return _REPO_ROOT / "output"


# Resolved once at import; set OUTPUT_DIR before importing opentl.paths if tests need isolation.
OUTPUT_DIR: Path = output_dir()


def find_carved_tlpart(repo_root: Path, *, deinterleaved_work: bool = False) -> Path | None:
    """
    Return the first existing ``tlpart.bin`` from canonical locations.

    Prefers :data:`OUTPUT_DIR` under ``carved_flash/``, then legacy ``re_artifacts/carved_flash/``.
    """
    if deinterleaved_work:
        candidates = (
            OUTPUT_DIR / "carved_flash" / "carve_deinterleaved" / "work" / "tlpart.bin",
            repo_root / "re_artifacts" / "carved_flash" / "carve_deinterleaved" / "work" / "tlpart.bin",
        )
    else:
        # Prefer carved_flash ``work/tlpart.bin`` layout, then flat ``tlpart.bin`` (e.g. pace_flash_carve).
        candidates = (
            OUTPUT_DIR / "carved_flash" / "work" / "tlpart.bin",
            OUTPUT_DIR / "carved_flash" / "tlpart.bin",
            repo_root / "re_artifacts" / "carved_flash" / "work" / "tlpart.bin",
            repo_root / "re_artifacts" / "carved_flash" / "tlpart.bin",
        )
    for p in candidates:
        if p.is_file():
            return p
    return None
