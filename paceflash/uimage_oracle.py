"""Pkgstream uImage oracle for stale-inode extent repair on lab NAND dumps."""

from __future__ import annotations

from pathlib import Path

from boardfs.ext2_extent_merge import load_uimage_oracle_from_pkgstream

_REPO = Path(__file__).resolve().parents[1]

DEFAULT_UIMAGE_PKGSTREAM = (
    _REPO
    / "gateway.c01.sbcglobal.net/firmware/00D09E/11.14.1.533857-PROD"
    / "att-5268-11.14.1.533857_prod_lightspeed-install.pkgstream"
)


def resolve_uimage_oracle(pkgstream: Path | str | None = None) -> bytes | None:
    """Load carrier uImage bytes for chunk-oracle extent repair (None if unavailable)."""
    paths: list[Path] = []
    if pkgstream is not None:
        paths.append(Path(pkgstream).expanduser())
    paths.append(DEFAULT_UIMAGE_PKGSTREAM)
    for path in paths:
        if path.is_file():
            try:
                return load_uimage_oracle_from_pkgstream(path)
            except (OSError, ValueError):
                continue
    return None
