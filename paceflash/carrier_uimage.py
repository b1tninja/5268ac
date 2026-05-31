"""Load carrier ``sys1/uImage`` bytes from a ``.pkgstream`` for lab comparisons."""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]

DEFAULT_UIMAGE_PKGSTREAM = (
    _REPO
    / "gateway.c01.sbcglobal.net/firmware/00D09E/11.14.1.533857-PROD"
    / "att-5268-11.14.1.533857_prod_lightspeed-install.pkgstream"
)


def load_carrier_uimage(pkgstream: Path | str | None = None) -> bytes | None:
    """Extract ``sys1/uImage`` FILE payload bytes from a carrier ``.pkgstream``."""
    from lib2spy.native_pkgstream import load_pkgstream_bytes, try_decompress_bzip2_prefix
    from lib2spy.pkgstream_verify import verify_pkgstream

    paths: list[Path] = []
    if pkgstream is not None:
        paths.append(Path(pkgstream).expanduser())
    paths.append(DEFAULT_UIMAGE_PKGSTREAM)
    for path in paths:
        if not path.is_file():
            continue
        try:
            body, _ = try_decompress_bzip2_prefix(load_pkgstream_bytes(path))
            for rec in verify_pkgstream(path).file_records:
                if rec.path.rsplit("/", 1)[-1] == "uImage":
                    return body[rec.payload_offset : rec.payload_end]
        except (OSError, ValueError):
            continue
    return None
