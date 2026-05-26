"""
Export ``pem_certificate`` carve artifacts as normalized ``.pem`` files.

Primary carves may already use a ``.pem`` extension.
Older trees used ``.bin``. Some slices contain
multiple PEM blocks (chain bundles). This module splits on ``BEGIN … END`` pairs and
writes one ``.pem`` per block.

For **carrier TLV / PKCS#7** certificates inside an ``.pkgstream``, use::

    python -m lib2spy.pkgstream FILE.pkgstream --extract-trust-store DIR

instead.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Match any PEM armor line (certificate, CSR, key, …); split generically.
_PEM_ARMOR = re.compile(
    rb"-----BEGIN [A-Z0-9 ]+-----\r?\n.*?\r?\n-----END [A-Z0-9 ]+-----",
    re.DOTALL,
)


def split_pem_blocks(data: bytes) -> List[bytes]:
    """Return non-overlapping PEM blocks (bytes including armor lines)."""
    out: List[bytes] = []
    for m in _PEM_ARMOR.finditer(data):
        blk = m.group(0)
        if blk.strip():
            out.append(blk if blk.endswith(b"\n") else blk + b"\n")
    return out


def _stem_pem_path(src: Path, index: int | None, out_dir: Path) -> Path:
    stem = src.stem
    if index is None:
        return out_dir / f"{stem}.pem"
    return out_dir / f"{stem}_{index:02d}.pem"


def export_carved_pem_bins(
    carved_dir: Path,
    out_dir: Path,
    *,
    glob_pattern: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Find PEM carve inputs under ``carved_dir``, split PEM blocks, write ``.pem`` files.

    When ``glob_pattern`` is ``None``, matches ``*pem_certificate*.pem`` and
    ``*pem_certificate*.bin``. Otherwise uses that single ``rglob`` pattern.

    Returns a manifest dict suitable for JSON (paths as strings).
    """
    carved_dir = carved_dir.resolve()
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    written: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    if glob_pattern is None:
        patterns = ("*pem_certificate*.pem", "*pem_certificate*.bin")
        paths = sorted(
            {p for pat in patterns for p in carved_dir.rglob(pat) if p.is_file()}
        )
        glob_report = list(patterns)
    else:
        paths = sorted(p for p in carved_dir.rglob(glob_pattern) if p.is_file())
        glob_report = [glob_pattern]
    for src in paths:
        if not src.is_file():
            continue
        try:
            raw = src.read_bytes()
        except OSError as e:
            skipped.append({"path": str(src), "reason": str(e)})
            continue

        blocks = split_pem_blocks(raw)
        if not blocks:
            # Whole file might be PEM without regex match (wrong line endings); try raw BEGIN scan
            if b"-----BEGIN " in raw and b"-----END " in raw:
                blocks = [raw] if raw.strip().startswith(b"-----BEGIN ") else []
            if not blocks:
                skipped.append(
                    {"path": str(src), "reason": "no PEM armor found", "size": len(raw)}
                )
                continue

        try:
            rel_parent = src.parent.relative_to(carved_dir)
        except ValueError:
            rel_parent = Path(".")
        dest_sub = out_dir / rel_parent
        dest_sub.mkdir(parents=True, exist_ok=True)

        if len(blocks) == 1:
            dst = _stem_pem_path(src, None, dest_sub)
            dst.write_bytes(blocks[0])
            written.append(
                {
                    "src": str(src),
                    "dst": str(dst),
                    "blocks": 1,
                    "bytes": len(blocks[0]),
                }
            )
        else:
            for i, blk in enumerate(blocks):
                dst = _stem_pem_path(src, i, dest_sub)
                dst.write_bytes(blk)
                written.append(
                    {
                        "src": str(src),
                        "dst": str(dst),
                        "blocks_index": i,
                        "bytes": len(blk),
                    }
                )

    return {
        "carved_dir": str(carved_dir),
        "out_dir": str(out_dir),
        "glob": glob_report,
        "inputs_matched": len(paths),
        "written_files": len(written),
        "written": written,
        "skipped": skipped,
    }


__all__ = ["export_carved_pem_bins", "split_pem_blocks"]
