"""Single-pass MD5 + SHA-1 digests for corpus content-addressed indexing."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

_MD5SUMS_LINE_RE = re.compile(
    r"^([0-9a-fA-F]{32})\s+(.+)$",
)


@dataclass(frozen=True)
class ContentDigests:
    md5: str  # 32 hex lowercase
    sha1: str  # 40 hex lowercase


def digest_bytes(data: bytes) -> ContentDigests:
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    return ContentDigests(md5=md5, sha1=sha1)


def _update_digests(md5: "hashlib._Hash", sha1: "hashlib._Hash", chunk: bytes) -> None:
    md5.update(chunk)
    sha1.update(chunk)


def digest_stream(stream: BinaryIO, *, chunk_size: int = 1 << 20) -> ContentDigests:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        _update_digests(md5, sha1, chunk)
    return ContentDigests(md5=md5.hexdigest(), sha1=sha1.hexdigest())


def digest_file(path: Path, *, chunk_size: int = 1 << 20) -> ContentDigests:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            _update_digests(md5, sha1, chunk)
    return ContentDigests(md5=md5.hexdigest(), sha1=sha1.hexdigest())


def parse_md5sums_txt(text: str) -> dict[str, str]:
    """Parse ``sys1/md5sums.txt`` style lines → ``{basename: md5_hex}``."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _MD5SUMS_LINE_RE.match(line)
        if not m:
            continue
        md5_hex = m.group(1).lower()
        name = m.group(2).strip().replace("\\", "/")
        if name.startswith("*"):
            name = name[1:]
        base = name.rsplit("/", 1)[-1]
        out[base] = md5_hex
        out[name] = md5_hex
    return out


def verify_pkgstream_digests(
    payload: bytes,
    *,
    hash_alg: int,
    wire_digest: bytes,
) -> dict[str, object]:
    """
    Cross-check pkgstream FILE/SCRIPT TLV wire digest against computed digests.

    ``hash_alg``: 1 = SHA-1 (20 bytes), 2 = MD5 (16 bytes).
    """
    d = digest_bytes(payload)
    wire_hex = wire_digest.hex().lower()
    if hash_alg == 1:
        ok = d.sha1 == wire_hex
        expected = d.sha1
    elif hash_alg == 2:
        ok = d.md5 == wire_hex
        expected = d.md5
    else:
        return {
            "ok": False,
            "error": f"unsupported hash_alg={hash_alg}",
            "md5": d.md5,
            "sha1": d.sha1,
        }
    return {
        "ok": ok,
        "hash_alg": hash_alg,
        "expected": expected,
        "wire": wire_hex,
        "md5": d.md5,
        "sha1": d.sha1,
    }


def iter_md5sums_lines(path: Path) -> Iterator[tuple[str, str]]:
    """Yield ``(basename, md5)`` from an on-disk md5sums file."""
    text = path.read_text(encoding="utf-8", errors="replace")
    for base, md5_hex in parse_md5sums_txt(text).items():
        if "/" not in base:
            yield base, md5_hex
