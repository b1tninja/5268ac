"""Public corpus-facing artifacts for ``.pkgstream`` carriers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator

from corpus.artifacts import CorpusArtifact
from lib2spy.native_pkgstream import scan_embedded_images, try_decompress_bzip2_prefix
from lib2spy.pkgstream_verify import verify_pkgstream

_VERSION_RE = re.compile(rb"\b\d+\.\d+\.\d+\.\d+\b")


def _safe_posix_path(path: str) -> str | None:
    p = path.strip().replace("\\", "/").lstrip("/")
    if not p or p.startswith("../") or "/../" in p:
        return None
    return p


def _source_prefix(pkgstream_path: Path, collection: str | None) -> str:
    core = f"pkgstream:{pkgstream_path.resolve()}"
    if collection:
        return f"collection:{collection.strip().strip('/')}:{core}"
    return core


def _artifact(
    prefix: str,
    kind: str,
    logical_path: str,
    data: bytes,
    **metadata: object,
) -> CorpusArtifact:
    return CorpusArtifact(
        source_key=f"{prefix}:{kind}:{logical_path}",
        kind=kind,
        logical_path=logical_path,
        data=data,
        metadata=dict(metadata),
    )


def iter_pkgstream_artifacts(
    pkgstream_path: str | Path,
    *,
    collection: str | None = None,
    include_tlv: bool = True,
    include_embedded: bool = True,
    include_certs: bool = True,
    verify: bool = False,
) -> Iterator[CorpusArtifact]:
    """
    Yield normalized artifacts from one ``.pkgstream`` carrier.

    This is the library boundary corpus should use: lib2spy owns carrier parsing,
    verification records, TLV offsets, scripts, certificates, and embedded image discovery.
    """
    src = Path(pkgstream_path).expanduser().resolve()
    raw = src.read_bytes()
    body, outer_bzip2 = try_decompress_bzip2_prefix(raw)
    prefix = _source_prefix(src, collection)
    rep = verify_pkgstream(src, rsa_verify=verify)

    meta = {
        "path": str(src),
        "raw_size": len(raw),
        "body_size": len(body),
        "outer_bzip2": outer_bzip2,
        "verify_summary": rep.summary,
        "header_u32": list(rep.header_u32),
        "prefix_tlv_count": rep.prefix_tlv_count,
    }
    yield _artifact(
        prefix,
        "pkgstream_metadata",
        "pkgstream_metadata.json",
        json.dumps(meta, indent=2).encode("utf-8"),
        **meta,
    )

    if include_tlv:
        for rec in rep.file_records:
            rel = _safe_posix_path(rec.path) or f"_unsafe/file_@{rec.tlv_offset:07d}.bin"
            if 0 <= rec.payload_offset <= rec.payload_end <= len(body):
                data = body[rec.payload_offset : rec.payload_end]
            else:
                data = b""
            yield _artifact(
                prefix,
                "tlv_file",
                rel,
                data,
                tlv_offset=rec.tlv_offset,
                file_size=rec.file_size,
                digest_verified=rec.digest_verified,
                file_mode=rec.file_mode,
                timestamp_candidates=rec.timestamp_candidates,
            )

        for i, rec in enumerate(rep.script_records):
            rel = f"_scripts/script_{i:02d}_@{rec.tlv_offset:07d}.bin"
            if 0 <= rec.payload_offset <= rec.payload_end <= len(body):
                data = body[rec.payload_offset : rec.payload_end]
            else:
                data = b""
            yield _artifact(
                prefix,
                "tlv_script",
                rel,
                data,
                tlv_offset=rec.tlv_offset,
                payload_size=rec.payload_size,
                digest_verified=rec.digest_verified,
                timestamp_candidates=rec.timestamp_candidates,
            )

    if include_certs:
        cert_doc = {
            "pkcs7_present": rep.pkcs7_present,
            "pkcs7_offset": rep.pkcs7_offset,
            "pkcs7_length": rep.pkcs7_length,
            "signers": [s.to_json() for s in rep.signers],
            "certificates": [c.to_json() for c in rep.certificates],
            "trailing_pem_offsets": rep.trailing_pem_offsets,
        }
        yield _artifact(
            prefix,
            "certificate_metadata",
            "_certs/certificate_metadata.json",
            json.dumps(cert_doc, indent=2).encode("utf-8"),
            certificate_count=len(rep.certificates),
            signer_count=len(rep.signers),
        )
        if rep.pkcs7_present:
            yield _artifact(
                prefix,
                "pkcs7",
                "_certs/pkcs7.der",
                body[rep.pkcs7_offset : rep.pkcs7_end],
                offset=rep.pkcs7_offset,
                size=rep.pkcs7_length,
            )
        end_marker = b"-----END CERTIFICATE-----"
        for i, off in enumerate(rep.trailing_pem_offsets):
            j = body.find(end_marker, off)
            if j < 0:
                continue
            end = j + len(end_marker)
            if end < len(body) and body[end : end + 1] in (b"\n", b"\r"):
                end += 1
            yield _artifact(
                prefix,
                "trailing_pem",
                f"_certs/trailing_cert_{i}.pem",
                body[off:end],
                offset=off,
                size=end - off,
            )

    if include_embedded:
        for hit in scan_embedded_images(body):
            name = str(hit.get("name") or "embedded")
            off = int(hit["offset"])
            size = int(hit["size"])
            yield _artifact(
                prefix,
                name,
                f"embedded/{name}_{off:#010x}_{size}.bin",
                body[off : off + size],
                offset=off,
                size=size,
            )

    versions = sorted({m.group(0).decode("ascii", "replace") for m in _VERSION_RE.finditer(body)})
    if versions:
        yield _artifact(
            prefix,
            "version_metadata",
            "versions.json",
            json.dumps({"versions": versions}, indent=2).encode("utf-8"),
            versions=versions,
        )


__all__ = ["iter_pkgstream_artifacts"]
