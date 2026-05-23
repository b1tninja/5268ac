"""
Best-effort extraction of X.509 material from a ``.pkgstream`` carrier for **offline chain
validation experiments**.

The device's real PKCS# trust roots live primarily in ``libpki.so.0`` (compiled-in) and are
**not** guaranteed to appear inside any pkgstream.  Install carriers typically embed the CMS
signing chain in PKCS#7 ``SignedData``, optional trailing PEM blocks, and — when vendors ship
cert rotation bundles — FILE TLV payloads whose paths end in ``.pem`` / ``.crt`` / ``.cer``.

This module gathers every certificate-like artifact it can find, writes them under a stable
directory layout, and labels **heuristic** trust anchors (self-signed certs only — a coarse
proxy for “root”).  For upgrade simulation, point your verifier at the ``trust_store`` produced
from **firmware N** (or from ``att_cms-certs.pkgstream`` **N**) and validate signatures on the
carrier from release **N+1**.

Requires ``cryptography`` for PEM classification and fingerprinting; without it, only raw PEM
byte slices are copied (no DER sniffing on FILE payloads).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from lib2spy.native_pkgstream import try_decompress_bzip2_prefix
from lib2spy.pkgstream_verify import verify_pkgstream

PathLike = Union[str, Path]

_PEM_BEGIN = b"-----BEGIN CERTIFICATE-----"
_PEM_END = b"-----END CERTIFICATE-----"
_CERT_EXT = (".pem", ".crt", ".cer", ".ca-bundle", ".p7b")  # p7b not parsed as PEM cert list here


def _read_body(src: PathLike | bytes | bytearray | memoryview) -> Tuple[bytes, Optional[str], bool]:
    if isinstance(src, (bytes, bytearray, memoryview)):
        raw = bytes(src)
        path = None
    else:
        path = str(Path(src).resolve())
        raw = Path(src).read_bytes()
    body, was_bz2 = try_decompress_bzip2_prefix(raw)
    return body if isinstance(body, bytes) else bytes(body), path, was_bz2


def _try_load_crypto() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


_HAS_CRYPTO = _try_load_crypto()


def _der_fingerprint_sha256(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _parse_der_cert_blob(data: bytes):
    """Return list of cryptography ``Certificate`` objects parsed from PEM or raw DER."""
    from cryptography import x509

    out = []
    if not data or not _HAS_CRYPTO:
        return out
    # PEM blocks
    idx = 0
    while True:
        s = data.find(_PEM_BEGIN, idx)
        if s < 0:
            break
        e = data.find(_PEM_END, s)
        if e < 0:
            break
        block = data[s : e + len(_PEM_END)]
        try:
            out.append(x509.load_pem_x509_certificate(block))
        except Exception:
            pass
        idx = e + len(_PEM_END)
    # Single DER sequence (common for lone FILE payload)
    if not out and len(data) >= 4 and data[0] == 0x30:
        try:
            out.append(x509.load_der_x509_certificate(data))
        except Exception:
            pass
    return out


def _names_equal(a, b) -> bool:
    try:
        return a.public_bytes() == b.public_bytes()
    except Exception:
        return False


def _classify(cert) -> str:
    """Return ``anchor_heuristic`` if self-signed; ``chain`` otherwise."""
    if _names_equal(cert.subject, cert.issuer):
        return "anchor_heuristic"
    return "chain"


def _cert_pem_der(cert) -> Tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.serialization import Encoding

    der = cert.public_bytes(Encoding.DER)
    pem = cert.public_bytes(Encoding.PEM)
    return pem, der


def _sniff_file_tlv_cert_payload(path: str, blob: bytes) -> bool:
    lp = path.lower()
    if any(lp.endswith(ext) for ext in _CERT_EXT):
        return True
    if "cert" in lp or "ca-bundle" in lp or "trust" in lp:
        return True
    if blob.startswith(_PEM_BEGIN):
        return True
    if len(blob) >= 4 and blob[0] == 0x30:
        # Might be DER cert — only accept if crypto parses
        if _HAS_CRYPTO and _parse_der_cert_blob(blob):
            return True
    return False


def extract_trust_anchors_to_directory(
    src: PathLike | bytes | bytearray | memoryview,
    dest: PathLike,
    *,
    rsa_verify: bool = True,
) -> Dict[str, Any]:
    """
    Parse ``src`` (path or raw bytes), verify like :func:`~lib2spy.pkgstream_verify.verify_pkgstream`,
    and write all recoverable certificate material under ``dest``.

    Layout::

        dest/
          README.txt
          trust_manifest.json
          pkcs7_embedded/     # one PEM per cert from SignedData (order preserved)
          file_tlv/           # FILE payloads that look like certificates
          trailing/           # PEM blocks after the payload region
          anchors_heuristic/  # self-signed certs only (best-effort “roots”)
          chain_other/        # non-self-signed certs from pkcs7/file_tlv (deduped)

    Certificates are deduplicated by SHA-256 of DER across all sources; first occurrence wins for
    manifest bookkeeping.

    :returns: manifest dict (also written to ``trust_manifest.json``).
    """
    body, path, outer_bz2 = _read_body(src)
    rep = verify_pkgstream(body, rsa_verify=rsa_verify)

    dest_path = Path(dest)
    dest_path.mkdir(parents=True, exist_ok=True)
    sub = {
        "pkcs7_embedded": dest_path / "pkcs7_embedded",
        "file_tlv": dest_path / "file_tlv",
        "trailing": dest_path / "trailing",
        "anchors_heuristic": dest_path / "anchors_heuristic",
        "chain_other": dest_path / "chain_other",
    }
    for d in sub.values():
        d.mkdir(parents=True, exist_ok=True)

    seen_fp: Set[str] = set()
    written: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    # --- PKCS#7 embedded certs ---
    if rep.pkcs7_present:
        p7 = body[rep.pkcs7_offset : rep.pkcs7_end]
        if _HAS_CRYPTO:
            try:
                from cryptography.hazmat.primitives.serialization.pkcs7 import (
                    load_der_pkcs7_certificates,
                )

                import warnings

                with warnings.catch_warnings():
                    warnings.filterwarnings(
                        "ignore", message="PKCS#7 certificates could not be parsed"
                    )
                    certs = load_der_pkcs7_certificates(p7)
                for i, cert in enumerate(certs):
                    pem, der = _cert_pem_der(cert)
                    fp = _der_fingerprint_sha256(der)
                    if fp in seen_fp:
                        skipped.append({"fingerprint_sha256": fp, "reason": "duplicate", "source": "pkcs7_embedded"})
                        continue
                    seen_fp.add(fp)
                    role = _classify(cert)
                    target_dir = sub["anchors_heuristic"] if role == "anchor_heuristic" else sub["chain_other"]
                    fname = f"pkcs7_{i:02d}_{fp[:16]}.pem"
                    (sub["pkcs7_embedded"] / fname).write_bytes(pem)
                    # Also place copy under role dir for openssl ``CAfile`` convenience
                    fname2 = f"pkcs7_{i:02d}_{fp[:16]}.pem"
                    (target_dir / fname2).write_bytes(pem)
                    written.append(
                        {
                            "path": str(sub["pkcs7_embedded"] / fname),
                            "source": "pkcs7_embedded",
                            "detail": f"index {i}",
                            "role": role,
                            "subject": cert.subject.rfc4514_string(),
                        }
                    )
            except Exception as e:
                skipped.append({"kind": "pkcs7_embedded", "reason": str(e)})
        else:
            der_path = sub["pkcs7_embedded"] / "pkcs7.der"
            der_path.write_bytes(p7)
            written.append(
                {
                    "path": str(der_path),
                    "source": "pkcs7_embedded",
                    "detail": "raw SignedData (install cryptography for PEM split)",
                    "role": "opaque",
                }
            )
            skipped.append({"kind": "pkcs7_embedded", "reason": "cryptography not installed; wrote pkcs7.der"})

    # --- FILE TLV payloads ---
    for f in rep.file_records:
        if f.error or f.payload_end <= f.payload_offset:
            continue
        blob = body[f.payload_offset : f.payload_end]
        if not _sniff_file_tlv_cert_payload(f.path, blob):
            continue
        certs = _parse_der_cert_blob(blob)
        if not certs:
            looks_pem = blob.startswith(_PEM_BEGIN) or any(
                f.path.lower().endswith(ext) for ext in _CERT_EXT
            )
            if looks_pem:
                h = hashlib.sha256(blob).hexdigest()[:16]
                safe_name = Path(f.path).name.replace("..", "_")[:120]
                fname = f"{safe_name}_unparsed_{h}.pem"
                (sub["file_tlv"] / fname).write_bytes(blob)
                written.append(
                    {
                        "path": str(sub["file_tlv"] / fname),
                        "source": "file_tlv",
                        "detail": f.path,
                        "role": "raw_pem",
                    }
                )
            else:
                skipped.append({"kind": "file_tlv", "path": f.path, "reason": "not parseable as X.509"})
            continue
        for j, cert in enumerate(certs):
            pem, der = _cert_pem_der(cert)
            fp = _der_fingerprint_sha256(der)
            if fp in seen_fp:
                skipped.append({"fingerprint_sha256": fp, "reason": "duplicate", "source": "file_tlv"})
                continue
            seen_fp.add(fp)
            role = _classify(cert)
            safe_name = Path(f.path).name.replace("..", "_")[:120]
            fname = f"{safe_name}_{j}_{fp[:16]}.pem"
            (sub["file_tlv"] / fname).write_bytes(pem)
            target_dir = sub["anchors_heuristic"] if role == "anchor_heuristic" else sub["chain_other"]
            (target_dir / fname).write_bytes(pem)
            written.append(
                {
                    "path": str(sub["file_tlv"] / fname),
                    "source": "file_tlv",
                    "detail": f.path,
                    "role": role,
                    "subject": cert.subject.rfc4514_string(),
                }
            )

    # --- Trailing PEM ---
    for i, off in enumerate(rep.trailing_pem_offsets):
        end = body.find(_PEM_END, off)
        if end < 0:
            skipped.append({"kind": "trailing_pem", "offset": off, "reason": "no end marker"})
            continue
        pem_bytes = body[off : end + len(_PEM_END)]
        if end + len(_PEM_END) < len(body) and body[end + len(_PEM_END)] in (10, 13):
            pass  # keep conservative slice without consuming optional newline for DER logic
        certs = _parse_der_cert_blob(pem_bytes) if _HAS_CRYPTO else []
        if not certs:
            fname = f"trailing_raw_{i}_{off:08x}.pem"
            (sub["trailing"] / fname).write_bytes(pem_bytes)
            skipped.append(
                {
                    "kind": "trailing_pem",
                    "offset": off,
                    "reason": "parse failed or no cryptography; saved raw PEM slice",
                }
            )
            continue
        for j, cert in enumerate(certs):
            pem, der = _cert_pem_der(cert)
            fp = _der_fingerprint_sha256(der)
            if fp in seen_fp:
                skipped.append({"fingerprint_sha256": fp, "reason": "duplicate", "source": "trailing"})
                continue
            seen_fp.add(fp)
            role = _classify(cert)
            fname = f"trailing_{i}_{j}_{fp[:16]}.pem"
            (sub["trailing"] / fname).write_bytes(pem)
            target_dir = sub["anchors_heuristic"] if role == "anchor_heuristic" else sub["chain_other"]
            (target_dir / fname).write_bytes(pem)
            written.append(
                {
                    "path": str(sub["trailing"] / fname),
                    "source": "trailing_pem",
                    "detail": f"offset {off}",
                    "role": role,
                    "subject": cert.subject.rfc4514_string(),
                }
            )

    readme = """Trust material extracted from a 2WIRE/LIB2SP .pkgstream (best effort).

What this is NOT:
  - It is not a dump of the device's full runtime trust store. Factory roots live in
    libpki.so.0 and may never appear in any pkgstream (see pkgstream.md §9.10).

What this IS:
  - PKCS#7 SignedData certificates (signing chain packaged with the carrier).
  - FILE TLV payloads that look like PEM/DER certs or use cert-like paths.
  - Optional trailing PEM blocks after the payload region.

anchors_heuristic/ contains only self-signed certificates (common root heuristic). For strict
offline chain validation between firmware versions, merge anchors from the OLD release's
extracted store (or from libpki RE) with the PKCS#7 chain from the NEW carrier and validate with
openssl verify or your PKIX stack.

Suggested workflow (upgrade simulation):
  1. extract_trust_anchors_to_directory(old_att_cms-certs.pkgstream, trust_old/)
  2. extract_trust_anchors_to_directory(new_install.pkgstream, trust_new_chain/)
  3. Build CAfile from trust_old/anchors_heuristic (plus any roots you extracted from libpki).
  4. openssl verify -CAfile ca.pem -untrusted chain.pem leaf.pem
"""
    (dest_path / "README.txt").write_text(readme, encoding="utf-8")

    manifest: Dict[str, Any] = {
        "src_pkgstream": path,
        "body_bytes": len(body),
        "outer_bzip2": outer_bz2,
        "cryptography_present": _HAS_CRYPTO,
        "verify_summary": rep.summary,
        "written": written,
        "skipped": skipped,
        "unique_certificates": len(seen_fp),
        "notes": [
            "roots_heuristic = subject == issuer only; device may require additional compiled roots.",
            "Dedup key = SHA-256(DER); first source wins in manifest.",
        ],
    }
    (dest_path / "trust_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


__all__ = ["extract_trust_anchors_to_directory"]
