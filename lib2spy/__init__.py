"""
``lib2spy`` — 2WIRE ``.pkgstream`` carrier parsing, TLV decode, PKCS#7 verification, and
``lib2sp_*`` install-phase documentation stubs (offline research).

Use ``import lib2spy`` / ``python -m lib2spy`` for CLI and programmatic access.
"""

from __future__ import annotations

from lib2spy.artifacts import iter_pkgstream_artifacts
from lib2spy.pkgstream import extract_payloads, format_full_report
from lib2spy.pkgstream_corpus import extract_pkgstream_slices, write_directory_manifest
from lib2spy.pkgstream_verify import (
    BUNDLE_FIRMWARE_TAG,
    BUNDLE_VERSION,
    CertificateSummary,
    ChainStatus,
    FileRecord,
    ProvenanceWarning,
    ScriptRecord,
    SignerSummary,
    VerifyReport,
    bundled_trust_roots_dir,
    format_report,
    parse_file_tlv_body,
    parse_script_tlv_body,
    verify_pkgstream,
)

__all__ = [
    "BUNDLE_FIRMWARE_TAG",
    "BUNDLE_VERSION",
    "CertificateSummary",
    "ChainStatus",
    "FileRecord",
    "ProvenanceWarning",
    "ScriptRecord",
    "SignerSummary",
    "VerifyReport",
    "bundled_trust_roots_dir",
    "extract_payloads",
    "extract_pkgstream_slices",
    "iter_pkgstream_artifacts",
    "format_full_report",
    "format_report",
    "parse_file_tlv_body",
    "parse_script_tlv_body",
    "verify_pkgstream",
    "write_directory_manifest",
]
