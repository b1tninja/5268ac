"""
``lib2spy.pkgstream`` — descriptive parser, integrity verifier, and payload extractor for ATT /
2Wire ``.pkgstream`` install carriers.

Run as a module:

    python -m lib2spy.pkgstream <input.pkgstream>           # full descriptive dump + verify
    python -m lib2spy.pkgstream <input.pkgstream> --extract DIR
    python -m lib2spy.pkgstream <input.pkgstream> --no-verify --json --out-json out.json

The default invocation prints **everything available** about the carrier:

* outer header (``2WIRE_SP`` magic + 4 BE u32 fields, optional outer ``BZh`` bzip2)
* every prefix TLV (type code + symbolic name, **one-word install action** + ``install_comment`` when known, offset, length, hex preview)
* every FILE TLV (path, mode, size, hash algorithm + digest verdict, candidate timestamps)
* every SCRIPT TLV (algorithm, payload offset / size, digest verdict)
* PKCS#7 / CMS ``SignedData`` envelope: presence, offset, length, ``messageDigest`` match,
  every SignerInfo (digest alg, signature alg, RSA verdict, issuerAndSerialNumber match), and
  every X.509 certificate (subject, issuer, serial, ``notBefore`` / ``notAfter``, key alg + bits)
* embedded SquashFS / uImage member ranges
* trailing PEM trust-chain offsets
* legacy DPI signature TLV flag (older firmware)
* full integrity verdict line

The integrity layer is the on-disk reimplementation of ``lib2sp_internal_check_data`` —
see :mod:`lib2spy.pkgstream_verify` and ``pkgstream.md`` § 9 for the full algorithm.

Prefix TLV ``name`` strings come from ``_TLV_NAMES``, kept in lockstep with
``reference/010editor/Pkgstream_2WIRE_SP.bt`` where the wire type appears in the
metadata prefix. Install-time dispatch in ``lib2sp_payload_data`` can reuse the same
opcode for different ``demarshall_2sp_*`` paths (see ``lib2spy.pkgstream_runtime``).
Embedded-image rows are **only** from ``lib2spy.native_pkgstream.scan_embedded_images``
(magic / superblock scan), not from TLV install order.

For on-device semantics (stubs, mount vs copy vs stream), see ``lib2spy.pkgstream_runtime``.
Runtime TLV walk vs offline tools: ``opentl/pkgstream_format_lib2sp.md`` (repo root) and ``pkgstream.md`` §10.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from lib2spy.native_pkgstream import (
    HEADER_SIZE,
    MAGIC_2WIRE_SP,
    Header2SP,
    TLV_TYPE_DPI_SIG,
    TLV_TYPE_FILE_1,
    TLV_TYPE_FILE_3,
    TLV_TYPE_PATH_FILE,
    TLV_TYPE_SCRIPT,
    TlvRecord,
    iter_tlvs_prefix_only,
    parse_2sp_header,
    scan_embedded_images,
    try_decompress_bzip2_prefix,
)
from lib2spy.pkgstream_trust_anchors import extract_trust_anchors_to_directory
from lib2spy.pkgstream_runtime.lib2sp_dispatch import (
    install_runtime_hint_dict,
)
from lib2spy.pkgstream_verify import (
    CertificateSummary,
    FileRecord,
    ScriptRecord,
    SignerSummary,
    VerifyReport,
    format_report,
    verify_pkgstream,
)

PathLike = Union[str, Path]


# ---------------------------------------------------------------------------
# TLV type symbolic names (for the full prefix-chain table)
# ---------------------------------------------------------------------------
# Kept in lockstep with reference/010editor/Pkgstream_2WIRE_SP.bt (PKGSTREAM_TLV_TYPE +
# PkgstreamTlvTypeName). Ghidra lib2sp_payload_data routing (demarshall_2sp_path /
# demarshall_2sp_move) applies in install phase and can differ from prefix semantics for
# the same opcode — see output/ghidra_mcp_lib2sp_10_5_3_527064/README.md and
# lib2spy.pkgstream_runtime.lib2sp_dispatch (``install_runtime_hint_dict`` / jump-table stubs).

_TLV_NAMES: Dict[int, str] = {
    0x00: "PREFIX_END",
    TLV_TYPE_FILE_1: "FILE",
    0x02: "STRING_LIST",
    TLV_TYPE_FILE_3: "FILE",
    0x04: "PATH",
    0x05: "CHECKSUM",
    0x06: "TIMESTAMP",
    0x07: "CONFIG",
    0x08: "INTEGER",
    0x09: "STRING",
    0x0A: "SIGNATURE",
    0x0B: "KEY_VALUE",
    0x0C: "BOOLEAN",
    0x0D: "BYTE_ARRAY",
    0x1A: "METADATA",
    0x1B: "WIRE_1B",
    0x20: "WIRE_20",
    0x25: "WIRE_25",
    TLV_TYPE_SCRIPT: "SCRIPT",
    0x27: "PATH_27",
    0x28: "PATH_28",
    0x29: "MOVE_29",
    0x2A: "MOVE_2A",
    0x2B: "MOVE_2B",
    0x2E: "RUN",
    TLV_TYPE_PATH_FILE: "PATH_FILE",
    TLV_TYPE_DPI_SIG: "DPI_SIG",
}


def _tlv_name(t: int) -> str:
    return _TLV_NAMES.get(t, f"type_0x{t:02x}")


def _tlv_row(i: int, r: TlvRecord) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "index": i,
        "type": f"0x{r.type:02x}",
        "wire_type": r.type,
        "name": _tlv_name(r.type),
        "offset": r.absolute_offset,
        "length": r.length,
        "end_offset": r.end_offset,
        "payload_hex_preview": r.payload[:32].hex(),
    }
    irt = install_runtime_hint_dict(r.type)
    if irt is not None:
        row["install_runtime"] = irt
    return row


# ---------------------------------------------------------------------------
# Pure parsing — produces the "no-verify" structured view
# ---------------------------------------------------------------------------


def _parse_only(path: PathLike) -> Dict[str, Any]:
    """
    Header + TLV walk + embedded-image scan, no PKCS#7 / digest checks.  Used when ``--no-verify``
    is set or when ``verify_pkgstream`` raises before producing a report.
    """
    raw = Path(path).read_bytes()
    body, was_bz2 = try_decompress_bzip2_prefix(raw)
    header = parse_2sp_header(body)
    tlvs = iter_tlvs_prefix_only(body, start=HEADER_SIZE)
    scans = scan_embedded_images(body)
    return {
        "path": str(Path(path).resolve()),
        "raw_size": len(raw),
        "body_size": len(body),
        "outer_bzip2": was_bz2,
        "header": {
            "magic": header.magic.decode("ascii", "replace"),
            "u32": [header.u32_0, header.u32_1, header.u32_2, header.u32_3],
            "is_supported_magic": header.is_supported_magic,
        },
        "tlvs": [
            _tlv_row(i, r)
            for i, r in enumerate(tlvs)
        ],
        "embedded_images": scans,
    }


# ---------------------------------------------------------------------------
# Text formatter — full descriptive dump (combines verify report + parse-only)
# ---------------------------------------------------------------------------


def _ok(b: Optional[bool]) -> str:
    if b is True:
        return "OK"
    if b is False:
        return "FAIL"
    return "?"


def _fmt_header_block(parsed: Dict[str, Any]) -> List[str]:
    h = parsed["header"]
    return [
        "Outer container",
        f"  path           : {parsed['path']}",
        f"  raw_size       : {parsed['raw_size']:,} bytes",
        f"  body_size      : {parsed['body_size']:,} bytes  (outer_bzip2={parsed['outer_bzip2']})",
        f"  header.magic   : {h['magic']!r}  (supported={h['is_supported_magic']})",
        f"  header.u32     : {h['u32']}",
    ]


def _fmt_tlv_chain(parsed: Dict[str, Any]) -> List[str]:
    rows = parsed["tlvs"]
    lines = [f"TLV prefix chain ({len(rows)} records)"]
    if not rows:
        lines.append("  (none)")
        return lines
    lines.append(
        "  {:>3}  {:>6}  {:<14}  {:<9}  {:<36}  {:>8}  {:>10}  payload[:32]".format(
            "#", "type", "name", "action", "install_comment", "offset", "length"
        )
    )
    for r in rows:
        irt = r.get("install_runtime") or {}
        act = (irt.get("install_action") or "")[:9]
        com = (irt.get("install_comment") or "")[:36]
        lines.append(
            "  {:>3}  {:>6}  {:<14}  {:<9}  {:<36}  {:>8}  {:>10}  {}".format(
                r["index"],
                r["type"],
                r["name"],
                act,
                com,
                r["offset"],
                r["length"],
                r["payload_hex_preview"],
            )
        )
    return lines


def _fmt_embedded(parsed: Dict[str, Any]) -> List[str]:
    rows = parsed["embedded_images"]
    lines = [f"Embedded images ({len(rows)})"]
    if not rows:
        lines.append("  (none)")
        return lines
    for row in rows:
        lines.append(
            "  {name:<10}  offset={offset:>10}  size={size:>10}".format(**row)
        )
    return lines


def _fmt_pkcs7(rep: VerifyReport) -> List[str]:
    if not rep.pkcs7_present:
        return ["PKCS#7 envelope: (absent)"]
    lines = [
        "PKCS#7 / CMS SignedData envelope",
        f"  offset            : body[{rep.pkcs7_offset}]",
        f"  length            : {rep.pkcs7_length} bytes",
        f"  end               : body[{rep.pkcs7_end}]",
        f"  messageDigest     : match={_ok(rep.prefix_messagedigest_match)}  "
        f"actual_sha1={rep.prefix_messagedigest_actual_hex}",
    ]
    if rep.signers:
        lines.append(f"  signers ({len(rep.signers)}):")
        for s in rep.signers:
            err = f"  err={s.rsa_signature_error}" if s.rsa_signature_error else ""
            lines.append(
                f"    [{s.index}] digest={s.digest_alg_name or '?'}  "
                f"sig_oid={s.signature_alg_oid_hex or '?'}  "
                f"sig_len={s.signature_length}  "
                f"messageDigest={s.message_digest_hex}  "
                f"issuer_match={s.issuer_serial_summary or '?'}  "
                f"rsa_verify={_ok(s.rsa_signature_verified)}{err}"
            )
    if rep.certificates:
        lines.append(f"  certificates ({len(rep.certificates)}):")
        for c in rep.certificates:
            lines.append(
                f"    [{c.index}] subject={c.subject}"
            )
            lines.append(
                f"          issuer ={c.issuer}"
            )
            lines.append(
                f"          serial={c.serial}  "
                f"validity={c.not_before} .. {c.not_after}  "
                f"pubkey={c.public_key_alg} {c.public_key_bits or '?'} bits  "
                f"sig={c.signature_alg}"
            )
    return lines


def _fmt_files(rep: VerifyReport) -> List[str]:
    rows = rep.file_records
    lines = [f"FILE TLVs ({len(rows)})  payload_base = body[{rep.file_payload_base}]"]
    if not rows:
        lines.append("  (none)")
        return lines
    for f in rows:
        ts = _format_timestamps(getattr(f, "timestamp_candidates", None))
        err = f"  err={f.error}" if f.error else ""
        lines.append(
            f"  tlv@{f.tlv_offset:<6}  {f.path}"
        )
        lines.append(
            f"      hash={_hash_name(f.hash_alg)}  "
            f"verify={_ok(f.digest_verified)}  "
            f"size={f.file_size:>10}  "
            f"offset={f.payload_offset:>10}  "
            f"end={f.payload_end:>10}  "
            f"mode={oct(f.file_mode) if f.file_mode is not None else '-'}"
            f"{err}"
        )
        lines.append(f"      digest_hex={f.digest.hex()}")
        if ts:
            lines.append(f"      timestamps={ts}")
    return lines


def _fmt_scripts(rep: VerifyReport) -> List[str]:
    rows = rep.script_records
    lines = [f"SCRIPT TLVs ({len(rows)})"]
    if not rows:
        lines.append("  (none)")
        return lines
    for s in rows:
        ts = _format_timestamps(getattr(s, "timestamp_candidates", None))
        err = f"  err={s.error}" if s.error else ""
        lines.append(
            f"  tlv@{s.tlv_offset:<6}  hash={_hash_name(s.hash_alg)}  "
            f"verify={_ok(s.digest_verified)}  "
            f"size={s.payload_size:>10}  "
            f"offset={s.payload_offset:>10}  "
            f"end={s.payload_end:>10}"
            f"{err}"
        )
        lines.append(f"      digest_hex={s.digest.hex()}")
        if ts:
            lines.append(f"      timestamps={ts}")
    return lines


_HASH_NAMES = {1: "SHA-1", 2: "MD5", 3: "SHA-256"}


def _hash_name(alg: int) -> str:
    return _HASH_NAMES.get(alg, f"unknown({alg})")


def _format_timestamps(cands: Optional[List[Dict[str, Any]]]) -> str:
    """Render heuristic timestamp candidates added by ``parse_file_tlv_body``."""
    if not cands:
        return ""
    parts = []
    for c in cands:
        parts.append(f"@{c['offset']}={c['iso8601']} ({c['width']} BE)")
    return "; ".join(parts) + " (heuristic)"


def _fmt_trailing(rep: VerifyReport) -> List[str]:
    lines = [f"Trailing PEM certificates: {len(rep.trailing_pem_offsets)}"]
    for off in rep.trailing_pem_offsets:
        lines.append(f"  body[{off}]")
    if rep.legacy_dpi_sig_present:
        lines.append("Legacy DPI signature TLV (0x3E8): PRESENT (older format)")
    return lines


def _fmt_summary(rep: VerifyReport) -> List[str]:
    s = rep.summary
    lines = [
        "Integrity summary",
        f"  pkcs7_present                 : {s.get('pkcs7_present')}",
        f"  pkcs7_messageDigest_match     : {s.get('pkcs7_messageDigest_match')}",
        f"  rsa_signers (total/ok/fail)   : "
        f"{s.get('rsa_signers_total')}/"
        f"{s.get('rsa_signers_verified')}/"
        f"{s.get('rsa_signers_failed')}",
        f"  files   (total/ok/fail)       : "
        f"{s.get('files_total')}/"
        f"{s.get('files_verified')}/"
        f"{s.get('files_failed')}",
        f"  scripts (total/ok/fail)       : "
        f"{s.get('scripts_total')}/"
        f"{s.get('scripts_verified')}/"
        f"{s.get('scripts_failed')}",
        f"  trailing_pem_certs            : {s.get('trailing_pem_cert_count')}",
        f"  ALL_VERIFIED                  : {s.get('all_verified')}",
    ]
    cv = s.get("chain_validation")
    if cv is not None:
        lines += [
            f"  chain_validation.evaluated    : {cv.get('evaluated')}",
            f"  chain_validation.any_valid    : {cv.get('any_valid')}",
            f"  chain_validation.trust_engcert: {cv.get('trust_engcert')}",
            f"  chain_validation.expected_cn  : {cv.get('expected_signer_cn')}",
            f"  chain_validation.root_count   : {cv.get('trust_root_count')}",
            f"  chain_validation.status_counts: {cv.get('status_counts')}",
            f"  ALL_VERIFIED_WITH_CHAIN       : {s.get('all_verified_with_chain')}",
        ]
    return lines


def format_full_report(rep: Optional[VerifyReport], parsed: Dict[str, Any]) -> str:
    """
    Combine the parse-only structural view (header + every TLV + embedded scans) with the
    integrity verifier's report (PKCS#7, signers, certificates, per-FILE/SCRIPT digest).

    When ``rep`` is ``None`` (``--no-verify``), only the structural sections are rendered.
    """
    sections: List[List[str]] = []
    sections.append(_fmt_header_block(parsed))
    sections.append(_fmt_tlv_chain(parsed))
    sections.append(_fmt_embedded(parsed))
    if rep is not None:
        sections.append(_fmt_pkcs7(rep))
        sections.append(_fmt_files(rep))
        sections.append(_fmt_scripts(rep))
        sections.append(_fmt_trailing(rep))
        sections.append(_fmt_summary(rep))
    return "\n\n".join("\n".join(block) for block in sections)


# ---------------------------------------------------------------------------
# Payload extraction — implements `--extract DIR` from plan §3
# ---------------------------------------------------------------------------


def _safe_relative_path(unix_path: str) -> Optional[Path]:
    """
    Sanitize a FILE TLV ``path`` field for use as a destination relative path.  Returns ``None``
    if the path is unsafe (contains ``..`` segments after stripping the leading ``/``, NUL bytes,
    drive letters, or is empty).
    """
    if not unix_path or "\x00" in unix_path:
        return None
    p = unix_path.replace("\\", "/").lstrip("/")
    if not p:
        return None
    parts = [seg for seg in p.split("/") if seg and seg != "."]
    if any(seg == ".." for seg in parts):
        return None
    if any(":" in seg for seg in parts):
        return None
    return Path(*parts)


def _pem_encode_cert_der(der: bytes) -> bytes:
    import base64

    b64 = base64.encodebytes(der).decode("ascii").strip()
    chunks = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(chunks) + "\n-----END CERTIFICATE-----\n").encode("ascii")


def extract_payloads(
    src: PathLike,
    dest_dir: PathLike,
    *,
    rep: Optional[VerifyReport] = None,
) -> Dict[str, Any]:
    """
    Write every FILE / SCRIPT payload, every X.509 cert (PEM), the raw PKCS#7 envelope, and a
    structured manifest under ``dest_dir``.  Layout described in ``pkgstream.md`` §9.9 / plan §3.

    :param src: pkgstream file path.
    :param dest_dir: output directory (created if needed).
    :param rep: pre-computed :class:`VerifyReport`; if ``None``, the verifier is invoked with
        ``rsa_verify=False`` (no cryptography dependency required).
    :returns: a manifest dict describing every artifact written.
    """
    src_path = Path(src).resolve()
    dest = Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    raw = src_path.read_bytes()
    body, _ = try_decompress_bzip2_prefix(raw)

    if rep is None:
        rep = verify_pkgstream(src_path, rsa_verify=False)

    written: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    # FILE TLV payloads — mirror the path field
    for f in rep.file_records:
        rel = _safe_relative_path(f.path)
        if rel is None:
            skipped.append({"kind": "file", "path": f.path, "reason": "unsafe path"})
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if f.payload_offset >= 0 and f.payload_end <= len(body):
            target.write_bytes(body[f.payload_offset : f.payload_end])
        else:
            skipped.append({"kind": "file", "path": f.path, "reason": "out-of-range"})
            continue
        if f.file_mode is not None:
            try:
                os.chmod(target, f.file_mode & 0o7777)
            except OSError:
                pass
        written.append(
            {
                "kind": "file",
                "src_path": f.path,
                "out_path": str(target),
                "size": f.file_size,
                "hash_alg": _hash_name(f.hash_alg),
                "digest_verified": f.digest_verified,
            }
        )

    # SCRIPT TLV payloads — numbered (no path in the TLV)
    if rep.script_records:
        scripts_dir = dest / "_scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        for i, s in enumerate(rep.script_records):
            target = scripts_dir / f"script_{i:02d}_@{s.tlv_offset:07d}.bin"
            if s.payload_offset >= 0 and s.payload_end <= len(body):
                target.write_bytes(body[s.payload_offset : s.payload_end])
            else:
                skipped.append({"kind": "script", "index": i, "reason": "out-of-range"})
                continue
            written.append(
                {
                    "kind": "script",
                    "out_path": str(target),
                    "size": s.payload_size,
                    "hash_alg": _hash_name(s.hash_alg),
                    "digest_verified": s.digest_verified,
                }
            )

    # PKCS#7 envelope + embedded certs (PEM-encoded)
    certs_dir = dest / "_certs"
    if rep.pkcs7_present:
        certs_dir.mkdir(parents=True, exist_ok=True)
        p7_blob = body[rep.pkcs7_offset : rep.pkcs7_end]
        (certs_dir / "pkcs7.der").write_bytes(p7_blob)
        written.append(
            {
                "kind": "pkcs7",
                "out_path": str(certs_dir / "pkcs7.der"),
                "size": len(p7_blob),
            }
        )
        # Try to extract individual X.509 certs as PEM
        try:
            from cryptography.hazmat.primitives.serialization.pkcs7 import (
                load_der_pkcs7_certificates,
            )
            from cryptography.hazmat.primitives import serialization
            import warnings

            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore", message="PKCS#7 certificates could not be parsed"
                )
                certs = load_der_pkcs7_certificates(p7_blob)
            for i, cert in enumerate(certs):
                pem = cert.public_bytes(serialization.Encoding.PEM)
                cert_path = certs_dir / f"cert_{i}.pem"
                cert_path.write_bytes(pem)
                written.append(
                    {
                        "kind": "cert",
                        "out_path": str(cert_path),
                        "subject": cert.subject.rfc4514_string(),
                        "serial": hex(cert.serial_number),
                    }
                )
        except ImportError:
            skipped.append({"kind": "cert", "reason": "cryptography not installed"})

    # Trailing PEM certs (any PEM blocks after the file payloads)
    if rep.trailing_pem_offsets:
        certs_dir.mkdir(parents=True, exist_ok=True)
        for i, off in enumerate(rep.trailing_pem_offsets):
            # PEM block: look for the matching END marker
            end_marker = b"-----END CERTIFICATE-----"
            j = body.find(end_marker, off)
            if j < 0:
                skipped.append({"kind": "trailing_pem", "offset": off, "reason": "no end marker"})
                continue
            pem_end = j + len(end_marker)
            if pem_end < len(body) and body[pem_end : pem_end + 1] in (b"\n", b"\r"):
                pem_end += 1
            cert_path = certs_dir / f"trailing_cert_{i}.pem"
            cert_path.write_bytes(body[off:pem_end])
            written.append({"kind": "trailing_pem", "out_path": str(cert_path), "offset": off})

    manifest = {
        "src_pkgstream": str(src_path),
        "dest_dir": str(dest),
        "written": written,
        "skipped": skipped,
        "verify_summary": rep.summary,
    }
    (dest / "pkgstream_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m lib2spy",
        description=(
            "Parse, verify, and optionally extract a 2WIRE / LIB2SP .pkgstream install carrier. "
            "Default: full descriptive dump (header + every TLV + FILE/SCRIPT digest verdict + "
            "PKCS#7 envelope + signers + certificates + embedded images)."
        ),
        epilog=(
            "Format + lib2sp dispatch: opentl/pkgstream_format_lib2sp.md (under opentl/). "
            "Runtime TLV / upgrade context: reference/pkgstream.md §10, "
            "lib2spy.pkgstream_runtime (stubs)."
        ),
    )
    p.add_argument("pkgstream_file", type=str, help="Path to a .pkgstream carrier file")
    p.add_argument(
        "--extract",
        metavar="DIR",
        default=None,
        help="Extract every FILE/SCRIPT payload + PKCS#7 envelope + PEM certs under DIR",
    )
    p.add_argument(
        "--extract-trust-store",
        metavar="DIR",
        default=None,
        dest="extract_trust_store",
        help=(
            "Best-effort trust material for offline chain experiments: PEM/DER certs from "
            "PKCS#7, FILE TLV sniffing, trailing PEM → DIR (see lib2spy.pkgstream_trust_anchors)"
        ),
    )
    p.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip integrity verification (header + TLV walk + embedded scan only)",
    )
    p.add_argument(
        "--no-rsa",
        action="store_true",
        help="Verify but skip the RSA SignerInfo step (in-band layers still checked)",
    )
    chain = p.add_argument_group(
        "X.509 chain validation",
        "Offline mirror of the device's pki_ver_setup_trust_roots + lib2sp_check_data "
        "policy. ANY-of-N: at least one signer must chain to a configured trust root and "
        "pass notBefore/notAfter. See pkgstream_security.md and "
        "lib2spy/data/trust_roots/PROVENANCE.md.",
    )
    chain.add_argument(
        "--validate-chain",
        action="store_true",
        help=(
            "Build and verify each SignerInfo chain to a configured trust root. Without "
            "--trust-roots the bundled device PEMs are auto-resolved with a "
            "ProvenanceWarning."
        ),
    )
    chain.add_argument(
        "--trust-roots",
        metavar="DIR_OR_PEM",
        action="append",
        default=[],
        dest="trust_roots",
        help=(
            "Path to a PEM file or directory of PEMs used as trust anchors. May be repeated. "
            "If supplied, replaces the bundled roots."
        ),
    )
    chain.add_argument(
        "--eng-root",
        metavar="PEM",
        action="append",
        default=[],
        dest="eng_roots",
        help=(
            "Mark a PEM as the engineering root. Chains terminating here are reported as "
            "skipped_eng unless --trust-engcert is set. May be repeated."
        ),
    )
    chain.add_argument(
        "--trust-engcert",
        action="store_true",
        help=(
            "Trust engineering-rooted signers (mirrors the device's "
            "tw_ulib_is_trustengcert_enabled CMDB toggle)."
        ),
    )
    chain.add_argument(
        "--expected-cn",
        metavar="CN",
        default=None,
        help=(
            "Require every signer's leaf CN to equal CN (mirrors "
            "tw_ulib_get_trust_2sp_cn). Signers with a different CN are reported as "
            "cn_mismatch."
        ),
    )
    chain.add_argument(
        "--at-time",
        metavar="ISO8601",
        default=None,
        help=(
            "Validate the chain against this UTC datetime (e.g. 2016-06-01T00:00:00). "
            "Defaults to now."
        ),
    )
    chain.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Exit non-zero unless ALL_VERIFIED is true AND --validate-chain reports at "
            "least one signer with chain_status=valid. Use in CI."
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit the structured report as JSON to stdout (instead of text)",
    )
    p.add_argument(
        "--out-json",
        metavar="PATH",
        default=None,
        help="Write the structured report as JSON to a file",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the text dump (useful with --extract or --out-json)",
    )
    return p


def _build_json_payload(
    parsed: Dict[str, Any],
    rep: Optional[VerifyReport],
    extract_manifest: Optional[Dict[str, Any]],
    trust_manifest: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"parse": parsed}
    if rep is not None:
        out["verify"] = rep.to_json()
    if extract_manifest is not None:
        out["extract"] = extract_manifest
    if trust_manifest is not None:
        out["trust_store"] = trust_manifest
    return out


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    src = Path(args.pkgstream_file)
    if not src.is_file():
        print(f"lib2spy.pkgstream: not a file: {src}", file=sys.stderr)
        return 1

    # Step 1 — parse-only structural view (always runs)
    try:
        parsed = _parse_only(src)
    except Exception as e:
        print(f"lib2spy.pkgstream: parse failed: {e}", file=sys.stderr)
        return 1

    at_time = None
    if args.at_time:
        import datetime as _dt

        try:
            at_time = _dt.datetime.fromisoformat(args.at_time)
            if at_time.tzinfo is None:
                at_time = at_time.replace(tzinfo=_dt.timezone.utc)
        except ValueError as e:
            print(f"lib2spy.pkgstream: --at-time parse error: {e}", file=sys.stderr)
            return 1

    trust_root_dir = None
    extra_root_pem_paths: List[str] = []
    if args.trust_roots:
        first = Path(args.trust_roots[0])
        if first.is_dir():
            trust_root_dir = str(first)
            extra_root_pem_paths = list(args.trust_roots[1:])
        else:
            extra_root_pem_paths = list(args.trust_roots)

    rep: Optional[VerifyReport] = None
    if not args.no_verify:
        try:
            rep = verify_pkgstream(
                src,
                rsa_verify=not args.no_rsa,
                validate_chain=args.validate_chain,
                trust_root_dir=trust_root_dir,
                extra_root_pem_paths=extra_root_pem_paths or None,
                eng_root_pem_paths=list(args.eng_roots) or None,
                trust_engcert=args.trust_engcert,
                expected_signer_cn=args.expected_cn,
                chain_validation_time=at_time,
            )
        except Exception as e:
            print(
                f"lib2spy.pkgstream: verify failed: {e}\n"
                "(continuing with structural dump; pass --no-verify to skip this step)",
                file=sys.stderr,
            )

    # Step 3 — optional payload extraction
    extract_manifest: Optional[Dict[str, Any]] = None
    trust_manifest: Optional[Dict[str, Any]] = None
    if args.extract:
        try:
            extract_manifest = extract_payloads(src, args.extract, rep=rep)
        except Exception as e:
            print(f"lib2spy.pkgstream: extract failed: {e}", file=sys.stderr)
            return 1

    if args.extract_trust_store:
        try:
            trust_manifest = extract_trust_anchors_to_directory(
                src,
                args.extract_trust_store,
                rsa_verify=not args.no_rsa,
            )
        except Exception as e:
            print(f"lib2spy.pkgstream: extract-trust-store failed: {e}", file=sys.stderr)
            return 1

    # Step 4 — output
    if args.out_json:
        Path(args.out_json).write_text(
            json.dumps(_build_json_payload(parsed, rep, extract_manifest, trust_manifest), indent=2),
            encoding="utf-8",
        )
        print(f"Wrote {args.out_json}", file=sys.stderr)
    if args.json:
        print(json.dumps(_build_json_payload(parsed, rep, extract_manifest, trust_manifest), indent=2))
    elif not args.quiet:
        print(format_full_report(rep, parsed))
        if extract_manifest is not None:
            n_written = len(extract_manifest["written"])
            n_skipped = len(extract_manifest["skipped"])
            print(
                f"\nExtract: wrote {n_written} artifacts to {extract_manifest['dest_dir']}"
                + (f" (skipped {n_skipped})" if n_skipped else "")
            )
        if trust_manifest is not None:
            n_cert = trust_manifest.get("unique_certificates", 0)
            dest_t = args.extract_trust_store
            print(f"\nTrust store: {n_cert} unique cert(s) → {dest_t}")

    if rep is None:
        return 0
    if args.strict:
        if rep.summary.get("all_verified_with_chain"):
            return 0
        if not args.validate_chain:
            print(
                "lib2spy.pkgstream: --strict without --validate-chain; in-band integrity is "
                "not enough to assert authenticity. Re-run with --validate-chain.",
                file=sys.stderr,
            )
        return 2
    if rep.summary.get("all_verified"):
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "format_full_report",
    "extract_payloads",
    "extract_trust_anchors_to_directory",
    "main",
    "_parse_only",
    "_tlv_name",
    "_safe_relative_path",
]
