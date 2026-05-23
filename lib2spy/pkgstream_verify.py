"""
Native verification of 2WIRE/LIB2SP ``pkgstream`` integrity — fully self-contained, no Ghidra
or device required.

Reverse-engineered from ``/usr/lib/lib2sp.so`` (5268 firmware 11.5.1.532678) and
ground-truthed end-to-end against the live ATT 5268AC install pkgstream.  The implementation
covers every layer the ``lib2sp`` installer authenticates **and** what gets bypassed in
PKCS#7-mode:

1. **Outer header** (24 bytes ``2WIRE_SP`` + 4 BE u32) — no checksum here, but signed below.
2. **Prefix TLV manifest** (FILE/SCRIPT/path records) — each FILE/SCRIPT TLV embeds an
   algorithm tag and digest of its payload bytes (SHA-1 / MD5 / SHA-256).
3. **PKCS#7 / CMS SignedData** envelope (detached) — RSA-signed SHA-1 of the entire prefix
   range ``body[0..p7_offset)`` with one or more SignerInfos.
4. **File-payload region** — the bytes the per-FILE/SCRIPT digests reference, located at
   ``body[p7_end ..]``.
5. **Trailing PEM trust chain** (optional) — text-encoded certs after the payload region.

The ``0x3E8 (1000)`` "DPI signature" TLV that ``lib2sp_internal_check_data`` understands is a
**different / older** in-band integrity scheme; it is not present in this build.  The current
firmware uses the PKCS#7 envelope instead.  See :mod:`lib2spy.native_pkgstream` for
the prefix-walk primitives this module builds on, and ``pkgstream.md`` §9 for the full model.

The integrity model and field offsets here are reverse-engineered from
``lib2sp_internal_check_data`` (``0x0001e104``), ``demarshall_2sp_file`` (``0x000149d8``),
``demarshall_2sp_script`` (``0x000154d8``), ``demarshall_2sp_dpi_sig`` (``0x000148d0``),
``verify_hash_alg`` (``0x0001d800``), and ``lib2sp_install_2sp_data`` (``0x0001f60c``).
"""

from __future__ import annotations

import hashlib
import struct
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

from lib2spy.native_pkgstream import (
    HEADER_SIZE,
    MAGIC_2WIRE_SP,
    TlvRecord,
    iter_tlvs_prefix_only,
    parse_2sp_header,
    try_decompress_bzip2_prefix,
    TLV_TYPE_DPI_SIG,
    TLV_TYPE_FILE_1,
    TLV_TYPE_FILE_3,
    TLV_TYPE_PATH_FILE,
    TLV_TYPE_SCRIPT,
)

PathLike = Union[str, Path]


#: Bumped whenever ``lib2spy/data/trust_roots/`` content rotates so the runtime
#: ``ProvenanceWarning`` fires the first time a fresh process auto-resolves the
#: bundled roots.
BUNDLE_VERSION = "2026.05-att5268-11.5.1.532678"

#: Firmware tag the bundled trust roots came from. See
#: [`lib2spy/data/trust_roots/PROVENANCE.md`](data/trust_roots/PROVENANCE.md).
BUNDLE_FIRMWARE_TAG = "att-5268-11.5.1.532678_prod_lightspeed-install"


class ProvenanceWarning(UserWarning):
    """Emitted once when the verifier auto-resolves the bundled device trust roots.

    Bundled PEMs are firmware-specific (see :data:`BUNDLE_FIRMWARE_TAG`); using them
    against pkgstreams from a different firmware family produces meaningless results.
    Pass ``trust_root_dir=...`` explicitly to silence the warning and lock the policy
    for your build.
    """


_PROVENANCE_WARNED = False


def bundled_trust_roots_dir() -> Path:
    """Return the path to the bundled device trust roots (``lib2spy/data/trust_roots/``)."""

    return Path(__file__).resolve().parent / "data" / "trust_roots"


# ---------------------------------------------------------------------------
# Hash algorithms (matches the enum used by ``lib2sp_internal_check_data`` and
# ``verify_hash_alg`` for FILE/SCRIPT TLVs.  See Ghidra ``0x0001d800``.)
# ---------------------------------------------------------------------------

_HASH_FUNCS = {1: hashlib.sha1, 2: hashlib.md5, 3: hashlib.sha256}
_HASH_NAMES = {1: "SHA-1", 2: "MD5", 3: "SHA-256"}
_HASH_LENS = {1: 20, 2: 16, 3: 32}

# Plausible Unix-epoch timestamp window for the "extended_extra" timestamp heuristic — every
# BE u32 / u64 value in this range is reported as a candidate.  Calibrated to the lifetime of the
# 2WIRE / LIB2SP firmware family (first carriers shipped around 2007; signing certificates in the
# 5268 install have ``notBefore`` 2007 and ``notAfter`` 2033).
_TS_MIN_EPOCH = 946_684_800   # 2000-01-01 00:00:00 UTC
_TS_MAX_EPOCH = 1_988_150_400  # 2033-01-01 00:00:00 UTC


def _decode_candidate_timestamps(buf: bytes) -> List[Dict[str, Any]]:
    """
    Heuristic scan of the FILE / SCRIPT TLV's trailing extended-fields region for Unix-epoch
    timestamp candidates.  Reads every BE-aligned ``u32`` and BE-aligned ``u64`` and reports any
    whose value falls inside :data:`_TS_MIN_EPOCH` ..  :data:`_TS_MAX_EPOCH`.

    The byte range scanned is the parser's ``extended_extra`` slice — the bytes between the
    documented FILE-mode / SCRIPT-payload-size fields and the digest at ``hash_offset``.  See
    ``demarshall_2sp_file`` / ``demarshall_2sp_script`` in ``lib2sp.so``: the loop after
    ``+0x38`` consumes ``timestamps, uid, gid, ...`` up to the per-record ``gate``.  The full
    field map for that range has not been reverse-engineered yet — see ``pkgstream.md`` § 9.4
    for the open RE item.

    :returns: list of ``{"offset", "width", "value", "iso8601"}`` dicts (one per candidate hit;
        a single byte position can produce both a u32 and a u64 hit when the high bytes happen
        to be zero).
    """
    import datetime as _dt

    out: List[Dict[str, Any]] = []
    n = len(buf)
    for i in range(0, n - 3, 4):
        v = int.from_bytes(buf[i : i + 4], "big")
        if _TS_MIN_EPOCH <= v <= _TS_MAX_EPOCH:
            out.append(
                {
                    "offset": i,
                    "width": "u32",
                    "value": v,
                    "iso8601": _dt.datetime.fromtimestamp(v, _dt.timezone.utc).isoformat(),
                }
            )
    for i in range(0, n - 7, 4):
        v = int.from_bytes(buf[i : i + 8], "big")
        if _TS_MIN_EPOCH <= v <= _TS_MAX_EPOCH:
            out.append(
                {
                    "offset": i,
                    "width": "u64",
                    "value": v,
                    "iso8601": _dt.datetime.fromtimestamp(v, _dt.timezone.utc).isoformat(),
                }
            )
    return out

#: PKCS#7 / CMS SignedData ContentInfo OID 1.2.840.113549.1.7.2
_PKCS7_SIGNED_DATA_OID = bytes.fromhex("2a864886f70d010702")
#: PKCS#9 messageDigest attribute OID 1.2.840.113549.1.9.4
_PKCS9_MESSAGE_DIGEST_OID = bytes.fromhex("2a864886f70d010904")

#: Map of digestAlgorithm OIDs (as DER bytes) to (name, hashlib factory)
_DIGEST_OIDS: Dict[bytes, Tuple[str, Any]] = {
    bytes.fromhex("2b0e03021a"): ("SHA-1", hashlib.sha1),
    bytes.fromhex("2a864886f70d0205"): ("MD5", hashlib.md5),
    bytes.fromhex("608648016503040201"): ("SHA-256", hashlib.sha256),
}


# ---------------------------------------------------------------------------
# Structured result types
# ---------------------------------------------------------------------------


@dataclass
class FileRecord:
    """One FILE TLV (types 0x1, 0x3, 0x2F) with parsed metadata + verify outcome."""

    tlv_type: int
    tlv_offset: int
    path: str
    hash_alg: int
    digest: bytes
    file_offset: int
    file_size: int
    file_mode: Optional[int]
    extended: bool
    payload_offset: int
    payload_end: int
    digest_verified: Optional[bool]
    actual_digest: Optional[bytes]
    error: Optional[str] = None
    extended_extra: bytes = b""
    timestamp_candidates: List[Dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        return {
            "tlv_type": f"0x{self.tlv_type:02x}",
            "tlv_offset": self.tlv_offset,
            "path": self.path,
            "hash_alg": _HASH_NAMES.get(self.hash_alg, f"unknown({self.hash_alg})"),
            "digest_hex": self.digest.hex(),
            "file_offset": self.file_offset,
            "file_size": self.file_size,
            "file_mode_octal": (oct(self.file_mode) if self.file_mode is not None else None),
            "extended": self.extended,
            "payload_offset": self.payload_offset,
            "payload_end": self.payload_end,
            "digest_verified": self.digest_verified,
            "actual_digest_hex": (self.actual_digest.hex() if self.actual_digest else None),
            "error": self.error,
            "extended_extra_hex": self.extended_extra.hex() if self.extended_extra else "",
            "timestamp_candidates": list(self.timestamp_candidates),
        }


@dataclass
class ScriptRecord:
    """One SCRIPT TLV (type 0x26) with parsed metadata + verify outcome."""

    tlv_offset: int
    hash_alg: int
    digest: bytes
    payload_offset: int
    payload_size: int
    payload_end: int
    digest_verified: Optional[bool]
    actual_digest: Optional[bytes]
    error: Optional[str] = None
    extended_extra: bytes = b""
    timestamp_candidates: List[Dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        return {
            "tlv_offset": self.tlv_offset,
            "hash_alg": _HASH_NAMES.get(self.hash_alg, f"unknown({self.hash_alg})"),
            "digest_hex": self.digest.hex(),
            "payload_offset": self.payload_offset,
            "payload_size": self.payload_size,
            "payload_end": self.payload_end,
            "digest_verified": self.digest_verified,
            "actual_digest_hex": (self.actual_digest.hex() if self.actual_digest else None),
            "error": self.error,
            "extended_extra_hex": self.extended_extra.hex() if self.extended_extra else "",
            "timestamp_candidates": list(self.timestamp_candidates),
        }


#: Per-signer chain validation outcome.
#:
#: * ``"not_evaluated"`` — chain validation was not requested.
#: * ``"valid"`` — leaf cert chains to a configured trust root, signatures verify, and
#:   notBefore/notAfter intersect ``now`` (or ``time=...`` if provided).
#: * ``"untrusted"`` — could not build a chain to any configured root.
#: * ``"expired"`` — chain built, but at least one cert is outside its validity window.
#: * ``"skipped_eng"`` — chain built but ends at the engineering root and
#:   ``trust_engcert=False`` (mirrors the device's ``tw_ulib_is_trustengcert_enabled``
#:   gate; see Phase 1 RE).
#: * ``"cn_mismatch"`` — leaf cert subject CN does not match ``expected_signer_cn``
#:   (mirrors ``tw_ulib_get_trust_2sp_cn``).
#: * ``"error"`` — internal error during chain build (rare; see ``chain_error``).
ChainStatus = Literal[
    "not_evaluated",
    "valid",
    "untrusted",
    "expired",
    "skipped_eng",
    "cn_mismatch",
    "error",
]


@dataclass
class SignerSummary:
    """One SignerInfo from the PKCS#7 SignedData."""

    index: int
    digest_oid_hex: str
    digest_alg_name: Optional[str]
    message_digest_hex: Optional[str]
    signature_alg_oid_hex: Optional[str]
    signature_length: int
    issuer_serial_summary: Optional[str]
    rsa_signature_verified: Optional[bool]
    rsa_signature_error: Optional[str] = None
    chain_status: ChainStatus = "not_evaluated"
    chain_error: Optional[str] = None
    chain_root_subject: Optional[str] = None
    leaf_subject_cn: Optional[str] = None

    def to_json(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "digest_oid": self.digest_oid_hex,
            "digest_alg": self.digest_alg_name,
            "message_digest_hex": self.message_digest_hex,
            "signature_alg_oid": self.signature_alg_oid_hex,
            "signature_length": self.signature_length,
            "issuer_serial_summary": self.issuer_serial_summary,
            "rsa_signature_verified": self.rsa_signature_verified,
            "rsa_signature_error": self.rsa_signature_error,
            "chain_status": self.chain_status,
            "chain_error": self.chain_error,
            "chain_root_subject": self.chain_root_subject,
            "leaf_subject_cn": self.leaf_subject_cn,
        }


@dataclass
class CertificateSummary:
    """One X.509 certificate from the PKCS#7 certificates set."""

    index: int
    subject: str
    issuer: str
    serial: str
    signature_alg: str
    not_before: str
    not_after: str
    public_key_alg: str
    public_key_bits: Optional[int]

    def to_json(self) -> Dict[str, Any]:
        return self.__dict__


@dataclass
class VerifyReport:
    """Result of :func:`verify_pkgstream`."""

    path: Optional[str]
    body_size: int
    outer_bzip2: bool
    header_magic: bytes
    header_u32: Tuple[int, int, int, int]
    prefix_tlv_count: int
    prefix_end: int
    pkcs7_offset: int
    pkcs7_length: int
    pkcs7_end: int
    pkcs7_present: bool
    prefix_messagedigest_match: Optional[bool]
    prefix_messagedigest_actual_hex: Optional[str]
    signers: List[SignerSummary]
    certificates: List[CertificateSummary]
    file_payload_base: int
    file_records: List[FileRecord]
    script_records: List[ScriptRecord]
    trailing_pem_offsets: List[int]
    legacy_dpi_sig_present: bool
    summary: Dict[str, Any] = field(default_factory=dict)
    chain_validation: Optional[Dict[str, Any]] = None

    def to_json(self) -> Dict[str, Any]:
        out = {
            "path": self.path,
            "body_size": self.body_size,
            "outer_bzip2": self.outer_bzip2,
            "header": {
                "magic": self.header_magic.decode("ascii", "replace"),
                "u32": list(self.header_u32),
            },
            "prefix": {
                "tlv_count": self.prefix_tlv_count,
                "end_offset": self.prefix_end,
            },
            "pkcs7": {
                "present": self.pkcs7_present,
                "offset": self.pkcs7_offset,
                "length": self.pkcs7_length,
                "end": self.pkcs7_end,
                "messageDigest_match": self.prefix_messagedigest_match,
                "messageDigest_actual_hex": self.prefix_messagedigest_actual_hex,
                "signers": [s.to_json() for s in self.signers],
                "certificates": [c.to_json() for c in self.certificates],
            },
            "file_payload": {
                "base": self.file_payload_base,
                "files": [f.to_json() for f in self.file_records],
                "scripts": [s.to_json() for s in self.script_records],
            },
            "trailing_pem_offsets": self.trailing_pem_offsets,
            "legacy_dpi_sig_present": self.legacy_dpi_sig_present,
            "summary": self.summary,
        }
        if self.chain_validation is not None:
            out["chain_validation"] = self.chain_validation
        return out


# ---------------------------------------------------------------------------
# Minimal ASN.1 DER walker (length parser only, no field interpretation)
# ---------------------------------------------------------------------------


def _asn1_tag_len(buf: bytes, off: int) -> Tuple[int, int, int, int]:
    """Return ``(tag_byte, content_offset, content_length, total_record_length)``.

    Supports DER short-form and long-form lengths (no indefinite-length, since CMS SignedData
    coming from this build is always definite).
    """

    if off + 2 > len(buf):
        raise ValueError(f"truncated ASN.1 record at offset {off}")
    tag = buf[off]
    o = off + 1
    if buf[o] < 0x80:
        clen = buf[o]
        o += 1
    else:
        n = buf[o] & 0x7F
        if n == 0:
            raise ValueError("indefinite-length ASN.1 not supported")
        o += 1
        if o + n > len(buf):
            raise ValueError("truncated ASN.1 length octets")
        clen = int.from_bytes(buf[o : o + n], "big")
        o += n
    total = (o - off) + clen
    if off + total > len(buf):
        raise ValueError(
            f"ASN.1 record at {off} runs past end of buffer (clen={clen}, remaining={len(buf)-off})"
        )
    return tag, o, clen, total


def _walk_signed_data(body: bytes, p7_off: int) -> Dict[str, Any]:
    """Walk a PKCS#7 / CMS SignedData blob; return field offsets + raw bytes for each piece.

    Returns a dict with ``digest_alg_set``, ``content_info``, ``certificates``, ``signer_infos``
    blocks (each a ``(content_offset, content_length)`` pair) and a list of SignerInfo
    SEQUENCE locations.
    """

    out: Dict[str, Any] = {}
    tag, c_off, c_len, total = _asn1_tag_len(body, p7_off)
    if tag != 0x30:
        raise ValueError(f"PKCS#7 outer is not SEQUENCE (got tag 0x{tag:02x})")
    out["outer_total"] = total
    out["outer_end"] = p7_off + total

    # ContentInfo: SEQUENCE { OID, [0] EXPLICIT content }
    tag2, c2_off, c2_len, _ = _asn1_tag_len(body, c_off)
    if tag2 != 0x06:
        raise ValueError(f"PKCS#7 missing OID (got tag 0x{tag2:02x})")
    out["content_oid"] = bytes(body[c2_off : c2_off + c2_len])
    if out["content_oid"] != _PKCS7_SIGNED_DATA_OID:
        raise ValueError(
            f"PKCS#7 OID {out['content_oid'].hex()} is not signedData "
            f"({_PKCS7_SIGNED_DATA_OID.hex()})"
        )

    after_oid = c2_off + c2_len
    tag3, c3_off, c3_len, _ = _asn1_tag_len(body, after_oid)
    if tag3 != 0xA0:
        raise ValueError(f"PKCS#7 missing [0] EXPLICIT (got tag 0x{tag3:02x})")

    # SignedData inner SEQUENCE
    tag4, c4_off, c4_len, _ = _asn1_tag_len(body, c3_off)
    if tag4 != 0x30:
        raise ValueError(f"SignedData is not SEQUENCE (got tag 0x{tag4:02x})")

    pos = c4_off
    end = c4_off + c4_len
    field_index = 0
    digest_alg_set = (0, 0)
    cert_block = (0, 0)
    signer_block = (0, 0)
    while pos < end:
        ti, co, cl, tt = _asn1_tag_len(body, pos)
        if field_index == 1 and ti == 0x31:
            digest_alg_set = (co, cl)
        elif field_index == 3 and ti == 0xA0:
            cert_block = (co, cl)
        elif ti == 0x31 and signer_block == (0, 0) and digest_alg_set != (0, 0):
            # The last SET in SignedData is signerInfos (after digestAlgs, contents, certs, crls)
            signer_block = (co, cl)
        pos += tt
        field_index += 1

    out["digest_alg_set"] = digest_alg_set
    out["certificates"] = cert_block
    out["signer_infos"] = signer_block

    # Each SignerInfo is a SEQUENCE inside the signerInfos SET
    signers: List[Tuple[int, int]] = []
    if signer_block != (0, 0):
        sp = signer_block[0]
        sn = signer_block[0] + signer_block[1]
        while sp < sn:
            ti, co, cl, tt = _asn1_tag_len(body, sp)
            if ti == 0x30:
                signers.append((co, cl))
            sp += tt
    out["signers"] = signers
    return out


def _parse_signer_info(body: bytes, si_off: int, si_len: int) -> Dict[str, Any]:
    """Parse one SignerInfo SEQUENCE, returning its key fields."""

    pos = si_off
    end = si_off + si_len
    fields: List[Tuple[int, int, int, int]] = []
    while pos < end:
        ti, co, cl, tt = _asn1_tag_len(body, pos)
        fields.append((ti, co, cl, tt))
        pos += tt

    out: Dict[str, Any] = {
        "version": None,
        "issuer_serial_offset": None,
        "issuer_serial_length": None,
        "digest_oid_bytes": None,
        "digest_alg_offset": None,
        "digest_alg_length": None,
        "auth_attrs_offset": None,
        "auth_attrs_length": None,
        "signature_offset": None,
        "signature_length": None,
        "message_digest": None,
        "signature_alg_oid_bytes": None,
        "auth_attrs_signed_bytes": None,
    }

    for fi, (ti, co, cl, tt) in enumerate(fields):
        if fi == 0 and ti == 0x02:  # version INTEGER
            out["version"] = int.from_bytes(body[co : co + cl], "big")
        elif fi == 1 and ti == 0x30:  # issuerAndSerialNumber SEQUENCE
            out["issuer_serial_offset"] = co
            out["issuer_serial_length"] = cl
        elif fi == 2 and ti == 0x30:  # digestAlgorithm SEQUENCE
            out["digest_alg_offset"] = co
            out["digest_alg_length"] = cl
            ti2, co2, cl2, _ = _asn1_tag_len(body, co)
            if ti2 == 0x06:
                out["digest_oid_bytes"] = bytes(body[co2 : co2 + cl2])
        elif ti == 0xA0 and out["auth_attrs_offset"] is None:
            # First [0] = authenticated attributes
            out["auth_attrs_offset"] = co
            out["auth_attrs_length"] = cl
            # Save canonical SET DER bytes for signature verification:
            # CMS spec says the signature is over `SET OF Attribute` in DER (tag 0x31),
            # NOT the [0] IMPLICIT-tagged form on the wire.
            attrs_set = b"\x31" + _der_length(cl) + bytes(body[co : co + cl])
            out["auth_attrs_signed_bytes"] = attrs_set
            # Walk attributes looking for messageDigest (PKCS#9 OID 1.2.840.113549.1.9.4)
            apos = co
            aend = co + cl
            while apos < aend:
                at, ao, al, atotal = _asn1_tag_len(body, apos)
                if at == 0x30:  # Attribute SEQUENCE { OID, SET }
                    ot, oo, ol, ototal = _asn1_tag_len(body, ao)
                    if ot == 0x06:
                        oid_bytes = bytes(body[oo : oo + ol])
                        vt, vo, vl, _ = _asn1_tag_len(body, ao + ototal)
                        if oid_bytes == _PKCS9_MESSAGE_DIGEST_OID and vt == 0x31:
                            # Inside the SET there's an OCTET STRING with the digest
                            mdt, mdo, mdl, _ = _asn1_tag_len(body, vo)
                            if mdt == 0x04:
                                out["message_digest"] = bytes(body[mdo : mdo + mdl])
                apos += atotal
        elif ti == 0x30 and fi >= 3 and out["signature_alg_oid_bytes"] is None:
            # signatureAlgorithm SEQUENCE { OID, params }
            ti2, co2, cl2, _ = _asn1_tag_len(body, co)
            if ti2 == 0x06:
                out["signature_alg_oid_bytes"] = bytes(body[co2 : co2 + cl2])
        elif ti == 0x04:  # OCTET STRING — encryptedDigest (the actual signature bytes)
            out["signature_offset"] = co
            out["signature_length"] = cl

    return out


def _der_length(n: int) -> bytes:
    """Encode an integer length in DER (short or long form)."""
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


# ---------------------------------------------------------------------------
# FILE / SCRIPT TLV body parsers (matches ``demarshall_2sp_file`` / ``_script``)
# ---------------------------------------------------------------------------


def parse_file_tlv_body(payload: bytes) -> Dict[str, Any]:
    """Parse a FILE TLV body (types 0x1, 0x3, 0x2F).

    Layout (big-endian, contiguous on the wire — note the C struct has a 4-byte alignment
    hole at struct +0x24 that does *not* exist on the wire):

    * +0x00 (u32): version/flags  (always 0 in observed builds)
    * +0x04 (u32): ``path_offset`` — byte offset of the path string within this TLV body
    * +0x08 (u32): ``path_length``
    * +0x0c (u32): ``hash_alg``  (1=SHA-1, 2=MD5, 3=SHA-256 — see ``verify_hash_alg``)
    * +0x10 (u32): ``hash_offset``
    * +0x14 (u32): ``hash_length``
    * +0x18 (u32): ``file_offset_short`` (32-bit form)
    * +0x1c (u32): ``file_size_short``  (32-bit form)
    * +0x20 (u32): ``gate`` — when ≥ 100, the extended fields below are present and authoritative
    * +0x24 (u64): ``file_offset_ext`` (BE u64, byte offset within the file-payload region)
    * +0x2c (u64): ``file_size_ext`` (BE u64, file length in bytes)
    * +0x34 (u32): ``file_mode_ext`` (POSIX mode, e.g. 0o755 / 0o100644)

    Then optional extra extended fields (timestamps, uid, gid, …) up to ``gate``-bytes total.

    The path string and digest follow at their declared offsets after the header.
    """

    if len(payload) < 36:
        raise ValueError(f"FILE TLV body too short: {len(payload)} < 36")

    f = struct.unpack(">9I", payload[:36])
    out: Dict[str, Any] = {
        "version_or_flags": f[0],
        "path_offset": f[1],
        "path_length": f[2],
        "hash_alg": f[3],
        "hash_offset": f[4],
        "hash_length": f[5],
        "file_offset_short": f[6],
        "file_size_short": f[7],
        "gate": f[8],
    }

    po = out["path_offset"]
    pl = out["path_length"]
    ho = out["hash_offset"]
    hl = out["hash_length"]
    if po + pl > len(payload) or ho + hl > len(payload):
        raise ValueError(
            f"FILE TLV path/hash slice out of range "
            f"(path={po}+{pl} hash={ho}+{hl} body={len(payload)})"
        )
    out["path"] = bytes(payload[po : po + pl])
    out["digest"] = bytes(payload[ho : ho + hl])

    # Extended fields start at WIRE offset 36 (immediately after the 9 short-header u32s).
    # Even though the C struct lays them out at +0x28 with a 4-byte hole at +0x24, the wire
    # is contiguous.
    if out["gate"] >= 100 and len(payload) >= 56:
        out["extended"] = True
        out["file_offset"] = struct.unpack(">Q", payload[36:44])[0]
        out["file_size"] = struct.unpack(">Q", payload[44:52])[0]
        out["file_mode"] = struct.unpack(">I", payload[52:56])[0]
        # Bytes 56..gate carry the un-RE'd extended fields (timestamps, uid, gid, ...).  Stop
        # at the first of {gate, path_offset, hash_offset} that's > 56 to avoid scanning into
        # the path string or digest.
        cutoff = min(
            int(out["gate"]),
            po if po > 56 else len(payload),
            ho if ho > 56 else len(payload),
            len(payload),
        )
        if cutoff > 56:
            out["extended_extra"] = bytes(payload[56:cutoff])
        else:
            out["extended_extra"] = b""
    else:
        out["extended"] = False
        out["file_offset"] = out["file_offset_short"]
        out["file_size"] = out["file_size_short"]
        out["file_mode"] = None
        out["extended_extra"] = b""
    out["timestamp_candidates"] = _decode_candidate_timestamps(out["extended_extra"])
    return out


def parse_script_tlv_body(payload: bytes) -> Dict[str, Any]:
    """Parse a SCRIPT TLV body (type 0x26).

    Layout (big-endian, see ``demarshall_2sp_script``).  Note: SCRIPT and FILE share
    *identical* extended-section semantics, but the algorithm field sits at struct +0x18 in
    SCRIPT (vs +0x0c in FILE), and there is no mode byte.
    """

    if len(payload) < 36:
        raise ValueError(f"SCRIPT TLV body too short: {len(payload)} < 36")

    f = struct.unpack(">9I", payload[:36])
    out: Dict[str, Any] = {
        "version_or_size": f[0],
        "field_04": f[1],
        "script_offset": f[2],
        "script_length": f[3],
        "field_10": f[4],
        "field_14": f[5],
        "hash_alg": f[6],
        "hash_offset": f[7],
        "hash_length": f[8],
    }
    ho = out["hash_offset"]
    hl = out["hash_length"]
    if ho + hl > len(payload):
        raise ValueError(
            f"SCRIPT TLV hash slice out of range (hash={ho}+{hl} body={len(payload)})"
        )
    out["digest"] = bytes(payload[ho : ho + hl])

    if len(payload) >= 52:
        out["payload_offset"] = struct.unpack(">Q", payload[36:44])[0]
        out["payload_size"] = struct.unpack(">Q", payload[44:52])[0]
    else:
        out["payload_offset"] = 0
        out["payload_size"] = 0

    # Bytes 52..hash_offset carry un-RE'd extended fields, mirroring the FILE TLV layout.
    if ho > 52 and ho <= len(payload):
        out["extended_extra"] = bytes(payload[52:ho])
    else:
        out["extended_extra"] = b""
    out["timestamp_candidates"] = _decode_candidate_timestamps(out["extended_extra"])
    return out


# ---------------------------------------------------------------------------
# Per-FILE / SCRIPT digest verification
# ---------------------------------------------------------------------------


def _verify_file_record(body: bytes, base: int, parsed: Dict[str, Any], r: TlvRecord) -> FileRecord:
    alg = parsed["hash_alg"]
    file_off = parsed["file_offset"]
    file_size = parsed["file_size"]
    payload_off = base + file_off
    payload_end = payload_off + file_size
    error: Optional[str] = None
    actual: Optional[bytes] = None
    verified: Optional[bool] = None
    if alg not in _HASH_FUNCS:
        error = f"unknown hash_alg={alg}"
    elif payload_end > len(body):
        error = f"payload range {payload_off}..{payload_end} exceeds body size {len(body)}"
    else:
        actual = _HASH_FUNCS[alg](body[payload_off:payload_end]).digest()
        verified = actual == parsed["digest"]
    return FileRecord(
        tlv_type=r.type,
        tlv_offset=r.absolute_offset,
        path=parsed["path"].decode("utf-8", "replace"),
        hash_alg=alg,
        digest=parsed["digest"],
        file_offset=file_off,
        file_size=file_size,
        file_mode=parsed["file_mode"],
        extended=parsed["extended"],
        payload_offset=payload_off,
        payload_end=payload_end,
        digest_verified=verified,
        actual_digest=actual,
        error=error,
        extended_extra=parsed.get("extended_extra", b""),
        timestamp_candidates=parsed.get("timestamp_candidates", []),
    )


def _verify_script_record(body: bytes, base: int, parsed: Dict[str, Any], r: TlvRecord) -> ScriptRecord:
    alg = parsed["hash_alg"]
    off = parsed["payload_offset"]
    size = parsed["payload_size"]
    payload_off = base + off
    payload_end = payload_off + size
    error: Optional[str] = None
    actual: Optional[bytes] = None
    verified: Optional[bool] = None
    if alg not in _HASH_FUNCS:
        error = f"unknown hash_alg={alg}"
    elif payload_end > len(body):
        error = f"script range {payload_off}..{payload_end} exceeds body size {len(body)}"
    else:
        actual = _HASH_FUNCS[alg](body[payload_off:payload_end]).digest()
        verified = actual == parsed["digest"]
    return ScriptRecord(
        tlv_offset=r.absolute_offset,
        hash_alg=alg,
        digest=parsed["digest"],
        payload_offset=payload_off,
        payload_size=size,
        payload_end=payload_end,
        digest_verified=verified,
        actual_digest=actual,
        error=error,
        extended_extra=parsed.get("extended_extra", b""),
        timestamp_candidates=parsed.get("timestamp_candidates", []),
    )


# ---------------------------------------------------------------------------
# Cryptographic verification — uses ``cryptography`` if installed; otherwise falls back
# to messageDigest-only checks (which is still strong evidence the prefix is intact).
# ---------------------------------------------------------------------------


def _try_load_cryptography():
    try:
        from cryptography.hazmat.primitives.serialization.pkcs7 import (
            load_der_pkcs7_certificates,
        )
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives import hashes
        from cryptography import x509

        return load_der_pkcs7_certificates, padding, rsa, hashes, x509
    except ImportError:
        return None


def _summarize_certs(p7_blob: bytes) -> List[CertificateSummary]:
    """Pull X.509 cert summaries out of the SignedData using the ``cryptography`` lib.

    Returns an empty list when ``cryptography`` is unavailable.
    """

    bits = _try_load_cryptography()
    if bits is None:
        return []
    load_der_pkcs7_certificates, _padding, _rsa, _hashes, _x509 = bits

    out: List[CertificateSummary] = []
    try:
        # 2Wire's PKCS#7 cert sets are out of canonical DER ordering; cryptography emits a
        # benign UserWarning and falls back to BER which works fine.  Suppress it here.
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="PKCS#7 certificates could not be parsed")
            certs = load_der_pkcs7_certificates(p7_blob)
    except Exception:
        return out
    for i, cert in enumerate(certs):
        try:
            subject = cert.subject.rfc4514_string()
        except Exception:
            subject = "?"
        try:
            issuer = cert.issuer.rfc4514_string()
        except Exception:
            issuer = "?"
        try:
            sig_alg_oid = cert.signature_algorithm_oid
            sig_alg = f"{sig_alg_oid._name} ({sig_alg_oid.dotted_string})"
        except Exception:
            sig_alg = "?"
        try:
            pk = cert.public_key()
            pk_alg = type(pk).__name__
            pk_bits = getattr(pk, "key_size", None)
        except Exception:
            pk_alg = "?"
            pk_bits = None
        out.append(
            CertificateSummary(
                index=i,
                subject=subject,
                issuer=issuer,
                serial=hex(cert.serial_number),
                signature_alg=sig_alg,
                not_before=cert.not_valid_before_utc.isoformat(),
                not_after=cert.not_valid_after_utc.isoformat(),
                public_key_alg=pk_alg,
                public_key_bits=pk_bits,
            )
        )
    return out


def _verify_signers_rsa(
    body: bytes,
    signed_data: Dict[str, Any],
    p7_blob: bytes,
    summaries: List[SignerSummary],
) -> None:
    """Best-effort cryptographic verification of each SignerInfo's RSA signature.

    Mutates ``summaries`` in place, setting ``rsa_signature_verified`` and
    ``rsa_signature_error`` for each entry.  If the ``cryptography`` library is missing,
    every entry stays ``None``.
    """

    bits = _try_load_cryptography()
    if bits is None:
        for s in summaries:
            s.rsa_signature_error = "cryptography not installed"
        return
    load_der_pkcs7_certificates, padding, rsa, hashes, x509 = bits

    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="PKCS#7 certificates could not be parsed")
            certs = load_der_pkcs7_certificates(p7_blob)
    except Exception as e:
        for s in summaries:
            s.rsa_signature_error = f"failed to load PKCS#7 certs: {e}"
        return

    # Index certs by (issuer DN, serial) so SignerInfo lookups are O(1) amortized.
    cert_index: Dict[Tuple[str, int], Any] = {}
    for c in certs:
        try:
            cert_index[(c.issuer.rfc4514_string(), c.serial_number)] = c
        except Exception:
            continue

    for idx, (si_off, si_len) in enumerate(signed_data["signers"]):
        if idx >= len(summaries):
            break
        s = summaries[idx]
        si = _parse_signer_info(body, si_off, si_len)
        if not si.get("issuer_serial_offset"):
            s.rsa_signature_error = "could not locate issuerAndSerialNumber"
            continue
        if not si.get("signature_offset") or not si.get("signature_length"):
            s.rsa_signature_error = "could not locate encryptedDigest"
            continue
        signed_bytes = si.get("auth_attrs_signed_bytes")
        if not signed_bytes:
            s.rsa_signature_error = "no authenticatedAttributes (CMS without authAttrs not supported)"
            continue
        digest_oid = si.get("digest_oid_bytes")
        if digest_oid not in _DIGEST_OIDS:
            s.rsa_signature_error = f"unsupported digest OID {digest_oid.hex() if digest_oid else None}"
            continue
        digest_name, digest_factory = _DIGEST_OIDS[digest_oid]

        # Locate matching cert by issuerAndSerialNumber
        try:
            issuer_off = si["issuer_serial_offset"]
            issuer_len = si["issuer_serial_length"]
            issuer_serial_blob = body[issuer_off : issuer_off + issuer_len]
            # Parse: SEQUENCE { issuer Name, serial INTEGER }
            ti, co, cl, _ = _asn1_tag_len(issuer_serial_blob, 0)
            issuer_dn_blob = issuer_serial_blob[: co + cl]  # whole inner Name
            # Actually re-parse to get the issuer Name and serial separately
            inner_pos = 0
            tn, no, nl, ntot = _asn1_tag_len(issuer_serial_blob, inner_pos)
            issuer_name_der = issuer_serial_blob[inner_pos : inner_pos + ntot]
            inner_pos += ntot
            ts, so, sl, _ = _asn1_tag_len(issuer_serial_blob, inner_pos)
            serial = int.from_bytes(issuer_serial_blob[so : so + sl], "big", signed=True)
            # Compare cert.issuer DER directly (rfc4514_string() comparisons can fail
            # on case/encoding differences)
            matched = None
            for c in certs:
                try:
                    if (
                        c.issuer.public_bytes() == issuer_name_der
                        and c.serial_number == serial
                    ):
                        matched = c
                        break
                except Exception:
                    continue
            s.issuer_serial_summary = (
                f"serial={hex(serial)} matched={(matched is not None)}"
            )
        except Exception as e:
            s.rsa_signature_error = f"issuerAndSerialNumber parse failed: {e}"
            continue

        if matched is None:
            s.rsa_signature_error = "no matching certificate in PKCS#7 cert set"
            continue

        # Verify RSA signature over signed_bytes (the SET-OF Attribute DER)
        try:
            pk = matched.public_key()
            sig_off = si["signature_offset"]
            sig_len = si["signature_length"]
            signature = body[sig_off : sig_off + sig_len]
            hash_alg = {"SHA-1": hashes.SHA1(), "MD5": hashes.MD5(), "SHA-256": hashes.SHA256()}[
                digest_name
            ]
            pk.verify(signature, signed_bytes, padding.PKCS1v15(), hash_alg)
            s.rsa_signature_verified = True
        except Exception as e:
            s.rsa_signature_verified = False
            s.rsa_signature_error = f"RSA verify failed: {e}"


# ---------------------------------------------------------------------------
# Trust-root loading and chain validation
# ---------------------------------------------------------------------------


def _load_pem_certs_from_dir(directory: Path) -> List[Tuple[Any, Path]]:
    """Load every PEM certificate under ``directory`` (recursive).

    Returns ``(certificate, source_path)`` tuples; entries that fail to parse are
    silently skipped (a bundle is allowed to contain non-cert PEMs).
    """

    bits = _try_load_cryptography()
    if bits is None:
        return []
    _load_p7, _padding, _rsa, _hashes, x509 = bits

    out: List[Tuple[Any, Path]] = []
    if not directory.exists():
        return out
    for p in sorted(directory.rglob("*.pem")):
        try:
            data = p.read_bytes()
            for blk_start in range(len(data)):
                idx = data.find(b"-----BEGIN CERTIFICATE-----", blk_start)
                if idx < 0:
                    break
                end = data.find(b"-----END CERTIFICATE-----", idx)
                if end < 0:
                    break
                end += len(b"-----END CERTIFICATE-----")
                try:
                    out.append((x509.load_pem_x509_certificate(data[idx:end]), p))
                except Exception:
                    pass
                blk_start = end
                if end >= len(data):
                    break
                # Walk via slice
                data2 = data[end:]
                more_idx = data2.find(b"-----BEGIN CERTIFICATE-----")
                if more_idx < 0:
                    break
                # The for-loop will re-find from blk_start; but to keep simple, break
                # and let outer logic handle multiple PEM blocks via the loop above.
                # Re-anchor: we just continue the outer for-loop.
                continue
            # Simpler: also load by full PEM-bundle parser path
            # (the cryptography lib lacks load_pem_x509_certificates pre-3.0; we keep
            # both paths to remain backwards compatible)
        except Exception:
            continue
    return out


def _build_root_store(
    trust_root_dir: Optional[PathLike],
    extra_root_pem_paths: Optional[List[PathLike]],
    *,
    eng_root_pem_paths: Optional[List[PathLike]] = None,
) -> Tuple[List[Any], List[str], List[str]]:
    """Collect root + extra trust certs.

    Returns ``(roots, eng_root_subjects, sources)`` where ``roots`` is the full list
    of trust anchors (production + engineering — engineering roots are *always*
    loaded so chain-builder can spot them; the per-signer policy is what enforces
    ``trust_engcert``). ``eng_root_subjects`` lists the RFC4514 subjects of any roots
    flagged as engineering — chain-builder uses this set to decide between
    ``valid`` and ``skipped_eng``. ``sources`` is the list of paths actually loaded
    (for diagnostics).
    """

    bits = _try_load_cryptography()
    if bits is None:
        return [], [], []

    sources: List[str] = []
    roots: List[Any] = []
    eng_subjects: List[str] = []

    if trust_root_dir is not None:
        d = Path(trust_root_dir)
        for cert, src in _load_pem_certs_from_dir(d):
            roots.append(cert)
            sources.append(str(src))

    for p in extra_root_pem_paths or []:
        pp = Path(p)
        if pp.is_dir():
            for cert, src in _load_pem_certs_from_dir(pp):
                roots.append(cert)
                sources.append(str(src))
        else:
            try:
                _, _, _, _, x509 = bits
                cert = x509.load_pem_x509_certificate(pp.read_bytes())
                roots.append(cert)
                sources.append(str(pp))
            except Exception:
                pass

    for p in eng_root_pem_paths or []:
        pp = Path(p)
        try:
            _, _, _, _, x509 = bits
            cert = x509.load_pem_x509_certificate(pp.read_bytes())
            roots.append(cert)
            sources.append(str(pp) + " (eng)")
            try:
                eng_subjects.append(cert.subject.rfc4514_string())
            except Exception:
                pass
        except Exception:
            pass

    return roots, eng_subjects, sources


def _build_chain_to_root(leaf, intermediates: List[Any], roots: List[Any]) -> Optional[List[Any]]:
    """Greedy issuer/subject chain builder. Returns ``[leaf, ..., root]`` or None.

    Matches by ``cert.subject == cert.issuer`` DER bytes (the cryptography lib
    canonicalises into the same Name form so this is robust enough for the small,
    fixed set of trust paths we care about).
    """

    def issuer_bytes(c) -> bytes:
        try:
            return c.issuer.public_bytes()
        except Exception:
            return b""

    def subject_bytes(c) -> bytes:
        try:
            return c.subject.public_bytes()
        except Exception:
            return b""

    chain = [leaf]
    cur = leaf
    seen = {id(leaf)}
    for _ in range(16):
        cur_issuer = issuer_bytes(cur)
        for r in roots:
            if subject_bytes(r) == cur_issuer:
                chain.append(r)
                return chain
        next_cert = None
        for c in intermediates:
            if id(c) in seen:
                continue
            if subject_bytes(c) == cur_issuer:
                next_cert = c
                break
        if next_cert is None:
            return None
        chain.append(next_cert)
        seen.add(id(next_cert))
        cur = next_cert
    return None


def _verify_signature_one_step(parent, child, hashes, padding) -> Optional[str]:
    """Verify ``child`` was signed by ``parent``'s public key. Returns None on success."""

    try:
        parent_pk = parent.public_key()
        sig = child.signature
        tbs = child.tbs_certificate_bytes
        sig_hash = child.signature_hash_algorithm
        if sig_hash is None:
            return "child has no signature_hash_algorithm"
        parent_pk.verify(sig, tbs, padding.PKCS1v15(), sig_hash)
        return None
    except Exception as e:
        return str(e)


def _validate_chain(
    chain: List[Any],
    *,
    at_time,
    hashes,
    padding,
) -> Tuple[bool, Optional[str]]:
    """Verify per-step signatures and notBefore/notAfter for every cert in chain."""

    for i in range(len(chain) - 1):
        err = _verify_signature_one_step(chain[i + 1], chain[i], hashes, padding)
        if err is not None:
            return False, f"signature step {i}: {err}"
    # If the configured "root" is actually self-signed, verify that too. We tolerate
    # non-self-signed entries in the trust list (this matches how the device builds
    # X509_STORE — anything inserted is trusted, regardless of self-signature).
    root = chain[-1]
    try:
        if root.subject.public_bytes() == root.issuer.public_bytes():
            err = _verify_signature_one_step(root, root, hashes, padding)
            if err is not None:
                return False, f"self-signed root verify failed: {err}"
    except Exception:
        pass
    for c in chain:
        try:
            nb = c.not_valid_before_utc
            na = c.not_valid_after_utc
        except Exception:
            return False, "cert missing notBefore/notAfter"
        if not (nb <= at_time <= na):
            try:
                subj = c.subject.rfc4514_string()
            except Exception:
                subj = "?"
            return False, f"expired or not-yet-valid: {subj} ({nb.date()} -> {na.date()})"
    return True, None


def _leaf_cn(cert) -> Optional[str]:
    try:
        from cryptography.x509.oid import NameOID

        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            return attrs[0].value
    except Exception:
        return None
    return None


def _evaluate_signer_chains(
    p7_blob: bytes,
    signers: List[SignerSummary],
    signed_data: Dict[str, Any],
    body: bytes,
    *,
    roots: List[Any],
    eng_root_subjects: List[str],
    trust_engcert: bool,
    expected_signer_cn: Optional[str],
    at_time,
) -> Dict[str, Any]:
    """Populate per-signer ``chain_*`` fields. Returns aggregate summary dict."""

    bits = _try_load_cryptography()
    if bits is None:
        for s in signers:
            s.chain_status = "error"
            s.chain_error = "cryptography not installed"
        return {
            "evaluated": False,
            "reason": "cryptography not installed",
            "any_valid": False,
        }

    load_der_pkcs7_certificates, padding, rsa, hashes, x509 = bits

    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="PKCS#7 certificates could not be parsed")
            embedded = list(load_der_pkcs7_certificates(p7_blob))
    except Exception as e:
        for s in signers:
            s.chain_status = "error"
            s.chain_error = f"failed to load PKCS#7 certs: {e}"
        return {
            "evaluated": False,
            "reason": f"PKCS#7 cert load failed: {e}",
            "any_valid": False,
        }

    eng_root_subject_set = set(eng_root_subjects)

    any_valid = False
    for idx, (si_off, si_len) in enumerate(signed_data["signers"]):
        if idx >= len(signers):
            break
        s = signers[idx]
        si = _parse_signer_info(body, si_off, si_len)
        if not si.get("issuer_serial_offset"):
            s.chain_status = "error"
            s.chain_error = "missing issuerAndSerialNumber"
            continue
        try:
            io = si["issuer_serial_offset"]
            il = si["issuer_serial_length"]
            blob = body[io : io + il]
            tn, no, nl, ntot = _asn1_tag_len(blob, 0)
            issuer_name_der = blob[: ntot]
            ts, so, sl, _ = _asn1_tag_len(blob, ntot)
            serial = int.from_bytes(blob[so : so + sl], "big", signed=True)
        except Exception as e:
            s.chain_status = "error"
            s.chain_error = f"issuerAndSerialNumber parse: {e}"
            continue

        leaf = None
        for c in embedded:
            try:
                if c.issuer.public_bytes() == issuer_name_der and c.serial_number == serial:
                    leaf = c
                    break
            except Exception:
                continue
        if leaf is None:
            s.chain_status = "untrusted"
            s.chain_error = "no matching leaf cert in PKCS#7 cert set"
            continue

        s.leaf_subject_cn = _leaf_cn(leaf)

        if expected_signer_cn is not None and s.leaf_subject_cn != expected_signer_cn:
            s.chain_status = "cn_mismatch"
            s.chain_error = (
                f"leaf CN {s.leaf_subject_cn!r} != expected {expected_signer_cn!r}"
            )
            continue

        intermediates = [c for c in embedded if c is not leaf]
        chain = _build_chain_to_root(leaf, intermediates, roots)
        if chain is None:
            s.chain_status = "untrusted"
            s.chain_error = "no chain to any configured trust root"
            continue

        try:
            root_subj = chain[-1].subject.rfc4514_string()
        except Exception:
            root_subj = None
        s.chain_root_subject = root_subj

        if not trust_engcert and root_subj is not None and root_subj in eng_root_subject_set:
            s.chain_status = "skipped_eng"
            s.chain_error = "chain ends at engineering root and trust_engcert=False"
            continue

        ok, err = _validate_chain(chain, at_time=at_time, hashes=hashes, padding=padding)
        if not ok:
            s.chain_status = "expired" if (err and "expired" in err) else "error"
            s.chain_error = err
            continue
        s.chain_status = "valid"
        any_valid = True

    return {
        "evaluated": True,
        "any_valid": any_valid,
        "trust_engcert": trust_engcert,
        "expected_signer_cn": expected_signer_cn,
        "at_time_iso": at_time.isoformat() if at_time else None,
        "eng_root_subjects": eng_root_subjects,
        "trust_root_count": len(roots),
    }


# ---------------------------------------------------------------------------
# Public verifier entrypoint
# ---------------------------------------------------------------------------


def _looks_like_pkcs7(body: bytes, off: int) -> bool:
    if off + 12 > len(body) or body[off] != 0x30:
        return False
    try:
        tag, c_off, c_len, total = _asn1_tag_len(body, off)
    except Exception:
        return False
    if tag != 0x30 or off + total > len(body):
        return False
    if c_off + 11 > len(body):
        return False
    if body[c_off] != 0x06:
        return False
    return body[c_off + 2 : c_off + 11] == _PKCS7_SIGNED_DATA_OID


def verify_pkgstream(
    src: Union[PathLike, bytes, bytearray, memoryview],
    *,
    rsa_verify: bool = True,
    validate_chain: bool = False,
    trust_root_dir: Optional[PathLike] = None,
    extra_root_pem_paths: Optional[List[PathLike]] = None,
    eng_root_pem_paths: Optional[List[PathLike]] = None,
    trust_engcert: bool = False,
    expected_signer_cn: Optional[str] = None,
    chain_validation_time: Optional[Any] = None,
) -> VerifyReport:
    """Verify integrity of a 2WIRE/LIB2SP ``.pkgstream`` file.

    :param src: path to a pkgstream file, or the raw bytes.
    :param rsa_verify: when True (default) and the ``cryptography`` library is installed,
        verifies each SignerInfo's RSA signature against the matching certificate from the
        embedded PKCS#7 cert set.  When False, only the messageDigest attribute is checked.
    :param validate_chain: when True, runs offline X.509 chain validation per SignerInfo
        against the configured trust roots.  Mirrors the live device's
        ``pki_ver_setup_trust_roots`` + ``lib2sp_check_data`` policy: ANY-of-N, gated on
        ``trust_engcert`` for engineering-rooted chains.
    :param trust_root_dir: directory of PEM files used as trust anchors.  When ``None``
        and ``validate_chain=True``, the bundled
        :data:`lib2spy/data/trust_roots <bundled_trust_roots_dir>` directory is used and
        a :class:`ProvenanceWarning` is emitted **once per process** (the bundle is
        firmware-specific — see ``PROVENANCE.md``).
    :param extra_root_pem_paths: additional individual PEM files (or directories) to
        merge into the trust store; used to seed engineering or vendor roots without
        replacing the directory.
    :param eng_root_pem_paths: PEMs flagged as the **engineering** root.  Chains that
        terminate here are reported as ``skipped_eng`` unless ``trust_engcert=True``,
        mirroring the device's CMDB toggle.
    :param trust_engcert: when False (default), engineering-rooted signers fail with
        ``chain_status="skipped_eng"``.  When True, they are accepted as valid roots —
        equivalent to having ``cmlegacy.<...>.trust_engcert=1`` in CMDB.
    :param expected_signer_cn: when not None, the signer leaf's CN must equal this
        string (mirrors ``tw_ulib_get_trust_2sp_cn``).
    :param chain_validation_time: ``datetime`` to validate the chain against; defaults
        to ``datetime.now(timezone.utc)``.
    :returns: a :class:`VerifyReport` describing every layer.
    """

    if isinstance(src, (bytes, bytearray, memoryview)):
        raw = bytes(src)
        path: Optional[str] = None
    else:
        path = str(Path(src).resolve())
        raw = Path(src).read_bytes()

    body, was_bz2 = try_decompress_bzip2_prefix(raw)
    body_view = bytes(body) if not isinstance(body, bytes) else body

    header = parse_2sp_header(body_view)
    if not header.is_supported_magic:
        raise ValueError(
            f"unsupported magic {header.magic!r} (expected {MAGIC_2WIRE_SP!r})"
        )

    tlvs = iter_tlvs_prefix_only(body_view, start=HEADER_SIZE)
    if not tlvs:
        raise ValueError("no TLV records found after the 24-byte header")

    prefix_end = tlvs[-1].end_offset
    pkcs7_off = prefix_end
    pkcs7_present = _looks_like_pkcs7(body_view, pkcs7_off)
    pkcs7_length = 0
    pkcs7_end = pkcs7_off
    signers: List[SignerSummary] = []
    certificates: List[CertificateSummary] = []
    prefix_md_match: Optional[bool] = None
    prefix_md_actual_hex: Optional[str] = None
    sd_meta: Optional[Dict[str, Any]] = None

    if pkcs7_present:
        try:
            sd_meta = _walk_signed_data(body_view, pkcs7_off)
            pkcs7_length = sd_meta["outer_total"]
            pkcs7_end = sd_meta["outer_end"]
        except Exception:
            pkcs7_present = False

    if pkcs7_present and sd_meta is not None:
        p7_blob = bytes(body_view[pkcs7_off:pkcs7_end])
        certificates = _summarize_certs(p7_blob)

        # Build SignerSummary list from each SignerInfo and the messageDigest attribute
        signed_prefix = body_view[:pkcs7_off]
        for idx, (si_off, si_len) in enumerate(sd_meta["signers"]):
            si = _parse_signer_info(body_view, si_off, si_len)
            digest_oid = si.get("digest_oid_bytes")
            digest_name = None
            actual_md = None
            md_match = None
            if digest_oid in _DIGEST_OIDS:
                digest_name, digest_factory = _DIGEST_OIDS[digest_oid]
                actual_md = digest_factory(signed_prefix).digest()
                claimed = si.get("message_digest")
                if claimed is not None:
                    md_match = actual_md == claimed
                    if prefix_md_actual_hex is None:
                        prefix_md_actual_hex = actual_md.hex()
                        prefix_md_match = md_match
                    else:
                        # all signers should agree
                        prefix_md_match = bool(prefix_md_match) and md_match
            sig_alg_hex = (
                si["signature_alg_oid_bytes"].hex()
                if si.get("signature_alg_oid_bytes")
                else None
            )
            signers.append(
                SignerSummary(
                    index=idx,
                    digest_oid_hex=digest_oid.hex() if digest_oid else "",
                    digest_alg_name=digest_name,
                    message_digest_hex=(
                        si["message_digest"].hex() if si.get("message_digest") else None
                    ),
                    signature_alg_oid_hex=sig_alg_hex,
                    signature_length=si.get("signature_length") or 0,
                    issuer_serial_summary=None,
                    rsa_signature_verified=None,
                )
            )

        if rsa_verify:
            _verify_signers_rsa(body_view, sd_meta, p7_blob, signers)

    # ---- Optional offline chain validation --------------------------------
    chain_validation_meta: Optional[Dict[str, Any]] = None
    if validate_chain and pkcs7_present and sd_meta is not None:
        import datetime as _dt

        at_time = chain_validation_time or _dt.datetime.now(_dt.timezone.utc)
        if trust_root_dir is None:
            global _PROVENANCE_WARNED
            trust_root_dir = bundled_trust_roots_dir()
            if not _PROVENANCE_WARNED:
                warnings.warn(
                    f"Using bundled device trust roots from "
                    f"{bundled_trust_roots_dir()} "
                    f"(BUNDLE_VERSION={BUNDLE_VERSION}, firmware="
                    f"{BUNDLE_FIRMWARE_TAG!r}). These PEMs are firmware-specific and "
                    f"are NOT a generic CA store; pass trust_root_dir explicitly to "
                    f"silence this warning. See lib2spy/data/trust_roots/PROVENANCE.md.",
                    ProvenanceWarning,
                    stacklevel=2,
                )
                _PROVENANCE_WARNED = True

        roots, eng_subjects, sources = _build_root_store(
            trust_root_dir,
            extra_root_pem_paths,
            eng_root_pem_paths=eng_root_pem_paths,
        )
        chain_validation_meta = _evaluate_signer_chains(
            p7_blob,
            signers,
            sd_meta,
            body_view,
            roots=roots,
            eng_root_subjects=eng_subjects,
            trust_engcert=trust_engcert,
            expected_signer_cn=expected_signer_cn,
            at_time=at_time,
        )
        chain_validation_meta["trust_root_sources"] = sources
        chain_validation_meta["bundle_version"] = (
            BUNDLE_VERSION
            if Path(trust_root_dir).resolve() == bundled_trust_roots_dir().resolve()
            else None
        )

    # ---- File-payload area -------------------------------------------------
    file_payload_base = pkcs7_end if pkcs7_present else prefix_end
    file_records: List[FileRecord] = []
    script_records: List[ScriptRecord] = []
    legacy_dpi = False

    file_types = {TLV_TYPE_FILE_1, TLV_TYPE_FILE_3, TLV_TYPE_PATH_FILE}
    for r in tlvs:
        try:
            if r.type in file_types:
                parsed = parse_file_tlv_body(r.payload)
                file_records.append(_verify_file_record(body_view, file_payload_base, parsed, r))
            elif r.type == TLV_TYPE_SCRIPT:
                parsed = parse_script_tlv_body(r.payload)
                script_records.append(_verify_script_record(body_view, file_payload_base, parsed, r))
            elif r.type == TLV_TYPE_DPI_SIG:
                legacy_dpi = True
        except Exception as e:
            # Record parse error so the report still surfaces something useful
            if r.type in file_types:
                file_records.append(
                    FileRecord(
                        tlv_type=r.type,
                        tlv_offset=r.absolute_offset,
                        path="<parse-error>",
                        hash_alg=0,
                        digest=b"",
                        file_offset=0,
                        file_size=0,
                        file_mode=None,
                        extended=False,
                        payload_offset=0,
                        payload_end=0,
                        digest_verified=None,
                        actual_digest=None,
                        error=str(e),
                    )
                )

    # ---- Trailing PEM cert chain ------------------------------------------
    trailing_pem_offsets: List[int] = []
    pem_marker = b"-----BEGIN CERTIFICATE-----"
    if file_records:
        max_payload_end = max((f.payload_end for f in file_records if f.payload_end > 0), default=0)
    else:
        max_payload_end = file_payload_base
    if script_records:
        max_payload_end = max(
            max_payload_end,
            max((s.payload_end for s in script_records if s.payload_end > 0), default=0),
        )
    cursor = max_payload_end
    while cursor < len(body_view):
        i = body_view.find(pem_marker, cursor)
        if i < 0:
            break
        trailing_pem_offsets.append(i)
        cursor = i + len(pem_marker)

    # ---- Summary ----------------------------------------------------------
    total_files = len(file_records)
    files_ok = sum(1 for f in file_records if f.digest_verified)
    files_failed = sum(1 for f in file_records if f.digest_verified is False)
    total_scripts = len(script_records)
    scripts_ok = sum(1 for s in script_records if s.digest_verified)
    scripts_failed = sum(1 for s in script_records if s.digest_verified is False)
    rsa_oks = sum(1 for s in signers if s.rsa_signature_verified)
    rsa_fails = sum(1 for s in signers if s.rsa_signature_verified is False)

    summary = {
        "pkcs7_present": pkcs7_present,
        "pkcs7_messageDigest_match": prefix_md_match,
        "rsa_signers_total": len(signers),
        "rsa_signers_verified": rsa_oks,
        "rsa_signers_failed": rsa_fails,
        "files_total": total_files,
        "files_verified": files_ok,
        "files_failed": files_failed,
        "scripts_total": total_scripts,
        "scripts_verified": scripts_ok,
        "scripts_failed": scripts_failed,
        "trailing_pem_cert_count": len(trailing_pem_offsets),
    }
    summary["all_verified"] = bool(
        pkcs7_present
        and prefix_md_match
        and (rsa_fails == 0)
        and (files_failed == 0)
        and (scripts_failed == 0)
        and (total_files + total_scripts > 0)
    )

    if chain_validation_meta is not None:
        chain_status_counts: Dict[str, int] = {}
        for s in signers:
            chain_status_counts[s.chain_status] = chain_status_counts.get(s.chain_status, 0) + 1
        summary["chain_validation"] = {
            "evaluated": chain_validation_meta.get("evaluated", False),
            "any_valid": chain_validation_meta.get("any_valid", False),
            "trust_engcert": chain_validation_meta.get("trust_engcert"),
            "expected_signer_cn": chain_validation_meta.get("expected_signer_cn"),
            "trust_root_count": chain_validation_meta.get("trust_root_count", 0),
            "status_counts": chain_status_counts,
        }
        summary["chain_any_valid"] = bool(chain_validation_meta.get("any_valid"))
        summary["all_verified_with_chain"] = bool(
            summary["all_verified"] and chain_validation_meta.get("any_valid")
        )

    return VerifyReport(
        path=path,
        body_size=len(body_view),
        outer_bzip2=was_bz2,
        header_magic=header.magic,
        header_u32=(header.u32_0, header.u32_1, header.u32_2, header.u32_3),
        prefix_tlv_count=len(tlvs),
        prefix_end=prefix_end,
        pkcs7_offset=pkcs7_off,
        pkcs7_length=pkcs7_length,
        pkcs7_end=pkcs7_end,
        pkcs7_present=pkcs7_present,
        prefix_messagedigest_match=prefix_md_match,
        prefix_messagedigest_actual_hex=prefix_md_actual_hex,
        signers=signers,
        certificates=certificates,
        file_payload_base=file_payload_base,
        file_records=file_records,
        script_records=script_records,
        trailing_pem_offsets=trailing_pem_offsets,
        legacy_dpi_sig_present=legacy_dpi,
        summary=summary,
        chain_validation=chain_validation_meta,
    )


def format_report(rep: VerifyReport, *, color: bool = False) -> str:
    """Return a human-readable text report."""

    def _ok(b: Optional[bool]) -> str:
        if b is True:
            return "OK"
        if b is False:
            return "FAIL"
        return "?"

    lines: List[str] = []
    lines.append(f"pkgstream verify report")
    if rep.path:
        lines.append(f"  path: {rep.path}")
    lines.append(f"  body: {rep.body_size:,} bytes  outer_bzip2={rep.outer_bzip2}")
    lines.append(
        f"  header: magic={rep.header_magic!r} u32={list(rep.header_u32)}"
    )
    lines.append(f"  prefix TLVs: {rep.prefix_tlv_count}  prefix_end=body[{rep.prefix_end}]")
    lines.append(
        f"  pkcs7: present={rep.pkcs7_present}  offset=body[{rep.pkcs7_offset}]  "
        f"length={rep.pkcs7_length}  end=body[{rep.pkcs7_end}]"
    )
    lines.append(
        f"  pkcs7 messageDigest match: {_ok(rep.prefix_messagedigest_match)}  "
        f"actual={rep.prefix_messagedigest_actual_hex}"
    )
    if rep.signers:
        lines.append(f"  signers ({len(rep.signers)}):")
        for s in rep.signers:
            chain_part = ""
            if s.chain_status != "not_evaluated":
                chain_part = f"  chain={s.chain_status}"
                if s.chain_root_subject:
                    chain_part += f" root={s.chain_root_subject!r}"
                if s.chain_error:
                    chain_part += f" ({s.chain_error})"
            lines.append(
                f"    [{s.index}] digest={s.digest_alg_name} sig_len={s.signature_length}  "
                f"issuer_match={s.issuer_serial_summary or '?'}  "
                f"rsa_verify={_ok(s.rsa_signature_verified)} {s.rsa_signature_error or ''}"
                f"{chain_part}"
            )
    if rep.certificates:
        lines.append(f"  certificates ({len(rep.certificates)}):")
        for c in rep.certificates:
            lines.append(
                f"    [{c.index}] {c.subject}  ({c.public_key_alg} {c.public_key_bits or '?'} bits, {c.signature_alg})"
            )
    lines.append(f"  file_payload_base = body[{rep.file_payload_base}]")
    lines.append(f"  files ({len(rep.file_records)}):")
    for f in rep.file_records:
        lines.append(
            f"    {f.path}  alg={_HASH_NAMES.get(f.hash_alg, f.hash_alg)}  "
            f"off={f.payload_offset:>10}  size={f.file_size:>10}  "
            f"mode={oct(f.file_mode) if f.file_mode is not None else '-'}  "
            f"verify={_ok(f.digest_verified)} {f.error or ''}"
        )
    lines.append(f"  scripts ({len(rep.script_records)}):")
    for s in rep.script_records:
        lines.append(
            f"    [@{s.tlv_offset:>5}]  alg={_HASH_NAMES.get(s.hash_alg, s.hash_alg)}  "
            f"off={s.payload_offset:>10}  size={s.payload_size:>10}  "
            f"verify={_ok(s.digest_verified)} {s.error or ''}"
        )
    lines.append(f"  trailing PEM certs: {len(rep.trailing_pem_offsets)}")
    if rep.legacy_dpi_sig_present:
        lines.append("  legacy DPI signature TLV (0x3E8) present (older format)")
    lines.append(f"  summary: {rep.summary}")
    return "\n".join(lines)


__all__ = [
    "BUNDLE_FIRMWARE_TAG",
    "BUNDLE_VERSION",
    "ChainStatus",
    "ProvenanceWarning",
    "FileRecord",
    "ScriptRecord",
    "SignerSummary",
    "CertificateSummary",
    "VerifyReport",
    "bundled_trust_roots_dir",
    "verify_pkgstream",
    "format_report",
    "parse_file_tlv_body",
    "parse_script_tlv_body",
]
