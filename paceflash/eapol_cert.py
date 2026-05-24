"""Extract and decrypt Pace 5268AC WAN EAPOL PKCS#12 from assembled TL flash."""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any, Literal

from boardfs import temporary_registry_from_physical_nand
from opentl.driver import TranslateMode
from unand.mtd import DEFAULT_MTDPARTS

from paceflash.factory_params import parse_factory_params_from_loader

CertKind = Literal["lightspeed", "device"]

# libboard.so ``board_key_pkcs12_password``: snprintf("%s%s%s", devkey, salt, serial)
PKCS12_PASSWORD_SALT = "e289d70ad34e0683fe0152da271475d587fb12f1"

_SERIAL_RE = re.compile(rb"[0-9]{5}N[0-9]{6}")
_DEVKEY_LOADER_RE = re.compile(rb"devkey=([0-9A-Fa-f]{16})")
_SUBJECT_CN_RE = re.compile(r"CN=([^,]+)", re.IGNORECASE)
_SUBJECT_SN_RE = re.compile(r"(?:serialNumber|2\.5\.4\.5)=([^,]+)", re.IGNORECASE)


def _param_tag(cert: CertKind) -> bytes:
    return f"{cert}_p12=".encode("ascii")


def extract_p12_b64(tlpart: bytes, cert: CertKind = "lightspeed") -> str:
    """Return base64 PKCS#12 payload for ``lightspeed`` or ``device`` from assembled tlpart."""
    tag = _param_tag(cert)
    idx = tlpart.find(tag)
    if idx < 0:
        raise ValueError(f"{tag.decode('ascii')} not found in assembled tlpart")
    chunk = tlpart[idx : idx + 65536]
    end = len(chunk)
    for sep in (b"\n", b"\x00", b"\r"):
        j = chunk.find(sep)
        if j > 0:
            end = min(end, j)
    line = chunk[:end].decode("ascii", errors="replace")
    _key, b64 = line.split("=", 1)
    b64 = b64.strip()
    if not b64:
        raise ValueError(f"empty base64 after {tag.decode('ascii')}")
    return b64


def devkey_from_loader(loader: bytes) -> str | None:
    parsed = parse_factory_params_from_loader(loader)
    if parsed.get("ok") and isinstance(parsed.get("params"), dict):
        dk = parsed["params"].get("devkey")
        if isinstance(dk, str) and dk:
            return dk
    m = _DEVKEY_LOADER_RE.search(loader)
    return m.group(1).decode("ascii") if m else None


def serial_from_flash(*, loader: bytes, tlpart: bytes) -> str | None:
    parsed = parse_factory_params_from_loader(loader)
    if parsed.get("ok") and isinstance(parsed.get("params"), dict):
        sn = parsed["params"].get("sn")
        if isinstance(sn, str) and sn:
            return sn
    m = _SERIAL_RE.search(tlpart)
    return m.group().decode("ascii") if m else None


def _fs_safe_token(value: str, *, max_len: int = 48) -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    token = re.sub(r"-+", "-", token).strip("-_")
    return (token[:max_len] if token else "unknown")


def subject_output_slug(
    subject: str | None,
    *,
    serial: str | None = None,
    cert: CertKind = "lightspeed",
) -> str:
    """Filesystem-safe stem for default ``{stem}_eapol.pem`` / ``{stem}.p12`` names."""
    tokens: list[str] = [cert]
    if subject:
        cn = _SUBJECT_CN_RE.search(subject)
        if cn:
            tokens.append(_fs_safe_token(cn.group(1).replace(":", "-")))
        sn = _SUBJECT_SN_RE.search(subject)
        if sn:
            sn_tok = _fs_safe_token(sn.group(1))
            if sn_tok not in tokens[1:]:
                tokens.append(sn_tok)
    if len(tokens) == 1 and serial:
        tokens.append(_fs_safe_token(serial))
    stem = "_".join(tokens)
    return stem[:120].rstrip("-_") or cert


def default_eapol_output_paths(
    *,
    cert: CertKind,
    serial: str | None,
    subject: str | None,
    decrypt: bool,
) -> tuple[Path | None, Path]:
    """Default output paths when ``-o`` / ``--p12`` are omitted."""
    stem = subject_output_slug(subject, serial=serial, cert=cert)
    return (Path(f"{stem}_eapol.pem") if decrypt else None, Path(f"{stem}.p12"))


def pkcs12_password(devkey: str, serial: str, *, salt: str = PKCS12_PASSWORD_SALT) -> str:
    """Password for ``lightspeed_p12`` / ``device_p12`` (libboard ``%s%s%s``)."""
    return devkey + salt + serial


def decrypt_pkcs12_to_pem(p12_raw: bytes, password: str) -> tuple[bytes, dict[str, Any]]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
    except ImportError as e:
        raise RuntimeError(
            "dump-eapol-cert requires the cryptography package (pip install cryptography)"
        ) from e

    key, cert, extra = pkcs12.load_key_and_certificates(p12_raw, password.encode("ascii"))
    meta: dict[str, Any] = {"extra_certs": len(extra or [])}
    if cert is not None:
        meta["subject"] = cert.subject.rfc4514_string()
    pem = b""
    if key is not None:
        pem += key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    if cert is not None:
        pem += cert.public_bytes(serialization.Encoding.PEM)
    for ca in extra or []:
        pem += ca.public_bytes(serialization.Encoding.PEM)
    return pem, meta


def dump_eapol_cert(
    flash_path: str | Path,
    *,
    cert: CertKind = "lightspeed",
    cmdline: str | None = None,
    nand_translate: bool = True,
    nand_translate_mode: TranslateMode = "inline-2112",
    decrypt: bool = True,
    output_pem: str | Path | None = None,
    output_p12: str | Path | None = None,
    redact_password: bool = False,
    include_pem: bool = False,
    write_files: bool = True,
) -> dict[str, Any]:
    """
    Read assembled ``tlpart``, extract ``lightspeed_p12`` / ``device_p12``, optionally decrypt to PEM.

    PKCS#12 blobs live in the logical TL byte stream (param-style ``key=base64`` text), not in
    empty ``opentla1``/``opentla2`` slices on typical captures — see ``reference/board_params_nand.md``.
    """
    p = Path(flash_path).expanduser().resolve()
    line = cmdline if cmdline is not None else f"quiet rw {DEFAULT_MTDPARTS}"
    warnings: list[str] = []
    out: dict[str, Any] = {
        "flash": str(p),
        "cmdline": line,
        "cert": cert,
        "nand_translate": nand_translate,
        "warnings": warnings,
    }

    with temporary_registry_from_physical_nand(
        p, line, translate_mode=nand_translate_mode
    ) as (reg, man, _ot):
        if not nand_translate and man.get("warnings"):
            for w in man["warnings"]:
                warnings.append(str(w))
        try:
            tlpart = reg.flash.read_partition("tlpart")
        except Exception as e:
            out["ok"] = False
            out["error"] = f"tlpart read failed: {type(e).__name__}: {e}"
            return out
        try:
            loader = reg.flash.read_partition("loader")
        except Exception as e:
            loader = b""
            warnings.append(f"loader read failed: {type(e).__name__}: {e}")

    try:
        b64 = extract_p12_b64(tlpart, cert)
    except ValueError as e:
        out["ok"] = False
        out["error"] = str(e)
        return out

    serial = serial_from_flash(loader=loader, tlpart=tlpart)
    devkey = devkey_from_loader(loader) if loader else None
    if devkey is None:
        warnings.append("devkey not found in loader; decrypt will fail")

    out["serial"] = serial
    out["devkey"] = None if redact_password else devkey
    out["p12_b64_length"] = len(b64)
    try:
        p12_raw = base64.b64decode(b64, validate=True)
    except Exception as e:
        out["ok"] = False
        out["error"] = f"base64 decode failed: {type(e).__name__}: {e}"
        return out
    out["p12_bytes"] = len(p12_raw)

    subject: str | None = None
    pem: bytes | None = None

    if not decrypt:
        out["ok"] = True
        out["decrypted"] = False
    else:
        if not serial or not devkey:
            out["ok"] = False
            out["error"] = "missing serial or devkey (need loader manufacturing block)"
            return out

        password = pkcs12_password(devkey, serial)
        out["password"] = None if redact_password else password

        try:
            pem, meta = decrypt_pkcs12_to_pem(p12_raw, password)
        except Exception as e:
            out["ok"] = False
            out["error"] = f"PKCS#12 decrypt failed: {type(e).__name__}: {e}"
            return out

        out.update(meta)
        subject = meta.get("subject") if isinstance(meta.get("subject"), str) else None
        out["ok"] = True
        out["decrypted"] = True
        out["pem_bytes"] = len(pem)
        if include_pem:
            out["pem"] = pem.decode("ascii")

    auto_pem, auto_p12 = default_eapol_output_paths(
        cert=cert, serial=serial, subject=subject, decrypt=decrypt
    )
    out["output_stem"] = auto_p12.stem

    if output_p12 is None:
        output_p12 = auto_p12
    if output_pem is None and decrypt:
        output_pem = auto_pem

    p12_path = Path(output_p12).expanduser().resolve()
    out["p12_path"] = str(p12_path)
    if write_files:
        p12_path.parent.mkdir(parents=True, exist_ok=True)
        p12_path.write_bytes(p12_raw)

    if decrypt and pem is not None and output_pem is not None:
        pem_path = Path(output_pem).expanduser().resolve()
        out["pem_path"] = str(pem_path)
        if write_files:
            pem_path.parent.mkdir(parents=True, exist_ok=True)
            pem_path.write_bytes(pem)

    return out
