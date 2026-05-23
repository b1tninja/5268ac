"""Correlate carrier pkgstream squash fingerprints with NAND TL read views."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from lib2spy.native_pkgstream import squashfs_le_span_at
from boardfs import correlation_suggests_chain_aware_from_hits
from paceflash.squashfs_dissect import find_squashfs_superblock_offsets

MatchKind = Literal["strict_squash", "file_payload"]


@dataclass(frozen=True)
class CarrierBlobRef:
    """One FILE (or embedded squash) artifact from lib2spy / pkgstream ground truth."""

    path: str
    pkgstream_payload_offset: int
    file_payload_len: int
    strict_squash_len: int | None
    strict_sb_offset_in_payload: int
    strict_squash_sha256: str | None
    file_payload_sha256: str | None
    release_label: str = ""
    pkgstream_path: str = ""


@dataclass(frozen=True)
class CorrelationHit:
    source_label: str
    hsqs_offset: int
    matched_path: str
    match_kind: MatchKind
    sha256: str
    span_len: int
    release_label: str = ""
    pkgstream_path: str = ""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _embedded_by_offset(parse_obj: dict[str, Any]) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for img in parse_obj.get("embedded_images") or []:
        if not isinstance(img, dict):
            continue
        off = img.get("offset")
        if isinstance(off, int):
            out[off] = img
    return out


def load_carrier_refs(
    lib2spy_json: Path,
    pkgstream_path: Path | None = None,
) -> list[CarrierBlobRef]:
    """
    Build carrier reference rows from lib2spy JSON (+ optional on-disk pkgstream for SHA-256).
    """
    data = json.loads(Path(lib2spy_json).expanduser().read_text(encoding="utf-8"))
    verify = data.get("verify") or {}
    parse_obj = data.get("parse") or {}

    ps_str = str(pkgstream_path) if pkgstream_path else ""
    body: bytes | None = None
    if pkgstream_path is not None:
        p = Path(pkgstream_path).expanduser()
        if p.is_file():
            body = p.read_bytes()
    return _refs_from_lib2spy_dict(
        {"verify": verify, "parse": parse_obj},
        body=body,
        release_label="",
        pkgstream_path=ps_str,
    )


def _carrier_ref_row(
    *,
    path: str,
    po: int,
    pe: int,
    file_len: int,
    embedded: dict[int, dict[str, Any]],
    body: bytes | None,
    release_label: str,
    pkgstream_path: str,
) -> CarrierBlobRef:
    emb = embedded.get(po)
    strict_len: int | None = None
    strict_sb_in_payload = 0
    if isinstance(emb, dict) and emb.get("name") == "squashfs":
        sz = emb.get("size")
        if isinstance(sz, int) and sz > 0:
            strict_len = sz
            emb_off = emb.get("offset")
            if isinstance(emb_off, int) and emb_off == po:
                strict_sb_in_payload = 0
            elif isinstance(emb_off, int):
                strict_sb_in_payload = max(0, emb_off - po)
    strict_sha: str | None = None
    file_sha: str | None = None
    if body is not None and po + file_len <= len(body):
        file_blob = body[po:pe]
        file_sha = _sha256_hex(file_blob)
        if strict_len is not None:
            sb = strict_sb_in_payload
            end = sb + strict_len
            if end <= len(file_blob):
                strict_sha = _sha256_hex(file_blob[sb:end])
    return CarrierBlobRef(
        path=path,
        pkgstream_payload_offset=po,
        file_payload_len=file_len,
        strict_squash_len=strict_len,
        strict_sb_offset_in_payload=strict_sb_in_payload,
        strict_squash_sha256=strict_sha,
        file_payload_sha256=file_sha,
        release_label=release_label,
        pkgstream_path=pkgstream_path,
    )


def _refs_from_lib2spy_dict(
    data: dict[str, Any],
    *,
    body: bytes | None,
    release_label: str,
    pkgstream_path: str,
) -> list[CarrierBlobRef]:
    verify = data.get("verify") or {}
    fp = verify.get("file_payload") or {}
    files = fp.get("files") or []
    parse_obj = data.get("parse") or data
    embedded = _embedded_by_offset(parse_obj if "embedded_images" in parse_obj else data.get("parse") or {})
    refs: list[CarrierBlobRef] = []
    for rec in files:
        if not isinstance(rec, dict):
            continue
        path = rec.get("path")
        po = rec.get("payload_offset")
        pe = rec.get("payload_end")
        if not isinstance(path, str) or not isinstance(po, int) or not isinstance(pe, int):
            continue
        file_len = pe - po
        if file_len <= 0:
            continue
        refs.append(
            _carrier_ref_row(
                path=path,
                po=po,
                pe=pe,
                file_len=file_len,
                embedded=embedded,
                body=body,
                release_label=release_label,
                pkgstream_path=pkgstream_path,
            )
        )
    return refs


def load_carrier_refs_from_pkgstream(
    pkgstream_path: Path,
    *,
    release_label: str | None = None,
    verify: bool = True,
) -> list[CarrierBlobRef]:
    """Build refs from one on-disk ``.pkgstream`` (optional ``lib2spy`` verify)."""
    p = Path(pkgstream_path).expanduser().resolve()
    label = release_label if release_label else p.parent.name
    if verify:
        from lib2spy.pkgstream_verify import verify_pkgstream

        report = verify_pkgstream(p)
        data = report.to_json()
        parse_bit = {
            "embedded_images": [
                {"offset": img["offset"], "size": img["size"], "name": img["name"]}
                for img in analyze_pkgstream_embedded_only(p)
            ]
        }
        data["parse"] = parse_bit
    else:
        from lib2spy.native_pkgstream import analyze_pkgstream

        data = analyze_pkgstream(p, verify=False)
    body = p.read_bytes() if p.is_file() else None
    return _refs_from_lib2spy_dict(
        data,
        body=body,
        release_label=label,
        pkgstream_path=str(p),
    )


def analyze_pkgstream_embedded_only(pkgstream_path: Path) -> list[dict[str, Any]]:
    from lib2spy.native_pkgstream import analyze_pkgstream

    return list(analyze_pkgstream(pkgstream_path, verify=False).get("embedded_images") or [])


def iter_00d09e_install_pkgstreams(firmware_00d09e: Path) -> list[tuple[str, Path]]:
    """
    Discover AT&T 5268 **install** carriers under ``firmware/00D09E`` (device_code tree).

    Matches ``*install*.pkgstream``, ``5268.install.pkgstream``, and
    ``att-5268-*-install.pkgstream``; skips cert/config-only bundles.
    """
    root = Path(firmware_00d09e).expanduser().resolve()
    if not root.is_dir():
        return []
    found: list[tuple[str, Path]] = []
    for p in sorted(root.rglob("*.pkgstream")):
        low = p.name.lower()
        if not (
            "install" in low
            or low == "5268.install.pkgstream"
            or (low.startswith("att-5268") and "install" in low)
        ):
            continue
        if "cert" in low or low.startswith("att_config") or low.startswith("att_cms"):
            continue
        found.append((p.parent.name, p))
    return found


def load_carrier_refs_collection(
    firmware_00d09e: Path,
    *,
    carrier_index_json: Path | None = None,
    only_paths: tuple[str, ...] = ("/rwdata/tmp/sys2/rootimage.img", "/rwdata/tmp/sys2/ui.img"),
) -> list[CarrierBlobRef]:
    """
    Load squash FILE refs from every install ``.pkgstream`` under ``00D09E``.

    Uses cached index JSON when present and ``carrier_index_json`` is set; otherwise
    runs ``lib2spy`` verify per carrier (slow — use ``build_carrier_index`` first).
    """
    if carrier_index_json is not None and Path(carrier_index_json).is_file():
        return load_carrier_refs_from_index(Path(carrier_index_json), only_paths=only_paths)

    refs: list[CarrierBlobRef] = []
    for label, ps in iter_00d09e_install_pkgstreams(firmware_00d09e):
        for r in load_carrier_refs_from_pkgstream(ps, release_label=label):
            if only_paths and r.path not in only_paths:
                continue
            if r.strict_squash_sha256 or r.file_payload_sha256:
                refs.append(r)
    return refs


def build_carrier_index(
    firmware_00d09e: Path,
    out_json: Path,
    *,
    only_paths: tuple[str, ...] = ("/rwdata/tmp/sys2/rootimage.img", "/rwdata/tmp/sys2/ui.img"),
) -> dict[str, Any]:
    """Precompute per-release squash digests; write JSON cache for fast ``paceflash`` runs."""
    rows: list[dict[str, Any]] = []
    for label, ps in iter_00d09e_install_pkgstreams(firmware_00d09e):
        for r in load_carrier_refs_from_pkgstream(ps, release_label=label):
            if only_paths and r.path not in only_paths:
                continue
            if not r.strict_squash_sha256 and not r.file_payload_sha256:
                continue
            rows.append(asdict(r))
    doc = {
        "firmware_root": str(Path(firmware_00d09e).resolve()),
        "carrier_count": len(iter_00d09e_install_pkgstreams(firmware_00d09e)),
        "refs": rows,
    }
    out = Path(out_json).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return doc


def load_carrier_refs_from_index(
    index_json: Path,
    *,
    only_paths: tuple[str, ...] = ("/rwdata/tmp/sys2/rootimage.img", "/rwdata/tmp/sys2/ui.img"),
) -> list[CarrierBlobRef]:
    doc = json.loads(Path(index_json).expanduser().read_text(encoding="utf-8"))
    refs: list[CarrierBlobRef] = []
    for row in doc.get("refs") or []:
        if not isinstance(row, dict):
            continue
        r = CarrierBlobRef(**{k: row[k] for k in CarrierBlobRef.__dataclass_fields__ if k in row})
        if only_paths and r.path not in only_paths:
            continue
        refs.append(r)
    return refs


def find_squash_fingerprint_in_blob(
    blob: bytes,
    refs: list[CarrierBlobRef],
    *,
    source_label: str,
) -> list[CorrelationHit]:
    """
    Scan ``blob`` for ``hsqs`` superblocks; match strict ``bytes_used`` span (then FILE payload span).
    """
    if not refs:
        return []
    strict_targets: dict[str, list[CarrierBlobRef]] = {}
    for r in refs:
        if r.strict_squash_sha256:
            strict_targets.setdefault(r.strict_squash_sha256, []).append(r)
    file_targets: dict[str, list[CarrierBlobRef]] = {}
    for r in refs:
        if r.file_payload_sha256:
            file_targets.setdefault(r.file_payload_sha256, []).append(r)
    hits: list[CorrelationHit] = []
    seen: set[tuple[str, int, str]] = set()

    for off in find_squashfs_superblock_offsets(blob):
        span = squashfs_le_span_at(blob, off)
        if span is not None:
            sb_off, length = span
            digest = _sha256_hex(blob[sb_off : sb_off + length])
            for ref in strict_targets.get(digest, ()):
                key = (source_label, sb_off, "strict_squash", ref.release_label, ref.path)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    CorrelationHit(
                        source_label=source_label,
                        hsqs_offset=sb_off,
                        matched_path=ref.path,
                        match_kind="strict_squash",
                        sha256=digest,
                        span_len=length,
                        release_label=ref.release_label,
                        pkgstream_path=ref.pkgstream_path,
                    )
                )
            if strict_targets.get(digest):
                continue
        flen_candidates = {r.file_payload_len for r in refs if r.file_payload_sha256}
        for flen in sorted(flen_candidates, reverse=True):
            if off + flen > len(blob):
                continue
            digest = _sha256_hex(blob[off : off + flen])
            for ref in file_targets.get(digest, ()):
                if ref.file_payload_len != flen:
                    continue
                key = (source_label, off, f"file_payload:{ref.release_label}:{ref.path}")
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    CorrelationHit(
                        source_label=source_label,
                        hsqs_offset=off,
                        matched_path=ref.path,
                        match_kind="file_payload",
                        sha256=digest,
                        span_len=flen,
                        release_label=ref.release_label,
                        pkgstream_path=ref.pkgstream_path,
                    )
                )
    return hits


#region kernel_adjacent correlation_suggests_chain_aware
def correlation_suggests_chain_aware(hits: list[CorrelationHit]) -> bool:
    """True when strict squash appears on linear/ext2 file view but not on BBM-assembled virt slice."""
    strict_bbm = any(h.match_kind == "strict_squash" and h.source_label == "bbm_virt" for h in hits)
    strict_linear = any(
        h.match_kind == "strict_squash"
        and h.source_label in ("linear_tlpart", "linear_flash_tlpart")
        for h in hits
    )
    strict_ext2 = any(
        h.match_kind == "strict_squash" and h.source_label.startswith("ext2_file:")
        for h in hits
    )
    return correlation_suggests_chain_aware_from_hits(
        strict_on_bbm_virt=strict_bbm,
        strict_on_linear=strict_linear,
        strict_on_ext2_file=strict_ext2 and not strict_bbm,
    )


#endregion


#region kernel_adjacent best_dissect_hint
def best_dissect_hint(hits: list[CorrelationHit]) -> dict[str, Any] | None:
    """Prefer strict squash on ``bbm_virt``, then other TL views, then ``ext2_file:*``."""
    for src in ("bbm_virt", "linear_tlpart", "linear_flash_tlpart"):
        for h in hits:
            if h.source_label == src and h.match_kind == "strict_squash":
                return {
                    "source": src,
                    "read_model": "tl_slice_raw_hsqs",
                    "squashfs_superblock_offset": h.hsqs_offset,
                    "squashfs_image_bytes": h.span_len,
                    "matched_path": h.matched_path,
                    "match_kind": h.match_kind,
                    "sha256": h.sha256,
                    "release_label": h.release_label,
                    "pkgstream_path": h.pkgstream_path,
                }
    for h in hits:
        if h.source_label.startswith("ext2_file:") and h.match_kind == "strict_squash":
            return {
                "source": h.source_label,
                "read_model": "ext2_file_extract",
                "squashfs_superblock_offset": h.hsqs_offset,
                "squashfs_image_bytes": h.span_len,
                "matched_path": h.matched_path,
                "match_kind": h.match_kind,
                "sha256": h.sha256,
                "release_label": h.release_label,
                "pkgstream_path": h.pkgstream_path,
            }
    return None


#endregion


def summarize_release_matches(hits: list[CorrelationHit]) -> list[dict[str, Any]]:
    """Unique releases with any hit, ordered by first sighting."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for h in hits:
        if not h.release_label or h.release_label in seen:
            continue
        seen.add(h.release_label)
        out.append(
            {
                "release_label": h.release_label,
                "pkgstream_path": h.pkgstream_path,
                "matched_path": h.matched_path,
                "match_kind": h.match_kind,
                "nand_source": h.source_label,
                "hsqs_offset": h.hsqs_offset,
            }
        )
    return out


def run_sources_correlation(
    sources: list[tuple[str, bytes]],
    refs: list[CarrierBlobRef],
) -> tuple[list[CorrelationHit], dict[str, Any]]:
    """Run fingerprint scan on each carve source; build JSON-serializable report."""
    all_hits: list[CorrelationHit] = []
    per_source: list[dict[str, Any]] = []
    for src_name, blob in sources:
        src_hits = find_squash_fingerprint_in_blob(blob, refs, source_label=src_name)
        all_hits.extend(src_hits)
        per_source.append(
            {
                "source": src_name,
                "blob_len": len(blob),
                "hits": [asdict(h) for h in src_hits],
            }
        )
    warnings: list[str] = []
    strict_paths = {r.path for r in refs if r.strict_squash_sha256}
    matched_strict = {h.matched_path for h in all_hits if h.match_kind == "strict_squash"}
    for p in strict_paths - matched_strict:
        warnings.append(f"no strict_squash SHA match in NAND views for carrier path {p!r}")
    file_only = [
        h
        for h in all_hits
        if h.match_kind == "file_payload"
        and h.matched_path not in matched_strict
    ]
    if file_only:
        warnings.append(
            "file_payload SHA matched without strict_squash (possible FILE TLV trailer on NAND) "
            f"— paths: {sorted({h.matched_path for h in file_only})}"
        )
    if not all_hits:
        warnings.append(
            "no carrier fingerprint matched any TL read view in the scanned TL child slice "
            "(default opentla4). lib2sp stages FILE TLVs under /rwdata/tmp/sys2/ on the UBIFS "
            "rw volume — not inside opentla4 — so a miss is expected until promote/TL programming "
            "or if this dump predates the 532678 install. Also check firmware version vs pkgstream."
        )

    release_matches = summarize_release_matches(all_hits)
    if release_matches:
        warnings.insert(
            0,
            f"NAND matched {len(release_matches)} carrier release(s): "
            + ", ".join(r["release_label"] for r in release_matches),
        )
    elif refs and any(r.release_label for r in refs):
        warnings.append(
            f"no match among {len({r.release_label for r in refs if r.release_label})} "
            "indexed carrier releases — dump may predate install or squash not in opentla4 slice"
        )

    return all_hits, _correlation_report_dict(
        all_hits, refs, per_source, warnings, release_matches
    )


def _correlation_report_dict(
    all_hits: list[CorrelationHit],
    refs: list[CarrierBlobRef],
    per_source: list[dict[str, Any]],
    warnings: list[str],
    release_matches: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "carrier_ref_count": len(refs),
        "carrier_releases_indexed": sorted({r.release_label for r in refs if r.release_label}),
        "carrier_refs": [asdict(r) for r in refs],
        "per_source": per_source,
        "best_dissect_hint": best_dissect_hint(all_hits),
        "matched_releases": release_matches,
        "suggests_chain_aware": correlation_suggests_chain_aware(all_hits),
        "warnings": warnings,
    }


def run_correlation_with_ext2_files(
    tl_sources: list[tuple[str, bytes]],
    ext2_sources: list[tuple[str, bytes]],
    refs: list[CarrierBlobRef],
    *,
    ext2_probe_rows: list[dict[str, Any]] | None = None,
) -> tuple[list[CorrelationHit], dict[str, Any]]:
    """
    Correlate carrier digests against TL slice views and ext2-extracted image files.

    ``ext2_sources`` use labels like ``ext2_file:sys1/rootimage.img``.
    """
    slice_hits, report = run_sources_correlation(tl_sources, refs)
    ext2_hits: list[CorrelationHit] = []
    ext2_per: list[dict[str, Any]] = []
    for label, blob in ext2_sources:
        src_hits = find_squash_fingerprint_in_blob(blob, refs, source_label=label)
        ext2_hits.extend(src_hits)
        ext2_per.append(
            {
                "source": label,
                "blob_len": len(blob),
                "read_model": "ext2_file_extract",
                "hits": [asdict(h) for h in src_hits],
            }
        )
    all_hits = slice_hits + ext2_hits
    warnings = list(report.get("warnings") or [])
    per_source = list(report.get("per_source") or []) + ext2_per

    slice_strict = {h.source_label for h in slice_hits if h.match_kind == "strict_squash"}
    ext2_strict = {h.source_label for h in ext2_hits if h.match_kind == "strict_squash"}
    if ext2_strict and not slice_strict:
        warnings.insert(
            0,
            "carrier strict_squash matched ext2 file extract only — flash image lives inside "
            "opentla4 ext2 (sys1/rootimage.img), not as raw hsqs at TL slice offset 0; "
            "BBM virt slice scan is the wrong read model",
        )
    elif ext2_strict and slice_strict:
        warnings.insert(
            0,
            "carrier strict_squash matched both TL slice views and ext2 file extract",
        )

    release_matches = summarize_release_matches(all_hits)
    hint = best_dissect_hint(all_hits)
    if hint is None and ext2_hits:
        hint = best_dissect_hint(ext2_hits)
        if isinstance(hint, dict):
            hint = {**hint, "read_model": "ext2_file_extract"}

    out = _correlation_report_dict(
        all_hits,
        refs,
        per_source,
        warnings,
        release_matches,
    )
    out["best_dissect_hint"] = hint
    out["read_models"] = {
        "tl_slice_raw_hsqs": bool(slice_hits),
        "ext2_file_extract": bool(ext2_sources),
        "ext2_file_probe": ext2_probe_rows or [],
    }
    if ext2_sources and not slice_hits:
        out["primary_read_model"] = "ext2_file_extract"
    elif slice_hits:
        out["primary_read_model"] = "tl_slice_raw_hsqs"
    else:
        out["primary_read_model"] = "carrier_file"
    return all_hits, out
