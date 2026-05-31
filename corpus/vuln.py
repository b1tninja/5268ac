"""Discover corpus Syft SBOMs and run Grype vulnerability scans."""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator, List, Optional, Sequence

from corpus.index_db import collection_slug_for_fs, normalize_collection_slug
from corpus.sbom import safe_sbom_name

CATALOG_FILENAME = "corpus_sbom_catalog.jsonl"
GRYPE_REPORT_SUFFIX = ".grype.json"
_SYFT_JSON_SUFFIX = ".syft.json"
_HASH_TAIL_RE = re.compile(r"_[0-9a-f]{16}\.syft\.json$", re.I)


@dataclass
class SbomEntry:
    """One Syft SBOM file on disk."""

    path: Path
    collection_fs: Optional[str] = None
    collection_slug: Optional[str] = None
    source_hint: Optional[str] = None
    bytes: int = 0
    package_count: Optional[int] = None
    source_mode: Optional[str] = None
    image_key: Optional[str] = None
    grype_report: Optional[Path] = None
    grype_summary: Optional[dict[str, Any]] = field(default=None, repr=False)

    def grype_spec(self) -> str:
        return f"sbom:{self.path.resolve().as_posix()}"

    def default_grype_report_path(self) -> Path:
        name = self.path.name
        if name.endswith(_SYFT_JSON_SUFFIX):
            base = name[: -len(_SYFT_JSON_SUFFIX)]
            return self.path.with_name(base + GRYPE_REPORT_SUFFIX)
        return self.path.with_suffix(GRYPE_REPORT_SUFFIX)


def default_sbom_root(repo_root: Path) -> Path:
    from corpus.paths import default_sbom_dir

    return default_sbom_dir(repo_root)


def _collection_slug_from_fs_dir(name: str) -> Optional[str]:
    if name.startswith("version_"):
        ver = name[len("version_") :].replace("__", "/")
        return f"version:{ver}"
    return None


def _source_hint_from_sbom_name(filename: str) -> str:
    stem = filename
    if stem.endswith(_SYFT_JSON_SUFFIX):
        stem = stem[: -len(_SYFT_JSON_SUFFIX)]
    stem = _HASH_TAIL_RE.sub("", stem)
    return stem.lstrip("_")


def syft_package_count(path: Path, *, max_read: int = 4_000_000) -> Optional[int]:
    """Best-effort artifact count without loading huge JSON fully when possible."""
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if len(raw) > max_read:
        raw = raw[:max_read]
    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    artifacts = payload.get("artifacts")
    if isinstance(artifacts, list):
        return len(artifacts)
    return None


def summarize_grype_report(path: Path) -> dict[str, Any]:
    """Summarize a Grype JSON report (severity counts + top CVE ids)."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as e:
        return {"ok": False, "error": str(e), "path": str(path)}

    matches = payload.get("matches")
    if not isinstance(matches, list):
        matches = []

    by_severity: dict[str, int] = {}
    cve_ids: list[str] = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        vuln = match.get("vulnerability")
        if not isinstance(vuln, dict):
            continue
        sev = str(vuln.get("severity") or "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        vid = vuln.get("id")
        if isinstance(vid, str) and vid.startswith("CVE-") and vid not in cve_ids:
            cve_ids.append(vid)

    return {
        "ok": True,
        "path": str(path),
        "match_count": len(matches),
        "by_severity": by_severity,
        "sample_cves": cve_ids[:12],
    }


def _scan_roots(sbom_root: Path, collection_slug: Optional[str]) -> List[Path]:
    sbom_root = sbom_root.resolve()
    if not sbom_root.is_dir():
        return []
    if collection_slug:
        sub = sbom_root / collection_slug_for_fs(collection_slug)
        return [sub] if sub.is_dir() else []
    return [sbom_root]


def _iter_syft_paths(root: Path) -> Iterator[Path]:
    if not root.is_dir():
        return
    for path in sorted(root.rglob(f"*{_SYFT_JSON_SUFFIX}")):
        parts = {p.lower() for p in path.parts}
        if "sources" in parts or "mounts" in parts:
            continue
        yield path


def iter_sbom_entries(
    sbom_root: Path,
    *,
    collection_slug: Optional[str] = None,
    term: Optional[str] = None,
) -> Iterator[SbomEntry]:
    """Yield SBOM files under *sbom_root*, optionally filtered."""
    term_l = term.lower() if term else None
    catalog = load_sbom_catalog(sbom_root, collection_slug=collection_slug)
    catalog_by_path = {row["sbom_path"]: row for row in catalog if row.get("sbom_path")}

    for scan_root in _scan_roots(sbom_root, collection_slug):
        collection_fs = scan_root.name if scan_root != sbom_root.resolve() else None
        coll_slug = _collection_slug_from_fs_dir(collection_fs) if collection_fs else None
        for path in _iter_syft_paths(scan_root):
            rel_key = str(path)
            hint = _source_hint_from_sbom_name(path.name)
            if term_l and term_l not in path.name.lower() and term_l not in hint.lower():
                if term_l not in rel_key.lower():
                    continue
            row = catalog_by_path.get(rel_key.replace("\\", "/")) or catalog_by_path.get(str(path))
            entry = SbomEntry(
                path=path,
                collection_fs=collection_fs,
                collection_slug=coll_slug,
                source_hint=hint,
                bytes=path.stat().st_size,
                package_count=syft_package_count(path),
                source_mode=(row or {}).get("source_mode"),
                image_key=(row or {}).get("image_key"),
            )
            report = entry.default_grype_report_path()
            if report.is_file():
                entry.grype_report = report
                entry.grype_summary = summarize_grype_report(report)
            yield entry


def sbom_paths_for_image_keys(
    image_keys: Sequence[str],
    sbom_root: Path,
    *,
    collection_slug: Optional[str] = None,
) -> List[Path]:
    """Resolve on-disk SBOM paths for corpus ``images.path`` keys."""
    sbom_root = sbom_root.resolve()
    roots: List[Path] = []
    if collection_slug:
        sub = sbom_root / collection_slug_for_fs(collection_slug)
        if sub.is_dir():
            roots.append(sub)
    if sbom_root.is_dir() and sbom_root not in roots:
        roots.append(sbom_root)

    out: List[Path] = []
    seen: set[str] = set()
    for image_key in image_keys:
        name = safe_sbom_name(image_key)
        for root in roots:
            for sub in ("", "mounted"):
                candidate = (root / sub / name) if sub else (root / name)
                key = str(candidate.resolve())
                if candidate.is_file() and key not in seen:
                    seen.add(key)
                    out.append(candidate)
    return out


def append_sbom_catalog(
    sbom_dir: Path,
    *,
    image_key: str,
    sbom_path: Path,
    source_mode: Optional[str] = None,
    package_count: Optional[int] = None,
) -> None:
    """Append one catalog row for faster ``--list-sboms`` / ``--sbom-for`` lookups."""
    sbom_dir = Path(sbom_dir).resolve()
    sbom_dir.mkdir(parents=True, exist_ok=True)
    catalog = sbom_dir / CATALOG_FILENAME
    row = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "image_key": image_key,
        "sbom_path": str(sbom_path.resolve()).replace("\\", "/"),
        "source_mode": source_mode,
        "package_count": package_count,
    }
    with catalog.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_sbom_catalog(
    sbom_root: Path,
    *,
    collection_slug: Optional[str] = None,
) -> List[dict[str, Any]]:
    """Load catalog JSONL rows from collection dir(s)."""
    sbom_root = sbom_root.resolve()
    paths: List[Path] = []
    if collection_slug:
        sub = sbom_root / collection_slug_for_fs(collection_slug)
        paths.append(sub / CATALOG_FILENAME)
    paths.append(sbom_root / CATALOG_FILENAME)

    rows: List[dict[str, Any]] = []
    seen: set[str] = set()
    for catalog in paths:
        if not catalog.is_file():
            continue
        try:
            text = catalog.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = str(row.get("sbom_path") or "")
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
    return rows


def run_grype(
    sbom_path: Path,
    *,
    grype_bin: str = "grype",
    output_format: str = "table",
    report_path: Optional[Path] = None,
    fail_on: Optional[str] = None,
    db_update: bool = False,
    quiet: bool = False,
    only_fixed: bool = False,
    skip_existing: bool = False,
    timeout_s: int = 900,
    extra_args: Optional[Sequence[str]] = None,
) -> dict[str, Any]:
    """Run Grype against one Syft SBOM file."""
    sbom_path = Path(sbom_path).resolve()
    if not sbom_path.is_file():
        return {"ok": False, "error": f"SBOM not found: {sbom_path}", "sbom": str(sbom_path)}

    out_path = Path(report_path).resolve() if report_path else None
    if skip_existing and out_path is not None and out_path.is_file():
        if out_path.stat().st_mtime >= sbom_path.stat().st_mtime:
            summary = summarize_grype_report(out_path)
            return {
                "ok": True,
                "cached": True,
                "sbom": str(sbom_path),
                "report": str(out_path),
                "summary": summary,
                "grype_spec": f"sbom:{sbom_path.as_posix()}",
            }

    spec = f"sbom:{sbom_path.as_posix()}"
    cmd: List[str] = [grype_bin, spec]
    if quiet:
        cmd.append("-q")
    fmt = output_format.lower()
    if fmt == "json":
        cmd.extend(["-o", "json"])
        if out_path is not None:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            cmd.extend(["--file", str(out_path)])
    else:
        cmd.extend(["-o", fmt])
    if fail_on:
        cmd.extend(["--fail-on", fail_on])
    if only_fixed:
        cmd.append("--only-fixed")
    if extra_args:
        cmd.extend(list(extra_args))

    if db_update:
        try:
            db_proc = subprocess.run(
                [grype_bin, "db", "update"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_s,
            )
        except FileNotFoundError:
            return {
                "ok": False,
                "error": f"{grype_bin!r} not found on PATH",
                "sbom": str(sbom_path),
                "grype_spec": spec,
            }
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "error": "grype db update timed out",
                "sbom": str(sbom_path),
                "grype_spec": spec,
            }
        if db_proc.returncode != 0:
            msg = (db_proc.stderr or db_proc.stdout or f"exit {db_proc.returncode}").strip()
            return {
                "ok": False,
                "error": f"grype db update failed: {msg}",
                "sbom": str(sbom_path),
                "grype_spec": spec,
            }

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
    except FileNotFoundError:
        return {
            "ok": False,
            "error": f"{grype_bin!r} not found on PATH",
            "sbom": str(sbom_path),
            "grype_spec": spec,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "grype timed out",
            "sbom": str(sbom_path),
            "grype_spec": spec,
        }

    result: dict[str, Any] = {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "sbom": str(sbom_path),
        "grype_spec": spec,
        "stdout": (proc.stdout or "")[-8000:],
        "stderr": (proc.stderr or "")[-4000:],
    }
    if out_path is not None and out_path.is_file():
        result["report"] = str(out_path)
        result["summary"] = summarize_grype_report(out_path)
    elif fmt != "json" and proc.stdout:
        result["table"] = proc.stdout
    if proc.returncode != 0 and not result.get("error"):
        result["error"] = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()[-2000:]
    return result


def entries_to_rows(entries: Sequence[SbomEntry], *, repo_root: Optional[Path] = None) -> List[dict[str, Any]]:
    rows: List[dict[str, Any]] = []
    for ent in entries:
        row = asdict(ent)
        row["path"] = str(ent.path)
        if ent.grype_report is not None:
            row["grype_report"] = str(ent.grype_report)
        if repo_root is not None:
            try:
                row["path"] = str(ent.path.resolve().relative_to(repo_root.resolve()))
            except ValueError:
                pass
        row["grype_spec"] = ent.grype_spec()
        rows.append(row)
    return rows


def resolve_collection_slug_arg(slug: Optional[str]) -> Optional[str]:
    if not slug:
        return None
    from corpus.index_db import resolve_collection_slug_arg as _resolve

    return _resolve(slug)


__all__ = [
    "SbomEntry",
    "append_sbom_catalog",
    "default_sbom_root",
    "entries_to_rows",
    "iter_sbom_entries",
    "load_sbom_catalog",
    "resolve_collection_slug_arg",
    "run_grype",
    "sbom_paths_for_image_keys",
    "summarize_grype_report",
    "syft_package_count",
]
