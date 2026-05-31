"""Secret detection during corpus indexing and optional Gitleaks scans."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, List, Optional, Sequence

from corpus.sbom import safe_sbom_name

CATALOG_FILENAME = "corpus_secrets_catalog.jsonl"
GITLEAKS_REPORT_SUFFIX = ".gitleaks.json"
_MAX_SNIPPET = 512
_MAX_MATCHES_PER_FILE = 64


@dataclass(frozen=True, slots=True)
class SecretRule:
    rule_id: str
    description: str
    pattern: re.Pattern[str]
    severity: str = "high"


@dataclass(frozen=True, slots=True)
class SecretMatch:
    rule_id: str
    severity: str
    path: str
    line_no: Optional[int]
    byte_offset: int
    snippet: str
    description: str

    def fingerprint(self) -> str:
        core = f"{self.rule_id}\0{self.path}\0{self.byte_offset}\0{self.snippet[:120]}"
        return hashlib.sha256(core.encode("utf-8", errors="replace")).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_secret_rules() -> tuple[SecretRule, ...]:
    """Firmware- and gateway-relevant patterns (5268AC lab corpus)."""
    flags = re.MULTILINE
    return (
        SecretRule(
            "pem_private_key",
            "PEM private key block",
            re.compile(
                r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                flags,
            ),
            "critical",
        ),
        SecretRule(
            "pem_encrypted_private_key",
            "PEM encrypted private key",
            re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----", flags),
            "critical",
        ),
        SecretRule(
            "pkcs12_board_param",
            "board_param PKCS#12 (lightspeed/device)",
            re.compile(
                r"(?:lightspeed|device)_p12=[A-Za-z0-9+/=\s]{80,}",
                flags,
            ),
            "critical",
        ),
        SecretRule(
            "gw_devkey",
            "Pace gw:devkey",
            re.compile(r"gw:devkey=[^\s\x00\n\r]{8,}", flags),
            "critical",
        ),
        SecretRule(
            "gw_authcode",
            "Pace gw:authcode",
            re.compile(r"gw:authcode=[^\s\x00\n\r]{4,}", flags),
            "high",
        ),
        SecretRule(
            "gw_accesscode",
            "Pace gw:accesscode",
            re.compile(r"gw:accesscode=[^\s\x00\n\r]{4,}", flags),
            "high",
        ),
        SecretRule(
            "gw_trust_engcert",
            "Pace gw:trust_engcert blob",
            re.compile(r"gw:trust_engcert=[A-Za-z0-9+/=]{40,}", flags),
            "high",
        ),
        SecretRule(
            "aws_access_key_id",
            "AWS access key id",
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            "high",
        ),
        SecretRule(
            "generic_api_key",
            "api_key / api-key assignment",
            re.compile(
                r"(?i)\bapi[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
                flags,
            ),
            "medium",
        ),
        SecretRule(
            "password_assignment",
            "password= in config/script",
            re.compile(
                r"(?i)\bpassword\s*[:=]\s*['\"]?[^\s'\"\x00]{8,}",
                flags,
            ),
            "medium",
        ),
        SecretRule(
            "bearer_token",
            "Bearer token header/value",
            re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.]{20,}", flags),
            "high",
        ),
    )


def _line_number(data: bytes, offset: int) -> Optional[int]:
    if offset < 0 or offset > len(data):
        return None
    return data[:offset].count(b"\n") + 1


def _snippet(data: bytes, start: int, end: int) -> str:
    chunk = data[max(0, start) : min(len(data), end)]
    try:
        text = chunk.decode("utf-8", errors="replace")
    except Exception:
        text = repr(chunk)
    text = text.replace("\r", " ").replace("\n", " ")
    if len(text) > _MAX_SNIPPET:
        return text[: _MAX_SNIPPET - 3] + "..."
    return text


def scan_bytes(
    data: bytes,
    path: str,
    *,
    rules: Sequence[SecretRule] | None = None,
) -> list[SecretMatch]:
    """Run secret rules on raw file bytes."""
    if not data:
        return []
    rule_list = list(rules) if rules is not None else list(default_secret_rules())
    try:
        text = data.decode("utf-8", errors="surrogateescape")
    except Exception:
        text = data.decode("latin-1", errors="replace")

    out: list[SecretMatch] = []
    seen: set[str] = set()
    for rule in rule_list:
        count = 0
        for m in rule.pattern.finditer(text):
            if count >= _MAX_MATCHES_PER_FILE:
                break
            start = m.start()
            end = m.end()
            snip = _snippet(data, start, min(len(data), end + 80))
            match = SecretMatch(
                rule_id=rule.rule_id,
                severity=rule.severity,
                path=path,
                line_no=_line_number(data, start),
                byte_offset=start,
                snippet=snip,
                description=rule.description,
            )
            fp = match.fingerprint()
            if fp in seen:
                continue
            seen.add(fp)
            out.append(match)
            count += 1
    return out


def index_secret_matches(
    conn: Any,
    *,
    image_id: int,
    file_id: Optional[int],
    path: str,
    matches: Sequence[SecretMatch],
    indexed_at: Optional[str] = None,
) -> int:
    """Insert rows into ``secret_findings``; skip duplicates by fingerprint."""
    if not matches:
        return 0
    when = indexed_at or _utc_now()
    n = 0
    for m in matches:
        cur = conn.execute(
            "INSERT OR IGNORE INTO secret_findings("
            "image_id, file_id, path, rule_id, severity, line_no, byte_offset, snippet, fingerprint, indexed_at"
            ") VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                image_id,
                file_id,
                path,
                m.rule_id,
                m.severity,
                m.line_no,
                m.byte_offset,
                m.snippet,
                m.fingerprint(),
                when,
            ),
        )
        if cur.rowcount:
            n += 1
    return n


def scan_and_index_file_secrets(
    conn: Any,
    *,
    image_id: int,
    file_id: Optional[int],
    path: str,
    data: bytes,
    rules: Sequence[SecretRule] | None = None,
) -> int:
    matches = scan_bytes(data, path, rules=rules)
    return index_secret_matches(
        conn, image_id=image_id, file_id=file_id, path=path, matches=matches
    )


def summarize_secrets_for_image(conn: Any, image_id: int) -> dict[str, Any]:
    rows = conn.execute(
        "SELECT rule_id, severity, COUNT(*) AS n FROM secret_findings "
        "WHERE image_id = ? GROUP BY rule_id, severity ORDER BY n DESC",
        (image_id,),
    ).fetchall()
    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    total = 0
    for row in rows:
        rid = str(row["rule_id"])
        sev = str(row["severity"])
        n = int(row["n"])
        by_rule[rid] = by_rule.get(rid, 0) + n
        by_severity[sev] = by_severity.get(sev, 0) + n
        total += n
    return {
        "image_id": image_id,
        "total": total,
        "by_rule": by_rule,
        "by_severity": by_severity,
    }


def export_image_secrets_report(
    conn: Any,
    image_id: int,
    image_key: str,
    report_path: Path,
) -> dict[str, Any]:
    rows = conn.execute(
        "SELECT path, rule_id, severity, line_no, byte_offset, snippet "
        "FROM secret_findings WHERE image_id = ? ORDER BY path, byte_offset",
        (image_id,),
    ).fetchall()
    findings = [dict(row) for row in rows]
    payload = {
        "image_key": image_key,
        "image_id": image_id,
        "exported_at": _utc_now(),
        "summary": summarize_secrets_for_image(conn, image_id),
        "findings": findings,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def append_secrets_catalog(
    secrets_dir: Path,
    *,
    image_key: str,
    report_path: Path,
    source_mode: str = "inline",
    finding_count: Optional[int] = None,
) -> None:
    secrets_dir.mkdir(parents=True, exist_ok=True)
    catalog = secrets_dir / CATALOG_FILENAME
    row = {
        "ts": _utc_now(),
        "image_key": image_key,
        "report_path": str(report_path.resolve()).replace("\\", "/"),
        "source_mode": source_mode,
        "finding_count": finding_count,
    }
    with catalog.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_secrets_catalog(
    secrets_dir: Path,
    *,
    image_key: Optional[str] = None,
) -> list[dict[str, Any]]:
    catalog = secrets_dir / CATALOG_FILENAME
    if not catalog.is_file():
        return []
    out: list[dict[str, Any]] = []
    for line in catalog.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if image_key and row.get("image_key") != image_key:
            continue
        out.append(row)
    return out


@dataclass
class SecretReportEntry:
    path: Path
    image_key: Optional[str] = None
    finding_count: int = 0
    source_mode: Optional[str] = None
    by_severity: dict[str, int] = field(default_factory=dict)
    gitleaks_report: Optional[Path] = None


def iter_secret_report_entries(
    secrets_dir: Path,
    *,
    collection_slug: Optional[str] = None,
    term: Optional[str] = None,
) -> Iterator[SecretReportEntry]:
    from corpus.index_db import collection_slug_for_fs

    secrets_dir = secrets_dir.resolve()
    if not secrets_dir.is_dir():
        return
    term_l = term.lower() if term else None
    catalog = {r["image_key"]: r for r in load_secrets_catalog(secrets_dir) if r.get("image_key")}

    roots: list[Path] = [secrets_dir]
    if collection_slug:
        sub = secrets_dir / collection_slug_for_fs(collection_slug)
        if sub.is_dir():
            roots = [sub]

    seen: set[str] = set()
    for root in roots:
        for path in sorted(root.rglob("*.secrets.json")):
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            try:
                payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            image_key = payload.get("image_key")
            if isinstance(image_key, str) and collection_slug:
                from corpus.buildroot import collection_slug_from_image_path

                slug = collection_slug_from_image_path(image_key)
                if slug != collection_slug:
                    continue
            hint = path.name
            if term_l and term_l not in hint.lower():
                if not image_key or term_l not in str(image_key).lower():
                    continue
            summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
            entry = SecretReportEntry(
                path=path,
                image_key=str(image_key) if image_key else None,
                finding_count=int(summary.get("total") or 0),
                source_mode=(catalog.get(str(image_key)) or {}).get("source_mode"),
                by_severity=dict(summary.get("by_severity") or {}),
                gitleaks_report=path.with_suffix(GITLEAKS_REPORT_SUFFIX)
                if path.with_suffix(GITLEAKS_REPORT_SUFFIX).is_file()
                else None,
            )
            yield entry


def run_gitleaks_directory(
    source_dir: Path,
    report_path: Path,
    *,
    gitleaks_bin: str = "gitleaks",
    timeout_s: int = 900,
) -> dict[str, Any]:
    """Run ``gitleaks detect --no-git`` on a directory tree."""
    source_dir = source_dir.resolve()
    report_path = report_path.resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    if not source_dir.is_dir():
        return {"ok": False, "error": f"not a directory: {source_dir}"}
    if report_path.is_file() and report_path.stat().st_size > 0:
        return {"ok": True, "cached": True, "path": str(report_path)}

    cmd = [
        gitleaks_bin,
        "detect",
        "--source",
        str(source_dir),
        "--no-git",
        "--report-path",
        str(report_path),
        "--report-format",
        "json",
        "--exit-code",
        "0",
    ]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except FileNotFoundError:
        return {"ok": False, "error": f"{gitleaks_bin!r} not found on PATH"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "gitleaks timed out", "elapsed_s": timeout_s}

    elapsed = time.monotonic() - started
    if proc.returncode not in (0, 1):
        err = (proc.stderr or proc.stdout or "").strip()[:500]
        return {
            "ok": False,
            "error": err or f"gitleaks exit {proc.returncode}",
            "elapsed_s": elapsed,
        }
    if not report_path.is_file():
        report_path.write_text("[]", encoding="utf-8")
    try:
        findings = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
        count = len(findings) if isinstance(findings, list) else 0
    except json.JSONDecodeError:
        count = None
    return {
        "ok": True,
        "path": str(report_path),
        "finding_count": count,
        "elapsed_s": elapsed,
        "cached": False,
    }


def ingest_gitleaks_report_into_db(
    conn: Any,
    *,
    image_id: int,
    image_key: str,
    report_path: Path,
) -> int:
    """Map Gitleaks JSON findings into ``secret_findings`` (best-effort)."""
    try:
        raw = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return 0
    if not isinstance(raw, list):
        return 0
    matches: list[SecretMatch] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        rel = str(item.get("File") or item.get("file") or "")
        rule = str(item.get("RuleID") or item.get("Description") or "gitleaks")
        secret = str(item.get("Secret") or item.get("Match") or "")[:_MAX_SNIPPET]
        line = item.get("StartLine") or item.get("startLine")
        line_no = int(line) if line is not None else None
        offset = int(item.get("StartColumn") or 0)
        matches.append(
            SecretMatch(
                rule_id=f"gitleaks:{rule}",
                severity="high",
                path=rel or image_key,
                line_no=line_no,
                byte_offset=offset,
                snippet=secret,
                description=f"gitleaks:{rule}",
            )
        )
    return index_secret_matches(
        conn, image_id=image_id, file_id=None, path=image_key, matches=matches
    )


def scan_secrets_for_database(
    conn: Any,
    *,
    collection_slug: Optional[str] = None,
    secrets_dir: Optional[Path] = None,
    progress: Optional[Any] = None,
) -> dict[str, Any]:
    """
    Re-export per-image secret reports from the DB (no byte re-scan).

    Finding rows are written during ``--build-index --secrets``; this command
    only refreshes JSON reports under *secrets_dir*.
    """
    from corpus.index_db import collection_image_filter_sql

    coll_sql = ""
    coll_args: tuple[Any, ...] = ()
    if collection_slug:
        coll_sql, coll_args = collection_image_filter_sql(collection_slug, image_alias="i")

    rows = conn.execute(
        "SELECT id, path FROM images i" + coll_sql,
        coll_args,
    ).fetchall()
    exported = 0
    for row in rows:
        image_id = int(row["id"])
        image_key = str(row["path"])
        n = conn.execute(
            "SELECT COUNT(*) FROM secret_findings WHERE image_id = ?",
            (image_id,),
        ).fetchone()[0]
        if not n:
            continue
        if secrets_dir is None:
            continue
        write_image_secrets_artifacts(
            conn,
            image_id=image_id,
            image_key=image_key,
            secrets_dir=secrets_dir,
            collection_slug=collection_slug,
        )
        exported += 1
        if progress:
            progress(f"# secrets export {image_key} findings={n}")
    return {
        "ok": True,
        "images_exported": exported,
        "collection": collection_slug,
    }


def write_image_secrets_artifacts(
    conn: Any,
    *,
    image_id: int,
    image_key: str,
    secrets_dir: Path,
    collection_slug: Optional[str] = None,
) -> Optional[Path]:
    """Export per-image JSON report and append catalog row."""
    from corpus.index_db import collection_slug_for_fs

    sub = secrets_dir
    if collection_slug:
        sub = secrets_dir / collection_slug_for_fs(collection_slug)
    report_path = sub / safe_sbom_name(image_key, suffix=".secrets.json")
    payload = export_image_secrets_report(conn, image_id, image_key, report_path)
    if int(payload["summary"].get("total") or 0) == 0:
        return report_path if report_path.is_file() else None
    append_secrets_catalog(
        secrets_dir,
        image_key=image_key,
        report_path=report_path,
        source_mode="inline",
        finding_count=int(payload["summary"]["total"]),
    )
    return report_path


__all__ = [
    "CATALOG_FILENAME",
    "GITLEAKS_REPORT_SUFFIX",
    "SecretMatch",
    "SecretReportEntry",
    "SecretRule",
    "append_secrets_catalog",
    "default_secret_rules",
    "export_image_secrets_report",
    "index_secret_matches",
    "ingest_gitleaks_report_into_db",
    "iter_secret_report_entries",
    "load_secrets_catalog",
    "run_gitleaks_directory",
    "scan_and_index_file_secrets",
    "scan_bytes",
    "scan_secrets_for_database",
    "summarize_secrets_for_image",
    "write_image_secrets_artifacts",
]
