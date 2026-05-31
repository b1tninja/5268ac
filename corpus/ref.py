"""Parse and format compact corpus refs (grep → cat)."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from corpus.index_db import (
    collection_image_prefix,
    collection_slug_from_image_path,
    image_collection_prefix_from_path,
)

_MD5_REF_RE = re.compile(r"^@([0-9a-fA-F]{32})$")
_SHA1_REF_RE = re.compile(r"^@([0-9a-fA-F]{40})$")
_UNKNOWN_REF_RE = re.compile(r"^@unknown/", re.IGNORECASE)
_LEGACY_STAGING_VERSION_RE = re.compile(
    r"(?:^|[/\\])version_(\d{1,2}\.\d{1,2}\.\d{1,6}(?:\.\d{1,6})?)(?:[/\\]|$)"
)
_SCOPE_PREFIXES = ("pkgstream:", "nand:", "buildroot:", "version:")


@dataclass(frozen=True)
class CorpusRef:
    scope: str
    image_id: Optional[str]
    file_path: str
    query: Dict[str, str]

    @property
    def canonical(self) -> str:
        return format_ref(
            self.scope,
            self.file_path,
            image_id=self.image_id,
            query=self.query or None,
        )


def image_short_id(conn: sqlite3.Connection, image_path: str) -> str:
    row = conn.execute(
        "SELECT md5, sha1 FROM images WHERE path = ?", (image_path,)
    ).fetchone()
    if row is not None:
        if row["md5"]:
            return str(row["md5"])[:12]
        if row["sha1"]:
            return str(row["sha1"])[:12]
    import hashlib

    return hashlib.md5(image_path.encode("utf-8")).hexdigest()[:12]


def legacy_version_scope_from_image_path(image_path: str) -> Optional[str]:
    """``work_corpus/.../version_11.14.1.533857/…`` staging paths without ``collection:`` keys."""
    m = _LEGACY_STAGING_VERSION_RE.search(image_path.replace("\\", "/"))
    if m:
        return f"version:{m.group(1)}"
    return None


def scope_from_image_path(image_path: str) -> Optional[str]:
    """Derive ref scope (``pkgstream:…``, ``nand:…``) from an indexed image key."""
    slug = collection_slug_from_image_path(image_path)
    if slug:
        if slug.startswith(_SCOPE_PREFIXES):
            return slug
        if slug.startswith("version:"):
            return slug
        return f"pkgstream:{slug}"
    return legacy_version_scope_from_image_path(image_path)


def format_ref(
    scope: str,
    file_path: str,
    *,
    image_id: Optional[str] = None,
    query: Optional[Dict[str, str]] = None,
) -> str:
    file_path = file_path.replace("\\", "/").lstrip("/")
    body = f"{scope}/{image_id}/{file_path}" if image_id else f"{scope}/{file_path}"
    if query:
        qs = "&".join(f"{k}={v}" for k, v in sorted(query.items()))
        return f"{body}?{qs}"
    return body


_RELEASE_TAIL_RE = re.compile(
    r".*(\d{1,2}\.\d{1,2}\.\d{1,6}(?:\.\d{1,6})?-(?:PROD|LAB|ALPHA|BETA|DEV|STAGING))$",
    re.IGNORECASE,
)


def parse_ref(ref: str) -> CorpusRef:
    ref = ref.strip()
    if not ref:
        raise ValueError("empty ref")

    m = _MD5_REF_RE.match(ref)
    if m:
        return CorpusRef(scope=f"@{m.group(1).lower()}", image_id=None, file_path="", query={})
    m = _SHA1_REF_RE.match(ref)
    if m:
        return CorpusRef(scope=f"@{m.group(1).lower()}", image_id=None, file_path="", query={})

    query: Dict[str, str] = {}
    if "?" in ref:
        ref, _, q = ref.partition("?")
        for k, vals in parse_qs(q, keep_blank_values=True).items():
            if vals:
                query[k] = vals[0]

    if _UNKNOWN_REF_RE.match(ref):
        body = ref[len("@unknown/") :]
        parts = [p for p in body.split("/") if p]
        if parts and _looks_like_image_id(parts[0]):
            return CorpusRef(
                scope="@unknown",
                image_id=parts[0],
                file_path=unquote("/".join(parts[1:])),
                query=query,
            )
        return CorpusRef(scope="@unknown", image_id=None, file_path=unquote(body), query=query)

    scope_prefix: Optional[str] = None
    body = ref
    for prefix in _SCOPE_PREFIXES:
        if ref.startswith(prefix):
            scope_prefix = prefix
            body = ref[len(prefix) :]
            break
    if scope_prefix is None:
        scope_prefix = "pkgstream:"
        body = ref

    if scope_prefix == "nand:":
        scope, image_id, file_path = _parse_nand_body(scope_prefix, body)
    elif scope_prefix == "version:":
        scope, image_id, file_path = _parse_version_body(scope_prefix, body)
    else:
        scope, image_id, file_path = _parse_slash_scope_body(scope_prefix, body)

    return CorpusRef(
        scope=scope,
        image_id=image_id,
        file_path=unquote(file_path),
        query=query,
    )


def _parse_version_body(scope_prefix: str, body: str) -> Tuple[str, Optional[str], str]:
    parts = [p for p in body.split("/") if p]
    if not parts:
        raise ValueError("ref missing file path")
    scope = f"{scope_prefix}{parts[0]}"
    rest = parts[1:]
    if rest and _looks_like_image_id(rest[0]):
        return scope, rest[0], "/".join(rest[1:])
    if len(rest) == 1:
        return scope, None, rest[0]
    return scope, None, "/".join(rest)


def _parse_nand_body(scope_prefix: str, body: str) -> Tuple[str, Optional[str], str]:
    parts = body.split("/")
    if len(parts) == 1:
        return f"{scope_prefix}{parts[0]}", None, ""
    head = parts[0]
    rest = parts[1:]
    if rest and _looks_like_image_id(rest[0]):
        return f"{scope_prefix}{head}", rest[0], "/".join(rest[1:])
    return f"{scope_prefix}{head}", None, "/".join(rest)


def _parse_slash_scope_body(
    scope_prefix: str,
    body: str,
) -> Tuple[str, Optional[str], str]:
    segments = [s for s in body.split("/") if s != ""]
    if not segments:
        raise ValueError("ref missing file path")

    release_end = 0
    for i, seg in enumerate(segments):
        if _RELEASE_TAIL_RE.match(seg) or (
            i > 0 and re.search(r"\d{1,2}\.\d{1,2}\.\d{1,6}", seg)
        ):
            release_end = i + 1
    if release_end == 0:
        release_end = min(2, len(segments))

    scope = f"{scope_prefix}{'/'.join(segments[:release_end])}"
    rest = segments[release_end:]
    if rest and _looks_like_image_id(rest[0]):
        return scope, rest[0], "/".join(rest[1:])
    if len(rest) == 1:
        return scope, None, rest[0]
    return scope, None, "/".join(rest)


def _looks_like_image_id(token: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{8,16}", token))


def format_ref_for_hit(
    conn: sqlite3.Connection,
    hit: Any,
    *,
    image_id: Optional[str] = None,
) -> str:
    iid = image_id or image_short_id(conn, hit.image_path)
    scope = scope_from_image_path(hit.image_path)
    if not scope:
        return format_ref("@unknown", hit.path, image_id=iid)
    return format_ref(scope, hit.path, image_id=iid)


def collection_prefix_for_scope(scope: str) -> str:
    if scope.startswith("@"):
        return ""
    return collection_image_prefix(scope.rstrip(":") if scope.endswith(":") else scope)
