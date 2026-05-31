"""
Programmatic interface to the firmware corpus SQLite index.

    Agents and scripts should prefer this module over shelling out to
    ``python -m corpus``.  Opens the index **read-only** by default so queries
    can run while another process is indexing.  See ``corpus.mcp_server`` and
    ``docker/corpus-mcp/`` for MCP.

Example::

    from corpus.client import CorpusClient

    with CorpusClient() as corpus:
        for hit in corpus.grep("OWA:upgrade", collection="11.14.1.533857-PROD", fixed=True):
            print(hit.ref, hit.preview)
        data = corpus.read(hit.ref)
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Union

from corpus.buildroot import list_collection_details, list_firmware_collections
from corpus.fetch import LocateResult, apply_query_slice, fetch_bytes, locate_ref
from corpus.index_db import (
    SearchHit,
    connect_db,
    find_files,
    resolve_collection_slug_arg,
    search_index,
)
from corpus.paths import default_corpus_db_path, repo_root_from_module
from corpus.ref import CorpusRef, format_ref, image_short_id, parse_ref, scope_from_image_path

SearchKind = str
PatternInput = Union[str, Sequence[str]]


@dataclass(frozen=True)
class FindResult:
    """One indexed file matched by :meth:`CorpusClient.find`."""

    ref: str
    image_path: str
    file_path: str
    md5: Optional[str] = None
    size_bytes: Optional[int] = None
    content_class: Optional[str] = None
    collection: Optional[str] = None
    artifact_kind: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ref": self.ref,
            "image_path": self.image_path,
            "file_path": self.file_path,
            "md5": self.md5,
            "size_bytes": self.size_bytes,
            "content_class": self.content_class,
            "collection": self.collection,
            "artifact_kind": self.artifact_kind,
        }


@dataclass(frozen=True)
class GrepHit:
    """One search hit with a stable ref and JSON-friendly fields."""

    ref: str
    kind: str
    image_path: str
    path: str
    preview: str
    detail: Dict[str, Any]
    collection: Optional[str] = None

    @classmethod
    def from_search_hit(cls, conn: sqlite3.Connection, hit: SearchHit) -> GrepHit:
        payload = hit.to_json_dict(conn)
        return cls(
            ref=str(payload.get("ref") or hit.to_ref(conn)),
            kind=hit.kind,
            image_path=hit.image_path,
            path=hit.path,
            preview=str(payload.get("preview") or ""),
            detail=dict(hit.detail),
            collection=str(payload.get("scope") or "") or None,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ref": self.ref,
            "kind": self.kind,
            "image_path": self.image_path,
            "path": self.path,
            "preview": self.preview,
            "collection": self.collection,
            **self.detail,
        }


class CorpusClient:
    """Query the corpus index without invoking the CLI."""

    def __init__(
        self,
        db: str | Path | None = None,
        *,
        repo_root: str | Path | None = None,
        readonly: bool = True,
    ) -> None:
        self._repo_root = Path(repo_root) if repo_root is not None else repo_root_from_module()
        self._db_path = Path(db) if db is not None else default_corpus_db_path(self._repo_root)
        self._readonly = readonly
        self._conn: Optional[sqlite3.Connection] = None

    @property
    def repo_root(self) -> Path:
        return self._repo_root

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = connect_db(self._db_path, readonly=self._readonly)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> CorpusClient:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    @staticmethod
    def _normalize_patterns(patterns: PatternInput) -> List[str]:
        if isinstance(patterns, str):
            return [patterns]
        return [str(p) for p in patterns if p]

    @staticmethod
    def _resolve_collection(collection: Optional[str]) -> Optional[str]:
        if not collection:
            return None
        return resolve_collection_slug_arg(collection)

    def collections(self) -> List[str]:
        """Distinct firmware collection slugs in the index."""
        return list_firmware_collections(self.conn)

    def collection_details(self) -> List[Dict[str, Any]]:
        """Per-collection summary (images, file counts, metadata)."""
        return list_collection_details(self.conn)

    def find(
        self,
        path_globs: Optional[PatternInput] = None,
        *,
        collection: Optional[str] = None,
        kinds: Optional[Sequence[SearchKind]] = None,
        limit: int = 0,
    ) -> List[FindResult]:
        """
        Enumerate indexed files whose path matches any glob and/or artifact *kinds*.

        Globs use ``fnmatch`` semantics (``*``, ``?``, ``[…]``).  Omit *path_globs*
        when using *kinds* alone (e.g. ``kinds=["tlv_script"]``).
        """
        globs = self._normalize_patterns(path_globs) if path_globs else []
        if not globs and not kinds:
            raise ValueError("find requires path_globs and/or kinds")
        coll = self._resolve_collection(collection)
        out: List[FindResult] = []
        for row in find_files(
            self.conn,
            globs,
            kinds=list(kinds) if kinds else None,
            collection_slug=coll,
            limit=limit,
            completed_only=self._readonly,
        ):
            image_path = str(row["image_path"])
            file_path = str(row["file_path"])
            scope = scope_from_image_path(image_path) or "@unknown"
            iid = image_short_id(self.conn, image_path)
            ref = format_ref(scope, file_path, image_id=iid)
            out.append(
                FindResult(
                    ref=ref,
                    image_path=image_path,
                    file_path=file_path,
                    md5=row.get("md5"),
                    size_bytes=row.get("size_bytes"),
                    content_class=row.get("content_class"),
                    collection=scope if scope != "@unknown" else coll,
                    artifact_kind=row.get("artifact_kind"),
                )
            )
        return out

    def grep(
        self,
        patterns: PatternInput,
        *,
        collection: Optional[str] = None,
        fixed: bool = False,
        ignore_case: bool = False,
        kinds: Optional[Sequence[SearchKind]] = None,
        limit: int = 0,
        path_glob: Optional[PatternInput] = None,
    ) -> List[GrepHit]:
        """
        Search text lines, ELF symbols, rodata strings, and related index rows.

        *patterns* are regex unless *fixed* is true.  *kinds* defaults to
        :data:`corpus.index_db.DEFAULT_SEARCH_KINDS` (same as the CLI).
        """
        import fnmatch

        pats = self._normalize_patterns(patterns)
        coll = self._resolve_collection(collection)
        from corpus.index_db import DEFAULT_SEARCH_KINDS

        allowed = frozenset(kinds) if kinds else DEFAULT_SEARCH_KINDS
        globs = self._normalize_patterns(path_glob) if path_glob else []

        out: List[GrepHit] = []
        for hit in search_index(
            self.conn,
            pats,
            fixed=fixed,
            ignore_case=ignore_case,
            kinds=allowed,
            limit=limit,
            collection_slug=coll,
            completed_only=self._readonly,
        ):
            if globs:
                path = hit.path.replace("\\", "/")
                if not any(fnmatch.fnmatch(path, g) for g in globs):
                    continue
            out.append(GrepHit.from_search_hit(self.conn, hit))
        return out

    def iter_grep(
        self,
        patterns: PatternInput,
        *,
        collection: Optional[str] = None,
        fixed: bool = False,
        ignore_case: bool = False,
        kinds: Optional[Sequence[SearchKind]] = None,
        limit: int = 0,
        path_glob: Optional[PatternInput] = None,
    ) -> Iterator[GrepHit]:
        """Streaming variant of :meth:`grep` for large result sets."""
        for hit in self.grep(
            patterns,
            collection=collection,
            fixed=fixed,
            ignore_case=ignore_case,
            kinds=kinds,
            limit=limit,
            path_glob=path_glob,
        ):
            yield hit

    def locate(self, ref: str) -> LocateResult:
        """Resolve a corpus ref to on-disk / cache / extract locations."""
        return locate_ref(self.conn, ref, repo_root=self._repo_root)

    def read(self, ref: str) -> bytes:
        """Return raw file bytes for *ref* (SquashFS extract or index fallback)."""
        parsed = parse_ref(ref)
        data = fetch_bytes(self.conn, ref, repo_root=self._repo_root)
        return apply_query_slice(data, parsed.query)

    def read_text(
        self,
        ref: str,
        *,
        encoding: str = "utf-8",
        errors: str = "replace",
    ) -> str:
        return self.read(ref).decode(encoding, errors=errors)

    def parse_ref(self, ref: str) -> CorpusRef:
        return parse_ref(ref)

    def refs_containing(
        self,
        needles: Sequence[bytes],
        *,
        collection: Optional[str] = None,
        path_globs: PatternInput = "*",
        limit: int = 0,
    ) -> Dict[bytes, List[str]]:
        """
        Map each byte *needle* to refs whose file content contains it.

        Useful when string literals are not indexed (e.g. rodata-only hits).
        Scans materialized file bytes for paths matched by *path_globs*.
        """
        refs = [row.ref for row in self.find(path_globs, collection=collection, limit=limit or 0)]
        hits: Dict[bytes, List[str]] = {n: [] for n in needles}
        for ref in refs:
            try:
                data = self.read(ref)
            except LookupError:
                continue
            for needle in needles:
                if needle in data:
                    hits[needle].append(ref)
        return hits


__all__ = [
    "CorpusClient",
    "FindResult",
    "GrepHit",
    "LocateResult",
    "SearchHit",
]
