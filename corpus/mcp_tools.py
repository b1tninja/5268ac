"""Corpus MCP tool implementations (transport-agnostic, unit-testable)."""

from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional, Sequence, Union

from corpus.client import CorpusClient

PatternInput = Union[str, Sequence[str]]
DEFAULT_READ_MAX_BYTES = 512 * 1024


def corpus_collections(client: CorpusClient) -> Dict[str, Any]:
    return {"collections": client.collections(), "count": len(client.collections())}


def corpus_collection_details(client: CorpusClient) -> Dict[str, Any]:
    details = client.collection_details()
    return {"collections": details, "count": len(details)}


def corpus_find(
    client: CorpusClient,
    *,
    path_glob: Optional[str] = None,
    collection: Optional[str] = None,
    kinds: Optional[List[str]] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    rows = client.find(
        path_glob,
        collection=collection,
        kinds=kinds,
        limit=limit,
    )
    return {"results": [r.to_dict() for r in rows], "count": len(rows)}


def corpus_grep(
    client: CorpusClient,
    *,
    pattern: str,
    collection: Optional[str] = None,
    fixed: bool = False,
    ignore_case: bool = False,
    kinds: Optional[List[str]] = None,
    path_glob: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    hits = client.grep(
        pattern,
        collection=collection,
        fixed=fixed,
        ignore_case=ignore_case,
        kinds=kinds,
        limit=limit,
        path_glob=path_glob,
    )
    return {"hits": [h.to_dict() for h in hits], "count": len(hits)}


def corpus_locate(client: CorpusClient, *, ref: str) -> Dict[str, Any]:
    loc = client.locate(ref)
    return {
        "ref": loc.ref,
        "scope": loc.scope,
        "file_path": loc.file_path,
        "image_path": loc.image_path,
        "image_id": loc.image_id,
        "file_md5": loc.file_md5,
        "on_disk": str(loc.on_disk) if loc.on_disk else None,
        "cache_path": str(loc.cache_path) if loc.cache_path else None,
        "resolver": loc.resolver,
    }


def corpus_read(
    client: CorpusClient,
    *,
    ref: str,
    max_bytes: int = DEFAULT_READ_MAX_BYTES,
    as_text: bool = True,
) -> Dict[str, Any]:
    data = client.read(ref)
    truncated = False
    if max_bytes > 0 and len(data) > max_bytes:
        data = data[:max_bytes]
        truncated = True
    payload: Dict[str, Any] = {
        "ref": ref,
        "size_bytes": len(data),
        "truncated": truncated,
    }
    if as_text:
        payload["text"] = data.decode("utf-8", errors="replace")
    else:
        payload["base64"] = base64.b64encode(data).decode("ascii")
    return payload


def corpus_refs_containing(
    client: CorpusClient,
    *,
    needles: List[str],
    collection: Optional[str] = None,
    path_glob: str = "*",
    limit: int = 500,
) -> Dict[str, Any]:
    byte_needles = [n.encode("utf-8") for n in needles]
    hits = client.refs_containing(
        byte_needles,
        collection=collection,
        path_globs=path_glob,
        limit=limit,
    )
    return {
        "matches": {k.decode("utf-8", errors="replace"): refs for k, refs in hits.items()},
        "needle_count": len(needles),
    }
