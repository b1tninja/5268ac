"""
MCP server for the 5268ac firmware corpus index.

Run locally (stdio — Cursor / Claude Desktop)::

    python -m corpus.mcp_server

Run for Docker / remote clients (Streamable HTTP)::

    python -m corpus.mcp_server --transport streamable-http --host 0.0.0.0 --port 8100

Environment:
    CORPUS_DB          — SQLite index path (default: work_corpus/corpus/index.sqlite)
    CORPUS_REPO_ROOT   — repo root for materialized paths (default: auto)
    CORPUS_MCP_HOST    — bind address (default: 127.0.0.1)
    CORPUS_MCP_PORT    — listen port (default: 8100)
    CORPUS_MCP_TRANSPORT — stdio | streamable-http (overrides --transport when set)

The index is always opened **read-only** (``file:…?mode=ro`` + ``PRAGMA query_only``)
so MCP queries can run while ``corpus-fresh-index`` or other writers hold the DB.
"""

from __future__ import annotations

import argparse
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, List, Optional

from mcp.server.fastmcp import Context, FastMCP

from corpus.client import CorpusClient
from corpus.mcp_tools import (
    corpus_collection_details,
    corpus_collections,
    corpus_find,
    corpus_grep,
    corpus_locate,
    corpus_read,
    corpus_refs_containing,
)
from corpus.paths import default_corpus_db_path, repo_root_from_module


@dataclass
class AppState:
    client: CorpusClient


def _repo_root() -> Path:
    raw = os.environ.get("CORPUS_REPO_ROOT")
    return Path(raw).expanduser().resolve() if raw else repo_root_from_module()


def _db_path(repo_root: Path) -> Path:
    raw = os.environ.get("CORPUS_DB")
    if raw:
        return Path(raw).expanduser().resolve()
    return default_corpus_db_path(repo_root)


def _make_client() -> CorpusClient:
    repo = _repo_root()
    # Query-only: never run create_schema or take write locks during active indexing.
    return CorpusClient(db=_db_path(repo), repo_root=repo, readonly=True)


@asynccontextmanager
async def lifespan(_server: FastMCP) -> AsyncIterator[AppState]:
    client = _make_client()
    try:
        yield AppState(client=client)
    finally:
        client.close()


def create_mcp(*, host: str, port: int) -> FastMCP:
    mcp = FastMCP(
        "5268ac-corpus",
        instructions=(
            "Query the 5268ac firmware corpus SQLite index: list collections, "
            "grep strings/symbols, find files by glob, read file bytes by ref."
        ),
        host=host,
        port=port,
        lifespan=lifespan,
    )

    @mcp.tool()
    def collections(ctx: Context) -> dict:
        """List indexed firmware collection slugs (version:/pkgstream:/nand:)."""
        state: AppState = ctx.request_context.lifespan_context
        return corpus_collections(state.client)

    @mcp.tool()
    def collection_details(ctx: Context) -> dict:
        """Per-collection summary: images, file counts, release metadata."""
        state: AppState = ctx.request_context.lifespan_context
        return corpus_collection_details(state.client)

    @mcp.tool()
    def find(
        ctx: Context,
        path_glob: Optional[str] = None,
        collection: Optional[str] = None,
        kinds: Optional[List[str]] = None,
        limit: int = 100,
    ) -> dict:
        """Find indexed files by artifact kind and/or path glob (fnmatch: *, ?, [...])."""
        state: AppState = ctx.request_context.lifespan_context
        return corpus_find(
            state.client,
            path_glob=path_glob,
            collection=collection,
            kinds=kinds,
            limit=limit,
        )

    @mcp.tool()
    def grep(
        pattern: str,
        ctx: Context,
        collection: Optional[str] = None,
        fixed: bool = False,
        ignore_case: bool = False,
        kinds: Optional[List[str]] = None,
        path_glob: Optional[str] = None,
        limit: int = 50,
    ) -> dict:
        """Search text lines, ELF symbols, and rodata strings (regex unless fixed=true)."""
        state: AppState = ctx.request_context.lifespan_context
        return corpus_grep(
            state.client,
            pattern=pattern,
            collection=collection,
            fixed=fixed,
            ignore_case=ignore_case,
            kinds=kinds,
            path_glob=path_glob,
            limit=limit,
        )

    @mcp.tool()
    def locate(ref: str, ctx: Context) -> dict:
        """Resolve a corpus ref to on-disk, cache, or SquashFS extract paths."""
        state: AppState = ctx.request_context.lifespan_context
        return corpus_locate(state.client, ref=ref)

    @mcp.tool()
    def read(
        ref: str,
        ctx: Context,
        max_bytes: int = 512 * 1024,
        as_text: bool = True,
    ) -> dict:
        """Read file content for a corpus ref (truncates above max_bytes)."""
        state: AppState = ctx.request_context.lifespan_context
        return corpus_read(state.client, ref=ref, max_bytes=max_bytes, as_text=as_text)

    @mcp.tool()
    def refs_containing(
        needles: List[str],
        ctx: Context,
        collection: Optional[str] = None,
        path_glob: str = "*",
        limit: int = 500,
    ) -> dict:
        """Map string needles to refs whose file bytes contain each needle."""
        state: AppState = ctx.request_context.lifespan_context
        return corpus_refs_containing(
            state.client,
            needles=needles,
            collection=collection,
            path_glob=path_glob,
            limit=limit,
        )

    return mcp


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="5268ac corpus MCP server")
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default=os.environ.get("CORPUS_MCP_TRANSPORT", "stdio"),
        help="MCP transport (default: stdio, or CORPUS_MCP_TRANSPORT)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("CORPUS_MCP_HOST", "127.0.0.1"),
        help="HTTP bind address (streamable-http only)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("CORPUS_MCP_PORT", "8100")),
        help="HTTP port (streamable-http only)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    mcp = create_mcp(host=args.host, port=args.port)
    mcp.run(transport=args.transport)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
