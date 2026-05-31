# Corpus MCP server

Streamable HTTP [MCP](https://modelcontextprotocol.io/) server over the firmware corpus SQLite index. Wraps [`corpus/client.py`](../../corpus/client.py) — same surface agents use in Python, exposed as MCP tools.

## Tools

| Tool | Description |
|------|-------------|
| `collections` | List indexed collection slugs |
| `collection_details` | Per-collection image/file summaries |
| `find` | Path glob → refs |
| `grep` | Text / symbol / rodata search |
| `locate` | Resolve ref → on-disk / cache paths |
| `read` | File bytes (truncated, UTF-8 or base64) |
| `refs_containing` | Byte-needle scan across files |

## Local (stdio)

For Cursor / Claude Desktop without Docker:

```powershell
pip install -e ".[dissect,mcp]"
python -m corpus.mcp_server
```

Cursor **mcp.json**:

```json
{
  "mcpServers": {
    "5268ac-corpus": {
      "command": "D:/electronics/5268ac/.venv/Scripts/python.exe",
      "args": ["-m", "corpus.mcp_server"],
      "cwd": "D:/electronics/5268ac"
    }
  }
}
```

## Docker (Streamable HTTP)

From repo root:

```powershell
docker compose -f docker/corpus-mcp/compose.yml up -d --build
```

Or:

```powershell
docker compose -f docker-compose.corpus-mcp.yml up -d --build
```

Endpoint: **`http://localhost:8100/mcp`**

Cursor **mcp.json**:

```json
{
  "mcpServers": {
    "5268ac-corpus": {
      "url": "http://localhost:8100/mcp"
    }
  }
}
```

### Volumes

| Mount | Purpose |
|-------|---------|
| `../..` → `/work` | Live repo + PYTHONPATH |
| `../../work_corpus` → `/work/work_corpus` | SQLite index, SBOM trees, extract cache |

Set `CORPUS_DB` if the index is not at the default path.

### Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `CORPUS_MCP_HOST` | `0.0.0.0` | Bind address |
| `CORPUS_MCP_PORT` | `8100` | HTTP port |
| `CORPUS_MCP_TRANSPORT` | `streamable-http` | MCP transport |
| `CORPUS_DB` | `/work/work_corpus/corpus/index.sqlite` | Index path |
| `CORPUS_REPO_ROOT` | `/work` | Repo root for materialized paths |

The MCP server **always** opens the index read-only (`file:…?mode=ro`, `PRAGMA query_only=ON`, 30s `busy_timeout`). That avoids competing with `corpus-fresh-index` for write locks or schema migrations.

On **Docker Desktop (Windows)**, querying a bind-mounted `index.sqlite` from a second container while another container is writing may still hit `disk I/O error` — that is a mount limitation, not MCP. Use **stdio on the host** during active indexing in that case.

## HTTP smoke test

```powershell
curl -s http://localhost:8100/mcp `
  -H "Content-Type: application/json" `
  -H "Accept: application/json, text/event-stream" `
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
```

## Security

No authentication in v1 — intended for **local lab use** only. Do not expose port 8100 on untrusted networks without a reverse proxy and auth.
