#!/usr/bin/env bash
set -euo pipefail

# Prefer the host-mounted repo at /work (Compose) over the image copy.
if [[ -f /work/pyproject.toml ]]; then
  export PYTHONPATH="/work${PYTHONPATH:+:${PYTHONPATH}}"
  export CORPUS_REPO_ROOT="${CORPUS_REPO_ROOT:-/work}"
fi

export CORPUS_MCP_HOST="${CORPUS_MCP_HOST:-0.0.0.0}"
export CORPUS_MCP_PORT="${CORPUS_MCP_PORT:-8100}"
export CORPUS_MCP_TRANSPORT="${CORPUS_MCP_TRANSPORT:-streamable-http}"
export CORPUS_DB="${CORPUS_DB:-/work/work_corpus/corpus/index.sqlite}"

if [[ $# -eq 0 ]]; then
  set -- serve
fi

case "$1" in
  serve)
    shift
    exec python -m corpus.mcp_server \
      --transport "${CORPUS_MCP_TRANSPORT}" \
      --host "${CORPUS_MCP_HOST}" \
      --port "${CORPUS_MCP_PORT}" \
      "$@"
    ;;
  corpus-mcp|mcp)
    shift
    exec python -m corpus.mcp_server "$@"
    ;;
  shell|bash|sh)
    shift
    exec bash "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
