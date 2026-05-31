#!/usr/bin/env bash
set -euo pipefail

DB="${CORPUS_DB:-/work/work_corpus/corpus/index.sqlite}"
GATEWAY="/work/gateway.c01.sbcglobal.net"
REPORT="${PKGSTREAM_REPORT_JSON:-/work/work_corpus/gateway_fresh_index_report.json}"
PKGSTREAM_PATH_FILTER="${PKGSTREAM_PATH_FILTER:-00D09E}"

# Docker Desktop bind mounts (NTFS → virtiofs/9p): WAL + no mmap for concurrent readonly grep.
# Batch commits (CORPUS_INDEX_BATCH_FILES) still shorten writer lock windows.
export SBOM_SOURCE="${SBOM_SOURCE:-materialize}"
export CORPUS_JOBS="${CORPUS_JOBS:-4}"
export CORPUS_SQLITE_JOURNAL="${CORPUS_SQLITE_JOURNAL:-wal}"
export CORPUS_SQLITE_MMAP="${CORPUS_SQLITE_MMAP:-0}"
export CORPUS_INDEX_BATCH_FILES="${CORPUS_INDEX_BATCH_FILES:-100}"

fresh="${FRESH_INDEX:-1}"
if [[ "${RESUME:-0}" == "1" ]]; then
  fresh=0
fi

mkdir -p /work/work_corpus/corpus /work/work_corpus/reports /work/work_corpus/sbom /work/work_corpus/secrets

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export GATEWAY_ROOT="$GATEWAY"
export PKGSTREAM_PATH_FILTER
bash "${SCRIPT_DIR}/index_preflight.sh"

INDEX=(
  python -m corpus --build-index --db "$DB"
  --max-file-mb 0
  --max-strings-per-file 2000
  --symtab
  --dwarf
  --jobs "${CORPUS_JOBS}"
  --pkgstream-work /work/work_corpus/pkgstream_corpus_by_version
  --sbom-dir /work/work_corpus/sbom
  --sbom-source "${SBOM_SOURCE}"
  --sbom
  --secrets
  --secrets-gitleaks
  --secrets-dir /work/work_corpus/secrets
)

on_index_fail() {
  local code=$?
  echo "=== corpus index failed (exit ${code}) ===" >&2
  echo "If this was Bus error / SIGBUS during pkgstream phase:" >&2
  echo "  RESUME=1 SKIP_NANDS=1 CORPUS_JOBS=1 SBOM_SOURCE=materialize \\" >&2
  echo "    docker compose -f docker/corpus-runtime/compose.yml run --rm reindex" >&2
  echo "Optional: drop --dwarf from INDEX in this script, or SKIP_GRYPE=1 for index-only." >&2
  exit "$code"
}
trap on_index_fail ERR

if [[ "$fresh" == "1" ]]; then
  echo "=== fresh index: remove existing SQLite (${DB}) ==="
  rm -f "$DB" "${DB}-wal" "${DB}-shm"
else
  echo "=== resume: keeping existing SQLite (${DB}) ==="
fi

if [[ "${SKIP_NANDS:-0}" != "1" ]]; then
  echo "=== phase 1/3: NAND dumps (nands/) ==="
  for f in \
    "13171N034522 S34ML01G1@TSOP48.BIN" \
    "30151N058501 S34ML01G1@TSOP48.BIN" \
    "38161N043704 S34ML01G1@TSOP48.BIN"
  do
    echo "=== flash index: nands/${f} ==="
    "${INDEX[@]}" --flash "nands/${f}"
  done
else
  echo "=== phase 1/3: skipped (SKIP_NANDS=1) ==="
fi

echo "=== phase 2/3: pkgstreams under ${GATEWAY} (path *${PKGSTREAM_PATH_FILTER}*, Z->A) ==="
echo "=== SBOM_SOURCE=${SBOM_SOURCE} CORPUS_JOBS=${CORPUS_JOBS} ==="
"${INDEX[@]}" \
  --pkgstream-version-order desc \
  --pkgstream-path-substring "${PKGSTREAM_PATH_FILTER}" \
  --pkgstream-report-json "$REPORT" \
  --pkgstream-root "${GATEWAY}"

if [[ "${SKIP_GRYPE:-0}" != "1" ]]; then
  echo "=== phase 3/3: Grype on SBOMs ==="
  python -m corpus --db "$DB" \
    --grype --grype-all --grype-output json --grype-skip-existing \
    --sbom-dir /work/work_corpus/sbom
else
  echo "=== phase 3/3: skipped (SKIP_GRYPE=1) ==="
fi

echo "=== index complete: ${DB} ==="
