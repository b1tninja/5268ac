#!/usr/bin/env bash
# Reindex Pace NAND dumps with SQLite on container /tmp (avoids Windows bind-mount I/O errors).
set -euo pipefail

export CORPUS_SQLITE_JOURNAL="${CORPUS_SQLITE_JOURNAL:-wal}"
export CORPUS_SQLITE_MMAP="${CORPUS_SQLITE_MMAP:-0}"

DB=/tmp/index.sqlite
HOST_DB=/work/work_corpus/corpus/index.sqlite
mkdir -p /work/work_corpus/corpus

if [[ -f "$HOST_DB" ]]; then
  cp "$HOST_DB" "$DB"
  for sidecar in -wal -shm; do
    if [[ -f "${HOST_DB}${sidecar}" ]]; then
      cp "${HOST_DB}${sidecar}" "${DB}${sidecar}"
    fi
  done
fi

python - <<'PY'
import sqlite3
from pathlib import Path

db = Path("/tmp/index.sqlite")
if not db.is_file():
    raise SystemExit("no index database at /tmp/index.sqlite")
conn = sqlite3.connect(db)
n = 0
for slug in ("13171N034522", "30151N058501", "38161N043704"):
    cur = conn.execute(
        "DELETE FROM analysis_status WHERE image_path LIKE ?",
        (f"%nand:@{slug}%",),
    )
    n += cur.rowcount
conn.commit()
conn.close()
print(f"cleared {n} nand analysis_status rows")
PY

for f in \
  "13171N034522 S34ML01G1@TSOP48.BIN" \
  "30151N058501 S34ML01G1@TSOP48.BIN" \
  "38161N043704 S34ML01G1@TSOP48.BIN"
do
  echo "=== flash index: $f ==="
  python -m corpus --build-index --db "$DB" --flash "nands/$f"
done

cp "$DB" "$HOST_DB"
for sidecar in -wal -shm; do
  if [[ -f "${DB}${sidecar}" ]]; then
    cp "${DB}${sidecar}" "${HOST_DB}${sidecar}"
  else
    rm -f "${HOST_DB}${sidecar}" 2>/dev/null || true
  fi
done
echo "=== wrote $HOST_DB ==="
