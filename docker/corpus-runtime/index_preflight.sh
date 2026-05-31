#!/usr/bin/env bash
# Verify corpus index tooling and inputs before a long fresh/reindex run.
set -euo pipefail

GATEWAY="${GATEWAY_ROOT:-/work/gateway.c01.sbcglobal.net}"
SBOM_SOURCE="${SBOM_SOURCE:-materialize}"
SKIP_NANDS="${SKIP_NANDS:-0}"
PKGSTREAM_PATH_FILTER="${PKGSTREAM_PATH_FILTER:-00D09E}"

fail=0
need_cmd() {
  local name=$1
  if command -v "$name" >/dev/null 2>&1; then
    echo "  ok  $name -> $(command -v "$name")"
  else
    echo "  MISSING  $name" >&2
    fail=1
  fi
}

echo "=== index preflight: commands ==="
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.24.2}"
if ! command -v gitleaks >/dev/null 2>&1; then
  echo "=== installing gitleaks ${GITLEAKS_VERSION} ==="
  curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar xz -C /usr/local/bin gitleaks
fi
for cmd in python syft grype gitleaks vmlinux-to-elf file jq; do
  need_cmd "$cmd"
done

if [[ "$SBOM_SOURCE" == "auto" || "$SBOM_SOURCE" == "mount" ]]; then
  need_cmd squashfuse
else
  echo "  skip squashfuse (SBOM_SOURCE=${SBOM_SOURCE})"
fi

echo "=== index preflight: python packages ==="
python - <<'PY' || fail=1
import importlib

mods = (
    "corpus",
    "paceflash",
    "lib2spy",
    "boardfs",
    "opentl",
    "lief",
    "capstone",
)
for name in mods:
    importlib.import_module(name)
import dissect.squashfs  # noqa: F401
print("  ok  python modules")
PY

echo "=== index preflight: tool smoke ==="
syft version >/dev/null
grype version >/dev/null
gitleaks version >/dev/null
vmlinux-to-elf --help >/dev/null 2>&1 || vmlinux-to-elf -h >/dev/null 2>&1 || true
python -m corpus --help >/dev/null
echo "  ok  tool smoke"

echo "=== index preflight: inputs ==="
if [[ "$SKIP_NANDS" != "1" ]]; then
  for f in \
    "13171N034522 S34ML01G1@TSOP48.BIN" \
    "30151N058501 S34ML01G1@TSOP48.BIN" \
    "38161N043704 S34ML01G1@TSOP48.BIN"
  do
    path="nands/${f}"
    if [[ -f "/work/${path}" ]]; then
      echo "  ok  /work/${path}"
    else
      echo "  MISSING  /work/${path}" >&2
      fail=1
    fi
  done
else
  echo "  skip nands (SKIP_NANDS=1)"
fi

if [[ -d "$GATEWAY" ]]; then
  n=$(find "$GATEWAY" -type f -name '*.pkgstream' -path "*${PKGSTREAM_PATH_FILTER}*" 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$n" -gt 0 ]]; then
    echo "  ok  ${GATEWAY} (${n} pkgstreams matching *${PKGSTREAM_PATH_FILTER}*)"
  else
    echo "  MISSING  no pkgstreams under ${GATEWAY} matching *${PKGSTREAM_PATH_FILTER}*" >&2
    fail=1
  fi
else
  echo "  MISSING  ${GATEWAY}" >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo "=== index preflight FAILED ===" >&2
  exit 1
fi

echo "=== index preflight OK ==="
