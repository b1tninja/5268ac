#!/usr/bin/env bash
# Compare a Buildroot target/ tree (stock) against a staged firmware sysroot.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STOCK="${STOCK:-$ROOT/work_corpus/toolchain/output-2013.05/target}"
FIRMWARE="${FIRMWARE:-$ROOT/work_corpus/toolchain/sysroots/version_11.14.1.533857}"
PREFIX="${PREFIX:-}"

if [[ ! -d "$FIRMWARE" ]]; then
  echo "Missing firmware sysroot: $FIRMWARE" >&2
  echo "Run: make -C cross sysroot-533857" >&2
  exit 1
fi

if [[ ! -d "$STOCK" ]]; then
  echo "Missing stock target root: $STOCK" >&2
  echo "Build stock reference: make -C cross/buildroot PROFILE=stock target" >&2
  exit 1
fi

list_tree() {
  local base="$1"
  (cd "$base" && find . -type f | sed 's|^\./||' | sort)
}

mapfile -t fw_files < <(list_tree "$FIRMWARE")
mapfile -t st_files < <(list_tree "$STOCK")

echo "=== Firmware sysroot: $FIRMWARE (${#fw_files[@]} files) ==="
echo "=== Stock Buildroot target: $STOCK (${#st_files[@]} files) ==="
echo ""

# Firmware-only paths (vendor / Broadcom / Pace additions).
echo "=== Sample paths only on firmware (first 40) ==="
comm -23 <(printf '%s\n' "${fw_files[@]}") <(printf '%s\n' "${st_files[@]}") | head -40

echo ""
echo "=== Sample paths only on stock Buildroot (first 40) ==="
comm -13 <(printf '%s\n' "${fw_files[@]}") <(printf '%s\n' "${st_files[@]}") | head -40

echo ""
echo "=== Vendor library name heuristic (firmware lib/) ==="
find "$FIRMWARE/lib" "$FIRMWARE/usr/lib" -maxdepth 1 -name '*.so*' -type f 2>/dev/null \
  | xargs -r basename -a \
  | grep -E 'bcm|cms|wl|arris|pace|2sp|dhcp|pkg' \
  | sort -u | head -30 || true
