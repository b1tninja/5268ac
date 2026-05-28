#!/usr/bin/env bash
# Merge Buildroot host sysroot (crt, headers, linker scripts) with firmware libraries.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIRMWARE="${FIRMWARE:-$ROOT/work_corpus/toolchain/sysroots/version_11.14.1.533857}"
HOST_SYSROOT="${HOST_SYSROOT:-$ROOT/work_corpus/toolchain/output/host/usr/mips-unknown-linux-uclibc/sysroot}"
OUT="${OUT:-$ROOT/work_corpus/toolchain/sysroots/version_11.14.1.533857-link}"

if [[ ! -d "$FIRMWARE/lib" ]]; then
  echo "Missing firmware sysroot: $FIRMWARE" >&2
  exit 1
fi
if [[ ! -f "$HOST_SYSROOT/usr/lib/crt1.o" ]]; then
  echo "Missing host sysroot (run cross_compiler): $HOST_SYSROOT" >&2
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"
rsync -a "$HOST_SYSROOT"/ "$OUT"/
rsync -a "$FIRMWARE/lib/" "$OUT/lib/"
if [[ -d "$FIRMWARE/usr/lib" ]]; then
  mkdir -p "$OUT/usr/lib"
  rsync -a "$FIRMWARE/usr/lib/" "$OUT/usr/lib/"
fi

# uClibc SONAMEs expected by the dynamic linker on device.
ln -sf libuClibc-0.9.32.so "$OUT/lib/libc.so.0"
ln -sf ld-uClibc-0.9.32.so "$OUT/lib/ld-uClibc.so.0"

echo "Prepared link sysroot: $OUT"
echo "  host base: $HOST_SYSROOT"
echo "  firmware libs: $FIRMWARE/lib"
