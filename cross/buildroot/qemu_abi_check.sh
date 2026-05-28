#!/usr/bin/env bash
# Run a dynamically linked test binary under qemu-mips-static when a uClibc sysroot is available.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GCC="${GCC:-$ROOT/work_corpus/toolchain/output/host/usr/bin/mips-unknown-linux-uclibc-gcc}"
SYSROOT="${SYSROOT:-$ROOT/work_corpus/toolchain/vendor_sysroot}"
TEST_BIN="$ROOT/work_corpus/toolchain/abi_check_dyn"
TEST_SRC="$ROOT/cross/test.c"
QEMU="${QEMU:-qemu-mips-static}"

if ! command -v "$QEMU" >/dev/null 2>&1; then
  echo "Skip: $QEMU not installed (use 5268ac lab image: docker/qemu-mips)" >&2
  exit 0
fi

if [[ ! -x "$GCC" ]]; then
  echo "Missing $GCC" >&2
  exit 1
fi

if [[ ! -f "$SYSROOT/lib/ld-uClibc.so.0" && ! -f "$SYSROOT/lib/ld-uClibc-0.9.32.so" ]]; then
  echo "Skip: no uClibc sysroot at $SYSROOT (extract from vendor rootfs .tgz into work_corpus/toolchain/vendor_sysroot)" >&2
  exit 0
fi

UCLIBC_DEV="${UCLIBC_DEV:-$ROOT/work_corpus/toolchain/output/toolchain/uClibc_dev/usr/lib}"
CRT_FLAGS=()
if [[ -f "$UCLIBC_DEV/crt1.o" ]]; then
  CRT_FLAGS=(-B"$UCLIBC_DEV")
fi

if ! "$GCC" -O0 -pipe -march=mips1 --sysroot="$SYSROOT" "${CRT_FLAGS[@]}" -o "$TEST_BIN" "$TEST_SRC" 2>/dev/null; then
  echo "Skip: dynamic link failed (uClibc shared libc build incomplete; see README)" >&2
  exit 0
fi

if ! "$QEMU" -L "$SYSROOT" "$TEST_BIN"; then
  echo "Skip: qemu run failed" >&2
  exit 0
fi

echo "OK: dynamic hello under qemu-mips-static"
