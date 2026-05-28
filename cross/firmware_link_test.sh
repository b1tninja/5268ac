#!/usr/bin/env bash
# Compile and link a trivial program against the staged 11.14.1.533857 firmware sysroot.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LINK_SYSROOT="${LINK_SYSROOT:-$ROOT/work_corpus/toolchain/sysroots/version_11.14.1.533857-link}"
GCC="${GCC:-$ROOT/work_corpus/toolchain/output/host/usr/bin/mips-unknown-linux-uclibc-gcc}"
SRC="$ROOT/cross/test.c"
OUT="$ROOT/work_corpus/toolchain/firmware_link_test"
PREPARE="$ROOT/cross/prepare_link_sysroot.sh"

if [[ ! -x "$GCC" ]]; then
  echo "Missing $GCC — run: make -C cross/buildroot PROFILE=toolchain cross_compiler" >&2
  exit 1
fi

if [[ ! -f "$LINK_SYSROOT/lib/libc.so.0" ]]; then
  bash "$PREPARE"
fi

CFLAGS=( -O0 -pipe -march=mips1 )
LDFLAGS=( --sysroot="$LINK_SYSROOT" -Wl,-rpath-link,"$LINK_SYSROOT/lib" )

echo "=== Link test ==="
echo "GCC: $GCC"
echo "LINK_SYSROOT: $LINK_SYSROOT"

"$GCC" "${CFLAGS[@]}" "${LDFLAGS[@]}" -o "$OUT" "$SRC"
file "$OUT"
readelf -d "$OUT" | grep NEEDED || true

echo "OK: linked against firmware sysroot (libc.so.0 / uClibc 0.9.32)."
