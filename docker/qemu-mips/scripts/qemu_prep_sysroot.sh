#!/usr/bin/env bash
# uClibc dynamic linker expects libc.so.0 and ld-uClibc.so.0; firmware images often ship versioned SONAMEs only.
set -euo pipefail

ROOT="${1:?usage: qemu_prep_sysroot.sh <sysroot>}"
LIB="$ROOT/lib"

if [[ ! -d "$LIB" ]]; then
  echo "qemu_prep_sysroot: missing $LIB" >&2
  exit 1
fi

cd "$LIB"
if [[ -f libuClibc-0.9.32.so && ! -e libc.so.0 ]]; then
  ln -sf libuClibc-0.9.32.so libc.so.0
fi
if [[ -f ld-uClibc-0.9.32.so && ! -e ld-uClibc.so.0 ]]; then
  ln -sf ld-uClibc-0.9.32.so ld-uClibc.so.0
fi

echo "qemu_prep_sysroot: $ROOT"
