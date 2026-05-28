#!/usr/bin/env bash
# Compare vendor MIPS/uClibc ELF attributes vs the rebuilt Buildroot toolchain.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BR_OUTPUT="${BR_OUTPUT:-$ROOT/work_corpus/toolchain/output}"
GCC="$BR_OUTPUT/host/usr/bin/mips-unknown-linux-uclibc-gcc"
READELF="${READELF:-$BR_OUTPUT/host/usr/bin/mips-unknown-linux-uclibc-readelf}"
VENDOR_ELF="${VENDOR_ELF:-$ROOT/work_corpus/sbom/version_11.14.1.533857/sources/7_0001_att-5268-11.14.1.533857_prod_lightspeed-install_embedded_squashfs_0x0000b01c_21709742.bin_ddb4802f5c035ce7/bin/busybox}"
TEST_SRC="$ROOT/cross/test.c"
TEST_O="$ROOT/work_corpus/toolchain/abi_check_test.o"

if [[ ! -x "$GCC" ]]; then
  echo "Missing toolchain: $GCC" >&2
  echo "Run: make -C cross/buildroot PROFILE=toolchain cross_compiler" >&2
  exit 1
fi

if [[ ! -f "$VENDOR_ELF" ]]; then
  echo "Missing vendor ELF: $VENDOR_ELF" >&2
  echo "Run corpus index + SBOM for version:11.14.1.533857" >&2
  exit 1
fi

if [[ ! -x "$READELF" ]]; then
  READELF=readelf
fi

echo "=== Compiler ==="
"$GCC" --version | head -1

echo ""
echo "=== Vendor: $VENDOR_ELF ==="
"$READELF" -h "$VENDOR_ELF" | sed -n '1,20p'
"$READELF" -A "$VENDOR_ELF" 2>/dev/null | head -20 || true
"$READELF" -d "$VENDOR_ELF" | grep NEEDED || true

echo ""
echo "=== Compile test object (no link) ==="
"$GCC" -O0 -pipe -march=mips1 -c -o "$TEST_O" "$TEST_SRC"
"$READELF" -h "$TEST_O" | sed -n '1,20p'

echo ""
echo "=== .comment (compiler identity) ==="
echo -n "vendor: "
strings "$VENDOR_ELF" | grep -E 'GCC:|Buildroot' | head -3 || true
echo -n "test.o: "
strings "$TEST_O" | grep -E 'GCC:|Buildroot' | head -3 || true

VENDOR_CLASS=$("$READELF" -h "$VENDOR_ELF" | awk '/Class:/ {print $2}')
TEST_CLASS=$("$READELF" -h "$TEST_O" | awk '/Class:/ {print $2}')
VENDOR_DATA=$("$READELF" -h "$VENDOR_ELF" | awk '/Data:/ {print $3}')
TEST_DATA=$("$READELF" -h "$TEST_O" | awk '/Data:/ {print $3}')
VENDOR_MACH=$("$READELF" -h "$VENDOR_ELF" | awk '/Machine:/ {print $2}')
TEST_MACH=$("$READELF" -h "$TEST_O" | awk '/Machine:/ {print $2}')

if [[ "$VENDOR_CLASS" != "$TEST_CLASS" || "$VENDOR_DATA" != "$TEST_DATA" || "$VENDOR_MACH" != "$TEST_MACH" ]]; then
  echo "FAIL: ELF header mismatch (class/data/machine)" >&2
  exit 1
fi

VENDOR_GCC_VER=$(strings "$VENDOR_ELF" | grep -oE '4\.[0-9]+\.[0-9]+' | tail -1)
HOST_GCC_VER=$("$GCC" -dumpversion)

if [[ -n "$VENDOR_GCC_VER" && "$HOST_GCC_VER" != "$VENDOR_GCC_VER" ]]; then
  echo "WARN: host gcc $HOST_GCC_VER vs vendor toolchain $VENDOR_GCC_VER" >&2
fi

if ! strings "$TEST_O" | grep -q "$HOST_GCC_VER"; then
  echo "FAIL: test object missing gcc $HOST_GCC_VER in .comment" >&2
  exit 1
fi

if ! strings "$TEST_O" | grep -qi 'buildroot'; then
  echo "FAIL: test object missing Buildroot branding in .comment" >&2
  exit 1
fi

echo "OK: mips-unknown-linux-uclibc-gcc matches vendor ELF class/endian/machine."
