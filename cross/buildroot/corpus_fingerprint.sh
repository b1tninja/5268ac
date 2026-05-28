#!/usr/bin/env bash
# Print toolchain / Buildroot identity evidence from corpus 11.14.1.533857.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COLLECTION="${COLLECTION:-version:11.14.1.533857}"
SLUG="${COLLECTION#version:}"
SLUG="version_${SLUG}"

SBOM_ROOT="$ROOT/work_corpus/sbom/${SLUG}/sources"
PKG_ROOT="$ROOT/work_corpus/pkgstream_corpus_by_version/${SLUG}"

os_release="$(find "$SBOM_ROOT" -path '*/etc/os-release' 2>/dev/null | head -1 || true)"
squashfs="$(find "$PKG_ROOT" -path '*/embedded/squashfs_0x0000b01c*.bin' 2>/dev/null | head -1 || true)"
busybox="$(find "$SBOM_ROOT" -path '*/bin/busybox' 2>/dev/null | head -1 || true)"
httpd="$ROOT/work_corpus/ghidra_import/${SLUG}/usr_bin_httpd"
ld_uclibc="$(find "$SBOM_ROOT" -path '*/lib/ld-uClibc-0.9.32.so' 2>/dev/null | head -1 || true)"

echo "=== Collection: $COLLECTION ==="
echo "squashfs carve: ${squashfs:-<missing — run corpus index + SBOM>}"
echo ""

if [[ -f "$os_release" ]]; then
  echo "=== etc/os-release (Buildroot branding on device) ==="
  grep -E '^(NAME|VERSION|VERSION_ID|PRETTY_NAME)=' "$os_release" || true
  echo ""
fi

_readelf_comment() {
  local label="$1" path="$2"
  [[ -f "$path" ]] || return 0
  echo "=== $label ==="
  echo "path: $path"
  readelf -h "$path" 2>/dev/null | awk '/Class:|Data:|Machine:|Flags:/ {print}'
  readelf -p .comment "$path" 2>/dev/null | sed -n '/\[.*\]/p' || true
  echo ""
}

_readelf_comment "bin/busybox" "$busybox"
_readelf_comment "usr/bin/httpd (corpus import)" "$httpd"
_readelf_comment "lib/ld-uClibc" "$ld_uclibc"

if [[ -d "$(dirname "${busybox:-/nonexistent}")/lib" ]]; then
  libdir="$(dirname "$busybox")/lib"
  echo "=== uClibc SONAMEs (sample) ==="
  ls -1 "$libdir"/lib*uClibc* "$libdir"/lib*-0.9.32.so 2>/dev/null | head -8 || true
  echo ""
fi

cat <<'EOF'
=== Interpretation (11.14.1.533857) ===
- os-release reports Buildroot 2013.05 (vendor bumped build metadata).
- MIPS userspace ELFs (.comment) are still gcc 4.6.2 (Buildroot 2011.11) + uClibc 0.9.32.
- Use PROFILE=toolchain (2011.11) to rebuild the cross compiler for link-compatible objects.
- Use PROFILE=stock (2013.05) only for an upstream stock rootfs baseline to diff vs firmware.
- Link against the firmware sysroot: make -C cross sysroot-533857 && make -C cross firmware-link-test
EOF
