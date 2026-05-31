#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH="/work${PYTHONPATH:+:${PYTHONPATH}}"

QEMU_MIPS="${QEMU_MIPS:-qemu-mips-static}"
# Firmware rootfs (stage-rootfs); dockcross toolchain libc for cross-built harnesses.
FIRMWARE_SYSROOT="${QEMU_LD_PREFIX:-/work/work_corpus/qemu_mips/sysroots/default}"
TOOLCHAIN_SYSROOT="${TOOLCHAIN_SYSROOT:-/usr/xcc/mips-unknown-linux-gnu/mips-unknown-linux-gnu/sysroot}"

register_binfmt() {
  if [[ ! -w /proc/sys/fs/binfmt_misc/register ]]; then
    echo "5268ac: binfmt_misc not writable (run 5268ac-binfmt with --privileged)" >&2
    return 1
  fi
  local qemu_path
  qemu_path="$(command -v "$QEMU_MIPS" || true)"
  if [[ -z "$qemu_path" ]]; then
    echo "5268ac: $QEMU_MIPS not found in PATH" >&2
    return 1
  fi
  echo ":mips:M::\x7fELF\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28:$qemu_path:" \
    >/proc/sys/fs/binfmt_misc/register 2>/dev/null \
    || echo "5268ac: mips binfmt already registered or registration failed" >&2
}

prep_firmware_sysroot() {
  local root="${1:-$FIRMWARE_SYSROOT}"
  local lib="$root/lib"
  if [[ ! -d "$lib" ]]; then
    echo "5268ac: sysroot missing: $root" >&2
    return 1
  fi
  if [[ -f "$lib/libuClibc-0.9.32.so" && ! -e "$lib/libc.so.0" ]]; then
    ln -sf libuClibc-0.9.32.so "$lib/libc.so.0"
  fi
  if [[ -f "$lib/ld-uClibc-0.9.32.so" && ! -e "$lib/ld-uClibc.so.0" ]]; then
    ln -sf ld-uClibc-0.9.32.so "$lib/ld-uClibc.so.0"
  fi
}

run_mips() {
  local bin="$1"
  shift
  if [[ ! -f "$bin" ]]; then
    echo "5268ac: not a file: $bin" >&2
    exit 1
  fi
  if [[ ! -d "$FIRMWARE_SYSROOT" ]]; then
    echo "5268ac: sysroot missing: $FIRMWARE_SYSROOT" >&2
    echo "  Run: stage-rootfs --collection version:11.14.1.533857" >&2
    echo "  Or:  QEMU_LD_PREFIX=/work/work_corpus/toolchain/sysroots/version_11.14.1.533857" >&2
    exit 1
  fi
  prep_firmware_sysroot "$FIRMWARE_SYSROOT" || true
  exec "$QEMU_MIPS" -L "$FIRMWARE_SYSROOT" "$bin" "$@"
}

if [[ $# -eq 0 ]]; then
  exec bash
fi

case "$1" in
  shell|bash|sh)
    shift
    exec bash "$@"
    ;;
  register-binfmt)
    shift
    register_binfmt || true
    if [[ $# -gt 0 ]]; then
      exec "$@"
    fi
    exec bash
    ;;
  run-mips)
    shift
    if [[ $# -lt 1 ]]; then
      echo "usage: run-mips <mips-elf> [args...]" >&2
      echo "  QEMU_LD_PREFIX=$FIRMWARE_SYSROOT" >&2
      exit 2
    fi
    run_mips "$@"
    ;;
  stage-rootfs)
    shift
    exec python3 /work/docker/qemu-mips/scripts/stage_rootfs.py "$@"
    ;;
  prep-sysroot)
    shift
    prep_firmware_sysroot "${1:-$FIRMWARE_SYSROOT}"
    ;;
  corpus)
    shift
    exec python3 -m corpus "$@"
    ;;
  cross-make)
    shift
    if ! command -v docker >/dev/null 2>&1; then
      echo "5268ac: cross-make needs Docker on the host; inside the container run: cross-test" >&2
      exit 127
    fi
    exec make -C /work/cross "$@"
    ;;
  cross-test)
    shift
    set -e
    cd /work/cross
    mips-unknown-linux-gnu-gcc -march=r3000 test.c -o test
    exec "$QEMU_MIPS" -L "$TOOLCHAIN_SYSROOT" ./test "$@"
    ;;
  python|python3|pip|pip3|tcpdump|file|mips-unknown-linux-gnu-gcc|gcc|make)
    exec "$@"
    ;;
  *)
    if [[ -x "$1" ]] && file -b "$1" | grep -q 'MIPS'; then
      run_mips "$@"
    fi
    exec "$@"
    ;;
esac
