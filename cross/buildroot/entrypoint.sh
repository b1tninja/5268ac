#!/bin/bash
set -euo pipefail

BR_TREE="${BR_TREE:-/work/work_corpus/toolchain/buildroot-2011.11}"
BR_DL_DIR="${BR_DL_DIR:-/work/work_corpus/toolchain/dl}"
BR_OUTPUT="${BR_OUTPUT:-/work/work_corpus/toolchain/output}"
BR_CONFIG="${BR_CONFIG:-}"
PATCH_DIR="/patches"

mkdir -p "${BR_DL_DIR}" "${BR_OUTPUT}"

cd "${BR_TREE}"

if [[ -d support/scripts ]]; then
  while IFS= read -r -d '' f; do
    sed -i 's/\r$//' "$f"
  done < <(find support/scripts -type f -print0 2>/dev/null || true)
fi

if [[ -f "${PATCH_DIR}/m4-disable_gets_warning.patch" ]]; then
  M4_STDIO="$(find package -path '*/m4-*/lib/stdio.in.h' 2>/dev/null | head -1 || true)"
  if [[ -n "${M4_STDIO}" && -f "${M4_STDIO}" ]]; then
    if grep -q '_GL_WARN_ON_USE (gets' "${M4_STDIO}" 2>/dev/null; then
      patch -p0 -d "$(dirname "${M4_STDIO}")" < "${PATCH_DIR}/m4-disable_gets_warning.patch" || true
    fi
  fi
fi

export BR2_DL_DIR="${BR_DL_DIR}"
export BUILDROOT_DL_DIR="${BR_DL_DIR}"

mkdir -p "${BR_OUTPUT}"
if [[ -n "${BR_CONFIG}" && -f "${BR_CONFIG}" ]]; then
  cp "${BR_CONFIG}" "${BR_OUTPUT}/.config"
  sed -i "s|^BR2_DL_DIR=.*|BR2_DL_DIR=\"${BR_DL_DIR}\"|" "${BR_OUTPUT}/.config"
elif [[ ! -f "${BR_OUTPUT}/.config" && -f .config ]]; then
  cp .config "${BR_OUTPUT}/.config"
  sed -i "s|^BR2_DL_DIR=.*|BR2_DL_DIR=\"${BR_DL_DIR}\"|" "${BR_OUTPUT}/.config"
fi

if [[ ! -f .config && ! -f "${BR_OUTPUT}/.config" ]]; then
  echo "Missing .config — run: make -C cross/buildroot fetch sync-config" >&2
  exit 1
fi

if [[ $# -eq 0 ]]; then
  set -- bash
fi

case "$1" in
  bash|sh|/bin/bash|/bin/sh)
    exec "$@"
    ;;
  /*|./*)
    exec "$@"
    ;;
  make)
    shift
    exec make O="${BR_OUTPUT}" "$@"
    ;;
  *)
    exec make O="${BR_OUTPUT}" "$@"
    ;;
esac
