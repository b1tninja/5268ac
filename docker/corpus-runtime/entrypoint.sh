#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  exec python -m corpus --help
fi

case "$1" in
  corpus)
    shift
    exec python -m corpus "$@"
    ;;
  paceflash)
    shift
    exec python -m paceflash "$@"
    ;;
  boardfs|python|python3|pip|pip3|syft|grype|vmlinux-to-elf|jq|file|bash|sh)
    exec "$@"
    ;;
  mirror-pkgstreams|pkgstream-mirror)
    shift
    exec pkgstream-mirror "$@"
    ;;
  shell)
    shift
    exec bash "$@"
    ;;
  *)
    exec python -m corpus "$@"
    ;;
esac
