#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  exec bash
fi

case "$1" in
  shell)
    shift
    exec bash "$@"
    ;;
  syft|grype|jq|file|bash|sh)
    exec "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
