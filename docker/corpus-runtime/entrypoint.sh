#!/usr/bin/env bash
set -euo pipefail

export OPENTL_FULL_ASSEMBLY="${OPENTL_FULL_ASSEMBLY:-1}"

# Prefer the host-mounted repo at /work (Compose) over the image's /opt/5268ac install.
if [[ -f /work/pyproject.toml ]]; then
  export PYTHONPATH="/work${PYTHONPATH:+:${PYTHONPATH}}"
fi

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
  boardfs|python|python3|pip|pip3|syft|grype|gitleaks|vmlinux-to-elf|jq|file|bash|sh)
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
