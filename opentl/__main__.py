"""Unified OpenTL CLI entry point (extend with additional subcommands here)."""

from __future__ import annotations

import sys


def main() -> None:
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "tl-mount":
            from opentl.tl_mount.cli import main as tl_mount_cli_main

            sys.argv = [sys.argv[0]] + sys.argv[2:]
            raise SystemExit(tl_mount_cli_main())
        if cmd == "hexdump":
            sys.argv = [sys.argv[0]] + sys.argv[2:]
            from opentl.hexdump import main as hexdump_main
            hexdump_main()
            return

    print(
        "usage: python -m opentl tl-mount FLASH …  (or: python -m opentl.tl_mount …)\n"
        "       python -m opentl.hexdump PATH [--spare] [--range START END]\n"
        "Firmware carve / unified workflows live outside this package (see workspace docs).",
        file=sys.stderr,
    )
    raise SystemExit(2)


if __name__ == "__main__":
    main()
