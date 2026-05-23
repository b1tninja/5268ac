"""``python -m opentl.tl_mount`` → same CLI as ``python -m opentl tl-mount``."""

from __future__ import annotations

import sys

from opentl.tl_mount.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
