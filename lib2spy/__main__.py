"""``python -m lib2spy`` — forwards to :mod:`lib2spy.pkgstream` CLI."""

from __future__ import annotations

from lib2spy.pkgstream import main

if __name__ == "__main__":
    raise SystemExit(main())
