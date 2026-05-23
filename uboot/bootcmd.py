"""
U-Boot ``bootcmd`` script — conservative splitting and helpers.

U-Boot scripts are often ``;``-separated commands. This is **not** a full U-Boot parser
(no ``if`` nesting, no ``${var}`` expansion). Use for offline triage of dumps / env
extracts; combine with :mod:`uboot.cmdline` when a segment contains ``setenv bootargs …``.
"""

from __future__ import annotations

import re


def parse_bootcmd_segments(bootcmd: str) -> tuple[str, ...]:
    """
    Split ``bootcmd`` on ``;`` after stripping outer whitespace.

    Empty segments are dropped.
    """
    parts = [p.strip() for p in bootcmd.split(";")]
    return tuple(p for p in parts if p)


def segments_with_setenv_bootargs(segments: tuple[str, ...]) -> tuple[str, ...]:
    """Return segments that look like they assign ``bootargs`` (heuristic)."""
    pat = re.compile(r"setenv\s+bootargs\b", re.IGNORECASE)
    return tuple(s for s in segments if pat.search(s))


def extract_bootargs_value_from_setenv(segment: str) -> str | None:
    """
    If ``segment`` is ``setenv bootargs <rest>``, return ``<rest>`` (stripped).

    Does not strip quotes; caller may pass result to :func:`uboot.cmdline.parse_bootargs`
    or :func:`uboot.mtdparts.partition_table_from_bootargs`.
    """
    m = re.match(r"^\s*setenv\s+bootargs\s+(.+)$", segment, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return m.group(1).strip()
