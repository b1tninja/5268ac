"""
SCRIPT TLV **staging and execution** path (``lib2sp``) — stubs only.

Decompilation shows ``lib2sp_write_script`` reallocating a heap buffer and
``lib2sp_close_script`` finalizing it (including a newline + null trailer), then calling an
**indirect helper** — likely ``system`` / ``popen`` / a ``tw_*`` wrapper (rename pending
in Ghidra).

Carrier SCRIPT bodies observed in ``reference/pkgstream.md`` §9.10 are **POSIX shell**
(``#!/bin/sh``), not bytecode.
"""

from __future__ import annotations


def stub_close_script_runner() -> None:
    """Placeholder for the indirect target used from ``lib2sp_close_script``."""
    raise NotImplementedError(
        "Resolve PTR_00034448+0x50b4 (or equivalent) in Ghidra; see "
        "output/ghidra_mcp_lib2sp_10_5_3_527064/README.md Next steps."
    )
