"""Typed records for documenting on-device pkgstream / lib2sp behavior (stubs only)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Tuple

Subsystem = Literal["lib2sp", "pkgd", "pkgc", "libpkg_client", "httpd", "cwmd", "unknown"]
EffectClass = Literal[
    "stream_to_path",
    "stage_buffer",
    "fs_op",
    "orchestration",
    "verify_only",
    "scan_only",
    "unknown",
]


@dataclass(frozen=True)
class RuntimeHandlerStub:
    """One row of evidence-backed runtime semantics (no executable emulation)."""

    symbol: str
    subsystem: Subsystem
    effect_class: EffectClass
    notes: str
    evidence: Tuple[str, ...] = field(default_factory=tuple)
    open_questions: Tuple[str, ...] = field(default_factory=tuple)
    # Single-token install verb (copy, move, stage, …); details go in install_comment.
    install_action: str = ""
    # Tooltip-style sentence (like a 010 Editor <comment=…>); Ghidra symbol stays in symbol.
    install_comment: str = ""
