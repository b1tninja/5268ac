"""Shared artifact records consumed by the corpus indexer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class CorpusArtifact:
    """One logical payload with enough provenance to build a stable corpus image key."""

    source_key: str
    kind: str
    logical_path: str
    data: bytes
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.data)

    def read_bytes(self) -> bytes:
        return self.data


__all__ = ["CorpusArtifact"]
