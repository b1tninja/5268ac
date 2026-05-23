"""Parse ``root=`` from a Linux-style command line."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from uboot.cmdline import parse_bootargs

_MTDBLOCK = re.compile(r"^/dev/mtdblock(\d+)$", re.I)
_MTD = re.compile(r"^/dev/mtd(\d+)$", re.I)


@dataclass(frozen=True, slots=True)
class RootSpec:
    """Resolved ``root=`` device (subset supported in v1)."""

    kind: Literal["mtdblock", "mtd", "ubi", "path", "unknown"]
    index: int | None
    raw: str
    ubi_volume: str | None = None


def parse_root_from_cmdline(cmdline: str) -> RootSpec | None:
    """
    Return :class:`RootSpec` for ``root=`` token, or ``None`` if missing / unsupported.

    Supported: ``root=/dev/mtdblockN``, ``root=/dev/mtdN``, ``root=ubiN:volname``.
    """
    m = parse_bootargs(cmdline)
    raw = m.get("root")
    if not raw:
        return None
    raw = str(raw).strip()

    ubi_m = re.match(r"^ubi(\d+):([\w./+-]+)$", raw, re.I)
    if ubi_m:
        return RootSpec(
            kind="ubi",
            index=int(ubi_m.group(1)),
            raw=raw,
            ubi_volume=ubi_m.group(2),
        )

    mm = _MTDBLOCK.match(raw)
    if mm:
        return RootSpec(kind="mtdblock", index=int(mm.group(1)), raw=raw)

    mm2 = _MTD.match(raw)
    if mm2:
        return RootSpec(kind="mtd", index=int(mm2.group(1)), raw=raw)

    if raw.startswith("/"):
        return RootSpec(kind="path", index=None, raw=raw)

    return RootSpec(kind="unknown", index=None, raw=raw)


__all__ = ["RootSpec", "parse_root_from_cmdline"]
