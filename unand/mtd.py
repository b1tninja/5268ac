"""
MTD cmdline partition table (``mtdparts=``) on the **logical data plane** only.

Offsets and sizes are **main** bytes (``NandGeometry.logical_bytes``), i.e. what the
kernel exposes as MTD user data. They do **not** include OOB/spare; spare is not an
``mtdparts`` slice. See package ``README.md``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#region kernel_adjacent mtdparts_logical_plane (U-Boot / kernel MTD naming; cross-link uboot + boardfs.flash)
# Observed Pace 5268 (fwupgrade.txt / firmware.md)
DEFAULT_MTDPARTS = "mtdparts=mtd-0:524288(loader),1048576(mtdoops),-(tlpart)"

_SIZED_RE = re.compile(r"^(?P<size>0x[0-9a-fA-F]+|\d+)\s*\(\s*(?P<name>[a-zA-Z0-9_]+)\s*\)\s*$")
_REMAINDER_RE = re.compile(r"^-\s*\(\s*(?P<name>[a-zA-Z0-9_]+)\s*\)\s*$")


@dataclass(frozen=True, slots=True)
class MtdPart:
    name: str
    offset: int
    size: int


def parse_mtdparts(
    cmdline: str,
    *,
    logical_total: int | None = None,
) -> tuple[MtdPart, ...]:
    """
    Parse a single mtdparts=... segment from a kernel cmdline fragment.

    Example: ``mtdparts=mtd-0:524288(loader),1048576(mtdoops),-(tlpart)``
    """

    m = re.search(r"mtdparts\s*=\s*([^:\s]+)\s*:\s*(.+)", cmdline)
    if not m:
        raise ValueError(f"No mtdparts=... found in {cmdline!r}")
    rest = m.group(2).strip()
    specs = [s.strip() for s in rest.split(",") if s.strip()]
    parts: list[MtdPart] = []
    offset = 0
    has_remainder = False
    sum_explicit = 0
    rem_name: str | None = None

    for spec in specs:
        rm = _REMAINDER_RE.match(spec)
        if rm:
            if has_remainder:
                raise ValueError("multiple remainder (-) partitions not supported")
            has_remainder = True
            rem_name = rm.group("name")
            continue
        sm = _SIZED_RE.match(spec)
        if not sm:
            raise ValueError(f"Bad partition spec {spec!r}")
        size = int(sm.group("size"), 0)
        name = sm.group("name")
        parts.append(MtdPart(name=name, offset=offset, size=size))
        offset += size
        sum_explicit += size

    if has_remainder:
        if logical_total is None:
            raise ValueError("logical_total required when mtdparts uses '-' remainder")
        rem_size = logical_total - sum_explicit
        if rem_size < 0:
            raise ValueError("remainder negative — partition sizes exceed logical_total")
        assert rem_name is not None
        parts.append(MtdPart(name=rem_name, offset=sum_explicit, size=rem_size))

    return tuple(parts)


def part_by_name(parts: tuple[MtdPart, ...], name: str) -> MtdPart:
    for p in parts:
        if p.name == name:
            return p
    raise KeyError(name)


#endregion
