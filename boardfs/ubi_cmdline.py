"""Parse ``ubi.mtd=`` attachments from a kernel command line (separate from TL ``parse_bsd`` path)."""

from __future__ import annotations

from dataclasses import dataclass
@dataclass(frozen=True, slots=True)
class UbiMtdAttachSpec:
    """
    One ``ubi.mtd=`` token as passed to the kernel.

    * ``mtd_ref`` — MTD partition **name** (e.g. ``tlpart``) or **index** (decimal string).
    * ``mtd_sub_offset`` — optional byte offset within that MTD device (second comma field).
    """

    raw_token: str
    mtd_ref: str
    mtd_sub_offset: int | None


def iter_ubi_mtd_attach_specs(cmdline: str) -> tuple[UbiMtdAttachSpec, ...]:
    """
    Extract all ``ubi.mtd=…`` tokens (space-delimited cmdline).

    Does **not** validate names against ``mtdparts``; use :class:`~boardfs.registry.FsRegistry`
    to map ``mtd_ref`` to a :class:`~boardfs.block.BlockDev`.
    """
    out: list[UbiMtdAttachSpec] = []
    for tok in cmdline.split():
        t = tok.strip()
        if not t.lower().startswith("ubi.mtd="):
            continue
        val = t.split("=", 1)[1].strip()
        parts = val.split(",", 1)
        ref = parts[0].strip()
        sub: int | None = None
        if len(parts) > 1:
            sub = int(parts[1].strip(), 0)
        out.append(UbiMtdAttachSpec(raw_token=t, mtd_ref=ref, mtd_sub_offset=sub))
    return tuple(out)


__all__ = ["UbiMtdAttachSpec", "iter_ubi_mtd_attach_specs"]
