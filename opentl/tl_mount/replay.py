"""
Offline `ntl_mount` replay (mount-parity v2).

This module aims to be more kernel-faithful than a global spare-tag scan by:

- Using a `ntl_find_valid_spare`-like search per physical erase unit (scan pages until a
  mount-usable spare row is found).
- Following mode-2 `next_pblk` links (same semantics as `ntl_put_chain_in_array`) while
  enforcing that each hop's representative spare row claims the same virtual id.
- Populating the virt-slot table (`*(remap+8)`) with a deterministic choice derived from
  those chains, and emitting pool-style summaries via `opentl.chain.ChainPool`.

It is still an *offline* replay: it does not emulate allocator wear pressure, folding,
or every mount branch; the goal is faithful virt→phys selection for read parity.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from opentl.chain import ChainPool
from opentl.spare_chain_replay import next_phys_from_spare_chain_step, oob_page_spare
from opentl.tl_bbm import TLGeometry, TL_PHYS_BLOCK_HOLE, validate_virt_to_phys_block_entries
from opentl.tl_mount.replay_spare import MountSpareRow, mount_spare_row_or_none

_PAGES_PER_ERASE = 64


@dataclass(frozen=True)
class PhysProbe:
    """Representative mount spare row for a physical erase unit (or None if none found)."""

    row: MountSpareRow | None


def _probe_phys_representative(
    flat_oob: bytes,
    geo: TLGeometry,
    phys: int,
    *,
    pages_per_erase: int = _PAGES_PER_ERASE,
) -> PhysProbe:
    for pg in range(pages_per_erase):
        sp = oob_page_spare(flat_oob, geo, phys, pg)
        r = mount_spare_row_or_none(phys, pg, sp, large_page=True, pages_per_erase=pages_per_erase)
        if r is not None:
            return PhysProbe(row=r)
    return PhysProbe(row=None)


def _virt_chain_tail_for_start(
    flat_oob: bytes,
    geo: TLGeometry,
    start_phys: int,
    virt: int,
    *,
    phys_probe: dict[int, PhysProbe],
    max_hops: int = 0x46,
) -> tuple[int, int, bool]:
    """
    Follow mode-2 spare next links starting at start_phys while enforcing that each hop's
    representative spare row claims `virt`.

    Returns (tail_phys, chain_len, complete) where complete means we reached a terminator.
    """
    cur = int(start_phys)
    seen: set[int] = set()
    chain_len = 0
    complete = False
    tail = cur

    for _ in range(max_hops):
        if cur in seen:
            break
        if cur < 0 or cur >= geo.raw_blocks:
            break
        seen.add(cur)

        pr = phys_probe.get(cur)
        if pr is None:
            pr = _probe_phys_representative(flat_oob, geo, cur)
            phys_probe[cur] = pr
        if pr.row is None or pr.row.virt_u32 != (virt & 0xFFFFFFFF):
            break

        chain_len += 1
        tail = cur

        sp0 = oob_page_spare(flat_oob, geo, cur, 0)
        nxt, _fl = next_phys_from_spare_chain_step(sp0, page_size_is_0x200=False)
        if nxt is None:
            complete = True
            break
        cur = int(nxt)

    return int(tail), int(chain_len), bool(complete)


def build_virt_to_phys_from_mount_replay(
    flat_oob: bytes,
    geo: TLGeometry,
    *,
    max_hops: int = 0x46,
) -> tuple[list[int], list[str], list[str], dict]:
    """
    Build virt→phys table using mount-parity v2 replay rules.

    Returns (table, notes, warnings).
    """
    notes: list[str] = []
    warnings: list[str] = []
    debug: dict = {
        "geo": {
            "erase_bytes": int(geo.erase_bytes),
            "raw_blocks": int(geo.raw_blocks),
            "virt_blocks": int(geo.virt_blocks),
        },
        "per_virt": {},
        "stats": {},
    }

    phys_probe: dict[int, PhysProbe] = {}
    virt_candidates: dict[int, list[int]] = defaultdict(list)
    bad_phys: set[int] = set()

    for pb in range(int(geo.raw_blocks)):
        pr = _probe_phys_representative(flat_oob, geo, pb)
        phys_probe[pb] = pr
        if pr.row is None:
            continue
        v = int(pr.row.virt_u32)
        if 0 <= v < int(geo.virt_blocks):
            virt_candidates[v].append(int(pb))
        else:
            bad_phys.add(int(pb))

    table = [TL_PHYS_BLOCK_HOLE] * int(geo.virt_blocks)
    collisions = 0
    picked_tails: set[int] = set()

    for v in range(int(geo.virt_blocks)):
        cands = virt_candidates.get(v) or []
        if not cands:
            continue
        tails: list[tuple[int, int, bool, int]] = []
        per_v = {"candidates": sorted(set(cands)), "tails": []}
        for pb in sorted(set(cands)):
            tail, clen, complete = _virt_chain_tail_for_start(
                flat_oob,
                geo,
                pb,
                v,
                phys_probe=phys_probe,
                max_hops=max_hops,
            )
            # score: longer chain, complete terminator, lower tail phys
            tails.append((clen, 1 if complete else 0, -tail, tail))
            per_v["tails"].append(
                {"start_phys": int(pb), "tail_phys": int(tail), "chain_len": int(clen), "complete": bool(complete)}
            )

        tails.sort(reverse=True)
        chosen_tail = int(tails[0][3])
        table[v] = chosen_tail
        picked_tails.add(chosen_tail)
        if len({t[3] for t in tails}) > 1:
            collisions += 1
        per_v["chosen_tail"] = int(chosen_tail)
        debug["per_virt"][str(int(v))] = per_v

    # Pool-style summaries (not yet used to drive selection, but useful for debugging parity).
    freelist = ChainPool(raw_blocks=int(geo.raw_blocks))
    usedlist = ChainPool(raw_blocks=int(geo.raw_blocks))
    for pb in range(int(geo.raw_blocks)):
        if pb in bad_phys:
            continue
        if pb in picked_tails:
            usedlist.tl_add_chain(1, pb)
        else:
            freelist.tl_add_chain(1, pb)

    if collisions:
        warnings.append(f"mount_replay_v2: virt slots with multiple distinct tail candidates: {collisions}")

    n_mapped = sum(1 for x in table if x != TL_PHYS_BLOCK_HOLE)
    if n_mapped == 0:
        raise ValueError(
            "mount_replay_v2 found no mappable virt slots from flat spare "
            "(no xsum-valid rows with meaningful virt_u32)"
        )

    notes.append(
        f"mount_replay_v2: mapped {n_mapped} / {geo.virt_blocks} virt slots"
    )
    notes.append(f"mount_replay_v2: usedlist={usedlist.hdr.count} freelist={freelist.hdr.count} bad_phys={len(bad_phys)}")
    debug["stats"] = {
        "mapped": int(n_mapped),
        "holes": int(int(geo.virt_blocks) - n_mapped),
        "collisions": int(collisions),
        "usedlist": int(usedlist.hdr.count),
        "freelist": int(freelist.hdr.count),
        "bad_phys": int(len(bad_phys)),
    }

    validate_virt_to_phys_block_entries(table, geo)
    return table, notes, warnings, debug


__all__ = ["build_virt_to_phys_from_mount_replay"]

