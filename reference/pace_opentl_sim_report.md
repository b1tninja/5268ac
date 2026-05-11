# PACE OpenTL mount simulator — validation report

This report documents **Phase C** checks from the OpenTL block-device simulator plan. The implementation lives under `opentl/` (`opentl_sim.py`, `spare_layout.py`, `stats_block.py`, `chain.py`) and the **`tl-mount-sim`** CLI (`python -m binwalker tl-mount-sim …`).

## Commands (run from repo root with `PYTHONPATH` including this workspace root)

```powershell
$env:PYTHONPATH = 'D:\electronics\5268ac'   # parent of the ``binwalker`` package directory
$pace = 'PACE 5268AC S34ML01G1@TSOP48.BIN'  # adjust path to your full flash dump

# Full-chip capture (138412032 B): skip loader + mtdoops so OpenTL’s 1012 blocks start at 0x180000.
python -m binwalker tl-mount-sim $pace --nand-logical-offset 0x180000 --out-bbm pace_sim_bbm_offset.json --json 2> tl_mount_sim.stderr.txt

# Carved tlpart-only (starts at byte 0 of the file) — default offset 0
python -m binwalker tl-mount-sim $pace --out-bbm pace_sim_bbm.json --json 2> tl_mount_sim.stderr.txt

# Strategies (recovery plan): ``auto`` (stats v2/v1/v3 then OOB all-page spare walk then slide),
# ``slide_only`` (fast ext2 magic probe per slide), ``stats_only``, ``spare_all``, etc.

# All-page spare collision policy (default ``lex``): ``chain_v1`` prefers kernel-aligned
# duplicate/mirror hops (``spare[8] & 4``) before ``(page, phys)`` lex tie-break — see
# ``output/opentl_mount/spare_chain_fields.md``.
python -m binwalker tl-mount-sim $pace --strategy spare_all --spare-infer chain_v1 --out-bbm pace_chain_v1_bbm.json

python -m binwalker tl-mount-sim $pace --strategy slide_only --out-bbm pace_slide_bbm.json

python -m binwalker tl-extract $pace --bbm pace_sim_bbm_offset.json --out opentla4_sim.ext2 --json
# (``nand_logical_offset`` is stored in the BBM JSON; pass ``--nand-logical-offset`` only to override)
```

**Carved logical-plane `tlpart`** (when `output/carved_flash/work/tlpart.bin` exists): same pipeline at **`nand_logical_offset=0`** proves **`tl-extract`** against a chip-grounded carve — success means **`ext2_magic_ok: true`** in **`tl-extract --dry-run --json`** output.

```powershell
$tp = 'output/carved_flash/work/tlpart.bin'
python -m binwalker tl-mount-sim $tp --out-bbm carved_bbm.json --json
python -m binwalker tl-extract $tp --bbm carved_bbm.json --dry-run --json
# Strict exit: add --require-ext2-magic (fails non-zero until BBM is correct)
```

Optional uImage check (see carve summary):

```powershell
python -m binwalker tl-extract $pace --bbm pace_sim_bbm.json --out opentla4_sim.ext2 `
  --verify-uimage 'PATH\to\tlpart_uimage_0x05d23ac0_*.bin'
```

## Five hard checks (plan §5)

| # | Check | How to verify | Status (CI / agent run) |
|---|--------|----------------|-------------------------|
| 1 | `virt_to_phys_block` length **982** | `python -c "import json; d=json.load(open('pace_sim_bbm_offset.json')); assert len(d['virt_to_phys_block'])==982"` | **Pass** on PACE with `--nand-logical-offset 0x180000` (synthetic tests also pass) |
| 2 | Pool counts **Used+Free+Bad = 1012**, **Bad = 30**, **Stats = 1** | Compare `geometry` + notes from `tl-mount-sim` JSON to `fwupgrade.txt` boot trace; optional bad/stat heuristics are documented in `opentl_sim.py` | **Informational** — geometry defaults match RE; exact flash classification requires on-device trace correlation |
| 3 | ext2 magic **`0x53 0xEF`** at offset **`0x438`** in `opentla4_sim.ext2` | `python -m binwalker tl-extract … --dry-run` / JSON **`ext2_magic_ok`** or `python -c "p=open('opentla4_sim.ext2','rb').read(); print(p[0x438:0x43a].hex())"` → `534ef` | **Still failing** with recovered BBM (linear fallback after slide): magic probe ≠ **`534ef`** until virt→phys is correct |
| 4 | `e2fsck -n -f opentla4_sim.ext2` clean (timestamps ok) | Linux/WSL: run `e2fsck`; Windows may use WSL | **Pending** |
| 5 | **`/sys1/uImage`** bytes match carve in `PACE ... carve/carve_summary.md` (3740634 B att 5268 image) | Use `tl-extract --verify-uimage` against carved reference or SHA/compare | **Pending** |

If **`tl-extract`** reports **`ext2_magic_ok: false`** (or **`--require-ext2-magic`** exits non-zero), the assembled bytes were produced faithfully from the BBM JSON—the failure is **almost certainly a wrong `virt_to_phys_block`** (e.g. **`mount_sim_v1_fallback_linear`** identity on NAND), **not** a bug in **`extract_virtual_disk_bytes`**. Fix the BBM (spare-chain / slide scoring / firmware-derived map), then re-run **`tl-extract`**.

### Offline verification notes

- **PACE TSOP48 (138412032 B), `--nand-logical-offset 0x180000` (May 2026):** `tl-mount-sim --strategy auto` → **`mount_sim_v1_fallback_linear`**. Notes from JSON: **stats v2/v1** still absent on flash; **spare all-pages inference filled 35/982** virt slots (`lex` tie-break; **`--spare-infer chain_v1`** was **also 35/982** on the same dump — duplicate-bit filtering does not invent missing virt observations). Incomplete spare decode vs kernel **`ntl_mount`** chain replay; **slide** ranks **`983`** candidate **`brute_reserved`** maps (``s = 0 … virt_blocks``) by **`ext2_primary_superblock_sanity`** on a **32 KiB** **`opentla4`** prefix (`opentl/ext2_lite.py`) — PACE still ends with **no** slide scoring **> 0** (same outcome as the older **first-hit two-byte magic** probe). **`nand_logical_offset`** is persisted in BBM JSON (**`nand_logical_offset`** field). Input SHA256 over the **tlpart-relative** logical prefix: **`50503c959182c310a5233e3d69ed397d90ffb9dba0470991fbaed83a4e247a76`** (distinct from mapping byte 0 as block 0 on the full chip).
- **PACE TSOP48 capture (agent):** full-file search found **no** contiguous LE stats header pair (`0x10000`/`0xdead1001`) in logical prefix or OOB tail — stats-driven map is unavailable for this dump; rely on **OOB spare inference** and/or **`brute_reserved` slide** (`--strategy slide_only`: **~32 KiB** **`opentla4`** prefix per slide + **`ext2_lite`** ranking — heavier than the legacy two-byte magic probe, better when multiple slides accidentally hit **0xEF53**).
- **`mount_flash_image`** / **`tl-mount-sim`**: stats parsers **v2** (full erase-block scan, 4-byte aligned header) then **v1**, then **v3** (multi-page stitch per **`ntl_load_stat_table`** span under identity BBM — `stats_block.try_parse_stats_v3_mount_page_geometry`); then **`infer_virt_map_from_all_page_spares`** (64 pages × 1012 blocks; tie-break **`(page_index, phys_block)`**, **not** full **`ntl_verify_chain_seqnum`** replay — see `mount_from_oob_walk` docstring). When spare inference is incomplete, notes include **`spare_collision`** lines from **`collect_spare_virt_phys_candidates`**. Then slide search. See `output/opentl_mount/README.md` for **`ntl_load_stat_table`** read geometry.
- Ghidra JSON captures: `output/opentl_mount/*.json`.

## Synthetic unit tests

```
PYTHONPATH=D:\electronics\5268ac python -m pytest binwalker/tests/test_opentl_sim.py -v
```

All tests passed in development (`spare` decode, **0xD00D** chain header, OOB tail sizing, embedded stats table, `mount_flash_image`).
