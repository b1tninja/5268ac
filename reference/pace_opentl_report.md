# PACE OpenTL offline mount — validation report

This report documents **Phase C** checks from the OpenTL block-device offline tooling plan. The implementation lives under `opentl/` (**`opentl/tl_mount/`**, `spare_layout.py`, `stats_block.py`, `chain.py`, `spare_chain_replay.py`) and the **`tl-mount`** CLI (`python -m opentl.tl_mount ...`).

## Commands (run from repo root with `PYTHONPATH` including this workspace root)

```powershell
$env:PYTHONPATH = 'D:\electronics\5268ac'
$pace = 'PACE 5268AC S34ML01G1@TSOP48.BIN'  # adjust path to your full flash dump

# Full-chip capture (138412032 B): skip loader + mtdoops so OpenTL’s 1012 blocks start at 0x180000.
python -m opentl.tl_mount $pace --nand-logical-offset 0x180000 --spare PATH\to\flat_spare.bin --json 2> tl_mount.stderr.txt

# Carved tlpart-only (starts at byte 0 of the file) — default offset 0; pair with flat spare when available
python -m opentl.tl_mount $pace --spare PATH\to\flat_spare.bin --json 2> tl_mount.stderr.txt

# `tl-mount` / `tl-bbm` exit 2 until `opentl.bbm_kernel_replay` implements `ntl_mount` table fill.
# Optional: --dump-stats-candidates adds stats magic locations to the error text (diagnostics).

python -c "import json; from pathlib import Path; from opentl.tl_bbm import BlockMapBuild; from opentl.nand_pipeline import NandPipeline; m=BlockMapBuild.from_dict(json.loads(Path('pace_bbm_offset.json').read_text(encoding='utf-8'))); p=NandPipeline.for_logical_plane(Path('$pace')); p.bbm=m; p.extract_opentla4(out_ext2=Path('opentla4.ext2'), auto_build_bbm=False)"
# Or let the pipeline build BBM from spare once kernel replay exists: NandPipeline.for_logical_plane(..., spare=...).build_bbm()
```

**Carved logical-plane `tlpart`** (when `output/carved_flash/work/tlpart.bin` exists): same pipeline at **`nand_logical_offset=0`** — assemble with **`extract_opentla4`** / **`NandPipeline`**; **`ext2_magic_ok`** comes from the **`ExtractResult`** (dry-run omits writing **`opentla4.ext2`**).

```powershell
$tp = 'output/carved_flash/work/tlpart.bin'
python -m opentl.tl_mount $tp --spare PATH\to\flat_spare.bin --json
python -c "from pathlib import Path; from opentl.nand_pipeline import NandPipeline; print(NandPipeline.for_logical_plane(Path('$tp'), spare='PATH/to/spare.bin').extract_opentla4(dry_run=True, auto_build_bbm=False))"
```

Optional uImage check (see carve summary):

```powershell
python -c "from pathlib import Path; from opentl.extract import extract_opentla4; import json; from opentl.tl_bbm import BlockMapBuild; m=BlockMapBuild.from_dict(json.loads(Path('pace_bbm_offset.json').read_text(encoding='utf-8'))); extract_opentla4(Path('$pace'), block_map=m, out_path=Path('opentla4.ext2'), verify_uimage_path=Path(r'PATH\to\tlpart_uimage_0x05d23ac0.bin'))"
```

## Five hard checks (plan §5)

| # | Check | How to verify | Status (CI / agent run) |
|---|--------|----------------|-------------------------|
| 1 | `virt_to_phys_block` length **982** | `python -c "import json; d=json.load(open('pace_bbm_offset.json')); assert len(d['virt_to_phys_block'])==982"` | **Pass** on PACE with `--nand-logical-offset 0x180000` (synthetic tests also pass) |
| 2 | Pool counts **Used+Free+Bad = 1012**, **Bad = 30**, **Stats = 1** | Compare `geometry` + notes from `tl-mount` JSON to `fwupgrade.txt` boot trace; optional bad/stat heuristics are documented in **`opentl/tl_mount`** | **Informational** — geometry defaults match RE; exact flash classification requires on-device trace correlation |
| 3 | ext2 magic **`0x53 0xEF`** at offset **`0x438`** in `opentla4.ext2` | `extract_opentla4(..., dry_run=True)` → **`ext2_magic_ok`**, or hex-read `opentla4.ext2` at **`0x438`** → `534ef` | **Still failing** without a kernel-faithful map: magic probe ≠ **`534ef`** until virt→phys matches **`*(remap+8)+virt×8`** |
| 4 | `e2fsck -n -f opentla4.ext2` clean (timestamps ok) | Linux/WSL: run `e2fsck`; Windows may use WSL | **Pending** |
| 5 | **`/sys1/uImage`** bytes match carve in `PACE ... carve/carve_summary.md` (3740634 B att 5268 image) | Use **`opentl.extract.extract_opentla4(..., verify_uimage_path=..., block_map=...)`** against carved reference or SHA/compare | **Pending** |

If **`extract_opentla4`** returns **`ext2_magic_ok: false`**, the assembled bytes still reflect **`virt_to_phys_block`** faithfully—the failure is **almost certainly a wrong map** (not matching kernel **`*(remap+8)+virt×8`**), **not** a bug in **`extract_virtual_disk_bytes`**. Fix the BBM (kernel remap table dump / spare-chain / firmware-derived map), then re-run extraction.

### Offline verification notes

- **PACE TSOP48 (138412032 B), `--nand-logical-offset 0x180000` (May 2026):** `tl-mount` raises **`IncompleteBBMInferenceError`** until kernel replay ships (no in-tree identity JSON). Notes from **`--dump-stats-candidates`** may still list stats magic hits. Kernel **`ntl_read_page`** uses **`*(remap+8)+virt×8`**. **`nand_logical_offset`** is persisted when a map is loaded from JSON. Input SHA256 over the **tlpart-relative** logical prefix: **`50503c959182c310a5233e3d69ed397d90ffb9dba0470991fbaed83a4e247a76`** (distinct from mapping byte 0 as block 0 on the full chip).
- **PACE TSOP48 capture (agent):** full-file search found **no** contiguous LE stats header pair (`0x10000`/`0xdead1001`) in logical prefix or OOB tail — stats-driven map is unavailable for this dump without a **`*(remap+8)`** table parser.
- **`tl_mount.mount_flash_image`** / **`tl-mount`**: delegates to **`opentl.bbm_kernel_replay`**; optional flat spare **byte length** sizes **`TLGeometry`**; **`--dump-stats-candidates`** for stats magic in **diagnostic** text only. Full on-disk stats / remap table parsers are **not** implemented here.
- Ghidra JSON captures: `output/opentl_mount/*.json`.

## Synthetic unit tests

```
PYTHONPATH=D:\electronics\5268ac python -m pytest tests/test_tl_mount.py tests/test_tl_extract_hole.py -v
```

All tests passed in development (`spare` decode, **0xD00D** chain header, OOB tail sizing, embedded stats table, `tl_mount` diagnostics + `IncompleteBBMInferenceError` until kernel replay).
