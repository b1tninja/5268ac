# `opentl` — offline OpenTL on Pace 5268-class NAND

Python port of the **Broadcom/Pace OpenTL** block layer on the **`tlpart`** MTD slice: virtual erase-block translation (BBM), **BSD disklabel** slices (`opentla1` … `opentla4`), and assembly of **`opentla4`** ext2 for offline analysis.

This package does **not** talk to hardware. It consumes **logical NAND planes** (and optional flat spare streams) produced by **[`unand`](../unand/README.md)** and layout hints from **[`uboot`](../uboot/)** / **[`boardfs`](../reference/boardfs.md)**.

**Long-form firmware RE** (boot paths, partition table, open questions, grep strings): **[`reference/opentl.md`](../reference/opentl.md)**.  
**Stack diagram** (`unand` → `paceflash`): **[`reference/layers_unand_uboot_opentl_boardfs_paceflash.md`](../reference/layers_unand_uboot_opentl_boardfs_paceflash.md)**.

---

## What OpenTL does on the device (one paragraph)

After **`mtdparts=…(tlpart)`**, the kernel (and U-Boot) see a TL disk **`opentla0`** (~982 × 128 KiB virtual blocks, 512-byte sectors). A **disklabel** splits it into env slices (**`opentla1`/`opentla2`**) and a large **ext2** region **`opentla4`** (runtime **`/dev/opentla4`**, U-Boot **`opentl 0:5`** for `/sys1/uImage`). Raw **`tlpart.bin`** carves are not a linear ext2 image until **virt→phys** remap (and, for **`opentla4`**, NTL spare-chain reads) is replayed.

---

## Install

From the repo root (workspace package):

```bash
pip install -e ".[dissect]"
```

`dissect` is optional but needed for **`ext2_probe`** / Dissect-based chain inference. Generated files default under **`output/`** — override with **`OUTPUT_DIR`** before importing **`opentl.paths`** (see [`paths.py`](paths.py)).

---

## Import layout

| Import | Loads |
|--------|--------|
| `import opentl` | **`opentl.driver` only** — `OpenTL`, `LogicalOpenTLSession`, BBM builders, extract helpers (lightweight) |
| `from opentl.nand_pipeline import NandPipeline, nand` | Translate + BBM + **`extract_opentla4`** orchestration |
| `from opentl.tl_mount import mount_flash_image, …` | Kernel-shaped BBM replay + CLI |
| `from opentl.tldisk import enumerate_tl_slices, …` | Disklabel slice enumeration |

Host modules (**`nand_pipeline`**, **`tl_mount`**, **`nand_translate`**, **`ntl_rw`**, …) are **not** imported by `import opentl` so scripts can avoid the full dependency graph.

Driver-level API notes: **[`driver/README.md`](driver/README.md)**.

---

## Command-line tools

```bash
# BBM map from a logical plane or full-chip dump (auto spare on Pace-class raw files)
python -m opentl tl-mount "PACE 5268AC S34ML01G1@TSOP48.BIN" --json
python -m opentl.tl_mount tlpart.bin --spare flat_spare.bin --out-bbm bbm.json

# Page hexdump (main and/or spare)
python -m opentl hexdump tlpart.bin --range 0 0x2000
```

**`paceflash`** and **`binwalker`** workflows sit above this layer — see **[`reference/paceflash.md`](../reference/paceflash.md)** and **[`reference/tools.md`](../reference/tools.md)** (`partition-map`, `tl-bbm`, carve pipelines).

---

## Library quick start

### Translate + extract `opentla4`

```python
from pathlib import Path
from opentl.nand_pipeline import nand

# Full-chip inline 2048+64 dump → logical plane + spare, then BBM + ext2 bytes
nand("PACE 5268AC S34ML01G1@TSOP48.BIN").translate(mode="inline-2112").extract_opentla4(
    out_ext2=Path("output/opentla4.ext2"),
)

# Already-carved tlpart + sidecar spare
from opentl.nand_pipeline import NandPipeline
NandPipeline.for_logical_plane("output/carved_flash/work/tlpart.bin", spare="flat_spare.bin").extract_opentla4(
    dry_run=True,
)
```

### Driver-only virt read

```python
from opentl import OpenTL, LogicalOpenTLSession, build_block_map_from_kernel_mount_replay

# After tl-mount or kernel_replay: session over linear prefix + BlockMapBuild
session = LogicalOpenTLSession.from_linear_prefix_bytes(prefix_bytes, block_map)
virt_stream = session.virtual_tl_byte_stream()
```

---

## Module map

| Module | Role |
|--------|------|
| [`driver/`](driver/) | Public **kernel-shaped** facade (`OpenTL`, BBM, virt assembly) |
| [`open_tl.py`](open_tl.py) | `OpenTL`, `extract_opentla4`, virt/global byte helpers |
| [`logical_opentl_session.py`](logical_opentl_session.py) | Prefix + `BlockMapBuild`; chain-aware materialization |
| [`bbm_kernel_replay.py`](bbm_kernel_replay.py) | Spare-chain replay → `BlockMapBuild` (`kernel_replay_v1`) |
| [`ntl_rw.py`](ntl_rw.py) | **`opentla4`** NTL mode-2 page reads (offline port of kernel path) |
| [`opentla4_volume.py`](opentla4_volume.py) | Assemble rw slice (NTL / linear / BBM read models) |
| [`tldisk.py`](tldisk.py) | BSD disklabel slices from `tlpart` MTD bytes |
| [`nand_translate.py`](nand_translate.py) | Raw dump → logical main + flat spare files |
| [`nand_pipeline.py`](nand_pipeline.py) | **`NandPipeline`**, post-carve BBM hooks for binwalker |
| [`tl_mount/`](tl_mount/) | `mount_flash_image`, CLI |
| [`stats_block.py`](stats_block.py) | Stats-block tail layout (partial decode) |
| [`paths.py`](paths.py) | `OUTPUT_DIR`, `find_carved_tlpart()` |

Kernel RE cross-reference: Python sources use **`#region kernel: 0x…`** markers — index in **[`reference/kernel_python_regions.md`](../reference/kernel_python_regions.md)**.

---

## Ghidra / kernel documentation

| Topic | Doc |
|-------|-----|
| Driver symbols, ECC, attach | [`reference/opentl_kernel_ghidra.md`](../reference/opentl_kernel_ghidra.md) |
| **`opentla4`** NTL chains | [`reference/ghidra_ntl_rw_opentla4_mcp.md`](../reference/ghidra_ntl_rw_opentla4_mcp.md) |
| BBM read path | [`reference/ghidra_boardfs_bbm_readpath.md`](../reference/ghidra_boardfs_bbm_readpath.md) |
| Sector / `CBLKMAP` layout | [`reference/ghidra_opentla4_disk_layout_mcp.md`](../reference/ghidra_opentla4_disk_layout_mcp.md) |
| Stats block | [`reference/opentl_stats_block_layout.md`](../reference/opentl_stats_block_layout.md) |

---

## Consumers

| Package | How it uses `opentl` |
|---------|----------------------|
| **`boardfs`** | `FsRegistry`, `assemble_opentla4_volume`, BBM attach — [`reference/boardfs.md`](../reference/boardfs.md) |
| **`paceflash`** | Inventory / `ls` / `shell` via **boardfs** (no direct `opentl` imports in CLI) — [`reference/paceflash.md`](../reference/paceflash.md) |
| **`binwalker`** | `flash_layout`, carve manifests, `post_carve_bbm` — [`binwalker/README.md`](../binwalker/README.md) |

---

## Tests

```bash
pytest tests/test_opentl_ntl_rw.py tests/test_virt_slot.py tests/test_bbm_chain_session.py -q
```

Broader integration tests may require **`PACE_FLASH_INTEGRATION=1`** and a local flash dump (see root **`pyproject.toml`** markers).

---

## See also

- **[`reference/issue.md`](../reference/issue.md)** — why linear `tlpart` reads fail without BBM  
- **[`reference/README.md`](../reference/README.md)** — full RE index  
- **[`unand/README.md`](../unand/README.md)** — logical plane vs spare, `mtdparts` on main bytes only
