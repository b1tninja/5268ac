# `boardfs` — MTD layout, OpenTL slices, and ext2 assembly

Python orchestration layer for **offline Pace 5268AC** flash work: turn **`mtdparts=`** and **`ubi.mtd=`** cmdline tokens into byte ranges on a logical NAND image, enumerate **TL disklabel** slices inside **`tlpart`**, attach **OpenTL BBM** replay, assemble **`opentla4`** ext2 bytes, and expose **path-oriented** ext2 list/read helpers.

**`boardfs` does not implement virt→phys replay** — that lives in **`opentl`** (`LogicalOpenTLSession`, `BlockMapBuild`, NTL reads). This package wires **flash geometry**, **registry state**, and **ext2** tooling.

**Deep dive** (BBM vs linear `mtdparts`, CMDB walker, UBI VID scan, Ghidra anchors): **[`reference/boardfs.md`](../reference/boardfs.md)**.  
**Stack diagram:** **[`reference/layers_unand_uboot_opentl_boardfs_paceflash.md`](../reference/layers_unand_uboot_opentl_boardfs_paceflash.md)**.  
**User-facing CLI** for ext2 paths: **[`paceflash/README.md`](../paceflash/README.md)** (`paceflash` imports **boardfs** only).

---

## Layers (A → D)

| Layer | Modules | Role |
|-------|---------|------|
| **A** | [`flash.py`](flash.py) | **`mtdparts=`** → partition byte offsets on a logical plane |
| **B** | [`registry.py`](registry.py), [`tl_chain.py`](tl_chain.py), **`opentl.tldisk`** | **`tlpart`** scan buffer, TL slices, BBM-assembled **`AssembledBlockDev`** |
| **C** | [`ubi_cmdline.py`](ubi_cmdline.py), [`ubi_scan.py`](ubi_scan.py) | **`ubi.mtd=`** specs, raw **UBI VID** header hits |
| **D** | [`squashfs_probe.py`](squashfs_probe.py) | **`hsqs`** magic peek on a block slice |

**Ext2:** [`ext2_dissect.py`](ext2_dissect.py) (superblock, mount **`/`**, GD sanitize) and [`ext2_path.py`](ext2_path.py) (`list_ext2_directory`, `read_ext2_regular_file`). PACE CMDB directory skew uses lag/`+2` resolution in [`ext2_dissect.py`](ext2_dissect.py).

---

## Install

From the repo root:

```bash
pip install -e ".[dissect]"
```

Entry points:

- **`python -m boardfs`** — BBM introspection CLI
- **`boardfs`** — same (see **`pyproject.toml`** `[project.scripts]`)

**`paceflash`** is the primary operator CLI for **`ls` / `cat` / `shell`** on assembled **`opentla4`**.

---

## Command-line (`python -m boardfs`)

Low-level OpenTL / BBM debugging (not directory listing):

```bash
# Virt→phys map summary + TL scan head hash
python -m boardfs virt-map "PACE 5268AC S34ML01G1@TSOP48.BIN" --json

# NAND page rows for a virtual byte span on the TL disk
python -m boardfs page-table "PACE …BIN" --virt-start 0 --virt-len 8192
```

Shared flags (from **`cli_flash`**): **`--cmdline`**, **`--nand-translate`** (default on full-chip Pace size), **`--nand-mode inline-2112|flat-tail`**, **`--debug-log`**, **`--tl-probe-report`**.

---

## Library quick start

### Full-chip physical dump → registry + BBM

```python
from boardfs import temporary_registry_from_physical_nand, assemble_opentla4_volume

with temporary_registry_from_physical_nand(
    "PACE 5268AC S34ML01G1@TSOP48.BIN",
    "quiet rw mtdparts=mtd-0:524288(loader),1048576(mtdoops),-(tlpart)",
) as (reg, manifest, session):
    vol = assemble_opentla4_volume(reg, chain_aware=True)
    print(vol.read_model, vol.ext2_superblock_offset)
```

### `FsRegistry` on an existing logical image

```python
from boardfs import FsRegistry, flash_image_from_cmdline

flash = flash_image_from_cmdline("tlpart.bin", "quiet rw mtdparts=…")
reg = FsRegistry(flash=flash, cmdline="…")
reg.attach_open_tl_bbm(block_map, linear_prefix=prefix_bytes)

dev = reg.block_dev_for_tl_slice("opentla4")  # AssembledBlockDev when BBM attached
```

### Ext2 paths (in-memory slice bytes)

```python
from boardfs import list_ext2_directory, read_ext2_regular_file, assemble_opentla4_volume

vol = assemble_opentla4_volume(reg)
names = list_ext2_directory(vol.slice_bytes, "/cm")
data = read_ext2_regular_file(vol.slice_bytes, "cm/cmlegacy.498.xml")
```

Public exports are listed in [`__init__.py`](__init__.py) (`FsRegistry`, `assemble_opentla4_volume`, UBI helpers, chain-aware inference, …).

---

## `FsRegistry` essentials

| Concept | Behavior |
|---------|----------|
| **`attach_open_tl_bbm`** | Holds **`LogicalOpenTLSession`** + fills **`tlpart_tl_scan_bytes`** from the **virtual** TL stream |
| **`block_dev_for_tl_slice`** | **Assembled** payload via **`extract_virtual_disk_bytes`** when BBM is attached; else **linear** `tlpart` offset math |
| **`replace_open_tl_block_map`** | Swap map, refresh scan buffer, invalidate TL caches |
| **`temporary_registry_from_physical_nand`** | **`opentl.nand_bootstrap.translate_physical_nand`** + optional BBM attach in a temp dir |

**Hole semantics:** unmapped virt slots → zero-filled bytes (kernel **`ntl_read_page`** behavior). See **[`reference/ghidra_boardfs_bbm_readpath.md`](../reference/ghidra_boardfs_bbm_readpath.md)**.

---

## Module map

| Module | Role |
|--------|------|
| [`registry.py`](registry.py) | **`FsRegistry`**, BBM attach, TL enumeration, slice → **`BlockDev`** |
| [`block.py`](block.py) | **`BlockDev`**, **`AssembledBlockDev`**, **`BlockSlice`** |
| [`bootstrap.py`](bootstrap.py) | **`temporary_registry_from_physical_nand`** |
| [`tl_chain.py`](tl_chain.py) | **`assemble_opentla4_volume`**, chain-aware BBM inference |
| [`pipeline.py`](pipeline.py) | **`fs_registry_from_nand_pipeline`** |
| [`ext2_dissect.py`](ext2_dissect.py) | Superblock resolve, list **`/`**, Dissect-oriented sanitize |
| [`ext2_path.py`](ext2_path.py) | Directory listing and file read by path |
| [`ext2_volume_io.py`](ext2_volume_io.py) | Block-level ext2 I/O with optional NTL context |
| [`cli.py`](cli.py) | **`virt-map`**, **`page-table`** |
| [`cli_flash.py`](cli_flash.py) | Shared flash-open helpers for CLI |

---

## Dependencies

| Package | Use |
|---------|-----|
| **`unand`** | Logical plane geometry, **`mtdparts`** parse |
| **`uboot`** | Cmdline / env token helpers (via flash layout) |
| **`opentl`** | BBM, NTL, **`tldisk`**, nand bootstrap |
| **`boardfs.flash_layout` / `boardfs.ubi_carve`** | **`FlashImage`**, UBI media helpers |
| **dissect.extfs** | ext2 mount (optional **`[dissect]`**) |

---

## Consumers

| Package | Relationship |
|---------|----------------|
| **`paceflash`** | All NAND → ext2 operator commands; **`build_inventory`** |
| **`corpus`** | Consumes public flash artifacts via **`paceflash.artifacts`** |
| **`opentl`** | Replay implementation; **boardfs** calls into **`opentl.tl_chain`** / **`nand_bootstrap`** |

---

## Ghidra / kernel docs

| Topic | Doc |
|-------|-----|
| BBM read path | [`reference/ghidra_boardfs_bbm_readpath.md`](../reference/ghidra_boardfs_bbm_readpath.md) |
| **`opentla4`** NTL | [`reference/ghidra_ntl_rw_opentla4_mcp.md`](../reference/ghidra_ntl_rw_opentla4_mcp.md) |
| ext2 / CMDB | [`reference/ghidra_ext2_cm_cmdb_kernel_mcp.md`](../reference/ghidra_ext2_cm_cmdb_kernel_mcp.md) |
| TL disklabel | [`reference/ghidra_parse_bsd_disklabel_layout.md`](../reference/ghidra_parse_bsd_disklabel_layout.md) |
| `#region kernel:` markers | [`reference/kernel_python_regions.md`](../reference/kernel_python_regions.md) |

---

## Tests

```bash
pytest tests/test_boardfs.py tests/test_boardfs_import_boundary.py \
  tests/test_ext2_path.py tests/test_opentla4_volume.py tests/test_logical_opentl_session.py -q
```

Full **PACE** integration:

```powershell
$env:PACE_FLASH_INTEGRATION = "1"
pytest tests/test_opentla4_532678_mount.py -q --timeout=300
```

---

## See also

- **[`opentl/README.md`](../opentl/README.md)** — BBM replay, **`tl-mount`**, NTL  
- **[`unand/README.md`](../unand/README.md)** — logical plane vs spare  
- **[`reference/boot_and_storage.md`](../reference/boot_and_storage.md)** — boot + MTD diagrams  
- **[Root README](../README.md)** — workspace overview
