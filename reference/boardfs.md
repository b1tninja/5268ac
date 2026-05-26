# `boardfs` — MTD, TL disklabel, UBI hints

Python package at repo root: **`boardfs/`**. It chains **MTD** layout (**`mtdparts`**) with **OpenTL TL disklabel** slices (**`opentl.tldisk`**) and optional **filesystem** helpers. It complements **[boot_and_storage.md](boot_and_storage.md)** for scripted offline workflows.

**BBM / spare vs linear `mtdparts` bytes:** The kernel’s **`parse_bsd`** reads **512-byte logical sectors** through **`read_dev_sector`** (page cache → **`ntl_read_page`** BBM remap), **not** by grepping the linear plane for a contiguous printk tuple chain — see **[ghidra_parse_bsd_disklabel_layout.md](ghidra_parse_bsd_disklabel_layout.md)**. Offline, **`opentl.tldisk.parse_bsd_disklabel_sector`** mirrors the **`FUN_8020ec1c`** layout; **`enumerate_tlpart_tl`** prefers the **BBM virtual** stream when it has a disklabel anchor, otherwise **linear ``tlpart``** when the virtual head is zeroed but linear still has **`bsd_magic`** / valid sectors ([`FsRegistry._tlpart_enumeration_bytes_and_source`](D:/electronics/5268ac/boardfs/registry.py)). **Identity** linear **`block_dev_for_tl_slice`** offsets can still disagree with **virtual** slice payloads when the primary BBM map is wrong — use chain-aware assembly (**`paceflash --bbm-chain-aware`** or automatic inference in **`paceflash.inventory`**).

When a **`BlockMapBuild`** is attached via **`FsRegistry.attach_open_tl_bbm(block_map, linear_prefix=…)`**, the registry (1) builds **`LogicalOpenTLSession`** and fills **`tlpart_tl_scan_bytes`** from **`LogicalOpenTLSession.virtual_tl_byte_stream()`** so **`enumerate_tlpart_tl`** sees the **virtual** stream, and (2) returns **`boardfs.block.AssembledBlockDev`** from **`block_dev_for_tl_slice`**, whose payloads come from **`LogicalOpenTLSession.extract_virtual_disk_bytes`** at each slice’s **`(offset_bytes, length_bytes)`** in virtual space. The default **linear prefix** is **`min(block_map.logical_prefix_bytes, flash.size)`** read from **file offset 0** on the same logical plane as the map (see **`boardfs.registry.read_linear_plane_prefix`**). That convention must match how the map was built (typically the first **`logical_prefix_bytes`** of the **full** logical image, not a substring starting mid-file); BBM mode is **invalid** for carve-only images unless prefix and map agree.

**Layer boundary:** **`boardfs`** orchestrates MTD + TL enumeration + assembled slices; it does **not** implement OpenTL virt→phys replay. The single read-model object for prefix + BBM + in-place map swap is **`FsRegistry.attached_logical_opentl_session`** (`LogicalOpenTLSession | None`). Use **`FsRegistry.replace_open_tl_block_map`** to swap the map while keeping the stored linear prefix; it refreshes **`tlpart_tl_scan_bytes`**, syncs **`attached_block_map`**, delegates to **`LogicalOpenTLSession.replace_block_map`**, and calls **`invalidate_tl_cache()`** (TL disklabel cache + virt-slice payload cache only — the session object stays unless you re-attach BBM). For **`#region kernel:`** / **`#region kernel_adjacent`** conventions and Ghidra EA anchors, see **[kernel_python_regions.md](kernel_python_regions.md)** and **[ghidra_boardfs_bbm_readpath.md](ghidra_boardfs_bbm_readpath.md)**.

**Follow-up (non-kernel tooling):** kernel-faithful linearization of raw spare into a **`BlockMapBuild`** is not implemented in **`opentl.tl_bbm_linearize`** (placeholder / **`NotImplementedError`** for non-trivial paths); use **`opentl.tl_mount`** / kernel replay docs until that module is completed.

**Constructor:** optional ``block_map=`` and ``bbm_linear_prefix=`` on :class:`boardfs.registry.FsRegistry` call :meth:`~boardfs.registry.FsRegistry.attach_open_tl_bbm` during init (same effect as calling it afterward).

**Legacy path:** set **`FsRegistry.tlpart_tl_scan_bytes`** manually for TL enumeration only (without a full **`BlockMapBuild`**); without **`attach_open_tl_bbm`**, **`block_dev_for_tl_slice`** still uses **linear** **`tlpart.offset + mtd_skip + slice.offset_bytes`** on the flash backing.

**Ext2 dissect** (mount, list `/`, superblock normalize/sanitize for Dissect) lives in **`boardfs.ext2_dissect`**. **Path-oriented** list/read (**`ls`**, **`cat`**, shell) uses **`boardfs.ext2_path`** on the same in-memory slice bytes. **`/etc/fstab`** parsing remains in **`paceflash.fstab`**.

**Mount status (PACE `S34ML01G1@TSOP48.BIN`, May 2026):** After **`assemble_opentla4_volume`** with auto chain-aware BBM, Dissect mounts at **`ext2_superblock_offset=1024`**; root lists **`cm`**, **`sys1`**, … Large files (**`sys1/rootimage.img`**, **`sys1/ui.img`**) read via default **`read_ext2_regular_file`** (stock **`ext2_get_block`** + GD sanitize for Dissect). On opentla4 (**`s_inode_size == 0`**), **`read_ext2_regular_file`** / default **`paceflash cat`** use **`boardfs.cmdb_extent_walker`** (PACE on-disk **13-direct** layout, lag rules, near-extent **`<?xml`** scan when inode pointers miss the header — e.g. **`cm/cmlegacy.498`**). That **differs** from the running kernel’s **`ext2_get_block`** path (**12** direct, indirect at slot **12**, no orphan scan — Ghidra @ **`0x8013d5a0`** / **`0x8013c9f0`**). **`paceflash cat --cmdb-recover`** forces the walker on any volume. A true kernel-only read (stock mapping + **`i_size`**) is what **`debugfs`** / **`e2fsck stat`** report for stale inodes — see **[ghidra_ext2_cm_cmdb_kernel_mcp.md](ghidra_ext2_cm_cmdb_kernel_mcp.md)**.

For CLI: **`python -m paceflash ls`** (ext2 paths), **`shell`** (session keeps volume loaded) — **[paceflash.md](paceflash.md)**. Full inventory: **`paceflash ls --debug`**. Full-chip physical dumps use **`boardfs.temporary_registry_from_physical_nand`** (`opentl.nand_bootstrap` + BBM attach).

**Introspection CLI:** **`python -m boardfs virt-map`** prints whether a **`BlockMapBuild`** is attached, hole counts, head/tail **virt→phys** pairs, and a short SHA-256 of the assembled **`tlpart_tl_scan_bytes`** when BBM is active. **`python -m boardfs page-table`** prints **2048-byte NAND page** rows for a virtual byte span (see :func:`opentl.open_tl.virt_span_nand_page_rows`). Use **`--nand-translate`** on full-chip Pace physical sizes (same envelope as **`paceflash`**). **`--debug-log`** enables **`OPENTL_DEBUG`** stderr logging; **`--tl-probe-report`** sets **`OPENTL_TLDISK_REPORT=1`** for TL disklabel scans. Install entry point: **`boardfs`** script from **`pyproject.toml`**.

**Hole bytes:** :func:`opentl.open_tl.extract_virtual_disk_bytes` maps **BBM holes** (**``0xffffffff``**) to output fill (**default ``0x00``**, matching kernel **`ntl_read_page`** ``memset``; optional **`hole_fill_byte`** for experiments). See **[ghidra_boardfs_bbm_readpath.md](ghidra_boardfs_bbm_readpath.md)**.

## Layers

End-to-end stack (`unand` → `uboot` → `opentl` → `boardfs` → `paceflash`), mermaid flow, and Ghidra MCP hints: **[layers_unand_uboot_opentl_boardfs_paceflash.md](layers_unand_uboot_opentl_boardfs_paceflash.md)**.

| Layer | Module(s) | Role |
|-------|-----------|------|
| A | `boardfs.flash`, `boardfs.flash_layout.FlashImage` | `mtdparts` → byte offsets in a logical flash file (on-disk path or **`FlashImage.logical_image`** bytes from **`flash_image_from_cmdline_bytes`**) |
| B | `opentl.tldisk`, `opentl.logical_opentl_session`, `opentl.driver` | ``tlpart`` MTD bytes → ``opentla0``… via :func:`opentl.tldisk.enumerate_tl_slices_from_tlpart_mtd_bytes`; with BBM :class:`boardfs.registry.FsRegistry` holds :class:`~opentl.logical_opentl_session.LogicalOpenTLSession` — virtual scan via :meth:`~opentl.logical_opentl_session.LogicalOpenTLSession.virtual_tl_byte_stream`, assembled slices via :meth:`~opentl.logical_opentl_session.LogicalOpenTLSession.extract_virtual_disk_bytes`. |
| C | `boardfs.ubi_cmdline`, `boardfs.ubi_scan` | **`ubi.mtd=`** → backing **MTD** `BlockDev`; **VID** header scan (not named volume table) |
| D | `boardfs.squashfs_probe` | **`hsqs`** magic probe on a :class:`boardfs.block.BlockSlice` (``BlockDev`` or ``AssembledBlockDev``); reads four bytes without materializing the full slice for path-backed ``BlockDev`` |

## Imports (public surface)

```python
from boardfs import (
    AssembledBlockDev,
    FsRegistry,
    Opentla4VolumeResult,
    assemble_opentla4_volume,
    apply_chain_aware_virtual_tl_scan,
    infer_chain_aware_virtual_tl_scan,
    temporary_registry_from_physical_nand,
    flash_image_from_cmdline,
    list_ext2_directory,
    read_ext2_regular_file,
    normalize_ext2_path,
    resolve_mountable_ext2_superblock_offset,
    list_root_for_block_dev_with_meta,
    iter_ubi_mtd_attach_specs,
    scan_ubi_vid_headers_on_block_dev,
)
```

| Module | Use when |
|--------|----------|
| **`boardfs.ext2_dissect`** | Resolve superblock, list **`/`**, normalize corrupt GD pointers for Dissect |
| **`boardfs.ext2_path`** | **`list_ext2_directory`**, **`read_ext2_regular_file`** at arbitrary paths |
| **`boardfs.tl_chain`** | **`assemble_opentla4_volume`**, NTL bytes, chain-aware BBM inference |
| **`boardfs.bootstrap`** | **`temporary_registry_from_physical_nand`** |
| **`boardfs.registry`** | **`FsRegistry`**, BBM attach, TL enumeration |

`opentl` root import still avoids **`tldisk`**; use **`from opentl.tldisk import enumerate_tl_slices`** when needed without **`boardfs`**. Host modules: **`opentl.opentla4_volume`**, **`opentl.bbm_chain`**, **`opentl.nand_bootstrap`**, **`opentl.registry_hooks`** (facaded by **`boardfs.tl_chain`**).

## UBI (`ubi.mtd=`, `root=ubi0:…`)

- **`iter_ubi_mtd_attach_specs(cmdline)`** — every **`ubi.mtd=`** token. Optional second comma field = byte offset inside the MTD partition (kernel attachment form).
- **`FsRegistry.first_ubi_backing_block_dev()`** / **`block_dev_for_ubi_mtd_attach(spec)`** — map attachment to raw **MTD** bytes (what UBI attaches **before** volume decode).
- **`scan_ubi_vid_headers_in_bytes` / `scan_ubi_vid_headers_on_block_dev`** — collect plausible **`struct ubi_vid_hdr`** records via **`boardfs.ubi_carve`** ( **`UBI#`** + **`UBI!`** on erase-aligned PEBs). This is a **PEB VID hit list**, not **`ubinfo`**-style volume names. For decode/carve, see **`boardfs.ubi_carve`** and **`boardfs.ubifs_decode`** in **[tools.md](tools.md)**.

**`root=ubi0:rootfs`:** **`parse_root_from_cmdline`** returns **`kind="ubi"`**, **`index`** = UBI device, **`ubi_volume`** = volume name. Resolving that to a byte range requires **UBI/UBIFS** stack tooling (out of scope for raw `boardfs` slices).

## Ghidra cross-reference

**[ghidra_ext2_pace_lag_investigation.md](ghidra_ext2_pace_lag_investigation.md)** — PACE `i_block` lag formula vs kernel `ext2_get_block` (MCP May 2026).

**[ghidra_tldisk_partition.md](ghidra_tldisk_partition.md)** — listing for **`tldisk_partition`** including the instruction at **`0x8020f248`** (delay slot after **`jal printk`**).

**[ghidra_boardfs_bbm_readpath.md](ghidra_boardfs_bbm_readpath.md)** — MCP-backed notes on **`read_dev_sector`**, **`read_cache_page`**, **`ntl_read_page`** (`*(remap+8)+virt×8`), vs linear **`mtdparts`** slices.

**[ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md)** — **`opentla4`** rw volume (ptype 17): NTL mode-2 per-page chains beyond BBM virt assembly; **`opentl/ntl_rw.py`**.

## Tests

**`tests/test_boardfs.py`**, **`tests/test_boardfs_ubi_fstab.py`**, **`tests/test_boardfs_import_boundary.py`**, **`tests/test_ext2_path.py`**, **`tests/test_opentla4_volume.py`**, **`tests/test_logical_opentl_session.py`**, **`tests/test_opentl_tldisk.py`**, **`tests/test_opentl_tl_superblock.py`**, **`tests/test_open_tl_nand_pages.py`**, **`tests/test_opentla4_532678_mount.py`** (integration, **`PACE_FLASH_INTEGRATION=1`**).
