# MCP kernel gap matrix — Python stacks vs att-5268 OpenTL (read path + write anchor)

**Ghidra program:** `att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_ld0x80010000_ep0x80458130-kernel.elf` (MIPS BE, image base `0x80010000`).

**MCP evidence (2026-05-15):** `list_open_programs`, `get_function_callees`, `get_xrefs_to`, `decompile_function` on `user-ghidra`. Read-anchor lists mirror **`ntl_read_page`** evidence; **write-anchor** **`ntl_write_page`** row + [`ghidra_nand_layout_write_path_mcp.md`](ghidra_nand_layout_write_path_mcp.md) close the NAND-layout doc gap for programming order vs **`mtd->_write`**.

**Python anchor ground truth:** `rg '#region kernel:'` on `D:/electronics/5268ac/**/*.py` (see also [kernel_python_regions.md](kernel_python_regions.md)).

---

## Gap categories

- **parity gap** — Kernel routine affects observable read/mount bytes; Python has no analogue or a **simplified** analogue (documented in prose or `#region`).
- **intentional omission** — Host-only orchestration (`#region kernel_adjacent`); no 1:1 kernel EA.
- **partial / roadmap** — Documented in [ghidra_boardfs_bbm_readpath.md](ghidra_boardfs_bbm_readpath.md) “Offline parity roadmap”; MCP confirms callee set.
- **environment gap** — Needs raw NAND + ECC path (e.g. `ntl_verify_read_phy_page`); logical-plane dumps omit data.

---

## Anchor functions — MCP callees vs Python

### `ntl_read_page` @ `0x80289170`

**MCP callees:** `memcpy`, `memset`, `ntl_find_phy` @ `0x80288bd4`, `ntl_put_chain_in_array` @ `0x802888f8`, `ntl_verify_read_phy_page` @ `0x80288600`, `printk`.

**Python (claimed):** `opentl/open_tl.py` (`extract_virtual_disk_bytes`, `virt_span_nand_page_rows`), `opentl/virt_page_table.py`, `opentl/logical_opentl_session.py`, `boardfs/registry.py`, `opentl/tlpart_bbm_assembly.py`, `paceflash/bbm_scan.py` (chain-aware refresh).

**Gap (BBM virt stream):** Primary **virt→phys** uses **one** `BlockMapBuild.virt_to_phys_block[vb]`; kernel loops **`ntl_find_phy`** + verify until success or **memset**. **Partial mitigation:** `extract_virtual_disk_bytes_chain_aware`, chain-aware session OOB.

**`opentla4` / ptype 17 (May 2026):** :mod:`opentl.ntl_rw` implements per-page **`ntl_find_phy`**, **`ntl_verify_read_phy_page`** (ECC does not fail the read), hole **zero-fill** — see [ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md). Remaining **parity gap** for mount: **BBM tail / page-map** replay, not NTL page resolution telemetry.

**MCP `get_xrefs_to` @ `0x80289170`:** Includes `ntl_access_pages` @ `0x8028a574` (primary caller path); confirms stack is sector/page I/O, not only TL user tools.

---

### `ntl_write_page` @ `0x8028df78`

**MCP callees:** `memcpy`, `ntl_allocate_unit` @ `0x8028d428`, `ntl_find_phy` @ `0x80288bd4`, `ntl_fold_block` @ `0x8028d1d4`, `ntl_free_block_if_notbad` @ `0x8028cbac`, `ntl_log_all` @ `0x8028a344`, `ntl_prepare_wspare` @ `0x8028c5d0`, `ntl_put_chain_in_array` @ `0x802888f8`, `ntl_read_verify_phy_spare` @ `0x80288750`, `ntl_update_page_map` @ `0x80285444`, `ntl_write_verify_phy_page` @ `0x8028c804`, `ntl_write_verify_phy_spare` @ `0x8028ca24`, `panic`, `printk`, `tl_add_chain` @ `0x802864ec`.

**Python (claimed):** Read-side parity modules (`extract_virtual_disk_bytes`, BBM replay, spare helpers) — **none** implement **`ntl_write_page`** allocation, fold pressure, or **`mtd->_write`**.

**Gap:** **intentional omission** — affects **live** NAND programming / TSOP placement; offline tooling stays **read-anchored**. Narrative + xref proof: [`ghidra_nand_layout_write_path_mcp.md`](ghidra_nand_layout_write_path_mcp.md).

**MCP `get_xrefs_to` @ `0x8028df78`:** `ntl_access_pages` @ `0x8028a808`, `0x8028a838`; rodata `0x8049d470`.

---

### `ntl_put_chain_in_array` @ `0x802888f8`

**MCP callees:** `ntl_read_verify_phy_spare` @ `0x80288750`, `panic`, `printk`.

**Python (claimed):** `opentl/spare_chain_replay.py`, `opentl/virt_page_table.py` (chain-aware table), `opentl/logical_opentl_session.py` (`set_chain_aware_virt_reads`).

**Gap:** Offline implements **spare walk + chain ordering**; full **`ntl_read_verify_phy_spare`** parity (all skip/printk gates in §7.1) is not replicated byte-for-byte — heuristic / partial checks only → **partial / roadmap** unless spare bytes come from a faithful capture.

---

### `ntl_mount` @ `0x8028ac28`

**MCP callees (abbrev.):** `ntl_access_pages`, `ntl_allocate_memory` @ `0x802893a0`, `ntl_dismount`, `ntl_erase_unit`, `ntl_find_valid_spare`, `ntl_initialize_memory` @ `0x80289610`, `ntl_load_stat_table` @ `0x8028aab0`, `ntl_read_phy_spare`, `ntl_verify_chain_seqnum` @ `0x80289a30`, `ntl_verify_phy_erase`, `ntl_xsum_read` @ `0x802885d0`, `tl_add_chain` @ `0x802864ec`, `tl_delete_chain`, `tl_init_chain` @ `0x80285b60`, memcpy, memset, printk, panic, …

**Python (claimed):** `opentl/bbm_kernel_replay.py`, `opentl/tl_mount/__init__.py`, `opentl/tl_superblock.py`, `opentl/stats_block.py` (stats arena / `ntl_access_pages` **window** semantics in comments).

**Gap:** Offline **`kernel_replay_v1`** materializes **`BlockMapBuild`** from flat spare + logical prefix — **not** a RAM replay of **`ntl_allocate_memory`**, **`tl_add_chain`** doubly-linked pools, or full **`ntl_mount`** branch tree ([ntl_mount_virt_table_fill.md](ntl_mount_virt_table_fill.md)). **parity gap** for “full mount fidelity”; **acceptable** for TL read if `*(remap+8)` slots match replayed map.

---

### `read_dev_sector` @ `0x8020ac20`

**MCP callees:** `put_page`, `read_cache_page` @ `0x8008a310`.

**Python (claimed):** `opentl/open_tl.py` (512 B sector / layout helpers), `opentl/tldisk.py` @ `0x8020ec1c` **disklabel sector** parse (`parse_bsd` family).

**Gap:** Kernel goes through **page cache** + **512 B slots**; `boardfs` / `tldisk` read **contiguous buffers** (`tlpart` bytes or virtual assembly). **parity gap** for cache aliasing / coherency; usually irrelevant for static NAND dumps — **document as environment** for “same bytes as running kernel” comparisons.

When byte-level label or BBM comparisons disagree with a live router, first confirm the capture is **logical-plane** at offset 0 (same as `read_linear_plane_prefix` / `nand_translate`), then compare **virtual** `tlpart_tl_scan_bytes` vs **linear** `tlpart` via `FsRegistry` enumeration fallback — not the kernel VFS cache.

---

### `FUN_8020ec1c` / `read_dev_sector` disklabel helper (see `tldisk`)

**MCP callees @ `0x8020ec1c`:** `printk`, `put_page`, `read_dev_sector`, `snprintf`, `strlcat`.

**Python (claimed):** `opentl/tldisk.py` — parses **logical** disklabel buffer (anchor `0x8020ec1c` in-region comment).

**Gap:** Offline does not emulate **`put_page`** / **VFS** stack; parses bytes only → **intentional omission** for host tooling, **parity gap** only if label view must match **exactly** kernel cache fill order.

---

### `ntl_access_pages` @ `0x8028a574`

**MCP callees:** `memset`, `ntl_delete_page`, `ntl_read_page`, `ntl_write_page`, `panic`, `printk`.

**Python:** No dedicated module mimicking full **`ntl_access_pages`** I/O splitter. **`opentl/stats_block.py`** documents **`ntl_access_pages`** usage for **stats flush/load window** only.

**Gap:** **parity gap** for generic block-layer pacing; **intentional omission** for paceflash/boardfs read tooling (different entry points).

---

## Package routing (from [layers_unand_uboot_opentl_boardfs_paceflash.md](layers_unand_uboot_opentl_boardfs_paceflash.md))

| Package | Role in gap analysis |
|--------|----------------------|
| **unand** | Geometry / carve / `normalize_to_logical` — **kernel_adjacent** vs `opentl_add_mtd` (`0x80286c30`); not expected to implement NTL |
| **opentl** | Primary **parity** target for `ntl_read_page`, chains, mount replay, spare layout, stats |
| **boardfs** | MTD + `tlpart` scan buffer + `tldisk` enumeration — **kernel_adjacent** + **read_dev_sector** buffer semantics gap |
| **paceflash** | Inventory / `nand_logicalize` — **intentional omission** except BBM attach hooks |

---

## Current phase vs gaps (rolling)

Implementation status is tracked in [ghidra_boardfs_bbm_readpath.md](ghidra_boardfs_bbm_readpath.md) **Offline parity roadmap — Current implementation phase**: **P1** (`extract_virtual_disk_bytes_chain_aware` + tests) shipped; **P2** spare-xsum verify helper (`opentl.spare_verify`) wired as optional **`verify_page`** composition; **P3** ECC still environment-scoped.

## Suggested next steps (prioritized)

1. **Keep parity docs in sync** — When MCP shows new callees under `ntl_read_page`, grep Python for symbol names and update [opentl_kernel_ghidra.md](opentl_kernel_ghidra.md) / this file.
2. **`ntl_find_phy` + verify loop** — Extend §7.1 spare gates beyond xsum (reject-and-continue already supported via **`verify_page`** on each chain candidate).
3. **`ntl_mount` scope** — If `BlockMapBuild` mismatches on-disk semantics, deepen **`bbm_kernel_replay`** against **`tl_add_chain`** write sites (advanced).
4. **Disklabel** — If anchor fails on a capture, compare **linear `tlpart`** vs **virt assembly** already handled in `FsRegistry._tlpart_enumeration_bytes_and_source`.

---

## `opentla4` / disklabel vs NAND (coordinate spaces)

**Issue:** **`opentla4`** is a **BSD-label slice** on the **same** OpenTL virt volume as **`opentla0`** — not its own linear NAND span.

**MCP doc:** [`ghidra_opentla4_disk_layout_mcp.md`](ghidra_opentla4_disk_layout_mcp.md) — **`opentl_accesssectors`** page-index formula, **`opentl_ioctl`** **`CBLKMAP`** → **`process_map`**, remaining gaps (**`ctx+0x88`**, **`ctx+0xec`** layout).

**Offline:** Still **`extract_virtual_disk_bytes`** (or chain-aware variant) **then** disklabel slice — [`opentl/open_tl.py`](../opentl/open_tl.py), [`opentl/tldisk.py`](../opentl/tldisk.py).

---

## Upgrade write path vs offline read (`pkgstream` → NAND)

**Purpose:** Explain mismatches between **carrier SquashFS** (`lib2spy` / dissect carves) and **`paceflash`** treating **`opentla4`** as a contiguous SquashFS arena.

**Ground truth (532678):** [`firmware_upgrade_process.md`](firmware_upgrade_process.md) §6a + [`output/lib2spy_532678_install_pkgstream.json`](../output/lib2spy_532678_install_pkgstream.json) — **`rootimage.img`** FILE payload **`43788` + `26775552` B**; strict **`hsqs`/`bytes_used`** carve **`43788` + `26771550` B** (**different SHA-256** — see[`ghidra_upgrade_write_path_532678.md`](ghidra_upgrade_write_path_532678.md)).

**Kernel write plumbing:** [`opentl_kernel_ghidra.md`](opentl_kernel_ghidra.md) §12.4 — **`ntl_write_page`** → **`ntl_write_verify_phy_page`** → **`(*(ctx+0x54))`** (**`opentl_dev_page_write`**) → **`mtd->_write`**; same BBM/spare translation as read-side before the MTD hook. MCP tables: [`ghidra_nand_layout_write_path_mcp.md`](ghidra_nand_layout_write_path_mcp.md).

**Correlation (automated):** With carrier ground truth loaded, **`python -m paceflash ls --nand-translate --lib2spy-json output/lib2spy_532678_install_pkgstream.json [--pkgstream …install.pkgstream]`** emits **`upgrade_nand_correlation`** — scans **`bbm_virt`**, **`linear_tlpart`**, **`linear_flash_tlpart`**, and **`ext2_file:sys1/rootimage.img`** (etc.) for **SHA-256** strict squash (`4331b829…` on 532678 **`rootimage.img`**) and full FILE span (`31e41884…`). **`read_model`** / **`primary_read_model`** distinguish **carrier file**, **TL slice `hsqs` scan**, and **ext2 file extract**; warns when strict match is ext2-only ([`paceflash/upgrade_correlation.py`](../paceflash/upgrade_correlation.py), [`paceflash/ext2_file_extract.py`](../paceflash/ext2_file_extract.py)). **SquashFS flash vs pkgstream (no extra NAND decompressor):** [`ghidra_squashfs_flash_read_gap_mcp.md`](ghidra_squashfs_flash_read_gap_mcp.md).

**Linear MTD probes (loader / mtdoops):** OpenTL attaches only to the **`tlpart`** partition name ([`ghidra_mtd_loader_mtdoops_mcp.md`](ghidra_mtd_loader_mtdoops_mcp.md)). For boot env and panic-ring forensics on **linear** slices (no BBM), use **`python -m paceflash ls --nand-translate --probe-loader-env --probe-mtdoops`** → JSON **`mtd_partition_probes`** ([`paceflash/mtd_partition_probes.py`](../paceflash/mtd_partition_probes.py)). Do not expect pkgstream squash SHA matches in loader/mtdoops.

**Read-side gaps (post ext2-first):** **`ntl_lookup_page_map` / `ntl_build_page_map`** RAM cache on read is **not** replayed offline — primary **`BlockMapBuild`** only ([`ghidra_squashfs_flash_read_gap_mcp.md`](ghidra_squashfs_flash_read_gap_mcp.md) §7.12). **ext2-first** dissect/carve is implemented; partition-level **`hsqs`** on **`opentla4`** without file extract remains a **misaligned read model**.

**`opentla4` NTL-rw (May 2026):** Phase 2 shipped in [`opentl/ntl_rw.py`](../opentl/ntl_rw.py) (page-map helpers, ECC verify, per-vblk cache, **`unresolved_vpages=0`** on PACE). **Ext2 mount** on PACE capture still xfail — BBM tail / `s_magic` @ `0x438`, not vpage resolution. Master docs: [ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md), [ghidra_ntl_mcp_2026-05-20.md](ghidra_ntl_mcp_2026-05-20.md). Squash: **`sys1/rootimage.img`** via ext2 file extract only.

**Gap:** Python stacks model **read** (`ntl_read_page`, BBM replay); **write path** (`ntl_write_page`, UBIFS allocator interaction) has **no offline emulator** — **intentional omission** except structural docs above.

---

## Checklist: kernel EAs with `#region kernel:` in Python (inventory)

| EA | Typical symbol | Python homes |
|----|----------------|--------------|
| `0x8020ac20` | `read_dev_sector` | `opentl/open_tl.py` |
| `0x8020ec1c` | parse_bsd / disklabel sector | `opentl/tldisk.py` |
| `0x80286c30` | `opentl_add_mtd` | `opentl/tl_physical.py` |
| `0x802888f8` | `ntl_put_chain_in_array` | `opentl/spare_chain_replay.py`, `opentl/logical_opentl_session.py`, `opentl/virt_page_table.py` |
| `0x80289170` | `ntl_read_page` | `opentl/open_tl.py`, `opentl/virt_page_table.py`, `boardfs/registry.py`, `opentl/tlpart_bbm_assembly.py`, `paceflash/bbm_scan.py` |
| `0x8028df78` | `ntl_write_page` | *(no emulator — structural docs only:* [`ghidra_nand_layout_write_path_mcp.md`](ghidra_nand_layout_write_path_mcp.md)*)* |
| `0x80289a30` | `ntl_verify_chain_seqnum` | `opentl/spare_chain_replay.py` |
| `0x8028a938` | stats / `ntl_reset_stat_table` family | `opentl/stats_block.py` |
| `0x8028ac28` | `ntl_mount` | `opentl/bbm_kernel_replay.py`, `opentl/tl_mount/__init__.py`, `opentl/tl_superblock.py` |
| `0x80288560` / `0x8028c5d0` | spare xsum / prepare | `opentl/spare_layout.py` |
| `0x802882a4` | `ntl_map_page_state` | `opentl/spare_layout.py` |
| `0x80288bd4` | `ntl_find_phy` | `opentl/ntl_rw.py` |
| `0x80284a20` / `0x80285248` | `ntl_build_page_map` / `ntl_lookup_page_map` | *(planned `opentl/ntl_page_map.py`)* |
| `0x80288388` / `0x80284740` / `0x80284358` | ECC read / correct / calculate | *(planned `opentl/ntl_ecc.py`)* |
| `0x80289610` | `ntl_initialize_memory` (remap sizing) | `opentl/tl_bbm.py` |

EAs with **no** `#region kernel:` but **kernel_adjacent** only: **uboot**, **unand** layout/io/mtd, **boardfs/pipeline**, **paceflash/nand_logicalize**, etc. — see `rg '#region kernel_adjacent'`.
