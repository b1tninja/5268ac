# Kernel Ghidra anchors in Python sources

Offline tooling in this repo mirrors specific **Linux / OpenTL** routines from the att-5268-class kernel ELF. To keep implementation and RE notes aligned, many modules use **region comments** (IDE-friendly, grep-friendly) with **MIPS load addresses** from Ghidra.

## Comment shape

Use **`#region kernel: 0x........`** (**colon after `kernel`**, then space and the MIPS load address).

```text
#region kernel: 0x80289170
# Optional one-line note (symbol name, doc pointer, secondary EA, …)
… Python code …
#endregion
```

- **`#region kernel: 0x........`** — code is a direct analogue of the named kernel routine at that EA (dominant symbol for the block). Do **not** use meaningless placeholder addresses (e.g. `0xdeadbeef`) here — only cited Ghidra EAs so `grep #region kernel:` reliably finds real kernel mirrors.
- **`#region kernel_adjacent …`** — host glue (carve orchestration, `mtdparts` layout, `nand_translate` seams, U-Boot cmdline subset, etc.); **no** fake all-zero address.
- **`#endregion`** — closes the region (no space after `#`).

Indentation matches the wrapped code (module-level flush left; method bodies use the same indent as the `#region` line).

## Non-kernel region tags (hypothesis, debug, test)

Use these when code **must not** be mistaken for Ghidra-verified kernel parity. They are **grep-first** markers for audits, dead-code removal, or “ignore when reasoning about `ntl_*` fidelity”.

```text
#region hypothesis_only tl_bbm_linearize
# One line: what is assumed / what would disprove it / link to an issue or doc section
… Python …
#endregion
```

| Tag | Meaning | When to remove or ignore |
|-----|---------|---------------------------|
| **`#region hypothesis_only …`** | Exploratory mapping, tie-break heuristics, or design stubs **without** a cited kernel EA path. | After MCP/doc confirms or refutes; or replace with **`#region kernel:`** once anchored. |
| **`#region debug_only …`** | Verbose logging, optional asserts, scratch counters, or stderr-only diagnostics. | Strip for minimal prod paths; keep out of “kernel parity” reviews. |
| **`#region test_support …`** | Helpers embedded in library modules **only** for unit tests (rare); or large fixture builders in `tests/` if you want them grep-excludable. | Never required for runtime correctness; may delete when tests refactor. |

**Rules**

- Do **not** put a MIPS **`0x…`** address on **`hypothesis_only`** / **`debug_only`** / **`test_support`** lines — those EAs are reserved for **`#region kernel:`** (real load symbols only; never placeholder addresses such as `0xdeadbeef`).
- Prefer a **short slug** after the tag (e.g. `hypothesis_only nand_mode_autodetect`) so `rg '#region hypothesis_only'` is meaningful.
- **`tests/**/*.py`** may use the same tags for huge fixtures; most tests need no region — use only when it helps agents or humans filter noise.

**Grep**

```bash
rg '#region hypothesis_only' .
rg '#region debug_only' .
rg '#region test_support' .
```

**`kernel` / `kernel_adjacent` / non-kernel** — three disjoint intents: do not label host glue as **`kernel:`**, and do not label unproven heuristics as **`kernel_adjacent`** if they are not “documented seam” glue but a **guess**.

## Source of truth for addresses

| Reference | Use |
|-----------|-----|
| [ghidra_boardfs_bbm_readpath.md](ghidra_boardfs_bbm_readpath.md) | `read_dev_sector`, `ntl_read_page`, `ntl_mount`, boardfs / paceflash read path |
| [ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md) | `opentla4` ptype 17, NTL mode-2, page-map + ECC gaps, `opentl/ntl_rw.py` |
| [opentl_kernel_ghidra.md](opentl_kernel_ghidra.md) | OpenTL / NTL symbol table, spare layout, chain replay, stats block, `opentl_add_mtd`, etc. |

When one region spans **multiple** kernel symbols, the **primary** EA is on the `#region kernel:` line; secondary symbols are noted on the **next** `#` comment line inside the region.

## Representative anchors (not exhaustive)

| EA | Symbol (typical) | Python home (examples) |
|----|------------------|-------------------------|
| `0x8020ac20` | `read_dev_sector` | `opentl/open_tl.py` (512 B sector geometry) |
| `0x80289170` | `ntl_read_page` | `opentl/open_tl.py`, `opentl/tlpart_bbm_assembly.py`, `boardfs/registry.py` |
| `0x8028ac28` | `ntl_mount` | `opentl/tl_mount/__init__.py`, `opentl/bbm_kernel_replay.py`, `opentl/tl_superblock.py` |
| `0x80286c30` | `opentl_add_mtd` | `opentl/tl_physical.py` |
| `0x802888f8` | `ntl_put_chain_in_array` | `opentl/spare_chain_replay.py` (`next_phys_from_spare_chain_step`, `replay_put_chain_mode2_from_oob`, `iter_mode2_phys_chain_from_oob`; host helper `_pages_per_tl_erase` is `kernel_adjacent`) |
| `0x80289a30` | `ntl_verify_chain_seqnum` | `opentl/spare_chain_replay.py` |
| `0x80288560` / `0x8028c5d0` | `ntl_compute_spare_xsum` / `ntl_prepare_wspare` | `opentl/spare_layout.py` |
| `0x802882a4` | `ntl_map_page_state` | `opentl/spare_layout.py` |
| `0x80288bd4` | `ntl_find_phy` | `opentl/ntl_rw.py` (partial — no page-map branch) |
| `0x80284a20` / `0x80285248` | `ntl_build_page_map` / `ntl_lookup_page_map` | *(planned `opentl/ntl_page_map.py`)* |
| `0x80288388` / `0x80284740` | `ntl_ecc_read` / `opentl_correct_data` | *(planned `opentl/ntl_ecc.py`)* |
| `0x8028a938` (+ related) | stats arena (`ntl_reset_stat_table`, …) | `opentl/stats_block.py` |
| `0x8013e4dc` | `ext2_get_inode` | `boardfs/ext2_dissect.py` (`_ext2_read_inode_fields`, inode table stride) |
| `0x8013cb50` | `ext2_get_branch` | `boardfs/ext2_dissect.py` (`_ext2_decode_block_ptr`, indirect sanitize) |
| `0x80289610` | `ntl_initialize_memory` (remap sizing) | `opentl/tl_bbm.py` (default geometry constants) |

**`paceflash` orchestration:** `opentl/ntl_rw.py` (`#region kernel: 0x80289170` / `0x802888f8`), `paceflash/opentla4_extract.py`, `paceflash/bbm_scan.py`, `paceflash/inventory.py` (`build_inventory_opentla4_extract`) — see [ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md).

**`opentl/spare_verify.py`:** `verify_page_require_spare_xsum` under `#region kernel: 0x80288560` (chain-aware extract P2 gate).

**`hypothesis_only` in production trees:** `find_ext2_superblock_offsets` in `boardfs/ext2_dissect.py` (`#region hypothesis_only ext2_ef53_signature_grep`) — not used on mount/extract hot paths; deprecated `paceflash/ext2_dissect.py` re-exports it for offline tools only.

| Slug / file | What it marks |
|-------------|----------------|
| `infer_chain_aware_tl_scan` | `opentl/tl_chain_heuristic.py`, `paceflash/bbm_scan.py` |
| `infer_ext2_opentla4_chain_aware` | `opentl/opentla4_volume.py` — linear ext2 vs NTL mount |
| `correlation_suggests_chain_aware*` | `opentl/tl_chain_heuristic.py`, `paceflash/upgrade_correlation.py` |
| `ntl_chain_head_spare_scan_fallback` | `opentl/ntl_rw.py` — page-0 spare scan when virt map is hole |
| `ext2_ef53_signature_grep` | `boardfs/ext2_dissect.py` — `find_ext2_superblock_offsets` (EF53 byte grep) |
| `tldisk_printk_constants_fallback` | `opentl/tldisk.py` — U-Boot printk triples when on-disk tuples missing |
| `tldisk_offline_chain_anchor_search` | `opentl/tldisk.py` — full-buffer chain5/chain4 anchor search |
| `SpareRecord_erased_bootcode_heuristics` | `opentl/spare_layout.py` |
| `opentla4_product_superblock_offsets` | `boardfs/ext2_dissect.py`, `opentl/ext2_probe.py` — sb @ 1024 / magic @ 0x438 |

**Host orchestration (not a single kernel EA):** :func:`opentl.open_tl.extract_virtual_disk_bytes_chain_aware` uses **`#region kernel_adjacent extract_virtual_disk_bytes_chain_aware`** — mirrors the **`ntl_read_page`** (**`0x80289170`**) try-candidates-then-verify *shape* using spare-chain order from **`0x802888f8`**; see [ghidra_boardfs_bbm_readpath.md](ghidra_boardfs_bbm_readpath.md).

**`kernel_adjacent`** regions appear in `unand/io.py`, `unand/layout.py`, `unand/mtd.py`, `unand/geometry.py`, `opentl/nand_translate.py`, `opentl/nand_pipeline.py`, `boardfs/*`, `paceflash/*`, `uboot/cmdline.py`, and related modules—see ripgrep for `#region kernel_adjacent`.

## Maintenance

When Ghidra renames or re-bases an ELF, update **both** the reference markdown and the matching `#region kernel:` line so tests and prose stay consistent. Prefer adding a sentence to [opentl_kernel_ghidra.md](opentl_kernel_ghidra.md) or [ghidra_boardfs_bbm_readpath.md](ghidra_boardfs_bbm_readpath.md) before changing EAs in Python.
