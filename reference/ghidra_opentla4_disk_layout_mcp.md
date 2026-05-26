# OpenTL / `opentla4` disk layout — what still matters & MCP anchors (532678 kernel)

**Goal:** Separate **three address spaces** people confuse when asking for **`opentla4` “disk layout”**, point at **kernel evidence** for how **partition-relative block I/O** maps onto **OpenTL virtual pages** and then **NAND physical units**, and list **honest gaps** (structs below **`mtd_blktrans`**, exact **`ctx+0x88`** semantics).

**Program:** `att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_ld0x80010000_ep0x80458130-kernel.elf`  
**Method:** `user-ghidra` MCP — `list_open_programs`, `decompile_function`, `get_xrefs_to`, `search_strings` (**no** rodata literal **`opentla`** — names come from **`mtd_blktrans` / `snprintf`** patterns, not a grep-friendly string).

**Companion docs:** [opentl.md](opentl.md) (BSD slices, sector table), [opentl_kernel_ghidra.md](opentl_kernel_ghidra.md) §3–§5, §11 (**inner** vs **root**), [ghidra_nand_layout_write_path_mcp.md](ghidra_nand_layout_write_path_mcp.md) (virt→phys programming chain), [ghidra_tldisk_partition.md](ghidra_tldisk_partition.md), [mcp_kernel_gap_matrix.md](mcp_kernel_gap_matrix.md), **[ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md)** (ptype 17 / NTL mode-2 read path, offline port status).

---

## 1. Three coordinate spaces (do not merge)

| Space | Meaning | Typical offline handle |
|-------|---------|-------------------------|
| **A — Raw NAND / `tlpart` linear** | Bytes or erase units on the MTD partition backing OpenTL | `tlpart.bin`, `nand_translate`, logical+OOB |
| **B — OpenTL virtual volume** | **`~982` virt blocks × 128 KiB**, **`ntl_*`** page index, **`*(remap+8)`** 8-byte virt entries | `BlockMapBuild`, `extract_virtual_disk_bytes`, BBM replay |
| **C — Disklabel child (`opentla4`)** | **512 B sector** stream relative to **BSD partition** start (**~`0x180`** sectors on class captures — see `open_tl.py` comments) | `opentl/tldisk.py`, `extract_opentla4` |

**Key invariant (kernel):** **`opentla1`…`opentla4` are not separate NAND regions.** They are **slices of the same virt volume** as **`opentla0`**, enforced by **partition base arithmetic** in **`opentl_accesssectors`** plus bookkeeping updated from **`parse_bsd`** / **`CBLKMAP`** (**`opentl_ioctl`**). Phys placement of a sector still flows **`ntl_access_pages` → `ntl_read_page` / `ntl_write_page` → `ntl_find_phy`** (RAM page-map cache may short-circuit walks — §7.12 in main kernel doc).

---

## 2. MCP — how partition base enters virt addressing

### 2.1 `opentl_accesssectors` @ `0x80286884`

- **`piVar7 = (int *)(param_3 + 0xa0)`** — **`inner`** OpenTL context (**same as §11 `root + 0xa0`**).
- **`*(uint *)(param_3 + 0x80)`** — sector quantum (**512** on this platform).
- **`*(uint *)(param_3 + 0xb0)`** — I/O page stride used with **`0x200`** guard (“bad IO size” branch).
- When the **large-page** path is taken (`*(ctx+0xb0) > 0x1ff`), the decompiler computes a **starting logical page index**:

```text
page_index = (param_4 / sector_size) + *(ushort*)( *(int*)(param_3 + 0xec) + 0x1c )
```

(all units consistent with Ghidra’s **`uVar1`** reuse — interpret **`param_4`** as **byte-linear offset** in the **block device’s address space**, **`sector_size = *(ctx+0x80)`**).

That **`+0x1c`** **ushort** is the **partition’s base in OpenTL page-index units** (per-device state hung off **`ctx+0xec`**). **`opentla0`** uses **`0`**; each **child** bumps the cumulative base as partitions are registered.

### 2.2 `opentl_ioctl` @ `0x80287858` — **`CBLKMAP`** (`cmd == -0x7feb11fe`)

When **`param_4 + 0x60`** points at a **valid partition object** ( **`param_4 + 0x58 != param_4`** parent check):

1. Copy userspace bitmap (`__copy_user` into kmalloc buffer).
2. Call **`process_map(...)`** with **`inner = param_3 + 0xa0`**.
3. Pass **accumulated page base**:

```text
new_base_arg =
    ((uint)(*(int*)(partition + 4) << 9) / *(uint*)(param_3 + 0x88))
  + (uint)*(ushort*)( *(int*)(param_3 + 0xec) + 0x1c )
```

- **`*(partition + 4)`** participates in the **`tldisk_Partition__d__sectors__d__`** printk — treat as **partition sector count** (or tightly coupled field; confirm against **`struct hd_struct`** / Pace **`tldisk`** layout in Listing).
- **`<< 9`** converts **sectors → bytes**.
- **Division by `*(param_3 + 0x88)`** converts **that byte span** into **OpenTL page-index strides** for **`process_map`**’s erase/`ntl_access_pages` sweep — **exact physical meaning of `ctx+0x88`** is still a **follow-up** (candidate: **bytes per virt page × sectors-per-page** or **erase-aligned quantum**; verify by correlating with **`inner[4]`** pages-per-buffer and **`*(ushort*)(inner+10)`** pages-per-block).

**Offline implication:** **`opentla4`** starts at disklabel **sector `start`** inside **`opentla0`**; the kernel **does not** expose that as “byte offset in NAND” — it exposes **`opentla4`** as **sector 0 … len-1** with **`ctx+0xec/+0x1c`** carrying the **TL page base**.

---

## 3. MCP — `process_map` @ `0x80287234` (partition bitmap → TL ops)

**Role:** Walk a **bitmaps-over-sectors** description (`param_4`), allocate a **`__n`-bit** scratch (**`__n = param_10/param_9`** — geometry derived from ioctl args), and for each **full TL page** of coverage:

- optionally **`ntl_erase_unit`** when the page would be empty, else
- **`ntl_access_pages(..., op=(void*)2, …)`** — **delete-page path** for holes in the map ( **`param_6 == 2`** in **`ntl_access_pages`**).

So **`CBLKMAP`** is not cosmetic — it **mutates OpenTL metadata** for **partition shaping** (holes / aligned deletes) on top of the **same virt BBM** as the live filesystem.

---

## 4. MCP — `opentl_add_mtd` @ `0x80286c30` (whole-volume geometry seeds)

**Attach path** ( **`tlpart`**, NAND **`type == 4`**):

- Alloc **`0x80d0`** **`mtd_priv`**, **`kmalloc(mtd->writesize)`** bounce (**`puVar5[0x1e]`**).
- Fill **`puVar5[0x21]`** (`mtd->size`), **`[0x22]`** (`writesize`), **`[0x23]`** (`oobsize`), derive **`pages_per_unit`** **`*(ushort*)(puVar5+0xaa)`**, **`puVar5[0x2e]`** shift, **`puVar5[0x20]`** **`writesize >> 9`** (sectors per NAND page when **`writesize==0x200`**).
- **`opentl_dev_setup(puVar5 + 0x28)`** — **`inner`** base.
- **`ntl_mount(..., puVar5 + 0x28, …)`** — constructs **`remap`**, freelists, virt table (**§11**).
- **`puVar5[0x10]`** ← **`cap`**-style sector capacity derived from **stats block pointer** **`puVar5[0x3b]`** — feeds **`add_mtd_blktrans_dev`** and **`opentl_getgeo`** (**`param_3 + 0x9c..0x9f`** CHS fiction).

**Relation to `opentla4`:** **`opentla0`** capacity here is the **whole TL disk**; **`opentla4`** is **strictly smaller** and **label-defined** — correlate **offline** with **`tldisk`** slices, not **`paceflash`** “whole **`opentla4`** = contiguous SquashFS arena” shortcuts ([opentl_kernel_ghidra.md](opentl_kernel_ghidra.md) §12.4).

---

## 5. What is **still** poorly specified (recommended RE)

| Topic | Why it matters |
|-------|----------------|
| **Exact layout of `*(root+0xec)`** | Holds pointer whose **`+0x1c`** ushort is the **page base** for **child** devices; need **`struct`** sizing vs **`mtd_blktrans_dev`** |
| **Precise meaning of `*(root+0x88)`** | **`CBLKMAP`** **`process_map`** divisor — ties **partition sector spans** to **virt page accumulation** |
| **`*(root+0x84)`** (passed to **`process_map`**) | Last integer argument — likely **alignment / erase quantum**; confirm from Listing |
| **`mtd_blktrans` glue** | **`opentl_readsectors`/`writesectors`** only show **direct** xrefs from symbol stubs — **actual** queue **`request_fn`** lives in **generic `mtd_blktrans`**; trace **`open`/`release`** that chain **`param_4 + 0x60`** partition pointers into **`opentl_ioctl`** |
| **`opentla` device names** | **`search_strings` `opentla`** → **no hits** — dynamic **`snprintf`** from **`add_mtd_blktrans_dev`** template |

---

## 6. Offline tooling checklist (unchanged physics)

1. Build **`BlockMapBuild`** / chain-aware virt plane (**read path** parity — [mcp_kernel_gap_matrix.md](mcp_kernel_gap_matrix.md)).
2. For **`opentla4` (ptype 17)**, prefer **NTL mode-2 per-page assembly** ([`opentl/ntl_rw.py`](../opentl/ntl_rw.py)) — BBM-only virt stream is **not** sufficient for rw volumes; see [ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md).
3. Apply **BSD disklabel** sector **`(start, len)`** for **`opentla4`** ([opentl/open_tl.py](../opentl/open_tl.py), [opentl/tldisk.py](../opentl/tldisk.py)).
4. **`extract_opentla4`** = virt assembly **then** slice — **not** linear NAND carve at partition offset ([`paceflash/opentla4_extract.py`](../paceflash/opentla4_extract.py)).
5. When the slice is **ext2** (post-upgrade **`sys1/rootimage.img`**), extract **file bytes** before SquashFS dissect — not partition-level **`hsqs`** grep ([`ghidra_squashfs_flash_read_gap_mcp.md`](ghidra_squashfs_flash_read_gap_mcp.md), [`paceflash/ext2_file_extract.py`](../paceflash/ext2_file_extract.py)).

---

## 7. Changelog

| Date | Source |
|------|--------|
| 2026-05-15 | Ghidra MCP `decompile_function` on **`opentl_accesssectors`**, **`opentl_ioctl`**, **`process_map`**, **`opentl_add_mtd`** |
| 2026-05-20 | Cross-link [ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md); checklist step for NTL-rw before disklabel slice |
