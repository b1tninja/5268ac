# OpenTL Linux kernel driver — Ghidra notes (5268-class)

This document records **reverse-engineering findings** from Ghidra on the **`drivers/mtd/opentl`** stack (MIPS **Linux 3.4.x** image matching **`fwupgrade.txt`**). **Function names** follow **`…_ghidra_m00_kernel.kallsyms.txt`** / ELF **`symtab`** (same KSEG0 addresses as legacy **`FUN_8028…`** Ghidra auto-names). Addresses are **KSEG0** for this **`…80458130`** kernel member unless noted.

**Related:** **[issue.md](issue.md)** (strategy, BBM tooling), **[opentl.md](opentl.md)** (boot/U-Boot layout, **`opentla*`** diagrams), **[prom_init_ghidra.md](prom_init_ghidra.md)** (BCM63xx **`prom_init`** before **`opentl_add_mtd`**), **[tools.md](tools.md)** (`tl-bbm`, `tl-extract`, `vmlinux-to-elf`).

**Notebook refresh (May 2026):** **§2–§11** use **kernel symbol names** from **`kallsyms`** (see **`binwalker/scripts/kallsyms_replace_fun_in_md.py`** to regenerate). **`extract_ghidra_fun.py`** / **`.bin.c`** exports may still show **`FUN_8028…`** until re-exported from Ghidra with applied symbols.

---

## 0. Recommended Ghidra input — `vmlinux-to-elf` ELF

For **new** Ghidra databases on this kernel, prefer the **reconstructed ELF** over the raw `.bin` carve:

| Path | Role |
|------|------|
| **`firmware_11.5.1.532678/11.5.1.532678/install_package/pkgstream_carves/att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_36645b10_ghidra_m00_kernel.elf`** | ELF32 BE MIPS, `e_entry=0x80458130` (`kernel_entry`), `.kernel` LOAD at `0x80010000`, **17,277-entry `.symtab`** recovered from kallsyms by **[`marin-m/vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf)**. |
| **`…_ghidra_m00_kernel.kallsyms.txt`** | `nm`-style symbol listing (~515 KB) for grep / cross-reference. |
| **`…_ghidra_m00_kernel.elf.md`** | Per-carve summary: kallsyms field offsets, ELF section layout, reproduction commands. |

**Loading:** drop the `.elf` straight into Ghidra — `e_machine=MIPS`, segments, and entry come directly from the ELF, and the import populates the function listing with kernel-side names (`do_one_initcall`, `_stext`, `kernel_entry`, etc.) before any analysis runs. No manual base-address or entry-point setup, no `ghidra_load.json` plumbing for the **kernel** member. Continue to use the existing `binwalker uimage-ghidra` manifest for the **ramdisk** member at `0x80A9A000` (it is not a kernel and has no `kallsyms`).

**Existing analyses keyed off the static `.bin.c` export and `FUN_8028…` addresses still apply** — `_ghidra_m00_kernel.bin` and the **`vmlinux-to-elf`** ELF cover the **same load image** at the same KSEG0 addresses; only the symbol surface has improved. Names recorded throughout this document (e.g. `kernel_entry`, `_stext`, …) can now be cross-checked against the `.kallsyms.txt` listing without round-tripping through Ghidra. See **[tools.md](tools.md)** § *`vmlinux-to-elf` — kernel symbol recovery for Ghidra/IDA* for installation, the auxiliary `kallsyms-finder` / `vmlinuz-decompressor` commands, and override flags.

---

## 1. `opentl` strings → referencing functions (symtab-backed database)

**Method:** Ghidra REST **`/search_strings?search_term=opentl`** on the loaded kernel, then **`POST /get_bulk_xrefs`** for each **`.rodata`** hit in **`0x804f68xx`–`0x804f76xx`**, and **`/get_function_by_address`** on each xref **`from`** address. **ELF `.strtab`** entries only (**`0x00029…`** symbol spellings such as **`opentl_ioctl`**) are omitted—those name symbols rather than printk paths.

### 1.1 printk / path strings

| String (abbrev.) | rodata | Referencing function(s) |
|------------------|--------|-------------------------|
| `opentl_correct_data: ECC1…` | `0x804f6858` | **`opentl_correct_data`** |
| `Oldbyte=` … | `0x804f688c` | **`opentl_correct_data`** |
| `bad byte loc` | `0x804f68c4` | **`opentl_correct_data`** |
| **`drivers/mtd/opentl/opentl_map.c`** | `0x804f69c8` | **`ntl_build_page_map`**, **`ntl_invalidate_page_map`** |
| `tl_malloc failure` | `0x804f7068` | **`tl_malloc`** |
| `OPENTL: get geo` | `0x804f7088` | **`opentl_getgeo`** |
| `opentlcore.c $Rev` | `0x804f70a0` | **`init_opentl`** |
| `remove_dev` | `0x804f70d0` | **`opentl_remove_dev`** |
| `bad IO size` | `0x804f70ec` | **`opentl_accesssectors`** |
| `access page=` | `0x804f710c` | **`opentl_accesssectors`** |
| `opentl_sectors:` | `0x804f7138` | **`opentl_accesssectors`** |
| `Invoked for a MTD` | `0x804f7168` | **`opentl_add_mtd`** |
| `add_mtd for` | `0x804f719c` | **`opentl_add_mtd`** |
| `out of memory…structures` | `0x804f71b4` | **`opentl_add_mtd`** |
| `…pagebuffer` | `0x804f71e0` | **`opentl_add_mtd`** |
| `could not mount` | `0x804f731c` | **`opentl_add_mtd`** |
| `Found new opentl` | `0x804f73f8` | **`opentl_add_mtd`** |
| bare **`"opentl"`** | `0x804f75f4` | **Data ref** @ **`0x80553b30`** only (device/module tag — **no enclosing function**) |
| `opentl_dev_page_write` printk | `0x804f75fc` | **`opentl_dev_page_write`** |
| `…page_read` | `0x804f763c` | **`opentl_dev_page_read`** |
| `…erase` | `0x804f767c` | **`opentl_dev_erase`** |
| `…spare_read` | `0x804f76a8` | **`opentl_dev_spare_read`** |
| `…spare_write` | `0x804f76e8` | **`opentl_dev_spare_write`** |

**Related (not matching substring `opentl`):** **`ntl_acc_page`** / **`ntl_access_pages`** printks (**`0x804f8120`–`0x804f8290`**) all xref **`ntl_access_pages`** (**`0x8028a574`**). Most **`ntl_read_page:*`** strings xref **`ntl_read_page`** (**`0x80289170`**); the **`ntl_read_page: virtual_block=%d`** line also appears from **`ntl_access_pages`** (debug path).

### 1.2 Priority for BBM / offline extract

| Priority | String / path | Why |
|----------|----------------|-----|
| Highest | **`opentl_sectors: …`** | Sector translation logging. |
| Highest | **`drivers/mtd/opentl/opentl_map.c`** | Filename anchor — **`ntl_build_page_map` / `ntl_invalidate_page_map`**. |
| High | **`OPENTL: get geo(%d)`** | Geometry (`cap`, units) — ties to **`tldisk_partition: cap: 0x0003D4FC`**. |
| High | **`OPENTL: access page=…`** | **`opentl_accesssectors`** translation path. |
| High | **`opentl_dev_*`** printks | NAND primitives; **spare** paths matter for **bad-block chains**. |
| Medium | **`OPENTL: add_mtd for %s`** | **`opentl_add_mtd`** — MTD registration. |
| Lower | **`opentl_correct_data: ECC…`** | Software ECC — neighbors **`ntl_verify_read_phy_page`**-class logic (**§7**). |

---

## 2. Call stack sketch (read path) — symbol names

```text
High-level byte I/O (512-byte sectors, block alignment)
    opentl_accesssectors
        → ntl_schedule_folds   (cache / fold scheduling)
        → ntl_access_pages    ("ntl_acc_page" loop)
            → ntl_read_page
                → ntl_put_chain_in_array
                → loop until done:
                      ntl_find_phy
                          → ntl_read_verify_phy_spare   (ctx+0x58)
                          → ntl_prev_phy_location       (chain stepper)
                      ntl_verify_read_phy_page          (ctx+0x50; ECC helpers)

Write/delete/fold:
    ntl_access_pages → ntl_write_page / ntl_delete_page
    ntl_write_page → ntl_allocate_unit → ntl_write_verify_phy_page
    ntl_fold_block → tl_fold_chain
    ntl_write_page / ntl_schedule_folds → ntl_fold_block when remap mode permits fold
```

**`memcpy`** remains an optimized **memcpy** (noise for mapping RE).

---

## 3. `opentl_accesssectors` (`0x80286884`) — sector-aligned bulk read/write

**Role:** Split a **byte range** (`param_4` offset, `param_5` length) into:

1. Optional **unaligned head** (within first **`*(uint *)(ctx + 0x80)`** granularity — power-of-two mask),
2. **Full middle** chunks,
3. Optional **tail**.

**Observations:**

- Arithmetic uses **`0x200` (512)** for memcpy sizes → **logical sector size** matches U-Boot/OpenTL **512-byte sectors**.
- **`*(uint *)(ctx + 0xb0)`** participates in **`opentl write: bad IO size %d/%d`** together with **`0x200`** → treat **`+0xb0`** as **page (or I/O) size in bytes** once confirmed from probe code.
- **`*(int *)(ctx + 0xec) + 0x1c`** (via nested pointer) adds a **base** to **`param_4 / block_granularity`** → likely **partition base virtual block** or similar.
- **`*(void **)(ctx + 0x78)`** — bounce / **page buffer** for partial operations.

**Debug branch:** When verbosity **`> 2`**, calls printk **`OPENTL: access page=%d:%d to %d:%d`** with computed block/page indices.

### 3.1 MTD glue + ECC (`opentl_calculate_ecc` … `opentl_dev_setup`) — Ghidra MCP (May 2026)

Decompilation targets **`att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_36645b10_ghidra_m00_kernel.elf`** (MIPS BE). These sit **below** **`ntl_access_pages`** / **`ntl_mount`**: they define **how 512-byte sectors** sit on **2048-byte NAND pages**, **software ECC**, **CHS reporting**, and **raw MTD callbacks** (`page` / `oob` / `erase`). Offline **`tl-extract`** still depends on **`ntl_*` BBM math**; this layer mainly constrains **alignment** and **what to ignore** when simulating **opentla4**.

| Symbol | Address | Role |
|--------|---------|------|
| **`opentl_calculate_ecc`** | **`0x80284358`** | Walks data in **32-byte** steps (eight **`uint32`** per step), emits **3-byte** software ECC into caller buffer — Hamming-style XOR/parity folding (pairs with **`ntl_verify_read_phy_page`**). |
| **`opentl_correct_data`** | **`0x80284740`** | Compares read vs computed ECC (after bitwise **not** on inputs); **bit-count** branches — single-bit correctible path flips **one byte** in **`param_3`** buffer; **`printk`** on fatal/bad patterns. |
| **`opentl_getgeo`** | **`0x802867c0`** | Fills **`hd_geometry`** from private **`ctx+0x9c..0x9f`** (heads / sectors / cylinders **fiction** for the block layer — **not** the NAND BBM). |
| **`opentl_remove_dev`** | **`0x80286830`** | **`del_mtd_blktrans_dev`** + **`kfree`** private. |
| **`opentl_accesssectors`** | **`0x80286884`** | **`ntl_schedule_folds`** then splits I/O on **`*(ctx+0x80)`** (sector size, **512**) vs **`*(ctx+0xb0)`** (page / I/O size; crossed with **`0x200`** in “bad IO size”); bounce **`*(ctx+0x78)`**; **`ntl_access_pages`** with **`piVar7 = ctx+0xa0`**; virtual page index **`param_4/uVar1 + *(ushort*)(*(ctx+0xec)+0x1c)`**. |
| **`opentl_writesectors`** | **`0x80286bf0`** | **`opentl_accesssectors(..., 2)`**. |
| **`opentl_readsectors`** | **`0x80286c10`** | **`opentl_accesssectors(..., 1)`**. |
| **`opentl_add_mtd`** | **`0x80286c30`** | MTD notifier: type **`4`** (NAND), name **`tlpart`**, **`~0x80d0`**-byte private, **`__kmalloc(mtd->writesize)`** page buffer, **`writesize == 0x200`** branch sets erase **`shift`** (e.g. **9** for 512-page erase blocks), **`opentl_dev_setup`**, **`ntl_mount`**, geometry / **`add_mtd_blktrans_dev`**. |
| **`opentl_ioctl`** | **`0x80287858`** | **`cmd == -0x7feb11fe`**: user **CBLKMAP**-style buffer → **`__copy_user`** → **`process_map`** (partition map into **`ctx+0xa0`** context), scaled by **`*(ctx+0x88)`** vs partition sector count. |
| **`opentl_dev_page_write`** | **`0x80287a60`** | Build chip linear offset from **block + page** (`param_3[6]`/`[7]` shifts, **`mtd->size-1`** mask); **`mtd->_write`** @ **`mtd+0x6c`** if **`MTD_WRITEABLE`**. |
| **`opentl_dev_page_read`** | **`0x80287bdc`** | Same addressing; **`mtd->_read`** @ **`mtd+0x68`**. |
| **`opentl_erase`** | **`0x80287d40`** | **`mtd_erase`** wrapper. |
| **`opentl_dev_erase`** | **`0x80287dac`** | Logical block → chip coords (same shift split as spare); **`opentl_erase`**. |
| **`opentl_read_oob`** | **`0x80287e60`** | **`mtd->_read_oob`** @ **`+0x68`**, **`oob_ops.mode = 2`**, addr **`off & ~ (writesize-1)`** for alignment. |
| **`opentl_write_oob`** | **`0x80288014`** | **`mtd->_write_oob`** @ **`+0x6c`**, checks **`MTD_WRITEABLE`**. |
| **`opentl_dev_spare_read`** | **`0x80287f08`** | **`memset`** buffer length **`param_3[5]`** (spare bytes), **`opentl_read_oob`**. |
| **`opentl_dev_spare_write`** | **`0x802880d4`** | **`opentl_write_oob`**. |
| **`opentl_dev_setup`** | **`0x802881c0`** | Installs **`mtd_priv`** hooks: **`+0x50`** page read, **`+0x54`** page write, **`+0x58`** spare read, **`+0x5c`** spare write, **`+0x60`** erase. |

**Simulation / extract implications:**

1. **512-byte sectors × 4 per 2048-byte NAND page** (`mtd->writesize`, **not** the **`0x200`** literal used inside **`opentl_accesssectors`** for **sector-sized** memcpys) — **`tl-extract`** byte iteration is equivalent to sector iteration; **`KERNEL_*`** constants in **`opentl/tl_extract.py`** lock this to the kernel (**`KERNEL_NAND_PAGE_BYTES = 2048`**).  
2. **`opentl_getgeo` CHS** — reporting only; **do not** derive BBM from geometry fields.  
3. **ECC** — relevant when emulating **bit errors** or validating captured OOB; **not** required for a **clean** TSOP dump linearized by **virt→phys**.  
4. **`opentl_ioctl` / `process_map`** — why **partition-relative** sector bases differ from **whole-TL** BBM when correlating **`opentla4`** slices.  
5. **Flat dump layout** — **`opentl_dev_*`** addressing matches **standard MTD NAND** (block/page/OOB); **`binwalker`** **logical prefix + OOB tail** model should stay consistent with **`writesize`** / spare size from **`opentl_add_mtd`**.

---

## 4. `ntl_access_pages` (`0x8028a574`) — virtual block + page index loop

**Role:** Convert **linear page index** within the TL volume into **`(virtual_block, page_within_block)`** and invoke read/write/delete helpers.

**Key fields on **`param_3`** (OpenTL context):**

| Offset | Interpretation |
|--------|----------------|
| **`+0x0a`** (as **`ushort`**) | **Pages per virtual block** — divisor for **`block = start / n`**, **`page = start % n`**. |
| **`param_3[4]`** (`+0x10` int) | **Bytes per page** in the DMA/bounce buffer stride (**`uVar5 * param_3[4] + buf`**). |
| **`param_3[0x13]`** | Pointer to **sub-structure** used by **`ntl_read_page`** (remap object; see §5). |

**Reads:** **`ntl_read_page`**  
**Writes:** **`ntl_write_page`**  
**Delete:** **`ntl_delete_page`**

Printks (**`ntl_read_page: virtual_block=%d`**, **`ntl_acc_page`**, etc.) anchor this function in **`flash strings.txt`**.

---

## 5. `ntl_read_page` (`0x80289170`) — virtual block → physical unit(s) → read page

**Inputs:** `param_4` = **virtual block index**, `param_5` = **page index within block**, `param_6` = output buffer.

**Remap object:** **`sub = *(inner + 0x4c)`** — same word as **`inner[0x13]`** when **`param_3`** is **`int * inner`** (**`mtd_priv + 0xa0`**). Not the same as **`root[0x4c]`** on the **`0x80d0`** **`mtd_priv`** (**§11**).

| Field on **`sub`** | Role |
|--------------------|------|
| **`*(uint *)(sub + 0x10)`** | **Virtual block count** (valid indices **`0 … count-1`**). |
| **`*(int *)(sub + 8)`** | Base of **`8-byte`** record **per virtual block**. |
| **`*(uint **)(sub + 0x20)`** | Scratch / **aligned page buffer** for NAND DMA. |

**Per virtual block entry** at **`table + virt * 8`:**

| Offset | Content |
|--------|---------|
| **`+0`** **`uint32`** | **`phys_unit`** — raw NAND **erase-unit index** (or **`0xffffffff`** = hole). |
| **`+5`** **`uint8`** | Validity / presence flag (**`== 0`** or **`phys == 0xffffffff`** → **zero-filled page**, no NAND read). |

**Bounds:** Compare **`phys_unit`** against **`(ctx[1] - ctx[0])`** from **`param_3`** — treat **`ctx[0]`/`ctx[1]`** as allowed **physical unit range** for this MTD slice.

**After mapping:** **`ntl_put_chain_in_array`** fills the **chain array**. A loop calls **`ntl_find_phy`** to select the **next physical unit** / spare metadata for this **virtual block + logical page**, then **`ntl_verify_read_phy_page`** performs the **data** read and verify. Details: **§7.3**.

**Offline implication:** **`tl-bbm`** needs more than **`linear_v1`** identity: at minimum a **`uint32 phys`** per virt block; ideally **chain length** + **follow-up phys IDs** (§6).

---

## 6. `ntl_put_chain_in_array` (`0x802888f8`) — build physical-unit chain

**Ghidra MCP (live decompile, current program `att-5268-…ghidra_m00_kernel.elf`):** Confirms **`ntl_read_verify_phy_spare(..., phys, 0, spare_buf)`** — spare walk uses **page argument `0`** inside each erase block; **`spare[8]&4`** → **`ushort`** chain flags; small-page branch maps **`next==0xffff`** → **`0xffffffff`**; large-page branch ORs **`spare[16]<<16 | spare[17]<<24`** onto LE16 **`spare[9..10]`**. **`ntl_verify_chain_seqnum`** compares **`*(byte *)(row + 0xc)`** to the head row’s seq on each hop (**`piVar2[3]`** in uint indexing = offset **12**), ORs **`row[0xd] |= 0x10`**, max hops checked **`> 0x45`**.

**Purpose:** For **virtual block** `param_4`, fill caller array **`param_5`** with **`(phys_unit, flags)`** pairs until terminator **`0xffffffff`**.

**Parent object:** **`piVar10 = *(int **)(param_3 + 0x4c)`** — remap / BBM root (may relate to **`sub`** in §5; confirm equality vs parent/child in Ghidra).

**Again uses** **`piVar10[2] + virt * 8`**: first **`uint32`** = start phys unit, **`byte[+5]`** = **`chain_length`** (`uVar11`). Optional output **`*param_6 = chain_length`**.

### Mode **`*(int *)piVar10 == 2`** (bad-block / spare-chain style)

- For each link, **`ntl_read_verify_phy_spare`** reads **spare/OOB** for physical unit **`uVar5`** into **`piVar10[0xc]`** scratch.
- Parses **next physical erase-unit index** from the verified spare (**`FUN_802888f8`** / exported **`att-5268-…80458130.bin.c`**):
  - **`ushort` flags** written after each read: **`spare[8] & 4`** (duplicate/mirror hop bit).
  - If **`*(ctx+0x10) == 0x200`**: next **phys** = LE16 **`spare[9..10]`**; **`0xffff`** → terminator **`0xffffffff`**.
  - Else (**5268 large page**, **`ctx+0x10 == 0x800`**): next **phys** = **`LE16(spare[9..10]) | (spare[16]<<16) | (spare[17]<<24)`**; compare **`0xffffffff`** for end (**not** identical to **`SpareRecord.phys_u32`**, which packs **`<H` @ 16** — see **`opentl/spare_chain_replay.py`**).
- Writes **`param_5`** pairs: **`phys`**, **`ushort` flags** (e.g. spare byte **`& 4`**).
- Validates **`piVar10[5]`** upper bound on phys unit (**`bad_blk_put_chain_in_array`**).
- **`*(byte *)(virt_entry + 1) & 1`** must **match** whether a “duplicate spare” path was taken — else **`vblk_%u_flag_does_not_match_chai`**.

**Implication:** For worn/remapped media, **substitute blocks may exist only in spare**, not in the 8-byte virt table alone.

### Mode **`*(int *)piVar10 != 2`**

- **`piVar10[1]`** = base of **`0x10`-byte (16-byte)** records **indexed by physical unit**.
- Walk **`uVar5 = *record`** as **next** pointer until **`0xffffffff`**.
- **`ushort` flags** at **`param_5+1`** from **`*(byte *)(record + 0xd) & 8`** → **`4` or `0`**.

**Implication:** RAM-resident **linked list** loaded from flash at mount — candidate for **dumping struct layout** from **stats / BBM** initialization code.

---

## 7. `ntl_verify_read_phy_page` (`0x80288600`) — verify physical page

**Role:** After NAND fills **`param_6`** + metadata, **validate** and update status bytes.

| Offset on **`param_3`** | Role |
|-------------------------|------|
| **`+0x50`** | **Callback** — must return **0** to proceed (read-complete gate). |
| **`+0x10`** | **Byte offset** from **`param_6`** to **per-page sub-structure**: **`meta = param_6 + *(ctx+0x10)`**. |
| **`+0x24`** | **`ushort`** — additional offset into **`meta`** for a compared byte (must not stay **`0xFF`** when fixing). |

**On **`meta`:**

- **`*(byte *)(meta + 4)`** — status / ECC code (via **`ntl_map_page_state`** lookup).
- **`ntl_xsum_read`** — checksum failure path (`checksum_fail` printk).
- **`ntl_ecc_read`** — ECC handling; **`0x24`** special case; printks **`ECC_correction_occurred`** vs **`ECC_fail: phy_unit=…`**.

This aligns with **`opentl_correct_data`** strings — **software ECC path**, separate from **virt→phys table parsing**.

### 7.1 `ntl_read_verify_phy_spare` — read and verify physical spare

**Role:** Issue the **NAND spare/OOB read** for a **physical unit**, then normalize / validate the **status byte** and optional **checksum** — same building blocks as **`ntl_verify_read_phy_page`** on **data** meta, but **`param_6`** is the **raw spare/OOB buffer**.

| Item | Detail |
|------|--------|
| **Callback** | **`(*(code **)(param_3 + 0x58))()`** — must return **0** for success (full argument list not visible in this decompilation snippet). |
| **Buffer** | **`param_6`** — non-null spare region; **`panic`** on **`NULL`** (**`ntl_read_verify_phy_spare: NULL`**) or non-zero read status (**`read_f`**). |
| **PHY index** | **`param_4`** — physical unit (printk **`checksum_fail`** / **`phy_unit`**). |
| **`param_5`** | Passed through to error paths (opaque in snippet). |

**Post-read logic (exact order):**

1. **`iVar2 = ntl_map_page_state((uint)*(byte *)(param_6 + 4))`** — **lookup / normalize** spare **status** from byte **`spare[4]`** (same helper as **`ntl_verify_read_phy_page`** uses on **`meta+4`**).
2. **Conditional checksum:** if **`iVar2 != 0xff`** **and** **`*(char *)(param_6 + *(ushort *)(param_3 + 0x24)) == -1`** (`0xFF`), then **`ntl_xsum_read(param_3, param_6)`** must be **false** (checksum OK); else **`checksum_fail`** (**`%s: checksum_fail: phy_unit=…`**).
3. **Write-back:** **`*(char *)(param_6 + 4) = (char)iVar2`** — store **normalized** status (e.g. **`'$'`** / **`0`** classes after **`ntl_map_page_state`**).
4. Return **`0`** on success.

**Interpretation:** **`ctx + 0x24`** is a **`ushort` byte offset** into the **same spare buffer** as **`ntl_verify_read_phy_page`**’s **`meta + 0x24`** field — when that byte is **erased (`0xFF`)**, the driver still insists on **`ntl_xsum_read`** matching byte **`spare[0xf]`**. When it is **not** **`0xFF`**, checksum can be skipped (alternate marker path).

**Call context:** Invoked from **`ntl_put_chain_in_array`** (mode **`2`**), **`ntl_find_phy`**, **`ntl_write_page`**, **`ntl_delete_page`**, etc. **Offline BBM** should treat **`ntl_prepare_wspare`** (**§7.4b**) + **`ntl_compute_spare_xsum`** (**§7.4a**) + this routine as the **authoritative spare field map** for **`page_size == 0x200`** vs larger page.

**`+0x58` callback:** Decompilation still shows **no explicit arguments**; Ghidra may be missing **variadic** / register-passed **`(ctx, phy_unit, buf, …)`**. Recover from **`jalr`** sites that assign **`*(ctx+0x58)`**.

### 7.1a `ntl_prev_phy_location` — chain cursor (`param_5` index + `param_6` phys / page slot)

**Prototype (Ghidra):** **`ntl_prev_phy_location(ctx_or_geom, param_2, chain_base, chain_len, &idx, out_pair)`** — matches use from **`ntl_find_phy`** / write path.

**Chain record:** **`uint32 phys`** at **`base + i*8`**, **`int16 flags`** at **`base + i*8 + 4`** (Ghidra **`*(short *)(… + 4)`**).

| Step | Behavior |
|------|----------|
| **Duplicate drain** | If **`flags[i] == 4`** **and** **`out_pair[1] != 0`**: **`out_pair[1]`--**, **return** — **same **`phys`** index **`i`**, walk logical duplicates / mirrored pages without advancing **`i`**. |
| **Past end** | If **`chain_len - 1 <= idx`**: **`out_pair[0] = 0xffffffff`**, **`out_pair[1] = 0xffff`**, **return** — **no more candidates** (matches **`ntl_find_phy: Not_found_page`**). |
| **Advance** | **`idx++`**, **`out_pair[0] = phys[idx]`** (next unit). |
| **Slot metadata** | If **`flags[idx] != 4`**: **`out_pair[1] = param_2`** (caller passes **logical page** or **slice id**). If **`flags[idx] == 4`**: **`out_pair[1] = *(ushort *)(param_1 + 10) - 1`** — **`param_1`** is **OpenTL context**: **`*(ushort *)(ctx + 10)`** is **`pages_per_virtual_block - 1`** (same divisor **`ntl_access_pages`** uses). |

**Offline use:** **`short == 4`** marks **multi-page / mirror** chain hops; **`out_pair[1]`** is a **down-counter** for how many **duplicate iterations** remain before **`ntl_prev_phy_location`** advances **`idx`** again.

### 7.2 `ntl_ecc_read` — multi-slice ECC within one page

**Role:** Walk **fixed-size slices** of the **page buffer** **`param_4`** (plus a parallel **`+0x40`** region per slice — typical **main vs redundant ECC half** or **512 B user + OOB layout**), compare against **HW-calculated syndromes** and optionally apply correction. Sets **`param_5[0]`** non-zero if **software-visible correction** occurred.

**Derived iteration count:**

- **`uVar6 = *(uint *)(param_3 + 0x10) >> 9`** — i.e. **`page_size / 512`** (integer divide). Examples: **`0x800` → 4**, **`0x200` → 1** slice per outer loop body pattern.

**Per iteration** (index **`uVar4`**):

- **`pbVar3 = (byte *)((int)param_4 + page_size)`** — base used to pull **manufacturer / OOB-style bytes** **relative to the current slice’s page layout** (Ghidra shows **`pbVar3`** stepping with **`param_4 += 0x80`** — **`0x80`** words = **512 bytes** per slice advance).
- **`opentl_calculate_ecc(param_4, abStack_30)`** and **`opentl_calculate_ecc(param_4 + 0x40, abStack_2d)`** — likely **syndrome or ECC tag extraction** into **5-byte** (`abStack_2d`) / **3-byte** (`abStack_30`) scratch.
- **First slice only (`uVar4 == 0`):** builds **`local_38`** from **`pbVar3`**:
  - If **`*(int *)(param_3 + 0x10) == 0x200`**: bytes **`pbVar3[0], [1]`** and **`[2],[3],[6],[7]`** (512-byte-page spare layout).
  - Else: uses **`pbVar3[0x16], [0x17]`** instead of **`[0],[1]`** for the first two bytes — **larger page** uses **different spare field offsets**.
- **`opentl_correct_data(..., abStack_30, &local_38)`** — **BCM NAND ECC compare/correct**; return **`2`** → **`ntl_ecc_read` returns 1** (hard fail); **`1`** → correctable / flagged.
- Second **`opentl_correct_data`** on **`param_4 + 0x40`** with **`abStack_2d`** — second plane / parity half.
- **`puVar5`** advances by **6 bytes** per slice — compact **stored ECC metadata** stream copied via **`memcpy`** on later iterations.

**Takeaway:** **`ctx + 0x10`** is **page byte length**; ECC is processed in **512-byte granules** when **`page_size > 512`**. Spare byte indices **`0…7`** vs **`0x16…`** branch matches **`ntl_put_chain_in_array`**’s **`page_size == 0x200`** vs larger-page spare parsing — **one coherent spare geometry model** across chain-walk and ECC.

### 7.3 `ntl_find_phy` — find physical candidate

**Offline field table (spare vs RAM chain audit):** see **`output/opentl_mount/spare_chain_fields.md`**.

**Role:** Given **`param_4`** = **virtual block**, **`param_5`** = **logical page-in-block**, and the **chain array** from **`ntl_put_chain_in_array`** (**`param_8`**, length **`param_9`**), walk **candidate physical units** until spare proves this page belongs to **`param_4`** or exhaust the chain.

**Globals / counters**

- **`iVar9 = *(int *)(param_3 + 0x4c)`** — same remap root as **`ntl_put_chain_in_array`**.
- **`*(int *)(iVar9 + 0x150c0) += 1`** on entry (profiling / fault counter).
- **`*(int *)(iVar9 + 0x150c4) += 1`** on the **`param_7==0`** fast path when **`*(char *)(param_8 + 5) == 4`** and **`ntl_lookup_page_map`** returns **`2`** then **`ntl_build_page_map`** repair succeeds (vendor-specific **raid/dual-read** branch).

**Inputs / outputs**

| Param | Meaning |
|-------|---------|
| **`param_7`** | **`0`** = fresh search from **`param_8`** head; **`!= 0`** = resume using **`param_10[0]` / `[1]`** as cursor into chain. |
| **`param_6`** | **`1`** = “need alternate / mirror” mode (affects match acceptance and **`param_10`** fill). |
| **`param_10`** | Out: **`[0]`** = chosen **phys unit**, **`[1]`** = spare-related index (**`page` / slice**, often **`ushort`**); **`0xffffffff` / `0xffff`** = none yet. |

**Core loop**

1. **`ntl_prev_phy_location`** — updates **`local_40`** (chain index in **`param_8`**) and **`local_3c`** / **`local_38`** (**phys** + **page-slot counter**); see **§7.1a**. **`short == 4`** entries **hold **`idx`** while draining **`out[1]`** duplicate-page iterations.
2. **`ntl_read_verify_phy_spare(param_3, local_3c, local_38, scratch)`** — **`scratch = *(iVar9 + 0x30)`** — read **verified spare** for candidate phys unit.
3. **Interpret spare byte **`scratch[4]`**:**
   - **`'\0'`** or **`'$'`** (`0x24`) treated as **candidate valid marker** for decoding **embedded virtual block id** from **`CONCAT11(scratch[0xc], scratch[0xb])`** (16-bit); if **`page_size != 0x200`**, OR in **`scratch[0x12]`/`[0x13]`** for **24-bit** virtual id (matches **`ntl_put_chain_in_array`** large-page branch).
   - Must equal **`param_4`** or printk **`virtual_blk_is_bad`** / **`Hard_hart`**.
4. **Page / mirror selection:** compares **`param_6`**, chain flags **`*(short *)(param_8 + local_40*2 + 1)`** vs **`4`**, and **`scratch[0xd]`** vs **`param_5`** to accept **primary vs duplicate** spare.
5. **Status **`scratch[4] == -1`** (`0xff`):** accumulate **`local_2c`/`local_30`** as **fallback** phys; continue (**`ntl_prev_phy_location`**) unless **`param_6==1`** early exit with saved fallback.
6. **Bad spare read:** non-zero return from **`ntl_read_verify_phy_spare`** → **`read_spare_failed`** when verbose.

**Printks:** **`ntl_find_phy:*`**, **`bad_blk_find_phy`**, **`bad_status_*`**, **`Hard_hart`**.

### 7.4 `ntl_xsum_read` — spare checksum quick check

**`ntl_xsum_read(ctx, spare_buf)`** returns **`true`** iff **`*(byte *)(spare_buf + 0xf) != ntl_compute_spare_xsum(ctx, spare_buf)`** — one-byte **stored vs computed** comparison at **offset `0xf`** (used from **`ntl_read_verify_phy_spare`** / **`ntl_verify_read_phy_page`** paths).

### 7.4a `ntl_compute_spare_xsum` — additive checksum (must match **`spare[0xf]`**)

**Role:** **`ntl_compute_spare_xsum(ctx, spare)`** returns a **`char`** (**signed**, **wraps mod 256**) — sum of selected **OpenTL spare/OOB bytes** that **`ntl_write_verify_phy_page`** writes into **`meta + 0xf`** immediately before programming (**§7.9**).

**Algorithm (matches decompilation):**

1. **`partial = spare[9] + spare[10] + spare[11] + spare[12]`** (signed **`char`** arithmetic).
2. If **`*(int *)(ctx + 0x10) != 0x200`**: **`partial += spare[16] + spare[17] + spare[18] + spare[19]`** (Ghidra **`+0x10` … `+0x13`**).
3. **Return `spare[8] + spare[13] + spare[14] + partial`** (`**`0x8`**, **`0xd`**, **`0xe`**).

**Offline:** For any carved **512-byte-page** spare image, recompute this sum (with **`int8`** wrapping) and compare to **`spare[15]`** (`**`0xf`**`) unless **`ntl_read_verify_phy_spare`**’s skip path applies (**§7.1**).

### 7.4b `ntl_prepare_wspare` — fill spare/OOB template before program

**Role:** **`memset(param_2, 0xff, *(uint *)(ctx + 0x14))`** — spare region **`memset`** to **`0xFF`**, length **`ctx->spare_bytes`** (field at **`+0x14`**). Then writes **virt id**, **phys unit**, **page-in-block**, and **status flags** into **fixed byte offsets** — must match **`ntl_find_phy`** read-side decoding (**§7.3**) and **`ntl_read_verify_phy_spare`** verification (**§7.1**).

**Parameters:** **`param_3`** = **phys unit**, **`param_5`** = **virtual block id**, **`param_6`** / **`param_7`** = **`undefined1`** slots ( **`param_7`** lands at **byte 4**; **`param_6`** at **byte `0xd`** — **logical page** on write path), **`param_4`** lower **3 bits** + **`param_8 & 4`** + **`param_9 & 8`** merged into **byte 8**.

**Byte layout** (**`param_2`** base, **`page_size = *(ctx+0x10)`**):

| Offset | Content |
|--------|---------|
| **`4`** | **`param_7`** (`undefined1`) |
| **`8`** | **`(param_4 & 3) \| (param_8 & 4) \| (param_9 & 8)`** — **status / chain flags** ( **`ntl_find_phy`** inspects **`spare[4]`**; **`'$'`** = **`0x24`** is written elsewhere / via **`ntl_map_page_state`** normalization). |
| **`9`–`10`** | **`param_3` phys unit**, **low 16 bits** (**LE**: **`[9]`** LSB, **`[10]`** next). |
| **`11`–`12`** | **`param_5` virtual block**, **low 16 bits** (**LE** — matches **`CONCAT11(spare[0xc], spare[0xb])`** in **`ntl_find_phy`**). |
| **`13` (`0xd`)** | **`param_6`** — **page-in-block** ( **`ntl_find_phy`** compares to **`param_5`** page argument). |

If **`page_size != 0x200`** (large page branch), Ghidra also stores **upper** phys / virt bytes:

| Offset | Content |
|--------|---------|
| **`16`** | **`(char)(param_3 >> 16)`** — decompilation: **`*(char *)(param_2 + 4)`** with **`param_2`** typed **`uint *`** → **byte** **`param_2 + 16`**. |
| **`17` (`0x11`)** | **`(char)(param_3 >> 24)`** |
| **`18` (`0x12`)** | **`(char)(param_5 >> 16)`** |
| **`19` (`0x13`)** | **`(char)(param_5 >> 24)`** |

Together **`[9,10,16,17]`** / **`[11,12,18,19]`** extend **phys** / **virt** to **32-bit**, matching **`ntl_find_phy`** OR of **`[0x12]`/`[0x13]`** into the virtual id on non-512 pages.

### 7.5 `opentl_calculate_ecc` / `opentl_correct_data` — syndromes and single-byte ECC fix

**`opentl_calculate_ecc(page_words, out3)`**

- Scans **eight** **`uint`** lanes via **`get_word`** (bit-wise parity / GF-style reduction over overlapping nibbles).
- Folds XOR trees into **three output bytes** **`param_2[0..2]`** (syndrome-like). Optional **`^ 0xaaaaaa`** toggle when internal **`bVar1`** parity flips — vendor BCM/OpenTL convention.

### 7.5a `get_word` — 32-bit lane read (feeds **`opentl_calculate_ecc`**)

**Source:** **`python .cursor/skills/ghidra-vmlinux-extract/scripts/extract_ghidra_fun.py`** on **`att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_36645b10_kernel_load_80010000_ep_80458130.bin.c`**.

**`get_word(uint *param_1)`** does **`memcpy(local, param_1, 4); return local[0]`** — not custom GF math; it is an **aligned big-endian load** of **`param_1[0]`** after **`memcpy`**-style copy into stack (**same effect as reading one **`uint`** from **`param_1`**).

**`opentl_calculate_ecc`** then:

1. For **`uVar14` from 0 to 7**: read **eight** consecutive **`uint`** words **`get_word(param_1)` … `get_word(param_1 + 7)`**, XOR-fold them (**`uVar13`**, **`uVar10`–`uVar12`**, **`uVar15`**), reduce nibbles, compare **`((uVar2>>2^uVar2)&3)`** to **`{0,1}`** to advance **`local_40`** and toggle **`bVar1`** (tracks “which half” of the **8×8** pass).
2. Advance **`param_1 += 8`** (**32** bytes per outer column) — **eight** columns × **32** B = **256** bytes of page bits fed into the syndrome.
3. Final stage mixes **`uVar10`–`uVar15`** with masks (**`0xf0f0f0f0`**, **`0xaaaaaaaa`**, **`0xcccccccc`**, shifts, **`local_40`** nybble placement); if **`bVar1`**, XOR **`0xaaaaaa`** into the packed tag before writing **`param_2[0..2]`**.

So §7.5’s “parity over **`get_word`**” is **word-wise XOR / nibble parity over BCM-shaped lanes**, not arithmetic inside **`get_word`** itself.

**`opentl_correct_data(..., data_slice, syndrome_bytes)`**

- Bit-inverts first bytes of **`param_4`** / **`param_5`**, XOR-combines into **24-bit** word **`uVar3`**.
- Counts set bits in **`uVar3`** (**Hamming weight**):
  - **`== 1`** → **`unrecoverable_ECC_checksum`** (panic printk path).
  - **`== 0`** → return **`0`** (no error).
  - **`!= 12`** (`0xc`) → **`Bad_ECC: Read %x:%x:%x Calc …`**.
- For **`0xc`**, runs **single-error locating** (parity of halves), then **corrects one byte** at **`param_3 + uVar5`** using a **small decode table** and **`bVar2`** bit position — success returns **`1`** (**correctible**).
- Printks tie directly to **`opentl_correct_data: ECC1 …`**, **`correctible_error, changing byte`**, **`bad_byte_loc`**, **`unrecoverable_ECC_error`** in **`flash strings.txt`**.

### 7.6 `ntl_write_page` — write logical page

**Outline (high complexity):**

- Resolves **8-byte virt entry** **`puVar12`** at **`*(sub+8) + virt*8`**; tracks **dirty / locked** bits on **`puVar12[1]`** (**`|4`**, **`|2`**, **`|1`** mirror flag, **`0x1000000`** vendor bit).
- **`ntl_put_chain_in_array`** + **`ntl_find_phy(..., param_6=1, …)`** to locate **target phys** or allocate new (**`ntl_allocate_unit`** — free-block search).
- Builds/programmes spare + data: **`ntl_prepare_wspare`** (layout spare bytes **`0x24`**, **`0xb6`**, etc.), **`ntl_write_verify_phy_spare`** / **`ntl_write_verify_phy_page`** (program), **`tl_add_chain`**, **`ntl_update_page_map`** (bad-block / chain maintenance).
- On “write into existing spare slot” path: **`ntl_read_verify_phy_spare`** read-modify path, enforce **`local_40[2] & 0x4000000`**, set **`local_40[1]=0x24`**, **`memcpy`** copy user page.
- **`ntl_fold_block`** called when **fold** needed; **`ntl_free_block_if_notbad`** on program failure with retry budget **`iVar14`** starting **8**.

**Use for RE:** shows **which spare bytes are written** for **virtual block id**, **page**, **chain flags** — complements **`ntl_find_phy`** read-side parsing.

### 7.7 `ntl_delete_page` — delete logical page

- Validates virt entry; **`ntl_put_chain_in_array`** + loop **`ntl_find_phy(..., param_6=0)`**.
- **`ntl_read_verify_phy_spare`** on chosen phys; if **`spare[4]!=0`**, may clear delete metadata (**`spare[4]=0`**) via **`ntl_write_verify_phy_spare`**; optional **`ntl_update_page_map`** when **`puVar4[1] & 0x1000000`**.

### 7.8 `ntl_fold_block` — fold virtual block

- Requires **`*(int *)remap == 2`** (mounted TL with bad-block chain mode); else **`TL_part_unmounted`** or **`return 1`**.
- If **chain length byte** at **virt entry +5** is **`0`** → no fold.
- If **locked** (**`entry[4] & 2`**): **`unit_%d_is_locked`** / return **`0x10`**.
- Otherwise **`ntl_put_chain_in_array`**, bump **generation counter** **`*(byte *)(entry+6)`** (cap **`3`** wrap), **`tl_fold_chain`** (**§7.11** — heavy lifting), optional **`ntl_log_virt_chain`**, **`tl_log_chain`** (persist accounting blob).

### 7.9 `ntl_write_verify_phy_page` — write + read-verify physical page

**Role:** Program **one physical unit** (**`param_4`**) with caller buffer **`param_6`** (full **page** payload), fill **in-band meta** checksum, issue **write**, **read-back**, **ECC verify**, and **memcmp** against source.

| Step | Detail |
|------|--------|
| **Buffers** | **`bounce = *(uint **)(*(ctx+0x4c)+0x28)`** — driver scratch (**page + OOB-sized** window). **`meta = param_6 + *(ctx+0x10)`** — same **`meta`** convention as **`ntl_verify_read_phy_page`** (**§7**). |
| **Prep** | **`ntl_ecc_write(ctx, param_6)`** — layout / scrub before DMA. |
| **Checksum store** | **`*(meta+0xf) = ntl_compute_spare_xsum(ctx, meta)`** — **computed** xsum lands on **`meta`** (parallel to spare **`spare[0xf]`** in **`ntl_read_verify_phy_spare`** paths). |
| **Write** | **`(*(code **)(ctx+0x54))(ctx, param_4, param_5)`** — must return **0**. |
| **Verify read** | **`memset(bounce, 0, spare_bytes + page_size)`**; **`(*(code **)(ctx+0x50))(ctx, param_4)`** — read full verify window; **`ntl_xsum_read(ctx, meta)`** on **`meta`** (**`write_xsum_mismatch`** if fail). |
| **ECC** | **`ntl_ecc_read`** on **`bounce`**; printk paths **`page_write_failure`**, **`ECC_correction_occurred`** (**hard error on write path**). |
| **Identity check** | **`memcmp(bounce, param_6, spare_bytes + page_size)`** — **memcmp** programmed vs intended (**`write_mem_compare_failed`**). |

**Callbacks:** **`ctx+0x54`** = **page program**, **`ctx+0x50`** = **page read** (distinct from **`ctx+0x58`** spare read — **§7.1**).

### 7.10 `ntl_allocate_unit` — allocate free physical unit

**Role:** Return a **free NAND erase-unit index** from pool anchored at **`sub + 0x15010`** (**`sub = ctx[0x13]`**). May trigger **wear-driven fold**, **global fold sweep**, or **panic** when pool empty.

**Highlights:**

- **`tl_chain_size(sub+0x15010, …)`** — counts / reserves **free units** (returns small integer **`≤ 6`** in normal loop).
- **`param_4`** — **`NULL`** vs non-**`NULL`** toggles **reserve / fast path** (**`ntl_allocate_unit: using_reserve`**).
- **`param_5`** — optional **`byte *`**; set **`1`** when **`ntl_fold_block`** returns **`0x10`** (**locked**) so caller can distinguish **soft fail**.
- **Wear hook:** when **`param_4 == NULL`** and **`tl_chain_size > 0`**, **`random32`** (**timer/jiffies**) on multiples of **200** picks **`tl_follow_chain(sub+0x15080, 0xffffffff, …)`** **victim phys**, validates **`*(sub+4)+unit*0x10`** reverse-map (**`allocate_unit: Bad_unit_in_use`**), **`ntl_fold_block(ctx, victim_virt, 1)`** to **fold** that virt block and reclaim space.
- **Pressure loop:** while **`tl_chain_size ≤ 5`** (and **`param_4 == NULL`**), requires **`*(int *)sub == 2`**; scans **`virt ∈ [0, remap[4])`** for **maximum chain-depth byte** **`*(remap[8]+virt*8+5)`**, **`ntl_fold_block(ctx, worst_virt, 0)`** (**`ntl_fold_max`** / **`unable_to_fold_part`** printks).
- **Success:** **`tl_follow_chain(sub+0x15010, 0xffffffff, …)`** → **`tl_delete_chain`**, **`ntl_update_stat`** book-keeping; returns **phys unit id**.
- **Failure:** **`panic`** **`ntl_allocate_unit: Free_units_no`** after **`tl_log_chain`** reset attempt.

**Mount flags:** **`*(char *)(sub+0x150d1)`** gates **wear-level fold** vs **fold-in-mount** policy (**`nand: attempt_to_wear_level`** / **`attempt_to_fold_in_mount`**).

### 7.11 `tl_fold_chain` — collapse virt chain to new phys (`nand_fold_chain`)

**Role:** For **virtual block **`param_4`**, collect **every populated logical page** via **`ntl_find_phy`** ( **`pages = *(ushort *)(ctx+10)`** ), **allocate** fresh **`local_60`** unit (**`ntl_allocate_unit(..., (uint *)1, NULL, …)`** when **`local_360[0]==0`** ), program **fold header** spare (**`ntl_prepare_wspare`** with **`phys=0xffffffff`**, **`param_7=0xb6`**, **`param_8|param_9`** wiring **`8`** / **`0`** per snippet — **`ntl_write_verify_phy_spare`** spare-only program), then **for each** **`(phys_old, slot)`** in **`local_260`**: **`ntl_verify_read_phy_page`** read old → optional **`ntl_find_phy`** retry → **`ntl_prepare_wspare`** (**status `0x24`**) → **`ntl_write_verify_phy_page`** write into **`local_60`**.

**Teardown:** **`tl_erase_chain`** releases old mapping rows; **`tl_delete_chain`** returns units to free pool (or **`*(sub+4)+unit*0x10=*0xffffffff`** when **`sub+0x150d1`** wear flag set); **updates 8-byte virt entry** **`local_3c`**: **`phys = local_60`**, **`[5]=1`**, **`[6]=param_8`** generation, **`tl_add_chain`**, **`ntl_invalidate_page_map`** notifier.

**Edge:** If **no pages** collected (**`local_50==0`**), clears virt entry to **`phys=0xffffffff`**, **`[5]=[6]=0`**, still **`tl_erase_chain`** / **`ntl_invalidate_page_map`**.

### 7.12 `ntl_lookup_page_map` / `ntl_build_page_map` — RAM page-map cache

**Why:** **`ntl_find_phy`** fast path when **`*(chain_head+5)==4`** calls **`ntl_lookup_page_map`** then **`ntl_build_page_map`** to **avoid walking NAND** for **every page** once a **per–virtual-block map** exists.

**`ntl_lookup_page_map(ctx, virt_block, logical_page, out_pair, mode)`**

- Requires **`*(virt_entry+4) & 1`** (**`ntl_lookup_page_map: attempt_to_l…`** if clear).
- **`head = *(remap + (virt_block & 0xf) * 0xc + 0x14f50)`** — **16-way bucket** by low **virt** nibble.
- Walk **linked list** until **`node->field_0x14 == virt_block`**.
- **`mode == 0`:** **bitmap** presence test **`1<<(page&0x1f)`** in **`node->uint[(page>>5)+6]`**; if set, **`out = (-1, 0xffff)`** (“hole / skip”); else **`out = *(pair at node+(page+6)*8)`** (**phys**, **ushort index**).
- **`mode != 0`:** **`out = *(node+0x28)`**, **`*(node+0x2c)`** — **alternate / aggregate** phys slot.

**`ntl_build_page_map`** — allocates **`piVar16`** from **`remap+0x14f44`** / **`0x14f38`** LRU freelists (heavy **`tailq_remove`** integrity checks), walks **phys chain** starting **`virt_entry->phys`**, **`ntl_read_verify_phy_spare`** each hop, skips **`spare[4] ∈ {0xff, 0xb6}`**, fills **`piVar16`** arrays (**`piVar16+(page+6)*2`** stores **`phys`**, **`chain_idx`**), sets **bitmap words **`piVar16[(page>>5)+6]`**, splices node into **`0x14f50`** bucket list (**`remap+(virt&0xf)*0xc+0x14f50`**).

**Remap footprint:** Fields near **`0x14f38`–`0x14f50`** are **volatile cache** — **not** on-flash BBM; still explains **which spare bytes** (**`0xb`**, **`0xd`**, flags) feed **map entries**.

---

## 8. `ntl_schedule_folds` — pre-write cache bit clearing

Walks a small list, clears bit **`0x4`** on entries, may call **`ntl_fold_block`**. Relevant to **write caching**, not to **static BBM on-disk layout** unless flush serializes **stats**.

---

## 9. Suggested Ghidra next steps

1. **Struct-edit** the **8-byte virtual-block entry** (`phys` @0, flags @+1, chain metadata @+5, …).
2. **Xref writes** to **`*(sub+8)`** table base — **mount / BBM load** from NAND (incoming **`ntl_put_chain_in_array`** / loaders; **§11.3** **`tl_add_chain`** for **phys-unit doubly linked lists** tied to **`tl_init_chain`** headers **`0xd00d`**).
3. **Unify one diagram:** **`ntl_prepare_wspare`** (**§7.4b**) + **`ntl_compute_spare_xsum`** (**§7.4a**) + **`ntl_read_verify_phy_spare`** (**§7.1**) + **`ntl_write_verify_phy_page` meta+0xf** (**§7.9**) — confirm **`meta`** vs **raw spare** byte alignment on your NAND geometry.
4. **`ntl_prev_phy_location`** — **§7.1a**; **`ntl_prepare_wspare`** — **§7.4b**; **`ntl_compute_spare_xsum`** — **§7.4a**.
5. ~~**`get_word`**~~ — resolved **§7.5a** ( **`memcpy` + return first word** ); **`opentl_calculate_ecc`** outer structure (**8×8 `uint` lanes × 8 steps**) confirmed from the same **`.bin.c`** export.
6. **Done in-doc:** **`ntl_allocate_unit`** (**§7.10**), **`ntl_write_verify_phy_page`** (**§7.9**), **`tl_fold_chain`** (**§7.11**), **`ntl_lookup_page_map`/`ntl_build_page_map`** (**§7.12**).
7. **Label remap RAM:** **`sub+0x15010`** free pool, **`sub+0x15080`** wear victim scratch, **`0x14f38`/`0x14f44`** LRU nodes, **`0x14f50+(virt&0xf)*0xc`** bucket heads — tie to **`tl_chain_size`**, **`tl_follow_chain`**, **`ntl_update_stat`**, **`tl_erase_chain`** (see **§11.2** for **`ntl_initialize_memory`**/**`tl_init_chain`** anchor offsets into **`remap`**).
8. **Label `piVar10` fields:** **`[0]`** mode, **`[1]`** 16-byte phys table, **`[2]`** virt 8-byte table, **`[4]`** virt count, **`[5]`** max phys, **`[0xc]`** spare scratch, **`+0x28`** (**`ntl_write_verify_phy_page`** bounce), **`+0x30`** spare verify buffer base.
9. ~~**Confirm `ctx[0x13]` vs `*(ctx+0x4c)`**~~ — resolved for **`inner`**: same slot (**§11**); **`root+0x4c`** is a different **phase flag**.

---

## 10. Tie-in to repo tooling

| Component | Fit |
|-----------|-----|
| **`tl-bbm --mode linear_v1`** | Assumes **`virt_i → phys_i`**; firmware uses **`table[virt].phys`** — **wrong** when remap is non-identity or sparse. |
| **`tl-extract`** | Needs JSON **`virt_to_phys_block`** consistent with **8-byte table + optional chain** for bad blocks. **`KERNEL_LOGICAL_SECTOR_BYTES` / `KERNEL_NAND_PAGE_BYTES`** in **`tl_extract.py`** match **`opentl_accesssectors`** / **`opentl_add_mtd`** (§3.1). Helper **`layout_within_tl_erase_unit`** documents **512-in-2048** placement inside a **128 KiB** TL unit. |
| **`tl-bbm-score`** | Can still rank hypotheses using **ext2 / uImage** until BBM bytes are parsed from **`ntl_put_chain_in_array`** / loader init. |

---

## 11. OpenTL context layout — **root** vs **inner** (attach / mount)

Extracted with **`.cursor/skills/ghidra-vmlinux-extract`** from **`att-5268-…80458130.bin.c`**.

### Allocation size

- **`opentl_add_mtd`** (`nflaattach` / MTD notifier for **`tlpart`**): **`kmem_cache_alloc(…, 0x80d0)`** allocates **`puVar5`** — **main `mtd_priv` ~32976 bytes** (`0x80d0`).
- Second **`__kmalloc(…, mtd->writesize, 0x80d0)`** fills **`puVar5[0x1e]`** — page/DMA buffer pointer.

### Two bases (resolves **`[0x13]`** vs **`+0x4c`** confusion)

| Pointer | Role | Key offsets |
|---------|------|----------------|
| **`root`** | **`puVar5`** from attach — full driver private | **`root[0x13]`** (byte **`+0x4c`**) set to **`1`** in **`add_mtd_blktrans_dev`** — **early init / phase flag**, **not** the BBM remap pointer. **`root[0x14]`** (**`+0x50`**) = **`puVar2`** — large **`alloc_disk`** allocation (remap / TL control blob parent); **`puVar2[100] = root`** back-link. |
| **`inner`** | **`(int *)(root + 0xa0)`** i.e. **`puVar5 + 0x28`** as **`uint *`** — passed to **`ntl_mount`**, **`ntl_access_pages`**, **`ntl_read_page`**, **`ntl_read_verify_phy_spare`**. | **`inner[0x13]`** = word at **`inner + 0x4c`** = **`*(inner + 0x4c)`** = **pointer to remap / BBM object** (`piVar31` in **`ntl_mount`**). **`piVar31[8]`** = **`*(remap+8)`** = **virt→phys table base**. **`param_3[0x13]==0`** in **`ntl_mount`** = first mount → **`ntl_allocate_memory`**. |

So: **`*(param_3+0x4c)`** in NAND helpers is **`inner + 0x4c`**, i.e. **`inner[0x13]`** when **`param_3`** is the **`int *`** inner — **not** the same memory as **`root[0x13]`**.

### Mount sequence (sketch)

1. **`opentl_add_mtd`**: partition name **`tlpart`**, fill **`root[3]`** = MTD part, **`root[0x1e]`** page buffer, geometry **`[0x21]`–`[0x23]`**, **`opentl_dev_setup`**, then **`ntl_mount(root+0xa0, …)`** for TL mount.
2. **`add_mtd_blktrans_dev(root, …)`** (from attach after cap math): **`root[0x13]=1`**, allocate **`root[0x14]`**, worker **`mtd_blktrans_request`** / **`__raw_spin_lock_init`**, links **`add_disk`**, **`sysfs_create_group`** — builds block layer; **does not** replace **`inner[0x13]`** itself.
3. **`ntl_mount(inner, …)`**: if **`inner[0x13]`** null, **`ntl_allocate_memory`** **`kmalloc`s** the **remap** blob (size **`((phys_range+1)×0x18 + 0x150dc + …)`**), **`memset`**, sets **`inner[0x13]`**, allocates **`remap[8]`…`[11]`** (+ **`[12]`/`[13]`** pools) via **`tl_malloc`** (**`tl_malloc`**); then **`ntl_initialize_memory`** lays out freelists / buckets / LRU (**§11.2**) and fills the **8-byte virt table** with **`0xffffffff`**. Else branch **`ntl_initialize_memory`** only. Then **`piVar31 = inner[0x13]`**, **`tl_add_chain`** (and related loaders) populate from NAND; **`ntl_put_chain_in_array`** is the **chain-array** builder used from read/write/delete paths (**§6**), not to be confused with the thin **`ntl_read_phy_spare`** spare gate (**§11.2**).

**Offline implication:** the **virt→phys table** is **heap-backed** and **filled from spare/OOB walks** — not a dense array at a fixed offset inside a flat **`tlpart.bin`** carve. **`tl-bbm`** identity / **`brute_reserved`** maps remain **hypothesis generators** until stats-block layout or full chain replay exists (**[issue.md](issue.md)**).

**Xref target for virt table:** writes through **`*(remap+8)`** after **`ntl_allocate_memory`** — **`remap = *(inner+0x4c)`**; label **`inner`** as **`mtd_priv + 0xa0`** in Ghidra.

**Stats block NAND persistence:** **`ntl_update_stat`** only bumps **RAM** counters in **`remap+0x150cc`**; **`ntl_flush_table`** writes that buffer through **`ntl_access_pages(..., op=WRITE)`** with the **same virtual page window** as **`ntl_load_stat_table`** (**`ntl_stat_flush_if_needed`** rate-limits flush). See **`output/opentl_mount/stats_persist_ghidra.md`**.

### 11.1 Ghidra session confirmation (REST `127.0.0.1:8089`, kernel image loaded)

Program open: **`att-5268-…80458130.bin`**, **`MIPS:BE:32`**, **`ram` min `80010000`** — matches **`fwupgrade.txt`** load base.

**`ntl_allocate_memory`** ( **`tl_malloc`** / **`tl_malloc`** orchestrator): Decompilation matches §11 size sketch — **`param_3`** is **`inner`**, **`param_3[0x13]`** is **`inner+0x4c`** / remap pointer. When **`param_3[0x13]==0`**:

- **`phys_range = param_3[1] - *param_3`** (allowed physical unit span).
- **`uVar1 = ((phys_range + 1) * 0x18) + 0x150dc + ((((phys_range + 0xc) * 4 + (param_3[4] - 1)) & ~(param_3[4] - 1)))`** — main remap blob byte length (rounded-up tail matches **`param_3[4]`** alignment / freelist carve).
- **`tl_malloc`** allocates **`local_1c`**, **`memset(..., uVar1)`** clears it, **`param_3[0x13] = (int)local_1c`**.
- Seven more **`tl_malloc`** calls fill **`local_1c[8]` … `local_1c[0xd]`** — same indices as **`remap[8]`–`[13]`** pool pointers in §11 prose.

Failure paths **`kfree`** (via **`thunk_kfree`**) free partial allocations and zero **`param_3[0x13]`**. Non-first-mount branch returns **`0x10`** when remap already exists.

**Incoming calls — two different symbols (do not confuse):**

**`ntl_put_chain_in_array`** (**§6** `ntl_put_chain_in_array`) — BBM chain expansion into **`param_5`** pairs:

| Caller | Note |
|--------|------|
| **`ntl_read_page`** @ **`80289234`** | Read path (**§5**). |
| **`ntl_write_page`** | Write page. |
| **`ntl_delete_page`** | Delete page. |
| **`ntl_fold_block`** | Fold block. |
| **`ntl_erase_unit`** | (Related fold/write pressure.) |
| **`ntl_log_virt_chain`** | Auxiliary (**analyze in Ghidra**). |

**`ntl_read_phy_spare`** — **thin gate**: NULL **`param_6`** → panic string **`ntl_read_phy_spare…NULL`**; virt **`param_4`** vs **`remap[4]`** → **`bad_blk_in_read_spare`**; else **`(*(code **)(param_3+0x58))(param_3, param_4)`** (NAND **spare read** callback). **Not** the chain walker.

| Caller | Note |
|--------|------|
| **`ntl_mount`** @ **`8028adac`** | Mount / notifier. |
| **`ntl_find_valid_spare`** @ **`80289964`** | Per-page sweep (**§11.2**). |
| **`8028e9ec`** | Additional call site. |

### 11.2 Freelist tags and **`ntl_initialize_memory`** layout (decompilation)

**`tl_init_chain(hdr, phys_span, pool_base, label)`** — clears **`0x38`** bytes, stores **`hdr[10]=phys_span`**, **`hdr[9]=0`**, **`hdr[0xb]=hdr[0xc]=0xffffffff`**, **`hdr[0xd]=pool_base`**, **`*(ushort *)(hdr+8)=0xd00d`**, then copies a **NUL-terminated ASCII label** into the first bytes of **`hdr`** (tag string). **`ntl_initialize_memory`** calls it three times with **`s_freelist`**, **`s_badlist`**, **`s_usedlist`** into **`remap + 0x5404`**, **`+0x5412`**, **`+0x5420`** (pointer arithmetic on **`uint *`** **`remap`**).

**`ntl_initialize_memory(inner)`** — **`remap = inner[0x13]`**; **`return 0x16`** if remap null. Otherwise:

- **`inner[0]` / `inner[1]`** (physical erase-unit index bounds passed through **`ntl_mount`**): filled on **`opentl_add_mtd`** — export shows **`puVar5[0x28]=0`**, **`puVar5[0x29]`** from **`nand_geom`** so that **`inner[1]−inner[0]`** is **last−first** on an **inclusive** index pair (**`inner[1]=raw_blocks−1`** when **`inner[0]=0`**). **`ntl_allocate_memory`** uses **`(inner[1]−*inner)+1`** (physical **unit count**) in its **`kmalloc`** size; **`ntl_initialize_memory`** uses **`inner[1]−*inner`** alone as **`phys_span`** in **`align_up((phys_span+0xc)×4, inner[4])`** when writing **`remap[0x5432]`** (byte offset **`0x150c8`** — stats arena length). Details: **`output/opentl_mount/README.md`** §**`0x150c8`**.
- Zeros **`remap+0x542e`** (**24** B), sets **`remap[0x5432]`**, **`remap[0x5433]`**, **`remap[1]`**, **`remap[2]`** (phys / virt table anchors per **`puVar5` / `puVar8`** math), **`remap[3]`**, **`remap[4]`**, **`remap[5]`** = **`phys_range`**, mode words/bytes at **`remap[0]`**, **`*(remap+6)`**, **`*(remap+0x1a)`**, etc.
- **`memset`** **`remap+0xe`**, length **`0x14f00`** — large control region (**includes cache buckets / bookkeeping** per §7.12 footprint).
- **`memset`** **`remap+0x53d4`**, **`0xc0`** bytes; then **16** tailq bucket heads **`remap + 0x53d4 + i×(3×4)`** for **`i = 0..15`** (**low nibble hash lanes**).
- **80** (**`0x50`**) LRU-style nodes at stride **`0x10c`** bytes from base **`remap+0x12`**: each linked into **`remap[0x53d2]`** freelist, **`node[0]=index`**, **`node[1]=-1`**, inner loop fills **`pages_per_block`** **`(phys,0xffff)`** pairs with **`0xffffffff`** when **`*(ushort *)(inner+10) != 0`**.
- Final loops over **`virt_count = phys_range + 1`**: **`virt` words `0xffffffff`**, then **16-byte stripes** of **`0xffffffff`** triples on the **phys-side table** (`puVar5` advance).

**`ntl_find_valid_spare`** — iterates **`page = 0 .. pages_per_block-1`** (**`*(ushort *)(inner+10)`**): **`ntl_read_phy_spare`** (spare read gate → **`ctx+0x58`**), then **`ntl_map_page_state(*(byte *)(spare+4))`** and **`ntl_xsum_read`** checksum; sets caller’s flag byte if spare/checksum indicate **action needed**. **`ntl_mount`** and **`tl_handle_partial_fold`** call it — **mount / stats validation**, orthogonal to **`ntl_put_chain_in_array`** chain filling.

### 11.3 Phys-unit chain list (`tl_add_chain`) vs virt-chain logger (`ntl_log_virt_chain`)

**`tl_add_chain`** — printk paths **`tl_add_chain`**, **`Adding %d to chain`**, **`Bad_block`**, **`Bad_tail`**, **`Bad_head`** — mutates a **doubly linked list** of **`0x10`-byte** records indexed by **physical unit** **`param_4`**:

- **Magic guard:** **`*(short *)(pool + 0x20) == (short)0xd00d`** (same constant **`tl_init_chain`** stamps at **`*(ushort *)(hdr + 8)`**; mismatch → **`Bad_chain_magic`**). **`pool`** is one of the **`tl_init_chain`-initialized** chain headers (**freelist / bad / used** — §11.2).
- **`tl_in_chain`** — membership / sanity on **`(pool, param_4, …)`** before splice.
- **Records:** **`record = *(pool + 0x34) + param_4 * 0x10`** — **`record[0]`** next index, **`record[1]`** prev (**`-1`** when unset). **`pool+0x30`** = **tail** unit index, **`pool+0x2c`** = **head**, **`pool+0x24`** = **element count**.
- **`param_5`:** **`0`** = insert at **head** (prepend); **`1`** = insert at **tail** (append); else **`unknown_pos`** panic.
- **`tl_log_chain`** — emits **`chk_chain:`** debug lines after successful splice when **`debug > 2`** (**§11.4**).

**Incoming calls (selected):** **`ntl_mount`** (**four** call sites — mount / remap plumbing), **`ntl_write_page`**, **`ntl_allocate_unit`**, **`tl_fold_chain`**, **`ntl_free_block_if_notbad`**, **`tl_randomize_list`**, **`tl_handle_partial_fold`**, plus **`FUN_8028c22c`** / **`FUN_8028cd4c`** *(not in `…kallsyms.txt` — likely **`static`**; resolve by address in Ghidra)* — **any path that rewires spare-chain bookkeeping** should cross **`tl_add_chain`**.

#### Ghidra renames (printk strings, live DB — May 2026)

Saved on **`att-5268-…80458130.bin`**. Bridge **`NamingPolicy`** warns that **`tl_*` / `ntl_*` are not PascalCase**; names were chosen to match firmware **`printk`** text. Static **`.bin.c`** exports still show **`FUN_8028…`** unless re-exported.

| Address | Ghidra name |
|---------|-------------|
| **`0x802864ec`** | **`tl_add_chain`** |
| **`0x802862f8`** | **`tl_delete_chain`** |
| **`0x80286104`** | **`tl_log_chain`** (printk **`chk_chain:`**) |
| **`0x80285cbc`** | **`tl_in_chain`** |
| **`0x80289c40`** | **`ntl_log_virt_chain`** (optional Ghidra rename **`ntl_print_virt_chain`** from printks) |
| **`0x802888f8`** | **`ntl_put_chain_in_array`** |

#### Four **`tl_add_chain`** sites in **`ntl_mount`** (pool mapping)

Extracted from **`extract_ghidra_fun.py … ntl_mount`** on **`att-5268-…80458130.bin.c`** — **line numbers** refer to that export.

| # | `.bin.c` lines | Pool argument (arg 3) | List |
|---|----------------|------------------------|------|
| **1** | ~135 | **`(undefined1 *)local_5c`** where **`local_5c = remap + 0x5404`** (**§11.2**) | **Freelist** (**`s_freelist`**) |
| **2** | ~296 | same **`local_5c`** | **Freelist** |
| **3** | ~373 | **`(undefined1 *)(iVar9 + 0x15010)`** — same header as **`remap + 0x5404`** (**byte `sub+0x15010`**) | **Freelist** |
| **4** | ~728 | **`param_6`** after **`param_6 = (char *)(piVar31 + 0x5420)`** — byte **`sub+0x15080`** | **Usedlist** (**`s_usedlist`**) |

**Badlist** (**`remap + 0x5412`**, byte **`sub+0x15048`**) is **not** targeted by any of these four calls; it is set up in **`ntl_initialize_memory`** and updated from **other** callers of **`tl_add_chain`**.

**`ntl_log_virt_chain`** — **`ntl_print_virt_chain`** / **`SECTOR_MAP`** strings; **read-only reporting**:

- **`ntl_put_chain_in_array`** fills **`local_234`** / **`local_2c0`** (chain pairs); **`snprintf`** (**`snprintf`**-style) builds lines; **`ntl_read_verify_phy_spare`** reads spare per **phys**; decodes **virtual block** from spare **`[9]`/`[10]`** (+ **`[0x12]`/`[0x13]`** on large pages); **`ntl_find_phy`** walks **per-page** **`ntl_find_phy`** for **`SECTOR_MAP`** output when **`param_5 != 0`**.
- **`tl_in_chain`** annotates whether **phys** is on **`FREELIST`** vs **`STAT`** row (**reverse-map** check **`*(remap[4] + phys*0x10 + 8)`** vs **`param_4`**).
- **Callers:** **`ntl_fold_block`** (**fold** — §7.8) and **`ntl_log_all`** — **diagnostics around chain collapse / stats**, **not** the primary BBM writer.

### 11.4 **`tl_in_chain`**, **`tl_log_chain`** (printk prefix **`chk_chain:`**), dump orchestrator **`ntl_log_all`**

**`tl_in_chain`** — printk **`tl_in_chain`**, **`Bad_block`**, **`%d not_found_in_chain`**:

- Same **`0xd00d`** magic at **`*(ushort *)(pool + 0x20)`** as **`tl_add_chain`**.
- **`param_4`** must be **`≤ *(uint *)(pool + 0x28)`** (valid phys index upper bound).
- Walks the **singly linked** forward list starting at **`head = *(uint *)(pool + 0x2c)`**, following **`next = *(table + unit * 0x10)`** from **`table = *(pool + 0x34)`**, for at most **`*(pool + 0x24)`** hops — returns **`1`** if **`param_4`** appears, else **`0`** (with verbose **`not_found`** printk).

**`tl_log_chain`** — explicit **`*(ushort *)(pool + 0x20) == 0xd00d`** check (printk **`bad_chain_magic`** with actual halfword); **`snprintf`** builds **`chk_chain:%s … %d blks`** lines by walking the same **forward** chain from **`*(pool + 0x2c)`** through **`*(pool + 0x34)`** rows — **debug-only chain listing**, not a mutator. Callers include **`tl_add_chain`** / **`tl_delete_chain`** (after splice/remove when **`debug > 2`** — **§11.5**), **`ntl_allocate_unit`** (multiple sites), **`ntl_fold_block`**, **`ntl_log_all`**.

**`ntl_log_all`** — **partition dump** when **`debug`** (**`_DAT_805dc0d0`**) **> 0**:

- Requires mounted remap **`*(inner + 0x4c)`** with **`remap[0] != 0`**; else **`unable_to_dump_unmounted_part`**.
- **`________ begin_virtual_chains`** — for **`virt = 0 .. remap[4]-1`**, **`ntl_log_virt_chain`** (§11.3).
- **`________ begin_freelist`** — **`tl_log_chain((undefined1 *)(remap_ptr + 0x5404))`**.
- **`________ begin_usedlist`** — **`tl_log_chain((undefined1 *)(remap_ptr + 0x5420))`**.

With **`remap_ptr`** typed **`int *`** **`piVar2`**, **`piVar2 + 0x5404`** and **`piVar2 + 0x5420`** are **byte** offsets **`0x5404×4 = 0x15010`** and **`0x5420×4 = 0x15080`** — i.e. the **`tl_init_chain`** headers at **`§7.10`** **`sub+0x15010`** (**freelist / free pool**) and **`sub+0x15080`** (**usedlist** scratch region). This **anchors** the numeric **`sub+…`** prose to **`ntl_initialize_memory`**’s **`uint *`** layout.

**Callers:** **`ntl_mount`**, **`ntl_write_page`**, **`ntl_allocate_unit`** — invoked when turning on **verbose OpenTL** dumps during mount / IO pressure.

### 11.5 **`tl_delete_chain`** (`tl_delete_chain`), sequence audit (`ntl_verify_chain_seqnum`), erase stub (`ntl_verify_phy_erase`)

**`tl_delete_chain`** — printk **`Deleting %d from chain`**, **`tl_delete_chain`** — **removes** a **physical unit** from the same **`0xd00d`**-tagged doubly linked pool **`tl_add_chain`** maintains:

- Requires **`tl_in_chain(pool, param_4) != 0`** (unit **must** be present — else **`tl_delete_chain … Bad_block`**).
- **Unlink** cases mirror **`tl_add_chain`**: singleton (**`count==1`**) clears **head/tail/count**; else patches **pred/succ** indices in **`*(pool+0x34) + unit*0x10`**, decrements **`*(pool+0x24)`**, clears **`record[0]`/`[1]`** to **`-1`**.
- **`tl_log_chain`** after successful delete when **`debug > 2`**.
- **Callers:** **`ntl_mount`**, **`ntl_erase_unit`**, **`tl_randomize_list`**, **`ntl_allocate_unit`**, **`tl_fold_chain`** — **reclaim / fold / allocate** paths that **detach** phys indices from **freelist or usedlist** chains.

**`ntl_verify_chain_seqnum`** — **caller `ntl_mount` only**; **audits** one **virtual block**’s **bad-block chain** for internal consistency:

- **`rev_tab = *(int *)(remap + 0x10)`** bytes (**`int *` remap**, word **`[4]`**) — base of **`0x10`-byte** rows (**`row = rev_tab + virt * 0x10`**).
- Walks **`next = *(uint *)row`** until **`0xffffffff`**, sets **`*(byte *)(row + 0xd) |= 0x10`**, checks **`*(byte *)(row + 0xc)`** (**chain sequence id**) matches **`uVar6`** on every hop — printk **`mismatch_seq_in_chain`** / **`Hard_hart`** on mismatch.
- **Max chain length `0x45`** (**69**) — **`chain_length_over_max`**.

**Offline spare inference:** **`infer_virt_map_from_all_page_spares`** ( **`tl-mount-sim`** ) resolves duplicate spare decodes with **lexicographic `(page_index, phys_block)`**, not **`ntl_verify_chain_seqnum`** chain order. Wrong winners produce bad **`virt→phys`** even when **`extract_virtual_disk_bytes`** is correct—rank **`brute_reserved_v1`** slides with **`tl-bbm-score`** / **`tl-extract`** **`ext2_magic_ok`** after tightening spare decode or threading **`--nand-logical-offset`** on full-chip inputs.

**`ntl_verify_phy_erase`** — **`if ((*(code **)(ctx + 0x60))() != 0)`** → printk erase failure (**EB** erase); success returns **0**. **NAND erase** callback slot (**contrast §7.1 `+0x58` spare read, §7.9 `+0x50`/`+0x54` program/read-verify**). **Callers:** **`ntl_mount`**, **`ntl_free_block_if_notbad`**.

### 11.6 Allocate path **`ntl_allocate_unit`** + **`tl_log_chain`** (freelist vs usedlist)

Printk family **`ntl_allocate_unit`**, **`allocate_unit Bad_unit_in_use`**, **`Free_units_no`**, **`unable_to_fold_part`**. **`ntl_allocate_unit`** is the **phys-unit allocator**; **`remap = param_3[0x13]`** (**`iVar13`** in decompilation).

**Density / wear probe:** When **`param_4 == 0`**, **`tl_chain_size(…, remap + 0x15080, …)`** consults the **usedlist** region (same **byte `+0x15080`** header as **`ntl_log_all`**’s **`begin_usedlist`** dump — **§11.4**). Periodic **`random32`** gate triggers a **usedlist walk**: **`tl_follow_chain`** scans the **usedlist** chain for a candidate **`puVar4`** (phys index). If table invariants fail (**`Bad_unit_in_use`**), **`tl_log_chain((undefined1 *)(remap + 0x15080), …)`** runs **before** **`panic`** — the three **`tl_log_chain`** call sites inside **`ntl_allocate_unit`** (**`0x8028d6a8`**, **`0x8028d7e8`**, **`0x8028d844`**) all pass this **usedlist** pool pointer, i.e. they **list the usedlist** for debugging when **allocation invariants break**, not the freelist.

**Freelist normalization:** **`tl_in_chain((uint)freelist_hdr, puVar4)`** with **`freelist_hdr = remap + 0x15010`**. If the candidate phys is **already** on the freelist, **`tl_delete_chain`** removes it and **`tl_add_chain`** re-inserts at head — keeps freelist consistent before folding (**`ntl_fold_block`**) or wear moves.

**Happy path:** Main loop scores freelist pressure via **`tl_chain_size(freelist, …)`**, may **`ntl_fold_block`** fold; **`tl_follow_chain(freelist, 0xffffffff, …)`** pops a **freelist** phys **`uVar1`**; **`tl_delete_chain(freelist, uVar1)`** then **`ntl_update_stat`** (install mapping).

**Empty freelist:** Last **`tl_log_chain((undefined1 *)(remap + 0x15080), …)`** before **`panic`** (**`Free_units_no`**) — again the **usedlist** header, documenting **used** blocks when no free phys remains.

---

## 12. Linux MTD OOB stack — `mtd_oobsize_show`, `concat_*_oob`, `part_*_oob`, `mtdchar_*oob`, `brcmnand_*_oob`, `opentl_*_oob`

Ghidra **MCP** on **`att-5268-11.5.1.532678_…_ghidra_m00_kernel.elf`**: `search_strings` + `get_xrefs_to` + `batch_decompile` (May 2026). **Symbol / rodata** strings use the **`utf8 u8"…"`** / **`ds` forms** in C++-style exports; the ELF **`.rodata`** spellings are the same ASCII text below.

### 12.1 Summary table

| String / rodata | Referencing function(s) | Role |
|-----------------|---------------------------|------|
| **`mtd_oobsize_show`** | **`mtd_oobsize_show`** @ **`0x80278b20`** | **Sysfs** `oobsize` attribute: **`dev_get_drvdata`** → **`snprintf`** user buffer from **`*(ulong *)(mtd + 0x1c)`** ( **`oobsize`** field on **`struct mtd_info`** ). |
| **`concat_write_oob`** / **`concat_read_oob`** | **`concat_write_oob`** @ **`0x8027a320`**, **`concat_read_oob`** @ **`0x8027a6d8`** | **MTD concat:** iterate **`mtd->subdev`** table (**`*(mtd+0x1e0)`** count, **`*(mtd+0x1e4)`** array); map **linear** **`(ofs_hi, ofs_lo)`** into child MTD by **`child+8`**/**`child+0xc`** bases; dispatch **`_write_oob`** @ **`child+0x6c`**, **`_read_oob`** @ **`child+0x68`**. |
| **`part_write_oob`** / **`part_read_oob`** | **`part_write_oob`** @ **`0x8027c2b8`**, **`part_read_oob`** @ **`0x8027c86c`** | **MTD partition:** clip OOB request to **partition span** (**`part+8`**/**`part+0xc`**); add **partition offset** (**`part+0x1e8`**/**`0x1ec`**); forward to **master** **`mtd`** (**`part+0x1e0`**). **`part_read_oob`** includes **64-bit divide** path for alignment checks vs **`mtd->writesize`**. |
| **`mtdchar_readoob`** / **`mtdchar_writeoob`** | **`mtdchar_readoob`** @ **`0x8027e60c`**, **`mtdchar_writeoob`** @ **`0x8027e8dc`** | **`/dev/mtd*`** file ops: cap len **0x1000**; build **`struct mtd_oob_ops`** with **`.mode` `2`** vs **`1`** depending on **inode/partition-type** (**`*(inode_priv+0x88)+8`** vs **`3`**); **`kmalloc`** / **`memdup_user`**; call **`mtd->_read_oob`** (**`+0x68`**) / **`_write_oob`** (**`+0x6c`**); **`__copy_user`** to userspace. |
| **`brcmnand_access_oob`** | **`brcmnand_access_oob`** @ **`0x80283d2c`** | **Broadcom NAND core:** validate **`oob_ops.mode == 2`**, **`ooblen == mtd->oobsize`**, **`ooboffs == 0`** (printk **`BCMNAND: Access bad OOB offset`** / **`length`**), **`oobbuf != NULL`** (**`NULL oob buffer`**); optionally **`datalen == writesize`** + data buf for **combined page+OOB** via **`nandchip_read/write_onepage`** + **`nandchip_read/write_onespare`**. Debug **`BRCMNAND: brcmnand_access_oob: %llu mode=%d`** when NAND chip struct unset (**`*(chip+4)==0`** path). Also **`BCMNAND: Access Unsupported mode`**, **`Attempt read beyond end`**, **`bad length`**. |
| **`brcmnand_write_oob`** / **`brcmnand_read_oob`** | **`brcmnand_write_oob`** @ **`0x80283f94`**, **`brcmnand_read_oob`** @ **`0x80284004`** | Thin wrappers: **`nandchip_get_device`**, **`brcmnand_access_oob`** (**write** passes **`param_8 == 2`**, **read** **`param_8 == 1`**), **`nandchip_release_device`**. |
| **`opentl_read_oob`** / **`opentl_write_oob`** | **`opentl_read_oob`** @ **`0x80287e60`**, **`opentl_write_oob`** @ **`0x80288014`** | **OpenTL → MTD:** **`mtd_oob_ops.mode = 2`**, **`ooboffs = ofs & (writesize-1)`**, **`ooblen`** from args; call **`mtd->_read_oob`**/**`_write_oob`** (same §3.1). |
| **`oobsize`** (attr name) | **Sysfs** template next to **`mtd_oobsize_show`** | Literal used in **`snprintf`** format for **`type`/size** sysfs output (kernel **`drivers/mtd` sysfs** family). |
| **`Incompatible OOB or ECC data on \"%s\"\n`** @ **`0x804f5530`** | Single xref **`0x8027aff4`** → **`mtd_concat_create`** @ **`0x8027a964`** | Emitted when **concatenating** MTDs whose **OOB/ECC parameters** do not match (**cannot build one virtual MTD** across mismatched children). |
| **`Ip6InTooBigErrors`** @ **`0x8050cb64`** | *(no instruction xrefs in this ELF)* | **SNMP / MIB** statistic name — **not** NAND-related; listed only because it appeared beside NAND strings in a dump grep. |
| **`PktTooBigs`** @ **`0x8050cd54`** | **`0x80491820`** **[DATA]** only | **SNMP** counter label — **not** executed from **`brcmnand`**; unrelated to OOB path. |

### 12.2 Call chain (application → hardware)

```text
User / sysfs / ioctl
  mtd_oobsize_show              → sysfs read of mtd->oobsize
  mtdchar_readoob / writeoob    → /dev/mtdX OOB ioctl path
  part_read_oob / part_write_oob → partition-relative offset → master MTD
  concat_read_oob / concat_write_oob → stripe across sub-MTDs (whole-chip view)
  brcmnand_read_oob / write_oob → chip lock + brcmnand_access_oob
  brcmnand_access_oob           → nandchip_*onespare / *_onepage + ECC path
  opentl_read_oob / write_oob   → thin mtd->_read_oob / _write_oob on tlpart
```

### 12.3 Controller **`nandchip_*onespare`** + **`ntl_read_verify_phy_spare`** (hardware spare ↔ OpenTL verify)

**Authoritative MMIO table** ( **`brcmnand_ctrl_read` / `brcmnand_ctrl_write`** offsets **`0x204`/`0x208`/`0x20c`**, FIFO **`0x220`–`0x22c`** read / **`0x230`–`0x23c`** write, status **`0x26c`**, physical base **`DAT_b0000000`**) — **[`output/opentl_mount/brcmnand_oob_ghidra.md`](output/opentl_mount/brcmnand_oob_ghidra.md)** § **`nandchip_read_onespare` / `nandchip_write_onespare` — MMIO**.

**`nandchip_read_onespare`** @ **`0x80283480`**: **`*(chip + 0x6c) >> 4`** outer chunks; per chunk **`brcmnand_ctrl_write`** programs **`0x20c`**, **`0x208`**, **`0x204`** (`0x02000000`), **`nandchip_wait_status_isra_1`**, then **`brcmnand_ctrl_read`** **`0x220`…`0x22c`** (**16 B**). **`0x200`** stride on the linear address fields — matches **64 B** OOB as **four** **16 B** slices for typical **`oobsize`**.

**`nandchip_write_onespare`** @ **`0x80283c20`**: Same addressing **`0x20c`/`0x208`**; **`memcpy` 16 B** → **`nandchip_copy_to_spare_constprop_4`** (**`0x230`…`0x23c`**) → **`0x204`** (`0x05000000`) + wait; tail **`memset(..., 0xff, 0x10)`** + **`nandchip_copy_to_spare_constprop_4`** (**flush**).

**`ntl_read_verify_phy_spare`** @ **`0x80288750`**: **`param_6`** = spare buffer (**panic** if **`NULL`**). Calls **`mtd->_spare_read`** hook (**`param_3 + 0x58`** — **`opentl_dev_spare_read`** class path). On success: **`ntl_map_page_state`** on **`param_6[4]`**, conditional **`ntl_xsum_read`** vs **`param_3 + 0x24`** (**ushort** index — spare layout offset), printk **`checksum_fail`** branch; writes **`param_6[4]`** mapped page-state byte.

**Offline tooling:** Flat **`1012 × 64 × 64`** **OOB tail** is consistent with **full spare reads** per **page** at the BCM controller — **`tl-mount-sim`** **`oob_page_spare`** assumes **64 B** contiguous spare per **(phys_block, page)** with **no** interleaved partial copies inside **`nandchip_read_onespare`** beyond **16 B** FIFO bursts into a **64 B** buffer.

---

## 13. References in-tree

- **[printk_anchor_fwupgrade_ghidra.md](printk_anchor_fwupgrade_ghidra.md)** — **`fwupgrade.txt`** §196–367 printk anchors vs **BCMNAND / OpenTL** Ghidra rodata xrefs.
- **[fwupgrade.txt](fwupgrade.txt)** — **`tlpart`**, **`cap=0x0003D4FC`**, BBM/stats printks.
- **[flash strings.txt](flash%20strings.txt)** — `OPENTL:`, `ntl_`, `opentl_dev_`, `opentl_map.c`.
- **`opentl/tl_bbm.py`** — current map schemas (**`binwalker_tl_bbm_v1`**).
- **Reconstructed kernel ELF (`vmlinux-to-elf`)** — **§0**:
  - **[`…_ghidra_m00_kernel.elf`](firmware_11.5.1.532678/11.5.1.532678/install_package/pkgstream_carves/att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_36645b10_ghidra_m00_kernel.elf)** — preferred Ghidra/IDA input.
  - **[`…_ghidra_m00_kernel.kallsyms.txt`](firmware_11.5.1.532678/11.5.1.532678/install_package/pkgstream_carves/att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_36645b10_ghidra_m00_kernel.kallsyms.txt)** — 17,277-entry `nm`-style listing (grep this when you don't want to round-trip Ghidra).
  - **[`…_ghidra_m00_kernel.elf.md`](firmware_11.5.1.532678/11.5.1.532678/install_package/pkgstream_carves/att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_36645b10_ghidra_m00_kernel.elf.md)** — per-carve summary.
  - **[tools.md](tools.md) § _`vmlinux-to-elf` — kernel symbol recovery for Ghidra/IDA_** — installation, override flags, auxiliary commands.
- **Ghidra MCP / REST:** Live analysis uses **`http://127.0.0.1:8089`** with **`Authorization: Bearer`** matching **`GHIDRA_MCP_AUTH_TOKEN`** (see **`~/.cursor/mcp.json`**). If the Python bridge still errors on **`connect_instance`** (`duplicate parameter name: 'dry_run'`), apply the **`bridge_mcp_ghidra.py`** guard (**skip synthetic `dry_run` when the schema already defines it**) and **reload MCP**, or call the HTTP API directly as in **§11.1**. Offline **`extract_ghidra_fun.py`** on **`…80458130.bin.c`** remains valid (**§7.5a**).

---

*Document synthesized from chat RE notes (May 2026). §7.3–§7.12 cover read/find spare, ECC, write/verify, allocate, fold chain, page-map cache; **`ntl_compute_spare_xsum`** checksum formula §7.4a. §11: **`opentl_add_mtd` / `add_mtd_blktrans_dev` / `ntl_mount`** attach layout (`ghidra-vmlinux-extract`); §11.4 ties **`tl_init_chain`** headers to **`0x15010` / `0x15080`** byte offsets via **`ntl_log_all`**; §11.5 **`tl_delete_chain`** / **`ntl_verify_chain_seqnum`**; §11.3 optional Ghidra renames + **`ntl_mount`** pool map; §11.6 **`ntl_allocate_unit`** vs **`tl_log_chain`**. §12: Linux MTD OOB sysfs / concat / partition / **`mtdchar`** / **`brcmnand`** / **`opentl`** (`batch_decompile`). Function IDs bulk-updated from **`…kallsyms.txt`** via **`binwalker/scripts/kallsyms_replace_fun_in_md.py`**. Update as spare-chain layout is confirmed.*
