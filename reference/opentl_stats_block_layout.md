# OpenTL stats block — on-disk / virtual placement (5268 kernel)

This document captures **Ghidra MCP decompilation** of the Pace-class **Linux 3.4.x** OpenTL driver (`drivers/mtd/opentl`) with program **`att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_ld0x80010000_ep0x80458130-kernel.elf`**, **`image_base = 0x80010000`** (May 2026).

Python helpers: [`opentl/stats_block.py`](../opentl/stats_block.py). Cross-links: [`opentl_kernel_ghidra.md`](opentl_kernel_ghidra.md), [`opentl.md`](opentl.md).

---

## 1. RAM header after `ntl_reset_stat_table` (`0x8028a938`)

The stats working buffer (`remap` field at byte offset **`0x150cc`** — word index **`0x5433`** on `int * remap`) is cleared then stamped:

| Word | Offset | Value | Role |
|------|--------|-------|------|
| 0 | 0 | **`0x00010000`** | Magic / version tag |
| 1 | 4 | **`0xDEAD1001`** | Vendor token (literal written; Ghidra may show `-0x2152efff` in comparisons) |
| 2 | 8 | **`remap[5]`** at reset | Copied from `*(remap + 0x14)` byte offset = **word `remap[5]`** — same as **`inner[1] - *inner`** (phys span) right after `ntl_initialize_memory` |

`ntl_load_stat_table` (`0x8028aab0`) after a successful `ntl_access_pages` **READ** insists on the same triple before accepting loaded stats; otherwise it printk-branches (`resetting_stats` / `starting_new_stats`) and calls `ntl_reset_stat_table`.

---

## 2. Stats arena byte length — `ntl_initialize_memory` (`0x80289610`)

On the `remap` blob:

```text
remap[0x5432] = align_up((phys_span + 0xC) * 4, inner[4])
```

* **`phys_span`** = `inner[1] - inner[0]` (last minus first physical unit index).
* **`inner[4]`** = alignment (power of two; typically **4**).

For **1012** raw units with `inner[0]=0`, `inner[1]=1011` → `phys_span=1011` → `(1011+12)*4 = 4092` bytes.

See :func:`opentl.stats_block.stats_buffer_byte_count`.

---

## 3. Virtual TL placement — `ntl_load_stat_table` / `ntl_flush_table`

Let:

* **`S`** = `remap[0x5432]` (stats buffer bytes),
* **`P`** = `*(ushort*)(inner + 10)` = pages per virtual erase block (**64**),
* **`W`** = `*(uint*)(inner + 0x10)` = NAND data page bytes (**0x800**),

Then:

1. **`page_count`** = `ceil(S / W)`  
2. **`virt_stats_blocks`** = `ceil(page_count / P)` — stored in **`*(short*)(remap + 0x1a)`** (note: **short** at byte offset **`0x1a`** on the remap base; do not confuse with `inner+0x1a`).

**Linear page index** for `ntl_access_pages` (same window for read and write):

```text
start_linear_page = (remap[4] - virt_stats_blocks) * P
page_count        = page_count   # as above (not padded to whole erase blocks for the access length)
```

`remap[4]` is the **total virtual erase-block count** (dword at **byte offset `0x10`** on the `remap` blob — i.e. **index 4** when `remap` is typed as `uint32_t *`).

**Tail bytes on the assembled virtual TL disk** (whole erase blocks only — what you slice for a **linear identity** map):

```text
tail_bytes = virt_stats_blocks * ERASE_BYTES   # ERASE_BYTES = P * W = 128 KiB typical
```

See :func:`opentl.stats_block.stats_tail_virtual_disk_bytes` and :func:`opentl.stats_block.stats_region_linear_page_span`.

---

## 4. Flush policy — `ntl_stat_flush_if_needed` (`0x8028eb08`)

Counters at **`remap + 0x150b8`** (timestamp / jiffies) and **`remap + 0x150bc`** (dirty counter) gate flush:

* Flush when **`jiffies - *(remap+0x150b8) > 0x15180`** **OR** dirty counter **`> 200`**.
* **`ntl_flush_table`** (`0x8028ea6c`) reuses the **same** `ntl_access_pages` window with **write** opcode, then clears counters and stamps `*(remap+0x150b8)` with a global time base.

**Decompiler artifact:** Ghidra may show `ntl_flush_table()` with **no arguments** inside `ntl_stat_flush_if_needed`; the live ABI passes the OpenTL **inner** context in **`$a0`** on MIPS (same as other `ntl_*` methods).

---

## 5. Mount order relative to stats — `ntl_mount` (`0x8028ac28`)

High-level **late** sequence (after BBM phases 1–8, `ntl_init_phase_6`, used-list enqueue, optional `tl_randomize_list`):

1. **TL disk header** path: `ntl_access_pages(..., read first page)` — magic **`0xBA51CDEF`** on the payload (`*hdr != -0x45ae3211` check in decompilation).
2. **`ntl_load_stat_table(inner, local_9a == 1)`** — loads stats from the virtual tail described above (or resets if magic invalid / read fails).
3. Optional **`ntl_log_all`** when debug level ≥ 3.

Earlier phases walk **every physical unit** `0 .. remap[5]-1` with **`ntl_read_phy_spare`** (page **0** spare) to seed freelists / reverse maps — this is **not** the stats payload parse itself, but it is why mount touches **OOB page 0** across the array.

---

## 6. Offline extraction notes

* **Identity virt→phys:** stats tail is the last **`virt_stats_blocks`** erase blocks of the **virtual** 128 KiB TL disk; with identity mapping, that equals the tail of the **`tlpart`** logical data region (see :func:`opentl.stats_block.nand_logical_slice_for_stats_tail`).
* **Remapped media:** assemble **virtual** sector/block image first (same order the kernel’s `ntl_access_pages` iterator uses), **then** slice the tail — `unand` / `nand_translate` only provide **NAND file geometry**; they do not replace BBM.
* **CBLKMAP / `process_map`:** `process_map` (`0x80287234`) is a **bad-block sector bitmap** installer for vendor ioctl paths — orthogonal to the stats triple but part of the same `opentl_ioctl` family (see [`opentl_kernel_ghidra.md`](opentl_kernel_ghidra.md) §3.1).

---

*Last updated: May 2026 (Ghidra MCP live decompile on att-5268 … kernel.elf).*
