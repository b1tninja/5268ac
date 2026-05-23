# Ghidra: `parse_bsd` disklabel sector layout (att-5268 kernel)

Kernel ELF: `att-5268-11.5.1.532678_prod_lightspeed-install_uimage_*_kernel.elf` (MIPS BE).

Supplements [ghidra_tldisk_partition.md](ghidra_tldisk_partition.md) and [ghidra_tldisk_partition_boundaries.md](ghidra_tldisk_partition_boundaries.md).

## MCP recovery (2026)

- **`create_function` @ `0x8020ec1c`** created **`FUN_8020ec1c`** (body **`0x8020ebdc`–`0x8020f0cf`**, 692 B) — partition walk that was previously orphan code after truncated **`parse_bsd.constprop.1`** (`0x8020eb30`–`0x8020ec1b`).
- **`decompile_function` @ `0x8020ec1c`** shows the kernel-faithful path: **`read_dev_sector`** → validate magic → walk **`d_partitions`**.

## `read_dev_sector` (`0x8020ac20`)

- Returns a pointer into the **page cache**; sector index is a **64-bit** `(high, low)` pair passed as **`param_5` / `param_6`** (see decompiler on **`FUN_8020ec1c`**).
- Effective **512-byte** slot: `(sector_index & 7) * 0x200` within a 4 KiB page frame.

Offline analogue: **`KERNEL_LOGICAL_SECTOR_BYTES = 512`** in [opentl/open_tl.py](../opentl/open_tl.py); assemble via **`extract_virtual_disk_bytes`** / [virt_page_table](../opentl/virt_page_table.py).

## `FUN_8020ec1c` — TL label sector parse

**Calls:** `read_dev_sector(dev, …, carry, sector_hi, sector_lo, &page)`.

**On success:**

| Offset (bytes) | Field | Notes |
|----------------|--------|--------|
| `0x00` | `d_magic` | `*puVar2` byte-swapped must equal **`0x82564557`** (`BSD` magic) |
| `0x8a` | `d_npartitions` | **uint16 big-endian**; capped to **`0x10`** in kernel |
| `0x94 + i×16` | partition *i* | Stride **16** bytes |

**Each 16-byte partition entry** (kernel `printk` order **start / length / ptype**):

| Entry +0 | Entry +4 | Entry +0xc |
|----------|----------|------------|
| `start` u32 **BE** | `length` u32 **BE** | `ptype` u8 (skip if 0) |

`printk` format `* parse_bsd: Partition %x/%x %x/%x` uses **start**, **length**, **ptype** (see decompile: `puVar7[0]` → start, `puVar7[1]` → length).

**Not** the contiguous **`DISKLABEL_CHAIN_PATTERN`** printk substring used by [opentl/tl_physical.py](../opentl/tl_physical.py) offline scanner.

## `parse_bsd.constprop.1` header check (`0x8020eb30`)

- Compares caller buffer to rodata **`"tldisk"`** @ **`0x804ed62c`** (not a NAND grep for chain5/chain4).
- **`FUN_8020f270`** sets stack **`&"tldisk"`** and calls **`parse_bsd`**.

## `tldisk_partition` (`0x8020f220`)

- Prologue + **`printk`** only in a short Ghidra function; cap line in **`FUN_8020f24c`** (`%s: cap: 0x%08X`).
- Handoff to **`parse_bsd`** via **`FUN_8020f270`**.

## Offline mapping

| Kernel | Python |
|--------|--------|
| `read_dev_sector` buffer | `read_virtual_sector(virt_stream, sector_index)` or 512 B slice at sector-aligned offset |
| `FUN_8020ec1c` parse | `parse_bsd_disklabel_sector()` in [opentl/tldisk.py](../opentl/tldisk.py) |
| printk triple chain grep | Legacy anchor only; **not** on-flash layout for Pace-class vendor header captures |

## Pace `PACE 5268AC S34ML01G1@TSOP48.BIN` note

- **`bsd_magic`** + **`opentl` / `tldisk`** strings at linear **`0x3e60800`** (vendor header).
- **`d_npartitions`** at **`0x8a`** is **not** sane on that 512 B view (**1280**); no sector in linear **`tlpart`** passes kernel validation.
- Boot geometry still matches [fwupgrade.txt](../fwupgrade.txt) printk → use **`bsd_printk_constants`** fallback or fix BBM virt read so **`read_dev_sector`**-equivalent bytes match runtime.
