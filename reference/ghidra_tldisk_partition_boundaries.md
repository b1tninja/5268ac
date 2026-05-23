# Ghidra: fix `tldisk_partition` / `parse_bsd` boundaries (manual)

Kernel ELF: `att-5268-11.5.1.532678_prod_lightspeed-install_uimage_*_kernel.elf` (MIPS BE).

## Problem

- **`tldisk_partition`** @ `0x8020f220` is truncated at **`0x8020f24b`** (prologue + `jal printk` only).
- **`FUN_8020f24c`** @ `0x8020f24c`–`0x8020f26f` is the printk that uses **`s1`/`s2`** from the parent (cap / sector printk).
- **`FUN_8020f270`** @ `0x8020f270`–`0x8020f2b3` sets **`puStack0000001c = &DAT_804ed62c`** and calls **`parse_bsd_constprop_1`** — the real handoff into **`parse_bsd`**.
- **`parse_bsd: label corrupted`** rodata @ `0x804ed678` xrefs **`0x8020f0cc`**, which currently has **no owning function** in the database.

Until these are one continuous function (or clearly linked), the decompiler hides buffer layout and sector math.

## Steps in Ghidra CodeBrowser

1. Go to **`0x8020f220`**. Select from **`tldisk_partition`** entry through the tail of **`FUN_8020f270`** (end just before **`msdos_partition`** @ **`0x8020f2b4`** or wherever disassembly shows the next symbol).
2. **Clear** the three stub functions if needed, then **Create Function** on the merged range, or **Edit Function** → extend end address to include fall-through after printk.
3. Go to **`0x8020f0cc``. **Disassemble** if undefined. **Create Function** containing the **`label corrupted`** printk path, or **extend** **`parse_bsd_constprop_1`** upward/downward so the xref is inside the body.
4. **Re-run decompiler** on the merged **`tldisk_partition`** / **`parse_bsd`** region; export pseudocode for **`read_dev_sector`** callers (`0x8020ac20`) vs **`parse_bsd`** buffer pointer to document **512-byte sector** layout next to OpenTL offline tools.

## MCP re-check

After saving the program, use **`decompile_function`** / **`force_decompile`** on **`0x8020f220`** again to confirm the body is no longer printk-only.

**Automated (2026):** Ghidra MCP **`create_function` @ `0x8020ec1c`** recovered **`FUN_8020ec1c`** (body **`0x8020ebdc`–`0x8020f0cf`**). Decompile shows **`read_dev_sector`** + **`d_partitions`** walk — documented in **[ghidra_parse_bsd_disklabel_layout.md](ghidra_parse_bsd_disklabel_layout.md)** and **`opentl.tldisk.parse_bsd_disklabel_sector`**. Manual merge of **`0x8020f220`–`0x8020f2b3`** into **`tldisk_partition`** is still recommended for a single decompiler function.
