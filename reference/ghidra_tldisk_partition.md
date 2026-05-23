# Ghidra: `tldisk_partition` listing (att-5268 kernel)

This supplements **[opentl_kernel_ghidra.md](opentl_kernel_ghidra.md)** for the **block partition helper** that emits `tldisk_partition: going to enumerate` in **[fwupgrade.txt](../fwupgrade.txt)**.

## Symbol and strings

| Item | KSEG0 address |
|------|----------------|
| Function `tldisk_partition` | `0x8020f220` |
| Format `"%s: going to enumerate\n"` | `0x804ed778` |
| Literal subsystem name `tldisk_partition` | `0x804845b0` |
| `printk` | `0x8045f2d0` |

## Decompiler caveat

Ghidra’s decompiler often collapses `tldisk_partition` to a **single** `printk` tail-call. The listing below shows the **real** MIPS prologue and the **delay slot** at `0x8020f248` (not “only printk”).

## Disassembly (function entry → past first `jal printk`)

From Ghidra **Listing** on the loaded **att-5268** kernel (same addresses as `fwupgrade.txt` analysis). Opcodes are stored **big-endian** in the ELF.

| Address | Instruction (Ghidra / MIPS) |
|---------|------------------------------|
| `0x8020f220` | `addiu sp,sp,-0x30` |
| `0x8020f224` | `sw s2,0x28(sp)` |
| `0x8020f228` | `sw s1,0x24(sp)` |
| `0x8020f22c` | `lui s2,0x8048` |
| `0x8020f230` | `move s1,a0` |
| `0x8020f234` | `lui a0,0x804f` |
| `0x8020f238` | `addiu a1,s2,0x45b0` → **a1** = `&"tldisk_partition"` (`0x804845b0`) |
| `0x8020f23c` | `addiu a0,a0,-0x2888` → **a0** = format @ `0x804ed778` |
| `0x8020f240` | `sw ra,0x2c(sp)` |
| `0x8020f244` | `jal printk` → **`0x8045f2d0`** |
| `0x8020f248` | **delay slot:** `sw s0,0x20(sp)` |

So **`0x8020f248`** is **not** the start of a new basic block by itself; it is the **branch delay slot** of the `jal printk` at `0x8020f244`. Ghidra’s “function = one printk” view is **wrong** for control-flow: execution continues after `printk` returns.

## Raw bytes @ `0x8020f248` (128 B, Ghidra `read_memory`)

The following 128-byte window was read from the database at **`0x8020f248`** (hex pairs, big-endian wire order as returned by the MCP bridge):

```
afb000208e2200003c04804f8c42006c264545b08c50004c2484d790020030210c117cb402003821
3c02804f2442d62c022020210000382100003021afb00014afa2001cafa000100c083accafa00018
8fbf002c240200018fb200288fb100248fb0002003e0000827bd003027bdff78afb10064afbf00
84afbe0080afb7007c
```

Use **Listing → disassemble range** from `0x8020f248` in CodeBrowser if you need the full post-`printk` path (register restore, partition loop, calls into `parse_bsd` / disklabel helpers). If Ghidra **splits** the function incorrectly, clear and recreate the function from the listing.

## Relation to `parse_bsd`

`parse_bsd` (e.g. `parse_bsd.constprop.1` @ `0x8020eb30`) owns the **TL vs regular** header printk and the **partition tuple** walk; `tldisk_partition` is the **named** entry point that logs enumeration start. Offline mirror: **`opentl/tldisk.py`** + **`boardfs`**.

### MCP / Ghidra note (2026) — not “pkgstream TLV”, not full `parse_bsd` body

- **`decompile_function` on `tldisk_partition` (`0x8020f220`)** in the current database still collapses to a **single `printk`** tail-call (same caveat as §Decompiler caveat). Treat **Listing / `disassemble_function`** as authoritative for control flow.
- **`disassemble_function` on `parse_bsd.constprop.1` (`0x8020eb30`)** shows a **byte loop comparing** the caller-supplied buffer to a **small constant string** at `0x804f…` (branch at `0x8020eba4`): mismatch → printk **`parse_bsd: regular disk header`** path; match → printk **`parse_bsd: tldisk header`** path, then loads from **`*(a0)`** style structures (`lw … 0x6c`, `0x48`, bounds vs `s7`) before early returns. That is **vendor TL header discrimination + geometry**, not the **lib2spy / `.pkgstream` linear TLV`** format (different subsystem entirely).
- **Offline (2026):** Ghidra MCP recovered **`FUN_8020ec1c`** @ **`0x8020ec1c`** (partition walk via **`read_dev_sector`**). Layout is documented in **[ghidra_parse_bsd_disklabel_layout.md](ghidra_parse_bsd_disklabel_layout.md)** and implemented as **`parse_bsd_disklabel_sector()`** in **`opentl/tldisk.py`** (anchor kind **`bsd_disklabel_sector`**).
- **Legacy heuristic:** contiguous **printk-corroborated** triple substring (`DISKLABEL_CHAIN_PATTERN` in `opentl/tl_physical.py`) is **not** how the kernel stores the label on Pace-class captures; it remains a fallback when a full **512-byte BSD sector** validates.
- **Boundary fix:** still follow **[ghidra_tldisk_partition_boundaries.md](ghidra_tldisk_partition_boundaries.md)** to merge **`tldisk_partition`** / orphan **`0x8020ec1c`–`0x8020f21f`** in CodeBrowser for cleaner decompilation.

### Roadmap: materialized virtual disk + hole map (efficiency)

The kernel builds **virt→phys** (remap table) at **mount** and resolves **512 B sectors** through **`read_dev_sector` → `ntl_read_page`** on demand. Offline tools can instead **materialize once**: `virt_bytes[]` (or a sparse layer) + a **bitset of hole virt erase blocks** from `0xffffffff`, then run disklabel / ext2 probes on the materialized stream. That duplicates **~virt_disk** RAM but removes per-probe **`extract_virtual_disk_bytes`** walks; it does **not** replace spare replay for the **BBM table** itself — it is a **read path** optimization after `BlockMapBuild` exists.
