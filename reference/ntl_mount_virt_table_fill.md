# `ntl_mount` and the virt table at `*(remap + 8)`

Offline companion to [`ghidra_boardfs_bbm_readpath.md`](ghidra_boardfs_bbm_readpath.md) and [`opentl_kernel_ghidra.md`](opentl_kernel_ghidra.md) §11.

## Symbol / address reconciliation

| Source | Address | Note |
|--------|---------|------|
| `opentl_kernel_ghidra.md` §11 table | **`ntl_mount` @ `0x8028adac`** | KSEG0, att-5268 kernel ELF / kallsyms-backed listing |
| Legacy `FUN_8028ac28` / `.bin.c` export | **`0x8028ac28`** | Older Ghidra auto-name export line anchor; **not** the same row as the symtab-updated table — always resolve **`ntl_mount`** from the **ELF `.symtab`** when scripting |

In-tree region comments use **`0x8028ac28`** historically; prefer the **symtab** address when setting breakpoints in Ghidra.

## Kernel shape (read path)

- **`ntl_read_page`** @ `0x80289170`: `puVar5 = (uint *)(*(int *)(remap_root + 8) + virt * 8)` — each **virt erase block** indexes an **8-byte** RAM slot (first **uint32** is the physical erase index or **`0xffffffff`** for hole / unmapped).
- Unmapped / failed-verify: **`memset`** page buffer to **0**, not wire erase `0xFF`.

## Mount fill (high level, §11)

1. **`ntl_allocate_memory`** / **`ntl_initialize_memory`**: allocate remap; virt table base at **`*(remap+8)`**; slots initialized to **`0xffffffff`**.
2. **`tl_add_chain`** (multiple sites in **`ntl_mount`**) and related loaders walk **NAND spare** / chains to attach physical units to freelists and record **which phys backs each virt** in that table — **not** a dense scan of `tlpart.bin` main bytes.
3. **`ntl_put_chain_in_array`** (mode 2, etc.) builds **chain arrays** used on the **read** path after the table holds a **head** or link metadata; see [`opentl/spare_chain_replay.py`](../opentl/spare_chain_replay.py).

## Offline `kernel_replay_v1` (Python)

[`opentl/bbm_kernel_replay.py`](../opentl/bbm_kernel_replay.py) implements **`build_block_map_from_kernel_mount_replay`**: a **spare-first** reconstruction that:

- Requires a **full** flat spare blob matching `TLGeometry.raw_blocks × 64 pages × 64 B` spare per page.
- Iterates every **(phys_block, page_in_erase)** spare row; for rows that are **kernel-tagged** (`SpareRecord.kernel_tagged_like`), **xsum-valid**, and carry a **meaningful `virt_u32`**, records **(virt → phys_block)** candidates.
- Resolves **collisions** (same virt, multiple phys) with a deterministic tie-break aligned to [`spare_inspect`](../opentl/spare_inspect.py) commentary: **prefer rows without the spare[8] mirror/duplicate chain bit**, then **lower page index**, then **lower phys_block**.
- Leaves **`0xffffffff`** (`TL_PHYS_BLOCK_HOLE`) for virts with **no** qualifying spare observation.

This is a **documented offline analogue** of “table filled from spare walks” — **not** a byte-for-byte RAM replay of every `ntl_mount` branch until Ghidra maps each `tl_add_chain` write site into Python.

## When to extend `kernel_replay_v1` (tier-3 parity)

Treat **`tl_add_chain` / full `ntl_mount` RAM replay** as **deferred** until a **regression proves** that :func:`opentl.bbm_kernel_replay.build_block_map_from_kernel_mount_replay` (**`kernel_replay_v1`**) disagrees with **observed** on-device virt→phys semantics for the **same** capture (e.g. wrong TL child after `FsRegistry.attach_open_tl_bbm`). Until then, keep spare-walk collision rules documented here and in [`reference/mcp_kernel_gap_matrix.md`](mcp_kernel_gap_matrix.md); use Ghidra MCP on **`ntl_mount`** / **`tl_add_chain`** only when that failure mode appears.

## Future work (Ghidra)

- Map each **write** into `*(remap+8)+virt*8` in **`ntl_mount`** to confirm whether the stored **uint32** is strictly **head phys**, chain metadata, or differs for **stats tail** virts.
- Optionally run **`ntl_verify_chain_seqnum`**-style audits on decoded chain rows where spare provides hop lists.
