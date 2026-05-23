# Ghidra MCP verification: block reads vs OpenTL BBM (att-5268 kernel)

Offline **boardfs** / **paceflash** assume `tlpart` bytes match what the kernel’s partition parsers see. This note records **live Ghidra MCP** decompilation on the loaded kernel ELF (same program as `read_dev_sector` @ `0x8020ac20` in prior notes).

## Ghidra MCP (`user-ghidra`) — `ntl_put_chain_in_array` @ `0x802888f8`

**Tool:** `decompile_function` @ **`0x802888f8`** on program **`att-5268-…ghidra_m00_kernel.elf`** (session used for parity work).

**Findings (mode `*piVar10 == 2`):**

- Outer **`do { … } while (uVar5 != 0xffffffff)`** walks **`uVar11`** chain slots from the **8-byte virt table** entry’s **`chain_length`** (byte at **`virt_entry+5`**).
- Each hop: **`ntl_read_verify_phy_spare(param_1, param_2, param_3, uVar5, 0, (int)puVar8)`** — spare read uses **page argument `0`** (first NAND page in the erase unit) while **building** the chain array, matching the note already in [opentl_kernel_ghidra.md](opentl_kernel_ghidra.md) §6 for **`ntl_put_chain_in_array`**. Offline :func:`~opentl.spare_chain_replay.iter_mode2_phys_chain_from_oob` uses the same rule via default ``spare_page=0`` (data pages still use ``page_in_block`` for the 2048-byte slice).
- **`spare[8] & 4`** is copied into the **`ushort`** flags field after each phys (**`*(ushort *)(puVar9 + 1)`** in decompiler output).
- **Small-page** branch (**`*(int *)(param_3 + 0x10) == 0x200`**): next phys from **LE16 @ spare bytes 9–10**; **`0xffff`** widened to **`0xffffffff`** terminator.
- **Large-page** branch: next phys ORs **`(uint)spare[0x11] << 24 | (uint)spare[4] << 16`** onto the low 16 bits (decompiler shows **`CONCAT11(...,9)`** / extended form — same family as :func:`opentl.spare_chain_replay.next_phys_from_spare_chain_step`).
- **Bounds:** compares **`uVar5`** against **`piVar10[5]`** (raw phys ceiling); panic/printk paths on bad spare read (**`ntl_read_verify_phy_spare != 0`**) or chain length mismatch.

**Python:** :func:`opentl.spare_chain_replay.next_phys_from_spare_chain_step`, :func:`~opentl.spare_chain_replay.replay_put_chain_mode2_from_oob`, and :func:`~opentl.spare_chain_replay.iter_mode2_phys_chain_from_oob` live under **`#region kernel: 0x802888f8`** with **`#region kernel_adjacent spare_chain_replay_pages_per_tl_erase`** for the host-only page-count helper.

## `read_dev_sector` → page cache, 512-byte slots

**MCP:** `decompile_function` @ **`0x8020ac20`**

- Calls **`read_cache_page`** with a packed sector index (`param_5 << 0x1d | param_6 >> 3`).
- On success returns a host pointer offset using **4096-byte** page frames and **eight 512-byte slots**: `(param_6 & 7) * 0x200` (see decompiler output for `0x1000` / `0x200` terms).

So **512-byte logical sectors** are delivered through the **cache**, not raw NAND page addresses passed straight into `parse_bsd`.

## `read_cache_page` callers

**MCP:** `get_xrefs_to` @ **`0x8008a310`** (`read_cache_page`)

- Includes **`read_dev_sector`** (`From 8020ac54 in read_dev_sector` — call site within the function body).

Other callers (ext2, nfs, …) are generic VFS paths; partition code is on the `read_dev_sector` branch.

## OpenTL read path: `*(remap+8) + virt×8`

**MCP:** `decompile_function` @ **`0x80289170`** (`ntl_read_page`)

**MCP disassembly (indexing):** at **`0x80289170`**, after loading the device root in **`s2`**, the virt-slot pointer is formed as **`lw s4,0x8(s2)`** → **`sll v0,s1,0x3`** (virt block × 8) → **`addu s4,s4,v0`** → **`lw a1,0x0(s4)`** — i.e. **`*(remap+8) + virt_block×8`**, not a per–2048-byte-page host array.

- `iVar3 = param_3[0x13]` — remap / BBM root (see [opentl_kernel_ghidra.md](opentl_kernel_ghidra.md) §11 naming).
- `puVar5 = (uint *)(*(int *)(iVar3 + 8) + param_4 * 8)` — **virt block** `param_4` indexes an **8-byte** table entry at **`*(remap+8)`**.
- **Unmapped virt table / hole:** `*puVar5 == 0xffffffff` **or** `*(char *)((int)puVar5 + 5) == '\0'` (byte at +5 of the 8-byte unit is the “not yet populated” flag) → **`memset(param_6, 0, param_3[4])`** and return (no NAND read). Same **`memset(..., 0, ...)`** if the spare walk never finds a page that passes **`ntl_verify_read_phy_page`**.
- **Happy path:** **`ntl_put_chain_in_array`** → loop **`ntl_find_phy`** while `local_234 != 0xffffffff` → **`ntl_verify_read_phy_page`** → **`memcpy(param_6, __src, param_3[4])`**.
- **`uVar2` guard:** if `((uint)(param_3[1] - *param_3) <= uVar2) && (uVar2 != 0xffffffff)` the kernel **prints and does not return** (printk path in decompiler); offline we still treat **`0xffffffff`** as hole.

**Offline analogue:** [`opentl.open_tl.extract_virtual_disk_bytes`](D:\electronics\5268ac\opentl\open_tl.py) fills hole bytes with **`0x00`** by default (`hole_fill_byte=0`), matching **`memset(..., 0, ...)`**. Erased **NAND** cells are **`0xFF`** on the wire, but the kernel **page buffer** for unmapped / failed-verify paths is **zeroed**, not filled with raw erase pattern.

So the **data** seen at a virtual erase block is **not** necessarily `logical_plane[virt_block × erase_bytes]` under identity mapping.

### `ntl_read_page`: verify loop and chain exhaustion (MCP `decompile_function` @ `0x80289170`)

The decompiler body (att-5268 kernel ELF, Ghidra MCP) makes the control flow explicit after **`ntl_put_chain_in_array`** returns **0**:

1. Initialize **`iVar4 = 0`**.
2. **`while`** **`ntl_find_phy(..., iVar4, auStack_22c, local_238, &local_234)`** leaves **`local_234 != 0xffffffff`**:
   - Increment **`iVar4`**.
   - **`iVar1 = ntl_verify_read_phy_page(..., local_234, local_230, scratch)`** — NAND **data** read + ECC / meta / checksum gates (see [opentl_kernel_ghidra.md](opentl_kernel_ghidra.md) §7).
   - If **`iVar1 == 0`**: **`memcpy(param_6, scratch, page_size)`** and **`return 0`** (success).
   - Otherwise **continue** the **`while`** — the kernel tries the **next physical candidate** from **`ntl_find_phy`** for the **same** virtual block / logical page (bad-block **chain**), not the next virtual erase index.
3. If the **`while`** exits because **`local_234 == 0xffffffff`** (no more candidates) **without** a successful verify: **`memset(param_6, 0, param_3[4])`** — same **zero-filled page** outcome as an unmapped hole for data observed by the caller.

**Checksum / erased spare / ECC:** failures surface inside **`ntl_verify_read_phy_page`** / **`ntl_read_verify_phy_spare`** on **that** candidate; the outer loop advances **`ntl_find_phy`** instead of returning a half-read page.

**Not “try next virtual block”:** the walk stays on **`param_4`** (one virt block) along **substitute physical erase units**. Advancing **`param_4`** is a different path (e.g. higher-level **`ntl_access_pages`**).

### Kernel vs offline `extract_virtual_disk_bytes`

[`opentl.open_tl.extract_virtual_disk_bytes`](D:/electronics/5268ac/opentl/open_tl.py) uses **one** physical erase index per virtual block from **`BlockMapBuild.virt_to_phys_block[vb]`**, indexes **`logical_prefix[phys * erase + vo]`**, and has **no** `ntl_find_phy` / `ntl_verify_read_phy_page` loop. For **mode-2 spare chain** candidate order plus optional per-page verify, use **`extract_virtual_disk_bytes_chain_aware`** (same module). Hole **`0xffffffff`** still matches kernel **memset** behavior via **`hole_fill_byte`**.

### Offline derived page table (`VirtNandPageTable`)

The kernel does **not** materialize a full **virt NAND page → linear offset** RAM table. Offline, [`opentl.virt_page_table`](D:/electronics/5268ac/opentl/virt_page_table.py) **derives** one from the same primary data as **`*(remap+8)`** erase slots: for each global **2048-byte** virtual page, store the linear prefix byte offset (or a hole sentinel) so [`extract_virtual_disk_bytes_via_page_table`](D:/electronics/5268ac/opentl/virt_page_table.py) can **`memcpy`** / hole-**`memset`** without a per-byte loop. [`LogicalOpenTLSession.extract_virtual_disk_bytes`](D:/electronics/5268ac/opentl/logical_opentl_session.py) and [`virtual_tl_byte_stream_from_logical_plane`](D:/electronics/5268ac/opentl/tlpart_bbm_assembly.py) use the **primary** table by default; it is **not** a second in-kernel struct layout.

**Chain-aware table:** [`build_virt_nand_page_table_chain_aware`](D:/electronics/5268ac/opentl/virt_page_table.py) pre-resolves each virtual NAND page using the same spare **chain** order as [`extract_virtual_disk_bytes_chain_aware`](D:/electronics/5268ac/opentl/open_tl.py) (`ntl_put_chain_in_array` / `ntl_find_phy` analogue). Use when the primary `virt_to_phys_block` index is wrong but flat spare is available; extract still goes through `extract_virtual_disk_bytes_via_page_table`.

**`ValueError: physical offset … out of logical prefix length`** means the map’s implied byte offset is **past the end of the buffer you passed** (wrong NAND translate mode, truncated prefix, or BBM table inconsistent with that prefix). That is **not** the same as a kernel checksum failure on a valid in-range phys: the kernel never indexes “past the chip”; offline code rejects **past `len(logical_prefix)`** before any verify analogue runs.

### Offline parity roadmap (`ntl_find_phy` + `ntl_verify_read_phy_page`)

**Goal:** match kernel **substitute-on-verify-failure** for one **(virt block, logical page)** read: walk **multiple physical erase units** along the bad-block **chain**, run **verify** on each candidate’s **data + spare/ECC**, **`memcpy`** on first success, else **zero-fill** the page (same as exhausted chain in the **`ntl_read_page`: verify loop and chain exhaustion** subsection above).

**Gap vs today:** [`extract_virtual_disk_bytes`](D:/electronics/5268ac/opentl/open_tl.py) and [`virtual_tl_byte_stream_from_logical_plane`](D:/electronics/5268ac/opentl/tlpart_bbm_assembly.py) use **`BlockMapBuild.virt_to_phys_block[vb]`** only (one **primary** phys index per virt block). They do **not** carry **`ntl_put_chain_in_array`** output (phys, flags pairs until **`0xffffffff`**) and do **not** call anything equivalent to **`ntl_find_phy`** or **`ntl_verify_read_phy_page`**.

**Prerequisites (data):**

1. **Chain array per virt block** — same shape the kernel fills before the **`while`**: from spare walk / **`ntl_put_chain_in_array`** (mode **`*(remap)==2`** vs RAM-linked list mode **`!= 2`**, see [opentl_kernel_ghidra.md](opentl_kernel_ghidra.md) §6).
2. **Spare bytes per physical unit** — for **`ntl_read_verify_phy_spare`** / **`ntl_xsum_read`** parity; field map: [spare64_bbm_field_map.md](spare64_bbm_field_map.md).
3. **Optional ECC path** — **`ntl_ecc_read`** / **`opentl_correct_data`**; can ship a first milestone that **skips ECC** (“trust logical NAND bytes”) and only implements **chain order + spare checksum** to match a subset of media.

**Implementation phases (suggested):**

| Phase | Scope | Outcome |
|-------|--------|--------|
| **P0** | Document + types only | Explicit `VirtBlockReadModel` (primary + `list[tuple[int,int]]` chain or opaque blob) distinct from **`BlockMapBuild`** when chains are present. |
| **P1** | Page-grain API | :func:`~opentl.open_tl.extract_virtual_disk_bytes_chain_aware` (flat spare + optional ``verify_page``); unit tests in ``tests/test_open_tl_chain_extract.py``. |
| **P2** | Wire spare verify | Port **`ntl_read_verify_phy_spare`** / **`ntl_xsum_read`** checks from §7; reject candidate, **`ntl_find_phy`**-next. |
| **P3** | ECC + `extract_virtual_disk_bytes` | Replace or flag byte-at-a-time path; align with **`virt_span_nand_page_rows`** / paceflash assembly. |

**Current implementation phase (2026-05):**

- **P1 — shipped:** :func:`opentl.open_tl.extract_virtual_disk_bytes_chain_aware` (flat spare + per-candidate optional ``verify_page``), :class:`opentl.logical_opentl_session.LogicalOpenTLSession` chain-aware OOB + page table; tests in ``tests/test_open_tl_chain_extract.py``.
- **P2 — partial:** Callable **spare xsum** gate (:mod:`opentl.spare_layout` / :mod:`opentl.spare_verify` — ``ntl_compute_spare_xsum`` / ``spare[15]`` with candidate iteration). Full §7.1 skip rules remain roadmap.
- **P3 — shipped for `opentla4` NTL-rw:** :mod:`opentl.ntl_rw` + :mod:`opentl.ntl_ecc` — ``ntl_verify_read_phy_page`` / ``ntl_ecc_read`` on raw NAND bounce (PACE: ``ecc_failures`` telemetry, pages still returned). **Not** wired into default ``extract_virtual_disk_bytes`` BBM path.

**`opentla4` NTL-rw (beyond BBM virt stream):** [`opentl/ntl_rw.py`](../opentl/ntl_rw.py) replays **per-page** mode-2 chains for the rw volume (ptype 17). This is **orthogonal** to ``virtual_tl_byte_stream_from_logical_plane`` (one primary phys per virt erase block). **May 2026:** verify/ECC parity shipped; PACE **`unresolved_vpages=0`**; ext2 mount still blocked on BBM tail — [ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md), [ghidra_ntl_mcp_2026-05-20.md](ghidra_ntl_mcp_2026-05-20.md).

**Primary references:** [opentl_kernel_ghidra.md](opentl_kernel_ghidra.md) §5 (`ntl_read_page`), §6 (`ntl_put_chain_in_array`), §7.1–§7.3 (`ntl_read_verify_phy_spare`, **`ntl_find_phy`**), and MCP **`decompile_function`** @ **`0x80289170`**.

## `ntl_mount`

**MCP:** `decompile_function` @ **`0x8028ac28`** — large init (allocate / initialize / chain load). Use for xref into **`ntl_allocate_memory`**, **`ntl_initialize_memory`**, and BBM table population when extending offline replay.

## Python sources: Ghidra EA region comments

Implementation files that mirror the paths above are annotated with **`#region kernel: 0x…`** / **`#endregion`** (and **`#region kernel_adjacent`** for host-only glue), using the same load addresses as this note and [opentl_kernel_ghidra.md](opentl_kernel_ghidra.md). For **hypothesis**, **debug-only**, or **test-support** blocks (safe to strip when auditing kernel fidelity), see **[kernel_python_regions.md](kernel_python_regions.md)** — *Non-kernel region tags*.

## Offline tooling alignment (2026-05)

- **No JSON-on-disk BBM hooks:** `BlockMapBuild` is built in memory (`parse_block_map_dict` / `from_dict`, or future `NandPipeline.build_bbm` once `opentl.bbm_kernel_replay` replays `ntl_mount`). `paceflash` / `boardfs` use `temporary_registry_from_physical_nand` to capture spare during `nand_translate_to_bytes` and call `attach_open_tl_bbm` when kernel BBM replay succeeds.
- **Current default:** `mount_flash_image` delegates to **`kernel_replay_v1`** in :mod:`opentl.bbm_kernel_replay` (full flat spare required). There is no identity-map fallback in-tree — see **`reference/ntl_mount_virt_table_fill.md`**.
- **Next MCP pass:** extend xrefs from `ntl_mount` (`0x8028ac28`) into BBM RAM table population to drive offline `*(remap+8)` replay.
- **Gap matrix:** callee-level Python-vs-kernel sweep (MCP `get_function_callees` + `#region` inventory) lives in [mcp_kernel_gap_matrix.md](mcp_kernel_gap_matrix.md).

## Implication for **boardfs**

[`boardfs.registry.FsRegistry`](D:\electronics\5268ac\boardfs\registry.py) reads **`FlashImage.read_partition("tlpart")`** on the **flattened logical-plane** image. That matches **`nand_translate`** geometry, **not** the OpenTL **virt→phys** stream above unless **`attach_open_tl_bbm`** supplies kernel-equivalent virtual bytes for TL scan (assembled via `virtual_tl_byte_stream_from_logical_plane`).

See [boardfs.md](boardfs.md) and [opentl_kernel_ghidra.md §11](opentl_kernel_ghidra.md).
