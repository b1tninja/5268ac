# Ghidra RE: PACE `i_block[]` lag — kernel vs offline walker

Programs: **`att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_ld0x80010000_ep0x80458130-kernel.elf`**, **`/usr/lib/libcm_server.so.0.0.0`**.

MCP: `decompile_function`, `search_functions` (May 2026).

Related: [`ghidra_ext2_cm_cmdb_kernel_mcp.md`](ghidra_ext2_cm_cmdb_kernel_mcp.md), [`boardfs/cmdb_extent_walker.py`](../boardfs/cmdb_extent_walker.py).

---

## Bottom line

| Question | Ghidra / dump answer |
|----------|---------------------|
| Does the **kernel** implement “lag” (`first_block - (i_blocks - 24)`)? | **No.** `ext2_get_block` only uses `ext2_block_to_path` + `ext2_get_branch` + `bswap32`. |
| What is **`i_blocks`** in the kernel? | Standard ext2 **512-byte sector** count updated in `ext2_new_blocks` via `inode_add_bytes` / `inode_sub_bytes` on the in-core inode (`param_3 + 0x68` = `i_blocks` field in ext2_inode_info path). |
| What is byte **`0x01` in bits 16–23** of `i_block[n]`? | **Not** set by `__ext2_write_inode` or `ext2_get_block`. Treat as **on-disk / capture encoding**; offline `_ext2_repair_block_ptr` strips it for Dissect. |
| Why does **`i_blocks - 24`** sometimes match header distance? | **Empirical coincidence** on **stale-but-simple** inodes (e.g. `cmlegacy.203`). Fails when `i_blocks` is large or inode tree does not include the header block (e.g. `cmlegacy.498`). |
| Who writes CMDB XML? | **`libcm_server`**: `xmlReadFile` — no ext2 symbols in that `.so`. |

---

## Kernel: no lag, stock ext2 mapping

| Function | EA | Role |
|----------|-----|------|
| `ext2_block_to_path` | `0x8013c9f0` | `file_blk < 12` → direct `i_block[file_blk]`; else indirect slots **12 / 13 / 14**. Uses `s_addr_per_block_bits`. |
| `ext2_get_branch` | `0x8013cb50` | Each level: `__bread(..., bswap32(pointer), ...)`. |
| `ext2_get_block` | `0x8013d5a0` | Orchestrates path + branch; returns physical block for I/O. |
| `__ext2_write_inode` | `0x8013e7f4` | Writes on-disk inode: mode, times, `i_block[0..14]` region as **bswap32 `__le32`**, no `0x01` tag injection. |
| `ext2_new_blocks` | `0x80139420` | Allocates blocks; updates **`inode_add_bytes`** / **`inode_sub_bytes`** (sector accounting). |

**`libcm_server.so`**: `search_functions` for `ext2` → **no matches**. CMDB does not implement a parallel block mapper.

---

## Kernel: `i_blocks` = 512-byte sectors (not 1024-byte fs blocks)

In `ext2_new_blocks` @ `0x80139420`:

- `param_3 + 0x68` is used as **log2(block size)** for shifting allocated block counts.
- After allocation: `inode_add_bytes(inode, ~log2_blksz, blocks_in_fs_blks, ...)`.
- `__mark_inode_dirty(..., 7)`.

So **`i_blocks` on a mounted system counts 512-byte fragments**, as in mainline Linux ext2. A 1024-byte ext2 block allocation typically adds **2** to `i_blocks`.

**Implication for lag formula:** `i_blocks - 24` mixes **sector count** with **“24 = 2×12 direct slots”** (kernel direct count). On PACE captures with **13** on-disk direct slots, the constant may need to be **26** if the formula were ever valid — it still would not explain inode **6835** (lag 760 vs header distance ~338 blocks).

---

## Kernel: `s_inode_size == 0` on opentla4 (PACE product sb)

`ext2_fill_super` @ `0x8013d6c`:

- If superblock feature words at `+0x4c` are **all zero** (PACE dump): **`inode_size = 0x80` (128)**, **`s_first_ino` implied as 11** (`puVar5[0x17] = 0xb`).
- Otherwise reads `s_inode_size` from the superblock (bswap u16 @ `+0x58`).

The **running kernel** uses **128-byte** in-core/disk inode layout for mount. The **PACE NAND slice** often has **256-byte inode records** in the raw image (e.g. `/cm` inode **6833**). That is a **capture/layout** mismatch, not proof the kernel writes 256-byte ext2 inodes.

**`boardfs`**: `_ext2_volume_uses_pace_inode_layout()` is true when `s_inode_size == 0` on disk → enables **PACE on-disk 13-direct** walker, not kernel 12-direct reads.

---

## On-disk `0x01xxxxxx` pointers — **no separate writer** (May 2026 RE)

Observed on opentla4 CMDB paths when `s_inode_size == 0`:

- `i_block[n]` often has **`(raw >> 16) & 0xff == 0x01`**.
- Examples: `cmlegacy.203` `i_block[0] = 0x0001cf9e` → phys **118686**; `cmlegacy.498` `0x0001abf1` → **109553**; `/cm` dir `0x0001b491` → **111953**.

### Verdict: not a tag — LE32 shape for blocks 65536–131071

For any filesystem block number **B** with **65536 ≤ B ≤ 131071**, the little-endian `__le32` value has **byte at offset 2 equal to `0x01`**:

| Block | `__le32` hex | `(raw >> 16) & 0xff` |
|-------|----------------|----------------------|
| 109553 | `0x0001abf1` | `0x01` |
| 118686 | `0x0001cf9e` | `0x01` |
| 111953 | `0x0001b491` | `0x01` |

There is **no** `| 0x01000000` step in **`__ext2_write_inode`** @ `0x8013e7f4` (plain **`bswap32`** copy of in-core `i_block[]`). **`libcm_server.so`** has **no** `ext2` symbols; **`_cmdb_file_save`** @ `0x155c8` builds XML and writes via normal **`fopen`/`fwrite`** on **`dbdir`** (`/rwdata/cm`), so block pointers are allocated by the **mounted kernel ext2** path (`ext2_new_blocks` → `__ext2_write_inode`), not by a second “PACE tag” encoder.

**Implication:** Searching for a **non-kernel writer that sets `0x01` tags** is a dead end. The heuristic in **`_ext2_repair_block_ptr`** / **`_pace_pointer_lag_blocks`** keys off a **bit pattern that is automatic** for this device’s CMDB extent block numbers (opentla4 data starts around block **~10⁵**).

**Still offline-only:** `_ext2_repair_block_ptr` may wrongly trim pointers when `value > last_block` but `(>>16)&0xff==0x01` (low-16 fallback). Kernel path uses **`value <= last_block`** first and keeps the full **`__le32`**.

### What *is* different on the dump (not the `0x01` byte)

These are **not** explained by a `0x01` tag writer:

| Quirk | Likely cause |
|-------|----------------|
| **13-direct** walker vs kernel **12+indirect@12** | Offline **256-byte inode stride** / walker slot math vs kernel **`inode_size=128`** at mount — see [`ghidra_ext2_cm_cmdb_kernel_mcp.md`](ghidra_ext2_cm_cmdb_kernel_mcp.md) § inode size |
| **`ff ac`** indirect header | Unconfirmed in kernel `ext2_get_branch`; treat as **on-disk indirect block content** or dump-specific until a live `debugfs` indirect dump matches |
| **In-band pointer-table pages** | Payload-side metadata in CMDB extents; not written by `__ext2_write_inode` (separate from `i_block[]` tag fiction) |

The offline walker’s **`i_blocks - 2*12`** rule was **fitted** to cases where `decode(i_block[0]) - lag` lands on a `<?xml` header block. It is **not** a kernel-exported invariant.

---

## Empirical lag on S34ML01G1 dump (May 2026)

| File | ino | `i_blocks` | `i_blocks-24` | `decode(i_block[0])` | `<?xml` header block | Formula OK? |
|------|-----|------------|---------------|----------------------|---------------------|-------------|
| `config/cmlegacy.203` | 7323 | 58 | **34** | 118686 | **118652** (34 before) | **Yes** |
| `cm/cmlegacy.498` | 6835 | 784 | **760** | 109553 (blk0 **zeros**) | **109891** (~338 before first direct) | **No** |
| `/cm` dir | 6833 | 2 | **-2** (dir rule) | 111953 | real dir **111955** (`+2`) | **Dir +2**, not file lag |

**`cmlegacy.498`:** Stale inode points at mid-file / zero block; full XML lives at **109891..110334** but is **outside** the inode tree. No constant lag can fix that without **near-extent scan** (implemented in `recover_cmdb_near_inode_extent`).

---

## Alternative explanations for “inconsistent lag” (ranked)

1. **Stale metadata vs orphan payload** (power-loss, journal not on opentla4, `e2fsck` hygiene only) — inode fields describe one extent; newer XML lives elsewhere. Lag works only when both happen to stay in sync (203).
2. **`i_blocks` sector count ≠ “blocks before first direct”** — includes indirect metadata, holes, partial allocation; grows with file size (498: huge `i_blocks`, wrong lag).
3. **Wrong constant (12 vs 13 direct slots)** — formula uses kernel `NDIR=12`; PACE on-disk layout uses **13** direct slots before indirect at index **13**.
4. **Tagged `0x01` pointers are not kernel semantics** — lag rule assumes a relationship between tag, `i_blocks`, and header offset that the kernel never enforces.
5. **256 vs 128 inode stride** — mis-parsing `i_block[]` / `i_blocks` if inode table read with wrong `inode_size`.
6. **NTL/assembly** — ruled out for matched inode-table blocks when chain replay is correct; cannot explain consistent `sys1/` + wrong CMDB inode fields together.
7. **Terminal/display** — ruled out for `-o` output; was a red herring for “binary prefix” once mapping was wrong.

---

## `paceflash` / `boardfs` policy (May 2026)

| Mode | Behavior |
|------|----------|
| Default on opentla4 (`s_inode_size==0`) | `cmdb_extent_walker`: on-disk 13-direct layout; **reject lag** unless `first-lag` block has CMDB header; backward scan ≤128 blocks; else **`recover_cmdb_near_inode_extent`** (±512 blocks around inode anchors). |
| `paceflash cat --cmdb-recover` | Same walker, any volume. |
| Kernel-faithful (non-PACE layout volumes) | `_ext2_read_file_bytes` → `ext2_block_to_path` + `ext2_get_branch` semantics; truncate at `i_size`. |

---

## Who writes opentla4 CMDB metadata? (Ghidra 532678)

| Layer | Component | Role |
|-------|-----------|------|
| File bytes | **`libcm_server`** `_cmdb_file_save` @ `0x155c8` | XML via `_cmdb_stream_write`; temp file + rename under **`dbdir`** |
| Load | **`_cmdb_load`** @ `0x1a15c` | `xmlReadFile` / `opendir` — read-only |
| Block pointers | **Kernel ext2** `ext2_new_blocks` / `__ext2_write_inode` | Normal VFS write on **`/dev/opentla4`** → **`/rwdata/cm`** |
| FS check | **e2fsck** @ boot (Buildroot **1.42.7** per upgrade logs) | Bitmap / orphan hygiene — **does not** rewrite CMDB `i_block[]` to orphan headers on this dump |
| Factory / pkgd | **`lib2sp`** | Stages **`/rwdata/tmp/sys2/`** on UBIFS — **not** opentla4 inode tables; no `ext2` strings |

No Ghidra hit for **`mke2fs`**, **`mkfs.ext`**, or a vendor “PACE ext2 encoder” in **`pkgd`**, **`lib2sp`**, or **`libcm_server`**.

## Suggested follow-up RE

- Live **`debugfs -R 'stat <ino>' /dev/opentla4`** after boot: confirm **`i_block[0]`** `__le32` for inode **7323** is still `0x0001cf9e` (proves “tag” is just block **118686**, not a PACE codec).
- Dump one **indirect** block for inode **7323** (`i_block[12]`) and check for **`ff ac`** at byte 0 vs stock `__le32[]`.
- Compare inode table at **128 vs 256** byte stride on the same exported slice (`tools/_analyze_01_i_block_tag.py`).

---

## See also

- [`ghidra_ext2_cm_cmdb_kernel_mcp.md`](ghidra_ext2_cm_cmdb_kernel_mcp.md)
- [`pace_ext2_cm_directory.md`](pace_ext2_cm_directory.md)
- [`output/cmdb_ondisk_format.md`](../output/cmdb_ondisk_format.md)
- [`boardfs.md`](boardfs.md)
