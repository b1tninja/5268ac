# PACE opentla4 ext2: `/cm` directory and `ls cm`

Firmware: **att-5268-11.5.1.532678**, PACE dump **`PACE 5268AC S34ML01G1@TSOP48.BIN`**, chain-aware NTL assembly → **opentla4** ext2 @ superblock **1024**.

## Path mapping (one filesystem)

| Runtime path | ext2 path on opentla4 (unmounted) |
|--------------|-----------------------------------|
| **`/rwdata/cm`** | **`/cm`** (root dirent, inode **6833**) |
| **`/rwdata/sys1`** | **`/sys1`** |

Initramfs strings (532678 kernel tree / flash strings): **`mount /dev/opentla4 /rwdata`**, **`rwdata_fstype=ext2`**. **`paceflash ls cm`** is the correct offline listing for CMDB **`dbdir`**.

## Kernel (Ghidra) — no special `/cm` handling

**`ext2_readdir` @ `0x8013a0d8`** uses stock **`ext2_dir_entry`** layout: bswap32 inode, bswap16 **`rec_len`**, names at offset **8**. On **`rec_len == 0`** it logs **`zero length directory entry`** (@ **`0x804e3d38`**) and returns **`-EIO`**. There is **no** alternate directory decoder and **no** `/cm` path logic in kernel rodata.

See [`ghidra_ext2_cm_cmdb_kernel_mcp.md`](ghidra_ext2_cm_cmdb_kernel_mcp.md).

## CMDB on-disk format (userspace, Ghidra)

**`_cmdb_load` @ `0x1a15c`** in **`libcm_server.so.0.0.0`**:

- **`opendir(ctx+0x12c)`** — **`dbdir`**
- **`readdir`**: match **`d_name`** to OID prefix; revision = decimal suffix after **`.`** (max ≤ 999)
- **`S_IFREG`**: **`xmlReadFile`** (libxml2), not a custom cipher layer
- **`_cmdb_oplist_*`** journal around the load pass

Filenames on flash look like **`cmlegacy.498`**, **`cmlegacy.203`**, etc. (XML inside). Details: [`output/cmdb_ondisk_format.md`](../output/cmdb_ondisk_format.md).

## `boardfs` ext2 path (May 2026)

**Kernel-aligned parsing** (Ghidra 532678): inode table via GD **`+8`**, **`ext2_dir_entry` v1** when htree is off (walk the full **`rec_len`** chain — **`.`** is not assumed to be at byte 0 of the block), file blocks via **`i_block[0..12]`** data + singly-indirect at **`i_block[13]`** (with **`ff ac`** header → pointer table in the next block), sparse indirect slots expanded like allocation-time contiguous runs.

**Directory block resolution:** when **`i_block[0]`** has no **`.`** → **`dir_inum`**, the parser scans lag-adjusted and **+2** candidates (see **`recover_cmdb_dir_data_block`** / **`_ext2_dir_data_block_for_inode`**) until a valid **`ext2_dir_entry`** chain is found. **`.`** may appear after other dentries in the same block — the walker follows **`rec_len`** from offset 0.

**Assembly:** one **`assemble_opentla4_volume`** NTL replay slice — no per-read NTL fallback.

**Directories on this dump:**

| Path | Inode-table `i_block[0]` | On-disk directory block |
|------|--------------------------|-------------------------|
| **`config`** | **115801** | **115801** (works) |
| **`cm`** | **111953** (empty) | **111955** has **`.` → 6833** — inode table lags by **+2** blocks; reader uses **111955** when **111953** has no ``.`` dentry |
| **`service`** | **94177** (syslog) | no **`.` → 5857** anywhere; children only **`..` → 5857** |

**`paceflash ls cm`** / **`cat cm/cmlegacy.498`**: on opentla4 (**`s_inode_size == 0`**), reads go through **`boardfs.cmdb_extent_walker`** (PACE on-disk inode layout — **not** stock **`ext2_get_block`** slot math). Stale CMDB inodes (e.g. **6835** / **`cmlegacy.498`**) need the **near-extent XML scan** so output starts with **`<?xml`**; see **[`ghidra_ext2_cm_cmdb_kernel_mcp.md`](ghidra_ext2_cm_cmdb_kernel_mcp.md)** (Ghidra: kernel uses **12** direct + indirect at **12**; header at block **109891** is **outside** inode **6835**’s tree). **`paceflash cat --cmdb-recover`** forces the same walker on any volume. **`ls service`** still has no **`.`** → 5857`` dentry on disk (only **`..`** children).

| Block | Content (PACE dump) |
|-------|---------------------|
| **111955** | Valid ext2 dir: **`.`** → 6833, **`cmlegacy.498`** |
| **46417** | High-entropy non-dentry data (wrong pointer from 256-byte inode body / Dissect) |
| **115801** | Valid ext2 dir for **`config`**: **`cmlegacy.203`** |

## Verification

```powershell
python -m pytest tests/test_ext2_dissect.py tests/test_ext2_path.py -q
python -m paceflash --flash "PACE 5268AC S34ML01G1@TSOP48.BIN" ls cm
python -m paceflash --flash "PACE 5268AC S34ML01G1@TSOP48.BIN" ls config
```

## See also

- [`ghidra_ext2_pace_lag_investigation.md`](ghidra_ext2_pace_lag_investigation.md) — why `i_blocks-24` is inconsistent; Ghidra proof kernel has no lag
- [`cm_cmdb.md`](cm_cmdb.md)
- [`firmware_upgrade_process.md`](firmware_upgrade_process.md)
- [`ghidra_ext2_cm_cmdb_kernel_mcp.md`](ghidra_ext2_cm_cmdb_kernel_mcp.md)
