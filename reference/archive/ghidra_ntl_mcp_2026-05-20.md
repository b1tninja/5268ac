# Ghidra MCP session — NTL read path (2026-05-20)

**Program:** `att-5268-11.5.1.532678_prod_lightspeed-install_uimage_*-kernel.elf` (MIPS **BE**).

## Functions decompiled

| Symbol | Address | Notes |
|--------|---------|-------|
| `ntl_read_page` | `0x80289170` | Hole when `virt_entry+5==0` or `*entry==0xffffffff`; else `put_chain` → `find_phy` index loop → `verify` → `memcpy` |
| `ntl_put_chain_in_array` | `0x802888f8` | `chain_length = *(byte*)(virt_table+5)`; mode-2 walks `next` from `*virt_table` phys |
| `ntl_find_phy` | `0x80288bd4` | Page-map when `*(char*)(chain+5)==4` (**BE**: mirror flag in byte @+5); mirror slot requires `spare[0xd]==requested_page` |
| `ntl_prev_phy_location` | `0x80288210` | Mirror flag 4 decrements page; else next chain slot |
| `ntl_verify_read_phy_page` | `0x80288600` | ECC only if `spare[trailer_idx]==0xff`; **printk on xsum/ECC fail then `return 0`** — bounce data still used |
| `ntl_read_verify_phy_spare` | `0x80288750` | Same trailer gate + xsum before spare accept |
| `ntl_ecc_read` | `0x80288388` | Slice0 large-page syndromes `pb[0x16,0x17,2]` / `pb[3,6,7]`; later slices `bounce[page_size+0x12+n*6]` |
| `opentl_correct_data` | `0x80284740` | **`param_4`=calc syndrome, `param_5`=stored** (not page bytes); weight 0/12 gate |

## Python fixes from this session

1. **`opentl_correct_data(page, calc, stored)`** — was incorrectly XORing page bytes with stored syndrome.
2. **BBM anchor** — `virt_to_phys_block[vblk]` before `build_chain_head_cache` spare scan.
3. **`chain_page_map_fast_path`** — document BE byte @+5 mirror gate.

## PACE capture (`S34ML01G1@TSOP48.BIN`)

- `kernel_replay_v1` BBM; **`unresolved_vpages=0`** on 512 KiB smoke and full-slice assembly (holes → zero pages).
- **`ecc_failures` ~56k** on full slice — telemetry only; pages still returned (kernel verify behavior).
- **`s_magic` @ slice `0x438`**: fixed May 2026 — page map + **PACE `spare[0xd]==64`** (`virt_ppage+1` within erase block). **Dissect** on full NTL assembly: **`io.BytesIO(data)`** when SB @ 1024 (not `data[1024:]`), **`s_inode_size==0` → 128**, **`s_first_ino==0` → 11**, and **group-descriptor block pointers** with spurious high bytes masked to 16-bit (`paceflash/ext2_dissect.py`). **`paceflash ls`** lists **`/`** and **`sys1/rootimage.img` (squashfs, ok)** on `S34ML01G1@TSOP48.BIN`.
- Linear `tlpart` **`0x53EF`** hits are **false positives**; **do not** use partition-level **`hsqs`** grep — squash is **`sys1/rootimage.img`** via ext2 file extract after mount.
- See [ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md) §3 for the observation table.

## `unresolved_vpages` semantics (May 2026)

Kernel ``ntl_read_page`` **memset**s on hole virt slots and after exhausted ``find_phy`` / verify — it does not leave pages “unresolved.” Offline now returns **zero pages** for BBM holes, missing heads, and exhausted chain walks (``unresolved_vpages`` stays **0**; use ``ecc_failures`` / ``page_state_histogram`` for quality).

## Open items

- Persist **virt entry byte @+5** (`chain_length`) in `BlockMapBuild` when table source available.
- Re-run `paceflash ls` after BBM tail/chain metadata improves or ECC on real pages validates.
