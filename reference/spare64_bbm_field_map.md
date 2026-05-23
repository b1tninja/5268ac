# 64-byte OpenTL spare / OOB field map (virt↔phys & chain replay)

This document ties together **`opentl_kernel_ghidra.md`** §6–§7.4, the offline helpers in **`opentl/spare_layout.py`**, **`opentl/spare_chain_replay.py`**, and **`opentl/stats_block.py`** (virtual tail / NAND slice helpers) so you can see **which spare bytes matter** for:

1. **Primary virt→phys** — **`ntl_read_page`**: **`uint32` phys + validity byte** in an **8-byte table per virtual block** (`remap + 0x4c` subtree, see Ghidra doc §5). That path does **not** require decoding every spare row for a clean static map.
2. **Substitute / bad-block chain** — **`ntl_put_chain_in_array`** mode **`2`**: walks **spare on each physical erase unit**, parses **next phys** from spare bytes (**§6**). Offline: **`replay_put_chain_mode2_from_oob`**.
3. **“Which logical page lives on this phys?”** — **`ntl_find_phy`**: reads verified spare, checks **tag markers** on **`spare[4]`**, compares **virt id** and **page-in-block** (**§7.3**). Offline per-row decode: **`opentl/spare_layout.py`** / **`nand-oob-inspect`**; hop replay: **`replay_put_chain_mode2_from_oob`** — not a guessed full-plane virt→phys table.

---

## Ghidra MCP (live decompilation)

**Prerequisite:** In Ghidra CodeBrowser, open the **same** kernel ELF you used for `opentl_kernel_ghidra.md` (e.g. `att-5268-11.5.1.532678_prod_lightspeed-install_uimage_*_kernel_load_*_ep_80458130*.elf` or the exported `.gzf` program) so it is the **current program**.

Then MCP calls such as:

- `search_functions` — `ntl_prepare_wspare`, `ntl_compute_spare_xsum`, `ntl_find_phy`, `ntl_read_verify_phy_spare`, `ntl_put_chain_in_array`
- `decompile_function` — canonical addresses from the markdown (e.g. `ntl_put_chain_in_array` @ **`0x802888f8`**, `ntl_read_page` @ **`0x80289170`**, `ntl_read_verify_phy_spare` @ **`0x80288750`**)

If MCP returns **`No program loaded`**, the HTTP bridge has no active program — open the binary in Ghidra first, or use MCP `open_program` with an **absolute path** to the ELF on disk.

### MCP verification (May 2026)

On **`att-5268-11.5.1.532678…-kernel.elf`**, fresh decompiles of **`ntl_compute_spare_xsum`** (`0x80288560`) and **`ntl_prepare_wspare`** (`0x8028c5d0`) match the byte lanes implemented in **`opentl/spare_layout.py`** (`compute_spare_xsum` / `SpareRecord`): signed **char** sums are commutative across the kernel’s operand order for the partial sum; large-page extensions use **bytes 16–19** for phys/virt high halves as documented in §7.4b.

---

## Large-page (5268) spare byte layout — write vs read

**Context:** **`*(ctx + 0x10) == 0x800`** (2048-byte data page) is the **5268 / BCM large-page** case. **`page_size == 0x200`** in some branches means **512-byte** spare *semantics* for **small-page** devices — do not mix the two when comparing decompiler arms.

### `ntl_prepare_wspare` (program template) — §7.4b

| Offset | Role |
|--------|------|
| **`4`** | Status / class byte written as **`param_7`**; later normalized via **`ntl_map_page_state`**. |
| **`8`** | **`(param_4 & 3) \| (param_8 & 4) \| (param_9 & 8)`** — chain / mirror / flag nibble. **Bit 4** of **`spare[8]`** is the **duplicate / mirror hop** marker used in **`chain_v1`** offline tie-break. |
| **`9`–`10`** | **Physical unit**, **LE16** low. |
| **`11`–`12`** | **Virtual block id**, **LE16** low. |
| **`13` (`0xd`)** | **Page index within erase block**. |
| **`16`–`17`** | **Physical** high bytes (**`char` of `phys >> 16` / `>> 24`**) — extends **`9`–`10`** to 32-bit. |
| **`18`–`19`** | **Virtual** high bytes — extends **`11`–`12`** to 32-bit. |
| **`15` (`0xf`)** | **Stored xsum** — must match **`ntl_compute_spare_xsum`** (§7.4a). |

### `ntl_find_phy` (read / match) — §7.3

- Treats **`spare[4]`** as **`'\0'`** or **`'$'` (`0x24`)** for **tagged** spare suitable for decoding embedded **virt**.
- **Virt id:** **`CONCAT11(spare[0xc], spare[0xb])`** (LE16 from bytes **11–12**); if not small-page 512, **OR** in high bytes from **`0x12`–`0x13`** (see doc — same extension as prepare).
- **Page match:** **`spare[0xd]`** vs requested **page-in-block**.
- **`spare[4] == 0xFF`:** erased-like / fallback path in the decompiler narrative.

### `ntl_compute_spare_xsum` — §7.4a (matches `opentl/spare_layout.py::compute_spare_xsum`)

Signed **int8** wrapping sum:

1. **`partial = i8(spare[9]) + i8(spare[10]) + i8(spare[11]) + i8(spare[12])`**
2. If **large page** (`*(ctx+0x10) != 0x200`): **`partial += i8(spare[16]) + … + i8(spare[19])`**
3. **Return** **`i8(spare[8]) + i8(spare[13]) + i8(spare[14]) + partial`** (masked to byte), compare to **`spare[0xf]`**.

---

## `ntl_put_chain_in_array` mode 2 — **next phys** vs **virt fields**

After **`ntl_read_verify_phy_spare`**, the kernel parses **next physical erase unit** from spare:

- **Small-page (`ctx+0x10 == 0x200`):** **LE16** @ **`9`–`10`**; **`0xffff`** → end.
- **Large-page (5268):** **`LE16(9–10) | (spare[16]<<16) | (spare[17]<<24)`** — note this is **not** identical to **`SpareRecord.phys_u32`** in **`spare_layout.py`**, which uses **`<H` @ 16** for the high half. Offline chain replay uses **`next_phys_from_spare_chain_step`** in **`spare_chain_replay.py`** to mirror **`FUN_802888f8`**.

**Implication:** For **chain hopping**, trust **`spare_chain_replay.next_phys_from_spare_chain_step`**. For **virt decode** in **`SpareRecord`**, trust **`virt_u32` / `phys_u32`** as aligned with **`ntl_prepare_wspare`** *table* layout — but **reconcile** with Ghidra when **`phys_u32`** and chain-step **phys** parsers diverge (documented in **`spare_chain_replay.py`** header).

---

## Offline tooling map

| Kernel concept | Python module |
|----------------|---------------|
| **`ntl_compute_spare_xsum` / `ntl_xsum_read`** | **`opentl/spare_layout.py`** — **`compute_spare_xsum`**, **`xsum_matches`** |
| **`ntl_find_phy` tagged spare + virt** | **`SpareRecord.kernel_tagged_like`**, **`virt_u32`**, **`phys_u32`** in **`opentl/spare_layout.py`**; aggregate counts in **`opentl/spare_inspect.py`** |
| **`ntl_put_chain_in_array` mode 2** | **`opentl/spare_chain_replay.py`** — **`next_phys_from_spare_chain_step`**, **`replay_put_chain_mode2_from_oob`** |
| **Full-plane vs `tlpart.bin` spare slicing** | **`opentl/tlpart_spare.py`** — alignment only; per-row decode unchanged |

---

## What actually fixes **virt→phys** when spare is thin

- **On-flash stats table** (`ntl_load_stat_table` family) — **`opentl/stats_block.py`** + **`tl-mount --dump-stats-candidates`**.
- **8-byte remap table** from **`ntl_read_page`** / RAM dump / `binwalker_tl_bbm_v1` — not the same as “decode every spare”.
- **Spare all-pages inference** fills **virt slots** where **`ntl_find_phy`**-style tags exist; **`chain_v1`** only changes **collision tie-break**, not field definitions.

If spare is mostly **erased (`0xFF`)** or **un-tagged**, spare-driven **virt→phys** stays incomplete — that is a **signal** problem, not a wrong byte-offset table.
