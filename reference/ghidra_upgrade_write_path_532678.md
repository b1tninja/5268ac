# Ghidra / MCP notes — upgrade write path (`libpkg_client`, `lib2sp`, kernel OpenTL writes)

**Product:** AT&T 5268-class carrier **`att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream`** — **`python -m lib2spy`** inventory:[`output/lib2spy_532678_install_pkgstream.json`](../output/lib2spy_532678_install_pkgstream.json).

**Scope:** Connect **`pkgd`/`lib2sp.so`** FILE streaming (`demarshall_2sp_file` → **`lib2sp_do_payload_tlv`** → **`lib2sp_write_file`**) and **`libpkg_client.so`** RPC/FIFO orchestration to the kernel **`opentl_dev_page_write` → `mtd->_write` → `ntl_write_*`** chain documented in [`opentl_kernel_ghidra.md`](opentl_kernel_ghidra.md) §12.4.

---

## 1. Host-ground truth (`lib2spy`, no emulation)

| Path on gateway | TLV | Payload offset (bytes in `.pkgstream`) | Payload length | SHA-1 (`verify.file_payload`) | Role |
|-----------------|-----|----------------------------------------|----------------|-------------------------------|------|
| `/rwdata/config/lib.sh` | FILE `0x01` | 13492 | 28420 | `d8e2a7a6…` | Shell snippet |
| `/rwdata/tmp/sys2/rootimage.img` | FILE `0x01` | **43788** | **26775552** | `7e7a6e81…` | Primary root squash FS blob (**staging**) |
| `/rwdata/tmp/sys2/ui.img` | FILE `0x01` | **26819397** | 1380352 | `af3144da…` | Secondary squash (**staging**) |
| `/rwdata/tmp/sys2/uImage` | FILE `0x01` | **28199806** | 3740549 | `0ea5df11…` | Legacy **`MULTI`** uImage |
| `/rwdata/tmp/sys2/component.txt` | FILE `0x01` | 31940412 | 47 | … | Metadata |
| `/rwdata/tmp/sys2/md5sums.txt` | FILE `0x01` | 31940516 | 178 | … | Deferred integrity |
| `/rwdata/tmp/sys2/deferred_upg.sh` | FILE `0x01` | *(see JSON)* | 1538 | … | Promote/swap script |
| `/rwdata/tmp/sys2/deferred_cleanup.sh` | FILE `0x01` | … | … | … | Failure cleanup |
| `/rwdata/tmp/pkg1/*.pkgstream` | FILE `0x01` | … | … | … | Follow-on carriers |

**Embedded carve correlation (`native_pkgstream.scan_embedded_images`):**

| Span | Offset | Length | SHA-256 (carve file) | Notes |
|------|--------|--------|---------------------|-------|
| squashfs #1 | 43788 | **26771550** | `4331b829…` | Matches **`hsqs` + `bytes_used`** strict span |
| squashfs #2 | 26819397 | 1380332 | `08ead2c5…` | Matches **`ui.img`** FILE length (**−20 B** vs TLV rounding — see JSON `payload_end`) |
| uimage | 28199806 | 3740549 | `0fa735f2…` | Aligns with **`uImage`** FILE |

**Critical nuance — `rootimage.img` FILE vs squash carve:**

- FILE TLV declares **`26775552`** bytes starting at **`43788`**.
- Native squash carve uses **`26771550`** bytes (**−4002 B**).
- **SHA-256** over **`pkgstream[43788 : 43788+L]`** differs:

  | Slice definition | Length | SHA-256 |
  |------------------|--------|---------|
  | Strict carve (`bytes_used`) | 26771550 | `4331b829e2f579cf58bec41a34aa1d6637e617b92abe9f41c1e2e2b47e7e442e` |
  | Full FILE payload | 26775552 | `31e41884a639e8be33d423fcc01daa24a7aed2141c156ef5f2793d8d4cfbcba1` |

Offline **`unsquashfs`/`dissect`** on **`hsqs`** should use the **strict carve span** (or the filesystem FILE boundary excluding garbage trailer depending on tool). **`paceflash --lib2spy-json`** correlates **both** SHA-256 fingerprints against BBM-assembled and linear TL views ([`paceflash/upgrade_correlation.py`](../paceflash/upgrade_correlation.py)); installer verifies **SHA-1 on full FILE length**.

---

## 2. `lib2spy` vs `lib2sp.so`

| Layer | Responsibility |
|-------|----------------|
| **`lib2spy`** (repo) | Prefix TLV dump, PKCS#7 / per-FILE SHA digest verification, carve indexing (`embedded_images`). Does **not** run **`lib2sp_payload_data`**. |
| **`lib2sp.so`** (device) | **`lib2sp_install_data`** / **`lib2sp_simple_unpack`** / **`lib2sp_payload_data`** — filesystem verbs (**mkdir**, **copy**, streaming **`write`**). |

Symbolic runtime vocabulary:[`opentl/pkgstream_format_lib2sp.md`](../opentl/pkgstream_format_lib2sp.md).

---

## 3. Ghidra MCP — **`libpkg_client.so`** / **`lib2sp.so`** / **`pkgd`** / **`httpd`**

**Corpus skill:** [`.cursor/skills/ghidra-mcp-corpus/SKILL.md`](../.cursor/skills/ghidra-mcp-corpus/SKILL.md) — **`list_open_programs`**, firmware-style **`program`** paths (**`/usr/lib/lib2sp.so.0`**, **`/usr/lib/libpkg_client.so.0`**).

**Repo dissect baseline (`lib2sp` only, older build):**[`reference/ghidra_mcp_lib2sp_10_5_3_527064/README.md`](ghidra_mcp_lib2sp_10_5_3_527064/README.md) — **`lib2sp_payload_data` @ ~`0x0001ea2c`**, **`lib2sp_do_payload_tlv` @ ~`0x0001e4ac`**, **`lib2sp_simple_unpack`** thunk from **`pkgd`**.

**Ghidra MCP session (May 2026):** ELFs imported from dissect **`squashfs-root`** — programs **`/Firmware/532678/lib2sp.so.0.0.0`**, **`/Firmware/532678/pkgd`**, **`/Firmware/532678/libpkg_client.so.0.0.0`**. Full callee/decompile transcript: [`ghidra_mcp_lib2sp_11_5_1_532678/README.md`](ghidra_mcp_lib2sp_11_5_1_532678/README.md).

**Completed xref checklist (532678):**

1. **`libpkg_client`**: **`pkg_update`** present (4 string hits); **`/tmp/httpd`** / **`transport error talking to pkgd`** — not re-run against **`httpd`** in this session (see [`firmware_upgrade_process.md`](firmware_upgrade_process.md) §1.1 for **`httpd`** `DT_NEEDED` on reference bundle).
2. **`pkgd`**: **`lib2sp_simple_unpack`** @ **`0x0042d970`** — caller **`pkgman_extract_pkg`** @ **`0x0041c7fc`** invokes PLT **`0x004474d0`**; **`pkg_stream_handler`** / **`pkgman_run_installer`** call **`lib2sp_install_data`**.
3. **`lib2sp.so`**: **`lib2sp_do_payload_tlv`** @ **`0x0001e79c`** → **`lib2sp_open_file`** @ **`0x00018d70`** → **`lib2sp_write_file`** @ **`0x0001a234`** → **`write`** PLT @ **`0x00022a80`**. **No** rodata **`/rwdata/tmp/sys2/rootimage.img`** — path is supplied at runtime from FILE TLV metadata ([`output/lib2spy_532678_install_pkgstream.json`](../output/lib2spy_532678_install_pkgstream.json) §6a).
4. **`search_strings` sweep:** **`mtd_debug`**, **`nandwrite`**, **`ubiupdatevol`** → **0** hits in **`lib2sp`**, **`pkgd`**, **`libpkg_client`** — supports **“squash reaches NAND via normal FS `write(2)` on rwdata, then kernel OpenTL `mtd->_write`, not dd-to-opentla4.”** Kernel side: [`ghidra_nand_layout_write_path_mcp.md`](ghidra_nand_layout_write_path_mcp.md).

---

## 4. Ghidra MCP — **`532678` kernel ELF** (live session, May 2026)

**`list_open_programs`:** only program loaded → **`att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_ld0x80010000_ep0x80458130-kernel.elf`** (`program` path **`/att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_ld0x80010000_ep0x80458130-kernel.elf`**).

**`search_strings` sample:**

| Pattern | Hit count | Example rodata VA | Notes |
|---------|-----------|-------------------|-------|
| `squashfs` | ≥75 | `0x804e91a8` | Kernel **`squashfs_read_data`** etc.; **`Filesystem uses "%s" compression. This is not supported`** @ **`0x804e96e0`** |
| `OPENTL` | 42 | `0x804f7168` | **`OPENTL: add_mtd for %s`**, **`opentl_dev_page_write`** printk **`0x804f75fc`** |
| `ubifs` | 0 | — | Likely stripped printk tokens — inconclusive |
| `rootimage` | 0 | — | Not in kernel rodata; also **0** in **`lib2sp`/`pkgd`** — path from FILE TLV at runtime |

See[`opentl_kernel_ghidra.md`](opentl_kernel_ghidra.md) §12.4 for write-chain prose tying these anchors to **`ntl_write_page`**.

---

## 5. Related docs

- [`firmware_upgrade_process.md`](firmware_upgrade_process.md) — FIFO/`pkgd`/`lib2sp` orchestration + §6a FILE inventory table.
- [`ghidra_httpd_upgrade_chain_evidence.json`](../output/ghidra_httpd_upgrade_chain_evidence.json) — **`httpd`** `DT_NEEDED` (**10.5.3** reference bundle).
