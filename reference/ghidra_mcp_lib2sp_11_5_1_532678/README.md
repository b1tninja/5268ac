# Ghidra MCP / HTTP session — `lib2sp.so.0.0.0`, `pkgd`, `libpkg_client` (11.5.1.532678)

**Product:** `att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream` — dissect tree under `M:\old\electronics\5268ac\gateway.c01.sbcglobal.net\firmware\00D09E\11.5.1.532678-PROD\…\squashfs-root\`.

**Method:** ghidra-mcp HTTP `http://127.0.0.1:8089` — `import_file`, `search_strings`, `search_functions`, `get_function_callees`, `decompile_function` (2026-05-20).

**Kernel write chain (separate program):** [`ghidra_nand_layout_write_path_mcp.md`](../ghidra_nand_layout_write_path_mcp.md) — `ntl_write_page` → `opentl_dev_page_write` → `mtd->_write`.

**Older build reference (10.5.3.527064):** [`ghidra_mcp_lib2sp_10_5_3_527064/README.md`](../ghidra_mcp_lib2sp_10_5_3_527064/README.md) — same symbol names, **different** image-relative EAs.

---

## Ghidra `program` paths

| Host file | Ghidra `program` | Image base | Functions |
|-----------|------------------|------------|-----------|
| `…/usr/lib/lib2sp.so.0.0.0` | `/Firmware/532678/lib2sp.so.0.0.0` | `0x00010000` | 329 |
| `…/usr/bin/pkgd` | `/Firmware/532678/pkgd` | `0x00400000` | 966 |
| `…/usr/lib/libpkg_client.so.0.0.0` | `/Firmware/532678/libpkg_client.so.0.0.0` | `0x00010000` | 154 |

---

## `search_strings` — raw NAND bypass + path literals

| Pattern | `lib2sp` | `pkgd` | `libpkg_client` | Notes |
|---------|----------|--------|-----------------|-------|
| `nandwrite` | 0 | 0 | 0 | No userspace MTD dd shortcut |
| `mtd_debug` | 0 | 0 | 0 | Same |
| `ubiupdatevol` | 0 | 0 | 0 | Same |
| `rootimage` | 0 | 0 | 0 | **Expected** — path comes from FILE TLV in `.pkgstream` |
| `/rwdata/tmp/sys2` | 0 | 0 | 0 | **Expected** — runtime `snprintf` + demarshall path slot |
| `write` | 18 | 2 | 0 | `lib2sp_write_file` error strings + PLT |

**Carrier ground truth for `rootimage.img`:** [`output/lib2spy_532678_install_pkgstream.json`](../../output/lib2spy_532678_install_pkgstream.json) — FILE `/rwdata/tmp/sys2/rootimage.img` @ payload offset **43788**, length **26775552** (not rodata in `lib2sp`).

---

## FILE TLV → POSIX `write(2)` (532678 EAs)

### `lib2sp_do_payload_tlv` @ `0x0001e79c`

**Decompilation:** [`lib2sp_do_payload_tlv.c`](lib2sp_do_payload_tlv.c)

**`get_function_callees`:** `demarshall_2sp_file`, `demarshall_2sp_script`, `lib2sp_open_file`, `lib2sp_write_file`, `lib2sp_close_file`, `lib2sp_mkpath`, `memcpy`, …

Types **1 / 3 / 0x2F** demarshall FILE metadata, then stream body slices via **`lib2sp_write_file`**.

### `lib2sp_write_file` @ `0x0001a234`

**Decompilation:** [`lib2sp_write_file.c`](lib2sp_write_file.c)

**`get_function_callees`:** `write` @ `0x00022a80`, `lseek64`, `ftruncate64`, `close`, `unlink`, `lib2sp_check_space`, `snprintf`, …

Inner loop: **`PTR_write_00036888)(fd, buf+off)`** — ordinary VFS write, not `nandwrite` / MTD `ioctl`.

### `lib2sp_open_file` @ `0x00018d70`

**Decompilation:** [`lib2sp_open_file.c`](lib2sp_open_file.c)

**`get_function_callees`:** `snprintf`, `open64` (`0x301` flags), `stat64`, `verify_path`, `lib2sp_check_space` (via callers).

Path built from demarshall scratch + install-root words — matches 527064 pattern.

---

## `pkgd` → `lib2sp` glue

| Symbol | EA | Evidence |
|--------|-----|----------|
| `lib2sp_simple_unpack` | `0x0042d970` | PLT thunk ([`pkgd_lib2sp_simple_unpack.c`](pkgd_lib2sp_simple_unpack.c)) |
| `pkgman_extract_pkg` | `0x0041c7fc` | Calls **`PTR_lib2sp_simple_unpack_004474d0`** ([`pkgd_pkgman_extract_pkg.c`](pkgd_pkgman_extract_pkg.c) ~L65) |
| `pkgman_run_installer` | `0x00420d70` | Calls **`lib2sp_install_data`** PLT |
| `pkg_stream_handler` | `0x00421f78` | Calls **`lib2sp_install_data`** on stream path |

**`get_xrefs_to` @ `0x0042d970`:** `EXTERNAL` + DATA `0x004474d0` only (PIC PLT — use decompile on **`pkgman_extract_pkg`** for caller proof).

---

## Userspace → kernel bridge (hypothesis confirmed)

1. **Carrier** streams FILE bytes (e.g. **`rootimage.img`**) through **`lib2sp_do_payload_tlv` → `write(2)`** into **`/rwdata/tmp/sys2/`** staging.
2. **Deferred promote** (`deferred_upg.sh`) swaps **`sys2` → `sys1`** — still filesystem semantics.
3. **Kernel** (532678 ELF MCP): live **`opentl_writesectors` → `ntl_write_page` → `ntl_write_verify_phy_page` → `opentl_dev_page_write` → `mtd->_write`** programs OpenTL NAND when the rwdata/rootfs volume is written.

Squash correlation on NAND dumps uses **read-side** tooling; **no** `nandwrite`-to-`opentla4` path in the upgrade stack.

---

## Web-upload memory-safety RE (May 2026)

**Doc:** [`reference/pkgstream_memory_re.md`](../pkgstream_memory_re.md)  
**JSON:** [`output/ghidra_web_memory_bugs_532678.json`](../../output/ghidra_web_memory_bugs_532678.json)  
**Fuzz tool:** [`tools/pkgstream_mutate.py`](../../tools/pkgstream_mutate.py)

| Symbol | EA | Export |
|--------|-----|--------|
| `lib2sp_install_data` | `0x00020ae0` | [`lib2sp_install_data_532678.c`](lib2sp_install_data_532678.c) |
| `lib2sp_install_2sp_data` | `0x0001f60c` | [`lib2sp_install_2sp_data_532678.c`](lib2sp_install_2sp_data_532678.c) |
| `lib2sp_check_data` | `0x00020880` | [`lib2sp_check_data_532678.c`](lib2sp_check_data_532678.c) |
| `demarshall_2sp_file` | `0x000149d8` | [`lib2sp_demarshall_2sp_file_532678.c`](lib2sp_demarshall_2sp_file_532678.c) |
| `demarshall_2sp_script` | `0x000154d8` | [`lib2sp_demarshall_2sp_script_532678.c`](lib2sp_demarshall_2sp_script_532678.c) |
| `pkg_stream_handler` | `0x00421f78` | [`pkgd_pkg_stream_handler.c`](pkgd_pkg_stream_handler.c) |

`lib2sp_verify_signature` @ `0x0001c294` — decompiled in Ghidra session; summarized in JSON hypothesis **M9** (ASN.1 / PKCS#7).

---

## Files in this directory

| File | Contents |
|------|----------|
| `lib2sp_do_payload_tlv.c` | FILE/SCRIPT streaming dispatcher |
| `lib2sp_write_file.c` | **`write(2)`** loop |
| `lib2sp_open_file.c` | **`open64`** + path snprintf |
| `lib2sp_install_data_532678.c` | Incremental install / magic / BZ2 |
| `lib2sp_install_2sp_data_532678.c` | State jump table dispatch |
| `lib2sp_check_data_532678.c` | Streaming check helper |
| `lib2sp_demarshall_2sp_file_532678.c` | FILE TLV demarshall bounds |
| `lib2sp_demarshall_2sp_script_532678.c` | SCRIPT TLV demarshall bounds |
| `pkgd_pkgman_extract_pkg.c` | **`lib2sp_simple_unpack`** caller |
| `pkgd_pkgman_run_installer.c` | **`lib2sp_install_data`** installer |
| `pkgd_pkg_stream_handler.c` | Stream handler (large) |
| `pkgd_lib2sp_simple_unpack.c` | PLT stub |
