# Ghidra MCP / HTTP session — `lib2sp.so.0.0.0` (10.5.3.527064 carrier)

## How this was produced

- **Ghidra MCP** (`list_instances`) reported no UDS instances on this host; the plugin on **`http://127.0.0.1:8089`** was still reachable with **`Invoke-WebRequest`** / `curl`.
- **`POST /import_file`** imported  
  `M:\old\electronics\5268ac\gateway.c01.sbcglobal.net\firmware\00D09E\10.5.3.527064-PROD\_5268.install.pkgstream.extracted\squashfs-root\usr\lib\lib2sp.so.0.0.0`  
  as program path **`/Firmware/lib2sp/lib2sp.so.0.0.0`** (initially with `auto_analyze: false`).
- **`POST /reanalyze?program=...`** was required before **`get_function_callees`** / non-zero function bodies worked (PIC thunks cleared up).
- **`GET /decompile_function?address=<symbol>&program=<URL-encoded path>`** returns **plain C text** (not JSON).

Addresses below are **image-relative** (Ghidra listing). They **differ** from the 11.5.1.532678 offsets in [`reference/pkgstream.md`](../../reference/pkgstream.md) §2 — same symbols, different build.

## TLV runtime (not carving)

### `lib2sp_payload_data` — central TLV dispatcher

**Symbol:** `lib2sp_payload_data` @ **`0x0001ea2c`**  
**Decompilation:** [`lib2sp_payload_data.c`](lib2sp_payload_data.c)

This function is the **payload-phase state machine**: it reads the current TLV **type** from `param_1[0x13f]` (32-bit), then:

| Wire type (hex) | Handling in decomp |
|-----------------|-------------------|
| **`0x01` / `0x03`** | `demarshall_2sp_file` → `uVar2 = local_c0[0]` (parsed FILE header word 0) |
| **`0x26`** | `demarshall_2sp_script` → uses `local_1a4` / `local_194` flags |
| **`0x07`** | **`demarshall_2sp_path`** (explicit `uVar1 == 7` → `LAB_0001ebb8`) |
| **`0x08`** | **`demarshall_2sp_move`** (`uVar1 == 8` → `LAB_0001ebf4`) |
| **`0x27`–`0x28`** | Outer `uVar1 < 0x27` guard fails, so execution hits **`demarshall_2sp_path`** via the shared **`LAB_0001ebb8`** label |
| **`0x04`** (PATH in 010 template) | Does **not** hit the `1/3` FILE fast-path; `uVar2` stays **`0`** and execution reaches the **indirect per-type jump table** at the bottom (`uVar1 < 0x30`) |
| **`0x29`–`0x2b`** | **`demarshall_2sp_move`** for the `0x2b < uVar1` / `0x29 < uVar1` ladder |
| **`0x2f`** | **`demarshall_2sp_file`** (shared label with 1/3) |

After a successful demarshall, if `*param_1 == 3` and a parity flag `(uVar2 & 1) == 0`, execution hits an **indirect jump**:

```c
(*(code *)(&_gp_1 + *(int *)(PTR_LAB_00034444 + uVar1 * 4 + 0x3f80)))();
```

So **per-TLV-type behavior beyond parsing** is a **function pointer table** indexed by **`uVar1` (TLV type)** — this is where **`lib2sp_do_mkdir`**, **`lib2sp_do_sym_link`**, **`lib2sp_do_copy_file`**, **`lib2sp_do_payload_tlv`**, etc. are invoked (see callees list below). That is the **runtime “use”** of TLVs: demarshall → **vtable-style dispatch** → filesystem side effects / staged script buffers.

### `lib2sp_do_payload_tlv` — streaming chunk writer for FILE / SCRIPT bodies

**Symbol:** `lib2sp_do_payload_tlv` @ **`0x0001e4ac`**  
**Decompilation:** [`lib2sp_do_payload_tlv.c`](lib2sp_do_payload_tlv.c)  
**Callees (post-analysis):** `demarshall_2sp_file`, `demarshall_2sp_script`, `lib2sp_open_file`, `lib2sp_write_file`, `lib2sp_close_file`, `lib2sp_open_script`, `lib2sp_write_script`, `lib2sp_close_script`, `lib2sp_mkpath`, `memcpy`, `__assert`, `lib2sp_set_error`.

Control flow summary:

1. **`uVar1 = *param_2`** — TLV **type** word.
2. Types **`1`**, **`3`**, **`0x2f`** → **`demarshall_2sp_file`** into stack scratch `auStack_10b0`, optional **`lib2sp_mkpath`**, track cumulative **file** byte window (`param_1+0x4f0` … `0x50c`).
3. Type **`0x26`** → **`demarshall_2sp_script`** into the same scratch layout for **script** staging (`puStack_10b8` / `puStack_10b4` pointers).
4. Other types → **`lib2sp_set_error(..., 0xb, …)`** (unsupported TLV in this path).
5. **`memcpy`** pulls the next slice from the incoming byte stream **`param_4`** into the context buffer (`param_1+0x4d8` base + sliding offset).
6. When the staged object is complete, it calls **`lib2sp_open_*` / `lib2sp_write_*` / `lib2sp_close_*`** — that is the **extract-to-disk / extract-to-RAM** path for FILE vs SCRIPT payloads (not a simple “carve to host file”).

### Demarshallers (metadata → pointers)

- **`demarshall_2sp_file`** @ `0x00012758` — [`demarshall_2sp_file.c`](demarshall_2sp_file.c): copies **0x24** bytes of header, optional **BE `u64` size/offset** when gate ≥ 100 and buffer large enough, validates path/digest slices, returns pointer past TLV.
- **`demarshall_2sp_script`** @ `0x0001362c` — [`demarshall_2sp_script.c`](demarshall_2sp_script.c): analogous layout for script records.

### Script staging (`lib2sp_write_script` / `lib2sp_close_script`)

- **`lib2sp_write_script`** — [`lib2sp_write_script.c`](lib2sp_write_script.c): **`realloc` + `memcpy`** — grows a **heap buffer** for the staged script body (streamed like FILE bytes).
- **`lib2sp_close_script`** — [`lib2sp_close_script.c`](lib2sp_close_script.c): finalizes buffer (adds **`\\n\\0`** trailer when non-empty), builds **`snprintf`** paths, then calls an indirect helper (`PTR_00034448 + 0x50b4`) with **`(ctx, buffer, length)`** — almost certainly **fork/exec or script runner** (rename symbols in Ghidra to confirm). Also queues a small struct onto **`param_1 + 0x5c4`** (work list for the runner).

### `pkgd` / `pkgc`

`GET /search_functions?name_pattern=lib2sp_simple_unpack&program=/usr/bin/pkgd` → **`0x0042d970`** (PLT thunk to **`lib2sp.so`**).  
Full **`pkgd`** decompilation of that thunk failed pre-reanalysis (`EXTERNAL` address space error). A **`POST /reanalyze?program=/usr/bin/pkgd`** was started but is **slow** on this 968-function binary; re-run locally when you need **`pkg_stream_handler`** ↔ **`lib2sp_simple_unpack`** glue in **`pkgd`**.

## Files in this directory

| File | Contents |
|------|----------|
| `lib2sp_payload_data.c` | **Main TLV type switch + jump table** |
| `lib2sp_do_payload_tlv.c` | FILE/SCRIPT **streaming write** path |
| `demarshall_2sp_file.c` / `demarshall_2sp_script.c` | Wire → struct |
| `lib2sp_open_file.c` / `lib2sp_write_file.c` / `lib2sp_close_file.c` | FILE install |
| `lib2sp_open_script.c` / `lib2sp_write_script.c` / `lib2sp_close_script.c` | SCRIPT staging / close |
| `lib2sp_install_data.c` | Outer state machine (**bzip2**, header, sub-states) |
| `lib2sp_internal_check_data.c` | Integrity pass |
| `lib2sp_iter_next.c` | TLV iterator |
| `pkgd_lib2sp_simple_unpack.c` | Stub only (use **`pkgd`** after reanalyze) |

## Next steps (optional)

1. Finish **`pkgd`** auto-analysis; **`decompile_function`** on **`lib2sp_simple_unpack`** @ **`0x0042d970`** and **`FUN_*`** callers that pass **`/tmp/pkgspool`** / paths from [`reference/pkgstream_security.md`](../../reference/pkgstream_security.md).
2. In Ghidra, **rename** the indirect target at **`PTR_00034448 + 0x50b4`** once identified (likely `system`, `popen`, or a `tw_*` wrapper).
3. Dump the **jump table** at **`PTR_LAB_00034444 + 0x3f80`** (indexed by TLV type) to list **every** opcode → handler mapping beyond FILE/SCRIPT/PATH/MOVE.
