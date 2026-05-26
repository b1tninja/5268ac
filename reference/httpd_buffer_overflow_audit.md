# `httpd` buffer-overflow / stack-smash triage (ATT 11.5.1.532678)

**Binary:** `/usr/bin/httpd` (MIPS BE)  
**Ghidra:** program `httpd`; helper analysis in `/usr/lib/librgw_compat.so.0.0.0`  
**Scope:** Plain stack/heap buffer overflows reachable from HTTP — not command injection (`popen`), not `pkgd`/`lib2sp` (see [`pkgstream_memory_re.md`](pkgstream_memory_re.md)).

## Executive summary

Static review does **not** show a ready **pre-auth stack BOV → RCE** in `httpd`. Request parsing is mostly **heap-sized with explicit caps** (`malloc` + `strlcpy`, **0x2000** lite-message limit). Legacy **`sprintf`/`strcat`** appear in **authenticated** IPv6 firewall rule handling; user form fields are capped at **`map_copy_str(..., 0x50)`** (~79 chars), which keeps typical `sprintf` output well under the **4100-byte** scratch buffer.

The lead candidate **`tw_ulib_fw6_get_restports` → 264-byte stack buffer** is **not an overflow**: the library clears exactly **`0x108` (264)** bytes and the in-memory layout fits that size for up to **32** reserved-port slots.

**Highest-value follow-up:** black-box fuzzing of **`http_par_request`** (pre-auth) and **`xci_cmd_fw6_set_user_rules`** (post-auth). TR-064 SOAP is **gated off** on LAN vhosts (`soap.enable` ≠ `true`) — deprioritized; see [`httpd_soap_enable_gate.md`](httpd_soap_enable_gate.md).

---

## `tw_ulib_fw6_get_restports` — ruled out as stack BOV

| Item | Detail |
|------|--------|
| **Caller** | `_write_user_rules` @ `0x0045040c` |
| **Call site** | `tw_ulib_fw6_get_restports(param_1, auStack_13ec)` |
| **Stack buffer** | `auStack_13ec[264]` |
| **Implementation** | `librgw_compat.so` @ `0x0006ba88` (export; `httpd` has PIC thunk @ `0x004bf8a0`) |

**Library behavior (decompiled):**

```c
memset(param_2, 0, 0x108);   /* exactly 264 bytes */
/* loop iVar4 = 0 .. 0x1f (32 slots) */
*(uint *)(param_2 + (iVar1 + 2) * 4) = port;           /* ports from offset +8 */
*(int *)(param_2 + (iVar1 + 0x22) * 4) = malloc(...); /* name strings on heap */
strcpy(heap_ptr, acStack_220);  /* acStack_220 filled with snprintf/read cap 0x200 */
*(int *)(param_2 + 4) = count;
```

**Layout bound:** For `iVar1 == 31`, the last `uint32` port sits at offset **`(33*4) = 132`**, the last string pointer at **`(65*4) = 260`** — fits in **264** bytes.

**Consumer:** `is_mrp_forbidden_port` @ `0x0006b730` walks `param_3+8` in steps of 4 while `*(uint *)(param_3+8) != 0`; consistent with the structure above.

**Free:** `tw_ulib_fw6_free_restports(auStack_13ec)` on error paths — heap strings freed, not stack smash.

---

## `_write_user_rules` / `xci_cmd_fw6_set_user_rules` — sprintf cluster (auth)

| Item | Detail |
|------|--------|
| **Handler** | `xci_cmd_fw6_set_user_rules` @ `0x00451d60` |
| **Worker** | `_write_user_rules` @ `0x0045040c` |
| **Dangerous API** | Many `sprintf(auStack_103c, fmt, ...)` then `add_to_err_msg` |
| **Scratch** | `auStack_103c[4100]` |
| **User input** | `map_copy_str(param_3, key, buf, 0x50)` on rule fields; `strncpy(..., 0x50)` on protocol |
| **Error aggregation** | `add_to_err_msg` @ `0x0044f974` — `strcat` into global `err_msg` only if `strlen(err_msg)+strlen(append)+0x1d < 0x1000` |

**Reachability:** Admin session (**`AUTHWEB`** / gateway login). Not WAN-anonymous.

**Residual risk (low):** A format string or code path that passes **unbounded** CMDB/node names into `sprintf` without going through `map_copy_str`. Spot-check showed `strcpy` fallbacks use short constants (`"TCP"`, `"0"`). Fuzz with **max-length** (0x4f) and **over-length** (if any parser bypass) field values per rule index.

---

## `add_to_err_msg` — global cap, not stack BOV

Global **`err_msg[0x1000]`** (NUL at `err_msg[0xfff]` on truncate). Concat guarded; not a classic stack overflow.

---

## Pre-auth HTTP parser — `http_par_request` @ `0x00415158`

| Control | Limit |
|-----------|--------|
| Accumulated request (lite chain) | Reject if **`lite_msgdsize > 0x2000`** → return **`0x16`** → HTTP **400** (`webs_conn_sm` @ `0x00433cd8`) |
| Recv mbuf cells | **`lite_allocb(0x800)`** → **400** at total **10240** B (5 cells, `0x16`); **RST** at **≥10241** B (6th cell / `lite_allocb` fail). Default sweep cliff **N=10186** is header bytes + path, not path alone — see [`httpd_uri_10240_trace.md`](httpd_uri_10240_trace.md) (verified 2026-05-24) |
| URI path (`conn+0xe0`) | **`malloc(len+1)`** in `http_par_request` — no path cap; **`0xc`** on fail → connection teardown (RST), not 400 |
| Header line scratch | `acStack_864[2100]`; copy **`min(len, 0x831)`** |
| Stored header name field | `strlcpy(conn+0x17c, ..., 0x200)` |
| Request-URI / path | `malloc(uStack_868+1)` + `lite_par_copyout` |
| HTTP version token | `malloc` / bounded copy |
| **Host** | `lite_par_copyout` max **`0x61`** → `conn+0xe8`; `strlcpy` max **99** in query-string Host branch |
| Duplicate header merge (case 14) | `malloc(old+new+3)` — heap, not stack |

**Fuzz ideas:** URI just under/over **0x2000** total; header name length **0x1ff vs 0x200**; Host **0x61** boundary; chunked vs Content-Length; duplicate `Cookie`/`Set-Cookie` merge.

---

## Other modules (brief)

| Function | Address | BOV notes |
|----------|---------|-----------|
| `http_par_urlencoded` | `0x00414eb8` | `malloc` + `strlcpy` to `content_len` |
| `rewrite_mod_handle_uri` | `0x0041b2a0` | `snprintf` into `malloc(template+rest+1)` |
| `hurl_mod_handle_uri` | `0x004163f8` | `s_snprintf(..., 0x80)`, `strlcpy(..., 0x62)` |
| `soap_in_filter` | `0x0041bccc` | `reallocf` body; 512-byte stack read chunk |
| `xci_cmd_pkg_write_fifo` | `0x0046e5bc` | `write()` from mbufs — DoS, not stack BOV in `httpd` |
| `xci_cmd_nettools_start` | `0x004612c4` | `snprintf` / `map_insert(strlen+1)` — delegates to **`mifd`** (`popen`) |
| `webs_conn_read` | `0x00432bec` | Copies ≤ caller buffer length |

**Imports:** `strcpy`, `sprintf`, `strcat`, `memcpy`, `sscanf`, `popen` — no `gets`. Most `strcpy` in `_write_user_rules` are **fixed literals** on error paths.

---

## Out of scope for “plain BOV in httpd”

- **TR-064 SOAP / `soap_in_filter`** — URI is registered, but **`soap_mod_handle_request`** returns **404** unless vhost **`soap.enable=true`** (not set on stock **`home0:*`** LAN listeners). Not reachable without lab CMDB/XCI change; not worth fuzzing on production LAN. [`httpd_soap_enable_gate.md`](httpd_soap_enable_gate.md).
- **`popen` in `httpd`** — not traced to a stack smash; net tools → **`mifd`** (command injection class).
- **XSLT / libxml / libxslt** — transform/parser bugs, not `sprintf` on stack.
- **Firmware upload** — `pkgd` / `lib2sp` memory issues ([`pkgstream_memory_re.md`](pkgstream_memory_re.md)).
- **DHCP scripts** — `hostname "$var"` quoted in recovery cpio; not `httpd`.

---

## Fuzz / harness checklist

Machine-readable targets: [`output/httpd_fuzz_targets_att532678.json`](../output/httpd_fuzz_targets_att532678.json).

**Harness:** [`httpdfuzz`](../httpdfuzz/) — `python -m httpdfuzz login --host GATEWAY --flash "PACE….BIN"` (or `--accesscode`), then `python -m httpdfuzz run --cookie-file …`.

**Priority 0 (no cookie):**

1. Raw HTTP — oversized request line, headers, body; total size **0x2001+**.
2. `GET /xslt?PAGE=login&…` — long `PAGE` / query args (parser + `map_insert`).
3. `GET` rewrite prefixes from [`httpd_endpoints.md`](httpd_endpoints.md) with long path suffix.

**Priority 1 (valid `AUTHWEB` session):**

4. POST to IPv6 user-rules XCI (page wiring uses `xci_cmd_fw6_set_user_rules`) — fields `*_src`, `*_dst`, `*_protocol`, ports; **0x50** boundary and **multi-row** `strtok` lists.
5. `xci_cmd_fw_set_params` / pinholes — same `map_copy_str` pattern family.

**Priority 2 (deprioritized — SOAP gated):** TR-064 / `soap_in_filter` — **404 on LAN** (`soap.enable` gate). Cases remain in `httpdfuzz` for regression if you enable SOAP in lab; otherwise skip with `--max-priority 1`.

---

## Ghidra cross-reference table

| Symbol | `httpd` EA | `librgw_compat` EA |
|--------|------------|---------------------|
| `http_par_request` | `0x00415158` | — |
| `_write_user_rules` | `0x0045040c` | — |
| `xci_cmd_fw6_set_user_rules` | `0x00451d60` | — |
| `add_to_err_msg` | `0x0044f974` | — |
| `tw_ulib_fw6_get_restports` | thunk `0x004bf8a0` | `0x0006ba88` |
| `is_mrp_forbidden_port` | import | `0x0006b730` |
| `soap_in_filter` | `0x0041bccc` | — |

---

## Related docs

- [`httpd_endpoints.md`](httpd_endpoints.md) — URLs and `PAGE=` inventory  
- [`security.md`](security.md) — web attack-surface overview  
- [`c5_4_ip_utilities_security.md`](c5_4_ip_utilities_security.md) — `popen`/hostname (injection, not BOV)  
- [`pkgstream_memory_re.md`](pkgstream_memory_re.md) — upload path memory bugs  
