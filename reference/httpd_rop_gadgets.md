# httpd MIPS ROP gadgets (ATT 5268AC)

Image base: **0x00400000** (MIPS32 BE, o32).

## Live unit build (11.5.1.532678) — use this for exploit work

| Artifact | Path |
|----------|------|
| ELF | `M:\old\electronics\5268ac\gateway.c01.sbcglobal.net\firmware\00D09E\11.5.1.532678-PROD\...\squashfs-root\usr\bin\httpd` |
| Full scan | `output/httpd_rop_gadgets_att532678.json` (~11.6k hits) |
| Hotspots | `output/httpd_rop_hotspots_att532678.json` |

```powershell
$H532 = "M:\old\electronics\5268ac\gateway.c01.sbcglobal.net\firmware\00D09E\11.5.1.532678-PROD\_att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream.extracted\squashfs-root\usr\bin\httpd"
python tools/httpd_rop_hotspots.py $H532 -o output/httpd_rop_hotspots_att532678.json
python tools/httpd_rop_diff.py output/httpd_rop_hotspots_att532678.json output/httpd_rop_hotspots_att533857.json
```

## Newer corpus build (11.14.1.533857)

`output/httpd_rop_gadgets_att533857.json`, `output/httpd_rop_hotspots_att533857.json` — gadget EAs differ slightly from 532678; compare with `httpd_rop_diff.py`.

## Global counts (full binary)

| Kind | Approx. count | Exploit notes |
|------|---------------|---------------|
| `jr $ra` | ~hundreds | Function epilogues; stack pivot if you control `$ra` |
| `jalr $ra` | ~70 | Tail-call style |
| `jr $t9` | scattered | PLT / shared-object calls; needs `$t9` = target |
| `addiu $sp, $sp, imm` | many | Large positive `imm` = stack cleanup after big frames |
| `syscall` | many | Need preceding `li $v0, N` in same basic block |
| `lui` / `ori` chains | very many | Build pointers into `.rodata` / GOT |

## Hot functions (Ghidra EAs)

| Label | EA | Role |
|-------|-----|------|
| `http_par_request` | `0x00415158` | Request parser; URI `malloc(len+1)` |
| Parser epilogue cluster | `0x00416154` | Near `hurl_mod_handle_uri` (`0x004163f8`) |
| `rewrite_mod_handle_uri` | `0x0041b2a0` | Long-path rewrite / `snprintf` malloc |
| `soap_in_filter` | `0x0041bccc` | SOAP body `reallocf` |
| `_write_user_rules` | `0x0045040c` | Auth’d FW6 rules; `sprintf` into ~4100 stack |

Within **±0x3000** of each center, `tools/httpd_rop_hotspots.py` lists the nearest `jr $ra`, `jr $t9`, large `addiu $sp`, and `syscall` gadgets (see JSON).

### Example epilogues near `http_par_request` (532678)

| EA | Kind | Δ from `0x415158` |
|----|------|-------------------|
| `0x00415150` | `jr $ra` | −8 |
| `0x00414eb0` | `jr $ra` | −0x2a8 |
| `0x00414db8` | `jr $t9` | −0x3a0 |
| `0x004148b0` | `jr $t9` | −0x8a8 |

533857 build shifts many of these (see `httpd_rop_diff.py`); do not mix builds in one chain.

### `_write_user_rules` region

Large stack frame (`sprintf` lines). Look for `addiu $sp, $sp, 0x1100` class cleanup and nearby `jr $ra` in `output/httpd_rop_hotspots_att533857.json` under `_write_user_rules`.

## Live fuzz signal (URI length)

`AGG-uri-16k` (`GET /` + 16 KiB path) causes **TCP RST** (reproducible). Sweep (`tools/httpd_uri_len_sweep.py`):

| Path length (bytes after `/`) | Result |
|-------------------------------|--------|
| ≤ **10185** | `HTTP/1.1 400 Bad Request` |
| ≥ **10186** (line **10202**) | **Connection reset** |

See **[`httpd_uri_10240_trace.md`](httpd_uri_10240_trace.md)** — **`0x2000`** lite total → **`0x16`** → **400**; **`0xc`** (e.g. URI `malloc`) / sixth mbuf → **RST**. **httpd** stays up after RST (`curl /` → 200). Not a confirmed stack BOV.

## Chunked encoding

`AGG-chunked-no-cl` → **HTTP 500** (no reset). Worth mapping to parser error path; lower priority than URI reset.

## Rewrite fuzz (4 KiB prefix, fixed harness)

`output/httpdfuzz_runs/172_16_0_1_rewrite_fixed.json` on **172.16.0.1**:

| Path prefix | Status | Notes |
|-------------|--------|-------|
| `/setup/` + 4000×`A` | **200** | Hits rewrite / XSLT path |
| `/diag/` + 4000×`A` | 404 | No matching rewrite rule |
| `/upgrade/` + 4000×`A` | **200** | Large response (~6.6 KiB) |

No TCP reset at 4 KiB (well below URI **10240** reset threshold).
