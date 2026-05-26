# HTTP authentication vs HURL (Pace 5268AC)

## HURL is not a realm

**HURL** (**`/hurl`**) is a **redirect router**: `hurl_conf.xml` maps broadband/status event names (`PHY_NONE`, `PPP_AUTH_FAILED`, …) to **`/xslt?PAGE=HURLnn`**. It does not define HTTP **Basic/Digest** realms.

Authentication applies on:

- The **main UI** after **`PAGE=login`** (session + **`tw_ulib_pwd_auth`** on CM **`user`** rows).
- **MDC** vhost (**HTTP Basic**, realm **`tech-write`**, backend **`mdc`**).
- **TR-064 SOAP** (**HTTP Digest**, realm **`TR-064`**, users **`dslf-config`** / **`dslf-reset`**).

See **[`httpd_endpoints.md`](httpd_endpoints.md)** §7–9 and **[`httpd.md`](httpd.md)**.

## Where passwords live

| Credential | Factory (loader) | Runtime CMDB | Notes |
|------------|------------------|--------------|--------|
| **Device Access Code** | **`accesscode=`** | **`user` → `adm`** (`password` = `base64:…`, hint references label) | Factory plaintext; CM stores **digest/blob**, not the label string |
| **Auth / system codes** | **`authcode=`**, **`devkey=`** | — | **`board_key_systemcode`**, **`board_key_accesscode`** in **`libboard.so`** ([`libboard.md`](libboard.md)) |
| **Field tech (MDC)** | — | **`user` → `tech`** | Realm **`tech-write`** in **`webs_conf.xml`** |
| **TR-064** | — | Groups **`tr064`** / **`tr069`** → **`dslf-config`**, **`dslf-reset`** | Digest in **`soap_conf.xml`** |
| **Wi‑Fi defaults** | **`wifikey*`**, **`wifissid*`** | May diverge after provisioning | Factory block only |

**Durable CMDB** on device: **`/rwdata/cm`** (UBIFS). Offline on PACE dumps:

1. **ext2 `cm/cmlegacy.*`** — **`paceflash cat --cmdb-recover`** (extent recovery; see [`ghidra_ext2_cm_cmdb_kernel_mcp.md`](ghidra_ext2_cm_cmdb_kernel_mcp.md)).
2. **Embedded `TABLE N="user"`** in assembled **`tlpart`** — rw copies / stale mirrors ( **`paceflash dump-http-auth`** scans these).

Factory **`opentla1`/`opentla2`** param slices are often **empty** on lab captures; prefer **loader** + **CMDB** paths above ([`board_params_nand.md`](board_params_nand.md)).

## CLI

```powershell
python -m paceflash --flash "PACE …BIN" dump-http-auth
python -m paceflash dump-http-auth "PACE …BIN" --json
python -m paceflash dump-http-auth "PACE …BIN" --redact
python -m paceflash dump-http-auth "PACE …BIN" --decode-hashes
```

Outputs: realm map, **`factory_http`** (accesscode, authcode, Wi‑Fi), **`cmdb_ext2`** user rows per path, **`tlpart_user_tables`** if present.

## CM `adm` password algorithm (Ghidra, `librgw_compat.so.0.0.0`)

| Step | Function | Behavior |
|------|----------|----------|
| Set password | **`tw_ulib_pwd_set_passwd`** @ `0xc1454` | Reads CM **column 1** (`user` / username) → salt buffer; **`tw_ulib_pwd_hash(username, plaintext, …)`** |
| Hash | **`tw_ulib_pwd_hash`** @ `0xbf82c` | **`MD5(username ‖ password)`** → 16 bytes → **`nu_b64_ntop`** → stored as **`base64:…`** in column 2 |
| Store | CM **`password`** field | XML **`<S N="user">adm</S>`** + **`<S N="password">base64:…</S>`** |
| Login check | **`tw_ulib_pwd_auth`** @ `0xc03dc` | Reads column **2** only → **`strcmp(typed_password, stored/transformed string)`** (**not** re-hash of typed password) |

**Salt = username:** CM column **1** is the visible **`user`** field (`adm`, `dslf-config`, …) — not a hidden column. Hashcat **mode 20** line format: **`digest_hex:username`** (e.g. `1d2ded32179adb6523b6c4260746caa5:adm`). Full column map: **[`output/tw_ulib_pwd_re.md`](../output/tw_ulib_pwd_re.md)**.

**Pass-the-hash (web UI):** Because verification is **`strcmp`**, the typed password must equal whatever string ends up in the compare buffer after transform — often one of:

- `base64:HS3tMhea22UjtsQmB0bKpQ==`
- `HS3tMhea22UjtsQmB0bKpQ==` (payload only)
- `1d2ded32179adb6523b6c4260746caa5` (hex of digest)

That is **not** the same as knowing the label **accesscode**; factory **`accesscode=`** is plaintext in loader; **`tw_ulib_pwd_hash(known_salt, accesscode)`** did not match this dump without the correct salt.

**Lab tools:**

```powershell
python tools/extract_cm_http_auth_hashes.py --text path/to/dump-http-auth.log
python tools/extract_cm_http_auth_hashes.py --flash "PACE …BIN"
python tools/crack_cm_passwords.py
python tools/verify_cm_password.py --flash "PACE …BIN" --password "4\52@99095" --salt adm
```

Hashcat (outputs in **`crack/`**; use **`-D 2`** for OpenCL GPU on this box):

```powershell
cd D:\tools\hashcat-6.2.6
hashcat.exe -m 0  -a 0 -D 2 D:\electronics\5268ac\crack\cm_user_md5_mode0.txt  D:\electronics\5268ac\crack\cm_password_candidates.txt
hashcat.exe -m 20 -a 0 -D 2 D:\electronics\5268ac\crack\cm_user_md5_mode20.txt D:\electronics\5268ac\crack\cm_password_candidates.txt
```

Mode **0** treats digests as **unsalted MD5** (usually fails). Mode **20** is **`md5($salt.$pass)`** — use **`crack/cm_user_md5_mode20.txt`** (`digest:username`). Regenerate with **`tools/extract_cm_http_auth_hashes.py`** after any dump.

Module: **`paceflash/cmdb_password.py`** (`tw_ulib_pwd_hash`, `verify_password_candidates`).

## Security

Same class as CMDB / factory extracts — **[`cmdb_security.md`](cmdb_security.md)**. Use **`--redact`** before sharing logs.

## See also

- [`paceflash.md`](paceflash.md) — command table
- [`cm_cmdb.md`](cm_cmdb.md) — **`tw_ulib_pwd_*`**
- [`board_params_nand.md`](board_params_nand.md) — factory key=value block
