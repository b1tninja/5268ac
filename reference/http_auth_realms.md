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
| Set password | **`tw_ulib_pwd_set_passwd`** @ `0xc1454` | Reads **salt** from CM user row **column 1** → `auStack_318`; calls **`tw_ulib_pwd_hash(auStack_318, plaintext, …)`** |
| Hash | **`tw_ulib_pwd_hash`** @ `0xbf82c` | **`MD5_Init`**, **`MD5_Update(salt)`**, **`MD5_Update(password)`**, **`MD5_Final`** → 16 bytes → **`nu_b64_ntop`** into buffer |
| Store | CM **`password`** field | XML shows **`base64:HS3tMhea22UjtsQmB0bKpQ==`** (16-byte digest, not plaintext) |
| Login check | **`tw_ulib_pwd_auth`** @ `0xc03dc` | Loads CM password field → transform → **`strcmp(typed_password, transformed_field)`** @ `0xc0914` (**not** `memcmp` on raw MD5) |

**Salt:** CM **column 1** for the user row (not exported in the XML `<S N="password">` line alone). Offline brute must recover that salt string from RE or a fuller CM export.

**Pass-the-hash (web UI):** Because verification is **`strcmp`**, the typed password must equal whatever string ends up in the compare buffer after transform — often one of:

- `base64:HS3tMhea22UjtsQmB0bKpQ==`
- `HS3tMhea22UjtsQmB0bKpQ==` (payload only)
- `1d2ded32179adb6523b6c4260746caa5` (hex of digest)

That is **not** the same as knowing the label **accesscode**; factory **`accesscode=`** is plaintext in loader; **`tw_ulib_pwd_hash(known_salt, accesscode)`** did not match this dump without the correct salt.

**Lab tools:**

```powershell
python tools/verify_cm_password.py --cmdb cmlegacy.203.xml --password "4\52@99095"
python tools/verify_cm_password.py --flash "PACE …BIN" --salt "candidate_salt" --password "guess"
```

Module: **`paceflash/cmdb_password.py`** (`tw_ulib_pwd_hash`, `verify_password_candidates`).

## Security

Same class as CMDB / factory extracts — **[`cmdb_security.md`](cmdb_security.md)**. Use **`--redact`** before sharing logs.

## See also

- [`paceflash.md`](paceflash.md) — command table
- [`cm_cmdb.md`](cm_cmdb.md) — **`tw_ulib_pwd_*`**
- [`board_params_nand.md`](board_params_nand.md) — factory key=value block
