# EAPOL / 802.1X — `lightspeed_p12`, `device_p12`, and WAN authentication

Firmware slice: **11.5.1.532678** (ATT Lightspeed / 5268AC). Evidence: Ghidra **`/usr/bin/lmd`**, **`/usr/lib/librgw_compat.so`**, **`/usr/lib/libboard.so`**, CMDB XML in flash strings, **`att_unified_eapol-certs.pkgstream`**, NAND dump + **`paceflash dump-eapol-cert`**.

Related: [`paceflash.md`](paceflash.md) (offline extract/decrypt), [`linux_8021x_lightspeed.md`](linux_8021x_lightspeed.md) (systemd-networkd + wpa_supplicant), [`libboard.md`](libboard.md) (`board_param_*`), [`board_params_nand.md`](board_params_nand.md) (factory `devkey` / `sn`), [`firmware.md`](firmware.md) (carrier pkg layout), [`httpd_endpoints.md`](httpd_endpoints.md) (`EAPOL_FAILED`).

---

## Summary

| Artifact | Role |
|----------|------|
| **`lightspeed_p12`** | **WAN 802.1X client identity** (EAP-TLS). Default CMDB param **`eap pkcs12` = `lightspeed`**. |
| **`device_p12`** | Second per-unit PKCS#12 blob in the same store; **not** selected for production EAPOL (only **`lightspeed`** in CMDB). Purpose likely provisioning / other TLS consumers (open RE). |
| **`att_unified_eapol-certs.pkgstream`** | **CA trust store only** (`/etc/pki/eapol/*-cacerts.pem` → `cacerts.pem`). Does **not** contain client PKCS#12. |
| **Password** | **`devkey` + fixed salt + `serial`** — same formula in **`board_key_pkcs12_password`** and **`librgw_sec_get_shroud_key`**. |

---

## Where the PKCS#12 blobs live (persistence)

### On-flash / offline

After **`nand_translate`** on **`tlpart`**, the logical byte stream contains **textual** entries (not only structured `paramtool` keys):

```text
lightspeed_p12=MIIRSQIBAzCC...   # base64 PKCS#12 (~5.9 KiB b64 for lab unit)
device_p12=MIISIQIBAzCC...       # separate blob (~6+ KiB b64)
```

Example offsets in one full-chip dump (`flash strings.txt`): **`lightspeed_p12`** @ `0x41F47FE`, **`device_p12`** @ `0x41F2FBE` (paired with `gw:trust_engcert=false` nearby in param region).

These sit in the **board parameter / manufacturing persistence** area of **`tlpart`** (extension **`.board_param`** appears in flash). They are **not** in empty **`opentla1`/`opentla2`** env slices on typical captures.

### In-memory runtime (`libboard`)

**`board_param_open`** reads a file-backed blob, validates length/CRC, and builds an in-RAM **`key=value`** store. **`param_get`** / **`board_param_get`** locate keys by ASCII prefix:

- Lookup key: **`lightspeed_p12`** or **`device_p12`**
- Value: **base64** PKCS#12 bytes (same as offline `name=<b64>` line)

**`paramtool -get`** can read other `gw:*` keys from the same store; the **`_p12`** entries are **not** exposed via `paramtool` strings in corpus — they are consumed by **`tw_ulib_sec_find_pkcs12`**.

---

## How blobs are obtained (provisioning)

| Phase | Mechanism |
|-------|-----------|
| **Manufacturing / ACS** | Per-gateway **client certificate** issued for **MAC + serial** (cert subject in decrypted PEM: **`CN=14:ED:BB:DF:ED:5C`**, **`serialNumber=00D09E-38161N043704`**). Backend writes **`lightspeed_p12=`** / **`device_p12=`** into the **board_param** partition (exact writer not in squashfs — likely **modem prov / CWMP / factory tool**). |
| **Firmware install** | **`att_unified_eapol-certs.pkgstream`** refreshes **trust anchors** only (see below). |
| **Lab / RE** | Recover from NAND: **`paceflash dump-eapol-cert`** → `output/lightspeed.p12`, `output/lightspeed_eapol.pem`, optional `output/device_p12` via **`--cert device`**. |

No **`paramtool -set lightspeed_p12`** usage appears in flash strings; treat flash patching as **high risk** (CRC/layout).

### Offline recovery (documented tooling)

```powershell
pip install -e ".[eapol]"
python -m paceflash dump-eapol-cert "PACE 5268AC S34ML01G1@TSOP48.BIN" `
  -o output/lightspeed_eapol.pem --p12 output/lightspeed.p12
python -m paceflash dump-eapol-cert "PACE …BIN" --cert device --p12 output/device.p12 --no-decrypt
```

Password (Ghidra **`board_key_pkcs12_password`** @ `0x00013edc`, `.rodata` format **`%s%s%s`**):

```text
password = <devkey> + "e289d70ad34e0683fe0152da271475d587fb12f1" + <serial>
```

- **`devkey`**: 16 hex chars from loader factory block (`devkey=…`, see [`board_params_nand.md`](board_params_nand.md)).
- **`serial`**: `sn=` from factory block (e.g. `38161N043704`).

Repo artifacts (lab unit): **`output/lightspeed_p12.b64`**, **`output/device_p12.b64`**, **`output/lightspeed.p12`**, **`output/lightspeed_eapol.pem`**.

---

## What `att_unified_eapol-certs.pkgstream` does (not client cert)

**Role:** `eapol-certs` in CMDB pkg table; **`pkgd`** extracts to **`eapol-certs/att_unified_eapol-certs`**.

| Delivered path | Purpose |
|----------------|---------|
| `/etc/pki/eapol/lightspeed-prod-cacerts.pem` | Production **802.1X CA** bundle |
| `/etc/pki/eapol/lightspeed-test-cacerts.pem` | Lab/test CA bundle |
| Install **script** | Selects prod vs test **`cacerts.pem`** via CMDB pkg lock **`lightspeed-test-802_1X`** vs **`lightspeed-prod-802_1X`** |

Script logic (extracted from pkgstream): sources **`/rwdata/config/lib.sh`**, **`get_lock_version "lightspeed-test-802_1X"`** — if lock active, copy **test** PEM; else copy **production** PEM to **`/etc/pki/eapol/cacerts.pem`**.

**Does not install** `lightspeed_p12` / `device_p12` — those must already be in **board_param** from manufacturing.

---

## 802.1X runtime architecture (`lmd`)

### CMDB / link-manager layout

From CMDB XML blobs in flash:

| CMDB object | `sysname` | Notes |
|-------------|-----------|--------|
| Bridge row | **`pm_bb_bridge`** | **`dsl0`** + **`eth4`** (WAN broadband path) |
| EAPOL module (type **26**) | **`eapol0`** (usrname) | Child of bridge; params include **`eap pkcs12` = `lightspeed`**, **`eap authreqd` = 1**, timers |
| DHCP on WAN | **`pm_bb_eapol`** / **`pm_bb_dhcpc`** | CMDB **`dhcpc clientid` = `00D09E-<serial>`** (see [DHCP client identifier](#dhcp-client-identifier-lmd)) |

Default EAPOL parameters (representative):

| Param | Value | Meaning |
|-------|-------|---------|
| **`eap pkcs12`** | **`lightspeed`** | Selects **`lightspeed_p12`** board_param key |
| **`eap authreqd`** | **`1`** | Authentication required |
| **`eap reauth interval`** | **`300`** | Re-auth period (seconds) |
| **`module bypass`** | **`0`** (prod) | **`1`** = bypass EAP (lab scripts: `modprov -setparam eapol0 "module bypass" 1`) |
| **`eap heldperiod` / `authperiod` / `startperiod`** | 60 / 30 / 30 | EAPOL state machine timers |

Pkg lock **`lightspeed-prod-802_1X`** in CMDB correlates with production CA path above.

### Code path (Ghidra MCP verified — 532678 `/usr/bin/lmd`)

```mermaid
sequenceDiagram
  participant CM as CMDB_modprov
  participant SetCfg as eapol_setcfg
  participant Open as eapol_open_device
  participant Cfg as eapol_config
  participant SM as eapol_sm
  participant EAP as eap_tls_ssl_init
  participant TLS as tls_connection_private_key
  participant P12 as tls_read_pkcs12
  participant ULIB as librgw_compat
  participant BOARD as board_param

  CM->>SetCfg: eap pkcs12=lightspeed
  SetCfg->>Open: parent BB if, PF_PACKET 0x888e
  SetCfg->>Cfg: identity, shroud password, CA path
  Cfg->>SM: eapol_sm_notify_config
  SM->>EAP: EAP-TLS params
  EAP->>TLS: tls_connection_private_key
  TLS->>P12: after PEM file load fails
  P12->>ULIB: tw_ulib_sec_find_pkcs12 lightspeed
  ULIB->>BOARD: lightspeed_p12 base64
  P12->>P12: PKCS12_parse, SSL_CTX_use_cert/key
```

| Step | Function @ VA | Detail |
|------|----------------|--------|
| 1 | **`eapol_setcfg`** `0x00455554` | `lm_pub_get_str(..., "eap pkcs12", ctx+0x3dc, 0x20)` — rodata **`eap pkcs12`** @ `0x0049b318` |
| 2 | **`eapol_open_device`** `0x00453c70` | `lm_get_parent_dev` → `socket(PF_PACKET, …, 0x888e)` + bind; copies HWaddr to ctx+0x20 |
| 3 | **`eapol_config`** `0x00454228` | Default identity `snprintf(..., "%02X:%02X:…", MAC@+0x20)` @ `0x0049b28c`, or **`eap identity`** @ `0x0049b2d8`; **`librgw_sec_get_shroud_key`** → ctx+0x3fc`; **`/etc/pki/eapol/cacerts.pem`** @ `0x0049b2ac` if `stat` ok |
| 4 | **`eap_tls_ssl_init`** `0x00458ff0` | `tls_connection_ca_cert` → `tls_connection_client_cert` → **`tls_connection_private_key`** `0x0045db7c` |
| 5 | **`tls_read_pkcs12`** `0x0045cb60` | Called from **`tls_connection_private_key`** when `SSL_use_PrivateKey_file` fails; **`tw_ulib_sec_find_pkcs12(ctx, pkcs12_name)`** → **`PKCS12_parse`**, install cert/key/extra chain |
| 6 | **`eapol_sm_*`** | wpa_supplicant-derived state machine (`eapol_sm.c` strings) |

**Correction:** **`eapol_config` does not call `tls_read_pkcs12`.** PKCS#12 load happens later during **`eap_tls_ssl_init`** via **`tls_connection_private_key`**.

**EAPOL module context** (per-module block at `*(mod+0x254)`):

| Offset | Field |
|--------|--------|
| `+0x3dc` | PKCS#12 logical name (32 B), e.g. `lightspeed` |
| `+0x3fc` | PKCS#12 password (256 B), from shroud key |
| `+0x6c` | Pointer to CA file path |
| `+0xdc` | EAP identity buffer (256 B) |
| `+0x20`…`+0x25` | WAN MAC bytes for default identity |

**`tw_ulib_sec_find_pkcs12`** (`/usr/lib/librgw_compat.so.0.0.0` @ `0x000c3a1c`): `snprintf("%s_p12", name)` → **`board_param_get`** → base64 decode → **`d2i_PKCS12`**.

**`librgw_sec_get_shroud_key`** @ `0x000bf598`: **`snprintf(buf, "%s%s%s", devkey, salt, serial)`** — same as **`board_key_pkcs12_password`** @ `0x00013edc` in **`libboard`**.

### DHCP client identifier (`lmd`)

CMDB (flash `cmlegacy`): **`dhcpc clientid`** = **`00D09E-38161N043704`** on **`pm_bb_eapol`** and **`pm_bb_dhcpc`**.

| Step | Function @ VA | Detail |
|------|----------------|--------|
| Module config | **`dhcp_setcfg`** `0x0043f2cc` | Registers DHCP client via `lm_cfg_setcfg(..., dhcpc_recfginfo)`; rodata **`dhcpc clientid`** @ `0x004963e6` |
| DISCOVER/REQUEST | **`dhcpc_gen_discover`** `0x00439bb0`, **`dhcpc_gen_request`** `0x004397f4` | If `*(dhcp_ctx+0x1f4) != 0` → **`lm_mdhcp_set_str_clientid`**; else **`lm_mdhcp_set_hwaddr_clientid`** |
| Option 61 encoding | **`lm_mdhcp_set_str_clientid`** `0x0041a93c` | DHCP opt **`0x3d`**: length `strlen+1`, type byte **`0x00`**, ASCII payload (RFC 2132 string client-id) |
| chaddr | same generators | **`lm_mdhcp_set_hwaddr`** on ctx+0x2c — **MAC**, independent of option 61 |
| Vendor class | default | **`board_build_digits`** → **`"2WHPL %d.%d.%d"`** @ `0x004911b4` |

**Packet capture:** option 61 should show type **`0x00`** then ASCII **`00D09E-{factory_sn}`** (not bare serial unless that is the full string). **chaddr** remains the WAN MAC.

Linux mapping: [`linux_8021x_lightspeed.md`](linux_8021x_lightspeed.md) — **`paceflash gen-network-config`** emits EAP-TLS PKI, **`ClientIdentifier=00D09E-{sn}`**, **`MACAddress`**, and modem DHCP extras (vendor class **`2WHPL`**, param list, max message size).

### Trust vs identity

| Store | Content |
|-------|---------|
| **`/etc/pki/eapol/cacerts.pem`** | Operator/trust **CA** certs (from pkgstream) |
| **`board_param` `lightspeed_p12`** | **Client** cert + private key (per device) |
| **`board_param` `device_p12`** | Alternate client bundle (unused by default EAP param) |

---

## `device_p12` vs `lightspeed_p12`

| | **`lightspeed_p12`** | **`device_p12`** |
|--|-------------------|------------------|
| **Board key** | `lightspeed_p12=<b64>` | `device_p12=<b64>` (same `param_get` / `tw_ulib_sec_find_pkcs12` prefix rule: `{name}_p12`) |
| **CMDB `eap pkcs12`** | **`lightspeed`** (default everywhere in corpus) | Never set in corpus |
| **EAPOL (`lmd`)** | `eapol_setcfg` → `lm_pub_get_str(..., "eap pkcs12", buf@+0x3dc, 0x20)` → `tls_read_pkcs12` → `tw_ulib_sec_find_pkcs12(ctx, buf)` | Same code path if param were **`device`**; prod never does |
| **Other runtime** | — | **`libluacpe`**: Lua **`get_net_cert(name)`** (see below) |
| **Flash (lab dump)** | b64 ~5908 B → DER ~4429 B | b64 ~6196 B → DER ~4645 B (larger bundle) |
| **Decrypt password** | **`devkey+salt+serial`** | Identical formula |

Use **`paceflash dump-eapol-cert --cert device`** to extract/decrypt for subject/EE comparison vs **`lightspeed`**.

### `tw_ulib_sec_find_pkcs12` importers (squashfs symbol master)

Only **two** ELFs link this symbol:

| Binary | Role |
|--------|------|
| **`/usr/bin/lmd`** | WAN EAP-TLS: `tls_read_pkcs12` @ `0x0045cb60` → `PKCS12_parse` with shroud password |
| **`/usr/lib/libluacpe.so`** | TR-069 / CPE Lua: export PKCS#12 DER to scripts |

No **`cwmd`**, **`httpd`**, or other daemon imports it. **`ar_clnt_attr_set_pkcs12`** / **`ar_svc_attr_set_pkcs12`** exist in **`libarpc.so`** but have **no** recorded importers in the 532678 squashfs index (RPC TLS hook only stores pointers in a client attr struct @ `+0x34`).

### Lua path: `luacpe_tw_ulib_get_net_cert` (`libluacpe` @ `0x00016d60`)

Registered beside **`luacpe_tw_ulib_ssl_ctx_add_chain`** under **`luacpe_register_rgw_compat`**. Flow:

1. **`luaL_checklstring(L, 1)`** — logical cert name (**`lightspeed`**, **`device`**, …; not the `*_p12` suffix).
2. **`librgw_sec_get_shroud_key`** → password buffer (same **`devkey+salt+serial`** as EAPOL).
3. **`tw_ulib_sec_find_pkcs12(ctx, name)`** → `board_param` lookup **`{name}_p12`**, base64 decode, `d2i_PKCS12`.
4. **`BIO` + `i2d_PKCS12_bio`** → return **raw PKCS#12 DER** to Lua (`lua_pushlstring`).

So **`device_p12` is reachable from provisioning/CWMP Lua** without changing CMDB EAPOL params. No plaintext **`device`** / **`get_net_cert`** strings in **`flash strings.txt`** (name likely passed from ACS mapsets or compiled Lua).

**Not** the same as **`tw_ulib_rgc_get_pkcs12`** (`librgw_compat` @ `0x000bcc80`): that function walks **RGC/SQLite** paths (`cm_tran` + blob column `0x73`) and has **no** squashfs importers — legacy or unused on this image.

### `luacpe_tw_ulib_ssl_ctx_add_chain` (`0x000171fc`)

Lua helper: **`SSL_CTX*`** + table of extra **`X509*`** certs → **`SSL_CTX_ctrl(0xe, …)`** (extra chain certs). Uses **`tw_ulib_pushresult`** for table iteration; does **not** load PKCS#12 by itself.

---

## Operator-visible behavior

| Observation | Mechanism |
|-------------|-----------|
| WAN up after install | EAPOL success → DHCP **`pm_bb_eapol`** |
| **`EAPOL_FAILED`** web status | [`httpd_endpoints.md`](httpd_endpoints.md) → **`/xslt?PAGE=HURL18`** |
| Log: **`eapol0: unable to set default dscp 'CS0'`** | QoS hook failure; distinct from cert failure |
| Lab bypass | **`modprov -setparam eapol0 "module bypass" 1`** |
| Test RADIUS CAs | CMDB mapset lock **`lightspeed-test-802_1X`** → pkgscript copies **test** `cacerts.pem` |

---

## Security notes

- **Per-device binding:** PKCS#12 subject uses **Ethernet MAC** and **00D09E-serial**; password mixes **`devkey`** from factory block — offline NAND dump + factory block ⇒ full client key recovery (see [`paceflash.md`](paceflash.md), [`cmdb_security.md`](cmdb_security.md) class of secrets).
- **SHA-1** in pkgstream file digests for eapol-certs carrier (legacy 2SP).
- **Do not commit** decrypted PEM/P12 or passwords; **`--redact`** on `paceflash` JSON.

---

## Open RE

- Which manufacturing component **writes** `lightspeed_p12=` / `device_p12=` (CWMD? `modprov`? external ACS only).
- Exact **on-disk path** for `board_param_open` (GP-relative table in `libboard` not fully string-resolved).
- **`dhcpc_recfginfo`** ingest: CMDB **`dhcpc clientid`** → dhcp sub-context **`+0x1f4`** (callback registered from **`dhcp_setcfg`**; param loaded via link-manager cfg, not direct `lm_pub_get_str` in the functions decompiled above).
- **Lua/CWMP** call sites that invoke **`get_net_cert("device")`** (bytecode / mapset scripts not in static strings).
- **X.509 purpose diff** after decrypting **`device_p12`** (EE CN/serial/EKU vs lightspeed — same MAC-bound Foxconn-style EE is plausible but unverified here).
- **`tw_ulib_rgc_get_pkcs12`** — whether any dynamic loader uses it on live units.

---

## Quick reference commands

```text
# On device (read-only sanity; syntax may vary)
paramtool -show                    # lists gw:* keys, not necessarily _p12
cmc -c get …                       # CMDB; look for pm_bb_bridge / eapol0 params

# Offline
python -m paceflash factory-params "PACE ….BIN"
python -m paceflash dump-eapol-cert "PACE ….BIN" --cert lightspeed
python -m paceflash gen-network-config "PACE ….BIN" --firmware-version "11.5.1.532678"
# CA auto-resolves from att_unified_eapol-certs.pkgstream when extracted; see linux_8021x_lightspeed.md
python -m lib2spy firmware_…/eapol_certs/att_unified_eapol-certs.pkgstream --extract ./tmp-eapol-ca
```
