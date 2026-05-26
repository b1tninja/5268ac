# CWMP CPE authentication — 5268AC / Pace (`cwmd`)

How a **legitimate** AT&T 5268AC identifies itself to **`cwmp.c01.sbcglobal.net`** and what you can recover from **NAND CMDB** + **Ghidra** for **lab masquerade** (owned hardware, local ACS stub, or captured WAN only).

Related: [`board_params_nand.md`](board_params_nand.md), [`cmdb_security.md`](cmdb_security.md), [`acspy.md`](acspy.md), [`firmware_upgrade_process.md`](firmware_upgrade_process.md).

---

## Two directions on TR-069

| Direction | Protocol | Credentials |
|-----------|----------|-------------|
| **CPE → ACS** | HTTPS **POST** SOAP **Inform** (and session RPCs) | HTTP userinfo in URL + TLS; SOAP **DeviceId** |
| **ACS → CPE** | HTTP **Connection Request** to **`:3479`** | Digest **`connreq_username`** / **`connreq_passwd`** (CMDB) |

This document is about **outbound Inform** (masquerade as the CPE). Inbound **Connection Request** (ACS → CPE, port 3479, Digest auth) is documented in [`tr069_connection_request.md`](tr069_connection_request.md) with lab tooling **`python -m tr069`**. The older `acspy connreq` subcommand remains unchanged but uses a generic path default.

---

## Ghidra map (`/Firmware/532678/cwmd`)

| Symbol | Address | Role |
|--------|---------|------|
| `soap_msg_inform` | `0x004220c8` | Builds SOAP **DeviceId**, **Event**, **ParameterList** |
| `cwmd_work_start` | `0x00428594` | Orchestrates Inform → HTTP POST |
| `work_url_add_cred` | `0x004261d4` | Embeds ACS HTTP user/pass into URL |
| `periodic_inform_timer_callback` | `0x004280c4` | Periodic Inform timer |
| `board_info_serialnumber` | `0x0043d320` | Serial for **SerialNumber** (factory / board) |
| `board_info_productclass` | `0x0043cb10` | Product class (fallback **`homeportal`**) |

**Imports** (`librgw_compat.so.0.0.0`): `tw_ulib_mgmt_get_acs_url`, `tw_ulib_mgmt_get_acs_username`, `tw_ulib_mgmt_get_acs_passwd`, `tw_ulib_mgmt_get_keycode`, `tw_ulib_mgmt_set_bootstrapped_keycode`, `libkeycode.so.0`.

---

## SOAP **DeviceId** (from `soap_msg_inform`)

| XML field | Source on device |
|-----------|------------------|
| **Manufacturer** | Constant **`2Wire`** |
| **OUI** | Constant **`00D09E`** (Pace/2Wire allocation; matches `connreq_username` prefix) |
| **ProductClass** | `board_info_productclass()` or **`homeportal`** |
| **SerialNumber** | `board_info_serialnumber()` — from **factory NAND** `sn=` (loader MTD), not CMDB — see [`board_params_nand.md`](board_params_nand.md) |

From CMDB **`mgmt.connreq_username`**: `00D09E-38161N043704` → OUI + serial **mirror** of factory `sn=` (CMDB does not replace `board_info_serialnumber` for Inform).

---

## HTTP layer (outbound to ACS)

1. **`soap_msg_inform`** + **`soap_msg_end`** build the XML body.
2. **`work_url_add_cred`** reads **`tw_ulib_mgmt_get_acs_username`** / **`get_acs_passwd`** inside a CM transaction on table **`mgmt`** (CM OID **`4,1,0x31`**, columns **4** and **5**).
3. URL format (format string @ `0x004423e4`): **`%.*s://%s:%s@%.*s`** — credentials in **userinfo** (HTTP Basic over TLS in practice).
4. **`httpc_req_set_method`**: **`POST`**; headers include **`Content-Type: text/xml`**, **`Transfer-Encoding: chunked`**, **`Connection: close`**.
5. TLS: **`httpc_set_cert_verify_callback`** + trusted roots; CMDB **`acs_crl_disable=1`** on this unit.

**CMDB `mgmt` row (flash `cmlegacy.203.xml`)** does not expose separate `acs_username` / `acs_passwd` strings; only **`keycode`**, **`bootstrapped_keycode`**, **`connreq_*`**, **`acs_url`**. Ghidra shows passwd column ties to **keycode** when unset; cwmd uses literal fallbacks **`default`** / **`password`** if getters fail.

**Lab `acspy` default** (until you confirm on-wire capture): HTTP user = full **`connreq_username`**, HTTP password = **`keycode`**. Override with `acspy identity --cmdb …` and tune before posting to production.

---

## Inform **Event** / **CommandKey**

`cwmd_work_start` maps CM / internal flags to event codes, including:

- **`M Reboot`**, **`M ScheduleInform`**, **`M Download`**
- Scheduled Inform **CommandKey** from CMDB: `mgmt.name` = `schedule inform cmdkey`, `mgmt.value` = e.g. **`gpn-c1m6q-ryr325-0`**

Standard TR-069 codes (**`2 PERIODIC`**, **`0 BOOT`**, etc.) may also appear depending on code path; lab **`acspy inform`** defaults to **`2 PERIODIC`**.

---

## **ParameterList** (notify list)

CMDB **`mgmt.notifyparams`** (VTABLE) lists paths the CPE must report on Inform, e.g.:

- `InternetGatewayDevice.ManagementServer.ConnectionRequestURL`
- `InternetGatewayDevice.DeviceInfo.SoftwareVersion`
- `InternetGatewayDevice.DeviceInfo.ProvisioningCode`

Values are filled at runtime from the data model (`mif_find_params` in `soap_msg_inform`). For lab Inform, `acspy` can send placeholder values or values from **`mgmt_upgstate.part1.Name`** (active firmware version).

---

## CMDB fields → masquerade checklist

| Field | Example (this dump) | Use |
|-------|----------------------|-----|
| `acs_url` | `https://cwmp.c01.sbcglobal.net/cwmp/services/CWMP` | POST target |
| `connreq_username` | `00D09E-38161N043704` | DeviceId serial suffix; HTTP user (lab default) |
| `keycode` / `bootstrapped_keycode` | `52HP-2374-2262-22AT-F2BQ` | Bootstrap / HTTP pass (lab default) |
| `connreq_passwd` | `base64:…` | **ACS→CPE** digest only, not Inform |
| `periodic_interval` | `86400` | Inform cadence |
| `notifyparams` | see above | ParameterList names |
| `mgmt_upgstate.part1.Name` | `11.14.1.533857` | **SoftwareVersion** param |

---

## What masquerade does **not** give you

- **Production ACS** only returns **Download** / upgrade URLs when the **fleet backend** has queued an upgrade — not a pkgstream catalog on every Inform.
- **TLS trust**, **revocation**, and **bootstrap** state may reject clones without matching **keycode** history and carrier provisioning.
- **Legal/ToS**: only exercise against **your** lab ACS (`acspy serve-acs`), **your** CPE, or traffic you are authorized to capture.

---

## Tooling

```bash
# Identity from NAND CMDB (no network)
python -m acspy identity --cmdb cmlegacy.203.xml

# Build Inform XML (stdout)
python -m acspy inform --cmdb cmlegacy.203.xml --dry-run

# POST to lab stub (point mgmt.acs_url at serve-acs first)
python -m acspy serve-acs --port 8080
python -m acspy inform --cmdb cmlegacy.203.xml --acs-url http://127.0.0.1:8080/cwmp/services/CWMP
```

Machine-readable Ghidra notes: [`output/ghidra_cwmd_inform_auth.json`](../output/ghidra_cwmd_inform_auth.json).
