# `soap.enable` vhost gate (TR-064 / `soap_mod_handle_request`)

Firmware: **11.5.1.532678**, `/usr/bin/httpd` (MIPS BE). Complements [`httpd_endpoints.md`](httpd_endpoints.md) and [`httpd_buffer_overflow_audit.md`](httpd_buffer_overflow_audit.md).

## Why SOAP fuzzing sees HTTP 404

`/soap/tr064` **is** registered in `mod_uri_table` @ `0x004d57d0` → SOAP module @ `0x004e4c60` → `soap_mod_handle_request` @ `0x0041c704`. A **404 (`0x194`)** is returned **inside** that handler when the vhost does not expose TR-064.

### Gate (first check in `soap_mod_handle_request`)

```text
val = webs_vhost_get_config(vhost, "soap.enable", …);
if (val == NULL || strcmp(val, "true") != 0)
    → HTTP 404
```

| String | VA |
|--------|-----|
| `soap.enable` | `0x004c3150` |
| `true` | `0x004c22d0` |

Later gates (only if `soap.enable=true`): **POST** only (else 405), **`mif_connect`** (else 500 + `"soapmod: failed to connect ot mif"`), **`SOAPAction`** must match an action loaded from **`/ui/conf/soap_conf.xml`**.

`soap_in_filter` / `reallocf` run only after all of the above.

## Boot / config sources

| Layer | Mechanism | Notes |
|-------|-----------|--------|
| Global defaults | `soap_mod_init` → tail-call **`webs_config_insert`** (`0x0042e788`) with **`soap_config`** @ `0x004e4ce0` | One template row: key `soap.enable` (metadata); not the same as per-vhost `true` |
| Static vhosts | **`/mnt/web/conf/webs_conf.xml`** (ro string @ `0x004c5b0e`) | Parsed at startup into per-vhost multimaps (`vhost.enable`, `hurl.uri`, …). **`soap.enable` does not appear** in install squashfs blobs searched locally — expect it **absent** unless runtime adds it |
| Runtime set | **`xci_cmd_webs_configvhost`** @ `0x004a6e5c` | Args: **`VHOSTNAME`**, repeated **`NAME`** / **`VALUE`** → `webs_vhost_set_config` |
| Runtime read | **`xci_cmd_webs_getvhost`** @ `0x004a7284` | Args: **`VHOSTNAME`** → XML `<VHOST>…<CONFIG><PARAM NAME="…">value</PARAM>…` |
| CM publish | **`tw_http_pub_set_vhostparam`** (from `webs_vhost_enable` when a listener binds) | Publishes bound port/sysname; not the primary `soap.enable` setter |

`soap.enable` exists **only in `httpd`** (not in `mifd` / `cwmd` / `librgw_compat` strings on 532678).

### Vhosts vs ports ([`httpd_endpoints.md`](httpd_endpoints.md) §7)

| VHOST | Port | TLS | Typical LAN fuzz target |
|-------|------|-----|-------------------------|
| `home0:0` | 80 | no | yes |
| `home0:7` | 51008 | no | yes (`--soap-alt-ports`) |
| `home0:8` | 51009 | yes | yes |

If all three return **404** for SOAP, **`soap.enable` is not `true` on those vhosts** (or SOAP module context failed earlier — check syslog for `soapmod:` / `tr064:`).

## On-gateway checks

### 1. Static config (no XCI)

```sh
grep -n soap.enable /mnt/web/conf/webs_conf.xml /ui/conf/webs_conf.xml 2>/dev/null
# If secondary FS not mounted, try:
grep -n soap.enable /mnt/web/conf/webs_conf.xml
```

Expect **no lines** on stock 532678 if TR-064 is LAN-disabled by policy.

### 2. Read live vhost params (needs auth path to XCI)

`xci_cmd_webs_getvhost` returns every **`PARAM`** for a vhost, including `soap.enable` if set.

From an authenticated **XCI** session (tech UI / `cmd` / debug), conceptually:

- **`MOD=WEBS`**, **`CMD=getvhost`**, **`VHOSTNAME=home0:0`** (and `:7`, `:8`).

The HTTP surface is **`POST /xci`** with a valid **`SESSKEY`** and a **`PAGE`** that runs XCI commands (production builds require a page definition; `webs_isdebug` indexed args are not used on retail images).

### 3. Lab-only: enable SOAP on a vhost

**`xci_cmd_webs_configvhost`**: `VHOSTNAME=home0:0`, `NAME=soap.enable`, `VALUE=true`, then restart or reload `httpd` if your build does not hot-apply.

Only on **your** lab unit. Revert after testing.

After enable, SOAP **GetInfo** should **not** be a generic **404** (expect **200**, SOAP fault, or **401** digest — not 404).

## Tooling

```powershell
# SOAP + optional SSH config grep (see tools/httpd_vhost_soap_probe.py)
python tools/httpd_vhost_soap_probe.py --host 172.16.0.1 --accesscode "…"
python tools/httpd_vhost_soap_probe.py --host 172.16.0.1 --cookie-file cookies.txt
python tools/httpd_vhost_soap_probe.py --host 172.16.0.1 --ssh root@172.16.0.1
```

## Ghidra quick reference

| Item | VA |
|------|-----|
| `mod_uri_table` `/soap/tr064` | `0x004d57d0` |
| `soap_mod_handle_request` | `0x0041c704` |
| `webs_vhost_get_config` | `0x0042c3d8` |
| `xci_cmd_webs_getvhost` | `0x004a7284` |
| `xci_cmd_webs_configvhost` | `0x004a6e5c` |
| `soap_conf.xml` path | `/ui/conf/soap_conf.xml` |
| `webs_conf.xml` path | `/mnt/web/conf/webs_conf.xml` |
