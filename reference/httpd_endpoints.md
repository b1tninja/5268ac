# httpd URL endpoints, handlers, and authentication

**Firmware:** `att-5268-11.5.1.532678_prod_lightspeed-install`  
**Config corpus:** `work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/conf/`  
**Binary:** `/usr/bin/httpd` (Ghidra program name `httpd`, MIPS BE).

End-to-end **`.pkgstream` → `pkgd` → `lib2sp`** wiring (FIFO XCI, **`libpkg_client`**, **`cwmd`**, evidence JSON): **[`firmware_upgrade_process.md`](firmware_upgrade_process.md)** §1.1 and §3.

This document merges **`conf/*.xml` endpoint definitions** with **Ghidra-derived dispatch** in `httpd`. Additional `PAGE=` names may exist only in XSLT under `/mnt/web/ui/newxsl` (not exhaustively listed here).

---

## 1. Static URL rewrites (`rewrite_conf.xml`)

Matching is **prefix / startswith** on the request path (per file comment). Each row rewrites to an internal **`/xslt?...`** URI.

| External URL | Internal target |
|--------------|-----------------|
| `/upgrade` | `/xslt?PAGE=UPGRADE0&NEXTPAGE=UPGRADE0` |
| `/ncwqcdbg` | `/xslt?PAGE=NCWQCDBG0&NEXTPAGE=NCWQCDBG0` |
| `/fieldtest` | `/xslt?PAGE=fieldtest&NEXTPAGE=fieldtest` |
| `/ATT/cca5G` | `/xslt?PAGE=cca5G` |
| `/ATT/cca2G` | `/xslt?PAGE=cca2G` |
| `/ATT/topology` | `/xslt?PAGE=topology` |
| `/ATT/friendly-info` | `/xslt?PAGE=friendly-info` |
| `/ATT/steer` | `/xslt?PAGE=steer` |
| `/ATT/route` | `/xslt?PAGE=route` |
| `/setup` | `/xslt?PAGE=C_1_1&NEXTPAGE=C_1_1` |
| `/diag` | `/xslt?PAGE=DIAG0` |
| `/login.html` | `/xslt?PAGE=login` |
| `/wra` | `/xslt?PAGE=WRA01&NEXTPAGE=WRA02` |
| `/management/dsl_line_diags.txt` | `/xslt?PAGE=DSL_LINE_DIAGS` |
| `/management/dsl_dsm_diags.txt` | `/xslt?PAGE=DSL_DSM_DIAGS` |
| `/management/dsl_diags.2wd` | `/xslt?PAGE=DSL_DIAGS` |
| `/access/site_blocked.html` | `/xslt?PAGE=HURL19&COND=BLOCKED` |
| `/access/unrated_sites.html` | `/xslt?PAGE=HURL19&COND=CSUNRATED` |
| `/access/css_down.html` | `/xslt?PAGE=HURL19&COND=CSDOWN` |
| `/net/stat/status.html` | `/xslt?PAGE=KICK` |
| `/kick.html` | `/xslt?PAGE=KICK` |
| `/download/download_in_progress.html` | `/xslt?PAGE=UPGRADE2&NEXTPAGE=UPGRADE2` |
| `/BroadJump/Status` | `/xslt?PAGE=BJ_STATUS` |
| `/BroadJump/Setup` | `/xslt?PAGE=BJ_SETUP_POST` |
| `/BroadJump/Wireless` | `/xslt?PAGE=BJ_WIRELESS_POST` |
| `/speedmeter/speedmeter_data` | `/xslt?PAGE=C_5_1a` |
| `/ATT/BB_STATUS` | `/xslt?PAGE=BB_STATUS` |
| `/legal.txt` | `/xslt?PAGE=LEGAL` |

---

## 2. HURL redirects (`hurl_conf.xml` — standard DSL mode)

**Entry path:** vhosts expose **`hurl.uri`** = `/hurl` ([`webs_conf.xml`](work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/conf/webs_conf.xml)). The HURL module maps **broadband/status events** (`NAME`) to a **`PAGE=`** target. **Earlier rows win** (file comment).

| HURL NAME | Options | Target |
|-----------|---------|--------|
| PHY_NONE | SHOW_BB_STATUS | `/xslt?PAGE=HURL03` |
| NOT_PROV | SHOW_BB_STATUS | `/xslt?PAGE=HURL04` |
| DSL_TRAIN_FAILED | SHOW_FILTER_STATUS | `/xslt?PAGE=HURL05` |
| DSL_MISSING_FILTER | SHOW_FILTER_STATUS | `/xslt?PAGE=HURL06` |
| EAPOL_FAILED | SHOW_BB_STATUS | `/xslt?PAGE=HURL18` |
| BB_STANDBY | (none) | `/xslt?PAGE=HURL15` |
| NO_DHCP_SERVICE | SHOW_BB_STATUS | `/xslt?PAGE=HURL21` |
| NO_ATM_SERVICE | SHOW_BB_STATUS | `/xslt?PAGE=HURL01` |
| NO_PPP_SERVICE | SHOW_BB_STATUS | `/xslt?PAGE=HURL01` |
| PPP_AUTH_FAILED | SHOW_BB_STATUS | `/xslt?PAGE=HURL18` |
| PPP_NET_TROUBLE | SHOW_BB_STATUS | `/xslt?PAGE=HURL01` |
| NO_IP | SHOW_BB_STATUS | `/xslt?PAGE=HURL01` |
| BB_NOT_UP | SHOW_BB_STATUS | `/xslt?PAGE=HURL01` |
| EXCESSIVE_SESS | SERVICE_FW | `/xslt?PAGE=HURL07` |
| ROUTER_DETECTED | SERVICE_ROR | `/xslt?PAGE=HURL08` |
| ONDEMAND_REDIRECT | (empty body) | — |

**Unique `PAGE` tokens (standard):** `HURL01`, `HURL03`, `HURL04`, `HURL05`, `HURL06`, `HURL07`, `HURL08`, `HURL15`, `HURL18`, `HURL21`.

---

## 3. HURL redirects (`fwb_hurl_conf.xml` — fixed-wireless / WLL mode)

Same precedence rules; targets collapse to **`HURL01_FWB`**, **`HURL02_FWB`**, **`HURL03_FWB`** per carrier doc referenced in the XML.

---

## 4. Deduplicated `PAGE` tokens (rewrite + HURL standard)

`UPGRADE0`, `UPGRADE2`, `NCWQCDBG0`, `fieldtest`, `cca5G`, `cca2G`, `topology`, `friendly-info`, `steer`, `route`, `C_1_1`, `DIAG0`, `login`, `WRA01`, `DSL_LINE_DIAGS`, `DSL_DSM_DIAGS`, `DSL_DIAGS`, `HURL19`, `KICK`, `BJ_STATUS`, `BJ_SETUP_POST`, `BJ_WIRELESS_POST`, `C_5_1a`, `BB_STATUS`, `LEGAL`, plus HURL pages **`HURL01`–`HURL08`, `HURL15`, `HURL18`, `HURL21`** and FWB variants **`HURL##_FWB`**.

Default landing/error pages from [`webs_conf.xml`](work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/conf/webs_conf.xml): **`xci.default.page`** = `A_0_0`, **`xci.default.errorpage`** = `ERROR`.

---

## 5. Page-definition XML (`newxsl/pages/*.xml`)

Each admin screen is driven by a **page-definition** file: **`PAGE NAME="Token"`** matches the **`PAGE=`** query argument to **`/xslt`**. On disk the basename is usually the token (e.g. **`login.xml`** → **`PAGE=login`**). Stylesheets are referenced inside the XML (e.g. **`CMD MOD="PAGE" NAME="XSLT"`** with **`pages/login.xsl`**).

**Naming:** Many POST handlers use a **`_POST`** suffix (e.g. **`login_post.xml`**, **`TECHLOGIN_POST.xml`**). **`ARG`** / **`SARG`** elements pass **`CALLARG`** names to **`httpd`** command modules; optional **`WEBARG`** maps a form/query parameter name to a **`CALLARG`** (see [`xslt.md`](xslt.md)).

**Coverage vs this section:** [`rewrite_conf.xml`](work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/conf/rewrite_conf.xml) and HURL files expose only a **subset** of **`PAGE`** tokens. Many pages are reached via links, forms (**`NEXTPAGE`**), or default routing. **Machine-generated inventory** ( **`PAGE=`** / **`NEXTPAGE=`** from conf vs **`<PAGE NAME>`** in **`pages/*.xml`** ): **[`output/page_inventory_att_532678.md`](../output/page_inventory_att_532678.md)** — regenerate with **`python tools/page_inventory.py`**.

For this firmware slice: **247** distinct page names, **67** files matching **`*_POST.xml`**, **38** distinct **`PAGE=`** / **`NEXTPAGE=`** tokens across **`rewrite_conf.xml`** + **`hurl_conf.xml`** + **`fwb_hurl_conf.xml`**, **209** page names not appearing as **`PAGE=`** or **`NEXTPAGE=`** in those three files (still reachable from the UI).

**UPnP:** Service XML under **`ui/upnp/`** is **not** part of this **`PAGE`** namespace; it describes SOAP/TR-064 services consumed with **`soap_conf.xml`**.

---

## 6. SOAP / TR-064 (`soap_conf.xml`)

SOAP is **not** expressed as `/xslt?PAGE=...`. [`soap_conf.xml`](work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/conf/soap_conf.xml) lists many **`<ACTION NAME="urn:...#Method"/>`** entries. Most capabilities appear twice: **`urn:dslforum-org:service:...`** and **`urn:schemas-upnp-org:service:...`** (same method name).

**Authentication (mutating / sensitive actions):** blocks that include nested `<VALUE NAME="auth.type">` use **`digest`**, realm **`TR-064`**, **`auth.backend`** / **`auth.require.user`** tied to **`dslf-config`** (one action also allows **`dslf-config dslf-reset`**). Read-only actions are often **empty** `<ACTION .../>` with **no** auth block.

**Scale:** **[`soap_conf.xml`](work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/conf/soap_conf.xml)** contains **138** **`<ACTION …>`** tags in this corpus (dslforum + schemas pairs); exhaustive listing is best generated by XML parse if needed.

---

## 7. Virtual hosts and HTTP auth ([`webs_conf.xml`](work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/conf/webs_conf.xml))

| VHOST | Port(s) | TLS | Notes |
|-------|---------|-----|--------|
| `home0:0` | 80 | no | Main LAN UI; `hurl.uri` `/hurl` |
| `home0:1` | 443 | yes | Same; `hurl.uri` `/hurl` |
| `home0:2` | 80 | no | **disabled** (`vhost.enable` false); tech interface sysname |
| `home0:3` … `home0:6` | 80 / 443 | mixed | IPv6 (`pm_hm_if_ip6lan`), link/global scope variants |
| `home0:7` | 51008 | no | `hurl.uri` `/hurl` |
| `home0:8` | 51009 | yes | `hurl.uri` `/hurl` |
| `local0:0` | 80 | no | **127.0.0.1** only |
| `mdc0:0` | 50001 | yes | **`auth.type` basic**, **`auth.realm` tech-write**, **`auth.backend` mdc** (mobile diagnostics / field; default `vhost.enable` false, gated by `mdc`) |
| `mdc0:1` | 51001 | yes | No explicit auth block in snippet; sesslimit 3 |
| `wra0:0`, `wra0:1` | from params | opt TLS | **`location.default` `/wra`** (Web Remote Access); **`vhost.enable` false**, gated by `wra` |

**Paths:** UI document root **`file.base`** = `/mnt/web/ui`; XSLT **`xci.base.xsl`** = `/mnt/web/ui/newxsl`; default handler location **`location.default`** = `/xslt` (except WRA vhosts use `/wra`).

---

## 8. Ghidra: what handles responses in `httpd`

| Mechanism | Function(s) (addresses are VA in `httpd`) | Behavior |
|-----------|-------------------------------------------|----------|
| **URL rewrite → `/xslt?...`** | **`rewrite_mod_handle_uri`** @ `0x0041b2a0` | Walks a **map** of prefix → rewrite template; **`strncmp`** match on URI; builds new path via **`snprintf`** from template + remainder; may **`http_par_urlencoded`** on query part after `?`. Implements **`rewrite_conf.xml`** semantics. |
| **HURL `/hurl`** | **`hurl_mod_handle_uri`** @ `0x004163f8` | Validates vhost config vs request; walks HURL event list (`map_index` / **`strcasecmp`** against event names such as embedded **`PHY_NONE`**); updates redirect target (`strdup`); interacts with **`webs_vhost_get_config`**, **`cm_tran_*`**, **`tw_getdomainname`**. |
| **XSLT `PAGE=` pipeline** | **`xci_cmd_page_xslt`** @ `0x0046dc70`; **`xci_cmd_page_xsltjump`** @ `0x0046df08` | Reads **`PAGE`** / debug via **`webs_conn_getarg`**; loads **`webs_conn_get_config`** for stylesheet path; registers output filters **`page_xslt_ops`** (and **`page_xml_ops`** for alternate mode). **libxslt** invoked via **`page_xslt_ops`** / **`xsltApplyStylesheetUser`** (imports). |
| **SOAP TR-064** | **`soap_mod_handle_request`** @ `0x0041c704`; **`soap_mod_handle_response`** @ `0x0041bacc`; **`soap_mod_init`** @ `0x0041c610` | Requires vhost SOAP profile (**`webs_vhost_get_config`** matches expected service id); **POST** body filter **`soap_in_filter`**; dispatches registered SOAP actions. String **`soapmod_tr064`** and **`soap_tr064.c`** tie to **`tr064_*`** service handlers (WAN, WLAN, reboot, factory reset, etc.). |
| **ACL / passwords** | **`tw_http_acl_*`**, **`tw_ulib_pwd_auth`** @ `0x004c0160`, etc. | ACL rules and passwd-store auth used with HTTP realms; **`_auth_password_dslfconfig`** string present for TR-064/dslf backend alignment. |

SOAP HTTP path selection is driven by **per-service URI strings** registered in the SOAP module (matched in **`soap_mod_handle_request`** against request URI via **`memcmp`** over configured paths)—exact path strings live in **`.rodata`** next to service maps; use **`search_strings`** on **`httpd`** for the control URL if needed.

---

## 9. Authentication summary

| Surface | Mechanism | Realm / user | Config source |
|---------|-----------|--------------|----------------|
| Main UI (`home0`, `/xslt`, rewrites) | Session / app login (see `PAGE=login`); ACL helpers | (product-specific accounts) | Runtime + `tw_ulib_pwd_*` |
| **MDC** vhost | **HTTP Basic** | **`tech-write`** | [`webs_conf.xml`](work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/conf/webs_conf.xml) `mdc0:0`; backend **`mdc`** |
| **SOAP / TR-064** | **HTTP Digest** | **`TR-064`**; users **`dslf-config`** / **`dslf-reset`** | [`soap_conf.xml`](work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/conf/soap_conf.xml) |
| **TLS** | OpenSSL (`SSL_*` imports in `httpd`) | Certificate-based server auth to client | 443 / TLS vhosts |

---

## 10. Security reference

See **[`security.md`](security.md)** — web stack attack surface and fuzzing priority. This file expands the **enumerated URL / PAGE / SOAP** surface for review.

---

## See also

- [`httpd.md`](httpd.md) — stack overview
- [`output/page_inventory_att_532678.md`](output/page_inventory_att_532678.md) — generated **`PAGE`** / **`NEXTPAGE`** vs **`newxsl/pages/*.xml`** ( **`python tools/page_inventory.py`** )
- [`output/web_admin_ghidra_correlation.md`](output/web_admin_ghidra_correlation.md) — earlier MCP correlation
