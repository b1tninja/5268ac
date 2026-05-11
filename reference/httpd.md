# `/usr/bin/httpd` and the web admin stack (5268ac)

Firmware slice: **`att-5268-11.5.1.532678_prod_lightspeed-install`**, MIPS big-endian. Analysis used Ghidra project **`5268ac`** and extracted squashfs under `work_tl_crc/pkgstream_dissect_corpus/`.

## Role

**`/usr/bin/httpd`** is the primary on-device **HTTP/HTTPS server** for the web-based admin UI. It is not a minimal static file server: it loads **HURL** handling, **URL rewrites**, **XSLT** page generation, **SOAP (TR-064)**, and ties to **vhost** configuration. Companion **`/usr/bin/xsltproc`** is a separate CLI; the browser UI is served through **`httpd`** with embedded libxslt usage.

## Secondary squashfs: `conf/*_conf.xml`

Config and XSLT layout for the UI live on a **secondary squashfs** (corpus path used for file review):

`work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/conf/`

This directory contains **only XML** configuration files named `*_conf.xml` (there are **no** separate `*.conf` files in this bundle).

| File | Purpose |
|------|---------|
| `webs_conf.xml` | Virtual hosts (e.g. 80/443), `/hurl`, base paths `/mnt/web/ui`, `/mnt/web`, XSLT base dirs |
| `hurl_conf.xml` | HURL redirect map to `/xslt?PAGE=...` (broadband / status flows) |
| `fwb_hurl_conf.xml` | Fixed-wireless (FWB) HURL page variants |
| `rewrite_conf.xml` | URL rewrites (`/setup`, `/diag`, legacy `/management/...`, many `/xslt?PAGE=...` targets) |
| `soap_conf.xml` | TR-064–style SOAP actions; digest auth (realm **TR-064**, user **`dslf-config`**) |

These files define **runtime policy** the stack consumes when the secondary image is mounted (e.g. under `/mnt/web` as in `webs_conf.xml`).

## UI tree on the secondary squashfs (`ui/`)

Parallel to `conf/`, the same corpus exposes static and template assets under:

`work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/ui/`

| Area | Role |
|------|------|
| **`newxsl/`** | XSLT 1.0 admin UI: **`pages/`** holds paired **page-definition XML** (`<PAGE NAME="…">`) and **`.xsl`** templates, plus shared stylesheets such as **`common_nav.xsl`**. Consumed by **`httpd`** via paths in **`webs_conf.xml`** (e.g. `xci.base.pages`, `xci.base.xsl`). |
| **`css/`**, **`javascript/`**, **`images/`**, **`icons/`**, **`speedmeter/`** | Static assets referenced from stylesheets and HTML output. |
| **`upnp/`** | TR-064 / IGD / WFA **service description XML** for SOAP (not `/xslt?PAGE=` definitions). Aligns with **`soap_conf.xml`** and UPnP stacks. |
| **`licenses/`**, **`licenses.html`** | License text for shipped components. |

Localized strings are configured under **`xci.base.lang`** on device (`/mnt/web` in **`webs_conf.xml`**); they may live on another mounted tree and are not always present under **`ui/newxsl`** in a single extract.

**Machine-generated page list:** [`output/page_inventory_att_532678.md`](output/page_inventory_att_532678.md) (from **`tools/page_inventory.py`**).

### Virtual hosts (summary)

**`webs_conf.xml`** defines multiple listeners (**`home0`** LAN UI on 80/443 and alternate ports, **`local0`** loopback, **`mdc0`** diagnostics with optional basic auth, **`wra0`** Web Remote Access with **`location.default`** `/wra`). Full port/TLS/auth matrix: **[`httpd_endpoints.md`](httpd_endpoints.md) §7**.

## Binary ↔ config mapping (Ghidra)

Strings and symbols in **`httpd`** line up with the XML layers:

| Config | Indicators in `httpd` |
|--------|---------------------|
| HURL | `hurl_mod.c`, `hurl_mod_handle_uri`, `hurl_config`, `tw_ulib_hurl_*`, `webs_hurlmod` |
| Rewrites | `rewrite_config` |
| Vhosts / webs | `webs_config`, `webs_config_insert`, `webs_config_lookup`, `xci_cmd_webs_configvhost` |
| XSLT | `xci_cmd_page_xslt`, `xsltApplyStylesheetUser`, `libxslt.so.1` |
| SOAP / TR-064 | `soapmod_tr064`, `soap_service_*`, `soap_xml_*`, `libsoap.so.0` |

Literal strings **`TR-064`** or **`dslf-config`** are not required to appear as plain C strings; TR-064 behavior is still shown by **`soapmod_tr064`** and SOAP APIs, aligned with `soap_conf.xml`.

## Runtime libraries (observed)

- **`libhttp.so.0`**, **`libhttp_server.so.0`**, **`libhttp_client.so.0`**
- **`libsoap.so.0`**
- **`libxslt.so.1`**
- OpenSSL symbols present via imports (e.g. `SSL_*`, `X509_*`) for TLS on 443

Exact on-device paths follow normal rootfs layout (`/usr/lib`, `/lib`).

## Related binaries

- **`/usr/bin/xsltproc`**: command-line XSLT; not the live admin path.
- **`/usr/bin/wproxy`**: ancillary; quick string scan did not show the same XSLT/HTTP surface as `httpd`.

## See also

- [`xslt.md`](xslt.md) — XSLT/`libxslt` handling (`/xslt`, `PAGE=`, page-def XML vocabulary, `xsltproc` vs `httpd`)
- [`httpd_endpoints.md`](httpd_endpoints.md) — URL rewrites, HURL/`PAGE=` catalog, SOAP actions, vhost auth matrix, Ghidra handler addresses
- [`output/page_inventory_att_532678.md`](output/page_inventory_att_532678.md) — **`PAGE`** tokens vs **`rewrite_conf.xml` / `hurl_conf.xml`** (generated)
- [`output/web_admin_ghidra_correlation.md`](output/web_admin_ghidra_correlation.md) — full MCP session notes
- [`security.md`](security.md) — attack surface summary
- [`cm_cmdb.md`](cm_cmdb.md) — configuration manager / CMDB (`cm_tran_*`, `cmdb_*`), shared-memory access, password storage vs UI squashfs
