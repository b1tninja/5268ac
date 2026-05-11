# Security notes (5268ac)

This file tracks firmware-relevant exposure and analysis hooks. It is not a formal audit.

## Web admin / `httpd` attack surface

The **LAN (and often WAN-facing) web UI** is implemented by **`/usr/bin/httpd`**, with configuration and XSLT supplied from a **secondary squashfs** (`conf/*_conf.xml` and related templates). This is a **high-value attack surface**: any bug in request parsing, authentication, XSLT transform, SOAP handling, or URL rewrite logic can affect device integrity and confidentiality.

**Why it matters**

- **HTTP/HTTPS** on typical home-gateway ports (see `webs_conf.xml`: 80/443, vhosts such as `home0`).
- **Large feature surface**: HURL redirects, many **`/xslt?PAGE=...`** entry points, legacy paths (`/management/...`, `/BroadJump/...`, upgrades, diagnostics).
- **SOAP / TR-064** (`soap_conf.xml`, `soapmod_tr064`, `libsoap.so.0`): structured RPC-style endpoints with digest auth policy—credential handling and authorization bugs are in scope.
- **XSLT + libxml/libxslt** (`libxslt.so.1`): transforms are a historic source of complexity and parser/transform bugs; untrusted or malformed input reaching transforms is relevant.
- **TLS** (OpenSSL imports in `httpd`): certificate validation, cipher suites, and downgrade behavior belong in review.
- **Secondary squashfs content**: editable-config semantics mean **integrity of mounted config** matters (supply-chain / upgrade assumptions).

**Related documentation**

- **[`httpd.md`](httpd.md)** — stack map, `conf/*_conf.xml` roles, libraries, and Ghidra correlation.
- **[`httpd_endpoints.md`](httpd_endpoints.md)** — enumerated rewrites, HURL targets, SOAP/TR-064 scope, vhost/realm matrix, and **`httpd`** dispatch functions (rewrite/HURL/XSLT/SOAP modules).

Treat **`httpd`** and its **`libhttp*` / `libsoap` / libxslt / SSL** dependency chain as the primary web-admin exposure for threat modeling and fuzzing prioritization. Use **`httpd_endpoints.md`** as the checklist of URLs and `PAGE=` tokens to prioritize when assessing exposure (LAN/WAN, MDC port **50001**, WRA, digest TR-064).
