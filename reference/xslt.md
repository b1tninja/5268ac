# XSLT handling on the 5268AC firmware

**Scope:** How **XSLT 1.0** is used for the web admin UI versus the standalone **`xsltproc`** utility, which binaries and libraries are involved, and where configuration lives. Complements [`httpd.md`](httpd.md), [`httpd_endpoints.md`](httpd_endpoints.md), and [`security.md`](security.md).

---

## Two paths: live UI vs CLI

| Path | Binary | Role |
|------|--------|------|
| **Browser / HTTP** | **`/usr/bin/httpd`** | Serves the admin UI. Requests are rewritten or dispatched to internal **`/xslt?PAGE=...`** URIs; **`httpd`** drives **`libxslt`** (e.g. **`xsltApplyStylesheetUser`**) to render pages. This is the production surface. |
| **Shell / scripting** | **`/usr/bin/xsltproc`** | Stock **libxslt 1.1.28** command-line driver (`xsltproc.c`). Same family of libraries as **`httpd`**, but **not** used for normal browser traffic. |

Do not conflate **`xsltproc`** with the **`/xslt`** HTTP handler: they share **`libxslt.so`**, but only **`httpd`** ties transforms to **`PAGE=`** tokens and vhost policy.

---

## HTTP stack: `/xslt` and `PAGE=`

1. **URL rewrites** (`rewrite_conf.xml`) map friendly paths (`/setup`, `/diag`, `/login.html`, …) to internal targets such as **`/xslt?PAGE=C_1_1&NEXTPAGE=C_1_1`**. Matching is prefix-based.
2. **HURL** (`hurl_conf.xml`, etc.) can steer broadband/status flows to **`/xslt?PAGE=...`** as well.
3. **`PAGE`** names select which XSLT / template pipeline runs. Many tokens are cataloged in **`httpd_endpoints.md`**; additional names may exist only under the on-disk XSLT tree (see below).

Full rewrite and HURL tables: **`httpd_endpoints.md`**.

---

## Libraries and Ghidra symbols

| Component | Artifact | Notes |
|-----------|----------|--------|
| Transform API | **`libxslt.so.1`** (project / Ghidra: **`libxslt.so`**) | Upstream **libxslt 1.1.28**: parse stylesheet, build transform context, run templates. ELF exports match public libxslt (e.g. **`xsltParseStylesheetDoc`**, **`xsltApplyStylesheet`**, **`xsltNewTransformContext`**). |
| XML tree / XPath | **`libxml2`** | Linked as usual; versioned stubs (**`@@LIBXML2_*`**) appear in **`libxslt`** PLT. |
| HTTP server | **`httpd`** | Dispatch includes **`xci_cmd_page_xslt`** and calls into **`xsltApplyStylesheetUser`** per **`httpd.md`**. |

Optional runtime plugins (stock libxslt): environment **`LIBXSLT_PLUGINS_PATH`**, default search **`/usr/lib/libxslt-plugins`** (strings present in **`libxslt.so`**).

---

## Template and config layout

Runtime policy and base paths come from the **secondary squashfs** config bundle (see **`httpd.md`**), including **`webs_conf.xml`** (vhosts, **`/mnt/web/ui`**, XSLT base dirs), **`rewrite_conf.xml`**, and **`hurl_conf.xml`**.

### `ui/newxsl` layout (corpus extract)

Under **`work_tl_crc/.../ui/newxsl/`** (mirrors **`xci.base.xsl`** + **`xci.base.pages`** on device):

| Path | Contents |
|------|----------|
| **`pages/*.xml`** | Page-definition XML: root **`<PAGE NAME="Token">`** — **`Token`** is the **`PAGE=`** argument to **`/xslt`**. |
| **`pages/*.xsl`** | Stylesheets per page plus shared **`common_nav.xsl`**, **`common_script.xsl`**, **`common_error.xsl`**, **`navigations.xsl`**, etc. |
| *(device)* **`/mnt/web/.../lang/`** | Localized strings referenced from **`LANGFILES`** in page XML; **`xci.base.lang`** points at **`/mnt/web`** in **`webs_conf.xml`** (may not appear under **`ui/newxsl`** in a single squashfs slice). |

Sibling directories under **`ui/`** (same corpus): **`css/`**, **`javascript/`**, **`images/`**, **`icons/`**, **`speedmeter/`** — static assets referenced from XSLT/HTML output. **`ui/upnp/`** holds TR-064/IGD **service description XML** for SOAP, not **`/xslt`** pages.

### Page-definition XML vocabulary

Commands execute in order under **`<CMDLIST>`**:

- **`<CMD MOD="Module" NAME="Command">`** — dispatches to an **`httpd`** XCI handler (e.g. **`SESS`**, **`PAGE`**, **`WEBS`**, **`CM`**, **`USER`**).
- **`<SARG CALLARG="Name">value</SARG>`** — fixed argument value.
- **`<ARG CALLARG="Name"/>`** — argument supplied by the client (query/post).
- **`<ARG WEBARG="FormName" CALLARG="InternalName"/>`** — maps HTTP parameter **`FormName`** to internal **`InternalName`** (e.g. admin login maps **`ADM_PASSWORD`** → **`PASSWORD`** for **`SESS`/`AUTH`**).
- **`<ONSTATUS STATUS="…" PAGE="…"/>`** — navigation on command result; **`PAGE="*NEXTPAGE"`** uses the request’s **`NEXTPAGE`** parameter.

**Examples:** [`login_post.xml`](work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/ui/newxsl/pages/login_post.xml) (**`WEBARG`/`CALLARG`** for **`ADM_PASSWORD`**), [`TECHLOGIN_POST.xml`](work_tl_crc/pkgstream_dissect_corpus/att-5268-11.5.1.532678_prod_lightspeed-install_squashfs_0x01993b45_b9e08402/ui/newxsl/pages/TECHLOGIN_POST.xml) (fixed **`USERNAME`** **`tech`**, bare **`PASSWORD`** **`ARG`**).

### PAGE inventory tooling

Regenerate the conf-vs-pages report with **`python tools/page_inventory.py`** — writes **[`output/page_inventory_att_532678.md`](output/page_inventory_att_532678.md)** and **`page_inventory_att_532678.json`**. Full **`CMD MOD=`** frequency table is in that artifact.

---

## Reverse-engineering notes (Ghidra)

- **`xsltproc`** (MIPS BE, ~26 KB): **`main`** parses argv (same option set as upstream **`xsltproc.c`**), calls **`xmlReadFile`** / **`xsltParseStylesheetDoc`** / **`xsltProcess`**, uses **`xsltprocExternalEntityLoader`** for **`--path`**. Build paths in strings point at **`libxslt-1.1.28`**.
- **`libxslt.so`** (~306 KB, **826** functions): **`xsltApplyStylesheet`** delegates to **`xsltApplyStylesheetInternal`** (transform context, **`xsltProcessOneNode`**, output methods XML/HTML/text, profiling hooks). No vendor-specific algorithm changes observed—behavior matches published **libxslt 1.1.x** sources.

For symbol-level parity, use **`libxslt-1.1.28`** sources alongside Ghidra on the exported names above.

### libxslt “security preferences” API (not HTTP / DIAG passwords)

**Important:** The functions **`xsltNewSecurityPrefs`**, **`xsltSetSecurityPrefs`**, **`xsltSecurityAllow`**, **`xsltSecurityForbid`**, **`xsltCheckRead`**, and **`xsltCheckWrite`** implement **libxslt’s sandbox for transforms**—controlling whether an XSLT stylesheet may **read/write local files**, **create directories**, or **use network URLs** (e.g. `document('http://…')`, writing output to a path). They **do not** validate the **router admin password**, **digest credentials**, or **session state** for **`/diag`** or any **`/xslt?PAGE=…`** request. That gating lives in **`httpd`** (e.g. **`check_authweb`**, **`webs_auth_*`**, **`tw_ulib_pwd_auth`**, **`xci_cmd_sess_auth` / `xci_cmd_sess_authcheck`**) *before* the XSLT pipeline runs; **`xci_cmd_page_xslt`** only registers output filters and does not wire libxslt security prefs for page passwords.

Upstream libxslt defines **five preference slots** (indices **1–5**). **`xsltSetSecurityPrefs`** / **`xsltGetSecurityPrefs`** require **`xsltInitGlobals`** and validate **`option ∈ {1,…,5}`**; otherwise they return **`-1`** / **0**.

| Index | Name (libxslt source) | Purpose |
|------:|------------------------|---------|
| **1** | `XSLT_SECPREF_READ_FILE` | Local file read (`document()` / entities with file paths) |
| **2** | `XSLT_SECPREF_WRITE_FILE` | Writing result or temp files on disk |
| **3** | `XSLT_SECPREF_CREATE_DIRECTORY` | Creating directories for output |
| **4** | `XSLT_SECPREF_READ_NETWORK` | Network read (`document('http…')`, etc.) |
| **5** | `XSLT_SECPREF_WRITE_NETWORK` | Network write |

**`xsltNewSecurityPrefs`** allocates **`0x14`** bytes (**20**), zeroed—one word per preference slot plus header fields in libxslt’s internal struct.

**`xsltSecurityAllow`** and **`xsltSecurityForbid`** are **tiny predicates** used as **callback functions** when registering a preference: **`xsltSecurityAllow`** returns **1**, **`xsltSecurityForbid`** returns **0**. Callers treat **non-zero** as “allowed” and **zero** as “denied” when invoking the stored callback.

**`xsltCheckRead(URL)`** (decompiled in **`libxslt.so`**):

- **`xmlParseURI`** on the URL; failure → error, return **`-1`**.
- If the URI has **no scheme** or scheme is **`file`** (libxml URI → empty / `file`): consult preference **1** (**READ_FILE**). If a callback is set and returns **0**, emit **`xsltTransformError`** and deny (**return 0**).
- Else (**network-style** URI): consult preference **4** (**READ_NETWORK**); same deny path if callback returns **0**.
- Otherwise allow (**return 1**).

**`xsltCheckWrite(URL)`**:

- Parse URI as above.
- For **file-ish** paths, delegate to **`xsltCheckWritePath`** (directory **`stat`**, **`mkdir`**, preference **2** / **3** for write / create).
- For **non-file** URIs, consult preference **5** (**WRITE_NETWORK**); deny if callback returns **0**.

**`xsltCheckWritePath`** chains **WRITE_FILE** (2) then **CREATE_DIRECTORY** (3) when the parent directory does not exist, matching upstream **security.c** behavior.

**Firmware note:** **`xsltproc`**’s **`main`** sets **default** prefs and uses **`xsltSecurityForbid`** on slots **2, 3, 5** when **`--stylesheet`** security flags are used (CLI hardening). **`httpd`** does not need those calls for “DIAG password”—that is orthogonal HTTP authorization.

---

## Security perspective

XSLT plus libxml/libxslt adds **parser and transform complexity** to the admin attack surface. Untrusted or malformed input that reaches transforms is relevant for threat modeling. **HTTP authentication** for sensitive pages is enforced by **`httpd`**, not by **`xsltCheckRead`**. See **`security.md`** and **`httpd_endpoints.md`** (ACL / **`tw_ulib_pwd_auth`**) for the web-auth chain.

---

## See also

- [`httpd.md`](httpd.md) — **`httpd`** stack, **`conf/*.xml`**, **`xci_cmd_page_xslt`** / **`xsltApplyStylesheetUser`**
- [`httpd_endpoints.md`](httpd_endpoints.md) — **`/xslt?PAGE=...`** catalog from rewrites and HURL (§5 page-definition XML)
- [`output/page_inventory_att_532678.md`](output/page_inventory_att_532678.md) — generated **`PAGE`** / **`NEXTPAGE`** vs **`pages/*.xml`** inventory
- [`security.md`](security.md) — web admin exposure summary
