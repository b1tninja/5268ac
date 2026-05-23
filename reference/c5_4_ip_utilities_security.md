# IP Utilities (`PAGE=C_5_4`) — security notes

Firmware reference: **11.14.1.533827** squashfs (`ui/newxsl/pages/C_5_4*.xml|xsl`). Ghidra: **`httpd`**, **`librgw_compat.so.0.0.0`**, **`mifd`** (diags RPC target).

## What the page is

**IP Utilities** (not Dropbox). UI tools (lang `en/lang/C_5_4.xml`):

| UI label | `CMD` value | Backend |
|----------|-------------|---------|
| Ping | `PING` | `tw_ulib_diags_ping` |
| Traceroute | `TRACEROUTE` | `tw_ulib_diags_traceroute` |
| DNS query | `DNSQUERY` | `tw_ulib_diags_dnsquery` |
| Continuity test | `CONTINUITYTEST` | `tw_ulib_diags_continuitytest` |

Flow:

1. **GET** `C_5_4.xml` — `MOD NETTOOLS` status, `AUTHWEB` / tech / ACS checks, `CHECK_VHOST`.
2. **POST** `C_5_4_POST.xml` — `NONCECHECK`, maps form → `NETTOOLS START|STOP` (`C_5_4_POST.xsl`).
3. **`httpd`** `xci_cmd_nettools_start` @ `0x0045cdc4` → **`tw_ulib_diags_*`** in **`mifd`** via `PING_nettools` / `TRACEROUTE_nettools` / … module names.

Page registry marks **`C_5_4`** as redirect-hidden (reachable via menu / direct `PAGE=` URL, same class as other `C_5_*` pages).

## Authentication

| Path | Requirement |
|------|-------------|
| Main LAN UI (`home0`, `wra0`) | **`AUTHWEB`** — CM `user` session (`adm` / access code or pass-the-hash digest string) |
| `home0:0` / `home0:1` | **`AUTHCHECK`** tech user |
| MDC vhost `mdc0:1` | **`AUTHACSACCESS`** (ACS / installer lane) |

POST uses **`NONCECHECK`** (CSRF token on state-changing request). Does not remove need for a valid session on protected vhosts.

See [`http_auth_realms.md`](http_auth_realms.md).

## Input handling (`xci_cmd_nettools_start`)

| Parameter | Validation |
|-----------|------------|
| **`CMD`** | Whitelist only: `PING`, `TRACEROUTE`, `CONTINUITYTEST`, `DNSQUERY` (`strcasecmp`). Anything else → `MODNAME` / EINVAL. |
| **`COUNT`**, **`PKTLEN`** | `is_string_pos_int` → `regexPosInt` in `httpd`; `atoi`. **PKTLEN** clamped: out-of-range reset to **64** (`0x40`) or **576** (`0x240`). |
| **`HOSTNAME`** | Required. **`verify_address_resolution`** @ `0x00059998` (`librgw_compat`). Failure → `BAD_HOSTNAME` / `NO_HOSTNAME`. |
| **`RESOLVE`**, **`IPV6PREFER`** | Normalized `ON`→`TRUE`, `FALSE`→`FALSE`; passed as diags int params. |
| **`NAME`/`VALUE` pairs** | Up to **32** map inserts; only known keys consumed by diags. |

Important: **`verify_address_resolution` proves the string is a literal IP or resolvable via `getaddrinfo` — it does not rewrite `HOSTNAME`**. `httpd` still calls `tw_ulib_diags_set_param_str(..., "hostname", <original user string>)`.

### `verify_address_resolution` (`librgw_compat` @ `0x00059998`)

Called as `verify_address_resolution(hostname, ipv6prefer, &sockaddr_out, &addr_kind)`.

| Step | Function | Behavior |
|------|----------|----------|
| 1 | **`verify_hostname_contents`** @ `0x000559b4` | Copies **14 bytes** from **`gp + 0x40`** into a stack buffer, then scans up to **`min(strlen, 0x200)`** bytes. For each character, walks inclusive **`[lo, hi]`** pairs; if `lo <= c <= hi` → return **`0x16`** (`EINVAL`). Otherwise return **0**. |
| 2 | **`nu_ipaddr_from_str`** (`libnetutil` @ `0x4e54`) | If return **0**, copies **16-byte** parsed address to output and **`verify_address_resolution` returns 0** (no DNS). Parser walks the full string with a ctype-style table (digits, `.`, `:`, etc.); trailing garbage such as **`;`** is not treated as a valid literal IP. |
| 3 | **`tw_getaddrinfo(hostname, 1, …)`** | IPv6 lookup (`getaddrinfo` wrapper: `ai_family=10`, `ai_socktype=2`, `ai_protocol=3`). On success, builds a path from rodata fragments under **`/proc/sys/net/ipv4/conf/all/forwarding`** / **`conf/…/forwarding`**, does **`snprintf` + `fopen(..., "r")`** using the **user hostname** in the path, then **`nu_ipaddr_from_sockaddr`**. |
| 4 | **`tw_getaddrinfo(hostname, 0, …)`** | IPv4 lookup; if `ai_family == 2`, copies sockaddr, sets `*addr_kind` to **4** (IPv4) or **10** (IPv6-prefer variants **6** / **8**). |
| 5 | Else | `*addr_kind = 0`, return **-1** → `httpd` **`BAD_HOSTNAME`**. |

**`httpd` still passes the original `HOSTNAME` string** to `tw_ulib_diags_set_param_str(..., "hostname", …)` after validation — validation does not substitute the resolved address.

#### Charset table (`gp + 0x40`)

The denylist is **not** a rodata string; it is **14 bytes of pair data** loaded via `memcpy(..., gp+0x40, 0xe)` before the scan. Static inspection of the on-disk ELF at symbol **`_gp` (`0xfd5d0`) + 0x40** lands in **`.got`** (relocatable pointer words), so the exact runtime byte table was not recovered offline. Do not assume a “typical” `;|&` blacklist without device/lab confirmation.

#### `nu_ipaddr_from_str` note

Disassembly of `libnetutil.so.0.0.0` shows a full-string walk and **`inet_pton`-class** call with family **2** or **10**; strings like **`8.8.8.8;id`** should fail parsing (**`0x16`**) rather than accept a partial IPv4 and proceed.

### Plausible **problematic** hostnames (static RE; lab-verify on CPE)

These are candidates to test on a bench unit (authenticated **IP Utilities** POST, `CMD=PING` or `TRACEROUTE`). They are chosen against the logic above and the **`popen`** command shape (below).

| Hostname | Why test it |
|----------|-------------|
| **`fe80::1%br0`** or **`fe80::1%eth0`** | **`%`** is common in IPv6 zone IDs; may pass charset and **`getaddrinfo`**, yet appear verbatim in **`ping … %s 2>&1`** (and triggers the IPv6 **`fopen`** side path during resolution). |
| **`8.8.8.8 -n 1`** (if space passes charset) | **`nu_ipaddr_from_str`** skips spaces while scanning; **`getaddrinfo`** may still fail, but any acceptance leaks **extra tokens** into the shell line after **`-4`**. |
| **`127.0.0.1` + allowed punctuation** | Confirm what survives charset (e.g. **`,`**, **`/`**, **`-`**) if the runtime table is weaker than expected. |
| **`../../../all`** or **`lo/../../etc/passwd`** (if **`/`** allowed) | IPv6 validation **`snprintf`**s the hostname into a **`/proc/sys/net/…/conf/%s/…`**-style path before **`fopen`** — **`..`** / **`/`** in the name are the main traversal concern if not blocked by step 1. |
| **`$(id)`**, **`` `id` ``**, **`;id`**, **`\|id`** | Classic shell metacharacters; should fail **`getaddrinfo`** and (for **`;`**) **`nu_ipaddr_from_str`**, but confirm they return **`BAD_HOSTNAME`** vs. reaching **`popen`**. |
| **512-byte / 0x200-char label** | Charset scan caps at **`0x200`**; **`popen`** buffer is ~**512** bytes in diags — stress/DoS rather than injection. |
| **Resolvable attacker FQDN** (e.g. **`pingtest.example.com`**) | No injection, but confirms **egress ping/traceroute** from an authenticated session (network abuse). |

**Lower priority for injection:** pure FQDNs without metacharacters (e.g. **`google.com`**) — they validate and resolve cleanly; risk is abuse of diagnostics, not shell breakout, unless the charset table at runtime is broken.

There is **no dedicated reject** of shell metacharacters beyond the **`gp+0x40`** pair list and “must parse as IP or resolve via DNS.”

## Command execution — shell injection surface

**Ping, traceroute, and continuity test** in `librgw_compat` build a shell command with **`snprintf`**, then run it with **`popen(..., "r")`** (MIPS **`jalr`** to **`popen`** in `tw_ulib_diags_ping` @ `0x0005c5bc`, same pattern in **`tw_ulib_diags_traceroute`** @ `0x0005d928`).

The **hostname** (and numeric options) are concatenated into that command buffer before `/bin/sh -c` style execution.

**Ping command fragments** (`.rodata`, firmware **11.5.1.532678** `librgw_compat`): base tool name + **` -c %d`** (count) + **` -s %d`** (pkt len) + **` -4`** + **` %s 2>&1`** — the **user hostname is the final `%s` before shell redirect**, not the first argument. Option injection as the whole “hostname” is harder than a trailing **`;cmd`** after a parsable IP or resolvable name.

**Traceroute** uses **`traceroute`** + **` -q %d`** + **` -s %s`** (hostname as **string** source option) + similar **`popen`** pattern — metacharacters in **`%s`** are the relevant case there.

**DNS query** path uses resolver / formatting APIs (`tw_ulib_diags_dnsquery` @ `0x0005de14`) — no `popen` in the decompiled body.

### Risk assessment

| Issue | Severity | Notes |
|-------|----------|-------|
| **Classic `HOSTNAME` command injection** | **Medium (latent)** | Design is **unsafe-by-pattern** (`popen` + string concat). Practical exploit requires a hostname that (a) passes `verify_address_resolution` and (b) breaks out of the ping/traceroute command line. Literal IPs via `nu_ipaddr_from_str` likely exclude `;|&`. Hostnames must **`getaddrinfo`**-resolve — excludes most shell syntax. **Edge cases** (IDN canonname path, IPv6 zones, resolver oddities) not fully ruled out without black-box tests. |
| **`CMD` injection** | **Low** | Strict whitelist. |
| **`COUNT` / `PKTLEN` injection** | **Low** | Digits-only regex + integer snprintf. |
| **Arbitrary `NAME`/`VALUE` map keys** | **Low** | Extra keys not read by `xci_cmd_nettools_start` diags setup. |
| **CSRF** | **Low–Med** | Nonce on POST; LAN attacker with session can still drive tests. |
| **Auth bypass** | **Low** | Tied to normal web/tech/ACS gates; no unauth path found on this module. |
| **Network abuse** | **Med** | Authenticated user can ping/traceroute arbitrary allowed targets from the CPE (egress scan, DoS toward `COUNT`× targets). Rate limits not verified in this pass. |
| **DNS rebinding / internal scan** | **Med** | Resolved targets may include RFC1918 if resolver returns them; useful for probing LAN from browser-authenticated session. |

**Recommendation (vendor-style):** replace `popen` with `execv` of `/bin/ping` / `/usr/sbin/traceroute` with `argv[]` (no shell), or use `libping` only; pass **binary sockaddr** from `verify_address_resolution`, not the raw UI string.

## Related pages

- **`/diag`** → `PAGE=DIAG0` (broader diagnostics; separate XCI modules).
- [`httpd_endpoints.md`](httpd_endpoints.md) — page inventory.

## Ghidra symbols (quick)

| Symbol | Program | Address |
|--------|---------|---------|
| `xci_cmd_nettools_start` | httpd | `0x0045cdc4` |
| `is_string_pos_int` | httpd | `0x0043ad9c` |
| `verify_address_resolution` | librgw_compat | `0x00059998` |
| `verify_hostname_contents` | librgw_compat | `0x000559b4` |
| `tw_getaddrinfo` | librgw_compat | `0x00095400` |
| `nu_ipaddr_from_str` | libnetutil | `0x00004e54` |
| `tw_ulib_diags_ping` | librgw_compat | `0x0005c128` |
| `tw_ulib_diags_traceroute` | librgw_compat | `0x0005d36c` |
| `tw_ulib_diags_dnsquery` | librgw_compat | `0x0005de14` |
| `tw_ulib_diags_continuitytest` | librgw_compat | `0x0005cc28` |
