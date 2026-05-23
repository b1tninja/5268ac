# Flash credentials: `sysinit/etc` shadow (opentla4)

PACE / **`paceflash`** reads on **OpenTL partition 17 (`opentla4`)** expose a persistent ext2 tree including **`sysinit/`** (valid dirents — see [`ghidra_ext2_cm_cmdb_kernel_mcp.md`](ghidra_ext2_cm_cmdb_kernel_mcp.md) block compare vs opaque **`/cm`**). Under **`sysinit/etc/`** the standard Buildroot-style **`passwd`**, **`shadow`**, and backup siblings **`passwd-`**, **`shadow-`** are readable from a dump.

This is **orthogonal** to **CMDB** (`/rwdata/cm` XML) and **web admin** passwords (`httpd` → **`tw_ulib_pwd_*`** on CM OIDs). See [`cmdb_security.md`](cmdb_security.md).

## What was recovered (lab dump, May 2026)

| File | Role |
|------|------|
| `sysinit/etc/shadow` | Live password hashes for Unix accounts |
| `sysinit/etc/passwd` | Account names / shells (pair with shadow) |
| `shadow-` / `passwd-` | **Backup** copies from `pwconv`/`shadow` utilities — may retain **older** hashes after a password change |
| `grotp` | Present in same directory; purpose not confirmed in RE pass — inspect locally |

Example layout (redacted):

```text
root:$6$<salt>$<sha512-crypt-hash>:<lastchange>:0:99999:7:::
bin:*:...
daemon:*:...
...
default:*:...
```

Only **`root`** carries a real **`$6$`** hash; other entries use **`*`** (locked, no crackable secret).

## Hash format and offline cracking

| Field | Meaning |
|-------|---------|
| **`$6$`** | **SHA-512 crypt** (`crypt(3)` / glibc), default for modern Buildroot/uClibc roots |
| **Salt** | 16-character salt between 2nd and 3rd `$` (visible in dump — speeds targeted cracking) |
| **Hash body** | Base64-like digest after 3rd `$` |
| **lastchange `19781`** | Days since Unix epoch → password last set ~2024 on this unit (metadata only) |

**Offline attack (authorized lab only):**

- **hashcat** mode **1800** (`sha512crypt $6$`)
- **John** format `sha512crypt`
- Wordlists + rules (carrier default passwords, `2wire`, serial-derived patterns, leak reuse)
- Compare **`shadow-`** if present — may be an older hash if root password was rotated

**Do not** publish cracked passwords or full hashes in repo docs/commits.

Cracking succeeds only if the chosen root password has **low entropy**. Strong random passwords leave the hash as a slow offline nuisance, not instant compromise.

## Security impact

| Scenario | Impact |
|----------|--------|
| **Stolen / dumped flash** | Attacker obtains **root password hash** without network access |
| **Weak root password** | Offline crack → **Unix root** on box (SSH/shell/login paths that use `/etc/shadow`) |
| **Password reuse** | Same root password as **web admin**, **SSH**, or **another CPE** → one crack, many surfaces |
| **Fleet default** | If factory or provisioning sets a **predictable root password**, all dumps share one hash prefix pattern — compare salts across units |
| **Backup files** | **`shadow-`** may crack to an **older** password still valid elsewhere |

**Does not automatically unlock:**

- **Web UI** (`httpd`) — uses **`tw_ulib_pwd_auth`** / CM **`user`** table ([`cm_cmdb.md`](cm_cmdb.md)), not `shadow` directly
- **BDC `pull_passwd`**, **`root_rsa`**, Wi‑Fi keys — CMDB XML ([`cmdb_security.md`](cmdb_security.md))
- **Dropbear host keys** — separate files under **`/rwdata/dropbear/`** (flash strings); host key ≠ password

**May unlock (if enabled on product):**

- **`/usr/sbin/dropbear`** (SSH) if **password auth** is on and maps to Unix `root`
- **Serial / debug shell** if it validates against PAM/shadow
- Any init script that runs **`su`** / **`login`** against libc crypt

## Hardening / assessment checklist

1. Extract with **`-o`** (see [`paceflash.md`](paceflash.md)) — avoid corrupting binary copies.
2. Parse **`passwd`** + **`shadow`** + **`shadow-`**; note whether **`root`** is the only `$6$` entry.
3. Lab-only crack with hashcat/John; record **entropy class** (weak/default/strong), not the plaintext in git.
4. Cross-check: CMDB **`user`** / web passwords vs cracked root (reuse?).
5. Check **`/rwdata/dropbear/`** and **`qcsapi_telnet_enable`** exposure if pivoting from root hash to remote access.

## See also

- [`security.md`](security.md) — threat framing
- [`cmdb_security.md`](cmdb_security.md) — CMDB / flash XML secrets
- [`paceflash.md`](paceflash.md) — opentla4 extract
- [`ghidra_ext2_cm_cmdb_kernel_mcp.md`](ghidra_ext2_cm_cmdb_kernel_mcp.md) — `sysinit` ext2 block proof
