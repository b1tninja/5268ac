# Legal notice — security research use only

This document describes how the **5268ac** repository is intended to be used. It is **not legal advice**. Consult qualified counsel for obligations in your jurisdiction.

---

## Purpose

The **5268ac** workspace exists for **security testing and research** on Pace / AT&T-class residential gateway firmware: NAND and **OpenTL** layout, carrier **`.pkgstream`** install formats, boot environment, configuration stores (**CMDB**), and related operator trust material.

All work here is offered **solely for research and educational purposes**—to understand how devices you control store and update software—not to enable unauthorized access to networks, carrier infrastructure, or equipment belonging to others.

---

## Authorized use

You may use this documentation and tooling only when:

- You **own** the hardware under test, or
- You have **written authorization** from the owner or operator for security research in a defined lab scope, and
- Your activities comply with **applicable law**, contracts, and carrier terms that still bind the device or your account.

Do **not** use outputs from this project to attack production systems, impersonate subscribers, bypass billing or DRM for commercial gain, or violate export or computer-fraud statutes.

---

## DMCA — 17 U.S.C. § 1201

**Section 1201** of the Digital Millennium Copyright Act restricts circumvention of **technological measures** that control access to copyrighted works, and trafficking in circumvention tools.

### What this repository is

- **Documentation** of on-disk and on-wire **formats** (OpenTL, LIB2SP / `.pkgstream`, MTD layout, ext2 paths) derived from reverse engineering and captured logs.
- **Offline software** that operates on **files you supply locally** (NAND dumps, downloaded install carriers you lawfully obtained, carved slices in `output/`).
- **Security research methodology**—integrity verification, structure parsing, correlation between carrier packages and flash snapshots—not a turnkey “unlock” or piracy kit.

### What this repository is not

- A distribution point for **proprietary firmware images**, **bootloader exploits**, or **circumvention devices**.
- An offer to **defeat** technical protection measures on third-party systems you do not own or lack permission to test.
- Legal clearance for any specific act of circumvention; exemptions (including those relevant to **good-faith security research** under U.S. rulemaking) have **conditions**—authorization, scope, disclosure, and class of work—that you must satisfy independently.

Researchers who believe § 1201 exemptions apply to their work should document authorization, minimize circumvention to what is necessary for the research, and follow applicable CFR and case law. **This project does not provide legal clearance.**

---

## Attestation — repository scope

The maintainers state the following about content **in this git repository**:

| Attestation | Detail |
|-------------|--------|
| **Research only** | Committed code and docs describe **analysis and verification** on user-provided inputs. They are not marketed to circumvent operator, carrier, or manufacturer protections on live production fleets. |
| **No disclosure of software protection circumvention technology** | The repo does **not** publish tools whose **primary purpose** is to circumvent access controls or copy-protection measures. Scripts assemble and parse images; they do not ship live exploits against remote services. |
| **No redistribution of copyrighted material** | The project does **not** intend to commit **proprietary firmware binaries**, **decrypted signing keys**, **subscriber credentials**, or other **copyrighted works** as repository artifacts. Build identifiers (e.g. **11.5.1.532678**) appear as **metadata and RE notes**; obtain install carriers and dumps through your own lawful channels. |
| **No circumvention of contractual obligations** | Understanding a format is not permission to violate **terms of service**, **acceptable-use policies**, or **warranty** conditions. Users remain responsible for compliance. |

**Sensitive data** (CMDB XML, PKCS#12, Wi‑Fi or HTTP passwords, factory blocks) may be produced in a local **`output/`** directory, which is **gitignored**. **Do not commit, upload, or publish** those extracts. See [`reference/cmdb_security.md`](reference/cmdb_security.md).

---

## Copyright and third-party marks

**PACE**, **AT&T**, **2Wire**, **Arris**, and related names are trademarks of their respective owners. This project is **not affiliated** with or endorsed by those entities.

References to **DeviWiki / WikiDevi**, **Ghidra**, **Binwalk**, and other third-party projects are for documentation only.

---

## Responsible disclosure

If research on **your own** equipment uncovers vulnerabilities affecting other subscribers or operator infrastructure:

- Report through the vendor or carrier **coordinated disclosure** channel when one exists.
- Avoid testing against **production** ACS, CDN, or authentication endpoints without explicit permission (see [`reference/acspy.md`](reference/acspy.md) dry-run defaults).

---

## Disclaimer of warranty

Documentation and software are provided **“as is”**, without warranty of any kind, express or implied, including accuracy, fitness for a particular purpose, or non-infringement. You assume all risk from use of dumps, extracted credentials, and RE conclusions.

---

## Related documentation

| Document | Topic |
|----------|--------|
| [`README.md`](README.md) | Project overview |
| [`reference/tools.md`](reference/tools.md) | Tooling ethics (short) |
| [`reference/security.md`](reference/security.md) | Attack surface notes |
| [`reference/cmdb_security.md`](reference/cmdb_security.md) | Handling CMDB secrets |
| [`reference/pkgstream_security.md`](reference/pkgstream_security.md) | Package signing and trust |

---

*Last updated: May 2026 — revise when repository scope or distribution model changes.*
