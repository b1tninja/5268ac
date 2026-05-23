# PACE 5268AC — offline firmware research workspace

Research and Python tooling for **AT&T-branded Pace / Arris 5268AC** DSL gateways: **128 MiB NAND** dumps, **OpenTL** translation on **`tlpart`**, carrier **`.pkgstream`** install bundles, and Ghidra-backed notes on **Linux 3.4.x**, **U-Boot**, **lib2sp**, and operator-facing config (**CMDB**, EAPOL, HTTP).

The repo is built around **repeatable offline analysis**—not a single flash-layout hypothesis. You can go from a TSOP capture or a downloaded install carrier to **partition maps**, **assembled `opentla4` ext2**, **verified pkgstream payloads**, and cross-referenced documentation under **[`reference/`](reference/)**.

---

## Hardware (5268AC)

| Item | Detail |
|------|--------|
| **Platform** | Broadcom **BCM63168** (400 MHz, 2 cores) + Quantenna **QT3840** 802.11ac |
| **NAND** | **128 MiB** (primary flash — what this repo models) |
| **RAM** | 256 MiB + 128 MiB (Wi‑Fi side) per board listings |
| **Boot** | **U-Boot** → MIPS Linux; Pace **OpenTL** on **`tlpart`** |
| **Default LAN** | **192.168.1.254** |

**Wiki references**

- **[Pace 5268AC — DeviWiki](https://deviwiki.com/wiki/Pace_5268AC)** (ex WikiDevi mirror: FCC **PGR5200AC**, Foxconn ODM, boot log, specs)
- [Pace 5268AC — WikiDevi (wi-cat.ru mirror)](https://wikidevi.wi-cat.ru/Pace_5268AC)

Stock images on those pages are often **older** (e.g. Linux **2.6.30** in the archived serial log). This workspace’s primary traced build is **11.5.1.532678** (Lightspeed / ATT install path) — see **[`reference/firmware.md`](reference/firmware.md)** and capture **`fwupgrade.txt`**.

---

## What you can do here

```text
  Carrier .pkgstream          TSOP NAND dump (PACE 5268AC … BIN)
         │                              │
         ▼                              ▼
    lib2spy                      unand → opentl → boardfs
  parse / verify / extract              │
         │                              ▼
         └──────── corpus grep ──►  paceflash ls | cat | shell
                                   (opentla4 ext2, paramtool, …)
```

| Goal | Start here |
|------|------------|
| **Explore a flash dump** (directories, CMDB, `sys1/uImage`) | [`paceflash/README.md`](paceflash/README.md) — `python -m paceflash --flash "…BIN" ls` |
| **Understand OpenTL / BBM / `opentla*`** | [`opentl/README.md`](opentl/README.md), [`reference/opentl.md`](reference/opentl.md) |
| **Parse or verify an install `.pkgstream`** | [`lib2spy/README.md`](lib2spy/README.md) — `python -m lib2spy install.pkgstream` |
| **Carve partitions / run binwalk workflows** | [`binwalker/README.md`](binwalker/README.md), [`reference/tools.md`](reference/tools.md) |
| **Serial console hardware** | [`MEC1-108-02/README.md`](MEC1-108-02/README.md) — Samtec **MEC1-108-02** front-panel breakout |

**Generated artifacts** default to **`output/`** (override with env **`OUTPUT_DIR`** before importing **`opentl.paths`**).

**Carrier vs NAND:** a **`.pkgstream`** is a **content corpus** for correlation (SquashFS / `uImage` anchors, string grep)—not assumed byte-identical to a live **`tlpart`** snapshot. See **[`reference/firmware.md`](reference/firmware.md)** and **[`reference/pkgstream_corpus_report.md`](reference/pkgstream_corpus_report.md)**.

---

## Install

From the repo root:

```bash
pip install -e ".[dissect,shell,eapol,dev]"
```

| Extra | Use |
|-------|-----|
| **`dissect`** | ext2 + SquashFS via Dissect (AGPL) |
| **`shell`** | `paceflash shell` tab completion on Windows |
| **`eapol`** | `paceflash dump-eapol-cert` |
| **`dev`** | pytest |

Details: **[`pyproject.toml`](pyproject.toml)**, **[`requirements.txt`](requirements.txt)**.

---

## Python packages

Stack overview (diagram + Ghidra hints): **[`reference/layers_unand_uboot_opentl_boardfs_paceflash.md`](reference/layers_unand_uboot_opentl_boardfs_paceflash.md)**.

| Package | README | Role |
|---------|--------|------|
| **`unand`** | [unand/README.md](unand/README.md) | NAND dump → **128 MiB** logical data plane + spare |
| **`uboot`** | [reference/boot_and_storage.md](reference/boot_and_storage.md) | **`bootargs`** / **`bootcmd`** / **`mtdparts=`** offline |
| **`opentl`** | [opentl/README.md](opentl/README.md) | OpenTL BBM, NTL, **`tl-mount`**, `opentla4` extract |
| **`boardfs`** | [boardfs/README.md](boardfs/README.md) | **`FsRegistry`**, MTD slices, ext2 assembly |
| **`paceflash`** | [paceflash/README.md](paceflash/README.md) | Operator CLI: **`ls`**, **`cat`**, **`shell`**, **`paramtool`**, … |
| **`lib2spy`** | [lib2spy/README.md](lib2spy/README.md) | **`.pkgstream`** parse, PKCS#7 verify, extract |
| **`binwalker`** | [binwalker/README.md](binwalker/README.md) | Carve, **`partition-map`**, pkgstream slices |
| **`corpus`** | [reference/tools.md](reference/tools.md) | SquashFS SQLite index — **`python -m corpus`** |
| **`acspy`** | [reference/acspy.md](reference/acspy.md) | CWMP / ACS experiments |
| **`hexdumpy`** | — | Shared hexdump helpers |

Full RE index: **[`reference/README.md`](reference/README.md)**.

---

## Documentation map

| Topic | Document |
|-------|----------|
| Boot chain, MTD, storage | [reference/boot_and_storage.md](reference/boot_and_storage.md) |
| Boot env, UART, **`gw:trust_engcert`** | [reference/boot_environment_trust_eng.md](reference/boot_environment_trust_eng.md) |
| Carrier CDN, **532678** bundle | [reference/firmware.md](reference/firmware.md) |
| Command cheat sheet | [reference/tools.md](reference/tools.md) |
| **`.pkgstream`** byte layout | [reference/pkgstream.md](reference/pkgstream.md) |
| Security (pkg, CMDB, EAPOL) | [reference/security.md](reference/security.md) |
| Kernel ↔ Python `#region` EAs | [reference/kernel_python_regions.md](reference/kernel_python_regions.md) |

---

## Typical commands

```bash
# Flash dump → ext2 listing
python -m paceflash --flash "PACE 5268AC S34ML01G1@TSOP48.BIN" ls sys1

# Full flash inventory (MTD, BBM, disklabel)
python -m paceflash --flash "PACE …BIN" ls --debug

# Install carrier
python -m lib2spy firmware_11.5.1.532678/5268.install.pkgstream --extract output/_pkg_extract

# OpenTL BBM summary
python -m boardfs virt-map "PACE …BIN" --json
```

Use **`-o`** for binary output on Windows; avoid redirecting **`cat`** with PowerShell **`>`** on CMDB/XML (see [paceflash/README.md](paceflash/README.md)).

---

## Ethics and scope

Work here is intended for **devices you own** or **explicitly authorized** lab use. Extracted CMDB, PKCS#12, and HTTP credentials are **sensitive**—see **[`reference/cmdb_security.md`](reference/cmdb_security.md)** before publishing logs or JSON. Tooling legal notes: **[`reference/tools.md`](reference/tools.md)**.

---

## Where to start

1. **Have a `.BIN` dump?** → **[paceflash/README.md](paceflash/README.md)**  
2. **Have a `.pkgstream`?** → **[lib2spy/README.md](lib2spy/README.md)**  
3. **Need the storage model?** → **[reference/opentl.md](reference/opentl.md)** + **[reference/layers_unand_uboot_opentl_boardfs_paceflash.md](reference/layers_unand_uboot_opentl_boardfs_paceflash.md)**  
4. **Grep everything** → **[reference/README.md](reference/README.md)**
