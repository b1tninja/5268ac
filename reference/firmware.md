# Firmware delivery and software baseline

Carrier **`pkgstream`** layout, a sample downloaded bundle, **Linux** baseline, and **boot / upgrade** behaviour from **`fwupgrade.txt`**.

## Firmware delivery (high level)

Official updates often ship as **`.pkgstream`** / install packages; this repo may contain extracted streams or references under versioned directories (e.g. `firmware_*`).

## Carrier firmware index (`pkgstreams`)

The file **[`pkgstreams`](pkgstreams)** is a **plain-text catalog** of paths on AT&T’s historical gateway CDN **`gateway.c01.sbcglobal.net`**: **one logical URL per line**, without an `http://` or `https://` prefix (scripts and **[`binwalker/resolver.py`](binwalker/resolver.py)** prepend **`https://`** when downloading).

**S3 backend:** objects live in bucket **`ecouverseprodeast-firmware`** (account `601471275036`), served via **CloudFront** `d3s4wzxismc942.cloudfront.net`. **`s3:ListBucket` is denied** for anonymous callers and for IAM user **`vcdn`**; **GET of known keys via the gateway hostname still works**. See **[`gateway_s3_bucket.md`](gateway_s3_bucket.md)**.

Canonical **path layout**:

```text
https://gateway.c01.sbcglobal.net/firmware/{device_code}/{release_dir}/…/<artifact>
```

| Segment | Role |
|---------|------|
| **`firmware`** | Fixed prefix for this CDN tree. |
| **`device_code`** | Six-character **hex** id (examples from this repo’s list: **`00D09E`**, **`001E46`**). It **groups product families and packaging conventions**, not a single retail model. **`00D09E`** entries include Pace-class **`.install.pkgstream`** builds (**5268**, **5168**, **5031**, etc.) plus **`att_*.pkgstream`** / CMS **`.xml`**; **`001E46`** entries include Motorola **NVG510/589/599**, **BGW210**, **`.bin` + XML** bundles, and related lines. |
| **`release_dir`** | One directory per **listed firmware build**. **Pace / pkgstream** lines often use **`{major}.{minor}.{patch}.{6-digit}-PROD`** (e.g. **`11.5.1.532678-PROD`**). **Older NVG-style** dirs often encode model + vendor string (**`589_9.1.6h1d20`**, **`510_9.1.0h9d55`**), **`BGW210-700_…`**, **`7.8.7r26`**, or **`presigned`** / **`cferom`** variants—same top-level **`device_code`**, different naming scheme per board age. |
| **`…`** | Optional extra path segments. Some Pace builds expose **`att_*.pkgstream`** both at the **`release_dir`** root and under a **`fie/`** subdirectory (same package family, duplicate layout). Other rows use **`5268-xxxxx-prod`**-style hyphenated blobs or **`att_unified_*`** names—still under the same **`release_dir`**. |

**Artifacts** at the leaf are what identify the payload: **`5268.install.pkgstream`** / **`5031.install.pkgstream`**, **`att_config.pkgstream`**, **`att_cms-certs.pkgstream`**, **`att_unified_eapol-certs.pkgstream`**, companion **`CMS*…*.xml`** or **`ECO*…*.xml`**, or **standalone `*.bin`** images on legacy lines.

**Quirk:** a few scraped lines split the URL with a **space** after **`device_code/`** (e.g. `…/00D09E/ 10.5.3…`); remove the space before requesting the object.

**Tooling:** use **`python -m binwalker analyze <flash>`** (or **`scan`** / **`mtd-scan`**) to tie **dump-derived version strings** to **`pkgstreams`** URLs via **[`BinWalkerAnalyzer`](binwalker/analyzer.py)** / **[`URLResolver`](binwalker/resolver.py)**. **`python -m binwalker download`** / **`download-all`** were **removed** from the binwalker CLI — acquire artifacts manually under **`firmware_*`** and verify **`.pkgstream`** with **`python -m lib2spy.pkgstream`**. Root **`firmware_downloader.py`** remains a thin shim over **`binwalker.downloader`** for old scripts only.

## Downloaded carrier bundle (`firmware_11.5.1.532678/`)

This tree is a **local copy** of **`11.5.1.532678`** artifacts for **5268**, grouped under **`device_code` `00D09E`** and release dir **`11.5.1.532678-PROD`** (see matching lines in **[`pkgstreams`](pkgstreams)**).

**Layout (relative to repo root)**

| Path | Size (bytes) | Role |
|------|--------------:|------|
| [`firmware_11.5.1.532678/11.5.1.532678/install_package/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream`](firmware_11.5.1.532678/11.5.1.532678/install_package/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream) | 32,108,309 | Main **lightspeed install** `.pkgstream` (largest payload). |
| Same directory: [`…install.pkgstream.md`](firmware_11.5.1.532678/11.5.1.532678/install_package/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream.md), [`…install.pkgstream.json`](firmware_11.5.1.532678/11.5.1.532678/install_package/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream.json) | — | [Binwalk](https://github.com/ReFirmLabs/binwalk) **v3** scan (Docker **`binwalk:v3`**, `--log`): agent-oriented **`.md`** plus machine **`json`**; offsets are **relative to this file**, not whole-flash addresses. |
| [`…/cms_certs/att_cms-certs.pkgstream`](firmware_11.5.1.532678/11.5.1.532678/cms_certs/att_cms-certs.pkgstream) | 2,919 | CMS certs stream. |
| [`…/config/att_config.pkgstream`](firmware_11.5.1.532678/11.5.1.532678/config/att_config.pkgstream) | 142,799 | Config stream. |
| [`…/eapol_certs/att_unified_eapol-certs.pkgstream`](firmware_11.5.1.532678/11.5.1.532678/eapol_certs/att_unified_eapol-certs.pkgstream) | 18,920 | Unified EAPOL certs stream. |

**Canonical CDN paths** (same objects as in **`pkgstreams`**; prepend **`https://`** when fetching):

```text
gateway.c01.sbcglobal.net/firmware/00D09E/11.5.1.532678-PROD/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream
gateway.c01.sbcglobal.net/firmware/00D09E/11.5.1.532678-PROD/5268-11.5.1.532678-PROD-C/att_cms-certs.pkgstream
gateway.c01.sbcglobal.net/firmware/00D09E/11.5.1.532678-PROD/5268-11.5.1.532678-PROD-C/att_config.pkgstream
gateway.c01.sbcglobal.net/firmware/00D09E/11.5.1.532678-PROD/5268-11.5.1.532678-PROD-C/att_unified_eapol-certs.pkgstream
```

Duplicate **`fie/`**-prefixed URLs for the three smaller streams appear in **`pkgstreams`** as well (same package family, alternate path).

**Binwalk summary (install `.pkgstream` only):** signature hits include **two SquashFS 4.0 (xz)** blobs, a **uImage** **MIPS32** Linux multi-file image named **`Install image (5268/att)`** (**gzip** payload), **2Wire / AT&T** copyright text, and multiple **PEM** regions — see the **`.md`** for decimal/hex offsets and sizes. Treat these as **embedded-signature** clues; they do **not** replace MTD carving (**[`mtd_parts/`](mtd_parts/)**, **`partition-map`** — **[tools.md](tools.md)**).

- **Runtime:** Kernel logs and strings in captured images refer to **OpenWrt-like** or **buildroot** hostnames, **U-Boot**-passed bootargs, and **MTD**-backed storage.
- **Retail vs. BSP naming:** The **5268AC** / operator image labels (e.g. **Install image (5268/att)**) coexist with bootloader strings such as **BOARD: Pace Broadcom BCM63168D0**, **CPU: BCM63268**, kernel **`chipId 0x631680D0`**, and a vendor **Board Id** line—useful when reconciling TSOP dump labels with serial logs; one worked example is summarized under **Boot / upgrade trace** below.

Using **`.pkgstream`** blobs as **anchors** for flash correlation requires matching sizes/metadata — see **[issue.md](issue.md)**.

## Linux kernel baseline (`3.4.11-rt19`)

On full-flash **`signals-scan` / `full-scan`** runs, Pace-class images commonly surface printk text matching **`Linux version 3.4.11-rt19`** (often alongside **gcc 4.6.x** and **Buildroot 2011.x** hostname hints such as **`buildbot@krackel`**). The **released** upstream tree for that **`PREEMPT_RT`** version is **`linux-stable-rt`**, exactly as advertised in the RT release notes:

```text
git://git.kernel.org/pub/scm/linux/kernel/git/rt/linux-stable-rt.git
Head SHA1: 78475c9d785a6d7b3d110e8ebcc9a4d6f1ff473b
```

That commit is **`Linux 3.4.11-rt19`** (full merged kernel tree, not a bare patch quilt). HTTPS mirror: [`https://git.kernel.org/pub/scm/linux/kernel/git/rt/linux-stable-rt.git`](https://git.kernel.org/pub/scm/linux/kernel/git/rt/linux-stable-rt.git)

**Related:** **[`3.4-rt-patches` · tag `3.4.11-rt19`](https://kernel.googlesource.com/pub/scm/linux/kernel/git/paulg/3.4-rt-patches/+/refs/tags/3.4.11-rt19)** is the complementary **quilt-series** PREEMPT_RT stack (individual patches under `patches/`), useful when you want patch-by-patch diffs rather than browsing the merged tree.

A retail BSP still differs: it is roughly **Linux 3.4.11-rt19** (as above or equivalent) plus **Broadcom / gateway vendor deltas**.

**Local merged tree** (optional; shallow checkout of that HEAD only — fast, detached HEAD):

```bash
git init linux-stable-rt-3.4.11-rt19 && cd linux-stable-rt-3.4.11-rt19
git remote add origin https://git.kernel.org/pub/scm/linux/kernel/git/rt/linux-stable-rt.git
git fetch --depth 1 origin 78475c9d785a6d7b3d110e8ebcc9a4d6f1ff473b
git checkout FETCH_HEAD
```

**Patch quilt only** (optional):

```bash
git clone --depth 1 --branch 3.4.11-rt19 \
  https://kernel.googlesource.com/pub/scm/linux/kernel/git/paulg/3.4-rt-patches \
  linux-3.4-rt-patches-3.4.11-rt19
```

Nothing here is a substitute for the vendor’s documentation or support; it reflects **observed strings and binaries** from dumps and public reverse-engineering practice.

## Kernel modules

The **Lightspeed `11.5.1.532678`** install payload (and related carrier streams under the same release) ship a **Broadcom / Pace BSP** on **Linux 3.4.11-rt19** with many **out-of-tree loadable modules** (ELF **`.ko`**). They normally live on the **read-only SquashFS** dissected from **`.pkgstream`** (not as loose files in this repo unless you have extracted trees under **`work_tl_crc/`**).

**Finding paths:** index or grep the dissect corpus with **`tools/squashfs_corpus_grep.py`** and collection **`firmware_11.5.1.532678/11.5.1.532678`** — see **[`tools.md`](../tools.md)** and the **squashfs-corpus-index** skill ([`../.cursor/skills/squashfs-corpus-index/SKILL.md`](../.cursor/skills/squashfs-corpus-index/SKILL.md)). ELF **`.ko`** entries are indexed like **`.so`** binaries (symbols / strings). For **Ghidra**, import the resolved on-disk path via **ghidra-mcp** **`/import_file`** and always pass the firmware-style **`program`** path from **`/list_open_programs`** — see **ghidra-mcp-corpus** ([`../.cursor/skills/ghidra-mcp-corpus/SKILL.md`](../.cursor/skills/ghidra-mcp-corpus/SKILL.md)).

The table below is a **single baseline checklist** of vendor modules that appear in this RE scope (names as in the image; **subsystem labels are descriptive**, not formal ABI guarantees).

| Module | Typical role (high level) |
|--------|-------------------------|
| **`adsldd.ko`** | ADSL / DSL datapath (Broadcom); **`adsldd`** appears in kernel printk on this family. |
| **`bcm_bpm.ko`** | Broadcom buffer / packet manager–class support (BSP naming). |
| **`bcm_enet.ko`** | Ethernet driver / NAPI path for on-SoC switch / PHY stack. |
| **`bcm_ingqos.ko`** | Ingress QoS / marking (Broadcom gateway stack). |
| **`bcm_usb.ko`** | USB host/device glue for BCM USB blocks. |
| **`bcmarl.ko`** | ARL / L2 address learning or forwarding helper (switch dataplane). |
| **`bcmfap.ko`** | FAP (flow accelerator processor) offload / co-processor interface. |
| **`bcmvlan.ko`** | VLAN filtering / tagging in the BCM fastpath. |
| **`bcmxtmcfg.ko`** | XTM (DSL / ATM / PTM) **configuration** / link-type plumbing. |
| **`bcmxtmrtdrv.ko`** | XTM **runtime** / fastpath driver (pairs with **`bcmxtmcfg`**). |
| **`chipinfo.ko`** | SoC / chip ID export to userspace or late **`/proc`** style hooks. |
| **`conntrack_pace_ror.ko`** | Conntrack integration with **PACE** “RoR” / pacing extensions. |
| **`dect.ko`** | DECT base / radio stack (cordless). |
| **`dectshim.ko`** | Shim between DECT core and VoIP / telephony userspace. |
| **`dpicore.ko`** | Deep packet inspection / inspection engine core (operator class). |
| **`endpointdd.ko`** | Endpoint / voice-line device driver (BSP). |
| **`nciTMSkmod.ko`** | TMS / test & measurement kernel hooks (**`nci`** prefix in-tree naming). |
| **`pace_flowmgr.ko`** | **PACE** flow manager (QoS / session steering). |
| **`pace_tai.ko`** | **PACE** time / accounting / interval logic (TAI). |
| **`pacebattery.ko`** | **PACE** battery / UPS / power-fail telemetry (if equipped). |
| **`pcmshim.ko`** | PCM / voice-sample path shim (telephony). |
| **`pktflow.ko`** | Fastpath packet flow / offload orchestration (often interacts with **`wl`**, **`bcm_enet`**). |
| **`pwrmngtd.ko`** | Power management daemon kernel side (suspend / clocks / cpufreq hooks). |
| **`tdts.ko`** | Vendor kernel helper (BSP abbreviation **`tdts`**; role confirmed via strings / symbols in Ghidra). |
| **`wfd.ko`** | **Wi‑Fi Direct** ( **`wfd`** ) support alongside fullmac **`wl`**. |
| **`wl.ko`** | Broadcom **wireless fullmac** driver (primary 802.11 datapath on this class). |
| **`wlcsm.ko`** | Wireless **CSM** / coexistence / channel survey module. |
| **`wlemf.ko`** | Wireless **EMF** / regulatory / energy-related extension module. |

**Related in this repo:** kernel load / **`prom_init`** / OpenTL driver notes — **[`prom_init_ghidra.md`](prom_init_ghidra.md)**, **[`opentl_kernel_ghidra.md`](opentl_kernel_ghidra.md)**; modules depend on the **same vmlinux** export for unresolved kernel symbols when analyzed in isolation.

## Boot / upgrade trace (`fwupgrade.txt`)

The file **`fwupgrade.txt`** is a single **captive serial capture** (userspace shutdown through U-Boot into a recovery/install kernel and early upgrade steps). Bullets below are **observed there**, not guaranteed on every build. **Hardware** and **NAND** excerpts live in **[hardware.md](hardware.md)** (Boot log section).

### Stack: raw NAND → MTD → OpenTL → TL slices

1. **`mtdparts=mtd-0:524288(loader),1048576(mtdoops),-(tlpart)`** appears as U-Boot “Fixed up MTD partition” and again on the **Kernel command line** with **`cmdlinepart`** / printk ranges matching **`loader` / `mtdoops` / `tlpart`**.
2. **`tlpart`** is mapped from **`0x00180000`** to the end of flash (the large MTD slice **`binwalker`** parses as **tlpart**).
3. **OpenTL** mounts **`tlpart`** as a TL disk. U-Boot **`nflaattach`** (**`fwupgrade.txt`** ~223) reports **`pages per unit=64 shift=17 sectors_per_page=4`** → **one TL unit = one 128 KiB erase block** = **256 × 512-byte sectors**. **`TL_debug`** / **`nand_geom`** (**~224–231**) show **~1012 raw virtual blocks**, **30** reserved for **bad blocks**, **1** **stats** block → **982** blocks usable, **`cap=0x0003D4FC (251132)`** sectors, **`cyl=980 nhead=16 nsectors=16`**. Kernel **`tldisk_partition`** / **`parse_bsd`** (**~490–505**) parses the **tldisk header** and emits four **`parse_bsd: Partition …`** lines matching U-Boot’s disklabel probe (**~236–240**):
   - **`8`/`80`**, type **`0x1d`** → **`opentla1`** env primary  
   - **`88`/`80`**, type **`0x1d`** → **`opentla2`** env backup  
   - **`108`/`78`**, type **`0x1c`** → **`opentla3`** (small slice)  
   - **`180`/`3c080`**, type **`0x11`** (**BSD `FS_EX2FS`**) → **`opentla4`** (**ext2**, **`e2fsck`** **~604**)
4. **Env fingerprint:** both env slices report **`CRC=972f0f3`** / **`env_size=65531`** and duplicate **`bootcmd=…`** hex (**~246–248**) — useful **per-build** anchor when searching raw **`tlpart.bin`**.

Interpreting OpenTL inside **`tlpart`** for offline dumps (dump layout, BBM, disklabel search) is **[issue.md](issue.md)**.

### U-Boot boot target inside TL

- TL probing reports **five “partitions”** in the disklabel sense; the log then uses **`opentl0, partition 5`** (sector **`384`–`245888`**, **`512`**‑byte sectors)—tens to low‑hundreds of MiB class volume for the installer tree.
- FAT-style directory listing on that volume includes **`sys1`**, **`pkg`**, **`config`**, **`cm`**, **`tmp`**, **`lost+found`**, **`.upgrade`**—U-Boot loads **`/sys1/uImage`** from there for the **ATT install/recovery** path.

### Install image and initrd

- U-Boot verifies a **Legacy / multi-file gzip** image **`Install image (5268/att)`**: **MIPS Linux kernel** (~2.6 MiB) **plus** second payload (~989 KiB) used as **initial ramdisk**.
- **`Unable to read "/sys1/initrd"`** can appear even when the **initrd is embedded in the multi-file image**—absence of a standalone `/sys1/initrd` file is not proof there is no ramdisk.

### uImage header (`ih_*`) and 010 Editor templates

Carved **`uImage`** blobs (from **`tlpart`**, **`.pkgstream`**, or Binwalk **`carve`**) begin with U-Boot’s legacy **`image_header`** (**64 bytes**, big-endian fields): magic **`IH_MAGIC`** **`0x27051956`** (bytes **`27 05 19 56`**), **`ih_os` / `ih_arch` / `ih_type` / `ih_comp`**, **`ih_size`**, load/entry/CRCs, and a NUL-terminated **`ih_name`** (32 bytes). The string **`Install image (5268/att)`** in Binwalk output is exactly **`ih_name`** on this family.

SweetScape **`OpenWRT-BIN.bt`** declares the same **ID bytes `27 05 19 56`** so it aligns with the **start of a legacy uImage**; that template also scans for optional **SquashFS** (`hsqs`) and **`DEADC0DE`** tails. **Kernel-only** carves (no embedded rootfs in the same file) will not exercise those branches—use a dedicated uImage view or **`dumpimage`** for **multi-file** payloads.

**In-repo tooling:** **`python -m binwalker uimage-header <file> [--offset N]`** prints decoded **`ih_*`** fields; **`carve`** writes **`carve_summary.md`** with a **Legacy uImage headers (parsed)** section when **`uimage`** hits exist (see **[`binwalker/README.md`](binwalker/README.md)**).

### Filesystems and upgrade behavior

- Early kernel brings up **`squashfs`** (typical **read-only root** stack).
- **`e2fsck`** runs on **`/dev/opentla4`** (ext family) after an unclean shutdown; **at least one TL-exposed volume** is **ext[234]**, not UBIFS/JFFS for that slice.
- Running system (pre-reboot) touched **`/rwdata/sys2/version.txt`**, **`pkg_util_set_pkgmgr_pkg_state`**, **Deferred upgrade file download successful**—writable **`/rwdata`** and package manager state **alongside** **`tlpart`**-resident layout.
- During install: **`mtdoops is mtd1; clearing old logs`**—**`mtdoops`** is **MTD partition 1**, scrubbed as flash is rewritten.

For automated string correlation on a **`.BIN`**, use **`python -m binwalker full-scan`** — see **[tools.md](tools.md)**; this log is the human-readable **ground truth** for how the same strings line up during a real **reboot-for-upgrade**.

## Kernel ELF Ghidra (5268 install package carve)

The **`vmlinux-to-elf`** reconstruction and BCM63xx **`prom_init`** / OpenTL driver notes live outside this file: **[`prom_init_ghidra.md`](prom_init_ghidra.md)**, **[`opentl_kernel_ghidra.md`](opentl_kernel_ghidra.md)**, **[`opentl.md`](opentl.md)** ( **`opentla*`** Mermaid diagrams in §2.1 ).
