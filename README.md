# PACE 5268AC (Pacer) — gateway firmware notes

This repository collects research and tooling related to **AT&T-branded Pace / Arcadyan gateways** centered on the **5268AC** family: hardware identifiers (e.g. flash dumps labeled **PACE 5268AC**), **Linux-derived firmware**, and NAND layout as inferred from strings, dumps, and analysis scripts.

**Correlation strategy (carrier bundle vs flash snapshot):** a downloaded **`.pkgstream`** is treated as a **content corpus**—not assumed to match a TSOP **`tlpart`** dump byte-for-byte. Binwalk metadata often shows **different SquashFS / `uImage` generations** (sizes, dates) between install bundles and NAND; the workflow is **partial overlap**: carve slices from **`pkgstream`**, **`unsquashfs`**, then search **`tlpart.bin`** for shared file fragments as **anchors** and interpret hit clusters (alignment, duplicate offsets). See **[reference/issue.md](reference/issue.md)** (hypothesis: recovery vs installed skew) and **[reference/tools.md](reference/tools.md)** (`pkgstream-slices`, `tl-crc-index` / `tl-crc-scan`, **`python -m corpus`** / **`tools/squashfs_corpus_grep.py`**).

**Generated artifacts** default under **`output/`** at the repo root (override with env **`OUTPUT_DIR`**). See **`opentl.paths`**.

## Install

From the repo root:

```bash
pip install -e ".[dissect,shell,eapol,dev]"
```

See **[pyproject.toml](pyproject.toml)** for optional extras (`dissect` for ext2/squashfs, `shell` for `paceflash shell` on Windows, `eapol` for PKCS#12 tooling).

## Subprojects

Offline stack (bottom → top): **[reference/layers_unand_uboot_opentl_boardfs_paceflash.md](reference/layers_unand_uboot_opentl_boardfs_paceflash.md)** — mermaid map of how packages connect.

| Package | Source | Documentation |
|---------|--------|----------------|
| **`unand`** | [`unand/`](unand/) | **[unand/README.md](unand/README.md)** — NAND dump layout, **128 MiB** logical data plane, **`mtdparts=`** on main bytes only |
| **`uboot`** | [`uboot/`](uboot/) | **[reference/boot_and_storage.md](reference/boot_and_storage.md)** — boot chain; **[reference/boot_environment_trust_eng.md](reference/boot_environment_trust_eng.md)** — env / `bootcmd` / paramtool |
| **`opentl`** | [`opentl/`](opentl/) | **[reference/opentl.md](reference/opentl.md)** — OpenTL / `opentla*` / U-Boot paths; **[opentl/driver/README.md](opentl/driver/README.md)** — driver-facing helpers |
| **`boardfs`** | [`boardfs/`](boardfs/) | **[reference/boardfs.md](reference/boardfs.md)** — `FsRegistry`, BBM attach, ext2 assembly |
| **`paceflash`** | [`paceflash/`](paceflash/) | **[reference/paceflash.md](reference/paceflash.md)** — CLI: `python -m paceflash` (`ls`, `cat`, `shell`, `paramtool`, …) |
| **`lib2spy`** | [`lib2spy/`](lib2spy/) | **[reference/pkgstream.md](reference/pkgstream.md)** — `.pkgstream` / LIB2SP layout; **[reference/pkgstream_security.md](reference/pkgstream_security.md)** — verify / trust |
| **`reference/`** | [`reference/`](reference/) | **[reference/README.md](reference/README.md)** — full RE index (Ghidra MCP, security, CMDB, HTTP, …) |

### Other Python packages

| Package | Source | Documentation |
|---------|--------|----------------|
| **`binwalker`** | [`binwalker/`](binwalker/) | **[binwalker/README.md](binwalker/README.md)**; command catalog in **[reference/tools.md](reference/tools.md)** |
| **`corpus`** | [`corpus/`](corpus/) | SquashFS SQLite index — **`python -m corpus`**; see **[reference/tools.md](reference/tools.md)** |
| **`hexdumpy`** | [`hexdumpy/`](hexdumpy/) | Page-oriented hexdump helpers (used by other tools) |
| **`acspy`** | [`acspy/`](acspy/) | **[reference/acspy.md](reference/acspy.md)** — CWMP / ACS client experiments |

### Hardware

| Item | Path |
|------|------|
| **MEC1-108-02** front-panel debug breakout | **[MEC1-108-02/README.md](MEC1-108-02/README.md)** — Samtec socket PCB, gerbers, console cable photos |

## Reference docs (starting points)

Curated entry points under **[reference/](reference/)** (full list: **[reference/README.md](reference/README.md)**):

| Document | Contents |
|----------|----------|
| **[reference/issue.md](reference/issue.md)** | **OpenTL** and **`tlpart`**: anchor-based mapping, pkgstream as corpus, recovery vs installed skew |
| **[reference/hardware.md](reference/hardware.md)** | Platform, **MTD**, **BCMNAND** geometry |
| **[reference/firmware.md](reference/firmware.md)** | Carrier bundles, **Linux 3.4.11-rt19**, **`fwupgrade.txt`** boot trace |
| **[reference/tools.md](reference/tools.md)** | **`binwalker`**, **`nand-translate`**, **`partition-map`**, OpenTL **`tl-*`**, corpus grep |
| **[reference/boot_and_storage.md](reference/boot_and_storage.md)** | ROM → U-Boot → Linux; storage stack diagrams |
| **[reference/kernel_python_regions.md](reference/kernel_python_regions.md)** | `#region kernel: 0x…` markers vs Ghidra exports |

Security / operator surface (also in the index): **[reference/security.md](reference/security.md)**, **[reference/console_uart_disable.md](reference/console_uart_disable.md)**, **[reference/eapol_8021x_p12.md](reference/eapol_8021x_p12.md)**.

## External links

- [Pace 5268AC — WikiDevi (wi-cat.ru mirror)](https://wikidevi.wi-cat.ru/Pace_5268AC)

**Where to start:** **[reference/issue.md](reference/issue.md)** for OpenTL / **`tlpart`** motivation, **[reference/tools.md](reference/tools.md)** for commands, or **[reference/layers_unand_uboot_opentl_boardfs_paceflash.md](reference/layers_unand_uboot_opentl_boardfs_paceflash.md)** for the Python package stack.
