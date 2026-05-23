# PACE 5268AC (Pacer) — gateway firmware notes

This repository collects research and tooling related to **AT&T-branded Pace / Arcadyan gateways** centered on the **5268AC** family: hardware identifiers (e.g. flash dumps labeled **PACE 5268AC**), **Linux-derived firmware**, and NAND layout as inferred from strings, dumps, and analysis scripts.

**Correlation strategy (carrier bundle vs flash snapshot):** a downloaded **`.pkgstream`** is treated as a **content corpus**—not assumed to match a TSOP **`tlpart`** dump byte-for-byte. Binwalk metadata often shows **different SquashFS / `uImage` generations** (sizes, dates) between install bundles and NAND; the workflow is **partial overlap**: carve slices from **`pkgstream`**, **`unsquashfs`**, then search **`tlpart.bin`** for shared file fragments as **anchors** and interpret hit clusters (alignment, duplicate offsets). See **[reference/issue.md](reference/issue.md)** (hypothesis: recovery vs installed skew) and **[reference/tools.md](reference/tools.md)** (`pkgstream-slices`, `tl-crc-index` / `tl-crc-scan`, **`python -m corpus`** / **`tools/squashfs_corpus_grep.py`**).

**Generated artifacts** default under **`output/`** at the repo root (override with env **`OUTPUT_DIR`**). See **`opentl.paths`**.

## Python packages (repo layout)

| Package | Role |
|---------|------|
| **`hexdumpy`** | Domain-agnostic page hexdump (`PageView`, row formatting). |
| **`unand`** | SoC-facing **NAND data plane**: dump layout, **128 MiB** logical main plane, geometry, optional **4 MiB** spare stream; **`unand.mtd`** parses **`mtdparts=`** on that plane only. |
| **`uboot`** | Offline **`bootargs`** / simple **`bootcmd`** parsing; extracts the **`mtdparts=`** token and defers layout math to **`unand.mtd`**. |
| **`opentl`** | OpenTL on **`tlpart`**: MTD-partition-relative main bytes + spare-sidecar replay (**BBM**, `opentla4` extract, pipeline helpers). **`flash_layout`** resolves **`mtdparts`** (**U-Boot env v1** on the logical plane, then **`mtd-scan`**) for **`partition-map`** / **`carve`**. |
| **`lib2spy`** | 2WIRE `.pkgstream` parse/verify/TLV (`python -m lib2spy`). |
| **`corpus`** | SquashFS corpus SQLite index + grep (`python -m corpus`); `tools/squashfs_*` wrap it. |

Install editable from repo root: `pip install -e ".[dissect]"` (see root **`pyproject.toml`**).

Documentation is split into focused notes under **`reference/`**:

| Document | Contents |
|----------|----------|
| **[reference/issue.md](reference/issue.md)** | **OpenTL** and **`tlpart`**: linear-read limits, **anchor-based** mapping, **pkgstream as corpus** (not identical golden), recovery-vs-installed caveat, **`corpus_interpretation`** in reports. |
| **[reference/hardware.md](reference/hardware.md)** | Platform context, **MTD** patterns, **NAND** / **`BCMNAND`** geometry, **`BCMNAND`** vs upstream **`brcmnand`**, serial-log hardware excerpts. |
| **[reference/firmware.md](reference/firmware.md)** | **`pkgstreams`** CDN layout, downloaded **`firmware_11.5.1.532678/`** bundle, **Linux 3.4.11-rt19** baseline, **`fwupgrade.txt`** boot and upgrade trace. |
| **[reference/tools.md](reference/tools.md)** | **`binwalker`** workflows: **`nand-translate`** / **`nand-spare-extract`** / **`carve --nand-data-mode`** for **5268-class** TSOP packing, **`partition-map`**, OpenTL **`tl-*`** probes, **`pkgstream-slices`** + manifests, **`mtd_parts/`** binwalk summary, repository map, legal / ethics. |
| **[reference/boot_and_storage.md](reference/boot_and_storage.md)** | **Boot chain** (ROM → U-Boot → Linux **`bootargs`**) and **storage / MTD stack** mermaid diagrams; **`unand` / `uboot` / `opentl` / `binwalker`** offline map. |
| **[reference/kernel_python_regions.md](reference/kernel_python_regions.md)** | **`#region kernel: 0x…`** / **`#endregion`** markers in Python: Ghidra EAs, `kernel_adjacent` glue, and how they map to [ghidra_boardfs_bbm_readpath.md](reference/ghidra_boardfs_bbm_readpath.md) / [opentl_kernel_ghidra.md](reference/opentl_kernel_ghidra.md). |

## References

- [Pace 5268AC — WikiDevi (wi-cat.ru mirror)](https://wikidevi.wi-cat.ru/Pace_5268AC)

Start with **[reference/issue.md](reference/issue.md)** for **OpenTL** / **`tlpart`** motivation and corpus strategy, or **[reference/tools.md](reference/tools.md)** for commands first.
