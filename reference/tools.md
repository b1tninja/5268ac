# Tools and repository layout

**`binwalker`** workflows, **MTD carving**, **`mtd_parts/`** summaries, repository index, **`boardfs`** (MTD + OpenTL TL slices + **`ubi.mtd=`** — see **[boardfs.md](boardfs.md)**), and **`paceflash`** (inventory CLI + **`/etc/fstab`** via **`paceflash.fstab`** — **[paceflash.md](paceflash.md)**).

### Carrier corpus vs `tlpart` (manual pipeline)

There is **no** bundled “dissect probe” CLI anymore. Reproduce the same **carrier vs flash** workflow manually:

1. **`python -m binwalker pkgstream-slices`** … **`--unsquash-dissect DIR`** — carve **`.pkgstream`** and (optionally) expand SquashFS slices with **`dissect.squashfs`** into a directory tree.
2. **`python -m binwalker tl-crc-index --corpus-dir DIR …`** then **`tl-crc-scan`** on **`tlpart.bin`** — CRC anchor hits vs corpus files.
3. Optional: **`python -m corpus`** / **`tools/squashfs_corpus_grep.py`** for SQLite-backed string search across dissect trees (see repo skills).

Anchor / alignment **JSON reports** that older docs called **`opentl_analyze_*.json`** were produced by removed research code; keep any historical JSON you still need, but do not expect matching CLI flags.

### NAND logical plane (5268-class TSOP dumps)

For **full-chip** captures such as **`138412032` B** (**`65536 × (2048+64)`**), normalize **before** **`partition-map`**, **`tl-*`** on MTD-relative offsets, or Binwalk over **`tlpart`** slices:

1. **`python -m binwalker nand-translate`** *`PACE … TSOP48.BIN`* **`--out`** *`flash_logical.bin`* **`--mode auto`** — writes **`134217728` B** logical main (**`nand-spare-extract`** or **`--spare-out`** for the **4 MiB** spare stream).
2. **`python -m binwalker nand-oob-inspect --spare spare.bin`** (or **`--flash`** *raw dump*) — JSON audit of **64 B** spare rows (**OpenTL** fields + **`ntl_compute_spare_xsum`**, **`BootCode`** markers); see **[issue.md](issue.md)** **OOB / spare field decode**. Optional **`--spare-chain-replay --chain-length N`** + **`--chain-start-phys`** (head physical erase block) appends **`ntl_put_chain_in_array`** mode-2 hop decode (**`opentl/spare_chain_replay.py`**). Flat spare byte length determines erase-band geometry (**`tl_geometry_from_flat_spare`**); optional **`--virt-block`** labels the JSON report only. To resolve **`--chain-start-phys`** from a saved **`binwalker_tl_bbm_v1`** JSON file, use Python: **`BlockMapBuild.from_dict(json.loads(Path('map.json').read_text(encoding='utf-8'))))`** then **`virt_to_phys_block[i]`** (no binwalker **`--bbm-json`** flag).
3. **`python -m binwalker partition-map`** / **`carve`** on *`flash_logical.bin`* (or **`carve ... --nand-data-mode auto`** on the raw dump to combine translate + Docker Binwalk). **`partition-map`** without **`--mtdparts`** tries **U-Boot env v1** on the **logical** plane (then **`mtd-scan`**); Pace **138412032** B inputs use **128 MiB** remainder math even before normalize, but **linear** **`--extract`** on a raw **inline** file still expects a **logicalized** image—see **`binwalker.extract.flash_layout.FlashImage`**.
4. Optional: **`python -m binwalker carved-pem-export`** on the carve output dir — rewrite **`pem_certificate`** **`*.bin`** hits as **`*.pem`**.

See **[issue.md](issue.md)** **Dump layout** for why **`auto`** may choose **inline** vs **flat-tail** at this envelope size.

### OpenTL physical-layer probes

Implemented **`binwalker`** subcommands aligned with **[issue.md](issue.md)** (**Strategy** / **Dump layout**). **`tl-layout-detect`** scans for **`ELF`** @ **`0x21000`** and **`hsqs`** with an **`hsqs mod 2112`** stride hint — useful corroboration on a chosen file view, but **not decisive** for **`138412032` B** dumps: **flat-tail** and **inline 2048+64** share the same total length, so **`hsqs`** alignment neither proves nor disproves interleaved packing by itself (see **`nand-translate --mode auto`** and **`opentl/nand_translate.py`**).

| Command | Purpose |
|---------|---------|
| **`tl-layout-detect`** *flash.bin* | **ELF** magic check + **`hsqs`** stride heuristic; **`--json`** for machine output. |
| **`tl-disklabel`** *image.bin* | **Whole-disk + four slices** (**`match_kind: chain`**), legacy **four-tuple** only (**`chain4`**), **`first_triple`**, and BSD magic **`0x82564557`** (**`bsd_magic`**). May yield **zero** hits if on-disk layout differs from the **`fwupgrade.txt`** printk model. |
| **`tl-probe`** *flash.bin* | One-shot **JSON**: **`tl-layout-detect`**-style layout summary + **`tl-disklabel`** hit list (**no** env / bootcmd string scan). Former keys **`env_hits`**, **`env_hit_count`**, **`env_primary_backup_pairs`** were removed. |
| **`tl-bbm`** *tlpart.bin* | **`kernel_replay_v1`**: **`--spare`** flat stream + logical image → **`binwalker_tl_bbm_v1`** JSON; **`--logical-prefix-bytes`**, **`--out-json`**, **`--json`**. Raises **`ValueError`** if spare is missing or unusable. |
| **`tl-mount`** *flash.bin* | **`opentl.tl_mount.mount_flash_image`**: **`--spare`** (full flat spare) drives **`kernel_replay_v1`** virt→phys; **`--json`** / **`--out-bbm`**. Raises **`ValueError`** if spare is missing, wrong length, or has no mappable rows. |
| **`opentla4` assembly** (library) | **`import opentl`** exposes **`opentl.driver`**. Assign **`pipeline.bbm`** from **`BlockMapBuild.from_dict(...)`** and **`extract_opentla4(..., auto_build_bbm=False)`**, or **`NandPipeline.build_bbm()`** with a non-empty flat spare on **`spare_path`**. |
| **`tl-crc-index`** | **`--corpus-dir DIR`** (repeatable) **`--windows full,2048,131072`** **`--out-json idx.json`** — build **`binwalker_tl_crc_v1`** (CRC-32 / zlib polynomial over **full file**, **2048 B** pages, **128 KiB** erase windows). |
| **`tl-crc-scan`** *image.bin* | **`--index idx.json`** **`--stride N`** **`--workers N`** **`--gpu`** — sliding-window scan; JSON schema **`binwalker_tl_crc_scan_v1`** with **`backend`** **`cpu`** or **`cuda`**. If **`--gpu`** is set but no CUDA device is available (or the kernel fails), **`notes`** explains the fallback and **`backend`** is **`cpu`**. Install GPU support in your venv (from repo root): **`pip install -e "binwalker[cuda]"`** or **`pip install numba`** (needs an NVIDIA driver when you want **`backend: cuda`**). Optional **`--logical-prefix-bytes`**, **`--out-json`**, **`--json`**. |
| **`tl-bbm-score`** | *Not implemented in this repository* (no CLI); corpus ranking was design-only. |

**Map schema (`binwalker_tl_bbm_v1`):** top-level **`schema`**, **`geometry`** (adds boot-trace fields: **`head_pages`**, **`media_pages`**, **`spares_field`**, **`cap_sectors`**, **`geometry_wasted_sectors`**, **`sectors_per_unit`**), duplicate summary **`boot_trace_invariants`**, **`virt_to_phys_block`**, optional **`stats_physical_block_index`**, **`warnings`**, **`input_sha256_logical_prefix`**, optional **`nand_logical_offset`** (byte offset of **`tlpart`** in **`flash_file`**).

**CRC index (`binwalker_tl_crc_v1`):** **`entries_by_crc`** maps **8-digit lowercase hex** CRC keys to lists of **`{relative_path, file_offset, length, window_kind, …}`**; plus **`stride_page`**, **`stride_erase`**, **`window_kinds`**.

**BBM score (`binwalker_tl_bbm_score_v1`):** reserved schema name only — no scorer shipped in-tree.

```bash
python -m binwalker tl-layout-detect "PACE 5268AC S34ML01G1@TSOP48.BIN" --json
python -m binwalker tl-disklabel "PACE 5268AC S34ML01G1@TSOP48.BIN" --json
python -m binwalker tl-probe "PACE 5268AC S34ML01G1@TSOP48.BIN"

# `--verify-uimage` / `--uimage-ref` below use filenames from `carve_deinterleaved/carve_summary.md`
# after `partition-map`/`carve` on `flash_logical_deinterleaved.bin` (regenerate if missing locally).

# python -m binwalker tl-bbm … exits 2 until kernel replay exists; use BlockMapBuild.from_dict for captured maps.
python -c "from pathlib import Path; from opentl.nand_pipeline import NandPipeline; r=NandPipeline.for_logical_plane('mtd_parts/tlpart.bin').extract_opentla4(dry_run=True); print(r.ext2_magic_ok)"
# Optional: compare headers against a carved reference uImage (see reference/issue.md)
python -c "from pathlib import Path; from binwalker.extract.opentl import extract_opentla4; extract_opentla4(Path('mtd_parts/tlpart.bin'), Path('bbm.json'), out_path=Path('opentla4.ext2'), verify_uimage_path=Path('output/carved_flash/carve_deinterleaved/carved/tlpart_uimage_0x05a45800_24656ebd.bin'))"

python -m binwalker pkgstream-slices .../install.pkgstream --binwalk-json ...pkgstream.json \
  --out ./work/pkgstream_carves --unsquash-dissect ./work/pkgstream_unsquash_dissect
python -m binwalker tl-crc-index --corpus-dir ./work/pkgstream_unsquash_dissect --windows full,2048,131072 --out-json tl_crc_idx.json
python -m binwalker tl-crc-scan mtd_parts/tlpart.bin --index tl_crc_idx.json --stride 131072 --workers 4 --out-json tl_crc_hits.json --json
# Prefer chip carve matching fwupgrade /sys1/uImage size (3740634 B). Older bank at 0x3a71400 is shorter — mis-scores --uimage-ref.
```

**`flash strings.txt` / Ghidra cues** (see **[issue.md](issue.md)** **RE breadcrumbs**): **`TL_debug:`** `mediasize` / `spares` / `head_pages`; **`resetting statsBlock statistics Num Used=…`**; **`kerSysEarlyFlashInit`** early-flash printk; **`BootCode`** **`0x840`** strides in the loader/strings extract vs **`hsqs`** carve checks on the full chip. Spare / OOB field layout is decoded from the dump via **`nand-oob-inspect`** / **`nand-spare-extract`** (see **OOB / spare field decode** in **[issue.md](issue.md)**).

### Host dependencies: legacy `uImage` and **`dumpimage`**

**`python -m binwalker uimage-header`** (see **[`binwalker/README.md`](binwalker/README.md)**) parses the **64-byte** legacy header (**`IH_MAGIC` `0x27051956`**, **`ih_size`**, OS/arch/type/compression enums) and checks header CRC—aligned with U-Boot **`iminfo`** / **`imi`**.

**`IH_TYPE_MULTI`** layout follows U-Boot **`include/image.h`** (big-endian size words terminated by **`0`**, then member blobs with **4-byte** padding between members except after the last). **`python -m binwalker uimage-kernel`** reads that table, extracts member **`0`** (kernel) by default (**`--member N`** for ramdisk etc.), **gunzips** when the member starts with gzip magic, and writes **`{stem}_kernel_load_{ih_load:08x}_ep_{ih_ep:08x}.bin`** next to the input (or **`--out-dir`**). Use **`--no-gunzip`** to keep the raw member (**`.gz`** suffix when gzip magic is present).

```bash
python -m binwalker uimage-header firmware_11.5.1.532678/.../pkgstream_carves/att-5268-..._uimage_....bin --json
python -m binwalker uimage-kernel firmware_11.5.1.532678/.../pkgstream_carves/att-5268-..._uimage_....bin --json
```

**`dumpimage`** from **`u-boot-tools`** remains useful for cross-checks and odd layouts; example on a flash carve:

```bash
dumpimage -l "output/carved_flash/carve_deinterleaved/carved/tlpart_uimage_0x05a45800_24656ebd.bin"
# dumpimage -i <uImage.bin> -T kernel -f kernel.bin
```

On **Windows**, **`uimage-kernel`** needs only Python; **`dumpimage`** is easiest via **WSL2** or a Linux VM.

Header parsing and multi splitting are regression-tested with **`pytest binwalker/tests/test_uimage.py`**.

### `vmlinux-to-elf` — kernel symbol recovery for Ghidra/IDA

[`marin-m/vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf) reconstructs a fully-analyzable **`.elf`** (with **`.symtab`**) from a raw kernel binary by parsing the kernel's embedded **`kallsyms`** table. Run it on the **gzip-peeled kernel member** produced by **`binwalker uimage-ghidra`** / **`uimage-kernel`**, **not** the legacy uImage container or the ramdisk member. Auto-detects XZ / LZMA / GZip / BZ2 / LZ4 / LZO / Zstd compression, MIPSEL/MIPSEB/ARMEL/ARMEB/PowerPC/SPARC/x86/x86-64/ARM64/MIPS64/SuperH/ARC, and the kernel base address — overrides are usually unnecessary.

Sibling clone keeps it shareable across firmware projects:

```bash
git clone https://github.com/marin-m/vmlinux-to-elf.git D:\github\marin-m\vmlinux-to-elf
.venv\Scripts\python.exe -m pip install -e D:\github\marin-m\vmlinux-to-elf
```

Pulls **`lz4`**, **`zstandard>=0.25`**, **`minilzo>=1.2`**, **`peewee>=3.17`** (Python ≥ 3.9; tested on the workspace's 3.14 venv). On Windows **`minilzo`** builds from sdist using the same MSVC build tools the workspace already requires.

**Three commands** are exposed (all under `.venv\Scripts\`):

| Command | Purpose |
|---|---|
| **`vmlinux-to-elf`** *kernel.bin* *kernel.elf* | Produce the analyzable ELF. |
| **`kallsyms-finder`** *kernel.bin* | Print `/proc/kallsyms`-style symbol list (`nm`-like). |
| **`vmlinuz-decompressor`** *in* *out* | Standalone decompressor when only the inner payload is wanted (useful when chaining with **`binwalker uimage-kernel --no-gunzip`**). |

Typical run on the **5268-class** kernel carve (Linux **3.4.11-rt19**, MIPS32 BE, load `0x80010000`, entry `0x80458130`):

```bash
$carves = "firmware_11.5.1.532678/11.5.1.532678/install_package/pkgstream_carves"
$base   = "att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_36645b10_ghidra_m00_kernel"
.venv\Scripts\vmlinux-to-elf  "$carves\$base.bin" "$carves\$base.elf"
.venv\Scripts\kallsyms-finder "$carves\$base.bin" | Out-File -Encoding utf8 "$carves\$base.kallsyms.txt"
```

For this image the heuristics auto-detect everything; the produced ELF has `e_machine=EM_MIPS`, `e_entry=0x80458130` (`kernel_entry`), `.kernel` segment at `0x80010000`, default 16 MB `.bss` gap, and a **`.symtab`** with **17,277 entries**. Keep the carve-local `.elf.md` as the per-image ground truth: [`…_ghidra_m00_kernel.elf.md`](firmware_11.5.1.532678/11.5.1.532678/install_package/pkgstream_carves/att-5268-11.5.1.532678_prod_lightspeed-install_uimage_0x01ae4b7e_36645b10_ghidra_m00_kernel.elf.md) — kallsyms field offsets, ELF layout, reproduction commands.

**Override flags** (rarely needed):

| Flag | When to use |
|---|---|
| **`--base-address 0x…`** | First `T` symbol address doesn't have its lower 12 bits clear (custom linker script). |
| **`--bit-size {32,64}`** | Architecture banner missing or truncated. |
| **`--bss-size N`** | Decompilation needs more than the default 16 MB BSS gap (megabytes). |
| **`--use-absolute`** | Forces `kallsyms_offsets + relative_base` to be treated as absolute addresses. |
| **`--e-machine N`** | Multi-arch boot blob — force `EM_MIPS=8`, `EM_ARM=40`, etc. |
| **`--file-offset 0x…`** | Input is a wrapper and `vmlinuz-decompressor` couldn't locate the inner payload at `0`. |

**Use the ELF in Ghidra** instead of the raw `.bin` for the kernel member:

- Ghidra reads `e_machine=MIPS`, `e_entry=0x80458130`, and the `.kernel`/`.bss` segments straight from the ELF — no hand-set load address, no manual entry-point jump, no `ghidra_load.json` plumbing for the kernel.
- All 17 k recovered symbols populate the function listing immediately, including private symbols (`t`/`W` types) absent from any export table — see **[opentl_kernel_ghidra.md](opentl_kernel_ghidra.md)** for OpenTL-specific findings and **[prom_init_ghidra.md](prom_init_ghidra.md)** for BCM63xx **`prom_init`** / early **`mtdparts=`** defaults.
- The **ramdisk member** (`_ghidra_m01_ramdisk.bin`) is **not** a kernel and is unaffected by this step — keep loading it via the existing `binwalker uimage-ghidra` manifest at `0x80A9A000`.

**Caveats / limits** (from upstream README):

- Requires the kernel to be built with **`CONFIG_KALLSYMS=y`** — without it, `vmlinux-to-elf` fails with **`KallsymsNotFoundException`**.
- Kernel-version coverage: **2.6.10 (2004) through 6.4 (2023)**. Linux 3.4.11-rt19 sits comfortably in range.
- OpenWRT's `kallsyms_uncompressed.patch` style (no token table) is supported — the parser falls back automatically.

### Pkgstream slices (`pkgstream-slices`)

Carve **SquashFS** / **uImage** blobs from a **`.pkgstream`** using offsets from Binwalk v3 **`--log`** JSON (same length rules as **`artifact_carver`** for multi-file **`uImage`**). Writes **`corpus_manifest.json`** (SHA-256 per slice).

For **CRC corpus** work, prefer a **real file tree** from each carved SquashFS image:

- **`--unsquash-dissect DIR`** — after carving, extract every **`squashfs`** slice under **`DIR/<carve_stem>/`** using **[dissect.squashfs](https://pypi.org/project/dissect.squashfs/)** (`pip install dissect.squashfs` or **`pip install -e "binwalker[dissect]"`**). That library is **AGPL-3.0**; it supports SquashFS **4.x** little-endian (typical firmware). Pass **`DIR`** to **`tl-crc-index --corpus-dir`** so anchors come from **`/etc/os-release`**, scripts, etc., not only raw superblock-adjacent bytes from **`.bin`** carves.
- Alternative: run host **`unsquashfs -d ...`** on each carved SquashFS blob and point **`--anchor-dir`** / **`tl-crc-index`** at that tree.

```bash
python -m binwalker pkgstream-slices \
  firmware_11.5.1.532678/11.5.1.532678/install_package/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream \
  --binwalk-json firmware_11.5.1.532678/11.5.1.532678/install_package/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream.json \
  --out ./work/pkgstream_carves \
  --unsquash-dissect ./work/pkgstream_unsquash_dissect
```

Optional: **`write_directory_manifest`** in **`lib2spy.pkgstream_corpus`** writes **`tree_manifest.json`** (path, size, SHA-256 of file prefixes) for an extracted tree.

### Pkgstream descriptive dump + cryptographic verification (`python -m lib2spy`)

Single CLI for **everything** about a **`.pkgstream`** carrier: full descriptive dump (header + every TLV + every FILE/SCRIPT with verdict + every signer + every certificate + embedded SquashFS/uImage spans), end-to-end integrity verification, and optional payload extraction. The verifier is the on-disk reimplementation of `lib2sp_internal_check_data` (`lib2sp.so` `0x0001E104`) plus the surrounding **PKCS#7 / CMS `SignedData`** envelope and **per-FILE / per-SCRIPT TLV digests**. RSA-PKCS#1 v1.5 over SHA-1 verification needs the optional `cryptography` extra; in-band layers (messageDigest match + per-payload digests) work without it.

```bash
pip install -e "binwalker[verify]"   # optional, enables RSA + X.509 cert summaries

# Full descriptive dump + verify (exit 0 = all_verified, 2 = any failure, 1 = parse error)
python -m lib2spy \
  firmware_11.5.1.532678/11.5.1.532678/install_package/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream

# Extract every FILE / SCRIPT payload + every X.509 cert (PEM) + raw PKCS#7 envelope to a tree
python -m lib2spy <file>.pkgstream --extract ./out_dir

# Skip RSA, write the full structured report (parser view + verifier view) as JSON
python -m lib2spy <file>.pkgstream --no-rsa --out-json verify.json --quiet

# Offline X.509 chain validation against the bundled device PEMs (mirrors
# pki_ver_setup_trust_roots + lib2sp_check_data ANY-of-N policy). Exits 0 only
# when ALL_VERIFIED + at least one signer chain validates.
python -m lib2spy <file>.pkgstream --validate-chain --strict --quiet

# Pin to the production signer CN — fails on engineering-only carriers.
python -m lib2spy <file>.pkgstream --validate-chain \
    --expected-cn prod1.2sp.certs.2wire.com --strict

# Programmatic — same data, no shell
python -c "from lib2spy import verify_pkgstream, format_report; print(format_report(verify_pkgstream(r'<file>.pkgstream')))"
```

> The earlier `binwalker pkgstream-verify` subcommand has been retired — `python -m lib2spy` is a strict superset (every flag plus the descriptive dump and `--extract`). See [pkgstream.md § 9.9](pkgstream.md#99-cli) for the full surface.

The verifier reports:

- `pkcs7_messageDigest_match` — SHA-1 of `body[0..pkcs7_offset)` against every signer's PKCS#9 `messageDigest` attribute.
- `rsa_signers_verified` / `rsa_signers_failed` — RSA verify of each `SignerInfo`'s `encryptedDigest` over the canonical SET-OF-Attribute DER.
- `files_verified` / `scripts_verified` — per-FILE (`0x01`/`0x03`/`0x2F`) and per-SCRIPT (`0x26`) TLV digest checks (algorithm tag from the TLV body: SHA-1 / MD5 / SHA-256).
- `legacy_dpi_sig_present` — true when the older `0x3E8` DPI signature TLV is present (not used in the 5268 firmware drops).

Tamper detection: byte flips in the file-payload region trip per-FILE digest; flips inside the signed prefix trip `messageDigest` match — both surface as `all_verified=False`. Implementation in [`lib2spy/pkgstream_verify.py`](lib2spy/pkgstream_verify.py); full algorithm and trust-chain notes in [pkgstream.md § 9 — Integrity model](pkgstream.md#9-integrity-model). *(Pkgstream verifier unit tests: add under `lib2spy/tests/` when rebuilt.)*

**Operational security analysis:** [`pkgstream_security.md`](pkgstream_security.md) — gating logic (`trust_engcert`, signer CN pin), trust anchor inventory, weaknesses (path overwrite, decompression bomb, SHA-1 messageDigest, symlink follow during extract, ANY-of-N edge cases), and **historical** reproducible probes *(same note: former `opentl/tests/probes/` removed)*. When pointed at a different firmware family, supply your own `--trust-roots DIR` to silence the bundled-PEM `ProvenanceWarning`; bundled PEM provenance lives in [`opentl/data/trust_roots/PROVENANCE.md`](opentl/data/trust_roots/PROVENANCE.md).

## Binwalk signatures vs MTD-aligned carving

A **`*.BINWALK`** report (signature hits at arbitrary offsets) does **not** define partition boundaries: bytes at offset **`0x21000`** might be an ELF inside **`tlpart`**, not “start of flash.” To carve **loader** / **mtdoops** / **`tlpart`** from a full chip dump, use the same **`mtdparts`** string the kernel uses, then slice the file by **offset and size**.

The **`binwalker partition-map`** command resolves **`mtdparts`** via [`binwalker.extract.flash_layout`](../binwalker/extract/flash_layout.py) **`build_layout_interactive`** in this order when **`--mtdparts`** is omitted:

1. **U-Boot env v1** on the **logical data plane**: CRC-checked env images at common sizes, probed at **loader** (logical offset **0**) and at a **heuristic** OpenTL disklabel env offset (**`tlpart`** start from default layout + **8×512** B). Reads use **`unand.layout.read_logical_plane_interval`** so **inline 2048+64** and **flat-tail** full-chip dumps are addressed in **logical** space without copying the whole plane.
2. Else **`mtd-scan`** string heuristics (best embedded **`mtdparts=`** table that lays out cleanly).

For **Pace-class** full-chip sizes (**`138412032`** B inline / flat-tail envelope), remainder partitions (**`-(tlpart)`**) are sized against the **128 MiB** logical plane (**`effective_mtd_reference_size`**), not the raw file length.

Stdout prints **`Mtdparts:`** (resolved token or line), **`Layout source:`** (`explicit` / `uboot-env` / `mtd-scan`), and any **notes** (e.g. env offset/size). With **`--extract`**, **`partition-map.json`** may include **`layout_source`** and **`layout_notes`** when present. **`carve`** passes the same fields into its manifest.

```bash
# Resolve mtdparts (env v1 on logical plane, else mtd-scan); typical 5268-class layout
python -m binwalker partition-map "PACE 5268AC S34ML01G1@TSOP48.BIN" --extract out_parts

# Or pass the cmdline layout explicitly
python -m binwalker partition-map "PACE 5268AC S34ML01G1@TSOP48.BIN" \
  --mtdparts "mtd-0:524288(loader),1048576(mtdoops),-(tlpart)" --extract out_parts
```

Slicing is **MTD layer only**; layout **inside** **`tlpart`** (OpenTL / `opentla*`) is a separate step — see **[issue.md](issue.md)**, then **[firmware.md](firmware.md)** (`fwupgrade.txt` boot trace).

## Binwalk on carved MTD slices (`mtd_parts/`)

After **`partition-map --extract`**, [ReFirmLabs binwalk](https://github.com/ReFirmLabs/binwalk) v3 (e.g. via Docker) can be run on each **`.bin`**; machine output is **`*.json`** and agent-oriented summaries **`*.md`**. This table ties together **[`partition-map.json`](mtd_parts/partition-map.json)** and high-signal hits in **[`loader.bin.json`](mtd_parts/loader.bin.json)**, **[`mtdoops.bin.json`](mtd_parts/mtdoops.bin.json)**, and **[`tlpart.bin.json`](mtd_parts/tlpart.bin.json)** (the last is large; prefer **`tlpart.bin.md`** for a short table, **JSON** for exact offsets).

**Ghidra / paceflash on loader vs mtdoops vs tlpart:** Kernel **`opentl_add_mtd`** binds only **`tlpart`**; **`loader`** holds U-Boot env + ELF; **`mtdoops`** is the panic ring (**`mtdoops.record_size=131072`** on product cmdline). MCP notes: **[`ghidra_mtd_loader_mtdoops_mcp.md`](ghidra_mtd_loader_mtdoops_mcp.md)**. On a full dump (after **`nand-translate`**), **`python -m paceflash ls --probe-loader-env --probe-mtdoops`** parses env and scans mtdoops without OpenTL BBM ([`paceflash/mtd_partition_probes.py`](../paceflash/mtd_partition_probes.py)).

**`opentla4` ext2 (post-upgrade squash in files):** After promote, **`rootimage.img`** / **`ui.img`** live inside an **ext2** volume on **`opentla4`**, not as raw partition squash — see **[`ghidra_squashfs_flash_read_gap_mcp.md`](ghidra_squashfs_flash_read_gap_mcp.md)**. **Working on PACE full dump (May 2026):** **`python -m paceflash --flash "PACE …BIN" ls`**, **`ls sys1`**, **`cat sys1/rootimage.img`**, or **`shell`** (flash loaded once). Full inventory / extract: **`ls --debug`**, **`--extract-ext2-dir`**, **`--dump-opentla4-ext2`** — **[`paceflash.md`](paceflash.md)**. Requires **`pip install -e ".[dissect]"`**.

**Inline NAND:** **`mtd_parts/`** here reflects **legacy** extraction when **`mtdparts`** offsets were applied **directly** to the raw **`.BIN`**. For **PACE** TSOP48 (**verified inline**), chip-grounded Binwalk anchors are under **`output/carved_flash/carve_deinterleaved/`** on **`flash_logical_deinterleaved.bin`** — see **[issue.md](issue.md)** diagram + **NAND logical plane** above.

| Source | Takeaway |
|--------|----------|
| **`partition-map.json`** | Full dump **`PACE … TSOP48.BIN`** size **138412032** bytes (~132 MiB envelope). MTD byte ranges are **logical** addresses: **loader** `0x0`–`0x80000`, **mtdoops** `0x80000`–`0x180000`, **tlpart** `0x180000`–`0x8000000` on the **128 MiB data plane** (`mtdparts=mtd-0:524288(loader),1048576(mtdoops),-(tlpart)`). Apply to **`nand-translate`** output (or equivalent), not necessarily to raw inline file offsets for **linear** slice I/O. Optional keys **`layout_source`** / **`layout_notes`** record how **`mtdparts`** was resolved (**`uboot-env`**, **`mtd-scan`**, or **`explicit`**). |
| **`loader.bin`** | **MIPS32 big-endian ELF** at **`0x21000`** in the loader slice; **U-Boot `1.3.3(8.99.61.509224)`** (Aug 5 2015) string at **`0x58500`** — same stack called out in serial/`BINWALK` work. |
| **`mtdoops.bin`** | Binwalk **no `file_map` signatures** on this carve (expected for a dedicated oops/log MTD: unstructured or empty in this snapshot). |
| **`tlpart.bin`** | **uImage / install/recovery image:** signature **`uimage`** reports **Multi-File Image**, **gzip**, **MIPS32**, **Linux**, load **`0x80010000`**, entry **`0x804583E0`**, image name **`Install image (5268/att)`** — same family U-Boot loads from **`/sys1/uImage`** in **`fwupgrade.txt`**. Multiple embedded generations appear in the JSON (e.g. **2021-11-30** and **2023-05-04** creation times on different **`uImage`** hits). **Within-`tlpart` offset** for one strong hit: **`61281280`** (**`0x3A71400`**); **absolute** in the full dump: **`1572864 + 61281280 = 62854144`** (**`0x3BF1400`**). |
| **`tlpart.bin`** | **Linux identity string** in the scan: **`Linux version 3.4.11-rt19 (buildbot@krackel)`**, **gcc 4.6.2 (Buildroot 2011.11)**, dated **2021-11-29** — aligns with **[firmware.md](firmware.md)** kernel baseline. |
| **`tlpart.bin`** | **SquashFS 4.0**, **xz**, **~6.84 MiB** image (signature hit at **`tlpart` offset `67063936` / `0x3FF5080`**; absolute **`68636800` / `0x4175080`**). Typical **read-only rootfs** technology on these gateways; **mounting** requires unsquashfs (or kernel loop) on that byte range — inode/block counts in magic strings can be partial; validate with extraction tools. |
| **`tlpart.bin`** | Repeated **PACE / AT&T** copyright text and **PEM**-tagged regions — **credentials material** may be present; handle like any flash-derived secrets (see **Legal and ethics** below). |

**Interpretation:** Binwalk offsets are **signature-based**; **`uImage`** and **SquashFS** boundaries should be confirmed by carving or extraction, not only magic length fields. **`tlpart`** still contains **OpenTL**-level layout inside this MTD slice (see **[issue.md](issue.md)** and **[firmware.md](firmware.md)**).

## Repository contents (orienting map)

Paths and artifacts may change over time; treat this as an index rather than exhaustive inventory:

| Area | Purpose |
|------|--------|
| **`pkgstreams`** | Text index of **`gateway.c01.sbcglobal.net/firmware/…`** URLs — see **[firmware.md](firmware.md)**; used by **`URLResolver`** / downloader. |
| **`firmware_11.5.1.532678/`** | Downloaded **`11.5.1.532678`** bundle — see **[firmware.md](firmware.md)**; install package has committed binwalk **`*.json` / `*.md`**. |
| **`fwupgrade.txt`** | Serial capture — see **[firmware.md](firmware.md)** and **[hardware.md](hardware.md)**. |
| **`linux-stable-rt-3.4.11-rt19/`** | Optional **`linux-stable-rt`** checkout at **`78475c9d785a6d7b3d110e8ebcc9a4d6f1ff473b`** (`Linux 3.4.11-rt19`) — merged upstream RT kernel matching device **`Linux version 3.4.11-rt19`** printks. |
| **`linux-3.4-rt-patches-3.4.11-rt19/`** | Optional **`3.4-rt-patches`** quilt (tag **`3.4.11-rt19`**) — same RT release as patch files for bisect-style reading. |
| **`binwalker/`** | Python helpers: firmware sniffing (`scan`), **`mtd-scan`**, **`partition-map`**, **`signals-scan`**, **`full-scan`**, **`carve`**, OpenTL **`tl-*`** (**layout**, **BBM**, **extract**, **CRC corpus**, **BBM score**) — see **[issue.md](issue.md)**. |
| **`mtd_parts/`** | Carved MTD slices (`loader.bin`, `mtdoops.bin`, `tlpart.bin`), **`partition-map.json`**, and binwalk **`*.json` / `*.md`** — table above. |
| **Flash / binwalk outputs** | e.g. `*.BIN`, `*.BINWALK`, `flash strings.txt` — large references; not always committed. |
| **Scripts** | `analyze_flash.py`, `flash_scanner.py`, etc. — older entry points; prefer **`python -m binwalker …`**. **`python -m binwalker download`** / **`download-all`** were **removed**; use **`firmware_downloader.py`** / **`binwalker.downloader`** only if you still need programmatic downloads. Prefer **`python -m lib2spy.pkgstream`** for **`.pkgstream`** verification. |

### Example commands

```bash
python -m binwalker full-scan "PACE 5268AC S34ML01G1@TSOP48.BIN"
python -m binwalker mtd-scan "PACE 5268AC S34ML01G1@TSOP48.BIN"
python -m binwalker partition-map "PACE 5268AC S34ML01G1@TSOP48.BIN" --extract mtd_slices
python -m binwalker signals-scan "flash strings.txt"
python -m binwalker scan "flash.bin" --mtd --signals
```

More detail: **[`binwalker/README.md`](binwalker/README.md)**.

## Legal and ethics

Full notice: **[`LEGAL.md`](../LEGAL.md)** (DMCA § 1201, research-only attestation).

- Use this documentation and tooling only on **hardware you own** or are **explicitly authorized** to analyze.
- Do not use extracted material to bypass **DRM**, **legal terms of service**, or **export** rules.
- **Credentials, keys, and certificates** may appear in dumps; handle and publish according to responsible disclosure and local law.

## How these docs evolve

The split notes (**`issue.md`**, **`hardware.md`**, **`firmware.md`**, **`tools.md`**) are **living documents**: as new dumps, bootloader logs, or kernel sources are compared, update **partition tables**, **TL disk layout**, **BCM-specific printks**, and **toolchain versions**. Prefer dated notes or “observed on firmware X.Y” qualifiers when citing behaviour that may differ across BSP releases.
