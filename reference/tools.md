# Tools and repository layout

**`binwalker`** workflows, **MTD carving**, **`mtd_parts/`** summaries, and repository index.

### Opentla4 dissect probe (`opentl-dissect-probe`)

Bundled pass for **carrier corpus vs `tlpart`**: carve **`.pkgstream`** → **`dissect.squashfs`** trees → **`tl-crc-index`** / **`tl-crc-scan`** → **`opentl-analyze`**. Use the **same Python environment** as **`pip install dissect.squashfs`** (repo **`.venv`** recommended).

```bash
.venv\Scripts\python.exe -m binwalker opentl-dissect-probe mtd_parts/tlpart.bin \
  --pkgstream firmware_11.5.1.532678/.../install.pkgstream \
  --binwalk-json firmware_11.5.1.532678/.../install.pkgstream.json \
  --work ./work_tl_crc/opentla4_probe_bundle --json
```

Artifacts: **`opentla4_dissect_probe_summary.json`**, **`tl_crc_hits_dissect.json`**, **`opentl_analyze_dissect.json`**. Optionally run **`tl-crc-hits-align`** on the two JSON reports to emit **`tl_crc_hits_alignment.json`**. **`--reuse-corpus`** skips carving when **`pkgstream_dissect_corpus/`** already has roots.

### OpenTL correlation (`opentl-analyze`)

Research-first correlation of **`tlpart.bin`** (or a full flash image) against:

- a **contiguous carved SquashFS** (`--golden`), and/or
- an **unsquashed directory tree** from a pkgstream slice (`--anchor-dir`), and/or
- PEM files (`--pem`).

Produces mmap hit lists, per-anchor alignment hints, **`corpus_interpretation`** (match rate by anchor prefix, anchors with multiple physical hits), optional **`--pkgstream`** superblock ranking when **`--golden`** is set, and optional **`--experimental-reader`** stitch validation (requires **`--golden`**). See **[issue.md](issue.md)**.

### NAND logical plane (5268-class TSOP dumps)

For **full-chip** captures such as **`138412032` B** (**`65536 × (2048+64)`**), normalize **before** **`partition-map`**, **`tl-*`** on MTD-relative offsets, or Binwalk over **`tlpart`** slices:

1. **`python -m binwalker nand-translate`** *`PACE … TSOP48.BIN`* **`--out`** *`flash_logical.bin`* **`--mode auto`** — writes **`134217728` B** logical main (**`nand-spare-extract`** or **`--spare-out`** for the **4 MiB** spare stream).
2. **`python -m binwalker nand-oob-inspect --spare spare.bin`** (or **`--flash`** *raw dump*) — JSON audit of **64 B** spare rows (**OpenTL** fields + **`ntl_compute_spare_xsum`**, **`BootCode`** markers, **`chain_v1`** virt-slot fill); see **[issue.md](issue.md)** **OOB / spare field decode**. Optional **`--spare-chain-replay --chain-length N`** + **`--bbm-json`** **`--virt-block V`** (and/or **`--chain-start-phys`**) appends **`ntl_put_chain_in_array`** mode-2 hop decode (**`opentl/spare_chain_replay.py`**).
3. **`python -m binwalker partition-map`** / **`carve`** on *`flash_logical.bin`* (or **`carve ... --nand-data-mode auto`** on the raw dump to combine translate + Docker Binwalk).
4. Optional: **`python -m binwalker carved-pem-export`** on the carve output dir — rewrite **`pem_certificate`** **`*.bin`** hits as **`*.pem`**.

See **[issue.md](issue.md)** **Dump layout** for why **`auto`** may choose **inline** vs **flat-tail** at this envelope size.

### OpenTL physical-layer probes

Implemented **`binwalker`** subcommands aligned with **[issue.md](issue.md)** (**Strategy** / **Dump layout**). **`tl-layout-detect`** scans for **`ELF`** @ **`0x21000`** and **`hsqs`** with an **`hsqs mod 2112`** stride hint — useful corroboration on a chosen file view, but **not decisive** for **`138412032` B** dumps: **flat-tail** and **inline 2048+64** share the same total length, so **`hsqs`** alignment neither proves nor disproves interleaved packing by itself (see **`nand-translate --mode auto`** and **`opentl/nand_translate.py`**).

| Command | Purpose |
|---------|---------|
| **`tl-layout-detect`** *flash.bin* | **ELF** magic check + **`hsqs`** stride heuristic; **`--json`** for machine output. |
| **`tl-disklabel`** *image.bin* | **Whole-disk + four slices** (**`match_kind: chain`**), legacy **four-tuple** only (**`chain4`**), **`first_triple`**, and BSD magic **`0x82564557`** (**`bsd_magic`**). May yield **zero** hits if on-disk layout differs from the **`fwupgrade.txt`** printk model. |
| **`tl-env`** *image.bin* | Find **`bootcmd=if tl checkfstype`** plus nearby **`09 72 f0 f3`** CRC bytes (**`--json`**). |
| **`tl-probe`** *flash.bin* | One-shot **JSON**: layout + disklabel hit list + env hits + **`0x10000`**-spaced env pairs when present. |
| **`tl-bbm`** *tlpart.bin* | Emit **`binwalker_tl_bbm_v1`** map: **`--mode linear_v1`** (identity **`virt→phys`**, low confidence), **`heuristic_v1`** (+ scan for **`(1007,5,0)`** uint32 LE in first **512 B** of each erase block), **`synthetic_planted_v1`** (test **`BWTLMAP1`** header), **`brute_reserved_v1`** (slide one contiguous reserved raw band: **`--reserved-start`** slide index **`s`**, default **`virt_blocks`** → identity). **`--out-json`** / **`--json`**. Default logical prefix **`1012×128KiB`** (trim trailing **4 MiB** OOB appendix in standard carves). |
| **`tl-mount-sim`** *flash.bin* | Mount simulator → **`binwalker_tl_bbm_v1`** (**stats** / **OOB spare walk** / **slide**). Input must be either (a) a **carved `tlpart`** logical image (**`1012×128KiB` + optional OOB tail**) with **`--nand-logical-offset 0`** (default), or (b) a **full-chip TSOP** capture (**138 412 032 B** typical): use **`--nand-logical-offset 0x180000`** so bytes **`0..1.5 MiB`** (loader + mtdoops per **`mtdparts`**) are skipped before OpenTL’s **`1012`** erase blocks. **`--strategy`**, **`--out-bbm`**. |
| **`tl-extract`** *tlpart.bin* | **`--bbm map.json`** **`--out opentla4.ext2`** — assemble **`opentla4`** virtual sectors **`0x180`…`** (**`0x3C080`** sectors). **`--nand-logical-offset`** overrides BBM JSON when seeking into the same flash file (must match **`tl-mount-sim`**). **`--dry-run`**, **`--verify-uimage`** *reference.bin*, **`--json`** summary. |
| **`tl-crc-index`** | **`--corpus-dir DIR`** (repeatable) **`--windows full,2048,131072`** **`--out-json idx.json`** — build **`binwalker_tl_crc_v1`** (CRC-32 / zlib polynomial over **full file**, **2048 B** pages, **128 KiB** erase windows). |
| **`tl-crc-scan`** *image.bin* | **`--index idx.json`** **`--stride N`** **`--workers N`** **`--gpu`** — sliding-window scan; JSON schema **`binwalker_tl_crc_scan_v1`** with **`backend`** **`cpu`** or **`cuda`**. If **`--gpu`** is set but no CUDA device is available (or the kernel fails), **`notes`** explains the fallback and **`backend`** is **`cpu`**. Install GPU support in your venv (from repo root): **`pip install -e "binwalker[cuda]"`** or **`pip install numba`** (needs an NVIDIA driver when you want **`backend: cuda`**). Optional **`--logical-prefix-bytes`**, **`--out-json`**, **`--json`**. |
| **`tl-crc-hits-align`** | **`--hits-json tl_crc_hits.json`** **`--analyze-json opentl_report.json`** — **`binwalker_tl_crc_hits_alignment_v1`**: GCD of consecutive image offsets, **`residue_mod_erase_top`** (default **128 KiB**), and per-modulus overlap with **`merged_alignment`** from **`opentl-analyze`**. Optional **`--erase-bytes`**, **`--window-size`** (filter scan rows). Use after **`tl-crc-scan`** to relate CRC anchors to string-anchor alignment hints. |
| **`tl-crc-re`** *image.bin* | **`--env-from tl-env.json`** **`--expected-crc`** (default **`0x0972F0F3`** for printk **`CRC=972f0f3`**) — **`binwalker_tl_crc_re_v1`**: variant probe using env **payload after `crc_offset + 5`** (**CRC+NUL** header per **`fwupgrade.txt`**), then **`locate_hits`** / hole-model fallback. **`verify_against_nvram_crc`** (**`crc_re`**) cross-checks **`kerSysEarlyFlashInit`** (**4092** B / **`0x7f4bc607`**). **`--out-json`**, **`--json`**. |
| **`tl-bbm-score`** *tlpart.bin* | **`--candidates linear_v1,brute_reserved_v1`** **`--out-json score.json`** — ranks maps via **`binwalker_tl_bbm_score_v1`** (**`ranked`** / **`best`**). Optional **`--index`** (corpus CRC index), **`--uimage-ref`**, **`--reserved-start`** / **`--reserved-window`** (limit **`brute_reserved_v1`** slide range), **`--corpus-stride`**. **`--json`** prints copy to stdout. |

**Map schema (`binwalker_tl_bbm_v1`):** top-level **`schema`**, **`geometry`** (adds boot-trace fields: **`head_pages`**, **`media_pages`**, **`spares_field`**, **`cap_sectors`**, **`geometry_wasted_sectors`**, **`sectors_per_unit`**), duplicate summary **`boot_trace_invariants`**, **`virt_to_phys_block`**, optional **`stats_physical_block_index`**, **`warnings`**, **`input_sha256_logical_prefix`**, optional **`nand_logical_offset`** (byte offset of **`tlpart`** in **`flash_file`**).

**CRC index (`binwalker_tl_crc_v1`):** **`entries_by_crc`** maps **8-digit lowercase hex** CRC keys to lists of **`{relative_path, file_offset, length, window_kind, …}`**; plus **`stride_page`**, **`stride_erase`**, **`window_kinds`**.

**BBM score (`binwalker_tl_bbm_score_v1`):** **`ranked`** rows with **`mode`**, optional **`reserved_slide_start`**, **`total_score`**, **`score_detail`** (ext2 / uImage / corpus fields), physical span hints.

```bash
python -m binwalker tl-layout-detect "PACE 5268AC S34ML01G1@TSOP48.BIN" --json
python -m binwalker tl-disklabel "PACE 5268AC S34ML01G1@TSOP48.BIN" --json
python -m binwalker tl-env "PACE 5268AC S34ML01G1@TSOP48.BIN" --json
python -m binwalker tl-probe "PACE 5268AC S34ML01G1@TSOP48.BIN"

# `--verify-uimage` / `--uimage-ref` below use filenames from `carve_deinterleaved/carve_summary.md`
# after `partition-map`/`carve` on `flash_logical_deinterleaved.bin` (regenerate if missing locally).

python -m binwalker tl-bbm mtd_parts/tlpart.bin --mode linear_v1 --out-json tl_map.json --json
python -m binwalker tl-bbm mtd_parts/tlpart.bin --mode brute_reserved_v1 --reserved-start 0 --out-json tl_map_brute.json --json
python -m binwalker tl-extract mtd_parts/tlpart.bin --bbm tl_map.json --out opentla4.ext2 --dry-run --json
# Optional: compare headers against a chip uImage from the deinterleaved carve (see issue.md)
python -m binwalker tl-extract mtd_parts/tlpart.bin --bbm tl_map.json --out opentla4.ext2 \
  --verify-uimage "output/carved_flash/carve_deinterleaved/carved/tlpart_uimage_0x05a45800_24656ebd.bin"

python -m binwalker opentl-analyze mtd_parts/tlpart.bin \
  --golden "PACE 5268AC S34ML01G1@TSOP48_carve/carved/tlpart_squashfs_0x03ff5080_8a358306.bin" \
  --out-json opentl_report.json

# Partial overlap: extracted pkgstream tree only (no contiguous squash golden)
python -m binwalker opentl-analyze mtd_parts/tlpart.bin \
  --anchor-dir ./work/pkgstream_large_unsquash \
  --out-json opentl_corpus_report.json

# CRC corpus + bounded BBM ranking (carve pkgstream, unsquash with dissect.squashfs, then index files)
python -m binwalker pkgstream-slices .../install.pkgstream --binwalk-json ...pkgstream.json \
  --out ./work/pkgstream_carves --unsquash-dissect ./work/pkgstream_unsquash_dissect
python -m binwalker tl-crc-index --corpus-dir ./work/pkgstream_unsquash_dissect --windows full,2048,131072 --out-json tl_crc_idx.json
python -m binwalker tl-crc-scan mtd_parts/tlpart.bin --index tl_crc_idx.json --stride 131072 --workers 4 --out-json tl_crc_hits.json --json
python -m binwalker tl-crc-hits-align --hits-json tl_crc_hits.json --analyze-json opentl_corpus_report.json --out-json tl_crc_hits_alignment.json --json
python -m binwalker tl-env "PACE 5268AC S34ML01G1@TSOP48.BIN" --json > tl_env.json
python -m binwalker tl-crc-re mtd_parts/tlpart.bin --env-from tl_env.json --expected-crc 0x0972F0F3 --out-json tl_crc_re.json --json
# Prefer chip carve matching fwupgrade /sys1/uImage size (3740634 B). Older bank at 0x3a71400 is shorter — mis-scores --uimage-ref.
python -m binwalker tl-bbm-score mtd_parts/tlpart.bin \
  --candidates linear_v1,brute_reserved_v1 --index tl_crc_idx.json \
  --reserved-start 0 --reserved-window 64 \
  --uimage-ref "output/carved_flash/carve_deinterleaved/carved/tlpart_uimage_0x05a45800_24656ebd.bin" \
  --out-json tl_bbm_score.json --json
```

**`flash strings.txt` / Ghidra cues** (see **[issue.md](issue.md)** **RE breadcrumbs**): **`TL_debug:`** `mediasize` / `spares` / `head_pages`; **`resetting statsBlock statistics Num Used=…`**; **`kerSysEarlyFlashInit`** NVRAM CRC; **`BootCode`** **`0x840`** strides in the loader/strings extract vs **`hsqs`** carve checks on the full chip.

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

For **CRC corpus** and **`opentl-analyze --anchor-dir`**, prefer a **real file tree** from each carved SquashFS image:

- **`--unsquash-dissect DIR`** — after carving, extract every **`squashfs`** slice under **`DIR/<carve_stem>/`** using **[dissect.squashfs](https://pypi.org/project/dissect.squashfs/)** (`pip install dissect.squashfs` or **`pip install -e "binwalker[dissect]"`**). That library is **AGPL-3.0**; it supports SquashFS **4.x** little-endian (typical firmware). Pass **`DIR`** to **`tl-crc-index --corpus-dir`** so anchors come from **`/etc/os-release`**, scripts, etc., not only raw superblock-adjacent bytes from **`.bin`** carves.
- Alternative: run host **`unsquashfs -d ...`** on each carved SquashFS blob and point **`--anchor-dir`** / **`tl-crc-index`** at that tree.

```bash
python -m binwalker pkgstream-slices \
  firmware_11.5.1.532678/11.5.1.532678/install_package/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream \
  --binwalk-json firmware_11.5.1.532678/11.5.1.532678/install_package/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream.json \
  --out ./work/pkgstream_carves \
  --unsquash-dissect ./work/pkgstream_unsquash_dissect
```

Optional: **`write_directory_manifest`** in **`opentl.pkgstream_corpus`** writes **`tree_manifest.json`** (path, size, SHA-256 of file prefixes) for an extracted tree.

### Pkgstream descriptive dump + cryptographic verification (`python -m opentl.pkgstream`)

Single CLI for **everything** about a **`.pkgstream`** carrier: full descriptive dump (header + every TLV + every FILE/SCRIPT with verdict + every signer + every certificate + embedded SquashFS/uImage spans), end-to-end integrity verification, and optional payload extraction. The verifier is the on-disk reimplementation of `lib2sp_internal_check_data` (`lib2sp.so` `0x0001E104`) plus the surrounding **PKCS#7 / CMS `SignedData`** envelope and **per-FILE / per-SCRIPT TLV digests**. RSA-PKCS#1 v1.5 over SHA-1 verification needs the optional `cryptography` extra; in-band layers (messageDigest match + per-payload digests) work without it.

```bash
pip install -e "binwalker[verify]"   # optional, enables RSA + X.509 cert summaries

# Full descriptive dump + verify (exit 0 = all_verified, 2 = any failure, 1 = parse error)
python -m opentl.pkgstream \
  firmware_11.5.1.532678/11.5.1.532678/install_package/att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream

# Extract every FILE / SCRIPT payload + every X.509 cert (PEM) + raw PKCS#7 envelope to a tree
python -m opentl.pkgstream <file>.pkgstream --extract ./out_dir

# Skip RSA, write the full structured report (parser view + verifier view) as JSON
python -m opentl.pkgstream <file>.pkgstream --no-rsa --out-json verify.json --quiet

# Offline X.509 chain validation against the bundled device PEMs (mirrors
# pki_ver_setup_trust_roots + lib2sp_check_data ANY-of-N policy). Exits 0 only
# when ALL_VERIFIED + at least one signer chain validates.
python -m opentl.pkgstream <file>.pkgstream --validate-chain --strict --quiet

# Pin to the production signer CN — fails on engineering-only carriers.
python -m opentl.pkgstream <file>.pkgstream --validate-chain \
    --expected-cn prod1.2sp.certs.2wire.com --strict

# Programmatic — same data, no shell
python -c "from opentl import verify_pkgstream, format_report; print(format_report(verify_pkgstream(r'<file>.pkgstream')))"
```

> The earlier `binwalker pkgstream-verify` subcommand has been retired — `python -m opentl.pkgstream` is a strict superset (every flag plus the descriptive dump and `--extract`). See [pkgstream.md § 9.9](pkgstream.md#99-cli) for the full surface.

The verifier reports:

- `pkcs7_messageDigest_match` — SHA-1 of `body[0..pkcs7_offset)` against every signer's PKCS#9 `messageDigest` attribute.
- `rsa_signers_verified` / `rsa_signers_failed` — RSA verify of each `SignerInfo`'s `encryptedDigest` over the canonical SET-OF-Attribute DER.
- `files_verified` / `scripts_verified` — per-FILE (`0x01`/`0x03`/`0x2F`) and per-SCRIPT (`0x26`) TLV digest checks (algorithm tag from the TLV body: SHA-1 / MD5 / SHA-256).
- `legacy_dpi_sig_present` — true when the older `0x3E8` DPI signature TLV is present (not used in the 5268 firmware drops).

Tamper detection: byte flips in the file-payload region trip per-FILE digest; flips inside the signed prefix trip `messageDigest` match — both surface as `all_verified=False`. Implementation in [`opentl/pkgstream_verify.py`](opentl/pkgstream_verify.py); full algorithm and trust-chain notes in [pkgstream.md § 9 — Integrity model](pkgstream.md#9-integrity-model); test corpus in [`opentl/tests/test_pkgstream_verify.py`](opentl/tests/test_pkgstream_verify.py).

**Operational security analysis:** [`pkgstream_security.md`](pkgstream_security.md) — gating logic (`trust_engcert`, signer CN pin), trust anchor inventory, weaknesses (path overwrite, decompression bomb, SHA-1 messageDigest, symlink follow during extract, ANY-of-N edge cases), and reproducible probes under [`opentl/tests/probes/`](opentl/tests/probes/). When pointed at a different firmware family, supply your own `--trust-roots DIR` to silence the bundled-PEM `ProvenanceWarning`; bundled PEM provenance lives in [`opentl/data/trust_roots/PROVENANCE.md`](opentl/data/trust_roots/PROVENANCE.md).

## Binwalk signatures vs MTD-aligned carving

A **`*.BINWALK`** report (signature hits at arbitrary offsets) does **not** define partition boundaries: bytes at offset **`0x21000`** might be an ELF inside **`tlpart`**, not “start of flash.” To carve **loader** / **mtdoops** / **`tlpart`** from a full chip dump, use the same **`mtdparts`** string the kernel uses, then slice the file by **offset and size**. The **`binwalker partition-map`** command builds that table (from **`--mtdparts`** or by reusing the best **`mtdparts=`** string found in a **`mtd-scan`** of the dump) and can write raw per-partition binaries plus **`partition-map.json`**.

```bash
# Derive mtdparts from strings embedded in the .BIN (typical 5268-class layout)
python -m binwalker partition-map "PACE 5268AC S34ML01G1@TSOP48.BIN" --extract out_parts

# Or pass the cmdline layout explicitly
python -m binwalker partition-map "PACE 5268AC S34ML01G1@TSOP48.BIN" \
  --mtdparts "mtd-0:524288(loader),1048576(mtdoops),-(tlpart)" --extract out_parts
```

Slicing is **MTD layer only**; layout **inside** **`tlpart`** (OpenTL / `opentla*`) is a separate step — see **[issue.md](issue.md)**, then **[firmware.md](firmware.md)** (`fwupgrade.txt` boot trace).

## Binwalk on carved MTD slices (`mtd_parts/`)

After **`partition-map --extract`**, [ReFirmLabs binwalk](https://github.com/ReFirmLabs/binwalk) v3 (e.g. via Docker) can be run on each **`.bin`**; machine output is **`*.json`** and agent-oriented summaries **`*.md`**. This table ties together **[`partition-map.json`](mtd_parts/partition-map.json)** and high-signal hits in **[`loader.bin.json`](mtd_parts/loader.bin.json)**, **[`mtdoops.bin.json`](mtd_parts/mtdoops.bin.json)**, and **[`tlpart.bin.json`](mtd_parts/tlpart.bin.json)** (the last is large; prefer **`tlpart.bin.md`** for a short table, **JSON** for exact offsets).

**Inline NAND:** **`mtd_parts/`** here reflects **legacy** extraction when **`mtdparts`** offsets were applied **directly** to the raw **`.BIN`**. For **PACE** TSOP48 (**verified inline**), chip-grounded Binwalk anchors are under **`output/carved_flash/carve_deinterleaved/`** on **`flash_logical_deinterleaved.bin`** — see **[issue.md](issue.md)** diagram + **NAND logical plane** above.

| Source | Takeaway |
|--------|----------|
| **`partition-map.json`** | Full dump **`PACE … TSOP48.BIN`** size **138412032** bytes (~132 MiB envelope). MTD byte ranges are **logical** addresses: **loader** `0x0`–`0x80000`, **mtdoops** `0x80000`–`0x180000`, **tlpart** `0x180000`–`0x8000000` on the **128 MiB data plane** (`mtdparts=mtd-0:524288(loader),1048576(mtdoops),-(tlpart)`). Apply to **`nand-translate`** output (or equivalent), not necessarily to raw inline file offsets. |
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
| **`binwalker/`** | Python helpers: firmware sniffing (`scan`), **`mtd-scan`**, **`partition-map`**, **`signals-scan`**, **`full-scan`**, **`carve`**, OpenTL **`opentl-analyze`** / **`tl-*`** (**layout**, **BBM**, **extract**, **CRC corpus**, **BBM score**) — see **[issue.md](issue.md)**. |
| **`mtd_parts/`** | Carved MTD slices (`loader.bin`, `mtdoops.bin`, `tlpart.bin`), **`partition-map.json`**, and binwalk **`*.json` / `*.md`** — table above. |
| **Flash / binwalk outputs** | e.g. `*.BIN`, `*.BINWALK`, `flash strings.txt` — large references; not always committed. |
| **Scripts** | `analyze_flash.py`, `flash_scanner.py`, etc. — older entry points; prefer **`python -m binwalker …`**. Downloads: **`download`** / **`analyze`**, not the legacy **`firmware_downloader`** shim. |

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

- Use this documentation and tooling only on **hardware you own** or are **explicitly authorized** to analyze.
- Do not use extracted material to bypass **DRM**, **legal terms of service**, or **export** rules.
- **Credentials, keys, and certificates** may appear in dumps; handle and publish according to responsible disclosure and local law.

## How these docs evolve

The split notes (**`issue.md`**, **`hardware.md`**, **`firmware.md`**, **`tools.md`**) are **living documents**: as new dumps, bootloader logs, or kernel sources are compared, update **partition tables**, **TL disk layout**, **BCM-specific printks**, and **toolchain versions**. Prefer dated notes or “observed on firmware X.Y” qualifiers when citing behaviour that may differ across BSP releases.
