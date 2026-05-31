---
name: squashfs-corpus-index
description: >-
  Query the 5268ac firmware corpus SQLite index: list collection versions,
  search text lines / ELF symbols / rodata strings, resolve materialized
  pkgstream carve paths, then import into Ghidra via ghidra-mcp for RE.
  Use when the user asks to grep the corpus, find symbols/strings in
  libcm/httpd/kernel, scope a firmware release (version:* collection),
  locate indexed files under work_corpus, bridge corpus hits to Ghidra MCP
  (import_file, decompile_function), run MIPS PoCs under qemu-mips-static, or
  mentions python -m corpus, corpus_index.sqlite, or --collection. For index
  builds see reference/tools.md; for Ghidra see ghidra-mcp-corpus; for QEMU
  user-mode tests see qemu-mips-lab skill.
---

# Corpus CLI — query interface (5268ac)

`python -m corpus` is the **read-mostly interface** to the firmware corpus: a SQLite index over materialized pkgstream artifacts (scripts, certs, carved SquashFS blobs, kernel ELFs) plus optional SBOM sidecars. Use it to **discover which firmware collections are indexed**, **search strings and symbols**, **resolve on-disk paths**, and **choose what to open in Ghidra** (via **ghidra-mcp**).

The index answers *where* and *what name*; Ghidra answers *decompilation, xrefs, and types*. See **[ghidra-mcp-corpus](../.cursor/skills/ghidra-mcp-corpus/SKILL.md)** for kernel uImage, ramdisk tiers, and MCP endpoint semantics.

Default database: **`work_corpus/corpus/index.sqlite`** (under the Docker-mounted **`work_corpus/`** tree). Schema version **`corpus-index-v3`**: content dedup by **MD5** (primary) + **SHA-1** (pkgstream TLV lookup); grep hits include `content_md5` / `content_sha1`. Delete the DB and re-index after upgrading from v2 — no backfill.

If you still have **`work_corpus/corpus_index.sqlite`** from an older index, the CLI reads it automatically; run **`python -m corpus --migrate-db`** once to move it.

Default materialized tree: **`work_corpus/pkgstream_corpus_by_version/`**.

**`--db` is optional** for search, inspect, Grype **`--sbom-for`**, and **`--build-index`** — omit it unless you use a non-default path.

Indexing, Docker rebuilds, and gateway mirror download are documented in **`reference/tools.md`** and **`docker/corpus-runtime/README.md`** — not here.

**Resume:** Do **not** pass **`--fresh`** when continuing a long **`--pkgstream-root`** run. Completed work is tracked in SQLite:

- **`ingest_status`** — whole `.pkgstream` carrier (install + config + certs per file)
- **`analysis_status`** — each SquashFS carve and small materialized blob

Check progress: **`python -m corpus --index-status`**. Logs show **`# pkgstream ingest skip completed`** and **`# squashfs index skip completed`** when skipping.

## Prerequisites

From repo root **`5268ac`**:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt   # pyelftools; dissect only needed for --build-index
```

## 1. List collections and versions

### Collection slugs (what `--collection` expects)

Pkgstream ingest groups carriers into slugs like **`version:11.5.1.532678`**. Install, config, cms-certs, and eapol-certs from the same release directory share one slug.

**On disk** (staging layout mirrors slugs with `:` → `_`):

```powershell
Get-ChildItem work_corpus\pkgstream_corpus_by_version -Directory
# e.g. version_11.5.1.532678, version_11.14.1.533857
```

Pass **`--collection "version:11.5.1.532678"`** (with the `version:` prefix) when searching.

### Version evidence inside the DB

Per-file version strings extracted during indexing (build IDs, package versions, etc.):

```powershell
python -m corpus --versions --jsonl
python -m corpus --versions --limit 50
```

### What is in the index (formats)

```powershell
python -m corpus --format-summary --jsonl
```

## 2. Search strings and symbols

Patterns are **regex** unless **`-F`** (literal). **`-i`** ignores case. **`--limit N`** caps results.

During active indexing, SQLite may return transient **`malformed`** / **`disk I/O`** / **`locked`** errors. **`corpus grep`** and **`file-history`** auto-retry (5 attempts, backoff). If a query still fails, use **`find` + `cat`** or wait for indexing to finish.

### Text (scripts, configs, line-oriented files)

```powershell
python -m corpus -i rwdata "/rwdata/cm"
python -m corpus -F "cmdb_attr_setdbdir" --kind text
```

### ELF symbols (functions, globals)

```powershell
python -m corpus httpd --kind symbol --limit 40
python -m corpus -F "cmdb_password" --kind symbol
```

### ELF rodata strings

```powershell
python -m corpus -i "lightspeed" --kind rodata
```

### Default search (text + symbol + rodata)

```powershell
python -m corpus libcm_server
```

### Scope to one firmware collection

```powershell
python -m corpus grep --collection "pkgstream:firmware/00D09E/11.14.1.533857-PROD" -i httpd
python -m corpus grep --collection "11.14.1.533857" --kind symbol FUN_   # warns if PROD+LAB both indexed
python -m corpus grep -F cmdb_process --refs-only --limit 1 | python -m corpus cat
python -m corpus find '*shadow' --refs-only | python -m corpus xargs cat
python -m corpus find '*shadow' --refs-only -n 5 | python -m corpus xargs locate --jsonl
```

### Linker metadata (SONAME / NEEDED)

```powershell
python -m corpus libcm --kind soname --kind needed --limit 80
python -m corpus --explain-library libcm_server.so.0
```

**Providers** = ELFs whose `DT_SONAME` matches; **consumers** = ELFs that list it under `DT_NEEDED` (typically `libfoo.so.0`, not `libfoo.so`).

### Carrier metadata (pkgstream verify JSON)

Per-collection **`pkgstream_metadata.json`** / **`certificate_metadata.json`** from lib2spy ingest are indexed in **`carrier_metadata`**, not as rootfs **`files`** rows. They do not appear in **`corpus find`** or **`file-history`**.

```powershell
python -m corpus grep verify_summary --kind carrier_meta
python -m corpus grep -F db97c4498a2b --kind carrier_meta --collection "version:11.6.1.532855"
```

Hits use virtual path **`@carrier/pkgstream_metadata`**. Re-index a collection (without **`--fresh`**) to migrate old DB rows that still listed `pkgstream_metadata.json` as a file.

### Machine-readable hits

```powershell
python -m corpus -i mount --jsonl --limit 20
```

**Human line shape:**

- Text: `IMAGE_KEY::path/inside/rootfs:line:content`
- Symbol: `IMAGE_KEY::path/inside/rootfs:SYMBOL:scope:type:bind:name`
- Rodata: `IMAGE_KEY::path/inside/rootfs:RODATA[.rodata]:string`

`IMAGE_KEY` is usually a repo-relative path under **`work_corpus/pkgstream_corpus_by_version/...`**.

## 3. Access materialized files on disk

Search hits name an **image key** and an **inner path**. Use the helpers below to open the blob or inner file without re-dissecting pkgstreams.

### Find files by path (no content search)

List indexed file paths by glob, emitting stable refs you can pipe to `corpus cat` / `corpus xargs`:

```powershell
# One exact path (common for NAND ext2 materialization)
python -m corpus find "opentla4/sys1/component.txt" --collection "nand:@PACE 5268AC S34ML01G1@TSOP48.BIN"

# Single hit (quote globs on PowerShell: '*history' not *history)
python -m corpus find "opentla4/sys1/component.txt" --collection "nand:@PACE 5268AC S34ML01G1@TSOP48.BIN" --refs-only --limit 1 | `
  python -m corpus cat

# find without --refs-only also works (tab-separated ref + image::path); --refs-only is clearer
python -m corpus find '*history' --refs-only | python -m corpus xargs cat

# All hits (xargs-style): ``==> ref`` header before each file; use ``--raw`` to concatenate blindly
python -m corpus find '*shadow' --refs-only | python -m corpus xargs cat
python -m corpus find '*shadow' --refs-only | python -m corpus cat   # same when stdin has multiple lines

# Text files fall back to indexed ``text_lines`` when dissect cannot read the SquashFS carve

# Cap how many refs are processed; skip extract failures without aborting the batch
python -m corpus find '*shadow' --refs-only | python -m corpus xargs cat -n 10 --continue-on-error

# Resolve paths only (no SquashFS extract)
python -m corpus find '*shadow' --refs-only | python -m corpus xargs locate --jsonl

# Multiple globs (repeat positional args)
python -m corpus find "usr/sbin/*" "usr/bin/*" --collection "pkgstream:firmware/00D09E/11.14.1.533857-PROD"
```

### File history across firmware versions

Group every indexed copy of a path by **content hash** and show which firmware versions each variant appears in (contrast with line-level `corpus grep` and global `corpus --duplicates`):

```powershell
python -m corpus file-history etc/shadow
python -m corpus file-history etc/shadow --preview
python -m corpus file-history etc/shadow --jsonl
python -m corpus file-history etc/shadow --verbose
python -m corpus file-history "rodata/sysinit/etc/shadow"
python -m corpus file-history '*shadow'              # lists each matching path (etc/shadow, rodata/sysinit/etc/shadow, …)
```

With a glob, stderr lists all matching paths; each content-hash row includes a `paths=` column (comma-separated). JSONL includes a `paths` array per variant.

Example: one `md5` row may span `10.5.1.504323 – 11.14.1.533857 (42 versions)`; a second row covers only `9.8.x` when `rma:` hash lines differ.

### Resolve by path substring or SHA-256

After a search hit, look up file identity rows (size, hash, content class):

```powershell
python -m corpus --file-info "squashfs_0x00368538" --jsonl
python -m corpus --file-info "usr/bin/httpd"
```

### Typical on-disk layout

| Path under repo | Contents |
|-----------------|----------|
| **`work_corpus/pkgstream_corpus_by_version/version_<ver>/<NNNN>_<carrier>/`** | One pkgstream ingest tree per carrier |
| **`…/embedded/squashfs_*.bin`** | Carved SquashFS image (index walks these via dissect) |
| **`…/embedded/uimage_*.bin`** | Carved uImage; **`…/embedded/uimage_*.bin.sidecars/vmlinux.elf`** when conversion succeeded |
| **`…/tlv_extract/`**, **`…/_certs/`** | TLV scripts, PKCS#7, extracted certs |
| **`work_corpus/sbom/version_<ver>/`** | Syft JSON (if built with **`--sbom`**) |
| **`work_corpus/sbom/sources/`** | Materialized rootfs trees (SBOM fallback only) |

Example: hit

`work_corpus/pkgstream_corpus_by_version/version_11.5.1.532678/0061_5268.install/embedded/squashfs_0x....bin::usr/lib/libcm.so.0:SYMBOL:…`

→ the **SquashFS carve** is on disk; the **inner ELF** is not a separate file until you extract it (see §5). Use **`--explain-library`** to see which other ELFs import the same SONAME before opening Ghidra.

### Parent / child artifact edges

Find related blobs (e.g. ext2 slice → embedded SquashFS):

```powershell
python -m corpus --children "squashfs_0x" --jsonl
```

### Duplicate identical files across images

Global: any path sharing the same `files.md5` (not scoped to one path).

```powershell
python -m corpus --duplicates --jsonl
```

For one path (e.g. `etc/shadow`) use **`corpus file-history`** instead.

### DWARF (when index was built with `--dwarf`)

```powershell
python -m corpus --dwarf FUN_8028 --limit 30
```

## 4. Vulnerability scan (Syft SBOM + Grype)

Indexing with **`--sbom`** writes Syft JSON under **`work_corpus/sbom/version_<ver>/`**. Grype reads those reports directly (`grype sbom:PATH`). The corpus CLI wraps discovery and scanning so you do not hunt filenames by hand.

### List collected SBOMs

```powershell
$sbom = "work_corpus/sbom"
python -m corpus --list-sboms --sbom-dir $sbom --jsonl
python -m corpus --list-sboms --sbom-dir $sbom --collection "version:11.5.1.532678"
python -m corpus --list-sboms --sbom-dir $sbom --sbom-term "squashfs_0x00368538"
```

Each row includes **`grype_spec`** (`sbom:…`) and, when present, **`grype_report`** + severity summary from an existing **`.grype.json`**.

### Scan after a corpus search hit

```powershell
# Find the SquashFS carve in the index, then scan its SBOM
python -m corpus --sbom-for "squashfs_0x00368538" `
  --collection "version:11.5.1.532678" --grype --grype-output json

# Or pass the .syft.json path from --list-sboms
python -m corpus --grype --grype-sbom work_corpus/sbom/version_11.5.1.532678/....syft.json `
  --grype-output json
```

Reports default beside the SBOM as **`<same-stem>.grype.json`**. Reuse cached reports with **`--grype-skip-existing`**.

### Scan an entire release

```powershell
python -m corpus --grype --collection "version:11.5.1.532678" --grype-all `
  --grype-output json --grype-skip-existing
```

### Summarize existing Grype JSON (no rescan)

```powershell
python -m corpus --grype-summary --sbom-dir $sbom --collection "version:11.5.1.532678" --jsonl
```

### Useful flags

| Flag | Purpose |
|------|---------|
| **`--grype-fail-on high`** | Non-zero exit when high+ CVEs match (CI gates) |
| **`--grype-db-update`** | Refresh Grype vulnerability DB before scan |
| **`--grype-report-dir DIR`** | Write many **`.grype.json`** files when using **`--grype-all`** |
| **`--sbom-for`** | Map corpus **`images.path`** → SBOM via stable hash names (uses default DB) |

### Docker Compose (SBOM + Grype)

Syft and Grype ship in **`5268ac-corpus-runtime`**. Typical pipeline:

```powershell
docker compose -f docker/corpus-runtime/compose.yml build corpus
docker compose -f docker/corpus-runtime/compose.yml run --rm index-pkgstreams   # index + Syft SBOM
docker compose -f docker/corpus-runtime/compose.yml run --rm list-sboms           # sanity check
docker compose -f docker/corpus-runtime/compose.yml run --rm grype-sboms        # Grype all SBOMs
```

One release: use the **`corpus`** service (not **`grype-sboms`**) so flags are not replaced:

```powershell
docker compose -f docker/corpus-runtime/compose.yml run --rm corpus `
  --grype --grype-all --grype-output json --grype-skip-existing `
  --collection version:11.14.1.533857
```

First Grype run needs network to fetch the vulnerability DB.

Build-time **`--sbom`** appends rows to **`corpus_sbom_catalog.jsonl`** per collection for faster **`--sbom-for`** resolution. See **`docker/corpus-runtime/README.md`**.

## 5. Corpus → Ghidra MCP (reverse engineering)

Ghidra runs locally with **ghidra-mcp** (Cursor server **`user-ghidra`**, HTTP **`http://127.0.0.1:8089`**). **CodeBrowser must be open** with a project loaded — **`import_file`** fails in headless-only setups.

### Parse a search hit

Corpus lines split on **`::`**:

```text
work_corpus/.../embedded/squashfs_0x....bin::usr/sbin/httpd:SYMBOL:dynsym_export:FUNC:GLOBAL:cmdb_process
                              ^image on disk              ^firmware-inner path   ^symbol name (last field)
```

| Hit kind | Import strategy |
|----------|-----------------|
| **Symbol / rodata / soname / needed** on `…::usr/...` or `…::lib/...` | Extract **one inner ELF** from the SquashFS carve (below), then **`import_file`**. |
| **Kernel** (`vmlinux`, `FUN_8028`, kallsyms) | Prefer **`…/embedded/uimage_*.bin.sidecars/vmlinux.elf`** (already on disk). |
| **Text** on `tlv_extract/`, `_certs/`, `rwdata/` | Import or read the **host file** directly (often plain text / PEM / script). |
| **Whole SquashFS** | Do **not** import the `.bin` carve as the target binary — extract members first. |

Use **`--collection "version:11.14.1.533857"`** so hits stay on the release you care about (e.g. gateway tree **`gateway.c01.sbcglobal.net/firmware/.../11.14.1.533857-PROD/`** after indexing).

### Step A — Find candidates in the corpus

```powershell
python -m corpus --collection "version:11.14.1.533857" -F cmdb_process --kind symbol --jsonl --limit 20
python -m corpus --collection "version:11.14.1.533857" --explain-library libcm_server.so.0 --jsonl
python -m corpus --file-info "usr/sbin/httpd" --jsonl
```

Pick the **`image`** row (SquashFS carve or sidecar) and inner **`path`** (`usr/sbin/httpd`, `/usr/lib/libcm_server.so.0` — normalize without leading slash for extract).

### Step B — Host path for `import_file`

**Already a file on disk**

- **`…/tlv_extract/…`**, **`…/_certs/…`**, **`…/embedded/uimage_*.bin.sidecars/vmlinux.elf`**
- Optional SBOM tree: **`work_corpus/sbom/sources/<collection>/…`** (only if index was built with **`--sbom`** and materialize ran)

Convert to an **absolute** path (Ghidra on Windows needs e.g. `D:\electronics\5268ac\work_corpus\...`).

**Inner ELF inside SquashFS** (most userland hits)

One-shot extract with dissect (same library the indexer uses):

```powershell
python -c @"
from pathlib import Path
from lib2spy.pkgstream_corpus import iter_squashfs_files

sq = Path(r'work_corpus/pkgstream_corpus_by_version/version_11.14.1.533857/0061_5268.install/embedded/squashfs_0x....bin').resolve()
inner = 'usr/sbin/httpd'  # from hit after ::
out = Path('work_corpus/ghidra_import') / inner
out.parent.mkdir(parents=True, exist_ok=True)
for rel, data in iter_squashfs_files(sq):
    if rel.replace(chr(92), '/').lstrip('/') == inner.lstrip('/'):
        out.write_bytes(data)
        print(out.resolve())
        break
else:
    raise SystemExit('inner path not found in squashfs')
"@
```

For many ELFs from one rootfs, unpack once:

```python
from lib2spy.pkgstream_corpus import extract_squashfs_dissect_tree
extract_squashfs_dissect_tree("work_corpus/.../squashfs_0x....bin", "work_corpus/ghidra_import/version_11.14.1.533857/squashfs_0x....")
```

Then **`import_file`** each `work_corpus/ghidra_import/.../usr/sbin/httpd` (absolute path).

### Step C — MCP import and analyze

Use Cursor **CallMcpTool** on server **`user-ghidra`** (read tool schemas under **`mcps/user-ghidra/tools/`** first).

| Step | MCP tool | Notes |
|------|----------|--------|
| 1 | **`list_open_programs`** | See what is already loaded; note **`path`** vs **`executable_path`**. |
| 2 | **`import_file`** | **`file_path`** = absolute host ELF; **`project_folder`** e.g. `/5268/11.14.1.533857/usr/sbin`; **`auto_analyze`** true for ELFs. |
| 3 | **`list_open_programs`** again | Copy the row’s **`path`** for later calls. |
| 4 | **`search_functions`** | **`name_pattern`** = symbol from corpus (e.g. `cmdb_process`); **`program`** = full path from step 3. |
| 5 | **`decompile_function`** | **`address`** from search result; always pass **`program`**. |
| 6 | **`get_xrefs_to`** / **`get_xrefs_from`** | Same **`program`**; empty xrefs on MIPS PIC until analysis finishes — retry after **`run_analysis`**. |

**`program` parameter (critical):** After import, pass the firmware-style **`path`** from **`list_open_programs`** (e.g. **`/usr/lib/libcm_server.so.0`**), **not** only the basename. If several programs are open, omitting **`program`** targets the **active** tab (often the wrong binary).

**Kernel:** import **`vmlinux.elf`**, then always pass **`program`** = the row whose **`name`** matches **`*_ghidra_m00_kernel.elf`** or your project’s kernel domain name. Kernel VAs are often **`8028xxxx`** (KSEG0); see **ghidra-mcp-corpus** if **`get_function_by_address`** misses.

**Scale:** Keep **~5 programs** open in Ghidra; close between targets. Batch-hundred imports belong in headless Ghidra, not MCP.

### Step D — Corpus-assisted library graph in Ghidra

Before importing every `.so`:

1. **`python -m corpus --explain-library libcm_server.so.0`** — lists **providers** (SONAME) and **consumers** (DT_NEEDED).
2. Import **provider** ELFs first, then **consumers** (`httpd`, `cmd`, …).
3. In Ghidra, **`search_functions`** / **`decompile_function`** on the consumer; follow PLT/GOT to the provider if xrefs are thin.

Corpus **symbol hits do not include ELF addresses** — use Ghidra **`search_functions`** after import, or **DWARF** rows if the index was built with **`--dwarf`**.

### Example: 11.14.1.533857 install

```powershell
# 1) Corpus
python -m corpus --collection "version:11.14.1.533857" httpd --kind symbol --limit 15

# 2) Resolve carve (adjust dirname from hit)
$sq = "D:\electronics\5268ac\work_corpus\pkgstream_corpus_by_version\version_11.14.1.533857\0061_5268.install\embedded\squashfs_0x....bin"

# 3) Ghidra MCP (agent): import_file(file_path=<extracted httpd>, project_folder="/5268/11.14.1.533857")
# 4) list_open_programs → program="/usr/sbin/httpd" (or whatever path Ghidra assigned)
# 5) search_functions(name_pattern="cmdb", program="...") → decompile_function(...)
```

Pkgstream on disk (not indexed until ingest):  
`gateway.c01.sbcglobal.net/firmware/00D09E/11.14.1.533857-PROD/att-5268-11.14.1.533857_prod_lightspeed-install.pkgstream`

### Related Ghidra docs

- **[ghidra-mcp-corpus](../.cursor/skills/ghidra-mcp-corpus/SKILL.md)** — uImage → vmlinux-to-elf, ramdisk **`ih_load`**, **`run_script_inline`**, MCP limits.
- **[ghidra-vmlinux-extract](../.cursor/skills/ghidra-vmlinux-extract/SKILL.md)** — pull one **`FUN_8028…`** from a huge exported **`.bin.c`** without loading the full decompilation file.

## 6. End-to-end agent workflow

1. Confirm **`work_corpus/corpus/index.sqlite`** exists (or legacy **`corpus_index.sqlite`**); if missing, see **`reference/tools.md`** (build only when asked).
2. List collections (**`Get-ChildItem work_corpus/pkgstream_corpus_by_version`** or **`--versions`**).
3. Search with **`--collection "version:…"`** + **`--kind symbol`** / **`rodata`** / **`text`**.
4. **`--file-info`** / **`--explain-library`** to narrow files and `.so` dependencies.
5. Resolve **absolute** host paths (sidecar ELF, tlv file, or SquashFS extract).
6. **Ghidra MCP:** **`import_file`** → **`list_open_programs`** → **`search_functions`** / **`decompile_function`** with explicit **`program`**.

## 7. Buildroot stock vs manufacturer (`corpus/buildroot.py`)

Index a **Buildroot `target/`** tree (from `make -C cross/buildroot PROFILE=stock target` or a staged reference rootfs) as **`buildroot:<profile>`** (default profile **`2011.11`** for 5268AC ELFs). Compare against a firmware **`--collection`** already in the same SQLite DB.

```powershell
# Index stock reference (after Buildroot target/ exists)
python -m corpus --build-index --buildroot work_corpus/toolchain/output/target `
  --buildroot-profile 2011.11

# Summarize stock vs vendor paths
python -m corpus --buildroot-diff --collection version:11.14.1.533857 --buildroot-profile 2011.11

# One file
python -m corpus --buildroot-origin bin/busybox --collection version:11.14.1.533857
```

| `origin` | Meaning |
|----------|---------|
| `stock` | Same path and SHA-256 as Buildroot reference |
| `vendor_modified` | Path in Buildroot but different content (vendor patch) |
| `vendor_path` | Only on firmware (e.g. `lib2sp`, Broadcom blobs) |
| `buildroot_only` | In Buildroot reference but not in this collection |

`--list-collections` lists firmware **`collection:*`** slugs (carriers and file counts; **`--jsonl`** for image keys). **`--list-buildroot`** shows indexed `buildroot:*` images. Use **`--jsonl`** for machine-readable diff output.

### Cross-collection Buildroot versions report

One pass over every indexed **`collection:version:*`** image: join **`etc/os-release`** (`file_versions`, `source=release_file`) with **`bin/busybox`** `.comment` (`elf_strings`) and flag metadata vs toolchain mismatches (e.g. os-release **2013.05** but gcc **2011.11**).

```powershell
# Metadata only (fast)
python -m corpus --buildroot-versions-report --jsonl

# Limit to one collection
python -m corpus --buildroot-versions-report --collection version:11.14.1.533857

# Optional stock/vendor counts per indexed buildroot:<profile>
python -m corpus --build-index --buildroot work_corpus/toolchain/output/target --buildroot-profile 2011.11
python -m corpus --buildroot-versions-report --buildroot-profiles 2011.11,2013.05 --jsonl
```

| Flag | Role |
|------|------|
| `--buildroot-elf PATH` | Canonical ELF for `.comment` (default `bin/busybox`) |
| `--buildroot-profiles` | Comma-separated profiles; runs `diff_collection_vs_buildroot` counts only |

## 8. QEMU MIPS user-mode (Docker)

After corpus + Ghidra triage, run **MIPS32 BE** firmware binaries under Docker with **`qemu-mips-static`**. This does **not** replace the corpus index container — use **`docker/qemu-mips/`** for execution.

```powershell
docker compose -f docker/qemu-mips/compose.yml build 5268ac
docker compose -f docker/qemu-mips/compose.yml run --rm 5268ac stage-rootfs --collection "version:11.14.1.533857"
docker compose -f docker/qemu-mips/compose.yml run --rm 5268ac run-mips `
  /work/work_corpus/qemu_mips/sysroots/version_11.14.1.533857/bin/busybox --help
```

| Step | Command / path |
|------|----------------|
| Stage `lib/`, `usr/lib/` for QEMU `-L` | `stage-rootfs --collection version:…` → `work_corpus/qemu_mips/sysroots/` |
| uClibc link sysroot | `make -C cross sysroot-533857` → `work_corpus/toolchain/sysroots/` |
| Cross-compile harness | `docker compose … run --rm lab` → `cross-test` |
| Full workflow | **[qemu-mips-lab](../.cursor/skills/qemu-mips-lab/SKILL.md)** |

Requires a **materialized** `work_corpus/pkgstream_corpus_by_version/version_<ver>/…/squashfs_*.bin` tree (same as §4 Ghidra extract).

## Quick reference

| Goal | Command |
|------|---------|
| List staging collections | `Get-ChildItem work_corpus\pkgstream_corpus_by_version` |
| Version strings in index | `python -m corpus --versions` |
| Search (scoped) | `python -m corpus --collection "version:X" PATTERN` |
| Find file paths (scoped) | `python -m corpus find "PATH_GLOB" --collection "version:X"` |
| Symbols only | `… --kind symbol` |
| Rodata only | `… --kind rodata` |
| Resolve file / hash | `python -m corpus --file-info SUBSTRING` |
| Library graph | `python -m corpus --explain-library libfoo.so.0` |
| JSON output | add `--jsonl` |
| Ghidra import | extract inner ELF → **`import_file`** (absolute path) |
| Ghidra analyze | **`search_functions`** + **`decompile_function`** + **`program=`** |

## Related

- **`corpus/grep.py`** — CLI implementation
- **`corpus/index_db.py`** — schema, search, `file_info`, `version_rows`
- **[ghidra-mcp-corpus](../.cursor/skills/ghidra-mcp-corpus/SKILL.md)** — Ghidra MCP import and kernel workflow
- **[qemu-mips-lab](../.cursor/skills/qemu-mips-lab/SKILL.md)** — Docker + `qemu-mips-static` for firmware user-mode tests
- **`lib2spy/pkgstream_corpus.py`** — **`iter_squashfs_files`**, **`extract_squashfs_dissect_tree`**
- **`reference/tools.md`** — build index, pkgstream-root ingest, Docker, SBOM
- **`reference/firmware.md`** — CDN / pkgstream layout
