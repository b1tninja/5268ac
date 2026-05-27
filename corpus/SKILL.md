---
name: squashfs-corpus-index
description: >-
  Search or build the 5268ac firmware corpus SQLite index (SquashFS dissect +
  ELF symbols/strings + script lines). Use when the user asks to grep or search
  the dissect corpus, pkgstream (.pkgstream TLV + embedded squashfs), the
  gateway.c01.sbcglobal.net mirror, carved squashfs blobs, strings in
  libcm/httpd/.so, rwdata/cm, multi-carrier releases (--collection or
  version:* slugs), Docker corpus-runtime, --pkgstream-root, --jobs, SBOM/Syft
  (--sbom-source mount|auto|materialize), venv setup, or mentions
  python -m corpus, corpus grep, --build-index, corpus sqlite, or Ghidra MCP
  follow-up on corpus hits.
---

# SquashFS corpus index (5268ac)

## CLI entry point

Primary command (repo root):

```powershell
python -m corpus …
```

`tools/squashfs_corpus_grep.py` is a thin wrapper around the same **`corpus.grep`** CLI.

Default index path used in docs and Compose: **`work_corpus/corpus_index.sqlite`**. Staging for pkgstream ingest: **`work_corpus/pkgstream_corpus_by_version/`**.

## Docker corpus runtime (preferred for full gateway mirror)

When **`gateway.c01.sbcglobal.net/`** already exists on the host (local CDN mirror), **index it directly**. Do **not** run **`mirror-pkgstreams`** unless the user wants to refresh missing URLs from **`pkgstreams`**.

Compose mounts repo, mirror, and **`work_corpus/`** — see **`docker/corpus-runtime/README.md`**.

**Build image (once or after Dockerfile changes):**

```powershell
cd D:\electronics\5268ac
docker compose -f docker/corpus-runtime/compose.yml build corpus
```

**Fresh full index** (8 workers, symtab + DWARF, install + config + certs grouped by release):

```powershell
docker compose -f docker/corpus-runtime/compose.yml run --rm corpus `
  --build-index --fresh --max-file-mb 0 --max-strings-per-file 2000 `
  --symtab --dwarf --jobs 8 `
  --db /work/work_corpus/corpus_index.sqlite `
  --pkgstream-root /work/gateway.c01.sbcglobal.net `
  --pkgstream-work /work/work_corpus/pkgstream_corpus_by_version `
  --pkgstream-report-json /work/work_corpus/gateway_pkgstream_index_report.json
```

Add **`--sbom --sbom-dir /work/work_corpus/sbom --sbom-source auto`** when Syft SBOMs are wanted (see **SBOM / Syft** below). Omit **`--fresh`** to resume: completed SquashFS rows are skipped when path, SHA-256, and options match.

**Resume-friendly Compose service** (no **`--fresh`**, includes SBOM):

```powershell
docker compose -f docker/corpus-runtime/compose.yml run --rm index-pkgstreams
```

**Only refresh the mirror** (skip if local tree is already complete):

```powershell
docker compose -f docker/corpus-runtime/compose.yml run --rm mirror-pkgstreams
```

### `--pkgstream-root` collection behavior

Walking **`gateway.c01.sbcglobal.net`** (or any mirror root):

- Each **`.pkgstream`** is ingested (TLV, embedded SquashFS, uImage → kernel ELF when **`vmlinux-to-elf`** is available).
- **Default:** carriers are grouped into slugs like **`version:11.5.1.532678`** from firmware strings inside the install pkgstream, with path fallback.
- **Release-bundle rule:** in the same release directory (e.g. **`11.5.1.532678-PROD/`** plus **`5268-…-PROD-C/`** sidecars), **config**, **cms-certs**, and **eapol-certs** pkgstreams inherit the **install** carrier’s collection — they are not split into unrelated version buckets because of stray version-like strings in cert/config payloads.

Disable auto-version slugs with **`--no-pkgstream-version-collections`** and pass **`--collection SLUG`** instead.

## Python virtualenv (local / Windows host)

Work from repository root **`5268ac`**.

```powershell
cd D:\electronics\5268ac
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

- **`pyelftools`** — ELF symbols / rodata / SONAME / NEEDED.
- **`dissect.squashfs`** — SquashFS iteration for index ingest (**AGPL-3.0**, Python **3.10+**).

**Optional — embedded kernel ELF:**

```powershell
pip install -e D:\github\marin-m\vmlinux-to-elf
```

Without it, uImage paths fall back to indexing **`kernel_inner.bin`** only.

**Local fresh index** (same semantics as Docker, host paths):

```powershell
python -m corpus --build-index --fresh --max-file-mb 0 --jobs 8 `
  --db work_corpus/corpus_index.sqlite `
  --pkgstream-root gateway.c01.sbcglobal.net `
  --pkgstream-work work_corpus/pkgstream_corpus_by_version `
  --pkgstream-report-json work_corpus/gateway_pkgstream_index_report.json `
  --symtab --dwarf
```

## Manual multi-carrier ingest (single release)

For a **`firmware_<ver>/<ver>/`** download layout (not the gateway mirror tree), repeat **`--pkgstream`** with one **`--collection`** slug:

| Relative path | Role |
|---------------|------|
| **`install_package/*.pkgstream`** | Install bundle (SquashFS, uImage, TLV). |
| **`config/*.pkgstream`** | Configuration carrier. |
| **`eapol_certs/*.pkgstream`** | EAPOL / unified certs. |
| **`cms_certs/*.pkgstream`** | CMS cert bundle. |

```powershell
$c = "firmware_11.5.1.532678/11.5.1.532678"
$fw = "firmware_11.5.1.532678\11.5.1.532678"
python -m corpus --build-index --db work_corpus/corpus_index.sqlite `
  --collection $c --max-file-mb 0 --jobs 8 `
  --pkgstream "$fw\install_package\att-5268-11.5.1.532678_prod_lightspeed-install.pkgstream" `
  --pkgstream "$fw\config\att_config.pkgstream" `
  --pkgstream "$fw\eapol_certs\att_unified_eapol-certs.pkgstream" `
  --pkgstream "$fw\cms_certs\att_cms-certs.pkgstream"
```

On the gateway mirror, the same bundle grouping is automatic under **`--pkgstream-root`** when install + sidecars share a release directory.

## SBOM / Syft

**Indexing** still walks SquashFS via **dissect** (no full rootfs extract required for the SQLite corpus).

**Syft** is separate. With **`--sbom`**:

| `--sbom-source` | Behavior |
|-----------------|----------|
| **`auto`** (default in Compose) | Try **`mount -t squashfs -o loop,ro`** on the carved **`.bin`**, run Syft on the mountpoint, then unmount. On failure, fall back to materializing under **`<sbom-dir>/sources/`**. |
| **`mount`** | Require read-only mount; fail if the container cannot mount (needs **`CAP_SYS_ADMIN`** / privileged container or loop device). |
| **`materialize`** | Legacy: extract every file to **`sources/`** and run Syft on that tree. |

Mounted SBOM JSON is written under **`<sbom-dir>/mounted/`**; materialized fallback uses **`<sbom-dir>/sources/`**. Temporary mount parents default to **`<sbom-dir>/mounts/`** (override with **`--sbom-mount-root`**).

Example with SBOM in Docker:

```powershell
docker compose -f docker/corpus-runtime/compose.yml run --rm corpus `
  --build-index --fresh --max-file-mb 0 --jobs 8 --symtab --dwarf `
  --db /work/work_corpus/corpus_index.sqlite `
  --pkgstream-root /work/gateway.c01.sbcglobal.net `
  --pkgstream-work /work/work_corpus/pkgstream_corpus_by_version `
  --sbom --sbom-dir /work/work_corpus/sbom --sbom-source auto
```

Grype: **`grype sbom:/work/work_corpus/sbom/...`**.

## Modes (quick reference)

| Mode | Flags |
|------|--------|
| **Index search** | **`--db PATH`** + patterns; optional **`--collection`**. |
| **Explain library** | **`--explain-library libfoo.so.0`** — providers (SONAME) vs consumers (NEEDED). |
| **Build index** | **`--build-index`** + **`--pkgstream`**, **`--pkgstream-root`**, **`--image`**, **`--from-extracted`**, or **`--flash`**. |
| **Filesystem grep** | No **`--db`**; walks **`work_corpus/pkgstream_dissect_corpus/*`** or **`--roots`**. |

**`--fresh`**: delete DB + WAL/SHM before build.

**`--jobs N`**: parallel ELF workers inside each SquashFS image (SQLite writes stay in the parent).

**`--max-file-mb 0`**: unlimited size (needed for large **`vmlinux.elf`**).

Do not combine **`--pkgstream`** with **`--pkgstream-root`**, **`--image`**, or **`--from-extracted`** in one command.

## Search the index

**Whole DB:**

```powershell
python -m corpus --db work_corpus/corpus_index.sqlite -i rwdata "/rwdata/cm"
```

**One collection** (e.g. **`version:11.5.1.532678`** from **`--pkgstream-root`**):

```powershell
python -m corpus --db work_corpus/corpus_index.sqlite `
  --collection "version:11.5.1.532678" -i httpd
```

**Kinds:** **`text`**, **`symbol`**, **`rodata`**, **`soname`**, **`needed`** (repeat **`--kind`**).

**SONAME vs NEEDED:** dynamic linker uses **`libfoo.so.0`**, not necessarily **`libfoo.so`**. Rebuild the index after indexer upgrades so **`elf_soname`** / **`elf_needed`** tables are populated.

```powershell
python -m corpus --db work_corpus/corpus_index.sqlite `
  --explain-library libcm_server.so.0
```

Output: **`IMAGE_PATH::inner/path:line:text`**, or **`SYMBOL:`** / **`RODATA[section]:`** prefixes.

## Build from blobs / dissect trees

```powershell
python -m corpus --build-index --db work_corpus/corpus_index.sqlite --from-extracted
python -m corpus --build-index --db work_corpus/corpus_index.sqlite --image "PATH\to\*_squashfs_*.bin" --jobs 8
```

## After corpus hits: Ghidra MCP

The SQLite index stores **text**, **symbols**, and **rodata strings** — not decompilation or xrefs. For **`vmlinux.elf`**, **`httpd`**, or **`.so`** hits that need function bodies or cross-references, use **Ghidra MCP** (HTTP **8089**). See **[ghidra-mcp-corpus](../.cursor/skills/ghidra-mcp-corpus/SKILL.md)** for importing corpus carves via **`/import_file`**.

## Agent workflow

1. If **`gateway.c01.sbcglobal.net/`** exists locally → **`docker compose … run --rm corpus`** with **`--pkgstream-root`**; **do not** mirror-download unless asked.
2. If **`corpus_index.sqlite`** is missing or stale → **`--build-index --fresh`** (or resume without **`--fresh`**).
3. Prefer **`--db`** search over filesystem walk when the index covers those images.
4. Scope searches with **`--collection`** when the DB holds many **`version:*`** releases.
5. Use **`--kind symbol`** / **`rodata`** for **`cmdb_*`**, **`httpd`**, **`libc`**; **`--kind soname`** / **`needed`** or **`--explain-library`** for linker graphs.
6. For SBOM in Docker → **`--sbom --sbom-source auto`** (mount first); use **`materialize`** only when mount is impossible.
7. For decompilation / xrefs → **Ghidra MCP**, not another corpus rebuild.

## Related paths

- **`corpus/grep.py`** — CLI and **`--build-index`** orchestration.
- **`corpus/index_db.py`** — schema, **`plan_pkgstream_collections`**, **`build_index_from_pkgstream_root`**, search.
- **`corpus/sbom.py`** — **`mounted_squashfs_readonly`**, **`run_syft_from_squashfs_mount`**, materialize fallback.
- **`docker/corpus-runtime/`** — Dockerfile, Compose, runtime README.
- **`requirements.txt`** — **`pyelftools`**, **`dissect.squashfs`**.
- **`lib2spy`** — **`iter_pkgstream_artifacts`**, pkgstream TLV / embedded SquashFS.
- **`reference/firmware.md`**, **`reference/gateway_s3_bucket.md`** — CDN layout and **`pkgstreams`** catalog.
- [**ghidra-mcp-corpus**](../.cursor/skills/ghidra-mcp-corpus/SKILL.md) — batch import from corpus paths.
