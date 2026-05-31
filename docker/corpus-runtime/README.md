# Corpus Runtime Container

Full Docker runtime for corpus indexing and firmware triage. This image installs
the local project packages plus third-party analysis tools so Windows hosts do
not need a Python environment, Syft, Grype, or `vmlinux-to-elf` installed
globally.

Included project packages:

- `corpus`
- `lib2spy`
- `boardfs`
- `unand`
- `uboot`
- `opentl`
- `paceflash`

Included analysis tools:

- `dissect.squashfs` and `dissect.extfs`
- `pyelftools`, `capstone`, and `lief`
- `vmlinux-to-elf`
- `syft` and `grype`
- `gitleaks` (optional `--secrets-gitleaks` on materialized rootfs trees)
- `binutils`, `elfutils`, `squashfs-tools`, `jq`, and `file`

## Build

Build from the repository root. The context is the whole repo so the editable
project install can include all local packages; `.dockerignore` keeps firmware
dumps, Ghidra state, and generated corpora out of the image build context.

```powershell
docker build -t 5268ac-corpus-runtime -f docker/corpus-runtime/Dockerfile .
```

## Compose Workflow

Docker Compose is the preferred path when you want to reuse existing host
artifacts. The Compose file mounts the repository, `gateway.c01.sbcglobal.net/`,
and `work_corpus/` into the container. That means existing pkgstreams are reused
in place, the mirror refresh only downloads missing files, and expensive outputs
such as pkgstream extracts, kernel sidecars, temporary SBOM source trees, SBOM
JSON, reports, and SQLite databases stay on the host.

**Fresh reindex (NAND → gateway Z→A)**

`reindex` (alias: `fresh-index-gateway-z2a`) runs preflight checks, wipes
`work_corpus/corpus/index.sqlite`, indexes the three `nands/*.BIN` dumps, then
ingests every `.pkgstream` under `gateway.c01.sbcglobal.net` whose path contains
`00D09E` (PROD, ALPHA, lab, and any other mirror subtree for this device), highest
release version first, with `--symtab`, `--dwarf`, `--sbom`, and `--secrets`
(+ Gitleaks when SBOM trees materialize), then runs Grype on SBOMs.

```powershell
docker compose -f docker/corpus-runtime/compose.yml build corpus
# optional: docker compose -f docker/corpus-runtime/compose.yml run --rm mirror-pkgstreams
docker compose -f docker/corpus-runtime/compose.yml run --rm reindex
```

Resume after an interrupted run (keeps `index.sqlite`; corpus skips completed analyses):

```powershell
$env:RESUME = "1"
docker compose -f docker/corpus-runtime/compose.yml run --rm reindex
```

Tweaks:

```powershell
$env:PKGSTREAM_PATH_FILTER = "00D09E" # default; only index 5268AC device tree
$env:FRESH_INDEX = "1"          # full wipe + restart (default)
$env:SBOM_SOURCE = "materialize" # default in fresh-index script; avoids squashfuse on Docker Desktop
$env:SKIP_NANDS = "1"            # pkgstreams + Grype only
$env:SKIP_GRYPE = "1"            # index only, scan later with grype-sboms
$env:CORPUS_JOBS = "4"           # default in fresh-index script; use 1 if Bus error persists
$env:CORPUS_SQLITE_JOURNAL = "wal"   # default; allows concurrent grep during index
$env:CORPUS_SQLITE_MMAP = "0"        # default on Docker Desktop bind mounts
$env:RESUME = "1"                # after crash: keep index.sqlite, skip completed ingests
```

### Bus error / `database disk image is malformed`

Common on **Docker Desktop for Windows** when `work_corpus/` and `gateway.c01.sbcglobal.net/` are bind-mounted from NTFS:

| Symptom | Likely cause | Mitigation |
|---------|--------------|------------|
| **`Bus error (core dumped)`** during pkgstream phase | **squashfuse** FUSE on bind mount, **lief**/DWARF in `--jobs` workers, or **vmlinux-to-elf** on a bad kernel carve | `SBOM_SOURCE=materialize`, `CORPUS_JOBS=1`, resume with `RESUME=1 SKIP_NANDS=1` |
| **`database disk image is malformed`** on grep | Stale journal sidecars or mmap on bind mount | Defaults: `CORPUS_SQLITE_JOURNAL=wal`, `CORPUS_SQLITE_MMAP=0`; remove stale `index.sqlite-wal`/`-shm` after a crash |
| **`attempt to write a readonly database`** on grep | Indexer used **`journal_mode=delete`** while grep opened read-only | Use WAL (compose default) or wait for index to finish |
| Crash mid **phase 2/3** | One of three firmware trees (PROD / ALPHA / lab) | Script now indexes each `--pkgstream-root` separately; completed trees are skipped on resume |

Recovery after Bus error:

```powershell
$env:RESUME = "1"
$env:SKIP_NANDS = "1"
$env:SBOM_SOURCE = "materialize"
$env:CORPUS_JOBS = "1"
docker compose -f docker/corpus-runtime/compose.yml run --rm reindex
```

If it still crashes, temporarily remove `--dwarf` from `fresh_index_gateway_z2a.sh` (or index one release via `index-release` + `PKGSTREAM_ROOT`).

```powershell
docker compose -f docker/corpus-runtime/compose.yml build corpus
docker compose -f docker/corpus-runtime/compose.yml run --rm mirror-pkgstreams
docker compose -f docker/corpus-runtime/compose.yml run --rm index-pkgstreams
docker compose -f docker/corpus-runtime/compose.yml run --rm list-sboms
docker compose -f docker/corpus-runtime/compose.yml run --rm grype-sboms
```

**Index + SBOM + Grype (typical pipeline)**

1. **`index-pkgstreams`** — builds `work_corpus/corpus/index.sqlite`, stages pkgstreams, runs **Syft** (`--sbom`) into `work_corpus/sbom/version_<ver>/`.
2. **`list-sboms`** — lists `.syft.json` files and `grype_spec` lines (optional sanity check).
3. **`grype-sboms`** — runs **Grype** on every SBOM (`--grype-all`), writing `*.grype.json` next to each report (`--grype-skip-existing` for resume).

**Secret scanning (`--secrets`)**

- Inline rules during indexing: PEM private keys, `lightspeed_p12=`, `gw:devkey`, `gw:authcode`, AWS key ids, etc. → SQLite `secret_findings` + `work_corpus/secrets/<collection>/*.secrets.json`.
- **`index-pkgstreams-secrets`** — gateway index with `--secrets` and `--secrets-gitleaks` (Gitleaks on SBOM-materialized trees when `--sbom` is enabled).
- **`index-flash-secrets`** — NAND dump index with `--secrets` (default collection `nand:@<basename>`).
- **`list-secrets`** / **`--secrets-summary`** — list reports or aggregate by rule from the DB.

```powershell
docker compose -f docker/corpus-runtime/compose.yml run --rm index-flash-secrets
docker compose -f docker/corpus-runtime/compose.yml run --rm corpus `
  --collection "nand:@PACE 5268AC S34ML01G1@TSOP48.BIN.BAK" --kind secret lightspeed_p12
docker compose -f docker/corpus-runtime/compose.yml run --rm list-secrets
```

### One release directory (not the whole gateway)

Use **`index-release`** — same `cap_add` / `security_opt` as **`index-pkgstreams`**
(bare `corpus` + `docker compose run --cap-add` does **not** get mount privileges on
Windows; `docker compose run --security-opt` is not supported there either).

```powershell
$env:PKGSTREAM_ROOT = "/work/gateway.c01.sbcglobal.net/firmware/00D09E/11.14.1.533857-PROD"
$env:INDEX_REPORT_JSON = "/work/work_corpus/reports/11.14.1.533857-PROD_index_report.json"
docker compose -f docker/corpus-runtime/compose.yml run --rm index-release
# If SquashFS mounts fail on Docker Desktop: $env:SBOM_SOURCE = "materialize"

$env:CORPUS_COLLECTION = "version:11.14.1.533857"
docker compose -f docker/corpus-runtime/compose.yml run --rm grype-collection
docker compose -f docker/corpus-runtime/compose.yml run --rm list-sboms-collection
```

Ad-hoc queries (grep, `--grype-summary`, `--index-status`) can still use the lightweight
**`corpus`** service — only indexing needs **`index-release`** / **`index-pkgstreams`**.

```powershell
docker compose -f docker/corpus-runtime/compose.yml run --rm corpus `
  --grype-summary --collection version:11.14.1.533857 --jsonl
```

Compose volumes are runtime mounts. They are available to `mirror-pkgstreams`
and `index-pkgstreams`, but not to ordinary `docker build` layers. Use the
`runtime-with-pkgstreams` target only when you deliberately want a self-contained
image cache populated during the build.

The `index-pkgstreams` service is resume-friendly by default. It does not pass
`--fresh`, so completed SquashFS analyses remain in the SQLite index and can be
skipped on later runs when the artifact path, SHA-256, analysis version, and
indexing options match. Use `--fresh` manually only when you intentionally want
to discard the resumable state.

The service also uses `--jobs 8`, which parallelizes ELF analysis inside
SquashFS images while keeping SQLite writes in the parent process. Each SquashFS
image is written in a single transaction, so symbol-heavy ELFs do not pay
per-row commit overhead.

The index stores host-usable paths relative to the mounted work tree. For
example, a SquashFS payload found inside a pkgstream is persisted under
`work_corpus/pkgstream_corpus_by_version/...` and the SQLite `images.path` row
points at that relative file. Recursive SquashFS contents are indexed from the
SquashFS image, but they are not promoted to primary artifacts by default; SBOM
source trees under `work_corpus/sbom/sources/` are sidecars for Syft reuse.
Pkgstream collections are planned by release directory, so sibling config,
CMS-certs, and EAPOL-certs carriers inherit the install carrier's firmware
version collection.

When `--sbom` is enabled, `--sbom-source auto` is the default. It first tries to
run Syft against a temporary read-only SquashFS mount and falls back to the
legacy materialized source tree if the container cannot mount. Use
`--sbom-source mount` when you want mounting to be required, or
`--sbom-source materialize` to force the old behavior. Mount mode needs a **privileged** container (`x-index-privileged` in
`compose.yml`: `privileged: true` plus `CAP_SYS_ADMIN`). On **Docker Desktop
(Windows)** loop mounts against bind-mounted `work_corpus/` paths often still
return `wrong fs type` / `bad superblock` (no kernel `squashfs` module on Docker
Desktop). With `--sbom-source auto`, corpus tries **`squashfuse`** next, then
**`syft squashfs:carve.bin`** (no full rootfs extract). Gitleaks runs on
mounted trees only. Use `--sbom-source materialize` only when you explicitly
want a dissect-extracted tree under `work_corpus/sbom/sources/`.

## Pkgstream Mirror Cache

The repository `pkgstreams` file is the source of truth for known gateway
firmware URLs. The image includes a Python `pkgstream-mirror` helper in the
early `runtime-base` stage. The `pkgstream-cache` stage copies only `pkgstreams`
and runs that helper before project source is copied, so source edits do not
invalidate the downloaded pkgstream cache layer. By default it downloads only
`.pkgstream` entries; pass `--all-files` when using the helper manually if you
also want XML, `.bin`, and other listed firmware files.

Use a host volume when you want to avoid rebuilding the image and preserve
downloads across runs. Put or keep your local mirror at
`gateway.c01.sbcglobal.net/` and mount the repository at `/work`.

Refresh the mounted mirror without redownloading existing files:

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime `
  mirror-pkgstreams `
  --pkgstreams /work/pkgstreams `
  --out /work/gateway.c01.sbcglobal.net `
  --jsonl
```

Then index the mounted mirror:

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime `
  --build-index --fresh --max-file-mb 0 `
  --pkgstream-root gateway.c01.sbcglobal.net `
  --pkgstream-report-json work_corpus/gateway_pkgstream_index_report.json `
  --sbom
```

To bake the known pkgstreams into an image layer, build the dedicated target.
The download happens in the `pkgstream-cache` stage before project source is
copied, so Docker can reuse that layer when code changes but `pkgstreams` does
not:

```powershell
docker build -t 5268ac-corpus-runtime:with-pkgstreams `
  --target runtime-with-pkgstreams `
  -f docker/corpus-runtime/Dockerfile .
```

Index from the baked mirror without mounting `gateway.c01.sbcglobal.net/`:

```powershell
docker run --rm -v "${PWD}/work_corpus:/work/work_corpus" `
  5268ac-corpus-runtime:with-pkgstreams `
  --build-index --fresh --max-file-mb 0 `
  --pkgstream-root /opt/pkgstream-mirror/gateway.c01.sbcglobal.net `
  --pkgstream-report-json work_corpus/gateway_pkgstream_index_report.json `
  --sbom
```

## Index a Pkgstream Mirror

Mount the repository at `/work`; generated SQLite databases, reports, staged
rootfs trees, and SBOMs will be written back to the host under `work_corpus/`.
The corpus index defaults to **`work_corpus/corpus/index.sqlite`** (`--db` optional).

The entrypoint sets **`PYTHONPATH=/work`** when `pyproject.toml` is mounted, so
`python -m corpus` uses the live repo without rebuilding the image after code changes.

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime `
  --build-index --fresh --max-file-mb 0 `
  --pkgstream-root gateway.c01.sbcglobal.net `
  --pkgstream-report-json work_corpus/gateway_pkgstream_index_report.json `
  --sbom
```

The default command is `python -m corpus`, so corpus flags can be passed
directly. The same command can also be written explicitly:

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime corpus --help
```

## Scan SBOMs with Grype

`index-pkgstreams` enables **`--sbom`** (Syft). Prefer the **`grype-sboms`** Compose
service or the corpus CLI wrapper (same container image):

```powershell
docker compose -f docker/corpus-runtime/compose.yml run --rm grype-sboms
```

Equivalent one-off:

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime `
  --grype --grype-all --grype-output json --grype-skip-existing
```

Raw Grype against a single report:

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime `
  grype sbom:/work/work_corpus/sbom/version_<ver>/<name>.syft.json `
  -o json --file /work/work_corpus/sbom/version_<ver>/<name>.grype.json
```

## Other Tools

Run bundled project CLIs and third-party tools through the same image:

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime paceflash --help
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime boardfs --help
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime vmlinux-to-elf --help
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime syft version
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime grype version
```

Interactive shell:

```powershell
docker run --rm -it -v "${PWD}:/work" 5268ac-corpus-runtime shell
```
