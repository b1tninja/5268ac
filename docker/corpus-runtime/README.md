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

```powershell
docker compose -f docker/corpus-runtime/compose.yml build corpus
docker compose -f docker/corpus-runtime/compose.yml run --rm mirror-pkgstreams
docker compose -f docker/corpus-runtime/compose.yml run --rm index-pkgstreams
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
`--sbom-source materialize` to force the old behavior. Mount mode needs Docker
mount privileges, for example a privileged container or equivalent
`CAP_SYS_ADMIN`/loop-device access.

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
  --db work_corpus/corpus_index.sqlite `
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
  --db work_corpus/corpus_index.sqlite `
  --pkgstream-root /opt/pkgstream-mirror/gateway.c01.sbcglobal.net `
  --pkgstream-report-json work_corpus/gateway_pkgstream_index_report.json `
  --sbom
```

## Index a Pkgstream Mirror

Mount the repository at `/work`; generated SQLite databases, reports, staged
rootfs trees, and SBOMs will be written back to the host under `work_corpus/`.

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime `
  --build-index --fresh --max-file-mb 0 `
  --db work_corpus/corpus_index.sqlite `
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

`--sbom` emits Syft JSON files under `work_corpus/sbom/`. Grype can scan those
reports directly:

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime `
  grype sbom:/work/work_corpus/sbom/<name>.syft.json
```

Write Grype JSON output beside the SBOM:

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-runtime `
  grype sbom:/work/work_corpus/sbom/<name>.syft.json `
  -o json --file /work/work_corpus/sbom/<name>.grype.json
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
