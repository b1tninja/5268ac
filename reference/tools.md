# Firmware Corpus Tooling

The old carving package has been removed. Firmware search and artifact
indexing are split by owner:

- `lib2spy` parses and verifies `.pkgstream` carriers and exposes
  `lib2spy.iter_pkgstream_artifacts()`.
- `paceflash` opens Pace NAND / logical flash dumps and exposes
  `paceflash.iter_flash_corpus_artifacts()`.
- `boardfs` owns MTD layout, `FlashImage`, UBI media scans, and ext2 probes.
- `uboot.uimage` owns legacy U-Boot `image_header` parsing and member extraction.
- `corpus` builds and searches the SQLite index over artifacts from those public APIs.

## Index Carriers

```bash
python -m corpus --build-index --db output/corpus.sqlite \
  --pkgstream firmware_11.5.1.532678/.../install.pkgstream
```

The pkgstream path indexes TLV files, scripts, PKCS#7 / certificate metadata,
embedded SquashFS images, embedded uImages, and version hints. The carrier parser
and provenance offsets come from `lib2spy`.

To rebuild the full gateway mirror as fresh version-grouped collections:

```bash
python -m corpus --build-index --fresh --max-file-mb 0 \
  --db work_corpus/corpus_index.sqlite \
  --pkgstream-root gateway.c01.sbcglobal.net \
  --pkgstream-report-json work_corpus/gateway_pkgstream_index_report.json \
  --sbom
```

`--pkgstream-root` recursively finds every `.pkgstream`. By default, `corpus`
groups carriers into collection slugs like `version:11.5.1.532678` using
firmware-looking versions inside the pkgstream bytes, with path-version fallback
for config/cert carriers and `version:unknown` when neither source contains a
firmware version.

With `--sbom`, indexed SquashFS roots are materialized under `work_corpus/sbom/`
and Syft JSON files are emitted beside them. Grype can scan those reports
directly:

```bash
grype sbom:work_corpus/sbom/<generated>.syft.json
```

If Syft / Grype are not installed on the host, build the helper image:

```bash
docker build -t 5268ac-corpus-tools -f docker/corpus-tools/Dockerfile docker/corpus-tools
docker run --rm -v "$PWD:/work" 5268ac-corpus-tools \
  grype sbom:/work/work_corpus/sbom/<generated>.syft.json
```

See `docker/corpus-tools/README.md` for PowerShell examples and manual Syft
commands.

For a complete reproducible runtime, build `docker/corpus-runtime/`. It includes
the local project packages (`corpus`, `lib2spy`, `boardfs`, `unand`, `paceflash`),
`dissect`, Python ELF tooling, `vmlinux-to-elf`, Syft, and Grype:

```bash
docker build -t 5268ac-corpus-runtime -f docker/corpus-runtime/Dockerfile .
docker run --rm -v "$PWD:/work" 5268ac-corpus-runtime \
  --build-index --fresh --max-file-mb 0 \
  --db work_corpus/corpus_index.sqlite \
  --pkgstream-root gateway.c01.sbcglobal.net \
  --pkgstream-report-json work_corpus/gateway_pkgstream_index_report.json \
  --sbom
```

See `docker/corpus-runtime/README.md` for PowerShell examples and tool
passthrough commands.

The runtime can also cache the known `.pkgstream` URL list from `pkgstreams`.
The cache path is manifest-driven through the Python `pkgstream-mirror` helper,
so future URL updates only touch `pkgstreams`. Use the existing host mirror as a
volume to avoid redownloading between runs:

```bash
docker run --rm -v "$PWD:/work" 5268ac-corpus-runtime \
  mirror-pkgstreams --pkgstreams /work/pkgstreams --out /work/gateway.c01.sbcglobal.net
```

The same mounted workflow is available through Docker Compose:

```bash
docker compose -f docker/corpus-runtime/compose.yml run --rm mirror-pkgstreams
docker compose -f docker/corpus-runtime/compose.yml run --rm index-pkgstreams
```

The Compose workflow also mounts `work_corpus/`, so pkgstream extracts, SBOM
sidecars, generated reports, and SQLite databases persist on the host. The index
uses relative artifact paths like `work_corpus/pkgstream_corpus_by_version/...`,
which can be opened later from the host or passed to tools such as Ghidra.
When indexing a mirror root, config and cert pkgstreams under the same release
directory are grouped into the install carrier's firmware-version collection.
ELF analysis inside SquashFS images can be parallelized with `--jobs N`; the
Compose `index-pkgstreams` service uses `--jobs 8`. It is also resumable by
default: completed SquashFS image analyses are marked in the SQLite index by
path, SHA-256, analysis version, and options hash, so reruns skip matching
completed images unless you explicitly pass `--fresh`.

Or bake the mirror into an early Docker layer:

```bash
docker build -t 5268ac-corpus-runtime:with-pkgstreams \
  --target runtime-with-pkgstreams \
  -f docker/corpus-runtime/Dockerfile .
```

## Index Flash Dumps

```bash
python -m corpus --build-index --db output/corpus.sqlite \
  --flash "PACE 5268AC S34ML01G1@TSOP48.BIN"
```

The flash path indexes MTD metadata, loader / `mtdoops` probes, MTD partition
bytes, `opentla4` metadata, ext2 files, and embedded SquashFS images discovered
by `paceflash`.

## Search

```bash
python -m corpus --db output/corpus.sqlite "cmdb_attr_setdbdir"
python -m corpus --db output/corpus.sqlite --kind text "OPENWRT_RELEASE"
python -m corpus --db output/corpus.sqlite --explain-lib libcms_core.so
```

## Direct APIs

```python
from lib2spy import iter_pkgstream_artifacts
from paceflash import iter_flash_corpus_artifacts
from corpus import connect_db, index_artifact

conn = connect_db("output/corpus.sqlite")
for artifact in iter_pkgstream_artifacts("install.pkgstream", collection="11.5.1.532678"):
    index_artifact(conn, artifact)
for artifact in iter_flash_corpus_artifacts("flash.bin", collection="tsop48"):
    index_artifact(conn, artifact)
```

## Domain Helpers

- `boardfs.flash_layout` replaces the old MTD layout helper surface.
- `boardfs.ubi_carve` and `boardfs.ubifs_decode` provide UBI / UBIFS triage.
- `boardfs.ext2_lite` and `boardfs.ext2_probe` provide lightweight ext2 checks.
- `opentl.extract.verify_uimage_in_extract()` verifies uImage headers inside an
  assembled OpenTL ext2 image.
- `uboot.uimage` parses uImage headers, MULTI members, compression metadata, and
  Ghidra import manifests.
- `corpus.vmlinux_elf.try_vmlinux_to_elf()` calls `vmlinux-to-elf` directly.
