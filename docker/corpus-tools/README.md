# Corpus Tools Container

Helper image for third-party corpus tooling that is useful but awkward to keep
installed on every Windows host. It currently includes:

- `syft` for SBOM generation.
- `grype` for vulnerability scanning from Syft SBOMs or materialized rootfs
  directories.
- Small shell utilities (`jq`, `file`, archive tools) for inspecting outputs.

## Build

From the repository root:

```powershell
docker build -t 5268ac-corpus-tools -f docker/corpus-tools/Dockerfile docker/corpus-tools
```

## Run Syft

Mount the repository at `/work` and scan a materialized rootfs or SBOM source:

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-tools `
  syft /work/work_corpus/sbom/sources/<source-dir> `
  -o syft-json=/work/work_corpus/sbom/<name>.syft.json
```

The `corpus --sbom` path invokes local `syft` by default. If Syft is not
installed on the host, `corpus --sbom` still materializes rootfs directories
under `work_corpus/sbom/sources/` before recording the Syft failure. Run this
container against those materialized directories to produce the SBOMs manually.

## Run Grype

Scan a generated Syft JSON report:

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-tools `
  grype sbom:/work/work_corpus/sbom/<name>.syft.json
```

Write JSON results:

```powershell
docker run --rm -v "${PWD}:/work" 5268ac-corpus-tools `
  grype sbom:/work/work_corpus/sbom/<name>.syft.json `
  -o json --file /work/work_corpus/sbom/<name>.grype.json
```

## Interactive Shell

```powershell
docker run --rm -it -v "${PWD}:/work" 5268ac-corpus-tools shell
```
