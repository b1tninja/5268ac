# Cross compilation and MIPS user-mode testing (5268AC)

This directory holds **host-side** tooling to build and run **MIPS32 big-endian** code for Pace/ATT 5268AC firmware. Two complementary paths exist:

| Path | Compiler | libc | Use when |
|------|----------|------|----------|
| **Dockcross** (`5268ac` image) | `mips-unknown-linux-gnu-gcc` | glibc (dockcross sysroot) | Quick smoke tests, generic MIPS harnesses |
| **Buildroot vendor** ([`buildroot/`](buildroot/)) | `mips-unknown-linux-uclibc-gcc` 4.6.2 | uClibc 0.9.32 | Linking against **real device** `.so` files, ABI-matched objects |

Shipped firmware (e.g. **11.14.1.533857**) uses **uClibc** and **Buildroot 2011.11** in ELF `.comment` strings even when `etc/os-release` says **2013.05**. For production PoCs and library calls, prefer the **vendor toolchain + firmware sysroot**.

Dynamic execution (QEMU) is **`docker/qemu-mips/`** — see [`.cursor/skills/qemu-mips-lab/SKILL.md`](../.cursor/skills/qemu-mips-lab/SKILL.md).

## Layout

| Path | Role |
|------|------|
| [`Makefile`](Makefile) | Top-level targets: dockcross wrapper, 533857 sysroot, link test |
| [`Dockerfile`](Dockerfile) | Extends `dockcross/linux-mips`; optional pkgstream extract (legacy lab image) |
| [`test.c`](test.c) | Minimal Hello World for compile/link/QEMU checks |
| [`buildroot/`](buildroot/) | Rebuild **2011.11** / **2013.05** Buildroot; Dockerized `mips-unknown-linux-uclibc-gcc` |
| [`prepare_link_sysroot.sh`](prepare_link_sysroot.sh) | Merge Buildroot host sysroot + firmware `lib/` for `--sysroot` |
| [`firmware_link_test.sh`](firmware_link_test.sh) | Link `test.c` against device uClibc; output under `work_corpus/toolchain/` |

Artifacts live under **`work_corpus/`** (gitignored): `toolchain/output/`, `toolchain/sysroots/`, `qemu_mips/sysroots/`.

## Quick start — vendor uClibc (11.14.1.533857)

Requires an indexed corpus tree (`work_corpus/pkgstream_corpus_by_version/version_11.14.1.533857/…`).

```powershell
# What the firmware actually reports (os-release vs ELF .comment)
make -C cross fingerprint

# Cross compiler (long; Ubuntu 12.04 Docker — see buildroot/README.md)
make -C cross vendor-toolchain
make -C cross abi-check

# Stage device libs from install SquashFS; merge link sysroot; link test
make -C cross sysroot-533857
make -C cross link-sysroot-533857
make -C cross firmware-link-test
```

**Compiler:** `work_corpus/toolchain/output/host/usr/bin/mips-unknown-linux-uclibc-gcc`  

**Link sysroot:** `work_corpus/toolchain/sysroots/version_11.14.1.533857-link`

Example compile flags:

```text
-O0 -pipe -march=mips1
--sysroot=work_corpus/toolchain/sysroots/version_11.14.1.533857-link
-Wl,-rpath-link,work_corpus/toolchain/sysroots/version_11.14.1.533857-link/lib
```

Full Buildroot profiles, stock-vs-firmware diff, and Docker details: **[`buildroot/README.md`](buildroot/README.md)**.

## Quick start — dockcross (glibc smoke test)

Builds the **`5268ac-dockcross`** wrapper script that shells into a minimal dockcross container (`cross/Dockerfile`). For the full firmware lab image, use **`docker/qemu-mips/`** (image tag **`5268ac`**).

```powershell
make -C cross docker      # build 5268ac-dockcross from cross/Dockerfile
make -C cross toolchain   # write ./5268ac-dockcross helper
make -C cross test        # compile test.c, run under qemu-mips-static
```

Or use upstream dockcross directly:

```powershell
make -C cross vanilla_toolchain   # ./5268ac-dockcross from dockcross/linux-mips
```

This path does **not** match the gateway’s uClibc userspace ABI for linking vendor libraries.

## Quick start — QEMU with firmware rootfs

After staging (either path below), run ELFs under **`qemu-mips-static`**:

```powershell
docker compose -f docker/qemu-mips/compose.yml build 5268ac
docker compose -f docker/qemu-mips/compose.yml run --rm 5268ac stage-rootfs --collection version:11.14.1.533857
docker compose -f docker/qemu-mips/compose.yml run --rm 5268ac run-mips `
  /work/work_corpus/qemu_mips/sysroots/version_11.14.1.533857/bin/busybox --help
```

| Staged by | Sysroot path |
|-----------|----------------|
| `make -C cross sysroot-533857` | `work_corpus/toolchain/sysroots/version_11.14.1.533857/` |
| `5268ac stage-rootfs` (qemu-mips compose) | `work_corpus/qemu_mips/sysroots/version_11.14.1.533857/` |

Run the cross-built link test:

```powershell
docker compose -f docker/qemu-mips/compose.yml run --rm 5268ac run-mips `
  /work/work_corpus/toolchain/firmware_link_test
```

## Makefile targets

| Target | Description |
|--------|-------------|
| `docker` / `toolchain` / `test` | Dockcross **`5268ac`** wrapper + glibc Hello World under QEMU |
| `libtest` | Legacy example linking against an extracted cpio `lib/` |
| `vendor-toolchain` | `make -C buildroot PROFILE=toolchain cross_compiler` |
| `vendor-test` | Compile `test.c` with vendor gcc (host path, no firmware sysroot) |
| `fingerprint` | Corpus evidence for 533857 Buildroot/gcc/uClibc |
| `abi-check` | Compare vendor gcc output vs corpus `busybox` ELF headers |
| `sysroot-533857` | Extract `bin/`, `lib/`, `usr/lib/` from install SquashFS |
| `link-sysroot-533857` | `prepare_link_sysroot.sh` → `…533857-link/` |
| `firmware-link-test` | Link `test.c` against device uClibc (in Buildroot Docker) |
| `clean` | Remove `5268ac`, `test`, `libtest` helpers |

## Other firmware versions

Point **`--collection`** / **`sysroot-*`** at the matching `version:*` slug (e.g. **11.5.1.532678** uses the same **2011.11** toolchain profile). See [`reference/tools.md`](../reference/tools.md) for corpus ingest and index paths.

## Related docs

- [`buildroot/README.md`](buildroot/README.md) — Buildroot 2011.11 vs 2013.05 profiles, SDK export, stock diff
- [`docker/qemu-mips/README.md`](../docker/qemu-mips/README.md) — QEMU user-mode container
- [`reference/tools.md`](../reference/tools.md) — corpus index, SBOM, toolchain summary
