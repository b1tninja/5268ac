# Buildroot cross toolchain (5268AC / 11.14.1.533857)

Corpus firmware **`version:11.14.1.533857`** (`gateway.c01.sbcglobal.net/.../11.14.1.533857-PROD`) reports two Buildroot identities:

| Source | Value |
|--------|--------|
| `etc/os-release` | **Buildroot 2013.05** (`VERSION=2013.05-06034-g404c597`) |
| MIPS ELF `.comment` (busybox, httpd, pkgd) | **Buildroot 2011.11**, **gcc 4.6.2**, **uClibc 0.9.32** |

**Linking against device libraries** requires the **2011.11 toolchain profile** plus a **firmware sysroot** staged from the install SquashFS carve. The **2013.05 stock profile** rebuilds an upstream target tree for diffing manufacturer additions.

## Quick start (533857)

```powershell
# Evidence from corpus
make -C cross/buildroot fingerprint

# ABI-matched cross compiler (long; uses Ubuntu 12.04 Docker)
make -C cross/buildroot PROFILE=toolchain fetch docker source cross_compiler
make -C cross/buildroot PROFILE=toolchain abi-check

# Device libraries for --sysroot
make -C cross sysroot-533857
make -C cross link-sysroot-533857    # merge host sysroot + firmware libs
make -C cross firmware-link-test
```

Compiler: `work_corpus/toolchain/output/host/usr/bin/mips-unknown-linux-uclibc-gcc`

Link sysroot (crt/headers from Buildroot host, **libc and vendor `.so` from device**):

`work_corpus/toolchain/sysroots/version_11.14.1.533857-link`

Built by [`cross/prepare_link_sysroot.sh`](../prepare_link_sysroot.sh). Example:

```text
mips-unknown-linux-uclibc-gcc -O0 -pipe -march=mips1 \
  --sysroot=work_corpus/toolchain/sysroots/version_11.14.1.533857-link \
  -Wl,-rpath-link,work_corpus/toolchain/sysroots/version_11.14.1.533857-link/lib \
  -o myapp myapp.c -lsome_vendor_lib
```

## Stock vs firmware (manufacturer delta)

```powershell
# Optional: upstream 2013.05 target/ (Ubuntu 14.04 image buildroot_2013.05)
make -C cross/buildroot PROFILE=stock fetch docker source target

make -C cross sysroot-533857
make -C cross/buildroot PROFILE=stock diff-firmware
```

## Profiles

| `PROFILE` | Buildroot tag | Docker base | Output dir | Purpose |
|-----------|---------------|-------------|------------|---------|
| `toolchain` (default) | `2011.11` @ `c29253ef` | Ubuntu 12.04 | `output/` | Cross gcc matching device ELFs |
| `stock` | `2013.05` @ `404c597` | Ubuntu 14.04 | `output-2013.05/` | Stock `target/` for diff |

Saved configs: [`configs/`](configs/README.md). The repo-root [`.config`](.config) is legacy; **`sync-config` copies from `configs/`**.

## Older firmware (11.5.1.532678)

Same **2011.11** toolchain profile applies. Use that collection’s SquashFS carve for `--sysroot`.

## Known limitation: uClibc shared `libc.so`

`make cross_compiler` produces **`mips-unknown-linux-uclibc-gcc` 4.6.2**. Linking the final `libuClibc-0.9.32.so` inside Buildroot may fail (`_dl_phnum` / NPTL). Use the **firmware sysroot** `libuClibc-0.9.32.so` for dynamic links, or compile objects only (`abi_check.sh`).

## Docker notes

- **`buildroot_2011.11`**: `old-releases.ubuntu.com` apt on Precise.
- **`buildroot_2013.05`**: Trusty archive for 2013.05 host packages.
- Windows bind mounts: entrypoint strips CRLF from `support/scripts/*`.
- Invoke tools with `--entrypoint /bin/bash` if bypassing `make` routing.
