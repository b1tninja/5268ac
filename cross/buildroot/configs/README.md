# Buildroot configs (5268AC)

| File | Use |
|------|-----|
| `2011.11-mips-uclibc-5268ac.config` | **Toolchain profile** — matches `11.14.1.533857` MIPS BE OABI32 ELFs (`gcc 4.6.2`, uClibc `0.9.32`). `make -C cross/buildroot PROFILE=toolchain` |
| `2013.05-mips-from-5268ac-arch.config` | **Stock reference** — arch/endian from 2011.11 profile, applied on Buildroot `2013.05` tree after `make olddefconfig`. `PROFILE=stock` |

Corpus evidence (`make -C cross/buildroot fingerprint`):

- `etc/os-release` → `VERSION_ID=2013.05` (vendor build metadata).
- `busybox`, `httpd`, `pkgd` `.comment` → `GCC: (Buildroot 2011.11) 4.6.2`.

Link PoCs against **device libraries**, not the stock target tree:

```bash
make -C cross sysroot-533857
make -C cross firmware-link-test
```
