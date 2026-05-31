# 5268AC lab (Docker + qemu-mips-static)

Linux container for **MIPS32 BE user-mode** testing of 5268AC firmware binaries, using **dockcross/linux-mips** and **qemu-mips-static**. Mounts the repo and `work_corpus/` for corpus-staged firmware sysroots and cross-built harnesses.

**Image / Compose project:** `5268ac`  
**Agent skill:** [`.cursor/skills/qemu-mips-lab/SKILL.md`](../../.cursor/skills/qemu-mips-lab/SKILL.md)

## Build

From repo root:

```powershell
docker compose -f docker/qemu-mips/compose.yml build 5268ac
```

Or: `docker build -t 5268ac -f docker/qemu-mips/Dockerfile .`

## Quick start

```powershell
# 1) Stage libs + busybox (needs pkgstream corpus tree on host)
docker compose -f docker/qemu-mips/compose.yml run --rm 5268ac stage-rootfs `
  --collection version:11.14.1.533857

# 2) Smoke-test busybox under QEMU
docker compose -f docker/qemu-mips/compose.yml run --rm 5268ac run-mips `
  /work/work_corpus/qemu_mips/sysroots/version_11.14.1.533857/bin/busybox --help

# 3) Interactive shell (cross-compile, tcpdump, corpus CLI)
docker compose -f docker/qemu-mips/compose.yml run --rm 5268ac
```

Inside the shell, **`cross-test`** compiles `cross/test.c` and runs it under `qemu-mips-static` (dockcross glibc sysroot). For a host-side dockcross-only wrapper (no corpus tools), see **`make -C cross docker`** → image **`5268ac-dockcross`**.

## Sysroot layout

| Path | Role |
|------|------|
| `work_corpus/qemu_mips/sysroots/version_11.14.1.533857/` | Staged firmware tree for `QEMU_LD_PREFIX` |
| `work_corpus/qemu_mips/sysroots/default` | Symlink (or `default.txt` on Windows) to last staged collection |
| `work_corpus/toolchain/sysroots/…` | Optional sysroot from `make -C cross sysroot-533857` (Buildroot workflow) |

Override with `QEMU_LD_PREFIX=/work/...` in Compose or `docker compose run -e QEMU_LD_PREFIX=...`.

## Privileged binfmt (optional)

On Linux hosts, **`5268ac-binfmt`** registers MIPS ELF binfmt:

```powershell
docker compose -f docker/qemu-mips/compose.yml run --rm 5268ac-binfmt
```

Docker Desktop on Windows usually lacks this — use **`run-mips`** instead.

## Related

- [`cross/README.md`](../../cross/README.md) — vendor uClibc toolchain + link sysroots
- [`corpus/SKILL.md`](../../corpus/SKILL.md) — find collection, carve paths, Grype/CVE triage
