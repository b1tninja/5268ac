# `paceflash` — offline Pace 5268AC flash CLI

Command-line and library front end for **full-chip NAND dumps** and carved **`tlpart`** images: NAND translate, OpenTL BBM assembly, **`opentla4`** ext2 listing, file reads, interactive shell, factory/paramtool/EAPOL/HTTP-auth extracts, and flash inventory (`--debug`).

**`paceflash` imports [`boardfs`](../boardfs/) only** — not **`opentl`** directly. Translate, BBM replay, NTL assembly, and ext2 I/O go through **`boardfs`** / **`boardfs.tl_chain`**.

**Operational detail** (CMDB recovery, security redaction, per-command flags, kernel comparisons): **[`reference/paceflash.md`](../reference/paceflash.md)**.  
**Layer stack:** **[`reference/layers_unand_uboot_opentl_boardfs_paceflash.md`](../reference/layers_unand_uboot_opentl_boardfs_paceflash.md)**.  
**Boardfs / registry:** **[`reference/boardfs.md`](../reference/boardfs.md)**.

---

## Install

From the repo root:

```bash
pip install -e ".[dissect,shell,eapol]"
```

| Extra | Enables |
|-------|---------|
| **`dissect`** | ext2/3/4 via **dissect.extfs** (`ls`, `cat`, `shell`) |
| **`shell`** | Tab completion on Windows (**pyreadline3**) |
| **`eapol`** | **`dump-eapol-cert`** (PKCS#12 decrypt) |
| **`dev`** | pytest |

---

## Quick start

```powershell
# List ext2 root on opentla4 (one translate + mount per invocation)
python -m paceflash --flash "PACE 5268AC S34ML01G1@TSOP48.BIN" ls
python -m paceflash --flash "PACE …BIN" ls sys1

# Binary-safe file read (avoid PowerShell > for binary)
python -m paceflash --flash "PACE …BIN" cat sys1/rootimage.img -o rootimage.img

# REPL — flash loaded once (~10s on full dump); ls / cd / cat / pwd
python -m paceflash --flash "PACE …BIN" shell
```

Inside **`shell`**, the prompt is **`paceflash:/$`** on the **`opentla4`** ext2 root; **`cd sys1`** then **`ls`** shows **`rootimage.img`**, **`ui.img`**, etc.

**`--flash PATH`** may appear before or after the subcommand; positional **`FLASH`** is also accepted (`paceflash ls DUMP [PATH]`).

---

## Commands

| Command | Role |
|---------|------|
| **`ls`** | List an ext2 directory (default **`/`**). **`--debug`**: full JSON/human inventory (MTD, BBM, disklabel, …). |
| **`cat`** | Read a regular file; **`-o FILE`** for binary output. |
| **`shell`** | Interactive ext2 REPL; **`-c "…"`** for one-shot script. |
| **`factory-params`** | Manufacturing block from **loader** MTD (`sn=`, `mac=`, `devkey=`, …). |
| **`paramtool`** | Offline **`gw:*`** / `*_p12` keys from **`tlpart`** board_param store. |
| **`dump-eapol-cert`** | **`lightspeed_p12`** / **`device_p12`** → PEM (needs factory **`devkey`** + **`sn`**). |
| **`dump-http-auth`** | HTTP realm map, factory **accesscode**, CMDB **`user`** table. |
| **`build-carrier-index`** | Pkgstream squash digests for upgrade correlation. |

### Global options (common)

| Flag | Meaning |
|------|---------|
| **`--flash PATH`** | Full-chip **`.BIN`** or logical **`tlpart.bin`** |
| **`--nand-mode`** | **`inline-2112`** (default) or **`flat-tail`** |
| **`--no-nand-translate`** | Skip logicalize (e.g. already-linear **`loader.bin`**) |
| **`--bbm-chain-aware`** | Force spare-chain virt rebuild before ext2 |
| **`--tl-slice`** | TL child slice (default **`opentla4`**) |
| **`--cmdline`** | Override / supplement **`mtdparts=`** parsing |

Examples:

```powershell
python -m paceflash paramtool --flash "PACE …BIN" --get gw:trust_engcert
python -m paceflash factory-params "PACE …BIN" --json --redact
python -m paceflash dump-eapol-cert "PACE …BIN" -o output/lightspeed_eapol.pem
python -m paceflash ls --flash "PACE …BIN" --debug --json
```

---

## What you get on a PACE dump

| Layer | Offline behavior |
|-------|------------------|
| **NAND** | **`unand`** logical plane + spare (via **boardfs** bootstrap) |
| **OpenTL** | BBM / NTL replay → assembled **`opentla4`** bytes |
| **ext2** | Dissect mount; **`read_model`** often **`ntl_rw_chain_replay`** on 532678 captures |
| **SquashFS** | Embedded in ext2 files (**`sys1/rootimage.img`**) — not raw **`hsqs`** on the TL partition |

**CMDB** under **`cm/`** is plain XML on disk; bad **`cat`** output is usually stale inode extents — **`boardfs.cmdb_extent_walker`** recovery when needed. See **[`reference/cmdb_security.md`](../reference/cmdb_security.md)** before publishing extracts.

---

## Library API

```python
from paceflash import build_inventory
from paceflash.shell import Ext2ShellSession, ShellConfig, run_interactive
from boardfs.ext2_path import list_ext2_directory, read_ext2_regular_file

inv = build_inventory("PACE…TSOP48.BIN", nand_translate=True)
# Keys: flash_path, mtd, tl, ext2, opentla4_extract, bbm_virtual_scan, warnings, …

session = Ext2ShellSession.open(ShellConfig(flash_path="PACE…TSOP48.BIN"))
session.cmd_cd(["sys1"])
session.cmd_ls([])
```

**`fstab` helpers** (disk image files, not live mount):

```python
from paceflash import parse_fstab_from_extfs_image
entries = parse_fstab_from_extfs_image("opentla4.ext2")
```

---

## Module map

| Module | Role |
|--------|------|
| [`cli.py`](cli.py) | Argument parsing, all subcommands |
| [`flash_session.py`](flash_session.py) | Open registry + **`opentla4`** volume (shared by **`ls`** / **`cat`** / **`shell`**) |
| [`shell.py`](shell.py) | Interactive REPL + readline completion |
| [`inventory.py`](inventory.py) | **`build_inventory`** for **`ls --debug`** |
| [`opentla4_extract.py`](opentla4_extract.py) | ext2 mount telemetry + embedded squash probes |
| [`board_param.py`](board_param.py) | **`paramtool`** offline parse |
| [`factory_params.py`](factory_params.py) | Loader manufacturing block |
| [`eapol_cert.py`](eapol_cert.py) | PKCS#12 extract/decrypt |
| [`http_auth.py`](http_auth.py) | **`dump-http-auth`** |
| [`upgrade_correlation.py`](upgrade_correlation.py) | **`build-carrier-index`** |

Deprecation shims re-export **boardfs**: [`ext2_dissect.py`](ext2_dissect.py), [`nand_logicalize.py`](nand_logicalize.py), [`ntl_adapter.py`](ntl_adapter.py), [`bbm_scan.py`](bbm_scan.py).

---

## Related docs

| Topic | Doc |
|-------|-----|
| Boot env / **`paramtool`** | [`reference/boot_environment_trust_eng.md`](../reference/boot_environment_trust_eng.md) |
| Factory block vs CMDB | [`reference/board_params_nand.md`](../reference/board_params_nand.md) |
| EAPOL PKCS#12 | [`reference/eapol_8021x_p12.md`](../reference/eapol_8021x_p12.md) |
| HTTP / CM passwords | [`reference/http_auth_realms.md`](../reference/http_auth_realms.md) |
| NTL / **`opentla4`** Ghidra | [`reference/ghidra_ntl_rw_opentla4_mcp.md`](../reference/ghidra_ntl_rw_opentla4_mcp.md) |
| **`lib2spy`** carriers | [`lib2spy/README.md`](../lib2spy/README.md) |

---

## Tests

```bash
pytest tests/test_paceflash.py tests/test_paceflash_cli_operands.py \
  tests/test_paceflash_shell_paths.py tests/test_ext2_path.py -q
```

Full **PACE** dump (slow):

```powershell
$env:PACE_FLASH_INTEGRATION = "1"
pytest tests/test_opentla4_532678_mount.py -q --timeout=300
```

---

## See also

- **[`opentl/README.md`](../opentl/README.md)** — BBM / NTL below **boardfs**  
- **[`reference/tools.md`](../reference/tools.md)** — binwalker carve → **`paceflash ls`**  
- **[Root README](../README.md)** — workspace overview
