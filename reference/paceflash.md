# `paceflash` — Pace-class flash CLI and ext2 shell

Top-level package **`paceflash/`** at the 5268ac repo root. It composes **`boardfs`** and **`unand`** (and optional **[Dissect extfs](https://pypi.org/project/dissect.extfs/)** for ext2/3/4) for offline work on Pace **5268AC** dumps. **`paceflash` imports `boardfs` only** — not **`opentl`** directly; NAND translate, BBM, NTL assembly, and ext2 dissect are reached through **`boardfs`** / **`boardfs.tl_chain`**.

**`opentla4` (rw / ext2):** The kernel exposes this TL child as **OpenTL ptype 17** with **NTL mode-2** spare chains. Offline, **`boardfs.assemble_opentla4_volume`** assembles slice bytes (NTL rw replay → linear **`tlpart`** → BBM virt), then **`boardfs.ext2_dissect`** / **`boardfs.ext2_path`** mount via Dissect. On a full **PACE `S34ML01G1@TSOP48.BIN`** capture (May 2026): **`read_model=ntl_rw_chain_replay`**, mountable superblock at **`1024`**, root listing includes **`cm`**, **`sys1`**, etc. Ghidra: **[ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md)**.

**Squash on `opentla4`:** Product squash lives in ext2 **files** (e.g. **`sys1/rootimage.img`**), not as raw **`hsqs`** on the TL partition. Use **`paceflash/ext2_file_extract.py`** or **`cat`** in the shell after ext2 mounts — see **[ghidra_squashfs_flash_read_gap_mcp.md](ghidra_squashfs_flash_read_gap_mcp.md)**.

**Known read gap:** **`sys1/ui.img`** (~1.3 MiB inode) often fails Dissect indirect-block reads on the same capture (truncated vs assembled slice); **`sys1/rootimage.img`** (~21 MiB squash) usually reads successfully.

### CMDB XML reads and kernel comparison

On disk, CMDB files are **plain libxml2 XML** (`<?xml version="1.0" encoding="UTF-8"?>` then **`<CM VERS="1">`**, newlines, ASCII **`_`** in field names). See **[`output/cmdb_ondisk_format.md`](../output/cmdb_ondisk_format.md)** — no encryption wrapper.

**Root cause of wrong `cat` output:** stale **inode extent mapping** on the dump (not a binary CMDB envelope). The kernel (**`ext2_get_block` @ `0x8013d5a0`**, **`ext2_block_to_path` @ `0x8013c9f0`**) only follows **`i_block[]`**; **`paceflash`** adds **`cmdb_extent_walker`** + near-anchor **`<?xml`** recovery when that tree misses the real header (Ghidra + block-level proof: **[`ghidra_ext2_cm_cmdb_kernel_mcp.md`](ghidra_ext2_cm_cmdb_kernel_mcp.md)**).

**Security:** **`paceflash cat`** and **`--cmdb-recover`** on a full dump recover the same **credentials and keys** as live **`/rwdata/cm`** (BDC, `root_rsa`, Wi‑Fi, TR-069). See **[`cmdb_security.md`](cmdb_security.md)** — redact before publishing extracts.

### CMDB XML reads and terminal display

Stale PACE inodes may point at mid-file blocks; **`boardfs.cmdb_extent_walker`** recovers the document by scanning near inode anchors for the real header block, then reading through **`</ROOT></CM>`**. A bad read starts with high bytes (looks “binary” in a terminal) and may show **`è`** everywhere (**`0xE8`** in CP1252) or break the emulator with **ESC** bytes — that is mis-decoded / wrong-extent output, not the on-disk format.

Verify with **`-o`** (not PowerShell **`>`**, which mangles binary):

```powershell
python -m paceflash --flash "PACE …BIN" cat cm/cmlegacy.498 -o output/cmlegacy.498.bin
python -c "d=open('output/cmlegacy.498.bin','rb').read(); print(d[:80]); print('ok', d.startswith(b'<?xml'), d.endswith(b'</ROOT></CM>'))"
```

Expect a printable XML header and footer. If **`cat`** to the console still looks wrong after **`-o`** is correct, reset the terminal tab (binary/ESC noise from an earlier bad dump).

## Install

```text
pip install -e ".[dissect]"    # dissect.extfs + dissect.squashfs (AGPL-3.0)
pip install -e ".[shell]"      # pyreadline3 on Windows — tab completion in paceflash shell
pip install -e ".[eapol]"      # cryptography — paceflash dump-eapol-cert
pip install -e ".[dev]"        # pytest
```

See root **`pyproject.toml`** **`[project.optional-dependencies]`**.

## Quick start (ext2 on PACE dump)

```powershell
# List ext2 root (one NAND translate + mount per invocation)
python -m paceflash --flash "PACE 5268AC S34ML01G1@TSOP48.BIN" ls
python -m paceflash --flash "PACE …BIN" ls sys1

# Read a file (binary; prefer --output on Windows — PowerShell ``>`` mangles binary)
python -m paceflash --flash "PACE …BIN" cat sys1/rootimage.img -o rootimage.img

# Interactive shell — flash loaded once; ls / cd / cat / pwd
python -m paceflash --flash "PACE …BIN" shell
```

Inside the shell, **`paceflash:/$`** is the ext2 root on **`opentla4`**; **`cd sys1`** then **`ls`** lists **`rootimage.img`**, **`ui.img`**, etc.

## Commands

| Command | Role |
|---------|------|
| **`ls`** | Default: list one ext2 directory (default **`/`**). **`--debug`**: full JSON/human inventory (MTD, BBM, TL disklabel, UBI, …). |
| **`cat`** | Print a regular file from ext2 to stdout, or **`-o FILE`** for binary-safe output. |
| **`shell`** | REPL with **`ls`**, **`cd`**, **`cat`**, **`pwd`**, **`help`**, **`exit`**; Tab completes commands and paths (needs **`readline`** / **`pyreadline3`**). |
| **`factory-params`** | Parse factory **`sn=`** / **`mac=`** / … from **loader** MTD (manufacturing block). |
| **`dump-eapol-cert`** | Extract **`lightspeed_p12=`** / **`device_p12=`** from assembled **`tlpart`**, decrypt PKCS#12 to PEM. |
| **`paramtool`** | Offline **`paramtool -show`** / **`-get gw:…`** against **`board_param`** store in **`tlpart`** (`gw:*`, `*_p12` lines). See [`boot_environment_trust_eng.md`](boot_environment_trust_eng.md). |
| **`patch-trust-engcert`** | Set **`gw:trust_engcert`** in primary + backup env CRC blobs; writes **`--out`** (input unchanged). [`nand_patch_install.md`](nand_patch_install.md). |
| **`dump-http-auth`** | HTTP realm map, factory **accesscode** / Wi‑Fi, CMDB **`user`** table (ext2 + **tlpart** scan). |
| **`build-carrier-index`** | Precompute pkgstream squash digests for upgrade correlation. |

Global options (before or after the subcommand): **`--flash PATH`**, **`--cmdline`**, **`--nand-mode`**, **`--no-nand-translate`**, **`--bbm-chain-aware`**, **`--tl-slice`** (default **`opentla4`**).

### `paramtool`

Dump the flash-backed **`board_param_*`** database that **`/usr/bin/paramtool`** uses at runtime (Ghidra: **`libboard`** + **`paramtool`** on 532678). Data is carved from assembled **`tlpart`**, not from **`loader`** factory block.

```powershell
python -m paceflash paramtool --flash "PACE 5268AC S34ML01G1@TSOP48.BIN"
python -m paceflash paramtool --flash "PACE ….BIN" --get gw:trust_engcert
python -m paceflash paramtool --flash "PACE ….BIN" --get gw:trust_engcert -o output/trust_engcert.txt
python -m paceflash paramtool --flash "PACE ….BIN" --no-p12 --json
```

| Flag | Meaning |
|------|---------|
| (default) | List all **`gw:*`** keys found + **`lightspeed_p12`** / **`device_p12`** unless **`--no-p12`** |
| **`--get KEY`** | One key (mirrors **`paramtool -get KEY`**) |
| **`-o FILE`** | With **`--get`**, write raw value (like **`paramtool -get … -out FILE`**) |
| **`--redact`** | Mask **`_p12`** blobs and other sensitive values |
| **`--no-p12`** | Skip PKCS#12 base64 lines (operator params only) |

On-device reference:

```text
paramtool -show
paramtool -get gw:trust_engcert -out /tmp/_trustengcert
paramtool -set gw:trust_engcert true
```

### `factory-params`

Dump the Pace **manufacturing** key=value block from the **`loader`** MTD partition (not CMDB). See **[`board_params_nand.md`](board_params_nand.md)**.

```powershell
python -m paceflash --flash "PACE 5268AC S34ML01G1@TSOP48.BIN" factory-params
python -m paceflash factory-params "PACE …BIN" --json
python -m paceflash factory-params loader.bin --no-nand-translate --json
python -m paceflash factory-params "PACE …BIN" --redact
```

- Default: NAND-translate full-chip physical dumps, then read linear **loader** slice.
- **`--offset`**: hint for `model=` (PACE captures ~`0x1FF84`).
- **`--redact`**: mask `devkey`, `authcode`, Wi‑Fi keys for safe logs.

### `gen-network-config`

Emit **wpa_supplicant** + **systemd-networkd** files for Lightspeed WAN **802.1X** (router profile). With a flash operand, runs **`dump-eapol-cert`** internally: **`lightspeed_p12`** from **`tlpart`** → **`pki/lightspeed.p12`** + split **`client.pem`** / **`client.key`**. CA resolves from **`--ca-cert`**, pre-extracted **`lightspeed-prod-cacerts.pem`**, or **`att_unified_eapol-certs.pkgstream`**.

**DHCP modem parity** (default on): **`wan0.network`** gets **`ClientIdentifier=00D09E-{sn}`**, **`[Link] MACAddress=`** (WAN **chaddr**), **`VendorClassIdentifier=2WHPL M.m.b`**, **`RequestOptions=`** (modem parameter list), **`SendOption=57:uint16:1500`**. Use **`--firmware-version`** or **`--vendor-class`** for option 60; **`--wan-mac`** when **chaddr** ≠ cert CN. **`--no-modem-dhcp`** for minimal DHCP. Option **125** (BBF device id) is documented in README only — systemd-networkd cannot encode it. Full field guide: [`linux_8021x_lightspeed.md`](linux_8021x_lightspeed.md).

```powershell
python -m paceflash gen-network-config "PACE …BIN" --out-dir .\lightspeed-network --interface wan0

# Match a packet capture (different MAC / firmware line)
python -m paceflash gen-network-config "PACE …BIN" `
  --wan-mac d4:b2:7a:6b:b1:4c `
  --firmware-version "11.14.1.123456" `
  --out-dir .\lightspeed-network

python -m paceflash gen-network-config --help
```

| Flag | Role |
|------|------|
| **`--out-dir`** | Output tree (default `./lightspeed-network`) |
| **`--interface`** | Linux WAN ifname (default `wan0`) |
| **`--ca-cert`** / **`--eapol-certs-pkgstream`** | Operator CA PEM |
| **`--wan-mac`** / **`--no-clone-mac`** | DHCP **chaddr** via `MACAddress=` |
| **`--dhcp-client-id`** / **`--serial`** | Option **61** (`00D09E-{sn}`) |
| **`--firmware-version`** / **`--vendor-class`** | Option **60** `2WHPL …` |
| **`--product-class`** | README / option **125** notes (default `homeportal`) |
| **`--no-modem-dhcp`** | Omit vendor class, param list, max-msg size |
| **`--no-p12`** | PEM split only (no `pki/lightspeed.p12`) |
| **`--client-pem`** | Offline PEM instead of flash |
| **`--dry-run`** / **`--json`** | Plan or machine-readable result |

### `dump-eapol-cert`

WAN **lightspeed** (EAPOL) client credentials live as base64 PKCS#12 in the logical **`tlpart`** byte stream (`lightspeed_p12=`, `device_p12=`), not in empty **`opentla1`** param slices on typical dumps. Password is **`devkey` + firmware salt + `serial`** (`libboard` **`board_key_pkcs12_password`**); **`devkey`** and **`sn`** come from the **loader** factory block — use **`factory-params`** first if decrypt fails.

Requires **`pip install cryptography`** or **`pip install -e ".[eapol]"`**.

```powershell
python -m paceflash --flash "PACE 5268AC S34ML01G1@TSOP48.BIN" dump-eapol-cert
python -m paceflash dump-eapol-cert "PACE …BIN" -o output/lightspeed_eapol.pem --p12 output/lightspeed.p12
python -m paceflash dump-eapol-cert "PACE …BIN" --cert device --json --redact
python -m paceflash dump-eapol-cert "PACE …BIN" --no-decrypt --p12 lightspeed.p12
```

- Default output names include the cert **subject** (CN MAC, serial) so repeated dumps do not overwrite, e.g. **`lightspeed_14-ED-BB-DF-ED-5C_00D09E-38161N043704_eapol.pem`** and matching **`.p12`**.
- **`--stdout-pem`**: PEM to stdout (no **`-o`** file).
- **`--redact`**: omit **`devkey`** / password from **`--json`**.

Runtime consumers: **`tw_ulib_sec_find_pkcs12("lightspeed")`** and **`librgw_sec_get_shroud_key`** in **`lmd`** (full 802.1X path in [**`eapol_8021x_p12.md`**](eapol_8021x_p12.md)). Treat outputs like CMDB extracts (**[`cmdb_security.md`](cmdb_security.md)**).

### `dump-http-auth`

Clarifies **HURL** (redirects, not HTTP realms) and dumps **httpd** credentials: loader factory **`accesscode`**, CM **`adm`/`tech`/`dslf-config`**, optional **tlpart** CM mirrors. See **[`http_auth_realms.md`](http_auth_realms.md)**.

```powershell
python -m paceflash --flash "PACE …BIN" dump-http-auth
python -m paceflash dump-http-auth "PACE …BIN" --json --redact
```

Offline **`adm`** password check (Ghidra **`tw_ulib_pwd_hash`** + **`strcmp`** login): **`python tools/verify_cm_password.py`** — see **[`http_auth_realms.md`](http_auth_realms.md)** § CM algorithm.
```

### `ls` (default)

```text
python -m paceflash ls [FLASH] [PATH]
python -m paceflash --flash "PACE …BIN" ls config
python -m paceflash ls "PACE …BIN" sys1 -l
```

- Without **`--debug`**: only prints directory entries (one name per line), no MTD/BBM noise on stderr.
- **`--debug`**: previous full inventory output; development warnings on stderr.
- **`--json`**: JSON directory listing; with **`--debug`**, full **`build_inventory`** object.

### `ls --debug` / inventory flags

```text
python -m paceflash ls --flash "PACE …BIN" --debug
python -m paceflash ls --flash "PACE …BIN" --json --debug
    [--extract-ext2-dir DIR] [--dump-opentla4-ext2 PATH]
    [--probe-loader-env] [--probe-mtdoops]
    [--firmware-collection DIR] [--lib2spy-json PATH]
```

- **Full-chip physical + NAND translate (default):** **`boardfs.temporary_registry_from_physical_nand`** (`opentl.nand_bootstrap` + BBM attach). Chain-aware BBM is applied automatically when linear **`tlpart`** has payload but the primary virt stream does not (same heuristic as integration tests).
- **`--bbm-chain-aware`**: force spare-chain virt rebuild before TL/ext2 scans.
- **`--nand-mode`**: **`inline-2112`** (default) or **`flat-tail`** for logical+OOB tail captures.
- **`--no-nand-translate`**: skip logicalize on physical envelope sizes (TL/ext2/UBI probes skipped).

See **[ghidra_boardfs_bbm_readpath.md](ghidra_boardfs_bbm_readpath.md)** for virt vs linear **`mtdparts`** behavior.

### `shell`

```text
python -m paceflash shell [FLASH]
python -m paceflash --flash "PACE …BIN" shell
python -m paceflash --flash "PACE …BIN" shell -c "ls sys1"
```

Loads NAND + assembles **`opentla4`** once (~10 s on a full PACE dump). Subsequent commands reuse **`slice_bytes`** in memory.

| Shell command | Notes |
|---------------|--------|
| **`ls [-a] [-l] [PATH…]`** | List directories; default **`.`** |
| **`cd [PATH]`** | Change cwd on the ext2 volume |
| **`pwd`** | Print **`/…`** cwd |
| **`cat PATH`** | Binary stdout; errors stay in the shell (no traceback) |
| **`help`** / **`?`** | Built-in help |
| **`exit`** / **`quit`** | Leave |

## `/etc/fstab` (`paceflash.fstab`)

- **`parse_fstab(text)`** — six-field lines, **`#`** comments.
- **`read_fstab_text_from_extfs_image(path)`** / **`parse_fstab_from_extfs_image(path)`** — read **`/etc/fstab`** from an ext2/3/4 **disk image file** using **`dissect.extfs`**.

## Library

```python
from paceflash import build_inventory
from paceflash.shell import Ext2ShellSession, ShellConfig, run_interactive
from boardfs.ext2_path import list_ext2_directory, read_ext2_regular_file

# Full inventory (API / --debug)
inv = build_inventory("PACE…TSOP48.BIN", nand_translate=True)

# One-shot shell session in code
session = Ext2ShellSession.open(ShellConfig(flash_path="PACE…BIN"))
session.cmd_cd(["sys1"])
session.cmd_ls([])
```

Top-level JSON keys (**`build_inventory`**): **`flash_path`**, **`mtd`**, **`tl`**, **`ext2`**, **`opentla4_extract`**, **`nand_translate`**, **`bbm_virtual_scan`**, **`ubi_vid_scans`**, **`warnings`**, …

**`opentla4_extract` (selected):**

| Key | Meaning |
|-----|---------|
| **`read_model`** | **`ntl_rw_chain_replay`**, **`linear_tlpart`**, **`bbm_virt`**, … |
| **`ext2_superblock_offset`** | **`1024`** when mountable on PACE-class captures |
| **`root_ls`** | ext2 **`/`** directory rows when mount succeeds |
| **`embedded_squash_images`** | Probe rows for **`sys1/rootimage.img`**, **`ui.img`**, … (**`read_failed`** common for **`ui.img`**) |

## Module map

| Module | Role |
|--------|------|
| [`paceflash/cli.py`](../paceflash/cli.py) | **`ls`**, **`cat`**, **`shell`**, **`build-carrier-index`** |
| [`paceflash/shell.py`](../paceflash/shell.py) | Interactive ext2 REPL + readline completion |
| [`paceflash/flash_session.py`](../paceflash/flash_session.py) | Open flash registry + **`opentla4`** volume (shared by CLI/shell) |
| [`paceflash/inventory.py`](../paceflash/inventory.py) | **`build_inventory`** (**`--debug`**) |
| [`paceflash/opentla4_extract.py`](../paceflash/opentla4_extract.py) | ext2 mount + embedded squash extract |
| [`paceflash/ext2_file_extract.py`](../paceflash/ext2_file_extract.py) | Read **`.img`** paths inside ext2 |
| [`boardfs/ext2_dissect.py`](../boardfs/ext2_dissect.py) | Superblock normalize/sanitize, list **`/`** |
| [`boardfs/ext2_path.py`](../boardfs/ext2_path.py) | List/read paths on in-memory ext2 |
| [`boardfs/tl_chain.py`](../boardfs/tl_chain.py) | **`assemble_opentla4_volume`**, chain-aware BBM helpers |

Deprecation shims (re-export **`boardfs`**): **`paceflash/ext2_dissect.py`**, **`paceflash/nand_logicalize.py`**, **`paceflash/ntl_adapter.py`**, **`paceflash/bbm_scan.py`**.

Layer stack: **[layers_unand_uboot_opentl_boardfs_paceflash.md](layers_unand_uboot_opentl_boardfs_paceflash.md)**. **`boardfs`**: **[boardfs.md](boardfs.md)**.

## Tests

```text
python -m pytest tests/test_paceflash.py tests/test_paceflash_cli_operands.py tests/test_paceflash_shell_paths.py tests/test_paceflash_shell_complete.py tests/test_ext2_path.py tests/test_opentla4_extract.py tests/test_opentla4_volume.py tests/test_boardfs_import_boundary.py tests/test_paceflash_import_boundary.py -q

# Full PACE dump (opt-in)
$env:PACE_FLASH_INTEGRATION = "1"
python -m pytest tests/test_opentla4_532678_mount.py -q --timeout=300
```

Manual: **`python -m paceflash --flash "PACE …BIN" ls`**, **`shell`**, **`cat sys1/rootimage.img`**.
