# Board parameters — NAND, factory block, `libboard`, CMDB

Where **serial number**, **MAC**, **access codes**, and related identity live on the **5268AC**, and how that differs from **CMDB** (`cmlegacy.*.xml`) and **TR-069 Inform** fields.

Firmware slice: **11.5.1.532678** (and captures on **11.14.1.533857** CMDB). Evidence: Ghidra **`libboard.so`**, flash string sweep **`flash strings.txt`**, CMDB extract **`cmlegacy.203.xml`**, PACE dump notes in [`output/nand_rwdata_cm.md`](../output/nand_rwdata_cm.md).

See also: [`libboard.md`](libboard.md), [`cm_cmdb.md`](cm_cmdb.md), [`cwmp_cpe_authentication.md`](cwmp_cpe_authentication.md), [`cmdb_security.md`](cmdb_security.md), [`paceflash.md`](paceflash.md).

---

## Summary: three layers (do not conflate)

| Layer | What it is | Serial / OUI example | In NAND dump? |
|-------|------------|----------------------|--------------|
| **A. Factory / loader block** | Manufacturing key=value block ( Pace provisioning ) | `sn=38161N043704`, `mac=14:ED:BB:…` | **Yes** — ASCII in **loader** MTD (~`0x1FF84` in full-chip logical image) |
| **B. `libboard` + kernel `board` module** | Runtime API: small files + **`board_param_*`** DB + sysfs | `board_info_serialnumber()` → same SN | **Indirect** — copied/mounted into rwfs at boot; also **`/sys/module/board/parameters/*`** |
| **C. CMDB** (`/rwdata/cm`) | Operator/fleet config: TR-069, Wi‑Fi policy, DHCP, keys | `connreq_username` = `00D09E-38161N043704` | **Yes** — `cm/cmlegacy.*.xml` on **UBIFS** (OpenTL **`opentla*`** → rw root), **not** the factory block |

**TR-069 `DeviceId.SerialNumber`** comes from **B** (`board_info_serialnumber`), **not** from parsing **C** XML. **OUI `00D09E`** in **`cwmd`** is **hardcoded** in SOAP; CMDB only mirrors OUI+serial in **`connreq_username`**.

---

## A. Factory parameter block (NAND / loader)

### Location in offline dump

On **`PACE 5268AC S34ML01G1@TSOP48.BIN`** with default cmdline  
`mtdparts=mtd-0:524288(loader),1048576(mtdoops),-(tlpart)`:

| Item | Value |
|------|--------|
| MTD partition | **`loader`** — bytes **0 … 524287** on logical plane |
| Factory block offset | **`0x1FF84`** (string sweep; inside **loader**) |
| Format | `name=value` lines, NUL-terminated tokens |

This is **not** CMDB XML. It is **manufacturing / calibration** data written before or during first boot.

### Fields observed (this unit)

Extracted from [`flash strings.txt`](../flash strings.txt) at **`0x1FF84`** (redact secrets in your own notes; values below match the lab dump already in repo logs):

| Key | Example value | Role |
|-----|----------------|------|
| **`model`** | `5268AC` | Product model string |
| **`sn`** | `38161N043704` | **Gateway serial** — primary identity for CWMP, DHCP client id suffix, labels |
| **`mac`** | `14:ED:BB:DF:ED:5C` | Base Ethernet MAC (OUI **14:ED:BB** Pace) |
| **`devkey`** | 16-byte hex | Device secret input for **`board_key_*`** derivations |
| **`authcode`** | 32-byte hex | Auth material for **`board_key_authcode`** path |
| **`accesscode`** | `4\52@99095` | Printed **subscriber / access code** (UI); also exposed as sysfs **`accesscode`** |
| **`wifissid1`**, **`wifikey1`** | `ATT…` / passphrase | Factory Wi‑Fi defaults |
| **`wifi5gsn`**, **`wifi5gpca`**, … | same SN / PCA | 5 GHz radio identity mirrors |
| **`pca`** | `260-2173300` | PCA / manufacturing code |
| **`maccount`** | `12` | Account class |
| **`mfg_timestamp`** | `1474414020` | Manufacturing epoch |
| **`srom`** | hex tuples | Ethernet PHY SROM / calibration blob |
| **`factory_mode`** | `1` | Factory-test flag |

**Wi‑Fi / TR-069 OUI note:** Pace **gateway** TR-069 uses **`00D09E`** (2Wire allocation) in **`cwmd`**, while **`mac=`** uses **14:ED:BB**. Those are **different namespaces** (CWMP DeviceId vs Ethernet OUI).

### How software reads it

1. Boot / **`rgwdbsetup`** logs: `Serialnumber: 38161N043704` (confirms SN is loaded early).
2. **`libboard.so`**: **`board_info_serialnumber`**, **`board_info_accesscode`**, **`board_key_*`** — **`open()`** on one of two fallback paths, then **`_board_read_parameter()`** (see [`libboard.md`](libboard.md)).
3. **`board_param_*`**: structured store; string **`.board_param`** appears in flash (filename / extension for param DB).
4. Kernel **`board`** module publishes sysfs (scripts read these directly):

| Sysfs / script | Parameter |
|----------------|-----------|
| `/sys/module/board/parameters/accesscode` | Access code (same family as factory **`accesscode=`**) |
| `/sys/module/board/parameters/productclass` | Product class file → **`PRODUCTCLASSFILE=…`** in init |
| `/sys/module/board/parameters/wifissid0` | Factory SSID |
| `debugsys --info` | Human-readable **Serial Number:** line (parsed by shell: `${clientsn##*Serial Number: }`) |

**Ghidra:** import **`libboard.so.0.0.0`** and dump GP-relative path table from **`board_info_serialnumber`** @ **`0x00011f84`** to recover exact pathnames (not plain ASCII in `strings`).

---

## B. Runtime identity API (`libboard` → daemons)

| API | Consumers (subset) | Feeds |
|-----|-------------------|--------|
| **`board_info_serialnumber`** | **`cwmd`**, **`httpd`**, **`dhcpd`**, **`dsld`**, **`pkgd`**, **`rgwdbsetup`**, … | TR-069 **SerialNumber**, logs, DHCP **clientid** construction |
| **`board_info_productclass`** | **`cwmd`**, **`httpd`**, … | TR-069 **ProductClass** (fallback **`homeportal`**) |
| **`board_info_model`**, **`board_info_pca`**, **`board_info_macaddr_*`** | Wi‑Fi, provisioning | Model strings, MAC pools |
| **`board_key_accesscode`**, **`board_key_systemcode`**, **`board_key_secret`**, … | **`httpd`**, **`modprov`**, **`debugsys`** | Login / subscriber codes (derived from **A**, not CMDB) |

**Not read from CMDB for Inform:** `soap_msg_inform` calls **`board_info_*`** only; CMDB supplies **HTTP URL creds**, **keycode**, **connreq_***, **notify** list — see [`cwmp_cpe_authentication.md`](cwmp_cpe_authentication.md).

---

## C. CMDB mirrors and fleet fields (`/rwdata/cm`)

Runtime path: **`cmd --dbdir /rwdata/cm`** → **`cmlegacy.<n>.xml`** (UTF-16 LE). Offline: **`paceflash cat cm/cmlegacy.498`** or recovered XML in repo root.

### Fields tied to board identity (this dump)

| CMDB location | Field | Example | Relation to factory **A** |
|---------------|-------|---------|---------------------------|
| **`mgmt`** | **`connreq_username`** | `00D09E-38161N043704` | **`00D09E`** + **`-`** + **`sn`** |
| **`mgmt`** | **`connreq_passwd`** | `base64:…` | ACS→CPE digest secret (generated/stored at provision time) |
| **`mgmt`** | **`keycode`**, **`bootstrapped_keycode`** | `52HP-2374-…` | TR-069 bootstrap / HTTP creds — **not** same as factory **`authcode=`** hex |
| **`mgmt` → `notifyparams`** | TR-069 paths | includes **`DeviceInfo.SerialNumber`** | **Notify** on Inform; value filled from data model at runtime |
| **Device / DHCP params** (in full CMDB blob) | **`dhcpc clientid`** | `00D09E-38161N043704` | Same OUI-serial composite |
| **`mgmt_upgstate.part1.Name`** | active firmware | `11.14.1.533857` | Software version (Inform param), not hardware SN |

**There is no `mgmt.serial` row** in the parsed top-level **`mgmt`** fields — serial for CWMP is **not** authoritative in CMDB on this firmware; use **A/B**.

### Other CMDB tables (not board factory, but often grepped)

| Table | Content |
|-------|---------|
| **`pkgs`** | `.pkgstream` paths, digests |
| **`mgmt_upgstate`** | upgrade partitions, redirect URL |
| **`ap`**, **`bulkdata`**, … | Wi‑Fi, IoT reporting (separate from factory **`wifissid1`**) |

---

## NAND map (where to carve)

```text
Full chip (logical)
├── MTD0 loader (524 KiB)     ← factory sn=/mac=/devkey= block ~0x1FF84
├── MTD1 mtdoops (1 MiB)
└── MTD2 tlpart
    ├── opentla* slices
    │   ├── ext2 / UBIFS areas
    │   └── …
    └── UBIFS rw rootfs
        └── /rwdata/cm/cmlegacy.*.xml   ← CMDB (layer C)
            /rwdata/sys1, sys2, pkg, config/lib.sh, …
```

**`cmlegacy` XML also appears** as string hits inside **`tlpart`** (~`+0xc0440`) from filesystem clusters — use [`paceflash.md`](paceflash.md) + [`boardfs.md`](boardfs.md) for extraction.

---

## Offline recovery checklist

| Goal | Tool / action |
|------|----------------|
| Read factory **`sn=`** without booting | `python -m paceflash factory-params FLASH` or strings on **loader** @ **`0x1FF84`** |
| Read CMDB **`connreq_*`**, **keycode** | `python -m acspy identity --cmdb cmlegacy.203.xml` or parse **`mgmt`** table |
| List CMDB tree from NAND | `paceflash` UBIFS extract → `cm/` → [`tools/cmdb_tree_inventory.py`](../tools/cmdb_tree_inventory.py) |
| Confirm runtime path for serial | Live: `debugsys --info` or `strace -e openat cwmd … board_info_serialnumber` |

---

## Masquerade / clone implications

To present as this CPE you need consistency across layers:

1. **Inform `SerialNumber`** ← factory **`sn`** / **`board_info_serialnumber`**
2. **Inform `OUI`** ← **`00D09E`** (code constant; must match **`connreq_username`** prefix)
3. **ACS HTTP userinfo** ← CMDB **`connreq_username`** + **`keycode`** (lab default in **`acspy`**)
4. **Connection Request digest** ← CMDB **`connreq_passwd`** (base64)
5. **DHCP / EOC** ← strings like **`00D09E-38161N043704`** in CMDB device params and **`dsld`** EOC logs

Changing only CMDB without matching factory **A** can desync TR-069 **DeviceId** (still read from **B**) from **mgmt** credentials.

---

## See also

- [`libboard.md`](libboard.md) — API and **`board_key_*`** derivation
- [`output/nand_rwdata_cm.md`](../output/nand_rwdata_cm.md) — MTD indices, **`/rwdata/cm`** in dump
- [`reference/cwmp_cpe_authentication.md`](cwmp_cpe_authentication.md) — which fields Inform uses
