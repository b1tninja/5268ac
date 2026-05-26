# Offline `gw:trust_engcert` NAND patch

Immutable flash editing for the 5268AC Pace stack: patch **`gw:trust_engcert`** in board_param env copies and write a **new** TSOP/logical dump without modifying the source file.

**Firmware install / downgrade** is **not** done offline — use on-device **`pkgd`** after programming a trust-enabled dump (HTTP upgrade UI, TR-069, etc.). Offline ext2 / BBM write-back for **`opentla4`** was removed; kernel **`ntl_write_page`** + spare chains are required for large FILE installs.

See also: [`boot_environment_trust_eng.md`](boot_environment_trust_eng.md), [`pkgstream_security.md`](pkgstream_security.md), [`firmware_upgrade_process.md`](firmware_upgrade_process.md).

---

## Immutable I/O contract

**`patch-trust-engcert`** takes **`--flash IN`** and **`--out OUT`**. The input dump is opened read-only. A JSON **manifest** (default: `OUT.patch.json`) records input/output SHA-256 and patch metadata.

| Layer | Role |
|-------|------|
| [`unand`](../unand/) | `normalize_to_logical` / **`denormalize_logical_to_physical`** / **`refresh_spare_ecc_for_pages`** |
| [`paceflash/board_param.py`](../paceflash/board_param.py) | CRC board_param encode + dual env site patch |
| [`paceflash/flash_patch.py`](../paceflash/flash_patch.py) | **`FlashPatchSession`** orchestrator |

---

## Patch `gw:trust_engcert`

Patches **`gw:trust_engcert=true`** (or `false`) in **primary + backup** board_param env copies in linear **`tlpart`**, and adds **`trust_engcert=true`** to the **loader** manufacturing factory block (~`0x1F004` on lab dumps) so hard/factory reset paths can re-seed the param from defaults.

**Note:** This is the **paramtool / board_param** store. It enables UART via **`S01UART`** and causes **`chk_enable_trusteng`** to mirror **`trust_eng=1`** into CMDB **on first boot**. It does **not** directly set the CMDB OID that **`lib2sp`** reads during a live install without boot.

For **INLINE/FLAT_TAIL** TSOP images, `patch-trust-engcert` refreshes **only the ECC slices intersecting the patched bytes** on **only the touched NAND pages** — hole/erased spare rows and all unmodified pages pass through bit-identically from the source dump (including pre-existing correctable ECC drift elsewhere). **OpenTL xsum** (`spare[0xf]`) is recomputed only when xsum operand bytes change.

```powershell
python -m paceflash patch-trust-engcert `
  --flash "PACE 5268AC S34ML01G1@TSOP48.BIN" `
  --value true `
  --out output/PACE_trust_engcert_true.BIN
```

Verify:

```powershell
python -m paceflash paramtool --flash output/PACE_trust_engcert_true.BIN --get gw:trust_engcert
```

---

## Recommended lab workflow (downgrade / eng trust)

1. **`patch-trust-engcert`** → program output dump to NAND.
2. **Boot once** — CMDB **`trust_eng`** mirrors paramtool; **`pkgd`** skips 11.14+ downgrade gate when engineering trust is on.
3. **Upload carrier** on-device (`att-5268-…-install.pkgstream` via web UI or TR-069).

Pre-flight offline:

```powershell
python -m lib2spy carrier.pkgstream --validate-chain --trust-engcert --strict
```

---

## Validation checklist

1. **`paramtool --get gw:trust_engcert`** on **OUT** → `true` (or chosen value).
2. Input file unchanged; output size equals input (TSOP roundtrip).
3. Manifest lists **`trust_engcert`** patch sites.

---

## Library API

```python
from paceflash.flash_patch import patch_trust_engcert_flash

patch_trust_engcert_flash("PACE….BIN", value="true", out_path="out.BIN")
```
