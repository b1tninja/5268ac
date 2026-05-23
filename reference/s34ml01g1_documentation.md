# S34ML01G1 NAND Flash — Datasheet Specifications and Repository Integration

The **Spansion S34ML01G1** is a 1-Gbit (128 MiB) SLC NAND flash device used in the Pace 5268AC-class DSL gateway. This document maps the datasheet specifications to the reverse-engineered `unand`/`opentl` stack.

---

## 1. Key Parameters (Datasheet)

| Parameter | Value |
|-----------|------:|
| **Organization** | 1 Gbit = 134,217,728 bytes (data plane) |
| **Block size** | 128 KiB = 131,072 bytes |
| **Page size (data)** | 2,048 bytes |
| **Spare/OOB size** | 64 bytes per page |
| **Pages per block** | 64 |
| **Total blocks** | 1,024 |
| **Full image (data + OOB)** | 1,024 × 64 × (2,048 + 64) = **138,412,032 bytes** |
| **Flash ID** | `0x01F1` (kernel: `BRCM NAND flash device: nand0, id 0x01f1`) |
| **Package** | TSOP48 |
| **Family** | S34ML01G series (Spansion / Cypress) |

**Arithmetic:**

```text
128 MiB data plane
= 1,024 blocks × 64 pages × 2,048 bytes
= 1,024 × 128,000 bytes
= 134,217,728 bytes
```

---

## 2. Page Structure

A raw NAND page consists of a **2,048-byte main data area** followed by a **64-byte spare/OOB area**:

```
+-------------------------+----------------+
|  Data: 2,048 bytes      |  Spare: 64 B   |
+-------------------------+----------------+
  Byte 0              Byte 2047            Byte 2111
```

### 2.1 Spare/OOB Layout (raw NAND)

The **spare area** contains manufacturer-defined fields for bad-block management, ECC, and addressing. Per the Spansion datasheet Table 9.1 and reverse-engineered field map (`spare64_bbm_field_map.md`):

| Offset | Field | Size | Role |
|--------|-------|------|------|
| `4` | Status tag | 1 byte | `0x00` = good, `0x24` (`'$'`) = active, `0xFF` = erased |
| `8` | Chain flags | 1 byte | Bits for duplicate/mirror hop detection |
| `9-10` | Physical block | 2 bytes LE | NAND erase-block index |
| `11-12` | Virtual block ID | 2 bytes LE | OpenTL virtual block (kernel-level) |
| `13` | Page index | 1 byte | Page within the erase block |
| `15` (`0xF`) | Checksum | 1 byte | Additive checksum of selected spare bytes (§7.4a) |

**Additional for large-page (5268) devices:**
- Bytes 16-17: Upper phys block bits
- Bytes 18-19: Upper virtual block ID bits

---

## 3. NandDevice / S34ML Family

### 3.1 Class hierarchy

```
unand/chip.py:

NandChip (ABC)                          # Abstract base
├── S34ML01G1                           # Concrete instance
└── S34MLFamily                         # Factory: from_chip("TSOP48.BIN")
```

### 3.2 `NandChip` abstract class

**File:** `unand/chip.py`

The `NandChip` ABC defines:

| Method | Role |
|--------|------|
| `decode_spare(raw: bytes) -> dict` | Decode 64-byte spare row into structured fields |
| `decode_spare_stream(raw_all: bytes) -> List[dict]` | Decode all pages at once |
| `spare_info -> NandGeometry` | Return geometry metadata |
| `pages_total -> int` | Total NAND pages = `num_blocks × (erase_bytes // page_data)` |

Concrete subclasses implement chip-specific spare decoding. The `S34ML01G1` instance carries:

```python
S34ML01G1 = NandChip(
    manufacturer="Spansion",
    model="S34ML01G1",
    geometry=NandGeometry(  # from unand/geometry.py
        page_data=2048,
        page_spare=64,
        erase_bytes=131072,
        num_blocks=1024,
    ),
    flash_id=0x01F1,
)
```

### 3.3 `S34MLFamily` factory

The family provides a factory method `from_chip("TSOP48.BIN")` that creates a preset chip instance with correct geometry from a reader file name, enabling automatic geometry inference:

```python
from unand import S34MLFamily
chip = S34MLFamily.from_chip("TSOP48.BIN")
# -> S34ML01G1 preset with page_data=2048, page_spare=64, erase_bytes=131072
```

---

## 4. Geometry (`unand/geometry.py`)

**File:** `unand/geometry.py` — `NandGeometry` dataclass and `PACE_DEFAULT` preset

```python
NandGeometry(
    page_data=2048,       # Main data area bytes
    page_spare=64,        # Spare/OOB bytes per page
    erase_bytes=131072,   # Erase block size (128 KiB)
    num_blocks=1024,      # Total blocks
    page_phys=2112,       # Total page + spare (2048 + 64)
    pages_per_block=64,   # 131072 / 2048
    pages_total=65536,    # 1024 × 64
    logical_bytes=134217728,  # 128 MiB data plane
)
```

**`PACE_DEFAULT`** is the global preset for the 5268AC class. All `unand` tools (`hexdump`, `NandPageReader`, `normalize_to_logical`) use this geometry for page iteration and file-size arithmetic.

---

## 5. Raw NAND Pages vs OpenTL Spare Interpretation

This is the critical distinction between **manufacturer-defined** spare bytes and **software-defined** spare bytes added by the bootloader/kernel.

### 5.1 Raw NAND Spare (Manufacturer)

The **raw spare** is defined by the Spansion S34ML01G1 datasheet. These are **physical** fields burned into every erase block during manufacturing:

| Concept | Example |
|---------|---------|
| **Purpose** | Bad-block management, ECC, physical addressing |
| **Authority** | Spansion/Cypress datasheet (Table 9.1) |
| **Stability** | Fixed at factory, never changes |
| **Fields** | Status tag, physical block address, page index, chain flags, checksum |

**Decoded by:** `S34ML01G1.decode_spare()` — returns ECC, tag, status, physical block address, page index, xsum.

### 5.2 OpenTL Spare (Software-Defined)

**OpenTL** is the bootloader/kernel layer on the 5268AC. It adds **virtual addressing** and **block management** on top of the raw NAND:

| Concept | Example |
|---------|---------|
| **Purpose** | Wear-leveling, bad-block remap, disklabel-based partitioning |
| **Authority** | Broadcom BCM63xx bootloader / Linux OpenTL driver |
| **Stability** | Changes over time as blocks wear, remap, fold |
| **Fields** | Virtual block ID, remapped physical unit, chain pointers, mount flags, stats counters |

**Decoded by:** `opentl.spare_layout.parse_spare()` + `opentl.spare_chain_replay` — returns virtual block IDs, chain replay, CRC checksums.

### 5.3 Field Mapping: Raw → OpenTL

```
┌─────────────────────────────────────────────────────────────────┐
│                    64-Byte Spare OOB                             │
├──────────────────┬──────────────────────────────────────────────┤
│ Raw NAND (datasheet) │ OpenTL (software)                        │
├──────────────────┬──────────────────────────────────────────────┤
│ Byte 4: Status   │ → Page state (mount/active/erased/hole)    │
│ Byte 8: Chain    │ → Duplicate/mirror hop marker (chain_v1)   │
│ Byte 9-10: Phys  │ → Raw NAND erase-block index               │
│ Byte 11-12: Virt │ → OpenTL virtual block ID                  │
│ Byte 13: Page    │ → Page index within erase block            │
│ Byte 15: Xsum    │ → Checksum (ntl_compute_spare_xsum)        │
├──────────────────┴──────────────────────────────────────────────┤
│ 8-byte virt table (per block) │ OpenTL RAM chain │              │
│   [4]  = phys_unit (uint32)  │ ├─ ntl_put_chain_in_array()   │   │
│   [5]  = valid/flags (uint8) │ └─ ntl_find_phy()             │   │
│                                │                               │   │
│                                │ 8-byte remap table            │   │
│                                │ └─ ntl_read_page() → virt→phys│   │
└─────────────────────────────────────────────────────────────────┘
```

### 5.4 Key Differences Summary

| Aspect | Raw NAND Spare | OpenTL Spare |
|--------|----------------|--------------|
| **Origin** | Datasheet (Spansion) | Bootloader + Kernel |
| **Size** | Always 64 bytes | 64 bytes (same OOB area) |
| **Modified** | Only by erase | Continuously by write/delete/fold |
| **Physical block** | Direct NAND block index | Virtual block mapped to physical |
| **Bad block** | Factory-marked or detected on-read | Marked in stats + chain table |
| **ECC** | Manufacturer's (Hamming-style) | OpenTL software ECC (opentl_calculate_ecc) |
| **Tool** | `S34ML01G1.decode_spare()` | `parse_spare()` + `ntl_*` functions |

---

## 6. Boot-Time Geometry (fwupgrade.txt evidence)

The boot log (`fwupgrade.txt`) provides ground-truth verification of all parameters:

```
BCMNAND: size=128MB, block=128KB, page=2048B, spare=64
BRCM NAND flash device: nand0, id 0x01f1
1024 good blocks in-band

TL_debug: mediasize=128000 ... 1012 ... spares=85
Adjusting virtual blocks 1012 to account for 30 bb blocks
Adjusting virtual blocks 1012 to account for 1 stat blocks
resetting statsBlock statistics

nand_geom: cap=251132 cyl=980 nhead=16 nsectors=16
```

**Derivation:**

```
1012 raw TL units in tlpart slice (after loader + mtdoops)
  - 30 bad blocks → reserved for wear
  - 1 stats block → bookkeeping
  = 982 usable virtual blocks

982 × 128 KiB = 125,696 KiB = 251,392 sectors (× 512 B)
  = 251,132 sectors (observed: cap=0x0003D4FC)
```

---

## 7. Storage of Spare Data in the Repository

The repo stores spare data in several ways:

| Artifact | Role |
|----------|------|
| **`PACE 5268AC S34ML01G1@TSOP48.BIN`** | Full flash capture (138,412,032 B inline 2048+64) |
| **`flash strings.txt`** | String extraction from flash dump |
| **`mtd_parts/tlpart.bin`** | Carved MTD slice containing OpenTL data |
| **`reference/spare64_bbm_field_map.md`** | 64-byte spare field map with OpenTL vs raw NAND |
| **`reference/s34ml01g1_key_params.md`** | Key parameters summary |

### 7.1 Reader File Layouts

| Layout | File Size | Description |
|--------|-----------|-------------|
| **Inline** | 138,412,032 B | `2048 + 64` interleaved per page |
| **Flat-tail** | 138,412,032 B | 2,048 data bytes followed by spare tail |
| **Logical** | 134,217,728 B | Data plane only (no OOB) — after `nand-translate --mode auto` |

For Binwalk/carving on logical offsets, use the **logical** (data-only) view. For spare analysis, use the **inline** or **spare-extracted** view.

---

## 8. Tooling Integration

| Tool | Module | Uses Geometry For |
|------|--------|-------------------|
| `hexdump` | `unand/hexdump.py` | Page iteration, spare interleaving |
| `NandPageReader` | `unand/reader.py` | Sequential page-by-page reads |
| `normalize_to_logical` | `unand/layout.py` | Inline → flat-tail → logical conversion |
| `decode_spare` | `unand/s34ml.py` | 64-byte spare decoding |
| `parse_spare` | `opentl/spare_layout.py` | OpenTL spare interpretation |
| `tl-mount` | `opentl/tl_mount` | Offline virt→phys map inference |
| `tl-bbm` | `opentl/tl_bbm.py` | Bad-block mapping |
| `tl-extract` | `opentl/open_tl.py` | Virtual disk extraction |

---

## 9. S34ML Family Overview

The S34ML01G1 is part of the **S34ML01G** family (1-Gbit SLC NAND). Related devices in this repo's tooling:

| Device | Pages | Spare | Blocks |
|--------|------:|------:|-------:|
| **S34ML01G1** | 2,048 + 64 | 64 | 1,024 |
| **S34ML02G** | 2,048 + 128 | 128 | 2,048 |

The `S34MLFamily` factory (`unand/s34ml.py`) can preset geometry for both sizes, with the key difference being `page_spare=128` instead of 64.

---

## 10. Quick Reference

### Datasheet → Code Mapping

| Datasheet | Code |
|-----------|------|
| `page_size = 2048` | `geom.page_data = 2048` |
| `spare_size = 64` | `geom.page_spare = 64` |
| `block_size = 128KB` | `geom.erase_bytes = 131072` |
| `num_blocks = 1024` | `geom.num_blocks = 1024` |
| `flash_id = 0x01F1` | `S34ML01G1.flash_id = 0x01F1` |
| `page_phys = 2112` | `geom.page_phys = 2112` |

### OpenTL Kernel Functions → Python

| Kernel Function | Python Module |
|-----------------|---------------|
| `ntl_read_page` | `opentl/nand_translate.py` |
| `ntl_put_chain_in_array` | `opentl/spare_chain_replay.py` |
| `ntl_find_phy` | `opentl/spare_chain_replay.py` (via `tl_mount`) |
| `ntl_prepare_wspare` | `opentl/spare_layout.py` |
| `ntl_compute_spare_xsum` | `opentl/spare_layout.py::compute_spare_xsum` |
| `ntl_verify_read_phy_page` | kernel / future `tl_mount` parity |
| `ntl_mount` | `opentl/tl_mount` (orchestration TBD vs kernel `ntl_mount`) |
| `opentl_add_mtd` | `opentl/tl_physical.py` |
| `parse_bsd` | `opentl/tlpart_spare.py` |

### Boot Log Keywords (grep these)

| Keyword | File | Meaning |
|---------|------|---------|
| `BCMNAND: size=128MB` | `fwupgrade.txt` | NAND geometry confirmation |
| `TL_debug: mediasize` | `fwupgrade.txt` | OpenTL disk capacity |
| `resetting stats` | `fwupgrade.txt` | Stats block initialization |
| `nand_geom: cap=251132` | `fwupgrade.txt` | Sector count on TL disk |
| `parse_bsd: Partition` | `fwupgrade.txt` | Disklabel parsing |
| `bootcmd=if tl checkfstype` | `flash strings.txt` | Boot path selection |
| `opentla` | `flash strings.txt` | OpenTL partition names |

---

*Last updated: May 2026. Cross-references: `hardware.md`, `firmware.md`, `issue.md`, `spare64_bbm_field_map.md`, `opentl_kernel_ghidra.md`, `prom_init_ghidra.md`.*