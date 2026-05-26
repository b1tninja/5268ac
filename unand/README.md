# unand — NAND dump geometry for 5268-class Pace captures

`unand` turns **full-chip reader files** (inline **2048+64** B per page, or **flat-tail** packing, or already-logical **128 MiB**) into:

1. The **MTD data plane** — **134217728** contiguous bytes (what `mtdparts=` indexes).
2. Optionally, a **flat spare stream** — **4194304** bytes (**65536 × 64**), one spare row per NAND page in chip order.

Long-form evidence and tooling notes live under [`../reference/`](../reference/) (e.g. `hardware.md`, `firmware.md`, `opentl.md`, `spare64_bbm_field_map.md`).

### Kernel analogue

| Layer | Role in `unand` |
|-------|-----------------|
| NAND controller + chip → **one MTD master** (main user bytes) | `normalize_to_logical`, `LogicalPlane`, `NandGeometry.logical_bytes` |
| **`mtdparts=`** cmdline on that plane | `unand.mtd.parse_mtdparts` — **only** main-plane offsets/sizes |
| Logical byte run on a raw dump (no full deinterleave to RAM) | `unand.layout.read_logical_plane_interval` — maps a logical `[start, start+len)` through **LOGICAL_ONLY** / **flat-tail** / **inline 2048+64** packing (used by **`boardfs.flash_layout`** for U-Boot env-sized probes) |
| Spare / OOB | **Not** an `mtdparts` slice; optional **offline** sidecar (`spare_out`) in lockstep with pages |

Canonical boot + storage diagrams: [`reference/boot_and_storage.md`](../reference/boot_and_storage.md).

**Kernel ↔ Python anchors:** Ghidra load addresses in source comments (`#region kernel: 0x…`) are documented in [`reference/kernel_python_regions.md`](../reference/kernel_python_regions.md).

### `LogicalPlane` — high-level dump view (OpenTL / scripts)

[`unand.plane.LogicalPlane`](../unand/plane.py) is the preferred façade for “this path might be raw inline, flat-tail, or already logical”: call [`LogicalPlane.open_file`](../unand/plane.py) for [`detect_layout_file`](../unand/layout.py) + construction, [`flat_spare_bytes`](../unand/plane.py) when OOB is in-band, and [`materialize_logical_plane`](../unand/plane.py) to write a **128 MiB** logical file for tools that need a contiguous main image. Higher layers such as **`opentl`** use this instead of importing [`normalize_to_logical`](../unand/io.py) / [`extract_spare_bytes`](../unand/io.py) directly for tl-mount style flows.

---

## MTD partitions vs spare (OOB)

**Kernel `mtdparts=` describes only the data plane.** Names like `loader`, `mtdoops`, and `tlpart` are byte ranges within the **128 MiB** of **main** data the MTD stack exposes. They are **not** defined over the **4 MiB** spare aggregate, and spare is **not** a separate `mtd` device in the Pace/`fwupgrade.txt` model.

In `unand`, `parse_mtdparts()` applies to **`logical_bytes`** (main only). The optional **`spare_out`** file from `normalize_to_logical()` is an **offline artifact**: same page ordering as the chip, but **not** an MTD partition.

---

## NAND page vs OpenTL "sector"

Geometry is **per physical NAND page**:

| Region | Size | Role in `unand` |
|--------|------|------------------|
| Main | **2048** B | One step along the **logical** / MTD address space |
| Spare (OOB) | **64** B | One row **for that same page** (same page index) |

**OpenTL** (on `tlpart`) exposes a disk with **512**-byte **sectors**; **four** sectors fit in one **2048**-byte main page. The **64**-byte spare belongs to the **whole page**, not to four separate spare regions per 512-byte sector. So:

- `LogicalPlane.read(offset, …)` and MTD offsets → **main** bytes only.
- `LogicalPlane.read_oob_page(page_index)` → **64** bytes for NAND page `page_index` (main pages numbered **0 … pages_total−1**).

---

## What spare bytes can contain

The **64-byte row** is still "OOB" from the NAND perspective, but **different subsystems** use it for different purposes. `unand` does **not** decode these meanings; it only **extracts** or **indexes** rows. For interpretation, use the reference docs and `opentl`:

1. **Controller / chip housekeeping** — ECC-related fields and read status (see early Linux printks in `fwupgrade.txt`). Full-chip dumps are usually **host-visible** data already corrected for analysis; `unand` does not run ECC.
2. **Boot / partition discovery (U-Boot)** — e.g. vendor markers such as **`BootCode`** in early spare, used while probing layout (**not** the same as OpenTL's `ntl_*` BBM chain). See `reference/opentl.md` §6.1.
3. **OpenTL (`ntl_*`)** — virtual/physical block metadata, checksums, bad-block chain links, etc. Field offsets and algorithms are documented in **`reference/spare64_bbm_field_map.md`** and implemented under **`opentl/`** (`spare_layout.py`, `spare_chain_replay.py`, …).

---

## Layout detection (summary)

At **138412032** bytes, inline and flat-tail **both** sum to **128 MiB + 4 MiB**. `unand` picks between them using **weak** ELF anchors on the logical plane (see `layout.py`). The repo's **`PACE … TSOP48.BIN`** is **inline** per `reference/opentl.md` §6.

---

## Python API — Programmatic interface

### Chip identity (`NandChip`)

A `NandChip` carries the complete identity of a NAND flash device: manufacturer, model, geometry, and optional flash ID.

```python
from unand import NandChip, PACE_DEFAULT

chip = NandChip(
    manufacturer="Spansion",
    model="S34ML01G1",
    geometry=PACE_DEFAULT,
    flash_id=0x01F1,
)
```

Pre-built chip presets ship with the package:

```python
from unand import S34ML01G1_chip, S34ML02G1_chip, S34ML04G1_chip

print(S34ML01G1_chip)  # NandChip(Spansion S34ML01G1)
```

### Chip family — auto-detect from dump size

The S34ML family resolves the correct model from the file/bytes size:

```python
from unand.s34ml import S34MLFamily

# Auto-detect chip from file path, raw bytes, or file handle
chip = S34MLFamily.from_chip("TSOP48.BIN")
# chip → NandChip(Spansion S34ML01G1)  (if file is 138412032 bytes)

# Or from raw bytes
chip = S34MLFamily.from_chip(raw_dump_bytes)
```

### `NANDReader` — in-memory reader with `BytesIO` access

The generic reader accepts a `chip` parameter on every factory method:

```python
from unand import NANDReader

# With chip identity
reader = NANDReader.from_path("TSOP48.BIN", chip=S34ML01G1_chip)
reader = NANDReader.from_bytes(raw_data, chip=chip)
with open("dump.bin", "rb") as fh:
    reader = NANDReader.from_handle(fh, chip=chip)

# Or without — geometry falls back to PACE_DEFAULT
reader = NANDReader.from_path("dump.bin")
```

### Extract `BytesIO` planes

```python
logical = reader.logical_plane()      # BytesIO (128 MiB data plane)
spare   = reader.spare_stream()       # BytesIO | None (4 MiB OOB)
both    = reader.plane_and_spare()    # (BytesIO, BytesIO | None)

# Reader also stores the chip identity
print(reader.nand_chip)                # NandChip(Spansion S34ML01G1)
```

### Per-page random access

```python
page0_data = reader.read_page(0)      # 2048 bytes (main data)
page0_oob  = reader.read_oob(0)        # 64 bytes  (spare row)
mtd_chunk  = reader.read_mtd(0x1000, 4096)  # 4 KB from MTD address space
```

---

## CLI

```bash
python -m unand translate INPUT.bin -o logical.bin --spare-out spare.bin --print-mtd
python -m unand sha256-logical INPUT.bin