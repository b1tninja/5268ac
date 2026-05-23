# 010 Editor Binary Templates (5268)

This folder contains [SweetScape 010 Editor](https://www.sweetscape.com/010editor/) **Binary Templates** (`.bt`) for **5268** reverse-engineering workflows: **inline** NAND dumps (`unand` / `opentl` geometry) and **ATT / 2Wire `.pkgstream`** install carriers (`lib2spy.pkgstream`).

## Manual

- **[templates.md](templates.md)** — Binary Template engine: capabilities, language surface, curated manual links, and link to the full **`manual_md/`** index.
- **[scripts.md](scripts.md)** — Scripting engine (`.1sc`): automation, declaration rules, shared runtime, debugger, curated links.
- **[manual_md/README.md](manual_md/README.md)** — One **Markdown summary per `manual/*.htm`** topic (141 pages); see **[manual_md/MANUAL_MIRROR.md](manual_md/MANUAL_MIRROR.md)** for regeneration. Generator: **`reference/010editor/tools/gen_manual_md.py`**.
- **[010_TEMPLATE_AND_SCRIPTING.md](010_TEMPLATE_AND_SCRIPTING.md)** — agent-oriented synthesis (template vs script, `FTell`/`Read*`, `read=`, `startof`, limitations) with links into the local **`manual/*.htm`** mirror.
- Cursor skill **`010bt`** (`.cursor/skills/010bt/SKILL.md`) points agents at that synthesis for `.bt` work.
- [Writing Templates (Wayback)](https://web.archive.org/web/20260129195303/https://www.sweetscape.com/010editor/manual/IntroTemplates.htm) — C-like syntax, `LittleEndian()`, structs, `while (FTell() < FileSize())`, and optional field metadata such as `format=hex`.
- [Bitfields](https://www.sweetscape.com/010editor/manual/Bitfields.htm) — `ubyte name : 1` inside a small `typedef struct` renders **checkboxes** in Template Results for spare flag bytes and SR1.
- [Custom Variables / read=](https://www.sweetscape.com/010editor/manual/CustomVariables.htm) — `read=` on a typedef (including inline `Str(..., this)` in 010 v12+) for human-readable **tag** and **BBI** value columns.
- [On-Demand Structures](https://www.sweetscape.com/010editor/manual/OnDemand.htm) — each **2112-byte page** struct uses `<size=2112>` so **main + spare** are parsed only when you expand that page row (large dumps stay responsive).

## Layout assumption (read this first)

### Inline NAND (2048 + 64)

These two templates parse **only** the **inline** packing:

| Region per NAND page | Size |
|----------------------|------|
| Main (MTD data plane) | **2048** bytes |
| Spare (OOB) | **64** bytes |
| **Stride** | **2112** bytes |

That matches `NandGeometry.page_phys` in `unand/geometry.py` and `NandPageReader` in `unand/reader.py`.

**Not supported here:** logical-only dumps (`logical_bytes` = 128 MiB main with no OOB interleaved), or **flat-tail** dumps (`logical_bytes` + `oob_total_bytes` concatenated). See `unand/README.md` for those variants.

If `FileSize() % 2112 != 0`, each NAND template emits a **Warning** and may still parse whole pages up to the truncated tail.

### `.pkgstream` (2WIRE_SP + TLV prefix)

**[Pkgstream_2WIRE_SP.bt](Pkgstream_2WIRE_SP.bt)** expects **`2WIRE_SP`** at file offset **0** (24-byte big-endian header, then `>II` TLV records). If the file starts with **`BZh`**, decompress first (same rule as `lib2spy.native_pkgstream.try_decompress_bzip2_prefix`). The template walks only the **linear TLV prefix** until a length would pass EOF (same stopping behavior as `iter_tlvs_prefix_only`). Embedded SquashFS/uImage spans are **not** modeled in 010; use **`python -m lib2spy`** and **[pkgstream.md](../pkgstream.md)** for the full dump and verifier.

**What the template decodes in 010 (hints only):**

- **Header** `read=`: confirms structural `2WIRE_SP` and points to cryptographic verification in Python.
- **Per-TLV `tlv_hint`**: symbolic type, length, file offset; for **FILE** / **PATH_FILE** (`0x1`, `0x3`, `0x2F`) — `path_off`, `path_len`, `hash_alg` (SHA-1 / MD5 / SHA-256 when known) and a bounded **path** preview when in-bounds; for **SCRIPT** (`0x26`) — `hash_alg`; for small payloads (length ≤ 64) — a short **ASCII** preview.
- **Post-prefix row** `pkgstream_postfix_hint` (`comment="postfix analysis"`): if the first byte after the TLV prefix is **`0x30 0x82`**, notes a likely **DER PKCS#7** outer; otherwise a short non-match note.

**Python-only integrity** (see **[pkgstream.md](../pkgstream.md) §9.3–§9.4** and **`lib2spy/pkgstream_verify.py`**): SHA-1 over the signed prefix vs **`messageDigest`** in CMS, **RSA** signature and **X.509** chain trust, per-**FILE** / **SCRIPT** digest checks over **file-payload** blob offsets, and full **CMS** parsing. Run **`python -m lib2spy`** (with verify flags as documented) for those checks.

## Files

| Template | Use when |
|----------|----------|
| `S34ML_NAND_inline_2112.bt` | You want **datasheet-oriented** spare labels (Spansion S34ML large page) plus cross-notes to OpenTL where fields overlap. |
| `OpenTL_NAND_inline_2112.bt` | You want **OpenTL / kernel-aligned** names (`ntl_prepare_wspare`, `ntl_find_phy`, `ntl_compute_spare_xsum`, §7.3–§7.4 in `reference/spare64_bbm_field_map.md`). |
| `Pkgstream_2WIRE_SP.bt` | You have a **decompressed** `.pkgstream` (or body) starting with **`2WIRE_SP`**: header + TLV tree; cross-check TLV offsets with `python -m lib2spy <file>` (`lib2spy/native_pkgstream.py`, `pkgstream.md`). |

## Comment style

Both NAND `.bt` files and **`Pkgstream_2WIRE_SP.bt`** keep **full semantics in `//` comments** above members. **`format=hex`** stays on numeric fields where useful.

**`<comment="...">` is used sparingly:** on **`spare_decoded`** / **`tlv_hint`** / **`pkgstream_postfix_hint`** (`comment="spare analysis"` / **`comment="tlv analysis"`** / **`comment="postfix analysis"`**) so the Variables pane flags derived rows.

**Collapsed page rows:** each **`page[i]`** struct has a **`read=`** summary ([Custom Variables – struct read](https://www.sweetscape.com/010editor/manual/CustomVariables.htm)) built with **`ReadUByte` / `ReadUShort` at `startof(page)+2048+offset`**. That matches the on-demand `<size=2112>` layout so hints (**ERASED-like**, **xsum BAD**, **MIRROR**, **TAGGED**; S34ML adds **BBI bad**, **SR1 fault**) appear in the **Value** column **before** you expand `main_plane` or `spare`.

## Decoded spare (Template Results)

Each **64-byte spare** struct includes a zero-width **`spare_decoded`** `local string` with a **`read=`** function ([Declaring Template Variables](https://www.sweetscape.com/010editor/manual/TemplateVariables.htm), [Custom Variables](https://www.sweetscape.com/010editor/manual/CustomVariables.htm), [Functions](https://www.sweetscape.com/010editor/manual/Functions.htm)). Each **2112-byte `page`** row also has a struct **`read=`** one-line hint (see Comment style above). After running the template, expand **`spare` → `spare_decoded`** in the **Template Results** / Variables tree to see:

- `phys_u32`, `virt_u32` (LE low + high compose, same as `SpareRecord.phys_u32` / `virt_u32`)
- `chain_next_phys` (large-page **mode 2** packing from `next_phys_from_spare_chain_step` — differs from `phys_u32` when bytes 16–17 are non-zero)
- `xsum_calc` vs `xsum_stored` and **OK** / **MISMATCH** (matches `opentl.spare_layout.compute_spare_xsum` / `xsum_matches`)
- `kernel_tagged_like`, `mirror_dup` (from **`FLAGS08_BITS.mirror_dup`** checkbox on spare `[0x08]`)
- **`erased_page`** (heuristic: tag `0xFF`, phys/virt lows `0xFFFF`, stored xsum `0xFF` — spare-row fields only; not a full main-plane `0xFF` scan)
- **S34ML template only:** `SR1` hex plus mask tokens from **`SR1_BITS`** checkboxes; **`BBI_BYTE`** shows BAD/GOOD/ambiguous on spare `[0x02]`
- **Tag column:** spare `[0x04]` is **`SPARE_TAG_BYTE`** with inline **`Str(..., this)`** (010 **v12+**); older builds may need a named `read=` function instead

**Checkbox UI:** expand **`spare` → `spare_flags_byte8`** (OpenTL + S34ML) or **`spare_status_sr1`** (S34ML) to see named bits in Template Results.

**On-demand pages:** expand **`page[i]`** before **`main_plane`** / **`spare`** populate; the file still advances **2112 bytes** per page at the top level. With the template run, each **`page`** row’s **Value** column shows the **one-line `read=` hint** (file-relative spare reads) even while the row is collapsed.

No separate 010 Script is required; all logic lives in the `.bt` file.

## Provenance (Python / docs)

- `unand/s34ml.py`, `unand/geometry.py`, `unand/README.md`
- `opentl/spare_layout.py`, `opentl/spare_chain_replay.py`
- `lib2spy/native_pkgstream.py`, `lib2spy/pkgstream.py`, `pkgstream.md`
- `reference/spare64_bbm_field_map.md`
- `reference/pdfs/S34ML01G1.PDF` (chip / SR1 / factory spare table)
- `reference/opentl_kernel_ghidra.md` (if present — kernel symbol names)
- `reference/tools.md` (example paths to `*.pkgstream` under `firmware_*/…/install_package/` when present in your tree)

## Quick verify (Python + 010)

Committed fixture `fixtures/synthetic_inline_2pages.bin` (2 pages, inline 2112-byte stride). First spare row: file offset **2048** … **2111**.

```bash
python -c "from pathlib import Path; from opentl.spare_layout import compute_spare_xsum, parse_spare, xsum_matches; b=Path('reference/010editor/fixtures/synthetic_inline_2pages.bin').read_bytes(); s=b[2048:2112]; r=parse_spare(s); print('phys_u32', hex(r.phys_u32()), 'virt_u32', hex(r.virt_u32()), 'xsum', hex(compute_spare_xsum(s)), 'match', xsum_matches(s))"
```

Expected first spare: `phys_u32 0x3412`, `virt_u32 0x7856`, `xsum 0x19`, `match True`. In **010 Editor**, run the template on that fixture: the **`page[0]`** row should show a **Value** hint (e.g. `TAGGED` / `xsum BAD` / `-`) without expanding the page. Then expand **`page[0]`** and **`spare` → `spare_decoded`** to confirm the same values and **OK** on the xsum line. Truncate the file by one byte to confirm the **Warning** when `size % 2112 != 0`.

If `spare_decoded` fails to compile on an older 010 build, see [Template Limitations](https://www.sweetscape.com/010editor/manual/TemplateLimitations.htm); a tiny standalone `.1sc` script would be plan B only if `read=` locals are unsupported.

## Quick verify (pkgstream + 010)

With a **decompressed** carrier whose first bytes are `2WIRE_SP`, open it in 010 with **`Pkgstream_2WIRE_SP.bt`**, then compare TLV offsets/names to:

```bash
python -m lib2spy path/to/install.pkgstream --no-verify
```

(or add `--json --out-json out.json` for machine-readable TLV metadata). Example install paths when present in your tree: see **`reference/tools.md`** (`install.pkgstream` under `firmware_*/…/install_package/`).
