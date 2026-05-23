# 2WIRE / LIB2SP carrier format (from `lib2sp.so` RE)

For the **full** specification (Ghidra xref tables, diagrams, and repo tool links), see **[`pkgstream.md`](../pkgstream.md)** at the repository root.

Source: Ghidra decompilation of **`/usr/lib/lib2sp.so`** on MIPS big-endian firmware (`5268ac` project). Consumer **`pkgd`** links **`lib2sp_simple_unpack`** → **`lib2sp_install_data`**, which parses the byte stream.

**Naming authority:** Prefix TLV labels in **`lib2spy/pkgstream.py`** and **`reference/010editor/Pkgstream_2WIRE_SP.bt`** stay on the **metadata-prefix** wire vocabulary. For **what the gateway does** after trust checks, use the **single-token** **`install_action`** in **`lib2spy/pkgstream_runtime.lib2sp_dispatch`** (`copy`, `stage`, `dispatch`, `move`, `mkdir`, `link`, `clone`, …) and read **`install_comment`** for tooltip-style detail (same role as a 010 Editor `<comment=…>`). Ghidra **`demarshall_2sp_*`** names in [`../output/ghidra_mcp_lib2sp_10_5_3_527064/README.md`](../output/ghidra_mcp_lib2sp_10_5_3_527064/README.md) are parser entry points behind those tokens. **`libpkg_*`** (**`libpkg_client`**, **`libpkg_server`**, **`libpkg_common`**) are linked from **`pkgd`** / **`httpd`** / **`cwmd`** for **download and RPC orchestration**; filesystem side effects for TLV apply live in **`lib2sp.so`**. Inferred getter / ASCII payload notes in **`pkgstream.md`** §9.10 remain supporting context, not canonical type tokens.

## Outer container

| Offset | Size | Content |
|--------|------|---------|
| 0 | 8 | ASCII label (products use **`2WIRE_SP`**) |
| 8 | 4 | `uint32_t` big-endian |
| 12 | 4 | `uint32_t` big-endian |
| 16 | 4 | `uint32_t` big-endian |
| 20 | 4 | `uint32_t` big-endian |

**Functions:** `demarshall_2sp_header` / `marshall_2sp_header` — require **≥ 0x18** bytes; copy 8 bytes then four big-endian words via `nu_ngeth32` / `nu_hputn32`.

Example (`att-5268-…-lightspeed-install.pkgstream`), hex:

```text
32 57 49 52 45 5f 53 50   '2WIRE_SP'
00 00 00 01  00 00 00 01  00 01 51 30  01 e9 ba 61
```

## TLV records

Each record:

| Field | Size | Endian |
|-------|------|--------|
| type | 4 | big-endian |
| length | 4 | big-endian |
| payload | `length` | opaque |

**Functions:** `marshall_2sp_tlv` writes type + length (needs **≥ 8** bytes).

The metadata prefix is a **linear** sequence of TLVs. After the last TLV that fits this model, the stream may continue with **DER / PKCS#7** blobs (`30 82 …`) or large FILE payloads — do not assume TLVs span the entire file.

Observed **payload-related** types in **`lib2sp_do_payload_tlv`** (selector on first word) — this function **streams** FILE/SCRIPT bytes from the carrier into open/write/close helpers; unsupported types here go to `lib2sp_set_error` with category **`0xb`**:

| Type (hex) | Decimal | Role |
|------------|---------|------|
| 0x1, 0x3 | 1, 3 | File install (`demarshall_2sp_file`) |
| 0x26 | 38 | Script (`demarshall_2sp_script`) |
| 0x2F | 47 | Path / file variant (`demarshall_2sp_file`) |
| 0x3E8 | 1000 | DPI signature (`demarshall_2sp_dpi_sig`) |

**Install-phase dispatcher (`lib2sp_payload_data`)** — separate from the table above. After PKCS#7 and prefix TLVs are handled, the on-device state machine walks **payload** TLVs again and routes **many more wire types** before hitting a **per-type function pointer table** (mkdir, symlink, copy, **another** call into `lib2sp_do_payload_tlv` for byte streaming, etc.). The operator-facing reading is **filesystem verbs**; Ghidra names are the parser hooks. Decompilation on **`lib2sp.so` `10.5.3.527064`** (addresses differ from older builds) includes at least:

| Type (hex) | `install_action` (one word) | Ghidra parser (`lib2sp_payload_data`) | `install_comment` (summary) |
|------------|------------------------------|---------------------------------------|------------------------------|
| 0x01, 0x03, 0x2F | **copy** | `demarshall_2sp_file` → `lib2sp_do_payload_tlv` | Stream digest-verified bytes from carrier to absolute path (open/write/close). |
| 0x26 | **stage** | `demarshall_2sp_script` | Heap buffer for script body; close hands off to indirect runner. |
| 0x07, 0x27, 0x28 | **dispatch** | `demarshall_2sp_path` | Parse path TLV; jump table runs mkdir / symlink / rootfs copy helpers. |
| 0x08, 0x29–0x2B | **move** | `demarshall_2sp_move` | Move/rename ladder on target rootfs. |
| 0x04 | **dispatch** | (no FILE `1/3` fast-path) | Hits indirect jump table for `< 0x30`; same helper family as path/mkdir/link/clone/stream. |

Jump-table helpers (also one-word `install_action` in stubs): **mkdir**, **link** (symlink), **clone** (`lib2sp_do_copy_file`, rootfs-to-rootfs), **copy** (re-enter `lib2sp_do_payload_tlv` stream writer).

**Delete:** not a dedicated TLV opcode here; **`unlink`** appears in **`lib2sp_write_file`** teardown on some failure paths (partial file cleanup).

Decompiler C sources and notes: **[`../output/ghidra_mcp_lib2sp_10_5_3_527064/README.md`](../output/ghidra_mcp_lib2sp_10_5_3_527064/README.md)**. The offline CLI (**`python -m lib2spy`**) still only **verifies** prefix FILE/SCRIPT digests + PKCS#7; it does **not** emulate `lib2sp_payload_data` side effects.

**Symbolic TLV names** in dumps and in **`reference/010editor/Pkgstream_2WIRE_SP.bt`** follow the **prefix-chain** vocabulary (aligned with **`lib2spy/pkgstream.py`** `_TLV_NAMES`). For **`install_action`** (one token) and **`install_comment`** (verbose) per opcode, jump-table helpers, and carve vs mount, see **`lib2spy/pkgstream_runtime`** (no emulation — documentation only).

**Prefix TLV dry-run:** [`../lib2spy/pkgstream_runtime/tlv_dry_run.py`](../lib2spy/pkgstream_runtime/tlv_dry_run.py) exposes **`trace_pkgstream_path`** / **`trace_prefix_tlv_chain`**; CLI **`python -m lib2spy.pkgstream_runtime <file.pkgstream>`** (JSON by default, **`--text`** table). It replays only the **linear prefix** walk (`iter_tlvs_prefix_only`) plus optional **`install_hint`** fields from **`INSTALL_TLV_DEMARSHALL`**. It is **not** a `lib2sp_payload_data` state machine, does **not** open/write/mount filesystems, and does **not** run shell scripts.

FILE payloads use a fixed **100-byte** path slot (`marshall_2sp_file`: `param_3[1] == 100`) and nested header fields before variable path and file bytes.

## Compression

- **Outer stream:** If the first bytes match **`BZh` + digit**, `lib2sp_install_data` enters state **2**, allocates a **0xffd0**-byte decode slab, and runs **bzip2** (`BZ2_bzDecompressInit` / `BZ2_bzDecompress`). Decompressed bytes should begin with the same **`2WIRE_SP`** header when this wrapper is used.
- **Members:** Inner FILE/script handling can involve additional bzip2 segments (error strings reference **bzip2 magic / sequence / data** errors).

## Integrity

The **24-byte header has no checksum** and the TLV chain has **no per-record CRC/hash**. Carrier integrity is enforced by **three cryptographic layers** plus uImage CRCs:

1. **Detached PKCS#7 / CMS `SignedData`** — sits immediately after the TLV prefix (`body[5419..13492]` in the 5268 install). Signs `body[0..5419)` with **RSA-PKCS#1 v1.5 over SHA-1**. Three SignerInfos (one short-key engineering test signer, two production signers); 3-cert cert set in the SignedData; trust anchors in companion **`att_cms-certs.pkgstream`**.
2. **Per-FILE / per-SCRIPT TLV digests** — each FILE (`0x01` / `0x03` / `0x2F`) and SCRIPT (`0x26`) TLV body declares an algorithm tag (1=SHA-1, 2=MD5, 3=SHA-256), digest, payload offset, and size. Authenticated transitively through the PKCS#7 envelope (which signs the whole TLV manifest including these digest claims). Ground truth from the live 5268 install: **11 FILE TLVs + 13 SCRIPT TLVs, all SHA-1**.
3. **Outer bzip2** (when present): per-block + stream CRC32 — transport corruption only.
4. **Embedded uImage member**: standard U-Boot `ih_hcrc` + `ih_dcrc` (CRC32), **verified by U-Boot, not by `lib2sp`** — see [`fwupgrade.txt`](../fwupgrade.txt) `Verifying Checksum ... OK`.

The legacy in-band **DPI signature TLV `0x3E8`** (`demarshall_2sp_dpi_sig`) is **not present** in the 5268 firmware — that handler is for an older flow superseded by the PKCS#7 envelope.

Verification primitives reverse-engineered from `lib2sp_internal_check_data` (`0x0001E104`), `verify_hash_alg` (`0x0001D800`), and the FILE/SCRIPT demarshallers; reimplemented in [`../lib2spy/pkgstream_verify.py`](../lib2spy/pkgstream_verify.py). Use `python -m lib2spy <file>` for an end-to-end check, or `lib2spy.pkgstream_verify.verify_pkgstream(path)` programmatically; full layered analysis is in [`pkgstream.md` § 9 — Integrity model](../pkgstream.md#9-integrity-model).

## Standalone extraction without a carve index

For SquashFS **little-endian** (`hsqs`) and legacy **uImage** (`0x27051956` big-endian), offsets and lengths can be recovered by scanning the raw (or bzip2-decompressed) byte stream:

- **SquashFS LE:** magic `hsqs`, **`bytes_used`** at **+40** from the superblock (little-endian `uint32`).
- **uImage:** total length **64 + ih_size**, `ih_size` big-endian at header **+12**.

This matches typical `file_map`-style carve rows for the ATT **5268** sample (`squashfs` / `uimage` offsets and sizes).

Implementation: [`native_pkgstream.py`](native_pkgstream.py).
