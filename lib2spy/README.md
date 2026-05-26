# `lib2spy` — offline `.pkgstream` / LIB2SP analysis

Python toolkit for **ATT / 2Wire install carriers** (`.pkgstream`): parse the **2WIRE_SP** container, walk prefix TLVs, verify **PKCS#7** signatures and per-**FILE** / per-**SCRIPT** digests, extract payloads, and slice embedded **SquashFS** / **uImage** blobs for corpus work.

This package does **not** run **`pkgd`** or mount filesystems on a live gateway. It mirrors on-disk checks documented from **`/usr/lib/lib2sp.so`** (Ghidra) and feeds **corpus** workflows on the same files.

**Format specification:** **[`reference/pkgstream.md`](../reference/pkgstream.md)** (full byte layout, Ghidra xref tables).  
**Security / trust policy:** **[`reference/pkgstream_security.md`](../reference/pkgstream_security.md)**.  
**Short lib2sp RE summary:** **[`opentl/pkgstream_format_lib2sp.md`](../opentl/pkgstream_format_lib2sp.md)**.  
**010 Editor template:** **[`reference/010editor/Pkgstream_2WIRE_SP.bt`](../reference/010editor/Pkgstream_2WIRE_SP.bt)**.

---

## Install

From the repo root:

```bash
pip install -e .
```

Optional extras used by some helpers:

| Extra | Enables |
|-------|---------|
| **`[dissect]`** | SquashFS tree extract via `extract_squashfs_dissect_tree` |
| default `cryptography` | RSA chain validation when using `--validate-chain` (pull in via your env / `requirements.txt`) |

---

## Command-line

### Main carrier tool

```bash
# Full text report: header, TLVs, FILE/SCRIPT digests, PKCS#7, embedded images
python -m lib2spy firmware_11.5.1.532678/.../install.pkgstream

# JSON report + write to output/
python -m lib2spy carrier.pkgstream --json --out-json output/report.json

# Extract FILE/SCRIPT payloads and CMS material
python -m lib2spy carrier.pkgstream --extract output/_pkg_extract --quiet

# PKCS#7 + FILE sniff + trailing PEM → trust experiment dir
python -m lib2spy carrier.pkgstream --extract-trust-store output/trust_pems

# Offline chain check (bundled 532678 production roots unless --trust-roots)
python -m lib2spy carrier.pkgstream --validate-chain --strict
```

`python -m lib2spy.pkgstream` is the same entry point as `python -m lib2spy`.

### Prefix TLV dry-run (no full verify / no extract)

Walks **metadata prefix TLVs** only and prints **`install_action`** hints from the Ghidra dispatch table — not a full **`lib2sp_payload_data`** state machine:

```bash
python -m lib2spy.pkgstream_runtime carrier.pkgstream
python -m lib2spy.pkgstream_runtime carrier.pkgstream --text
```

---

## Library API

```python
from pathlib import Path
from lib2spy import verify_pkgstream, extract_payloads, format_full_report, iter_pkgstream_artifacts
from lib2spy.pkgstream import _parse_only  # structural parse dict (internal helper)

path = Path("install.pkgstream")

parsed = _parse_only(path)  # or use verify_pkgstream which parses internally
report = verify_pkgstream(
    path,
    validate_chain=True,
    trust_roots=None,  # None → bundled roots + ProvenanceWarning
)
print(format_full_report(report, parsed))

manifest = extract_payloads(path, out_dir=Path("output/extract"), verify_first=True)
artifacts = list(iter_pkgstream_artifacts(path))
```

Public exports from **`import lib2spy`** are listed in [`__init__.py`](__init__.py): `verify_pkgstream`, `VerifyReport`, `FileRecord`, `ScriptRecord`, `extract_payloads`, `extract_pkgstream_slices`, `write_directory_manifest`, etc.

### Corpus / carving

```python
from lib2spy.pkgstream_corpus import extract_pkgstream_slices, write_directory_manifest

# SquashFS + uImage slices for standalone inspection
summary = extract_pkgstream_slices("install.pkgstream", out_dir="output/slices")
```

For direct indexing, prefer **`python -m corpus --build-index --pkgstream install.pkgstream`**.

---

## Package layout

| Module | Role |
|--------|------|
| [`native_pkgstream.py`](native_pkgstream.py) | Header, TLV iteration, bzip2 peel, **embedded image scan** (magic / superblock) |
| [`pkgstream_verify.py`](pkgstream_verify.py) | Integrity: `lib2sp_internal_check_data`-style digests + optional PKCS#7 RSA |
| [`pkgstream.py`](pkgstream.py) | CLI, human report formatting, **`extract_payloads`** |
| [`pkgstream_trust_anchors.py`](pkgstream_trust_anchors.py) | `--extract-trust-store`, bundled root resolution |
| [`pkgstream_carves.py`](pkgstream_carves.py) | Carve-oriented helpers |
| [`artifacts.py`](artifacts.py) | Public artifact iterator for corpus ingestion |
| [`pkgstream_corpus.py`](pkgstream_corpus.py) | Slice extract + manifests for corpus |
| [`pkgstream_runtime/`](pkgstream_runtime/) | Install-phase **stubs** and prefix **`tlv_dry_run`** (dispatch hints, not runtime pkgd) |
| [`data/trust_roots/`](data/trust_roots/) | Device PEM anchors for **`--validate-chain`** — see **[PROVENANCE.md](data/trust_roots/PROVENANCE.md)** |

---

## Verification layers

| Layer | What `lib2spy` checks |
|-------|------------------------|
| **Structure** | `2WIRE_SP` header, optional outer **BZh**, prefix TLV chain |
| **Payload digests** | Per-**FILE** / per-**SCRIPT** hashes (algorithms from TLV bodies) |
| **CMS** | PKCS#7 `SignedData`, `messageDigest`, SignerInfo RSA (unless `--no-rsa`) |
| **Chain** | Optional X.509 path to **`--trust-roots`** or bundled PEMs (`--validate-chain`) |
| **Policy knobs** | `--eng-root`, `--trust-engcert`, `--expected-cn`, `--at-time` (mirror device CMDB / librgw policy) |

Default text output is verbose by design (audit-friendly). Use **`--json`** / **`--out-json`** for automation.

---

## Ghidra exports

Decompiled C for **`lib2sp_*`** on reference builds:

| Build | Path |
|-------|------|
| **11.5.1.532678** | [`reference/ghidra_mcp_lib2sp_11_5_1_532678/`](../reference/ghidra_mcp_lib2sp_11_5_1_532678/README.md) |
| **10.5.3.527064** | [`reference/ghidra_mcp_lib2sp_10_5_3_527064/`](../reference/ghidra_mcp_lib2sp_10_5_3_527064/README.md) |

Example ground-truth JSON from a carrier run: [`output/lib2spy_532678_install_pkgstream.json`](../output/lib2spy_532678_install_pkgstream.json) (under **`output/`**, not committed).

---

## Related workspace tools

| Tool | Relationship |
|------|----------------|
| **`corpus`** | Grep direct pkgstream artifacts or dissected SquashFS trees |
| **`paceflash`** | NAND / ext2 inventory; upgrade correlation may reference pkgstream digests |
| **`reference/firmware_upgrade_process.md`** | How install carriers reach the device |

---

## Tests

```bash
pytest tests/test_pkgstream_corpus.py tests/test_squashfs_dissect.py -q
```

Broader pkgstream / verify coverage may live under repo-root **`tests/`** as the suite grows.

---

## See also

- **[`reference/pkgstream.md`](../reference/pkgstream.md)** — authoritative on-disk format  
- **[`reference/pkgstream_security.md`](../reference/pkgstream_security.md)** — engineering cert gate, symlink policy  
- **[`reference/eapol_8021x_p12.md`](../reference/eapol_8021x_p12.md)** — example `att_unified_eapol-certs.pkgstream` (CA-only carrier)  
- **[Root README](../README.md)** — workspace install and package index
