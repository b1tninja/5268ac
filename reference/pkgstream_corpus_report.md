# pkgstream corpus scan

_Generated 2026-05-10T13:10:20Z (historical generator referenced `opentl/tests/test_pkgstream_corpus.py`; `opentl/tests/` removed — use `tests/test_pkgstream_corpus.py` or successor)._

Total files scanned: **354** (4 local + 350 remote).

Verifier: `verify_pkgstream(path, rsa_verify=False)` — checks PKCS#7 envelope presence, `messageDigest` over the signed prefix, and every per-FILE / per-SCRIPT TLV digest, but skips the RSA signer step (see `pkgstream.md` § 9 for the full integrity model).

Status legend:

* `ok` — every layer matched (parser walked the whole file, PKCS#7 messageDigest matched, every FILE+SCRIPT digest matched).
* `pkcs7_absent` — no PKCS#7 envelope found (older / unsigned / truncated configs).
* `messagedigest_mismatch` — PKCS#7 present but `messageDigest` does not match the prefix.
* `file_digest_mismatch` — at least one FILE TLV's per-payload digest failed.
* `script_digest_mismatch` — at least one SCRIPT TLV's per-payload digest failed.
* `parse_error` — the parser itself raised an exception (real bug — should be 0).
* `io_error` — file could not be opened (network / permission / dead path).

## Local (D:) — 4 files (32.3 MB, 0.1 s)

| Status | Count | Example file | Notes |
|--------|-------|--------------|-------|
| `ok` | 4 | `att_cms-certs.pkgstream` | — |

## Remote (M:) — 350 files (1774.6 MB, 1.5 s)

| Status | Count | Example file | Notes |
|--------|-------|--------------|-------|
| `ok` | 350 | `5268.install.pkgstream` | — |

