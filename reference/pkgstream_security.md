# pkgstream security analysis

> Operational security assessment of the AT&T-branded 5268AC `pkgstream` install /
> upgrade format. Pairs the Phase 1 reverse-engineering captured in
> [`output/trust_chain_re_notes.md`](output/trust_chain_re_notes.md) with
> reproducible pytest probes *(historical: the `opentl/tests/` tree was removed; rebuild under `lib2spy/tests/` or root `tests/` as needed).*
>
> Companion docs: [`pkgstream.md`](pkgstream.md) §9 (format / integrity model),
> [`firmware_upgrade_process.md`](firmware_upgrade_process.md) (end-to-end upgrade flow + diagrams),
> [`security.md`](security.md) (broader threat framing for the device).

## Contents

1. [Trust model in one diagram](#1-trust-model-in-one-diagram)
2. [Trust anchors and where they live](#2-trust-anchors-and-where-they-live)
3. [Gating logic — `trust_engcert` and signer CN pinning](#3-gating-logic--trust_engcert-and-signer-cn-pinning)
4. [Multi-signer policy: ANY-of-N](#4-multi-signer-policy-any-of-n)
5. [Concrete weaknesses and reproducible probes](#5-concrete-weaknesses-and-reproducible-probes)
   - [5.14 Install actions vs integrity and path safety](#514-install-actions-vs-integrity-and-path-safety)
6. [Mitigation recommendations](#6-mitigation-recommendations)
7. [Using the offline verifier (`lib2spy.pkgstream --validate-chain`)](#7-using-the-offline-verifier-opentlpkgstream---validate-chain)
8. [Open questions / out-of-scope items](#8-open-questions--out-of-scope-items)

---

## 1. Trust model in one diagram

```mermaid
flowchart LR
  subgraph storage [Persistent storage]
    cmdb[/rwdata/cm/ \nCMDB tree]
    pki[(libpki.so.0\nhardcoded DER blobs)]
    pem[/etc/pki/cacerts/\n+ /etc/pki/roots/]
  end
  subgraph runtime [Runtime - pkgd / lib2sp]
    rgw[librgw_compat.so\ntw_ulib_is_trustengcert_enabled\ntw_ulib_get_trust_2sp_cn]
    setup[pki_ver_setup_trust_roots]
    sp[lib2sp_check_data\nANY-of-N]
    unpack[lib2sp_simple_unpack]
  end
  subgraph attacker [Attacker primitives]
    leak[Leaked engineering key]
    cmcli[cmc -i / CMDB write]
    fs[shell on box]
  end
  cmdb -->|cm_tran_get_str| rgw
  pki -->|.rodata DER| setup
  pem -.->|extras dir scan| setup
  setup --> sp
  rgw --> sp
  sp --> unpack
  unpack -->|absolute paths\nno O_NOFOLLOW| fs
  cmcli -.flips trust_engcert.-> cmdb
  leak -.signs malicious carrier.-> sp
```

The model has **four** independent stores of trust state:

* **Compiled-in DER blobs in `libpki.so.0.0.0`** — the authoritative roots (5
  production + 1 engineering, sized `0x240 / 0x306 / 0x41e / 0x476 / 0x95c`
  and `0x3d4` respectively).
* **CMDB at `/rwdata/cm/`** — runtime state including the `trust_engcert`
  toggle and the expected signer CN, accessed via `cm_tran_*` and writable by
  any process with CMDB privilege.
* **`/etc/pki/cacerts/` and `/etc/pki/roots/`** — on-disk PEM mirrors for
  OpenSSL CLI tooling and the libpki "extras" directory scan. **Not
  authoritative for pkgstream verification** (the device's pki_ver_setup_trust_roots
  loads its compiled-in roots first; on-disk roots are additive).
* **PKCS#7 envelope inside the pkgstream itself** — the leaf and intermediate
  signing certs. **Carrier-supplied**, not trusted on its own — must chain to
  one of the above.

## 2. Trust anchors and where they live

| Source | Mechanism | Mutability | Authoritative for pkgstream? |
|---|---|---|---|
| `libpki.so.0.0.0` `.rodata` (5 prod + 1 eng DER blobs) | Compiled in at build time; loaded by `pki_ver_setup_trust_roots` | Immutable without flashing libpki | **Yes** |
| CMDB `cmlegacy.<...>.trust_engcert` (gate) | `cm_tran_get_*` from `/rwdata/cm/` | Mutable at runtime via `cmc -i` / cm RPC | Modulates whether eng root counts |
| CMDB `cmlegacy.<...>.trust_2sp_cn` (CN pin) | `cm_tran_get_*` from `/rwdata/cm/` | Mutable at runtime | Adds a constraint |
| `/etc/pki/cacerts/*.pem` + `/etc/pki/roots/*.pem` | Filesystem PEMs; libpki extras-dir scan | Mutable by anyone with rootfs write | Additive only |
| Pkgstream PKCS#7 cert set | Bytes inside the carrier under analysis | Attacker-controlled | **No** — must chain to one of the above |
| Trailing PEM blocks (post-payload) | Bytes inside the carrier | Attacker-controlled | **No** — observed empty in 11.5.1 install carrier |

The five production root subjects (DER sizes match `cacerts/` PEMs exactly):

```
OU=Class 3 Public Primary Certification Authority - G3, O=VeriSign, C=US
OU=Class 3 Public Primary Certification Authority - G2, O=VeriSign, C=US
OU=Class 3 Public Primary Certification Authority,      O=VeriSign, C=US
OU=Certification Authority - G1,                         O=2Wire Inc, C=US
CN=2Wire Gateway Emergency Authority - G1,               O=2Wire, Inc., C=US
```

Engineering root (no PEM mirror; engineering DER 980 bytes only in libpki):

```
CN=Gateway Engineering Root Cert - V1,                   O=2Wire Inc., C=US
```

The full provenance and SHA-256 fingerprints for the bundled-with-this-repo
copies live in [`opentl/data/trust_roots/PROVENANCE.md`](opentl/data/trust_roots/PROVENANCE.md).

## 3. Gating logic — `trust_engcert` and signer CN pinning

### 3.1 `tw_ulib_is_trustengcert_enabled` (CMDB-backed engineering kill switch)

* **Wrapper:** `librgw_compat.so` `@ 0x000bf6c0` — thin call to `cm_tran_get_*`
  on a CMDB OID key.
* **Storage:** OID-keyed entry in the CMDB tree at `/rwdata/cm/` (UBIFS-backed,
  MTD `tlpart` partition / OpenTL part 5).
* **Setter:** `tw_ulib_set_trustengcert @ 0x000bf730` — same RPC path, write
  through `cm_tran_set_*` + `_cm_tran_commit`.
* **Consumer:** `pkgd` reads it at install time and propagates via
  `lib2sp_set_sys_trusteng(ctx, flag)` (`lib2sp.so @ 0x00021c20`); the flag
  ends up at `verifier_ctx + 0x660` and is consulted in
  `lib2sp_verify_signature` (string `"found an engineering signature, but not
  configured to trust it"`).

**Implication:** the engineering-vs-production gate **is mutable from any
process with CMDB write access**. A privesc bug, a factory-mode flag in
`/sbin/serviceinit`, or a leaked support-staff credential that exposes
`cmc -i` is enough to flip from production-only to "accept anything an
engineering key signed."

### 3.2 `tw_ulib_get_trust_2sp_cn` (CMDB-backed signer CN pin)

* **Wrapper:** `librgw_compat.so` `@ 0x000bf78c` — copies a 16-byte (`0x10`)
  scratch buffer (likely the OID prefix) and calls `cm_tran_get_*`.
* **Storage:** another OID-keyed CMDB entry (key string not yet decoded — open
  RE item).
* **Consumer:** `lib2sp_verify_signature` matches the configured CN substring
  against the leaf cert's subject CN before allowing the signer to count.

**Implication:** the device runs with **either** an empty CN pin (anything
that chains to a trusted root passes) **or** a hard-coded production CN. The
CN pin is *advisory* — mismatching signers are skipped, not failed (consistent
with the ANY-of-N model below). An attacker with a valid signing chain to
*any* trusted root and the matching CN gets in.

### 3.3 Where the engineering DER comes from

`pki_ver_setup_trust_roots(store, include_eng_root)` always loads the 5
production roots, then conditionally adds the engineering root from
`libpki.so` `.rodata`. The `include_eng_root` argument is sourced from the
CMDB toggle above by the time pkgd has set up the verifier context. There is
no default-deny path — if libpki is rebuilt with the engineering DER absent,
the engineering signer chain becomes unverifiable; otherwise, the runtime
toggle is the only barrier.

## 4. Multi-signer policy: ANY-of-N

`lib2sp_check_data` iterates SignerInfos. For each:

1. Skip if untrusted (chain doesn't terminate at a configured root).
2. Skip if engineering-rooted and `trust_engcert=False`.
3. Skip if CN pin set and leaf CN doesn't match.
4. Otherwise verify the RSA signature; on success, increment
   `trusted_and_valid_count`.

The carrier passes if `trusted_and_valid_count >= 1`. Final log line:
`"checked %d signatures, %d are trusted and valid"`. Failure condition:
`"image contains no valid trusted signatures"`.

The 5268 install carrier ships with **3 signers** (1 engineering, 2
production); the production signers chain to `2Wire Certification Authority -
G1`. The engineering signer is silently skipped on a default device (we
verified this offline via [`lib2spy.pkgstream --validate-chain`](lib2spy/pkgstream.py)).

## 5. Concrete weaknesses and reproducible probes

Each weakness below **had** a corresponding probe under
`opentl/tests/probes/` *(removed)* that reproduced the gap. A rebuilt suite would run via:

```bash
pytest lib2spy/tests  # TBD: re-home security probes
```

### 5.1 Pre-auth parser DoS surface

**Probe:** **test_pre_auth_header_parse.py** *(historical probe; `opentl/tests/` removed)*

The 24-byte header walk and TLV iteration happen before any signature is
checked. Our verifier surfaces clean `ValueError`s on malformed input and
caps TLV lengths to body size. The device's `lib2sp.so` should do the same;
if it doesn't, a pre-auth crash inside the parser is a denial of service
against firmware updates. The probe asserts the offline tool's defensive
posture — divergence on the device requires live testing.

### 5.2 Expired engineering signer accepted (suspected)

The install carrier we have on disk includes `cert_0.pem` (engineering
signer, `notAfter = 2017-01-17`). If `trust_engcert=True` were set on a
device running this carrier today, OpenSSL's default `X509_V_FLAG_*`
behaviour should reject it for being out of validity window — but only if
`X509_V_FLAG_NO_CHECK_TIME` is not set. We have no decompilation evidence
either way for `lib2sp_verify_signature @ 0x0001c294`. The conservative
posture: **assume the device may install pkgstreams with expired signers
when trust_engcert is enabled**, especially since post-2017 firmware shipping
this carrier requires the system clock to lie or X509 time checking to be
disabled.

### 5.3 Outer bzip2 decompression bomb

**Probe:** **test_decompression_bomb.py** *(historical probe; `opentl/tests/` removed)*

`try_decompress_bzip2_prefix` calls `bz2.decompress(data)` with **no maximum
output cap**. The probe builds a sub-50-byte bzip2 file that decompresses to
1 MiB (>1000x ratio) and confirms the helper accepts it. On a 256 MiB device
running `lib2sp_install_data`, a similarly small carrier compressing to
200 MiB pre-auth is a reliable OOM. The probe is opt-in extensible to
`OPENTL_PROBE_BOMB_MIB=200` for analysts wanting to measure the device-side
behaviour.

### 5.4 SHA-1 / MD5 messageDigest across the entire corpus

**Probe:** **test_sha1_messagedigest.py** *(historical probe; `opentl/tests/` removed)*

Every signer in every `.pkgstream` we have on disk uses SHA-1 (with two
older test certs using MD5+RSA on the carrier-internal cert chain). Both
hashes are broken against chosen-prefix collisions (Shattered 2017,
SHA-1 chosen-prefix 2020, MD5 since 2009). An attacker who can pre-publish a
benign prefix with a colliding SHA-1 to a malicious one bypasses the
`messageDigest` binding without forging an RSA signature — the PKCS#7
signature still validates because the two prefixes share the same digest.

The probe walks the entire corpus and asserts the exclusive use of broken
hashes. If a future firmware introduces SHA-256, the assertion flips and
the probe forces the documentation here to be updated. Manifest written to
`pytest --basetemp` for downstream collision pipelines.

### 5.5 Trust anchor overwrite via FILE TLV path

**Probe:** **test_trust_anchor_overwrite.py** *(historical probe; `opentl/tests/` removed)*

`lib2sp_simple_unpack` accepts FILE TLVs with **arbitrary absolute
destination paths** (RE notes §5). A signed-but-malicious carrier could
declare a FILE at `/etc/pki/cacerts/twire_corprootg1.pem` and overwrite the
on-disk PEM mirror of the production root (used by libpki's "extras" dir
scan and by OpenSSL CLI tooling). The compiled-in DER in libpki is unaffected,
so this does not directly break PKCS#7 verification — but it does break any
peer code path that consults the disk mirror.

The probe demonstrates:

1. The verifier surfaces every FILE TLV path verbatim (defenders can grep).
2. The offline `extract_payloads` + `_safe_relative_path` helper refuses
   absolute paths, traversal segments, NUL bytes, and drive letters.
3. End-to-end extraction always lands inside `dest_dir`, never escapes.

The device-side gap (no allowlist on FILE TLV paths in `lib2sp_simple_unpack`)
is not patchable from the offline toolchain — it requires modifying
`lib2sp.so`. Mitigation candidates in §6.

### 5.6 Symlink follow during extract

**Probe:** **test_symlink_during_extract.py** *(historical probe; `opentl/tests/` removed)*

`lib2sp_simple_unpack` calls `lib2sp_open_file` (which uses `fopen64`/`open64`)
with **no `O_NOFOLLOW` flag** and no `realpath` validation. A signed-but-
malicious carrier could:

1. Emit a symlink TLV: `/rwdata/sys2/foo` -> `/etc/passwd`.
2. Emit a regular FILE TLV at `/rwdata/sys2/foo` containing the attacker's
   text. The open follows the symlink and overwrites `/etc/passwd` with the
   FILE TLV's mode bits.

This is a write-anywhere primitive once `trust_engcert=True` or once a
production key is leaked. The opentl extractor explicitly does not create
symlinks; the probe documents the dangerous device-side behaviour.

### 5.7 Engineering kill switch flip via CMDB

**Probe:** **test_signer_chain_invariants.py** *(historical probe; `opentl/tests/` removed)*

Demonstrates that toggling `trust_engcert` (modeled by the verifier's
matching argument) flips an engineering-rooted signer's chain status from
`skipped_eng` to `valid` without any other change. Combined with §5.5 and
§5.6, an attacker with shell + leaked engineering key + ability to flip
CMDB has a full firmware-replacement primitive.

The probe also asserts the bundled-roots `ProvenanceWarning` fires once,
and silences cleanly when an explicit `--trust-roots` is supplied.

### 5.8 `/tmp/pkgspool` staging is non-atomic with the trust check

`pkgd` downloads a candidate carrier to `/tmp/pkgspool/<name>.pkgstream`,
then opens it for verification + extraction. The download path and the
verify path operate on **the same on-disk bytes**; if any other process
with write access to `/tmp/pkgspool/` can replace the file between the
PKCS#7 verification phase and the file-payload extraction phase, the
post-verify bytes won't match the pre-verify bytes and a TOCTOU is possible.
We have no evidence pkgd uses `pread` from a single open file descriptor
across both phases. Open-RE item, but the structure of `pkg_extract.c`
(see [`unpkg.c`](unpkg.c) lines 47..81) re-reads through `lib2sp_create_context`
+ `lib2sp_simple_unpack`, suggesting a re-open is plausible.

### 5.9 Runtime PKCS#7-verification kill switch (`--noverifycert`)

**Probe:** **test_pkgd_verify_kill_switch.py** *(historical probe; `opentl/tests/` removed)*

This is the highest-impact pre-verify finding. RE'ing
`pkg_stream_handler @ pkgd:0x00422464` against
`lib2sp_disable_verify @ lib2sp.so:0x00021558` shows the install path is
guarded by a single runtime flag bit:

```c
/* pkg_stream_handler around 0x004224ac */
if ((pkgd_ctx->flags & 0x408000) == 0x400000) {
    pkg_cert_vfy_init(...);
    lib2sp_enable_verify(sp_ctx, vfy_ctx);
} else {
    lib2sp_disable_verify(sp_ctx);   /* <-- entire PKCS#7 path goes away */
}
```

The flag is mutated by **`pkg_verify_cert_1_svc @ pkgd:0x00429330`**:

* `pkg_verify_cert_1(enable=1, cert_type=1)` -> sets bit `0x200000`
* `pkg_verify_cert_1(enable=1, cert_type=2)` -> sets bit `0x400000`
* `pkg_verify_cert_1(enable=0, cert_type=2)` -> clears bit `0x400000`

The user-facing entry point is `pkgc --noverifycert` (string at
`pkgc:0x00404bcc`), which AXDR-encodes the call and dispatches it to pkgd
via the `axdr_pkg_server` SunRPC program.

`lib2sp_disable_verify` zeroes the verifier-context pointer at
`sp_ctx + 0x4a4` and the enable byte at `sp_ctx + 0x4a8`. Once that
happens, **`lib2sp_install_data` walks the entire stream — FILE TLVs,
SCRIPT TLVs, the lot — and `lib2sp_install_2sp_data` never consults the
PKCS#7 SignedData**. SCRIPT TLVs whose digests would have been checked by
the PKCS#7 wrapper are still extracted to disk, then dispatched by
`finish.sh` / `deferred_upg.sh` after install — so this kill switch is
also a SCRIPT-TLV exec primitive once the operator has pkgc access.

**The carrier doesn't need to be signed at all.** The probe does not
attempt to drive pkgd directly (live-fire); instead it asserts statically
that the relevant symbols are still present in the shipped binaries. If
they vanish in a future firmware, the probe trips and this section gets a
positive update.

### 5.10 Attacker-supplied source URL (`pkgc -h <url>`)

`pkgc -h/--http <url>` calls into `pkg_stream_handler(... url ...)`, which
invokes `pkg_util_http_init(&http_ctx, url)` then `pkg_update_httpc_create`,
then streams bytes directly into the lib2sp pipeline. The URL is
attacker-controllable end to end, with two interesting edge cases:

* The HTTPS code path uses `httpc_set_cert_verify_callback` and
  `pkg_util_verify_peer_cert` — but the same `--noverifycert` toggle that
  flips the PKCS#7 gate also tells the HTTP layer to accept any TLS leaf.
  An attacker who has shell + can flip the toggle no longer needs the
  signing key; they just need a HTTPS server they control and no
  CA-validated chain.
* `pkg_stream_handler` validates the URL via `nu_uri_index` for "is this
  scheme HTTP/HTTPS or local file?" — it explicitly accepts `local_25c == 5`
  (local-file scheme), which means a `pkgc -h file:///path/to/attacker-controlled`
  invocation would let pkgd self-install from any path the pkgd uid can read.
  Combined with §5.11, this is a write-anywhere primitive with no key.

The CLI string is at `pkgc:0x00403e6c` ("`-h/--http <url>  - start unresolved
url stream operation`"). RPC: `pkg_update_1` /
`pkg_get_pkgset_url_1_svc`.

### 5.11 `/tmp/pkgspool` is created world-writable (mode 0666)

**Probe:** **test_pkgd_verify_kill_switch.py::test_pkgd_spool_path_is_world_writable_mode** *(historical probe; `opentl/tests/` removed)*

`pkg_spool_init @ pkgd:0x0041fd70` creates the staging file with:

```c
unlink("/tmp/pkgspool");
fd = open64("/tmp/pkgspool", 0x502 /* O_RDWR|O_CREAT|O_TRUNC */, 0x1b6 /* 0666 */);
```

The mode bits are **`rw-rw-rw-`**. `/tmp` itself is the conventional sticky
1777 (we have no contrary evidence). So during the entire window between
"pkgd opens the spool, starts writing, lib2sp scans for verify" and "pkgd
unlinks the spool on completion", any process on the device can `open(2)`
the spool RW-and-shared-with-pkgd, then `pwrite`/truncate/swap bytes.

This is the concrete materialisation of §5.8: the TOCTOU is real, the
window is the entire install run, and the shared writable handle does
not require the attacker to win an unlink/replace race — they just
`O_RDWR` the file pkgd is actively streaming through.

The probe is static-only: it asserts pkgd still references
`/tmp/pkgspool`. The mode constant `0x1b6` is documented above and visible
in the Ghidra decompilation of `pkg_spool_init`; we don't byte-pattern it
because MIPS PIC code makes the constant location version-dependent.

### 5.12 BZ2 outer decompression runs before verify gating

**Probe:** **test_pkgd_pre_verify_decompression.py** *(historical probe; `opentl/tests/` removed)* (complements **test_decompression_bomb.py** *(historical probe; `opentl/tests/` removed)*, which exercises the offline helper)

RE'ing `lib2sp_install_data @ lib2sp.so:0x00020ae0` confirms that the BZ2
state machine is **upstream of** `lib2sp_install_2sp_data` (which is where
the per-TLV-digest gating lives):

```c
if (state == 1 /* WAIT_MAGIC */) {
    memcpy(buf + ctx[0x109], in, n);
    if (memcmp(buf, "2WIRE_SP", 8) == 0) state = 3;          /* raw SP */
    else if (memcmp(buf, "BZh", 3) == 0) {
        state = 2;                                            /* bzip2 */
        BZ2_bzDecompressInit(...);
    }
}
if (state == 2) {
    BZ2_bzDecompress(strm);                                   /* unauth */
    lib2sp_install_2sp_data(ctx, decoded, decoded_len, ...);  /* verify here */
}
```

The decoded buffer is a 0xFFD0-byte heap allocation. There is no `unzipMax`
or output-byte-count cap — the BZ2 driver runs to completion (or OOM /
crash) on whatever bytes the carrier delivers. **No PKCS#7 check, no TLV
digest check, no length sanity** has happened by the time
`BZ2_bzDecompress` is called.

This is the device-side root cause of the §5.3 decompression-bomb impact;
it also means a maliciously-crafted bzip2 stream that *crashes* `libbz2`
becomes a pre-auth pkgd crasher, even before §5.9's kill switch is
considered.

There is one mitigating observation: `pkg_stream_handler` calls
`lib2sp_disallow_compression(sp_ctx)` for the streaming-update path,
which sets a flag at `sp_ctx + 0x60c` that `lib2sp_install_data` checks
before entering state 2. **However** that flag is _not_ set by
`lib2sp_simple_unpack` (the path used for already-staged carriers in
`pkgman_extract_pkg @ pkgd:0x0041c7fc`). So `pkgc -P /attacker/path -i N
--archive` plus a bzip2-prefixed carrier still hits the unguarded BZ2
path. We treat the `disallow_compression` mitigation as partial.

### 5.13 Attacker-controllable pkgc destination paths

The `pkgc` argument surface lets the operator hand pkgd absolute paths in
several places:

| `pkgc` flag | RPC | Effect | Risk if combined with §5.9 |
|---|---|---|---|
| `-P/--path <path>` | `pkg_update_1` | Sets the on-disk install path for a new pkg | Attacker chooses where the unsigned package lands |
| `-b/--upobj <path>` | `pkg_update_1` | Path for the build update operation (pkgd reads this from disk) | Attacker chooses what bytes pkgd ingests |
| `-h/--http <url>` | `pkg_stream_handler` (via `pkg_get_pkgset_url_1_svc`) | Streaming source URL | Attacker chooses source bytes |
| `-U/--url <url>` | `pkg_update_1` | Per-pkg source URL | Attacker chooses per-pkg source bytes |
| `--deferred <name>` | `pkg_deferred_1_svc` | Stores `name` at `pkgd_ctx + 0x1f0` (128 bytes), called "update part2" | Influences which deferred pkg gets activated next |
| `--tracefile <path>` | `pkg_trace_1_svc` | Logging file | Pre-existing root primitive; not a new gap, but a useful hint that the daemon honours absolute paths from the RPC client |

The most direct attack chain is:

1. Attacker reaches `pkgc` (root shell, or RPC over a misconfigured
   transport — see §8 for the open-question on bind interface).
2. `pkgc --noverifycert 2` (clears bit `0x400000`).
3. `pkgc -h file:///some/attacker/staged.pkgstream` (or remote URL).
4. pkgd installs the carrier without PKCS#7 verification, with FILE TLVs
   landing wherever the carrier declares (see §5.5 and §5.6).

There is no "are we still in dev mode?" guard around `pkg_verify_cert_1`;
the bit-flip is unconditional. A defender's only tool today is locking
down who can talk to the pkgd RPC.

### 5.14 Install actions vs integrity and path safety

The repo labels on-device **install-phase** behaviour with one-word
**`install_action`** tokens and longer **`install_comment`** strings in
[`lib2spy/pkgstream_runtime/lib2sp_dispatch.py`](../lib2spy/pkgstream_runtime/lib2sp_dispatch.py)
(stubs only — no emulation). Semantic overview: [`pkgstream.md`](pkgstream.md) §10 and
[`opentl/pkgstream_format_lib2sp.md`](../opentl/pkgstream_format_lib2sp.md). This
subsection maps those tokens onto **integrity ordering** (PKCS#7, per-TLV
digests, pre-auth work) and **path / symlink abuse** already proved or argued
elsewhere in §5 — no new RE claims.

| `install_action` | When it runs vs integrity checks | Traversal / symlink / path escape | Cross-ref |
|------------------|----------------------------------|-----------------------------------|-----------|
| **copy** | **Happy path:** streaming FILE (or re-entrant chunk write) runs inside `lib2sp_install_2sp_data` **after** outer BZ2 decode and is tied to the per-TLV digest / internal-check model described in §5.12 (decode first, verify in `lib2sp_install_2sp_data`). **Bypass:** with `--noverifycert` (§5.9), PKCS#7 is skipped while FILE/SCRIPT bodies still stream — treat as **no CMS binding**. **TOCTOU:** if the carrier bytes change between verify and re-open (§5.8), digest verdict and bytes written can diverge. | **High:** arbitrary **absolute** FILE paths; no device allowlist (§5.5). **`fopen64` / `open64` without `O_NOFOLLOW`** — symlink + FILE overwrite pattern (§5.6). Offline `extract_payloads` rejects absolute paths, `..`, NUL (§5.5). | §5.5, §5.6, §5.8, §5.9, §5.12 |
| **stage** | Same pipeline class as **copy** for SCRIPT TLVs: staged in a growable buffer, finalized on close, then indirect runner. **§5.9:** with verify disabled, scripts still extract and later run via product scripts (`finish.sh` / `deferred_upg.sh`). | Script **target path** choice is product-side; carrier still controls **content** digested when verify is on. Symlink follow on **FILE** opens is the dominant traversal story for collateral writes (§5.6). | §5.6, §5.9 |
| **dispatch** | Install-phase **`demarshall_2sp_path`** (`0x07`, `0x27`, `0x28`) and the **`0x04`** indirect `< 0x30` path: parse TLV body, then **vtable** into **mkdir** / **link** / **clone** / re-entrant **copy**. Inherits the same **global** ordering as other `lib2sp_install_2sp_data` work (§5.12); **§5.9** applies if CMS verify is off. | **Inherited:** whatever path strings those records embed are subject to the **same lack of sanitization** as FILE destinations until RE shows otherwise (§5.5–5.6). Prefix-only `0x07` wire layout remains open (**A3** in [`pkgstream.md`](pkgstream.md)). | §5.5, §5.6, §5.9, §5.12; `pkgstream.md` A3 |
| **move** | **`demarshall_2sp_move`** ladder (`0x08`, `0x29`–`0x2B`): rename/move-class updates on the rootfs after parse; same process-wide integrity caveats as **dispatch**. | **High** if source/dest path strings are TLV-controlled without normalization: absolute paths and symlink follow apply to **both** endpoints (same family as §5.5–5.6). | §5.5, §5.6, §5.9 |
| **mkdir** | Jump-table helper after successful demarshall — not a separate TLV type in the stub map; runs in install phase with the same **verify / kill-switch / TOCTOU** context as sibling actions. | Creates directories under attacker-influenced parents if path records allow (same path-trust class as §5.5). | §5.5, §5.6 |
| **link** | Jump-table **`lib2sp_do_sym_link`** — explicit symlink creation on the rootfs. | **Direct symlink primitive**; combines with **copy** / open paths that lack **`O_NOFOLLOW`** (§5.6). | §5.6 |
| **clone** | Jump-table **`lib2sp_do_copy_file`** — file-to-file copy **on the rootfs**, not streaming from the `.pkgstream` blob. | **Both** operands can be absolute; either side can participate in symlink-follow if opens are not hardened (§5.5–5.6). | §5.5, §5.6 |

**Pre-auth work (no install “action” token yet):** header walk, TLV length parsing, and
**outer BZ2** expansion are **upstream** of `lib2sp_install_2sp_data` (§5.1, §5.12) — CPU /
memory DoS and crashers, not the same class as **`copy`**/**`stage`**, but they run
**before** per-TLV digest checks in the documented ordering.

**`unlink` (narrow delete-class):** partial file cleanup in **`lib2sp_write_file`**
error paths — security relevance is mostly **availability / hygiene**, not traversal;
see [`pkgstream.md`](pkgstream.md) §10 for the operator token table.

## 6. Mitigation recommendations

These are device-side fixes (require `lib2sp.so` / `pkgd` rebuild) — the
offline tooling can flag the gaps but not patch them.

| # | Fix | Where | Difficulty |
|---|---|---|---|
| 1 | Path allowlist for FILE TLV destinations: must be under the package's declared base path (`pkg_util_pkg_get_base()` return) — reject absolute paths and `..` segments | `lib2sp_simple_unpack` | Low (string compare) |
| 2 | `O_NOFOLLOW` on every `lib2sp_open_file` / `lib2sp_write_file` open; reject if any path component is a symlink | `lib2sp.so` | Low |
| 3 | Cap on `bz2.decompress` output size — reject carriers whose decompressed body exceeds e.g. 4× the compressed size or 64 MiB hard limit | `lib2sp_install_data` | Low (BZ2_bzDecompress incremental) |
| 4 | Mandate SHA-256 in PKCS#7: reject SHA-1 / MD5 messageDigest in production builds; rotate signing chain to SHA-256 | `lib2sp_check_data` + new prod cert chain | High (key rotation) |
| 5 | Make `trust_engcert` a build-time-only flag in production firmware: hard-fail at `tw_ulib_is_trustengcert_enabled` if firmware was built with `PROD_HARDEN=1` | `librgw_compat.so` | Low |
| 6 | Single-fd verify+extract: open the carrier once, mmap it, run PKCS#7 verify and FILE/SCRIPT extraction from the same memory mapping | `pkg_extract.c` / `pkgd` | Medium |
| 7 | Move the on-disk PEM mirrors into a read-only mount (separate squashfs slice) so §5.5's secondary effect is neutralised | filesystem / init | Medium |
| 8 | Drop the 1024-bit RSA test cert and the MD5+RSA leaves; raise minimum key size to 2048 (currently mixed: 1024 / 2048 / 4096 / 8192) | `lib2sp_check_data` constraint | Low |
| 9 | Pin `trust_2sp_cn` to a non-empty production value at first boot in `serviceinit` so an empty/wildcard CN pin can never be exploited | `etc/sv/cmd/run` post-create | Low |
| 10 | Add a CRL or OCSP step before counting a signer as valid — closes leaked-key recovery latency | `lib2sp_check_data` | Medium (requires PKI infra) |
| 11 | **Remove the `pkg_verify_cert_1` RPC entirely from production builds**, or hard-fail when the runtime detects a production-signed firmware. This single change closes §5.9 and most of §5.13's attack chain | `pkgd:pkg_verify_cert_1_svc` + `libpkg_server.so` | Low (delete branch) |
| 12 | Open `/tmp/pkgspool` with mode `0600` and `O_EXCL`, owned by `pkgd:pkgd`, in a `pkgd`-private subdirectory (e.g. `/run/pkgd/spool`) that is `0700 pkgd:pkgd`. Closes the §5.11 shared-write race | `pkg_spool_init` | Low (single open() call) |
| 13 | Reject `pkg_get_pkgset_url_1` URLs whose scheme is `file:///` (or any non-HTTPS scheme); enforce TLS cert verification and CA pinning on the HTTPS path even when `--noverifycert` is set for the carrier-PKCS#7 path. Closes §5.10 | `pkg_stream_handler` URL parser | Low |
| 14 | Cap `BZ2_bzDecompress` output: stream-decompress with a per-call output budget (e.g. 16 KiB) and abort if the carrier delivers more than `4× compressed_input` total. Apply on **both** `lib2sp_install_data` and `lib2sp_simple_unpack` (the latter currently bypasses `disallow_compression`). Closes §5.12 | `lib2sp_install_data` | Low (incremental BZ2 already used) |
| 15 | Authenticate the pkgd RPC: require an authenticated SunRPC client credential (AUTH_UNIX uid/gid check at minimum, ideally AUTH_SHORT or a Unix-socket peer-credential check). Restricts who can speak `pkg_verify_cert_1` and `pkg_get_pkgset_url_1` to root processes that already own the box | `pkgd` RPC accept callback | Medium |

## 7. Using the offline verifier (`lib2spy.pkgstream --validate-chain`)

The verifier mirrors the device's runtime policy enough to catch most of the
above issues from CI:

```bash
# Default chain validation against the bundled (firmware-specific) device roots
python -m lib2spy firmware/.../install.pkgstream --validate-chain

# CI-strict gate: ALL_VERIFIED + at least one valid chain
python -m lib2spy <pkgstream> --validate-chain --strict --quiet

# Pin to the production signer CN we expect — fails on engineering-only carriers
python -m lib2spy <pkgstream> --validate-chain \
    --expected-cn prod1.2sp.certs.2wire.com --strict

# Simulate the kill switch being flipped on (and supply the engineering root):
python -m lib2spy <pkgstream> --validate-chain \
    --eng-root extracted_eng_root.pem --trust-engcert

# Use a fresh (non-bundled) trust store — no ProvenanceWarning
python -m lib2spy <pkgstream> --validate-chain \
    --trust-roots /path/to/firmware-XYZ/etc/pki/cacerts \
    --trust-roots /path/to/firmware-XYZ/etc/pki/roots
```

Per-signer verdicts are surfaced as one of `valid` / `untrusted` / `expired`
/ `skipped_eng` / `cn_mismatch` / `error` / `not_evaluated`. The summary
adds `chain_validation.any_valid` (the ANY-of-N pass condition) and
`all_verified_with_chain` (the strict combined gate).

## 8. Open questions / out-of-scope items

* **CMDB OID keys for `trust_engcert` / `trust_2sp_cn`.** The .rodata
  literals are reachable only via MIPS PIC GOT indirection and were not
  resolved by static analysis. A live `cmc -d dump` listing or a dynamic
  trace on a booted device would resolve in seconds. Knowing the OIDs lets a
  defender lock them via CMDB ACL.
* **`X509_V_FLAG_*` configuration in `lib2sp_verify_signature`.** Whether
  `X509_V_FLAG_NO_CHECK_TIME` (or its Pace equivalent) is set drives §5.2.
  Needs decompilation of `0x0001c294`.
* **SCRIPT TLV exec environment.** What pid runs the SCRIPTs, what cwd, what
  env? Currently believed to be `pkgd` itself (root) at the unpack base
  directory; full RE pass on `lib2sp_close_script @ 0x00017fc4` would
  confirm.
* **Anti-rollback / version pinning by `pkgd`.** Documented as out-of-scope
  in `pkgstream.md` §9.6. Worth a follow-up.
* **~~`/tmp/pkgspool` ownership and mode.~~ Resolved (§5.11).** The file is
  created `0666` by `pkg_spool_init`. Ownership defaults to whatever uid pkgd
  runs under (likely root, given pkgd is started by `runsv` from `/etc/sv/pkgd/run`
  with no `chpst -u` wrapper); a non-root verification of the live process
  uid would be a 30-second `ps` away on a booted device.
* **`pkgd` RPC bind interface.** `pkgd` registers handlers via
  `ar_svc_tli_create` + `ar_svc_reg`, but the transport identifier (Unix
  socket, TCP loopback, or LAN-reachable TCP) was not resolved by static
  analysis. If the bind is `tcp` on a wildcard address, every weakness in
  §5.9 / §5.10 / §5.13 becomes remotely-reachable; if it's a Unix socket
  with `0600` perms, the chain only matters once the attacker already has
  shell. **This is the single highest-leverage open question.**
* **`lib2sp_simple_unpack` BZ2 path.** §5.12 notes that
  `lib2sp_disallow_compression` partially mitigates the streaming path but
  is not set by `pkgman_extract_pkg`. A decompile of `lib2sp_simple_unpack`
  to confirm which carrier-supplied bytes reach `BZ2_bzDecompress` would
  let us narrow the §5.12 finding to one path or both.
* **Live-device confirmation.** Every probe in the historical
  `opentl/tests/probes/` suite *(removed)* was offline-only. A
  controlled lab-device test (writing a forged carrier signed by a leaked
  engineering key, measuring whether `pkgd` accepts it with
  `trust_engcert=False` vs `True`, or `pkgc --noverifycert 2 -h
  file:///tmp/forged.pkgstream` followed by a `lib2sp_check_data` log
  inspection) would convert these probes from "documented gap" to
  "exploited end to end."

## See also

- [`output/trust_chain_re_notes.md`](output/trust_chain_re_notes.md) — Phase 1 RE story
- [`opentl/data/trust_roots/PROVENANCE.md`](opentl/data/trust_roots/PROVENANCE.md) — bundled-PEM provenance
- [`pkgstream.md`](pkgstream.md) §9 — pkgstream format and integrity model
- [`cm_cmdb.md`](cm_cmdb.md) — CMDB control-plane stack
- [`cmdb_security.md`](cmdb_security.md) — flash dump exposes CMDB secrets; **`keys`/`root_rsa`** feeds TLS/cert paths (bypasses need for live `cmc -i` on some attacks)
- [`output/nand_rwdata_cm.md`](output/nand_rwdata_cm.md) — `/rwdata/cm/` on-flash story
- [`security.md`](security.md) — broader device threat framing
- [`tools.md`](tools.md) — operator guide for the offline verifier CLI
- Historical pytest probes under `opentl/tests/probes/` *(removed)* — each weakness in §5 **had** a reproducer there; re-add under `lib2spy/tests/` or `tests/` when rebuilt.
