# Bundled trust roots — PROVENANCE

> **WARNING — firmware-specific trust store.** These PEMs were extracted from one
> AT&T-branded 5268AC firmware image (see `firmware_tag` below) and **are valid only for
> pkgstreams signed for that firmware family**. If you point `--validate-chain` at a
> pkgstream from a different vendor, model, or major release, results are meaningless.
> See [`lib2spy/pkgstream_verify.py`](../../lib2spy/pkgstream_verify.py) — `ProvenanceWarning`
> fires once per process when these roots are auto-resolved.

## Source

- **Firmware tag**: `att-5268-11.5.1.532678_prod_lightspeed-install`
- **Carrier**: install pkgstream / sub-squashfs `0x0000ab0c_7af30619`
- **On-device path**: `/etc/pki/cacerts/` (production roots) and `/etc/pki/roots/` (sub-CAs)
- **Live consumer**: `pki_ver_setup_trust_roots @ libpki.so.0+0x0002aef4`
  (the runtime trust loader — see [`output/trust_chain_re_notes.md`](../../../output/trust_chain_re_notes.md) §2)

## Critical caveat

The **factory-trusted** roots are **also baked into `libpki.so.0.0.0`** as DER blobs in
`.rodata` (5 production + 1 engineering, sized `0x240`, `0x306`, `0x41e`, `0x476`,
`0x95c`, `0x3d4`). The on-disk PEMs at `/etc/pki/{cacerts,roots}/` shipped here mirror
those compiled-in roots **for the production set only**. The engineering root has no
PEM mirror on disk; it is loaded only when `tw_ulib_is_trustengcert_enabled` reads
`true` from CMDB at `/rwdata/cm/`. For offline chain validation, this bundle therefore
covers only the production trust path. Engineering-signed pkgstreams (e.g. `cert_0.pem`
from the install carrier we have, signed by `eng2.2sp.certs.2wire.com`) **will not chain
to anything in this bundle** unless `--trust-engcert` is supplied along with an
engineering root PEM via `--trust-roots`.

## Files

| Layout | Subject (RFC4514) | Role | Validity (UTC) | Public key |
|---|---|---|---|---|
| `cacerts/twire_corprootg1.pem`        | `OU=Certification Authority - G1, O=2Wire Inc, C=US`                      | 2Wire production root (G1)              | 2005-03-16 → 2031-03-10 | RSA 2048 |
| `cacerts/twire_emrroot.pem`           | `CN=2Wire Gateway Emergency Authority - G1, O=2Wire, Inc., C=US`          | 2Wire emergency root (long validity)    | 1990-01-01 → 2049-12-31 | RSA 8192 |
| `cacerts/verisign_pca3.pem`           | `OU=Class 3 Public Primary Certification Authority, O=VeriSign, C=US`     | Legacy VeriSign Class 3 PCA             | 1996-01-29 → 2028-08-01 | RSA 1024 |
| `cacerts/verisign_pca3_g2.pem`        | `OU=Class 3 Public Primary Certification Authority - G2, O=VeriSign`      | VeriSign Class 3 PCA — G2               | 1998-05-18 → 2028-08-01 | RSA 1024 |
| `cacerts/verisign_pca3_g3.pem`        | `CN=VeriSign Class 3 Public Primary Certification Authority - G3`         | VeriSign Class 3 PCA — G3               | 1999-10-01 → 2036-07-16 | RSA 2048 |
| `roots/ARRIS_SWRobustnessCVC_Root.pem`| `CN=ARRIS Software Robustness CVC Root CA, O=ARRIS Group, C=US`           | ARRIS code-signing root (CVC chain)     | 2014-03-13 → 2044-03-13 | RSA 4096 |
| `roots/ARRIS_SWRobustnessCVC_SubCA.pem`| `CN=ARRIS Software Robustness CVC Sub-CA, O=ARRIS Group, C=US`           | ARRIS code-signing intermediate         | 2014-03-13 → 2044-03-13 | RSA 2048 |

## SHA-256 fingerprints

```
cdfbba14533691a74f083dc7eacedff6ae99541388c6fc8adedbbe10725fbc71  cacerts/twire_corprootg1.pem
1f49416cf369521cc905175a1ed59162ca7a24395df3c689ad170d94938e4da3  cacerts/twire_emrroot.pem
29b3dd325570432ec118508d1c5f151fe4ca605f50e74d3faa2566a4ea655ca0  cacerts/verisign_pca3.pem
72f3d95229565d13b1a642f6e76dd69344dcf4ec3e698cac67ce3c3377e4a244  cacerts/verisign_pca3_g2.pem
287333c9014a9fa3111e439c4426b204bd8415c116b8ae47524506611bb568fb  cacerts/verisign_pca3_g3.pem
6293518284ff2c953efcf414d3fd30e848cb2c614aa6afdf5e5a24ba9b4e0a8c  roots/ARRIS_SWRobustnessCVC_Root.pem
31cccee85c2ad3dd1064597aeca0816c7f69dd6e27a8ac37846cba419a93f714  roots/ARRIS_SWRobustnessCVC_SubCA.pem
```

These match exactly what shipped on the device — replace this directory only with PEMs
freshly extracted from a real firmware tree.

## Refreshing this bundle

1. Mount or extract a target firmware's rootfs (e.g. via firmware carving tools, `unsquashfs`).
2. Copy `/etc/pki/cacerts/*.pem` into `cacerts/` and `/etc/pki/roots/*.pem` into `roots/`.
3. Update the table above and the SHA-256 list.
4. Bump `firmware_tag` if the new bundle is from a different release.
5. **Bump the `BUNDLE_VERSION` constant in [`lib2spy/pkgstream_verify.py`](../../lib2spy/pkgstream_verify.py)** so the runtime warning re-fires on first use.
6. Diff the previous bundle to confirm what rotated. If a 2Wire / ARRIS / VeriSign root
   rolled, that is a vendor key-rotation event — call it out explicitly in the commit
   message and consider whether older firmware will fail chain validation against the
   newer bundle.

## Cross-references

- [`output/trust_chain_re_notes.md`](../../../output/trust_chain_re_notes.md) — full Phase 1 RE story for `pki_ver_setup_trust_roots`.
- [`reference/pkgstream_security.md`](../../../reference/pkgstream_security.md) — operational security analysis built on this bundle.
- [`reference/pkgstream.md`](../../../reference/pkgstream.md) §9.10 — RE backlog and runtime trust mechanics summary.
