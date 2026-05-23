"""
Embedded **SquashFS** / **uImage** spans — offline scan vs runtime.

**Offline (this repo):** ``lib2spy.native_pkgstream.scan_embedded_images`` finds ``hsqs``
and ``0x27051956`` magic inside the carrier body for carve / analysis tools. That is
**not** the same as the installer's FILE TLV byte stream.

**Runtime:** ``lib2sp`` streams FILE payload bytes to configured paths; **SquashFS
mount** (loop / pivot) happens later via shell scripts / init, not inside
``lib2sp_do_payload_tlv`` alone. **uImage** CRC32 fields are checked by **U-Boot** at
flash time per ``fwupgrade.txt`` / ``pkgstream.md`` §9.

**Dry-run:** ``lib2spy.pkgstream_runtime.tlv_dry_run`` only lists prefix TLVs and hints;
it does **not** mount images or emulate the full install FSM.
"""

from __future__ import annotations


def describe_offline_vs_runtime() -> str:
    """One-paragraph summary for logs or RE notes."""
    return (
        "scan_embedded_images = magic/superblock discovery on disk bytes; "
        "mount/pivot_root = post-install OS policy; uImage CRC = U-Boot path."
    )
