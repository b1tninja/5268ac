"""
Carrier ``.pkgstream`` → carved blobs (thin wrapper around :mod:`lib2spy.pkgstream_corpus`).

**Offline carving vs on-device install.** This path extracts **SquashFS / uImage / …**
slices by **magic and superblock scan** over the decompressed carrier body (same idea as
Binwalk ``file_map`` hits). It does **not** replay ``lib2sp``'s install state machine:
on the box, **FILE** / **SCRIPT** bytes are streamed via ``lib2sp_do_payload_tlv`` and
other opcodes go through ``lib2sp_payload_data`` (``demarshall_2sp_path``,
``demarshall_2sp_move``, jump-table helpers). **SquashFS** in the file is **payload
bytes**; **mounting** a rootfs is a **separate** boot / script step, not something the
magic-scan path does. See ``opentl/pkgstream_format_lib2sp.md``, ``reference/pkgstream.md``
§10, and :mod:`lib2spy.pkgstream_runtime` for how TLVs are used at runtime (stub map).

For the **same** :class:`~binwalker.carved.Artifact` model and a single entry point, prefer
:func:`binwalker.unified_carve.carve` (CLI: ``python -m binwalker carve-unified …``) or iterate
:class:`~binwalker.carved.Pkgstream` and call :meth:`~binwalker.carved.Artifact.save` per hit.

Use :func:`pkgstream` for a session handle, then :meth:`PkgstreamCarves.carve_artifacts`.

The parser / verifier module remains :mod:`lib2spy.pkgstream`; this module only handles **carving**.

Example::

    from lib2spy.pkgstream_carves import pkgstream

    summary = pkgstream(\"install.pkgstream\").carve_artifacts(\"output/carves\")
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from lib2spy.pkgstream_corpus import DEFAULT_EXTRACT_NAMES, extract_pkgstream_slices


@dataclass
class PkgstreamCarves:
    """Carved-blob workflow for one ``.pkgstream`` path."""

    path: Path

    def carve_artifacts(
        self,
        out_dir: str | Path,
        *,
        names: Optional[Sequence[str]] = None,
        write_manifest: bool = True,
        unsquash_dissect_out: str | Path | None = None,
        strict_uimage_decompress: bool = False,
    ) -> Dict[str, Any]:
        """
        Extract SquashFS / uImage / … slices into ``out_dir`` via :mod:`lib2spy.native_pkgstream`.

        Returns the same summary dict as :func:`~lib2spy.pkgstream_corpus.extract_pkgstream_slices`.
        """
        out = Path(out_dir).resolve()
        src = self.path
        want: Optional[list[str]] = list(names) if names is not None else None

        return extract_pkgstream_slices(
            str(src),
            str(out),
            names=want,
            write_manifest=write_manifest,
            unsquash_dissect_out=(
                str(unsquash_dissect_out) if unsquash_dissect_out else None
            ),
            strict_uimage_decompress=strict_uimage_decompress,
        )


def pkgstream(pkgstream_path: str | Path) -> PkgstreamCarves:
    """Open a carve session for a carrier ``.pkgstream`` file."""
    return PkgstreamCarves(path=Path(pkgstream_path).resolve())


__all__ = ["PkgstreamCarves", "pkgstream", "DEFAULT_EXTRACT_NAMES"]
