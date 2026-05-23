"""
Logical NAND plane → BBM (:meth:`~opentl.open_tl.OpenTL.from_logical_with_flat_spare`) → ``opentla4`` extract.

* **Interactive / library:** :class:`NandPipeline`, :func:`nand`, then :meth:`~NandPipeline.extract_opentla4`.
* **After Binwalk flash carve:** :meth:`NandPipeline.post_carve_bbm` (manifest fragment + exit code);
  :meth:`NandPipeline.post_carve_bbm_enabled` is the planning gate only.

Examples::

    from pathlib import Path
    from opentl.nand_pipeline import NandPipeline, nand

    nand(\"flash.bin\").translate(mode=\"inline-2112\").extract_opentla4(out_ext2=Path(\"e.ext2\"))

    NandPipeline.for_logical_plane(\"tlpart.bin\", spare=\"flat_spare.bin\").extract_opentla4(dry_run=True)

For carved **uImage** reference comparison on the assembled ext2, pass ``verify=`` into
:meth:`~opentl.nand_pipeline.NandPipeline.extract_opentla4` (or :func:`extract_opentla4`) with ``block_map=`` from the pipeline.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opentl.nand_translate import TranslateMode, nand_translate_to_file
from opentl.paths import OUTPUT_DIR
from opentl.open_tl import ExtractResult, OpenTL, extract_opentla4

def _bad_spare_file(path: Path) -> str | None:
    if not path.is_file():
        return f"spare not found: {path}"
    if path.stat().st_size <= 0:
        return f"spare empty: {path}"
    return None


def _with_nand_mode(d: dict[str, Any], nand_flash_carve_mode: str | None) -> dict[str, Any]:
    if nand_flash_carve_mode is None:
        return d
    return {**d, "nand_flash_carve_mode": nand_flash_carve_mode}


#region kernel_adjacent NandPipeline_post_carve_bbm (host orchestration → tl_mount + bbm_kernel_replay)
@dataclass
class NandPipeline:
    """Logical image + flat spare → :meth:`~opentl.open_tl.OpenTL.from_logical_with_flat_spare` BBM → ``opentla4``."""

    raw_path: Path
    work_dir: Path
    logical_path: Path | None = None
    spare_path: Path | None = None
    translate_manifest: dict[str, Any] | None = field(default=None)
    bbm: Any = field(default=None)  # BlockMapBuild from tl_bbm

    # --- post-carve (Binwalk manifest); class-level API ---

    @classmethod
    def post_carve_bbm_enabled(
        cls,
        spare: Path | str,
        *,
        skip: bool,
        force: bool,
        nand_translate_ran: bool,
    ) -> bool:
        """Whether :meth:`post_carve_bbm` does work (else it returns ``(0, None)`` immediately)."""
        if skip:
            return False
        if force or nand_translate_ran:
            return True
        return _bad_spare_file(Path(spare).expanduser().resolve()) is None

    @classmethod
    def post_carve_bbm(
        cls,
        logical: Path | str,
        spare: Path | str,
        *,
        skip: bool = False,
        force: bool = False,
        nand_translate_ran: bool = False,
        nand_flash_carve_mode: str | None = None,
    ) -> tuple[int, dict[str, Any] | None]:
        """
        Post-carve BBM via :meth:`~opentl.open_tl.OpenTL.from_logical_with_flat_spare` (kernel replay only).

        Returns ``(2, frag)`` when kernel BBM replay raises (e.g. missing spare, bad length, no mappable rows);
        ``(0, frag)`` on success; ``(0, None)`` when skipped.
        """
        li = Path(logical).expanduser().resolve()
        sp = Path(spare).expanduser().resolve()

        if not cls.post_carve_bbm_enabled(
            sp, skip=skip, force=force, nand_translate_ran=nand_translate_ran
        ):
            return 0, None

        bad = _bad_spare_file(sp)
        if bad is not None:
            return 0, _with_nand_mode({"tl_mount_bbm_skipped": bad}, nand_flash_carve_mode)

        pipe = cls(raw_path=li, work_dir=li.parent).use_logical_plane(li, spare=sp)
        try:
            pipe.build_bbm()
        except ValueError as e:
            frag = {"tl_mount_bbm_error": str(e), "tl_mount_bbm_skipped": "value_error"}
            return 2, _with_nand_mode(frag, nand_flash_carve_mode)

        assert pipe.bbm is not None
        nand_off = int(pipe.bbm.nand_logical_offset)
        frag = {
            "tl_mount_bbm_mode": pipe.bbm.mode,
            "tl_mount_logical_image": str(li),
            "tl_mount_spare_file": str(sp),
            "tl_mount_nand_logical_offset": nand_off,
        }
        frag = _with_nand_mode(frag, nand_flash_carve_mode)
        print(
            f"nand_pipeline: build_bbm ok mode={pipe.bbm.mode} (in-memory BBM)",
            file=sys.stderr,
        )
        return 0, frag

    # --- instance: translate / BBM / extract ---

    def _read_spare_blob(self) -> bytes | None:
        if self.spare_path is None or not self.spare_path.is_file():
            return None
        return self.spare_path.read_bytes()

    def translate(
        self,
        *,
        mode: TranslateMode = "inline-2112",
        logical_name: str = "logical_plane.bin",
        spare_name: str = "flat_spare.bin",
        logical_bytes: int | None = None,
    ) -> NandPipeline:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        logical_out = self.work_dir / logical_name
        spare_out = self.work_dir / spare_name
        man = nand_translate_to_file(
            Path(self.raw_path),
            logical_out,
            mode,
            logical_bytes=logical_bytes,
            spare_out=spare_out,
        )
        self.logical_path = logical_out
        self.spare_path = spare_out if man.get("spare_out") else None
        self.translate_manifest = man
        return self

    def use_logical_plane(
        self,
        logical: str | Path,
        *,
        spare: str | Path | None = None,
    ) -> NandPipeline:
        self.logical_path = Path(logical).resolve()
        self.spare_path = Path(spare).resolve() if spare else None
        self.translate_manifest = None
        return self

    @classmethod
    def for_logical_plane(
        cls,
        logical: str | Path,
        *,
        spare: str | Path | None = None,
        work_dir: str | Path | None = None,
    ) -> NandPipeline:
        lp = Path(logical).resolve()
        wd = (
            Path(work_dir).resolve()
            if work_dir is not None
            else OUTPUT_DIR / "nand_work" / lp.stem
        )
        return cls(raw_path=lp, work_dir=wd).use_logical_plane(lp, spare=spare)

    def build_bbm(
        self,
        *,
        logical_prefix_bytes: int | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Build :class:`~opentl.tl_bbm.BlockMapBuild` via :meth:`~opentl.open_tl.OpenTL.from_logical_with_flat_spare`.

        Requires non-empty **flat spare** bytes on :attr:`spare_path`. Raises
        :class:`ValueError` if spare is unusable or mount replay cannot build a map.
        """
        del kwargs
        if not self.logical_path or not self.logical_path.is_file():
            raise ValueError("Set logical plane via translate() or use_logical_plane() first")
        spare_blob = self._read_spare_blob()
        if spare_blob is None or len(spare_blob) == 0:
            raise ValueError(
                "NandPipeline.build_bbm requires non-empty flat spare bytes "
                "(set spare_path from nand_translate spare_out, or for_logical_plane(..., spare=...))."
            )

        nand_off = infer_tl_mount_nand_logical_offset(
            logical_image_size=self.logical_path.stat().st_size
        )
        ot = OpenTL.from_logical_with_flat_spare(
            self.logical_path,
            spare_bytes=spare_blob,
            nand_logical_offset=nand_off,
            logical_prefix_bytes=logical_prefix_bytes,
        )
        self.bbm = ot.block_map
        return self.bbm

    def extract_opentla4(
        self,
        *,
        out_ext2: str | Path | None = None,
        dry_run: bool = False,
        nand_logical_offset: int | None = None,
        auto_build_bbm: bool = True,
        build_bbm: dict[str, Any] | None = None,
    ) -> ExtractResult:
        if not self.logical_path:
            raise ValueError("no logical image: translate() or use_logical_plane() first")
        if self.bbm is None:
            if not auto_build_bbm:
                raise ValueError(
                    "no BBM: call build_bbm() with spare attached, or pass auto_build_bbm=False "
                    "and set pipeline.bbm from a BlockMapBuild"
                )
            self.build_bbm(**dict(build_bbm or {}))
        assert self.bbm is not None
        return extract_opentla4(
            str(self.logical_path),
            block_map=self.bbm,
            out_path=out_ext2,
            dry_run=dry_run,
            nand_logical_offset=nand_logical_offset,
        )


#endregion


def nand(raw_path: str | Path, *, work_dir: str | Path | None = None) -> NandPipeline:
    raw = Path(raw_path).resolve()
    wd = (
        Path(work_dir).resolve()
        if work_dir is not None
        else OUTPUT_DIR / "nand_work" / raw.stem
    )
    return NandPipeline(raw_path=raw, work_dir=wd)


__all__ = ["NandPipeline", "nand"]
