"""
Decode / extract **UBI** images and **UBIFS** filesystems using the third-party
`ubi_reader <https://github.com/jrspruitt/ubi_reader>`_ library (``pip install ubi_reader``).

This is a **thin, repo-local wrapper** around Jason Pruitt's ubireader implementation
(GPL-3.0) — it wires the same pipeline as ``ubireader_extract_files`` while avoiding
``sys.exit`` on recoverable failures and returning structured results.

Supported inputs:

* **UBI** — ``UBI#`` EC header at ``start_offset`` (multi-volume → one directory tree
  per volume under ``output_dir``).
* **Raw UBIFS** — UBIFS node magic ``31 18 10 06`` at ``start_offset`` (single FS).

Example::

    from pathlib import Path
    from boardfs.ubifs_decode import extract_ubifs_image

    r = extract_ubifs_image(
        Path(\"carved_ubi.bin\"),
        Path(\"out/extracted\"),
        start_offset=0,
    )
    print(r.success, r.volume_outputs)
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional


class UbifsDecodeError(RuntimeError):
    """Raised when ubireader reports a fatal condition (patched to avoid ``sys.exit``)."""


def _ensure_ubireader() -> None:
    try:
        import ubireader  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "UBIFS decoding requires the optional dependency: pip install ubi_reader"
        ) from e


@contextlib.contextmanager
def _patch_ubireader_fatal() -> Iterator[None]:
    """Turn ubireader ``error(..., 'Fatal', ...)`` into :exc:`UbifsDecodeError`."""
    import ubireader.debug as dbg

    _prev = dbg.error

    def _safe(obj: Any, level: str, message: str) -> None:
        if str(level).lower() == "fatal":
            raise UbifsDecodeError(f"{getattr(obj, '__name__', obj)}: {message}")
        return _prev(obj, level, message)

    dbg.error = _safe  # type: ignore[assignment]
    try:
        yield
    finally:
        dbg.error = _prev


def probe_ubifs_header(path: str | Path, *, start_offset: int = 0) -> dict[str, Any]:
    """
    Read four bytes at ``start_offset`` and classify **without** importing heavy parsers.

    If ``ubi_reader`` is installed, magic constants match ubireader's defines; otherwise
    falls back to the same UBI media literals as :mod:`boardfs.ubi_carve`.
    """
    path = Path(path)
    with path.open("rb") as f:
        f.seek(start_offset)
        buf = f.read(4)
    try:
        from ubireader.ubi.defines import UBI_EC_HDR_MAGIC
        from ubireader.ubifs.defines import UBIFS_NODE_MAGIC
    except ImportError:
        UBI_EC_HDR_MAGIC = b"\x55\x42\x49\x23"
        UBIFS_NODE_MAGIC = b"\x31\x18\x10\x06"

    kind = "unknown"
    if buf == UBI_EC_HDR_MAGIC:
        kind = "UBI"
    elif buf == UBIFS_NODE_MAGIC:
        kind = "UBIFS"
    return {
        "path": str(path.resolve()),
        "start_offset": start_offset,
        "magic_hex": buf.hex(),
        "kind": kind,
    }


@dataclass
class UbifsExtractResult:
    success: bool
    kind: str  # "UBI" | "UBIFS" | "unknown"
    output_dirs: list[str] = field(default_factory=list)
    error: Optional[str] = None


def _mkdir_empty(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)
    if any(p.iterdir()):
        raise FileExistsError(f"output directory must be empty: {p}")


def extract_ubifs_image(
    image_path: str | Path,
    output_dir: str | Path,
    *,
    start_offset: Optional[int] = None,
    end_offset: Optional[int] = None,
    guess_offset: int = 0,
    peb_size: Optional[int] = None,
    leb_size: Optional[int] = None,
    warn_only_block_read_errors: bool = False,
    ignore_block_header_errors: bool = False,
    uboot_fix: bool = False,
    master_key_path: Optional[str | Path] = None,
    keep_permissions: bool = False,
    verbose_ubireader: bool = False,
) -> UbifsExtractResult:
    """
    Extract filesystem tree(s) from a **UBI** or **UBIFS** image file.

    ``start_offset``: offset of UBI/UBIFS payload (default: scan with ubireader's
    ``guess_start_offset`` from ``guess_offset``).

    Mirrors ``ubireader_extract_files`` logic; writes under ``output_dir``.
    """
    _ensure_ubireader()

    import ubireader.settings as ur_settings
    from ubireader import settings as st
    from ubireader.ubi import ubi as ubi_cls
    from ubireader.ubi.defines import UBI_EC_HDR_MAGIC
    from ubireader.ubi_io import leb_virtual_file, ubi_file
    from ubireader.ubifs import ubifs as ubifs_cls
    from ubireader.ubifs.defines import UBIFS_NODE_MAGIC
    from ubireader.ubifs.output import extract_files
    from ubireader.utils import guess_leb_size, guess_peb_size, guess_start_offset

    image_path = Path(image_path)
    output_dir = Path(output_dir)
    out_dirs: list[str] = []

    if not image_path.is_file():
        return UbifsExtractResult(False, "unknown", [], f"not found: {image_path}")

    # Quiet ubireader unless requested
    st.logging_on = verbose_ubireader
    st.logging_on_verbose = verbose_ubireader
    st.warn_only_block_read_errors = warn_only_block_read_errors
    st.ignore_block_header_errors = ignore_block_header_errors
    st.uboot_fix = uboot_fix

    master_key: Optional[bytes] = None
    if master_key_path is not None:
        mk = Path(master_key_path).read_bytes()
        if len(mk) != 64:
            return UbifsExtractResult(False, "unknown", [], "master key must be 64 bytes")
        master_key = mk

    try:
        with _patch_ubireader_fatal():
            if start_offset is None:
                off = guess_start_offset(str(image_path), guess_offset)
                if off is None:
                    return UbifsExtractResult(False, "unknown", [], "guess_start_offset failed")
                start_offset = int(off)
            else:
                start_offset = int(start_offset)

            with image_path.open("rb") as fh:
                fh.seek(start_offset)
                hdr = fh.read(4)

            if hdr == UBI_EC_HDR_MAGIC:
                filetype = UBI_EC_HDR_MAGIC
                kind_guess = "UBI"
            elif hdr == UBIFS_NODE_MAGIC:
                filetype = UBIFS_NODE_MAGIC
                kind_guess = "UBIFS"
            else:
                return UbifsExtractResult(
                    False,
                    "unknown",
                    [],
                    f"no UBI/UBIFS magic at offset {start_offset:#x} (got {hdr.hex()})",
                )

            block_size: Optional[int] = peb_size or leb_size
            if block_size is None:
                if filetype == UBI_EC_HDR_MAGIC:
                    block_size = guess_peb_size(str(image_path))
                else:
                    block_size = guess_leb_size(str(image_path))
            if not block_size:
                return UbifsExtractResult(False, kind_guess, [], "could not determine block size")

            ufile_obj = ubi_file(str(image_path), block_size, start_offset, end_offset)
            try:
                if filetype == UBI_EC_HDR_MAGIC:
                    ubi_obj = ubi_cls(ufile_obj)
                    output_dir.mkdir(parents=True, exist_ok=True)
                    for image in ubi_obj.images:
                        img_out = output_dir / str(image.image_seq)
                        img_out.mkdir(parents=True, exist_ok=True)
                        for volume_name in image.volumes:
                            vol_blocks = image.volumes[volume_name].get_blocks(ubi_obj.blocks)
                            if not len(vol_blocks):
                                continue
                            vol_out = img_out / str(volume_name)
                            _mkdir_empty(vol_out)
                            lebv_file = leb_virtual_file(ubi_obj, vol_blocks)
                            ubifs_o = ubifs_cls(lebv_file, master_key=master_key)
                            extract_files(ubifs_o, str(vol_out), keep_permissions)
                            out_dirs.append(str(vol_out.resolve()))
                    return UbifsExtractResult(True, "UBI", out_dirs)

                _mkdir_empty(output_dir)
                ubifs_o = ubifs_cls(ufile_obj, master_key=master_key)
                extract_files(ubifs_o, str(output_dir), keep_permissions)
                out_dirs.append(str(output_dir.resolve()))
                return UbifsExtractResult(True, "UBIFS", out_dirs)
            finally:
                ufile_obj.close()
    except UbifsDecodeError as e:
        return UbifsExtractResult(False, "unknown", [], str(e))
    except Exception as e:
        return UbifsExtractResult(False, "unknown", [], str(e))


def main(argv: Optional[list[str]] = None) -> None:
    _ensure_ubireader()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=False)
    ap.add_argument("--start-offset", type=int, default=None)
    ap.add_argument("--end-offset", type=int, default=None)
    ap.add_argument("--guess-offset", type=int, default=0)
    ap.add_argument("--peb-size", type=int, default=None)
    ap.add_argument("--leb-size", type=int, default=None)
    ap.add_argument("--probe-only", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.probe_only:
        p = probe_ubifs_header(args.image, start_offset=args.start_offset or 0)
        print(json.dumps(p, indent=2))
        return

    if args.output_dir is None:
        ap.error("--output-dir is required unless --probe-only")

    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        ap.error(f"output directory must be empty: {args.output_dir}")

    r = extract_ubifs_image(
        args.image,
        args.output_dir,
        start_offset=args.start_offset,
        end_offset=args.end_offset,
        guess_offset=args.guess_offset,
        peb_size=args.peb_size,
        leb_size=args.leb_size,
        verbose_ubireader=args.verbose,
    )
    print(json.dumps({"success": r.success, "kind": r.kind, "output_dirs": r.output_dirs, "error": r.error}, indent=2))
    if not r.success:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
