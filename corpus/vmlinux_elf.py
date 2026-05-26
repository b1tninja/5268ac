"""
Optional **marin-m/vmlinux-to-elf** bridge: raw Linux kernel bytes → analyzable ELF.

Used by corpus indexing. Requires editable install
or ``vmlinux-to-elf`` on ``PATH`` — see repo ``tools.md``.
"""

from __future__ import annotations

import concurrent.futures
import io
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple

# ``corpus/`` — repo root is one level up (``.../5268ac`` with ``.venv/``).
_PKG_DIR = Path(__file__).resolve().parent
_ADJACENT_VENV_PREPENDED = False


def _adjacent_repo_root() -> Path:
    """Repository root containing ``corpus`` (often ``.../5268ac``)."""
    return _PKG_DIR.parent


def _venv_site_packages(repo: Path) -> Optional[Path]:
    venv = repo / ".venv"
    if not venv.is_dir():
        return None
    candidates = [
        venv / "Lib" / "site-packages",
        venv / "lib" / "site-packages",
    ]
    lib = venv / "lib"
    if lib.is_dir():
        for child in lib.iterdir():
            if child.name.startswith("python"):
                sp = child / "site-packages"
                if sp.is_dir():
                    candidates.append(sp)
    for p in candidates:
        if p.is_dir():
            return p.resolve()
    return None


def _prepend_adjacent_venv_site_packages() -> None:
    """
    If ``vmlinux_to_elf`` is installed only in a sibling ``.venv`` (common in this repo),
    prepend that ``site-packages`` so **in-process** import works even when the user runs
    ``python -m …`` with a global interpreter matching the venv's base Python.
    """
    global _ADJACENT_VENV_PREPENDED
    if _ADJACENT_VENV_PREPENDED:
        return
    sp = _venv_site_packages(_adjacent_repo_root())
    if sp is None:
        return
    s = str(sp)
    if s not in sys.path:
        sys.path.insert(0, s)
    _ADJACENT_VENV_PREPENDED = True


def _adjacent_venv_vmlinux_exe() -> Optional[Path]:
    """``vmlinux-to-elf`` entrypoint next to ``.venv`` when not on ``PATH``."""
    venv = _adjacent_repo_root() / ".venv"
    if not venv.is_dir():
        return None
    if sys.platform == "win32":
        scripts = venv / "Scripts"
        for name in ("vmlinux-to-elf.exe", "vmlinux-to-elf.cmd"):
            p = scripts / name
            if p.is_file():
                return p.resolve()
    else:
        p = (venv / "bin" / "vmlinux-to-elf").resolve()
        if p.is_file():
            return p
    return None


def _resolve_vmlinux_cli() -> Optional[str]:
    adj = _adjacent_venv_vmlinux_exe()
    if adj is not None:
        return str(adj)
    which = shutil.which("vmlinux-to-elf")
    return which


def _try_vmlinux_to_elf_inprocess(
    kernel_bin: Path,
    out_elf: Optional[Path],
    *,
    timeout_s: int,
) -> Optional[Tuple[bool, str, Optional[bytes]]]:
    """
    Same pipeline as ``vmlinux_to_elf.scripts.vmlinux_to_elf:main`` (no duplicated
    kallsyms logic). Returns ``None`` if the package is not importable so callers
    can fall back to the CLI.

    With ``out_elf`` set, writes that path (third tuple element is ``None`` on
    success). With ``out_elf`` ``None``, serializes to :class:`io.BytesIO` via
    upstream ``ElfSymbolizer(..., output_file=None, output_stream=buf)`` and
    returns the bytes as the third element.
    """
    _prepend_adjacent_venv_site_packages()
    try:
        from vmlinux_to_elf.core.architecture_detecter import ArchitectureGuessError
        from vmlinux_to_elf.core.elf_symbolizer import ElfSymbolizer
        from vmlinux_to_elf.core.vmlinuz_decompressor import VmlinuzDecompressor
    except ImportError:
        return None

    kb = kernel_bin.resolve()

    def _run() -> Optional[bytes]:
        data = kb.read_bytes()
        decompressed = VmlinuzDecompressor(data).decompressed
        if out_elf is not None:
            ElfSymbolizer(
                decompressed,
                str(out_elf),
                None,
                None,
                None,
                None,
                16,
                None,
                None,
            )
            return None
        buf = io.BytesIO()
        ElfSymbolizer(
            decompressed,
            None,
            buf,
            None,
            None,
            None,
            16,
            None,
            None,
        )
        return buf.getvalue()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_run)
            raw_out = fut.result(timeout=timeout_s)
    except ArchitectureGuessError as e:
        return False, str(e) or "architecture could not be guessed", None
    except concurrent.futures.TimeoutError:
        return False, "vmlinux-to-elf timed out", None
    except Exception as e:
        return False, str(e)[:800], None

    if out_elf is not None:
        if not out_elf.is_file():
            return False, "vmlinux-to-elf produced no output file", None
        return True, "", None
    if not raw_out:
        return False, "vmlinux-to-elf produced empty output", None
    return True, "", raw_out


def try_vmlinux_to_elf(
    kernel_bin: Path,
    out_elf: Optional[Path] = None,
    *,
    timeout_s: int = 600,
) -> Tuple[bool, str, Optional[bytes]]:
    """
    Convert raw kernel bytes to a symbolized ELF using **marin-m/vmlinux-to-elf**.

    Pass ``out_elf`` to write an ELF file on disk; pass ``out_elf=None`` to keep
    the result **in memory only** (third return value is the ``bytes``, or
    ``None`` on failure / when a path was written).

    Prefers an **in-process** call (``ElfSymbolizer`` + ``VmlinuzDecompressor`` —
    same as the upstream CLI) when ``vmlinux_to_elf`` is importable; otherwise
    runs the ``vmlinux-to-elf`` executable if it is on ``PATH`` (memory mode uses
    a temporary file for the subprocess-only path). ``pip install`` the project —
    see ``tools.md``.
    """
    disk = out_elf is not None
    if disk:
        out_elf = out_elf.resolve()
        out_elf.parent.mkdir(parents=True, exist_ok=True)

    _prepend_adjacent_venv_site_packages()

    ip = _try_vmlinux_to_elf_inprocess(
        kernel_bin, out_elf if disk else None, timeout_s=timeout_s
    )
    if ip is not None:
        return ip

    exe = _resolve_vmlinux_cli()
    if not exe:
        return False, (
            "vmlinux-to-elf not importable and no CLI in adjacent .venv or on PATH "
            "(pip install marin-m/vmlinux-to-elf into the project virtualenv)"
        ), None

    if disk:
        assert out_elf is not None
        try:
            r = subprocess.run(
                [exe, str(kernel_bin.resolve()), str(out_elf)],
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired:
            return False, "vmlinux-to-elf timed out", None
        if r.returncode != 0:
            tail = (r.stderr or r.stdout or "")[-800:]
            return False, tail or f"exit {r.returncode}", None
        if not out_elf.is_file():
            return False, "vmlinux-to-elf produced no output file", None
        return True, "", None

    with tempfile.TemporaryDirectory() as td:
        tmp_elf = Path(td) / "vmlinux.elf"
        try:
            r = subprocess.run(
                [exe, str(kernel_bin.resolve()), str(tmp_elf)],
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired:
            return False, "vmlinux-to-elf timed out", None
        if r.returncode != 0:
            tail = (r.stderr or r.stdout or "")[-800:]
            return False, tail or f"exit {r.returncode}", None
        if not tmp_elf.is_file():
            return False, "vmlinux-to-elf produced no output file", None
        return True, "", tmp_elf.read_bytes()
