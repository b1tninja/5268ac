"""Optional Syft SBOM generation for corpus artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

SquashfsTreeOpener = Callable[..., Iterator[Path]]


def safe_sbom_name(
    source_key: str,
    *,
    suffix: str = ".syft.json",
    carrier_md5: str | None = None,
) -> str:
    """Filesystem-safe, stable SBOM filename for a corpus source key."""
    if carrier_md5 and len(carrier_md5) >= 16:
        stem = f"sbom_{carrier_md5[:16]}"
        return f"{stem}{suffix}" if suffix else stem
    digest = hashlib.sha256(source_key.encode("utf-8", errors="replace")).hexdigest()[:16]
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", source_key)[-96:].strip("._")
    if not stem:
        stem = "artifact"
    return f"{stem}_{digest}{suffix}"


def _safe_relative_path(path: str) -> Path | None:
    rel = Path(path.replace("\\", "/").lstrip("/"))
    if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        return None
    return rel


def materialize_files(
    files: Iterable[tuple[str, bytes]],
    out_dir: Path,
    *,
    reuse_existing: bool = True,
) -> dict[str, Any]:
    """Write an iterable of ``(relative_path, bytes)`` rows under *out_dir*."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    reused = 0
    skipped: list[dict[str, str]] = []
    for rel_text, data in files:
        rel = _safe_relative_path(rel_text)
        if rel is None:
            skipped.append({"path": rel_text, "reason": "unsafe relative path"})
            continue
        dst = out_dir / rel
        if reuse_existing and dst.is_file() and dst.stat().st_size == len(data):
            reused += 1
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        written += 1
    return {"root": str(out_dir), "files_written": written, "files_reused": reused, "skipped": skipped}


def _squashfs_superblock_ok(image_path: Path) -> bool:
    """Cheap check that *image_path* begins with a SquashFS magic."""
    try:
        head = image_path.read_bytes()[:4]
    except OSError:
        return False
    return head in {b"hsqs", b"sqsh", b"shsq", b"hsqh"}


def _squashfs_mount_prefix(mount_root: Path, name_hint: str) -> Path:
    mount_root = Path(mount_root).resolve()
    mount_root.mkdir(parents=True, exist_ok=True)
    prefix = re.sub(r"[^A-Za-z0-9_.-]+", "_", name_hint)[:48].strip("._") or "squashfs"
    return Path(tempfile.mkdtemp(prefix=f"{prefix}_", dir=mount_root))


def _fusermount_unmount(mount_dir: Path) -> None:
    for cmd in (["fusermount", "-uz", str(mount_dir)], ["umount", str(mount_dir)]):
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode == 0:
            return


@contextmanager
def mounted_squashfs_kernel(
    image_path: Path,
    mount_root: Path,
    *,
    name_hint: str = "squashfs",
) -> Iterator[Path]:
    """Kernel loop mount (fast when ``squashfs`` module + image compression match)."""
    image_path = Path(image_path).resolve()
    if not _squashfs_superblock_ok(image_path):
        raise RuntimeError(f"not a squashfs image (bad magic): {image_path}")
    mount_dir = _squashfs_mount_prefix(mount_root, name_hint)
    mounted = False
    try:
        subprocess.run(
            ["modprobe", "squashfs"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        proc = subprocess.run(
            ["mount", "-t", "squashfs", "-o", "loop,ro", str(image_path), str(mount_dir)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
            raise RuntimeError(msg)
        mounted = True
        yield mount_dir
    finally:
        if mounted:
            subprocess.run(
                ["umount", str(mount_dir)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        try:
            mount_dir.rmdir()
        except OSError:
            pass


@contextmanager
def mounted_squashfs_fuse(
    image_path: Path,
    mount_root: Path,
    *,
    name_hint: str = "squashfs",
) -> Iterator[Path]:
    """
    FUSE mount via ``squashfuse`` (userspace; no kernel ``squashfs`` module).

    Preferred fallback on Docker Desktop when loop mount reports ``wrong fs type``.
    """
    image_path = Path(image_path).resolve()
    if not _squashfs_superblock_ok(image_path):
        raise RuntimeError(f"not a squashfs image (bad magic): {image_path}")
    mount_dir = _squashfs_mount_prefix(mount_root, name_hint)
    fused = False
    try:
        proc = subprocess.run(
            ["squashfuse", "-o", "ro", str(image_path), str(mount_dir)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode != 0:
            proc = subprocess.run(
                ["squashfuse", str(image_path), str(mount_dir)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
            raise RuntimeError(msg)
        fused = True
        yield mount_dir
    finally:
        if fused:
            _fusermount_unmount(mount_dir)
        try:
            mount_dir.rmdir()
        except OSError:
            pass


# Back-compat alias
mounted_squashfs_readonly = mounted_squashfs_kernel


@contextmanager
def open_squashfs_mount_tree(
    image_path: Path,
    mount_root: Path,
    *,
    name_hint: str = "squashfs",
    allow_fuse: bool = True,
) -> Iterator[tuple[Optional[Path], str]]:
    """
  Yield ``(mount_dir, mode)`` for Syft/Gitleaks directory scans.

  Tries kernel mount, then ``squashfuse``. On total failure yields
  ``(None, "squashfs-file")`` so the caller can use ``syft squashfs:PATH``.
  """
    image_path = Path(image_path).resolve()
    openers: list[tuple[str, SquashfsTreeOpener]] = [("mount", mounted_squashfs_kernel)]
    if allow_fuse:
        openers.append(("squashfuse", mounted_squashfs_fuse))

    errors: list[str] = []
    for mode_name, opener in openers:
        try:
            with opener(image_path, mount_root, name_hint=name_hint) as tree_dir:
                yield tree_dir, mode_name
                return
        except Exception as e:
            errors.append(f"{mode_name}: {type(e).__name__}: {e}")

    yield None, "squashfs-file"


def run_syft(
    source: Path | str,
    output_path: Path,
    *,
    syft_bin: str = "syft",
    output_format: str = "syft-json",
    source_type: str = "dir",
    timeout_s: int = 600,
    reuse_existing: bool = True,
) -> dict[str, Any]:
    """
    Run Syft and write a JSON SBOM.

    ``source`` may be a directory path or a scheme URI (e.g. ``squashfs:/path``).
    """
    source_label = str(source)
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if reuse_existing and output_path.is_file() and output_path.stat().st_size > 0:
        return {
            "ok": True,
            "cached": True,
            "source": source_label,
            "source_type": source_type,
            "format": output_format,
            "path": str(output_path),
            "bytes": output_path.stat().st_size,
            "grype_hint": f"grype sbom:{output_path}",
        }
    cmd = [syft_bin, source_label, "-o", output_format]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
    except FileNotFoundError:
        return {
            "ok": False,
            "error": f"{syft_bin!r} not found on PATH",
            "source": source_label,
            "source_type": source_type,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "syft timed out",
            "source": source_label,
            "source_type": source_type,
        }
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": (proc.stderr or proc.stdout or f"exit {proc.returncode}")[-2000:],
            "source": source_label,
            "source_type": source_type,
        }
    output_path.write_text(proc.stdout, encoding="utf-8")
    package_count = None
    try:
        payload = json.loads(proc.stdout)
        artifacts = payload.get("artifacts")
        if isinstance(artifacts, list):
            package_count = len(artifacts)
    except json.JSONDecodeError:
        pass
    return {
        "ok": True,
        "source": source_label,
        "source_type": source_type,
        "format": output_format,
        "path": str(output_path),
        "bytes": output_path.stat().st_size,
        "package_count": package_count,
        "grype_hint": f"grype sbom:{output_path}",
    }


def run_syft_squashfs_archive(
    image_path: Path,
    output_path: Path,
    *,
    syft_bin: str = "syft",
    output_format: str = "syft-json",
    timeout_s: int = 600,
    reuse_existing: bool = True,
) -> dict[str, Any]:
    """Run Syft against a ``.squashfs`` file via the ``squashfs:`` scheme (no extract)."""
    image_path = Path(image_path).resolve()
    if not _squashfs_superblock_ok(image_path):
        return {
            "ok": False,
            "error": f"not a squashfs image (bad magic): {image_path}",
            "source": str(image_path),
            "source_type": "squashfs-file",
            "source_mode": "squashfs-file",
        }
    source = f"squashfs:{image_path}"
    result = run_syft(
        source,
        output_path,
        syft_bin=syft_bin,
        output_format=output_format,
        source_type="squashfs-file",
        timeout_s=timeout_s,
        reuse_existing=reuse_existing,
    )
    result["source_image"] = str(image_path)
    result["source_mode"] = "squashfs-file"
    return result


def run_syft_from_squashfs_mount(
    image_path: Path,
    output_path: Path,
    *,
    mount_root: Path,
    syft_bin: str = "syft",
    output_format: str = "syft-json",
    timeout_s: int = 600,
    reuse_existing: bool = True,
    allow_fuse: bool = True,
    allow_archive: bool = True,
) -> dict[str, Any]:
    """
    SBOM for a SquashFS carve: mount tree (kernel or squashfuse) or ``syft squashfs:``.

    Does **not** dissect-extract the rootfs (too slow / too much disk).
    """
    image_path = Path(image_path).resolve()
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if reuse_existing and output_path.is_file() and output_path.stat().st_size > 0:
        return {
            "ok": True,
            "cached": True,
            "source": str(image_path),
            "source_type": "squashfs-mount",
            "source_mode": "mount",
            "format": output_format,
            "path": str(output_path),
            "bytes": output_path.stat().st_size,
            "grype_hint": f"grype sbom:{output_path}",
        }

    mount_errors: list[str] = []
    with open_squashfs_mount_tree(
        image_path,
        mount_root,
        name_hint=output_path.stem,
        allow_fuse=allow_fuse,
    ) as (tree_dir, tree_mode):
        if tree_dir is not None:
            result = run_syft(
                tree_dir,
                output_path,
                syft_bin=syft_bin,
                output_format=output_format,
                source_type="squashfs-mount",
                timeout_s=timeout_s,
                reuse_existing=False,
            )
            if result.get("ok"):
                result["source_image"] = str(image_path)
                result["source_mode"] = tree_mode
                return result
            mount_errors.append(f"{tree_mode}: {result.get('error') or 'syft failed'}")

    if allow_archive:
        archive_result = run_syft_squashfs_archive(
            image_path,
            output_path,
            syft_bin=syft_bin,
            output_format=output_format,
            timeout_s=timeout_s,
            reuse_existing=False,
        )
        if archive_result.get("ok"):
            return archive_result
        mount_errors.append(f"squashfs-file: {archive_result.get('error')}")

    return {
        "ok": False,
        "error": f"squashfs SBOM failed: {'; '.join(mount_errors)}",
        "source": str(image_path),
        "source_type": "squashfs-mount",
        "source_mode": "mount",
    }


__all__ = [
    "materialize_files",
    "mounted_squashfs_readonly",
    "mounted_squashfs_kernel",
    "mounted_squashfs_fuse",
    "open_squashfs_mount_tree",
    "run_syft",
    "run_syft_squashfs_archive",
    "run_syft_from_squashfs_mount",
    "safe_sbom_name",
]
