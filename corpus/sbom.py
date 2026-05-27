"""Optional Syft SBOM generation for corpus artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator


def safe_sbom_name(source_key: str, *, suffix: str = ".syft.json") -> str:
    """Filesystem-safe, stable SBOM filename for a corpus source key."""
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


@contextmanager
def mounted_squashfs_readonly(
    image_path: Path,
    mount_root: Path,
    *,
    name_hint: str = "squashfs",
) -> Iterator[Path]:
    """Temporarily mount a SquashFS image read-only and yield the mountpoint."""
    image_path = Path(image_path).resolve()
    mount_root = Path(mount_root).resolve()
    mount_root.mkdir(parents=True, exist_ok=True)
    prefix = re.sub(r"[^A-Za-z0-9_.-]+", "_", name_hint)[:48].strip("._") or "squashfs"
    mount_dir = Path(tempfile.mkdtemp(prefix=f"{prefix}_", dir=mount_root))
    mounted = False
    try:
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


def run_syft(
    source: Path,
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

    ``source_type`` is recorded for provenance only; paths are passed directly so Windows
    drive-letter paths work with Syft.
    """
    source = Path(source).resolve()
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if reuse_existing and output_path.is_file() and output_path.stat().st_size > 0:
        return {
            "ok": True,
            "cached": True,
            "source": str(source),
            "source_type": source_type,
            "format": output_format,
            "path": str(output_path),
            "bytes": output_path.stat().st_size,
            "grype_hint": f"grype sbom:{output_path}",
        }
    cmd = [syft_bin, str(source), "-o", output_format]
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
            "source": str(source),
            "source_type": source_type,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "syft timed out",
            "source": str(source),
            "source_type": source_type,
        }
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": (proc.stderr or proc.stdout or f"exit {proc.returncode}")[-2000:],
            "source": str(source),
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
        "source": str(source),
        "source_type": source_type,
        "format": output_format,
        "path": str(output_path),
        "bytes": output_path.stat().st_size,
        "package_count": package_count,
        "grype_hint": f"grype sbom:{output_path}",
    }


def run_syft_from_squashfs_mount(
    image_path: Path,
    output_path: Path,
    *,
    mount_root: Path,
    syft_bin: str = "syft",
    output_format: str = "syft-json",
    timeout_s: int = 600,
    reuse_existing: bool = True,
) -> dict[str, Any]:
    """Run Syft against a temporary read-only SquashFS mount."""
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
    try:
        with mounted_squashfs_readonly(
            image_path,
            mount_root,
            name_hint=output_path.stem,
        ) as mount_dir:
            result = run_syft(
                mount_dir,
                output_path,
                syft_bin=syft_bin,
                output_format=output_format,
                source_type="squashfs-mount",
                timeout_s=timeout_s,
                reuse_existing=False,
            )
    except Exception as e:
        return {
            "ok": False,
            "error": f"squashfs mount failed: {type(e).__name__}: {e}",
            "source": str(image_path),
            "source_type": "squashfs-mount",
            "source_mode": "mount",
        }
    result["source_image"] = str(image_path)
    result["source_mode"] = "mount"
    return result


__all__ = [
    "materialize_files",
    "mounted_squashfs_readonly",
    "run_syft",
    "run_syft_from_squashfs_mount",
    "safe_sbom_name",
]
