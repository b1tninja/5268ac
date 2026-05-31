"""Offline board identity + active firmware version from a Pace flash dump.

Combines:

- Factory loader block (``factory-params``)
- ``board_param`` / paramtool keys (``gw:trust_engcert``, …)
- ext2 **opentla4** version files (**``sys1/component.txt``**, … — runtime ``/rwdata/sys1/…``)
- CMDB ``mgmt_upgstate`` / ``pkgs`` (when ``cm/cmlegacy.*`` is readable)

Ghidra (**libboard.so** 532678): ``board_build_version`` → ``_board_build_version`` opens a
single GP-relative path (not cleartext in ``strings``); ``board_build_digits`` parses that
dotted string into four ``uint32`` values for ``lib2sp_set_sys_version``. See
``reference/libboard.md`` and ``LIBBOARD_VERSION_PATHS`` in this module.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from acspy.cmdb import parse_mgmt_upgstate, parse_pkgs
from boardfs.ext2_path import read_ext2_regular_file
from paceflash.board_param import dump_paramtool
from paceflash.cellular_identity import dump_cellular_identity
from paceflash.factory_params import dump_factory_params
from paceflash.flash_session import open_opentla4_ext2
from paceflash.http_auth import _CMDB_EXT2_PATHS, read_cmdb_xml_text_from_bytes

# ext2 paths on opentla4 (mounted at /rwdata at runtime — see reference/pace_ext2_cm_directory.md)
_VERSION_EXT2_CANDIDATES: tuple[tuple[str, str], ...] = (
    ("sys1/component.txt", "active_component"),
    ("sys1/version.txt", "active_version"),
    ("sys2/component.txt", "staging_component"),
    ("sys2/version.txt", "staging_version"),
)

_PARAMTOOL_KEYS = (
    "gw:trust_engcert",
    "gw:trust_2sp_cn",
)

# Ghidra /usr/lib/libboard.so.0.0.0 (att-5268 11.5.1.532678) — GP-relative path tables
LIBBOARD_VERSION_PATHS: dict[str, Any] = {
    "board_build_version": {
        "symbol": "board_build_version @ 0x00011ce0",
        "opens_via": "_board_build_version @ 0x00011c18",
        "path_rodata": "GP + board_param_size + 0x5394 (not plain ASCII in .rodata strings)",
        "runtime_reads": "small text file via open/read (same idiom as board_info_serialnumber)",
        "offline_ext2_equivalents": [
            "sys1/component.txt  →  /rwdata/sys1/component.txt",
            "sys1/version.txt    →  /rwdata/sys1/version.txt",
            "/etc/version.txt    →  squashfs or symlink on live system",
        ],
        "pkgd_downgrade_11_14": "pkg_stream_resolve_pkg compares lib2sp_get_version vs board_build_version()",
    },
    "board_get_deferred_version": {
        "symbol": "board_get_deferred_version @ 0x00011e78",
        "path_rodata": "GP + 0x5434",
        "offline_ext2_equivalents": ["sys2/component.txt", "sys2/version.txt"],
    },
    "board_build_digits": {
        "symbol": "board_build_digits @ 0x00011e94",
        "source": "strtol() on dotted string from board_build_version(), not a separate NAND blob",
        "consumer": "lib2sp_set_sys_version(ctx+0x648) during pkg_util_set_2sp_sys_info",
    },
    "board_info_serialnumber": {
        "symbol": "board_info_serialnumber @ 0x00011f84",
        "path_rodata": "two fallback paths at GP+0x5450, GP+0x547c",
    },
}

_TLPART_UPGSTATE = re.compile(
    rb'<TABLE N="mgmt_upgstate">.{0,12000}?</TABLE>',
    re.DOTALL,
)

_VERSION_LINE_RE = re.compile(
    r"^\s*(\d+)\.(\d+)\.(\d+)\.(\d+)\s*$",
)


def parse_dotted_version_quad(text: str) -> dict[str, Any]:
    """
    Parse ``major.minor.build.patch`` like ``pkg_stream_resolve_pkg`` / ``board_build_digits``.

    Returns dict with ``ok``, ``fields`` (n0..n3), and ``pkgd_downgrade_tuple`` notes.
    """
    line = (text or "").strip().splitlines()[0].strip() if text else ""
    m = _VERSION_LINE_RE.match(line)
    if not m:
        return {
            "ok": False,
            "raw_first_line": line[:200],
            "error": "expected dotted quad major.minor.build.patch on first line",
        }
    nums = [int(m.group(i)) for i in range(1, 5)]
    return {
        "ok": True,
        "raw_first_line": line,
        "fields": {
            "n0_major": nums[0],
            "n1_minor": nums[1],
            "n2_build": nums[2],
            "n3_patch": nums[3],
        },
        "digits_array": nums,
        "pkgd_downgrade_note": (
            "11.14+ pkgd rejects when n0<v0 OR (n0==v0 AND (n1<v1 OR n3<v3)); "
            "middle field n2 not used in tie branch"
        ),
    }


def _read_ext2_text(
    flash_path: Path,
    rel_path: str,
    *,
    cmdline: str | None,
    nand_translate: bool,
    nand_translate_mode: str,
    bbm_chain_aware: bool,
    cmdb_recover: bool,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "ext2_path": rel_path,
        "runtime_path": f"/rwdata/{rel_path}",
    }
    try:
        with open_opentla4_ext2(
            flash_path,
            cmdline,
            nand_translate=nand_translate,
            nand_translate_mode=nand_translate_mode,  # type: ignore[arg-type]
            bbm_chain_aware=bbm_chain_aware,
        ) as vol:
            data = read_ext2_regular_file(
                vol.slice_bytes,
                rel_path,
                sb_off=vol.sb_off,
                access=vol.access,
                cmdb_recover=cmdb_recover,
            )
    except FileNotFoundError:
        entry["ok"] = False
        entry["error"] = "not found"
        return entry
    except OSError as e:
        entry["ok"] = False
        entry["error"] = f"{type(e).__name__}: {e}"
        return entry
    text = data.decode("utf-8", errors="replace").strip()
    entry["ok"] = True
    entry["bytes"] = len(data)
    entry["text"] = text
    entry["parsed"] = parse_dotted_version_quad(text)
    return entry


def _scan_tlpart_mgmt_upgstate(tlpart: bytes) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for i, m in enumerate(_TLPART_UPGSTATE.finditer(tlpart)):
        try:
            text = m.group().decode("utf-8", errors="replace")
        except Exception:
            continue
        upg = parse_mgmt_upgstate(text)
        if not upg.part1.name and not upg.part2.name and not upg.part2_path:
            continue
        found.append(
            {
                "source": "tlpart_embedded",
                "index": i,
                "offset": m.start(),
                "mgmt_upgstate": {
                    "part1_name": upg.part1.name,
                    "part1_status": upg.part1.status,
                    "part2_name": upg.part2.name,
                    "part2_status": upg.part2.status,
                    "part2_path": upg.part2_path,
                    "deferred_enable": upg.deferred_enable,
                },
            }
        )
    return found


def _try_cmdb_upgrade_pkgs(
    flash_path: Path,
    *,
    cmdline: str | None,
    nand_translate: bool,
    nand_translate_mode: str,
    bbm_chain_aware: bool,
    paths: tuple[str, ...],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for rel in paths:
        entry: dict[str, Any] = {"path": rel, "source": "ext2_opentla4"}
        try:
            with open_opentla4_ext2(
                flash_path,
                cmdline,
                nand_translate=nand_translate,
                nand_translate_mode=nand_translate_mode,  # type: ignore[arg-type]
                bbm_chain_aware=bbm_chain_aware,
            ) as vol:
                data = read_ext2_regular_file(
                    vol.slice_bytes,
                    rel,
                    sb_off=vol.sb_off,
                    access=vol.access,
                    cmdb_recover=True,
                )
        except FileNotFoundError:
            entry["ok"] = False
            entry["error"] = "not found"
            results.append(entry)
            continue
        except OSError as e:
            entry["ok"] = False
            entry["error"] = f"{type(e).__name__}: {e}"
            results.append(entry)
            continue
        if not data.strip().startswith(b"<?xml") and b"<CM" not in data[:4096]:
            entry["ok"] = False
            entry["error"] = "not CMDB XML"
            entry["bytes"] = len(data)
            results.append(entry)
            continue
        text, enc = read_cmdb_xml_text_from_bytes(data)
        upg = parse_mgmt_upgstate(text)
        pkgs = parse_pkgs(text)
        install_pkgs = [
            {
                "name": r.name,
                "version": r.version,
                "role": r.role,
                "path": r.path,
            }
            for r in pkgs
            if r.name and ("install" in r.name.lower() or r.role == "install")
        ][:8]
        entry["ok"] = True
        entry["encoding"] = enc
        entry["bytes"] = len(data)
        entry["mgmt_upgstate"] = {
            "part1_name": upg.part1.name,
            "part1_status": upg.part1.status,
            "part2_name": upg.part2.name,
            "part2_status": upg.part2.status,
            "part2_path": upg.part2_path,
            "deferred_enable": upg.deferred_enable,
        }
        entry["pkgs_install_subset"] = install_pkgs
        results.append(entry)
    return results


def _pick_active_version(version_files: list[dict[str, Any]]) -> dict[str, Any]:
    """Prefer sys1/component.txt, then sys1/version.txt."""
    order = ("active_component", "active_version", "staging_component", "staging_version")
    by_role = {v.get("role"): v for v in version_files if v.get("ok")}
    for role in order:
        hit = by_role.get(role)
        if hit and isinstance(hit.get("parsed"), dict) and hit["parsed"].get("ok"):
            return {
                "ok": True,
                "source_role": role,
                "ext2_path": hit.get("ext2_path"),
                "runtime_path": hit.get("runtime_path"),
                "parsed": hit["parsed"],
                "text": hit.get("text"),
            }
    return {"ok": False, "error": "no readable dotted version file on opentla4"}


def dump_board_info(
    flash_path: str | Path,
    *,
    cmdline: str | None = None,
    nand_translate: bool = True,
    nand_translate_mode: Literal["inline-2112", "flat-tail", "identity"] = "inline-2112",
    bbm_chain_aware: bool = False,
    redact: bool = False,
    include_tlpart_scan: bool = True,
    cmdb_paths: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Aggregate board identity + firmware version sources from a flash dump."""
    p = Path(flash_path).expanduser().resolve()
    warnings: list[str] = []
    out: dict[str, Any] = {
        "flash": str(p),
        "ok": True,
        "warnings": warnings,
        "libboard_re": LIBBOARD_VERSION_PATHS,
    }

    fac_doc = dump_factory_params(
        p,
        cmdline=cmdline,
        nand_translate=nand_translate,
        nand_translate_mode=nand_translate_mode,
        redact=redact,
    )
    out["factory"] = fac_doc.get("factory")
    out["loader_partition"] = fac_doc.get("loader_partition")
    for w in fac_doc.get("warnings") or []:
        warnings.append(str(w))
    fac = fac_doc.get("factory") or {}
    if fac.get("ok"):
        params = fac.get("params") or {}
        out["identity"] = {
            "model": params.get("model"),
            "sn": params.get("sn"),
            "mac": params.get("mac"),
            "pca": params.get("pca"),
            "mfg_timestamp": params.get("mfg_timestamp"),
        }
        if redact:
            out["identity_redacted"] = True
    else:
        warnings.append(f"factory: {fac.get('error', 'failed')}")

    pt_doc = dump_paramtool(
        p,
        mode="show",
        cmdline=cmdline,
        nand_translate=nand_translate,
        nand_translate_mode=nand_translate_mode,
        redact=redact,
        include_p12_b64=False,
    )
    out["paramtool_ok"] = pt_doc.get("ok")
    if pt_doc.get("ok"):
        all_params = pt_doc.get("params") or {}
        out["paramtool_selected"] = {k: all_params[k] for k in _PARAMTOOL_KEYS if k in all_params}
        out["paramtool_count"] = pt_doc.get("param_count")
        te = out["paramtool_selected"].get("gw:trust_engcert")
        if te is not None:
            out["pkgd_downgrade_policy_note"] = (
                "11.14+ pkg_stream_resolve_pkg skips version-downgrade check when "
                "tw_ulib_is_trustengcert_enabled() != 0 (engineering trust); "
                f"flash gw:trust_engcert={te!r}"
            )
    else:
        warnings.append(f"paramtool: {pt_doc.get('error', 'failed')}")

    version_files: list[dict[str, Any]] = []
    try:
        for rel, role in _VERSION_EXT2_CANDIDATES:
            entry = _read_ext2_text(
                p,
                rel,
                cmdline=cmdline,
                nand_translate=nand_translate,
                nand_translate_mode=nand_translate_mode,
                bbm_chain_aware=bbm_chain_aware,
                cmdb_recover=False,
            )
            entry["role"] = role
            version_files.append(entry)
    except Exception as e:
        warnings.append(f"ext2 version files: {type(e).__name__}: {e}")
    out["version_files"] = version_files
    out["active_version"] = _pick_active_version(version_files)

    paths = cmdb_paths if cmdb_paths is not None else _CMDB_EXT2_PATHS
    try:
        out["cmdb_ext2"] = _try_cmdb_upgrade_pkgs(
            p,
            cmdline=cmdline,
            nand_translate=nand_translate,
            nand_translate_mode=nand_translate_mode,
            bbm_chain_aware=bbm_chain_aware,
            paths=paths,
        )
    except Exception as e:
        warnings.append(f"cmdb ext2: {type(e).__name__}: {e}")
        out["cmdb_ext2"] = []

    if include_tlpart_scan:
        try:
            from boardfs import temporary_registry_from_physical_nand
            from unand.mtd import DEFAULT_MTDPARTS

            line = cmdline if cmdline is not None else f"quiet rw {DEFAULT_MTDPARTS}"
            with temporary_registry_from_physical_nand(
                p, line, translate_mode=nand_translate_mode
            ) as (reg, man, _ot):
                if not nand_translate and man.get("warnings"):
                    for w in man["warnings"]:
                        warnings.append(str(w))
                tlpart = reg.flash.read_partition("tlpart")
            out["tlpart_mgmt_upgstate"] = _scan_tlpart_mgmt_upgstate(tlpart)
        except Exception as e:
            warnings.append(f"tlpart mgmt_upgstate scan: {type(e).__name__}: {e}")
            out["tlpart_mgmt_upgstate"] = []

    # Cross-check CMDB part1.Name vs ext2 component.txt when both present
    cm_name: str | None = None
    for block in out.get("cmdb_ext2") or []:
        if block.get("ok"):
            mu = block.get("mgmt_upgstate") or {}
            if mu.get("part1_name"):
                cm_name = str(mu["part1_name"])
                break
    av = out.get("active_version") or {}
    ext2_line = av.get("text") if av.get("parsed", {}).get("ok") else None
    if cm_name and ext2_line:
        out["version_crosscheck"] = {
            "cmdb_part1_name": cm_name,
            "ext2_active_first_line": ext2_line.splitlines()[0] if ext2_line else "",
            "match": cm_name.strip() == (ext2_line.splitlines()[0].strip() if ext2_line else ""),
        }

    if not fac.get("ok") and not any(v.get("ok") for v in version_files):
        out["ok"] = False

    try:
        out["cellular"] = dump_cellular_identity(
            p,
            cmdline=cmdline,
            nand_translate=nand_translate,
            nand_translate_mode=nand_translate_mode,
            bbm_chain_aware=bbm_chain_aware,
            include_tlpart_scan=include_tlpart_scan,
            cmdb_paths=cmdb_paths,
        )
        if out["cellular"].get("qxdm_passcode"):
            out["qxdm_passcode"] = out["cellular"]["qxdm_passcode"]
            out["imei"] = out["cellular"].get("imei")
    except Exception as e:
        warnings.append(f"cellular identity: {type(e).__name__}: {e}")
        out["cellular"] = {"ok": False, "error": str(e)}

    return out
