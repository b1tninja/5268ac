"""Extract firewall / pinhole CMDB state from ``cmlegacy.*`` (flash or file)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from boardfs.ext2_path import read_ext2_regular_file
from paceflash.cmdb_parse import (
    firmware_version_from_text,
    list_table_names,
    parse_tables,
    read_cmdb_text,
    table_index)
from paceflash.flash_session import open_opentla4_ext2
from paceflash.http_auth import _CMDB_EXT2_PATHS

_PROTO_NAMES = {6: "tcp", 17: "udp", "6": "tcp", "17": "udp"}

_DEFAULT_TABLES = (
    "hostapps",
    "apps",
    "ports",
    "nodetbl",
    "fw",
    "fwrules",
    "firewall",
    "firewall_rule",
    "firewall_chain",
    "firewall_level",
    "fw6_rule",
    "fw6_chain",
    "bind")

_TLPART_CM_CHUNK = re.compile(
    rb"<CM VERS=.[^<]{0,2000000}?</CM>",
    re.DOTALL)


def _intish(value: Any) -> int | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.startswith("-"):
        try:
            return int(s)
        except ValueError:
            return None
    if s.isdigit():
        return int(s)
    return None


def _app_id(fields: dict[str, Any]) -> str | None:
    for key in ("app_id", "appid", "APPID"):
        if key in fields:
            return str(fields[key])
    return None


def _node_id(fields: dict[str, Any]) -> str | None:
    for key in ("nodeid", "node_id", "NODEID"):
        if key in fields:
            return str(fields[key])
    return None


def derive_pinholes(tables: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Join ``hostapps`` rows with ``apps``, ``ports``, and ``nodetbl``."""
    apps = table_index(tables.get("apps") or [], "app_id")
    nodes = table_index(tables.get("nodetbl") or [], "nodeid")
    hostapps = tables.get("hostapps") or []
    out: list[dict[str, Any]] = []
    for row in hostapps:
        fields = dict(row.get("fields") or {})
        app_id = _app_id(fields)
        node_id = _node_id(fields)
        app = dict(apps.get(app_id, {})) if app_id is not None else {}
        node = dict(nodes.get(node_id, {})) if node_id is not None else {}
        port_rows: list[dict[str, Any]] = []
        if app_id is not None:
            for prow in tables.get("ports") or []:
                pf = prow.get("fields") or {}
                if str(pf.get("app_id", "")) == app_id:
                    port_rows.append(dict(pf))
        entry: dict[str, Any] = {
            "row": row.get("row"),
            "mapid": fields.get("mapid") or fields.get("MAPID"),
            "nodeid": node_id,
            "node_name": node.get("name"),
            "node_ip": node.get("ipaddr"),
            "node_mac": node.get("hwaddr"),
            "app_id": app_id,
            "app_name": app.get("app_name"),
            "app_category": app.get("category"),
            "hostapps": fields,
            "ports": [
                {
                    "proto": _PROTO_NAMES.get(pf.get("proto"), pf.get("proto")),
                    "start_port": pf.get("start_port"),
                    "end_port": pf.get("end_port"),
                    "host_port": pf.get("host_port"),
                    "timeout": pf.get("timeout"),
                    "alg_id": pf.get("alg_id"),
                }
                for pf in port_rows
            ],
        }
        out.append(entry)
    return out


def summarize_fw_table(tables: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    fw_rows = tables.get("fw") or []
    if not fw_rows:
        return {}
    fields = dict((fw_rows[0].get("fields") or {}))
    params = fields.pop("params", [])
    if isinstance(params, list):
        param_map = {p.get("name"): p.get("value") for p in params if isinstance(p, dict)}
    else:
        param_map = {}
    return {
        "inbound": fields.get("inbound"),
        "outbound": fields.get("outbound"),
        "params": param_map,
        "dmz_nodeid": fields.get("dmz_nodeid"),
        "dmz_mode": fields.get("dmz_mode"),
        "raw": fields,
    }


def summarize_rules(tables: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    def _compact(name: str, *, rule_key: str = "rule") -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for row in tables.get(name) or []:
            fields = dict(row.get("fields") or {})
            if not fields:
                continue
            item = {"row": row.get("row"), **fields}
            if rule_key in fields:
                item["rule"] = fields[rule_key]
            rows.append(item)
        return rows

    return {
        "fwrules": _compact("fwrules"),
        "firewall_rule": _compact("firewall_rule"),
        "firewall_chain": _compact("firewall_chain"),
        "firewall_level": _compact("firewall_level"),
        "firewall": _compact("firewall"),
        "fw6_rule": _compact("fw6_rule", rule_key="description"),
        "bind": _compact("bind"),
    }


def parse_cmdb_fw_document(
    text: str,
    *,
    tables: tuple[str, ...] | None = None,
    include_catalog: bool = False) -> dict[str, Any]:
    want = set(tables or _DEFAULT_TABLES)
    if include_catalog:
        want.update({"apps", "ports"})
    parsed = parse_tables(text, names=want)
    pinholes = derive_pinholes(parsed)
    catalog: dict[str, Any] | None = None
    if include_catalog:
        catalog = {
            "apps": [r.get("fields") for r in parsed.get("apps") or []],
            "ports": [r.get("fields") for r in parsed.get("ports") or []],
        }
    return {
        "firmware_version": firmware_version_from_text(text),
        "tables_present": list_table_names(text),
        "tables": parsed,
        "pinholes": pinholes,
        "fw": summarize_fw_table(parsed),
        "rules": summarize_rules(parsed),
        "catalog": catalog,
    }


def _parse_cmdb_bytes(
    data: bytes,
    *,
    source: str,
    tables: tuple[str, ...] | None,
    include_catalog: bool) -> dict[str, Any]:
    if not data.strip().startswith(b"<?xml") and b"<CM" not in data[:8192]:
        return {"source": source, "ok": False, "error": "not CMDB XML", "bytes": len(data)}
    text, enc = read_cmdb_text(data)
    doc = parse_cmdb_fw_document(text, tables=tables, include_catalog=include_catalog)
    doc.update({"source": source, "ok": True, "encoding": enc, "bytes": len(data)})
    return doc


def scan_tlpart_cmdb_fw(
    tlpart: bytes,
    *,
    tables: tuple[str, ...] | None = None,
    include_catalog: bool = False) -> list[dict[str, Any]]:
    """Find embedded ``<CM …>`` documents in assembled tlpart that contain firewall tables."""
    found: list[dict[str, Any]] = []
    for i, m in enumerate(_TLPART_CM_CHUNK.finditer(tlpart)):
        chunk = m.group()
        if b"hostapps" not in chunk and b'TABLE N="fw"' not in chunk:
            continue
        try:
            text = chunk.decode("utf-8", errors="replace")
        except Exception:
            continue
        doc = parse_cmdb_fw_document(text, tables=tables, include_catalog=include_catalog)
        if not any(doc.get("pinholes")) and not doc.get("fw") and not doc.get("rules", {}).get("fwrules"):
            # still keep if explicit fw tables requested
            if not doc.get("tables"):
                continue
        found.append(
            {
                "source": "tlpart_embedded",
                "index": i,
                "offset": m.start(),
                "ok": True,
                "bytes": len(chunk),
                **doc,
            }
        )
    return found


def _read_cmdb_from_ext2(
    flash_path: Path,
    *,
    cmdline: str | None,
    nand_translate: bool,
    nand_translate_mode: str,
    bbm_chain_aware: bool,
    paths: tuple[str, ...],
    tables: tuple[str, ...] | None,
    include_catalog: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    with open_opentla4_ext2(
        flash_path,
        cmdline,
        nand_translate=nand_translate,
        nand_translate_mode=nand_translate_mode,  # type: ignore[arg-type]
        bbm_chain_aware=bbm_chain_aware) as vol:
        for rel in paths:
            entry: dict[str, Any] = {"path": rel, "source": "ext2_opentla4"}
            try:
                data = read_ext2_regular_file(
                    vol.slice_bytes,
                    rel,
                    sb_off=vol.sb_off,
                    access=vol.access)
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
            parsed = _parse_cmdb_bytes(
                data,
                source=rel,
                tables=tables,
                include_catalog=include_catalog)
            entry.update(parsed)
            results.append(entry)
    return results


def dump_cmdb_fw(
    *,
    flash_path: str | Path | None = None,
    cmdb_path: str | Path | None = None,
    cmdline: str | None = None,
    nand_translate: bool = True,
    nand_translate_mode: Literal["inline-2112", "flat-tail", "identity"] = "inline-2112",
    bbm_chain_aware: bool = False,
    include_tlpart_scan: bool = True,
    cmdb_paths: tuple[str, ...] | None = None,
    tables: tuple[str, ...] | None = None,
    include_catalog: bool = False) -> dict[str, Any]:
    warnings: list[str] = []
    out: dict[str, Any] = {"ok": True, "warnings": warnings, "sources": []}

    if cmdb_path is not None:
        p = Path(cmdb_path).expanduser().resolve()
        data = p.read_bytes()
        doc = _parse_cmdb_bytes(
            data,
            source=str(p),
            tables=tables,
            include_catalog=include_catalog)
        out["sources"] = [doc]
        out["flash"] = None
        out["cmdb_path"] = str(p)
    else:
        if flash_path is None:
            raise ValueError("flash_path or cmdb_path required")
        p = Path(flash_path).expanduser().resolve()
        out["flash"] = str(p)
        paths = cmdb_paths if cmdb_paths is not None else _CMDB_EXT2_PATHS
        try:
            out["sources"] = _read_cmdb_from_ext2(
                p,
                cmdline=cmdline,
                nand_translate=nand_translate,
                nand_translate_mode=nand_translate_mode,
                bbm_chain_aware=bbm_chain_aware,
                paths=paths,
                tables=tables,
                include_catalog=include_catalog)
        except Exception as e:
            warnings.append(f"ext2 CMDB read: {type(e).__name__}: {e}")
            out["sources"] = []

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
                out["tlpart_cmdb"] = scan_tlpart_cmdb_fw(
                    tlpart,
                    tables=tables,
                    include_catalog=include_catalog)
            except Exception as e:
                warnings.append(f"tlpart CMDB scan: {type(e).__name__}: {e}")
                out["tlpart_cmdb"] = []

    if not any(s.get("ok") for s in out.get("sources") or []):
        out["ok"] = False
        if not warnings:
            warnings.append("no readable CMDB sources")
    return out
