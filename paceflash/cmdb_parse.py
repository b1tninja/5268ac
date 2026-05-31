"""Parse Pace CMDB XML tables from ``cmlegacy.*`` documents."""

from __future__ import annotations

import re
from typing import Any

from paceflash.cmdb_password import decode_cmdb_xml_bytes

_ROW_RE = re.compile(r'<ROW N="(\d+)">(.*?)</ROW>', re.DOTALL)
_TABLE_RE = re.compile(r'<TABLE N="([^"]+)">(.*?)</TABLE>', re.DOTALL)
_VTABLE_RE = re.compile(r'<VTABLE N="([^"]+)">(.*?)</VTABLE>', re.DOTALL)
_FIELD_RE = re.compile(
    r'<(S|U|I|T|ENUM|FLAG|IP|MAC) N="([^"]+)">([^<]*)</(?:S|U|I|T|ENUM|FLAG|IP|MAC)>'
)
_ROOT_FW_RE = re.compile(
    r'<ROOT NAME="cmlegacy"\s+B="([^"]+)"',
    re.IGNORECASE,
)


def read_cmdb_text(data: bytes) -> tuple[str, str]:
    return decode_cmdb_xml_bytes(data)


def firmware_version_from_text(text: str) -> str:
    m = _ROOT_FW_RE.search(text)
    return m.group(1) if m else ""


def _top_level_rows(table_body: str) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    i = 0
    while i < len(table_body):
        start = table_body.find("<ROW", i)
        if start < 0:
            break
        if start > i and table_body[i:start].strip():
            pass
        # Only count ROW at depth 0 (not inside VTABLE yet)
        prefix = table_body[:start]
        if prefix.rfind("<VTABLE") > prefix.rfind("</VTABLE"):
            i = start + 4
            continue
        open_end = table_body.find(">", start)
        if open_end < 0:
            break
        header = table_body[start:open_end]
        num_m = re.search(r'N="(\d+)"', header)
        row_num = int(num_m.group(1)) if num_m else len(rows)
        depth = 0
        j = start
        inner_start = -1
        while j < len(table_body):
            if table_body.startswith("<ROW", j):
                if depth == 0:
                    inner_start = table_body.find(">", j) + 1
                depth += 1
                j += 4
                continue
            if table_body.startswith("</ROW>", j):
                depth -= 1
                if depth == 0 and inner_start >= 0:
                    rows.append((row_num, table_body[inner_start:j]))
                    i = j + 6
                    break
                j += 6
                continue
            j += 1
        else:
            break
    return rows


def parse_table_rows(table_body: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row_num, inner in _top_level_rows(table_body):
        fields: dict[str, Any] = {}
        for fm in _FIELD_RE.finditer(inner):
            kind, name, value = fm.group(1), fm.group(2), fm.group(3)
            fields[name] = value
            fields[f"_{name}_type"] = kind.lower()
        for vm in _VTABLE_RE.finditer(inner):
            vname = vm.group(1)
            vrows: list[dict[str, str]] = []
            for vnum, vinner in _top_level_rows(vm.group(2)):
                sub = {fn.group(2): fn.group(3) for fn in _FIELD_RE.finditer(vinner)}
                if sub:
                    vrows.append(sub)
            fields[vname] = vrows
        if fields:
            rows.append({"row": row_num, "fields": fields})
    return rows


def parse_tables(text: str, *, names: set[str] | None = None) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for tm in _TABLE_RE.finditer(text):
        name = tm.group(1)
        if names is not None and name.lower() not in {n.lower() for n in names}:
            continue
        rows = parse_table_rows(tm.group(2))
        out[name] = rows
    return out


def list_table_names(text: str) -> list[str]:
    return sorted({m.group(1) for m in _TABLE_RE.finditer(text)})


def table_index(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    idx: dict[str, dict[str, Any]] = {}
    for row in rows:
        fields = row.get("fields") or {}
        val = fields.get(key)
        if val is None:
            continue
        idx[str(val)] = fields
    return idx


def rows_by_key(rows: list[dict[str, Any]], key: str, value: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        fields = row.get("fields") or {}
        if str(fields.get(key, "")) == value:
            out.append(fields)
    return out
