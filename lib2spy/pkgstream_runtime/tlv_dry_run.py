"""
Prefix TLV **dry-run** trace — pure data, no mount, no ``lib2sp`` FSM.

Walks the same **linear prefix** as ``iter_tlvs_prefix_only`` and annotates each record
with the display name used by ``python -m lib2spy.pkgstream`` plus an optional **install_hint**
when the wire type appears in ``INSTALL_TLV_DEMARSHALL`` (one-word ``install_action``,
``install_comment`` for verbose detail, plus Ghidra ``symbol`` from ``lib2sp_payload_data`` RE).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from lib2spy.native_pkgstream import (
    HEADER_SIZE,
    iter_tlvs_prefix_only,
    parse_2sp_header,
    try_decompress_bzip2_prefix,
)
from lib2spy.pkgstream_runtime.lib2sp_dispatch import (
    INSTALL_TLV_DEMARSHALL,
    install_runtime_hint_dict,
)

_NOTES_TRIM = 200
PathLike = Union[str, Path]


def _install_hint_for(wire_type: int) -> Optional[Dict[str, Any]]:
    base = install_runtime_hint_dict(wire_type)
    if base is None:
        return None
    stub = INSTALL_TLV_DEMARSHALL[wire_type]
    notes = stub.notes.strip()
    if len(notes) > _NOTES_TRIM:
        notes = notes[: _NOTES_TRIM - 3] + "..."
    com = stub.install_comment.strip()
    if len(com) > _NOTES_TRIM:
        com = com[: _NOTES_TRIM - 3] + "..."
    return {**base, "notes": notes, "install_comment": com}


def trace_prefix_tlv_chain(body: bytes) -> List[Dict[str, Any]]:
    """
    Return one dict per prefix TLV: type hex, name, offsets, length, optional install_hint.
    """
    # Local import: ``lib2spy.pkgstream`` pulls ``pkgstream_runtime`` package __init__, which
    # imports this module — eager ``_tlv_name`` import would circularize initialization.
    from lib2spy.pkgstream import _tlv_name

    tlvs = iter_tlvs_prefix_only(body, start=HEADER_SIZE)
    out: List[Dict[str, Any]] = []
    for i, r in enumerate(tlvs):
        row: Dict[str, Any] = {
            "index": i,
            "type": f"0x{r.type:02x}",
            "wire_type": r.type,
            "name": _tlv_name(r.type),
            "offset": r.absolute_offset,
            "length": r.length,
            "end_offset": r.end_offset,
        }
        hint = _install_hint_for(r.type)
        if hint is not None:
            row["install_hint"] = hint
        out.append(row)
    return out


def trace_pkgstream_path(path: PathLike) -> Dict[str, Any]:
    """
    Read a ``.pkgstream`` from disk, unwrap outer bzip2 if present, parse header, trace prefix TLVs.
    """
    p = Path(path)
    raw = p.read_bytes()
    body, was_bz2 = try_decompress_bzip2_prefix(raw)
    header = parse_2sp_header(body)
    trace = trace_prefix_tlv_chain(body)
    return {
        "path": str(p.resolve()),
        "raw_size": len(raw),
        "body_size": len(body),
        "outer_bzip2": was_bz2,
        "header": {
            "magic": header.magic.decode("ascii", "replace"),
            "u32": [header.u32_0, header.u32_1, header.u32_2, header.u32_3],
            "is_supported_magic": header.is_supported_magic,
        },
        "tlv_trace": trace,
    }
