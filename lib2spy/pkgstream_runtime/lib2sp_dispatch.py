"""
``lib2sp`` TLV dispatch — **documentation stubs** for Ghidra-derived control flow.

What operators care about is the **filesystem action** the carrier drives after trust
checks—not the internal ``demarshall_2sp_*`` label. On **`lib2sp.so`** (10.5.3.527064 RE):

* **Stream + write file** — ``lib2sp_do_payload_tlv`` opens/writes/closes the FILE body
  (digest-checked bytes to an absolute path). ``unlink`` appears in the FILE write path
  on teardown after some failures (partial **delete** of the temp/target path).
* **Stage shell** — SCRIPT TLVs grow a heap buffer then **close** hands off to an indirect
  runner (fork/exec class — still RE).
* **Path / move records** — ``demarshall_2sp_path`` / ``demarshall_2sp_move`` parse TLV
  bodies; follow-up **vtable** calls implement **mkdir**, **symlink**, **copy**, and
  **move/rename**-class ops (``lib2sp_do_mkdir``, ``lib2sp_do_sym_link``,
  ``lib2sp_do_copy_file``, …).

**``libpkg_client`` / ``libpkg_server`` / ``libpkg_common``** (linked from ``pkgd``,
``httpd``, ``cwmd``) handle **download, RPC, and session state**; they do **not** replace
the **lib2sp** TLV byte parser or the jump table that performs the FS side effects above.

Each ``RuntimeHandlerStub`` uses **one-word** ``install_action`` plus ``install_comment``
(tooltip-style detail); Ghidra symbol stays in ``symbol``. See ``INSTALL_TLV_DEMARSHALL``
and ``JUMP_TABLE_FOLLOWUP``.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from lib2spy.pkgstream_runtime.models import RuntimeHandlerStub

# Wire types -> demarshall_2sp_* in lib2sp_payload_data (10.5.3.527064 export).
INSTALL_TLV_DEMARSHALL: Dict[int, RuntimeHandlerStub] = {
    0x01: RuntimeHandlerStub(
        symbol="demarshall_2sp_file",
        subsystem="lib2sp",
        effect_class="stream_to_path",
        install_action="copy",
        install_comment=(
            "Stream digest-verified FILE bytes from the carrier payload region to an absolute "
            "path (lib2sp_do_payload_tlv → open/write/close)."
        ),
        notes="10.5.3.527064 lib2sp_payload_data export.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=("Exact jump-table slot per opcode on this build.",),
    ),
    0x03: RuntimeHandlerStub(
        symbol="demarshall_2sp_file",
        subsystem="lib2sp",
        effect_class="stream_to_path",
        install_action="copy",
        install_comment="Same as 0x01: FILE variant on wire; stream body to path after demarshall.",
        notes="Same demarshaller as 0x01.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=(),
    ),
    0x07: RuntimeHandlerStub(
        symbol="demarshall_2sp_path",
        subsystem="lib2sp",
        effect_class="fs_op",
        install_action="dispatch",
        install_comment=(
            "Parse path-style TLV; indirect jump table then runs mkdir / symlink / "
            "rootfs-to-rootfs copy helpers. Prefix 0x07 is labeled CONFIG in 010—same opcode, "
            "different phase."
        ),
        notes="Wire vs prefix CONFIG bulk records still open (A3).",
        evidence=(
            "output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",
            "reference/010editor/Pkgstream_2WIRE_SP.bt",
        ),
        open_questions=("Wire layout vs prefix CONFIG bulk records.",),
    ),
    0x08: RuntimeHandlerStub(
        symbol="demarshall_2sp_move",
        subsystem="lib2sp",
        effect_class="fs_op",
        install_action="move",
        install_comment=(
            "Parse move/rename ladder (demarshall_2sp_move); applies rename-style updates on the "
            "target rootfs. Prefix 0x08 may show as INTEGER in 010—same opcode, different phase."
        ),
        notes="Install-phase ladder in lib2sp_payload_data.c export.",
        evidence=(
            "output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",
            "reference/010editor/Pkgstream_2WIRE_SP.bt",
        ),
        open_questions=(),
    ),
    0x26: RuntimeHandlerStub(
        symbol="demarshall_2sp_script",
        subsystem="lib2sp",
        effect_class="stage_buffer",
        install_action="stage",
        install_comment=(
            "Stream script body into a heap buffer; lib2sp_close_script finalizes and hands off "
            "to an indirect runner (fork/exec class — symbol still to rename in Ghidra)."
        ),
        notes="SCRIPT TLV 0x26.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=("Indirect runner symbol at close (rename in Ghidra).",),
    ),
    0x27: RuntimeHandlerStub(
        symbol="demarshall_2sp_path",
        subsystem="lib2sp",
        effect_class="fs_op",
        install_action="dispatch",
        install_comment="Shared fall-through with 0x28 to demarshall_2sp_path; same jump-table FS follow-up.",
        notes="See 0x07.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=(),
    ),
    0x28: RuntimeHandlerStub(
        symbol="demarshall_2sp_path",
        subsystem="lib2sp",
        effect_class="fs_op",
        install_action="dispatch",
        install_comment="Shared fall-through with 0x27 to demarshall_2sp_path; same jump-table FS follow-up.",
        notes="See 0x07.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=(),
    ),
    0x29: RuntimeHandlerStub(
        symbol="demarshall_2sp_move",
        subsystem="lib2sp",
        effect_class="fs_op",
        install_action="move",
        install_comment="Move ladder step (0x29 / 0x2A / 0x2B share demarshall_2sp_move in export).",
        notes="See 0x08.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=(),
    ),
    0x2A: RuntimeHandlerStub(
        symbol="demarshall_2sp_move",
        subsystem="lib2sp",
        effect_class="fs_op",
        install_action="move",
        install_comment="Move ladder step; see 0x29.",
        notes="See 0x08.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=(),
    ),
    0x2B: RuntimeHandlerStub(
        symbol="demarshall_2sp_move",
        subsystem="lib2sp",
        effect_class="fs_op",
        install_action="move",
        install_comment="Move ladder step; see 0x29.",
        notes="See 0x08.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=(),
    ),
    0x2F: RuntimeHandlerStub(
        symbol="demarshall_2sp_file",
        subsystem="lib2sp",
        effect_class="stream_to_path",
        install_action="copy",
        install_comment="PATH_FILE wire type (0x2F); same FILE demarshaller and streaming write path as 0x01/0x03.",
        notes="PATH_FILE.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=(),
    ),
}

# Named follow-ups after demarshall in lib2sp_payload_data (README summary).
JUMP_TABLE_FOLLOWUP: List[RuntimeHandlerStub] = [
    RuntimeHandlerStub(
        symbol="lib2sp_do_mkdir",
        subsystem="lib2sp",
        effect_class="fs_op",
        install_action="mkdir",
        install_comment="Jump-table target: create directory on target rootfs after successful demarshall.",
        notes="vtable-style slot; opcode→slot map incomplete in repo.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=("Opcode -> slot mapping dump not yet in repo.",),
    ),
    RuntimeHandlerStub(
        symbol="lib2sp_do_sym_link",
        subsystem="lib2sp",
        effect_class="fs_op",
        install_action="link",
        install_comment="Jump-table target: create symlink (lib2sp_do_sym_link) on installed rootfs.",
        notes="Symlink path.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=(),
    ),
    RuntimeHandlerStub(
        symbol="lib2sp_do_copy_file",
        subsystem="lib2sp",
        effect_class="fs_op",
        install_action="clone",
        install_comment=(
            "Jump-table target: copy an existing on-disk file to another path on the rootfs "
            "(not streaming bytes from the .pkgstream blob)."
        ),
        notes="Rootfs-to-rootfs copy.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=(),
    ),
    RuntimeHandlerStub(
        symbol="lib2sp_do_payload_tlv",
        subsystem="lib2sp",
        effect_class="stream_to_path",
        install_action="copy",
        install_comment=(
            "Re-enter streaming TLV writer: chunk FILE or SCRIPT body bytes from carrier into "
            "open file or script buffer."
        ),
        notes="Re-entrant from jump table.",
        evidence=("output/ghidra_mcp_lib2sp_10_5_3_527064/README.md",),
        open_questions=(),
    ),
]


def install_runtime_hint_dict(wire_type: int) -> Optional[Dict[str, str]]:
    """
    Ghidra ``lib2sp_payload_data`` install-phase row: ``install_action`` (one token),
    ``install_comment`` (verbose, tooltip-style), ``symbol``, ``effect_class``, ``subsystem``;
    or ``None`` if unknown / prefix-only in the export.
    """
    stub = INSTALL_TLV_DEMARSHALL.get(wire_type)
    if stub is None:
        return None
    return {
        "symbol": stub.symbol,
        "effect_class": stub.effect_class,
        "subsystem": stub.subsystem,
        "install_action": stub.install_action,
        "install_comment": stub.install_comment,
    }


def install_runtime_hint_summary(wire_type: int) -> str:
    """Single-token ``install_action`` for narrow text tables (details in ``install_comment``)."""
    d = install_runtime_hint_dict(wire_type)
    if d is None:
        return ""
    return d.get("install_action") or ""


def stub_do_payload_tlv() -> None:
    """Placeholder for ``lib2sp_do_payload_tlv`` emulation — not implemented."""
    raise NotImplementedError(
        "Streaming FILE/SCRIPT install is device-local; see README in "
        "output/ghidra_mcp_lib2sp_10_5_3_527064/ and lib2sp_do_payload_tlv.c export."
    )


def stub_payload_data() -> None:
    """Placeholder for ``lib2sp_payload_data`` state machine — not implemented."""
    raise NotImplementedError(
        "Install TLV dispatch is device-local; see INSTALL_TLV_DEMARSHALL and "
        "output/ghidra_mcp_lib2sp_10_5_3_527064/lib2sp_payload_data.c."
    )
