"""
On-device **pkgstream / lib2sp** semantics — **stubs and registries only**.

The offline tools (:mod:`lib2spy.pkgstream`, :mod:`lib2spy.pkgstream_carves`) parse, verify,
and carve by **magic scan**. They **do not** emulate ``lib2sp_install_data``,
``lib2sp_payload_data``, or ``pkgd``.

**Read first**

* ``opentl/pkgstream_format_lib2sp.md`` — TLV wire + dual dispatch tables.
* ``output/ghidra_mcp_lib2sp_10_5_3_527064/README.md`` — Ghidra export for ``10.5.3.527064``.
* ``reference/pkgstream.md`` §10 — runtime narrative (scripts, SquashFS bytes vs mount).
* ``reference/firmware_upgrade_process.md`` — ``httpd`` / ``cwmd`` / ``pkgd`` chain.

**Exports**

* ``INSTALL_TLV_DEMARSHALL`` — wire opcode → install **action** + Ghidra ``demarshall_2sp_*`` symbol (install phase).
* ``JUMP_TABLE_FOLLOWUP`` — post-demarshall FS helpers (names from README).
* ``TLV_RUNTIME_REGISTRY`` — same mapping as ``INSTALL_TLV_DEMARSHALL`` (stable alias for tools/tests).
* ``trace_prefix_tlv_chain`` / ``trace_pkgstream_path`` — prefix TLV **dry-run** trace (``tlv_dry_run``); CLI: ``python -m lib2spy.pkgstream_runtime <file>``.
"""

from lib2spy.pkgstream_runtime.lib2sp_dispatch import (
    INSTALL_TLV_DEMARSHALL,
    JUMP_TABLE_FOLLOWUP,
    install_runtime_hint_dict,
    install_runtime_hint_summary,
    stub_do_payload_tlv,
    stub_payload_data,
)
from lib2spy.pkgstream_runtime.lib2sp_embedded_images import describe_offline_vs_runtime
from lib2spy.pkgstream_runtime.lib2sp_script_path import stub_close_script_runner
from lib2spy.pkgstream_runtime.models import EffectClass, RuntimeHandlerStub, Subsystem
from lib2spy.pkgstream_runtime.pkg_orchestration import (
    stub_httpd_pkg_fifo,
    stub_pkgd_unpack_chain,
)
from lib2spy.pkgstream_runtime.tlv_dry_run import trace_pkgstream_path, trace_prefix_tlv_chain

# Alias for callers that expect a single "registry" name.
TLV_RUNTIME_REGISTRY = INSTALL_TLV_DEMARSHALL

__all__ = [
    "EffectClass",
    "INSTALL_TLV_DEMARSHALL",
    "JUMP_TABLE_FOLLOWUP",
    "TLV_RUNTIME_REGISTRY",
    "RuntimeHandlerStub",
    "Subsystem",
    "describe_offline_vs_runtime",
    "install_runtime_hint_dict",
    "install_runtime_hint_summary",
    "stub_close_script_runner",
    "stub_do_payload_tlv",
    "stub_httpd_pkg_fifo",
    "stub_payload_data",
    "stub_pkgd_unpack_chain",
    "trace_pkgstream_path",
    "trace_prefix_tlv_chain",
]
