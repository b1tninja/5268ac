"""
**pkgd** / **pkgc** / **libpkg_*** and **httpd** / **cwmd** edges — stubs only.

Evidence-backed strings and PLT thunks (no invented RPC layouts):

* ``pkgd`` calls ``lib2sp_simple_unpack``; staging under ``/tmp/pkgspool``; strings such
  as ``deferred_upg.sh`` appear in the binary corpus.
* ``httpd`` / ``cwmd`` link ``libpkg_client.so.0`` / ``libpkg_common.so.0``; upgrade path
  includes FIFO ``write`` queues toward ``pkgd``-side handling.

See ``reference/firmware_upgrade_process.md`` and
``output/ghidra_httpd_upgrade_chain_evidence.json`` for the collected chain notes.
"""

from __future__ import annotations


def stub_pkgd_unpack_chain() -> None:
    """Placeholder: ``pkgd`` → ``lib2sp_simple_unpack`` → ``lib2sp_install_data``."""
    raise NotImplementedError(
        "Finish pkgd reanalysis in Ghidra; see output/ghidra_mcp_lib2sp_10_5_3_527064/README.md "
        "and reference/firmware_upgrade_process.md."
    )


def stub_httpd_pkg_fifo() -> None:
    """Placeholder: web/mgmt path → ``libpkg_client`` → ``pkgd`` (FIFO vs RPC nuances)."""
    raise NotImplementedError(
        "See output/ghidra_httpd_upgrade_chain_evidence.json and "
        "reference/firmware_upgrade_process.md §1–3."
    )
