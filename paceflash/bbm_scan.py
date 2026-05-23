"""Deprecated: use :mod:`boardfs` / :func:`boardfs.apply_chain_aware_virtual_tl_scan`."""

from boardfs.tl_chain import (
    apply_chain_aware_virtual_tl_scan,
    bbm_virtual_scan_summary,
    infer_chain_aware_virtual_tl_scan,
)

__all__ = [
    "apply_chain_aware_virtual_tl_scan",
    "bbm_virtual_scan_summary",
    "infer_chain_aware_virtual_tl_scan",
]
