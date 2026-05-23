"""BBM linearize for raw tlpart label scan (stub; use tl_mount / bbm_kernel_replay for reads)."""

from __future__ import annotations

from typing import Any


#region hypothesis_only tl_bbm_linearize
def linearize_tlpart_bytes_for_label_scan(
    tlpart_bytes: bytes,
    *,
    bbm_descriptor: dict[str, Any] | None = None,
) -> bytes:
    """
    Return bytes suitable for :func:`opentl.tldisk.enumerate_tl_slices_from_bytes` label scan.

    Without ``bbm_descriptor``, returns input unchanged. Full spare→virt replay is not implemented here.
    """
    if bbm_descriptor is None:
        return tlpart_bytes
    raise NotImplementedError(
        "tl_bbm_linearize: use opentl.tl_mount / bbm_kernel_replay + NTL chain replay instead"
    )
#endregion


__all__ = ["linearize_tlpart_bytes_for_label_scan"]
