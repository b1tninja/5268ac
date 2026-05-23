"""
Assemble OpenTL virtual TL disk bytes (compatibility shim for :meth:`LogicalOpenTLSession.virtual_tl_byte_stream`).
"""

from __future__ import annotations

from opentl.logical_opentl_session import LogicalOpenTLSession
from opentl.tl_bbm import BlockMapBuild


#region kernel: 0x80289170
# Shim delegating to LogicalOpenTLSession.virtual_tl_byte_stream (same as legacy tlpart_bbm_assembly hook)
def virtual_tl_byte_stream_from_logical_plane(
    logical_plane: bytes,
    block_map: BlockMapBuild,
    *,
    max_virt_bytes: int | None = None,
) -> bytes:
    """
    Same as :meth:`~opentl.logical_opentl_session.LogicalOpenTLSession.virtual_tl_byte_stream`
    using ``logical_plane`` + ``block_map``.
    """
    sess = LogicalOpenTLSession.from_linear_prefix_bytes(bytes(logical_plane), block_map)
    return sess.virtual_tl_byte_stream(max_virt_bytes=max_virt_bytes)


#endregion
