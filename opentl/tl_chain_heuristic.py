"""
Host heuristics for when to rebuild the virtual TL scan stream with spare-chain resolution.

Keeps imports free of boardfs (:class:`~boardfs.registry.FsRegistry`).
"""

from __future__ import annotations

from opentl.tldisk import buffer_has_tl_disklabel_anchor


#region kernel_adjacent infer_chain_aware_tl_scan
def infer_chain_aware_tl_scan(
    *,
    tlpart_tl_scan_bytes: bytes | None,
    linear_tlpart: bytes | None,
) -> bool:
    """
    Heuristic: auto-enable spare-chain BBM virtual-disk rebuild when linear ``tlpart`` shows
    filesystem magic but primary virt assembly is suspect.

    Cases:

    - **Zeroed virt head:** ``virt_to_phys_block`` holes zero the virtual label region while the
      linear plane still has payload (PACE-class full-chip dumps).
    - **Linear TL anchor only:** linear plane exposes a TL disklabel anchor BBM virt scan misses —
      enumerate-from-linear geometry vs BBM-assembled reads (``reference/ghidra_boardfs_bbm_readpath.md``).
    - **Linear squash not reflected in virt scan:** linear ``tlpart`` contains ``hsqs`` but the
      BBM-assembled :attr:`~boardfs.registry.FsRegistry.tlpart_tl_scan_bytes` buffer does not —
      primary page assembly omitted filesystem bytes the kernel finds via spare-chain reads.
    """
    if linear_tlpart is None or b"hsqs" not in linear_tlpart:
        return False
    if tlpart_tl_scan_bytes is None or len(tlpart_tl_scan_bytes) < 4096:
        return False
    if tlpart_tl_scan_bytes[:64] == b"\x00" * 64:
        return True
    if buffer_has_tl_disklabel_anchor(linear_tlpart) and not buffer_has_tl_disklabel_anchor(
        tlpart_tl_scan_bytes
    ):
        return True
    # Whole linear MTD partition exposes squash magic but assembled virt TL stream does not —
    # primary virt_to_phys map likely misses payload the kernel resolves via spare chains.
    if b"hsqs" not in tlpart_tl_scan_bytes:
        return True
    return False


#endregion


#region kernel_adjacent correlation_suggests_chain_aware_from_hits
def correlation_suggests_chain_aware_from_hits(
    *,
    strict_on_bbm_virt: bool,
    strict_on_linear: bool,
    strict_on_ext2_file: bool = False,
) -> bool:
    """Upgrade correlation: strict squash on linear/ext2 file view but not on BBM-assembled virt slice."""
    if strict_on_bbm_virt:
        return False
    if strict_on_linear:
        return True
    return strict_on_ext2_file


#endregion
