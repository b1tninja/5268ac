"""OpenTL-specific errors (BBM, NAND assembly)."""


class VirtBlockHoleError(ValueError):
    """Virtual erase block maps to no physical backing (kernel ``0xffffffff`` hole / unmapped slot)."""


class IncompleteBBMInferenceError(ValueError):
    """
    Reserved for callers that detect incomplete BBM inference without a usable
    :class:`~opentl.tl_bbm.BlockMapBuild`.

    :func:`~opentl.tl_mount.mount_flash_image` and :func:`~opentl.bbm_kernel_replay.build_block_map_from_kernel_mount_replay`
    raise :class:`ValueError` for missing spare, geometry mismatch, or empty replay results; load a
    captured map (``schema`` = :data:`~opentl.tl_bbm.SCHEMA_V1`) via :class:`~opentl.tl_bbm.BlockMapBuild`.from_dict when needed.
    """
