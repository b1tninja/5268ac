"""
OpenTL: **kernel-shaped driver** at import time, **host modules** on explicit paths.

**Logical plane** comes from :mod:`unand` (normalize, :class:`unand.plane.LogicalPlane`,
:data:`unand.geometry.PACE_DEFAULT`). **MTD layout** on dumps pairs :mod:`uboot` cmdline parsing
with the same ``mtdparts``→byte-offset model as :mod:`boardfs.flash` (logical-plane images).

**At package root** (``import opentl``): only :mod:`opentl.driver` is loaded — BBM, ``OpenTL`` /
virt slice assembly, errors, spare geometry hints, PACE-aligned page constants. This avoids
pulling :mod:`opentl.nand_pipeline` or :mod:`opentl.tl_mount` until you import them.

**Host workflows** (translate + BBM + extract, tl-mount CLI, TL disklabel slices, etc.)::

    from opentl.nand_pipeline import NandPipeline, nand
    from opentl.tl_mount import mount_flash_image, resolve_nand_logical_offset_for_mount
    from opentl.tldisk import enumerate_tl_slices, enumerate_tl_slices_auto_file

    from opentl import driver
    from opentl.driver import OpenTL, build_block_map_from_kernel_mount_replay

**Kernel RE cross-reference:** modules that mirror att-5268 OpenTL / NTL behavior bracket code with
``#region kernel: 0x…`` / ``#endregion`` (and ``#region kernel_adjacent`` for host glue). For
**hypothesis-only**, **debug-only**, or **test-support** blocks (not kernel fidelity), see
``reference/kernel_python_regions.md`` — *Non-kernel region tags*. Index and rules: same file.

"""

from __future__ import annotations

import opentl.driver as driver

for _name in driver.__all__:
    globals()[_name] = getattr(driver, _name)

__all__ = ["driver", *driver.__all__]
