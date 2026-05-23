# Kernel-shaped offline contract (5268 tooling)

Host-side tools align with **how the kernel uses** NAND and MTD, not with silent heuristics that guess capture format.

| Layer | Contract |
|-------|-----------|
| **unand / uboot** | Geometry and `mtdparts` / env parsing are **clean-room** vs docs and printk; they are **not** kernel code replay. |
| **NAND packing** | **Explicit** `RawDumpLayout` / translate mode only. No `auto` in translate, carve, or inventory defaults. Optional offline hint: `python -m unand layout-detect`. |
| **opentl BBM (virt→phys)** | **Only** `BlockMapBuild.from_dict` (captured JSON) or `build_block_map_from_kernel_mount_replay` when implemented — no alternate “strategy” paths in mount/CLI. |
| **paceflash / boardfs** | MTD offsets apply on the **logical** data plane. Full-chip physical Pace images require an explicit `--nand-mode` (or library default `inline-2112` where documented). BBM attach uses the same map sources as above. |

See [layers_unand_uboot_opentl_boardfs_paceflash.md](layers_unand_uboot_opentl_boardfs_paceflash.md) for the full stack diagram and [ghidra_boardfs_bbm_readpath.md](ghidra_boardfs_bbm_readpath.md) for `*(remap+8)` scope.

**`opentla4` (rw):** BBM virt replay alone is insufficient; offline ext2 also needs **NTL mode-2** per-page assembly (**`boardfs.assemble_opentla4_volume`** → **`opentl.ntl_rw`**). On PACE **`S34ML01G1@TSOP48.BIN`**, this path mounts ext2 at **`1024`** and lists **`/`**; use **`paceflash ls`**, **`paceflash shell`**, or **`build_inventory(..., debug=True)`** — [ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md), [paceflash.md](paceflash.md).
