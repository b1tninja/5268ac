# 5268ac reference index

Offline reverse-engineering notes for Pace **5268AC-class** firmware, OpenTL NAND, and tooling. Paths are relative to this directory unless noted.

## OpenTL / NAND read path

| Doc | Topic |
|-----|--------|
| [opentl.md](opentl.md) | Boot stack, `opentla*` slices, U-Boot vs Linux |
| [opentl_kernel_ghidra.md](opentl_kernel_ghidra.md) | Full kernel driver symbol table, spare/ECC, §7 routines |
| **[ghidra_ntl_rw_opentla4_mcp.md](ghidra_ntl_rw_opentla4_mcp.md)** | **`opentla4` ptype 17**, NTL mode-2, paceflash port status |
| **[archive/ghidra_ntl_mcp_2026-05-20.md](archive/ghidra_ntl_mcp_2026-05-20.md)** | Archived Ghidra MCP session log (May 2026) |
| [ghidra_opentla4_disk_layout_mcp.md](ghidra_opentla4_disk_layout_mcp.md) | Sector vs virt vs NAND coordinate spaces |
| [ghidra_boardfs_bbm_readpath.md](ghidra_boardfs_bbm_readpath.md) | `ntl_read_page`, BBM vs linear, parity roadmap |
| [mcp_kernel_gap_matrix.md](mcp_kernel_gap_matrix.md) | Python vs kernel callee gaps |
| [spare64_bbm_field_map.md](spare64_bbm_field_map.md) | 64-byte OOB field offsets |
| [layers_unand_uboot_opentl_boardfs_paceflash.md](layers_unand_uboot_opentl_boardfs_paceflash.md) | Package stack diagram |
| [kernel_python_regions.md](kernel_python_regions.md) | `#region kernel: 0x…` conventions |
| [kernel_offline_contract.md](kernel_offline_contract.md) | Explicit layout / no-heuristic contract |

## paceflash / boardfs

| Doc | Topic |
|-----|--------|
| [paceflash.md](paceflash.md) | **`ls`** / **`cat`** / **`shell`** on opentla4 ext2; **`--debug`** inventory |
| [boardfs.md](boardfs.md) | `FsRegistry`, BBM attach, **`ext2_dissect`**, **`ext2_path`**, `assemble_opentla4_volume` |

## SquashFS / upgrade / pkgstream

| Doc | Topic |
|-----|--------|
| [ghidra_squashfs_flash_read_gap_mcp.md](ghidra_squashfs_flash_read_gap_mcp.md) | ext2-embedded squash vs partition grep |
| [firmware_upgrade_process.md](firmware_upgrade_process.md) | Carrier install path |
| [ghidra_upgrade_write_path_532678.md](ghidra_upgrade_write_path_532678.md) | Write path evidence |
| [pkgstream.md](pkgstream.md) | `.pkgstream` TLV layout |

## Tooling

| Doc | Topic |
|-----|--------|
| [tools.md](tools.md) | corpus indexing, lib2spy, paceflash, uImage, vmlinux-to-elf |
| [010editor/README.md](010editor/README.md) | Binary templates for NAND / pkgstream |

## Ghidra MCP exports (lib2sp)

| Doc | Topic |
|-----|--------|
| [ghidra_mcp_lib2sp_11_5_1_532678/README.md](ghidra_mcp_lib2sp_11_5_1_532678/README.md) | 11.5.1.532678 lib2sp decompiles |
| [ghidra_mcp_lib2sp_10_5_3_527064/README.md](ghidra_mcp_lib2sp_10_5_3_527064/README.md) | 10.5.3.527064 lib2sp decompiles |
