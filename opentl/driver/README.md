# `opentl.driver` — kernel-shaped API

This subpackage re-exports **read-path shaped** pieces of OpenTL: virt→phys BBM types and
builders, hole handling, sector/page layout constants, virt-disk byte assembly (`OpenTL` /
`extract_opentla4`), **`LogicalOpenTLSession`** (prefix + `BlockMapBuild` + `replace_block_map`),
spare-derived geometry (`tl_geometry_from_flat_spare`), and MTD-relative physical constants
(`infer_tl_mount_nand_logical_offset`, page sizes from `PACE_DEFAULT`).

## Host modules (BBM / chains / NTL — import explicitly)

| Module | Role |
|--------|------|
| `opentl.bbm_chain` | Virtual scan summary, chain-aware infer/apply on `LogicalOpenTLSession` |
| `opentl.opentla4_volume` | NTL / linear / BBM read models for the rw slice |
| `opentl.ext2_probe` | Minimal Dissect mount probe for chain inference |
| `opentl.nand_bootstrap` | Physical NAND translate + OpenTL attach (paths owned by caller) |
| `opentl.registry_hooks` | `FsRegistry`-aware helpers (lazy `boardfs` types) |
| `opentl.nand_pipeline` | Translate + BBM + extract orchestration (`NandPipeline`, `nand`) |
| `opentl.tl_mount` | Offline BBM via **`kernel_replay_v1`** + CLI (`mount_flash_image`, …; full flat spare) |
| `opentl.nand_translate` | Raw dump → logical plane files |
| `opentl.mtd_scanner` | Embedded `mtdparts=` string scan in dumps |

Package root `import opentl` loads **only** this facade (plus the `opentl.driver` submodule);
it does **not** import `nand_pipeline` or `tl_mount` so lightweight tooling avoids that graph.

## Public TL / BBM API

Use these instead of importing `opentl.tlpart_bbm_assembly`, `opentl.virt_page_table`, or
`open_tl.extract_virtual_disk_bytes` from higher layers. **boardfs** holds `FsRegistry` and
composes host modules; **paceflash** imports **boardfs** only.

| Name | Role |
|------|------|
| `LogicalOpenTLSession` | Canonical prefix + `BlockMapBuild`; `replace_block_map`, `virtual_tl_byte_stream()` (primary table), `extract_virtual_disk_bytes`, chain-aware helpers |
| `virtual_tl_byte_stream_from_logical_plane(linear_prefix_bytes, map)` | Public shim: same bytes as `LogicalOpenTLSession.from_linear_prefix_bytes(...).virtual_tl_byte_stream()` |
| `infer_chain_aware_tl_scan(...)` | Heuristic (`tlpart_tl_scan_bytes` vs linear `tlpart`) for when to rebuild scan with spare chains |
| `apply_chain_aware_flat_oob` (on session) | Full-disk materialization under chain-aware page table; used by `boardfs.apply_chain_aware_virtual_tl_scan` → `opentl.bbm_chain` |
| `verify_page_require_spare_xsum` / `verify_page_all` (`opentl.spare_verify`, re-exported) | Optional **`verify_page`** predicates for `extract_virtual_disk_bytes_chain_aware` (P2 xsum gate vs `ntl_read_verify_phy_spare`) |

Disklabel **parsing** (`enumerate_tl_slices_from_tlpart_mtd_bytes`, slice types) stays in `opentl.tldisk`.
