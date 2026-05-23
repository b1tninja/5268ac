# Fixtures for 010 Editor templates

`synthetic_inline_2pages.bin` — **4224 bytes** (2 × 2112), inline **2048+64** layout. The first page spare begins at file offset **2048** and holds a small synthetic OpenTL-tagged row (`spare[4]=0x24`, phys/virt lows, page-in-block `5`, valid `spare[0x0F]` per `opentl.spare_layout.compute_spare_xsum`). Open in 010 Editor with `S34ML_NAND_inline_2112.bt` or `OpenTL_NAND_inline_2112.bt` and confirm the template tree matches these values.

Quick check from repo root:

```bash
python -c "from pathlib import Path; from opentl.spare_layout import parse_spare, xsum_matches; b=Path('reference/010editor/fixtures/synthetic_inline_2pages.bin').read_bytes(); s=b[2048:2112]; print(xsum_matches(s), parse_spare(s).virt_low16())"
```
