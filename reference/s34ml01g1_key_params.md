# S34ML01G1 — key on-die parameters (5268AC / Pace context)

Primary evidence for this repo’s **128 MiB large-block NAND** capture is the **serial / kernel log** and **`hardware.md`**, not an attached PDF. Use a full datasheet for timing, AC/DC, and exact **Read ID** tables when available.

## Agreed geometry (PACE class, `fwupgrade.txt` + `hardware.md`)

| Parameter | Value |
|-----------|------:|
| Total capacity (data plane) | 128 MiB (**134217728** B) |
| Erase block | **128** KiB (**131072** B) |
| Page (main) | **2048** B |
| Spare (OOB) per page | **64** B |
| Pages per erase block | **64** |
| Erase blocks | **1024** |
| Full reader image (inline 2048+64) | **138412032** B = **65536 × 2112** |
| Spare-only aggregate | **4194304** B |

## Flash ID (kernel)

- **`BRCM NAND flash device: nand0, id 0x01f1`** (`fwupgrade.txt`, early Linux).
- Bootloader may print **Spansion SO30ML01G** family string; TSOP label **S34ML01G1** is the same **1 Gbit** role — see **`hardware.md`**.

## Datasheet TODO (when `reference/pdfs/S34ML01G1.PDF` is added)

- Confirm **Read ID** command output vs **`0x01F1`**.
- Confirm **bad block marker** in factory **spare** (first byte of spare / first page of block) for generic SLC NAND — **OpenTL** on this platform also uses vendor spare layout; see **`spare64_bbm_field_map.md`**.
