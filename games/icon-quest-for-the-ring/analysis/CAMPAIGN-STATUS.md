# ICON RE campaign status

**Started:** 2026-07-29  
**Checkpoint:** `checkpoint/20260729T205337Z-icon-re-campaign` @ dumpexe `d9aee76`

## Goals
1. Full RE → UASM rebuild of ICON
2. Professionalize dumpexe (CLI RE)

## Done this session
- [x] pmem orient
- [x] File inventory + SHA256 (`analysis/INVENTORY.md`)
- [x] GOAL.md
- [x] dumpexe `-a --callgraph --subroutines` on ICON.EXE + ICON0/1/2.OVL
- [x] Git checkpoint before campaign

## dumpexe subroutine counts
| Binary | Subs extracted |
|--------|----------------|
| ICON.EXE | 139 |
| ICON0.OVL | 94 |
| ICON1.OVL | 58 |
| ICON2.OVL | 101 |

## Confirmed (static)
- All four MZ: header 200h, CS:IP 0:0, 0 relocs, Pascal MT+ string
- Entry: `E8 xx xx` CALL runtime then segment table words at CS+3
- ICON.EXE strings: `ICON 1.1`, `icon0.ovl`, `Pascal MT+ Error`

## Next
- [ ] r2 deep dive + xrefs on chain loader
- [ ] Ghidra 12 project for all 4 images
- [ ] DOSBox+Xmux smoke (use existing auto scripts carefully)
- [ ] dumpexe FEATURE backlog from gap analysis
- [ ] Extend dummy/ UASM toward real entry/runtime

## Outputs
- `analysis/dumpexe/{ICON,ICON0,ICON1,ICON2}/full.txt` + `subs/`
- `analysis/INVENTORY.md`
- `analysis/DUMPEXE-GAP-ANALYSIS.md` (explore agent)
