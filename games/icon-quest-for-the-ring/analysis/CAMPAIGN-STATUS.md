# ICON RE campaign status

**Updated:** 2026-07-30T00:40Z
**Checkpoint:** `checkpoint/20260729T212940Z-icon-full-re` @ e410c23 (+ pending FEATURE commits)

## Goals
1. Full RE → UASM rebuild of ICON
2. Professionalize dumpexe (CLI RE)

## Checklist (plan)
- [x] Checkpoint git; inventory; pmem seed
- [x] Fingerprint DB (`analysis/fingerprint/mt_fingerprint_db.json`, 60 matches)
- [x] Static suite complete (dumpexe headers/strings, r2 static, Ghidra project all 4 MZ)
- [x] Dynamic play path (title → legend → CGA overworld under DOSBox+Xmux)
- [x] Jump-table + function map (`function_map.json` 83 procs; Ghidra labels applied)
- [x] UASM rebuild + make test + push (icon_dummy → DUMMY.COM runs play terrain)

## Evidence paths
| Gate | Path |
|------|------|
| Fingerprint | `analysis/fingerprint/mt_fingerprint_db.json` |
| Function map | `analysis/function_map.json`, `FUNCTION-MAP.md` |
| Ghidra labels | `analysis/ghidra/LABELS-APPLIED.md` |
| Play path | `analysis/dynamic/playpath/` |
| Dummy run | `analysis/dynamic/dummy-run/dummy2-t*.png` |
| dumpexe tests | `make test` → 8/8 |
| Spice86 | `analysis/dynamic/spice86/` |

## SPECTATOR
```
SPECTATOR: xmux attach icon-re --no-reconnect
```

## FIXUP: Ghidra label addresses
- v1.0 used file_offset (+0x200 wrong)
- v1.1 image_offset; CheckLabels 83/83 ok
