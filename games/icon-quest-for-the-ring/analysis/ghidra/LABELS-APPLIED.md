# Ghidra labels for ICON function map

## Status (applied headless 2026-07-30)

| Program | Labels applied | Skipped |
|---------|----------------|---------|
| ICON.EXE | 39 | 0 |
| ICON0.OVL | 14 | 0 |
| ICON1.OVL | 17 | 0 |
| ICON2.OVL | 13 | 0 |
| **Total** | **83** | **0** |

Script: `ApplyFunctionMap.java` + `labels.tsv` via Ghidra 12 `analyzeHeadless`.

```
ApplyFunctionMap.java: ICON.EXE applied=39 skipped=0
ApplyFunctionMap.java: ICON0.OVL applied=14 skipped=0
ApplyFunctionMap.java: ICON1.OVL applied=17 skipped=0
ApplyFunctionMap.java: ICON2.OVL applied=13 skipped=0
```

## Sources
- Machine-readable map: `../function_map.json` (83 procedures)
- TSV: `labels.tsv`
- Per-image symbol lists: `symbols_ICON_EXE.txt` etc.
- Jump table list: `jump_table_labels.txt`
- Project: `icon_project.gpr` (x86:LE:16:Real Mode)

## Summary from function_map.json
```
procedure_count=83
jump_table_slots=23
fingerprint_matches=60
tier A/B/C = 60/21/2
```
