# Ghidra labels for ICON function map

## Addressing (critical)

Ghidra MZ load image is at **`1000:0000` = file_offset − 0x200** (header is separate).

| Field | Use for Ghidra labels? |
|-------|------------------------|
| `image_offset` / IP | **Yes** — CODE address |
| `file_offset` | No (that is dumpexe/file view; +0x200 vs Ghidra) |

**v1.0 bug:** `ApplyFunctionMap` placed labels at `file_offset` → all 83 were +0x200 wrong.  
**v1.1 fix:** use `image_offset` column; clear stale labels; `CheckLabels` proves bytes.

## Status (re-applied + verified 2026-07-30)

| Program | Applied | CheckLabels ok | fail | missing |
|---------|---------|----------------|------|---------|
| ICON.EXE | 39 | 39 | 0 | 0 |
| ICON0.OVL | 14 | 14 | 0 | 0 |
| ICON1.OVL | 17 | 17 | 0 | 0 |
| ICON2.OVL | 13 | 13 | 0 | 0 |
| **Total** | **83** | **83** | **0** | **0** |

### ICON.EXE spot-checks (bytes at label address)

```
SPOT OK jt_01_pascal_near @ 1000:00d5 bytes=558bec
SPOT OK pascal_mt_startup_call__0200 @ 1000:0000 bytes=e82865
SPOT OK rtl_error_string__02EE @ 1000:00ee bytes=506173   ("Pas")
```

Log: `{SCRATCH}/ghidra/reapply-check.log` (session) and headless output above.

## Scripts
- `ApplyFunctionMap.java` — apply at image_offset; removes stale names first
- `CheckLabels.java` — address + prologue/string byte match; throws on fail
- `labels.tsv` v1.1 columns: image, file_offset, image_offset, ip, ghidra_name, tier, kind, role, prologue_hex

## Sources
- `../function_map.json` v1.1 (`addressing` block documents the fix)
- Project: `icon_project.gpr`
