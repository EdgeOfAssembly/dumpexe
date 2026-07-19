# Sourcer listings for ICON

Generated with **Sourcer 8.01** via `SOURCER/run_sr.sh`.

| File | Source | Size (approx) |
|------|--------|----------------|
| `ICON.LST` | ICON.EXE | ~14k lines |
| `ICON0.LST` | ICON0.OVL | ~16k lines |
| `ICON1.LST` | ICON1.OVL | ~27k lines (gameplay) |
| `ICON2.LST` | ICON2.OVL | ~11k lines |
| `*.SDF` | Sourcer session data | |

Regenerate:

```bash
cd ../../SOURCER && ./run_sr.sh all
```

### Already confirmed in ICON.LST / ICON1.LST

- `DS:[206C]` — far/near ptr used with `les di` / scroll (`rep movsw`)
- `DS:31D4` — map table (`data_179`)
- FCB random block-read remarks
- `rep movsw` blit paths

Cross-check with live `mem_dumps/` and `dummy/icon_dummy.asm`.
