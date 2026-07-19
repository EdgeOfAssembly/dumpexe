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

### Confirmed landmarks (ICON / ICON0 / ICON1)

| Address | Meaning | Where |
|---------|---------|--------|
| `DS:206C` / `206E` | Offscreen text buffer far ptr | ICON.LST, ICON1 `les di` / `sub_81` |
| `DS:31D4` | MAP index table (`data_123` / `data_179`) | ICON1 `mov al,data_123[di]` @ `2F65`; draw strips `mov ax,31D4h` |
| `DS:207A` | Runtime stamp bank (192×24) | ICON1 `mov ax,207Ah` + `mul bx,18h`; ICON0 bake @ `0B54` |
| `DS:5DE4` | Stamp SI into blit | set before `call sub_83` |
| `DS:810C` / `810E` | Screen row / col for stamp dest | strip callers ~`9475` / `9483` |
| `DS:822C` / `8230` | Camera tile_x / tile_y | strip index math |
| **`sub_83` @ `2B9A`** | **2×6 terrain stamp** (`cx=6`, 2×`movsw`, stride `50h`) | ICON1.LST |
| **`sub_84` @ `2BCD`** | 2-row (half-height) stamp | ICON1.LST |
| **`sub_81` @ `2B71`** | Offscreen → display page (`cx=0FA0h` `rep movsw`) | ICON1.LST |
| `2D9A` | **Not** terrain draw — inside `sub_89` (entity remap) | corrected |
| ICON0 `sub_32` ~`0B17` | BA/BB bake: count byte + `N×24` char,attr → `207A` | confirmed |
| ICON0 ~`1209` | MAP RLE expand → `31D4` (`n-1` extras on high-bit runs) | confirmed |

Full write-up: `../FORMAT-NOTES.md` § “MAP → stamp draw” / BA bake / MAP RLE.

Cross-check with live `mem_dumps/` and `dummy/icon_dummy.asm` (`blit_viewport`).
