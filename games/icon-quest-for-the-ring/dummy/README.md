# ICON dummy stub (v3)

DOS COM that implements the **ICON1 terrain draw path** in assembly.
PNG / full-disk decode is **out of scope** here — once this blit matches, a host
tool can reuse the same rules.

## Modes

| Mode | Data files | Camera default | Purpose |
|------|------------|----------------|---------|
| **Parity** | `STAMPS.BIN` + `MAPRT.BIN` | (0,0) | Near byte-id with live ICON B800 (terrain) |
| **File** | `BA.DAT` [+`BB.DAT`] + `LA.MAP` | (7,75) | Work from on-disk assets (BA leading `5Ah` stripped) |

Parity dumps are copies of DOSBox `mem_dumps` (runtime `DS:207A` / `DS:31D4`).
Install them next to the COM (see Makefile `install-rt`).

## Draw rules (ICON1)

```
clear B800 to 00,00
for sr in 0..3:
  for sc in 0..18:
    id = map[(cam_x+sc)*100 + (cam_y+sr)]   ; full byte, mod 192
    blit 2×6 char,attr cells at (col=1+2*sc, row=2+6*sr)
  ; right edge (live col 39): left cell of stamp at map x=cam_x+19
```

Stamp cells in the bank are **char,attr** (B800 order).  
On-disk `BA.DAT` is `5Ah` + char,attr stream → bake = drop first byte.

## Build

```bash
cd games/icon-quest-for-the-ring/dummy
make && make install          # COM → ICON/
make install-rt               # STAMPS.BIN + MAPRT.BIN from mem_dumps/
```

## Run

From `ICON/`:

```text
icon_dummy.com
```

Keys: **←↑↓→** camera, **R** reset, **ESC** quit.  
DOS 8.3 name → dumps as `ICON_D1_...`.

**Note:** Boot text is cleared when mode 01h starts (BIOS wipe). On **ESC**, mode 03 returns and prints whether the run was **parity** or **file**. Confirm loads via `game_trace.log` (`STAMPS.BIN` / `MAPRT.BIN` FCB lines) or by matching `expected_b800_parity.bin`.

## Expected match

| Compare | Result |
|---------|--------|
| Parity blit vs live `ICON_g0013_…0008` | **1988/2000** bytes; **100% terrain** (player sprite cols 7–9 bottom only) |
| `expected_b800_parity.bin` | Offline gold for parity mode |
| File mode vs live overworld | Not expected equal (runtime map ≠ `LA.MAP`) |

```bash
# after Ctrl+F10 dump in parity mode:
cmp -l ICON/screen_dumps/ICON_D1_*m01*0002.bin dummy/expected_b800_parity.bin | head
```

## Later (not this stub)

- MAP/BA file → PNG tools that **call the same blit rules**
- Load-time bake RE (`LA.MAP` → `MAPRT`, full `207A` build) when needed for file mode fidelity
