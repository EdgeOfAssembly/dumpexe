# Sourcer 8.01 (V Communications) — batch RE helper

Installed under `SOURCER/` for offline multi-pass disassembly of DOS MZ binaries.
Complements **dumpexe** (static/sim) and **DOSBox debugtrace** (live dumps).

## Help

```bash
cd SOURCER
dosbox . -c "sr -? 2>&1 > loki.txt" -c "exit"
# → LOKI.TXT
```

```
sr [filename|defname] [-d|-e|-h|-j|-l|-n|-n1|-s|-v|-x|-w|-2|-?]
  -n / -n1  no direct screen writes (use under DOSBox)
  -x        no display output
```

**Interactive:** `sr` alone opens the menu.  
**Batch:** use a `.DEF` with **`Go`** on its own line (column 1), **CRLF** line endings.

## Batch ICON

```bash
./run_sr.sh icon     # ICON.EXE  → ICON.LST
./run_sr.sh icon0    # ICON0.OVL
./run_sr.sh icon1    # ICON1.OVL (gameplay)
./run_sr.sh icon2
./run_sr.sh all
./run_sr.sh help
```

Copies binaries from `games/icon-quest-for-the-ring/ICON/`, runs  
`sr ICON.DEF -n -x` under DOSBox, writes:

| Output | Meaning |
|--------|---------|
| `ICON.LST` | Multi-pass listing |
| `ICON.SDF` | Sourcer data file |

Also copied to `games/icon-quest-for-the-ring/sourcer-out/`.

## DEF requirements (easy to get wrong)

1. **CRLF** (`\r\n`) — LF-only `.DEF` is ignored; `Go` never runs.  
2. Control lines start in **column 1** (`Input filename = ...`).  
3. End section 1 with **`Go`**.  
4. Prefer short 8.3 names in the SOURCER directory.

Example minimal DEF:

```
Input filename     = ICON.EXE
Output filename    = ICON.LST
Format             = LST
Code style         = exe
Passes             = 5
uP                 = 8088
Go
```

## Role vs dumpexe

| Tool | Strength |
|------|----------|
| **Sourcer** | Multi-pass code/data split, labels, INT remarks, LST/ASM |
| **dumpexe** | Modern CLI, CFG, sim, interrupt DB, automation |
| **DOSBox debugtrace** | Live FCB/VRAM/DS dumps |

Use Sourcer listings to label addresses (`206C`, `31D4`, draw loops), then confirm live with dumps and re-implement in the dummy ASM.
