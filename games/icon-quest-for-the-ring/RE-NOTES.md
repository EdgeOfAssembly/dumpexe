# ICON: Quest for the Ring — reverse-engineering notes

**Target:** `ICON/` (≈198 KB payload, 43 files; directory mtimes show 1980-01-01 FAT epoch)  
**Tooling:** `dumpexe` from repo root  
**Status:** reconnaissance complete; not yet reassemblable  

---

## Identity

| Field | Value |
|--------|--------|
| Title | ICON: Quest for the Ring |
| Version string | `ICON 1.1` |
| Authors | Neal White III, Rand E. Bohrer |
| Publisher | Macrocom, Inc. |
| Year | 1984 (`(c) 84 - NW & RB`) |
| Runtime | **Pascal MT+** (Digital Research) — string `Pascal MT+ Error` |
| Display | CGA required; hybrid text/graphics; README notes custom 8×8 font vs stock CGA |
| DOS I/O | Heavy **FCB** use (DOS 1.x style); needs `FCBS=10` in `CONFIG.SYS` |

Wagner-inspired plot text lives mainly in **ICON0.OVL** (“LOVE AND THE SWORD”, dragon, Siglund/Siegfried, broken sword, etc.).

---

## File inventory

### Executables (MZ, shared memory model)

| File | Size | Role |
|------|------|------|
| `ICON.EXE` | 35328 | Boot / menu / save load / CGA check / copy-protect prompts → chains to `icon0.ovl` |
| `ICON0.OVL` | 31744 | Story / overworld / `dr.dat`+`sp.dat` assets → `icon1.ovl` |
| `ICON1.OVL` | 51712 | Main play / death messages / combat strings → `icon2.ovl` / back to `icon0.ovl` |
| `ICON2.OVL` | 24064 | Save game / score / help-ish UI strings |

All four are full MZ images with **identical** Pascal MT+ segment table at CS+3:

```
CS:[0003] = 0C80h  paragraphs  (data/code arena sizing)
CS:[0005] = 08B0h  paragraphs
CS:[0007] = 0090h  paragraphs  → stack size 0900h after SHL 4
CS:[0009] = 0000h
```

Entry is always:

```
CS:0000  CALL  <runtime>     ; near call into Pascal MT+ startup
CS:0003  <segment table>     ; NOT code — data after the 3-byte call
```

- **0 relocation entries** (single-segment style / self-contained image).  
- Header size **200h**, CS:IP **0000:0000**, SS:SP **0000:0080** (tiny bootstrap stack until runtime sets SS:SP).  
- These are **chain overlays** (load another whole EXE), not classic DOS relocatable overlays.

### Levels `L[A–G].{ADV,DAT,MAP}`

Seven levels **A–G**. Each has:

| Ext | Nature | Notes |
|-----|--------|--------|
| `.ADV` | ASCII CR/LF, ends `1Ah` | Level parameters (spawn/coords/flags); small (86–128 B) |
| `.DAT` | Same style as `.ADV` | Parallel parameter set (often object placements) |
| `.MAP` | Binary | Tilemap; sizes 3712–4736; common factors include **64×N** and **32×N** (likely 2-plane CGA or cell packing) |

Example `LA.ADV` (numbers only):

```
3 3
2 2
2880 2400
14 20
250
8
3 10
-1 … -1
86 67
```

### Mobs / entities `M[A–G].{ADV,DAT}`

ASCII records with **length-prefixed-looking names in binary assets**, free text here:

- Names: `Bat`, `Rat left/right`, `Poison_Mushroom`, `Snake`, `Dwarf`, `Kobold`, `Alligator`, …  
- Numeric fields: HP-like values, scores (`8000`, `6500`), flags, animation frame indices.

### Graphics / sprite banks

| File | Size | Notes |
|------|------|--------|
| `BA.DAT` / `BB.DAT` | 2304 each | Opaque binary; likely tile/charset banks |
| `DR.DAT` | 7168 | Named frames: health bar, man poses, weapons, mobs, items (`magic sword`, `red wand`, …) — **length-prefixed ASCII labels** embedded in blob |
| `SP.DAT` | 5376 | Same labeling scheme; overlapping set with DR plus snakes/dwarves/effects |

Referenced from ICON0 as `dr.dat` / `sp.dat`.

### Saves

- Pattern `ICON` + digit + `.GAM` (prompts for save number 0,1–9 and drive A/B/C).  
- Corrupt-save messages delete the file (“for your protection”).  
- Version gate: `ICON 1.1` / `Incompatible saved game`.

---

## Runtime / memory (from `--simulate` + disasm)

Pascal MT+ startup (IP `652Bh` in `ICON.EXE`):

1. Sum `CS + [3]+[5]+[7]+[9]` and compare to **PSP:[0002]** (mem top).  
2. On failure: print `OUT OF MEMORY` via INT 21h AH=09, `RETF` exit.  
3. On success: copy 100h bytes (PSP) to new DS arena, set DS/ES/SS/SP from the segment table, then continue into Pascal RTL + program.

`dumpexe --simulate` now follows the entry `CALL`, models PSP at `loadBase-10h`, and evaluates the mem check so this path is visible.

Near-jump dispatch table at **IP 0090h** (23× `E9` stubs) — likely Pascal procedure entry vectors after RTL init.

---

## DOS services observed

FCB-era path (matches README `FCBS=10`):

| AH | Meaning (typical) | Evidence |
|----|-------------------|----------|
| 0Fh / 10h / 14h / 15h / 16h | FCB open/close/seq R/W/create | `mov ah` counts in image |
| 21h / 22h / 27h / 28h | FCB random / block R/W | + string `FCB Table Exhausted!` |
| 1Ah | Set DTA | near FCB block I/O |
| 09h | Print `$`-string | errors / banners |
| 06h | Direct console I/O | keyboard/CGA path |
| 2Ah–2Dh | Get/set date/time | possibly PRNG or copy-protect |

Handle-based INT 21h (3Ch/3Dh/…) is scarce; design is **pre-2.0 FCB**.

---

## Overlay graph

```
ICON.EXE  --loads-->  icon0.ovl  --loads-->  icon1.ovl
                         ^                      |
                         |                      v
                         +---------------- icon2.ovl
```

- Boot EXE only references `icon0.ovl`.  
- ICON0 → `icon1.ovl`.  
- ICON1 ↔ `icon2.ovl` / `icon0.ovl` (save UI / return).

---

## Copy protection / disk checks (strings)

- `This is an illegal copy of ICON` / `You should be ashamed of yourself!`  
- `Put the original game disk in floppy drive A or B & press the Space Bar.`  
- CGA gate: requires Color Graphics Adapter; suggests `MODE CO40`.  

Exact sector/key check not fully mapped yet; expect diskette fingerprint or file presence on “original” media.

---

## Recommended RE workflow (next steps)

1. **Static**  
   - Disassemble from jump table @ `0090h` and from Pascal main after startup (post-`65BAh` region).  
   - Map FCB open of `icon?.ovl`, `L?.MAP`, `*.GAM`.  

2. **Dynamic (DOSBox + debugger)**  
   - Break on INT 21h AH=0Fh/27h; log FCB filenames.  
   - Trace overlay load (likely EXEC or manual image replace).  

3. **Data tools**  
   - Parser for `.ADV`/`.DAT` line records.  
   - `.MAP` visualizer trying 64×N and 40×N CGA layouts.  
   - Extract named frames from `DR.DAT`/`SP.DAT` via length-prefixed labels.  

4. **Rebuild path**  
   - Dump each MZ to UASM with correct ORG / segment table.  
   - Replace overlay chain with file loads once entry + RTL understood.  
   - Later: C23 port of map/mob data + SDL CGA renderer.

---

## dumpexe bugs found while analyzing ICON

Fixed in-tree while working this title:

1. **`final_len == 0`** must mean a full 512-byte last page (was under-counting load image by 512 and false “extra bytes”).  
2. **Reloc “padding”** dumped the MZ header when `off_reloc=0` and `num_reloc=0`.  
3. **Relocs only loaded with `-r`**, so `--simulate` skipped fixups on reloc-bearing EXEs.  
4. **EXE load model**: DS/ES must be **PSP** (`loadBase - 10h`), not image base.  
5. **Simulator** walked into data after entry `CALL`; now follows near call/jmp/jcc and reads CS image + synthetic PSP for startup.

---

## Quick commands

```bash
# from repo root
./dumpexe games/icon-quest-for-the-ring/ICON/ICON.EXE
./dumpexe --simulate games/icon-quest-for-the-ring/ICON/ICON.EXE
./dumpexe -d games/icon-quest-for-the-ring/ICON/ICON.EXE | less
./dumpexe games/icon-quest-for-the-ring/ICON/ICON0.OVL
strings -n 5 games/icon-quest-for-the-ring/ICON/ICON*.OVL

# Static CFG + INT/string xrefs (preferred RE entry point)
./dumpexe --cfg-interesting --cfg-no-insns ICON/ICON.EXE | less
./dumpexe --cfg --cfg-max=20 ICON/ICON.EXE   # full dump truncated

# Simulate with INT21 breakpoints (file I/O when reached)
./dumpexe --simulate --max-insns=500000 --bp=int:21,ah=0F --bp=int:21,ah=27 ICON/ICON.EXE
```

### CFG snapshot (ICON.EXE)

- Entry `BB 0000`: only `call 652B` (Pascal MT+ startup).
- Jump table at `0090h` (~23× `E9` stubs) `[JMP-TABLE]`.
- INT opcodes forced as leaders (catches far-callable DOS helpers).

**Filename / I/O gold (pred AH + Pascal inline strings):**

| IP | Tags / meaning |
|----|----------------|
| `1CC6` / `1CE8` | `path:icon0.ovl` `overlay-name` — Pascal `call` / `db 9,"icon0.ovl"` |
| `1BF7` | `path:l?.map` `map-file` — level map name pattern |
| `1BCA` / `1BE2` | `path:.dat` / `path:.adv` |
| `1116` / `112B` | `path:ICON` / `path:.GAM` save naming |
| `1C31` | copy-protect message |
| `7A77` | **INT 21 AH=1A** set-DTA (**AH from pred**) |
| `7A84` | **INT 21 AH=27** FCB block-read, **DX=005C** → `FCB@DS:5C` (name filled at runtime) |
| `69FD` | `"FCB Table Exhausted!"` (matches README `FCBS=10`) |

Pascal MT+ strings are often **inline after CALL** (return addr = length-prefixed string), not `mov dx, offset`. FCB I/O uses the **default FCB at DS:005C**.

### Load graph

```bash
./dumpexe --cfg-interesting --cfg-no-insns --cfg-load-max=30 ICON/ICON.EXE
```

Emits reverse-pred chains from path/FCB seeds (e.g. `1CC6 icon0.ovl`, `1BF7 l?.map`, `7A84 FCB@DS:5C`).

### Data formats

See **[FORMAT-NOTES.md](FORMAT-NOTES.md)** for MAP/ADV/DAT layout hypotheses (64-wide tilemaps, ASCII ADV, sprite banks).

---

*Living document — extend as procedures and file formats are confirmed.*
