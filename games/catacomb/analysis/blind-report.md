# Blind RE report — `subject.exe`

**Binary:** `/tmp/grok-goal-c8d573d7f31d/implementer/blind-catacomb/subject.exe`  
**Tool:** `/usr/local/bin/dumpexe` 1.7 (Capstone yes)  
**Method:** dumpexe only (header, `--strings`, `--json`, `-d -o listing-agent.asm`, `--cfg-interesting --cfg-no-insns`). No source trees, no external Catacomb notes.

**Artifacts written here:**

| File | Source command |
|------|----------------|
| `header.txt` | `dumpexe subject.exe` |
| `strings.txt` | `dumpexe --strings subject.exe` |
| `report.json` | `dumpexe --json subject.exe` |
| `listing-agent.asm` | `dumpexe -d -o listing-agent.asm subject.exe` |
| `listing-agent.stderr.txt` | stderr: `listing: wrote listing-agent.asm (266 procs, 7423 insns)` |
| `cfg-interesting.txt` | `dumpexe --cfg-interesting --cfg-no-insns subject.exe` |

---

## 1. Identity / product

**Product name (from dumpexe Turbo Pascal auto-detect):** **Catacomb**.

Quoted from `header.txt` / `strings.txt` Turbo Pascal block:

```text
=== Turbo Pascal (auto) ===
Confidence:  97%
Compiler:    Turbo Pascal 5.5
…
Product:     Catacomb
Evidence:
  …
  - Catacomb UI help strings
  - rebuild-proven: MAKECAT.BAT with /usr/share/games/TP5.5 TPC.EXE
=== End Turbo Pascal ===
```

**Independent string evidence (no source needed):** length-prefixed UI copy describes a top-down fantasy action game:

- Function keys: Help, Sound, Controls, Game reset, Pause, Quit  
- Demo: “Watch the demo… Hit fire at the demo to begin playing.”  
- Combat: shot power / super shot, healing potion / body meter, spells, “nuke spell”, monsters  
- Assets: `VGAPICS.CAT`, `SOUNDS.CAT`, `DEMO.CAT`, `TOPSCORS.CAT`  
- HUD: Level / Score / Top; warp levels 1–99; high scores table  

There is **no** embedded title string like `"Catacomb"` in the extracted string table; product ID is **dumpexe’s classifier + UI/asset fingerprint**, not a literal product banner in the binary.

---

## 2. File format

| Field | Value |
|-------|--------|
| Format | MS-DOS **MZ EXE** (`file` + dumpexe `format: mz`) |
| File size | `21720h` = **136 992** bytes |
| Load image | `21320h` = 135 968 bytes |
| Header size | `0400h` = **1024** bytes |
| Relocations | **248** (`00F8h`), table at `001Ch` |
| Min extra paras | `0F00h` (3840) |
| Max memory | `AF000h` (716800) |
| Checksum | `0000h` |
| Overlay | `0000h` (primary EXE, not an overlay stub) |
| Entry (CS:IP) | **`0000:4285`** |
| Entry file offset | `04685h` (18053) |
| Entry image offset | `04285h` (17029) |
| Initial SS:SP | **`2C32:4000`** |

Single-segment code image at load CS base (dumpexe CFG uses **CS=1000h** as analysis base). Large BSS/stack reservation via SS and max-memory fields is consistent with a TP real-mode game with graphics buffers.

---

## 3. Compiler / toolchain

### Quoted Turbo Pascal section (human dumpexe output)

From `header.txt` (same block in `strings.txt` / `cfg-interesting.txt` preamble):

```text
=== Turbo Pascal (auto) ===
Confidence:  97%
Compiler:    Turbo Pascal 5.5
TP 5.5:      yes (TPC 5.5 class — /usr/share/games/TP5.5)
Toolchain:   Borland Turbo Pascal 5.5 (TPC) + TASM for {$L} units (Catacomb-class)
Product:     Catacomb
Evidence:
  - "Runtime error " at file 0x2067F (Borland Pascal RTL)
  - 90× near frame 55 89 E5 (push bp; mov bp,sp)
  - 23× near frame 55 8B EC
  - 9× far CALL (9A) in first 256 bytes at entry
  - Catacomb UI help strings
  - rebuild-proven: MAKECAT.BAT with /usr/share/games/TP5.5 TPC.EXE
=== End Turbo Pascal ===
```

### Supporting observations from listing / strings

- Dominant **near** prologues `push bp; mov bp,sp` (`55 89 E5`) — classic TP/Borland near procedures.  
- Heavy use of **far CALL** (`9A …`) to other segments — TP unit/runtime linkage, not a pure tiny COM.  
- RTL string: `"Runtime error "` + `" at "` at file ~`0x20670`.  
- Pascal **length-prefixed** strings dominate UI text (`pascal-len` kind; 103 of 263 strings).  
- **Not** Pascal MT+86: JSON `pascal_mt.detected = false`.  
- **Not** JWASM/CuteMouse toolchain path: JSON `toolchain.detected = false`.

### Version confidence

| Claim | Confidence | Notes |
|-------|------------|--------|
| Borland Turbo Pascal family | **Very high** | RTL string + frame prologues + far unit calls |
| **TP 5.5 specifically** | **High (tool: 97%)** | dumpexe auto-class; blind session cannot re-run TPC rebuild |
| TPC + TASM `{$L}` mixed units | **Medium–high** | Toolchain line is product-class heuristic; far-call density fits units/asm |
| Exact patch level / TPC.EXE build date | **Unknown** | Not in dumpexe output |

**JSON caveat:** `report.json` (tool version field `"1.5"`) exposes only `pascal_mt` and JWASM-style `toolchain` objects, both false. The **TP 5.5 / Catacomb** block appears in the **text** reports, not as a dedicated JSON key in this dump. Prefer the text Turbo Pascal section for compiler identity.

---

## 4. Entry / early control flow (from listing)

Entry label in `listing-agent.asm`:

```text
func_4285:                ; entry
    4285  9A00000920        lcall    0x2009, 0
    428A  9A0000F11F        lcall    0x1ff1, 0
    428F  9A27067E1F        lcall    0x1f7e, 0x627
    4294  9A00007D17        lcall    0x177d, 0
    4299  9A00001B17        lcall    0x171b, 0
    429E  9A05001717        lcall    0x1717, 5
    42A3  9A00006011        lcall    0x1160, 0
    42A8  9A0000F305        lcall    0x5f3, 0
    42AD  55                push     bp
    42AE  89E5              mov      bp, sp
    42B0  83EC02            sub      sp, 2
    42B3  E8F4FB            call     func_3EAA
    …
    42C2  9A26100920        lcall    0x2009, 0x1026   ; push buffer @DS:7BC2, size 800h, tag 63h
```

**Interpretation (static, blind):**

1. **Eight far calls** before a Pascal frame — typical TP program start: unit initialization / CRT / graphics / sound setup (targets are other CS values: `2009`, `1ff1`, `1f7e`, `177d`, `171b`, `1717`, `1160`, `05f3`).  
2. Near call `func_3EAA`, then a large **table fill** at `DS:7BC2` (byte map / tile attributes; loops write 0, 2, 3, 4, 5 into ranges).  
3. Nested loops with stride `0xAC` writing `0x81` into structures at `0x414A` / `0x6D6` — looks like **map / visibility / wall** table init (dimensions involving `0x55` and `0x0A`/`0x4A`).  
4. Mouse/driver probe (`INT`-style far call with `AL=33h`, check for `0xCF` at vector) setting flag `[0x248]`.  
5. Near calls `func_1F17`, `func_1FD1`, `func_1DED`, `func_0076` (early code uses **B800h** — text/video helper), `func_1A15`, `func_4847`.  
6. Installs a far pointer `0x0000:424D` into `[0x22A]` (likely a **timer/ISR or callback** hook related to game timing).  
7. Sets mode byte **`[0x242] = 1`**, then falls into the **main dispatch loop**.

### Main loop (clear game-mode state machine)

```text
func_45F1:
    45F1  A04202            mov      al, byte ptr [0x242]
    45F4  3C00              cmp      al, 0
    45F6  7524              jne      0x1461c
    … calls func_3A62, func_3847; submodes via [0x243] …
    461C  3C02              cmp      al, 2
    …
    4630  3C01              cmp      al, 1
    …
func_464C:
    464C  EBA3              jmp      func_45F1
```

- **`[0x242]`** is the primary mode: `0`, `1`, `2` (and self-resets to `1` after some paths).  
- **`[0x243]`** is a sub-mode when mode is 0 (`1` → `func_3C9F`; `3` → `func_392C` + `func_3C9F`).  
- Infinite **`jmp func_45F1`** — classic **non-returning game loop** after init.

CFG also tags demo UI (`" --- DEMO --- "`, `"SPACE TO START"`), high scores, `TOPSCORS.CAT` path seed at IP `4703`, `INT21/AH=2C` get-time, and several `INT10` video sites (`4E3A`, `4E8B`, `4F32`).

---

## 5. Strings / gameplay hints

**263 strings** (`103` pascal-len, `160` asciiz). Gameplay-relevant (clean UI, not binary noise):

| Theme | Examples |
|-------|----------|
| Keys | `F1 = Help`, `F2 = Sound on / off`, `F3 = Controls`, `F4 = Game reset`, `F9 = Pause`, `F10= Quit` |
| Demo | Watch demo / hit fire to start; CFG also has `SPACE TO START`, ` --- DEMO --- ` |
| Movement | Arrows; Button1 Ctrl (charge shot); Button2 Alt (strafe / face lock); joystick + mouse switch text |
| Combat / RPG | shot power meter, super shot, healing potion, body meter death, spells, nuke spell, monsters |
| Meta | `PAUSED`, `Quit (Y/N)?`, `Reset game (Y/N)?`, `Player Control:`, Sound, Joystick calibration |
| Levels / score | `Level` / `Score` / `Top`; `Warp to which level (1-99)?`; High scores table |
| Data files | `VGAPICS.CAT`, `SOUNDS.CAT`, `DEMO.CAT`, `TOPSCORS.CAT`, `LEVEL` |
| Errors | `File not found: `, `DOS ioresult `, `Runtime error ` |

**Gameplay picture (from strings alone):** VGA-era DOS action dungeon crawler with charged shots, potions, area-nuke magic, demo attract mode, high-score file, and optional joystick/mouse. External **`.CAT`** resource packs for pictures, sounds, demo, and scores.

Many mid-file “strings” are false positives on graphics/data (e.g. `????`, `}}}{`) — ignore for product narrative.

---

## 6. Architecture (game loop / modes)

```text
                    ┌─────────────────────────┐
  MZ load ────────►│ func_4285 entry          │
                    │  far unit inits (×8)     │
                    │  map/table init @7BC2    │
                    │  input/video helpers     │
                    │  hook [22A] ← 0000:424D  │
                    └───────────┬─────────────┘
                                ▼
                    ┌─────────────────────────┐
              ┌────►│ func_45F1  mode loop     │◄──┐
              │     │  AL = [0x242]            │   │
              │     └───────────┬─────────────┘   │
              │       ┌────────┼────────┐         │
              │       ▼        ▼        ▼         │
              │    mode 0   mode 1   mode 2       │
              │    (+[243]  (play?)  (other)      │
              │     sub)                          │
              │       └────────┬────────┘         │
              │                ▼                  │
              │         func_464C ────────────────┘
              │         jmp short back
              │
   External: VGAPICS.CAT / SOUNDS.CAT / DEMO.CAT / TOPSCORS.CAT
   BIOS: INT10 video; INT21 time; mouse int 33h probe
```

**Hypotheses (labeled):**

- **Mode byte `[0x242]`:** attract/demo vs active play vs secondary screen (help/scores/controls). Exact mapping **not proven** without dynamic run.  
- **`func_3A62` / `func_3847`:** shared per-frame or per-tick work (input + draw candidates).  
- **`func_3C9F` / `func_392C`:** mode-0 specializations (e.g. demo playback vs menu).  
- **Tile map at `7BC2`:** level cell types; value `0x63` appears as a sentinel/fill in init (`cmp …, 0x63`).  
- **No overlays** in MZ header — game is a **monolithic EXE** plus external `.CAT` files (not TP overlay chain).

CFG stats: **1872** basic blocks, **~2941** edges, **~554** back-edges, **4** INT sites, **253** string xrefs — consistent with a full game, not a tiny utility.

---

## 7. What kind of `.asm` did dumpexe produce?

### Classification

**Human multi-pass annotated listing** — **not** a JWASM `.model` export, **not** a raw hex dump only.

Evidence from the first lines of `listing-agent.asm`:

```text
; dumpexe multi-pass listing (not single-stream Capstone only)
; source: subject.exe
; CS=1000h  entry=4285h  blocks=1872  symbols=266
; labels: func_<IP> (+ names from --map / <stem>.sym when present)
; call/jmp/jcc near targets rewritten to labels when known
; blank line after procedure regions ending in ret/retf/iret
;

func_000E:                ; call target
    000E  55                push     bp
    000F  89E5              mov      bp, sp
    0011  31C0              xor      ax, ax
    0013  9A44020920        lcall    0x2009, 0x244
    0018  A04102            mov      al, byte ptr [0x241]
    001B  3C00              cmp      al, 0
    001D  750E              jne      0x1002d
    001F  FF7608            push     word ptr [bp + 8]
    0022  FF7606            push     word ptr [bp + 6]
    0025  FF7604            push     word ptr [bp + 4]
    0028  E86949            call     func_4994
    002B  EB22              jmp      func_004F
    002D  3C01              cmp      al, 1
    002F  750E              jne      0x1003f
    0031  FF7608            push     word ptr [bp + 8]
    0034  FF7606            push     word ptr [bp + 6]
```

(First **25** lines of the file, as required.)

### Format properties

| Property | Observation |
|----------|-------------|
| Labels | `func_<IP>` (266 procedures); entry tagged `; entry` |
| Instruction line | `IP  HEXBYTES  mnemonic operands` |
| Near calls/jmps | Often rewritten to `func_*` |
| Far calls | Left as `lcall seg, off` (relocated segments) |
| Directives | **No** `.model`, `SEGMENT`, `ENDS`, `ASSUME`, `PROC`/`ENDP`, `ORG` |
| Data | Code-oriented; trailing region becomes **garbage decode** of data (e.g. after `464C` loop, bytes at `46C4+` disassembled as nonsense; end of file is data-as-code) |
| stderr | `listing: wrote listing-agent.asm (266 procs, 7423 insns)` |

JWASM export would require `--model=…` and would emit assemblable segment structure; **this run used plain `-d`**, so multi-pass RE listing only.

### Assemblable as-is by TPC / TASM / JWASM?

| Assembler | Assemblable as-is? | Why |
|-----------|--------------------|-----|
| **TPC** | **No** | Not Pascal source; not an include unit |
| **TASM** | **No** | Missing segments, assumes, proc frames, data definitions; Capstone syntax (`lcall`, `ptr`, `byte ptr`) ≠ TASM ideal; mixed code/data |
| **JWASM** | **No** (this file) | Same; would need `--model=` export path + cleanup, not this listing |

**Usefulness:** excellent for **static reading**, CFG correlation, and naming call targets; **not** a rebuild artifact.

---

## 8. Unknowns without source

1. **Exact mode meanings** for `[0x242]` / `[0x243]` (demo vs play vs menu) — structure clear, labels not.  
2. **Unit / procedure names** — only `func_<IP>`; no `.map`/`.sym` loaded.  
3. **Level / `.CAT` file formats** — filenames only; no schema.  
4. **Which far-call segments are RTL vs game units vs `{$L}` asm** — not separated blindly.  
5. **Whether TP is exactly 5.5 vs 5.x sibling** — tool says 5.5 @ 97%; blind session did not rebuild.  
6. **Author / publisher / version string** — not present in clean string set.  
7. **Sound hardware path** (PC speaker vs other) — only “Sound on/off” UI.  
8. **Full ISR at `0000:424D`** — pointer installed; body not fully characterized here.  
9. **JSON vs text detect gap** — TP product block not mirrored in `report.json` fields.  
10. **Dynamic behavior** (actual video mode number, file open order) — static only; `--simulate` not used in this pass.

---

## 9. Confidence table

| Topic | Confidence | Basis |
|-------|------------|--------|
| **Product = Catacomb-class fantasy VGA DOS game** | **High** | dumpexe Product line + UI/asset strings + `.CAT` names |
| **Product marketing name “Catacomb”** | **High (tool)** / **Medium (strings alone)** | Named by detector; no literal title string in extract |
| **Compiler = Turbo Pascal 5.5** | **High (97% tool)** | RTL + frames + far inits; version pin is classifier |
| **Toolchain TPC + some TASM `{$L}`** | **Medium–high** | Toolchain string + far-call pattern; not proven unit-by-unit |
| **Architecture: init → mode loop on `[0x242]`** | **High** | Clear listing at `45F1`/`464C` |
| **External resource files required** | **High** | Explicit filenames + “File not found” |
| **Listing usefulness for RE reading** | **High** | 266 procs, labels, entry, loops |
| **Listing usefulness for reassembly** | **Very low** | Multi-pass dump, not JWASM/TASM source |
| **Overlay / multi-EXE chain** | **High that none** | Overlay #0; single MZ |

---

## Evidence commands (this session)

```text
dumpexe subject.exe                         → header.txt
dumpexe --strings subject.exe               → strings.txt
dumpexe --json subject.exe                  → report.json
dumpexe -d -o listing-agent.asm subject.exe → listing-agent.asm (+ stderr OK)
dumpexe --cfg-interesting --cfg-no-insns subject.exe → cfg-interesting.txt
```

All of the above completed with **exit 0**.

---

*End of blind report. No Catacomb sources or external RE notes were consulted.*
