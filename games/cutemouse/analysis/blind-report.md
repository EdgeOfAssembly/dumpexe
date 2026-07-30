# Blind RE Report: `ctmouse.exe`

**Binary:** `/tmp/dumpexe/games/cutemouse/bin/ctmouse.exe`  
**Size:** 5829 bytes (016C5h)  
**Tool:** `/tmp/dumpexe/dumpexe` 1.4 (listing header also reports 1.3 in `--json`)  
**Artifacts:** `/tmp/grok-goal-c8d573d7f31d/implementer/blind-ctm/`  
**Method:** binary + dumpexe only (no `.asm`/`.c` source trees). Same-dir `ctmouse.sym` / `ctmouse.map` were present and auto-loaded by dumpexe; `.sym` contributes only the name `start` at image IP `0000`. `.map` is a tiny linker map (`_TEXT`/`_DATA`/`CONST`).

---

## Identity (what is this program?)

This is **CuteMouse**, a **DOS mouse driver TSR** for FreeDOS-class systems.

Evidence (all from the binary / dumpexe):

| Evidence | Location |
|----------|----------|
| Banner string | file `0x12CC`: `CuteMouse v2.1 beta4 [FreeDOS]` |
| Product name | file `0xB20` / strings: `CuteMouse`; `CTMOUSE` at `0x1120` |
| Driver lifecycle messages | `CuteMouse driver is not installed!`, `Driver successfully unloaded...`, `Driver unload failed: some interrupts intercepted...`, `Installed at `, `Resident part reset to ` |
| Hardware modes | `PS/2 port`, `Mouse Systems mode`, `Microsoft mode`, `Logitech mode`, `(wheel present)` |
| CLI help | Options `/V /P /S /3 /O /M /R /L /B /N /W /U /?` describing mouse probe, TSR load/unload, UMB |
| Mouse API | `INT 33h` present; install path does `AH=35h/25h, AL=33h` (get/set interrupt vector **33h**) |
| dumpexe toolchain auto-detect | Product: **CuteMouse 2.1 beta4 [FreeDOS]** @ 95% confidence |

**Role:** installable **TSR mouse driver** that:

1. Probes **PS/2** (BIOS INT 15h AH=C2h) and/or **serial** mice (COM1–4, IRQ),
2. Hooks **INT 33h** (and related vectors) to provide the standard DOS mouse API,
3. Draws a software cursor (INT 10h + VGA GC ports `03CEh`),
4. Supports unload (`/U`), UMB residence (`/W` disables UMB move), and “already present” checks (`/B`, `/N`).

---

## File format / load model

### MZ header (dumpexe)

```
DOS File Size                 016C5h (5829)
Load Image Size               016A5h (5797)
Header Size                   0020h  (32 bytes)
Relocation entries            0000h
Overlay Number                0000h
Entry Point File Offset       00020h
Initial SS:SP                 FFF0:19AE
Program Entry CS:IP           FFF0:0100
Min extra memory              0020h paragraphs
Max memory                    0200h paragraphs (per dumpexe header display)
```

### COM-in-EXE (com2exe-style)

Classic **COM program wrapped as MZ**:

- `CS:IP = FFF0:0100` → with load segment `S`, effective entry is `S:0000` of the load image while IP looks like a COM `ORG 100h` entry.
- **Zero relocations**, **32-byte header** → typical `com2exe` / `exe2bin`+wrapper layout.
- dumpexe: `COM-in-EXE: yes`; listing uses **image IP 0 = first byte after MZ header** (= traditional COM offset `0100h`).

**Addressing caveat (important for reading the listing):**

- Listing labels (`start`, `func_0B0E`, …) are **image IPs** (`file_offset − 0x20`).
- Many **immediate offsets in the code** were assembled with **`ORG 100h`**, so a pointer like `0x175F` in an instruction is a **COM address** = image IP `0x165F` (`COM − 100h`).
- Example: option switch table at COM `175Fh`–`17A5h` lives at image `165Fh`–`16A5h` (EOF).

### Segments / layout (from `.map` + image)

| Range (map) | Name   | Class | Notes |
|-------------|--------|-------|--------|
| `00000–014E3` | `_TEXT` | CODE | Main code + resident + transient |
| `014E4–014E5` | `_DATA` | DATA | Tiny |
| `014E6–01A9E` | `CONST` | CONST | Help strings, messages, tables (extends past pure file image via BSS/stack model) |
| Entry | `0000:0100` (map) | | Matches COM-style entry; dumpexe image entry IP `0000` |

Not an overlay EXE (`overlay = 0`). Not a device driver `.SYS` (no `FFFFFFFF` device header).

---

## Toolchain hypotheses (compiler/assembler/linker)

| Hypothesis | Confidence | Why |
|------------|------------|-----|
| **Assembler: JWASM and/or TASM**, tiny model | **High (~90%)** | Pure asm style (no HLL prologues, heavy `out`/`in`, `rep movsw`, hand-rolled TSR); dumpexe auto: “JWASM/TASM tiny model”; `.map` shows classic `_TEXT`/`_DATA`/`CONST` |
| **Link → flat COM (`exe2bin` or equiv.) → `com2exe` MZ wrapper** | **High (~95%)** | `CS:IP=FFF0:0100`, 0 relocs, 32-byte header, COM org 100h immediates |
| **Not Pascal MT+** | **High** | `pascal_mt.detected: false`; “pascal-len” string hits are length-prefix false positives on English text |
| **Not a C compiler (MSC/Turbo C) runtime** | **High** | No typical C startup, no large data segment model, no CRT strings |
| **Target: FreeDOS / DOS mouse stack** | **High** | Banner `[FreeDOS]`; INT 33h driver semantics; UMB strategy via INT 21h AH=58h |

dumpexe toolchain block (verbatim summary):

> Toolchain: JWASM/TASM tiny model + exe2bin + com2exe (CuteMouse build)  
> Product: CuteMouse 2.1 beta4 [FreeDOS] — **95%**

---

## Entry point and early control flow (from listing)

### True entry

```
start:                ; image IP 0000h  (file 00020h)
    0000  E90B0B      jmp  func_0B0E
```

- Relative jump `E9 0B 0B` → target **`0B0E`** (3 + `0B0Bh`).
- Bytes immediately after the jmp at the load image start are **data** (cursor masks / tables), not fall-through code — first 64 bytes dump shows mask-like patterns (`ff 3f ff 1f…`, `00 40 00 60 00 70`).

### Transient installer — `func_0B0E` (main)

High-level flow from listing + CFG:

1. **`0B0E`:** `cld`
2. **`0B0F–0B18`:** `mov ax,3533h` / `int 21h` → **get INT 33h vector**; save at `[00FC]` / `[00FE]`
3. **`0B1C–0B1F`:** `mov di,13AAh` / `call func_1007` → print a string (help/banner fragment region)
4. **`0B22–0B2B`:** read PSP command tail at `SI=0080h`, NUL-terminate, **`call func_0FB1`** → **CLI option parser**
5. **`0B2E–0B30`:** `mov al,1Fh` / `call func_0F3A` → far call through saved INT 33h vector (probe existing mouse services)
6. Branch on flags in `[11EC]` (option bitfield built by parser):
   - **`call func_0CAD`** — serial mouse path setup
   - **`call func_0DA2`** — **PS/2 probe** (INT 11h + INT 15h C2xx)
7. On failure paths: load `DI` with message ptrs (`128Dh` “Logitech mode” area / error strings) → **`jmp func_103F` / print+exit**
8. **Install path `func_0B71`:**
   - Optional **`call func_0F26`** — signature scan for already-loaded CuteMouse (`'M'` magic / `repe cmpsb`)
   - **`call func_1046`** — free env block (`INT 21h AH=49h`), UMB/strategy prep
   - Copy old INT 33h vector; **`mov ax,2533h` / `int 21h`** with `DX=0B5Eh` → **set INT 33h** to resident handler
   - Print “Installed at …” / mode strings via **`func_1007`**
   - VGA check **`func_0BE8`:** `AX=1A00h` / `INT 10h` (display combination)
   - Relocate/copy resident image (`rep movsw`, size related to `CX=0585h` words at `0C9B`)
   - **`retf`** chain into installed entry (`AX=0B5Eh` pushed) — classic TSR go-resident sequence
9. **Terminate:** `AH=4Ch` / `INT 21h` at **`1000`**; char output `AH=02h` at **`1004`** used by string printer

### Secondary entry-ish stubs

| IP | Role (guess from code) |
|----|-------------------------|
| `00C4` | `jmp func_0A76` — alternate path into **`iret` epilogue** (`0A76–0A79`: `popaw; pop es; pop ds; iret`) |
| `00C7` | PS/2 handler install helper (INT 15h C207/C200 + call sample-rate) |
| `0A76` | Common **interrupt return** stub |

---

## Notable strings and what they imply

### Identity / version

- `CuteMouse v2.1 beta4 [FreeDOS]` — definitive product + version + platform.
- `CTMOUSE` — executable/product short name; message about older CTMOUSE for EGA RIL.

### Install / uninstall

| String | Implication |
|--------|-------------|
| `Installed at ` + `PS/2 port` / `COM` + `(0000h/IRQ` + `) in ` | Reports I/O base + IRQ + protocol after install |
| `Mouse Systems mode` / `Microsoft mode` / `Logitech mode` | Multi-protocol serial/PS2 support |
| `(wheel present)` | Wheel mouse detection |
| `Driver successfully unloaded...` | Clean TSR removal path |
| `Driver unload failed: some interrupts intercepted...` | Safety check before unhook |
| `CuteMouse driver is not installed!` | Unload when not resident |
| `Resident part reset to ` | Re-init without full uninstall |

### CLI (from embedded help at file `0x12CC+`)

| Switch | Meaning (from binary help text) |
|--------|----------------------------------|
| `/V` | Reverse search: PS/2 after serial |
| `/P` | Force PS/2; do not probe serial |
| `/S[c[i]]` | Force serial COM `c` (1–4), IRQ `i` (1–7) |
| `/3` | Force 3-button if MS/PS2 found |
| `/O` | PS2 + BIOS USB wheel detect (may hang) |
| `/M` | Old Mouse Systems / Genius non-PnP |
| `/R[h[v]]` | Resolution 1–9 / auto |
| `/L` | Swap left/right buttons |
| `/B` | Abort if mouse services already present |
| `/N` | Load new TSR even if CuteMouse already loaded |
| `/W` | Do not move into UMB |
| `/U` | Uninstall / remove TSR |
| `/?` | Help |

### Errors

- `Error: Inv`…` argument` — bad CLI
- `Enter /? o`… — hint to help
- EGA RIL note: VGA-focused build; older CTMOUSE for EGA RIL

**Parser implementation note:** at image `0FB1` a loop uppercases option letters (`and al,0DFh`) and walks a **5-byte table** (letter, flags word OR’d into `[11EC]`, call handler word) from COM `175Fh` through `17A5h` (image `165Fh`…EOF). Letters visible in-table include `P O S V R L B N W U Y M` plus non-ASCII control entries (help/`?` path).

---

## Interrupts / DOS API usage

Counts from listing annotations (static; some sites may be misaligned mid-instruction — see caveats).

| INT | Approx. sites | Role in this binary |
|-----|---------------|---------------------|
| **INT 21h** | ~26 | DOS: get/set vectors (`AH=35/25`, often `AL=33` or `10`), terminate (`4C`), write char (`02`), close (`3E`), alloc/free (`48/49`), memory strategy (`58`) |
| **INT 15h** | ~11–13 | **PS/2 pointing device BIOS** (`AH=C2h`): init `C205`, resolution `C203`, get type `C204`, set handler `C207`, enable/disable `C200`, sample rate `C202` |
| **INT 10h** | 3 | Video: cursor shape `AH=01`, display combination `AH=1A`, plus raw `CD10` in cursor-draw path (`0504`) |
| **INT 33h** | 1 explicit opcode @ image `0FA7` (file `0FC7`) | Probe/call **existing** mouse driver (`mov al,21h; int 33h`); driver **provides** INT 33h after install via vector set |
| **INT 11h** | 1 @ `0DA7` | Equipment word; test bit for pointing device before PS/2 init |
| **INT 13h** | 1 annotated @ `0FC2` | **Likely false positive** — sits on bytes of `mov di,13CDh` (`BF CD 13`) in the option parser; treat as disassembly desync unless proven by execution |

### Notable INT 21h patterns

| Image IP | AH/AX | Purpose |
|----------|-------|---------|
| `0B12`, `07FD` | `AX=3533h` | Get INT **33h** vector |
| `0BA1`, `1036` | `AX=2533h` | Set INT **33h** vector (install/restore) |
| `0807`, `0837` | get vector `AL=10h` | INT **10h** vector save (video chain) |
| `0849` | `AH=25h`, `DX=0434h` | Set vector (handler at `0434`) |
| `1000` | `AH=4Ch` | Exit |
| `1004` | `AH=02h` | Putchar (string print loop) |
| `1050`, `10E1`, `10E9` | `AH=49h` | Free memory (env / UMB trials) |
| `10CE` | `AH=48h` | Allocate (UMB probe) |
| `1081`…`10C8` | `AX=58xxh` | Get/set allocation strategy + UMB link |
| `0BDF`/`0BE6` | `AH=3Eh` | Close handles (cleanup loop `BX=13h` downward) |

### Hardware I/O (not INTs, but central)

- **PIC:** `in/out 21h` (mask) around `015E–0162`
- **Serial/mouse data path:** `in`/`out` via DX from `[01A8]` (port base)
- **VGA graphics controller:** ports **`03CEh`/`03CFh`** in `func_050D` / `func_057E` / `func_05DA` (cursor XOR plane programming)

---

## Structure: TSR? driver? overlay? segments?

| Question | Answer |
|----------|--------|
| **TSR?** | **Yes.** Installs INT 33h, copies a resident image, frees transient/env, returns via DOS; unload strings + `/U` |
| **DOS device driver (.SYS)?** | **No** — MZ COM-in-EXE, not `FFFFFFFF` header chain |
| **Overlay EXE?** | **No** (`overlay_number = 0`, single image) |
| **Multiplex/API** | Provides **INT 33h** mouse API; may chain INT 10h for cursor |
| **Memory** | Tiny single segment model; optional **UMB** relocation (`/W` disables; AH=58h/48h/49h) |
| **Resident vs transient** | Low image IPs (~`0000–0A79`): IRQ/API/cursor **resident** services; high IPs (~`0B0E–10EB`): **transient** install, parse, probe, messages, exit |

Rough split:

```
image 0000     jmp to installer
image 0003..   data (masks, state)
image ~00C7    PS/2 BIOS helpers (also used when resident)
image ~0127    hardware IRQ / packet path (ports, EOI-ish)
image ~021C..  mouse packet decode / button mapping
image ~0371..  higher mouse services / callback
image ~04F1..  cursor draw (VGA GC + INT10)
image ~07F5..  vector install helpers → PS/2 enable
image 0A76     iret stub
image 0B0E..   TRANSIENT: parse, probe, install, print, exit
image ~12ACh   CONST: messages + help + option table (thru EOF)
```

---

## Procedure map sketch

Labels are **only** those emitted by dumpexe listing (`start`, `func_XXXX`). Roles are **hypotheses** from callees, INTs, and string xrefs — not source names.

| Label | IP | Role hypothesis |
|-------|-----|-----------------|
| `start` | `0000` | Entry: jump to installer |
| `func_00C7` | `00C7` | PS/2: set handler (`C207`) + enable (`C200`); call sample-rate |
| `func_00F2` | `00F2` | PS/2 set sampling rate (`C202`); `ret` |
| `func_021C` | `021C` | Packet/button decode (neg cx, bit tests, calls `029B`) |
| `func_029B` | `029B` | Sub-decoder for axis/button nibbles |
| `func_02C8` | `02C8` | Continuation of decode state machine |
| `func_02EF` | `02EF` | Called from mode setup (`07D1`) — init structure fields |
| `func_0310` | `0310` | Small helper called 3× from `021C` path |
| `func_0322` | `0322` | Helper from packet path |
| `func_0371` | `0371` | Larger service; calls resolution/IO helpers; STI path from `0915` |
| `func_03E5` | `03E5` | Error/merge path in services |
| `func_04F1` / `04FE` / `0508` | `04F1+` | Cursor-related; ends at `INT 10h` @ `0504` |
| `func_050D` | `050D` | **Draw/restore cursor** — VGA GC `03CE`, `rep movsb` |
| `func_057E` | `057E` | Plane/bit write for cursor |
| `func_05DA` | `05DA` | Reset VGA GC registers to defaults |
| `func_05F2` | `05F2` | Video-memory addressing helper for cursor |
| `func_0621` / `063F` / `065F` | `0621+` | Geometry / bounds / user-callback support |
| `func_069D` / `06A2` | `069D+` | Vector-hook post-processing |
| `func_0915` | `0915` | Serialized “do work with IF” wrapper (`cli`/`sti`, counter `[0167]`) |
| `func_0955` | `0955` | Cursor position update → may `INT 10h AH=01` |
| `func_0A76` | `0A76` | **`iret` epilogue** for interrupt handlers |
| `func_0B0E` | `0B0E` | **Main installer / program entry target** |
| `func_0B71` | `0B71` | Post-probe install: set INT 33h, print status |
| `func_0BE8` | `0BE8` | VGA/MCGA detect via `INT 10h AH=1A` |
| `func_0CAD` / `0CC7` | `0CAD` | **Serial mouse open/probe** (port from table, `call di`) |
| `func_0DA2` / `0DA7` | `0DA2` | **PS/2 detect+init** (INT 11, INT 15 C2xx) |
| `func_0E8F` | `0E8F` | PS/2 failure: `stc; ret` |
| `func_0E91` | `0E91` | Map rate codes → `INT 15h C202` sample rate |
| `func_0ED3` | `0ED3` | Format COM port / IRQ into message buffer (`1354h`…) |
| `func_0F26` | `0F26` | Detect already-loaded CuteMouse (signature `'M'` + `cmpsb`) |
| `func_0F3A` | `0F3A` | Far call old INT 33h if segment `[00FE]≠0` |
| `func_0FB1` | `0FB1` | **Command-line option parser** (table walk) |
| `func_0FF1` | `0FF1` | Print message then fall into exit sequence |
| `func_1007` | `1007` | **ASCIZ print** via `INT 21h AH=02` loop |
| `func_103F` | `103F` | Error print trampoline → `0FF1` |
| `func_1046` | `1046` | Free env (`AH=49`); prepare resident segment / MCB name |
| `func_107E` / `108F` / `10A0` | `107E+` | UMB allocation strategy dance + trial `AH=48` |
| `func_10E7` | `10E7` | `AH=49` free wrapper |

Listing summary line: **1339 instructions, 57 procedure labels, 459 CFG blocks, 674 edges.**

---

## What you still cannot know without source

1. **Authoritative procedure names** — only `start` + `func_IP` (no real public symbol map beyond that).
2. **Exact INT 33h function dispatch table** (AX=0000…0034 semantics per entry) — needs resident handler disasm + behavioral tests, not just install path.
3. **Full serial protocol state machines** (Mouse Systems vs Microsoft vs Logitech packet layouts) — code at `021C+` is dense; blind static read is incomplete.
4. **Whether INT 13h @ `0FC2` is real** — almost certainly a misaligned block leader; needs execution or forced leaders off.
5. **IRQ handler entry IPs for hardware** (which vector: IRQ1/3/4/12?) — get/set vector sites exist but exact IRQ number wiring needs following the serial/PS2 enable paths dynamically.
6. **Wheel / USB BIOS path** (`/O`) micro-details and hang conditions.
7. **Build flags / exact assembler version / source file split** — only toolchain class is evidenced.
8. **All self-modifying sites** — installer patches bytes (`[0293]`, `[02C4]`, `[02CE]`, jump hooks at `0950`/`08E5`, etc.); full meaning needs before/after install memory image.
9. **Complete option table letter→flags mapping** for every entry (some bytes are non-letter).
10. **Legal/version provenance** beyond the banner string (license text not in this 5.8K binary).

---

## Confidence summary

| Claim | Confidence |
|-------|------------|
| **Product identity** (CuteMouse 2.1b4 FreeDOS mouse TSR) | **98%** |
| **Toolchain** (asm JWASM/TASM tiny + com2exe COM-in-EXE) | **92%** |
| **Overall architecture** (transient installer + resident INT33/cursor/PS2/serial driver, optional UMB) | **90%** |
| **PS/2 via INT 15h C2h** | **95%** |
| **CLI option set** (from help strings) | **97%** |
| **Per-function role labels above** | **55–75%** (varies; installer high, packet decode lower) |
| **INT 13h as real disk use** | **10%** (treat as listing artifact) |

---

## Appendix: commands run

```text
/tmp/dumpexe/dumpexe ctmouse.exe                         → header.txt
/tmp/dumpexe/dumpexe --strings ctmouse.exe               → strings.txt
/tmp/dumpexe/dumpexe -d --no-asm-file ctmouse.exe        → listing-stdout.txt
/tmp/dumpexe/dumpexe -d --no-asm-file --no-map ...       → listing-nomap.txt
/tmp/dumpexe/dumpexe --cfg-interesting --cfg-no-insns …  → cfg-interesting.txt
/tmp/dumpexe/dumpexe --json ctmouse.exe                  → report.json
```

### JSON top-level keys

`tool`, `version`, `file`, `format`, `mz`, `pascal_mt`, `strings` (71), `cfg` (459 blocks, 43 int_sites, 65 interesting).

### Key concrete anchors

| Item | Value |
|------|--------|
| Entry file offset | `00020h` |
| Entry image IP | `0000h` → `jmp 0B0Eh` |
| Banner file offset | `012CCh` |
| INT 33h opcode file offset | `0FC7h` (image `0FA7h`) |
| INT 33h vector install | image `0BA1h` (`AX=2533h`) |
| PS/2 init cluster | image `0DA7h–0EC3h` |
| String printer | `func_1007` @ `1007h` |
| Exit | `AH=4C` @ `1000h` |
