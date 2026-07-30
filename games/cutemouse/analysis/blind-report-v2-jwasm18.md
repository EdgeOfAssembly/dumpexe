# Blind reverse-engineering report — subject.exe

**Subject:** `/tmp/grok-goal-c8d573d7f31d/implementer/blind-ctm-jwasm18/subject.exe`  
**Analyzer:** `/usr/local/bin/dumpexe` 1.5 (Capstone-backed multi-pass listing)  
**Method:** Blind — only dumpexe output on this file; no source trees, no project notes, no external RE notes.  
**Artifacts:**

| Command | Output file |
|---------|-------------|
| `dumpexe subject.exe` | `dumpexe-default.txt` |
| `dumpexe --strings subject.exe` | `dumpexe-strings.txt` |
| `dumpexe --json subject.exe` | `dumpexe-json.txt` |
| `dumpexe -d --no-asm-file subject.exe` | `dumpexe-disasm.txt` |
| `dumpexe --cfg-interesting --cfg-no-insns subject.exe` | `dumpexe-cfg.txt` |

All commands exited 0.

---

## 1. Identity

| Field | Value | Source |
|-------|--------|--------|
| File size | 5829 bytes (016C5h) | MZ header / dumpexe |
| Format | MS-DOS MZ executable | `file` + dumpexe |
| Product name (in-image) | **CuteMouse** | asciiz / banner strings |
| Version banner | **CuteMouse v2.1 beta4 [FreeDOS]** | file offset 0x12CC |
| Short id | **CTMOUSE** (help text: “older CTMOUSE…”) | strings |
| Role | DOS mouse driver / TSR | strings + INT 33h install path |

**Product identity from pure strings (independent of toolchain fingerprint):** very high. The binary embeds the full FreeDOS-style help and status messages naming CuteMouse, CTMOUSE, PS/2 / serial / Microsoft / Logitech modes, unload/install, UMB, and TSR options.

**dumpexe product line:** `CuteMouse 2.1 beta4 [FreeDOS]` (Toolchain section + JSON `product` / `product_version`).

---

## 2. File format / load model

### MZ header (dumpexe)

```
DOS File Size                                     016C5h  (  5829. )
Load Image Size                                   016A5h  (  5797. )
Relocation Table entry count                      0000h  (     0. )
Relocation Table address                          001Ch  (    28. )
Header Size                                       0020h  (    32. )
Minimum Extra Memory                              0020h  (    32. )
Maximum Memory Requirement                        0200h  (   512. )
Entry Point File Offset                           00020h  (    32. )
Entry Point Image Offset                          00000h  (     0. )
Initial Stack Segment  (SS:SP)                    FFF0:19AE
Program Entry Point    (CS:IP)                    FFF0:0100
```

### Load model interpretation

- **COM-in-EXE (com2exe-style):** CS:IP = `FFF0:0100` with a **32-byte** MZ header and **zero relocations** is the classic pattern for a `.COM` image packaged as `.EXE` (load image starts at file offset 0x20; runtime IP = 0100h relative to the COM paragraph).
- dumpexe states: `COM-in-EXE: yes (CS:IP=FFF0:0100, COM org=0100h)` and recommends **org 100h** labels when mapping symbols.
- Listing uses synthetic CS=`1000h` with entry image offset `0000h` for the first instruction at file 0x20; that first instruction is a near jump into the install path (see §4). The COM “org 100h” view and the listing’s IP=0000-at-image-start view differ by a constant 100h — both describe the same bytes.
- Max memory 512 paragraphs and min extra 32 paragraphs are modest; consistent with a small resident driver plus transient install code.

### JSON `mz` object (verbatim fields)

```json
"mz": {
  "file_size": 5829,
  "load_image_size": 5797,
  "header_bytes": 32,
  "entry_cs": "FFF0",
  "entry_ip": "0100",
  "ss": "FFF0",
  "sp": "19AE",
  "reloc_count": 0,
  "overlay": 0,
  "entry_file_offset": 32
}
```

`pascal_mt`: `{"detected": false, "confidence": 0.000}` — not a Pascal MT+ binary.

---

## 3. Assembler / toolchain

### dumpexe Toolchain section (verbatim)

```
=== Toolchain (auto) ===
Confidence:  98%
Toolchain:   JWASM 1.80 (jwasmd -mt) + tlink/wlink + exe2bin + com2exe -s512
Assembler:   JWASM 1.80
JWASM 1.8:   yes (1.80 class — era tool in bin/jwasm/)
Tool binary: bin/jwasm/jwasm-1.8.exe (Win32) / jwasmd-1.8.exe (DOS)
Product:     CuteMouse 2.1 beta4 [FreeDOS]
COM-in-EXE:  yes  (CS:IP=FFF0:0100, COM org=0100h)
Note:        Image is a COM program wrapped as MZ; prefer org 100h labels when mapping symbols.
Evidence:
  - MZ CS:IP = FFF0:0100 (COM-in-EXE / com2exe-style load)
  - zero relocation entries (typical com2exe)
  - 32-byte MZ header (com2exe -s512 style)
  - string "CuteMouse" at file 0xB20
  - banner at 0x12CC: CuteMouse v2.1 beta4 [FreeDOS]
  - string "CTMOUSE" at file 0x1120
  - INT 33h opcode at file 0xFC7
  - rebuild-proven: CuteMouse 2.1b4 load image byte-identical with bin/jwasm/jwasm-1.8.exe
=== End Toolchain ===
```

### JSON `toolchain` object (verbatim)

```json
"toolchain": {
  "detected": true,
  "confidence": 0.980,
  "assembler": "JWASM",
  "assembler_version": "1.80",
  "jwasm_1_8": true,
  "com_in_exe": true,
  "product": "CuteMouse",
  "product_version": "2.1 beta4 [FreeDOS]",
  "toolchain": "JWASM 1.80 (jwasmd -mt) + tlink/wlink + exe2bin + com2exe -s512",
  "tool_path_hint": "bin/jwasm/jwasm-1.8.exe (Win32) / jwasmd-1.8.exe (DOS)",
  "fc_pad_runs": 0,
  "evidence": [
    "MZ CS:IP = FFF0:0100 (COM-in-EXE / com2exe-style load)",
    "zero relocation entries (typical com2exe)",
    "32-byte MZ header (com2exe -s512 style)",
    "string \"CuteMouse\" at file 0xB20",
    "banner at 0x12CC: CuteMouse v2.1 beta4 [FreeDOS]",
    "string \"CTMOUSE\" at file 0x1120",
    "INT 33h opcode at file 0xFC7",
    "rebuild-proven: CuteMouse 2.1b4 load image byte-identical with bin/jwasm/jwasm-1.8.exe"
  ]
}
```

### Assembler name + version (as reported)

| Item | Reported value |
|------|----------------|
| Assembler | **JWASM** |
| Version | **1.80** (JWASM 1.8 class) |
| Pipeline | `jwasmd -mt` → tlink/wlink → exe2bin → **com2exe -s512** |
| Tool confidence | **98%** (tool-stated) |

### Honest confidence split (assembler version)

| Claim | Depends on | Blind confidence |
|-------|------------|------------------|
| Product is CuteMouse 2.1 beta4 FreeDOS | **In-image strings** (banner at 0x12CC, help text) | **95–100%** |
| COM-in-EXE / com2exe-style packaging | **MZ geometry** (FFF0:0100, 0 relocs, 32-byte header) | **90–95%** |
| Assembler is **JWASM 1.80** specifically | Almost entirely **dumpexe fingerprint + “rebuild-proven” claim**; **no** “JWASM” / “1.80” string in the binary | **~40–55% from pure static RE alone**; **~98% if one trusts dumpexe’s rebuild database** |
| Tiny model (`-mt`) + exe2bin + com2exe | Inferred from COM-in-EXE layout + tool knowledge of CuteMouse builds | **Medium** without rebuild |

**Bottom line:** dumpexe **does** name **JWASM 1.80**. That version pin is a **tool-side identification** (including a rebuild-identity claim), not something a blind analyst would recover from strings alone. Packaging (COM-in-EXE) and product identity stand on their own from the file.

---

## 4. Entry / early control flow (from listing)

Listing header:

```
; CS=1000h  entry=0000h  blocks=459  symbols=57
; labels: func_<IP> (+ names from --map / <stem>.sym when present)
; call/jmp/jcc near targets rewritten to labels when known
```

### Entry

```
func_0000:                ; entry
    0000  E90B0B            jmp      func_0B0E
```

First image bytes at file 0x20: `E9 0B 0B` — near jump to install/CLI path `func_0B0E` (IP 0B0Eh). The low image region before 0B0Eh holds **resident** code (handlers, PS/2 INT 15h helpers, mouse state), not the transient entry.

### Install path sketch (`func_0B0E`)

1. `cld`
2. `mov ax, 0x3533` / `int 0x21` — **DOS get vector INT 33h** (mouse API); save old vector at `[0xfc]` / `[0xfe]`
3. Print banner via `func_1007` (DI → string)
4. Parse PSP command tail at `DS:0080h` (`func_0FB1` option walker)
5. Probe hardware paths (`func_0CAD` serial-ish, `func_0DA2` PS/2 / INT 15h C2h family)
6. On success: allocate/relocate (`func_1046`), **set INT 33h** (`mov ax, 0x2533` / `int 21h`, handler at DX=`0xb5e`), copy resident image (`rep movsw`), far-return into installed copy
7. Failure / help / unload messages via DI string pointers + `func_1007` / terminate `AH=4Ch`

### Early resident helpers (low IPs)

```
func_00C7:  INT 15h AX=C207 (set pointing-device handler), AX=C200 (enable/disable), call func_00F2
func_00F2:  INT 15h AX=C202 (set sampling rate); ret
func_0A76:  popaw / pop es / pop ds / iret   ; interrupt-handler epilogue
```

Also present: port I/O (`in`/`out` on PIC mask port 0x21 and serial-ish DX bases), far call through function pointer `[0xb8]` (user mouse event callback pattern).

### CFG summary

- Basic blocks: **459**; edges: **674**; back-edges ~**36**; INT sites: **43**; string xrefs: **28**

---

## 5. Strings / product behavior

dumpexe `--strings`: **71** string hits (many overlapping pascal-len windows on the same help blob).

### High-signal asciiz / banners

| Theme | Example text |
|-------|----------------|
| Identity | `CuteMouse 2.1`, `CuteMouse v2.1 beta4 [FreeDOS]` |
| Install status | `Installed at `, `PS/2 port`, ` (0000h/IRQ`, `) in ` |
| Protocols | `Mouse Systems mode`, `Microsoft mode`, `Logitech mode` |
| Unload | `Driver successfully unloaded...`, `Driver unload failed: some interrupts intercepted...`, `CuteMouse driver is not installed!` |
| Errors | `Error: Invalid option`, `Mouse services already present`, `Error: device not found` |
| VGA note | `No VGA? Use older CTMOUSE if you need EGA RIL support` |

### CLI options (from help text)

| Switch | Behavior (as documented in binary) |
|--------|-------------------------------------|
| `/V` | Reverse search: PS/2 after serial |
| `/P` | Force PS/2; do not probe serial |
| `/S[c[i]]` | Force serial COM c (1–4), IRQ i (1–7) |
| `/3` | Force 3-button if Microsoft or PS/2 |
| `/O` | PS/2 + BIOS USB wheel detection (may hang) |
| `/M` | Old Mouse Systems / Genius non-PnP |
| `/R[h[v]]` | Resolution 1–9 / auto |
| `/L` | Swap left/right buttons |
| `/B` | Cancel if mouse services already present |
| `/N` | Load as **new TSR** even if already loaded |
| `/W` | Do not move into **UMB** |
| `/U` | Uninstall / remove TSR |
| `/?` | Help |

**Behavioral summary:** FreeDOS-oriented **mouse class driver** supporting PS/2 (BIOS INT 15h C2h), serial mice (COM1–4), multiple packet protocols, optional wheel, install/uninstall, and optional UMB residency.

---

## 6. Interrupts / APIs

From multi-pass listing + CFG interesting blocks (AH recovery is best-effort).

| Interrupt | Role in this binary |
|-----------|---------------------|
| **INT 21h** | DOS: get/set vector (AH=35/25, often AL=33h for mouse), terminate AH=4Ch, write char AH=02, close AH=3E, alloc/free AH=48/49, memory strategy AH=58 |
| **INT 33h** | Microsoft mouse API — **service vector installed/queried**; one explicit `int 0x33` site in listing (service probe / call-through) |
| **INT 15h AH=C2xx** | PS/2 pointing-device BIOS (init, enable, resolution, type, handler, sampling rate) — many sites |
| **INT 10h** | Video: cursor shape AH=01, display combination AH=1A (VGA check path) |
| **INT 11h** | Equipment list (probe) |
| **INT 13h** | Tagged once in CFG/listing near option parser — **likely misaligned false positive** (see §8); not a disk driver |

**Vector install evidence (CFG):**

- `0B12` get-vector AL=33h  
- `0BA1` set-vector AL=33h DX≈0B5Eh  
- `1036` set-vector AL=33h (restore/uninstall path)  
- Also get/set of other vectors (e.g. INT 10h) around 07FD–0849 for chaining/video.

**I/O:** direct `in`/`out` for IRQ unmask and serial/hardware control in low resident code.

---

## 7. Architecture (TSR? etc.)

**Yes — classic DOS mouse TSR / device driver architecture.**

Evidence:

1. **Strings:** “load CuteMouse as new TSR”, “uninstall driver, remove TSR from memory”, “Resident part reset to…”, “do not allow CuteMouse to move itself into UMB”.
2. **INT 33h hook:** save old vector, install new handler, restore on unload.
3. **Split layout:** low IPs = resident handlers (`iret` epilogue at `func_0A76`); high IPs ≈ 0B0E+ = transient install, CLI, messages, then discard/relocate.
4. **Memory management:** INT 21h AH=48/49/58 — allocate, free, strategy (UMB-related); copy loop `rep movsw` of resident image; MCB-ish word stores near `func_1046`.
5. **Not** a pure one-shot utility: after install it remains as the INT 33h provider.

Architectural layers (inferred):

```
[CLI / install transient] ──probe──► [PS/2 INT15 C2 | serial UART]
         │                                    │
         ▼                                    ▼
   set INT 33h  ◄──────────────────── [packet decode / buttons / wheel]
         │
         ▼
   apps via INT 33h; optional user callback far call
```

---

## 8. Listing quality notes (`func_*` labels, call rewrite)

| Metric | Value |
|--------|--------|
| Procedure labels `func_<IP>` | **57** |
| Instructions listed | **1339** |
| `call`/`jmp` rewritten to `func_*` | **87** (sample) |
| Conditional/other branches still numeric `0x…` | many (~155 jcc/call/jmp forms still absolute) |
| Blank lines after `ret`/`retf`/`iret` | yes (procedure separation) |
| INT comments | Ralf Brown–style annotations when AH known |
| Symbols from external `.sym` / `--map` | none present; all synthetic `func_*` |

### Strengths

- Multi-pass CFG-driven labeling: entry `func_0000`, install `func_0B0E`, helpers `func_00C7` / `func_00F2`, print `func_1007`.
- Near **call** targets frequently rewritten (`call func_029B`, `call func_0DA2`, etc.).
- Interesting-block CFG correlates INT tags with string xrefs usefully for navigation.

### Weaknesses / noise

1. **Data-as-code:** region ~0B02–0B0A disassembles ASCII `"teMous…"` / version fragment as instructions before `func_0B0E`.
2. **Option parser mis-sync:** around IP 0FC1–0FC2, `mov di, 0x13cd` overlaps a spurious `int 0x13` — CFG **INT13-disk** tag is not trustworthy.
3. **AH recovery errors:** e.g. `0BA1` set-vector AL=33h correctly in CFG detail, but listing comment sometimes says “Phar Lap … SET EXCEPTION HANDLER” for plain DOS AH=25h.
4. **Overlapping decode** near terminate/print (`0FF0`–`1006`): mixed data/control; `AH=4C` exit still visible.
5. **jcc targets** often left as `0x10xxx` flat addresses rather than `func_*` labels.
6. Entry listed as IP `0000` while MZ COM entry is IP `0100` — document the org convention when correlating to COM listings.

Overall: **good structural map for a 5.8K COM-in-EXE**, not a clean source-level listing.

---

## 9. What remains unknown without source

- Exact module/file split of original assembly (which `.asm` units, macros, build flags beyond tool guess).
- **Assembler version proof independent of dumpexe** (JWASM 1.80 vs other MASM-compatible assemblers producing equivalent code).
- Full INT 33h function-number dispatch table and complete API surface.
- Precise serial protocol state machines and timing constants (need careful data-flow RE).
- Wheel / USB-BIOS detection algorithm details (`/O`).
- Exact UMB relocation and MCB patching sequence correctness conditions.
- Whether “rebuild-proven byte-identical with jwasm-1.8.exe” holds for *this* file copy (tool asserts it; this blind session did not re-run a rebuild).
- Copyright/author strings beyond product banner (not prominent in dumpexe string set).
- Runtime behavior under real DOS (not executed here).

---

## 10. Confidence table

| Finding | Confidence | Basis |
|---------|------------|--------|
| **Product:** CuteMouse 2.1 beta4 [FreeDOS] | **98%** | Banner + help strings in-image; dumpexe agrees |
| **Assembler version:** JWASM 1.80 | **50% pure-blind / 98% tool-trust** | No assembler ID string; dumpexe fingerprint + rebuild claim at 98% |
| **Architecture:** COM-in-EXE mouse **TSR** installing INT 33h | **95%** | MZ geometry + vectors + TSR/UMB strings + listing |
| **PS/2 via INT 15h C2h + serial options** | **90%** | Many INT 15h C2 sites + help text + probes |
| **Overall (identity + role)** | **95%** | Strings + control flow sufficient |
| **Overall (full toolchain pin)** | **~70% blended** | Product solid; JWASM 1.80 is tool-dependent |

### Tool vs pure strings (explicit)

| Fact | Pure strings / MZ | dumpexe toolchain DB |
|------|-------------------|----------------------|
| Name CuteMouse | Yes | Yes |
| v2.1 beta4 FreeDOS | Yes (banner) | Yes |
| Mouse TSR / INT 33h | Yes + code | Yes |
| com2exe-style EXE | MZ only | Yes |
| **JWASM 1.80** | **No** | **Yes (primary source of this claim)** |

---

## Appendix — command evidence

```text
Verify: $ /usr/local/bin/dumpexe subject.exe
        /usr/local/bin/dumpexe --strings subject.exe
        /usr/local/bin/dumpexe --json subject.exe
        /usr/local/bin/dumpexe -d --no-asm-file subject.exe
        /usr/local/bin/dumpexe --cfg-interesting --cfg-no-insns subject.exe
exit: 0 (all five)
formal: not run (RE observation only; no code under test)
```

**Report path:** `/tmp/grok-goal-c8d573d7f31d/implementer/blind-ctm-jwasm18/blind-report-v2.md`
