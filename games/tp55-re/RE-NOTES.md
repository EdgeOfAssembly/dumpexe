# Turbo Pascal 5.5 product RE notes (`/usr/share/games/TP5.5`)

## What this tree is

| Content | Role |
|---------|------|
| `TPC.EXE` / `TURBO.EXE` | Compiler + IDE **binaries** (not open source) |
| `TURBO.TPL` | **Precompiled RTL** (System, Crt, Dos, Overlay, Printer, …) |
| `GRAPH.TPU` | Graph unit binary |
| `*.PAS` demos | Borland **examples** (BGI, OOP, TCALC, …) |
| `*.ASM` + `*.OBJ` | Demo **assembler helpers** for OOP streams / TCALC / windows |
| `DOC/`, `README` | Product documentation |

**Not** the source of the TPC compiler. **Is** the official 5.5 distribution used to rebuild Catacomb.

## Useful for RE (yes)

### 1. RTL fingerprints in `TURBO.TPL` (linked into every TP EXE)

| Symbol / string | Use |
|-----------------|-----|
| `Runtime error \0 at \0.\r\n` | Primary TP/BP detect (also in Catacomb EXE) |
| `RUNERROR`, `ERRORADDR`, `EXITPROC`, `EXITCODE` | System unit globals |
| `HEAPORG`, `HEAPPTR`, `FREEPTR`, `HEAPERROR`, `STACKLIMIT` | Heap/stack |
| `OVRHEAP*`, `OVRINIT`, `OVERLAY.PAS` | Overlay unit |
| `IORESULT`, `FILEMODE`, `INPUT`, `OUTPUT` | I/O |
| Unit markers `SYSTEM`, `CRT`, `DOS`, `PRINTER`, `OVERLAY` | TPL directory |
| Internal objs listed as `HEAP.OBJ`, `MAIN.OBJ`, `ERRC.OBJ`, … | How Borland split the RTL |

Catacomb’s `Runtime error ` blob matches TPL’s pattern (relocated data addresses differ).

### 2. Calling convention from demo ASM (ground truth)

From `BUFSTM.ASM` / OMF pubs:

```text
Method naming:  TypeName@MethodName   e.g. BufStream@Flush, DosStream@Read
Calling:        FAR PROC (methods)
Self:           DWORD PTR [BP+6]  (far pointer @Self)
Stack cleanup:  RET 4 / RET n after POP BP
Frame:          PUSH BP / MOV BP,SP  (55 8B EC or 55 89 E5)
```

OMF public symbols recovered from demo OBJs:

| OBJ | Publics |
|-----|---------|
| BUFSTM.OBJ | `BUFSTREAM@FLUSH`, `@READ`, `@WRITE`, `@GETPOS` |
| DOSSTM.OBJ | `DOSSTREAM@OPEN/CLOSE/READ/WRITE/SETPOS/...` |
| STREAM.OBJ | `STREAM@GET`, `STREAM@PUT`, `STREAMERROR` |
| WIN.OBJ | `WRITESTR`, `WRITECHAR`, `FILLWIN`, `WINSIZE`, … |
| TCCOMPAR.OBJ | `COMPARE` |
| TCMVSMEM.OBJ | `MOVETOSCREEN`, `MOVEFROMSCREEN` |

→ When RE’ing TP EXEs, **far calls** and **`ret n`** after frames are normal; method names won’t appear unless debug/map, but **layout matches** these demos.

### 3. Compiler binary `TPC.EXE`

- Banner: `Turbo Pascal Version 5.5  Copyright (c) 1983,89 Borland International`
- CLI switches: `/B` build all, `/M` make, `/U` unit dirs, `/Fxxx` find runtime error, …
- Keyword table in binary: `UNIT`, `INTERFACE`, `IMPLEMENTATION`, `USES`, `INLINE`, `EXTERNAL`, `INTERRUPT`, OOP `DESTRUCTOR`, …
- Entry CS:IP `0000:0000`, small reloc count — **not** a typical app EXE shape
- Full decompile of TPC is a multi-year project; **strings + switch table** already help identify “built with TPC 5.5” environments

### 4. What does *not* recover Catacomb `.PAS`

Demo sources ≠ game sources. They teach **conventions**, not Catacomb’s identifiers.  
Recovering Catacomb Pascal still needs: game sources (`/tmp/Catacomb`), maps, or heavy interactive RE.

## Implications for dumpexe

| Already | Enhanced from this RE |
|---------|------------------------|
| Detect TP via `Runtime error `, frames, far CALLs | Extra TPL globals as optional evidence |
| TP export: PROC/ENDP, `[TP near frame]`, `[far call / unit]` | Document `@Method` naming for future symbol maps |
| Catacomb rebuild-proven 5.5 | TPL string catalog for confidence |

## Files in this fixture

- `analysis/obj-symbols.md` — OMF publics from demo OBJs  
- `analysis/tpl-strings.txt` — filtered TPL strings (generated)  
- This `RE-NOTES.md`
