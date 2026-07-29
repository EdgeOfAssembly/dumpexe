# CuteMouse 2.1 beta4 — ground-truth RE notes

## Layout
- Upstream tree: `/tmp/cutemouse21b4` (`bin/`, `source/ctmouse/`, `doc/ctmouse/`)
- Fixture copies: `games/cutemouse/bin/ctmouse.exe` (+ `ctm-en.exe`)

## Toolchain (proven)
- **Assembler:** JWASM (MASM-compatible), historically TASM; see `doc/ctmouse/jwasm.txt`
- **Build:** `jwasmd -mt` → `tlink /x` → `exe2bin` → **`com2exe -s512`**
- **Not** Pascal MT+ / high-level compiler

## Binary shape
- MZ header **32 bytes**, **0 relocs**, **CS:IP = FFF0:0100**, SS=FFF0
- Classic **COM-in-EXE** wrapper (com2exe)
- Strings: `CuteMouse`, `CuteMouse v2.1 beta4`, unload messages
- Map segments (`ctmouse.map`): `_TEXT` 0..14E3h, tiny `_DATA`, `CONST`

## dumpexe support
- Auto **toolchain** detect (default on): COM-in-EXE + CuteMouse product
- **Symbol maps:** `ctmouse.sym` / `ctmouse.map` auto-loaded next to input
- Listing: multi-pass `-d` uses map names when present (`start` at image 0)

## Expanding symbols
Full public symbol recovery needs a richer map/listing from a successful rebuild
or manual `.sym` lines (`<IP_hex> <name>`). Source has ~98 `proc`s and `::` globals
in `source/ctmouse/ctmouse.asm` + `asmlib/`.
