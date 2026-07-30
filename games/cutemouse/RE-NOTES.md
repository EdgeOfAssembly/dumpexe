# CuteMouse 2.1 beta4 — ground-truth RE notes

## Layout
- Upstream tree: `/tmp/cutemouse21b4` (`bin/`, `source/ctmouse/`, `doc/ctmouse/`)
- Fixture: `games/cutemouse/bin/ctmouse.exe` (+ `ctm-en.exe`, `.sym`, `.map`)
- Method doc: `docs/TOOLCHAIN-SUPPORT.md`

## Toolchain (rebuild-proven)
- **Assembler:** **JWASM 1.80** (Japheth; MASM-compatible). Historically also TASM.
- **Build:** `jwasmd -mt` → `tlink` / `wlink` → `exe2bin` → **`com2exe -s512`**
- **Not** Pascal MT+
- **Tool binaries:** `bin/jwasm/jwasm-1.8.exe`, `jwasmd-1.8.exe` (also 1.7); backup `/mnt/re-tools/jwasm/`
- **Proof:** assemble with jwasm-1.8 + link + wrap → **byte-identical** to shipped `ctmouse.exe`

## Binary shape
- MZ header **32 bytes**, **0 relocs**, **CS:IP = FFF0:0100**, SS=FFF0
- **COM-in-EXE** → memory model **always tiny** (≤64K; `--model=` ignored)
- Banner: `CuteMouse v2.1 beta4 [FreeDOS]`

## dumpexe support
- Auto toolchain: **JWASM 1.80** + COM-in-EXE + product (default on; `--no-toolchain`)
- JSON: `toolchain.jwasm_1_8`, `assembler_version`
- Symbols: `ctmouse.sym` / auto `.map`
- `-d`: JWASM-export path (assemblable layout; model tiny)

## Blind RE reports
- `analysis/blind-report.md` — first blind run (pre–version pin)
- `analysis/blind-report-v2-jwasm18.md` — after JWASM 1.8 detect in dumpexe

## Expanding symbols
Add lines to `bin/ctmouse.sym`: `<image_IP_hex> <name>`  
Source has ~98 `proc`s in `source/ctmouse/ctmouse.asm` + `asmlib/`.
