# Catacomb — Turbo Pascal 5.5 ground truth

## Layout
- Sources: `/tmp/Catacomb` (Flat Rock / GPL sources)
- Compiler: `/usr/share/games/TP5.5` (TPC.EXE 5.5)
- Assembler for `{$L}` units: `C:\TASM\BIN\TASM.EXE` (PATH)
- Fixture binary: `games/catacomb/bin/CATACOMB.EXE` (rebuild 2026-07-30)

## Rebuild (DOSBox + Xmux)

```text
SPECTATOR: xmux attach catacomb-build --no-reconnect
```

```bash
# conf mounts C=/usr/share/games D=/tmp/Catacomb
# PATH=C:\DOS;C:\TP5.5;C:\TASM\BIN;C:\BORLANDC\BIN
dosbox -noprimaryconf -conf /tmp/Catacomb/dosbox-build.conf
# or from /tmp/Catacomb: dosbox .  then D: and PATH fix if needed
MAKECAT.BAT
# tasm catasm → tasm soundlib → tpc -b catacomb
```

**Note:** `SOUNDLIB.ASM` assembles fine with TASM here (SOUNDLIB.OBJ produced).
If sound fails on another machine, undefine `{$DEFINE SOUNDS}` / stub SPKLIB.

## Toolchain (proven)
- **Turbo Pascal 5.5** (TPC) + **TASM** for CATASM.OBJ / SOUNDLIB.OBJ
- Units: SPKlib, CTRlib, CGAscr, CGAdata, EGAdata + linked OBJs

## dumpexe
- Auto **Turbo Pascal 5.5** detect (default with toolchain)
- Does **not** false-positive JWASM (0xFC padding alone no longer claims JWASM)
- Pascal MT+ still used for ICON (different product)

## Binary shape (rebuild)
- Size ~136992, header 0x400, ~248 relocs, CS:IP 0000:4285
- RTL: `Runtime error ` string; many `55 89 E5` frames; far CALLs at entry
