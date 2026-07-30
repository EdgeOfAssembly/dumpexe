# Adding compiler / assembler support to dumpexe

This is the **official workflow** for teaching dumpexe a new DOS toolchain
(compiler or assembler) so it can detect binaries and emit useful (ideally
assemblable) output.

## The method (easy when ground truth exists)

```text
1. Find DOS software/game with BOTH:
     • shipping binaries (MZ / COM / OVL / …)
     • source tree (or rebuildable sources)
   Prefer packages that hint the tool (makefile, README, history).

2. Static RE with dumpexe (and friends):
     dumpexe file.exe
     dumpexe --strings / -d / --json / --cfg-dot=…

3. Identify candidate toolchain + version window
     (timestamps, docs, “built with TASM/JWASM/Pascal MT+ …”).

4. Obtain that exact tool version if possible
     • keep versioned under bin/<tool>/name-X.Y
     • backup under /mnt/re-tools/…

5. Reproduce the build
     assemble/compile → link → pack (exe2bin, com2exe, …)
     cmp load images (and full EXE when headers match).

6. If binaries match (or match within documented deltas):
     officially add support in dumpexe:
       • fingerprint / detect (default ON; only --no-… to disable)
       • listing / export tuned for that tool
       • tests + fixture under games/ or fixtures/
       • notes in RE-NOTES + this doc

7. Dual-write durable facts:
     pmem + ~/.grok/memory + git commit/push
```

## Why this works

| Without sources | With sources + same tool |
|-----------------|---------------------------|
| Product/strings, layout, CFG | Author names, exact encodings |
| Heuristic “looks like JWASM” | **Rebuild-proven** “is JWASM 1.80” |
| Human listing (`func_*`) | Assemblable export / golden tests |

Blind RE can still score high on *identity* and *architecture*; **version pins**
and **round-trip asm** need ground truth (or a perfect map).

## Memory model rules (JWASM export)

| Image | Model | Notes |
|-------|--------|--------|
| Pure **.COM** | **tiny** always | ≤64KB single segment; **no exceptions** |
| **COM-in-EXE** (com2exe, CS:IP FFF0:0100) | **tiny** always | Same as COM; `--model=` ignored |
| Unknown non-COM | **small** default | Override: `--model=tiny\|small\|medium\|…` |

## CLI policy (always)

- Sane defaults; default-ON features only get `--no-*`.
- No-args → usage; always `-h`/`--help`, `-v`/`--version`.
- Inputs and options any order (where applicable).
- See skill `cli-design` / rule `14-cli-sane-defaults`.

## Case study: CuteMouse 2.1b4 → JWASM 1.80

| Step | Result |
|------|--------|
| Package | `/tmp/cutemouse21b4` (bin + source + docs) |
| Hint | history/makefile: Japheth JWASM, `jwasmd -mt`, com2exe |
| Timestamps | sources/binary **2008-07-11**; JWASM **1.8** released **2008-06-21** |
| Tool kept | `bin/jwasm/jwasm-1.8.exe`, `jwasmd-1.8.exe` (+ 1.7); `/mnt/re-tools/jwasm/` |
| Rebuild | wine jwasm-1.8 + wlink + exe2bin + com2exe wrap → **byte-identical** EXE |
| dumpexe | Toolchain auto: **JWASM 1.80** @ ~98%; COM-in-EXE; product CuteMouse |
| Export | `-d` on JWASM-detected images → JWASM-oriented `.asm` (model tiny for COM) |
| Fixture | `games/cutemouse/` |
| Blind tests | `games/cutemouse/analysis/blind-report*.md` |

### Reproduce CuteMouse (summary)

```bash
# From CuteMouse source tree (asmlib includes, ctmouse.msg present):
wine bin/jwasm/jwasm-1.8.exe -mt -Iasmlib -Iasmlib\\bios -Iasmlib\\convert \
  -Iasmlib\\dos -Iasmlib\\hard -Fo ctmouse.obj ctmouse.asm
wlink name ctmouse-raw.exe format dos file ctmouse.obj
exe2bin ctmouse-raw.exe ctmouse.bin
# wrap as com2exe -s512 (32-byte MZ, CS:IP=FFF0:0100) → compare to bin/ctmouse.exe
```

## Case study: ICON (Quest for the Ring) → Pascal MT+ 3.1.1

| Step | Result |
|------|--------|
| Package | `games/icon-quest-for-the-ring/` |
| Tool | Pascal MT+86 3.1.1 (RTL sources under `/tmp/Pascal MT-86 3.1.1 for MSDOS`) |
| dumpexe | Default Pascal MT+ report (entry, segtable, jump table, fingerprints) |
| Disable | `--no-pascal-mt` only |

## Checklist for a new toolchain PR

- [ ] Fixture binary (+ optional sources path documented)
- [ ] Versioned tool binary in `bin/<tool>/` if we own a copy
- [ ] Fingerprint in product code (e.g. `pascal_mt.h`, `toolchain.h`)
- [ ] Default ON; only `--no-…` to disable
- [ ] Listing/export behavior documented (human vs assemblable)
- [ ] `make test` contracts (detect + JSON if applicable)
- [ ] RE-NOTES or `docs/` update
- [ ] pmem + Grok memory dual-write
- [ ] Commit FEATURE/FIXUP + push

## What “support” means (levels)

| Level | Meaning |
|-------|---------|
| **L1 Detect** | Name tool/version with evidence; confidence |
| **L2 Annotate** | Jump tables, RTL sites, INT notes, symbols from `.sym` |
| **L3 Export** | Assemblable source for that tool (byte-exact `db` + labels OK) |
| **L4 Round-trip** | Export → tool → binary matches golden (or documented delta) |

CuteMouse/JWASM 1.80: **L1–L2 solid**, **L3 in progress** (JWASM export path), **L4 proven from original sources** (not yet from pure reverse export).

## Related paths

| Path | Role |
|------|------|
| `bin/jwasm/` | Versioned JWASM 1.7/1.8 |
| `games/cutemouse/` | CuteMouse fixture + RE-NOTES |
| `games/icon-quest-for-the-ring/` | ICON / Pascal MT+ campaign |
| `pascal_mt.h` | Pascal MT+ 3.1.1 |
| `toolchain.h` | COM-in-EXE, JWASM 1.8, CuteMouse |
| `listing.h` | Multi-pass listing + JWASM export |
| `/mnt/re-tools/jwasm/` | Durable tool backup |

## Case study: Catacomb → Turbo Pascal 5.5

| Step | Result |
|------|--------|
| Package | `/tmp/Catacomb` sources + `/usr/share/games/TP5.5` |
| Build | `MAKECAT.BAT`: TASM catasm/soundlib + `tpc -b catacomb` |
| DOSBox | mount C games, D Catacomb; PATH includes TP5.5 + TASM\BIN |
| Proof | `CATACOMB.EXE` produced (~137 KB) |
| dumpexe | **Turbo Pascal 5.5** auto @ ~97%; product Catacomb |
| Fixture | `games/catacomb/` |
| Export | `-d` → **Turbo Pascal–oriented** TASM byte export (`.MODEL LARGE`, PROC/ENDP, `db` + comments) |
| Note | Fixed false JWASM from 0xFC-only heuristic on TP EXEs |
