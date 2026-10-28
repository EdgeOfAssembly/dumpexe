# Changelog

All notable changes to dumpexe. The version is `DUMPEXE_VERSION` in
`version.h`; `dumpexe --version`, the JSON `version` field and the man page
show it. Earlier work is summarised from `TODO.md` ("Done" and "Near-term").

## 2.46.0 (2026-10-28)

### Added

- Function-pointer variables: near and far cell stores (immediate or
  `mov r,imm`), static initializers in DGROUP and far code-pointer tables
  (vtables) anchored on decoded code seed new functions in the cell's own
  frame. Near initializers are used only with independent evidence.
- Unguarded byte-index jump tables are bounded by the index width and the next
  code; holes are skipped, and slots after a hole are kept only inside the
  span of the handler before it.
- Function starts right after a terminator (or padding) are seeded when a
  straight-line trial decode is clean, anchored, and never touches known code,
  relocations or addresses used as data. These starts are tried after the
  fixpoint, never before indirect-jump tables, ES/SS/computed bases.
- Callback arguments are followed through far slots (`call dword ptr [bp+d]`
  with a relocated segment or `push cs`) and from far callers (`9A`, arguments
  at `bp+6`).

### Fixed

- PKLITE 1.50 small compressed files (v1): `0xfe` is treated as an
  uncompressed area when the decompressor does.
- Far pointer runs that hold the base of an indexed far `jmp`/`call` are left
  to the jump-table rules instead of the function-pointer rules.

## 2.45.0 (2026-10-25)

First tagged release.

### Changed

- A file with no mode switch now gets the full `-a` analysis (header,
  relocations, hex dump, multi-pass listing, strings, unpacking, and the
  default `<stem>.asm`). Mode switches are `-r -x -d --strings --json --uasm
  --cfg --cfg-interesting --cfg-dot --simulate --xrefs`; modifiers such as
  `--base`, `-n` or `--no-*` do not count. New `--header-only` prints the
  header report and entry preview only (the old default).
- `--uasm` help and error text: NE is supported (since 2.39); the error for a
  32-bit extender payload or a `.SYS` file now says "16-bit MZ, COM and NE".
- The build requires Capstone 6 (`pkg-config capstone >= 6.0`).
- Tests refer to the private fixtures by generic ids (`fx01`...`fx12`,
  `s01`...`s07`) and find them by SHA-256; no private path or title is in the
  repository. Product-specific scoring and comments were removed from the
  toolchain and string-tag code, so detection stays generic.
- The version string is `2.45.0` everywhere (binary, JSON, man page, README).
- The private session notes (`LAST_SESSION`, `logs/`) are no longer tracked.
- THIRD_PARTY_NOTICES names the runtime of each static build: libstdc++ and
  libgcc (GPL-3.0 with the GCC Runtime Library Exception) for the default
  build, musl for musl builds, libc++/libc++abi/libunwind for zig builds.

### Added

- Generic jump-table and indirect-call recovery for `--uasm-verified`, with
  tentative slots after a hole only on independent evidence, and table bounds
  from a dominating index range guard and `and` masks (near and far tables,
  bias, inverted guards; repros in `tests/test_jump_tables.sh` and
  `tests/n8_syn`).
- UASM readability round 1: quoted ASCII data, high-bit text comments, INT 21h
  DOS comments, `func_` call targets.
- `CHANGELOG.md`, `COPYING` (GPL-2.0 text), complete `THIRD_PARTY_NOTICES.md`,
  README exit-status and prerequisites sections, and the 11 missing options in
  the man page.

### Fixed

- `pair_key` read instruction fields with no bound (review B6): it now reads
  only the unit's own bytes, and a field of size 0, more than 8 bytes, or past
  the unit is class `x`. `pair_key` bounds the unit before `decode()`, and
  `pair_verified` checks the length before reading the first byte
  (tests/test_pair_bounds.cpp).
- `make test` honours the caller's `-jN` / jobserver.

## 2.44

- Linker fingerprints from MZ header bytes 1Ch..1Fh (TLINK series, MS LINK,
  TPC), BC++ 3.1 memory model, TLINK `/v` trailer, TP 7.0 stack check; toolchain
  and linker in `--json`.
- `--uasm-verified`: segment layout (DGROUP and huge far data as data), Borland
  init/exit records, DS=CS INT 21h/25h handlers, stored code pointers and code
  pointers passed as callback arguments are seeded; the Borland FP emulator is
  decoded; Turbo Pascal Halt/RunError ends code before zero padding.
- Simulator `imul`/`mul`/`div`/`idiv` without signed overflow; #DE on quotient
  overflow (UBSan regression test).

## 2.43

- Simulator refactor (`CpuRegs`, allocator in `SimState`, more instructions)
  and multi-path exploration: `--sim-paths`, `--sim-fork-depth`,
  `--sim-total-insns`, `--sim-no-dispatch-int`.

## 2.36 - 2.42

- NE (Win16): chained relocations, entry table, resident and non-resident
  exports, KERNEL/USER/GDI ordinal names; `--uasm` on NE writes one verified
  listing per code segment plus `.nemap`/`.neskel`, and the new `bin2ne`
  rebuilds the file byte-identically (2.39).
- `--hints`, `--hints-out`, `--bytemap`, `--explain`, `--strict` (2.40).
- Pointer and string typing, `jt_`/`str_`/`cstr_`/`ptrtab_` names (2.41).
- Verified pair table and `@m16`/`JS8` pins; listings without UASM keep only
  shapes proven to reassemble (2.42).

## 2.30 - 2.35

- Image model and flow records (2.30), the verified UASM emitter
  (`--uasm-verified`, 2.31), `--uasm-header` whole-EXE rebuild (2.32), bounded
  jump tables and string pointers (2.33), fixpoint between tables and the
  graph (2.34), `--evidence=sim` (2.35). Toolchain detection reruns on the
  unpacked image.

## 2.13 - 2.29

- Structural packer detection and in-process unpacking with Deark modules
  (Microsoft EXEPACK, LZEXE 0.90/0.91, PKLITE, DIET, LHarc), `_UNPACKED`
  outputs, `--uasm` export for COM and MZ with `uasm -bin` / `uasm -mz` round
  trips, relocated far-call following, `.SYS` CFG walking, `ZM` signature,
  load-image cap (`--max-image`), and many review fixes. `bin2exe` 0.1/0.2.

## Before 2.13

- TDUMP-style MZ header report, relocation table, hex dump, Capstone
  disassembly, multi-pass listing, `.COM` PSP detection, `.SYS` headers,
  Pascal MT+ and JWASM 1.8 fingerprints, auto-repack, static CFG
  (`--cfg`, `--cfg-dot`), `--json`, `--strings`, and the DOS load simulator
  (`--simulate`, `--bp`, `--dump`, loop limits).
