# dumpexe — TODO

Living roadmap for the DOS RE toolkit and ICON preservation work.

## Done (recent)

- [x] MZ `final_len==0` size fix, reloc padding, always-load relocs
- [x] EXE load model (PSP = base−10h), call-following sim trace
- [x] 1 MiB arena + step loop + INT 21 FCB/handle stubs
- [x] Flexible breakpoints (`--bp=…`) and `--dump=`
- [x] Tight-loop back-edge limit (`--loop-limit` / `--loop-span`)
- [x] Static CFG recovery (`--cfg`)
- [x] CFG annotations: INT sites (AH best-effort), string xrefs, RE tags
- [x] Interesting-block summary (`--cfg-interesting`)

## Near-term

- [x] Richer AH recovery across **predecessor** blocks
- [x] FCB path recovery: DX imm + default `DS:005C`; Pascal inline `call/db len,'name'`
- [x] Overlay/map/dat tags (`icon0.ovl`, `l?.map`, …)
- [x] Load/I/O call graph from path+FCB seeds (`cfg_print_load_graph`)
- [x] MAP/ADV/DAT working notes (`games/icon-quest-for-the-ring/FORMAT-NOTES.md`)
- [x] UASM-friendly listing export (2.12, `--uasm`). No address column. COM round-trips with `uasm -bin` and keeps `end func_0100`. A single-segment EXE does too. An image past 64KB is `sN segment` blocks and ends with a bare `end`, so `uasm -bin` accepts it. EXE load images also round-trip with `uasm -mz`. `.model` is emitted before `.186` / `.286` / `.386`. A signed-byte AX imm16 stays db.
- [x] dumpexe 2.18 P0 slice. A listing plus `--cfg`, `--cfg-dot`, or `--json` builds the annotated CFG once and reuses it. An entry past 64 KiB is still not seeded in the listing. `--cfg` and `--json` still seed IP 0 for that entry. A COM without a PSP still prints file offsets minus `0x100` and does not write DOT from that shared path. Q5 and P1–P7 are not in this tree.
- [x] dumpexe 2.17 P0 slice. `strings.h` is now `dx_strings.h` (guard `DX_STRINGS_H`). `--uasm-stats` prints one stderr coverage line and does not imply `--uasm`. A synthetic COM shift test checks that a sized branch follows an inserted `nop` and a frozen `db` displacement does not. Q5, Q11, and P1–P7 are not in this tree.
- [x] dumpexe 2.16 P0 slice. A relocated far `9A`/`EA` is followed at `seg*16+off` inside the load image. A non-relocated far transfer still matches the file CS. `--uasm` prints a relocated `mov r16, imm16` as `mov rx, (dxfrm_XXXX - dximg0) SHR 4` when that frame is in the image. Q4, Q5, Q10, Q11, and P1–P7 are not in this tree.
- [x] dumpexe 2.15 P0 slice. `--uasm` prints `cbw`/`cwd`, sized near branches, and keeps any other non-branch line only when `uasm` assembles it back to the same bytes. `-d` prints `cbw`/`cwd` for opcodes 98/99 unless a 66h prefix is present. INT 20h, INT 27h, and INT 21h with AH 00h, 4Ch, or 31h end the CFG walk. Q4, Q5, the relocation half of Q7, Q8, Q10, Q11, and P1–P7 are not in this tree.
- [x] dumpexe 2.14 P0 slice. Direct `lcall` and immediate `ljmp` set CS:IP. Opcode 98 (Capstone `cwde` in 16-bit mode) sign-extends AL. NE `-d` and `-a` stop at the on-disk segment. Q1, Q2, Q4, Q5, Q7 through Q11, and P1–P7 are not in this tree.
- [x] dumpexe 2.13 bugfix. File CS far calls at the default base. Guest-file cap 64 with capacity released on truncate. Listing refuses to clobber the input or a symlink and returns non-zero. `--uasm` does not write `_UNPACKED` unless `-d` or `-a`. LHarc needs a checksum and an SFX trailer. LZEXE 0.90 minalloc covers the stack. JSON has one `edges` array and `n_edges`, plus `packer`. A rejected MZ with `--json` is one object and exit 1. Chained `.SYS` is not reported as COM. `--max-insns=-1` is a usage error. The multipass design was not in 2.13.
- [x] bin2exe 0.2. `--header` appends a matching original tail unless `--no-tail`. An existing default `<stem>.exe` is kept (exit 1, pass `-o`). The write is a no-follow temporary file renamed into place. A bad header error names the `--header` path.
- [x] **bin2exe** 0.1, built and installed with dumpexe (`tools/bin2exe/`). Default COM wrap (`CS=SS=FFF0`, `IP=0100`, `SP=FFFE`). `--header` copies an original MZ header unchanged. dumpexe does not exec bin2exe.
- [ ] Validate MAP 64×H decode vs DOSBox screenshot
- [ ] On FCB AH=27 hit, dump DS:5C name (sim or DOSBox) for real `LA.MAP` strings
- [ ] Propagate DX/AH through more than fall/call preds (memory stores to FCB@5C)

## Medium-term

- [ ] Sim edge-coverage overlay on CFG (“this edge taken in run”)
- [x] `--strings` standalone string dumper with file offsets
- [ ] Better COM simulation parity with EXE engine
- [ ] ICON: document jump-table @ `0090h` slot → procedure names

## Last / polish

- [x] **Graphviz export** (`--cfg-dot=FILE.dot`) — colored nodes (entry/interesting/table/call), edge kinds
- [x] **Machine-readable** (`--json`) — header, Pascal MT+, strings, CFG summary/edges
- [ ] Interactive TUI walker (optional)

## ICON preservation end goals

- [ ] Reassemblable UASM sources that build under Linux and run in DOSBox
- [ ] Optional high-level C23 port later
