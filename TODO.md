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
- [x] dumpexe 2.13 bugfix. File CS far calls at the default base. Guest-file cap 64 with capacity released on truncate. Listing refuses to clobber the input or a symlink and returns non-zero. `--uasm` does not write `_UNPACKED` unless `-d` or `-a`. LHarc needs a checksum and an SFX trailer. LZEXE 0.90 minalloc covers the stack. JSON has one `edges` array and `n_edges`, plus `packer`. A rejected MZ with `--json` is one object and exit 1. Chained `.SYS` is not reported as COM. `--max-insns=-1` is a usage error. The multipass design is not in this tree.
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
