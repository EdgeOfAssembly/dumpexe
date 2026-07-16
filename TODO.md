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
- [ ] Validate MAP 64×H decode vs DOSBox screenshot
- [ ] On FCB AH=27 hit, dump DS:5C name (sim or DOSBox) for real `LA.MAP` strings
- [ ] UASM-friendly listing export (per-block, ORG, labels at BB starts)
- [ ] Propagate DX/AH through more than fall/call preds (memory stores to FCB@5C)

## Medium-term

- [ ] Sim edge-coverage overlay on CFG (“this edge taken in run”)
- [ ] `--strings` standalone string dumper with file offsets
- [ ] Better COM simulation parity with EXE engine
- [ ] ICON: document jump-table @ `0090h` slot → procedure names

## Last / polish

- [ ] **Graphviz export** (`--cfg-dot=FILE.dot`) — pretty CFG rendering, cluster by segment/overlay, color interesting nodes (INT21/FCB/strings). Keep as **last** visualization feature after analysis quality is solid.
- [ ] Interactive TUI walker (optional)

## ICON preservation end goals

- [ ] Reassemblable UASM sources that build under Linux and run in DOSBox
- [ ] Optional high-level C23 port later
