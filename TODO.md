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
- [x] dumpexe 2.24. The leader-cover stop applies only to opcode 00, so a real instruction that overlaps a speculative INT-nearby seed stays decoded. A zero hole still does not swallow the next leader. main is still 2.13. P1 has not started. L11-J is not in this round.
- [x] dumpexe 2.23 P0 remainder. 'ZM' is accepted as MZ. An empty load image is an error on stderr and exit 1. A near target outside the image is printed as SSSS:OOOO (outside image). Zero `--uasm-verify` candidates say `; NOT VERIFIED (0 candidates)` and do not spawn. A sized branch is demoted to `db` only in the segment that does not define the label. The instruction after a call is decoded even when the following bytes are mostly zero. NE `-a` disassembles each distinct CODE segment once and stops at min(16 MiB, twice the file size). The MZ/COM load image, including an unpacked listing, is capped at 1114112 bytes; `--max-image=N` raises it. bin2exe accepts a 16-byte header when `e_cparhdr` is 1 and the relocation table fits. A zero-length Deark `dbuf_copy` returns before forming a pointer from a NULL membuf. `main` is still 2.13. P1 has not started.
- [x] dumpexe 2.22 P0 pre-merge. PATH search skips an empty or relative component, so a cwd `./uasm` is not run. `--uasm-bin` and `$DUMPEXE_UASM` may still be relative. `--uasm-verify` passes `-e100000`, does not offer a branch whose operand is a number, and when recovery stops early the header says how many candidates were rejected and how many were left unverified. `main` is still 2.13. P1 has not started.
- [x] N1 wrapper false fail on 2.21 `805aadf`. `p0_acceptance.sh` N1 failed on this host when arg 3 was `with_usr_bin_uasm.sh`. That script copies `/workspace/rev1006/exe/bin/uasm` and runs under `set -e`. The path is not on this machine, so the wrapped run writes no listing and the compare looks like a regression (`without='db 08Bh, 0C3h' with=''`). It is not a product failure. Default `--uasm` does not spawn. Hiding `/usr/bin/uasm` with `unshare -rm` and a bind-mount of a non-assembler left the same `db 08Bh, 0C3h` listing as the normal run (`N1_OK`).
- [x] dumpexe 2.21 P0 re-review. An INT in the first 64 KiB is seeded at frame 0 even when the entry frame is higher. An equ literal whose first hex digit is A–F is written with a leading 0 (`0A004h`). A near or short branch to a label defined in another `sN` segment stays `db`. `--uasm-verify` drops a line the assembler rejects and does not call that listing verified. A relative assembler path, a directory named `uasm` on `PATH`, and `$UASM` in the child environment do not break verify. `main` is still 2.13. P1 has not started.
- [x] dumpexe 2.20 P0 merge gate. `ret 0` / `retf 0` stay `db`. A sized branch whose label is not emitted becomes `equ sN_base+(off-org)`, or `db` when that equ is in another segment. A wrapping rel8 stays `db`. Default `--uasm` does not spawn an assembler (`--uasm-verify` is enable-only, one spawn per listing). A negative CS entry keeps a signed frame. INT-seed lookup and string xrefs are not quadratic. `main` is still 2.13. P1 has not started.
- [x] dumpexe 2.19 P0 slice. An MZ entry inside the load image is decoded at its linear address, including past 64 KiB. Near flow wraps inside that segment (`cs * 16`) and does not spill into the next 64 KiB. A relocation-pinned far target past 64 KiB is followed when `seg*16+off` is still inside the image. An entry outside the image is not labeled `func_FFFF`, and `--cfg` / `--json` still seed IP 0 for that entry. Addresses at or below `0xFFFF` stay four hex digits. P1–P7 are not in this tree.
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
