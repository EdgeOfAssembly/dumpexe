# dumpexe gap analysis — vs Ghidra/BN-class CLI RE (16-bit DOS)

**Scope:** `/tmp/dumpexe` product source only (not `games/` payloads).  
**Date:** 2026-07-29  
**Goal context:** ICON (Quest for the Ring) RE + general 1980s real-mode DOS preservation  
**Sources:** `README.md`, `Makefile`, `TODO.md`, `dumpexe.cpp`, headers (`options.h`, `cfg.h`, `sim.h`, `disasm.h`, `analysis.h`, …), `dumpexe.1`, `examples/`, live CLI via `options.h::show_usage`

---

## Executive summary

**dumpexe today** is a strong **static dump + annotated CFG + best-effort real-mode simulator** for MZ / COM / SYS. It is already more DOS-aware than a generic Capstone wrapper (RBIL INT DB, FCB path recovery, Pascal MT+ inline strings, load/I/O graph).

It is **not** yet a Ghidra/Binary Ninja-class RE tool: no durable database, no multi-segment/overlay project model, no reassemblable listing export, no decompiler/types, no automated test gate, and linear disassembly that does not separate code from data.

For **ICON**, the highest leverage gaps are: **UASM export**, **`make test`**, **overlay-chain / multi-image workflow**, and **runtime FCB name recovery** (static CFG already tags many I/O sites).

---

## 1. Current features (with file refs)

### Formats & CLI entry

| Capability | Where |
|------------|--------|
| Content-based format detect: MZ (`MZ`), SYS (`FFFFFFFFh`), else COM | [`dumpexe.cpp`](../../../../dumpexe.cpp) L67–134 |
| CLI: help/version, reloc/hex/disasm/all, base, COM PSP force | [`options.h`](../../../../options.h) `Options::parse`, `show_usage` |
| CFG flags (`--cfg*`), sim/BP/dump/loop controls | [`options.h`](../../../../options.h) L71–106, L344–469, L503–552 |
| Man page (partially behind live CLI) | [`dumpexe.1`](../../../../dumpexe.1) |
| Build: single TU, Capstone required, C++23, static link | [`Makefile`](../../../../Makefile) |

### MZ EXE static analysis

- Packed `MZHeader` + `RelocEntry` ([`exe.h`](../../../../exe.h))
- Header validation, declared size (`final_len==0` full last page), entry/image sizes ([`analysis.h`](../../../../analysis.h) `validate_header`, `calculate_sizes`, `print_header_info`)
- Relocation load + optional dump with padding ([`analysis.h`](../../../../analysis.h) `load_relocations`, `dump_relocations`)
- Hex+ASCII dump, zero-compression (`*`) ([`formatting.h`](../../../../formatting.h) `print_hex_dump`; wired via `dump_hex`)
- Overlay number field printed; extra bytes beyond declared size noted

### COM / SYS

- COM PSP heuristic (`CD 20` + command-tail) and `--psp` / `--no-psp` ([`com_analysis.h`](../../../../com_analysis.h) `detect_psp`, `analyze_com`)
- COM header summary + linear disasm from entry
- COM “simulation” = initial regs + ~20-insn Capstone **trace** (not full `sim.h` engine) ([`com_analysis.h`](../../../../com_analysis.h) `run_com_simulation`)
- SYS driver header, attributes, strategy/interrupt entry disasm ([`sys.h`](../../../../sys.h), [`sys_analysis.h`](../../../../sys_analysis.h))

### Disassembly & INT annotations

- Capstone x86-16, **linear** from entry → EOF ([`disasm.h`](../../../../disasm.h) `disassemble`)
- Tracks last `mov ah/al` for INT comments
- RBIL-derived compile-time DB: `gen_int_db.py` + `interrupts/INTERRUP.*` → `int_db.h` ([`int_annotate.h`](../../../../int_annotate.h))

### Static CFG (`--cfg`)

- Leader-based recursive-descent CFG: fall / jmp / jcc / call / ret / table edges ([`cfg.h`](../../../../cfg.h) `cfg_build`)
- **Same-segment near control flow only** (header comment L7)
- Near jump-table scan (Pascal MT+ style `E9` stubs) (`cfg_find_near_jmp_tables`)
- Pascal MT+ entry: avoid treating post-entry segment table as code
- Annotations: INT sites, AH/AL/DX recovery (local + predecessor walk), FCB 8.3 + ASCIIZ paths, string xrefs, filename/message tags (`overlay-name`, `map-file`, `FCB@DS:5C`, …)
- Pascal inline `call` + length-prefixed string (`cfg_find_pascal_inline_strings`)
- Interesting-block summary (`--cfg-interesting`)
- Load/I/O reverse call graph from path+FCB seeds (`cfg_print_load_graph`)

### Dynamic simulation (`--simulate` / EXE)

- 1 MiB real-mode arena, PSP + load image + reloc fixups ([`sim.h`](../../../../sim.h) `SimMemory::load_mz`)
- Capstone-decoded step loop: ALU, shifts, string ops, near/far call/jmp/ret, LOOP, flags, segment overrides (substantial but not full 8086)
- Breakpoints: IP, CS:IP, INT, INT+AH; flags stop/continue/log/once; `--dump=seg:off:len`
- Tight-loop back-edge skip (`--loop-limit` / `--loop-span`); LOOP/CX not skipped
- INT stubs: 20h terminate; 21h FCB open/close/read/create, handle open/close/read, console, DTA, vectors, alloc/resize, version, date/time; INT 10 mode set (ignore rest); INT 16 keyboard inject
- Host files resolved relative to EXE directory (`host_dir`)

### Docs / roadmap already aware of gaps

- [`TODO.md`](../../../../TODO.md): UASM export, sim↔CFG coverage, `--strings`, COM sim parity, Graphviz last, ICON jump-table @ `0090h`
- [`GOAL.md`](../GOAL.md): UASM rebuild + dumpexe toward Ghidra/BN CLI + `make test`

### Explicit non-features (today)

- No packer/unpacker (EXEPACK etc. only mentioned as test advice in README)
- No NE/LE/PE, no DPMI/protected mode
- No decompiler, type system, or user symbol DB
- No multi-file “project” (ICON.EXE + ICON0/1/2.OVL as one session)
- No automated tests in product `Makefile` (`test` / `verify` targets absent)

---

## 2. Gaps prioritized (ICON + general DOS)

### P0 — blocking ICON RE / professional CLI baseline

| Gap | Why it matters | Notes |
|-----|----------------|-------|
| **No `make test` / contract suite** | GOAL + max-quality rules require green tests before FEATURE claims; regressions in CFG/sim are silent | Makefile has only `all` / `install` / `clean` |
| **No UASM-friendly listing export** | End goal is reassemblable sources under Linux → DOSBox | TODO: per-block ORG, labels at BB starts; linear `-d` is not rebuildable |
| **Linear disasm treats data as code** | ICON: segment table at CS+3, jump tables, Pascal strings after `call` | CFG partially avoids this; `-d` does not |
| **No overlay / multi-MZ project model** | ICON is chain of 4 MZ images (EXE+3 OVL), not classic reloc overlays | CFG tags `icon0.ovl` strings but cannot load/analyze chain as one graph |
| **Runtime FCB name at DS:5C** | Many ICON opens use default FCB filled at runtime; static path empty | TODO: dump on AH=0F/27; sim already has FCB open stubs |
| **Jump-table → procedure map** | ICON jump table @ `0090h` (RE-NOTES / TODO) | CFG finds some tables; no naming / export of slot→proc |
| **README / man / examples stale vs CLI** | `examples/output_help.txt` lacks `--cfg`, `--bp`, etc.; README options incomplete | Hurts adoption and agent/tooling |

### P1 — high value for DOS RE depth (Ghidra/BN parity subset)

| Gap | Why |
|-----|-----|
| **CFG multi-segment / far edges** | Same-segment only; far call/jmp targets unresolved in graph |
| **Sim edge-coverage overlay on CFG** | Prove which paths run; TODO already lists this |
| **COM uses full `sim.h` engine** | COM path is ~20-insn trace only; breakpoints/FCB useless for COM |
| **`--strings` standalone** | Fast inventory without full CFG |
| **Deeper dataflow (AH/DX/FCB@5C stores)** | Pred walk is shallow; memory writes to FCB not tracked |
| **INT 10/16/1A richer stubs + CGA B800 model** | ICON is CGA hybrid; video/keyboard fidelity limits sim past menus |
| **Symbol / rename / comment persistence** | Ghidra/BN: durable DB; dumpexe is stdout-only |
| **Xref index (code↔data, all call sites)** | Partial via CFG; no global xref report / query |
| **Overlay load in sim (INT 21 AH=4B / custom chain)** | ICON chains OVL by loading next MZ; sim does not model chain |

### P2 — polish / later BN-class features

| Gap | Why |
|-----|-----|
| **Graphviz `--cfg-dot`** | Visualization; TODO marks last |
| **Interactive TUI walker** | Optional; spectator via Xmux later |
| **Packer detection / unpack assist** | Common on DOS shareware; not ICON |
| **Decompiler / SSA / types / structs** | Full BN/Ghidra; huge scope |
| **Scripting API (Python)** | BN/Ghidra strength; not required for UASM path |
| **NE/LE, 32-bit DOS extenders** | Out of ICON scope |
| **Formal verify (`make verify`)** | After tests; CBMC on pure helpers if extracted |

---

## 3. Suggested FEATURE series (concrete)

Ordered for ICON leverage + testability. Subjects follow efficient-git `FEATURE vN` style.

### FEATURE series A — quality gate (do first)

1. **`FEATURE v1 make test harness`**  
   - Add `make test` / `tests` alias (Catch2 or Criterion).  
   - Fixtures: tiny synthetic MZ/COM/SYS blobs (or ICON header-only cases).  
   - Contract tests: format detect, MZ size (`final_len==0`), reloc count, CLI `-h`/`-v` exit 0.  
   - Evidence: `make test` exit 0.

2. **`FEATURE v1 golden CLI snapshots`**  
   - Capture stable subsets of `--cfg-interesting` / header output for a fixed fixture.  
   - Prevents silent CFG annotation regressions.

### FEATURE series B — reassembly path

3. **`FEATURE v1 UASM listing export`**  
   - `--asm=FILE.asm` (or stdout): BB labels, `ORG`, raw `db` for non-code gaps, INT comments.  
   - Prefer CFG-reachable code only (not linear EOF).  
   - Acceptance: assemble a tiny fixture with UASM; optional ICON stub later.

4. **`FEATURE v1 code/data separation for -d`**  
   - Drive linear listing from CFG leaders + data ranges (segment table, string lits).  
   - Fixes Pascal MT+ “disasm garbage” after entry `CALL`.

### FEATURE series C — ICON I/O & overlays

5. **`FEATURE v1 FCB runtime dump assist`**  
   - On sim BP `int:21,ah=0F` / `ah=27`, auto-dump DS:DX FCB name (and DS:5C).  
   - Log resolved host path on successful open (already partial).  
   - Acceptance: against ICON.EXE + data dir, log `LA.MAP` / `icon0.ovl` style names.

6. **`FEATURE v1 multi-image / overlay session`**  
   - `--also=ICON0.OVL` or directory scan of sibling OVLs.  
   - Per-image CFG + cross-image string tags; later: sim load-next-MZ stub.  
   - Acceptance: one command reports I/O seeds across EXE+OVL set.

7. **`FEATURE v1 jump-table map export`**  
   - Detect table @ configurable / auto (ICON `0090h`); emit slot → target IP (+ optional names file).  
   - Feeds UASM labels and RE-NOTES.

### FEATURE series D — analysis depth (after A–C)

8. **`FEATURE v1 sim coverage on CFG`**  
   - After `--simulate`, mark taken edges / hot BBs on next `--cfg` print (or combined mode).  

*(Optional follow-ons, not required in first 8: `--strings`, COM full sim, `--cfg-dot`, Graphviz.)*

---

## 4. Test coverage status

| Item | Status |
|------|--------|
| **`make test` / `make tests`** | **Absent** — [`Makefile`](../../../../Makefile) only `all`, `install`, `clean` |
| **`make verify` (formal)** | **Absent** |
| **Unit / integration tests under product tree** | **None** found (no `tests/`, no Catch2/Criterion/pytest for dumpexe) |
| **Manual examples** | [`examples/`](../../../../examples/) pre-generated text outputs (help/version/reloc/AR static); **stale help** vs current CLI |
| **Game-side tests** | ICON `dummy/` has its own Makefile (terrain parity) — **not** dumpexe product tests |
| **GOAL requirement** | Explicit: “Tests (`make test`)” and “dumpexe FEATURE improvements landed with tests” — **open** |

**Verdict:** Product has **no automated regression gate**. Any FEATURE that changes CFG/sim/disasm behavior should land **with** series A first.

**CLI help (live):** Implemented in `options.h::show_usage` — includes `--cfg*`, `--simulate`, `--bp=`, `--dump=`, `--loop-limit`, COM PSP flags. README and `examples/output_help.txt` are **behind** this surface.

**Build (not re-run in this read-only pass):** Capstone + g++ C++23 required per Makefile; binary may already exist in tree from prior builds.

---

## 5. Capability matrix (quick)

| Capability | dumpexe now | Ghidra/BN-class DOS RE |
|------------|-------------|-------------------------|
| MZ/COM/SYS headers | Yes | Yes |
| Relocs | Yes | Yes |
| Linear disasm | Yes (Capstone) | Yes + recursive |
| CFG + xrefs | Partial (near, one CS image) | Full multi-segment |
| INT/RBIL annotate | Yes | Plugins / scripts |
| FCB/Pascal DOS heuristics | **Strong niche** | Manual / scripts |
| Emulation | Best-effort sim | Debugger + emulator bridges |
| Database / symbols | No | Yes |
| Decompiler | No | Yes (limited 16-bit) |
| Reassemblable export | No | Partial / plugins |
| Overlay projects | Tags only | Manual load |
| Automated tests | No | Project-dependent |

**Niche strength to keep:** DOS FCB + Pascal MT+ + load graph — this is where dumpexe can beat generic tools for 1980s games **without** becoming a full decompiler.

---

## 6. Recommended near-term focus (ICON)

1. Land **`make test`** + fixtures (series A).  
2. **UASM export from CFG** (series B) — direct line to GOAL reassembly.  
3. **FCB runtime dumps + multi-OVL batch** (series C) — unlocks load-path documentation already half-done in CFG tags.  
4. Keep Graphviz/TUI/decompiler **out** until listings + tests are green (aligns with [`TODO.md`](../../../../TODO.md)).

---

## Appendix — source map (product)

| File | Role |
|------|------|
| `dumpexe.cpp` | main, format dispatch |
| `dumpexe.h` | umbrella includes |
| `exe.h` / `com.h` / `sys.h` | format structs |
| `analysis.h` | EXE header/reloc/hex/sim glue |
| `com_analysis.h` / `sys_analysis.h` | COM/SYS paths |
| `disasm.h` | linear Capstone disasm |
| `cfg.h` | CFG + annotations + load graph |
| `sim.h` | 1 MiB execution engine |
| `options.h` | CLI |
| `registers.h` | global CPU state |
| `formatting.h` | TDUMP/hexdump |
| `int_annotate.h` + `gen_int_db.py` | RBIL INT DB |
| `Makefile` | build/install only |
| `TODO.md` | living roadmap |

*Report generated by read-only exploration; product code not modified.*
