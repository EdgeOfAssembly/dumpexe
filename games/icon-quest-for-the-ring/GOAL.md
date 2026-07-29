# Goal: Full RE of ICON + professional dumpexe

## Primary
Reverse-engineer ICON (Quest for the Ring) under `ICON/`:
1. Fully understand EXE + OVL chain + data formats
2. Reconstruct **UASM** sources that build and run in DOSBox
3. Optional later: HLL port (C preferred)

## Secondary
Improve **dumpexe** toward Ghidra/Binary Ninja class **CLI** RE:
- Better analysis depth, xrefs, types, overlays, Pascal MT+ awareness
- Tests (`make test`), docs, evidence-driven FEATURE/FIXUP commits

## Workflow
Skill **dos-re**: dumpexe → r2 → Ghidra → Spice86/DOSBox+Xmux → UASM → pmem

## Success criteria
- [ ] All major code paths documented with offsets
- [ ] Formats in FORMAT-NOTES complete enough to decode all MAP/DAT/ADV
- [ ] UASM rebuild boots and plays a known path
- [ ] dumpexe FEATURE improvements landed with tests
