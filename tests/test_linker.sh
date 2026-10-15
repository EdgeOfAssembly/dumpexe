#!/usr/bin/env bash
# Linker fingerprint from MZ header bytes 1Ch..1Fh, on hand-made MZ files.
# TLINK reports only the major series; MS LINK and TPC are "(likely)";
# TPC needs Turbo Pascal runtime evidence; no assembler is guessed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-linker-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
# mk NAME LFARLC HEX-OF-1C.. [tp]: header 2 paragraphs, image = mov ah,4Ch; int 21h
mk() {
python3 - "$TD/$1.exe" "$2" "$3" "${4:-}" <<'PY'
import struct, sys
out, lfarlc, extra, tp = sys.argv[1], int(sys.argv[2], 16), bytes.fromhex(sys.argv[3]), sys.argv[4]
img = bytes([0xB4, 0x4C, 0xCD, 0x21])
if tp:
    img += b'\0Runtime error \0 at \0Portions Copyright (c) 1983,92 Borland\0'
img += bytes(-len(img) % 16)
hl = 0x40
hdr = struct.pack('<13H', 0x5A4D, (hl + len(img)) % 512, (hl + len(img) + 511) // 512, 0, hl // 16, 0, 0xFFFF,
                  len(img) // 16, 0x100, 0, 0, 0, lfarlc) + extra
hdr += bytes(hl - len(hdr))
open(out, 'wb').write(hdr + img)
PY
}
run() { "$BIN" -a --no-asm-file --no-repack "$TD/$1.exe" 2>&1 | grep -E '^Linker:' | sed 's/^Linker: *//' || true; }
mk tl5 3E 0000"0100FB50"
mk tl7 3E 0000"0100FB71"
mk tl3 3E 0000"0100FB30"
mk ms 1E 0000"0100"
mk tp 1C 0000"" tp
mk tpnort 1C 0000""
mk plain 1C 0000""
mk fbbad 3E 0000"0100FB05"
check tlink5 test "$(run tl5)" = "Borland TLINK 5.x"
check tlink7 test "$(run tl7)" = "Borland TLINK 7.x"
check tlink3 test "$(run tl3)" = "Borland TLINK 3.x"
check tlink_no_minor bash -c "! '$BIN' -a --no-asm-file --no-repack '$TD/tl5.exe' 2>&1 | grep -qE 'TLINK 5\.[0-9]'"
check tlink_evidence bash -c "'$BIN' -a --no-asm-file --no-repack '$TD/tl7.exe' 2>&1 | grep -qF '01 00 FB 71'"
check mslink test "$(run ms)" = "Microsoft LINK (likely)"
check tpc test "$(run tp)" = "Turbo Pascal linker (likely)"
check tpc_needs_runtime test -z "$(run tpnort)"
check bad_series test -z "$(run fbbad)"
for f in tl5 tl7 ms; do check no_assembler_guess_$f bash -c "! '$BIN' -a --no-asm-file --no-repack '$TD/$f.exe' 2>&1 | grep -qiE 'TASM|MASM|Assembler:'"; done
check json_linker bash -c "'$BIN' --json '$TD/tl5.exe' 2>&1 | grep -qF '\"linker\": \"Borland TLINK 5.x\"'"
echo "linker passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
