#!/usr/bin/env bash
# P5 tools: --hints (code/data/label), --hints-out round trip, --bytemap,
# --explain, --strict. Missing assembler: exit 77 (skip).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_p5_tools (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p5t-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
cat > "$TD/t.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    xor bx, bx
again:
    call word ptr cs:[bx+tbl]
    add bx, 2
    cmp bx, 8
    jb again
    mov ah, 4Ch
    int 21h
    db 0EAh
h0: mov al, 0
    ret
    db 0EAh
h1: mov al, 1
    ret
    db 0EAh
h2: mov al, 2
    ret
    db 0EAh
h3: mov al, 3
    ret
tbl dw h0, h1, h2, h3
_TEXT ends
end start
ASM
(cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fot.com t.asm >/dev/null 2>&1)
V="$BIN --uasm --uasm-verified --uasm-bin $UASM_BIN"
printf 'code 114 # h0\ncode 118\nlabel 114 handler0\nlabel 123 jumptab\ndata 11C 4\nbogus 1\nlabel 120 L00120\n' > "$TD/h.txt"
(cd "$TD" && $V --hints=h.txt --hints-out=ho.txt --bytemap=bm.txt --explain=118 --explain=11C -o a.asm t.com >out.txt 2>err.txt) || true
check hints_verified grep -q '^; VERIFIED identical' "$TD/a.asm"
check hints_header grep -q '^; hints: 2 code, 1 data range(s), 2 label name(s) from h.txt' "$TD/a.asm"
check hints_label_used grep -q '^handler0:' "$TD/a.asm"
check hints_code_decoded grep -qE '^    mov al, 1h' "$TD/a.asm"
check hints_data_kept bash -c "! grep -qE '^    mov al, 2h' '$TD/a.asm'"
check hints_bad_keyword grep -q "hints:6: unknown keyword 'bogus'" "$TD/err.txt"
check hints_reserved_name grep -q "bad or duplicate label 'L00120'" "$TD/err.txt"
check hints_out_lines bash -c "grep -q '^code 00114$' '$TD/ho.txt' && grep -q '^data 0011C 4$' '$TD/ho.txt' && grep -q '^label 00114 handler0$' '$TD/ho.txt'"
(cd "$TD" && $V --hints=ho.txt -o b.asm t.com >/dev/null 2>&1) || true
check hints_roundtrip bash -c "diff <(grep -v '^; hints' '$TD/a.asm') <(grep -v '^; hints' '$TD/b.asm') >/dev/null"
check bytemap_format bash -c "grep -qE '^00100-[0-9A-F]{5} code mnemonic$' '$TD/bm.txt' && grep -qE '^[0-9A-F]{5}-[0-9A-F]{5} data -$' '$TD/bm.txt'"
check explain_code grep -qE "^explain 00118: code unit 00118\+2 'mov al, 1'.*seeded entry" "$TD/err.txt"
check explain_data grep -qE '^explain 0011C: data unit .*\(data hint\)' "$TD/err.txt"
(cd "$TD" && $V --strict -o s.asm t.com >/dev/null 2>&1) || true
check strict_header grep -qE '^; strict: [0-9]+ instruction\(s\) with only Likely/Hint evidence printed as data' "$TD/s.asm"
check strict_verified grep -q '^; VERIFIED identical' "$TD/s.asm"
check needs_verified bash -c "! '$BIN' --uasm --strict '$TD/t.com' >/dev/null 2>&1"
# S4: assembler reserved words are rejected as labels; the listing still verifies.
printf 'label 114 mov\nlabel 118 AX\nlabel 11C offset\nlabel 120 Loop\nlabel 123 okname\n' > "$TD/rw.txt"
(cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" --hints=rw.txt -o rw.asm t.com >/dev/null 2>rw.err) || true
check hints_rw_rejected test "$(grep -c 'is an assembler reserved word' "$TD/rw.err")" -eq 4
check hints_rw_verified grep -q '^; VERIFIED identical' "$TD/rw.asm"
check hints_rw_ok_kept grep -q '^okname' "$TD/rw.asm"
echo "p5_tools passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
