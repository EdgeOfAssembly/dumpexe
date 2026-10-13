#!/usr/bin/env bash
# P4: value references in the verified listing. S01 ($-string pointer for
# int 21h/09) and S02 (bounded jump table) become offset expressions, the
# listing stays identical, and the shift tests check every new reference.
# Missing assembler: exit 77 (skip).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_p4_values (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p4-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
asm() { (cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo"$2" "$1" >/dev/null 2>&1); }
gen() { # $1 = name, $2 = 1 for a good table, 0 for one entry into data
  local c1call="    call c1" mid="c1"; [[ $2 == 0 ]] && mid="0FFF0h"
  cat > "$TD/$1.asm" <<ASM
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov ah, 9
    mov dx, offset msg
    int 21h
    call c0
    call c2
$c1call
    mov bx, 2
    cmp bx, 2
    ja done
    shl bx, 1
    jmp word ptr [bx+tbl]
c0: mov al, 0
    ret
c1: mov al, 1
    ret
c2: mov al, 2
    ret
done:
    mov ah, 4Ch
    int 21h
tbl dw c0, $mid, c2
msg db 'Hello\$'
_TEXT ends
end start
ASM
  asm "$1.asm" "$1.com"
  (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o "$1_out.asm" "$1.com" >/dev/null 2>&1) || true
}
gen all 1
O="$TD/all_out.asm"
check s01_verified grep -q '^; VERIFIED identical' "$O"
check s01_offset grep -qE '^    mov dx, offset L[0-9A-F]{5}' "$O"
check s02_jmp_symbolic grep -qE 'jmp word ptr \[bx\+\(L[0-9A-F]{5} - L00100 \+ 100h\)\]' "$O"
check s02_three_entries test "$(grep -c 'table word' "$O")" -eq 3
check s02_header grep -q '^; value references: 1 bounded jump table(s) (3 entries), 1 \$-string pointer(s)' "$O"
check shift_mid_clean grep -qE '^; shift mid: [0-9]+ references checked, 0 broken' "$O"
check reassembles bash -c "cd '$TD' && env -u UASM '$UASM_BIN' -bin -nologo -Fore.bin all_out.asm >/dev/null 2>&1 && cmp -s re.bin all.com"
# All-or-nothing: one entry points outside the image, so the table stays literal.
gen part 0
check partial_table_literal bash -c "! grep -q 'table word' '$TD/part_out.asm' && grep -q '^; VERIFIED identical' '$TD/part_out.asm'"
echo "p4_values passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
