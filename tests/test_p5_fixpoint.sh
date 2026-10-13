#!/usr/bin/env bash
# P5: fixpoint. A bounded jump table whose case the first graph never
# decoded seeds that case as an entry; the rebuilt listing decodes it and
# symbolizes the whole table.
# Missing assembler: exit 77 (skip).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_p5_fixpoint (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p5-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
asm() { (cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo"$2" "$1" >/dev/null 2>&1); }
gen() { # $1 = name, $2 = 1 for a good table, 0 for one entry into data
  local c1call="" mid="c1"; [[ $2 == 0 ]] && mid="0FFF0h"
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
    jmp done
c1: mov al, 1
    ret
    jmp done
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
gen fx 1
O="$TD/fx_out.asm"
check fx_verified grep -q '^; VERIFIED identical' "$O"
check fx_rounds grep -qE '^; fixpoint: 2 round\(s\), 1 jump-table target\(s\) seeded' "$O"
check fx_table_symbolic test "$(grep -c 'table word' "$O")" -eq 3
check fx_shift_clean grep -qE '^; shift mid: [0-9]+ references checked, 0 broken' "$O"
check fx_reassembles bash -c "cd '$TD' && env -u UASM '$UASM_BIN' -bin -nologo -Fore.bin fx_out.asm >/dev/null 2>&1 && cmp -s re.bin fx.com"
# A table with an entry outside the image seeds nothing.
gen bad 0
check bad_no_fixpoint bash -c "! grep -q '^; fixpoint' '$TD/bad_out.asm'"
echo "p5_fixpoint passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
