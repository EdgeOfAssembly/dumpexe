#!/usr/bin/env bash
# Coverage: --uasm-verified seeds proven entries the graph cannot see:
#  - Borland startup init/exit table records (mov si,S / mov di,E / call P,
#    P walks 6-byte records with add bx,6 and es:[bx]);
#  - INT 21h/25h handlers set with DS = CS;
#  - immediates stored into a cell that is called (mov [X],imm / call [X]).
# Negative: a table with an unknown record type and a set-vector without
# DS = CS seed nothing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_coverage (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-cov-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
mk() { # $1 = stem, $2 = record type byte, $3 = 1 for DS=CS
  local dscs
  if [[ $3 == 1 ]]; then dscs=$'    push cs\n    pop ds'; else dscs=$'    nop'; fi
  cat > "$TD/$1.asm" <<ASM
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT, es:_TEXT
org 100h
start:
    mov si, offset itab
    mov di, offset iend
    call walk
    mov ax, 2500h
$dscs
    mov dx, offset handler
    int 21h
    mov word ptr ds:[cell], offset hooked
    call word ptr ds:[cell]
    mov ax, 4C00h
    int 21h
walk:
    mov bx, si
wloop:
    cmp bx, di
    je wdone
    cmp byte ptr es:[bx], 0FFh
    je wnext
    call word ptr es:[bx+2]
wnext:
    add bx, 6
    jmp short wloop
wdone:
    ret
    db 0EBh
initfn:
    mov ax, 1
    xor bx, bx
    ret
    db 0EBh
handler:
    mov cx, 2
    iret
    db 0EBh
hooked:
    mov dx, 3
    ret
cell dw 0
itab db $2, 1
    dw offset initfn, 0
iend label byte
_TEXT ends
end start
ASM
  (cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo"$1.com" "$1.asm" >/dev/null 2>&1)
  (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o "$1_out.asm" "$1.com" >/dev/null 2>&1) || true
}
mk good 0 1
G="$TD/good_out.asm"
check good_verified grep -q '^; VERIFIED identical' "$G"
check good_header grep -qF '; startup entries: 1 init/exit table record(s), 1 DS=CS interrupt handler(s), 1 stored code pointer(s) (seeded as entries)' "$G"
check good_init_code grep -qE '^    mov ax, 1h	; [0-9A-F]{5}: B8 01 00' "$G"
check good_handler_code grep -qE '^    mov cx, 2h	; [0-9A-F]{5}: B9 02 00' "$G"
check good_hooked_code grep -qE '^    mov dx, 3h	; [0-9A-F]{5}: BA 03 00' "$G"
mk bad 7 0
B="$TD/bad_out.asm"
check bad_verified grep -q '^; VERIFIED identical' "$B"
check bad_no_init bash -c "! grep -qE '^    mov ax, 1h	; [0-9A-F]{5}: B8 01 00' '$B'"
check bad_no_handler bash -c "! grep -qE '^    mov cx, 2h	; [0-9A-F]{5}: B9 02 00' '$B'"
check bad_hooked_still grep -qE '^    mov dx, 3h	; [0-9A-F]{5}: BA 03 00' "$B"
check bad_header grep -qF '; startup entries: 0 init/exit table record(s), 0 DS=CS interrupt handler(s), 1 stored code pointer(s)' "$B"
echo "coverage passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
