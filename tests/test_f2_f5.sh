#!/usr/bin/env bash
# F2: the U3 `_main` hint needs the startup call within 512 bytes of the
#     entry and an exit target that does not return (or reaches DOS
#     terminate). TCREF.EXE's `call getter / push ax / call parser` (the
#     "exit" returns, then `cmp ax, 2`) is no longer hinted.
# F5: short (under 8 bytes) U2 strings must look like text: no code-like
#     punctuation, letter runs all upper or CamelCase, no period-2 repeat.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_f2_f5 (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-f2f5-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
build() { # $1 = stem; assembles $1.asm to $1.com and lists it to $1_out.asm
  (cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo"$1.com" "$1.asm" >/dev/null 2>&1)
  (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o "$1_out.asm" "$1.com" >/dev/null 2>&1) || true
}

# F2 negative (TCREF shape): the "exit" returns and its result is compared.
cat > "$TD/n1.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    call getter
    push ax
    call parse
    cmp ax, 2
    jne done
    pop ax
done:
    mov ax, 4C00h
    int 21h
getter:
    mov ax, word ptr ds:[val]
    ret
parse:
    xor ax, ax
    ret
val dw 3
_TEXT ends
end start
ASM
build n1
check f2_n1_verified grep -q '^; VERIFIED identical' "$TD/n1_out.asm"
check f2_returning_exit_no_hint bash -c "! grep -q 'possibly _main' '$TD/n1_out.asm'"

# F2 positive: exit -> __exit (has a ret path) -> terminate (int 21h/4Ch).
cat > "$TD/p1.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    call cmain
    push ax
    call cexit
cexit:
    push bp
    mov bp, sp
    push word ptr [bp+4]
    call xexit
    pop bp
    ret
xexit:
    cmp word ptr ds:[quick], 0
    jne quickret
    call term
quickret:
    ret
term:
    mov bp, sp
    mov ah, 4Ch
    mov al, byte ptr [bp+2]
    int 21h
cmain:
    xor ax, ax
    ret
quick dw 0
_TEXT ends
end start
ASM
build p1
check f2_p1_verified grep -q '^; VERIFIED identical' "$TD/p1_out.asm"
check f2_chain_exit_hint grep -qE '^; hint: possibly _main at (L|func_)00126 ' "$TD/p1_out.asm"

# F2 negative: a real exit, but the pattern is more than 512 bytes past the entry.
cat > "$TD/n2.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    jmp far_away
    db 600 dup (90h)
far_away:
    call cmain
    push ax
    call cexit
cexit:
    pop ax
    mov ah, 4Ch
    int 21h
cmain:
    xor ax, ax
    ret
_TEXT ends
end start
ASM
build n2
check f2_n2_verified grep -q '^; VERIFIED identical' "$TD/n2_out.asm"
check f2_far_from_entry_no_hint bash -c "! grep -q 'possibly _main' '$TD/n2_out.asm'"

# F5: junk short strings are not labeled; short real text still is.
cat > "$TD/s.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov ax, 4C00h
    int 21h
    db 0
j1 db '$RPj', 0
j2 db '6kIj', 0
j3 db '}SDH', 0
j4 db 'pNzK', 0
j5 db 'dJdJdJ', 0
j6 db 'tMtMtM', 0
g1 db 'ChDir', 0
g2 db 'READ$', 0
g3 db 'TEMP', 0
g4 db 'XXXXXX', 0
g5 db 'Long enough text', 0
g6 db '%s%s%s', 0
g7 db '%-5ld%s', 0
j7 db '%dkRM', 0
_TEXT ends
end start
ASM
build s
S="$TD/s_out.asm"
check f5_verified grep -q '^; VERIFIED identical' "$S"
for j in '$RPj' '6kIj' '}SDH' 'pNzK' 'dJdJdJ' 'tMtMtM'; do
  check "f5_junk_${j//[^A-Za-z0-9]/_}" bash -c "! grep -B1 -F \"'$j'\" '$S' | grep -q '^cstr_'"
done
for g in ChDir 'READ' TEMP XXXXXX 'Long enough text'; do
  check "f5_text_${g// /_}" bash -c "grep -B1 -F \"'$g\" '$S' | grep -q '^cstr_'"
done
check f5_fmt_sss grep -B1 -qF "db 25h, 's', 25h, 's', 25h, 's', 0h" "$S"
check f5_fmt_sss_label bash -c "grep -B1 -F \"db 25h, 's', 25h, 's', 25h, 's', 0h\" '$S' | grep -q '^cstr_'"
check f5_fmt_ld bash -c "grep -B1 -F \"db 25h, '-5ld', 25h, 's', 0h\" '$S' | grep -q '^cstr_'"
check f5_fmt_junk_still bash -c "! grep -B1 -F \"'dkRM'\" '$S' | grep -q '^cstr_'"
check f5_count grep -qF '; C strings: 7 NUL-terminated string(s) found in data' "$S"
echo "f2_f5 passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
