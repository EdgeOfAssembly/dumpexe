#!/usr/bin/env bash
# Readability round 1 (game-agnostic rules), synthetic fixtures only:
# R1 ASCII runs in data are quoted db (quote chars stay numeric),
# R2 high-bit text keeps hex db plus a decoded comment (one trailing
#    bit-7-clear printable byte allowed), R3 int 21h gets a DOS function
#    comment when AH comes from an immediate mov in the same block,
# R4 near-call targets are func_XXXXX with a separator (hints win).
# Text-looking bytes inside decoded code stay instructions. Every listing
# must rebuild byte-identical.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
source "$ROOT/tests/lib_uasm.sh"
N=35
UASM_BIN="$(uasm_resolve)" || { echo "SKIP $N readability checks: no uasm"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-rd-XXXXXX")"
trap '[[ -n "${KEEP:-}" ]] || rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
has() { grep -qF -- "$1" "$2"; }
hasnt() { ! grep -qF -- "$1" "$2"; }

cat > "$TD/r.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov ah, 9
    mov dx, 200h
    int 21h
    call helper
    mov ah, 30h
    call helper
    int 21h
    jmp short past1
    db 'He said ', 27h, 'hello', 27h, ' to everyone', 0Dh, 0Ah, '$'
past1:
    jmp short past2
    db 'H'+80h,'e'+80h,'l'+80h,'l'+80h,'o'+80h,' '+80h,'w'+80h,'o'+80h,'r'+80h,'l'+80h,'d'
past2:
    jmp short past4
    db 'Ending right at code'
past4:
    push ax
    inc bx
    push bx
    push cx
    push dx
    push si
    push di
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    mov ax, 4C00h
    mov bx, 1
    int 21h
helper:
    mov cx, 2
    ret
    db 'G'+80h,'o'+80h,'o'+80h,'d'+80h,' '+80h,'l'+80h,'u'+80h,'c'+80h,'k'+80h,'!'+80h
    db 0, 'Hi', 80h+'x', 0C1h, 0C2h, 'AbAbAbAbAb', 1, 2, 'xyzw', 0FFh
_TEXT ends
end start
ASM
(cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo r.com r.asm >/dev/null)
run() { # $1 out stem, rest extra args
  local o=$1; shift
  (cd "$TD" && "$BIN" --uasm --uasm-verified "$@" -o "$o.asm" r.com >"$o.out" 2>&1)
  (cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo "$o.bin" "$o.asm" >/dev/null)
  cmp -s "$TD/r.com" "$TD/$o.bin"
}
check rd_rebuild run a
A="$TD/a.asm"
# R1
check r1_quoted has "db 'He said ', 27h, 'hello', 27h, ' to everyone', 0Dh, 0Ah, '\$'" "$A"
check r1_ends_at_code has "db 'Ending right at code'" "$A"
check r1_no_short_noise hasnt "'Hi'" "$A"
check r1_no_period2 hasnt "'AbAbAbAbAb'" "$A"
check r1_code_not_quoted hasnt "'PCSQRVW" "$A"
check r1_code_push_kept has "push ax" "$A"
check r1_code_inc_kept has "inc bx" "$A"
# R2
check r2_trailing_clear has '; hi-bit text: "Hello world"' "$A"
check r2_all_set has '; hi-bit text: "Good luck!"' "$A"
check r2_bytes_hex has "db 0C8h, 0E5h, 0ECh, 0ECh" "$A"
check r2_short_none bash -c "[ \$(grep -c 'hi-bit text' '$A') -eq 2 ]"
# R3
check r3_write_string grep -qE 'int 21h.*DOS AH=9h: .*WRITE STRING' "$A"
check r3_exit grep -qE 'int 21h.*DOS AH=4Ch: .*TERMINATE' "$A"
check r3_call_breaks bash -c "! grep -qE 'DOS AH=30h' '$A'"
check r3_count bash -c "[ \$(grep -c 'DOS AH=' '$A') -eq 2 ]"
# R4
check r4_func_label grep -qE '^func_[0-9A-F]{5}:' "$A"
check r4_separator bash -c "grep -B1 -E '^func_[0-9A-F]{5}:' '$A' | grep -q '^; -----'"
check r4_call_uses_name grep -qE 'call near ptr func_[0-9A-F]{5}' "$A"
check r4_jmp_target_not_func bash -c "[ \$(grep -cE '^func_' '$A') -eq 1 ]"
# R4 hints win
FL=$(grep -oE '^func_[0-9A-F]{5}' "$A" | head -1 | sed 's/func_//')
printf 'label %s my_helper\n' "$FL" > "$TD/h.txt"
check rd_rebuild_hints run b --hints="$TD/h.txt"
check r4_hint_name grep -qE '^my_helper:' "$TD/b.asm"
check r4_hint_no_func bash -c "! grep -qE '^func_' '$TD/b.asm'"
check r4_hint_separator bash -c "grep -B1 '^my_helper:' '$TD/b.asm' | grep -q '^; -----'"
# M1 (RetroCodeMess 02b7bd140 verify-2d4661b repro/test_collision.sh):
# a hints label spelled like an auto func_ name must not define a symbol
# twice (that made verification fail and the listing fall back to db).
cat > "$TD/n.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    call f1
    call f2
    call f3
    mov ax, 4C00h
    int 21h
f1: mov cx, 1
    ret
f2: mov cx, 2
    ret
f3: mov cx, 3
    ret
_TEXT ends
end start
ASM
(cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo n.com n.asm >/dev/null)
nrun() { # $1 stem, $2 hints line
  local o=$1
  printf '%s\n' "$2" > "$TD/$o.hints"
  (cd "$TD" && "$BIN" --uasm --uasm-verified --hints="$o.hints" -o "$o.asm" n.com >"$o.out" 2>&1)
  (cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo "$o.bin" "$o.asm" >/dev/null)
  cmp -s "$TD/n.com" "$TD/$o.bin"
}
ninsns() { [ "$(grep -cE '^    (call|mov|ret|int)' "$TD/$1.asm")" -ge 9 ]; }
nuniq() { [ -z "$(grep -oE '^[A-Za-z_][A-Za-z0-9_]*:' "$TD/$1.asm" | sort | uniq -d)" ]; }
for h in "override:label 0010E my_helper" "collide_auto:label 0010E func_00112" "collide_nonlabel:label 00109 func_00116"; do
  st=${h%%:*}
  check m1_${st}_rebuild nrun "$st" "${h#*:}"
  check m1_${st}_insns ninsns "$st"
  check m1_${st}_unique nuniq "$st"
done
check m1_func_hint_rejected grep -q "bad or duplicate label 'func_00112'" "$TD/collide_auto.out"
check m1_override_named grep -qE '^my_helper:' "$TD/override.asm"
echo "readability passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
