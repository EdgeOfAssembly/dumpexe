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
check s01_offset grep -qE '^    mov dx, offset str_[0-9A-F]{5}' "$O"
check s02_jmp_symbolic grep -qE 'jmp word ptr \[bx\+\(jt_[0-9A-F]{5} - L00100 \+ 100h\)\]' "$O"
check s02_three_entries test "$(grep -c 'table word' "$O")" -eq 3
check s02_header grep -q '^; value references: 1 bounded jump table(s) (3 entries), 1 \$-string pointer(s)' "$O"
check shift_mid_clean grep -qE '^; shift mid: [0-9]+ references checked, 0 broken' "$O"
check reassembles bash -c "cd '$TD' && env -u UASM '$UASM_BIN' -bin -nologo -Fore.bin all_out.asm >/dev/null 2>&1 && cmp -s re.bin all.com"
# All-or-nothing: one entry points outside the image, so the table stays literal.
gen part 0
check partial_table_literal bash -c "! grep -q 'table word' '$TD/part_out.asm' && grep -q '^; VERIFIED identical' '$TD/part_out.asm'"
# S06: code pointer loaded through a register from a table.
cat > "$TD/s06.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov si, offset ptab
    mov bx, [si+2]
    call bx
    mov ah, 4Ch
    int 21h
    db 0EAh
h0: mov al, 0
    ret
    db 0EAh
h1: mov al, 1
    ret
ptab dw h0, h1
_TEXT ends
end start
ASM
asm s06.asm s06.com
(cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o s06_out.asm s06.com >/dev/null 2>&1) || true
O6="$TD/s06_out.asm"
check s06_verified grep -q '^; VERIFIED identical' "$O6"
check s06_handler_decoded grep -qE '^    mov al, 1h' "$O6"
check s06_offset grep -qE '^    mov si, offset ptrtab_[0-9A-F]{5}' "$O6"
check s06_table_word grep -qE '^    dw offset L[0-9A-F]{5}	; [0-9A-F]{5}: table word' "$O6"
check s06_shift grep -qE '^; shift mid: [0-9]+ references checked, 0 broken' "$O6"
check s06_reassembles bash -c "cd '$TD' && env -u UASM '$UASM_BIN' -bin -nologo -Fos06re.bin s06_out.asm >/dev/null 2>&1 && cmp -s s06re.bin s06.com"
# S09: string pointer pushed to a callee that dereferences it.
cat > "$TD/s09.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov ax, offset msg
    push ax
    call f
    add sp, 2
    mov ah, 4Ch
    int 21h
f:  push bp
    mov bp, sp
    mov bx, [bp+4]
    mov al, [bx]
    pop bp
    ret
msg db 'Hello, world', 0
_TEXT ends
end start
ASM
asm s09.asm s09.com
(cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o s09_out.asm s09.com >/dev/null 2>&1) || true
O9="$TD/s09_out.asm"
check s09_verified grep -q '^; VERIFIED identical' "$O9"
check s09_offset grep -qE '^    mov ax, offset cstr_[0-9A-F]{5}' "$O9"
check s09_typed grep -qE "^    db 'Hello, world', 0h	; [0-9A-F]{5}: string" "$O9"
check s09_shift grep -qE '^; shift mid: [0-9]+ references checked, 0 broken' "$O9"
check s09_reassembles bash -c "cd '$TD' && env -u UASM '$UASM_BIN' -bin -nologo -Fos09re.bin s09_out.asm >/dev/null 2>&1 && cmp -s s09re.bin s09.com"
# S01 string is typed too.
check s01_typed grep -qE "^    db 'Hello\\\$'	; [0-9A-F]{5}: string" "$O"

# Long typed string (TD386 regression): chunked so UASM accepts the lines.
cat > "$TD/slong.asm" <<'ASM'
.model tiny
_TEXT segment
org 100h
start:
    mov dx, offset msg
    mov ah, 9
    int 21h
    ret
msg db 400 dup('A'), '$'
_TEXT ends
end start
ASM
asm slong.asm slong.com
(cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o slong_out.asm slong.com >/dev/null 2>&1) || true
check long_string_verified grep -q '^; VERIFIED identical' "$TD/slong_out.asm"
check long_string_chunked bash -c "[ \$(awk '{ if (length > m) m = length } END { print m }' '$TD/slong_out.asm') -lt 200 ]"

echo "p4_values passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
