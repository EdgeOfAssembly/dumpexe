#!/usr/bin/env bash
# Generic jump/call tables (arch/jump-tables). Synthetic only; the private
# fixtures run from `make test-fixtures-jt` when present.
#  J1 COM: byte opcode dispatcher (lodsb / xor ah,ah / shl / jmp [bx+T]) with
#     no compare guard, a 160-entry table with two 0000 holes, and code
#     starting right after the table (the table ends there, not at the
#     lowest entry target).
#  J2 COM: call [disp16] with no index register is a variable, not a table.
#  J3 COM: compare guard with a sub bias (cmp al,N; ja; sub al,K).
#  J4 EXE: cs: near table in a second code segment.
#  J5 EXE: far table (call dword ptr cs:[bx+T]), relocated segment words.
#  J6 COM: hint `table ADDR N near` overrides.
# Every listing must rebuild byte-identical. Missing assembler: exit 77.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_jump_tables (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-jt-XXXXXX")"
trap '[[ -n "${JT_KEEP:-}" ]] || rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
asm() { (cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo"$2" "$1" >/dev/null 2>&1); }
asmz() { (cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -mz -nologo -Fo"$2" "$1" >/dev/null 2>&1); }
lst() { (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" "${@:3}" -o "$2" "$1" >/dev/null 2>&1) || true; }
same() { # rebuild listing $1 (bin or mz) and compare with $2
  local mode=$3
  (cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -"$mode" -nologo -Fo"re_$2" "$1" >/dev/null 2>&1) && cmp -s "$TD/re_$2" "$TD/$2"
}

# ---- J1 ----
{
  echo "_TEXT segment para public use16 'CODE'"
  echo "assume cs:_TEXT, ds:_TEXT"
  echo "org 100h"
  echo "start:"
  echo "    call after"
  echo "    mov si, offset prog"
  echo "next:"
  echo "    lodsb"
  echo "    xor ah, ah"
  echo "    mov bx, ax"
  echo "    shl bx, 1"
  echo "    jmp word ptr [bx+tbl]"
  echo "h0: mov ah, 4Ch"
  echo "    int 21h"
  for i in $(seq 1 149); do printf 'h%d: mov al, %d\n    jmp next\n' "$i" "$i"; done
  echo "tbl:"
  for i in $(seq 0 159); do
    if [[ $i == 40 || $i == 41 ]]; then echo "    dw 0"; else echo "    dw h$i"; fi
  done
  echo "after: mov cx, 1"
  echo "    ret"
  for i in $(seq 150 159); do printf 'h%d: mov al, %d\n    jmp next\n' "$i" "$i"; done
  echo "prog db 1, 2, 3, 150, 159, 0"
  echo "_TEXT ends"
  echo "end start"
} > "$TD/j1.asm"
asm j1.asm j1.com
lst j1.com j1_out.asm
O="$TD/j1_out.asm"
check j1_verified grep -q '^; VERIFIED identical' "$O"
check j1_entries test "$(grep -c 'table word' "$O")" -eq 158
check j1_handlers test "$(grep -cE '^    mov al, [0-9A-F]+h?' "$O")" -eq 157
check j1_header grep -qE '^; jump tables: 1 generic table\(s\), 158 entries, 2 hole\(s\)' "$O"
check j1_ends_at_code bash -c "grep -B4 'mov cx, 1' '$O' | grep -q 'table word'"
check j1_symbolic grep -qE 'jmp word ptr \[bx\+\(jt_[0-9A-F]{5} - L00100 \+ 100h\)\]' "$O"
check j1_rebuild same j1_out.asm j1.com bin

# ---- J2: variable ----
cat > "$TD/j2.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov bx, 2
    call word ptr [vec]
    mov ah, 4Ch
    int 21h
vec dw 0
    dw 0
ASM
printf '_TEXT ends\nend start\n' >> "$TD/j2.asm"
asm j2.asm j2.com
lst j2.com j2_out.asm
check j2_verified grep -q '^; VERIFIED identical' "$TD/j2_out.asm"
check j2_no_table bash -c "! grep -q 'generic table' '$TD/j2_out.asm'"
check j2_rebuild same j2_out.asm j2.com bin

# ---- J3: compare guard with a sub bias ----
cat > "$TD/j3.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov al, 10
    cmp al, 12
    ja done
    sub al, 9
    xor ah, ah
    mov bx, ax
    shl bx, 1
    call word ptr [bx+tbl]
done:
    mov ah, 4Ch
    int 21h
c0: mov al, 0
    ret
c1: mov al, 1
    ret
c2: mov al, 2
    ret
c3: mov al, 3
    ret
tbl dw c0, c1, c2, c3
    dw 0110h, 0120h
ASM
printf '_TEXT ends\nend start\n' >> "$TD/j3.asm"
asm j3.asm j3.com
lst j3.com j3_out.asm
check j3_verified grep -q '^; VERIFIED identical' "$TD/j3_out.asm"
check j3_entries test "$(grep -c 'table word' "$TD/j3_out.asm")" -eq 4
check j3_rebuild same j3_out.asm j3.com bin

# ---- J4: EXE, near cs: table in a second code segment ----
cat > "$TD/j4.asm" <<'ASM'
CODE1 segment para public use16 'CODE'
assume cs:CODE1
start:
    mov ax, seg CODE2
    mov ds, ax
    call far ptr disp
    mov ah, 4Ch
    int 21h
CODE1 ends
CODE2 segment para public use16 'CODE'
assume cs:CODE2
disp proc far
    mov bl, 2
    xor bh, bh
    shl bx, 1
    call word ptr cs:[bx+tbl]
    retf
disp endp
e0: mov al, 0
    ret
e1: mov al, 1
    ret
e2: mov al, 2
    ret
tbl dw e0, e1, e2
CODE2 ends
STK segment para stack 'STACK'
    db 256 dup (0)
STK ends
end start
ASM
asmz j4.asm j4.exe
lst j4.exe j4_out.asm
check j4_built test -s "$TD/j4.exe"
check j4_verified grep -q '^; VERIFIED identical' "$TD/j4_out.asm"
check j4_handlers test "$(grep -cE '^    mov al, [0-2]h?' "$TD/j4_out.asm")" -eq 3
check j4_header grep -qE '^; jump tables: 1 generic table\(s\), 3 entries' "$TD/j4_out.asm"

# ---- J5: EXE far table ----
cat > "$TD/j5.asm" <<'ASM'
CODE1 segment para public use16 'CODE'
assume cs:CODE1
start:
    mov bl, 1
    xor bh, bh
    shl bx, 1
    shl bx, 1
    call dword ptr cs:[bx+ftbl]
    mov ah, 4Ch
    int 21h
ftbl dd f0, f1
CODE1 ends
CODE2 segment para public use16 'CODE'
assume cs:CODE2
f0: mov al, 0
    retf
f1: mov al, 1
    retf
CODE2 ends
STK segment para stack 'STACK'
    db 256 dup (0)
STK ends
end start
ASM
asmz j5.asm j5.exe
lst j5.exe j5_out.asm
check j5_verified grep -q '^; VERIFIED identical' "$TD/j5_out.asm"
check j5_far_handlers test "$(grep -cE '^    mov al, [01]h?' "$TD/j5_out.asm")" -eq 2

# ---- J6: hint override on a table no rule reaches (index from memory) ----
cat > "$TD/j6.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov bx, word ptr [idx]
    mov ax, word ptr [bx]
    call ax
    mov ah, 4Ch
    int 21h
idx dw tbl
hk0: mov al, 0
    ret
hk1: mov al, 1
    ret
tbl dw hk0, hk1
ASM
printf '_TEXT ends\nend start\n' >> "$TD/j6.asm"
asm j6.asm j6.com
T6=$(python3 -c "import os,sys; print('%X' % (0x100+os.path.getsize(sys.argv[1])-4))" "$TD/j6.com")
printf 'table %s 2 near\n' "$T6" > "$TD/j6.hints"
lst j6.com j6_out.asm --hints="$TD/j6.hints"
check j6_verified grep -q '^; VERIFIED identical' "$TD/j6_out.asm"
check j6_hinted test "$(grep -cE '^    mov al, [01]h?' "$TD/j6_out.asm")" -eq 2
check j6_rebuild same j6_out.asm j6.com bin

echo "---"
echo "passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
