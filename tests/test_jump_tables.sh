#!/usr/bin/env bash
# Generic jump/call tables (arch/jump-tables). Synthetic only; the private
# fixtures run from `make test-fixtures-jt` when present.
#  J1 COM: byte opcode dispatcher (lodsb / xor ah,ah / shl / jmp [bx+T]) with
#     no compare guard, a 160-entry table with two 0000 holes, and code
#     starting right after the table. Without hints the table ends at the
#     first hole (nothing else references the later handlers); J1h adds a
#     `table` hint and gets all 160 slots with both holes.
#  J2 COM: call [disp16] with no index register is a variable, not a table.
#  J3 COM: compare guard with a sub bias (cmp al,N; ja; sub al,K).
#  J4 EXE: cs: near table in a second code segment.
#  J5 EXE: far table (call dword ptr cs:[bx+T]), relocated segment words.
#  J6 COM: hint `table ADDR N near` overrides.
#  J7 COM (negative): unguarded byte dispatcher, then zero padding and a word
#     list pointing at text; a 0000 hole followed by an entry that is not
#     plausible code ends the table (no false code from the text).
#  J8 EXE (negative): cs: table at the very end of its segment; the next
#     segment starts with words pointing at text. The table never runs past
#     its segment.
#  J9 COM (negative): `mov si, offset X` names the word list just past the
#     table; an immediate address load ends the table.
#  J10 COM: rule 7 (branch-target promotion). A call target in data whose
#     next byte only a heuristic head decoded is promoted; a call target one
#     byte before flow-proven code is not (the proven decode is kept).
#  K1a-K1c, K2a, M1a, M1b, L1a, N1a-N1c, P1a-P1c: review repros (see the blocks at the end).
#  N8 round 2: tests/n8_syn verify repros, data slots never decoded as code.
#  G1-G11 (n8): index range guards. cmp/ja, cmp/jae, byte index (cmp al),
#     scaled (compare on the doubled offset), jbe taken, signed jg, a guard
#     smaller than the table; and no usable guard: another register, a branch
#     between guard and jump, index rewritten, byte compare on a word index,
#     a second dispatcher after a guarded one.
#  G12-G15 (n8 round 3): far table bound /4, mask after a guard, signed byte
#     compare, word inc after xor bh,bh.
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
# No hints: the slots after the 0000 holes point at handlers nothing else
# references, so the generic rule ends the table at the first hole.
check j1_entries test "$(grep -c 'table word' "$O")" -eq 40
check j1_handlers test "$(grep -cE '^    mov al, [0-9A-F]+h?' "$O")" -eq 39
check j1_header grep -qE '^; jump tables: 1 generic table\(s\), 40 entries, 0 hole\(s\)' "$O"
check j1_cut_at_hole bash -c "! grep -B4 'mov cx, 1' '$O' | grep -q 'table word'"
check j1_symbolic grep -qE 'jmp word ptr \[bx\+\(jt_[0-9A-F]{5} - L00100 \+ 100h\)\]' "$O"
check j1_rebuild same j1_out.asm j1.com bin
# J1h: the same program with a hint `table T A0 near`: all 160 slots, the
# two holes kept, the table ends at the code after it, one table label.
T1=$(sed -n 's/^jt_\([0-9A-F]\{5\}\):$/\1/p' "$O" | head -1)
printf 'table %s A0 near\n' "$T1" > "$TD/j1.hints"
lst j1.com j1h_out.asm --hints="$TD/j1.hints"
O="$TD/j1h_out.asm"
check j1h_verified grep -q '^; VERIFIED identical' "$O"
check j1h_entries test "$(grep -c 'table word' "$O")" -eq 158
check j1h_handlers test "$(grep -cE '^    mov al, [0-9A-F]+h?' "$O")" -eq 157
check j1h_holes grep -qE '^    db 0h, 0h, 0h, 0h.; ' "$O"
check j1h_ends_at_code bash -c "grep -B4 'mov cx, 1' '$O' | grep -q 'table word'"
check j1h_rebuild same j1h_out.asm j1.com bin

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

# ---- J7: 0000 hole + pointer list (negative) ----
cat > "$TD/j7.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
tbl dw h0, h1
    dw 6 dup(0)
msgp dw m1, m2
m1 db 'ABC', 0C3h
m2 db 'GHI', 0C3h
prog db 1, 0
ASM
printf '_TEXT ends\nend start\n' >> "$TD/j7.asm"
asm j7.asm j7.com
lst j7.com j7_out.asm
O="$TD/j7_out.asm"
check j7_verified grep -q '^; VERIFIED identical' "$O"
check j7_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check j7_text_is_data grep -qE '^    db .*41h, 42h, 43h, 0C3h, 47h, 48h, 49h, 0C3h' "$O"
check j7_no_false_code bash -c "! grep -qE '^    inc (cx|dx|bx)' '$O'"
check j7_rebuild same j7_out.asm j7.com bin

# ---- J8: table at the end of its segment (negative) ----
cat > "$TD/j8.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_DATA
start:
    mov ax, _DATA
    mov ds, ax
    mov bx, 0
    shl bx, 1
    jmp word ptr cs:[bx+tbl]
c0: mov ax, 4C00h
    int 21h
c1: mov al, 1
    ret
    db 0FFh, 0FFh
txt db 'AB', 0C3h
tbl dw c0, c1
_TEXT ends
_DATA segment para public use16 'DATA'
    dw txt, txt, 0
_DATA ends
_STACK segment para stack 'STACK'
    db 64 dup(0)
_STACK ends
end start
ASM
asmz j8.asm j8.exe
lst j8.exe j8_out.asm
O="$TD/j8_out.asm"
check j8_verified grep -q '^; VERIFIED identical' "$O"
check j8_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check j8_text_is_data grep -qE '^    db .*41h, 42h, 0C3h' "$O"
check j8_no_false_code bash -c "! grep -qE '^    inc (cx|dx)' '$O'"
check j8_built test -s "$TD/j8.exe"

# ---- J9: immediate address load just past the table (negative) ----
cat > "$TD/j9.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov si, offset after
    mov bx, 0
    shl bx, 1
    jmp word ptr [bx+tbl]
c0: mov ax, 4C00h
    int 21h
c1: mov al, 1
    ret
tbl dw c0, c1
after dw m1, m1
m1 db 'AB', 0C3h
ASM
printf '_TEXT ends\nend start\n' >> "$TD/j9.asm"
asm j9.asm j9.com
lst j9.com j9_out.asm
O="$TD/j9_out.asm"
check j9_verified grep -q '^; VERIFIED identical' "$O"
check j9_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check j9_no_false_code bash -c "! grep -qE '^    inc (cx|dx)' '$O'"
check j9_rebuild same j9_out.asm j9.com bin

# ---- J10: rule 7, branch-target promotion (positive and negative) ----
cat > "$TD/j10a.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov ax, 4C00h
    int 21h
    db 0FFh, 0FFh
orphan:
    mov dx, offset msg
    mov ah, 9
    int 21h
    call tgt
    ret
    db 0FFh, 0FFh
tgt:
    mov byte ptr ds:[168h], 1
    jmp orphan
    db 0FFh
    mov ah, 9
    int 21h
    ret
msg db 'Hi$'
ASM
printf '_TEXT ends\nend start\n' >> "$TD/j10a.asm"
asm j10a.asm j10a.com
lst j10a.com j10a_out.asm
O="$TD/j10a_out.asm"
check j10a_verified grep -q '^; VERIFIED identical' "$O"
check j10a_promoted grep -qE '1 direct target\(s\) promoted' "$O"
check j10a_target_decoded grep -qE '^    mov byte ptr ds:\[168h\], 1h?	; 00114:' "$O"
check j10a_rebuild same j10a_out.asm j10a.com bin
cat > "$TD/j10b.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    jmp near ptr tgt1
    db 0FFh, 0FFh
orphan:
    mov dx, offset msg
    mov ah, 9
    int 21h
    call tgt
    ret
    db 0FFh, 0FFh
tgt:
    db 0C6h
tgt1:
    push es
    pop es
    mov ax, 4C00h
    int 21h
msg db 'Hi$'
ASM
printf '_TEXT ends\nend start\n' >> "$TD/j10b.asm"
asm j10b.asm j10b.com
lst j10b.com j10b_out.asm
O="$TD/j10b_out.asm"
check j10b_verified grep -q '^; VERIFIED identical' "$O"
check j10b_not_promoted bash -c "! grep -qE '[1-9][0-9]* direct target\(s\) promoted' '$O'"
check j10b_proven_kept grep -qE '^    push es	; 00113:' "$O"
check j10b_rebuild same j10b_out.asm j10b.com bin

# ---- K1/K2 (verify-29e977e repros b1, b3, b4, c1) ----
#  K1a b1: byte dispatcher, 2 holes, then a callback array of directly
#      called functions and a pointer into text: the table ends at the hole.
#  K1b b3: several holes with called-function pointers between them.
#  K1c b4: a hole, then a pointer to a text byte followed by a jmp into a
#      called function: not dispatch evidence, the table ends at the hole.
#  K2a c1: `mov cx, offset tbl+4` is a loop count, not an address; it must
#      not cut the 4-entry table.
cat > "$TD/k1a.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    call f1
    call f2
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
f1: mov al, 11h
    ret
f2: mov al, 12h
    ret
tbl dw h0, h1
    dw 0, 0
cbs dw f1, f2
    dw m1
m1 db 'ABC', 0C3h
prog db 1, 0
_TEXT ends
end start
ASM
asm k1a.asm k1a.com
lst k1a.com k1a_out.asm
O="$TD/k1a_out.asm"
check k1a_verified grep -q '^; VERIFIED identical' "$O"
check k1a_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check k1a_no_false_code bash -c "! grep -qE '^    inc (cx|dx|bx)' '$O'"
check k1a_no_cb_table_word bash -c "! grep -qE 'offset func_[0-9A-F]+\s; [0-9A-F]+: table word' '$O'"
check k1a_rebuild same k1a_out.asm k1a.com bin
cat > "$TD/k1b.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    call f1
    call f2
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
f1: mov al, 11h
    ret
f2: mov al, 12h
    ret
tbl dw h0, h1
    dw 0, 0, 0
    dw f2
    dw 0, 0
    dw f1, m1
m1 db 'ABC', 0C3h
prog db 1, 0
_TEXT ends
end start
ASM
asm k1b.asm k1b.com
lst k1b.com k1b_out.asm
O="$TD/k1b_out.asm"
check k1b_verified grep -q '^; VERIFIED identical' "$O"
check k1b_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check k1b_no_false_code bash -c "! grep -qE '^    inc (cx|dx|bx)' '$O'"
check k1b_no_cb_table_word bash -c "! grep -qE 'offset func_[0-9A-F]+\s; [0-9A-F]+: table word' '$O'"
check k1b_rebuild same k1b_out.asm k1b.com bin
cat > "$TD/k1c.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    call f1
    call f2
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
f1: mov al, 11h
    ret
f2: mov al, 12h
    ret
tbl dw h0, h1
    dw 0
    dw m2
m2 db 'A', 0EBh, (f1 - ($+1)) and 0FFh
prog db 1, 0
_TEXT ends
end start
ASM
asm k1c.asm k1c.com
lst k1c.com k1c_out.asm
O="$TD/k1c_out.asm"
check k1c_verified grep -q '^; VERIFIED identical' "$O"
check k1c_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check k1c_no_false_code bash -c "! grep -qE '^    inc (cx|dx|bx)' '$O'"
check k1c_no_cb_table_word bash -c "! grep -qE 'offset func_[0-9A-F]+\s; [0-9A-F]+: table word' '$O'"
check k1c_rebuild same k1c_out.asm k1c.com bin
cat > "$TD/k2a.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov cx, offset tbl+4   ; a loop count that happens to equal an address inside the table
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
h2: mov al, 2
    jmp next
h3: mov al, 3
    jmp next
tbl dw h0, h1, h2, h3
prog db 1, 2, 3, 0
_TEXT ends
end start
ASM
asm k2a.asm k2a.com
lst k2a.com k2a_out.asm
O="$TD/k2a_out.asm"
check k2a_verified grep -q '^; VERIFIED identical' "$O"
check k2a_four_entries grep -qE '^; jump tables: 1 generic table\(s\), 4 entries, 0 hole\(s\)' "$O"
check k2a_handlers bash -c "grep -qE '^    mov al, 2h' '$O' && grep -qE '^    mov al, 3h' '$O'"
check k2a_rebuild same k2a_out.asm k2a.com bin

# ---- M1/L1 (verify-ce17c82 repros e1, e5, f2) ----
#  M1a e1: unguarded byte dispatcher, a hole, then pointers to handlers of
#      another table and a pointer into text; nothing hard-bounds the slots,
#      so the table ends at the hole.
#  M1b e5: several holes with another table's handlers between them.
#  L1a f2: `mov bx, offset tbl+4 ; add bx, 40 ; mov al, [bx]`: the register
#      is modified before use, so the immediate does not end the table.
cat > "$TD/m1a.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov bx, 1
    cmp bx, 1
    ja skip
    shl bx, 1
    jmp word ptr [bx+gtab]
g0: mov al, 20h
    jmp next
g1: mov al, 21h
    jmp next
skip:
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
tbl dw h0, h1
    dw 0
    dw g0, g1
    dw m1
m1 db 'ABC', 0C3h
gtab dw g0, g1
prog db 1, 0
_TEXT ends
end start
ASM
asm m1a.asm m1a.com
lst m1a.com m1a_out.asm
O="$TD/m1a_out.asm"
check m1a_verified grep -q '^; VERIFIED identical' "$O"
check m1a_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check m1a_no_false_code bash -c "! grep -qE '^    inc (cx|dx|bx)' '$O'"
check m1a_text_is_data grep -qE '^    db .*41h, 42h, 43h, 0C3h' "$O"
check m1a_rebuild same m1a_out.asm m1a.com bin
cat > "$TD/m1b.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov bx, 1
    cmp bx, 1
    ja skip
    shl bx, 1
    jmp word ptr [bx+gtab]
g0: mov al, 20h
    jmp next
g1: mov al, 21h
    jmp next
skip:
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
tbl dw h0, h1
    dw 0, 0
    dw g0
    dw 0
    dw g1, m1
m1 db 'ABC', 0C3h
gtab dw g0, g1
prog db 1, 0
_TEXT ends
end start
ASM
asm m1b.asm m1b.com
lst m1b.com m1b_out.asm
O="$TD/m1b_out.asm"
check m1b_verified grep -q '^; VERIFIED identical' "$O"
check m1b_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check m1b_no_false_code bash -c "! grep -qE '^    inc (cx|dx|bx)' '$O'"
check m1b_text_is_data grep -qE '^    db .*41h, 42h, 43h, 0C3h' "$O"
check m1b_rebuild same m1b_out.asm m1b.com bin
cat > "$TD/l1a.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov bx, offset tbl+4
    add bx, 40
    mov al, [bx]
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
h2: mov al, 2
    jmp next
h3: mov al, 3
    jmp next
tbl dw h0, h1, h2, h3
prog db 1, 2, 3, 0
_TEXT ends
end start
ASM
asm l1a.asm l1a.com
lst l1a.com l1a_out.asm
O="$TD/l1a_out.asm"
check l1a_verified grep -q '^; VERIFIED identical' "$O"
check l1a_four_entries grep -qE '^; jump tables: 1 generic table\(s\), 4 entries, 0 hole\(s\)' "$O"
check l1a_handlers bash -c "grep -qE '^    mov al, 2h' '$O' && grep -qE '^    mov al, 3h' '$O'"
check l1a_rebuild same l1a_out.asm l1a.com bin

# ---- N1 (verify-eaf0728 repro n7) ----
#  N1a n7: the slots end exactly at a function reached by a direct jmp (a
#      hard end), but the slot after the hole points at text whose flow
#      probe joins no proven code: the table ends at the hole.
cat > "$TD/n1a.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov dx, offset msg
    mov bx, 1
    cmp bx, 1
    ja skip
    shl bx, 1
    jmp word ptr [bx+gtab]
g0: mov al, 20h
    jmp next
skip:
    test dl, dl
    jz fn
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
tbl dw h0, h1
    dw 0
    dw txt

fn: mov al, 22h
    jmp next
gtab dw g0, fn
prog db 1, 0
msg db 'hi$'
txt db 'ABC', 0C3h

_TEXT ends
end start
ASM
asm n1a.asm n1a.com
lst n1a.com n1a_out.asm
O="$TD/n1a_out.asm"
check n1a_verified grep -q '^; VERIFIED identical' "$O"
check n1a_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check n1a_no_false_code bash -c "! grep -qE '^    inc (cx|dx|bx)' '$O'"
check n1a_rebuild same n1a_out.asm n1a.com bin

# ---- N1 follow-up: provenance and explicit joins ----
#  N1b: the slot after the hole points at 'A' + call fn + ret. A call is not
#      a join, so nothing proves it; on a22069d the call counted, the slot
#      was seeded and decoded in the next round only because of itself, and
#      that decode then confirmed it. Now rejected in every round.
#  N1c: the slot points at text sitting right in front of a function that
#      is reached by a direct jmp; it decodes cleanly and falls through into
#      the function. Fall-through into proven code is not a join: rejected.
cat > "$TD/n1b.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov dx, offset msg
    mov bx, 1
    cmp bx, 1
    ja skip
    shl bx, 1
    jmp word ptr [bx+gtab]
g0: mov al, 20h
    jmp next
skip:
    test dl, dl
    jz fn
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
tbl dw h0, h1
    dw 0
    dw txt

fn: mov al, 22h
    jmp next
gtab dw g0, fn
prog db 1, 0
msg db 'hi$'
txt db 'A', 0E8h
    dw fn - ($ + 2)
    db 0C3h

_TEXT ends
end start
ASM
asm n1b.asm n1b.com
lst n1b.com n1b_out.asm
O="$TD/n1b_out.asm"
check n1b_verified grep -q '^; VERIFIED identical' "$O"
check n1b_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check n1b_no_false_code bash -c "! grep -qE '^    inc (cx|dx|bx)' '$O'"
check n1b_rebuild same n1b_out.asm n1b.com bin
cat > "$TD/n1c.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov dx, offset msg
    mov bx, 1
    cmp bx, 1
    ja skip
    shl bx, 1
    jmp word ptr [bx+gtab]
g0: mov al, 20h
    jmp next
skip:
    test dl, dl
    jz fn
    test dh, dh
    jz fn2
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
tbl dw h0, h1
    dw 0
    dw txt

fn: mov al, 22h
    jmp next
txt db 'AB'
fn2: mov al, 23h
    jmp next
gtab dw g0, fn
prog db 1, 0
msg db 'hi$'

_TEXT ends
end start
ASM
asm n1c.asm n1c.com
lst n1c.com n1c_out.asm
O="$TD/n1c_out.asm"
check n1c_verified grep -q '^; VERIFIED identical' "$O"
check n1c_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check n1c_no_false_code bash -c "! grep -qE '^    inc (cx|dx|bx)' '$O'"
check n1c_rebuild same n1c_out.asm n1c.com bin

# ---- P1 (verify-61ff043 repros n10, n10b, n13) ----
#  P1a n10:  slot after a hole -> 'ABC' + jmp short exactly onto fn.
#  P1b n10b: the same with a near jmp.
#  P1c n13:  'AB' + jz exactly onto fn, then 'C', ret.
#  A join is not evidence: nothing outside the table references the target,
#  so the table ends at the hole.
cat > "$TD/p1a.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov dx, offset msg
    mov bx, 1
    cmp bx, 1
    ja skip
    shl bx, 1
    jmp word ptr [bx+gtab]
g0: mov al, 20h
    jmp next
skip:
    test dl, dl
    jz fn
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
tbl dw h0, h1
    dw 0
    dw dat

fn: mov al, 22h
    jmp next
gtab dw g0, fn
prog db 1, 0
msg db 'hi$'
dat db 41h, 42h, 43h, 0EBh
    db (offset fn - ($+1)) and 0FFh

_TEXT ends
end start
ASM
asm p1a.asm p1a.com
lst p1a.com p1a_out.asm
O="$TD/p1a_out.asm"
check p1a_verified grep -q '^; VERIFIED identical' "$O"
check p1a_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check p1a_no_false_code bash -c "! grep -qE '^    inc (cx|dx|bx)' '$O'"
check p1a_rebuild same p1a_out.asm p1a.com bin
cat > "$TD/p1b.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov dx, offset msg
    mov bx, 1
    cmp bx, 1
    ja skip
    shl bx, 1
    jmp word ptr [bx+gtab]
g0: mov al, 20h
    jmp next
skip:
    test dl, dl
    jz fn
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
tbl dw h0, h1
    dw 0
    dw dat

fn: mov al, 22h
    jmp next
gtab dw g0, fn
prog db 1, 0
msg db 'hi$'
dat db 41h, 42h, 43h
    db 0E9h
    dw offset fn - ($+2)

_TEXT ends
end start
ASM
asm p1b.asm p1b.com
lst p1b.com p1b_out.asm
O="$TD/p1b_out.asm"
check p1b_verified grep -q '^; VERIFIED identical' "$O"
check p1b_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check p1b_no_false_code bash -c "! grep -qE '^    inc (cx|dx|bx)' '$O'"
check p1b_rebuild same p1b_out.asm p1b.com bin
cat > "$TD/p1c.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov dx, offset msg
    mov bx, 1
    cmp bx, 1
    ja skip
    shl bx, 1
    jmp word ptr [bx+gtab]
g0: mov al, 20h
    jmp next
skip:
    test dl, dl
    jz fn
    mov si, offset prog
next:
    lodsb
    xor ah, ah
    mov bx, ax
    shl bx, 1
    jmp word ptr [bx+tbl]
h0: mov ax, 4C00h
    int 21h
h1: mov al, 1
    jmp next
tbl dw h0, h1
    dw 0
    dw dat

fn: mov al, 22h
    jmp next
gtab dw g0, fn
prog db 1, 0
msg db 'hi$'
dat db 41h, 42h, 74h
    db (offset fn - ($+1)) and 0FFh
    db 43h, 0C3h

_TEXT ends
end start
ASM
asm p1c.asm p1c.com
lst p1c.com p1c_out.asm
O="$TD/p1c_out.asm"
check p1c_verified grep -q '^; VERIFIED identical' "$O"
check p1c_two_entries grep -qE '^; jump tables: 1 generic table\(s\), 2 entries, 0 hole\(s\)' "$O"
check p1c_no_false_code bash -c "! grep -qE '^    inc (cx|dx|bx)' '$O'"
check p1c_rebuild same p1c_out.asm p1c.com bin

# ---- G1-G9: index range guards (n8) ----
# Six plausible entries; a dominating guard on the index register allows
# fewer. The table stops at the guard's bound; with no usable guard the old
# rule runs to the next boundary (6 entries).
gtest() { # name expected_entries dispatch-lines...
  local name=$1 want=$2; shift 2
  {
    echo "_TEXT segment para public use16 'CODE'"
    echo "assume cs:_TEXT, ds:_TEXT"
    echo "org 100h"
    echo "start:"
    echo "    mov si, offset prog"
    echo "    mov bx, word ptr [si]"
    printf '%s\n' "$@"
    echo "    mov ax, 4C00h"
    echo "    int 21h"
    echo "def: ret"
    for i in 0 1 2 3 4 5; do echo "h$i: mov al, $i"; echo "    ret"; done
    echo "tbl dw h0, h1, h2, h3, h4, h5"
    if [[ $name == g11 ]]; then echo "gtb dw h0, h1"; fi
    echo "prog db 1, 0"
    echo "_TEXT ends"
    echo "end start"
  } > "$TD/$name.asm"
  asm "$name.asm" "$name.com"
  lst "$name.com" "${name}_out.asm"
  local O="$TD/${name}_out.asm"
  check "${name}_verified" grep -q '^; VERIFIED identical' "$O"
  check "${name}_${want}_entries" test "$(grep -c 'table word' "$O")" -eq "$want"
  check "${name}_rebuild" same "${name}_out.asm" "$name.com" bin
}
# G1 cmp/ja (unsigned, inclusive): 0..2.
gtest g1 3 "    cmp bx, 2" "    ja def" "    shl bx, 1" "    jmp word ptr [bx+tbl]"
# G2 cmp/jae: 0..2.
gtest g2 3 "    cmp bx, 3" "    jae def" "    shl bx, 1" "    jmp word ptr [bx+tbl]"
# G3 byte index: compare on al, high byte cleared after the compare, copied to bx.
gtest g3 3 "    lodsb" "    cmp al, 2" "    ja def" "    xor ah, ah" "    mov bx, ax" "    shl bx, 1" "    jmp word ptr [bx+tbl]"
# G3b byte index, high byte cleared before the compare, jbe taken form.
gtest g3b 3 "    lodsb" "    xor ah, ah" "    cmp al, 2" "    jbe ok3" "    jmp def" "ok3: mov bx, ax" "    shl bx, 1" "    jmp word ptr [bx+tbl]"
# G4 scaled index: compare on the doubled offset (0, 2, 4).
gtest g4 3 "    shl bx, 1" "    cmp bx, 4" "    ja def" "    jmp word ptr [bx+tbl]"
# G5 guard bound smaller than the apparent table, jbe taken around a jmp.
gtest g5 2 "    cmp bx, 1" "    jbe ok5" "    jmp def" "ok5: shl bx, 1" "    jmp word ptr [bx+tbl]"
# G6 missing guard: the compare tests another register.
gtest g6 2 "    cmp cx, 1" "    ja def" "    shl bx, 1" "    jmp word ptr [bx+tbl]"
# G7 guard does not dominate: a branch enters between the guard and the jump.
gtest g7 2 "    jmp skip7" "back7: cmp bx, 1" "    ja def" "mid7: shl bx, 1" "    jmp word ptr [bx+tbl]" "skip7: test si, si" "    jz back7" "    jmp mid7"
# G8 signed compare (jg): upper bound 0..2.
gtest g8 3 "    cmp bx, 2" "    jg def" "    shl bx, 1" "    jmp word ptr [bx+tbl]"
# G9 index rewritten after the guard: the guard no longer applies.
gtest g9 2 "    cmp bx, 1" "    ja def" "    mov bx, word ptr [si+2]" "    shl bx, 1" "    jmp word ptr [bx+tbl]"
# G10 byte compare on a word index whose high byte is not cleared: no guard.
gtest g10 2 "    cmp bl, 1" "    ja def" "    shl bx, 1" "    jmp word ptr [bx+tbl]"
# G11 the old scan crossed into another path: a guarded table's compare
# must not bound a second, unguarded dispatcher further down.
# Expected: gtb 2 + tbl 2: the voided guard keeps the pre-n8 cap (M2, round 2).
gtest g11 4 "    test si, si" "    jz nx11" "    cmp bx, 1" "    ja def" "    shl bx, 1" "    jmp word ptr [bx+gtb]" "nx11: mov bx, word ptr [si]" "    shl bx, 1" "    jmp word ptr [bx+tbl]"

# ---- n8 round 3 (review-e2ac48e) ----
# G12 (M-b) far table, 4-byte entries: the compare on the offset after both
# shl (0..0Ch) allows 4 entries, not 6 (the old code halved the bound).
cat > "$TD/g12.asm" <<'ASM'
CODE1 segment para public use16 'CODE'
assume cs:CODE1
start:
    mov bx, word ptr cs:[idx]
    shl bx, 1
    shl bx, 1
    cmp bx, 0Ch
    ja out1
    jmp dword ptr cs:[bx+ftbl]
out1: mov ah, 4Ch
    int 21h
idx dw 1
ftbl dd f0, f1, f2, f3, f4, f5
CODE1 ends
CODE2 segment para public use16 'CODE'
assume cs:CODE2
f0: mov al, 0
    retf
f1: mov al, 1
    retf
f2: mov al, 2
    retf
f3: mov al, 3
    retf
f4: mov al, 4
    retf
f5: mov al, 5
    retf
CODE2 ends
STK segment para stack 'STACK'
    db 256 dup (0)
STK ends
end start
ASM
asmz g12.asm g12.exe
lst g12.exe g12_out.asm
check g12_verified grep -q '^; VERIFIED identical' "$TD/g12_out.asm"
check g12_far_4_handlers test "$(grep -cE '^    mov al, [0-5]h?\b' "$TD/g12_out.asm")" -eq 4
# (no raw -mz rebuild check: as in J5, the MZ header differs; VERIFIED covers it)
# G13 (M-a) a mask after an inverted guard is the last write: first 0, 4 entries.
gtest g13 4 "    cmp bx, 5" "    jbe def" "    and bx, 3" "    shl bx, 1" "    jmp word ptr [bx+tbl]"
# G14 (L-a) a signed compare on a zero-extended byte gives no bound (bl=80..FF
# passes jg): not capped at 3; every handler word is kept.
gtest g14 6 "    mov bl, byte ptr [si]" "    xor bh, bh" "    cmp bl, 2" "    jg def" "    shl bx, 1" "    jmp word ptr [bx+tbl]"
# G15 (L-c) a word inc after xor bh,bh can carry into bh: the byte guard is
# voided (pre-n8 cap 6, first 0) instead of bound 7 with first slot 1.
gtest g15 6 "    mov bl, byte ptr [si]" "    xor bh, bh" "    cmp bl, 5" "    ja def" "    inc bx" "    shl bx, 1" "    jmp word ptr [bx+tbl]"

# N8 round 2: verify repros (tests/n8_syn). Data slots d0..d3 are
# `mov al, 70h..73h; ret`; none may be decoded as code (d1_jbe_to_next is
# open: 4 false, same as main c552a32, see TODO.md).
for spec in a1_double_shl:0 a5_add_self_shl:0 a4_shl_cmp_shl:0 e1_si_double:0 \
            h1_inc_after_TD:0 h2_cmp_other_reg_TD:0 d2_land_at_jump:0 d3_land_mid:0 \
            a2_add_bias:0 e2_si_addbias:0 a3_inverted_jb:0 e3_di_invjb:0 c10_lodsb_hi:0 \
            d1_jbe_to_next:4; do
  n=${spec%%:*}; want=${spec##*:}
  cp "$ROOT/tests/n8_syn/$n.asm" "$TD/$n.asm"
  asm "$n.asm" "$n.com"
  lst "$n.com" "${n}_out.asm"
  check "${n}_verified" grep -q '^; VERIFIED identical' "$TD/${n}_out.asm"
  check "${n}_false_${want}" test "$(grep -cE 'mov al, 7[0-3]h' "$TD/${n}_out.asm")" -eq "$want"
  check "${n}_rebuild" same "${n}_out.asm" "$n.com" bin
done

# verify-5333adb HIGH: an upper guard before a wider `and` mask still bounds
# the table (count = min(guard, mask+1)). spec name:real-entries; data slots
# d0..d3 (mov al, 70h..73h) must stay data.
for spec in y11_guard_mask_wider:3 y12_guard1_mask3:2 y13_guard_jae_mask:2 y14_byte_guard_mask:3; do
  n=${spec%%:*}; want=${spec##*:}
  cp "$ROOT/tests/n8_syn/$n.asm" "$TD/$n.asm"
  asm "$n.asm" "$n.com"
  lst "$n.com" "${n}_out.asm"
  check "${n}_verified" grep -q '^; VERIFIED identical' "$TD/${n}_out.asm"
  check "${n}_${want}_entries" test "$(grep -c 'table word' "$TD/${n}_out.asm")" -eq "$want"
  check "${n}_false_0" test "$(grep -cE 'mov al, 7[0-3]h' "$TD/${n}_out.asm")" -eq 0
  check "${n}_rebuild" same "${n}_out.asm" "$n.com" bin
done
# y15: the same on a far table (4-byte entries): 2 handlers, no false slot.
cp "$ROOT/tests/n8_syn/y15_far_guard_mask.asm" "$TD/y15.asm"
asmz y15.asm y15.exe
lst y15.exe y15_out.asm
check y15_verified grep -q '^; VERIFIED identical' "$TD/y15_out.asm"
check y15_far_2_handlers test "$(grep -cE '^    mov al, [01]h?\b' "$TD/y15_out.asm")" -eq 2
check y15_false_0 test "$(grep -cE 'mov al, 7[0-3]h' "$TD/y15_out.asm")" -eq 0

echo "---"
echo "passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
