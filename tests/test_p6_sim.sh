#!/usr/bin/env bash
# P6: --evidence=sim. A handler table called without a bound (t01 class)
# is invisible to the static graph; the simulator executes the handlers and
# they are decoded. Opt-in; deterministic; a spin loop stays bounded.
# Missing assembler: exit 77 (skip).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_p6_sim (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p6-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
asm() { (cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo"$2" "$1" >/dev/null 2>&1); }
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
asm t.asm t.com
V="$BIN --uasm --uasm-verified --uasm-bin $UASM_BIN"
(cd "$TD" && $V -o s.asm t.com >/dev/null 2>&1) || true
(cd "$TD" && $V --evidence=sim -o d.asm t.com >/dev/null 2>&1) || true
(cd "$TD" && $V --evidence=sim -o d2.asm t.com >/dev/null 2>&1) || true
check static_misses test "$(grep -c '^    mov al, ' "$TD/s.asm")" -eq 0
check sim_decodes test "$(grep -c '^    mov al, ' "$TD/d.asm")" -eq 4
check sim_verified grep -q '^; VERIFIED identical' "$TD/d.asm"
check sim_header grep -qE '^; simulation evidence: [0-9]+ address\(es\) executed, [0-9]+ confirm decoded heads, [1-9][0-9]* seeded' "$TD/d.asm"
check sim_no_conflict grep -q ' 0 inside a decoded instruction' "$TD/d.asm"
check deterministic cmp -s "$TD/d.asm" "$TD/d2.asm"
check needs_verified bash -c "! '$BIN' --uasm --evidence=sim '$TD/t.com' >/dev/null 2>&1"
# Budget safety: an infinite spin stops at the cap and the listing is identical.
printf '\xeb\xfe' > "$TD/spin.com"
(cd "$TD" && timeout 60 $V --evidence=sim --max-insns=5000 -o spin.asm spin.com >/dev/null 2>&1) || true
check spin_bounded grep -q '^; VERIFIED identical' "$TD/spin.asm"

# ---- P6 exploration (--sim-paths) ----
# Fork: the DOS-version check is never taken on the first path (DOS 5);
# the forked path reaches a handler called through a table.
cat > "$TD/f.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov ah, 30h
    int 21h
    cmp al, 2
    jb old_dos
    mov ah, 4Ch
    int 21h
old_dos:
    call word ptr cs:[ftbl]
    mov ah, 4Ch
    int 21h
    db 0EAh
fh: mov al, 7
    ret
ftbl dw fh
_TEXT ends
end start
ASM
asm f.asm f.com
(cd "$TD" && $V --evidence=sim -o f1.asm f.com >/dev/null 2>&1) || true
(cd "$TD" && $V --evidence=sim --sim-paths=8 -o f8.asm f.com >/dev/null 2>&1) || true
(cd "$TD" && $V --evidence=sim --sim-paths=8 -o f8b.asm f.com >/dev/null 2>&1) || true
(cd "$TD" && $V --evidence=sim --sim-paths=8 --strict -o f8s.asm f.com >/dev/null 2>&1) || true
check fork_single_misses test "$(grep -c '^    mov al, 7' "$TD/f1.asm")" -eq 0
check fork_reaches test "$(grep -c '^    mov al, 7' "$TD/f8.asm")" -eq 1
check fork_verified grep -q '^; VERIFIED identical' "$TD/f8.asm"
check fork_header grep -qE '^; simulation paths: [2-9][0-9]* run \(cap 8\), [1-9][0-9]* fork\(s\).*[1-9][0-9]* likely$' "$TD/f8.asm"
check fork_deterministic cmp -s "$TD/f8.asm" "$TD/f8b.asm"
check fork_strict_not_seeded test "$(grep -c '^    mov al, 7' "$TD/f8s.asm")" -eq 0
check fork_strict_header grep -q 'likely not seeded: --strict' "$TD/f8s.asm"
check single_path_unchanged bash -c "! grep -q '^; simulation paths' '$TD/f1.asm'"
# t04: INT 1Ch handler installed with INT 21h/25h runs as a scheduled path.
cat > "$TD/v.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov dx, word ptr cs:[hptr]
    mov ax, 251Ch
    int 21h
    mov ah, 4Ch
    int 21h
    db 0EAh
tick:
    inc word ptr cs:[cnt]
    iret
hptr dw tick
cnt dw 0
_TEXT ends
end start
ASM
asm v.asm v.com
(cd "$TD" && $V --evidence=sim -o v1.asm v.com >/dev/null 2>&1) || true
(cd "$TD" && $V --evidence=sim --sim-paths=4 -o v4.asm v.com >/dev/null 2>&1) || true
(cd "$TD" && $V --evidence=sim --sim-paths=4 --sim-no-dispatch-int -o v4n.asm v.com >/dev/null 2>&1) || true
check dispatch_single_misses test "$(grep -c '^    iret' "$TD/v1.asm")" -eq 0
check dispatch_handler test "$(grep -c '^    iret' "$TD/v4.asm")" -eq 1
check dispatch_header grep -qE ', 1 handler dispatch\(es\)' "$TD/v4.asm"
check dispatch_off test "$(grep -c '^    iret' "$TD/v4n.asm")" -eq 0
# S-4: a program-installed vector runs its handler on the first path (faithful).
cat > "$TD/i.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov dx, word ptr cs:[iptr]
    mov ax, 2560h
    int 21h
    int 60h
    mov ah, 4Ch
    int 21h
    db 0EAh
i60:
    mov al, 60h
    iret
iptr dw i60
_TEXT ends
end start
ASM
asm i.asm i.com
(cd "$TD" && $V --evidence=sim -o i1.asm i.com >/dev/null 2>&1) || true
check ivt_dispatch test "$(grep -c '^    mov al, 60h' "$TD/i1.asm")" -eq 1
check ivt_dispatch_verified grep -q '^; VERIFIED identical' "$TD/i1.asm"
# S-8: xlat/aam/aad/daa/das/aaa/aas/enter/leave no longer stop the path.
cat > "$TD/e.asm" <<'ASM'
.186
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov bx, offset xt
    mov al, 1
    xlat
    aam
    aad
    daa
    das
    aaa
    aas
    enter 4, 0
    leave
    call word ptr cs:[etbl]
    mov ah, 4Ch
    int 21h
    db 0EAh
eh: mov al, 5
    ret
xt  db 0, 9
etbl dw eh
_TEXT ends
end start
ASM
asm e.asm e.com
(cd "$TD" && $V --evidence=sim -o e1.asm e.com >/dev/null 2>&1) || true
check s8_continues test "$(grep -c '^    mov al, 5' "$TD/e1.asm")" -eq 1
(cd "$TD" && "$BIN" --simulate --sim-quiet e.com > e.sim 2>&1) || true
check s8_simulate bash -c "! grep -q 'unsupported opcode' '$TD/e.sim' && grep -q '^Reason: ' '$TD/e.sim'"
# Budget safety with exploration: the spin stays bounded by the total cap.
(cd "$TD" && timeout 60 $V --evidence=sim --sim-paths=64 --sim-total-insns=20000 --max-insns=5000 -o spin8.asm spin.com >/dev/null 2>&1) || true
check spin_paths_bounded grep -q '^; VERIFIED identical' "$TD/spin8.asm"
check paths_range bash -c "! '$BIN' --uasm --uasm-verified --evidence=sim --sim-paths=0 '$TD/t.com' >/dev/null 2>&1"
check paths_need_sim bash -c "! '$BIN' --uasm --uasm-verified --sim-paths=4 '$TD/t.com' >/dev/null 2>&1"
# T1: imul/mul/div/idiv overflow corners under UBSan (review 2026-10-14b).
cat > "$TD/m.asm" <<'ASM'
.386
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov ax, 8000h
    imul cx, ax, 7FFFh
    imul cx, ax, -1
    imul dx, ax, -128
    mov bx, 8000h
    imul ax, bx
    imul bx
    mov dx, 7FFFh
    mov ax, 0FFFFh
    mov cx, 0FFFFh
    mul cx
    cmp ax, 1
    jne done
    mov dx, 8000h
    xor ax, ax
    mov cx, -1
    idiv cx
done:
    mov ah, 4Ch
    int 21h
_TEXT ends
end start
ASM
asm m.asm m.com
(cd "$TD" && $V --evidence=sim --sim-paths=64 -o m.asm.out m.com >/dev/null 2>&1) || true
check t1_verified grep -q '^; VERIFIED identical' "$TD/m.asm.out"
(cd "$TD" && "$BIN" --simulate m.com > m.sim 2>&1) || true
check t1_idiv_overflow_stops grep -q '^Reason: divide overflow' "$TD/m.sim"
if [[ -x "$ROOT/dumpexe-asan" ]]; then
  check t1_ubsan_clean bash -c "cd '$TD' && UBSAN_OPTIONS=print_stacktrace=1 '$ROOT/dumpexe-asan' --uasm --uasm-verified --uasm-bin '$UASM_BIN' --evidence=sim --sim-paths=64 -o mu.asm m.com >/dev/null 2>ubsan.err; ! grep -qE 'runtime error|AddressSanitizer' ubsan.err"
  check t1_ubsan_simulate bash -c "cd '$TD' && '$ROOT/dumpexe-asan' --simulate m.com >/dev/null 2>ubsan2.err; ! grep -qE 'runtime error|AddressSanitizer' ubsan2.err"
else
  echo "SKIP t1_ubsan (no dumpexe-asan; make asan)"
fi
echo "p6_sim passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
