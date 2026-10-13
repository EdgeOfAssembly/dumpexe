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
echo "p6_sim passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
