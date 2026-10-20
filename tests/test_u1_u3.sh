#!/usr/bin/env bash
# U1: sim/evidence options without their prerequisites name the full chain
#     (and do not enable --uasm on their own).
# U2: NUL-terminated text in data is labeled cstr_ in the verified listing.
# U3: the C startup `call X / push ax / call exit` marks X as a possible
#     _main, as a comment only (the label is not renamed).
# Missing assembler: U2/U3 skipped (U1 still runs).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-u13-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
CHAIN='full option chain: --uasm --uasm-verified --evidence=sim --sim-paths=N -o OUT.asm FILE'

# --- U1 ---------------------------------------------------------------
printf '\xb4\x4c\xcd\x21' > "$TD/t.com"
u1() { # $1 = name, rest = flags; must fail, name the chain, write no .asm
  local name=$1; shift
  local rc=0
  (cd "$TD" && "$BIN" "$@" t.com >"$TD/$name.out" 2>"$TD/$name.err") || rc=$?
  check "u1_${name}_rc" test "$rc" -ne 0
  check "u1_${name}_chain" grep -qF -- "$CHAIN" "$TD/$name.err"
  check "u1_${name}_no_asm" test ! -e "$TD/t.asm"
}
u1 evidence --evidence=sim --sim-paths=64
u1 evidence_a -a --evidence=sim --sim-paths=64
u1 paths_only --sim-paths=8
u1 no_uasm --uasm-verified --evidence=sim
check u1_old_message grep -qF -- 'Error: --uasm-verified requires --uasm' "$TD/no_uasm.err"
# Unrelated prerequisite errors do not mention sim.
rc=0; (cd "$TD" && "$BIN" --uasm-verified t.com >/dev/null 2>"$TD/plain.err") || rc=$?
check u1_plain_rc test "$rc" -ne 0
check u1_plain_no_chain bash -c "! grep -qF -- 'evidence=sim' '$TD/plain.err'"

N_UASM_CHECKS=17
UASM_BIN="$(uasm_resolve)" || {
  echo "SKIP $N_UASM_CHECKS U2/U3 checks: no uasm on PATH (set UASM=/path/to/uasm to run them)"
  echo "u1_u3 passed=$pass failed=$fail skipped=$N_UASM_CHECKS"
  [[ $fail -eq 0 ]]; exit
}
cat > "$TD/c.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov ax, 1
    call cmain
    push ax
    call cexit
cexit:
    pop ax
    mov ah, 4Ch
    int 21h
cmain:
    mov ah, 9
    mov dx, offset dmsg
    int 21h
    xor ax, ax
    ret
    db 0
greet db 'Hello, world', 0Ah, 0
short1 db 'Hi', 0
bin1 db 1, 2, 3, 4, 0
fmt db 'value=%d', 0
dmsg db 'Dollar$'
_TEXT ends
end start
ASM
(cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Foc.com c.asm >/dev/null 2>&1)
(cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o c_out.asm c.com >/dev/null 2>&1) || true
O="$TD/c_out.asm"
check u2_verified grep -q '^; VERIFIED identical' "$O"
check u2_greet grep -qE "^cstr_[0-9A-F]{5}:" "$O"
check u2_greet_text grep -qF "db 'Hello, world', 0Ah, 0h" "$O"
check u2_fmt grep -qF "db 'value=', 25h, 'd', 0h" "$O"
check u2_count grep -qF '; C strings: 2 NUL-terminated string(s) found in data' "$O"
check u2_short_not_labeled bash -c "! grep -qF \"'Hi', 0h\" '$O'"
check u2_dollar_still_str grep -qE '^    mov dx, offset str_[0-9A-F]{5}' "$O"
check u2_typed_unchanged grep -qF 'pointers and types: 0 code pointer(s) through a register, 1 typed string(s)' "$O"
check u3_header grep -qE '^; hint: possibly _main at (L|func_)[0-9A-F]{5} \(C startup pattern.*not verified, label not renamed' "$O"
check u3_comment grep -qE '^; hint: possibly _main \(C startup calls it' "$O"
check u3_not_named bash -c "! grep -qE '^_?main:' '$O'"
# The comment sits right before the label of cmain (0x10F).
check u3_target bash -c "grep -A1 '^; hint: possibly _main (' '$O' | grep -qE '^(L|func_)0010F:'"
# No startup pattern: no hint.
printf '\xb4\x4c\xcd\x21' > "$TD/n.com"
(cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o n_out.asm n.com >/dev/null 2>&1) || true
check u3_no_pattern bash -c "! grep -q 'possibly _main' '$TD/n_out.asm'"
# F1: a cstr never starts on (or covers) a relocated segment word. The
# word at image 0Fh is 01h 'Q' and "QRSTU",0 follows: printable from 'Q'.
python3 - "$TD/r.exe" <<'PY'
import struct, sys
img = bytes([0xB4, 0x4C, 0xCD, 0x21, 0]) + b'Good text\0' + bytes([0x01]) + b'QRSTU\0'
img += bytes(-len(img) % 16)
hdr = struct.pack('<14H', 0x5A4D, (32 + len(img)) % 512, (32 + len(img) + 511) // 512, 1, 2, 0, 0xFFFF,
                  len(img) // 16, 0x100, 0, 0, 0, 0x1C, 0) + struct.pack('<HH', 0x0F, 0) + bytes(32 - 0x20)
open(sys.argv[1], 'wb').write(hdr + img)
PY
(cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o r_out.asm r.exe >/dev/null 2>&1) || true
R="$TD/r_out.asm"
check f1_verified grep -q '^; VERIFIED identical' "$R"
check f1_reloc_symbolic grep -qF '; relocations: 1 of 1 segment words symbolic, 0 in undecoded data' "$R"
check f1_no_cstr_on_reloc bash -c "! grep -qE '^cstr_0001[01]:' '$R'"
check f1_good_string grep -qE '^cstr_00005:' "$R"
echo "u1_u3 passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
