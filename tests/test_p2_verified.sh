#!/usr/bin/env bash
# P2: verified emitter (--uasm --uasm-verified), shift tests, negative
# control, relocation-set compare, --xrefs, and the G15 unpacked -o path.
# Missing assembler: exit 77 (skip).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_p2_verified (no uasm)"; exit 77; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p2-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0
fail=0
check() {
  local name=$1
  shift
  if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi
}

asm() { (cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo"$2" "$1" >/dev/null 2>&1); }

# Synthetic COM: branches of every size, a jump into the middle of an
# instruction (the CFG decodes the target as its own leader), and three
# encodings UASM never picks (pins).
cat > "$TD/s.asm" <<'ASM'
_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov ax, 3
    db 89h, 0C3h          ; mov bx, ax (d=0)
    db 05h, 02h, 00h      ; add ax, 2 (accumulator imm16)
    db 81h, 0C3h, 10h, 00h ; add bx, 10h (imm16)
    call near ptr sub1
    cmp ax, 5
    jz short done
    jmp near ptr mid+1
mid:
    db 0B0h, 90h          ; mov al, 90h ; mid+1 is a nop
    mov cx, 4
lp: loop lp
done:
    mov ah, 4Ch
    int 21h
sub1:
    inc ax
    ret
_TEXT ends
end start
ASM
asm s.asm s.com

V="$BIN --uasm --uasm-verified --uasm-bin $UASM_BIN"
$V -o "$TD/s_out.asm" "$TD/s.com" >"$TD/s.stdout" 2>"$TD/s.stderr" || true
check com_verified grep -q '^; VERIFIED identical' "$TD/s_out.asm"
check com_reassembles bash -c "cd '$TD' && env -u UASM '$UASM_BIN' -bin -nologo -Fos_re.bin s_out.asm >/dev/null 2>&1 && cmp -s s_re.bin s.com"
check com_branch_symbolic grep -q 'call near ptr L' "$TD/s_out.asm"
check com_pin_used grep -qE '^    (mov_rm|add_aw|add_iw) ' "$TD/s_out.asm"
check com_shift_start_clean grep -qE '^; shift start: [1-9][0-9]* references checked, 0 broken' "$TD/s_out.asm"
check com_shift_mid_clean grep -qE '^; shift mid: [1-9][0-9]* references checked, 0 broken' "$TD/s_out.asm"
check com_status_zero $V -o "$TD/s_out2.asm" "$TD/s.com"

# Negative control: every code line raw db. Identity still holds. A start
# shift only moves references that cross the entry; the mid shift catches
# the call and loop around the median line.
DUMPEXE_UASM_NEGCONTROL=1 $V -o "$TD/neg.asm" "$TD/s.com" >/dev/null 2>&1 || true
check negcontrol_identical grep -q '^; VERIFIED identical' "$TD/neg.asm"
check negcontrol_breaks grep -qE '^; shift mid: [0-9]+ references checked, [1-9][0-9]* broken' "$TD/neg.asm"

# Requires --uasm; no assembler means NOT VERIFIED and exit 1.
check needs_uasm bash -c "! '$BIN' --uasm-verified '$TD/s.com' >/dev/null 2>&1"
set +e
"$BIN" --uasm --uasm-verified --uasm-bin /nonexistent/uasm -o "$TD/nobin.asm" "$TD/s.com" >/dev/null 2>&1
rc=$?
set -e
check no_assembler_exit1 test "$rc" -eq 1
check no_assembler_header grep -q '^; NOT VERIFIED' "$TD/nobin.asm"
check no_assembler_no_mnemonic grep -q '^; lines: mnemonic 0 ' "$TD/nobin.asm"

# MZ with relocations: relocated words are segment expressions, the
# rebuilt load image is identical, and both shifts keep every reference.
AR="$ROOT/games/alternate-reality-the-city/CITY.EXE"
if [[ -f "$AR" ]]; then
  cp "$AR" "$TD/CITY.EXE"
  (cd "$TD" && $V -o city.asm CITY.EXE >/dev/null 2>&1) || true
  check mz_verified grep -q '^; VERIFIED identical' "$TD/city.asm"
  check mz_seg_expr grep -qE '\(\(L[0-9A-F]{5} - L00000\) shr 4\)' "$TD/city.asm"
  check mz_relocs_line grep -qE '^; relocations: [1-9][0-9]* of [0-9]+ segment words symbolic' "$TD/city.asm"
  check mz_shift_start grep -qE '^; shift start: [1-9][0-9]* references checked, 0 broken' "$TD/city.asm"
  check mz_shift_mid grep -qE '^; shift mid: [1-9][0-9]* references checked, 0 broken' "$TD/city.asm"
  check mz_image_identical python3 - "$TD/CITY.EXE" "$TD/city.asm" "$UASM_BIN" <<'PY'
import os, struct, subprocess, sys
f, a, u = sys.argv[1:]
d = open(f, 'rb').read()
cblp, cp = struct.unpack_from('<HH', d, 2)
hdr = struct.unpack_from('<H', d, 8)[0] * 16
size = cp * 512 - (512 - cblp if cblp else 0)
env = dict(os.environ); env.pop('UASM', None)
wd = os.path.dirname(a)
subprocess.run([u, '-bin', '-nologo', '-Fo' + wd + '/city.bin', a], cwd=wd, capture_output=True, env=env)
sys.exit(0 if open(wd + '/city.bin', 'rb').read() == d[hdr:min(size, len(d))] else 1)
PY
fi

# --xrefs: entry row first, then edges with model evidence.
"$BIN" --xrefs "$TD/s.com" >"$TD/x.txt" 2>&1
check xrefs_header grep -q '^; dumpexe --xrefs' "$TD/x.txt"
check xrefs_entry_first bash -c "grep -A1 '^; dumpexe --xrefs' '$TD/x.txt' | tail -1 | grep -q '^ENTRY  00100  entry      proven(entry)'"
check xrefs_call grep -qE '^[0-9A-F]{5}  [0-9A-F]{5}  call +proven\(direct-call\)' "$TD/x.txt"
check xrefs_jcc grep -qE 'jcc-true +proven\(direct-jcc\)' "$TD/x.txt"

# Review R1: --xrefs read a freed fact vector. ASan build, when present.
if [[ -x "$ROOT/dumpexe-asan" ]]; then
  check xrefs_asan_clean bash -c "'$ROOT/dumpexe-asan' --xrefs '$TD/s.com' >/dev/null 2>'$TD/asan.err'; ! grep -q AddressSanitizer '$TD/asan.err'"
fi

# G15: with -o FILE the unpacked listing is <FILE stem>_UNPACKED.asm.
PK="$ROOT/games/psychic-war/PW.EXE"
if [[ -f "$PK" ]]; then
  mkdir -p "$TD/pk" "$TD/pkout"
  cp "$PK" "$TD/pk/PW.EXE"
  (cd "$TD/pk" && "$BIN" -d -o "$TD/pkout/listing.asm" PW.EXE >/dev/null 2>&1) || true
  check unpacked_packed_listing test -f "$TD/pkout/listing.asm"
  check unpacked_follows_o test -f "$TD/pkout/listing_UNPACKED.asm"
  check unpacked_not_next_to_input test ! -f "$TD/pk/PW_UNPACKED.asm"
  check unpacked_image_written test -f "$TD/pk/PW_UNPACKED.EXE"
  # Without -o the unpacked listing stays next to the input, as before.
  mkdir -p "$TD/pk2"
  cp "$PK" "$TD/pk2/PW.EXE"
  (cd "$TD/pk2" && "$BIN" -d PW.EXE >/dev/null 2>&1) || true
  check unpacked_default_path test -f "$TD/pk2/PW_UNPACKED.asm"
fi

# Review R2 (intended since 2.31): toolchain detection reruns on the
# unpacked image, so an unpacked listing whose toolchain is recognised is
# the JWASM export. The sample is not redistributable: DUMPEXE_R2_SAMPLE.
if [[ -n "${DUMPEXE_R2_SAMPLE:-}" && -f "${DUMPEXE_R2_SAMPLE}" ]]; then
  mkdir -p "$TD/r2"; cp "$DUMPEXE_R2_SAMPLE" "$TD/r2/IN.EXE"
  (cd "$TD/r2" && "$BIN" -d --no-repack IN.EXE >out.txt 2>&1) || true
  check r2_unpacked_jwasm bash -c "sed -n '/=== UNPACKED ===/,\$p' '$TD/r2/out.txt' | grep -q 'JWASM-assemblable export'"
fi

echo "p2_verified passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
