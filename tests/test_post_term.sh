#!/usr/bin/env bash
# Function starts right after a terminator (ret, retf, jmp, or padding
# after one). A start is seeded only when a straight-line trial decode
# reaches ret/retf/jmp cleanly, never touches known code, an invalid or
# unusual opcode, a relocation or an address the code uses as data, and is
# anchored (a bp-frame prologue, or a direct call/jmp to decoded code).
#  pos_prologue: an unreferenced bp-frame function after `ret`
#  pos_pad:      nop padding after `ret` (the start word-aligned), then a
#                function that calls known code
# Negatives (bytes stay data):
#  neg_noanchor: `mov cx, 7 / ret` after `ret`, no prologue, no call
#  neg_dataref:  a prologued run whose address is loaded by `mov si, offset`
#  neg_known:    a prologued run that falls through into a decoded function
#  neg_invalid:  a prologued run with `hlt` before its ret
#  neg_jmpback:  3 insns ending in one short jmp back into known code
#  neg_pretable: a prologued run right before the table of a decoded
#                `jmp word ptr cs:[bx+T]`
#  far_frame / neg_es_ref: a prologued run after retf in a second code
#                segment; seeded, unless code elsewhere names its offset
#                through ES (the segment is not known to be DS or the frame)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_post_term (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-pt-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
mk() { # name body-lines...
  local name=$1; shift
  {
    echo "_TEXT segment para public use16 'CODE'"
    echo "assume cs:_TEXT, ds:_TEXT"
    echo "org 100h"
    echo "start:"
    printf '%s\n' "$@"
    echo "_TEXT ends"
    echo "end start"
  } > "$TD/$name.asm"
  (cd "$TD" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo"$name.com" "$name.asm" >/dev/null 2>&1)
  (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o "${name}_out.asm" "$name.com" >/dev/null 2>&1) || true
  check "${name}_verified" grep -q '^; VERIFIED identical' "$TD/${name}_out.asm"
}
has() { grep -qE "^    $2" "$TD/$1_out.asm"; }
MAIN=("    call kfn" "    mov ax, 4C00h" "    int 21h" "kfn: mov bl, 1" "    ret")
mk pos_prologue "${MAIN[@]}" "f1: push bp" "    mov bp, sp" "    mov ax, 5" "    pop bp" "    ret"
check pos_prologue_code has pos_prologue 'mov ax, 5h'
mk pos_pad "${MAIN[@]:0:3}" "    jmp kfn" "    nop" "kfn: mov bl, 1" "    ret" "    nop" "    nop" "f2: mov dx, 6" "    call kfn" "    ret"
check pos_pad_code has pos_pad 'mov dx, 6h'
mk neg_noanchor "${MAIN[@]}" "    mov cx, 7" "    ret"
check neg_noanchor_data bash -c "! grep -qE '^    mov cx, 7h' '$TD/neg_noanchor_out.asm'"
mk neg_dataref "    mov si, offset f3" "${MAIN[@]}" "f3: push bp" "    mov bp, sp" "    mov ax, 5" "    pop bp" "    ret"
check neg_dataref_data bash -c "! grep -qE '^    mov ax, 5h' '$TD/neg_dataref_out.asm'"
mk neg_known "    call kfn" "    call kb2" "    mov ax, 4C00h" "    int 21h" "kfn: mov bl, 1" "    ret" "    push bp" "    mov bp, sp" "    mov dx, 3" "kb2: mov bl, 2" "    ret"
check neg_known_data bash -c "! grep -qE '^    mov dx, 3h' '$TD/neg_known_out.asm'"
mk neg_invalid "${MAIN[@]}" "    push bp" "    mov bp, sp" "    mov ax, 5" "    hlt" "    pop bp" "    ret"
check neg_invalid_data bash -c "! grep -qE '^    mov ax, 5h' '$TD/neg_invalid_out.asm'"
mk neg_jmpback "${MAIN[@]}" "    mov cx, 7" "    mov dx, 8" "    jmp kfn"
check neg_jmpback_data bash -c "! grep -qE '^    mov cx, 7h' '$TD/neg_jmpback_out.asm'"
mk neg_pretable "    call kfn" "    mov ax, 4C00h" "    int 21h" "kfn: xor bx, bx" "    and bx, 2" "    jmp word ptr cs:[bx+tbl]" "h1: mov bl, 1" "    ret" "    push bp" "    mov bp, sp" "    mov ax, 5" "    pop bp" "    ret" "tbl dw h1, h1"
check neg_pretable_data bash -c "! grep -qE '^    mov ax, 5h' '$TD/neg_pretable_out.asm'"
check neg_pretable_table grep -q 'jmp word ptr cs:\[bx+' "$TD/neg_pretable_out.asm"
python3 - "$TD" <<'PY'
import struct, sys, os
td = sys.argv[1]
def mz(name, img, relocs):
    img = img + bytes(-len(img) % 16)
    hl = 0x40
    n = hl + len(img)
    h = struct.pack('<14H', 0x5A4D, n % 512, (n + 511) // 512, len(relocs), hl // 16, 0, 0xFFFF,
                    len(img) // 16, 0x80, 0, 0, 0, 0x1C, 0)
    for r in relocs:
        h += struct.pack('<HH', r, 0)
    open(os.path.join(td, name), 'wb').write(h + bytes(hl - len(h)) + img)
for name, es in (('far_frame', False), ('neg_es_ref', True)):
    a = bytearray(0x40); b = bytearray(0x40); d = bytearray(0x20)
    code = b'\xba\x08\x00\x8e\xda' + (b'\x26\xa1\x10\x00' if es else b'\x90\x90\x90\x90') + b'\x9a\x00\x00\x04\x00' + b'\xb8\x00\x4c\xcd\x21'
    a[0:len(code)] = code
    relocs = [1, 9 + 3]
    b[0:4] = b'\xb8\x01\x00\xcb'
    b[4:0x10] = b'\x90' * 12
    b[0x10:0x19] = b'\x55\x8b\xec\xb8\x05\x00\x5d\xcb\x90'
    mz(name + '.exe', bytes(a) + bytes(b) + bytes(d), relocs)
PY
for f in far_frame neg_es_ref; do
  (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o ${f}_out.asm $f.exe >/dev/null 2>&1) || true
  check ${f}_verified grep -q '^; VERIFIED identical' "$TD/${f}_out.asm"
done
check far_frame_code grep -qE '^    mov ax, 5h	; 00053' "$TD/far_frame_out.asm"
check neg_es_ref_data bash -c "! grep -qE '^    mov ax, 5h	; 00053' '$TD/neg_es_ref_out.asm'"
echo "post_term passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
