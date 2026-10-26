#!/usr/bin/env bash
# Code pointers passed as call arguments (Borland printf passes __FPUTN to
# __VPRINTER, which calls it with `call word ptr [bp+d]`). The caller pushes
# `mov ax, CB / push ax` in the argument slot that the callee calls through,
# so CB is seeded as an entry and the immediate becomes a symbolic offset.
# Controls: the callee overwrites the slot, or calls through another slot,
# or a branch enters the push run after the mov: CB stays data.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_callback_args (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-cba-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
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
def build(name, callee, entered=False):
    img = bytearray(0x50)
    # mov dx, DGROUP; mov ds, dx; mov ax, 30h; push ax; mov ax, 5; push ax; call F(20h)
    img[0:0x10] = b'\xba\x04\x00\x8e\xda\xb8\x30\x00\x50\xb8\x05\x00\x50\xe8\x10\x00'
    img[0x10:0x15] = b'\xb8\x00\x4c\xcd\x21'
    if entered:
        # mov ax, 30h / jmp short +0 (a branch target inside the push run)
        img[0:0x12] = b'\xba\x04\x00\x8e\xda\xb8\x30\x00\xeb\x00\x50\xb8\x05\x00\x50\xe8\x0e\x00'
        img[0x12:0x17] = b'\xb8\x00\x4c\xcd\x21'
    img[0x20:0x20 + len(callee)] = callee
    img[0x30:0x34] = b'\xb9\x07\x00\xc3'           # CB: mov cx, 7 / ret
    mz(name, bytes(img), [1])
ok = b'\x55\x8b\xec\xff\x76\x04\xff\x56\x06\x59\x5d\xc3'          # push [bp+4]; call [bp+6]
build('cb.exe', ok)
build('written.exe', b'\x55\x8b\xec\xc7\x46\x06\x00\x00\xff\x56\x06\x5d\xc3')  # [bp+6] overwritten
build('slot.exe', b'\x55\x8b\xec\xff\x56\x04\x5d\xc3')            # calls the other slot
build('entered.exe', ok, entered=True)
PY
for f in cb written slot entered; do (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o $f.asm $f.exe >/dev/null 2>&1) || true; done
check cb_verified grep -q '^; VERIFIED identical' "$TD/cb.asm"
check cb_header grep -q '^; callback arguments: 1 code pointer' "$TD/cb.asm"
check cb_target_code grep -qE '^    mov cx, 7h	; 00030: B9 07 00' "$TD/cb.asm"
check cb_symbolic grep -qE '^    mov ax, \(L00030 - L00000\)	; 00005: B8 30 00' "$TD/cb.asm"
for f in written slot entered; do
  check ${f}_verified grep -q '^; VERIFIED identical' "$TD/$f.asm"
  check ${f}_target_data bash -c "! grep -qE '^    mov cx, 7h	; 00030: B9 07 00' '$TD/$f.asm'"
done
echo "callback_args passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
