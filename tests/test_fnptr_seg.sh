#!/usr/bin/env bash
# Stored code pointers use the frame of the code that calls through the
# cell. Here the store and `call word ptr ds:[X]` sit in a second code
# segment (reached by a relocated far call), so imm is not an offset in the
# entry segment: bytes at entry_frame+imm stay data. In the entry segment the
# same pattern seeds the target (positive control).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_fnptr_seg (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-fnp-XXXXXX")"
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
def build(name, in_second):
    # Segment A (0x00-0x3F, entry), B (0x40-0x7F), DGROUP (0x80).
    a = bytearray(0x40); b = bytearray(0x40)
    a[0:5] = b'\xba\x08\x00\x8e\xda'                  # mov dx, DGROUP(reloc); mov ds, dx
    relocs = [1]
    if in_second:
        a[5:10] = b'\x9a\x00\x00\x04\x00'             # call far B:0 (reloc)
        relocs.append(8)
        a[10:15] = b'\xb8\x00\x4c\xcd\x21'
        b[0:11] = b'\xc7\x06\x00\x00\x20\x00\xff\x16\x00\x00\xcb'  # mov [0],20h; call [0]; retf
        b[0x20:0x24] = b'\xb8\x05\x00\xc3'            # B:20h  mov ax, 5 / ret (real target)
    else:
        a[5:16] = b'\xc7\x06\x00\x00\x20\x00\xff\x16\x00\x00\x90'  # mov [0],20h; call [0]; nop
        a[16:21] = b'\xb8\x00\x4c\xcd\x21'
    a[0x20:0x24] = b'\xb9\x07\x00\xc3'                # A:20h  mov cx, 7 / ret
    data = b'\0\0' + b'\0' * 14
    mz(name, bytes(a) + bytes(b) + data, relocs)
build('second.exe', True)
build('entry.exe', False)
PY
for f in second entry; do (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o $f.asm $f.exe >/dev/null 2>&1) || true; done
check second_verified grep -q '^; VERIFIED identical' "$TD/second.asm"
check second_far_decoded grep -qE '^    call word ptr ds:\[0h\]	; 0004[0-9A-F]: FF 16 00 00' "$TD/second.asm"
check second_entry_bytes_stay_data bash -c "! grep -qE '^    mov cx, 7h	; 00020: B9 07 00' '$TD/second.asm'"
check second_no_ptr_root bash -c "! grep -qE '^; startup entries: .*[1-9][0-9]* stored code pointer' '$TD/second.asm'"
check entry_verified grep -q '^; VERIFIED identical' "$TD/entry.asm"
check entry_target_code grep -qE '^    mov cx, 7h	; 00020: B9 07 00' "$TD/entry.asm"
check entry_ptr_root grep -qE '^; startup entries: 0 init/exit table record\(s\), 0 DS=CS interrupt handler\(s\), 1 stored code pointer' "$TD/entry.asm"
echo "fnptr_seg passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
