#!/usr/bin/env bash
# Borland FP emulator shape: a second code segment installs an interrupt
# handler with `mov ax, seg E / mov ds, ax / mov dx, off / int 21h AH=25h`
# (DS relocated, not DS=CS). The handler dispatches through a cs:[bx+T]
# table whose index is bounded only by `and bx, 6` (4 entries). Without the
# mask (control) the index is unbounded and the table targets stay data.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_fp_emu (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-fpe-XXXXXX")"
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
def build(name, masked):
    # Segment A (0x00-0x3F, entry), E (0x40-0xBF, emulator), DGROUP (0xC0).
    a = bytearray(0x40); e = bytearray(0x80)
    a[0:5] = b'\xba\x0c\x00\x8e\xda'                  # mov dx, DGROUP(reloc); mov ds, dx
    a[5:10] = b'\x9a\x00\x00\x04\x00'                 # call far E:0 (reloc)
    a[10:15] = b'\xb8\x00\x4c\xcd\x21'
    relocs = [1, 8]
    # E:0  mov ax, E(reloc); mov ds, ax; mov dx, 20h; mov ax, 2534h; int 21h; retf
    e[0:16] = b'\xb8\x04\x00\x8e\xd8\xba\x20\x00\xb8\x34\x25\xcd\x21\xcb\x90\x90'
    relocs.append(0x41)
    if masked:
        e[0x20:0x2A] = b'\x8b\xd8\x83\xe3\x06\x2e\xff\xa7\x40\x00'  # mov bx,ax; and bx,6; jmp cs:[bx+40h]
    else:
        e[0x20:0x2A] = b'\x8b\xd8\x90\x90\x90\x2e\xff\xa7\x40\x00'  # unbounded index
    e[0x40:0x48] = struct.pack('<4H', 0x50, 0x54, 0x58, 0x5C)
    for k in range(4):
        e[0x50 + 4 * k:0x54 + 4 * k] = bytes([0xB9, 0x11 * (k + 1), 0x00, 0xCF])  # mov cx, N / iret
    data = b'\0' * 16
    mz(name, bytes(a) + bytes(e) + data, relocs)
build('masked.exe', True)
build('open.exe', False)
PY
for f in masked open; do (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o $f.asm $f.exe >/dev/null 2>&1) || true; done
check masked_verified grep -q '^; VERIFIED identical' "$TD/masked.asm"
check masked_handler_count grep -q '^; far interrupt handlers: 1 ' "$TD/masked.asm"
check masked_handler_code grep -qE '^    mov bx, ax	; 00060: 8B D8' "$TD/masked.asm"
check masked_table_bounded grep -qE '^; value references: 1 bounded jump table\(s\) \(4 entries\)' "$TD/masked.asm"
check masked_targets_code bash -c "for o in 90 94 98 9C; do grep -qE \"^    mov cx, [0-9A-F]+h	; 000\$o: B9\" '$TD/masked.asm' || exit 1; done"
check open_verified grep -q '^; VERIFIED identical' "$TD/open.asm"
check open_handler_code grep -qE '^    mov bx, ax	; 00060: 8B D8' "$TD/open.asm"
check open_targets_data bash -c "! grep -qE '^    mov cx, [0-9A-F]+h	; 00090: B9' '$TD/open.asm'"
echo "fp_emu passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
