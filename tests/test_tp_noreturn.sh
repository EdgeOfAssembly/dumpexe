#!/usr/bin/env bash
# Turbo Pascal programs: System.Halt is found by its code signature (TP EXEs
# carry no symbols). A far call to Halt or RunError followed only by zero
# padding up to the next paragraph ends the code: the padding stays data.
# The same holds after the last overlay stub (`int 3Fh` + 3 stub bytes).
# The next paragraph is seeded when it is a relocated frame that starts
# with `push bp / mov bp, sp`. Control: with the signature broken (not TP)
# the padding after the call is decoded as before.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_tp_noreturn (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-tpn-XXXXXX")"
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
def build(name, tp=True, runerror=False):
    # A main (0x00), O overlay stub (0x20), P unit proc (0x30),
    # S System (0x40: RunError at S:0, Halt at S:4), DGROUP (0x60).
    img = bytearray(0x70)
    img[0:5] = b'\xba\x06\x00\x8e\xda'               # mov dx, DGROUP; mov ds, dx
    img[5:16] = b'\x90' * 11                         # nops: 4 bytes of padding remain
    img[16:21] = b'\x9a\x00\x00\x02\x00'             # call far O:0
    if runerror:
        img[21:23] = b'\xb0\xc8'                     # mov al, 0C8h
        img[23:28] = b'\x9a\x00\x00\x04\x00'         # call far RunError
    else:
        img[21:23] = b'\x31\xc0'                     # xor ax, ax
        img[23:28] = b'\x9a\x04\x00\x04\x00'         # call far Halt
    img[0x20:0x25] = b'\xcd\x3f\x0d\x00\x00'         # int 3Fh stub
    img[0x30:0x38] = b'\x55\x89\xe5\xb8\x01\x00\x5d\xcb'  # push bp/mov bp,sp/mov ax,1/pop bp/retf
    s = b'\x59\x5b\xeb\x04' + b'\x33\xc9\x33\xdb\xba\x06\x00\x8e\xda' + \
        (b'\xfb' if tp else b'\x90') + b'\xa3\x2c\x00\x8b\xc1\x0b\xc3\x74\x00\xb8\x00\x4c\xcd\x21'
    img[0x40:0x40 + len(s)] = s
    img[0x60:0x62] = b'\x03\x00'                     # dw seg P (relocated)
    mz(name, bytes(img), [1, 19, 26, 0x49, 0x60])
build('halt.exe')
build('runerr.exe', runerror=True)
build('nontp.exe', tp=False)
PY
for f in halt runerr nontp; do (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o $f.asm $f.exe >/dev/null 2>&1) || true; done
for f in halt runerr; do
  check ${f}_verified grep -q '^; VERIFIED identical' "$TD/$f.asm"
  check ${f}_padding_data bash -c "! grep -qE '^    add byte ptr \[bx\+si\], al	; 000(1[C-F]|2[5-9A-F]):' '$TD/$f.asm'"
  check ${f}_proc_seeded grep -qE '^    mov ax, 1h	; 00033: B8 01 00' "$TD/$f.asm"
done
check nontp_verified grep -q '^; VERIFIED identical' "$TD/nontp.asm"
check nontp_padding_decoded grep -qE '^    add byte ptr \[bx\+si\], al	; 0001C: 00 00' "$TD/nontp.asm"
check nontp_proc_not_seeded bash -c "! grep -qE '^    mov ax, 1h	; 00033: B8 01 00' '$TD/nontp.asm'"
echo "tp_noreturn passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
