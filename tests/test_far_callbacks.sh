#!/usr/bin/env bash
# Far callbacks: a callee that calls through `call dword ptr [bp+d]`, its
# caller pushing the segment (relocated, or push cs) then the offset; and a
# far caller (`call seg:F`, arguments from [bp+6]) for a near slot.
#  far_imm:   mov ax, seg (relocated) / push ax / mov ax, 20h / push ax
#  far_pushcs: push cs / mov ax, 28h / push ax
#  far_caller: call far B:10h, B:10h calls word ptr [bp+6], arg mov ax,20h / push ax
# Negatives (the target stays data):
#  far_badseg:  the segment is a plain (non-relocated) immediate
#  far_written: the callee overwrites the segment word [bp+6] first
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_far_callbacks (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-fcb-XXXXXX")"
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
# A (0x00-0x3F, entry, frame 0), B (0x40-0x7F, para 4), DGROUP 0x80 (para 8).
# A:30h near callee: push bp / mov bp,sp / [extra] / call dword ptr [bp+4] / pop bp / ret
# Targets: A:28h `mov cx,7 / ret`, B:20h `mov ax,5 / retf`.
def build(name, args, seg_reloc_at=None, extra=b'', far_caller=False):
    a = bytearray(0x40); b = bytearray(0x40); d = bytearray(0x20)
    a[0:5] = b'\xba\x08\x00\x8e\xda'
    relocs = [1]
    p = 5 + len(args)
    a[5:p] = args
    if seg_reloc_at is not None:
        relocs.append(5 + seg_reloc_at)
    if far_caller:
        a[p:p+5] = b'\x9a\x10\x00\x04\x00'; relocs.append(p + 3); p += 5
    else:
        rel = 0x30 - (p + 3)
        a[p:p+3] = b'\xe8' + struct.pack('<h', rel); p += 3
    a[p:p+3] = b'\x83\xc4\x04'; p += 3
    a[p:p+5] = b'\xb8\x00\x4c\xcd\x21'; p += 5
    assert p <= 0x28, name
    a[0x28:0x2C] = b'\xb9\x07\x00\xc3'
    cal = b'\x55\x8b\xec' + extra + b'\xff\x5e\x04' + b'\x5d\xc3'
    a[0x30:0x30+len(cal)] = cal
    b[0x10:0x18] = b'\x55\x8b\xec\xff\x56\x06\x5d\xcb'   # far callee, near slot [bp+6]
    b[0x20:0x24] = b'\xb8\x05\x00\xcb'
    mz(name, bytes(a) + bytes(b) + bytes(d), relocs)
seg_off = b'\xb8\x04\x00\x50' + b'\xb8\x20\x00\x50'      # mov ax,4 / push ax / mov ax,20h / push ax
build('far_imm.exe', seg_off, 1)
build('far_badseg.exe', seg_off, None)
build('far_written.exe', seg_off, 1, b'\xc7\x46\x06\x04\x00')
build('far_pushcs.exe', b'\x0e' + b'\xb8\x28\x00\x50')
build('far_caller.exe', b'\xb8\x20\x00\x50', None, b'', True)
PY
for f in far_imm far_badseg far_written far_pushcs far_caller; do
  (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o $f.asm $f.exe >/dev/null 2>&1) || true
  check ${f}_verified grep -q '^; VERIFIED identical' "$TD/$f.asm"
done
B20='^    mov ax, 5h	; 00060: B8 05 00'
A28='^    mov cx, 7h	; 00028: B9 07 00'
check far_imm_seeded grep -qE "$B20" "$TD/far_imm.asm"
check far_pushcs_seeded grep -qE "$A28" "$TD/far_pushcs.asm"
check far_caller_seeded grep -qE "$B20" "$TD/far_caller.asm"
check far_badseg_data bash -c "! grep -qE '$B20' '$TD/far_badseg.asm'"
check far_written_data bash -c "! grep -qE '$B20' '$TD/far_written.asm'"
echo "far_callbacks passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
