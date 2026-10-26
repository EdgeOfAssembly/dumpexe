#!/usr/bin/env bash
# Segment layout: a BC++ 3.1-compatible startup (relocated mov dx, DGROUP)
# makes DGROUP..end data in the verified listing; the C-string scan looks
# there (and at far data named by mov ax, seg X / mov ds, ax), not in code.
# Missing assembler: exit 77 (skip).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_segment_layout (no uasm; set UASM=/path/to/uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-seg-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
python3 - "$TD" <<'PY'
import struct, sys, os
td = sys.argv[1]
def mz(name, img, relocs):
    img = img + bytes(-len(img) % 16)
    hl = 0x200
    n = hl + len(img)
    h = struct.pack('<13H', 0x5A4D, n % 512, (n + 511) // 512, len(relocs), hl // 16, 0, 0xFFFF,
                    len(img) // 16, 0x80, 0, 0, 0, 0x3E) + b'\0\0\x01\0\xfb\x50'
    h += bytes(0x3E - len(h))
    for r in relocs:
        h += struct.pack('<HH', r, 0)
    open(os.path.join(td, name), 'wb').write(h + bytes(hl - len(h)) + img)
def build(name, off, far=False, code_in_dg=False):
    # c0: mov dx, DGROUP; mov cs:[DGROUP@], dx; mov ah, 30h; int 21h; ...
    code = bytearray(b'\xba\0\0\x2e\x89\x16' + struct.pack('<H', off) + b'\xb4\x30\xcd\x21')
    relocs = [1]
    if far:
        relocs.append(len(code) + 1)
        code += b'\xb8\0\0\x8e\xd8'            # mov ax, seg FAR; mov ds, ax
    if code_in_dg:
        code += b'\xe9\0\0'                    # jmp into DGROUP (fixed below)
        jmp_at = len(code) - 3
    code += b'\xb4\x4c\xcd\x21'
    # Code-looking printable junk with a NUL after it, in the code segment.
    code += b'\xebAbcdQRST\0'
    code += bytes(-len(code) % 16)
    farseg = b''
    if far:
        farseg = b'Far string data\0' + bytes(16)
    base = len(code) + len(farseg)
    if far:
        code[relocs[1]:relocs[1] + 2] = struct.pack('<H', len(code) // 16)
    code[1:3] = struct.pack('<H', base // 16)
    data = b'\0\0Hello, DGROUP\0' + b'value=%d\n\0' + bytes(32)
    if code_in_dg:
        rel = base + 2 - (jmp_at + 3)
        code[jmp_at + 1:jmp_at + 3] = struct.pack('<H', rel & 0xFFFF)
        data = b'\0\0\xb4\x4c\xcd\x21' + data[6:]
    mz(name, bytes(code) + farseg + data + b'Borland C++ - Copyright 1991 Borland Intl.\0', relocs)
build('small.exe', 0x2BE)
build('large.exe', 0x291)
build('huge.exe', 0x284, far=True)
build('other.exe', 0x2BF)                  # not a BC 3.1 model operand
build('conflict.exe', 0x2BE, code_in_dg=True)
PY
v() { (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o "$1.asm" "$1.exe" >/dev/null 2>&1) || true; }
for f in small large huge other conflict; do v $f; done
for f in small large huge other conflict; do check "${f}_verified" grep -q '^; VERIFIED identical' "$TD/$f.asm"; done
check small_layout grep -qE '^; segment layout: DGROUP at [0-9A-F]{5} .*small model' "$TD/small.asm"
check large_layout grep -qE '^; segment layout: DGROUP at [0-9A-F]{5} .*large model' "$TD/large.asm"
check huge_far grep -qE '^; segment layout: DGROUP .*huge model.*; far data [0-9A-F]{5}-[0-9A-F]{5} below it' "$TD/huge.asm"
check small_dgroup_str grep -qF "db 'Hello, DGROUP', 0h" "$TD/small.asm"
check small_no_code_junk bash -c "! grep -qF \"'AbcdQRST'\" '$TD/small.asm'"
check other_junk_kept grep -qF "'AbcdQRST', 0h" "$TD/other.asm"
check other_no_layout bash -c "! grep -q 'segment layout' '$TD/other.asm'"
check huge_far_str grep -qF "db 'Far string data', 0h" "$TD/huge.asm"
check huge_dgroup_str grep -qF "db 'Hello, DGROUP', 0h" "$TD/huge.asm"
check conflict_not_applied grep -qE '^; segment layout: not applied \([0-9]+ decoded instruction' "$TD/conflict.asm"
check conflict_code_kept grep -qE 'mov ah, 4Ch.*; [0-9A-F]{5}: B4 4C' "$TD/conflict.asm"
check small_relocs grep -qF '; relocations: 1 of 1 segment words symbolic' "$TD/small.asm"
# L1 (verify-34420d6): layout ranges are not user hints.
for f in small large huge; do check "${f}_no_hints_line" bash -c "! grep -q '^; hints:' '$TD/$f.asm'"; done
printf 'data 10 2\n' > "$TD/h.txt"
(cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" --hints=h.txt -o smallh.asm small.exe >/dev/null 2>&1) || true
check hints_user_count grep -qF '; hints: 0 code, 1 data range(s), 0 label name(s) from h.txt' "$TD/smallh.asm"
check hints_layout_still grep -qE '^; segment layout: DGROUP at' "$TD/smallh.asm"
echo "segment_layout passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
