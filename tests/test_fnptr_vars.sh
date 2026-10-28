#!/usr/bin/env bash
# Function-pointer variables (stores into cells) and far code-pointer tables.
#  far_store:  mov [X],off / mov [X+2],seg (relocated) / call dword ptr [X]
#  far_init:   call dword ptr [X], the DGROUP image holds a relocated far ptr
#  near_reg:   mov ax,imm / mov [X],ax / jmp word ptr [X]
#  vtable:     a run of relocated far pointers in data, one already decoded
# Negatives (target bytes stay data):
#  vt_noanchor: the same run with no entry at decoded code
#  far_badseg:  the segment store is a plain (non-relocated) immediate
#  near_zero:   as near_init, but the image word names 30h (zero bytes)
#  near_dgroup: as near_init, but the word names 90h, code-like bytes in DGROUP
#  near_init:   call word ptr [X]; only the image word (no store) names 28h,
#               and 28h decodes as a clean run to ret (RTL exit/matherr hooks)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_fnptr_vars (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-fnv-XXXXXX")"
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
# Layout: A (0x00-0x3F, entry, frame 0), B (0x40-0x7F, frame 0x40, para 4),
# DGROUP at 0x80 (para 8). B is reached by a relocated far call from A.
# Targets: A:28h `mov cx,7 / ret`, B:20h `mov ax,5 / retf`, B:30h `mov dx,9 / retf`.
def base():
    a = bytearray(0x40); b = bytearray(0x40); d = bytearray(0x20)
    a[0:5] = b'\xba\x08\x00\x8e\xda'                  # mov dx, DGROUP; mov ds, dx
    relocs = [1]
    a[0x28:0x2C] = b'\xb9\x07\x00\xc3'
    b[0x00:0x05] = b'\xb8\x01\x00\xcb\x90'            # B:0 mov ax,1 / retf (decoded via far call)
    b[0x20:0x24] = b'\xb8\x05\x00\xcb'
    b[0x30:0x34] = b'\xba\x09\x00\xcb'
    return a, b, d, relocs
def tail(a, at):
    a[at:at+5] = b'\xb8\x00\x4c\xcd\x21'
def far_store(badseg=False):
    a, b, d, relocs = base()
    code = b'\xc7\x06\x00\x00\x20\x00' + b'\xc7\x06\x02\x00\x04\x00' + b'\xff\x1e\x00\x00' + b'\x9a\x00\x00\x04\x00'
    a[5:5+len(code)] = code
    if not badseg:
        relocs.append(5 + 6 + 4)
    relocs.append(5 + 16 + 3)
    tail(a, 5 + len(code))
    return a, b, d, relocs
def emit(name, parts):
    a, b, d, relocs = parts
    mz(name, bytes(a) + bytes(b) + bytes(d), relocs)
emit('far_store.exe', far_store())
emit('far_badseg.exe', far_store(True))
# far_init: DGROUP:4 = B:20h (segment word relocated).
a, b, d, relocs = base()
code = b'\xff\x1e\x04\x00' + b'\x9a\x00\x00\x04\x00'
a[5:5+len(code)] = code; relocs.append(5 + 4 + 3); tail(a, 5 + len(code))
d[4:8] = b'\x20\x00\x04\x00'; relocs.append(0x80 + 6)
emit('far_init.exe', (a, b, d, relocs))
# near_init: DGROUP:6 = 28h, call word ptr [6] in A.
a, b, d, relocs = base()
code = b'\xff\x16\x06\x00'
a[5:5+len(code)] = code; tail(a, 5 + len(code))
d[6:8] = b'\x28\x00'
emit('near_init.exe', (a, b, d, relocs))
d = bytearray(d); d[6:8] = b'\x30\x00'
emit('near_zero.exe', (a, b, d, relocs))
d = bytearray(d); d[6:8] = b'\x90\x00'; d[0x10:0x14] = b'\xb9\x07\x00\xc3'
emit('near_dgroup.exe', (a, b, d, relocs))
# near_reg: mov ax,28h / mov [8],ax / call word ptr [8].
a, b, d, relocs = base()
code = b'\xb8\x28\x00' + b'\xa3\x08\x00' + b'\xff\x16\x08\x00'
a[5:5+len(code)] = code; tail(a, 5 + len(code))
emit('near_reg.exe', (a, b, d, relocs))
# vtable: DGROUP:10h = {B:0 (decoded), B:20h, B:30h}, all segments relocated.
def vt(anchor):
    a, b, d, relocs = base()
    code = b'\x9a\x00\x00\x04\x00' if anchor else b'\x90\x90\x90\x90\x90'
    a[5:10] = code
    if anchor:
        relocs.append(8)
    tail(a, 10)
    first = b'\x00\x00\x04\x00' if anchor else b'\x10\x00\x04\x00'
    d[0x10:0x1C] = first + b'\x20\x00\x04\x00' + b'\x30\x00\x04\x00'
    relocs += [0x80 + 0x12, 0x80 + 0x16, 0x80 + 0x1A]
    return a, b, d, relocs
emit('vtable.exe', vt(True))
emit('vt_noanchor.exe', vt(False))
PY
for f in far_store far_badseg far_init near_init near_zero near_dgroup near_reg vtable vt_noanchor; do
  (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o $f.asm $f.exe >/dev/null 2>&1) || true
  check ${f}_verified grep -q '^; VERIFIED identical' "$TD/$f.asm"
done
B20='^    mov ax, 5h	; 00060: B8 05 00'
B30='^    mov dx, 9h	; 00070: BA 09 00'
A28='^    mov cx, 7h	; 00028: B9 07 00'
check far_store_seeded grep -qE "$B20" "$TD/far_store.asm"
check far_badseg_data bash -c "! grep -qE '$B20' '$TD/far_badseg.asm'"
check far_init_seeded grep -qE "$B20" "$TD/far_init.asm"
check near_init_seeded grep -qE "$A28" "$TD/near_init.asm"
check near_zero_data bash -c "! grep -vE '^    d[bwd] ' '$TD/near_zero.asm' | grep -qE '; 0003[0-9A-F]:'"
check near_dgroup_data bash -c "! grep -qE '^    mov cx, 7h	; 00090' '$TD/near_dgroup.asm'"
check near_reg_seeded grep -qE "$A28" "$TD/near_reg.asm"
check vtable_b20 grep -qE "$B20" "$TD/vtable.asm"
check vtable_b30 grep -qE "$B30" "$TD/vtable.asm"
check vt_noanchor_data bash -c "! grep -qE '$B20|$B30' '$TD/vt_noanchor.asm'"
echo "fnptr_vars passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
