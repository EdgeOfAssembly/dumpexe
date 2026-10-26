#!/usr/bin/env bash
# Adversarial inputs for the callback-argument rule (from the ac1ffcc review):
# pos_* seed the callback, neg_* (slot written through any [bp+..] form, BP
# rebased or handed to a nested routine, frameless helper writing the slot,
# lea of the slot, relocated imm, SP change or pop in the push run, branch
# into the run, far call, call dword, enter, unresolved indirect jump) and
# edge_* (NULL, target already code, target in DGROUP) do not; crash_* (a
# call past the end of the image in the callee) must not crash. All verify.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_callback_adv (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-cbadv-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
python3 - "$TD" <<'PY'
import struct, sys, os
td = sys.argv[1]
def mz(name, img, relocs):
    img = bytes(img) + bytes(-len(img) % 16); hl = 0x40; n = hl + len(img)
    h = struct.pack('<14H', 0x5A4D, n % 512, (n + 511) // 512, len(relocs), hl // 16, 0, 0xFFFF,
                    len(img) // 16, 0x80, 0, 0, 0, 0x1C, 0)
    for r in relocs: h += struct.pack('<HH', r, 0)
    open(os.path.join(td, name), 'wb').write(h + bytes(hl - len(h)) + img)
def rel16(at, size, tgt): return struct.pack('<H', (tgt - (at + size)) & 0xFFFF)
def build(name, pre, callee, helper=b'', relocs_extra=(), tail=b'', far=False, cbimm=0x50, size=0x80):
    img = bytearray(size)
    c = bytearray(b'\xba\x07\x00\x8e\xda') + pre       # mov dx,DGROUP ; mov ds,dx ; <pushes>
    at = len(c)
    if far:  # call far 0000:0020 (relocated)
        c += b'\x9a\x20\x00\x00\x00'; relocs_extra = tuple(relocs_extra) + (at + 3,)
    else:
        c += b'\xe8' + rel16(at, 3, 0x20)
    c += tail + b'\xb8\x00\x4c\xcd\x21'
    c = bytes(c).replace(b'CB', struct.pack('<H', cbimm))
    img[0:len(c)] = c
    img[0x20:0x20 + len(callee)] = callee
    img[0x50:0x54] = b'\xb9\x07\x00\xc3'
    img[0x58:0x58 + len(helper)] = helper
    mz(name, img, [1] + list(relocs_extra))
P = b'\xb8CB\x50\xb8\x05\x00\x50'            # mov ax,CB ; push ax ; mov ax,5 ; push ax  (CB in slot 1 -> [bp+6])
OK = b'\x55\x8b\xec\xff\x76\x04\xff\x56\x06\x59\x5d\xc3'      # push [bp+4]; call [bp+6]; pop cx; pop bp; ret
def callee(mid): return b'\x55\x8b\xec' + mid + b'\xff\x56\x06\x5d\xc3'
build('pos_ok.exe', P, OK)
build('pos_push_imm.exe', b'\x68CB\x6a\x05', OK)                                    # push CB (68) ; push 5 (6A)
build('neg_write_disp16.exe', P, callee(b'\x89\x86\x06\x00'))                       # mov [bp+0006],ax (mod=10)
build('neg_write_ss_prefix.exe', P, callee(b'\x36\x89\x46\x06'))                    # mov ss:[bp+6],ax
build('neg_write_indexed.exe', P, callee(b'\x33\xff\x89\x43\x06'))                  # xor di,di ; mov [bp+di+6],ax
build('neg_write_via_si.exe', P, callee(b'\x8b\xf5\xc7\x44\x06\x00\x00'))            # mov si,bp ; mov word [si+6],0
build('neg_pop_bp_rebase.exe', P, callee(b'\x56\x5d'))                              # push si ; pop bp  (BP := SI)
build('neg_write_static_link.exe', P, callee(b'\x55\xe8' + rel16(0x24, 3, 0x58) + b'\x59'),
      helper=b'\x55\x8b\xec\x8b\x5e\x04\xc7\x47\x06\x00\x00\x5d\xc3')                # G(bp): [parent_bp+6] := 0
build('neg_write_helper.exe', P, callee(b'\xe8' + rel16(0x23, 3, 0x58)), helper=b'\x89\x46\x06\xc3')  # frameless helper writes slot
build('neg_lea_slot.exe', P, callee(b'\x8d\x76\x06\x89\x04'))                       # lea si,[bp+6]; mov [si],ax
build('neg_reloc_imm.exe', P, OK, relocs_extra=(6,))                                # imm of mov ax,CB relocated
build('neg_add_sp_in_run.exe', b'\xb8CB\x50\x83\xc4\x00\xb8\x05\x00\x50', OK)       # add sp,0 between the pushes
build('neg_pop_in_run.exe', b'\xb8CB\x50\x59\x51\xb8\x05\x00\x50', OK)             # pop cx; push cx in the run
build('neg_branch_into_run.exe', b'\xb8CB\x50\xb8\x05\x00\x50', OK, tail=b'\xe3' + bytes([(0x09 - (0x10 + 2)) & 0xFF]))  # jcxz back to 'mov ax,5'
build('neg_far_call.exe', P, OK, far=True)                                          # caller uses call far
build('neg_far_slot_call.exe', P, callee(b'') .replace(b'\xff\x56\x06', b'\xff\x5e\x06'))  # call dword ptr [bp+6]
build('neg_enter.exe', P, b'\xc8\x00\x00\x00\xff\x56\x06\xc9\xc3')                  # enter 0,0 ; call [bp+6]; leave; ret
build('neg_indirect_jmp.exe', P, callee(b'\x8b\xd8\xff\xe3'))                        # jmp bx inside body (before the call)
build('pos_push_cs_near_far.exe', b'\xb8CB\x50\x0e', b'\x55\x8b\xec\xff\x56\x06\x5d\xcb')  # push cs; call near F; F retf, calls [bp+6]
build('edge_target_decoded.exe', P, OK, tail=b'\xe8' + rel16(0x10, 3, 0x50))        # CB also called directly -> symbolic only
build('edge_target_dgroup.exe', P, OK, cbimm=0x74, size=0x80)                      # CB points into DGROUP (70h..)
build('edge_target_midinsn.exe', P, OK, cbimm=0x51)                                 # CB points inside the CB instruction
build('edge_null_cb.exe', P, OK, cbimm=0x0000)                                      # NULL callback
# OOB: callee body contains E8 whose target is past the end of the image (frame 0, < 64K).
build('crash_e8_past_image.exe', P, callee(b'\xe8' + rel16(0x23, 3, 0x0090)))
build('crash_e8_far_past_image.exe', P, callee(b'\xe8' + rel16(0x23, 3, 0xF000)))
PY
for e in "$TD"/*.exe; do
  n=$(basename "$e" .exe)
  rc=0; (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o "$n.asm" "$n.exe" >/dev/null 2>"$n.err") || rc=$?
  check "${n}_rc0" test "$rc" -eq 0
  check "${n}_no_sanitizer" bash -c "! grep -qE 'AddressSanitizer|runtime error:' '$TD/$n.err'"
  check "${n}_verified" grep -q '^; VERIFIED identical' "$TD/$n.asm"
  case $n in
    pos_*) check "${n}_seeded" grep -q '^; callback arguments: 1 ' "$TD/$n.asm" ;;
    edge_target_midinsn) ;;  # an undecoded byte in the code segment: seeded per rule
    *) check "${n}_not_seeded" bash -c "! grep -q '^; callback arguments:' '$TD/$n.asm'" ;;
  esac
done
check null_not_symbolic bash -c "! grep -qE '^    mov ax, \(L00000 - L00000\)' '$TD/edge_null_cb.asm'"
echo "callback_adv passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
