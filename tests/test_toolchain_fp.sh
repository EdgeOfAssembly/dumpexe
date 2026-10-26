#!/usr/bin/env bash
# Toolchain fingerprints on hand-made files: BC++ 3.1 memory model from the
# c0 DGROUP@ store, TLINK /v debug trailer, TP 7.0 main-block stack check,
# Turbo Pascal and linker objects in --json, packed-file linker caveat.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-tcfp-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
python3 - "$TD" <<'PY'
import struct, sys, os
td = sys.argv[1]
BANNER = b'Borland C++ - Copyright 1991 Borland Intl.\0'
def mz(name, img, extra=b'\0\0\x01\0\xfb\x50', lfarlc=0x3E, ip=0, sp=0x80, tail=b''):
    img = img + bytes(-len(img) % 16)
    hl = 0x200 if lfarlc == 0x3E or lfarlc == 0x1E else 0x40
    n = hl + len(img)
    h = struct.pack('<13H', 0x5A4D, n % 512, (n + 511) // 512, 0, hl // 16, 0, 0xFFFF,
                    len(img) // 16, sp, 0, ip, 0, lfarlc) + extra
    open(os.path.join(td, name), 'wb').write(h + bytes(hl - len(h)) + img + tail)
def c0(off, head=b'\xba\x00\x00'):
    return head + b'\x2e\x89\x16' + struct.pack('<H', off) + b'\xb4\x30\xcd\x21\xb4\x4c\xcd\x21' + bytes(64) + BANNER
for m, off in [('small', 0x2BE), ('medium', 0x2C4), ('compact', 0x28B), ('large', 0x291), ('huge', 0x284)]:
    mz(f'bc_{m}.exe', c0(off))
mz('bc_wrong.exe', c0(0x2BF))
mz('bc_nob430.exe', c0(0x2BE).replace(b'\xb4\x30', b'\xb4\x31', 1))
mz('bc_tinyoff.exe', c0(0x396))                      # tiny offset without 8C CA: nothing
mz('bc_dbg.exe', c0(0x2BE), tail=b'\xfb\x52' + bytes(30))
mz('bc_dbg71.exe', c0(0x2BE), extra=b'\0\0\x01\0\xfb\x71', tail=b'\xfb\x52' + bytes(30))
mz('bc_trail_other.exe', c0(0x2BE), tail=b'\x52\xfb' + bytes(30))
open(os.path.join(td, 'bc_tiny.com'), 'wb').write(c0(0x396, head=b'\x8c\xca'))
open(os.path.join(td, 'bc_tiny_bad.com'), 'wb').write(c0(0x2BE, head=b'\x8c\xca'))
# Turbo Pascal: unit-init far calls, main block, RTL text.
def tp(name, main, year):
    img = b'\x9a\0\0\0\0' * 4 + main + b'\xb4\x4c\xcd\x21' + bytes(300)
    img += b'\0Runtime error \0 at \0' + (b'Portions Copyright (c) 1983,92 Borland\0' if year else b'')
    mz(name, img, extra=b'', lfarlc=0x1C)
tp('tp7.exe', b'\x55\x89\xe5\x31\xc0\x9a\0\0\0\0', True)
tp('tp7_mov.exe', b'\x55\x89\xe5\xb8\x00\x01\x9a\0\0\0\0', True)
tp('tp7_s.exe', b'\x55\x89\xe5\xc7\x06\x52\x00', True)       # $S-: no stack check
tp('tp55.exe', b'\x55\x89\xe5\xbf\x3e\x01', False)
# EXEPACK-shaped file with a TLINK header: the label is marked packed.
img = bytearray(400); img[14:16] = b'RB'; img[16 + 220:16 + 227] = bytes([0xCD, 0x21, 0xB8, 0xFF, 0x4C, 0xCD, 0x21])
mz('packed.exe', bytes(img), ip=16, sp=0x80)
PY
txt() { "$BIN" -a --no-asm-file --no-repack "$TD/$1" 2>&1 || true; }
js() { "$BIN" --json "$TD/$1" 2>/dev/null || true; }
model() { txt "$1" | sed -n 's/^Memory model: //p'; }
for m in small medium compact large huge; do
  check "model_$m" test "$(model bc_$m.exe)" = "$m (Borland C++ 3.1-compatible startup)"
done
check model_tiny_com test "$(model bc_tiny.com)" = "tiny (Borland C++ 3.1-compatible startup)"
for f in bc_wrong.exe bc_nob430.exe bc_tinyoff.exe bc_tiny_bad.com; do check "model_none_$f" test -z "$(model $f)"; done
check model_json bash -c "'$BIN' --json '$TD/bc_large.exe' | grep -q '\"memory_model\": \"large\"'"
check model_json_absent bash -c "! '$BIN' --json '$TD/bc_wrong.exe' | grep -q memory_model"
check debug_trailer bash -c "'$BIN' -a --no-asm-file --no-repack '$TD/bc_dbg.exe' 2>&1 | grep -q '^Debug info:  Borland (bytes FB 52'"
check debug_trailer_71 bash -c "'$BIN' -a --no-asm-file --no-repack '$TD/bc_dbg71.exe' 2>&1 | grep -q '^Debug info:'"
check debug_none bash -c "! '$BIN' -a --no-asm-file --no-repack '$TD/bc_small.exe' 2>&1 | grep -q '^Debug info:'"
check debug_byteorder bash -c "! '$BIN' -a --no-asm-file --no-repack '$TD/bc_trail_other.exe' 2>&1 | grep -q '^Debug info:'"
check debug_json bash -c "'$BIN' --json '$TD/bc_dbg.exe' | grep -qE '\"debug_trailer_offset\": [1-9]'"
check tp7_stack bash -c "'$BIN' -a --no-asm-file --no-repack '$TD/tp7.exe' 2>&1 | grep -q 'stack-check far call (TP 7.0 style'"
check tp7_stack_mov bash -c "'$BIN' -a --no-asm-file --no-repack '$TD/tp7_mov.exe' 2>&1 | grep -q 'stack-check far call'"
check tp7_s_minus bash -c "! '$BIN' -a --no-asm-file --no-repack '$TD/tp7_s.exe' 2>&1 | grep -q 'stack-check far call'"
check tp55_none bash -c "! '$BIN' -a --no-asm-file --no-repack '$TD/tp55.exe' 2>&1 | grep -q 'stack-check far call'"
check tp7_json bash -c "'$BIN' --json '$TD/tp7.exe' | grep -q '\"turbo_pascal\": {\"detected\": true.*\"version\": \"7.0\".*\"main_stack_check\": true'"
check tp55_json bash -c "'$BIN' --json '$TD/tp55.exe' | grep -q '\"turbo_pascal\": {\"detected\": true.*\"version\": \"5.5\".*\"main_stack_check\": false'"
check tp_json_linker bash -c "'$BIN' --json '$TD/tp7.exe' | grep -q '\"linker\": {\"detected\": true, \"linker\": \"Turbo Pascal linker (likely)\"'"
check bc_json_no_tp bash -c "'$BIN' --json '$TD/bc_small.exe' | grep -q '\"turbo_pascal\": {\"detected\": false}'"
check bc_json_linker bash -c "'$BIN' --json '$TD/bc_small.exe' | grep -q '\"linker\": \"Borland TLINK 5.x\".*\"packed\": false'"
check tp_export_no_large_claim bash -c "! '$BIN' -a --no-repack -o - '$TD/tp7.exe' 2>/dev/null | grep -q 'TP far-call / dense frames'"
check packed_label bash -c "'$BIN' -a --no-asm-file --no-repack '$TD/packed.exe' 2>&1 | grep -q '^Linker: .*Borland TLINK 5.x (packed by Microsoft EXEPACK: header may be the packer.s; low confidence)'"
check packed_json bash -c "'$BIN' --json '$TD/packed.exe' | grep -q '\"packed\": true, \"packer\": \"Microsoft EXEPACK\"'"
echo "toolchain_fp passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
