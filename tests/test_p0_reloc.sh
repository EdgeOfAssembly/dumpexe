#!/usr/bin/env bash
# P0 relocation contracts: Q7 pinned far 9A/EA and Q8 relocated mov r16.
# M1 (non-relocated far transfer vs file CS) stays. These checks do not skip.
# Synthetic MZ fixtures only. No --simulate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
[[ -x /usr/bin/uasm ]] || { echo "FAIL: /usr/bin/uasm not found"; exit 1; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p0-reloc-XXXXXX")"
trap 'rm -rf "$TD"' EXIT

pass=0
fail=0
check() {
  local name=$1
  shift
  if "$@"; then
    echo "PASS $name"
    pass=$((pass + 1))
  else
    echo "FAIL $name"
    fail=$((fail + 1))
  fi
}

python3 - "$TD" << 'PY'
import struct, sys
from pathlib import Path
td = Path(sys.argv[1])

def build_mz(image, crlc=0, paras=2, sp=0x200, ip=0, cs=0, lfarlc=0x1C, reloc=None):
    header_bytes = paras * 16
    total = header_bytes + len(image)
    final_len = total % 512
    num_blocks = (total + 511) // 512
    if total % 512 == 0:
        final_len = 0
    hdr = bytearray(header_bytes)
    struct.pack_into("<14H", hdr, 0,
                     0x5A4D, final_len, num_blocks, crlc, paras,
                     0, 0xFFFF, 0, sp, 0, ip, cs & 0xFFFF, lfarlc, 0)
    if reloc is not None:
        off, seg = reloc
        struct.pack_into("<HH", hdr, lfarlc, off & 0xFFFF, seg & 0xFFFF)
    return bytes(hdr) + bytes(image)

def save(name, image, **kw):
    blob = build_mz(image, **kw)
    (td / f"{name}.exe").write_bytes(blob)
    (td / f"{name}.img").write_bytes(bytes(image))

# M1 still follows lcall 0:0006 when the segment word is not relocated.
save("m1_still", bytes([0x9A, 0x06, 0x00, 0x00, 0x00, 0xC3, 0xC3]), ip=0, cs=0)
save("m1_cross", bytes([0x9A, 0x06, 0x00, 0x34, 0x12, 0xC3, 0xC3]), ip=0, cs=0)

lcall = bytearray(0x23)
lcall[0:5] = bytes([0x9A, 0x00, 0x00, 0x02, 0x00])
lcall[0x20:0x23] = bytes([0xB0, 0x42, 0xC3])
save("reloc_lcall", lcall, crlc=1, ip=0, cs=0, reloc=(3, 0))
save("reloc_lcall_noreloc", lcall, crlc=0, ip=0, cs=0)

ljmp = bytearray(0x22)
ljmp[0:5] = bytes([0xEA, 0x00, 0x00, 0x02, 0x00])
ljmp[0x20:0x22] = bytes([0xB0, 0x42])
save("reloc_ljmp", ljmp, crlc=1, ip=0, cs=0, reloc=(3, 0))

beats = bytearray(0x1336)
beats[0x100:0x105] = bytes([0x9A, 0x34, 0x12, 0x10, 0x00])
beats[0x1234:0x1236] = bytes([0xB0, 0x99])
beats[0x1334:0x1336] = bytes([0xB0, 0x42])
save("reloc_beats_cs", beats, crlc=1, ip=0, cs=0x10, reloc=(0x103, 0))

save("reloc_outside", bytes([0x9A, 0x00, 0x00, 0x50, 0x00, 0xC3]),
     crlc=1, ip=0, cs=0, reloc=(3, 0))

past = bytearray(32)
past[0:5] = bytes([0x9A, 0x00, 0x00, 0x00, 0x10])
save("reloc_past64", past, crlc=1, ip=0, cs=0, reloc=(3, 0))

mis = bytearray(0x23)
mis[0:5] = bytes([0x9A, 0x00, 0x00, 0x02, 0x00])
mis[0x20:0x23] = bytes([0xB0, 0x42, 0xC3])
save("reloc_misaligned", mis, crlc=1, ip=0, cs=0, reloc=(0, 0))

bx = bytearray(0x23)
bx[0:4] = bytes([0xBB, 0x02, 0x00, 0xC3])
bx[0x20:0x23] = bytes([0xB0, 0x42, 0xC3])
save("uasm_bx", bx, crlc=1, ip=0, cs=0, reloc=(1, 0))

save("uasm_outside", bytes([0xB8, 0x00, 0x01, 0xC3]),
     crlc=1, ip=0, cs=0, reloc=(1, 0))
save("uasm_plain", bytes([0xB8, 0x02, 0x00, 0xC3]), ip=0, cs=0)

interior = bytearray(0x12)
interior[0:3] = bytes([0xB8, 0x01, 0x00])
for i in range(0x03, 0x0E):
    interior[i] = 0x90
interior[0x0E:0x12] = bytes([0xB8, 0x00, 0x4C, 0xC3])
save("uasm_interior", interior, crlc=1, ip=0, cs=0, reloc=(1, 0))
print("fixtures", td)
PY

json_edges() {
  local name=$1
  "$BIN" --json "$TD/$name.exe" >"$TD/$name.json" 2>"$TD/$name.err" || {
    echo "dumpexe --json failed for $name" >&2
    cat "$TD/$name.err" >&2
    return 1
  }
}

edge_to() {
  local name=$1 to=$2 kind=$3
  python3 - "$TD/$name.json" "$to" "$kind" << 'PY'
import json, sys
path, to, kind = sys.argv[1:]
d = json.load(open(path))
edges = d["cfg"]["edges"]
hit = [e for e in edges if e.get("to") == to and e.get("kind") == kind]
if not hit:
    sys.exit(f"no edge to {to} kind {kind}: {edges}")
print("edge", hit[0])
PY
}

no_edge_to() {
  local name=$1 to=$2
  python3 - "$TD/$name.json" "$to" << 'PY'
import json, sys
path, to = sys.argv[1:]
d = json.load(open(path))
edges = d["cfg"]["edges"]
hit = [e for e in edges if e.get("to") == to]
if hit:
    sys.exit(f"unexpected edge to {to}: {hit}")
print("no edge", to)
PY
}

case_m1_still() {
  json_edges m1_still || return 1
  edge_to m1_still 0006 call
}

case_m1_cross() {
  json_edges m1_cross || return 1
  no_edge_to m1_cross 0006
}

case_reloc_lcall() {
  json_edges reloc_lcall || return 1
  edge_to reloc_lcall 0020 call || return 1
  json_edges reloc_lcall_noreloc || return 1
  no_edge_to reloc_lcall_noreloc 0020
}

case_reloc_ljmp() {
  json_edges reloc_ljmp || return 1
  # CfgEdgeKind::Jump is serialized as "jmp".
  edge_to reloc_ljmp 0020 jmp
}

case_reloc_beats_cs() {
  json_edges reloc_beats_cs || return 1
  edge_to reloc_beats_cs 1334 call || return 1
  no_edge_to reloc_beats_cs 1234
}

case_reloc_outside() {
  json_edges reloc_outside || return 1
  no_edge_to reloc_outside 0500
}

case_reloc_past64() {
  json_edges reloc_past64 || return 1
  python3 - "$TD/reloc_past64.json" << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
edges = d["cfg"]["edges"]
hit = [e for e in edges if e.get("kind") in ("call", "jmp") and e.get("has_target")]
if hit:
    sys.exit("past-64k far transfer became an in-image target: " + str(edges))
print("past64 ok", edges)
PY
}

case_reloc_misaligned() {
  json_edges reloc_misaligned || return 1
  no_edge_to reloc_misaligned 0020
}

uasm_emit() {
  local name=$1
  "$BIN" --uasm -o "$TD/$name.asm" "$TD/$name.exe" >"$TD/$name.out" 2>"$TD/$name.err" || {
    echo "dumpexe --uasm failed for $name" >&2
    cat "$TD/$name.err" >&2
    return 1
  }
}

uasm_bin_eq() {
  local name=$1
  # uasm writes <basename>.err in cwd. Stay in the temp dir.
  (
    cd "$TD" || exit 1
    /usr/bin/uasm -bin -nologo -Fo "$name.bin" "$name.asm" \
      >"$name.uasm" 2>"$name.uasmerr"
  ) || {
    echo "uasm -bin failed for $name" >&2
    cat "$TD/$name.uasmerr" >&2
    cat "$TD/$name.asm" >&2
    return 1
  }
  cmp -s "$TD/$name.bin" "$TD/$name.img" || {
    echo "uasm -bin mismatch for $name" >&2
    echo "asm:" >&2
    cat "$TD/$name.asm" >&2
    return 1
  }
}

case_uasm_bx() {
  uasm_emit uasm_bx || return 1
  local asm="$TD/uasm_bx.asm"
  grep -F -q 'mov bx, (dxfrm_0020 - dximg0) SHR 4' "$asm" || {
    echo "missing Q8 mov line" >&2
    cat "$asm" >&2
    return 1
  }
  grep -q '^dximg0:$' "$asm" || { echo "missing dximg0"; cat "$asm" >&2; return 1; }
  grep -q '^dxfrm_0020:$' "$asm" || { echo "missing dxfrm_0020"; cat "$asm" >&2; return 1; }
  uasm_bin_eq uasm_bx || return 1
  (
    cd "$TD" || exit 1
    /usr/bin/uasm -mz -nologo -Fo "uasm_bx.built.exe" "uasm_bx.asm" \
      >"uasm_bx.mzout" 2>"uasm_bx.mzerr"
  ) || {
    echo "uasm -mz failed" >&2
    cat "$TD/uasm_bx.mzerr" >&2
    cat "$asm" >&2
    return 1
  }
  python3 - "$TD/uasm_bx.built.exe" "$TD/uasm_bx.pay" << 'PY'
import struct, sys
p = open(sys.argv[1], "rb").read()
cpar = struct.unpack_from("<H", p, 8)[0]
open(sys.argv[2], "wb").write(p[cpar * 16:])
print(f"e_cparhdr={cpar} payload={len(p) - cpar * 16}")
PY
  cmp -s "$TD/uasm_bx.pay" "$TD/uasm_bx.img" || {
    echo "uasm -mz payload mismatch" >&2
    return 1
  }
}

no_q8() {
  local name=$1
  if grep -q 'dxfrm_' "$TD/$name.asm"; then
    echo "unexpected dxfrm_ in $name" >&2
    cat "$TD/$name.asm" >&2
    return 1
  fi
  if grep -q ' SHR ' "$TD/$name.asm"; then
    echo "unexpected SHR in $name" >&2
    cat "$TD/$name.asm" >&2
    return 1
  fi
}

case_uasm_outside() {
  uasm_emit uasm_outside || return 1
  no_q8 uasm_outside || return 1
  uasm_bin_eq uasm_outside
}

case_uasm_plain() {
  uasm_emit uasm_plain || return 1
  no_q8 uasm_plain || return 1
  uasm_bin_eq uasm_plain
}

case_uasm_interior() {
  uasm_emit uasm_interior || return 1
  no_q8 uasm_interior || return 1
  uasm_bin_eq uasm_interior
}

check m1_still case_m1_still
check m1_cross case_m1_cross
check reloc_lcall case_reloc_lcall
check reloc_ljmp case_reloc_ljmp
check reloc_beats_cs case_reloc_beats_cs
check reloc_outside case_reloc_outside
check reloc_past64 case_reloc_past64
check reloc_misaligned case_reloc_misaligned
check uasm_bx case_uasm_bx
check uasm_outside case_uasm_outside
check uasm_plain case_uasm_plain
check uasm_interior case_uasm_interior

echo "reloc tests: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
