#!/usr/bin/env bash
# P0 Q11: one annotated CFG build when a listing and a CFG view are both on.
# Output matches a separate build. These checks do not skip.
# Synthetic fixtures only. No --simulate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p0-cfg-once-XXXXXX")"
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

def build_mz(image, crlc=0, paras=2, sp=0x200, ip=0, cs=0, lfarlc=0x1C, ovno=0):
    header_bytes = paras * 16
    total = header_bytes + len(image)
    final_len = total % 512
    num_blocks = (total + 511) // 512
    if total % 512 == 0:
        final_len = 0
    hdr = bytearray(header_bytes)
    struct.pack_into("<14H", hdr, 0,
                     0x5A4D, final_len, num_blocks, crlc, paras,
                     0, 0xFFFF, 0, sp, 0, ip, cs & 0xFFFF, lfarlc, ovno)
    return bytes(hdr) + bytes(image)

# In-window near call so the edge list is not empty.
tiny = bytes([0xE8, 0x01, 0x00, 0xC3, 0xC3])
(td / "tiny.exe").write_bytes(build_mz(tiny, ip=0, cs=0))

# CS 0x1000, IP 0 is linear 0x10000, inside this 65537-byte image.
past = bytearray(65537)
past[0] = 0xC3
past[65536] = 0xC3
(td / "past.exe").write_bytes(build_mz(bytes(past), ip=0, cs=0x1000))

# delta == image size. C3 at image 0 is the linear-0 seed.
outside = bytearray(65536)
outside[0] = 0xC3
(td / "outside.exe").write_bytes(build_mz(bytes(outside), ip=0, cs=0x1000))

(td / "ret.com").write_bytes(b"\xC3")
psp = bytearray(257)
psp[256] = 0xC3
(td / "psp.com").write_bytes(psp)
print("fixtures", td)
PY

cfg_sig() {
  python3 - "$@" << 'PY'
import json, sys
sigs = []
for path in sys.argv[1:]:
    d = json.load(open(path))
    cfg = d.get("cfg")
    if cfg is None:
        sys.exit("cfg is null in " + path)
    edges = [(e["from"], e["to"], e["kind"]) for e in cfg["edges"]]
    sigs.append((cfg["blocks"], cfg["n_edges"], edges))
if any(s != sigs[0] for s in sigs[1:]):
    for path, sig in zip(sys.argv[1:], sigs):
        print(path, "blocks", sig[0], "n_edges", sig[1], "edges", sig[2], file=sys.stderr)
    sys.exit(1)
print("cfg sig", sigs[0][0], "blocks", sigs[0][1], "edges")
PY
}

case_mz_json_eq() {
  "$BIN" --json "$TD/tiny.exe" >"$TD/tiny.json" 2>"$TD/tiny.err" || return 1
  "$BIN" -d --json "$TD/tiny.exe" >"$TD/tiny_d.json" 2>"$TD/tiny_d.err" || return 1
  "$BIN" --cfg --json "$TD/tiny.exe" >"$TD/tiny_cfg.json" 2>"$TD/tiny_cfg.err" || return 1
  cfg_sig "$TD/tiny.json" "$TD/tiny_d.json" "$TD/tiny_cfg.json"
}

case_mz_uasm_json() {
  "$BIN" --json "$TD/tiny.exe" >"$TD/u_base.json" 2>"$TD/u_base.err" || return 1
  "$BIN" --uasm --json -o "$TD/tiny.asm" "$TD/tiny.exe" \
    >"$TD/u_uasm.json" 2>"$TD/u_uasm.err" || return 1
  [[ -f "$TD/tiny.asm" ]] || { echo "asm file missing" >&2; return 1; }
  cfg_sig "$TD/u_base.json" "$TD/u_uasm.json"
}

case_mz_past_window() {
  "$BIN" --uasm -o "$TD/past.asm" "$TD/past.exe" \
    >"$TD/past_u.out" 2>"$TD/past_u.err" || return 1
  if grep -F -q 'entry is past the 64 KiB decode window' "$TD/past.asm"; then
    echo "in-image entry printed the past-window note" >&2
    return 1
  fi
  if grep -F -q 'func_FFFF' "$TD/past.asm"; then
    echo "func_FFFF still emitted" >&2
    return 1
  fi
  if ! grep -F -q 'func_10000' "$TD/past.asm"; then
    echo "missing func_10000" >&2
    return 1
  fi
  "$BIN" --json "$TD/past.exe" >"$TD/past.json" 2>"$TD/past.err" || return 1
  "$BIN" --uasm --json -o "$TD/past_u.json.asm" "$TD/past.exe" \
    >"$TD/past_uj.json" 2>"$TD/past_uj.err" || return 1
  cfg_sig "$TD/past.json" "$TD/past_uj.json" || return 1
  python3 - "$TD/past.json" "$TD/past_uj.json" << 'PY'
import json, sys
for path in sys.argv[1:]:
    d = json.load(open(path))
    cfg = d["cfg"]
    starts = {b["start_ip"] for b in cfg["interesting"]}
    froms = {e["from"] for e in cfg["edges"]}
    if "10000" not in starts and "10000" not in froms:
        sys.exit(path + " has no block at 10000: " + str(starts) + " " + str(froms))
    print(path, "blocks", cfg["blocks"], "has 10000")
PY
}

case_mz_outside_image() {
  "$BIN" --uasm -o "$TD/outside.asm" "$TD/outside.exe" \
    >"$TD/outside_u.out" 2>"$TD/outside_u.err" || return 1
  if ! grep -F -q 'entry is past the 64 KiB decode window' "$TD/outside.asm"; then
    echo "missing past-window note" >&2
    return 1
  fi
  if grep -F -q 'func_FFFF' "$TD/outside.asm"; then
    echo "func_FFFF still emitted" >&2
    return 1
  fi
  "$BIN" --json "$TD/outside.exe" >"$TD/outside.json" 2>"$TD/outside.err" || return 1
  python3 - "$TD/outside.json" << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
cfg = d.get("cfg")
if cfg is None:
    sys.exit("cfg is null")
if cfg["blocks"] < 1:
    sys.exit("expected cfg.blocks >= 1 from the IP 0 seed")
print("outside blocks", cfg["blocks"])
PY
}

bb_file() {
  local out=$1
  local off=$2
  local n
  n=$(grep -c -E '^BB 0100' "$out" || true)
  if [[ "$n" -ne 1 ]]; then
    echo "expected one BB 0100 line, got $n" >&2
    cat "$out" >&2
    return 1
  fi
  local line
  line=$(grep -E '^BB 0100' "$out")
  if [[ "$line" != *"file ${off}h"* ]]; then
    echo "BB line missing file ${off}h: $line" >&2
    return 1
  fi
}

case_com_nopsp_off() {
  "$BIN" --no-psp -d --cfg "$TD/ret.com" >"$TD/nopsp.out" 2>"$TD/nopsp.err" || return 1
  bb_file "$TD/nopsp.out" 00000000
}

case_com_psp_off() {
  "$BIN" --psp -d --cfg "$TD/psp.com" >"$TD/psp.out" 2>"$TD/psp.err" || return 1
  bb_file "$TD/psp.out" 00000100
}

case_com_cfg_only() {
  "$BIN" --no-psp --cfg "$TD/ret.com" >"$TD/cfgonly.out" 2>"$TD/cfgonly.err" || return 1
  bb_file "$TD/cfgonly.out" 00000000
}

check mz_json_eq case_mz_json_eq
check mz_uasm_json case_mz_uasm_json
check mz_past_window case_mz_past_window
check mz_outside_image case_mz_outside_image
check com_nopsp_off case_com_nopsp_off
check com_psp_off case_com_psp_off
check com_cfg_only case_com_cfg_only

echo "cfg-once tests: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
