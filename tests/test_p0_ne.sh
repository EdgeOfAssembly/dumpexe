#!/usr/bin/env bash
# P0: NE -d/-a must not decode past the on-disk code segment.
# These checks do not skip.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p0-ne-XXXXXX")"
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
import struct
import sys
from pathlib import Path

td = Path(sys.argv[1])

def build_ne(ip, segment):
    """Minimal NE that ne_parse accepts. Poison B0 EE follows cbseg."""
    poison = b"\xB0\xEE"
    blob = bytearray(0x100 + len(segment) + len(poison))
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x40)
    struct.pack_into("<H", blob, 0x40, 0x454E)
    struct.pack_into("<H", blob, 0x40 + 0x14, ip)
    struct.pack_into("<H", blob, 0x40 + 0x16, 1)
    struct.pack_into("<H", blob, 0x40 + 0x1C, 1)
    struct.pack_into("<H", blob, 0x40 + 0x1E, 0)
    struct.pack_into("<H", blob, 0x40 + 0x22, 0x40)
    struct.pack_into("<H", blob, 0x40 + 0x26, 0x48)
    struct.pack_into("<H", blob, 0x40 + 0x32, 4)
    blob[0x40 + 0x36] = 2
    struct.pack_into("<HHHH", blob, 0x80, 0x10, len(segment), 0, len(segment))
    blob[0x100:0x100 + len(segment)] = segment
    blob[0x100 + len(segment):] = poison
    return bytes(blob)

(td / "ip0.exe").write_bytes(build_ne(0, b"\xB0\x42"))
# IP 3 is EB FB (jmp short 0). The mov at IP 0 is reached only when the
# entry window is the whole segment from foff, not cbseg-ip bytes at entry.
(td / "ip3.exe").write_bytes(build_ne(3, b"\xB0\x11\xC3\xEB\xFB"))

def build_dup_ne(n_code, code, lengths=None):
    """CODE segments sharing one file window, plus a trailing DATA poison.

    lengths, when set, is a list of distinct cbseg values at that window
    (truncation). Otherwise n_code copies of the same length.
    k in "same bytes as segment k" is the 1-based segment index.
    """
    if lengths is None:
        segs = [(len(code), 0)] * n_code
    else:
        segs = [(n, 0) for n in lengths]
    segs.append((2, 0x0001))  # DATA
    nseg = len(segs)
    seg_bytes = nseg * 8
    rest_from_ne = 0x40 + seg_bytes
    file_after = 0x40 + rest_from_ne + 1
    code_off = (file_after + 15) & ~15
    data_off = (code_off + len(code) + 15) & ~15
    poison = b"\xB0\xEE"
    blob = bytearray(data_off + len(poison))
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x40)
    struct.pack_into("<H", blob, 0x40, 0x454E)
    struct.pack_into("<H", blob, 0x40 + 0x14, 0)
    struct.pack_into("<H", blob, 0x40 + 0x16, 1)
    struct.pack_into("<H", blob, 0x40 + 0x1C, nseg)
    struct.pack_into("<H", blob, 0x40 + 0x1E, 0)
    struct.pack_into("<H", blob, 0x40 + 0x22, 0x40)
    struct.pack_into("<H", blob, 0x40 + 0x24, rest_from_ne)
    struct.pack_into("<H", blob, 0x40 + 0x26, rest_from_ne)
    struct.pack_into("<H", blob, 0x40 + 0x32, 4)
    blob[0x40 + 0x36] = 2
    sector = code_off >> 4
    data_sector = data_off >> 4
    for i, (cb, flags) in enumerate(segs):
        off = 0x80 + i * 8
        sec = data_sector if flags & 1 else sector
        struct.pack_into("<HHHH", blob, off, sec, cb, flags, cb)
    blob[code_off:code_off + len(code)] = code
    blob[data_off:data_off + len(poison)] = poison
    return bytes(blob)

# 400 identical CODE windows. Old -a reprinted each one.
code = bytes([0x90]) * 79 + b"\xC3"
(td / "dup.exe").write_bytes(build_dup_ne(400, code))
# Distinct lengths at one window so the -a byte sum exceeds 2 * file size.
(td / "trunc.exe").write_bytes(build_dup_ne(0, bytes([0x90]) * 200 + b"\xC3",
                                            lengths=list(range(200, 180, -1))))
PY

# mode, fixture, required substrings, forbidden substrings
run_case() {
  local mode=$1
  local file=$2
  shift 2
  local out="$TD/out.txt"
  local err="$TD/err.txt"
  "$BIN" "$mode" --no-asm-file "$file" >"$out" 2>"$err"
  grep -q 'New Executable' "$out"
  local need
  for need in "$@"; do
    case "$need" in
      '!'*)
        local ban="${need:1}"
        if grep -q -F -- "$ban" "$out"; then
          echo "banned text present: $ban" >&2
          return 1
        fi
        ;;
      *)
        if ! grep -q -F -- "$need" "$out"; then
          echo "missing text: $need" >&2
          return 1
        fi
        ;;
    esac
  done
}

check ip0_d run_case -d "$TD/ip0.exe" 'B042' '0x42' '!B0EE' '!0xee'
check ip0_a run_case -a "$TD/ip0.exe" 'B042' '0x42' 'decoded 2 bytes' '!B0EE' '!0xee' '!first '
# -d must show the prefix. -a would show B011 from ip 0 even if entry dropped it.
check ip3_d run_case -d "$TD/ip3.exe" 'B011' '0x11' '!B0EE' '!0xee'
check ip3_a run_case -a "$TD/ip3.exe" 'decoded 5 bytes' '!B0EE' '!0xee' '!first '

# k is the 1-based segment index (same numbering as "CODE segment N").
case_dup_code() {
  local out="$TD/dup.out"
  local err="$TD/dup.err"
  "$BIN" -a --no-asm-file "$TD/dup.exe" >"$out" 2>"$err" || {
    echo "dup NE failed" >&2
    cat "$err" >&2
    return 1
  }
  local n
  n=$(grep -c 'Disassembly CODE segment' "$out" || true)
  if [[ "$n" != "1" ]]; then
    echo "full disassemblies $n" >&2
    return 1
  fi
  n=$(grep -c -F 'same bytes as segment 1' "$out" || true)
  if [[ "$n" != "399" ]]; then
    echo "same-bytes lines $n" >&2
    return 1
  fi
  if grep -F -q 'B0EE' "$out"; then
    echo "DATA segment was disassembled" >&2
    return 1
  fi
  local sz
  sz=$(wc -c < "$out")
  if (( sz >= 1048576 )); then
    echo "dup stdout $sz bytes" >&2
    return 1
  fi
  echo "dup stdout $sz"
}

case_trunc_code() {
  local out="$TD/trunc.out"
  "$BIN" -a --no-asm-file "$TD/trunc.exe" >"$out" 2>"$TD/trunc.err" || {
    echo "trunc NE failed" >&2
    cat "$TD/trunc.err" >&2
    return 1
  }
  grep -E -q 'truncated: [0-9]+ more CODE segments' "$out" || {
    echo "missing truncation line" >&2
    tail -n 20 "$out" >&2
    return 1
  }
  local full
  full=$(grep -c 'Disassembly CODE segment' "$out" || true)
  # 20 distinct lengths (200..181) plus the duplicate rule. Not all of them.
  if (( full < 1 || full >= 20 )); then
    echo "trunc disassemblies $full" >&2
    return 1
  fi
  local sz
  sz=$(wc -c < "$out")
  if (( sz >= 1048576 )); then
    echo "trunc stdout $sz" >&2
    return 1
  fi
  echo "trunc disassemblies $full stdout $sz"
}

check dup_code case_dup_code
check trunc_code case_trunc_code

echo "---"
echo "p0_ne passed=$pass failed=$fail"
[[ "$fail" -eq 0 ]]
