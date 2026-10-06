#!/usr/bin/env bash
# P0 Q10: a symbolic near displacement follows an inserted nop.
# The db form keeps the original displacement and must miss C3.
# Synthetic COM only. /usr/bin/uasm is required. Does not skip.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
[[ -x /usr/bin/uasm ]] || { echo "FAIL: /usr/bin/uasm not found"; exit 1; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p0-shift-XXXXXX")"
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
import sys
from pathlib import Path
td = Path(sys.argv[1])
call = bytes([0xE8, 0x01, 0x00, 0x90, 0xC3])
jmp = bytes([0xEB, 0x00, 0xC3])
for name in ("call_sym", "call_db"):
    (td / f"{name}.com").write_bytes(call)
for name in ("jmp_sym", "jmp_db"):
    (td / f"{name}.com").write_bytes(jmp)
print("fixtures", td)
PY

# kind is call or jmp. freeze=1 replaces the branch line with db bytes.
shift_one() {
  local name=$1 kind=$2 freeze=$3 expect=$4
  [[ -f "$TD/$name.com" ]] || { echo "missing $name.com"; return 1; }
  "$BIN" --uasm -o "$TD/$name.asm" "$TD/$name.com" >"$TD/$name.out" 2>"$TD/$name.err" || {
    echo "dumpexe --uasm failed for $name" >&2
    cat "$TD/$name.err" >&2
    return 1
  }
  python3 - "$TD/$name.asm" "$TD/$name.shifted.asm" "$kind" "$freeze" << 'PY'
import re
import sys
from pathlib import Path
src_path, dst_path, kind, freeze = sys.argv[1:]
text = Path(src_path).read_text(encoding="utf-8")
if kind == "call":
    if not re.search(r"(?m)^    call near ptr \S+\s*$", text):
        sys.stderr.write("missing 'call near ptr'\n")
        sys.exit(1)
else:
    if not re.search(r"(?m)^    jmp short \S+\s*$", text):
        sys.stderr.write("missing 'jmp short'\n")
        sys.exit(1)
lines = text.splitlines(keepends=True)
ret_i = None
for i, line in enumerate(lines):
    if line.strip() == "ret":
        ret_i = i
        break
if ret_i is None:
    sys.stderr.write("no ret instruction\n")
    sys.exit(1)
j = ret_i - 1
while j >= 0 and lines[j].strip() == "":
    j -= 1
if j < 0 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*:", lines[j].strip()):
    sys.stderr.write("no label on ret\n")
    sys.stderr.write(text)
    sys.exit(1)
lines.insert(j, "    nop\n")
text = "".join(lines)
if freeze == "1":
    if kind == "call":
        text, n = re.subn(
            r"(?m)^    call near ptr \S+\s*$",
            "    db 0E8h, 001h, 000h",
            text,
            count=1,
        )
    else:
        text, n = re.subn(
            r"(?m)^    jmp short \S+\s*$",
            "    db 0EBh, 000h",
            text,
            count=1,
        )
    if n != 1:
        sys.stderr.write(f"db replace count {n}\n")
        sys.exit(1)
Path(dst_path).write_text(text, encoding="utf-8")
PY
  (
    cd "$TD"
    /usr/bin/uasm -bin -nologo -Fo "$name.bin" "$name.shifted.asm" \
      >"$name.uasm" 2>"$name.uasmerr"
  ) || {
    echo "uasm -bin failed for $name" >&2
    cat "$TD/$name.uasmerr" >&2
    return 1
  }
  python3 - "$TD/$name.bin" "$kind" "$expect" << 'PY'
import sys
from pathlib import Path
blob = Path(sys.argv[1]).read_bytes()
kind = sys.argv[2]
expect = sys.argv[3] == "c3"
op = 0xE8 if kind == "call" else 0xEB
if not blob or blob[0] != op:
    got = blob[:8].hex() if blob else "empty"
    sys.stderr.write(f"image does not start with {op:#x}: {got}\n")
    sys.exit(1)
if op == 0xE8:
    disp = int.from_bytes(blob[1:3], "little", signed=True)
    tgt = 3 + disp
else:
    disp = int.from_bytes(blob[1:2], "little", signed=True)
    tgt = 2 + disp
lands = 0 <= tgt < len(blob) and blob[tgt] == 0xC3
if lands != expect:
    sys.stderr.write(
        f"disp {disp} target {tgt} byte "
        f"{blob[tgt]:#x} lands={lands} expect={expect} image={blob.hex()}\n"
        if 0 <= tgt < len(blob)
        else f"disp {disp} target {tgt} out of range image={blob.hex()}\n"
    )
    sys.exit(1)
PY
}

case_call_symbolic() { shift_one call_sym call 0 c3 || return 1; }
case_call_db() { shift_one call_db call 1 miss || return 1; }
case_jmp_symbolic() { shift_one jmp_sym jmp 0 c3 || return 1; }
case_jmp_db() { shift_one jmp_db jmp 1 miss || return 1; }

check call_symbolic case_call_symbolic
check call_db case_call_db
check jmp_symbolic case_jmp_symbolic
check jmp_db case_jmp_db

echo "shift tests: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
