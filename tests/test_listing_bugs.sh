#!/usr/bin/env bash
# Regression tests for dumpexe listing/CFG bugs 2, 5, and 11.
# Not wired into `make test` yet (Makefile is owned by another agent).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -z "${PKG_CONFIG_PATH:-}" && -d /usr/local/lib/pkgconfig ]]; then
  export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
fi

make -s V=0 -j"$(nproc)"
BIN="$ROOT/dumpexe"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe was not built"; exit 1; }

TD="$(mktemp -d /tmp/dumpexe-listbugs-XXXXXX)"
trap 'rm -rf "$TD"' EXIT

python3 - "$TD" << 'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
p.joinpath("YESNO.COM").write_bytes(bytes.fromhex(
    "b38032ff8a1fc78781002028c7878300592fc78785004e29c78787002024"
    "ba8200b409cd21b40dcd21b401cd2132e43c6e741a3c4e7416fec43c797410"
    "3c59740c3c0d74bbb208b402cd21ebdc50b20db402cd21b20ab402cd2158"
    "b04c86e0cd21"))
p.joinpath("STARTUP.COM").write_bytes(bytes.fromhex("BAD7012E89165301B430CD21"))
# je lands on the immediate of `mov ax, 0x1234` (IP 0101), not an insn start.
p.joinpath("JCCMID.COM").write_bytes(bytes.fromhex("B8341274FC"))
# je +1 lands inside the next instruction (mov ax, 0x1234). Fall-through
# must keep B8 34 12; the interior byte must not become xor al, 0x12.
p.joinpath("JCCFWD.COM").write_bytes(bytes.fromhex("7401B83412C3"))
# Near call to the ret, then far lcall (seg 0x60 is inside the PSP hole),
# nop (far-call fall-through), far ljmp (must not fall into mov ax), ret.
p.joinpath("FARCALL.COM").write_bytes(bytes.fromhex(
    "e80e009a6823600090ea78564000b83412c3"))
PY

fail=0
pass=0
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

# Bug 2: YESNO must not overlap, and the six-byte mov stays one instruction.
# mov dx / mov ah,9 appear before the first int 0x21.
"$BIN" -d --no-asm-file "$TD/YESNO.COM" >"$TD/yesno.txt" 2>"$TD/yesno.err"
check yesno_no_overlap python3 - "$TD/yesno.txt" << 'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
rows = []
for line in text:
    m = re.match(r"\s+([0-9A-Fa-f]{4})\s+([0-9A-Fa-f]+)\s+\S+", line)
    if not m:
        continue
    ip = int(m.group(1), 16)
    hx = m.group(2)
    if len(hx) % 2:
        print("odd hex", line)
        sys.exit(1)
    nbytes = len(hx) // 2
    rows.append((ip, nbytes, line))
if not rows:
    print("no instructions")
    sys.exit(1)
for (ip, n, line), (ip2, _, line2) in zip(rows, rows[1:]):
    shown = n if n < 8 else 8
    if ip2 < ip + shown:
        print("overlap", line)
        print("       ", line2)
        sys.exit(1)
blob = next((ln for ln in text if "C78785004E29" in ln.upper()), None)
if blob is None:
    print("missing C78785004E29 as one instruction")
    sys.exit(1)
m = re.search(r"\s+([0-9A-Fa-f]{4})\s+C78785004E29", blob, re.I)
if not m:
    print("six-byte mov hex is not a single field:", blob)
    sys.exit(1)
want = int(m.group(1), 16) + 6
if not any(ip == want for ip, _, _ in rows):
    print("no instruction at +6 after the six-byte mov")
    sys.exit(1)
code = [ln for ln in text if re.match(r"\s+[0-9A-Fa-f]{4}\s+[0-9A-Fa-f]", ln)]
def is_int21(ln):
    return re.search(r"\bint\b", ln, re.I) and re.search(r"0x21\b", ln, re.I)
def is_mov_dx(ln):
    return re.search(r"\bmov\b", ln, re.I) and re.search(r"\bdx\b", ln, re.I) and re.search(r"0x82\b|82h", ln, re.I)
def is_mov_ah9(ln):
    return (re.search(r"\bmov\b", ln, re.I) and re.search(r"\bah\b", ln, re.I)
            and re.search(r"(?:,\s*9\b|,\s*0x9\b)", ln, re.I))
try:
    i_int = next(i for i, ln in enumerate(code) if is_int21(ln))
except StopIteration:
    print("no int 0x21")
    sys.exit(1)
pre = code[:i_int]
if not any(is_mov_dx(ln) for ln in pre):
    print("mov dx, 0x82 not before first int 0x21")
    sys.exit(1)
if not any(is_mov_ah9(ln) for ln in pre):
    print("mov ah, 9 not before first int 0x21")
    sys.exit(1)
print("yesno overlap ok", len(rows), "insns")
PY

# Bug 2: Turbo C startup bytes must not be split at offset 2.
"$BIN" -d --no-asm-file "$TD/STARTUP.COM" >"$TD/startup.txt" 2>"$TD/startup.err"
check startup_bytes python3 - "$TD/startup.txt" << 'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
if "1689" in text:
    print("mis-decoded add [0x1689]")
    sys.exit(1)
if not re.search(r"mov\s+dx,\s*(0x1d7|1d7h)\b", text, re.I):
    print("missing mov dx, 0x1d7")
    sys.exit(1)
if not re.search(r"mov\s+word ptr cs:\[[^\]]+\],\s*dx", text, re.I):
    print("missing mov cs:[...], dx")
    sys.exit(1)
if not re.search(r"mov\s+ah,\s*(0x30|30h)\b", text, re.I):
    print("missing mov ah, 0x30")
    sys.exit(1)
if not re.search(r"\bint\s+0x21\b", text, re.I):
    print("missing int 0x21")
    sys.exit(1)
# order: mov dx before int
lines = text.splitlines()
i_dx = next(i for i, ln in enumerate(lines) if re.search(r"mov\s+dx,\s*(0x1d7|1d7h)", ln, re.I))
i_int = next(i for i, ln in enumerate(lines) if re.search(r"\bint\s+0x21\b", ln, re.I))
if not (i_dx < i_int):
    print("mov dx is not before int 0x21")
    sys.exit(1)
print("startup ok")
PY

check startup_no_overlap python3 - "$TD/startup.txt" << 'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
rows = []
for line in text:
    m = re.match(r"\s+([0-9A-Fa-f]{4})\s+([0-9A-Fa-f]+)\s+\S+", line)
    if not m:
        continue
    ip = int(m.group(1), 16)
    n = len(m.group(2)) // 2
    rows.append((ip, n, line))
for (ip, n, line), (ip2, _, line2) in zip(rows, rows[1:]):
    shown = n if n < 8 else 8
    if ip2 < ip + shown:
        print("overlap", line, line2)
        sys.exit(1)
print("startup overlap ok")
PY

# Bug 5: COM without a PSP is org 0100h, and "; source:" is the filename.
check com_org100 python3 - "$TD/yesno.txt" "$TD/YESNO.COM" << 'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
name = sys.argv[2]
if f"; source: {name}" not in text:
    print("source line is not the input filename")
    for ln in text.splitlines():
        if "source:" in ln:
            print(ln)
    sys.exit(1)
if "; source: binary" in text:
    print("source is the literal word binary")
    sys.exit(1)
if "func_0100" not in text:
    print("missing func_0100")
    sys.exit(1)
if re.search(r"func_0000\b", text):
    print("unexpected func_0000")
    sys.exit(1)
if not re.search(r"entry=0100h", text):
    print("entry is not 0100h")
    sys.exit(1)
rows = []
for line in text.splitlines():
    m = re.match(r"\s+([0-9A-Fa-f]{4})\s+[0-9A-Fa-f]", line)
    if m:
        rows.append(int(m.group(1), 16))
if not rows or rows[0] != 0x100:
    print("first address column is not 0100:", rows[:4])
    sys.exit(1)
# Branch targets share the IP base: no CS*16 linear immediates (0x1xxxx).
if re.search(r"\b0x1[0-9A-Fa-f]{4}\b", text):
    print("branch/immediate still uses a linear 0x1xxxx address")
    sys.exit(1)
print("com org ok")
PY

# Bug 11: jcc targets on an instruction boundary become loc_XXXX and are defined.
# YESNO's forward je lands on `push ax` (not a call/jmp entry) → loc_.
# The backward je lands on the entry → func_0100, which must stay.
check jcc_loc python3 - "$TD/yesno.txt" << 'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
uses = set(re.findall(r"\b(?:j[a-z]+|loop[a-z]*)\s+loc_([0-9A-Fa-f]{4})\b", text))
defs = set(re.findall(r"(?m)^loc_([0-9A-Fa-f]{4}):", text))
if not uses:
    print("no jcc/loop operand uses loc_")
    sys.exit(1)
missing = uses - defs
if missing:
    print("loc_ used but not defined", sorted(missing))
    sys.exit(1)
if not re.search(r"\bje\s+func_0100\b", text):
    print("backward je to entry was not kept as func_0100")
    sys.exit(1)
if not re.search(r"\bjmp\s+func_[0-9A-Fa-f]{4}\b", text):
    print("jmp func_ label was lost")
    sys.exit(1)
print("jcc loc ok", sorted(uses))
PY

# A target strictly inside an owned instruction stays numeric (same IP base).
"$BIN" -d --no-asm-file "$TD/JCCMID.COM" >"$TD/jccmid.txt" 2>"$TD/jccmid.err"
check jcc_numeric_inside python3 - "$TD/jccmid.txt" << 'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
if not re.search(r"\bje\s+0x101\b", text):
    print("expected numeric je 0x101")
    print(text)
    sys.exit(1)
if "loc_0101" in text:
    print("interior target was labeled loc_0101")
    sys.exit(1)
if "0x10101" in text.lower():
    print("linear address 0x10101 leaked")
    sys.exit(1)
print("jcc interior numeric ok")
PY

# Forward jcc into the next instruction must not steal its opcode.
"$BIN" -d --no-asm-file "$TD/JCCFWD.COM" >"$TD/jccfwd.txt" 2>"$TD/jccfwd.err"
check jcc_forward_keeps_mov python3 - "$TD/jccfwd.txt" << 'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
if not re.search(r"B83412", text, re.I):
    print("mov ax immediate was split; missing B83412")
    print(text)
    sys.exit(1)
if re.search(r"\bxor\s+al,\s*0x12\b", text, re.I):
    print("interior byte decoded as xor al, 0x12")
    print(text)
    sys.exit(1)
if not re.search(r"\bmov\s+ax,\s*0x1234\b", text, re.I):
    print("missing mov ax, 0x1234")
    print(text)
    sys.exit(1)
print("jcc forward ok")
PY

# Far lcall: Capstone operand 0 is the segment. Keep seg,off text; do not
# invent func_<segment>. Far call falls through; far jmp does not.
# Near call in the same image still gets a func_ label.
"$BIN" -d -o - --no-repack --no-asm-file "$TD/FARCALL.COM" >"$TD/far.txt" 2>"$TD/far.err"
check far_lcall_keeps_seg_off python3 - "$TD/far.txt" "$TD/FARCALL.asm" << 'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
asm = sys.argv[2]
import os
if os.path.exists(asm):
    print(" -o - still wrote", asm)
    sys.exit(1)
if not re.search(r"\blcall\b", text, re.I):
    print("missing lcall")
    print(text)
    sys.exit(1)
if not re.search(r"0x60\b", text, re.I) or not re.search(r"0x2368\b", text, re.I):
    print("lcall segment/offset text missing")
    print(text)
    sys.exit(1)
if "func_0060" in text or "func_0040" in text:
    print("far segment was turned into a near func_ label")
    print(text)
    sys.exit(1)
if not re.search(r"\bljmp\b", text, re.I):
    print("missing ljmp (far call did not fall through)")
    print(text)
    sys.exit(1)
if not re.search(r"0x40:0x5678", text, re.I):
    print("ljmp seg:off text missing")
    print(text)
    sys.exit(1)
if not re.search(r"\bnop\b", text, re.I):
    print("missing nop after far call")
    print(text)
    sys.exit(1)
if re.search(r"\bmov\s+ax,\s*0x1234\b", text, re.I):
    print("far jmp fell through into mov ax")
    print(text)
    sys.exit(1)
if not re.search(r"\bcall\s+func_0111\b", text):
    print("near call label was lost")
    print(text)
    sys.exit(1)
if not re.search(r"(?m)^func_0111:", text):
    print("near call target label missing")
    print(text)
    sys.exit(1)
print("far lcall ok")
PY

# Default <stem>.asm is kept. -o PATH may replace that same file.
mkdir -p "$TD/ow"
printf 'KEEP\n' > "$TD/ow/t.asm"
printf '\xc3' > "$TD/ow/t.com"
"$BIN" -d "$TD/ow/t.com" >"$TD/ow/stdout.txt" 2>"$TD/ow/err.txt"
check asm_refuse_default python3 - "$TD/ow/t.asm" "$TD/ow/err.txt" "$TD/ow/stdout.txt" << 'PY'
import sys
asm, err_p, out_p = sys.argv[1:]
body = open(asm, encoding="utf-8").read()
if body != "KEEP\n":
    print("default asm was overwritten:", repr(body[:80]))
    sys.exit(1)
err = open(err_p, encoding="utf-8", errors="replace").read()
want = f"listing: refuse to overwrite '{asm}'"
if want not in err:
    print("missing", want)
    print(err)
    sys.exit(1)
out = open(out_p, encoding="utf-8", errors="replace").read()
if "Multi-pass assembly listing" not in out:
    print("listing did not stay on stdout")
    sys.exit(1)
print("asm refuse ok")
PY

"$BIN" -d -o "$TD/ow/t.asm" "$TD/ow/t.com" >"$TD/ow/stdout2.txt" 2>"$TD/ow/err2.txt"
check asm_o_may_replace python3 - "$TD/ow/t.asm" "$TD/ow/err2.txt" << 'PY'
import sys
asm, err_p = sys.argv[1:]
body = open(asm, encoding="utf-8", errors="replace").read()
if body == "KEEP\n" or "KEEP" == body.strip() and "func_" not in body:
    print(" -o did not replace t.asm:", repr(body[:80]))
    sys.exit(1)
if "func_0100" not in body:
    print("replaced asm has no listing")
    print(body[:400])
    sys.exit(1)
err = open(err_p, encoding="utf-8", errors="replace").read()
if "refuse to overwrite" in err:
    print(" -o was refused:", err)
    sys.exit(1)
print("asm -o replace ok")
PY

check help_keeps_default_outputs bash -c "$BIN -h 2>&1 | grep -q 'unless -o or --repack-output'"

# Repack: existing default <stem>.repack.exe is kept. --repack-output may replace.
CAT="$ROOT/games/catacomb/bin/CATACOMB.EXE"
if [[ ! -f "$CAT" ]]; then
  echo "FAIL repack_fixture_missing"
  fail=$((fail + 1))
else
  mkdir -p "$TD/re"
  cp -f "$CAT" "$TD/re/CATACOMB.EXE"
  "$BIN" -d "$TD/re/CATACOMB.EXE" >/dev/null 2>"$TD/re/err1.txt"
  cp -f "$TD/re/CATACOMB.repack.exe" "$TD/re/first.repack.exe"
  "$BIN" -d "$TD/re/CATACOMB.EXE" >/dev/null 2>"$TD/re/err2.txt"
  check repack_refuse_default python3 - "$TD/re" << 'PY'
import pathlib, sys
re = pathlib.Path(sys.argv[1])
first = (re / "first.repack.exe").read_bytes()
second = (re / "CATACOMB.repack.exe").read_bytes()
if first != second:
    print("default repack bytes changed", len(first), len(second))
    sys.exit(1)
if len(first) < 64:
    print("repack output too small")
    sys.exit(1)
err = (re / "err2.txt").read_text(encoding="utf-8", errors="replace")
want = "repack: refuse to overwrite '" + str(re / "CATACOMB.repack.exe") + "'"
if want not in err:
    print("missing", want)
    print(err)
    sys.exit(1)
if "repack: failed" in err:
    print("refuse also printed repack: failed")
    print(err)
    sys.exit(1)
print("repack refuse ok", len(first))
PY
  printf 'KEEP' > "$TD/re/named.exe"
  "$BIN" -d --repack-output="$TD/re/named.exe" "$TD/re/CATACOMB.EXE" >/dev/null 2>"$TD/re/err3.txt"
  check repack_named_overwrite python3 - "$TD/re" << 'PY'
import pathlib, sys
re = pathlib.Path(sys.argv[1])
named = (re / "named.exe").read_bytes()
if named.startswith(b"KEEP") or named == b"KEEP":
    print("--repack-output did not replace named.exe")
    sys.exit(1)
if not named.startswith(b"MZ"):
    print("named.exe is not an MZ image")
    sys.exit(1)
kept = (re / "CATACOMB.repack.exe").read_bytes()
first = (re / "first.repack.exe").read_bytes()
if kept != first:
    print("named repack rewrote the default file")
    sys.exit(1)
err = (re / "err3.txt").read_text(encoding="utf-8", errors="replace")
if "repack: failed" in err:
    print(err)
    sys.exit(1)
if "repack: wrote" not in err:
    print("missing repack: wrote")
    print(err)
    sys.exit(1)
print("repack named overwrite ok", len(named))
PY
fi

echo "---"
echo "passed=$pass failed=$fail"
[[ "$fail" -eq 0 ]]
