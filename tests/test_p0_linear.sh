#!/usr/bin/env bash
# P0 Q5: image-linear MZ CFG. Near flow wraps inside the real-mode segment.
# Skips (exit 77) only when uasm is absent. Synthetic MZ only. No --simulate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || {
  echo "SKIP test_p0_linear: uasm not found"
  exit 77
}

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p0-linear-XXXXXX")"
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
    (td / f"{name}.exe").write_bytes(build_mz(image, **kw))
    (td / f"{name}.img").write_bytes(bytes(image))

# 1. In-image entry CS=0x1000 IP=0x10, ret at linear 0x10010.
entry = bytearray(0x10011)
entry[0x10010] = 0xC3
save("entry_10010", entry, ip=0x10, cs=0x1000)

# 2. Near stay: EB 00 C3 at linear 0x10000. Target is 0x10002, not 0x0002.
stay = bytearray(0x10003)
stay[0x10000:0x10003] = bytes([0xEB, 0x00, 0xC3])
save("near_stay", stay, ip=0, cs=0x1000)

# 3. Near wrap: EB FC at 0x10000 targets ip16 0xFFFE (linear 0x1FFFE).
wrap = bytearray(0x1FFFF)
wrap[0x10000:0x10002] = bytes([0xEB, 0xFC])
wrap[0x1FFFE] = 0xC3
save("near_wrap", wrap, ip=0, cs=0x1000)

# 4. Nops at the end of CS=0x1000 wrap to 0x10000, not into 0x20000.
spill = bytearray(0x20001)
spill[0x10000] = 0xC3
spill[0x1FFFE] = 0x90
spill[0x1FFFF] = 0x90
spill[0x20000] = 0xC3
save("no_spill", spill, ip=0xFFFE, cs=0x1000)

# 5. First segment also wraps to IP 0, not to linear 0x10000.
low = bytearray(0x10001)
low[0] = 0xC3
low[0xFFFE] = 0x90
low[0xFFFF] = 0x90
low[0x10000] = 0xC3
save("no_spill0", low, ip=0xFFFE, cs=0)

# 6. Reloc-pinned far call whose target linear 0x10000 is inside the image.
far_in = bytearray(0x10002)
far_in[0:5] = bytes([0x9A, 0x00, 0x00, 0x00, 0x10])
far_in[0x10000] = 0xC3
save("far_in", far_in, crlc=1, ip=0, cs=0, reloc=(3, 0))

# 7. Pinned outside, and the segment word equals the file CS (M1 bait).
far_out = bytearray(0x10005)
far_out[0x10000:0x10005] = bytes([0x9A, 0x06, 0x00, 0x00, 0x10])
save("far_out", far_out, crlc=1, ip=0, cs=0x1000, reloc=(3, 0x1000))

# 8. Unaligned pinned segment 0x1100. EB 00 C3 stays in that segment.
unalign = bytearray(0x11003)
unalign[0:5] = bytes([0x9A, 0x00, 0x00, 0x00, 0x11])
unalign[0x11000:0x11003] = bytes([0xEB, 0x00, 0xC3])
save("unalign", unalign, crlc=1, ip=0, cs=0, reloc=(3, 0))

# 9. com2exe CS=FFF0 IP=0100. delta <= 0, entry linear 0.
save("com2exe", bytes([0xC3]), ip=0x100, cs=0xFFF0)

# 10 and 11. In-image ret at linear 0x10000. Multi-segment UASM.
past = bytearray(65537)
past[0] = 0xC3
past[65536] = 0xC3
save("past64", past, ip=0, cs=0x1000)

# 12. CS=FFFFh IP=0020h. delta = 0x10, frame = -16.
# eb 02 90 90 b8 00 4c cd 21 at linear 0x10: jmp, mov ax,4C00h, int 21h.
neg = bytearray(0x40)
neg[0x10:0x1A] = bytes.fromhex("eb029090b8004ccd21")
save("negcs", neg, ip=0x20, cs=0xFFFF)

# 13. CS=FFF0h IP=0110h. delta = 0x10, frame = -256. EB 00 C3 stays in-image.
fff0 = bytearray(0x20)
fff0[0x10:0x13] = bytes([0xEB, 0x00, 0xC3])
save("negcs_fff0", fff0, ip=0x110, cs=0xFFF0)

# 14. X6: CS=1000h, 0x10000 zeros + C3 + 32767 x CD 21.
x6 = bytearray(0x10000) + bytes([0xC3]) + bytes([0xCD, 0x21]) * 32767
save("x6", x6, ip=0, cs=0x1000)

# 15. X10: 64 KiB COM of byte 0x73. Branch targets are not string immediates.
(td / "x10.com").write_bytes(bytes([0x73]) * 65536)
print("fixtures", td)
PY

json_of() {
  local name=$1
  "$BIN" --json "$TD/$name.exe" >"$TD/$name.json" 2>"$TD/$name.err" || {
    echo "dumpexe --json failed for $name" >&2
    cat "$TD/$name.err" >&2
    return 1
  }
}

# Print edges and exit 1 with a message when the predicate fails.
# Usage: py_edges name  <<'PY' ... PY
py_edges() {
  local name=$1
  python3 - "$TD/$name.json" "$name"
}

case_entry_10010() {
  json_of entry_10010 || return 1
  "$BIN" --uasm -o "$TD/entry_10010.asm" "$TD/entry_10010.exe" \
    >"$TD/entry_10010.uout" 2>"$TD/entry_10010.uerr" || return 1
  if grep -F -q 'entry is past the 64 KiB decode window' "$TD/entry_10010.asm"; then
    echo "in-image entry printed the past-window note" >&2
    return 1
  fi
  if grep -F -q 'func_FFFF' "$TD/entry_10010.asm"; then
    echo "func_FFFF emitted" >&2
    return 1
  fi
  py_edges entry_10010 << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
cfg = d["cfg"]
starts = {b["start_ip"] for b in cfg["interesting"]}
froms = {e["from"] for e in cfg["edges"]}
if "10010" not in starts and "10010" not in froms:
    sys.exit("no block at 10010: " + str(starts) + " " + str(froms))
print("entry 10010 ok", cfg["blocks"])
PY
}

case_near_stay() {
  json_of near_stay || return 1
  py_edges near_stay << 'PY'
import json, sys
edges = json.load(open(sys.argv[1]))["cfg"]["edges"]
hit = [e for e in edges if e["to"] == "10002" and e["kind"] == "jmp" and e["has_target"]]
bad = [e for e in edges if e["to"] == "0002"]
if not hit or bad:
    sys.exit("stay edges " + str(edges))
print("near stay ok")
PY
}

case_near_wrap() {
  json_of near_wrap || return 1
  py_edges near_wrap << 'PY'
import json, sys
edges = json.load(open(sys.argv[1]))["cfg"]["edges"]
hit = [e for e in edges if e["to"] == "1FFFE" and e["kind"] == "jmp" and e["has_target"]]
bad = [e for e in edges if e["to"] in ("0FFFE", "FFFE")]
if not hit or bad:
    sys.exit("wrap edges " + str(edges))
print("near wrap ok")
PY
}

case_no_spill() {
  json_of no_spill || return 1
  py_edges no_spill << 'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))["cfg"]
edges = cfg["edges"]
hit = [e for e in edges if e["to"] == "10000" and e["kind"] == "fall" and e["has_target"]]
bad = [e for e in edges if e["from"] == "20000" or e["to"] == "20000"]
starts = {b["start_ip"] for b in cfg["interesting"]}
if not hit or bad or "20000" in starts:
    sys.exit("spill edges " + str(edges) + " starts " + str(starts))
print("no spill ok")
PY
}

case_no_spill0() {
  json_of no_spill0 || return 1
  py_edges no_spill0 << 'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))["cfg"]
edges = cfg["edges"]
bad = [e for e in edges if e["from"] == "10000" or e["to"] == "10000"]
starts = {b["start_ip"] for b in cfg["interesting"]}
if bad or "10000" in starts:
    sys.exit("low spill " + str(edges) + " starts " + str(starts))
print("no spill0 ok", len(edges))
PY
}

case_far_in() {
  json_of far_in || return 1
  py_edges far_in << 'PY'
import json, sys
edges = json.load(open(sys.argv[1]))["cfg"]["edges"]
hit = [e for e in edges if e["to"] == "10000" and e["kind"] == "call" and e["has_target"]]
if not hit:
    sys.exit("far in edges " + str(edges))
print("far in ok")
PY
}

case_far_out() {
  json_of far_out || return 1
  py_edges far_out << 'PY'
import json, sys
edges = json.load(open(sys.argv[1]))["cfg"]["edges"]
bad = [e for e in edges if e["to"] in ("0006", "10006")]
if bad:
    sys.exit("pinned outside fell through: " + str(edges))
print("far out ok", edges)
PY
}

case_unalign() {
  json_of unalign || return 1
  py_edges unalign << 'PY'
import json, sys
edges = json.load(open(sys.argv[1]))["cfg"]["edges"]
call = [e for e in edges if e["to"] == "11000" and e["kind"] == "call" and e["has_target"]]
jmp = [e for e in edges if e["to"] == "11002" and e["kind"] == "jmp" and e["has_target"]]
bad = [e for e in edges if e["to"] in ("10002", "12000")]
if not call or not jmp or bad:
    sys.exit("unalign edges " + str(edges))
print("unalign ok")
PY
}

case_com2exe() {
  json_of com2exe || return 1
  "$BIN" --uasm -o "$TD/com2exe.asm" "$TD/com2exe.exe" \
    >"$TD/com2exe.uout" 2>"$TD/com2exe.uerr" || return 1
  if grep -F -q 'entry is past the 64 KiB decode window' "$TD/com2exe.asm"; then
    echo "com2exe printed the past-window note" >&2
    return 1
  fi
  py_edges com2exe << 'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))["cfg"]
starts = {b["start_ip"] for b in cfg["interesting"]}
froms = {e["from"] for e in cfg["edges"]}
if "0000" not in starts and "0000" not in froms:
    sys.exit("no block at 0000: " + str(starts) + " " + str(froms))
print("com2exe ok")
PY
}

case_q11_past64() {
  "$BIN" --json "$TD/past64.exe" >"$TD/past64.json" 2>"$TD/past64.err" || return 1
  "$BIN" --uasm --json -o "$TD/past64.asm" "$TD/past64.exe" \
    >"$TD/past64_uj.json" 2>"$TD/past64_uj.err" || return 1
  python3 - "$TD/past64.json" "$TD/past64_uj.json" << 'PY'
import json, sys
sigs = []
for path in sys.argv[1:]:
    d = json.load(open(path))
    cfg = d.get("cfg")
    if cfg is None:
        sys.exit("cfg is null in " + path)
    edges = [(e["from"], e["to"], e["kind"], e["has_target"]) for e in cfg["edges"]]
    starts = {b["start_ip"] for b in cfg["interesting"]}
    froms = {e["from"] for e in cfg["edges"]}
    if "10000" not in starts and "10000" not in froms:
        sys.exit(path + " missing 10000")
    sigs.append((cfg["blocks"], cfg["n_edges"], edges))
if sigs[0] != sigs[1]:
    sys.exit("Q11 mismatch " + str(sigs))
print("q11 ok", sigs[0][0], "blocks")
PY
}

case_uasm_bin_len() {
  "$BIN" --uasm -o "$TD/past64_bin.asm" "$TD/past64.exe" \
    >"$TD/past64_bin.out" 2>"$TD/past64_bin.err" || return 1
  (
    cd "$TD" || exit 1
    "$UASM_BIN" -bin -nologo -Fo past64.bin past64_bin.asm \
      >past64.uasm 2>past64.uasmerr
  ) || {
    echo "uasm -bin failed" >&2
    cat "$TD/past64.uasmerr" >&2
    return 1
  }
  python3 - "$TD/past64.bin" "$TD/past64.img" << 'PY'
import sys
built = open(sys.argv[1], "rb").read()
image = open(sys.argv[2], "rb").read()
if len(built) != len(image):
    sys.exit(f"length {len(built)} != image {len(image)}")
if built != image:
    sys.exit("uasm -bin bytes differ from the load image")
print("uasm bin", len(built))
PY
}

case_negcs() {
  json_of negcs || return 1
  "$BIN" -d --no-asm-file --no-repack "$TD/negcs.exe" \
    >"$TD/negcs.d" 2>"$TD/negcs.derr" || return 1
  py_edges negcs << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
cfg = d["cfg"]
if cfg["blocks"] < 2:
    sys.exit("blocks " + str(cfg["blocks"]))
edges = cfg["edges"]
jmp = [e for e in edges if e["from"] == "0010" and e["kind"] == "jmp" and e["has_target"] and e["to"] == "0014"]
if not jmp:
    sys.exit("negcs jmp " + str(edges))
ints = []
for b in cfg["interesting"]:
    ints.extend(b.get("ints") or [])
hit = [s for s in ints if s.get("ip") == "0017" and s.get("int") == 33]
if not hit:
    sys.exit("negcs int " + str(ints))
print("negcs blocks", cfg["blocks"])
PY
  grep -F -q '0014' "$TD/negcs.d" || { echo "missing mov site 0014"; return 1; }
  grep -E -q '0014[[:space:]].*mov' "$TD/negcs.d" || { echo "missing mov at 0014"; cat "$TD/negcs.d"; return 1; }
  grep -E -q '0017[[:space:]].*int' "$TD/negcs.d" || { echo "missing int at 0017"; cat "$TD/negcs.d"; return 1; }
}

case_negcs_fff0() {
  json_of negcs_fff0 || return 1
  py_edges negcs_fff0 << 'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))["cfg"]
if cfg["blocks"] < 2:
    sys.exit("blocks " + str(cfg["blocks"]))
edges = cfg["edges"]
jmp = [e for e in edges if e["from"] == "0010" and e["to"] == "0012" and e["kind"] == "jmp" and e["has_target"]]
bad = [e for e in edges if e["to"] not in ("0012", "0000") and e["has_target"]]
if not jmp or bad:
    sys.exit("fff0 jmp " + str(edges))
print("negcs fff0 ok", cfg["blocks"])
PY
}

case_x6_int_past64() {
  local start end ms
  start=$(date +%s%N)
  "$BIN" -d --no-asm-file --no-repack "$TD/x6.exe" >"$TD/x6.out" 2>"$TD/x6.err" || {
    echo "x6 dumpexe failed" >&2
    cat "$TD/x6.err" >&2
    return 1
  }
  end=$(date +%s%N)
  ms=$(( (end - start) / 1000000 ))
  if (( ms >= 2000 )); then
    echo "x6 took ${ms} ms (budget 2000)" >&2
    return 1
  fi
  echo "x6 ${ms} ms"
}

case_x10_printrun() {
  local start end ms
  start=$(date +%s%N)
  "$BIN" -d --cfg --no-asm-file --no-repack "$TD/x10.com" >"$TD/x10.out" 2>"$TD/x10.err" || {
    echo "x10 dumpexe failed" >&2
    cat "$TD/x10.err" >&2
    return 1
  }
  end=$(date +%s%N)
  ms=$(( (end - start) / 1000000 ))
  if (( ms >= 1000 )); then
    echo "x10 took ${ms} ms (budget 1000)" >&2
    return 1
  fi
  python3 - "$TD/x10.out" "$ms" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
m = re.search(r"String xrefs:\s*(\d+)", text)
if not m or m.group(1) != "0":
    sys.exit("string xrefs " + (m.group(0) if m else "missing"))
print("x10", sys.argv[2], "ms xrefs 0")
PY
}

check entry_10010 case_entry_10010
check near_stay case_near_stay
check near_wrap case_near_wrap
check no_spill case_no_spill
check no_spill0 case_no_spill0
check far_in case_far_in
check far_out case_far_out
check unalign case_unalign
check com2exe case_com2exe
check q11_past64 case_q11_past64
check uasm_bin_len case_uasm_bin_len
check negcs case_negcs
check negcs_fff0 case_negcs_fff0
check x6_int_past64 case_x6_int_past64
check x10_printrun case_x10_printrun

echo "linear tests: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
