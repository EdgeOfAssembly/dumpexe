#!/bin/bash
# CLI contracts for bin2exe: help, version, order, names, header copy.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="$REPO/bin2exe"
WORK="$(mktemp -d /tmp/bin2exe-cli.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail()
{
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

[[ -x "$BIN" ]] || fail "missing $BIN"

diff -u <("$BIN") <("$BIN" -h) >/dev/null
diff -u <("$BIN" -h) <("$BIN" --help) >/dev/null
[[ "$("$BIN")" == *"Usage: bin2exe"* ]] || fail "usage text"
[[ "$("$BIN" -v)" == "bin2exe 0.2" ]] || fail "version -v"
[[ "$("$BIN" --version)" == "bin2exe 0.2" ]] || fail "version --version"
[[ "$("$BIN" -h)" == *"--no-tail"* ]] || fail "help --no-tail"

set +e
"$BIN" >/dev/null
noargs_rc=$?
set -e
[[ "$noargs_rc" -eq 0 ]] || fail "no-args exit $noargs_rc"

set +e
"$BIN" --no-header >/dev/null 2>"$WORK/bad.err"
bad_rc=$?
set -e
[[ "$bad_rc" -eq 2 ]] || fail "unknown option exit $bad_rc"
[[ "$(cat "$WORK/bad.err")" == *"unknown option"* ]] || fail "unknown option text"

printf 'ABCD' > "$WORK/flat.bin"
"$BIN" "$WORK/flat.bin"
[[ -f "$WORK/flat.exe" ]] || fail "default stem.exe"
cmp -s <("$BIN" -o - "$WORK/flat.bin") "$WORK/flat.exe" || fail "stdout wrap"

"$BIN" -o "$WORK/ordered.exe" "$WORK/flat.bin"
"$BIN" "$WORK/flat.bin" -o "$WORK/ordered2.exe"
cmp -s "$WORK/ordered.exe" "$WORK/ordered2.exe" || fail "flag order"

# Round-trip: the COM wrap is itself a 32-byte MZ header plus the image.
"$BIN" --header "$WORK/flat.exe" "$WORK/flat.bin" -o "$WORK/copied.exe"
cmp -s "$WORK/flat.exe" "$WORK/copied.exe" || fail "header copy round trip"
"$BIN" "$WORK/flat.bin" --header="$WORK/flat.exe" -o "$WORK/copied2.exe"
cmp -s "$WORK/copied.exe" "$WORK/copied2.exe" || fail "--header= form"

printf 'ZZ' > "$WORK/short.bin"
"$BIN" --header "$WORK/flat.exe" -o "$WORK/short.exe" "$WORK/short.bin" \
    2>"$WORK/short.err"
[[ "$(cat "$WORK/short.err")" == *"original payload"* ]] || fail "length warning"
[[ "$(wc -c < "$WORK/short.exe")" -eq 34 ]] || fail "mismatch size"
cmp -n 32 "$WORK/flat.exe" "$WORK/short.exe" || fail "header bytes changed"

printf 'Z' > "$WORK/a.com"
printf 'Y' > "$WORK/b.com"
"$BIN" "$WORK/a.com" "$WORK/b.com" -o "$WORK/batchout" 2>"$WORK/dirnote.err"
[[ "$(cat "$WORK/dirnote.err")" == *"creating directory"* ]] || fail "dir note"
[[ -f "$WORK/batchout/a.exe" && -f "$WORK/batchout/b.exe" ]] || fail "new -o directory"

printf 'keep' > "$WORK/y.exe"
"$BIN" "$WORK/a.com" "$WORK/b.com" -o "$WORK/y.exe" 2>"$WORK/multi.err"
[[ "$(cat "$WORK/multi.err")" == *"warning"* ]] || fail "multi -o warning"
[[ -f "$WORK/y_a.exe" && -f "$WORK/y_b.exe" ]] || fail "multi names"
[[ "$(cat "$WORK/y.exe")" == "keep" ]] || fail "existing -o file changed"

mkdir -p "$WORK/batch"
printf 'A' > "$WORK/batch/a.bin"
printf 'B' > "$WORK/batch/b.com"
printf 'C' > "$WORK/batch/skip.txt"
printf 'D' > "$WORK/batch/.hidden.bin"
"$BIN" "$WORK/batch" -o "$WORK/out/"
[[ -f "$WORK/out/a.exe" && -f "$WORK/out/b.exe" ]] || fail "directory batch"
[[ ! -e "$WORK/out/skip.exe" && ! -e "$WORK/out/.hidden.exe" ]] || fail "batch filter"

mkdir -p "$WORK/deep/nested"
"$BIN" "$WORK/flat.bin" -o "$WORK/deep/nested/exact.exe"
[[ -f "$WORK/deep/nested/exact.exe" ]] || fail "parent create"

"$BIN" -o - --header "$WORK/flat.exe" "$WORK/flat.bin" > "$WORK/stdout.exe"
cmp -s "$WORK/stdout.exe" "$WORK/flat.exe" || fail "stdout header copy"

dd if=/dev/zero of="$WORK/big.bin" bs=65281 count=1 status=none
set +e
"$BIN" "$WORK/big.bin" >"$WORK/big.out" 2>"$WORK/big.err"
big_rc=$?
set -e
[[ "$big_rc" -eq 1 ]] || fail "oversize exit $big_rc"
[[ ! -s "$WORK/big.out" ]] || fail "oversize wrote stdout"
[[ "$(cat "$WORK/big.err")" == *"--header"* ]] || fail "oversize hint"
[[ ! -e "$WORK/big.exe" ]] || fail "oversize wrote a file"

set +e
"$BIN" "$WORK/flat.bin" -o "$WORK/flat.bin" >/dev/null 2>"$WORK/self.err"
self_rc=$?
set -e
[[ "$self_rc" -eq 1 ]] || fail "self overwrite exit $self_rc"
[[ "$(cat "$WORK/self.err")" == *"refusing to overwrite"* ]] || fail "self overwrite text"

set +e
"$BIN" --header "$WORK/flat.exe" "$WORK/flat.bin" >/dev/null 2>"$WORK/hdr.err"
hdr_rc=$?
set -e
[[ "$hdr_rc" -eq 1 ]] || fail "header overwrite exit $hdr_rc"
cmp -s "$WORK/flat.exe" <("$BIN" -o - "$WORK/flat.bin") || fail "header was modified"

printf 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' > "$WORK/text.bin"
set +e
"$BIN" --header "$WORK/text.bin" "$WORK/flat.bin" -o "$WORK/bad.exe" >/dev/null 2>"$WORK/text.err"
text_rc=$?
set -e
[[ "$text_rc" -eq 1 ]] || fail "non-mz exit $text_rc"
[[ "$(cat "$WORK/text.err")" == *"not an MZ"* ]] || fail "non-mz text"
[[ "$(cat "$WORK/text.err")" == *"$WORK/text.bin"* ]] || fail "non-mz names header"
[[ "$(cat "$WORK/text.err")" != *"$WORK/flat.bin"* ]] || fail "non-mz names flat input"
[[ ! -e "$WORK/bad.exe" ]] || fail "non-mz wrote output"

: > "$WORK/empty.bin"
set +e
"$BIN" "$WORK/empty.bin" >/dev/null 2>"$WORK/empty.err"
empty_rc=$?
set -e
[[ "$empty_rc" -eq 1 ]] || fail "empty exit $empty_rc"

set +e
"$BIN" --header >/dev/null 2>"$WORK/miss.err"
miss_rc=$?
set -e
[[ "$miss_rc" -eq 2 ]] || fail "missing header value exit $miss_rc"

set +e
"$BIN" -o - "$WORK/a.com" "$WORK/b.com" >/dev/null 2>"$WORK/stdout-multi.err"
sm_rc=$?
set -e
[[ "$sm_rc" -eq 2 ]] || fail "stdout multi exit $sm_rc"

set +e
"$BIN" -o "$WORK/unused.exe" >/dev/null 2>"$WORK/noin.err"
noin_rc=$?
set -e
[[ "$noin_rc" -eq 2 ]] || fail "missing input exit $noin_rc"
[[ ! -e "$WORK/unused.exe" ]] || fail "missing input wrote a file"

set +e
"$BIN" --tail "$WORK/flat.bin" >/dev/null 2>"$WORK/tailflag.err"
tailflag_rc=$?
set -e
[[ "$tailflag_rc" -eq 2 ]] || fail "--tail exit $tailflag_rc"
[[ "$(cat "$WORK/tailflag.err")" == *"unknown option"* ]] || fail "--tail text"

printf 'AB' > "$WORK/prefix.bin"
"$BIN" --header "$WORK/flat.exe" -o "$WORK/prefix.exe" "$WORK/prefix.bin" \
    2>"$WORK/prefix.err"
[[ ! -s "$WORK/prefix.err" ]] || fail "matching prefix warned: $(cat "$WORK/prefix.err")"
cmp -s "$WORK/prefix.exe" "$WORK/flat.exe" || fail "tail not equal to original"
"$BIN" "$WORK/prefix.bin" --no-tail --header "$WORK/flat.exe" -o "$WORK/prefix-notail.exe" \
    2>"$WORK/notail.err"
[[ "$(wc -c < "$WORK/prefix-notail.exe")" -eq 34 ]] || fail "no-tail size"
! cmp -s "$WORK/prefix-notail.exe" "$WORK/flat.exe" || fail "no-tail kept the tail"
[[ "$(cat "$WORK/notail.err")" == *"original payload"* ]] || fail "no-tail warning"

python3 - "$WORK" <<'PY'
import pathlib, sys
work = pathlib.Path(sys.argv[1])
hdr = bytearray(32)
hdr[0] = ord("M")
hdr[1] = ord("Z")
hdr[8] = 2
payload = b"P" * 70000
tail = b"T" * 689
(work / "wide.exe").write_bytes(bytes(hdr) + payload + tail)
(work / "wide.bin").write_bytes(payload)
(work / "wide-bad.bin").write_bytes(b"Q" * 70000)
huge = bytearray(32)
huge[0] = ord("M")
huge[1] = ord("Z")
huge[8] = 0x01
huge[9] = 0x10
(work / "huge.hdr").write_bytes(huge)
PY
"$BIN" --header "$WORK/wide.exe" "$WORK/wide.bin" -o "$WORK/wide-out.exe" \
    2>"$WORK/wide.err"
[[ ! -s "$WORK/wide.err" ]] || fail "wide tail warned: $(cat "$WORK/wide.err")"
cmp -s "$WORK/wide.exe" "$WORK/wide-out.exe" || fail "wide tail cmp"
"$BIN" --no-tail --header "$WORK/wide.exe" -o "$WORK/wide-notail.exe" "$WORK/wide.bin" \
    2>"$WORK/wide-notail.err"
[[ "$(cat "$WORK/wide-notail.err")" == *"original payload"* ]] || fail "wide no-tail warning"
wide_orig=$(wc -c < "$WORK/wide.exe")
wide_notail=$(wc -c < "$WORK/wide-notail.exe")
[[ "$wide_notail" -eq $((wide_orig - 689)) ]] || fail "wide no-tail size $wide_notail vs $wide_orig"
"$BIN" --header "$WORK/wide.exe" "$WORK/wide-bad.bin" -o "$WORK/wide-bad.exe" \
    2>"$WORK/wide-bad.err"
[[ "$(cat "$WORK/wide-bad.err")" == *"original payload"* ]] || fail "non-prefix warning"
bad_size=$(wc -c < "$WORK/wide-bad.exe")
[[ "$bad_size" -eq $((32 + 70000)) ]] || fail "non-prefix appended tail size $bad_size"

set +e
"$BIN" --header "$WORK/huge.hdr" -o "$WORK/huge.exe" "$WORK/flat.bin" >/dev/null 2>"$WORK/huge.err"
huge_rc=$?
set -e
[[ "$huge_rc" -eq 1 ]] || fail "oversized header exit $huge_rc"
[[ "$(cat "$WORK/huge.err")" == *"$WORK/huge.hdr"* ]] || fail "oversized names header"
[[ "$(cat "$WORK/huge.err")" == *"65536"* ]] || fail "oversized text"
[[ "$(cat "$WORK/huge.err")" != *"$WORK/flat.bin"* ]] || fail "oversized names flat"
[[ ! -e "$WORK/huge.exe" ]] || fail "oversized wrote output"

printf 'ABCD' > "$WORK/keep.bin"
printf 'OLD' > "$WORK/keep.exe"
set +e
"$BIN" "$WORK/keep.bin" >/dev/null 2>"$WORK/keep.err"
keep_rc=$?
set -e
[[ "$keep_rc" -eq 1 ]] || fail "existing default exit $keep_rc"
[[ "$(cat "$WORK/keep.exe")" == "OLD" ]] || fail "existing default changed"
[[ "$(cat "$WORK/keep.err")" == *"-o"* ]] || fail "existing default text"
"$BIN" -o - "$WORK/keep.bin" > "$WORK/keep-stdout.exe"
"$BIN" "$WORK/keep.bin" -o "$WORK/keep.exe"
cmp -s "$WORK/keep.exe" "$WORK/keep-stdout.exe" || fail "explicit replace bytes"

printf 'SENTINEL' > "$WORK/sentinel"
ln -s sentinel "$WORK/link.exe"
set +e
"$BIN" "$WORK/keep.bin" -o "$WORK/link.exe" >/dev/null 2>"$WORK/link.err"
link_rc=$?
set -e
[[ "$link_rc" -eq 1 ]] || fail "symlink -o exit $link_rc"
[[ -L "$WORK/link.exe" ]] || fail "symlink -o was replaced"
[[ "$(cat "$WORK/sentinel")" == "SENTINEL" ]] || fail "symlink target changed"
[[ "$(cat "$WORK/link.err")" == *"symlink"* ]] || fail "symlink text"

printf 'ok\n'
