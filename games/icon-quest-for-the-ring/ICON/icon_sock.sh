# shellcheck shell=bash
# Shared control-socket helpers for ICON automation (no xdotool).
# Source from auto_icon.sh / other scripts:
#   source "$(dirname "$0")/icon_sock.sh"

ICON_SOCK="${DOSBOX_CONTROL_SOCK:-/tmp/dosbox-control.sock}"
ICON_SOCK_PID="${DOSBOX_CONTROL_PID:-/tmp/dosbox-control.pid}"

sock_cmd() {
	# $1 = command line (e.g. "KEY y" or "KEYDOWN down")
	python3 - "$ICON_SOCK" "$1" <<'PY'
import socket, sys
path, line = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(30)
s.connect(path)
# greet
buf = b""
while b"\n" not in buf:
    buf += s.recv(256)
s.sendall((line + "\n").encode())
data = b""
while True:
    chunk = s.recv(8192)
    if not chunk:
        break
    data += chunk
    t = data.decode("utf-8", "replace")
    if t.startswith("OK TEXT") or t.startswith("OK B800"):
        if "\nEND\n" in t or t.endswith("END\n"):
            sys.stdout.write(t)
            break
    elif t.endswith("\n"):
        sys.stdout.write(t)
        break
try:
    s.sendall(b"QUIT\n")
except OSError:
    pass
s.close()
PY
}

sock_wait() {
	# Wait until socket exists and STATUS works
	local i
	for i in $(seq 1 120); do
		if [[ -S "$ICON_SOCK" ]]; then
			if sock_cmd STATUS 2>/dev/null | grep -q '^OK pid='; then
				return 0
			fi
		fi
		sleep 0.25
	done
	return 1
}

sock_key() {
	sock_cmd "KEY $*" >/dev/null
}

sock_keydown() {
	sock_cmd "KEYDOWN $*" >/dev/null
}

sock_keyup() {
	sock_cmd "KEYUP $*" >/dev/null
}

sock_hold() {
	# $1=key $2=hold_ms (default 1100)
	local k="$1" ms="${2:-1100}"
	sock_keydown "$k"
	sleep "$(awk -v m="$ms" 'BEGIN{printf "%.3f", m/1000}')"
	sock_keyup "$k"
}

sock_capture() {
	sock_cmd "CAPTURE ${1:-grouped}" >/dev/null
}

sock_dump_screen() {
	sock_cmd DUMPSCREEN >/dev/null
}

sock_dump_mem() {
	sock_cmd DUMPMEM >/dev/null
}

sock_hostpause() {
	sock_cmd HOSTPAUSE >/dev/null
}

sock_hostunpause() {
	sock_cmd HOSTUNPAUSE >/dev/null
}

sock_overlay() {
	sock_cmd "OVERLAY $*" >/dev/null
}
