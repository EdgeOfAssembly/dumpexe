#!/usr/bin/env bash
# Automate ICON.EXE under DOSBox Staging with xdotool.
# Usage (from anywhere):
#   ./auto_icon.sh title-frames    # spam Ctrl+F10 on title ring -> TITLES.BIN
#   ./auto_icon.sh ani-frames      # ESC title, spam F10 on particles -> ANIS.BIN
#   ./auto_icon.sh intro-singles   # one F10 title, ESC, one F10 ani
#   ./auto_icon.sh to-play         # skip intros/menus to overworld, F11 mem dump
#   ./auto_icon.sh kill            # Ctrl+F9 shutdown any DOSBox
#
# Requires: dosbox, xdotool, DISPLAY
# Gameplay key sequence from /tmp/ICON_gameplay.txt

set -euo pipefail

ICON_DIR="$(cd "$(dirname "$0")" && pwd)"
DUMMY_DIR="$(cd "$ICON_DIR/../dummy" && pwd)"
CONF="$ICON_DIR/dosbox-staging.conf"
AUTO_CONF="$ICON_DIR/dosbox-auto.conf"
CYCLES="${CYCLES:-20000}"
TITLE_FRAMES="${TITLE_FRAMES:-8}"
ANI_FRAMES="${ANI_FRAMES:-6}"
FRAME_GAP="${FRAME_GAP:-0.35}"   # seconds between Ctrl+F10
BOOT_WAIT="${BOOT_WAIT:-2.5}"    # wait after launch for title

# Logs on stderr so `w=$(start_icon)` only gets the window id on stdout.
log() { printf '[auto_icon] %s\n' "$*" >&2; }

need() {
	command -v "$1" >/dev/null || { log "missing: $1"; exit 1; }
}

need dosbox
need xdotool
[[ -n "${DISPLAY:-}" ]] || { log "DISPLAY not set"; exit 1; }

# Title becomes "ICON.EXE - ..." so name search for DOSBox fails after start.
# Prefer: pgrep dosbox -> xdotool search --pid $pid windowmap windowactivate --sync
dosbox_pids() {
	local p=""
	if [[ -f /tmp/auto_icon_dosbox.pid ]]; then
		p=$(cat /tmp/auto_icon_dosbox.pid 2>/dev/null || true)
		if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
			echo "$p"
			return 0
		fi
	fi
	pgrep -x dosbox 2>/dev/null || pgrep -x dosbox-staging 2>/dev/null || true
}

find_wid() {
	local p w=""
	for p in $(dosbox_pids); do
		# May return several client windows; take last (usually the toplevel)
		w=$(xdotool search --pid "$p" 2>/dev/null | tail -1 || true)
		if [[ -n "$w" ]]; then
			echo "$w"
			return 0
		fi
	done
	# Last resort: class / name (works before ICON rewrites the title)
	w=$(xdotool search --class dosbox-staging 2>/dev/null | tail -1 || true)
	[[ -z "$w" ]] && w=$(xdotool search --class dosbox 2>/dev/null | tail -1 || true)
	[[ -z "$w" ]] && w=$(xdotool search --name 'DOSBox' 2>/dev/null | tail -1 || true)
	[[ -z "$w" ]] && w=$(xdotool search --name 'ICON' 2>/dev/null | tail -1 || true)
	echo "$w"
}

wait_wid() {
	local i=0 w=""
	while [[ $i -lt 60 ]]; do
		w=$(find_wid)
		if [[ -n "$w" ]]; then
			log "window id=$w pid(s)=$(dosbox_pids | tr '\n' ' ')"
			echo "$w"
			return 0
		fi
		sleep 0.2
		i=$((i + 1))
	done
	log "no DOSBox window (pgrep dosbox / xdotool search --pid)"
	return 1
}

# Like feh chain, but PID-based (title rename safe):
#   xdotool search --pid $pid windowmap windowactivate --sync key ...
dosbox_xdo() {
	local p
	p=$(dosbox_pids | head -1)
	if [[ -n "$p" ]]; then
		if xdotool search --pid "$p" windowmap windowactivate --sync "$@" 2>/dev/null; then
			return 0
		fi
	fi
	local w
	w=$(find_wid)
	if [[ -n "$w" ]]; then
		xdotool windowmap "$w" windowactivate --sync "$w" "$@" 2>/dev/null
		return $?
	fi
	log "dosbox_xdo: no window (pids: $(dosbox_pids | tr '\n' ' '))"
	return 1
}

# Focus + click center so SDL grabs keyboard.
activate() {
	local w geo X Y WIDTH HEIGHT cx cy
	w=$(find_wid)
	[[ -z "$w" ]] && return 1
	xdotool windowmap "$w" windowactivate --sync "$w" 2>/dev/null || true
	geo=$(xdotool getwindowgeometry --shell "$w" 2>/dev/null || true)
	if [[ -n "$geo" ]]; then
		# shellcheck disable=SC2086
		eval "$geo"
		cx=$((X + WIDTH / 2))
		cy=$((Y + HEIGHT / 2))
		xdotool mousemove --sync "$cx" "$cy" click 1 2>/dev/null || true
		xdotool windowmap "$w" windowactivate --sync "$w" 2>/dev/null || true
	fi
	sleep 0.1
}

# $1 wid optional — always re-resolve via pgrep/pid
press() {
	shift || true
	activate || true
	dosbox_xdo key --clearmodifiers --delay 60 "$@"
}

dump_f10() {
	activate || true
	dosbox_xdo key --clearmodifiers ctrl+F10
}

dump_f11() {
	activate || true
	dosbox_xdo key --clearmodifiers ctrl+F11
}

shutdown_f9() {
	local pid
	if [[ -n "$(find_wid)" ]]; then
		log "Ctrl+F9 shutdown (windowmap+activate+key)"
		dosbox_xdo key --clearmodifiers ctrl+F9 2>/dev/null || true
		sleep 0.8
	fi
	if [[ -f /tmp/auto_icon_dosbox.pid ]]; then
		pid=$(cat /tmp/auto_icon_dosbox.pid)
		if kill -0 "$pid" 2>/dev/null; then
			log "SIGTERM pid=$pid"
			kill "$pid" 2>/dev/null || true
			sleep 0.5
			kill -9 "$pid" 2>/dev/null || true
		fi
		rm -f /tmp/auto_icon_dosbox.pid
	fi
}

start_icon() {
	shutdown_f9 || true
	sleep 0.4

	cd "$ICON_DIR"
	log "starting dosbox cycles=fixed $CYCLES in $ICON_DIR"
	dosbox --conf "$CONF" --conf "$AUTO_CONF" . \
		-c "cycles fixed $CYCLES" \
		-c "ICON.EXE" \
		-exit \
		>/tmp/auto_icon_dosbox.log 2>&1 &
	echo $! >/tmp/auto_icon_dosbox.pid
	log "pid=$(cat /tmp/auto_icon_dosbox.pid) log=/tmp/auto_icon_dosbox.log"

	local w
	w=$(wait_wid)
	log "window id=$w"
	activate "$w"
	sleep "$BOOT_WAIT"
	echo "$w"
}

cmd_title_frames() {
	log "=== capture title multi-frame (spam Ctrl+F10) ==="
	rm -f "$ICON_DIR/screen_dumps"/*
	# Dump early while ring may still be drawing
	BOOT_WAIT="${BOOT_WAIT:-1.0}"
	FRAME_GAP="${FRAME_GAP:-0.25}"
	local w
	w=$(start_icon)
	local i
	for i in $(seq 1 "$TITLE_FRAMES"); do
		log "title dump $i/$TITLE_FRAMES"
		dump_f10 "$w"
		sleep "$FRAME_GAP"
	done
	press "$w" Escape
	sleep 0.3
	press "$w" Escape
	sleep 0.3
	shutdown_f9
	local pid=""
	[[ -f /tmp/auto_icon_dosbox.pid ]] && pid=$(cat /tmp/auto_icon_dosbox.pid)
	[[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
	(cd "$DUMMY_DIR" && make install-title-frames)
	log "done -> $ICON_DIR/TITLES.BIN"
	log "hotkeys: $(rg -l 'reason=hotkey' "$ICON_DIR/screen_dumps"/*.meta 2>/dev/null | wc -l)"
}

cmd_ani_frames() {
	log "=== capture ani multi-frame ==="
	rm -f "$ICON_DIR/screen_dumps"/*
	BOOT_WAIT="${BOOT_WAIT:-1.2}"
	FRAME_GAP="${FRAME_GAP:-0.3}"
	local w
	w=$(start_icon)
	# skip title — give ring a moment then ESC
	sleep 1.5
	press "$w" Escape
	sleep 1.5
	local i
	for i in $(seq 1 "$ANI_FRAMES"); do
		log "ani dump $i/$ANI_FRAMES"
		dump_f10 "$w"
		sleep "$FRAME_GAP"
	done
	press "$w" Escape
	sleep 0.3
	shutdown_f9
	local pid=""
	[[ -f /tmp/auto_icon_dosbox.pid ]] && pid=$(cat /tmp/auto_icon_dosbox.pid)
	[[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
	(cd "$DUMMY_DIR" && make install-ani-frames)
	log "done -> $ICON_DIR/ANIS.BIN"
	log "hotkeys: $(rg -l 'reason=hotkey' "$ICON_DIR/screen_dumps"/*.meta 2>/dev/null | wc -l)"
}

cmd_intro_singles() {
	log "=== single title + single ani hotkey ==="
	rm -f "$ICON_DIR/screen_dumps"/*
	local w
	w=$(start_icon)
	sleep 0.8
	dump_f10 "$w"
	sleep 0.5
	press "$w" Escape
	sleep 1.0
	dump_f10 "$w"
	sleep 0.3
	press "$w" Escape
	sleep 0.3
	shutdown_f9
	wait "$(cat /tmp/auto_icon_dosbox.pid)" 2>/dev/null || true
	(cd "$DUMMY_DIR" && make install-intro)
}

# Skip intros/menus to overworld; optional mem dump (Ctrl+F11)
cmd_to_play() {
	log "=== skip to overworld (ICON_gameplay.txt steps 2-7) ==="
	local w
	w=$(start_icon)
	# 2-3 intros
	sleep 0.8
	press "$w" Escape
	sleep 1.2
	press "$w" Escape
	sleep 1.5
	# 4 restart saved? N
	press "$w" n
	sleep 1.0
	# 5 advanced? N
	press "$w" n
	sleep 2.0
	# 6 story space
	press "$w" space
	sleep 1.5
	# 7 quit? N
	press "$w" n
	sleep 3.0
	# overworld — mem dump if requested
	if [[ "${MEM_DUMP:-1}" == "1" ]]; then
		log "Ctrl+F11 mem dump"
		dump_f11 "$w"
		sleep 0.5
	fi
	if [[ "${SCREEN_DUMP:-1}" == "1" ]]; then
		log "Ctrl+F10 screen dump"
		dump_f10 "$w"
		sleep 0.3
	fi
	# quit path: ESC, Y quit, N no save
	if [[ "${QUIT:-1}" == "1" ]]; then
		press "$w" Escape
		sleep 1.0
		press "$w" y
		sleep 1.0
		press "$w" n
		sleep 1.0
	fi
	shutdown_f9
	wait "$(cat /tmp/auto_icon_dosbox.pid)" 2>/dev/null || true
	log "done (see screen_dumps/ mem_dumps/)"
}

usage() {
	sed -n '2,12p' "$0" | tr -d '#'
}

main() {
	local cmd="${1:-}"
	case "$cmd" in
		title-frames) cmd_title_frames ;;
		ani-frames)   cmd_ani_frames ;;
		intro-singles) cmd_intro_singles ;;
		to-play)      cmd_to_play ;;
		kill)         shutdown_f9 ;;
		help|-h|--help|"") usage ;;
		*) log "unknown: $cmd"; usage; exit 1 ;;
	esac
}

main "$@"
