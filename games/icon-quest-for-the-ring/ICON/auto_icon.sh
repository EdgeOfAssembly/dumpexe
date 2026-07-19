#!/usr/bin/env bash
# Automate ICON.EXE under DOSBox Staging via [controlsocket] — no xdotool.
# Usage (from anywhere):
#   ./auto_icon.sh title-frames    # spam DUMPSCREEN on title ring -> TITLES.BIN
#   ./auto_icon.sh ani-frames      # ESC title, spam dumps on particles -> ANIS.BIN
#   ./auto_icon.sh intro-singles   # one dump title, ESC, one dump ani
#   ./auto_icon.sh to-play         # answer startup prompts → overworld (+ dumps)
#   ./auto_icon.sh damage-capture  # to-play + wander/attack + shots/dumps
#   ./auto_icon.sh kill            # stop DOSBox (socket or SIGTERM)
#
# Requires: dosbox, python3; fork with controlsocket (no xdotool/DISPLAY needed for keys)
# Prefer: ./live_agent.py for new work. This script is the socket port of the old path.
# Prompt strings + Y/N defaults: STARTUP-PROMPTS.md
#   ADVANCED=y   → answer advanced game with Y
#   STORY_SPACES=40  → more Space for legend / "SPACE BAR to continue"
#   ESC_GAP=1.5      → delay between title Esc and ani Esc
#   QUIT=0       → leave DOSBox running in play
#   WANDER=1 WANDER_STEPS=40 MOVE_GAP=0.2
#   GET_SWORD=1 SWORD_SOUTH_STEPS=6  → Down×6 then P (level A sword; default 6)
#   MEM_DUMP=0 SCREEN_DUMP=0
#   PNG_SHOT=1 (default) → CAPTURE grouped PNGs → capture/ + filmstrip/
# Title + ani skip with Esc only (two Esc presses); story uses Space.

set -euo pipefail

ICON_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=icon_sock.sh
source "$ICON_DIR/icon_sock.sh"
DUMMY_DIR="$(cd "$ICON_DIR/../dummy" && pwd)"
CONF="$ICON_DIR/dosbox-staging.conf"
AUTO_CONF="$ICON_DIR/dosbox-auto.conf"
CAPTURE_DIR="${CAPTURE_DIR:-$ICON_DIR/capture}"
# ICON intros are slow at 3000; automation defaults much higher.
CYCLES="${CYCLES:-100000}"
TITLE_FRAMES="${TITLE_FRAMES:-8}"
ANI_FRAMES="${ANI_FRAMES:-8}"
FRAME_GAP="${FRAME_GAP:-0.25}"   # host seconds between dumps
BOOT_WAIT="${BOOT_WAIT:-2.0}"    # after socket ready, before first keys
ANI_WAIT="${ANI_WAIT:-4.0}"      # after ESC title, wait for particle intro
PNG_SHOT="${PNG_SHOT:-1}"        # 1 = Staging CAPTURE PNGs
FILMSTRIP_DIR=""                 # set by session_begin
SHOT_N=0

# Logs on stderr so `w=$(start_icon)` only gets a token on stdout.
log() { printf '[auto_icon] %s\n' "$*" >&2; }

# New session filmstrip dir under capture/
session_begin() {
	mkdir -p "$CAPTURE_DIR"
	FILMSTRIP_DIR="$CAPTURE_DIR/filmstrip_$(date +%Y%m%d_%H%M%S)"
	mkdir -p "$FILMSTRIP_DIR"
	SHOT_N=0
	# marker so we only copy PNGs newer than session start
	: >"$FILMSTRIP_DIR/.session_start"
	log "filmstrip -> $FILMSTRIP_DIR (Staging capture_dir=$CAPTURE_DIR)"
}

# Staging PNG via control socket CAPTURE (no xdotool / no window focus).
shot_png() {
	local tag="${1:-shot}"
	[[ "${PNG_SHOT}" == "1" ]] || return 0
	SHOT_N=$((SHOT_N + 1))
	local n
	n=$(printf '%04d' "$SHOT_N")

	sock_capture grouped || true
	sleep 0.15
	sock_capture rendered || true
	sleep 0.25
	# Harvest newest PNGs from capture/ into filmstrip with tag
	if [[ -n "$FILMSTRIP_DIR" && -d "$CAPTURE_DIR" ]]; then
		local f newest
		# shellcheck disable=SC2012
		newest=$(ls -t "$CAPTURE_DIR"/*.png 2>/dev/null | head -8 || true)
		for f in $newest; do
			[[ -f "$f" ]] || continue
			if [[ -f "$FILMSTRIP_DIR/.session_start" && "$f" -nt "$FILMSTRIP_DIR/.session_start" ]]; then
				local base
				base=$(basename "$f")
				if [[ ! -f "$FILMSTRIP_DIR/${n}_${tag}_${base}" ]]; then
					cp -n "$f" "$FILMSTRIP_DIR/${n}_${tag}_${base}" 2>/dev/null || \
						cp "$f" "$FILMSTRIP_DIR/${n}_${tag}_${base}"
				fi
			fi
		done
	fi
	log "png shot #$SHOT_N tag=$tag"
}

need() {
	command -v "$1" >/dev/null || { log "missing: $1"; exit 1; }
}

need dosbox
need python3

# Title becomes "ICON.EXE - ..." so name search for DOSBox fails after start.
# DOSBox pids from pidfile or pgrep
#
dosbox_pids() {
	local p=""
	if [[ -f /tmp/auto_icon_dosbox.pid ]]; then
		p=$(cat /tmp/auto_icon_dosbox.pid 2>/dev/null || true)
		if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
			echo "$p"
			return 0
		fi
	fi
	if [[ -f "${ICON_SOCK_PID:-/tmp/dosbox-control.pid}" ]]; then
		p=$(cat "${ICON_SOCK_PID:-/tmp/dosbox-control.pid}" 2>/dev/null || true)
		if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
			echo "$p"
			return 0
		fi
	fi
	pgrep -x dosbox 2>/dev/null || pgrep -x dosbox-staging 2>/dev/null || true
}

# No window focus needed — keys go through the control socket.
activate() { return 0; }
settle_focus() { return 0; }
find_wid() { echo "socket"; }

# Map old xdotool key names → control-socket key names
_sock_keyname() {
	case "$1" in
		Escape|Esc|escape) echo esc ;;
		Return|Enter) echo enter ;;
		space|Space|KP_Space) echo space ;;
		Down|KP_Down|KP_2|2) echo down ;;
		Up|KP_Up|KP_8|8) echo up ;;
		Left|KP_Left|KP_4|4) echo left ;;
		Right|KP_Right|KP_6|6) echo right ;;
		*) echo "$1" ;;
	esac
}

# $1 wid optional (ignored) — rest are key names
press() {
	shift || true
	local k
	for k in "$@"; do
		sock_key "$(_sock_keyname "$k")"
		sleep 0.05
	done
}

# One movement step: hold via socket. Usage: move_step "$w" Down KP_2 2
move_step() {
	shift # ignore wid
	local k hold_ms
	hold_ms=$(awk -v s="${KEY_HOLD:-1.1}" 'BEGIN{printf "%d", s*1000}')
	# Prefer first named direction
	for k in "$@"; do
		case "$k" in
			Down|KP_Down|KP_2|2|Up|KP_Up|KP_8|8|Left|KP_Left|KP_4|4|Right|KP_Right|KP_6|6)
				sock_hold "$(_sock_keyname "$k")" "$hold_ms"
				sleep "${MOVE_GAP:-0.45}"
				return 0
				;;
		esac
	done
	# fallback first arg
	sock_hold "$(_sock_keyname "${1:-down}")" "$hold_ms"
	sleep "${MOVE_GAP:-0.45}"
}

dump_f10() {
	sock_dump_screen
}

dump_f11() {
	sock_dump_mem
}

shutdown_f9() {
	local pid
	# Prefer graceful: no guest Ctrl+F9 needed; SIGTERM DOSBox
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
	pid=$(cat "${ICON_SOCK_PID:-/tmp/dosbox-control.pid}" 2>/dev/null || true)
	if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		sleep 0.3
		kill -9 "$pid" 2>/dev/null || true
	fi
	rm -f "${ICON_SOCK:-/tmp/dosbox-control.sock}" "${ICON_SOCK_PID:-/tmp/dosbox-control.pid}" 2>/dev/null || true
}

start_icon() {
	shutdown_f9 || true
	sleep 0.4

	cd "$ICON_DIR"
	# Note: callers must run session_begin in the *parent* shell.
	log "starting dosbox cycles=fixed $CYCLES in $ICON_DIR (control socket)"
	dosbox --conf "$CONF" --conf "$AUTO_CONF" . \
		-c "cycles fixed $CYCLES" \
		-c "ICON.EXE" \
		-exit \
		>/tmp/auto_icon_dosbox.log 2>&1 &
	echo $! >/tmp/auto_icon_dosbox.pid
	log "pid=$(cat /tmp/auto_icon_dosbox.pid) log=/tmp/auto_icon_dosbox.log"

	if ! sock_wait; then
		log "control socket not ready ($ICON_SOCK)"
		return 1
	fi
	sock_overlay on || true
	sleep "${BOOT_WAIT:-1.5}"
	log "ready via $ICON_SOCK status=$(sock_cmd STATUS | tr -d '\n' | head -c 80)"
	echo "socket"
}

cmd_title_frames() {
	log "=== capture title multi-frame (early+dense F10 while ring draws) ==="
	rm -f "$ICON_DIR/screen_dumps"/*
	# Dump ASAP after focus — progressive paint is early, not after settle idle
	BOOT_WAIT="${BOOT_WAIT:-0.15}"
	FRAME_GAP="${FRAME_GAP:-0.12}"
	TITLE_FRAMES="${TITLE_FRAMES:-16}"
	session_begin
	local w
	w=$(start_icon)
	shot_png "title0"
	local i
	for i in $(seq 1 "$TITLE_FRAMES"); do
		log "title dump $i/$TITLE_FRAMES"
		dump_f10 "$w"
		shot_png "title_$i"
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
	log "=== capture ani multi-frame (cycles=$CYCLES; dump while intro runs) ==="
	rm -f "$ICON_DIR/screen_dumps"/*
	CYCLES="${CYCLES:-100000}"
	BOOT_WAIT="${BOOT_WAIT:-0.8}"
	FRAME_GAP="${FRAME_GAP:-0.15}"
	ANI_FRAMES="${ANI_FRAMES:-16}"
	# Brief pause so title is up, then ESC and dump immediately (do not idle 5s)
	local w
	w=$(start_icon)
	sleep 0.6
	press "$w" Escape
	log "dumping during particle intro (FRAME_GAP=${FRAME_GAP}s x ${ANI_FRAMES})"
	settle_focus || true
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

# Answer one Y/N (see STARTUP-PROMPTS.md). $2 = y or n
answer_yn() {
	local w="$1" key="$2"
	press "$w" "$key"
	sleep "${YN_GAP:-0.9}"
}

# Spam Space for story + "Press the SPACE BAR to continue" (NOT for title/ani)
press_spaces() {
	local w="$1" n="${2:-24}"
	local i
	for i in $(seq 1 "$n"); do
		press "$w" space
		sleep "${SPACE_GAP:-0.35}"
	done
}

# Title + intro animation: each needs Esc (see STARTUP-PROMPTS.md)
skip_title_and_ani() {
	local w="$1"
	log "Esc #1: skip TITLE (not Space)"
	press "$w" Escape
	sleep "${ESC_GAP:-1.2}"
	log "Esc #2: skip ANI / intro animation (not Space)"
	press "$w" Escape
	sleep "${ESC_GAP:-1.5}"
}

# Skip intros/menus to overworld; optional mem dump (Ctrl+F11)
# Prompt table: STARTUP-PROMPTS.md (defaults are NOT all N — some are Y!)
cmd_to_play() {
	log "=== to-play (answers from STARTUP-PROMPTS.md) ==="
	session_begin
	local w
	# start_icon echos wid only; session state must stay in this shell
	w=$(start_icon)
	shot_png "boot"

	# 1) "Is this an IBM PC Jr" — default Y → need N on normal PC
	log "YN: IBM PC Jr? -> n (default is Y)"
	answer_yn "$w" n
	sleep 0.5

	# 2-3) title + animation — Esc each (Space does not skip these)
	skip_title_and_ani "$w"
	shot_png "after_intros"

	# 4) "Do you want to restart a saved game" — default N
	log "YN: restart saved? -> n"
	answer_yn "$w" n

	# 5) "Do you want to play an advanced game" — default N (set ADVANCED=y for Y)
	if [[ "${ADVANCED:-n}" == "y" || "${ADVANCED:-n}" == "Y" ]]; then
		log "YN: advanced? -> y"
		answer_yn "$w" y
	else
		log "YN: advanced? -> n"
		answer_yn "$w" n
	fi

	# 6) Story pages + any "Press the SPACE BAR to continue"
	log "Space x ${STORY_SPACES:-28} (story / SPACE BAR to continue)"
	press_spaces "$w" "${STORY_SPACES:-28}"
	sleep 1.0

	# 7) "Do you want to use the joystick" — default Y → need N for keys
	log "YN: joystick? -> n (default is Y)"
	answer_yn "$w" n
	sleep 2.0
	shot_png "overworld"

	# overworld — dumps
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

	# Optional: wander + attack + periodic F10 (hurt/death capture)
	if [[ "${WANDER:-0}" == "1" ]]; then
		cmd_wander_dumps "$w"
	fi

	shot_png "pre_quit"

	# Quit: "Do you want to quit" default N → Y; "save this game" default Y → N
	if [[ "${QUIT:-1}" == "1" ]]; then
		log "quit: Esc, Y quit, N save"
		press "$w" Escape
		sleep 1.0
		answer_yn "$w" y
		answer_yn "$w" n
		sleep 0.5
	fi
	shutdown_f9
	wait "$(cat /tmp/auto_icon_dosbox.pid)" 2>/dev/null || true
	# index filmstrip
	if [[ -n "$FILMSTRIP_DIR" && -d "$FILMSTRIP_DIR" ]]; then
		local npc
		npc=$(find "$FILMSTRIP_DIR" -maxdepth 1 -name '*.png' 2>/dev/null | wc -l)
		log "done — filmstrip $npc PNGs in $FILMSTRIP_DIR"
		ls -lt "$FILMSTRIP_DIR"/*.png 2>/dev/null | head -12 >&2 || true
	fi
	log "done (see capture/ filmstrip, screen_dumps/, mem_dumps/)"
}

# After overworld: optional sword grab, then wander/attack + F10 dumps.
# F1 help: arrows/keypad move; P = pick up; Space = attack.
cmd_wander_dumps() {
	local w="$1"
	local n="${WANDER_STEPS:-40}"
	local i dirs

	# Level A: sword is 6 steps south of spawn — walk Down then P (ASCII 50h).
	# ICON1 @4B4F: cmp ax,50h → call sub_135 pick-up. 'p' alone may not match.
	# Observed: arm-reach can play without item if not on/adjacent to object tile.
	if [[ "${GET_SWORD:-1}" == "1" ]]; then
		local south="${SWORD_SOUTH_STEPS:-6}"
		log "sword: south x${south} then uppercase P (no Space/attack during grab)"
		sleep 1.2
		settle_focus || true
		local s
		for s in $(seq 1 "$south"); do
			log "sword: step $s/$south south"
			move_step "$w" Down KP_Down KP_2 2
			shot_png "south_$s"
			# Try P on last 3 steps (user: in front vs on top both seen)
			if [[ "$s" -ge $((south - 2)) ]]; then
				sleep 0.35
				log "sword: P attempt after step $s"
				# uppercase only (je on ax==50h)
				press "$w" P
				sleep 0.55
				press "$w" P
				sleep 0.45
				shot_png "pickup_try_$s"
				dump_f10 "$w"
				sleep 0.2
			fi
		done
		# Extra: one more south + P, then P spam while standing still
		log "sword: +1 south and stand still P"
		move_step "$w" Down KP_2 2
		shot_png "south_extra"
		sleep 0.6
		local pi
		for pi in 1 2 3 4 5; do
			press "$w" P
			sleep 0.5
		done
		shot_png "after_pickup"
		dump_f10 "$w"
		sleep 0.25
		log "sword: pick-up sequence done (look for man-front-weapon / no ground sword)"
	fi

	# F1 help shows keypad-style 8 directions + arrows
	log "wander ${n} steps (rats roam here) + Space attack; PNG every step"
	for i in $(seq 1 "$n"); do
		# Prefer keypad (F1 layout); also arrows
		case $(( (i - 1) % 8 )) in
			0) move_step "$w" Down KP_2 2 ;;
			1) move_step "$w" Left KP_4 4 ;;
			2) move_step "$w" Right KP_6 6 ;;
			3) move_step "$w" Up KP_8 8 ;;
			4) move_step "$w" Down KP_2 2 ;;
			5) move_step "$w" Right KP_6 6 ;;
			6) move_step "$w" Down KP_2 2 ;;
			7) move_step "$w" Left KP_4 4 ;;
		esac
		if (( i % 2 == 0 )); then
			press "$w" space
			sleep 0.12
		fi
		shot_png "wander_$i"
		# B800 less often (can steal focus / drop keys)
		if (( i % 4 == 0 )); then
			log "wander B800 dump step $i"
			dump_f10 "$w"
			sleep 0.15
		fi
	done
	# Burst shots at end — catch brief hurt flash (bat → yellow triangle)
	log "end burst PNG + F10 (hurt flash)"
	local bi
	for bi in 1 2 3 4 5 6; do
		shot_png "end_$bi"
		dump_f10 "$w"
		sleep 0.12
	done
	dump_f11 "$w" || true
	sleep 0.3
	log "wander done"
}

# Full path: to-play without quit, wander for damage, then leave DOSBox running or quit
cmd_damage_capture() {
	log "=== damage-capture: to-play + wander dumps ==="
	export QUIT=0
	export WANDER=1
	export SCREEN_DUMP=1
	export MEM_DUMP=1
	cmd_to_play
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
		to-play)         cmd_to_play ;;
		damage-capture)  cmd_damage_capture ;;
		kill)            shutdown_f9 ;;
		help|-h|--help|"") usage ;;
		*) log "unknown: $cmd"; usage; exit 1 ;;
	esac
}

main "$@"
