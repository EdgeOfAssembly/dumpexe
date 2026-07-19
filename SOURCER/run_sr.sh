#!/usr/bin/env bash
# Batch Sourcer 8.01 (V Communications) under DOSBox Staging.
# DEF files MUST use DOS CRLF line endings.
#
#   ./run_sr.sh help          # sr -? > LOKI.TXT
#   ./run_sr.sh icon          # ICON.EXE -> ICON.LST
#   ./run_sr.sh icon0|icon1|icon2
#   ./run_sr.sh all
#
# Flags: -n (no direct screen) -x (no display). Needs Go in .DEF.
# Outputs: SOURCER/*.LST *.SDF and games/.../sourcer-out/

set -euo pipefail
SR_DIR="$(cd "$(dirname "$0")" && pwd)"
ICON_SRC="${ICON_SRC:-$SR_DIR/../games/icon-quest-for-the-ring/ICON}"
OUT_HOST="${OUT_HOST:-$SR_DIR/../games/icon-quest-for-the-ring/sourcer-out}"
CYCLES="${CYCLES:-80000}"
TIMEOUT="${TIMEOUT:-300}"

log() { printf '[run_sr] %s\n' "$*" >&2; }
need() { command -v "$1" >/dev/null || { log "missing $1"; exit 1; }; }
need dosbox
mkdir -p "$OUT_HOST"

sync_bins() {
	local f
	for f in ICON.EXE ICON0.OVL ICON1.OVL ICON2.OVL; do
		[[ -f "$ICON_SRC/$f" ]] && cp -f "$ICON_SRC/$f" "$SR_DIR/$f"
	done
}

run_one() {
	local base="$1"  # ICON / ICON0 / ICON1 / ICON2
	local def="${base}.DEF"
	[[ -f "$SR_DIR/$def" ]] || { log "missing $def"; return 1; }
	log "sr $def -n -x  (cycles fixed $CYCLES)"
	rm -f "$SR_DIR/${base}.LST" "$SR_DIR/${base}.SDF" "$SR_DIR/${base}.ASM"
	(
		cd "$SR_DIR"
		timeout "$TIMEOUT" dosbox . \
			-c "cycles fixed $CYCLES" \
			-c "sr $def -n -x" \
			-c "exit" \
			>"/tmp/run_sr_${base}.log" 2>&1 || log "dosbox rc=$?"
	)
	pkill -x dosbox 2>/dev/null || true
	sleep 0.4
	if [[ -f "$SR_DIR/${base}.LST" ]]; then
		cp -f "$SR_DIR/${base}.LST" "$OUT_HOST/"
		[[ -f "$SR_DIR/${base}.SDF" ]] && cp -f "$SR_DIR/${base}.SDF" "$OUT_HOST/"
		log "OK $OUT_HOST/${base}.LST ($(wc -c < "$SR_DIR/${base}.LST") bytes, $(wc -l < "$SR_DIR/${base}.LST") lines)"
	else
		log "FAIL: no ${base}.LST — see /tmp/run_sr_${base}.log"
		return 1
	fi
}

cmd_help() {
	rm -f "$SR_DIR/LOKI.TXT"
	(
		cd "$SR_DIR"
		timeout 20 dosbox . -c "sr -? 2>&1 > loki.txt" -c "exit" >/tmp/run_sr_help.log 2>&1 || true
	)
	pkill -x dosbox 2>/dev/null || true
	[[ -f "$SR_DIR/LOKI.TXT" ]] && { cp -f "$SR_DIR/LOKI.TXT" "$OUT_HOST/"; cat "$SR_DIR/LOKI.TXT"; }
}

main() {
	sync_bins
	case "${1:-icon}" in
		help) cmd_help ;;
		icon|ICON) run_one ICON ;;
		icon0|ICON0) run_one ICON0 ;;
		icon1|ICON1) run_one ICON1 ;;
		icon2|ICON2) run_one ICON2 ;;
		all)
			for x in ICON ICON0 ICON1 ICON2; do run_one "$x" || true; done
			;;
		*) log "usage: $0 [icon|icon0|icon1|icon2|all|help]"; exit 1 ;;
	esac
}
main "$@"
