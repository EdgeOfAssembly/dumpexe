# ICON dummy staged loader (UASM)
UASM ?= uasm
ICONDIR := ../ICON
MEMDUMPS := $(ICONDIR)/mem_dumps
SCREENS := $(ICONDIR)/screen_dumps
MAX_FRAMES ?= 8

.PHONY: all clean install install-rt install-intro install-title-frames \
	install-ani-frames clean-dumps

all: icon_dummy.com

icon_dummy.com: icon_dummy.asm
	$(UASM) -bin -Fo $@ $<

install: icon_dummy.com
	cp -f icon_dummy.com $(ICONDIR)/icon_dummy.com

install-rt:
	@stamps=$$(ls $(MEMDUMPS)/*_stamps_*.bin 2>/dev/null | sort | tail -1); \
	maprt=$$(ls $(MEMDUMPS)/*_map_*.bin 2>/dev/null | sort | tail -1); \
	if [ -n "$$stamps" ] && [ -n "$$maprt" ]; then \
	  cp -f "$$stamps" $(ICONDIR)/STAMPS.BIN; \
	  cp -f "$$maprt" $(ICONDIR)/MAPRT.BIN; \
	  echo "STAMPS.BIN <- $$stamps"; \
	  echo "MAPRT.BIN  <- $$maprt"; \
	else \
	  echo "no mem_dumps — run ICON + Ctrl+F11 on overworld first"; exit 1; \
	fi

clean-dumps:
	rm -f $(SCREENS)/*
	@echo "emptied $(SCREENS)"

# Concatenate all hotkey dumps (sorted by name/seq) into one multi-frame file.
# Each frame = first 2000 bytes of the dump. Max MAX_FRAMES frames.
define PACK_HOTKEY_FRAMES
	mkdir -p $(SCREENS); \
	metas=$$(for m in $(SCREENS)/*.meta; do \
	  [ -f "$$m" ] || continue; \
	  grep -q '^reason=hotkey$$' "$$m" 2>/dev/null || continue; \
	  echo "$$m"; \
	done | sort); \
	if [ -z "$$metas" ]; then \
	  echo "no hotkey dumps in $(SCREENS)"; \
	  echo "  make clean-dumps && run ICON.EXE && spam Ctrl+F10, then re-run this target"; \
	  exit 1; \
	fi; \
	out="$(1)"; rm -f "$$out"; n=0; \
	for m in $$metas; do \
	  [ "$$n" -ge $(MAX_FRAMES) ] && break; \
	  b=$${m%.meta}.bin; \
	  dd if="$$b" bs=2000 count=1 status=none >> "$$out"; \
	  n=$$((n+1)); \
	  echo "  frame $$n <- $$b"; \
	done; \
	echo "wrote $$out ($$n frames, $$((n*2000)) bytes)"
endef

# Title ring animation: clean-dumps, ICON, spam F10 on title, quit, then:
install-title-frames:
	@$(call PACK_HOTKEY_FRAMES,$(ICONDIR)/TITLES.BIN)
	@# also keep first frame as TITLE.BIN for tools that expect it
	@dd if=$(ICONDIR)/TITLES.BIN of=$(ICONDIR)/TITLE.BIN bs=2000 count=1 status=none
	@echo "TITLE.BIN = frame 1 of TITLES.BIN"

# Particle animation: clean-dumps, ICON, ESC title, spam F10 on ani, quit:
install-ani-frames:
	@$(call PACK_HOTKEY_FRAMES,$(ICONDIR)/ANIS.BIN)
	@dd if=$(ICONDIR)/ANIS.BIN of=$(ICONDIR)/ANI.BIN bs=2000 count=1 status=none
	@echo "ANI.BIN = frame 1 of ANIS.BIN"

# Legacy: first hotkey TITLE, second ANI (single frames each)
install-intro:
	@mkdir -p $(SCREENS)
	@metas=$$(for m in $(SCREENS)/*.meta; do \
	  [ -f "$$m" ] || continue; \
	  grep -q '^reason=hotkey$$' "$$m" 2>/dev/null || continue; \
	  echo "$$m"; \
	done | sort); \
	n=$$(echo "$$metas" | grep -c . 2>/dev/null || echo 0); \
	if [ -z "$$metas" ] || [ "$$n" -lt 1 ]; then \
	  echo "need >=1 hotkey dump; prefer install-title-frames / install-ani-frames"; exit 1; \
	fi; \
	t=$$(echo "$$metas" | sed -n '1p'); \
	tb=$${t%.meta}.bin; \
	dd if="$$tb" of=$(ICONDIR)/TITLE.BIN bs=2000 count=1 status=none; \
	cp -f $(ICONDIR)/TITLE.BIN $(ICONDIR)/TITLES.BIN; \
	echo "TITLE.BIN/TITLES.BIN <- $$tb"; \
	if [ "$$n" -ge 2 ]; then \
	  a=$$(echo "$$metas" | sed -n '2p'); ab=$${a%.meta}.bin; \
	  dd if="$$ab" of=$(ICONDIR)/ANI.BIN bs=2000 count=1 status=none; \
	  cp -f $(ICONDIR)/ANI.BIN $(ICONDIR)/ANIS.BIN; \
	  echo "ANI.BIN/ANIS.BIN <- $$ab"; \
	fi

clean:
	rm -f icon_dummy.com *.ERR *.err *.lst
