# ICON dummy staged loader (UASM)
UASM ?= uasm
ICONDIR := ../ICON
MEMDUMPS := $(ICONDIR)/mem_dumps
SCREENS := $(ICONDIR)/screen_dumps

.PHONY: all clean install install-rt install-intro clean-dumps

all: icon_dummy.com

icon_dummy.com: icon_dummy.asm
	$(UASM) -bin -Fo $@ $<

install: icon_dummy.com
	cp -f icon_dummy.com $(ICONDIR)/icon_dummy.com

# Runtime terrain tables (Ctrl+F11 mem dumps)
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

# Wipe screen_dumps so the next ICON run only has what you capture.
clean-dumps:
	rm -f $(SCREENS)/*
	@echo "emptied $(SCREENS)"

# After a clean dir: start ICON.EXE → Ctrl+F10 on title → ESC → Ctrl+F10 on ani.
# Uses only dumps whose .meta says reason=hotkey (ignores auto mode-set dumps).
# First hotkey → TITLE.BIN, second → ANI.BIN. No timestamp hunting.
install-intro:
	@mkdir -p $(SCREENS)
	@metas=$$(for m in $(SCREENS)/*.meta; do \
	  [ -f "$$m" ] || continue; \
	  grep -q '^reason=hotkey$$' "$$m" 2>/dev/null || continue; \
	  echo "$$m"; \
	done | sort); \
	n=$$(echo "$$metas" | grep -c . 2>/dev/null || echo 0); \
	if [ -z "$$metas" ] || [ "$$n" -lt 2 ]; then \
	  echo "need >=2 hotkey dumps in $(SCREENS) (found $$n)."; \
	  echo "1) make clean-dumps"; \
	  echo "2) ICON.EXE → Ctrl+F10 on title → ESC → Ctrl+F10 on animation"; \
	  echo "3) make install-intro"; \
	  exit 1; \
	fi; \
	t=$$(echo "$$metas" | sed -n '1p'); \
	a=$$(echo "$$metas" | sed -n '2p'); \
	tb=$${t%.meta}.bin; \
	ab=$${a%.meta}.bin; \
	dd if="$$tb" of=$(ICONDIR)/TITLE.BIN bs=2000 count=1 status=none; \
	dd if="$$ab" of=$(ICONDIR)/ANI.BIN bs=2000 count=1 status=none; \
	echo "TITLE.BIN <- $$tb"; \
	echo "ANI.BIN   <- $$ab"

clean:
	rm -f icon_dummy.com *.ERR *.err *.lst
