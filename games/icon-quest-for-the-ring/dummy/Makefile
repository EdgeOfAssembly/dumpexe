# ICON dummy staged loader (UASM)
UASM ?= uasm
ICONDIR := ../ICON
MEMDUMPS := $(ICONDIR)/mem_dumps
SCREENS := $(ICONDIR)/screen_dumps

.PHONY: all clean install install-rt install-intro

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

# Seed intro pages from earliest mode-01 dumps (often mid-paint).
# Prefer replacing with Ctrl+F10 captures of start.png / animation.png screens.
install-intro:
	@d1=$$(ls $(SCREENS)/ICON_g*_m01_*_0001.bin 2>/dev/null | sort | head -1); \
	d2=$$(ls $(SCREENS)/ICON_g*_m01_*_0002.bin 2>/dev/null | sort | head -1); \
	if [ -n "$$d1" ]; then \
	  dd if="$$d1" of=$(ICONDIR)/TITLE.BIN bs=2000 count=1 status=none; \
	  echo "TITLE.BIN <- $$d1 (trim 2000B) — re-dump on full title if incomplete"; \
	else echo "no m01 0001 dump for TITLE.BIN"; fi; \
	if [ -n "$$d2" ]; then \
	  dd if="$$d2" of=$(ICONDIR)/ANI.BIN bs=2000 count=1 status=none; \
	  echo "ANI.BIN   <- $$d2 (trim 2000B) — re-dump on animation screen"; \
	else echo "no m01 0002 dump for ANI.BIN"; fi

clean:
	rm -f icon_dummy.com *.ERR *.err *.lst
