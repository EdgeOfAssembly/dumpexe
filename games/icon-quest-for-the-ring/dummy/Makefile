# Build ICON dummy COM with UASM
UASM ?= uasm
ICONDIR := ../ICON
MEMDUMPS := $(ICONDIR)/mem_dumps

.PHONY: all clean install install-rt

all: icon_dummy.com

icon_dummy.com: icon_dummy.asm
	$(UASM) -bin -Fo $@ $<

# COM next to game data (FCB opens relative to CWD)
install: icon_dummy.com
	cp -f icon_dummy.com $(ICONDIR)/icon_dummy.com

# Runtime parity tables from latest DOSBox mem dumps (if present)
install-rt:
	@stamps=$$(ls $(MEMDUMPS)/*_stamps_*.bin 2>/dev/null | sort | tail -1); \
	maprt=$$(ls $(MEMDUMPS)/*_map_*.bin 2>/dev/null | sort | tail -1); \
	if [ -n "$$stamps" ] && [ -n "$$maprt" ]; then \
	  cp -f "$$stamps" $(ICONDIR)/STAMPS.BIN; \
	  cp -f "$$maprt" $(ICONDIR)/MAPRT.BIN; \
	  echo "installed $$stamps → STAMPS.BIN"; \
	  echo "installed $$maprt → MAPRT.BIN"; \
	else \
	  echo "no mem_dumps/*stamps* / *map* — run ICON + Ctrl+F11 first"; \
	  exit 1; \
	fi

clean:
	rm -f icon_dummy.com *.ERR *.err
