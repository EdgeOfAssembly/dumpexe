# Build ICON dummy COM with UASM
UASM ?= uasm

.PHONY: all clean install

all: icon_dummy.com

icon_dummy.com: icon_dummy.asm
	$(UASM) -bin -Fo $@ $<

# Copy next to game data so FCB opens find BA.DAT / LA.MAP
install: icon_dummy.com
	cp -f icon_dummy.com ../ICON/icon_dummy.com

clean:
	rm -f icon_dummy.com *.ERR *.err
