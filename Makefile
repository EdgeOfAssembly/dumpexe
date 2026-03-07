# Makefile for dumpexe - MS-DOS MZ EXE Analyzer & Disassembler
# Author: EdgeOfAssembly <haxbox2000@gmail.com>
#
# Capstone disassembly support is MANDATORY.
# Install it before building: sudo apt-get install libcapstone-dev

CXX = g++
CXXFLAGS = -static -static-libstdc++ -no-pie -Wl,--build-id=none -std=c++23 -Wall -Wextra -O2

# Capstone is a hard requirement for compiling — checked only when building,
# not for `make clean` or `make install` which don't need the library headers.
ifeq ($(filter clean install,$(MAKECMDGOALS)),)
ifeq ($(shell pkg-config --exists capstone && echo 1 || echo 0),0)
$(error Capstone library not found. Install it with: sudo apt-get install libcapstone-dev)
endif
endif

CAPSTONE_CFLAGS := $(shell pkg-config --cflags capstone 2>/dev/null)
CAPSTONE_LIBS   := $(shell pkg-config --libs capstone 2>/dev/null)

.PHONY: all clean install

all: dumpexe

HEADERS = dumpexe.h exe.h registers.h format.h options.h disasm.h analysis.h

dumpexe: dumpexe.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(CAPSTONE_CFLAGS) -o dumpexe dumpexe.cpp $(CAPSTONE_LIBS)
	@echo "Built dumpexe with Capstone disassembly support"

PREFIX ?= /usr/local
install: dumpexe
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 755 dumpexe $(DESTDIR)$(PREFIX)/bin/
	install -m 644 dumpexe.1 $(DESTDIR)$(PREFIX)/share/man/man1/

clean:
	rm -f dumpexe *.o
