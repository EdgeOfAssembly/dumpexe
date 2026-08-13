# Makefile for dumpexe - MS-DOS MZ / Win16 NE Analyzer & Disassembler
# Note: needs libstdc++ with <format> (g++-13+). CUDA host stays gcc-12 via gcc-config.
# Author: EdgeOfAssembly <haxbox2000@gmail.com>
#
# Capstone disassembly support is MANDATORY.
# Install it before building: sudo apt-get install libcapstone-dev
#
# Default: silent parallel-friendly flags when invoked as
#   make -s V=0 -j$(nproc)

# Prefer g++-15+ for <format> when present (host gcc may stay 12 for CUDA).
CXX ?= g++
ifneq ($(shell command -v g++-15 2>/dev/null),)
CXX := g++-15
endif
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

HEADERS = dumpexe.h exe.h registers.h formatting.h options.h int_db.h int_annotate.h disasm.h listing.h cfg.h analysis.h sim.h sys.h sys_analysis.h com.h com_analysis.h ne.h ne_analysis.h dos_extender.h strings.h pascal_mt.h turbo_pascal.h toolchain.h symbols.h repack.h json_report.h

dumpexe: dumpexe.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(CAPSTONE_CFLAGS) -o dumpexe dumpexe.cpp $(CAPSTONE_LIBS)
	@echo "Built dumpexe with Capstone disassembly support"

# Auto-generate interrupt annotation database from Ralph Brown's Interrupt List
int_db.h: gen_int_db.py $(wildcard interrupts/INTERRUP.*)
	python3 gen_int_db.py

PREFIX ?= /usr/local
install: dumpexe
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 755 dumpexe $(DESTDIR)$(PREFIX)/bin/
	install -m 644 dumpexe.1 $(DESTDIR)$(PREFIX)/share/man/man1/

clean:
	rm -f dumpexe *.o int_db.h

.PHONY: test tests verify
test: dumpexe
	@bash tests/test_cli_contracts.sh

tests: test

verify: test
	@echo "formal: not run (no CBMC harness for dumpexe yet)"
