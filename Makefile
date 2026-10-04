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
# Honor a command-line or environment CXX=. g++-15 is only substituted when
# make's built-in CXX is still the default (origin "default").
ifeq ($(origin CXX),default)
ifneq ($(shell command -v g++-15 2>/dev/null),)
CXX := g++-15
endif
endif
CXX ?= g++
CC ?= gcc
CXXFLAGS = -static -static-libstdc++ -no-pie -Wl,--build-id=none -std=c++23 -Wall -Wextra -O2
# Separate non-static sanitizer binary. Do not fold these into CXXFLAGS.
ASAN_CXXFLAGS = -std=c++23 -Wall -Wextra -O1 -g -fsanitize=address,undefined
# NE shift is C23 so the same translation unit is what CBMC verifies.
CFLAGS_NE = -std=c23 -Wall -Wextra

# Capstone is a hard requirement for compiling — checked only when building,
# not for `make clean` or `make install` which don't need the library headers.
ifeq ($(filter clean install,$(MAKECMDGOALS)),)
ifeq ($(shell pkg-config --exists capstone && echo 1 || echo 0),0)
$(error Capstone library not found. Install it with: sudo apt-get install libcapstone-dev)
endif
endif

CAPSTONE_CFLAGS := $(shell pkg-config --cflags capstone 2>/dev/null)
CAPSTONE_LIBS   := $(shell pkg-config --libs capstone 2>/dev/null)

.PHONY: all clean install asan

all: dumpexe

HEADERS = dumpexe.h exe.h registers.h formatting.h options.h int_db.h int_annotate.h disasm.h listing.h cfg.h analysis.h sim.h sys.h sys_analysis.h com.h com_analysis.h ne.h ne_shift.h ne_analysis.h dos_extender.h strings.h pascal_mt.h turbo_pascal.h toolchain.h symbols.h repack.h json_escape.h json_report.h

ne_shift.o: ne_shift.c ne_shift.h
	$(CC) $(CFLAGS_NE) -O2 -c ne_shift.c -o ne_shift.o

ne_shift-asan.o: ne_shift.c ne_shift.h
	$(CC) $(CFLAGS_NE) -O1 -g -fsanitize=address,undefined -c ne_shift.c -o ne_shift-asan.o

dumpexe: dumpexe.cpp ne_shift.o $(HEADERS)
	$(CXX) $(CXXFLAGS) $(CAPSTONE_CFLAGS) -o dumpexe dumpexe.cpp ne_shift.o $(CAPSTONE_LIBS)
	@echo "Built dumpexe with Capstone disassembly support"

# ASan/UBSan cannot link -static. Capstone comes from pkg-config, shared.
dumpexe-asan: dumpexe.cpp ne_shift-asan.o $(HEADERS)
	$(CXX) $(ASAN_CXXFLAGS) $(CAPSTONE_CFLAGS) -o dumpexe-asan dumpexe.cpp ne_shift-asan.o $(CAPSTONE_LIBS)
	@echo "Built dumpexe-asan (address,undefined)"

asan: dumpexe-asan

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
	rm -f dumpexe dumpexe-asan *.o int_db.h

.PHONY: test tests verify
test: dumpexe
	@bash tests/test_cli_contracts.sh
	@bash tests/test_report_bugs.sh
	@bash tests/test_listing_bugs.sh

tests: test

verify: test
	$(HOME)/.local/bin/cbmc ne_shift.c formal/harness_ne_shift.c \
	  --bounds-check --pointer-check --unwind 2 --unwinding-assertions
