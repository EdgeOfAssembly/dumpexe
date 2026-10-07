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

all: dumpexe bin2exe

HEADERS = dumpexe.h exe.h registers.h formatting.h options.h int_db.h int_annotate.h disasm.h listing.h cfg.h analysis.h sim.h sim_path.h sys.h sys_analysis.h com.h com_analysis.h ne.h ne_shift.h ne_analysis.h dos_extender.h dx_strings.h pascal_mt.h turbo_pascal.h toolchain.h symbols.h repack.h json_escape.h json_report.h unpack.h unpack_integrate.h

# Deark modules (MIT, Jason Summers). Host glue is unpack_host.c.
# -I so <#include <deark-private.h>> in the modules resolves.
# Function sections let the relocatable bundle drop Deark code the unpack
# call graph never reaches. The final dumpexe link does not use --gc-sections.
DEARK_CFLAGS := -std=gnu99 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-but-set-variable -Wno-unused-variable \
	-Wno-format-truncation -O2 -ffunction-sections -fdata-sections \
	-Ithird_party/deark/src
DEARK_ASAN_CFLAGS := -std=gnu99 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
	-Wno-sign-compare -Wno-unused-but-set-variable -Wno-unused-variable \
	-Wno-format-truncation -O1 -g -fsanitize=address,undefined \
	-ffunction-sections -fdata-sections -Ithird_party/deark/src

DEARK_SRCS := \
	third_party/deark/src/deark-util.c \
	third_party/deark/src/deark-data.c \
	third_party/deark/src/deark-dbuf.c \
	third_party/deark/src/deark-ucstring.c \
	third_party/deark/src/fmtutil.c \
	third_party/deark/src/fmtutil-cmpr.c \
	third_party/deark/src/fmtutil-exe.c \
	third_party/deark/src/fmtutil-huffman.c \
	third_party/deark/src/fmtutil-lzh.c \
	third_party/deark/src/fmtutil-lzw.c \
	third_party/deark/src/fmtutil-lzah.c \
	third_party/deark/modules/exepack.c \
	third_party/deark/modules/lzexe.c \
	third_party/deark/modules/pklite.c \
	third_party/deark/modules/diet.c \
	third_party/deark/modules/lha.c

DEARK_OBJS := $(DEARK_SRCS:.c=.o)
DEARK_ASAN_OBJS := $(DEARK_SRCS:.c=-asan.o)

ne_shift.o: ne_shift.c ne_shift.h
	$(CC) $(CFLAGS_NE) -O2 -c ne_shift.c -o ne_shift.o

ne_shift-asan.o: ne_shift.c ne_shift.h
	$(CC) $(CFLAGS_NE) -O1 -g -fsanitize=address,undefined -c ne_shift.c -o ne_shift-asan.o

sim_path.o: sim_path.c sim_path.h
	$(CC) $(CFLAGS_NE) -O2 -c sim_path.c -o sim_path.o

sim_path-asan.o: sim_path.c sim_path.h
	$(CC) $(CFLAGS_NE) -O1 -g -fsanitize=address,undefined -c sim_path.c -o sim_path-asan.o

third_party/deark/src/%.o: third_party/deark/src/%.c
	$(CC) $(DEARK_CFLAGS) -c $< -o $@

third_party/deark/modules/%.o: third_party/deark/modules/%.c
	$(CC) $(DEARK_CFLAGS) -c $< -o $@

third_party/deark/src/%-asan.o: third_party/deark/src/%.c
	$(CC) $(DEARK_ASAN_CFLAGS) -c $< -o $@

third_party/deark/modules/%-asan.o: third_party/deark/modules/%.c
	$(CC) $(DEARK_ASAN_CFLAGS) -c $< -o $@

unpack_host.o: unpack_host.c unpack.h third_party/deark/src/dx_capture.h
	$(CC) $(DEARK_CFLAGS) -c unpack_host.c -o unpack_host.o

unpack_host-asan.o: unpack_host.c unpack.h third_party/deark/src/dx_capture.h
	$(CC) $(DEARK_ASAN_CFLAGS) -c unpack_host.c -o unpack_host-asan.o

# Relocatable bundle. --gc-sections applies only inside this link, rooted at
# dx_unpack, so unused Deark format helpers are not part of dumpexe.
deark_bundle.o: unpack_host.o $(DEARK_OBJS)
	$(CC) -nostdlib -no-pie -Wl,-r -Wl,--gc-sections -Wl,-u,dx_unpack -Wl,-u,dx_unpack_free \
		-o deark_bundle.o unpack_host.o $(DEARK_OBJS)

deark_bundle-asan.o: unpack_host-asan.o $(DEARK_ASAN_OBJS)
	$(CC) -nostdlib -no-pie -Wl,-r -Wl,--gc-sections -Wl,-u,dx_unpack -Wl,-u,dx_unpack_free \
		-o deark_bundle-asan.o unpack_host-asan.o $(DEARK_ASAN_OBJS)

dumpexe: dumpexe.cpp ne_shift.o sim_path.o deark_bundle.o $(HEADERS)
	$(CXX) $(CXXFLAGS) $(CAPSTONE_CFLAGS) -o dumpexe dumpexe.cpp ne_shift.o sim_path.o deark_bundle.o $(CAPSTONE_LIBS)
	@echo "Built dumpexe with Capstone disassembly support"

# ASan/UBSan cannot link -static. Capstone comes from pkg-config, shared.
dumpexe-asan: dumpexe.cpp ne_shift-asan.o sim_path-asan.o deark_bundle-asan.o $(HEADERS)
	$(CXX) $(ASAN_CXXFLAGS) $(CAPSTONE_CFLAGS) -o dumpexe-asan dumpexe.cpp ne_shift-asan.o sim_path-asan.o deark_bundle-asan.o $(CAPSTONE_LIBS)
	@echo "Built dumpexe-asan (address,undefined)"

asan: dumpexe-asan

# Auto-generate interrupt annotation database from Ralph Brown's Interrupt List
int_db.h: gen_int_db.py $(wildcard interrupts/INTERRUP.*)
	python3 gen_int_db.py

# bin2exe is the sibling that turns a uasm -bin image back into an EXE.
# It does not link Capstone and dumpexe does not exec it.
_PKG_CONFIG_PATH_IN := $(PKG_CONFIG_PATH)
PKG_CONFIG_PATH := $(HOME)/.local/share/pkgconfig:$(HOME)/.local/lib64/pkgconfig:$(HOME)/.local/lib/pkgconfig$(if $(_PKG_CONFIG_PATH_IN),:$(_PKG_CONFIG_PATH_IN),)
export PKG_CONFIG_PATH
CATCH_CFLAGS := $(shell pkg-config --cflags catch2-with-main 2>/dev/null)
CATCH_LIBS   := $(shell pkg-config --libs catch2-with-main 2>/dev/null)
BIN2EXE_INC := -Itools/bin2exe/include
BIN2EXE_TEST_CXXFLAGS := -std=c++23 -Wall -Wextra -O1 -g -fsanitize=address,undefined $(BIN2EXE_INC)

bin2exe: tools/bin2exe/src/main.cpp tools/bin2exe/src/header.cpp tools/bin2exe/src/mz_pages.c \
		tools/bin2exe/include/bin2exe/header.hpp tools/bin2exe/include/bin2exe/mz_pages.h \
		tools/bin2exe/include/bin2exe/version.hpp
	$(CXX) $(CXXFLAGS) $(BIN2EXE_INC) -o bin2exe \
		tools/bin2exe/src/main.cpp tools/bin2exe/src/header.cpp tools/bin2exe/src/mz_pages.c

tools/bin2exe/test_header: tools/bin2exe/tests/test_header.cpp tools/bin2exe/src/header.cpp \
		tools/bin2exe/src/mz_pages.c tools/bin2exe/include/bin2exe/header.hpp \
		tools/bin2exe/include/bin2exe/mz_pages.h
	$(CXX) $(BIN2EXE_TEST_CXXFLAGS) $(CATCH_CFLAGS) -o $@ \
		tools/bin2exe/tests/test_header.cpp tools/bin2exe/src/header.cpp tools/bin2exe/src/mz_pages.c \
		$(CATCH_LIBS) -Wl,-rpath,$(HOME)/.local/lib64

PREFIX ?= /usr/local
install: dumpexe bin2exe
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 755 dumpexe $(DESTDIR)$(PREFIX)/bin/
	install -m 755 bin2exe $(DESTDIR)$(PREFIX)/bin/
	install -m 644 dumpexe.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	install -m 644 tools/bin2exe/bin2exe.1 $(DESTDIR)$(PREFIX)/share/man/man1/

clean:
	rm -f dumpexe dumpexe-asan bin2exe tools/bin2exe/test_header *.o int_db.h \
		unpack_host.o unpack_host-asan.o \
		deark_bundle.o deark_bundle-asan.o $(DEARK_OBJS) $(DEARK_ASAN_OBJS)

.PHONY: test tests verify
test: dumpexe bin2exe tools/bin2exe/test_header
	@bash tests/test_cli_contracts.sh
	@bash tests/test_report_bugs.sh
	@bash tests/test_listing_bugs.sh
	@bash tests/test_uasm.sh
	@bash tests/test_v213.sh
	@bash tests/test_p0_sim.sh
	@bash tests/test_p0_ne.sh
	@bash tests/test_p0_uasm.sh
	@bash tests/test_p0_cfg.sh
	@bash tests/test_p0_reloc.sh
	@bash tests/test_p0_stats.sh
	@bash tests/test_p0_shift.sh
	@bash tests/test_p0_cfg_once.sh
	@bash tests/test_p0_linear.sh
	@./tools/bin2exe/test_header
	@bash tools/bin2exe/tests/test_cli.sh

tests: test

verify: test
	$(HOME)/.local/bin/cbmc ne_shift.c formal/harness_ne_shift.c \
	  --bounds-check --pointer-check --unwind 2 --unwinding-assertions
	$(HOME)/.local/bin/cbmc sim_path.c formal/harness_sim_path.c \
	  --bounds-check --pointer-check --unwind 8 --unwinding-assertions
	$(HOME)/.local/bin/cbmc tools/bin2exe/src/mz_pages.c tools/bin2exe/formal/harness_pages.c \
	  -Itools/bin2exe/include \
	  --bounds-check --pointer-check --unwind 2 --unwinding-assertions
