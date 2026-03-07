# Makefile for dumpexe - MS-DOS MZ EXE Analyzer & Disassembler
# Author: EdgeOfAssembly <haxbox2000@gmail.com>

CXX = g++
CXXFLAGS = -static -static-libstdc++ -no-pie -Wl,--build-id=none -std=c++23 -Wall -Wextra -O2

HAS_CAPSTONE := $(shell pkg-config --exists capstone && echo 1 || echo 0)

ifeq ($(HAS_CAPSTONE),1)
CAPSTONE_CFLAGS := $(shell pkg-config --cflags capstone)
CAPSTONE_LIBS := $(shell pkg-config --libs capstone)
else
CAPSTONE_CFLAGS :=
CAPSTONE_LIBS :=
endif

.PHONY: all clean install

all: dumpexe

HEADERS = dumpexe.h exe.h registers.h format.h options.h disasm.h analysis.h

dumpexe: dumpexe.cpp $(HEADERS)
ifeq ($(HAS_CAPSTONE),1)
	$(CXX) $(CXXFLAGS) $(CAPSTONE_CFLAGS) -o dumpexe dumpexe.cpp $(CAPSTONE_LIBS)
	@echo "Built dumpexe WITH Capstone disassembly support"
else
	$(CXX) $(CXXFLAGS) -o dumpexe dumpexe.cpp
	@echo "Built dumpexe WITHOUT Capstone (install libcapstone-dev for disassembly)"
endif

dumpexe-nocap: dumpexe.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -o dumpexe dumpexe.cpp

PREFIX ?= /usr/local
install: dumpexe
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 755 dumpexe $(DESTDIR)$(PREFIX)/bin/
	install -m 644 dumpexe.1 $(DESTDIR)$(PREFIX)/share/man/man1/

clean:
	rm -f dumpexe *.o
