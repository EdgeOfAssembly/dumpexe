// dumpexe.h - MS-DOS MZ EXE header analysis toolkit
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Orchestration header: includes all modular sub-headers so that dumpexe.cpp
// only needs to include this single file.
//
// Sub-headers:
//   exe.h       — MZ EXE format structures (MZHeader, RelocEntry)
//   registers.h — 16-bit x86 CPU register state definitions and macros
//   format.h    — TDUMP-style hex/dec formatting and hexdump output
//   options.h   — CLI options struct (Options) and show_usage()
//   disasm.h    — Capstone-backed disassemble() (Capstone required)
//   analysis.h  — File loading, validation, header printing, simulation

#ifndef DUMPEXE_H
#define DUMPEXE_H

#include "exe.h"
#include "registers.h"
#include "format.h"
#include "options.h"
#include "disasm.h"
#include "analysis.h"

#endif // DUMPEXE_H
