// dumpexe.h - MS-DOS binary analysis toolkit
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Orchestration header: includes all modular sub-headers so that dumpexe.cpp
// only needs to include this single file.
//
// Sub-headers:
//   exe.h          — MZ EXE format structures (MZHeader, RelocEntry)
//   registers.h    — 16-bit x86 CPU register state definitions and macros
//   formatting.h   — TDUMP-style hex/dec formatting and hexdump output
//   options.h      — CLI options struct (Options) and show_usage()
//   int_db.h       — Auto-generated constexpr INT annotation database (RBIL)
//   int_annotate.h — annotate_int() and format_int_annotation() helpers
//   disasm.h       — Capstone-backed disassemble() (Capstone required)
//   analysis.h     — File loading, validation, header printing, simulation
//   sys.h          — DOS device driver (.SYS) format structures and constants
//   sys_analysis.h — DOS device driver analysis functions

#ifndef DUMPEXE_H
#define DUMPEXE_H

#include "exe.h"
#include "registers.h"
#include "formatting.h"
#include "options.h"
#include "int_annotate.h"
#include "disasm.h"
#include "analysis.h"
#include "sys.h"
#include "sys_analysis.h"

#endif // DUMPEXE_H
