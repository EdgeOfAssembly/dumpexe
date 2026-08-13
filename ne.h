// ne.h - Windows 3.x New Executable (NE) format structures
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Pure data definitions for NE (Win16) after the MZ DOS stub.
// All multi-byte fields are little-endian on disk.

#ifndef NE_H
#define NE_H

#include <cstddef>
#include <cstdint>

//=============================================================================
// NE format constants
//=============================================================================

/// NE signature ('NE' little-endian: 0x4E='N', 0x45='E')
inline constexpr uint16_t NE_SIGNATURE = 0x454E;

/// File offset of e_lfanew (DWORD) in the extended MZ header
inline constexpr std::size_t MZ_E_LFANEW_OFF = 0x3C;

/// Minimum bytes needed to read e_lfanew
inline constexpr std::size_t MZ_E_LFANEW_MIN = 0x40;

/// Target OS values (ne_exetyp)
inline constexpr uint8_t NE_EXETYP_UNKNOWN = 0;
inline constexpr uint8_t NE_EXETYP_OS2     = 1;
inline constexpr uint8_t NE_EXETYP_WINDOWS = 2;
inline constexpr uint8_t NE_EXETYP_DOS4    = 3;
inline constexpr uint8_t NE_EXETYP_WIN386  = 4;
inline constexpr uint8_t NE_EXETYP_BOSS    = 5;

/// Segment table entry flags (ne_flags in segment record)
inline constexpr uint16_t NE_SEG_DATA       = 0x0001; ///< 1=DATA, 0=CODE
inline constexpr uint16_t NE_SEG_MOVEABLE   = 0x0010;
inline constexpr uint16_t NE_SEG_PRELOAD    = 0x0040;
inline constexpr uint16_t NE_SEG_RELOCINFO  = 0x0100; ///< has per-segment relocs
inline constexpr uint16_t NE_SEG_DISCARDABLE = 0x1000;

/// Resource type IDs (integer types have high bit set: 0x8000 | id)
inline constexpr uint16_t NE_RT_CURSOR       = 1;
inline constexpr uint16_t NE_RT_BITMAP       = 2;
inline constexpr uint16_t NE_RT_ICON         = 3;
inline constexpr uint16_t NE_RT_MENU         = 4;
inline constexpr uint16_t NE_RT_DIALOG       = 5;
inline constexpr uint16_t NE_RT_STRING       = 6;
inline constexpr uint16_t NE_RT_FONTDIR      = 7;
inline constexpr uint16_t NE_RT_FONT         = 8;
inline constexpr uint16_t NE_RT_ACCELERATOR  = 9;
inline constexpr uint16_t NE_RT_RCDATA       = 10;
inline constexpr uint16_t NE_RT_GROUP_CURSOR = 12;
inline constexpr uint16_t NE_RT_GROUP_ICON   = 14;
inline constexpr uint16_t NE_RT_VERSION      = 16;

//=============================================================================
// Packed on-disk structures
//=============================================================================

#pragma pack(push, 1)

/// NE header (64 bytes). Offsets of tables are relative to the start of this
/// header (file offset = e_lfanew + table_offset), except ne_nrestab which is
/// a file offset.
struct NEHeader {
    uint16_t magic;          ///< 0x00: "NE" (0x454E)
    uint8_t  ver;            ///< 0x02: linker major version
    uint8_t  rev;            ///< 0x03: linker minor version
    uint16_t enttab;         ///< 0x04: entry table offset (from NE header)
    uint16_t cbenttab;       ///< 0x06: entry table length (bytes)
    uint32_t crc;            ///< 0x08: checksum (often 0)
    uint16_t flags;          ///< 0x0C: module flags
    uint16_t autodata;       ///< 0x0E: automatic data segment number (1-based; 0=none)
    uint16_t heap;           ///< 0x10: initial local heap size
    uint16_t stack;          ///< 0x12: initial stack size
    uint16_t ip;             ///< 0x14: initial IP
    uint16_t cs;             ///< 0x16: initial CS (segment index, 1-based)
    uint16_t sp;             ///< 0x18: initial SP
    uint16_t ss;             ///< 0x1A: initial SS (segment index, 1-based)
    uint16_t cseg;           ///< 0x1C: number of entries in segment table
    uint16_t cmod;           ///< 0x1E: number of entries in module-reference table
    uint16_t cbnrestab;      ///< 0x20: bytes in non-resident name table
    uint16_t segtab;         ///< 0x22: segment table offset (from NE header)
    uint16_t rsrctab;        ///< 0x24: resource table offset (from NE header)
    uint16_t restab;         ///< 0x26: resident name table offset
    uint16_t modtab;         ///< 0x28: module-reference table offset
    uint16_t imptab;         ///< 0x2A: imported names table offset
    uint32_t nrestab;        ///< 0x2C: non-resident name table file offset
    uint16_t cmovent;        ///< 0x30: count of movable entries
    uint16_t align;          ///< 0x32: logical sector alignment shift count
    uint16_t cres;           ///< 0x34: number of resource segments
    uint8_t  exetyp;         ///< 0x36: target OS
    uint8_t  flagsothers;    ///< 0x37: additional flags
    uint16_t pretthunks;     ///< 0x38: offset to return thunks (or gangload area)
    uint16_t psegrefbytes;   ///< 0x3A: offset to segment ref bytes
    uint16_t swaparea;       ///< 0x3C: minimum code swap area size
    uint8_t  expver_min;     ///< 0x3E: expected Windows version (minor)
    uint8_t  expver_maj;     ///< 0x3F: expected Windows version (major)
};

/// One segment table entry (8 bytes)
struct NESegment {
    uint16_t sector;     ///< offset of segment data in sectors (<< align)
    uint16_t cbseg;      ///< length of segment in file (0 = 64K)
    uint16_t flags;      ///< NE_SEG_* flags
    uint16_t minalloc;   ///< minimum allocation size (0 = 64K)
};

/// One resource entry within a type (12 bytes)
struct NEResource {
    uint16_t offset;     ///< offset in alignment units from start of file
    uint16_t length;     ///< length in alignment units
    uint16_t flags;
    uint16_t id;         ///< integer id if high bit set, else offset to name
    uint16_t handle;     ///< reserved (runtime)
    uint16_t usage;      ///< reserved (runtime)
};

#pragma pack(pop)

static_assert(sizeof(NEHeader) == 64, "NEHeader must be 64 bytes");
static_assert(sizeof(NESegment) == 8, "NESegment must be 8 bytes");
static_assert(sizeof(NEResource) == 12, "NEResource must be 12 bytes");

#endif // NE_H
