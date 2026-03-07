// exe.h - MS-DOS MZ EXE format structures
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Pure data definitions: packed structs for the MZ EXE header and relocation
// table entries. No functions, no register state, no formatting.

#ifndef EXE_H
#define EXE_H

#include <cstdint>

//=============================================================================
// MS-DOS MZ EXE Format Constants
//=============================================================================

/// MZ executable signature ('MZ' in little-endian: 0x4D='M', 0x5A='Z')
inline constexpr uint16_t MZ_SIGNATURE = 0x5A4D;

//=============================================================================
// MS-DOS MZ EXE Format Structures
//=============================================================================

/// Packed MZ EXE header structure (28 bytes minimum)
/// This structure represents the standard MS-DOS executable format header.
/// All multi-byte fields are stored in little-endian byte order.
#pragma pack(push,1)
struct MZHeader {
    uint16_t signature;         ///< 0x00: "MZ" signature (0x5A4D in little-endian)
    uint16_t final_len;         ///< 0x02: Bytes in last 512-byte page (0 = full page)
    uint16_t num_blocks;        ///< 0x04: Number of 512-byte pages in file
    uint16_t num_reloc;         ///< 0x06: Number of relocation entries
    uint16_t header_size;       ///< 0x08: Header size in 16-byte paragraphs
    uint16_t mem_extra;         ///< 0x0A: Minimum extra memory needed (paragraphs)
    uint16_t mem_max;           ///< 0x0C: Maximum extra memory wanted (paragraphs, 0xFFFF = all)
    int16_t  ss;                ///< 0x0E: Initial SS register value (relative to load segment)
    uint16_t sp;                ///< 0x10: Initial SP register value
    uint16_t checksum;          ///< 0x12: File checksum (rarely used)
    uint16_t ip;                ///< 0x14: Initial IP register value (entry point offset)
    int16_t  cs;                ///< 0x16: Initial CS register value (relative to load segment)
    uint16_t off_reloc;         ///< 0x18: File offset to relocation table
    uint16_t overlay_index;     ///< 0x1A: Overlay number (0 for main program)
};
#pragma pack(pop)

/// Relocation table entry (4 bytes)
/// Each entry specifies a location in the image that needs to be adjusted
/// by adding the actual load segment when the program is loaded into memory.
#pragma pack(push,1)
struct RelocEntry {
    uint16_t offset;            ///< Offset within segment
    uint16_t segment;           ///< Segment value (relative to start of image)
};
#pragma pack(pop)

#endif // EXE_H
