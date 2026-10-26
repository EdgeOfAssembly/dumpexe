// com.h - MS-DOS .COM file format constants
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Constants for the MS-DOS .COM (plain binary) executable format.
// .COM files are flat 16-bit images.  DOS loads the image at offset 0x100
// within the load segment (after the Program Segment Prefix), sets all
// segment registers to the load segment, and jumps to CS:0100h.
//
// A .COM file on disk normally does NOT contain the PSP — it starts directly
// with the code/data that will reside at memory offset 0x100.  Occasionally
// a .COM is saved as a raw memory dump that includes the 256-byte PSP at
// the beginning; detect_psp() in com_analysis.h handles both cases.

#ifndef COM_H
#define COM_H

#include <cstdint>

//=============================================================================
// MS-DOS .COM Format Constants
//=============================================================================

/// Size of the Program Segment Prefix (PSP) in bytes.
/// DOS creates the PSP at offset 0x000 in the load segment; the .COM image
/// begins at offset 0x100.
inline constexpr uint16_t COM_PSP_SIZE = 0x0100;

/// Memory offset of the .COM entry point relative to the load segment.
/// Regardless of whether a PSP is embedded in the file or not, execution
/// always begins at CS:0100h when the program runs under DOS.
inline constexpr uint16_t COM_ENTRY_IP = 0x0100;

/// Byte offset within the PSP of the INT 20h (terminate) instruction.
/// The first two bytes of a PSP are always {0xCD, 0x20}.
inline constexpr uint16_t COM_PSP_INT20_OFFSET = 0x0000;

/// Byte offset within the PSP of the command-tail length byte.
/// The byte at 0x80 holds the number of characters in the command tail
/// (0–0x7E).  The tail text follows at 0x81, terminated by 0x0D (CR).
inline constexpr uint16_t COM_PSP_CMD_TAIL_OFFSET = 0x0080;

/// Maximum valid command-tail length stored at COM_PSP_CMD_TAIL_OFFSET.
inline constexpr uint8_t COM_PSP_CMD_TAIL_MAX_LEN = 0x7E;

/// Carriage-return (0x0D) terminator expected at the end of the command tail.
inline constexpr uint8_t COM_PSP_CMD_TAIL_CR = 0x0D;

#endif // COM_H
