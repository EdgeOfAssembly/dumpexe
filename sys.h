// sys.h - MS-DOS Device Driver (.SYS) format structures and constants
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Pure data definitions: packed struct for the DOS device driver header,
// attribute bit constants, and known block device signature table.

#ifndef SYS_H
#define SYS_H

#include <cstdint>
#include <string_view>
#include <array>

//=============================================================================
// MS-DOS Device Driver Header Structure (18 bytes)
// Reference: Ralph Brown's Interrupt List, INT 21/AH=52h
//=============================================================================

#pragma pack(push,1)
struct SYSHeader {
    uint32_t next_driver;    ///< 0x00: Pointer to next driver; 0xFFFFFFFF = last in chain
    uint16_t attributes;     ///< 0x04: Device attributes bitfield
    uint16_t strategy;       ///< 0x06: Strategy entry point (offset from start of driver)
    uint16_t interrupt;      ///< 0x08: Interrupt entry point (offset from start of driver)
    union {
        char name[8];        ///< 0x0A: Character device: blank-padded device name
        struct {
            uint8_t num_units;   ///< 0x0A: Block device: number of subunits (drives)
            char signature[7];   ///< 0x0B: Block device: optional driver signature
        } block;
    };
};
#pragma pack(pop)

static_assert(sizeof(SYSHeader) == 18, "SYSHeader must be exactly 18 bytes");

//=============================================================================
// Device Attribute Bit Masks
//=============================================================================

/// Bit 15: Set = character device, Clear = block device
inline constexpr uint16_t SYS_ATTR_CHAR_DEVICE       = 0x8000;

// --- Character device bits (bit 15 = 1) ---
/// Bit 14: IOCTL supported
inline constexpr uint16_t SYS_ATTR_IOCTL              = 0x4000;
/// Bit 13 (char): Output until busy supported (DOS 3.0+)
inline constexpr uint16_t SYS_ATTR_CHAR_OUTPUT_BUSY   = 0x2000;
/// Bit 11: OPEN/CLOSE/RemovableMedia supported (DOS 3.0+)
inline constexpr uint16_t SYS_ATTR_OPEN_CLOSE         = 0x0800;
/// Bit 7: Generic IOCTL check supported (DOS 5.0+)
inline constexpr uint16_t SYS_ATTR_IOCTL_CHECK        = 0x0080;
/// Bit 6: Generic IOCTL supported (DOS 3.2+)
inline constexpr uint16_t SYS_ATTR_GENERIC_IOCTL      = 0x0040;
/// Bit 4: Special device (INT 29 fast console output)
inline constexpr uint16_t SYS_ATTR_SPECIAL            = 0x0010;
/// Bit 3: CLOCK$ device
inline constexpr uint16_t SYS_ATTR_CLOCK              = 0x0008;
/// Bit 2: NUL device
inline constexpr uint16_t SYS_ATTR_NUL                = 0x0004;
/// Bit 1: Standard output
inline constexpr uint16_t SYS_ATTR_STDOUT             = 0x0002;
/// Bit 0: Standard input
inline constexpr uint16_t SYS_ATTR_STDIN              = 0x0001;

// --- Block device bits (bit 15 = 0) ---
/// Bit 13 (block): Non-IBM format
inline constexpr uint16_t SYS_ATTR_NON_IBM            = 0x2000;
/// Bit 12: Network device (remote)
inline constexpr uint16_t SYS_ATTR_NETWORK            = 0x1000;
/// Bit 1 (block): 32-bit sector addressing (DOS 3.31+)
inline constexpr uint16_t SYS_ATTR_32BIT_SECTOR       = 0x0002;

//=============================================================================
// Known Block Device Driver Signatures (offset 0x0B, 7 bytes)
//=============================================================================

struct KnownSignature {
    std::string_view sig;   ///< 7-byte signature (may contain spaces)
    std::string_view desc;  ///< Human-readable description
};

inline constexpr std::array<KnownSignature, 7> KNOWN_SIGNATURES = {{
    { "$PCMATA", "PCMCIA driver PCMATA.SYS"                    },
    { "AHADDVR", "Adaptec SCSI disk driver ASPIDISK.SYS"       },
    { "DBLSPAC", "MS DoubleSpace or DriveSpace"                 },
    { "DSKREET", "NortonUtils v5+ Diskreet"                     },
    { "GFS    ", "LapLink III device driver DD.BIN"             },
    { "STAC-CD", "Stacker/Stacker Anywhere"                     },
    { "SIDExxx", "PCMCIA driver ATADRV.EXE"                    },
}};

#endif // SYS_H
