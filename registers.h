// registers.h - 16-bit x86 CPU register state definitions
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Defines the complete register state for a 16-bit x86 CPU used during
// simulation and register tracing. Unions allow accessing 16-bit registers
// and their 8-bit high/low byte components via convenience macros.

#ifndef REGISTERS_H
#define REGISTERS_H

#include <cstdint>

//=============================================================================
// 16-bit x86 CPU Register State
//=============================================================================

/// AX register with byte-level access (AL/AH)
#pragma pack(push,1)
inline union {
    uint16_t value;             ///< 16-bit AX register
    struct {
        uint8_t lo;             ///< AL - low byte
        uint8_t hi;             ///< AH - high byte
    };
} __AX__;
#pragma pack(pop)

#define AX __AX__.value         ///< Access full 16-bit AX register
#define AH __AX__.hi            ///< Access high byte (AH)
#define AL __AX__.lo            ///< Access low byte (AL)

/// BX register with byte-level access (BL/BH)
#pragma pack(push,1)
inline union {
    uint16_t value;             ///< 16-bit BX register
    struct {
        uint8_t lo;             ///< BL - low byte
        uint8_t hi;             ///< BH - high byte
    };
} __BX__;
#pragma pack(pop)

#define BX __BX__.value         ///< Access full 16-bit BX register
#define BH __BX__.hi            ///< Access high byte (BH)
#define BL __BX__.lo            ///< Access low byte (BL)

/// CX register with byte-level access (CL/CH)
#pragma pack(push,1)
inline union {
    uint16_t value;             ///< 16-bit CX register
    struct {
        uint8_t lo;             ///< CL - low byte
        uint8_t hi;             ///< CH - high byte
    };
} __CX__;
#pragma pack(pop)

#define CX __CX__.value         ///< Access full 16-bit CX register
#define CH __CX__.hi            ///< Access high byte (CH)
#define CL __CX__.lo            ///< Access low byte (CL)

/// DX register with byte-level access (DL/DH)
#pragma pack(push,1)
inline union {
    uint16_t value;             ///< 16-bit DX register
    struct {
        uint8_t lo;             ///< DL - low byte
        uint8_t hi;             ///< DH - high byte
    };
} __DX__;
#pragma pack(pop)

#define DX __DX__.value         ///< Access full 16-bit DX register
#define DH __DX__.hi            ///< Access high byte (DH)
#define DL __DX__.lo            ///< Access low byte (DL)

/// Segment registers - 16-bit only, no byte access
inline uint16_t CS = 0;                ///< Code Segment
inline uint16_t DS = 0;                ///< Data Segment
inline uint16_t ES = 0;                ///< Extra Segment
inline uint16_t SS = 0;                ///< Stack Segment

/// Pointer and index registers - 16-bit only
inline uint16_t IP = 0;                ///< Instruction Pointer
inline uint16_t BP = 0;                ///< Base Pointer
inline uint16_t SP = 0;                ///< Stack Pointer
inline uint16_t DI = 0;                ///< Destination Index
inline uint16_t SI = 0;                ///< Source Index

/// CPU FLAGS register with bitfield access
/// The FLAGS register contains status and control bits set by various CPU operations
#pragma pack(push,1)
inline union {
    uint16_t value;             ///< Full 16-bit FLAGS register value
    struct {
        unsigned CF   : 1;      ///< Bit 0: Carry Flag
        unsigned _r1  : 1;      ///< Bit 1: Reserved (always 1)
        unsigned PF   : 1;      ///< Bit 2: Parity Flag
        unsigned _r2  : 1;      ///< Bit 3: Reserved
        unsigned AF   : 1;      ///< Bit 4: Auxiliary Carry Flag
        unsigned _r3  : 1;      ///< Bit 5: Reserved
        unsigned ZF   : 1;      ///< Bit 6: Zero Flag
        unsigned SF   : 1;      ///< Bit 7: Sign Flag
        unsigned TF   : 1;      ///< Bit 8: Trap Flag (single-step)
        unsigned IF   : 1;      ///< Bit 9: Interrupt Enable Flag
        unsigned DF   : 1;      ///< Bit 10: Direction Flag
        unsigned OF   : 1;      ///< Bit 11: Overflow Flag
        unsigned IOPL : 2;      ///< Bits 12-13: I/O Privilege Level (286+)
        unsigned NT   : 1;      ///< Bit 14: Nested Task Flag (286+)
        unsigned _r4  : 1;      ///< Bit 15: Reserved
    };
} __FLAGS__;
#pragma pack(pop)

#define FLAGS __FLAGS__.value   ///< Access full 16-bit FLAGS register
#define CF __FLAGS__.CF         ///< Access Carry Flag
#define PF __FLAGS__.PF         ///< Access Parity Flag
#define AF __FLAGS__.AF         ///< Access Auxiliary Carry Flag
#define ZF __FLAGS__.ZF         ///< Access Zero Flag
#define SF __FLAGS__.SF         ///< Access Sign Flag
#define TF __FLAGS__.TF         ///< Access Trap Flag
#define IF __FLAGS__.IF         ///< Access Interrupt Enable Flag
#define DF __FLAGS__.DF         ///< Access Direction Flag
#define OF __FLAGS__.OF         ///< Access Overflow Flag
#define IOPL __FLAGS__.IOPL     ///< Access I/O Privilege Level
#define NT __FLAGS__.NT         ///< Access Nested Task Flag

#endif // REGISTERS_H
