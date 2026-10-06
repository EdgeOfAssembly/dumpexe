// com_analysis.h - MS-DOS .COM file analysis functions
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Provides PSP heuristic detection and full analysis output for MS-DOS .COM
// (plain binary) files.  Follows the same conventions as sys_analysis.h:
// all helpers are static inline, use formatting.h for TDUMP-style output,
// and accept the shared Options struct.
//
// PSP detection background
// ------------------------
// DOS loads a .COM file by:
//   1. Allocating a memory segment, building a 256-byte PSP at offset 0x000.
//   2. Copying the .COM *file* to offset 0x100 inside that segment.
//   3. Setting CS = DS = ES = SS = load segment, SP = 0xFFFE, IP = 0x100.
//   4. Jumping to CS:0100h.
//
// Therefore a typical .COM file on disk starts with the code/data that
// will sit at memory offset 0x100 — it does NOT include the PSP.  However,
// some .COM files are saved as raw memory snapshots that begin with the PSP
// (making the code start at file offset 0x100 rather than 0x000).
//
// detect_psp() uses two quick sanity checks to distinguish these cases:
//   • Check 1 – INT 20h marker: file[0x00]==0xCD && file[0x01]==0x20.
//     The first two bytes of every real PSP are the INT 20h instruction.
//   • Check 2 – Command-tail plausibility: len = file[0x80], len <= 0x7E,
//     and file[0x81 + len] == 0x0D (CR terminator).
// Both checks must pass before we declare a PSP present.  If the file is
// shorter than 256 bytes it cannot contain a PSP.

#ifndef COM_ANALYSIS_H
#define COM_ANALYSIS_H

#include <iostream>
#include <format>
#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>

#include "com.h"
#include "formatting.h"
#include "options.h"
#include "disasm.h"
#include "cfg.h"
#include "registers.h"
#include "analysis.h"   // trace_comment(), reg_get(), reg_set(), reg_fmt()

//=============================================================================
// PSP Heuristic Detection
//=============================================================================

/// Detect whether a .COM file begins with an embedded Program Segment Prefix.
///
/// Returns true only when BOTH of the following hold:
///   1. The first two bytes are 0xCD 0x20 (INT 20h — the canonical PSP start).
///   2. The command-tail at offset 0x80 is plausible: length byte <= 0x7E
///      and the byte at 0x81 + length equals 0x0D (carriage return).
///
/// If either check fails the function returns false (no PSP embedded).
/// A file shorter than COM_PSP_SIZE (256 bytes) automatically returns false.
///
/// @param data Full file contents as a byte vector.
/// @return true if an embedded PSP is detected, false otherwise.
static inline bool detect_psp(const std::vector<uint8_t>& data) {
    // A full PSP is 256 bytes; a shorter file cannot contain one.
    if (data.size() < COM_PSP_SIZE) return false;

    // Check 1: PSP always begins with INT 20h (0xCD 0x20).
    if (data[COM_PSP_INT20_OFFSET]     != 0xCD) return false;
    if (data[COM_PSP_INT20_OFFSET + 1] != 0x20) return false;

    // Check 2: Command-tail structure at offset 0x80.
    //   • data[0x80] is the length of the command tail (0 to 0x7E).
    //   • The character at data[0x81 + length] must be 0x0D (CR).
    uint8_t tail_len = data[COM_PSP_CMD_TAIL_OFFSET];
    if (tail_len > COM_PSP_CMD_TAIL_MAX_LEN) return false;

    // Ensure the CR byte is still within the buffer.
    size_t cr_offset = static_cast<size_t>(COM_PSP_CMD_TAIL_OFFSET) + 1 + tail_len;
    if (cr_offset >= data.size()) return false;
    if (data[cr_offset] != COM_PSP_CMD_TAIL_CR) return false;

    return true;
}

//=============================================================================
// COM Header / Info Printing
//=============================================================================

/// Print .COM file summary information in TDUMP style.
///
/// @param opts         Parsed CLI options (filename for display).
/// @param fileSize     Total file size in bytes.
/// @param has_psp      Whether an embedded PSP was detected (or forced).
/// @param entry_offset File offset of the entry point (0x000 or 0x100).
static inline void print_com_info(const Options& opts,
                                  int64_t fileSize,
                                  bool has_psp,
                                  size_t entry_offset) {
    std::cout << "Display of File " << opts.filename << "\n\n";

    std::cout << std::format("{:<50}{}\n", "File Format", ".COM (flat binary, 16-bit MS-DOS)");
    print_field("File Size", static_cast<uint32_t>(fileSize), 5);

    if (has_psp) {
        std::cout << std::format("{:<50}{}\n", "Load Model",
                                 "PSP embedded in file (entry at file offset 0100h)");
    } else {
        std::cout << std::format("{:<50}{}\n", "Load Model",
                                 "No PSP in file (code starts at file offset 0000h)");
    }

    print_field("Entry Point File Offset", static_cast<uint32_t>(entry_offset), 4);

    // In memory, CS:IP = load_segment:0100h for all .COM programs.
    std::cout << std::format("\n{:<50}{:04X}:{:04X}\n",
                             "Program Entry Point (CS:IP)",
                             opts.loadBase, COM_ENTRY_IP);

    // Stack: DOS sets SP to 0xFFFE, pointing to segment top minus two bytes.
    std::cout << std::format("{:<50}{:04X}:{:04X}\n",
                             "Initial Stack (SS:SP)",
                             opts.loadBase, uint16_t{0xFFFE});

    // DS, ES, SS all equal the load segment at startup.
    std::cout << std::format("{:<50}{:04X}h\n", "DS = ES = SS = CS", opts.loadBase);
}

//=============================================================================
// COM Simulation
//=============================================================================

/// Execute a .COM under the real-mode simulator (in-memory guest files only).
///
/// @param opts         Parsed CLI options.
/// @param data         Full file contents.
/// @param entry_offset File byte offset where code begins (0x000 or 0x100).
static inline void run_com_simulation(const Options& opts,
                                      const std::vector<uint8_t>& data,
                                      size_t entry_offset) {
    std::cout << "\n========================================\n";
    std::cout << "=== DOS LOAD SIMULATION (.COM) ===\n";
    std::cout << "========================================\n";
    std::cout << "Note: Guest file I/O stays inside the simulator "
                 "and does not read or write the host.\n";

    if (entry_offset > data.size()) {
        std::cout << "Simulation skipped: entry offset ("
                  << entry_offset << ") is beyond file size ("
                  << data.size() << ").\n";
        return;
    }

    Options opts_mut = opts;
    sim_run_com(opts_mut, data, entry_offset);
}

//=============================================================================
// Listing image (org 0100h)
//=============================================================================

/**
 * @brief Build the CS-relative image used for a .COM listing.
 *
 * With no embedded PSP, file byte 0 is DOS IP 0100h. The returned image is
 * prefixed with a 256-byte hole so instruction addresses and labels match the
 * header's CS:IP (1000:0100), not file offset 0. An embedded PSP is already a
 * segment image and is copied unchanged.
 *
 * @param data    File bytes.
 * @param has_psp True when the file begins with a PSP.
 * @param out     Image whose index equals the DOS IP. Cleared and replaced.
 */
static inline void com_listing_image(const std::vector<uint8_t>& data,
                                     bool has_psp,
                                     std::vector<uint8_t>& out)
{
    if (has_psp)
    {
        out = data;
        return;
    }
    out.assign(static_cast<size_t>(COM_PSP_SIZE) + data.size(), 0);
    if (!data.empty())
    {
        std::memcpy(out.data() + COM_PSP_SIZE, data.data(), data.size());
    }
}

//=============================================================================
// Main COM Analysis Entry Point
//=============================================================================

/// Analyze a .COM file and print its information.
///
/// Detection order for the entry point:
///   1. --psp flag  → force PSP present, entry file offset = 0x100.
///   2. --no-psp flag → force no PSP,    entry file offset = 0x000.
///   3. Otherwise  → use detect_psp() heuristic.
///
/// @param opts     Parsed CLI options.
/// @param data     Full file contents as a byte vector.
/// @param fileSize Actual file size in bytes.
static inline int analyze_com(const Options& opts,
                                const std::vector<uint8_t>& data,
                                int64_t fileSize) {
    // Resolve PSP presence using flags or heuristic.
    bool has_psp = false;
    if (opts.comForcePsp) {
        has_psp = true;
    } else if (opts.comForceNoPsp) {
        has_psp = false;
    } else {
        has_psp = detect_psp(data);
    }

    // Entry point file offset: 0x100 when the PSP is part of the file,
    // 0x000 otherwise (file content goes to memory starting at 0x100).
    size_t entry_offset = has_psp ? COM_PSP_SIZE : 0;

    const bool uasm_quiet = opts.uasm_stdout_only();
    if (!uasm_quiet)
        print_com_info(opts, fileSize, has_psp, entry_offset);

    // Hex dump from entry point to EOF (same behaviour as EXE path).
    if (!uasm_quiet && (opts.showHexdump || opts.showAll)) {
        if (entry_offset < data.size()) {
            size_t dump_size = data.size() - entry_offset;
            print_hex_dump(data, entry_offset, dump_size,
                           "=== Hex+ASCII Dump (from entry point to EOF) ===");
        }
    } else if (!uasm_quiet && !opts.showReloc && !opts.showDisasm) {
        // Default: show a 64-byte preview when no section flag is given.
        if (entry_offset < data.size()) {
            size_t preview = std::min((size_t)64, data.size() - entry_offset);
            print_hex_dump(data, entry_offset, preview,
                           "Code at Entry Point (first 64 bytes):");
        }
    }

    // Disassembly from entry point. No-PSP images are org 0100h (see
    // com_listing_image); the filename is the listing "; source:" line.
    // The listing image is the CFG image. Reuse it when --cfg will print.
    CfgGraph com_cfg{};
    bool com_cfg_shared = false;
    if (opts.showDisasm || opts.showAll || opts.uasm) {
        std::vector<uint8_t> image;
        com_listing_image(data, has_psp, image);
        const bool want_cfg = opts.showCfg && !uasm_quiet;
        CfgGraph* cfg_slot = want_cfg ? &com_cfg : nullptr;
        if (listing_run(image, 0, image.size(), COM_ENTRY_IP, opts.loadBase,
                        opts.loadBase, opts, opts.filename, nullptr, nullptr, true,
                        has_psp, true, {}, cfg_slot) != 0)
        {
            return 1;
        }
        // A failed generate does not write *cfg_slot (image_size stays 0).
        com_cfg_shared = cfg_slot != nullptr && com_cfg.image_size != 0;
    }

    if (opts.showCfg && !uasm_quiet) {
        // COM: file image maps to CS:0100 (or CS:0000 if PSP embedded).
        // Build CFG in a virtual image where IP 0100 is entry for no-PSP files.
        if (com_cfg_shared)
        {
            if (has_psp)
            {
                // File offsets already match cfg_analyze_image. DOT + human.
                cfg_emit_views(com_cfg, opts);
            }
            else
            {
                // listing_run's 256-byte hole makes file_off equal the IP.
                // Same adjustment as the no-PSP build. No DOT on this path.
                for (auto& [ip, blk] : com_cfg.blocks)
                {
                    (void)ip;
                    if (blk.start_ip >= COM_PSP_SIZE)
                    {
                        blk.file_off = blk.start_ip - COM_PSP_SIZE;
                    }
                    for (auto& in : blk.insns)
                    {
                        if (in.ip >= COM_PSP_SIZE)
                        {
                            in.file_off = in.ip - COM_PSP_SIZE;
                        }
                    }
                }
                cfg_print(com_cfg, opts);
            }
        }
        else if (has_psp) {
            cfg_analyze_image(data, 0, data.size(), COM_ENTRY_IP, opts.loadBase,
                              opts.loadBase, opts);
        } else {
            // Prepend 0x100 zero bytes so IPs match DOS (code at 0100h).
            std::vector<uint8_t> virt(COM_PSP_SIZE + data.size(), 0);
            std::memcpy(virt.data() + COM_PSP_SIZE, data.data(), data.size());
            // file offsets in dump will be wrong by +100h for virt — pass file base 0
            // and note in analysis; use image that starts at 0 with code at 100h.
            CfgGraph g = cfg_build(virt, COM_ENTRY_IP, opts.loadBase, opts.loadBase, 0,
                                   opts.cfgFollowCalls, 20000);
            cfg_annotate(g, virt);
            // Fix displayed file offsets: real file off = ip - 0x100
            for (auto& [ip, blk] : g.blocks) {
                (void)ip;
                if (blk.start_ip >= COM_PSP_SIZE)
                    blk.file_off = blk.start_ip - COM_PSP_SIZE;
                for (auto& in : blk.insns)
                    if (in.ip >= COM_PSP_SIZE)
                        in.file_off = in.ip - COM_PSP_SIZE;
            }
            cfg_print(g, opts);
        }
    }

    if (opts.simulate) {
        run_com_simulation(opts, data, entry_offset);
    }
    return 0;
}

#endif // COM_ANALYSIS_H
