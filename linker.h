#ifndef LINKER_H
#define LINKER_H
/**
 * @file linker.h
 * @brief MZ linker fingerprint from the bytes after the fixed header fields.
 *
 * Observed on real builds (header 18h..1Fh):
 *  - Borland TLINK: relocation table at 3Eh, 1Ch = 01 00 FB vv. vv is a
 *    version byte (TLINK 5.1 writes 50h, 7.1.30.1 writes 71h), so only the
 *    major series (vv >> 4) is reported, never an exact version.
 *  - Microsoft LINK 3.64 (MASM 5.10): relocation table at 1Eh, word 0001h
 *    at 1Ch, no FBh.
 *  - Turbo Pascal (TPC built-in linker, 5.5 and 7.0): relocation table at
 *    1Ch. Common enough that it is only reported with TP runtime evidence.
 * The assembler or compiler is never inferred from these bytes.
 */
#include <cstdint>
#include <format>
#include <iostream>
#include <string>
#include <vector>

struct LinkerReport
{
    bool detected = false;
    std::string linker;   ///< e.g. "Borland TLINK 7.x"
    std::string evidence; ///< what in the header says so
};

static inline LinkerReport linker_detect(const std::vector<uint8_t>& f, bool tp_runtime)
{
    LinkerReport r;
    if (f.size() < 0x20 || !((f[0] == 'M' && f[1] == 'Z') || (f[0] == 'Z' && f[1] == 'M')))
        return r;
    const uint16_t lfarlc = static_cast<uint16_t>(f[0x18] | (f[0x19] << 8));
    const uint16_t w1c = static_cast<uint16_t>(f[0x1C] | (f[0x1D] << 8));
    const uint8_t v = f[0x1F];
    if (lfarlc >= 0x20 && w1c == 1 && f[0x1E] == 0xFB && (v >> 4) >= 1 && (v >> 4) <= 9)
    {
        r.detected = true;
        r.linker = std::format("Borland TLINK {}.x", v >> 4);
        r.evidence = std::format("header 1Ch: 01 00 FB {:02X} (TLINK signature; version byte {:02X}h gives the "
                                 "{}.x series only)", v, v, v >> 4);
    }
    else if (lfarlc == 0x1E && w1c == 1)
    {
        r.detected = true;
        r.linker = "Microsoft LINK (likely)";
        r.evidence = "relocation table at 1Eh, word 0001h at 1Ch, no FBh (Microsoft LINK layout)";
    }
    else if (lfarlc == 0x1C && tp_runtime)
    {
        r.detected = true;
        r.linker = "Turbo Pascal linker (likely)";
        r.evidence = "relocation table at 1Ch right after the header fields (TPC layout), with Turbo Pascal "
                     "runtime evidence";
    }
    return r;
}

static inline void linker_print_report(const LinkerReport& r)
{
    if (!r.detected)
        return;
    std::cout << "\n=== Linker (MZ header) ===\n";
    std::cout << std::format("Linker:      {}\n", r.linker);
    std::cout << "Evidence:\n  - " << r.evidence << "\n";
    std::cout << "=== End Linker ===\n";
}

#endif // LINKER_H
