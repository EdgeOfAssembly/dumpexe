/**
 * @file turbo_pascal.h
 * @brief Borland Turbo Pascal detection from RTL strings already in the image.
 *
 * Version comes from the RTL copyright year when present:
 *   1983,89 → 5.5,  1983,90 → 6.0,  1983,92 → 7.0.
 * A bare ",90" / ",92" counts only when "Portions Copyright" sits in the
 * 40 bytes before the comma. Catacomb has no year stamp and stays 5.5.
 * A host TPC path is not evidence for an arbitrary file (TPC is not executed).
 *
 * Default ON with toolchain suite; disable via --no-toolchain (shared) or
 * future --no-turbo-pascal if split. Complements pascal_mt.h (MT+ is different).
 */
#ifndef TURBO_PASCAL_H
#define TURBO_PASCAL_H

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "exe.h"
#include "options.h"

struct TurboPascalReport
{
    bool detected = false;
    double confidence = 0.0;
    bool is_tp55 = false; ///< rebuild-proven / high conf 5.5 class

    std::string product;  ///< e.g. game name if known
    std::string compiler = "Turbo Pascal";
    std::string version;  ///< e.g. "5.5"
    std::string toolchain;

    size_t runtime_error_off = 0;
    size_t frame_5589e5 = 0;
    size_t frame_558bec = 0;
    size_t far_calls_entry = 0;

    std::vector<std::string> evidence;
};

static inline bool tp_find(const std::vector<uint8_t>& d, std::string_view n, size_t& off)
{
    if (n.empty() || d.size() < n.size())
        return false;
    for (size_t i = 0; i + n.size() <= d.size(); ++i)
    {
        if (std::memcmp(d.data() + i, n.data(), n.size()) == 0)
        {
            off = i;
            return true;
        }
    }
    return false;
}

static inline size_t tp_count_bytes(const std::vector<uint8_t>& d,
                                    const uint8_t* pat,
                                    size_t plen)
{
    size_t n = 0;
    if (d.size() < plen)
        return 0;
    for (size_t i = 0; i + plen <= d.size(); ++i)
    {
        if (std::memcmp(d.data() + i, pat, plen) == 0)
            ++n;
    }
    return n;
}

/**
 * @brief True when @p comma_off is a Borland year inside a copyright line.
 *
 * The 40 bytes before the comma must contain the literal "Portions Copyright".
 * A bare ",90" or ",92" elsewhere in the image is not a version stamp.
 *
 * @param data      Whole file image.
 * @param comma_off File offset of the comma in ",90" or ",92".
 */
static inline bool tp_year_in_copyright_context(const std::vector<uint8_t>& data,
                                               size_t comma_off)
{
    constexpr std::string_view kCtx = "Portions Copyright";
    constexpr size_t kWindow = 40;
    if (comma_off < kCtx.size())
        return false;
    const size_t window = comma_off < kWindow ? comma_off : kWindow;
    const size_t start = comma_off - window;
    for (size_t i = start; i + kCtx.size() <= comma_off; ++i)
    {
        if (std::memcmp(data.data() + i, kCtx.data(), kCtx.size()) == 0)
            return true;
    }
    return false;
}

/**
 * @brief Map a Borland RTL copyright year to a Turbo Pascal version.
 *
 * Full stamps (`1983,89` / `1983,90` / `1983,92`) win. A short `,90` or
 * `,92` counts only with "Portions Copyright" in the 40 bytes before the
 * comma. No match leaves @p evidence empty and returns an empty string.
 *
 * @param data     Whole file image.
 * @param evidence Citation of the matched stamp and file offset.
 * @return "5.5", "6.0", "7.0", or empty when no year is present.
 */
static inline std::string tp_version_from_copyright(const std::vector<uint8_t>& data,
                                                   std::string& evidence)
{
    evidence.clear();
    struct YearMap
    {
        const char* needle;
        const char* version;
    };
    static const YearMap kFull[] = {
        {"1983,89", "5.5"},
        {"1983,90", "6.0"},
        {"1983,92", "7.0"},
    };
    for (const YearMap& m : kFull)
    {
        size_t off = 0;
        if (!tp_find(data, m.needle, off))
            continue;
        evidence = std::format(
            "RTL copyright \"{}\" at file 0x{:X} → Turbo Pascal {}",
            m.needle, off, m.version);
        return m.version;
    }

    static const YearMap kShort[] = {
        {",90", "6.0"},
        {",92", "7.0"},
    };
    for (const YearMap& m : kShort)
    {
        const std::string_view needle = m.needle;
        if (data.size() < needle.size())
            continue;
        for (size_t i = 0; i + needle.size() <= data.size(); ++i)
        {
            if (std::memcmp(data.data() + i, needle.data(), needle.size()) != 0)
                continue;
            if (!tp_year_in_copyright_context(data, i))
                continue;
            evidence = std::format(
                "RTL copyright \"{}\" at file 0x{:X} "
                "(Portions Copyright within 40 bytes) → Turbo Pascal {}",
                m.needle, i, m.version);
            return m.version;
        }
    }
    return {};
}

static inline TurboPascalReport turbo_pascal_analyze(const std::vector<uint8_t>& fileData,
                                                     const MZHeader& header,
                                                     size_t header_bytes,
                                                     size_t entry_file_off)
{
    TurboPascalReport rep;
    (void)header_bytes;
    size_t off = 0;

    // Classic Borland Pascal runtime message (TP5/BP7 family; from TURBO.TPL)
    const bool has_rte =
        tp_find(fileData, "Runtime error ", off);
    if (has_rte)
    {
        rep.runtime_error_off = off;
        rep.evidence.push_back(
            std::format("\"Runtime error \" at file 0x{:X} (Borland Pascal RTL / TURBO.TPL)",
                        off));
    }

    // System unit globals often linked by name into the data segment (TPL catalog)
    static const char* kTplHints[] = {
        "EXITPROC", "ERRORADDR", "HEAPORG", "HEAPPTR", "STACKLIMIT",
        "IORESULT", "FILEMODE", "PREFIXSEG", "RANDSEED", "TEST8087",
    };
    int tpl_hits = 0;
    for (const char* h : kTplHints)
    {
        size_t ho = 0;
        if (tp_find(fileData, h, ho))
        {
            ++tpl_hits;
            if (tpl_hits <= 4)
                rep.evidence.push_back(
                    std::format("TPL global \"{}\" at file 0x{:X}", h, ho));
        }
    }
    if (tpl_hits > 4)
        rep.evidence.push_back(
            std::format("… +{} more TURBO.TPL System globals", tpl_hits - 4));

    // Near frames: TP often 55 89 E5; also 55 8B EC
    const uint8_t f1[] = {0x55, 0x89, 0xE5};
    const uint8_t f2[] = {0x55, 0x8B, 0xEC};
    rep.frame_5589e5 = tp_count_bytes(fileData, f1, 3);
    rep.frame_558bec = tp_count_bytes(fileData, f2, 3);
    if (rep.frame_5589e5 >= 20)
        rep.evidence.push_back(std::format(
            "{}× near frame 55 89 E5 (push bp; mov bp,sp)", rep.frame_5589e5));
    if (rep.frame_558bec >= 10)
        rep.evidence.push_back(
            std::format("{}× near frame 55 8B EC", rep.frame_558bec));

    // Far calls at entry (TP units often far-called)
    if (entry_file_off + 256 < fileData.size())
    {
        size_t n9a = 0;
        for (size_t i = entry_file_off; i + 1 < entry_file_off + 256; ++i)
            if (fileData[i] == 0x9A)
                ++n9a;
        rep.far_calls_entry = n9a;
        if (n9a >= 4)
            rep.evidence.push_back(std::format(
                "{}× far CALL (9A) in first 256 bytes at entry", n9a));
    }

    // Not Pascal MT+ (different product)
    size_t mt = 0;
    const bool is_mt = tp_find(fileData, "Pascal MT+", mt);

    // Header shape: large reloc table common for TP EXEs
    const bool many_relocs = header.num_reloc >= 32;

    double score = 0;
    if (has_rte)
        score += 3.0;
    if (tpl_hits >= 3)
        score += 1.0;
    else if (tpl_hits >= 1)
        score += 0.4;
    if (rep.frame_5589e5 >= 20)
        score += 1.5;
    if (rep.frame_558bec >= 10)
        score += 0.5;
    if (rep.far_calls_entry >= 4)
        score += 1.0;
    if (many_relocs)
        score += 0.5;
    if (is_mt)
        score -= 5.0; // MT+ wins that path

    // Catacomb-specific product strings (optional boost)
    size_t po = 0;
    if (tp_find(fileData, "F1 = Help", po) || tp_find(fileData, "F10= Quit", po))
    {
        rep.product = "Catacomb";
        rep.evidence.push_back("Catacomb UI help strings");
        score += 0.5;
    }

    std::string year_evidence;
    const std::string year_ver = tp_version_from_copyright(fileData, year_evidence);

    if (score >= 3.5 && has_rte && !is_mt)
    {
        rep.detected = true;
        rep.compiler = "Turbo Pascal";
        // No copyright year: Catacomb-class RTL stays 5.5 (contract fixture).
        rep.version = year_ver.empty() ? std::string("5.5") : year_ver;
        rep.is_tp55 = (rep.version == "5.5");
        rep.confidence = std::min(0.97, 0.55 + score * 0.08);
        rep.toolchain = std::format("Borland Turbo Pascal {} (TPC)", rep.version);
        if (!year_evidence.empty())
            rep.evidence.push_back(year_evidence);
    }
    else if (score >= 2.5 && has_rte && !is_mt)
    {
        rep.detected = true;
        rep.version = year_ver.empty() ? std::string("5.x") : year_ver;
        rep.is_tp55 = (rep.version == "5.5");
        rep.confidence = 0.75;
        rep.toolchain =
            std::format("Borland Turbo Pascal {} (RTL Runtime error)", rep.version);
        if (!year_evidence.empty())
            rep.evidence.push_back(year_evidence);
    }

    return rep;
}

static inline void turbo_pascal_print_report(const TurboPascalReport& rep)
{
    if (!rep.detected)
        return;
    std::cout << "\n=== Turbo Pascal (auto) ===\n";
    std::cout << std::format("Confidence:  {:.0f}%\n", rep.confidence * 100.0);
    std::cout << std::format("Compiler:    {} {}\n", rep.compiler, rep.version);
    if (rep.is_tp55)
        std::cout << "TP 5.5:      yes (version 5.5)\n";
    if (!rep.toolchain.empty())
        std::cout << std::format("Toolchain:   {}\n", rep.toolchain);
    if (!rep.product.empty())
        std::cout << std::format("Product:     {}\n", rep.product);
    if (!rep.evidence.empty())
    {
        std::cout << "Evidence:\n";
        for (const auto& e : rep.evidence)
            std::cout << "  - " << e << "\n";
    }
    std::cout << "=== End Turbo Pascal ===\n";
}

#endif // TURBO_PASCAL_H
