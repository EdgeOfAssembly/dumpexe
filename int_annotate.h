// int_annotate.h - INT instruction annotation using RBIL database
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Provides annotate_int() and format_int_annotation() backed by the
// compile-time constexpr INT_DB table generated from Ralph Brown's
// Interrupt List. All functions are static inline.

#ifndef INT_ANNOTATE_H
#define INT_ANNOTATE_H

#include "int_db.h"
#include <string_view>
#include <string>
#include <optional>
#include <algorithm>
#include <format>

/// Look up an interrupt entry by number and optional AH/AL values.
///
/// Matching priority (best first):
///   1. Exact     — int_num + ah + al all match
///   2. AH match  — int_num + ah match, entry al is wildcard (0xFF)
///   3. Generic   — int_num matches, entry ah is wildcard (0xFF)
///
/// Pass 0xFF for ah/al when the value is unknown.
/// Returns the description of the best match, or nullopt if not found.
static inline std::optional<std::string_view>
annotate_int(uint8_t int_num, uint8_t ah = 0xFF, uint8_t al = 0xFF) {
    // Binary-search lower bound for (int_num, 0x00, 0x00)
    IntEntry key{int_num, 0x00, 0x00, {}};
    auto cmp = [](const IntEntry& a, const IntEntry& b) {
        if (a.int_num != b.int_num) return a.int_num < b.int_num;
        if (a.ah      != b.ah)      return a.ah      < b.ah;
        return a.al < b.al;
    };
    auto it = std::lower_bound(INT_DB.begin(), INT_DB.end(), key, cmp);

    std::optional<std::string_view> generic_match;
    std::optional<std::string_view> ah_match;

    for (; it != INT_DB.end() && it->int_num == int_num; ++it) {
        // Exact match
        if (it->ah == ah && it->al == al)
            return it->desc;

        // AH-level match: entry ah matches, entry al is wildcard
        if (it->ah == ah && it->al == 0xFF && !ah_match)
            ah_match = it->desc;

        // Generic match: entry ah is wildcard AND entry al is wildcard
        if (it->ah == 0xFF && it->al == 0xFF && !generic_match)
            generic_match = it->desc;
    }

    if (ah_match)      return ah_match;
    if (generic_match) return generic_match;
    return std::nullopt;
}

/// Format an annotation comment string for disassembly output.
/// Returns e.g. "; DOS 1+ - TERMINATE PROGRAM" or "; INT 21h" when not found.
static inline std::string
format_int_annotation(uint8_t int_num, uint8_t ah = 0xFF, uint8_t al = 0xFF) {
    auto desc = annotate_int(int_num, ah, al);
    if (desc)
        return std::format("; INT {:02X}h - {}", int_num, *desc);
    return std::format("; INT {:02X}h", int_num);
}

#endif // INT_ANNOTATE_H
