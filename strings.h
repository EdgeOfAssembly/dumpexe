/**
 * @file strings.h
 * @brief Standalone string extraction for DOS images (Pascal + ASCIIZ).
 *
 * Pascal MT+ and Turbo Pascal commonly embed:
 *   - Length-prefixed strings:  db len, 'chars...'
 *   - Inline after near CALL:   call $+3+len+1 / db len, 'chars...'
 *
 * Also reports C-style ASCIIZ runs for convenience.
 */
#ifndef STRINGS_H
#define STRINGS_H

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <format>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "options.h"

/// One recovered string with file offset and kind.
struct ExtractedString
{
    size_t file_off = 0;   ///< offset of first character (not length byte)
    size_t len_byte_off = 0; ///< offset of length byte (Pascal only)
    std::string text;
    enum class Kind
    {
        PascalLenPrefixed, ///< [len][ascii]
        PascalInlineCall,  ///< E8 rel16; [len][ascii] with rel==1+len
        Asciiz             ///< null-terminated printable run
    } kind = Kind::Asciiz;
};

static inline const char* string_kind_name(ExtractedString::Kind k)
{
    switch (k)
    {
    case ExtractedString::Kind::PascalLenPrefixed:
        return "pascal-len";
    case ExtractedString::Kind::PascalInlineCall:
        return "pascal-call";
    case ExtractedString::Kind::Asciiz:
        return "asciiz";
    }
    return "?";
}

static inline bool is_printable_ascii(uint8_t c)
{
    return c >= 32 && c < 127;
}

/// Scan image for Pascal length-prefixed and CALL-inline strings + ASCIIZ.
static inline void extract_strings(const std::vector<uint8_t>& image,
                                   std::vector<ExtractedString>& out,
                                   size_t min_len = 4)
{
    out.clear();
    const size_t n = image.size();
    std::set<size_t> seen_char_off; // dedup by first char offset

    auto push_unique = [&](ExtractedString s)
    {
        if (s.text.size() < min_len)
            return;
        if (!seen_char_off.insert(s.file_off).second)
            return;
        out.push_back(std::move(s));
    };

    // --- Pascal MT+ inline: E8 rel16; db len, 'text' with rel == 1+len ---
    for (size_t i = 0; i + 4 < n; ++i)
    {
        if (image[i] != 0xE8)
            continue;
        const int16_t rel =
            static_cast<int16_t>(image[i + 1] | (static_cast<uint16_t>(image[i + 2]) << 8));
        if (rel < 2 || rel > 80)
            continue;
        const size_t str_at = i + 3;
        if (str_at >= n)
            continue;
        const uint8_t len = image[str_at];
        if (len < 3 || len > 64 || static_cast<int>(1 + len) != rel)
            continue;
        if (str_at + 1 + len > n)
            continue;
        bool ok = true;
        for (size_t k = 0; k < len; ++k)
        {
            if (!is_printable_ascii(image[str_at + 1 + k]))
            {
                ok = false;
                break;
            }
        }
        if (!ok)
            continue;
        ExtractedString s;
        s.len_byte_off = str_at;
        s.file_off = str_at + 1;
        s.text.assign(reinterpret_cast<const char*>(&image[str_at + 1]), len);
        s.kind = ExtractedString::Kind::PascalInlineCall;
        push_unique(std::move(s));
    }

    // --- Generic Pascal length-prefixed: [len][printable...] ---
    for (size_t i = 0; i + 1 < n; ++i)
    {
        const uint8_t len = image[i];
        if (len < min_len || len > 80)
            continue;
        if (i + 1 + len > n)
            continue;
        bool ok = true;
        for (size_t k = 0; k < len; ++k)
        {
            if (!is_printable_ascii(image[i + 1 + k]))
            {
                ok = false;
                break;
            }
        }
        if (!ok)
            continue;
        // Prefer runs that look like words (letter start) or contain space/dot
        const uint8_t first = image[i + 1];
        const bool letter =
            (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z');
        if (!letter)
            continue;
        ExtractedString s;
        s.len_byte_off = i;
        s.file_off = i + 1;
        s.text.assign(reinterpret_cast<const char*>(&image[i + 1]), len);
        s.kind = ExtractedString::Kind::PascalLenPrefixed;
        push_unique(std::move(s));
    }

    // --- ASCIIZ runs ---
    size_t i = 0;
    while (i < n)
    {
        if (!is_printable_ascii(image[i]))
        {
            ++i;
            continue;
        }
        size_t j = i;
        while (j < n && is_printable_ascii(image[j]))
            ++j;
        const size_t len = j - i;
        if (len >= min_len && (j >= n || image[j] == 0))
        {
            ExtractedString s;
            s.file_off = i;
            s.len_byte_off = i;
            s.text.assign(reinterpret_cast<const char*>(&image[i]), len);
            s.kind = ExtractedString::Kind::Asciiz;
            push_unique(std::move(s));
        }
        i = (j > i) ? j : i + 1;
    }

    // Drop length-prefix hits that are strict substrings of a longer hit
    // (common when scanning every offset inside a long Pascal string).
    std::vector<ExtractedString> filtered;
    filtered.reserve(out.size());
    for (const auto& s : out)
    {
        if (s.kind == ExtractedString::Kind::PascalInlineCall ||
            s.kind == ExtractedString::Kind::Asciiz)
        {
            filtered.push_back(s);
            continue;
        }
        bool subsumed = false;
        for (const auto& t : out)
        {
            if (t.file_off == s.file_off && t.text.size() == s.text.size())
                continue;
            if (t.kind != ExtractedString::Kind::PascalLenPrefixed &&
                t.kind != ExtractedString::Kind::PascalInlineCall)
                continue;
            if (t.text.size() <= s.text.size())
                continue;
            // s is a substring of t's text at some offset
            if (t.text.find(s.text) != std::string::npos)
            {
                // and s's file range lies inside t's character range
                if (s.file_off >= t.file_off &&
                    s.file_off + s.text.size() <= t.file_off + t.text.size())
                {
                    subsumed = true;
                    break;
                }
            }
        }
        if (!subsumed)
            filtered.push_back(s);
    }
    out.swap(filtered);

    std::sort(out.begin(), out.end(),
              [](const ExtractedString& a, const ExtractedString& b)
              { return a.file_off < b.file_off; });
}

/// Print string table to stdout.
static inline void print_strings_report(const std::vector<ExtractedString>& strs)
{
    std::cout << std::format("\n=== Strings ({} found) ===\n", strs.size());
    std::cout << "file_off  kind          text\n";
    for (const auto& s : strs)
    {
        std::string escaped;
        escaped.reserve(s.text.size());
        for (unsigned char c : s.text)
        {
            if (c == '\\')
                escaped += "\\\\";
            else if (c == '"')
                escaped += "\\\"";
            else
                escaped.push_back(static_cast<char>(c));
        }
        std::cout << std::format("{:08X}  {:12}  \"{}\"\n", s.file_off,
                                 string_kind_name(s.kind), escaped);
    }
}

/// Run string extraction for the load image (or whole file for COM).
static inline void dump_strings(const Options& opts,
                                const std::vector<uint8_t>& fileData,
                                size_t image_file_off,
                                size_t image_len)
{
    if (!opts.showStrings && !opts.showAll)
        return;
    if (image_file_off >= fileData.size())
        return;
    const size_t avail = fileData.size() - image_file_off;
    const size_t len = (image_len == 0 || image_len > avail) ? avail : image_len;
    std::vector<uint8_t> image(fileData.begin() + static_cast<std::ptrdiff_t>(image_file_off),
                               fileData.begin() + static_cast<std::ptrdiff_t>(image_file_off + len));
    std::vector<ExtractedString> strs;
    extract_strings(image, strs, 4);
    // Adjust offsets to file offsets
    for (auto& s : strs)
    {
        s.file_off += image_file_off;
        s.len_byte_off += image_file_off;
    }
    print_strings_report(strs);
}

#endif // STRINGS_H
