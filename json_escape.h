/**
 * @file json_escape.h
 * @brief JSON string escaping shared by the MZ report and the NE report.
 *
 * One escaper. NE analysis cannot include json_report.h: dumpexe.h includes
 * ne_analysis.h first, and json_report.h pulls in the MZ analysis headers.
 */
#ifndef JSON_ESCAPE_H
#define JSON_ESCAPE_H

#include <format>
#include <string>
#include <string_view>

/**
 * @brief Escape a string for inclusion in a JSON double-quoted value.
 *
 * Quotes, backslashes, and the JSON control escapes are rewritten. Any other
 * byte below 0x20, and every byte at or above 0x80, becomes a `\u00XX`
 * escape so the document is UTF-8. The result is the raw contents of a JSON
 * string, without the surrounding quotes.
 *
 * @param[in] s Text to escape. May contain a quote, a backslash, or a newline.
 * @return Escaped text safe to place between JSON string quotes.
 */
static inline std::string json_escape(std::string_view s)
{
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"':  o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\b': o += "\\b"; break;
        case '\f': o += "\\f"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if (c < 0x20 || c >= 0x80)
            {
                o += std::format("\\u{:04x}", c);
            }
            else
            {
                o.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    return o;
}

#endif // JSON_ESCAPE_H
