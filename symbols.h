/**
 * @file symbols.h
 * @brief Load external symbol maps for multi-pass listing (ground-truth names).
 *
 * Formats (auto-detected by content):
 *   1) dumpexe .sym — lines:  <IP_hex> <name>   or  <IP_hex>:<name>
 *      optional: file_offset <hex> <name>
 *   2) sparse TLINK segment map — records entry point if present
 *
 * CLI: --map=FILE  or auto-try <stem>.sym then <stem>.map next to input
 *      (default ON auto-try; --no-map disables auto; explicit --map always loads)
 */
#ifndef SYMBOLS_H
#define SYMBOLS_H

#include <cctype>
#include <cstdint>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "options.h"

struct SymbolMap
{
    std::map<uint16_t, std::string> by_ip; ///< IP → name
    std::string source_path;
    size_t count = 0;
};

static inline std::string symbols_trim(std::string_view s)
{
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.remove_suffix(1);
    return std::string(s);
}

static inline bool symbols_parse_hex(std::string_view s, uint32_t& out)
{
    s = symbols_trim(s);
    if (s.empty())
        return false;
    if (s.size() > 1 && (s.back() == 'h' || s.back() == 'H'))
        s.remove_suffix(1);
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s.remove_prefix(2);
    try
    {
        out = static_cast<uint32_t>(std::stoul(std::string(s), nullptr, 16));
        return true;
    }
    catch (...)
    {
        return false;
    }
}

/**
 * @brief Parse dumpexe .sym or simple address-name lines into @p out.
 */
static inline bool symbols_load_file(const std::string& path, SymbolMap& out)
{
    std::ifstream in(path);
    if (!in)
        return false;
    out = SymbolMap{};
    out.source_path = path;
    std::string line;
    while (std::getline(in, line))
    {
        std::string t = symbols_trim(line);
        if (t.empty() || t[0] == '#' || t[0] == ';')
            continue;
        // TLINK: "Program entry point at 0000:0100"
        if (t.find("entry point") != std::string::npos ||
            t.find("Entry point") != std::string::npos)
        {
            auto colon = t.rfind(':');
            if (colon != std::string::npos && colon + 1 < t.size())
            {
                uint32_t ip = 0;
                if (symbols_parse_hex(t.substr(colon + 1), ip))
                {
                    out.by_ip[static_cast<uint16_t>(ip & 0xFFFF)] = "start";
                    ++out.count;
                }
            }
            continue;
        }
        // Skip TLINK segment table headers / pure prose
        if (t.find("Start") == 0 && t.find("Stop") != std::string::npos)
            continue;
        if (t.find("Length Name") != std::string::npos)
            continue;

        // Formats:
        //   0100 start
        //   0100:start
        //   0000:0100 start
        //   file 0xB20 str_CuteMouse   (ignored for IP map unless ip form)
        std::string addr_tok;
        std::string name;
        auto colon = t.find(':');
        if (colon != std::string::npos && colon < 8)
        {
            // maybe seg:off name  or ip:name
            std::string left = t.substr(0, colon);
            std::string rest = symbols_trim(t.substr(colon + 1));
            // if left is short hex and rest starts with hex then name...
            uint32_t a = 0, b = 0;
            auto sp = rest.find_first_of(" \t");
            std::string mid = (sp == std::string::npos) ? rest : rest.substr(0, sp);
            std::string tail =
                (sp == std::string::npos) ? std::string() : symbols_trim(rest.substr(sp));
            if (symbols_parse_hex(left, a) && symbols_parse_hex(mid, b) && !tail.empty())
            {
                // seg:off name → use off as IP
                out.by_ip[static_cast<uint16_t>(b & 0xFFFF)] = tail;
                ++out.count;
                continue;
            }
            if (symbols_parse_hex(left, a) && !rest.empty() &&
                !std::isxdigit(static_cast<unsigned char>(rest[0])))
            {
                out.by_ip[static_cast<uint16_t>(a & 0xFFFF)] = rest;
                ++out.count;
                continue;
            }
        }

        std::istringstream iss(t);
        if (!(iss >> addr_tok >> name))
            continue;
        if (name.empty())
            continue;
        uint32_t ip = 0;
        if (!symbols_parse_hex(addr_tok, ip))
            continue;
        out.by_ip[static_cast<uint16_t>(ip & 0xFFFF)] = name;
        ++out.count;
    }
    return out.count > 0 || !out.source_path.empty();
}

/// Resolve map path: explicit opts.mapPath, else auto stem.sym / stem.map
static inline std::string symbols_resolve_path(const Options& opts,
                                               const std::string& input_path)
{
    if (!opts.mapPath.empty())
        return opts.mapPath;
    if (!opts.autoMap)
        return {};
    if (input_path.empty())
        return {};

    std::string p = input_path;
    while (p.size() > 1 && (p.back() == '/' || p.back() == '\\'))
        p.pop_back();
    size_t slash = p.find_last_of("/\\");
    std::string dir = (slash == std::string::npos) ? std::string() : p.substr(0, slash + 1);
    std::string base = (slash == std::string::npos) ? p : p.substr(slash + 1);
    size_t dot = base.find_last_of('.');
    if (dot != std::string::npos && dot > 0)
        base = base.substr(0, dot);

    const std::string sym = dir + base + ".sym";
    const std::string map = dir + base + ".map";
    std::ifstream ts(sym);
    if (ts)
        return sym;
    std::ifstream tm(map);
    if (tm)
        return map;
    return {};
}

static inline SymbolMap symbols_load_for_input(const Options& opts,
                                               const std::string& input_path)
{
    SymbolMap sm;
    const std::string path = symbols_resolve_path(opts, input_path);
    if (path.empty())
        return sm;
    if (!symbols_load_file(path, sm))
    {
        if (!opts.mapPath.empty())
            std::cerr << "Warning: could not load symbol map '" << path << "'\n";
        return {};
    }
    if (!opts.jsonOut)
        std::cerr << std::format("symbols: loaded {} names from {}\n", sm.count,
                                 sm.source_path);
    return sm;
}

#endif // SYMBOLS_H
