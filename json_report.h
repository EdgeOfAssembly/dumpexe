/**
 * @file json_report.h
 * @brief Minimal JSON report builder for dumpexe --json (no external deps).
 *
 * Machine-readable stdout for scripting: header, Pascal MT+, strings, CFG summary.
 * Opt-in only (--json); default remains human text (cli-design).
 */
#ifndef JSON_REPORT_H
#define JSON_REPORT_H

#include <algorithm>
#include <cstdint>
#include <format>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "analysis.h" // ExeSizes
#include "cfg.h"
#include "exe.h"
#include "options.h"
#include "pascal_mt.h"
#include "strings.h"

//=============================================================================
// Escape
//=============================================================================

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
            if (c < 0x20)
                o += std::format("\\u{:04x}", c);
            else
                o.push_back(static_cast<char>(c));
            break;
        }
    }
    return o;
}

//=============================================================================
// Report
//=============================================================================

struct JsonReport
{
    std::string tool = "dumpexe";
    std::string version = "1.3";
    std::string file;
    std::string format; ///< "mz" | "com" | "sys"

    // MZ header subset
    bool has_mz = false;
    uint32_t file_size = 0;
    uint32_t load_image_size = 0;
    uint16_t header_bytes = 0;
    uint16_t entry_cs = 0;
    uint16_t entry_ip = 0;
    uint16_t ss = 0;
    uint16_t sp = 0;
    uint16_t reloc_count = 0;
    uint16_t overlay = 0;
    size_t entry_file_offset = 0;

    PascalMtReport pascal_mt{};
    bool pascal_mt_ran = false;

    std::vector<ExtractedString> strings;
    bool strings_ran = false;

    CfgGraph cfg{};
    bool cfg_ran = false;
    std::string cfg_dot_path;

    void set_mz(const std::string& path,
                const MZHeader& h,
                const ExeSizes& sizes,
                int64_t fsize)
    {
        file = path;
        format = "mz";
        has_mz = true;
        file_size = static_cast<uint32_t>(fsize);
        load_image_size = static_cast<uint32_t>(sizes.loadImageSize);
        header_bytes = static_cast<uint16_t>(sizes.headerSizeBytes);
        entry_cs = static_cast<uint16_t>(h.cs);
        entry_ip = h.ip;
        ss = static_cast<uint16_t>(h.ss);
        sp = h.sp;
        reloc_count = h.num_reloc;
        overlay = h.overlay_index;
        entry_file_offset = static_cast<size_t>(sizes.entryPointFileOffset);
    }

    void print(std::ostream& os) const
    {
        os << "{\n";
        os << std::format("  \"tool\": \"{}\",\n", json_escape(tool));
        os << std::format("  \"version\": \"{}\",\n", json_escape(version));
        os << std::format("  \"file\": \"{}\",\n", json_escape(file));
        os << std::format("  \"format\": \"{}\",\n", json_escape(format));

        if (has_mz)
        {
            os << "  \"mz\": {\n";
            os << std::format("    \"file_size\": {},\n", file_size);
            os << std::format("    \"load_image_size\": {},\n", load_image_size);
            os << std::format("    \"header_bytes\": {},\n", header_bytes);
            os << std::format("    \"entry_cs\": \"{:04X}\",\n", entry_cs);
            os << std::format("    \"entry_ip\": \"{:04X}\",\n", entry_ip);
            os << std::format("    \"ss\": \"{:04X}\",\n", ss);
            os << std::format("    \"sp\": \"{:04X}\",\n", sp);
            os << std::format("    \"reloc_count\": {},\n", reloc_count);
            os << std::format("    \"overlay\": {},\n", overlay);
            os << std::format("    \"entry_file_offset\": {}\n", entry_file_offset);
            os << "  },\n";
        }

        // Pascal MT+
        os << "  \"pascal_mt\": ";
        if (!pascal_mt_ran)
            os << "null";
        else if (!pascal_mt.detected)
            os << std::format("{{\"detected\": false, \"confidence\": {:.3f}}}",
                              pascal_mt.confidence);
        else
        {
            os << "{\n";
            os << "    \"detected\": true,\n";
            os << std::format("    \"compiler\": \"{}\",\n",
                              json_escape(pascal_mt.compiler));
            os << std::format("    \"confidence\": {:.3f},\n", pascal_mt.confidence);
            os << std::format("    \"entry_call_target_ip\": \"{:04X}\",\n",
                              pascal_mt.entry_call_target_ip);
            os << "    \"segment_table\": {\n";
            os << std::format("      \"code_paras\": \"{:04X}\",\n",
                              pascal_mt.seg_code_paras);
            os << std::format("      \"data_paras\": \"{:04X}\",\n",
                              pascal_mt.seg_data_paras);
            os << std::format("      \"stack_paras\": \"{:04X}\",\n",
                              pascal_mt.seg_stack_paras);
            os << std::format("      \"extra_paras\": \"{:04X}\"\n",
                              pascal_mt.seg_extra_paras);
            os << "    },\n";
            os << std::format("    \"jump_table_base_ip\": \"{:04X}\",\n",
                              static_cast<unsigned>(pascal_mt.jump_table_base_ip));
            os << "    \"jump_table\": [\n";
            for (size_t i = 0; i < pascal_mt.jump_table.size(); ++i)
            {
                const auto& s = pascal_mt.jump_table[i];
                os << std::format(
                    "      {{\"slot\": {}, \"table_ip\": \"{:04X}\", "
                    "\"target_ip\": \"{:04X}\", \"target_file_offset\": {}, "
                    "\"kind\": \"{}\", \"prologue_hex\": \"{}\"}}{}",
                    s.slot, s.table_ip, s.target_ip, s.target_file_off,
                    json_escape(s.kind), json_escape(s.prologue_hex),
                    (i + 1 < pascal_mt.jump_table.size()) ? ",\n" : "\n");
            }
            os << "    ],\n";
            os << "    \"hits\": [\n";
            for (size_t i = 0; i < pascal_mt.hits.size(); ++i)
            {
                const auto& h = pascal_mt.hits[i];
                os << std::format(
                    "      {{\"file_offset\": {}, \"image_offset\": {}, "
                    "\"pattern_id\": \"{}\", \"role\": \"{}\", "
                    "\"confidence\": {:.2f}, \"evidence\": \"{}\"}}{}",
                    h.file_offset, h.image_offset,
                    json_escape(h.pattern_id), json_escape(h.role),
                    h.confidence, json_escape(h.evidence),
                    (i + 1 < pascal_mt.hits.size()) ? ",\n" : "\n");
            }
            os << "    ]\n";
            os << "  }";
        }
        os << ",\n";

        // Strings
        os << "  \"strings\": ";
        if (!strings_ran)
            os << "null";
        else
        {
            os << "[\n";
            for (size_t i = 0; i < strings.size(); ++i)
            {
                const auto& s = strings[i];
                os << std::format(
                    "    {{\"file_offset\": {}, \"kind\": \"{}\", \"text\": \"{}\"}}{}",
                    s.file_off, json_escape(string_kind_name(s.kind)),
                    json_escape(s.text),
                    (i + 1 < strings.size()) ? ",\n" : "\n");
            }
            os << "  ]";
        }
        os << ",\n";

        // CFG
        os << "  \"cfg\": ";
        if (!cfg_ran)
            os << "null";
        else
        {
            os << "{\n";
            os << std::format("    \"cs_seg\": \"{:04X}\",\n", cfg.cs_seg);
            os << std::format("    \"image_file_base\": {},\n", cfg.image_file_base);
            os << std::format("    \"image_size\": {},\n", cfg.image_size);
            os << std::format("    \"blocks\": {},\n", cfg.blocks.size());
            os << std::format("    \"edges\": {},\n", cfg.n_edges);
            os << std::format("    \"back_edges\": {},\n", cfg.n_loops_back);
            os << std::format("    \"int_sites\": {},\n", cfg.n_int_sites);
            os << std::format("    \"string_xrefs\": {},\n", cfg.n_str_xrefs);
            if (!cfg_dot_path.empty())
                os << std::format("    \"dot_path\": \"{}\",\n",
                                  json_escape(cfg_dot_path));

            // Interesting blocks summary
            std::vector<const CfgBlock*> interesting;
            for (const auto& kv : cfg.blocks)
            {
                const CfgBlock& b = kv.second;
                if (b.is_interesting &&
                    (!b.ints.empty() || !b.str_xrefs.empty() || !b.tags.empty()))
                    interesting.push_back(&b);
            }
            std::sort(interesting.begin(), interesting.end(),
                      [](const CfgBlock* a, const CfgBlock* b)
                      { return a->start_ip < b->start_ip; });

            os << "    \"interesting\": [\n";
            for (size_t i = 0; i < interesting.size(); ++i)
            {
                const CfgBlock& b = *interesting[i];
                os << "      {\n";
                os << std::format("        \"start_ip\": \"{:04X}\",\n", b.start_ip);
                os << std::format("        \"file_offset\": {},\n", b.file_off);
                os << "        \"tags\": [";
                for (size_t t = 0; t < b.tags.size(); ++t)
                {
                    if (t)
                        os << ", ";
                    os << std::format("\"{}\"", json_escape(b.tags[t]));
                }
                os << "],\n";
                os << "        \"ints\": [";
                for (size_t t = 0; t < b.ints.size(); ++t)
                {
                    if (t)
                        os << ", ";
                    const auto& s = b.ints[t];
                    os << std::format(
                        "{{\"ip\": \"{:04X}\", \"int\": {}, \"ah\": {}, \"note\": \"{}\", "
                        "\"path\": \"{}\"}}",
                        s.ip, s.int_num,
                        (s.ah == 0xFF ? -1 : static_cast<int>(s.ah)),
                        json_escape(s.note), json_escape(s.path));
                }
                os << "]\n";
                os << "      }" << (i + 1 < interesting.size() ? "," : "") << "\n";
            }
            os << "    ],\n";

            // Edges (capped for size)
            os << "    \"edges\": [\n";
            size_t ecount = 0;
            const size_t emax = 2000;
            bool first_e = true;
            for (const auto& kv : cfg.blocks)
            {
                const CfgBlock& b = kv.second;
                for (const CfgEdge& e : b.outs)
                {
                    if (ecount >= emax)
                        break;
                    if (!first_e)
                        os << ",\n";
                    first_e = false;
                    os << std::format(
                        "      {{\"from\": \"{:04X}\", \"to\": \"{:04X}\", "
                        "\"kind\": \"{}\", \"has_target\": {}}}",
                        b.start_ip, e.to_ip, cfg_edge_name(e.kind),
                        e.has_target ? "true" : "false");
                    ++ecount;
                }
                if (ecount >= emax)
                    break;
            }
            os << "\n    ]\n";
            os << "  }";
        }
        os << "\n}\n";
    }
};

#endif // JSON_REPORT_H
