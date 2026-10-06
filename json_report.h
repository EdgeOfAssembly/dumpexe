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
#include "json_escape.h"
#include "pascal_mt.h"
#include "dx_strings.h"
#include "toolchain.h"

//=============================================================================
// Report
//=============================================================================

struct JsonReport
{
    std::string tool = "dumpexe";
    std::string version = "2.17";
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
    uint16_t min_alloc = 0;       ///< e_minalloc paragraphs
    uint16_t max_alloc = 0;       ///< e_maxalloc paragraphs
    uint16_t checksum = 0;
    uint16_t overlay_number = 0;  ///< e_ovno (not the extra-byte tail)
    int64_t extra_bytes = 0;      ///< bytes past the declared MZ size (0 if short)
    size_t entry_file_offset = 0;
    /// COM only: "psp" (PSP embedded, entry at file 0x100) or "org100"
    /// (no PSP; code starts at file offset 0, loaded at IP 0100h).
    std::string load_model;
    std::vector<RelocEntry> relocs;
    bool relocs_truncated = false; ///< true when num_reloc exceeded the JSON cap

    PascalMtReport pascal_mt{};
    bool pascal_mt_ran = false;

    ToolchainReport toolchain{};
    bool toolchain_ran = false;

    std::vector<ExtractedString> strings;
    bool strings_ran = false;

    CfgGraph cfg{};
    bool cfg_ran = false;
    std::string cfg_dot_path;
    /// Non-empty: print one error object and nothing else. Exit stays 1.
    std::string error;

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
        min_alloc = h.mem_extra;
        max_alloc = h.mem_max;
        checksum = h.checksum;
        overlay_number = h.overlay_index;
        extra_bytes = sizes.extraBytes > 0 ? sizes.extraBytes : static_cast<int64_t>(0);
        entry_file_offset = static_cast<size_t>(sizes.entryPointFileOffset);
    }

    /**
     * @brief Keep relocation entries for the JSON `relocs` array.
     *
     * At most 4096 entries are stored. A longer table sets
     * @c relocs_truncated so the printer can flag the cut.
     *
     * @param all Entries from @c load_relocations (may be empty).
     */
    void set_relocs(const std::vector<RelocEntry>& all)
    {
        constexpr size_t kCap = 4096;
        relocs_truncated = all.size() > kCap;
        const size_t n = relocs_truncated ? kCap : all.size();
        relocs.assign(all.begin(),
                      all.begin() + static_cast<std::ptrdiff_t>(n));
    }

    void print(std::ostream& os) const
    {
        if (!error.empty())
        {
            os << "{\n";
            os << std::format("  \"tool\": \"{}\",\n", json_escape(tool));
            os << std::format("  \"version\": \"{}\",\n", json_escape(version));
            os << std::format("  \"file\": \"{}\",\n", json_escape(file));
            os << std::format("  \"format\": \"{}\",\n", json_escape(format));
            os << std::format("  \"error\": \"{}\"\n", json_escape(error));
            os << "}\n";
            return;
        }
        os << "{\n";
        os << std::format("  \"tool\": \"{}\",\n", json_escape(tool));
        os << std::format("  \"version\": \"{}\",\n", json_escape(version));
        os << std::format("  \"file\": \"{}\",\n", json_escape(file));
        os << std::format("  \"format\": \"{}\",\n", json_escape(format));

        if (format == "com")
        {
            os << "  \"com\": {\n";
            os << std::format("    \"file_size\": {},\n", file_size);
            os << std::format("    \"entry_ip\": \"{:04X}\",\n", entry_ip);
            os << std::format("    \"entry_file_offset\": {},\n", entry_file_offset);
            os << std::format("    \"load_model\": \"{}\"\n", json_escape(load_model));
            os << "  },\n";
        }

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
            os << std::format("    \"min_alloc\": {},\n", min_alloc);
            os << std::format("    \"max_alloc\": {},\n", max_alloc);
            os << std::format("    \"checksum\": {},\n", checksum);
            os << std::format("    \"overlay_number\": {},\n", overlay_number);
            os << std::format("    \"extra_bytes\": {},\n", extra_bytes);
            os << std::format("    \"entry_file_offset\": {},\n", entry_file_offset);
            os << "    \"relocs\": [";
            if (!relocs.empty())
            {
                os << "\n";
                for (size_t i = 0; i < relocs.size(); ++i)
                {
                    const RelocEntry& r = relocs[i];
                    const uint32_t file_off =
                        static_cast<uint32_t>(header_bytes) +
                        static_cast<uint32_t>(r.segment) * 16u + r.offset;
                    os << std::format(
                        "      {{\"file_offset\": {}, \"segment\": \"{:04X}\", "
                        "\"offset\": \"{:04X}\"}}{}",
                        file_off, r.segment, r.offset,
                        (i + 1 < relocs.size()) ? ",\n" : "\n");
                }
                os << "    ]";
            }
            else
            {
                os << "]";
            }
            if (relocs_truncated)
                os << ",\n    \"relocs_truncated\": true";
            os << "\n";
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

        // Toolchain (JWASM 1.8 / COM-in-EXE / CuteMouse)
        os << "  \"toolchain\": ";
        if (!toolchain_ran)
            os << "null";
        else if (!toolchain.detected)
            os << std::format(
                "{{\"detected\": false, \"confidence\": {:.3f}, \"packer\": \"{}\"}}",
                toolchain.confidence, json_escape(toolchain.packer));
        else
        {
            os << "{\n";
            os << "    \"detected\": true,\n";
            os << std::format("    \"confidence\": {:.3f},\n", toolchain.confidence);
            os << std::format("    \"packer\": \"{}\",\n", json_escape(toolchain.packer));
            os << std::format("    \"assembler\": \"{}\",\n",
                              json_escape(toolchain.assembler));
            os << std::format("    \"assembler_version\": \"{}\",\n",
                              json_escape(toolchain.assembler_version));
            os << std::format("    \"jwasm_1_8\": {},\n",
                              toolchain.jwasm_1_8 ? "true" : "false");
            os << std::format("    \"com_in_exe\": {},\n",
                              toolchain.com_in_exe ? "true" : "false");
            os << std::format("    \"product\": \"{}\",\n",
                              json_escape(toolchain.product));
            os << std::format("    \"product_version\": \"{}\",\n",
                              json_escape(toolchain.product_version));
            os << std::format("    \"toolchain\": \"{}\",\n",
                              json_escape(toolchain.toolchain));
            os << std::format("    \"tool_path_hint\": \"{}\",\n",
                              json_escape(toolchain.tool_path_hint));
            os << std::format("    \"fc_pad_runs\": {},\n", toolchain.fc_pad_runs);
            os << "    \"evidence\": [\n";
            for (size_t i = 0; i < toolchain.evidence.size(); ++i)
            {
                os << std::format(
                    "      \"{}\"{}", json_escape(toolchain.evidence[i]),
                    (i + 1 < toolchain.evidence.size()) ? ",\n" : "\n");
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
            os << std::format("    \"n_edges\": {},\n", cfg.n_edges);
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

            // Edges (capped for size). The count is n_edges, above.
            os << "    \"edges\": [\n";
            size_t ecount = 0;
            const size_t emax = 2000;
            bool edges_truncated = false;
            bool first_e = true;
            for (const auto& kv : cfg.blocks)
            {
                const CfgBlock& b = kv.second;
                for (const CfgEdge& e : b.outs)
                {
                    if (ecount >= emax)
                    {
                        edges_truncated = true;
                        break;
                    }
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
                if (edges_truncated)
                    break;
            }
            os << "\n    ],\n";
            os << std::format("    \"edges_truncated\": {}\n",
                              edges_truncated ? "true" : "false");
            os << "  }";
        }
        os << "\n}\n";
    }
};

#endif // JSON_REPORT_H
