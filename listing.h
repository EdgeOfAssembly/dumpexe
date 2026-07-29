/**
 * @file listing.h
 * @brief Multi-pass annotated assembly listing for dumpexe (-d / -a).
 *
 * Product decision: there is NO separate --listing flag. Multi-pass listing
 * *is* what -d/--disassemble means. Bare dumpexe <file> stays light (no dump).
 *
 * Passes (on IR / CFG — not text re-parse):
 *   1. Decode via CFG build (block IR)
 *   2. Annotate INT / tags from cfg_annotate
 *   3. Discover proc starts → symbols func_<IP>
 *   4. Emit: labels, rewritten call/jmp, blank line after proc regions
 *
 * Default: also write <stem>.asm (disable with --no-asm-file). -o overrides path.
 */
#ifndef LISTING_H
#define LISTING_H

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "cfg.h"
#include "int_annotate.h"
#include "options.h"

//=============================================================================
// Paths
//=============================================================================

/// Default listing path: same directory/stem as input, extension .asm
static inline std::string listing_default_asm_path(const std::string& input_path)
{
    if (input_path.empty())
        return "out.asm";
    // Strip trailing slashes
    std::string p = input_path;
    while (p.size() > 1 && (p.back() == '/' || p.back() == '\\'))
        p.pop_back();
    // Find last slash
    size_t slash = p.find_last_of("/\\");
    std::string dir = (slash == std::string::npos) ? std::string() : p.substr(0, slash + 1);
    std::string base = (slash == std::string::npos) ? p : p.substr(slash + 1);
    // Strip extension
    size_t dot = base.find_last_of('.');
    if (dot != std::string::npos && dot > 0)
        base = base.substr(0, dot);
    return dir + base + ".asm";
}

static inline std::string listing_symbol_name(uint16_t ip)
{
    return std::format("func_{:04X}", ip);
}

//=============================================================================
// Symbol discovery (pass 3)
//=============================================================================

static inline void listing_collect_symbols(const CfgGraph& g,
                                           uint16_t entry_ip,
                                           std::map<uint16_t, std::string>& sym,
                                           std::set<uint16_t>& proc_starts)
{
    auto add = [&](uint16_t ip, std::string_view why)
    {
        (void)why;
        if (!g.blocks.count(ip) && ip != entry_ip)
        {
            // still allow label at known edge targets even if block missing
        }
        proc_starts.insert(ip);
        if (!sym.count(ip))
            sym[ip] = listing_symbol_name(ip);
    };

    add(entry_ip, "entry");
    sym[entry_ip] = listing_symbol_name(entry_ip); // ensure

    for (const auto& kv : g.blocks)
    {
        const CfgBlock& b = kv.second;
        if (b.is_entry || b.is_call_target || b.is_table_entry)
            add(b.start_ip, "cfg-flag");

        // Pascal near frame at block start
        if (!b.insns.empty())
        {
            const auto& in0 = b.insns[0];
            if (in0.size >= 3 && in0.bytes[0] == 0x55 && in0.bytes[1] == 0x8B &&
                in0.bytes[2] == 0xEC)
                add(b.start_ip, "pascal-frame");
        }

        for (const CfgEdge& e : b.outs)
        {
            if (!e.has_target)
                continue;
            if (e.kind == CfgEdgeKind::Call || e.kind == CfgEdgeKind::Table ||
                e.kind == CfgEdgeKind::Jump)
            {
                // Jump to lower/equal often loop — still a label target
                if (g.blocks.count(e.to_ip) || e.kind == CfgEdgeKind::Call ||
                    e.kind == CfgEdgeKind::Table)
                    add(e.to_ip, "edge-target");
            }
        }
    }
}

//=============================================================================
// Operand rewrite (pass 4 at emit)
//=============================================================================

/// Replace immediate near targets in Capstone op text with symbol when possible.
static inline std::string listing_rewrite_ops(std::string_view mnem,
                                              std::string_view op_str,
                                              const CfgBlock& blk,
                                              const std::map<uint16_t, std::string>& sym)
{
    // Prefer CFG edge targets for call / uncond jmp / table
    uint16_t edge_tgt = 0;
    bool have_edge = false;
    for (const CfgEdge& e : blk.outs)
    {
        if (!e.has_target)
            continue;
        if (e.kind == CfgEdgeKind::Call || e.kind == CfgEdgeKind::Jump ||
            e.kind == CfgEdgeKind::Table || e.kind == CfgEdgeKind::CondTrue)
        {
            // For jcc, CondTrue is taken target; still rewrite if op matches
            edge_tgt = e.to_ip;
            have_edge = true;
            if (e.kind == CfgEdgeKind::Call || e.kind == CfgEdgeKind::Jump ||
                e.kind == CfgEdgeKind::Table)
                break;
        }
    }

    if (!have_edge || !sym.count(edge_tgt))
        return std::string(op_str);

    const std::string& name = sym.at(edge_tgt);
    std::string m(mnem);
    for (char& c : m)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    const bool is_xf =
        m == "call" || m == "jmp" || m == "ljmp" || m == "lcall" || m == "callf" ||
        m == "jmpf" || (m.size() >= 2 && m[0] == 'j'); // jcc

    if (!is_xf)
        return std::string(op_str);

    // If op_str is a simple imm / segment:off, replace wholesale with name
    // Capstone often: "0x652b" or "0x1652b" (linear) or "word ptr [0x..]"
    std::string op(op_str);
    // word ptr / byte ptr — leave memory ops alone
    if (op.find('[') != std::string::npos)
        return op;

    // Far pointer "seg:off" — leave
    if (op.find(':') != std::string::npos && op.find("ptr") == std::string::npos)
    {
        // still try near-only rewrite if no second colon issues
    }

    // Replace any hex token that equals target IP or CS*16+IP forms is hard;
    // use edge: entire operand becomes the label for near call/jmp/jcc.
    if (m == "call" || m == "jmp" || m.starts_with("j"))
        return name;

    return op;
}

static inline bool listing_is_ret_mnem(std::string_view m)
{
    return m == "ret" || m == "retn" || m == "retf" || m == "retfq" || m == "iret" ||
           m == "iretd";
}

//=============================================================================
// Emit listing text
//=============================================================================

static inline std::string listing_emit_text(const CfgGraph& g,
                                            uint16_t entry_ip,
                                            const Options& opts,
                                            const std::string& source_name,
                                            size_t& n_procs,
                                            size_t& n_insns)
{
    std::map<uint16_t, std::string> sym;
    std::set<uint16_t> proc_starts;
    listing_collect_symbols(g, entry_ip, sym, proc_starts);
    n_procs = proc_starts.size();
    n_insns = 0;

    std::ostringstream out;
    out << "; dumpexe multi-pass listing (not single-stream Capstone only)\n";
    out << std::format("; source: {}\n", source_name);
    out << std::format("; CS={:04X}h  entry=func_{:04X}  blocks={}  symbols={}\n",
                       g.cs_seg, entry_ip, g.blocks.size(), sym.size());
    out << "; labels: func_<IP> at entry, call/table targets, Pascal frames\n";
    out << "; call/jmp/jcc near targets rewritten to labels when known\n";
    out << "; blank line after procedure regions ending in ret/retf/iret\n";
    out << ";\n\n";

    std::vector<const CfgBlock*> order;
    order.reserve(g.blocks.size());
    for (const auto& kv : g.blocks)
        order.push_back(&kv.second);
    std::sort(order.begin(), order.end(),
              [](const CfgBlock* a, const CfgBlock* b)
              { return a->start_ip < b->start_ip; });

    // Cap emission for huge graphs (still enough for ICON entry + many procs)
    const size_t max_blocks = opts.cfgMaxBlocks ? opts.cfgMaxBlocks : 500;
    // For listing, allow more than CFG print default when user wants -d
    const size_t list_cap = std::max(max_blocks, size_t{2000});

    size_t shown = 0;
    for (const CfgBlock* bp : order)
    {
        if (shown >= list_cap)
        {
            out << std::format(
                "\n; ... {} more blocks omitted (raise --cfg-max=N for listing cap)\n",
                order.size() - shown);
            break;
        }
        const CfgBlock& b = *bp;
        ++shown;

        // Label at proc start
        if (proc_starts.count(b.start_ip) || sym.count(b.start_ip))
        {
            const std::string& name =
                sym.count(b.start_ip) ? sym[b.start_ip] : listing_symbol_name(b.start_ip);
            out << name << ":";
            if (b.is_entry)
                out << "                ; entry";
            else if (b.is_table_entry)
                out << "                ; jump-table slot";
            else if (b.is_call_target)
                out << "                ; call target";
            out << "\n";
        }

        // INT annotations map by IP
        std::map<uint16_t, std::string> int_notes;
        for (const auto& site : b.ints)
        {
            std::string note;
            if (!opts.noIntAnnot)
            {
                if (site.ah != 0xFF)
                    note = format_int_annotation(site.int_num, site.ah, site.al);
                else
                    note = std::format("; INT {:02X}h", site.int_num);
                if (!site.path.empty())
                    note += std::format("  ; path \"{}\"", site.path);
            }
            int_notes[site.ip] = note;
        }

        for (const auto& in : b.insns)
        {
            ++n_insns;
            // bytes
            std::string hex;
            for (uint8_t i = 0; i < in.size && i < 8; ++i)
                hex += std::format("{:02X}", in.bytes[i]);

            // split mnem / ops from text "mnem ops"
            std::string mnem = in.text;
            std::string ops;
            size_t sp = in.text.find(' ');
            if (sp != std::string::npos)
            {
                mnem = in.text.substr(0, sp);
                ops = in.text.substr(sp + 1);
            }
            std::string mlow = mnem;
            for (char& c : mlow)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            std::string rops = listing_rewrite_ops(mlow, ops, b, sym);

            out << std::format("    {:04X}  {:<16}  {:<8} {}", in.ip, hex, mnem,
                               rops);

            if (int_notes.count(in.ip))
            {
                size_t line_len = mnem.size() + (rops.empty() ? 0 : 1 + rops.size());
                int pad = std::max(1, 20 - static_cast<int>(line_len));
                out << std::string(static_cast<size_t>(pad), ' ') << int_notes[in.ip];
            }
            else if (!b.tags.empty() && &in == &b.insns[0])
            {
                // tag comment on first insn
                out << "  ;";
                for (size_t t = 0; t < b.tags.size() && t < 3; ++t)
                    out << " " << b.tags[t];
            }
            out << "\n";
        }

        // Blank line after procedure region: block ends with ret and is a proc start
        // or sole successor-less ret block
        bool ends_ret = false;
        if (!b.insns.empty())
        {
            std::string tm = b.insns.back().text;
            size_t sp2 = tm.find(' ');
            std::string lastm = (sp2 == std::string::npos) ? tm : tm.substr(0, sp2);
            for (char& c : lastm)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            ends_ret = listing_is_ret_mnem(lastm);
        }
        if (ends_ret && (proc_starts.count(b.start_ip) || b.is_call_target ||
                         b.is_entry || b.is_table_entry))
            out << "\n";
    }

    out << std::format("\n; end listing: {} instructions, {} procedure labels\n",
                       n_insns, n_procs);
    return out.str();
}

//=============================================================================
// Public API
//=============================================================================

/**
 * @brief Build multi-pass listing text for a CS-relative image.
 * @return false on hard failure (empty image / capstone)
 */
static inline bool listing_generate(const std::vector<uint8_t>& fileData,
                                    size_t image_file_off,
                                    size_t image_len,
                                    uint16_t entry_ip,
                                    uint16_t cs_seg,
                                    const Options& opts,
                                    const std::string& source_name,
                                    std::string& out_text,
                                    size_t& n_procs,
                                    size_t& n_insns)
{
    out_text.clear();
    n_procs = 0;
    n_insns = 0;
    if (image_file_off >= fileData.size())
        return false;
    size_t len = std::min(image_len, fileData.size() - image_file_off);
    if (len == 0)
        return false;

    Options cfg_opts = opts;
    cfg_opts.showCfg = false; // never human CFG dump from listing
    CfgGraph g = cfg_build_annotated(fileData, image_file_off, len, entry_ip, cs_seg,
                                     cfg_opts);
    if (g.blocks.empty())
    {
        out_text = "; dumpexe listing: no basic blocks recovered\n";
        return true;
    }

    out_text = listing_emit_text(g, entry_ip, opts, source_name, n_procs, n_insns);
    return true;
}

/// Write listing to stdout (human) and/or default/override .asm file.
static inline void listing_deliver(const Options& opts,
                                   const std::string& input_path,
                                   const std::string& text,
                                   size_t n_procs,
                                   size_t n_insns)
{
    if (text.empty())
        return;

    // Human stdout (not in --json mode)
    if (!opts.jsonOut)
    {
        std::cout << "\n=== Multi-pass assembly listing ===\n";
        std::cout << text;
        if (!text.empty() && text.back() != '\n')
            std::cout << "\n";
    }

    // Default-on .asm file (cli-design: only --no-asm-file disables)
    if (opts.writeAsmFile)
    {
        std::string path = opts.outputPath.empty()
                               ? listing_default_asm_path(input_path)
                               : opts.outputPath;
        if (path == "-")
        {
            // explicit stdout only already done
            std::cerr << std::format(
                "listing: {} procs, {} insns (stdout only, -o -)\n", n_procs,
                n_insns);
            return;
        }
        std::ofstream f(path);
        if (!f)
        {
            std::cerr << "Error: cannot write listing to '" << path << "'\n";
            return;
        }
        f << text;
        f.flush();
        std::cerr << std::format("listing: wrote {} ({} procs, {} insns)\n", path,
                                 n_procs, n_insns);
    }
}

/**
 * @brief Run multi-pass listing for MZ/COM-style image and deliver outputs.
 */
static inline void listing_run(const std::vector<uint8_t>& fileData,
                               size_t image_file_off,
                               size_t image_len,
                               uint16_t entry_ip,
                               uint16_t cs_seg,
                               const Options& opts,
                               const std::string& input_path)
{
    std::string text;
    size_t n_procs = 0, n_insns = 0;
    if (!listing_generate(fileData, image_file_off, image_len, entry_ip, cs_seg, opts,
                          input_path, text, n_procs, n_insns))
    {
        if (!opts.jsonOut)
            std::cout << "\nListing: image offset outside file or empty.\n";
        return;
    }
    listing_deliver(opts, input_path, text, n_procs, n_insns);
}

/**
 * @brief Backward-compatible entry: multi-pass listing from a file slice.
 *
 * @param data   Full file bytes
 * @param offset File offset where the disassembly window starts
 * @param cs     Capstone CS base (segment)
 * @param ip     Entry IP (also used as first IP in window when window==entry)
 * @param opts   Options
 * @param input_path Original filename for .asm default naming (may be empty)
 *
 * When @p offset is the entry-point file offset, the image window is from
 * offset to EOF and entry_ip is @p ip only if the window starts at IP 0 of a
 * synthetic image — for COM we pass offset=0 and real entry_ip.
 */
static inline void disassemble(const std::vector<uint8_t>& data, size_t offset,
                               uint16_t cs, uint16_t ip, const Options& opts,
                               const std::string& input_path = {})
{
    if (offset >= data.size())
    {
        if (!opts.jsonOut)
            std::cout << "\nDisassembly: Entry point is beyond end of file.\n";
        return;
    }
    // Treat [offset, EOF) as image with entry at `ip` only when offset maps to
    // image IP 0. For classic MZ call (offset=entry file off, ip=entry IP),
    // use a synthetic image starting at entry with entry_ip=0... but then
    // symbols won't match real IPs. Prefer: image from offset with base IP = ip.
    //
    // CFG expects image[0] = IP 0. So for entry-only window we need file bytes
    // from (offset - ip) if ip is within image... For MZ, callers should use
    // listing_run on full load image. This wrapper builds a padded view:
    // if ip > 0 and offset >= ip, start image at offset-ip so image[ip]=entry.
    size_t img_off = offset;
    size_t entry = ip;
    if (ip > 0 && offset >= static_cast<size_t>(ip))
    {
        img_off = offset - static_cast<size_t>(ip);
        entry = ip;
    }
    else
    {
        // window starts at entry; remap entry to 0 for CFG — BAD for labels.
        // Keep entry as 0 and accept func_0000 as entry for slice mode.
        img_off = offset;
        entry = 0;
    }
    const size_t img_len = data.size() - img_off;
    const std::string path = input_path.empty() ? std::string("binary") : input_path;
    listing_run(data, img_off, img_len, static_cast<uint16_t>(entry), cs, opts, path);
}

#endif // LISTING_H
