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
#include "symbols.h"
#include "toolchain.h"
#include "turbo_pascal.h"

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
                                           std::set<uint16_t>& proc_starts,
                                           const SymbolMap* external = nullptr)
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

    // External ground-truth names first (CuteMouse .sym, TLINK maps, …)
    if (external)
    {
        for (const auto& kv : external->by_ip)
        {
            sym[kv.first] = kv.second;
            proc_starts.insert(kv.first);
        }
    }

    add(entry_ip, "entry");
    if (!sym.count(entry_ip))
        sym[entry_ip] = listing_symbol_name(entry_ip);

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
                                            size_t& n_insns,
                                            const SymbolMap* external = nullptr)
{
    std::map<uint16_t, std::string> sym;
    std::set<uint16_t> proc_starts;
    listing_collect_symbols(g, entry_ip, sym, proc_starts, external);
    n_procs = proc_starts.size();
    n_insns = 0;

    std::ostringstream out;
    out << "; dumpexe multi-pass listing (not single-stream Capstone only)\n";
    out << std::format("; source: {}\n", source_name);
    out << std::format("; CS={:04X}h  entry={:04X}h  blocks={}  symbols={}\n",
                       g.cs_seg, entry_ip, g.blocks.size(), sym.size());
    out << "; labels: func_<IP> (+ names from --map / <stem>.sym when present)\n";
    out << "; call/jmp/jcc near targets rewritten to labels when known\n";
    out << "; blank line after procedure regions ending in ret/retf/iret\n";
    if (external && !external->source_path.empty())
        out << std::format("; symbol map: {} ({} names)\n", external->source_path,
                           external->count);
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
// JWASM / MASM assemblable export (when toolchain is JWASM)
//=============================================================================

/// Capstone / 0x… → MASM-ish operand text for JWASM 1.8.
static inline std::string listing_masm_ops(std::string ops)
{
    // 0xAB → 0ABh (leading 0 if starts with A–F)
    std::string out;
    out.reserve(ops.size() + 8);
    for (size_t i = 0; i < ops.size();)
    {
        if (i + 2 < ops.size() && ops[i] == '0' &&
            (ops[i + 1] == 'x' || ops[i + 1] == 'X'))
        {
            size_t j = i + 2;
            while (j < ops.size() && std::isxdigit(static_cast<unsigned char>(ops[j])))
                ++j;
            std::string hex = ops.substr(i + 2, j - (i + 2));
            for (char& c : hex)
                c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            if (!hex.empty() && hex[0] >= 'A' && hex[0] <= 'F')
                out.push_back('0');
            out += hex;
            out.push_back('h');
            i = j;
            continue;
        }
        out.push_back(ops[i]);
        ++i;
    }
    // strip spaces around + - in brackets lightly
    return out;
}

static inline std::string listing_masm_mnem(std::string m)
{
    for (char& c : m)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (m == "popaw")
        return "popa";
    if (m == "pushaw")
        return "pusha";
    if (m == "retn")
        return "ret";
    if (m == "retf" || m == "retfq")
        return "retf";
    if (m == "callw")
        return "call";
    if (m == "jmpw")
        return "jmp";
    return m;
}

/**
 * @brief Emit JWASM 1.8-assemblable tiny-model source covering the full image.
 *
 * Policy: if dumpexe identifies JWASM, the .asm product must be compilable
 * with bin/jwasm/jwasm-1.8.exe (not a hex dump listing).
 */
static inline std::string listing_emit_jwasm(const CfgGraph& g,
                                            const std::vector<uint8_t>& image,
                                            uint16_t entry_ip,
                                            const Options& opts,
                                            const std::string& source_name,
                                            const ToolchainReport& tc,
                                            size_t& n_procs,
                                            size_t& n_insns,
                                            const SymbolMap* external)
{
    std::map<uint16_t, std::string> sym;
    std::set<uint16_t> proc_starts;
    listing_collect_symbols(g, entry_ip, sym, proc_starts, external);
    n_procs = proc_starts.size();
    n_insns = 0;

    // Index instructions by IP (first wins)
    std::map<uint16_t, CfgInsn> at;
    std::map<uint16_t, const CfgBlock*> blk_at;
    for (const auto& kv : g.blocks)
    {
        const CfgBlock& b = kv.second;
        for (const auto& in : b.insns)
        {
            if (!at.count(in.ip))
            {
                at[in.ip] = in;
                blk_at[in.ip] = &b;
            }
        }
    }

    std::ostringstream out;
    // Memory model policy:
    //   • pure .COM or COM-in-EXE → always tiny (≤64KB single segment; no exceptions)
    //   • else if --model= set → user value
    //   • else → small (default when unknown)
    const bool is_com_image = tc.com_in_exe; // COM-wrapped MZ; pure COM sets this too via caller
    std::string model;
    std::string model_why;
    if (is_com_image)
    {
        model = "tiny";
        model_why = " (forced: .COM / COM-in-EXE ≤64K — no exceptions)";
        if (opts.memModelUserSet && opts.memModel != "tiny")
            model_why += " [--model= ignored for COM]";
    }
    else if (opts.memModelUserSet)
    {
        model = opts.memModel;
        model_why = " (--model=)";
    }
    else
    {
        model = "small";
        model_why = " (default when unknown)";
    }

    out << "; dumpexe JWASM-export — assemblable with JWASM 1.80\n";
    out << std::format("; source binary: {}\n", source_name);
    out << std::format("; toolchain: {} {}\n", tc.assembler, tc.assembler_version);
    out << std::format("; memory model: {}{}\n", model, model_why);
    out << "; assemble: wine bin/jwasm/jwasm-1.8.exe -Fo out.obj this.asm\n";
    out << ";   (model is in the source via .model — do not also pass -mt/-ms)\n";
    out << "; layout: full load image as db + labels (byte-exact; disasm in comments)\n";
    if (external && !external->source_path.empty())
        out << std::format("; symbols: {}\n", external->source_path);
    out << ";\n";
    out << std::format(".model {}\n", model);
    out << ".code\n";
    // .COM / COM-in-EXE: image[0] is first COM byte at runtime org 100h
    if (model == "tiny")
        out << "org 100h\n";
    else
        out << "org 0\n";
    out << "\n";

    const size_t img_sz = image.size();
    auto emit_label = [&](uint16_t ip)
    {
        if (!sym.count(ip) && !proc_starts.count(ip))
            return;
        const std::string name =
            sym.count(ip) ? sym[ip] : listing_symbol_name(ip);
        out << name << ":";
        if (ip == entry_ip)
            out << "\t\t; entry";
        out << "\n";
    };

    auto emit_db_run = [&](size_t from, size_t to, std::string_view comment)
    {
        if (from >= to || from >= img_sz)
            return;
        if (to > img_sz)
            to = img_sz;
        for (size_t i = from; i < to;)
        {
            out << "\tdb\t";
            size_t line_end = std::min(to, i + 12);
            for (size_t j = i; j < line_end; ++j)
            {
                if (j > i)
                    out << ", ";
                // MASM: hex constants need leading digit
                out << std::format("0{:02X}h", image[j]);
            }
            if (i == from && !comment.empty())
                out << "\t; " << comment;
            out << "\n";
            i = line_end;
        }
    };

    /*
     * Byte-exact export: emit the full image as db with labels + disasm comments.
     * Capstone→MASM text is not reliable enough for JWASM 1.8 (CPU level, PTR
     * sizes, popa/pusha, …). Raw bytes always assemble and preserve layout;
     * comments keep the listing readable. Rebuild: jwasm -mt → link → com2exe.
     */
    size_t ip = 0;
    while (ip < img_sz)
    {
        const uint16_t uip = static_cast<uint16_t>(ip & 0xFFFF);
        emit_label(uip);

        auto it = at.find(uip);
        if (it != at.end() && it->second.size > 0 &&
            ip + it->second.size <= img_sz)
        {
            const CfgInsn& in = it->second;
            bool match = true;
            for (uint8_t k = 0; k < in.size; ++k)
            {
                if (image[ip + k] != in.bytes[k])
                {
                    match = false;
                    break;
                }
            }
            std::string comment;
            if (match)
            {
                std::string mnem = in.text;
                std::string ops;
                size_t sp = in.text.find(' ');
                if (sp != std::string::npos)
                {
                    mnem = in.text.substr(0, sp);
                    ops = in.text.substr(sp + 1);
                }
                std::string mlow = listing_masm_mnem(mnem);
                const CfgBlock* bp = blk_at.count(uip) ? blk_at[uip] : nullptr;
                std::string rops = ops;
                if (bp)
                    rops = listing_rewrite_ops(mlow, ops, *bp, sym);
                rops = listing_masm_ops(rops);
                comment = rops.empty() ? mlow : (mlow + " " + rops);
                ++n_insns;
                emit_db_run(ip, ip + in.size, comment);
                ip += in.size;
            }
            else
            {
                emit_db_run(ip, ip + 1, {});
                ++ip;
            }
            continue;
        }

        size_t run_end = ip + 1;
        while (run_end < img_sz)
        {
            const uint16_t u = static_cast<uint16_t>(run_end & 0xFFFF);
            if (at.count(u) || sym.count(u) || proc_starts.count(u))
                break;
            ++run_end;
        }
        emit_db_run(ip, run_end, {});
        ip = run_end;
    }

    // Entry symbol for END
    std::string entry_name =
        sym.count(entry_ip) ? sym[entry_ip] : listing_symbol_name(entry_ip);
    out << "\nend " << entry_name << "\n";
    out << std::format("; end JWASM-export: {} insns, {} labels, image {} bytes\n",
                       n_insns, n_procs, img_sz);
    return out.str();
}

//=============================================================================
// Turbo Pascal–oriented export (when TP 5.x detected)
//=============================================================================

/**
 * @brief TASM-oriented reconstruction of a Turbo Pascal load image.
 *
 * Not a .PAS source (TPC compiles Pascal). Emits:
 *   - .MODEL LARGE|SMALL|… (COM → always tiny)
 *   - PROC/ENDP around Pascal frames where detected
 *   - byte-exact db with Capstone comments (TASM can assemble the bytes)
 *   - far-call density notes for unit linkage
 *
 * Assemble sketch: tasm /ml export.asm  (object is RE aid; full EXE still from TPC)
 */
static inline std::string listing_emit_turbo_pascal(const CfgGraph& g,
                                                    const std::vector<uint8_t>& image,
                                                    uint16_t entry_ip,
                                                    const Options& opts,
                                                    const std::string& source_name,
                                                    const TurboPascalReport& tp,
                                                    bool com_in_exe,
                                                    size_t& n_procs,
                                                    size_t& n_insns,
                                                    const SymbolMap* external)
{
    std::map<uint16_t, std::string> sym;
    std::set<uint16_t> proc_starts;
    listing_collect_symbols(g, entry_ip, sym, proc_starts, external);
    n_procs = proc_starts.size();
    n_insns = 0;

    std::map<uint16_t, CfgInsn> at;
    for (const auto& kv : g.blocks)
        for (const auto& in : kv.second.insns)
            if (!at.count(in.ip))
                at[in.ip] = in;

    // Model: COM → tiny always; else --model=; else LARGE if far-heavy TP, else small
    std::string model;
    std::string model_why;
    if (com_in_exe)
    {
        model = "tiny";
        model_why = " (forced: .COM / COM-in-EXE ≤64K)";
    }
    else if (opts.memModelUserSet)
    {
        model = opts.memModel;
        model_why = " (--model=)";
    }
    else if (tp.far_calls_entry >= 4 || tp.frame_5589e5 + tp.frame_558bec >= 40)
    {
        model = "large"; // typical TP program with units / far calls
        model_why = " (auto: TP far-call / dense frames → large)";
    }
    else
    {
        model = "small";
        model_why = " (default when unknown)";
    }

    std::ostringstream out;
    out << "; dumpexe Turbo Pascal export — TASM-oriented load-image reconstruction\n";
    out << "; NOT a .PAS file (TPC compiles Pascal source; this is RE assembly)\n";
    out << std::format("; source binary: {}\n", source_name);
    out << std::format("; compiler: {} {}\n", tp.compiler, tp.version);
    if (!tp.product.empty())
        out << std::format("; product: {}\n", tp.product);
    out << std::format("; toolchain: {}\n", tp.toolchain);
    out << std::format("; memory model: {}{}\n", model, model_why);
    out << "; frames: 55 89 E5 (TP near) / 55 8B EC; RTL \"Runtime error \"\n";
    out << "; assemble (bytes): tasm /ml this.asm   →  this.obj\n";
    out << "; original rebuild: TPC 5.5 + TASM {$L} units (see MAKECAT.BAT)\n";
    if (external && !external->source_path.empty())
        out << std::format("; symbols: {}\n", external->source_path);
    out << ";\n";

    // TASM: .MODEL TPASCAL is for TP-linked units; full EXE image uses LARGE/SMALL.
    if (model == "tiny")
        out << ".MODEL TINY\n";
    else if (model == "small")
        out << ".MODEL SMALL\n";
    else if (model == "medium")
        out << ".MODEL MEDIUM\n";
    else if (model == "compact")
        out << ".MODEL COMPACT\n";
    else if (model == "huge")
        out << ".MODEL HUGE\n";
    else
        out << ".MODEL LARGE\n";
    out << ".CODE\n";
    if (model == "tiny")
        out << "org 100h\n";
    else
        out << "org 0\n";
    out << "\n";

    const size_t img_sz = image.size();
    auto emit_db_run = [&](size_t from, size_t to, std::string_view comment)
    {
        if (from >= to || from >= img_sz)
            return;
        if (to > img_sz)
            to = img_sz;
        for (size_t i = from; i < to;)
        {
            out << "\tdb\t";
            size_t line_end = std::min(to, i + 12);
            for (size_t j = i; j < line_end; ++j)
            {
                if (j > i)
                    out << ", ";
                out << std::format("0{:02X}h", image[j]);
            }
            if (i == from && !comment.empty())
                out << "\t; " << comment;
            out << "\n";
            i = line_end;
        }
    };

    size_t ip = 0;
    bool in_proc = false;
    std::string cur_proc;
    auto close_proc = [&]()
    {
        if (in_proc)
        {
            out << cur_proc << "\tENDP\n\n";
            in_proc = false;
            cur_proc.clear();
        }
    };

    while (ip < img_sz)
    {
        const uint16_t uip = static_cast<uint16_t>(ip & 0xFFFF);

        // New procedure label
        if (sym.count(uip) || proc_starts.count(uip))
        {
            close_proc();
            const std::string name =
                sym.count(uip) ? sym[uip] : listing_symbol_name(uip);
            cur_proc = name;
            out << name;
            if (uip == entry_ip)
                out << "\tPROC\tFAR\t; program entry (CS:IP)";
            else
            {
                // Heuristic: Pascal near frame at start → NEAR PROC
                bool near_fr = false;
                if (ip + 3 <= img_sz)
                {
                    if (image[ip] == 0x55 && image[ip + 1] == 0x89 &&
                        image[ip + 2] == 0xE5)
                        near_fr = true;
                    if (image[ip] == 0x55 && image[ip + 1] == 0x8B &&
                        image[ip + 2] == 0xEC)
                        near_fr = true;
                }
                if (near_fr)
                    out << "\tPROC\tNEAR\t; Pascal frame";
                else
                    out << "\tPROC\tNEAR";
            }
            out << "\n";
            in_proc = true;
        }

        auto it = at.find(uip);
        if (it != at.end() && it->second.size > 0 &&
            ip + it->second.size <= img_sz)
        {
            const CfgInsn& in = it->second;
            bool match = true;
            for (uint8_t k = 0; k < in.size; ++k)
                if (image[ip + k] != in.bytes[k])
                {
                    match = false;
                    break;
                }
            std::string comment;
            if (match)
            {
                std::string mnem = in.text;
                std::string ops;
                size_t sp = in.text.find(' ');
                if (sp != std::string::npos)
                {
                    mnem = in.text.substr(0, sp);
                    ops = in.text.substr(sp + 1);
                }
                std::string mlow = listing_masm_mnem(mnem);
                std::string rops = listing_masm_ops(ops);
                comment = rops.empty() ? mlow : (mlow + " " + rops);
                // Tag Pascal frame / far call
                if (in.size >= 3 && in.bytes[0] == 0x55 && in.bytes[1] == 0x89 &&
                    in.bytes[2] == 0xE5)
                    comment += "  [TP near frame]";
                if (in.bytes[0] == 0x9A)
                    comment += "  [far call / unit]";
                if (in.bytes[0] == 0xCB)
                    comment += "  [retf]";
                if (in.bytes[0] == 0xC2 || in.bytes[0] == 0xC3)
                    comment += "  [ret]";
                ++n_insns;
                emit_db_run(ip, ip + in.size, comment);
                ip += in.size;
            }
            else
            {
                emit_db_run(ip, ip + 1, {});
                ++ip;
            }
            continue;
        }

        size_t run_end = ip + 1;
        while (run_end < img_sz)
        {
            const uint16_t u = static_cast<uint16_t>(run_end & 0xFFFF);
            if (at.count(u) || sym.count(u) || proc_starts.count(u))
                break;
            ++run_end;
        }
        emit_db_run(ip, run_end, {});
        ip = run_end;
    }
    close_proc();

    std::string entry_name =
        sym.count(entry_ip) ? sym[entry_ip] : listing_symbol_name(entry_ip);
    out << "\n\tEND\t" << entry_name << "\n";
    out << std::format(
        "; end Turbo Pascal export: {} insns, {} labels, image {} bytes\n", n_insns,
        n_procs, img_sz);
    return out.str();
}

//=============================================================================
// Public API
//=============================================================================

enum class ListingExportKind
{
    Human,
    Jwasm,
    TurboPascal
};

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
                                    size_t& n_insns,
                                    ListingExportKind& kind_out,
                                    const ToolchainReport* tc = nullptr,
                                    const TurboPascalReport* tp = nullptr)
{
    out_text.clear();
    n_procs = 0;
    n_insns = 0;
    kind_out = ListingExportKind::Human;
    if (image_file_off >= fileData.size())
        return false;
    size_t len = std::min(image_len, fileData.size() - image_file_off);
    if (len == 0)
        return false;

    Options cfg_opts = opts;
    cfg_opts.showCfg = false;
    CfgGraph g = cfg_build_annotated(fileData, image_file_off, len, entry_ip, cs_seg,
                                     cfg_opts);
    if (g.blocks.empty())
    {
        out_text = "; dumpexe listing: no basic blocks recovered\n";
        return true;
    }

    SymbolMap sm = symbols_load_for_input(opts, source_name);
    const SymbolMap* ext = sm.count ? &sm : nullptr;

    std::vector<uint8_t> image(
        fileData.begin() + static_cast<std::ptrdiff_t>(image_file_off),
        fileData.begin() + static_cast<std::ptrdiff_t>(image_file_off + len));

    const bool want_tp = tp && tp->detected;
    const bool want_jwasm =
        !want_tp && tc &&
        (tc->jwasm_1_8 || tc->assembler == "JWASM" ||
         (tc->com_in_exe && tc->jwasm_tasm_hint));

    if (want_tp)
    {
        kind_out = ListingExportKind::TurboPascal;
        const bool com = tc && tc->com_in_exe;
        out_text = listing_emit_turbo_pascal(g, image, entry_ip, opts, source_name, *tp,
                                             com, n_procs, n_insns, ext);
    }
    else if (want_jwasm)
    {
        kind_out = ListingExportKind::Jwasm;
        out_text = listing_emit_jwasm(g, image, entry_ip, opts, source_name, *tc,
                                      n_procs, n_insns, ext);
    }
    else
    {
        kind_out = ListingExportKind::Human;
        out_text =
            listing_emit_text(g, entry_ip, opts, source_name, n_procs, n_insns, ext);
    }
    return true;
}

/// Write listing to stdout and/or default/override .asm file.
static inline void listing_deliver(const Options& opts,
                                   const std::string& input_path,
                                   const std::string& text,
                                   size_t n_procs,
                                   size_t n_insns,
                                   ListingExportKind kind)
{
    if (text.empty())
        return;

    if (!opts.jsonOut)
    {
        if (kind == ListingExportKind::Jwasm)
            std::cout << "\n=== JWASM-assemblable export ===\n";
        else if (kind == ListingExportKind::TurboPascal)
            std::cout << "\n=== Turbo Pascal–oriented export (TASM bytes) ===\n";
        else
            std::cout << "\n=== Multi-pass assembly listing ===\n";
        std::cout << text;
        if (!text.empty() && text.back() != '\n')
            std::cout << "\n";
    }

    const bool want_file =
        !opts.outputPath.empty() || opts.writeAsmFile;
    if (want_file)
    {
        std::string path = opts.outputPath.empty()
                               ? listing_default_asm_path(input_path)
                               : opts.outputPath;
        if (path == "-")
        {
            std::cerr << std::format(
                "listing: {} procs, {} insns (stdout only, -o -)\n", n_procs,
                n_insns);
            return;
        }
        if (opts.outputPath.empty() && !opts.writeAsmFile)
            return;
        std::ofstream f(path);
        if (!f)
        {
            std::cerr << "Error: cannot write listing to '" << path << "'\n";
            return;
        }
        f << text;
        f.flush();
        if (kind == ListingExportKind::Jwasm)
            std::cerr << std::format(
                "listing: wrote JWASM-assemblable {} ({} procs, {} insns)\n"
                "         assemble: wine bin/jwasm/jwasm-1.8.exe -Fo out.obj {}\n",
                path, n_procs, n_insns, path);
        else if (kind == ListingExportKind::TurboPascal)
            std::cerr << std::format(
                "listing: wrote Turbo Pascal export {} ({} procs, {} insns)\n"
                "         TASM bytes: tasm /ml {}\n"
                "         original build: TPC 5.5 + TASM {{$L}} units\n",
                path, n_procs, n_insns, path);
        else
            std::cerr << std::format("listing: wrote {} ({} procs, {} insns)\n", path,
                                     n_procs, n_insns);
    }
}

/**
 * @brief Run multi-pass listing / JWASM / Turbo Pascal export.
 */
static inline void listing_run(const std::vector<uint8_t>& fileData,
                               size_t image_file_off,
                               size_t image_len,
                               uint16_t entry_ip,
                               uint16_t cs_seg,
                               const Options& opts,
                               const std::string& input_path,
                               const ToolchainReport* tc = nullptr,
                               const TurboPascalReport* tp = nullptr)
{
    std::string text;
    size_t n_procs = 0, n_insns = 0;
    ListingExportKind kind = ListingExportKind::Human;
    if (!listing_generate(fileData, image_file_off, image_len, entry_ip, cs_seg, opts,
                          input_path, text, n_procs, n_insns, kind, tc, tp))
    {
        if (!opts.jsonOut)
            std::cout << "\nListing: image offset outside file or empty.\n";
        return;
    }
    listing_deliver(opts, input_path, text, n_procs, n_insns, kind);
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
