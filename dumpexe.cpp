// dumpexe.cpp - MS-DOS / Win16 binary analyzer: MZ EXE, NE, .COM, .SYS
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
// Target: 16-bit MS-DOS binaries and Windows 3.x NE (New Executable)

#include "dumpexe.h"

/// Print version information to stdout, including the linked Capstone version.
static inline void print_version()
{
    int cap_major = 0;
    int cap_minor = 0;
    (void)cs_version(&cap_major, &cap_minor);
    std::cout << "dumpexe 2.13 — 16/32-bit MS-DOS (extender) + Win16 NE Analyzer\n"
                 "Copyright (c) 2026 EdgeOfAssembly <haxbox2000@gmail.com>\n"
                 "License: GPLv2 | Commercial (contact author)\n";
    std::cout << std::format(
        "Built with Capstone disassembly support: yes (Capstone {}.{})\n",
        cap_major, cap_minor);
}

/**
 * @brief One JSON object for a rejected MZ, then exit status 1.
 *
 * Stderr already has the human error. With @c --json, stdout is that
 * object and nothing else. Without @c --json this only returns 1.
 *
 * @param opts Parsed options. @c filename is copied into the object.
 * @return Always 1.
 */
static int dx_mz_json_reject(const Options& opts)
{
    if (opts.jsonOut)
    {
        JsonReport rep;
        rep.file = opts.filename;
        rep.format = "mz";
        rep.error = "rejected MZ header";
        rep.print(std::cout);
    }
    return 1;
}

/**
 * @brief True when strategy and interrupt offsets fall inside the file.
 *
 * Both must be non-zero. Offsets are from @p base, the file offset of
 * this device header.
 *
 * @param data File bytes.
 * @param base File offset of @p header.
 * @param header Device header at @p base.
 * @return True when both entry points are inside @p data.
 */
static bool dx_sys_entries_in_file(const std::vector<uint8_t>& data,
                                  size_t base,
                                  const SYSHeader& header)
{
    if (header.strategy == 0 || header.interrupt == 0)
    {
        return false;
    }
    if (base >= data.size())
    {
        return false;
    }
    const size_t room = data.size() - base;
    if (static_cast<size_t>(header.strategy) >= room)
    {
        return false;
    }
    if (static_cast<size_t>(header.interrupt) >= room)
    {
        return false;
    }
    return true;
}

/**
 * @brief DOS device driver, including a chained header.
 *
 * The last driver in a chain stores @c next_driver as 0xFFFFFFFF. A
 * chained header stores segment 0 and an offset to a second header
 * whose strategy and interrupt also lie inside the file. A flat COM
 * image does not satisfy both checks.
 *
 * @param data File bytes.
 * @return True when @p data begins with a .SYS device header.
 */
static bool dx_is_sys_image(const std::vector<uint8_t>& data)
{
    if (data.size() < sizeof(SYSHeader))
    {
        return false;
    }
    SYSHeader header{};
    std::memcpy(&header, data.data(), sizeof(header));
    if (!dx_sys_entries_in_file(data, 0, header))
    {
        return false;
    }
    if (header.next_driver == 0xFFFFFFFFu)
    {
        return true;
    }
    const uint16_t next_off = static_cast<uint16_t>(header.next_driver & 0xFFFFu);
    const uint16_t next_seg = static_cast<uint16_t>(header.next_driver >> 16);
    if (next_seg != 0 || next_off == 0)
    {
        return false;
    }
    if (static_cast<size_t>(next_off) + sizeof(SYSHeader) > data.size())
    {
        return false;
    }
    SYSHeader next{};
    std::memcpy(&next, data.data() + next_off, sizeof(next));
    return dx_sys_entries_in_file(data, next_off, next);
}

/// Read the entire contents of a file into a byte vector.
/// Returns false and prints an error if the file cannot be opened or read.
static inline bool read_entire_file(const std::string& filename,
                                    std::vector<uint8_t>& data,
                                    int64_t& fileSize) {
    try {
        fileSize = static_cast<int64_t>(std::filesystem::file_size(filename));
    } catch (...) {
        std::cerr << "Error: Cannot get file size of '" << filename << "'\n";
        return false;
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open file '" << filename << "'\n";
        return false;
    }

    const std::size_t bufferSize = static_cast<std::size_t>(fileSize);
    data.resize(bufferSize);
    file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(bufferSize));
    if (!file || file.gcount() != static_cast<std::streamsize>(bufferSize)) {
        std::cerr << "Error: Failed to read full contents of '" << filename << "'\n";
        return false;
    }
    return true;
}

/**
 * @brief Load-image IP of the MZ entry.
 *
 * com2exe CS=FFF0 IP=0100 becomes IP 0. An entry past the 64 KiB window is
 * not clamped to FFFF: that label is the wrong place, and the window stays.
 */
struct MzEntryLoc
{
    uint16_t ip = 0;
    bool in_window = true;
};

static inline MzEntryLoc mz_entry_image_ip(const MZHeader& header)
{
    MzEntryLoc loc{};
    const int32_t delta =
        static_cast<int32_t>(static_cast<int16_t>(header.cs)) * 16 +
        static_cast<int32_t>(header.ip);
    if (delta <= 0)
    {
        loc.ip = 0;
        return loc;
    }
    if (delta > 0xFFFF)
    {
        loc.ip = 0;
        loc.in_window = false;
        return loc;
    }
    loc.ip = static_cast<uint16_t>(delta);
    return loc;
}

/// Shared MZ image window for CFG (CS-relative).
static inline void mz_cfg_window(const MZHeader& header,
                                 const ExeSizes& sizes,
                                 size_t& cfg_file_off,
                                 size_t& cfg_len,
                                 uint16_t& cs_seg,
                                 const Options& opts)
{
    const size_t img_off = sizes.headerSizeBytes;
    const size_t img_len = (sizes.loadImageSize > 0)
        ? static_cast<size_t>(sizes.loadImageSize)
        : 0;
    // Prefer loadBase as CS for image[0]=IP0 (works for CS=0 and com2exe).
    cs_seg = opts.loadBase;
    (void)header;
    cfg_file_off = img_off;
    cfg_len = img_len;
}

#include "unpack_integrate.h"

int main(int argc, char* argv[]) {
    Options opts;
    if (!opts.parse(argc, argv)) { show_usage(argv[0]); return 1; }
    if (opts.showHelp)    { show_usage(argv[0]); return 0; }
    if (opts.showVersion) { print_version();     return 0; }

    if (opts.uasm && !opts.writeAsmFile && opts.outputPath.empty())
    {
        std::cerr << "dumpexe: --uasm needs an .asm file\n";
        return 1;
    }

    if (opts.filename.empty()) {
        std::cerr << "Error: No file specified\n\n";
        show_usage(argv[0]);
        return 1;
    }

    // Load file and detect format from first bytes
    int64_t fileSize = 0;
    std::vector<uint8_t> fileData;
    if (!read_entire_file(opts.filename, fileData, fileSize)) return 1;

    if (fileData.empty()) {
        std::cerr << "Error: File is empty and cannot be a valid DOS binary\n";
        return 1;
    }

    const uint16_t sig16 = static_cast<uint16_t>(fileData[0]) |
                           (fileData.size() >= 2
                                ? static_cast<uint16_t>(fileData[1]) << 8
                                : uint16_t{0});

    if (sig16 == MZ_SIGNATURE) {
        if (fileData.size() < sizeof(MZHeader)) {
            std::cerr << "Error: File is too small to contain a valid MZ header\n";
            return dx_mz_json_reject(opts);
        }

        // Win 3.x NE: MZ stub + e_lfanew → "NE". A planted "NE" that does not
        // parse (truncated segment table, etc.) warns and falls through to MZ.
        {
            uint32_t e_lfanew = 0;
            if (ne_probe(fileData, e_lfanew))
            {
                if (opts.uasm)
                {
                    NEParsed ne_tmp;
                    if (ne_parse(fileData, ne_tmp))
                    {
                        std::cerr << "dumpexe: --uasm is implemented for MZ and COM\n";
                        return 1;
                    }
                }
                std::string ne_error;
                if (analyze_ne(opts, fileData, fileSize, ne_error))
                    return 0;
                std::cerr << std::format(
                    "Warning: {} (NE at e_lfanew 0x{:X}; falling back to MZ)\n",
                    ne_error, e_lfanew);
            }
        }

        MZHeader header;
        std::memcpy(&header, fileData.data(), sizeof(header));
        if (!validate_header(header, fileSize))
            return dx_mz_json_reject(opts);

        ExeSizes sizes = calculate_sizes(header, fileSize);
        const bool human = !opts.jsonOut && !opts.uasm_stdout_only();

        if (human)
            print_header_info(opts, header, sizes);

        // DOS extender / DPMI (default ON) — may switch Capstone to 32-bit
        DosExtenderReport dext_rep{};
        if (opts.dosExtenderDetect)
        {
            dext_rep = dos_extender_analyze(fileData, header);
            if (human)
                dos_extender_print_report(dext_rep);
            // Auto bits: 32 when extender says so, unless user forced --bits=
            if (opts.x86Bits == 0 && dext_rep.detected && dext_rep.x86_bits == 32)
                opts.x86Bits = 32;
            else if (opts.x86Bits == 0)
                opts.x86Bits = 16;
            if (opts.uasm && dext_rep.detected && dext_rep.x86_bits == 32)
            {
                std::cerr << "dumpexe: --uasm is implemented for MZ and COM\n";
                return 1;
            }
        }
        else if (opts.x86Bits == 0)
        {
            opts.x86Bits = 16;
        }

        // Pascal MT+ (default ON)
        PascalMtReport mt_rep{};
        if (opts.pascalMt)
        {
            mt_rep = pascal_mt_analyze(
                fileData,
                static_cast<size_t>(sizes.headerSizeBytes),
                static_cast<size_t>(sizes.loadImageSize),
                static_cast<size_t>(header.ip));
            if (human)
                pascal_mt_print_report(mt_rep);
        }

        // Turbo Pascal 5.x (before weak asm heuristics)
        TurboPascalReport tp_rep{};
        if (opts.toolchainDetect)
        {
            tp_rep = turbo_pascal_analyze(
                fileData, header, static_cast<size_t>(sizes.headerSizeBytes),
                static_cast<size_t>(sizes.entryPointFileOffset));
            if (human)
                turbo_pascal_print_report(tp_rep);
        }

        // COM-in-EXE / JWASM / CuteMouse. A Turbo Pascal hit skips those
        // heuristics (they false-positive on TP) but still scans banners.
        ToolchainReport tc_rep{};
        if (opts.toolchainDetect && !tp_rep.detected)
        {
            tc_rep = toolchain_analyze(fileData, header,
                                       static_cast<size_t>(sizes.headerSizeBytes));
            if (human)
                toolchain_print_report(tc_rep);
        }
        else if (opts.toolchainDetect && tp_rep.detected)
        {
            tc_rep = toolchain_fingerprints_only(fileData);
            if (human)
                toolchain_print_report(tc_rep);
        }

        std::vector<RelocEntry> relocs;
        if (human)
        {
            dump_relocations(opts, header, fileData, sizes, relocs);
            dump_hex(opts, fileData, sizes);
        }
        else
        {
            load_relocations(header, fileData, relocs);
        }

        std::vector<ExtractedString> strs;
        if (opts.showStrings || opts.showAll || opts.jsonOut)
        {
            const size_t img_off = static_cast<size_t>(sizes.headerSizeBytes);
            size_t img_len = static_cast<size_t>(sizes.loadImageSize);
            if (img_len == 0 || img_off + img_len > fileData.size())
                img_len = fileData.size() > img_off ? fileData.size() - img_off : 0;
            std::vector<uint8_t> image(
                fileData.begin() + static_cast<std::ptrdiff_t>(img_off),
                fileData.begin() + static_cast<std::ptrdiff_t>(img_off + img_len));
            extract_strings(image, strs, 4);
            // Fix file offsets: extract_strings uses image-relative as file_off
            for (auto& s : strs)
            {
                s.file_off += img_off;
                if (s.len_byte_off)
                    s.len_byte_off += img_off;
            }
            if (human && (opts.showStrings || opts.showAll))
                print_strings_report(strs);
        }

        const bool want_listing_file =
            !opts.outputPath.empty() && opts.outputPath != "-";
        const bool want_human_listing =
            (opts.showDisasm || opts.showAll) && !opts.jsonOut;
        // --json -d -o FILE still writes the listing. JSON stays on stdout.
        const bool want_json_listing_file =
            opts.jsonOut && want_listing_file &&
            (opts.showDisasm || opts.showAll || opts.uasm);
        if (opts.uasm || want_human_listing || want_json_listing_file) {
            int listing_rc = 0;
            if (opts.x86Bits == 32 && dext_rep.detected &&
                dext_rep.payload_len > 0)
            {
                // 32-bit extender payload: linear Capstone CS_MODE_32.
                // --uasm already rejected this above.
                if (want_human_listing)
                    dos_extender_disasm_payload(fileData, dext_rep, opts);
            }
            else
            {
                // Multi-pass 16-bit listing on full load image.
                size_t cfg_file_off = 0, cfg_len = 0;
                uint16_t cs_seg = 0;
                mz_cfg_window(header, sizes, cfg_file_off, cfg_len, cs_seg, opts);
                const MzEntryLoc entry = mz_entry_image_ip(header);
                listing_rc = listing_run(fileData, cfg_file_off, cfg_len,
                                entry.ip, cs_seg, static_cast<uint16_t>(header.cs), opts, opts.filename,
                                opts.toolchainDetect ? &tc_rep : nullptr,
                                opts.toolchainDetect ? &tp_rep : nullptr,
                                false, false, entry.in_window);
            }
            // A refused packed listing must not hide the unpack report.
            if (want_human_listing || (opts.uasm && !opts.jsonOut))
                dx_after_packed_listing(opts, fileData, tc_rep.packer);
            if (listing_rc != 0)
                return 1;
        }

        // CFG: human --cfg, Graphviz --cfg-dot, or always under --json (scripting)
        CfgGraph cfg_g{};
        bool cfg_ran = false;
        if (opts.showCfg || !opts.cfgDotPath.empty() || opts.jsonOut)
        {
            size_t cfg_file_off = 0, cfg_len = 0;
            uint16_t cs_seg = 0;
            mz_cfg_window(header, sizes, cfg_file_off, cfg_len, cs_seg, opts);
            Options cfg_opts = opts;
            if ((opts.jsonOut && !opts.showCfg) || opts.uasm_stdout_only())
                cfg_opts.showCfg = false; // DOT/JSON or --uasm -o - — no human CFG dump
            const MzEntryLoc cfg_entry = mz_entry_image_ip(header);
            cfg_g = cfg_analyze_image(fileData, cfg_file_off, cfg_len,
                                      cfg_entry.in_window ? cfg_entry.ip : uint16_t{0},
                                      cs_seg, static_cast<uint16_t>(header.cs), cfg_opts);
            cfg_ran = true;
        }

        if (opts.simulate && !opts.uasm_stdout_only())
        {
            if (opts.x86Bits == 32 ||
                (dext_rep.detected && dext_rep.x86_bits == 32))
            {
                std::cerr << "Note: --simulate is real-mode 16-bit only; "
                             "32-bit DOS extender simulation is not implemented.\n";
            }
            else
            {
                run_simulation(opts, header, fileData, relocs, sizes);
            }
        }

        if (opts.jsonOut)
        {
            JsonReport rep;
            rep.set_mz(opts.filename, header, sizes, fileSize);
            rep.set_relocs(relocs);
            if (opts.pascalMt)
            {
                rep.pascal_mt = std::move(mt_rep);
                rep.pascal_mt_ran = true;
            }
            if (opts.toolchainDetect)
            {
                rep.toolchain = std::move(tc_rep);
                rep.toolchain_ran = true;
            }
            rep.strings = std::move(strs);
            rep.strings_ran = true;
            if (cfg_ran)
            {
                rep.cfg = std::move(cfg_g);
                rep.cfg_ran = true;
                rep.cfg_dot_path = opts.cfgDotPath;
            }
            rep.print(std::cout);
        }

    } else if (dx_is_sys_image(fileData)) {
        if (opts.uasm)
        {
            std::cerr << "dumpexe: --uasm is implemented for MZ and COM\n";
            return 1;
        }
        ToolchainReport tc_rep{};
        if (opts.toolchainDetect)
            tc_rep = toolchain_fingerprints_only(fileData);
        if (opts.jsonOut) {
            JsonReport rep;
            rep.file = opts.filename;
            rep.format = "sys";
            if (opts.toolchainDetect)
            {
                rep.toolchain = std::move(tc_rep);
                rep.toolchain_ran = true;
            }
            rep.print(std::cout);
        } else {
            analyze_sys(opts, fileData, fileSize);
            if (opts.toolchainDetect)
                toolchain_print_report(tc_rep);
            dx_after_packed_listing(opts, fileData, tc_rep.packer);
        }

    } else {
        // Same PSP order as analyze_com: --psp, --no-psp, else detect_psp.
        bool has_psp = false;
        if (opts.comForcePsp)
            has_psp = true;
        else if (opts.comForceNoPsp)
            has_psp = false;
        else
            has_psp = detect_psp(fileData);
        const size_t entry_offset = has_psp ? static_cast<size_t>(COM_PSP_SIZE) : 0;

        ToolchainReport tc_rep{};
        if (opts.toolchainDetect)
            tc_rep = toolchain_fingerprints_only(fileData);

        const bool com_json_listing =
            opts.jsonOut &&
            (opts.uasm ||
             ((opts.showDisasm || opts.showAll) && !opts.outputPath.empty() &&
              opts.outputPath != "-"));
        if (com_json_listing) {
            std::vector<uint8_t> image;
            com_listing_image(fileData, has_psp, image);
            if (listing_run(image, 0, image.size(), COM_ENTRY_IP, opts.loadBase,
                            opts.loadBase, opts, opts.filename, nullptr, nullptr, true,
                            has_psp) != 0)
            {
                return 1;
            }
        }
        if (opts.jsonOut) {
            JsonReport rep;
            rep.file = opts.filename;
            rep.format = "com";
            rep.file_size = static_cast<uint32_t>(fileSize);
            // In memory CS:IP is always load_segment:0100h. The file offset
            // follows the human report: 0x100 with an embedded PSP, else 0.
            rep.entry_ip = COM_ENTRY_IP;
            rep.entry_file_offset = entry_offset;
            rep.load_model = has_psp ? "psp" : "org100";
            if (opts.toolchainDetect)
            {
                rep.toolchain = std::move(tc_rep);
                rep.toolchain_ran = true;
            }
            rep.print(std::cout);
        } else {
            const int com_rc = analyze_com(opts, fileData, fileSize);
            if (opts.toolchainDetect && !opts.uasm_stdout_only())
                toolchain_print_report(tc_rep);
            dx_after_packed_listing(opts, fileData, tc_rep.packer);
            if (com_rc != 0)
                return 1;
        }
    }

    return 0;
}
