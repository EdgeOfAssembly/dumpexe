// dumpexe.cpp - MS-DOS binary analyzer: MZ EXE, .COM, and device driver (.SYS)
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
// Target: 16-bit MS-DOS binaries (MZ EXE, plain .COM, and device drivers)

#include "dumpexe.h"

/// Print version information to stdout
static inline void print_version() {
    std::cout << "dumpexe 1.8 — 16-bit MS-DOS Binary Analyzer (TP/JWASM/MT+ export)\n"
                 "Copyright (c) 2026 EdgeOfAssembly <haxbox2000@gmail.com>\n"
                 "License: GPLv2 | Commercial (contact author)\n"
                 "Built with Capstone disassembly support: yes\n";
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

/// Load-image IP of the MZ entry (handles com2exe CS=FFF0 IP=0100 → IP 0).
static inline uint16_t mz_entry_image_ip(const MZHeader& header)
{
    const int32_t delta =
        static_cast<int32_t>(static_cast<int16_t>(header.cs)) * 16 +
        static_cast<int32_t>(header.ip);
    if (delta <= 0)
        return 0;
    if (delta > 0xFFFF)
        return 0xFFFF;
    return static_cast<uint16_t>(delta);
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

int main(int argc, char* argv[]) {
    Options opts;
    if (!opts.parse(argc, argv)) { show_usage(argv[0]); return 1; }
    if (opts.showHelp)    { show_usage(argv[0]); return 0; }
    if (opts.showVersion) { print_version();     return 0; }

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
    const uint32_t sig32 = (fileData.size() >= 4)
        ? (static_cast<uint32_t>(fileData[0])        |
           (static_cast<uint32_t>(fileData[1]) << 8)  |
           (static_cast<uint32_t>(fileData[2]) << 16) |
           (static_cast<uint32_t>(fileData[3]) << 24))
        : 0u;

    if (sig16 == MZ_SIGNATURE) {
        if (fileData.size() < sizeof(MZHeader)) {
            std::cerr << "Error: File is too small to contain a valid MZ header\n";
            return 1;
        }
        MZHeader header;
        std::memcpy(&header, fileData.data(), sizeof(header));
        if (!validate_header(header, fileSize)) return 1;

        ExeSizes sizes = calculate_sizes(header, fileSize);
        const bool human = !opts.jsonOut;

        if (human)
            print_header_info(opts, header, sizes);

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

        // COM-in-EXE / JWASM / CuteMouse (skip weak asm if TP already identified)
        ToolchainReport tc_rep{};
        if (opts.toolchainDetect && !tp_rep.detected)
        {
            tc_rep = toolchain_analyze(fileData, header,
                                       static_cast<size_t>(sizes.headerSizeBytes));
            if (human)
                toolchain_print_report(tc_rep);
        }
        else if (opts.toolchainDetect && tp_rep.detected && human)
        {
            // still run COM-in-EXE only if needed? skip JWASM false positives
        }

        std::vector<RelocEntry> relocs;
        if (human)
        {
            dump_relocations(opts, header, fileData, sizes, relocs);
            dump_hex(opts, fileData, sizes);
        }
        else if (opts.showReloc || opts.showAll)
        {
            // Still load relocs if requested for future JSON; skip for now
            dump_relocations(opts, header, fileData, sizes, relocs);
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

        if ((opts.showDisasm || opts.showAll) && !opts.jsonOut) {
            // Multi-pass listing on full load image (real IPs / func_* labels).
            // No separate --listing: -d/-a *is* the annotated listing.
            size_t cfg_file_off = 0, cfg_len = 0;
            uint16_t cs_seg = 0;
            mz_cfg_window(header, sizes, cfg_file_off, cfg_len, cs_seg, opts);
            // TP → Turbo Pascal export; JWASM → JWASM export; else human listing
            listing_run(fileData, cfg_file_off, cfg_len,
                        mz_entry_image_ip(header), cs_seg, opts, opts.filename,
                        opts.toolchainDetect ? &tc_rep : nullptr,
                        opts.toolchainDetect ? &tp_rep : nullptr);
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
            if (opts.jsonOut && !opts.showCfg)
                cfg_opts.showCfg = false; // DOT/JSON only — no human CFG dump
            cfg_g = cfg_analyze_image(fileData, cfg_file_off, cfg_len,
                                      mz_entry_image_ip(header), cs_seg, cfg_opts);
            cfg_ran = true;
        }

        if (opts.simulate)
            run_simulation(opts, header, fileData, relocs, sizes);

        if (opts.jsonOut)
        {
            JsonReport rep;
            rep.set_mz(opts.filename, header, sizes, fileSize);
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

    } else if (sig32 == 0xFFFFFFFF) {
        if (opts.jsonOut) {
            JsonReport rep;
            rep.file = opts.filename;
            rep.format = "sys";
            rep.print(std::cout);
        } else {
            analyze_sys(opts, fileData, fileSize);
        }

    } else {
        if (opts.jsonOut) {
            JsonReport rep;
            rep.file = opts.filename;
            rep.format = "com";
            rep.file_size = static_cast<uint32_t>(fileSize);
            rep.print(std::cout);
        } else {
            analyze_com(opts, fileData, fileSize);
        }
    }

    return 0;
}
