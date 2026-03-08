// dumpexe.cpp - MS-DOS binary analyzer: MZ EXE, .COM, and device driver (.SYS)
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
// Target: 16-bit MS-DOS binaries (MZ EXE, plain .COM, and device drivers)

#include "dumpexe.h"

/// Print version information to stdout
static inline void print_version() {
    std::cout << "dumpexe 1.0 — 16-bit MS-DOS Binary Analyzer & Single-Pass Disassembler\n"
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
        // Even a 1-byte .COM is theoretically valid; only reject empty files.
        std::cerr << "Error: File is empty and cannot be a valid DOS binary\n";
        return 1;
    }

    // Content-based format detection.
    // Read up to 4 bytes for signature matching; pad with zeroes for short files.
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
        // --- MZ EXE path ---
        if (fileData.size() < sizeof(MZHeader)) {
            std::cerr << "Error: File is too small to contain a valid MZ header\n";
            return 1;
        }
        MZHeader header;
        std::memcpy(&header, fileData.data(), sizeof(header));
        if (!validate_header(header, fileSize)) return 1;

        ExeSizes sizes = calculate_sizes(header, fileSize);
        print_header_info(opts, header, sizes);

        std::vector<RelocEntry> relocs;
        dump_relocations(opts, header, fileData, sizes, relocs);
        dump_hex(opts, fileData, sizes);

        if (opts.showDisasm || opts.showAll) {
            disassemble(fileData, sizes.entryPointFileOffset,
                        static_cast<uint16_t>(header.cs), header.ip, opts);
        }

        run_simulation(opts, header, fileData, relocs, sizes);

    } else if (sig32 == 0xFFFFFFFF) {
        // --- DOS device driver (.SYS) path ---
        analyze_sys(opts, fileData, fileSize);

    } else {
        // --- .COM path (fallback for any unrecognized flat DOS binary) ---
        analyze_com(opts, fileData, fileSize);
    }

    return 0;
}

