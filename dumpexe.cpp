// dumpexe.cpp - MS-DOS MZ EXE header dumper, analyzer, and single-pass disassembler
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
// Target: 16-bit MS-DOS MZ EXE files only

#include "dumpexe.h"

/// Print version information to stdout
static inline void print_version() {
    std::cout << "dumpexe 1.0 — 16-bit MS-DOS MZ EXE Analyzer & Single-Pass Disassembler\n";
    std::cout << "Copyright (c) 2026 EdgeOfAssembly <haxbox2000@gmail.com>\n";
    std::cout << "License: GPLv2 | Commercial (contact author)\n";
    std::cout << "Built with Capstone disassembly support: yes\n";
}

int main(int argc, char* argv[]) {
    Options opts;
    if (!opts.parse(argc, argv)) { show_usage(argv[0]); return 1; }
    if (opts.showHelp)    { show_usage(argv[0]); return 0; }
    if (opts.showVersion) { print_version();     return 0; }

    if (opts.filename.empty()) {
        std::cerr << "Error: No EXE file specified\n\n";
        show_usage(argv[0]);
        return 1;
    }

    // Load file
    int64_t dosFileSize = 0;
    std::vector<uint8_t> fileData = read_exe_file(opts.filename, dosFileSize);
    if (fileData.empty()) return 1;

    // Read and validate MZ header
    if (fileData.size() < sizeof(MZHeader)) {
        std::cerr << "Error: File is too small to contain a valid MZ header\n";
        return 1;
    }
    MZHeader header;
    std::memcpy(&header, fileData.data(), sizeof(header));
    if (!validate_header(header, dosFileSize)) return 1;

    // Derive sizes
    ExeSizes sizes = calculate_sizes(header, dosFileSize);

    // Print header fields
    print_header_info(opts, header, sizes);

    // Relocation table (also fills relocs vector for simulation)
    std::vector<RelocEntry> relocs;
    dump_relocations(opts, header, fileData, sizes, relocs);

    // Hex dump
    dump_hex(opts, fileData, sizes);

    // Full disassembly
    if (opts.showDisasm || opts.showAll) {
        disassemble(fileData, sizes.entryPointFileOffset,
                    static_cast<uint16_t>(header.cs), header.ip);
    }

    // DOS load simulation
    run_simulation(opts, header, fileData, relocs, sizes);

    return 0;
}
