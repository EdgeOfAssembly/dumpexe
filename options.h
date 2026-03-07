// options.h - Command-line options parsing and usage display
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Defines the Options struct for holding all parsed CLI flags and the
// show_usage() helper. All helper functions are static inline.
// Capstone is a mandatory build dependency.

#ifndef OPTIONS_H
#define OPTIONS_H

#include <iostream>
#include <format>
#include <string>
#include <string_view>
#include <cstdint>

//=============================================================================
// Command-Line Options
//=============================================================================

/// Structure holding all command-line options and flags
struct Options {
    std::string filename;       ///< EXE file to analyze
    bool showHelp = false;      ///< -h, --help
    bool showVersion = false;   ///< -v, --version
    bool showReloc = false;     ///< -r, --relocation
    bool showHexdump = false;   ///< -x, --hexdump
    bool showDisasm = false;    ///< -d, --disassemble
    bool showAll = false;       ///< -a, --all
    bool simulate = false;      ///< --simulate
    bool noIntAnnot = false;    ///< -n, --no-int-annotations
    uint16_t loadBase = 0x1000; ///< --base=XXXX (default: 1000h, after PSP)

    /// Parse command-line arguments
    /// @param argc Argument count from main()
    /// @param argv Argument vector from main()
    /// @return true if parsing succeeded, false on error
    bool parse(int argc, char* argv[]) {
        if (argc < 2) {
            // No arguments - print usage
            showHelp = true;
            return true;
        }

        for (int i = 1; i < argc; i++) {
            std::string_view arg{argv[i]};

            if (arg == "-h" || arg == "--help") {
                showHelp = true;
            } else if (arg == "-v" || arg == "--version") {
                showVersion = true;
            } else if (arg == "-r" || arg == "--relocation") {
                showReloc = true;
            } else if (arg == "-x" || arg == "--hexdump") {
                showHexdump = true;
            } else if (arg == "-d" || arg == "--disassemble") {
                showDisasm = true;
            } else if (arg == "-a" || arg == "--all") {
                showAll = true;
            } else if (arg == "--simulate") {
                simulate = true;
            } else if (arg == "-n" || arg == "--no-int-annotations") {
                noIntAnnot = true;
            } else if (arg.starts_with("--base=")) {
                std::string baseStr{arg.substr(7)};
                try {
                    int baseValue = std::stoi(baseStr, nullptr, 16);
                    if (baseValue < 0 || baseValue > 0xFFFF) {
                        std::cerr << "Error: Base segment value '" << baseStr << "' out of 16-bit range (0000-FFFF)\n";
                        return false;
                    }
                    loadBase = static_cast<uint16_t>(baseValue);
                } catch (const std::invalid_argument&) {
                    std::cerr << "Error: Invalid base segment value '" << baseStr << "'\n";
                    std::cerr << "Expected hexadecimal value (e.g., 1000, 2000, ABCD)\n";
                    return false;
                } catch (const std::out_of_range&) {
                    std::cerr << "Error: Base segment value '" << baseStr << "' out of range\n";
                    return false;
                }
            } else if (arg[0] != '-' && filename.empty()) {
                // Not a flag, assume it's the filename
                filename = std::string(arg);
            } else {
                std::cerr << "Error: Unknown option '" << arg << "'\n";
                return false;
            }
        }

        // If --all is set, enable all display sections
        if (showAll) {
            showReloc = true;
            showHexdump = true;
            showDisasm = true;
        }

        return true;
    }
};

/// Print usage information
/// @param progname argv[0] — used to display the correct invocation name
static inline void show_usage(const char* progname) {
    std::cout << std::format(
        "dumpexe - MS-DOS MZ EXE header analyzer and disassembler\n\n"
        "Usage: {} [options] <exe_file>\n\n"
        "Options:\n"
        "  -h, --help          Show this help message and exit\n"
        "  -v, --version       Show version information and exit\n"
        "  -r, --relocation    Show relocation table (with padding)\n"
        "  -x, --hexdump       Show full hex+ASCII dump from entry point to EOF\n"
        "  -d, --disassemble   Show disassembly from entry point to EOF\n"
        "  -a, --all           Show all sections (relocation + hexdump + disassembly)\n"
        "  -n, --no-int-annotations  Suppress INT annotation comments in disassembly\n"
        "  --simulate          Enable DOS load simulation with register tracking\n"
        "  --base=XXXX         Set load base segment (hex, default: 1000h)\n\n"
        "If no section options are given, only the EXE header information is displayed.\n"
        "Multiple options can be combined, e.g., -r -x for relocations and hexdump.\n\n",
        progname);
}

/// Legacy alias kept for compatibility with call sites using the old name
static inline void usage(const char* progname) { show_usage(progname); }

#endif // OPTIONS_H
