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
#include <vector>
#include <cstdint>
#include <cctype>

//=============================================================================
// Simulation breakpoints
//=============================================================================

/// Kind of execution breakpoint for --simulate
enum class BreakpointType {
    Ip,      ///< Match IP only (any CS):  --bp=ip:652B
    CsIp,    ///< Match CS:IP:            --bp=csip:1000:652B  or  --bp=1000:652B
    Int,     ///< Match INT n:            --bp=int:21
    IntAh,   ///< Match INT n with AH:    --bp=int:21,ah=0F
};

/// One user-defined breakpoint (multiple allowed)
struct Breakpoint {
    BreakpointType type = BreakpointType::Ip;
    uint16_t ip = 0;
    uint16_t cs = 0;
    bool     has_cs = false;
    uint8_t  int_num = 0;
    uint8_t  ah = 0;
    bool     has_ah = false;
    bool     stop = true;     ///< stop simulation on hit (default)
    bool     log  = true;     ///< print hit info (default)
    bool     once = false;    ///< disable after first hit
    bool     enabled = true;
    uint64_t hits = 0;
    std::string raw;          ///< original --bp= text
};

/// Optional memory dump performed on each breakpoint hit: seg:off:len
/// seg may be a hex segment or a register name (cs/ds/es/ss).
struct DumpSpec {
    bool valid = false;
    std::string seg_token;    ///< "ds", "cs", "1000", "B800", ...
    uint16_t offset = 0;
    uint16_t length = 64;
};

//=============================================================================
// Command-Line Options
//=============================================================================

/// Structure holding all command-line options and flags
struct Options {
    std::string filename;           ///< File to analyze
    bool showHelp = false;          ///< -h, --help
    bool showVersion = false;       ///< -v, --version
    bool showReloc = false;         ///< -r, --relocation
    bool showHexdump = false;       ///< -x, --hexdump
    bool showDisasm = false;        ///< -d, --disassemble
    bool showAll = false;           ///< -a, --all
    bool showCfg = false;           ///< --cfg  static control-flow graph
    bool simulate = false;          ///< --simulate
    bool noIntAnnot = false;        ///< -n, --no-int-annotations
    uint16_t loadBase = 0x1000;     ///< --base=XXXX (default: 1000h)
    bool comForcePsp   = false;     ///< --psp
    bool comForceNoPsp = false;     ///< --no-psp

    // --- Simulation controls ---
    /// Max instructions to execute (0 = default: 1_000_000, or 64 if --trace
    /// and no breakpoints for a short startup dump).
    uint64_t maxInsns = 0;
    bool maxInsnsSet = false;
    bool simTrace = false;          ///< --trace: print every executed instruction
    bool simQuiet = false;          ///< --sim-quiet: only BP hits + summary
    /// Max times a *tight* jmp/jcc back-edge may be taken; then force fall-through.
    /// Only short back-edges (see loopSpan). Does not affect LOOP/CX instructions.
    /// Default 10000: finite counting loops usually finish; infinite spins get cut.
    /// Use 1 for "run body once then continue" (may break real multi-iter loops).
    /// 0 = disabled.
    uint64_t loopLimit = 10000;
    bool loopLimitSet = false;
    /// Max byte span (IP delta) treated as a tight loop back-edge (default 100h).
    /// Long backward jumps (shared epilogues, error restarts) are never skipped.
    uint16_t loopSpan = 0x100;
    std::vector<Breakpoint> breakpoints;
    DumpSpec dumpOnHit;             ///< --dump=seg:off:len on each BP hit

    // --- Static CFG (--cfg) ---
    bool cfgFollowCalls = true;     ///< enqueue near call targets as leaders
    bool cfgNoInsns = false;        ///< --cfg-no-insns: edges only
    bool cfgInterestingOnly = false; ///< --cfg-interesting: skip full block dump
    size_t cfgMaxBlocks = 500;      ///< max blocks to print (--cfg-max=N)
    size_t cfgInsnsPerBlock = 12;   ///< insns shown per block (0 = all)
    size_t cfgInterestingMax = 80;  ///< max interesting blocks to expand
    size_t cfgLoadDepth = 6;        ///< reverse-pred walk depth for load graph
    size_t cfgLoadMaxSeeds = 40;    ///< max I/O seeds to expand in load graph

    /// Parse a hex number (optional 0x / h suffix) into u16.
    static bool parse_u16_hex(std::string_view s, uint16_t& out) {
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
            s.remove_prefix(1);
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
            s.remove_suffix(1);
        if (s.empty()) return false;
        if (s.size() > 1 && (s.back() == 'h' || s.back() == 'H'))
            s.remove_suffix(1);
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
            s.remove_prefix(2);
        if (s.empty()) return false;
        try {
            unsigned long v = std::stoul(std::string(s), nullptr, 16);
            if (v > 0xFFFFUL) return false;
            out = static_cast<uint16_t>(v);
            return true;
        } catch (...) {
            return false;
        }
    }

    /// Parse one --bp= specification. Returns false and sets err on failure.
    static bool parse_breakpoint(std::string_view spec, Breakpoint& bp, std::string& err) {
        bp = Breakpoint{};
        bp.raw = std::string(spec);

        // Split on commas: head, key=val, key=val, ...
        std::vector<std::string> parts;
        {
            std::string cur;
            for (char c : spec) {
                if (c == ',') {
                    if (!cur.empty()) parts.push_back(cur);
                    cur.clear();
                } else {
                    cur.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
                }
            }
            if (!cur.empty()) parts.push_back(cur);
        }
        if (parts.empty()) {
            err = "empty breakpoint";
            return false;
        }

        auto strip = [](std::string& s) {
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
                s.erase(s.begin());
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
                s.pop_back();
        };
        for (auto& p : parts) strip(p);

        std::string head = parts[0];

        // Flags on any part
        for (size_t i = 1; i < parts.size(); ++i) {
            const std::string& p = parts[i];
            if (p == "stop") { bp.stop = true; continue; }
            if (p == "continue" || p == "cont") { bp.stop = false; continue; }
            if (p == "log") { bp.log = true; continue; }
            if (p == "nolog") { bp.log = false; continue; }
            if (p == "once") { bp.once = true; continue; }
            if (p.starts_with("ah=") || p.starts_with("ah:")) {
                uint16_t v = 0;
                if (!parse_u16_hex(std::string_view(p).substr(3), v) || v > 0xFF) {
                    err = "invalid ah= value in breakpoint";
                    return false;
                }
                bp.has_ah = true;
                bp.ah = static_cast<uint8_t>(v);
                continue;
            }
            err = "unknown breakpoint option '" + p + "'";
            return false;
        }

        // Head forms:
        //   ip:XXXX  ip=XXXX
        //   csip:CS:IP
        //   CS:IP          (two hex words)
        //   int:NN  int=NN  intNN
        //   int:NN:AH      (AH as second hex)
        auto after_key = [&](const std::string& key) -> std::string_view {
            if (head.starts_with(key))
                return std::string_view(head).substr(key.size());
            return {};
        };

        if (head.starts_with("ip:") || head.starts_with("ip=")) {
            bp.type = BreakpointType::Ip;
            if (!parse_u16_hex(after_key(head.starts_with("ip:") ? "ip:" : "ip="), bp.ip)) {
                err = "invalid --bp=ip: value";
                return false;
            }
            return true;
        }

        if (head.starts_with("csip:") || head.starts_with("csip=")) {
            std::string_view rest = after_key(head.starts_with("csip:") ? "csip:" : "csip=");
            auto colon = rest.find(':');
            if (colon == std::string_view::npos) {
                err = "csip requires CS:IP";
                return false;
            }
            bp.type = BreakpointType::CsIp;
            bp.has_cs = true;
            if (!parse_u16_hex(rest.substr(0, colon), bp.cs) ||
                !parse_u16_hex(rest.substr(colon + 1), bp.ip)) {
                err = "invalid --bp=csip:CS:IP";
                return false;
            }
            return true;
        }

        if (head.starts_with("int:") || head.starts_with("int=") || head.starts_with("int")) {
            std::string_view rest;
            if (head.starts_with("int:") || head.starts_with("int="))
                rest = after_key(head.starts_with("int:") ? "int:" : "int=");
            else
                rest = std::string_view(head).substr(3);

            // int:21 or int:21:0f or int21
            uint16_t inum = 0;
            auto colon = rest.find(':');
            if (colon == std::string_view::npos) {
                if (!parse_u16_hex(rest, inum) || inum > 0xFF) {
                    err = "invalid --bp=int: number";
                    return false;
                }
                bp.int_num = static_cast<uint8_t>(inum);
                if (bp.has_ah)
                    bp.type = BreakpointType::IntAh;
                else
                    bp.type = BreakpointType::Int;
                return true;
            }
            if (!parse_u16_hex(rest.substr(0, colon), inum) || inum > 0xFF) {
                err = "invalid --bp=int: number";
                return false;
            }
            uint16_t ahv = 0;
            if (!parse_u16_hex(rest.substr(colon + 1), ahv) || ahv > 0xFF) {
                err = "invalid --bp=int:n:ah";
                return false;
            }
            bp.int_num = static_cast<uint8_t>(inum);
            bp.has_ah = true;
            bp.ah = static_cast<uint8_t>(ahv);
            bp.type = BreakpointType::IntAh;
            return true;
        }

        // Bare CS:IP (both sides hex)
        {
            auto colon = head.find(':');
            if (colon != std::string::npos && head.find(':', colon + 1) == std::string::npos) {
                uint16_t c = 0, i = 0;
                if (parse_u16_hex(std::string_view(head).substr(0, colon), c) &&
                    parse_u16_hex(std::string_view(head).substr(colon + 1), i)) {
                    bp.type = BreakpointType::CsIp;
                    bp.has_cs = true;
                    bp.cs = c;
                    bp.ip = i;
                    return true;
                }
            }
        }

        err = "unrecognized breakpoint syntax (try ip:XXXX, CS:IP, int:21, int:21,ah=0F)";
        return false;
    }

    static bool parse_dump_spec(std::string_view s, DumpSpec& d, std::string& err) {
        d = DumpSpec{};
        // seg:off:len  or  seg:off  (len defaults 64)
        std::string str(s);
        for (char& c : str)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        auto p1 = str.find(':');
        if (p1 == std::string::npos) {
            err = "--dump needs seg:off or seg:off:len";
            return false;
        }
        auto p2 = str.find(':', p1 + 1);
        d.seg_token = str.substr(0, p1);
        std::string off_s, len_s;
        if (p2 == std::string::npos) {
            off_s = str.substr(p1 + 1);
            len_s = "40"; // 64 decimal default as hex 40
        } else {
            off_s = str.substr(p1 + 1, p2 - p1 - 1);
            len_s = str.substr(p2 + 1);
        }
        if (d.seg_token.empty() || off_s.empty()) {
            err = "invalid --dump=seg:off:len";
            return false;
        }
        if (!parse_u16_hex(off_s, d.offset)) {
            err = "invalid dump offset";
            return false;
        }
        if (!parse_u16_hex(len_s, d.length) || d.length == 0) {
            err = "invalid dump length";
            return false;
        }
        if (d.length > 0x1000) d.length = 0x1000;
        d.valid = true;
        return true;
    }

    /// Parse command-line arguments
    /// @return true if parsing succeeded, false on error
    bool parse(int argc, char* argv[]) {
        if (argc < 2) {
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
            } else if (arg == "--cfg") {
                showCfg = true;
            } else if (arg == "--cfg-no-insns") {
                cfgNoInsns = true;
                showCfg = true;
            } else if (arg == "--cfg-no-calls") {
                cfgFollowCalls = false;
                showCfg = true;
            } else if (arg == "--cfg-interesting") {
                cfgInterestingOnly = true;
                showCfg = true;
            } else if (arg.starts_with("--cfg-max=")) {
                try {
                    cfgMaxBlocks = static_cast<size_t>(std::stoull(std::string(arg.substr(10))));
                    showCfg = true;
                } catch (...) {
                    std::cerr << "Error: Invalid --cfg-max value\n";
                    return false;
                }
            } else if (arg.starts_with("--cfg-insns=")) {
                try {
                    cfgInsnsPerBlock = static_cast<size_t>(std::stoull(std::string(arg.substr(12))));
                    showCfg = true;
                } catch (...) {
                    std::cerr << "Error: Invalid --cfg-insns value\n";
                    return false;
                }
            } else if (arg.starts_with("--cfg-interesting-max=")) {
                try {
                    cfgInterestingMax = static_cast<size_t>(std::stoull(std::string(arg.substr(22))));
                    showCfg = true;
                } catch (...) {
                    std::cerr << "Error: Invalid --cfg-interesting-max value\n";
                    return false;
                }
            } else if (arg.starts_with("--cfg-load-depth=")) {
                try {
                    cfgLoadDepth = static_cast<size_t>(std::stoull(std::string(arg.substr(17))));
                    showCfg = true;
                } catch (...) {
                    std::cerr << "Error: Invalid --cfg-load-depth value\n";
                    return false;
                }
            } else if (arg.starts_with("--cfg-load-max=")) {
                try {
                    cfgLoadMaxSeeds = static_cast<size_t>(std::stoull(std::string(arg.substr(15))));
                    showCfg = true;
                } catch (...) {
                    std::cerr << "Error: Invalid --cfg-load-max value\n";
                    return false;
                }
            } else if (arg == "--simulate") {
                simulate = true;
            } else if (arg == "-n" || arg == "--no-int-annotations") {
                noIntAnnot = true;
            } else if (arg == "--psp") {
                comForcePsp = true;
            } else if (arg == "--no-psp") {
                comForceNoPsp = true;
            } else if (arg == "--trace") {
                simTrace = true;
                simulate = true; // imply simulation
            } else if (arg == "--sim-quiet") {
                simQuiet = true;
                simulate = true;
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
            } else if (arg.starts_with("--max-insns=")) {
                try {
                    maxInsns = std::stoull(std::string(arg.substr(12)));
                    maxInsnsSet = true;
                    simulate = true;
                } catch (...) {
                    std::cerr << "Error: Invalid --max-insns value\n";
                    return false;
                }
            } else if (arg.starts_with("--loop-limit=")) {
                try {
                    loopLimit = std::stoull(std::string(arg.substr(13)));
                    loopLimitSet = true;
                    simulate = true;
                } catch (...) {
                    std::cerr << "Error: Invalid --loop-limit value (use 0 to disable)\n";
                    return false;
                }
            } else if (arg.starts_with("--loop-span=")) {
                uint16_t v = 0;
                if (!parse_u16_hex(arg.substr(12), v) || v == 0) {
                    std::cerr << "Error: Invalid --loop-span= (hex byte distance, e.g. 80 or 100)\n";
                    return false;
                }
                loopSpan = v;
                simulate = true;
            } else if (arg.starts_with("--bp=")) {
                Breakpoint bp;
                std::string err;
                if (!parse_breakpoint(arg.substr(5), bp, err)) {
                    std::cerr << "Error: --bp: " << err << "\n";
                    std::cerr << "  Examples: --bp=ip:652B  --bp=1000:0000  --bp=int:21\n"
                                 "            --bp=int:21,ah=0F  --bp=int:21,ah=0F,continue\n";
                    return false;
                }
                breakpoints.push_back(bp);
                simulate = true;
            } else if (arg.starts_with("--dump=")) {
                std::string err;
                if (!parse_dump_spec(arg.substr(7), dumpOnHit, err)) {
                    std::cerr << "Error: " << err << "\n";
                    return false;
                }
                simulate = true;
            } else if (arg[0] != '-' && filename.empty()) {
                filename = std::string(arg);
            } else {
                std::cerr << "Error: Unknown option '" << arg << "'\n";
                return false;
            }
        }

        if (showAll) {
            showReloc = true;
            showHexdump = true;
            showDisasm = true;
        }

        if (comForcePsp && comForceNoPsp) {
            std::cerr << "Error: --psp and --no-psp cannot be used together\n";
            return false;
        }

        // Default instruction budget
        if (!maxInsnsSet) {
            if (!breakpoints.empty())
                maxInsns = 1'000'000;
            else if (simTrace)
                maxInsns = 10'000;
            else
                maxInsns = 64; // short startup dump when only --simulate
        }

        return true;
    }
};

/// Print usage information
static inline void show_usage(const char* progname) {
    std::cout << std::format(
        "dumpexe - MS-DOS binary analyzer: MZ EXE, .COM, and device driver (.SYS)\n\n"
        "Usage: {} [options] <file>\n\n"
        "Options:\n"
        "  -h, --help          Show this help message and exit\n"
        "  -v, --version       Show version information and exit\n"
        "  -r, --relocation    Show relocation table (with padding) [EXE only]\n"
        "  -x, --hexdump       Show full hex+ASCII dump from entry point to EOF\n"
        "  -d, --disassemble   Show disassembly from entry point to EOF\n"
        "  --cfg               Build/print static CFG + INT/string xref annotations\n"
        "  --cfg-interesting   Only print interesting-block summary/detail (no full dump)\n"
        "  --cfg-no-insns      CFG edges/tags only (no per-block disassembly)\n"
        "  --cfg-no-calls      Do not follow near call targets as new leaders\n"
        "  --cfg-max=N         Max basic blocks in full dump (default 500)\n"
        "  --cfg-insns=N       Insns shown per block (default 12; 0=all)\n"
        "  --cfg-interesting-max=N  Max interesting blocks to expand (default 80)\n"
        "  --cfg-load-depth=N  Reverse walk depth for load/I/O graph (default 6)\n"
        "  --cfg-load-max=N    Max path/FCB seeds in load graph (default 40)\n"
        "  -a, --all           Show all sections (relocation + hexdump + disassembly)\n"
        "  -n, --no-int-annotations  Suppress INT annotation comments in disassembly\n"
        "  --simulate          Enable DOS load simulation / execution engine\n"
        "  --base=XXXX         Set load image segment (hex, default: 1000h)\n"
        "  --psp               Force .COM to be treated as having an embedded PSP\n"
        "  --no-psp            Force .COM to be treated as having no embedded PSP\n\n"
        "Simulation / breakpoints (imply --simulate):\n"
        "  --max-insns=N       Stop after N instructions (default: 64, or 1e6 with --bp)\n"
        "  --loop-limit=N      Tight jmp/jcc: take short back-edge at most N times,\n"
        "                      then fall through (default: 10000; 0=off; 1≈once)\n"
        "  --loop-span=XX      Max IP distance for a 'tight' loop (hex, default 100h)\n"
        "  --trace             Print every executed instruction\n"
        "  --sim-quiet         Only print breakpoint hits and a final summary\n"
        "  --bp=SPEC           Add breakpoint (repeatable). SPEC forms:\n"
        "                        ip:XXXX              IP only\n"
        "                        CS:IP  /  csip:CS:IP  full address\n"
        "                        int:21               any INT 21h\n"
        "                        int:21,ah=0F         INT 21h with AH=0Fh (FCB open)\n"
        "                        int:21:0F            same (short form)\n"
        "                      Flags (comma-separated): stop|continue, log|nolog, once\n"
        "  --dump=seg:off:len  Hex-dump memory on each breakpoint hit\n"
        "                        seg = hex or cs|ds|es|ss  (len hex, default 40h)\n\n"
        "Supported file formats (detected from file content):\n"
        "  MZ EXE   — first two bytes are 'MZ' (0x5A4D)\n"
        "  .SYS     — first four bytes are FFFFFFFFh (DOS device driver)\n"
        "  .COM     — all other files (fallback); PSP presence auto-detected\n\n"
        "Examples:\n"
        "  {} --simulate --bp=int:21,ah=0F --dump=ds:0:25 game.EXE\n"
        "  {} --simulate --bp=ip:652B --trace --max-insns=200 game.EXE\n\n",
        progname, progname, progname);
}

static inline void usage(const char* progname) { show_usage(progname); }

#endif // OPTIONS_H
