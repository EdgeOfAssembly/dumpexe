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
    bool showStrings = false;       ///< --strings  Pascal + ASCIIZ string table (opt-in)
    bool pascalMt = true;           ///< Pascal MT+ 3.1.1 detect/annotate (default ON)
    bool showCfg = false;           ///< --cfg  static control-flow graph (human dump)
    bool simulate = false;          ///< --simulate
    bool noIntAnnot = false;        ///< -n, --no-int-annotations
    uint16_t loadBase = 0x1000;     ///< --base=XXXX (default: 1000h)
    bool comForcePsp   = false;     ///< --psp
    bool comForceNoPsp = false;     ///< --no-psp
    bool jsonOut = false;           ///< --json  machine-readable report on stdout (opt-in)
    std::string cfgDotPath;         ///< --cfg-dot=FILE  Graphviz DOT export (opt-in)
    bool writeAsmFile = true;       ///< write <stem>.asm on -d/-a (default ON)
    std::string outputPath;         ///< -o/--output single path for .asm (optional)
    bool toolchainDetect = true;    ///< COM-in-EXE / CuteMouse / etc. (default ON)
    bool dosExtenderDetect = true;  ///< DOS extender / DPMI detect (default ON; --no-dos-extender)
    /// Capstone x86 width: 16 (real-mode default) or 32 (DOS extender payload).
    /// 0 = auto (16, or 32 when extender detected). Override: --bits=16|32
    int x86Bits = 0;
    bool autoMap = true;            ///< auto-load <stem>.sym/.map (default ON)
    std::string mapPath;            ///< --map=FILE explicit symbol map
    /// Memory model for JWASM export (cli-design).
    /// Rules: pure .COM and COM-in-EXE → always **tiny** (≤64K, no exceptions).
    /// Otherwise default **small** if unknown; override with --model=.
    std::string memModel = "small";
    bool memModelUserSet = false;
    /// After TP/JWASM export, also write <stem>.repack.exe (default ON)
    bool writeRepack = true;
    std::string repackOutputPath; ///< optional override path for repack EXE
    /// --uasm: write UASM source (enable-only; no disable switch).
    /// The file has no address column and no hex-byte column. -d stdout is unchanged.
    /// Default output does not spawn an assembler.
    bool uasm = false;
    /// --uasm-stats: one stderr coverage line (enable-only). Does not imply
    /// --uasm. There is no disable twin. Parse fails unless --uasm is also set.
    /// Does not require --uasm-verify.
    bool uasm_stats = false;
    /// --uasm-verify: assemble candidate lines once per listing (enable-only).
    /// Default off. There is no disable twin. Parse fails unless --uasm is set.
    bool uasm_verify = false;
    /// --uasm-bin PATH: assembler for --uasm-verify. Empty means $DUMPEXE_UASM,
    /// then PATH. Never a built-in absolute path.
    std::string uasm_bin;

    /**
     * @brief True when --uasm -o - should be the only stdout.
     *
     * -d, -a, and the other human reports are omitted. No address listing and
     * no file. --json still owns stdout; the UASM file is separate unless -o -
     * is also set, in which case JSON remains the stdout product.
     */
    bool uasm_stdout_only() const
    {
        return uasm && outputPath == "-" && !jsonOut;
    }

    // --- Simulation controls ---
    /// Max instructions to execute. 0 means the parser fills the default:
    /// 1_000_000 with --bp, 10_000 with --trace, otherwise 64.
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
            } else if (arg == "--strings") {
                showStrings = true;
            } else if (arg == "--no-pascal-mt" || arg == "--no-pascal-mt+") {
                // Default ON: only provide disable switch (cli-design sane defaults)
                pascalMt = false;
            } else if (arg == "--json") {
                // Opt-in machine-readable report (default OFF → enable-only switch)
                jsonOut = true;
            } else if (arg == "--uasm") {
                // Enable-only. There is no disable twin (cli-design sane defaults).
                uasm = true;
            } else if (arg == "--uasm-stats") {
                // Enable-only. Does not imply --uasm. There is no disable twin.
                uasm_stats = true;
            } else if (arg == "--uasm-verify") {
                // Enable-only. Default off. Does not imply --uasm.
                uasm_verify = true;
            } else if (arg == "--uasm-bin") {
                if (i + 1 >= argc) {
                    std::cerr << "Error: --uasm-bin requires a path\n";
                    return false;
                }
                uasm_bin = argv[++i];
                if (uasm_bin.empty()) {
                    std::cerr << "Error: --uasm-bin requires a path\n";
                    return false;
                }
            } else if (arg.starts_with("--uasm-bin=")) {
                uasm_bin = std::string(arg.substr(11));
                if (uasm_bin.empty()) {
                    std::cerr << "Error: --uasm-bin= requires a path\n";
                    return false;
                }
            } else if (arg == "--no-asm-file") {
                // Default ON when disassembling: only provide disable switch
                writeAsmFile = false;
            } else if (arg == "--no-repack") {
                // Default ON after TP/JWASM export: rebuild runnable EXE from listing
                writeRepack = false;
            } else if (arg.starts_with("--repack-output=")) {
                repackOutputPath = std::string(arg.substr(16));
                if (repackOutputPath.empty()) {
                    std::cerr << "Error: --repack-output= requires a path\n";
                    return false;
                }
                writeRepack = true;
            } else if (arg == "--no-toolchain") {
                toolchainDetect = false;
            } else if (arg == "--no-dos-extender") {
                dosExtenderDetect = false;
            } else if (arg.starts_with("--bits=")) {
                const std::string_view v = arg.substr(7);
                if (v == "16")
                    x86Bits = 16;
                else if (v == "32")
                    x86Bits = 32;
                else
                {
                    std::cerr << "Error: --bits= requires 16 or 32\n";
                    return false;
                }
            } else if (arg == "--no-map") {
                autoMap = false;
            } else if (arg.starts_with("--map=")) {
                mapPath = std::string(arg.substr(6));
                if (mapPath.empty()) {
                    std::cerr << "Error: --map= requires a path\n";
                    return false;
                }
            } else if (arg.starts_with("--model=")) {
                // Default small when unknown; COM/.COM always tiny (not overridable).
                std::string m(arg.substr(8));
                for (char& c : m)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (m != "tiny" && m != "small" && m != "medium" && m != "compact" &&
                    m != "large" && m != "huge")
                {
                    std::cerr << "Error: --model= must be tiny|small|medium|compact|large|huge\n";
                    return false;
                }
                memModel = std::move(m);
                memModelUserSet = true;
            } else if (arg == "-o" || arg == "--output") {
                if (i + 1 >= argc) {
                    std::cerr << "Error: " << arg << " requires a path\n";
                    return false;
                }
                outputPath = argv[++i];
            } else if (arg.starts_with("--output=")) {
                outputPath = std::string(arg.substr(9));
                if (outputPath.empty()) {
                    std::cerr << "Error: --output= requires a path\n";
                    return false;
                }
            } else if (arg == "--cfg") {
                showCfg = true;
            } else if (arg.starts_with("--cfg-dot=")) {
                cfgDotPath = std::string(arg.substr(10));
                if (cfgDotPath.empty()) {
                    std::cerr << "Error: --cfg-dot= requires a path\n";
                    return false;
                }
                // DOT export builds CFG; human dump only if --cfg also set
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
                const std::string_view num = arg.substr(12);
                if (num.empty() || num.front() == '-' || num.front() == '+')
                {
                    std::cerr << "Error: Invalid --max-insns value\n";
                    return false;
                }
                try {
                    maxInsns = std::stoull(std::string(num));
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
            showStrings = true;
        }

        if (comForcePsp && comForceNoPsp) {
            std::cerr << "Error: --psp and --no-psp cannot be used together\n";
            return false;
        }

        if (uasm_stats && !uasm)
        {
            std::cerr << "Error: --uasm-stats requires --uasm\n";
            return false;
        }
        if (uasm_verify && !uasm)
        {
            std::cerr << "Error: --uasm-verify requires --uasm\n";
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
        "dumpexe - MS-DOS / Win16 binary analyzer: MZ EXE, NE, .COM, .SYS\n\n"
        "Usage: {} [options] <file>\n\n"
        "Options:\n"
        "  -h, --help          Show this help message and exit\n"
        "  -v, --version       Show version information and exit\n"
        "  -r, --relocation    Show relocation table (with padding) [EXE only]\n"
        "  -x, --hexdump       Show full hex+ASCII dump from entry point to EOF\n"
        "  -d, --disassemble   Multi-pass annotated listing (func_* labels, INT notes,\n"
        "                      call/jmp→labels); also writes <stem>.asm by default.\n"
        "                      Microsoft EXEPACK, LZEXE 0.91, LZEXE 0.90, PKLITE, DIET, and\n"
        "                      LHarc also write <stem>_UNPACKED.EXE (or .COM) and\n"
        "                      <stem>_UNPACKED.asm of the unpacked program.\n"
        "                      DIET and LHarc are structural (Deark identify rules), not\n"
        "                      the bytes DIET at 0x1C or an LHA sentence. LHarc also needs\n"
        "                      a header checksum (or a level-2 CRC) in the SFX trailer.\n"
        "  -o, --output PATH   Packed listing file (default: <stem>.asm); use - for stdout only.\n"
        "                      -o - writes no .asm, no _UNPACKED.EXE, and no _UNPACKED.asm.\n"
        "                      A named -o file is not also printed on stdout.\n"
        "                      --json keeps JSON on stdout and still writes a named -o file.\n"
        "                      --json -o - does not claim a UASM listing was written.\n"
        "  --no-asm-file       Do not write .asm file (listing still on stdout unless --json)\n"
        "  --no-repack         Do not write <stem>.repack.exe after TP/JWASM export (default: on)\n"
        "  --repack-output=P   Override repack EXE path (implies repack on)\n"
        "  Note: existing default <stem>.asm or <stem>.repack.exe is kept unless -o or --repack-output names it.\n"
        "        An existing <stem>_UNPACKED.EXE, .COM, or .asm is kept.\n"
        "        A kept _UNPACKED.EXE/.COM is not paired with a new _UNPACKED.asm.\n"
        "  --cfg               Build/print static CFG + INT/string xref annotations\n"
        "  --cfg-interesting   Only print interesting-block summary/detail (no full dump)\n"
        "  --cfg-no-insns      CFG edges/tags only (no per-block disassembly)\n"
        "  --cfg-no-calls      Do not follow near call targets as new leaders\n"
        "  --cfg-max=N         Max basic blocks in the CFG full dump (default 500).\n"
        "                      The -d listing cap is max(N, 2000)\n"
        "  --cfg-insns=N       Insns shown per block (default 12; 0=all)\n"
        "  --cfg-interesting-max=N  Max interesting blocks to expand (default 80)\n"
        "  --cfg-load-depth=N  Reverse walk depth for load/I/O graph (default 6)\n"
        "  --cfg-load-max=N    Max path/FCB seeds in load graph (default 40)\n"
        "  -a, --all           Show all sections (reloc + hex + disasm + strings).\n"
        "                      Unpacks the same packers as -d\n"
        "  --strings           Extract Pascal length-prefixed + CALL-inline + ASCIIZ strings\n"
        "  --no-pascal-mt      Disable Pascal MT+ 3.1.1 detect/annotate (default: on)\n"
        "  --no-toolchain      Disable JWASM 1.8 / COM-in-EXE / CuteMouse / packer detect\n"
        "                      (default: on). Also skips unpack\n"
        "  --no-dos-extender   Disable DOS extender / DPMI stub detect (default: on)\n"
        "  --bits=16|32        Force Capstone x86 width (default: auto; 32 if extender)\n"
        "  --map=FILE          Load symbol map for listing (IP name); disables need for auto\n"
        "  --no-map            Do not auto-load <stem>.sym / <stem>.map (default: auto on)\n"
        "  --model=M           Memory model for JWASM export: tiny|small|medium|compact|large|huge\n"
        "                      (default: small if unknown; .COM / COM-in-EXE always tiny)\n"
        "  --uasm              Write UASM source (uasm -bin for COM, uasm -mz for EXE) to\n"
        "                      <stem>.asm. Enable-only; does not require -d. The UASM file has\n"
        "                      no address column and no hex-byte column. -d/-a with a file keeps\n"
        "                      the address listing on stdout. -o PATH names the UASM file. -o -\n"
        "                      is UASM on stdout only and no file, including with -d or -a.\n"
        "                      Does not write _UNPACKED.EXE or _UNPACKED.asm unless -d or -a\n"
        "                      is also set. MZ and COM only. Skips auto-repack (no\n"
        "                      REPACK-V1). Images longer than 65536 bytes are split into\n"
        "                      segments of at most 65536 bytes with no padding.\n"
        "                      uasm -mz writes a 32-byte MZ header (0 relocations, CS:IP\n"
        "                      and SS:SP 0:0) and warns A4205/A4204. e_cparhdr*16 is the\n"
        "                      MZ header size, not the load image. Prefer uasm -bin and\n"
        "                      bin2exe --header to restore the original header.\n"
        "                      A same-segment far call is followed when its segment is the\n"
        "                      file CS (the MZ header), including when --base is not 0.\n"
        "                      Past 64 KiB is decoded when reached through the entry, near\n"
        "                      wrap, or a decoded relocation-pinned far call. A pinned\n"
        "                      target outside the image is not followed. An entry outside\n"
        "                      the image is not labeled func_FFFF.\n"
        "  --uasm-verify       With --uasm, assemble candidate lines once and keep a line\n"
        "                      only when the bytes match. Enable-only. Default off, so\n"
        "                      --uasm does not run an assembler. Requires --uasm.\n"
        "                      Does not imply --uasm-stats. The listing header says\n"
        "                      \"; verified: uasm … at PATH\" or \"; NOT VERIFIED\".\n"
        "  --uasm-bin PATH     Assembler used by --uasm-verify. Otherwise $DUMPEXE_UASM,\n"
        "                      otherwise uasm on PATH. No built-in assembler path.\n"
        "  --uasm-stats        With --uasm, print one coverage line on stderr when a\n"
        "                      UASM listing is emitted (image, decoded, text, db,\n"
        "                      labels, whether verification ran). Enable-only. Does not\n"
        "                      imply --uasm or --uasm-verify. Requires --uasm. Not a\n"
        "                      JSON field.\n"
        "  --json              Machine-readable JSON report on stdout (default: off).\n"
        "                      Does not unpack\n"
        "  --cfg-dot=FILE      Write Graphviz DOT of CFG to FILE (default: off)\n"
        "  -n, --no-int-annotations  Suppress INT annotation comments in disassembly\n"
        "  --simulate          In-memory DOS sandbox. Guest data files start empty.\n"
        "                      Guest I/O does not open host files. A write to handle 1\n"
        "                      or 2 (stdout/stderr) returns CF=1 and AX=6.\n"
        "                      At most 64 guest files. Truncate releases capacity, so\n"
        "                      recreate does not keep the old allocation.\n"
        "  --base=XXXX         Set load image segment (hex, default: 1000h)\n"
        "  --psp               Force .COM to be treated as having an embedded PSP\n"
        "  --no-psp            Force .COM to be treated as having no embedded PSP\n\n"
        "Simulation / breakpoints (imply --simulate):\n"
        "  --max-insns=N       Stop after N instructions (default: 64;\n"
        "                      10000 with --trace; 1e6 with --bp). A leading minus is an error.\n"
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
        "  MZ EXE   — first two bytes are 'MZ' (0x5A4D); pure DOS image\n"
        "  NE EXE   — MZ stub with e_lfanew → 'NE' (Windows 3.x / Win16)\n"
        "  .SYS     — DOS device driver (last-in-chain FFFFFFFFh, or a chained header)\n"
        "  .COM     — all other files (fallback); PSP presence auto-detected\n\n"
        "Examples:\n"
        "  {} --simulate --bp=int:21,ah=0F --dump=ds:0:25 game.EXE\n"
        "  {} --simulate --bp=ip:652B --trace --max-insns=200 game.EXE\n\n",
        progname, progname, progname);
}

static inline void usage(const char* progname) { show_usage(progname); }

#endif // OPTIONS_H
