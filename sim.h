// sim.h - DOS real-mode execution engine for --simulate
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// 1 MiB conventional-style address space, PSP + load image, Capstone-decoded
// step loop, flexible breakpoints, and a minimal INT 21h stub (FCB + DOS).
// Best-effort — not a full DOS/BIOS emulator.

#ifndef SIM_H
#define SIM_H

#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <capstone/capstone.h>

#include "exe.h"
#include "registers.h"
#include "options.h"
#include "formatting.h"
#include "int_annotate.h"

//=============================================================================
// Linear memory (20-bit real mode: seg*16+off, wrap at 1 MiB)
//=============================================================================

struct SimMemory {
    static constexpr size_t kSize = 0x100000; // 1 MiB
    std::vector<uint8_t> ram;

    SimMemory() : ram(kSize, 0) {}

    static uint32_t linear(uint16_t seg, uint16_t off) {
        return (static_cast<uint32_t>(seg) * 16u + off) & 0xFFFFFu;
    }

    uint8_t read8(uint16_t seg, uint16_t off) const {
        return ram[linear(seg, off)];
    }
    uint16_t read16(uint16_t seg, uint16_t off) const {
        uint32_t a = linear(seg, off);
        return static_cast<uint16_t>(ram[a] | (ram[(a + 1) & 0xFFFFF] << 8));
    }
    void write8(uint16_t seg, uint16_t off, uint8_t v) {
        ram[linear(seg, off)] = v;
    }
    void write16(uint16_t seg, uint16_t off, uint16_t v) {
        uint32_t a = linear(seg, off);
        ram[a] = static_cast<uint8_t>(v & 0xFF);
        ram[(a + 1) & 0xFFFFF] = static_cast<uint8_t>((v >> 8) & 0xFF);
    }

    /// Install a minimal PSP and load the MZ image; apply relocation fixups.
    void load_mz(uint16_t image_seg, uint16_t psp_seg,
                 const std::vector<uint8_t>& fileData,
                 size_t header_bytes, size_t image_bytes,
                 const std::vector<RelocEntry>& relocs) {
        // --- PSP ---
        write8(psp_seg, 0x00, 0xCD);
        write8(psp_seg, 0x01, 0x20);          // INT 20h
        write16(psp_seg, 0x02, 0xA000);       // first free paragraph (mem top)
        write16(psp_seg, 0x0A, 0xFFFF);       // old INT 22
        write16(psp_seg, 0x0C, 0xFFFF);
        write16(psp_seg, 0x0E, 0xFFFF);       // old INT 23
        write16(psp_seg, 0x10, 0xFFFF);
        write16(psp_seg, 0x12, 0xFFFF);       // old INT 24
        write16(psp_seg, 0x14, 0xFFFF);
        write16(psp_seg, 0x16, psp_seg);      // parent PSP
        // Command tail empty
        write8(psp_seg, 0x80, 0);
        write8(psp_seg, 0x81, 0x0D);

        // --- Load image ---
        size_t copy = std::min(image_bytes, fileData.size() > header_bytes
                                                ? fileData.size() - header_bytes
                                                : 0);
        for (size_t i = 0; i < copy; ++i) {
            // Images can exceed 64K; walk linear addresses past one segment
            uint32_t a = (static_cast<uint32_t>(image_seg) * 16u
                          + static_cast<uint32_t>(i)) & 0xFFFFF;
            ram[a] = fileData[header_bytes + i];
        }

        // --- Relocations ---
        for (const auto& r : relocs) {
            uint32_t img_off = static_cast<uint32_t>(r.segment) * 16u + r.offset;
            uint32_t a = (static_cast<uint32_t>(image_seg) * 16u + img_off) & 0xFFFFF;
            uint16_t orig = static_cast<uint16_t>(ram[a] | (ram[(a + 1) & 0xFFFFF] << 8));
            uint16_t fixed = static_cast<uint16_t>(orig + image_seg);
            ram[a] = static_cast<uint8_t>(fixed & 0xFF);
            ram[(a + 1) & 0xFFFFF] = static_cast<uint8_t>((fixed >> 8) & 0xFF);
        }
    }
};

//=============================================================================
// Open host files for FCB / handle stubs
//=============================================================================

struct SimFile {
    std::FILE* fp = nullptr;
    std::string path;
    uint32_t rec_size = 128;
    uint32_t seq_rec = 0;
};

struct SimState {
    SimMemory mem;
    uint16_t image_seg = 0;
    uint16_t psp_seg = 0;
    std::filesystem::path host_dir;   ///< directory of the guest EXE (for FCB opens)
    std::unordered_map<uint32_t, SimFile> fcb_files; // key = linear FCB addr
    std::unordered_map<uint16_t, SimFile> handle_files; // DOS handles
    uint16_t next_handle = 5;
    uint16_t dta_seg = 0;
    uint16_t dta_off = 0x80;
    bool halted = false;
    bool unsupported_stop = false;
    std::string halt_reason;
    uint64_t insn_count = 0;
    uint64_t int21_count = 0;
    uint64_t kbd_polls = 0;       ///< INT 16/21 keyboard polls (for auto-key inject)
    uint64_t keys_injected = 0;
    uint64_t loops_skipped = 0;   ///< back-edges forced to fall-through
    csh cs_handle = 0;
    cs_insn* insn = nullptr;

    // Segment override for current instruction (0xFFFF = default)
    uint16_t seg_override = 0xFFFF;

    /// Back-edge take counts: key = (CS << 32) | (from_ip << 16) | to_ip
    std::unordered_map<uint64_t, uint64_t> backedge_hits;
};

/// Decide whether a taken branch to @p target_ip should be suppressed (loop skip).
/// Backward edges (target_ip <= insn_ip) are counted; after loopLimit takes,
/// we force fall-through so the body ran a few times then the sim continues.
static inline bool sim_should_skip_backedge(SimState& st, const Options& opts,
                                            uint16_t insn_ip, uint16_t target_ip,
                                            uint16_t fallthrough_ip) {
    if (opts.loopLimit == 0)
        return false;
    // Forward jumps are never loops.
    if (target_ip > insn_ip)
        return false;
    // Only *tight* back-edges (small IP span). Long backward jumps are normal
    // control flow (epilogues, retries) and must not be force-broken.
    const uint16_t span = static_cast<uint16_t>(insn_ip - target_ip);
    if (span > opts.loopSpan)
        return false;
    (void)fallthrough_ip;

    const uint64_t key = (static_cast<uint64_t>(CS) << 32)
                       | (static_cast<uint64_t>(insn_ip) << 16)
                       | target_ip;
    uint64_t& hits = st.backedge_hits[key];
    hits++;
    if (hits <= opts.loopLimit)
        return false;

    st.loops_skipped++;
    // Log only the first time we break this edge (avoid spam on hot spins).
    if (hits == opts.loopLimit + 1) {
        std::cout << std::format(
            "  [loop-skip] {:04X}:{:04X} -> {:04X} (span {:X}h) after {} takes "
            "(limit {}); fall-through {:04X}\n",
            CS, insn_ip, target_ip, span, hits, opts.loopLimit, fallthrough_ip);
    }
    return true;
}

//=============================================================================
// Helpers: registers via Capstone IDs
//=============================================================================

static inline bool sim_reg_get(x86_reg r, uint16_t& out) {
    switch (r) {
    case X86_REG_AX: out = AX; return true;
    case X86_REG_BX: out = BX; return true;
    case X86_REG_CX: out = CX; return true;
    case X86_REG_DX: out = DX; return true;
    case X86_REG_SI: out = SI; return true;
    case X86_REG_DI: out = DI; return true;
    case X86_REG_BP: out = BP; return true;
    case X86_REG_SP: out = SP; return true;
    case X86_REG_CS: out = CS; return true;
    case X86_REG_DS: out = DS; return true;
    case X86_REG_ES: out = ES; return true;
    case X86_REG_SS: out = SS; return true;
    case X86_REG_IP: out = IP; return true;
    case X86_REG_AL: out = AL; return true;
    case X86_REG_AH: out = AH; return true;
    case X86_REG_BL: out = BL; return true;
    case X86_REG_BH: out = BH; return true;
    case X86_REG_CL: out = CL; return true;
    case X86_REG_CH: out = CH; return true;
    case X86_REG_DL: out = DL; return true;
    case X86_REG_DH: out = DH; return true;
    default: return false;
    }
}

static inline bool sim_reg_set(x86_reg r, uint16_t v) {
    switch (r) {
    case X86_REG_AX: AX = v; return true;
    case X86_REG_BX: BX = v; return true;
    case X86_REG_CX: CX = v; return true;
    case X86_REG_DX: DX = v; return true;
    case X86_REG_SI: SI = v; return true;
    case X86_REG_DI: DI = v; return true;
    case X86_REG_BP: BP = v; return true;
    case X86_REG_SP: SP = v; return true;
    case X86_REG_CS: CS = v; return true;
    case X86_REG_DS: DS = v; return true;
    case X86_REG_ES: ES = v; return true;
    case X86_REG_SS: SS = v; return true;
    case X86_REG_IP: IP = v; return true;
    case X86_REG_AL: AL = static_cast<uint8_t>(v); return true;
    case X86_REG_AH: AH = static_cast<uint8_t>(v); return true;
    case X86_REG_BL: BL = static_cast<uint8_t>(v); return true;
    case X86_REG_BH: BH = static_cast<uint8_t>(v); return true;
    case X86_REG_CL: CL = static_cast<uint8_t>(v); return true;
    case X86_REG_CH: CH = static_cast<uint8_t>(v); return true;
    case X86_REG_DL: DL = static_cast<uint8_t>(v); return true;
    case X86_REG_DH: DH = static_cast<uint8_t>(v); return true;
    default: return false;
    }
}

static inline bool sim_is_byte_reg(x86_reg r) {
    return r == X86_REG_AL || r == X86_REG_AH || r == X86_REG_BL || r == X86_REG_BH ||
           r == X86_REG_CL || r == X86_REG_CH || r == X86_REG_DL || r == X86_REG_DH;
}

static inline void sim_set_szp8(uint8_t v) {
    ZF = (v == 0) ? 1 : 0;
    SF = (v & 0x80) ? 1 : 0;
    // PF approximate: even parity of low 8
    unsigned p = v;
    p ^= p >> 4; p ^= p >> 2; p ^= p >> 1;
    PF = (~p & 1) ? 1 : 0;
}
static inline void sim_set_szp16(uint16_t v) {
    ZF = (v == 0) ? 1 : 0;
    SF = (v & 0x8000) ? 1 : 0;
    unsigned p = v & 0xFF;
    p ^= p >> 4; p ^= p >> 2; p ^= p >> 1;
    PF = (~p & 1) ? 1 : 0;
}

static inline void sim_set_cmp(uint16_t left, uint16_t right, bool is8) {
    if (is8) {
        uint8_t l = static_cast<uint8_t>(left), r = static_cast<uint8_t>(right);
        uint8_t res = static_cast<uint8_t>(l - r);
        CF = (l < r) ? 1 : 0;
        OF = (((l ^ r) & (l ^ res)) & 0x80) ? 1 : 0;
        sim_set_szp8(res);
    } else {
        uint16_t res = static_cast<uint16_t>(left - right);
        CF = (left < right) ? 1 : 0;
        OF = (((left ^ right) & (left ^ res)) & 0x8000) ? 1 : 0;
        sim_set_szp16(res);
    }
}

//=============================================================================
// Effective address
//=============================================================================

static inline uint16_t sim_default_seg(SimState& st, x86_reg base, x86_reg index) {
    if (st.seg_override != 0xFFFF) return st.seg_override;
    // BP-based → SS, else DS (classic 16-bit)
    if (base == X86_REG_BP || base == X86_REG_SP)
        return SS;
    (void)index;
    return DS;
}

static inline bool sim_ea(SimState& st, const cs_x86_op& op,
                          uint16_t& seg, uint16_t& off) {
    if (op.type != X86_OP_MEM) return false;
    const x86_op_mem& m = op.mem;
    if (m.segment == X86_REG_CS) seg = CS;
    else if (m.segment == X86_REG_DS) seg = DS;
    else if (m.segment == X86_REG_ES) seg = ES;
    else if (m.segment == X86_REG_SS) seg = SS;
    else seg = sim_default_seg(st, m.base, m.index);

    if (st.seg_override != 0xFFFF)
        seg = st.seg_override;

    uint32_t ea = static_cast<uint32_t>(static_cast<int32_t>(m.disp));
    if (m.base != X86_REG_INVALID) {
        uint16_t bv = 0;
        if (!sim_reg_get(m.base, bv)) return false;
        ea += bv;
    }
    if (m.index != X86_REG_INVALID) {
        uint16_t iv = 0;
        if (!sim_reg_get(m.index, iv)) return false;
        ea += iv;
    }
    off = static_cast<uint16_t>(ea & 0xFFFF);
    return true;
}

static inline bool sim_read_op(SimState& st, const cs_x86_op& op, uint16_t& val, bool is8) {
    if (op.type == X86_OP_REG) {
        uint16_t v = 0;
        if (!sim_reg_get(op.reg, v)) return false;
        val = is8 ? (v & 0xFF) : v;
        return true;
    }
    if (op.type == X86_OP_IMM) {
        val = static_cast<uint16_t>(op.imm);
        if (is8) val &= 0xFF;
        return true;
    }
    if (op.type == X86_OP_MEM) {
        uint16_t seg = 0, off = 0;
        if (!sim_ea(st, op, seg, off)) return false;
        val = is8 ? st.mem.read8(seg, off) : st.mem.read16(seg, off);
        return true;
    }
    return false;
}

static inline bool sim_write_op(SimState& st, const cs_x86_op& op, uint16_t val, bool is8) {
    if (op.type == X86_OP_REG) {
        if (is8) val &= 0xFF;
        return sim_reg_set(op.reg, val);
    }
    if (op.type == X86_OP_MEM) {
        uint16_t seg = 0, off = 0;
        if (!sim_ea(st, op, seg, off)) return false;
        if (is8) st.mem.write8(seg, off, static_cast<uint8_t>(val));
        else st.mem.write16(seg, off, val);
        return true;
    }
    return false;
}

//=============================================================================
// Stack
//=============================================================================

static inline void sim_push(SimState& st, uint16_t v) {
    SP = static_cast<uint16_t>(SP - 2);
    st.mem.write16(SS, SP, v);
}
static inline uint16_t sim_pop(SimState& st) {
    uint16_t v = st.mem.read16(SS, SP);
    SP = static_cast<uint16_t>(SP + 2);
    return v;
}

//=============================================================================
// FCB helpers
//=============================================================================

static inline std::string sim_fcb_name(SimState& st, uint16_t seg, uint16_t off) {
    // FCB: +0 drive, +1..8 name, +9..11 ext (space padded)
    std::string n, e;
    for (int i = 0; i < 8; ++i) {
        char c = static_cast<char>(st.mem.read8(seg, static_cast<uint16_t>(off + 1 + i)));
        if (c != ' ' && c != 0) n.push_back(c);
    }
    for (int i = 0; i < 3; ++i) {
        char c = static_cast<char>(st.mem.read8(seg, static_cast<uint16_t>(off + 9 + i)));
        if (c != ' ' && c != 0) e.push_back(c);
    }
    if (e.empty()) return n;
    return n + "." + e;
}

static inline void sim_fcb_to_lower(std::string& s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

//=============================================================================
// INT 21h stubs
//=============================================================================

static inline void sim_int21(SimState& st, const Options& opts) {
    st.int21_count++;
    const uint8_t ah = AH;
    CF = 0;

    auto log_int = [&](std::string_view msg) {
        // Always log file-ish / exit / string; skip spammy console I/O unless --trace
        const bool noisy = (ah == 0x02 || ah == 0x06 || ah == 0x0B || ah == 0x0C);
        if (noisy && !opts.simTrace) return;
        std::cout << std::format("  [INT21 AH={:02X}h] {}\n", ah, msg);
    };

    switch (ah) {
    case 0x00: // terminate
    case 0x4C: // exit with code AL
        st.halted = true;
        st.halt_reason = std::format("DOS terminate (AH={:02X}h, AL={:02X}h)", ah, AL);
        log_int(st.halt_reason);
        return;

    case 0x09: { // print $-string at DS:DX
        std::string s;
        uint16_t off = DX;
        for (int i = 0; i < 4096; ++i) {
            char c = static_cast<char>(st.mem.read8(DS, off));
            if (c == '$') break;
            s.push_back(c);
            off = static_cast<uint16_t>(off + 1);
        }
        log_int(std::format("write string DS:{:04X}: \"{}\"", DX, s));
        std::cout << "  DOS: " << s;
        if (s.empty() || s.back() != '\n') std::cout << "\n";
        return;
    }

    case 0x02: // write char DL
        log_int(std::format("write char '{:c}'", DL >= 32 && DL < 127 ? DL : '.'));
        return;

    case 0x06: // direct console I/O
        if (DL == 0xFF) {
            // input: after a few polls inject Space so menus can advance
            st.kbd_polls++;
            if (st.kbd_polls > 30) {
                AL = ' '; ZF = 0;
                st.kbd_polls = 0;
                st.keys_injected++;
            } else {
                AL = 0; ZF = 1;
            }
        } else {
            log_int(std::format("console out {:02X}h", DL));
        }
        return;

    case 0x07: // char input no echo
    case 0x08: // char input no echo
        AL = ' ';
        st.keys_injected++;
        return;

    case 0x0A: { // buffered input DS:DX
        // structure: max, count, data...
        uint8_t max = st.mem.read8(DS, DX);
        if (max > 0) {
            st.mem.write8(DS, static_cast<uint16_t>(DX + 1), 0); // zero length
        }
        return;
    }

    case 0x0B: // check keyboard
        st.kbd_polls++;
        AL = (st.kbd_polls > 30) ? 0xFF : 0;
        if (AL) st.kbd_polls = 0;
        return;

    case 0x0C: // flush + invoke AL
        AL = ' ';
        st.keys_injected++;
        return;

    case 0x1A: // set DTA
        st.dta_seg = DS;
        st.dta_off = DX;
        log_int(std::format("set DTA {:04X}:{:04X}", DS, DX));
        return;

    case 0x25: // set vector
        log_int(std::format("set INT {:02X}h vector to {:04X}:{:04X}", AL, DS, DX));
        // Store in IVT
        st.mem.write16(0, static_cast<uint16_t>(AL * 4), DX);
        st.mem.write16(0, static_cast<uint16_t>(AL * 4 + 2), DS);
        return;

    case 0x30: // DOS version
        AX = 0x0005; // 5.00
        BX = 0xFF00;
        CX = 0;
        log_int("get DOS version → 5.0");
        return;

    case 0x35: // get vector
        BX = st.mem.read16(0, static_cast<uint16_t>(AL * 4));
        ES = st.mem.read16(0, static_cast<uint16_t>(AL * 4 + 2));
        log_int(std::format("get INT {:02X}h vector → {:04X}:{:04X}", AL, ES, BX));
        return;

    case 0x48: { // allocate paragraphs BX
        // Toy allocator: hand out from high conventional mem downward
        static uint16_t next_alloc = 0x9000;
        uint16_t paras = BX;
        if (next_alloc < paras) {
            CF = 1; AX = 8; BX = next_alloc; // not enough
            log_int(std::format("alloc {:04X}h paras → FAIL", paras));
        } else {
            next_alloc = static_cast<uint16_t>(next_alloc - paras);
            AX = next_alloc;
            CF = 0;
            log_int(std::format("alloc {:04X}h paras → {:04X}h", paras, AX));
        }
        return;
    }

    case 0x49: // free block ES
        log_int(std::format("free block ES={:04X}h (ignored)", ES));
        CF = 0;
        return;

    case 0x4A: // resize ES to BX paras
        log_int(std::format("resize ES={:04X}h to {:04X}h paras (stub ok)", ES, BX));
        CF = 0;
        return;

    case 0x0F: { // FCB open
        std::string name = sim_fcb_name(st, DS, DX);
        sim_fcb_to_lower(name);
        auto path = st.host_dir / name;
        // Also try uppercase original path components
        uint32_t key = SimMemory::linear(DS, DX);
        SimFile sf;
        sf.path = path.string();
        sf.fp = std::fopen(path.string().c_str(), "rb");
        if (!sf.fp) {
            // try as-is from FCB without lower
            std::string n2 = sim_fcb_name(st, DS, DX);
            path = st.host_dir / n2;
            sf.path = path.string();
            sf.fp = std::fopen(path.string().c_str(), "rb");
        }
        if (!sf.fp) {
            AL = 0xFF;
            log_int(std::format("FCB open '{}' → FAIL (looked in {})", name, st.host_dir.string()));
        } else {
            AL = 0;
            // Default record size
            st.mem.write16(DS, static_cast<uint16_t>(DX + 0x0E), 128);
            st.fcb_files[key] = sf;
            log_int(std::format("FCB open '{}' → OK ({})", name, sf.path));
        }
        return;
    }

    case 0x10: { // FCB close
        uint32_t key = SimMemory::linear(DS, DX);
        auto it = st.fcb_files.find(key);
        if (it != st.fcb_files.end()) {
            if (it->second.fp) std::fclose(it->second.fp);
            log_int(std::format("FCB close '{}'", it->second.path));
            st.fcb_files.erase(it);
            AL = 0;
        } else {
            AL = 0xFF;
            log_int("FCB close → unknown FCB");
        }
        return;
    }

    case 0x14:   // sequential read
    case 0x21:   // random read
    case 0x27: { // random block read
        uint32_t key = SimMemory::linear(DS, DX);
        auto it = st.fcb_files.find(key);
        if (it == st.fcb_files.end() || !it->second.fp) {
            AL = 1;
            log_int("FCB read → no open FCB");
            return;
        }
        uint16_t rec_size = st.mem.read16(DS, static_cast<uint16_t>(DX + 0x0E));
        if (rec_size == 0) rec_size = 128;
        uint16_t recs = (ah == 0x27) ? CX : 1;
        uint32_t bytes = static_cast<uint32_t>(recs) * rec_size;

        // Random record number at FCB+0x21 (3 bytes) for 0x21/0x27
        if (ah == 0x21 || ah == 0x27) {
            uint32_t rec =
                st.mem.read8(DS, static_cast<uint16_t>(DX + 0x21)) |
                (static_cast<uint32_t>(st.mem.read8(DS, static_cast<uint16_t>(DX + 0x22))) << 8) |
                (static_cast<uint32_t>(st.mem.read8(DS, static_cast<uint16_t>(DX + 0x23))) << 16);
            std::fseek(it->second.fp, static_cast<long>(rec * rec_size), SEEK_SET);
        }

        std::vector<uint8_t> buf(bytes);
        size_t n = std::fread(buf.data(), 1, bytes, it->second.fp);
        // Write into DTA
        for (size_t i = 0; i < n; ++i)
            st.mem.write8(st.dta_seg, static_cast<uint16_t>(st.dta_off + i), buf[i]);

        if (ah == 0x27)
            CX = static_cast<uint16_t>(n / rec_size);
        AL = (n < bytes) ? 1 : 0; // 1 = EOF partial
        log_int(std::format("FCB read {} bytes from '{}' → DTA {:04X}:{:04X} (AL={})",
                            n, it->second.path, st.dta_seg, st.dta_off, AL));
        return;
    }

    case 0x16: { // FCB create
        std::string name = sim_fcb_name(st, DS, DX);
        sim_fcb_to_lower(name);
        auto path = st.host_dir / name;
        uint32_t key = SimMemory::linear(DS, DX);
        SimFile sf;
        sf.path = path.string();
        sf.fp = std::fopen(path.string().c_str(), "wb+");
        if (!sf.fp) {
            AL = 0xFF;
            log_int(std::format("FCB create '{}' → FAIL", name));
        } else {
            AL = 0;
            st.mem.write16(DS, static_cast<uint16_t>(DX + 0x0E), 128);
            st.fcb_files[key] = sf;
            log_int(std::format("FCB create '{}' → OK", name));
        }
        return;
    }

    case 0x3D: { // handle open DS:DX asciiz, AL mode
        std::string name;
        uint16_t off = DX;
        for (int i = 0; i < 128; ++i) {
            char c = static_cast<char>(st.mem.read8(DS, off));
            if (c == 0) break;
            name.push_back(c);
            off = static_cast<uint16_t>(off + 1);
        }
        auto path = st.host_dir / name;
        const char* mode = (AL & 1) ? "rb+" : "rb";
        std::FILE* fp = std::fopen(path.string().c_str(), mode);
        if (!fp) {
            CF = 1; AX = 2; // file not found
            log_int(std::format("handle open '{}' → FAIL", name));
        } else {
            uint16_t h = st.next_handle++;
            SimFile sf;
            sf.fp = fp;
            sf.path = path.string();
            st.handle_files[h] = sf;
            AX = h; CF = 0;
            log_int(std::format("handle open '{}' → handle {:04X}h", name, h));
        }
        return;
    }

    case 0x3E: { // close handle BX
        auto it = st.handle_files.find(BX);
        if (it == st.handle_files.end()) {
            CF = 1; AX = 6;
            log_int(std::format("handle close {:04X}h → FAIL", BX));
        } else {
            if (it->second.fp) std::fclose(it->second.fp);
            log_int(std::format("handle close {:04X}h ({})", BX, it->second.path));
            st.handle_files.erase(it);
            CF = 0;
        }
        return;
    }

    case 0x3F: { // read BX handle, CX bytes, DS:DX buffer
        auto it = st.handle_files.find(BX);
        if (it == st.handle_files.end() || !it->second.fp) {
            CF = 1; AX = 6;
            log_int("handle read → bad handle");
            return;
        }
        std::vector<uint8_t> buf(CX);
        size_t n = std::fread(buf.data(), 1, CX, it->second.fp);
        for (size_t i = 0; i < n; ++i)
            st.mem.write8(DS, static_cast<uint16_t>(DX + i), buf[i]);
        AX = static_cast<uint16_t>(n); CF = 0;
        log_int(std::format("handle read {} bytes from '{}' -> DS:{:04X}",
                            n, it->second.path, DX));
        return;
    }

    case 0x2A: // get date
        CX = 2026; DH = 7; DL = 16; AL = 4;
        return;
    case 0x2C: // get time
        CH = 12; CL = 0; DH = 0; DL = 0;
        return;

    default:
        log_int(std::format("unimplemented → CF=1 ({})",
                            format_int_annotation(0x21, ah, AL)));
        CF = 1;
        AX = 1;
        return;
    }
}

static inline void sim_int(SimState& st, const Options& opts, uint8_t num) {
    if (num == 0x21) {
        sim_int21(st, opts);
        return;
    }
    if (num == 0x20) {
        st.halted = true;
        st.halt_reason = "INT 20h terminate";
        std::cout << "  [INT20] terminate\n";
        return;
    }
    if (num == 0x10) {
        // Video: ignore most; log mode set
        if (AH == 0x00)
            std::cout << std::format("  [INT10] set video mode {:02X}h\n", AL);
        return;
    }
    if (num == 0x16) {
        // Keyboard: after idle polls inject Space (scan 0x39) then Enter
        if (AH == 0x01) {
            st.kbd_polls++;
            if (st.kbd_polls > 40) {
                ZF = 0;
                AX = (st.keys_injected & 1) ? 0x1C0D : 0x3920;
            } else {
                ZF = 1;
            }
            return;
        }
        if (AH == 0x00) {
            AX = (st.keys_injected & 1) ? 0x1C0D : 0x3920;
            st.keys_injected++;
            st.kbd_polls = 0;
            return;
        }
        return;
    }
    std::cout << std::format("  [INT{:02X}] unhandled AH={:02X}h\n", num, AH);
}

//=============================================================================
// Breakpoints
//=============================================================================

static inline bool sim_bp_match_ip(const Breakpoint& bp) {
    if (!bp.enabled) return false;
    if (bp.type == BreakpointType::Ip)
        return IP == bp.ip;
    if (bp.type == BreakpointType::CsIp)
        return CS == bp.cs && IP == bp.ip;
    return false;
}

static inline bool sim_bp_match_int(const Breakpoint& bp, uint8_t int_num) {
    if (!bp.enabled) return false;
    if (bp.type == BreakpointType::Int)
        return bp.int_num == int_num;
    if (bp.type == BreakpointType::IntAh)
        return bp.int_num == int_num && bp.has_ah && bp.ah == AH;
    return false;
}

static inline uint16_t sim_resolve_seg_token(std::string_view tok) {
    if (tok == "cs") return CS;
    if (tok == "ds") return DS;
    if (tok == "es") return ES;
    if (tok == "ss") return SS;
    uint16_t v = 0;
    Options::parse_u16_hex(tok, v);
    return v;
}

static inline void sim_print_regs() {
    std::cout << std::format(
        "  AX={:04X} BX={:04X} CX={:04X} DX={:04X}  SI={:04X} DI={:04X} BP={:04X} SP={:04X}\n"
        "  CS={:04X} DS={:04X} ES={:04X} SS={:04X}  IP={:04X}  FLAGS={:04X}"
        "  [C={} Z={} S={} O={} D={} I={}]\n",
        AX, BX, CX, DX, SI, DI, BP, SP,
        CS, DS, ES, SS, IP, FLAGS,
        static_cast<unsigned>(CF), static_cast<unsigned>(ZF),
        static_cast<unsigned>(SF), static_cast<unsigned>(OF),
        static_cast<unsigned>(DF), static_cast<unsigned>(IF));
}

static inline void sim_dump_mem(SimState& st, const DumpSpec& d) {
    if (!d.valid) return;
    uint16_t seg = sim_resolve_seg_token(d.seg_token);
    std::cout << std::format("  dump {:s}:{:04X} len {:04X}h:\n", d.seg_token, d.offset, d.length);
    std::vector<uint8_t> tmp(d.length);
    for (uint16_t i = 0; i < d.length; ++i)
        tmp[i] = st.mem.read8(seg, static_cast<uint16_t>(d.offset + i));
    // Reuse hex printer with fake vector at offset 0 — print_hex_dump uses vector offset
    print_hex_dump(tmp, 0, tmp.size(), "");
}

static inline bool sim_fire_bps_ip(SimState& st, Options& opts) {
    bool should_stop = false;
    for (auto& bp : opts.breakpoints) {
        if (!sim_bp_match_ip(bp)) continue;
        bp.hits++;
        if (bp.log) {
            std::cout << std::format("\n*** BREAKPOINT hit #{}  {}  at {:04X}:{:04X}  (insn {})\n",
                                     bp.hits, bp.raw, CS, IP, st.insn_count);
            sim_print_regs();
            sim_dump_mem(st, opts.dumpOnHit);
        }
        if (bp.once) bp.enabled = false;
        if (bp.stop) should_stop = true;
    }
    return should_stop;
}

static inline bool sim_fire_bps_int(SimState& st, Options& opts, uint8_t int_num) {
    bool should_stop = false;
    for (auto& bp : opts.breakpoints) {
        if (!sim_bp_match_int(bp, int_num)) continue;
        bp.hits++;
        if (bp.log) {
            std::cout << std::format(
                "\n*** BREAKPOINT hit #{}  {}  INT {:02X}h AH={:02X}h AL={:02X}h  at {:04X}:{:04X}  (insn {})\n",
                bp.hits, bp.raw, int_num, AH, AL, CS, IP, st.insn_count);
            std::cout << "  " << format_int_annotation(int_num, AH, AL) << "\n";
            sim_print_regs();
            // Auto-dump FCB (37 bytes) on FCB-ish calls
            if (int_num == 0x21 && (AH == 0x0F || AH == 0x10 || AH == 0x14 ||
                                    AH == 0x15 || AH == 0x16 || AH == 0x21 ||
                                    AH == 0x22 || AH == 0x27 || AH == 0x28)) {
                std::string nm = sim_fcb_name(st, DS, DX);
                std::cout << std::format("  FCB @ DS:{:04X} name='{}'\n", DX, nm);
                DumpSpec fcb_dump;
                fcb_dump.valid = true;
                fcb_dump.seg_token = "ds";
                fcb_dump.offset = DX;
                fcb_dump.length = 0x25;
                sim_dump_mem(st, fcb_dump);
            }
            if (int_num == 0x21 && AH == 0x3D) {
                std::string name;
                uint16_t off = DX;
                for (int i = 0; i < 64; ++i) {
                    char c = static_cast<char>(st.mem.read8(DS, off));
                    if (!c) break;
                    name.push_back(c);
                    off = static_cast<uint16_t>(off + 1);
                }
                std::cout << std::format("  asciiz @ DS:{:04X} = '{}'\n", DX, name);
            }
            sim_dump_mem(st, opts.dumpOnHit);
        }
        if (bp.once) bp.enabled = false;
        if (bp.stop) should_stop = true;
    }
    return should_stop;
}

//=============================================================================
// Condition codes for jcc
//=============================================================================

static inline int sim_jcc(const std::string& m) {
    if (m == "je" || m == "jz") return ZF ? 1 : 0;
    if (m == "jne" || m == "jnz") return ZF ? 0 : 1;
    if (m == "jb" || m == "jnae" || m == "jc") return CF ? 1 : 0;
    if (m == "jnb" || m == "jae" || m == "jnc") return CF ? 0 : 1;
    if (m == "jbe" || m == "jna") return (CF || ZF) ? 1 : 0;
    if (m == "ja" || m == "jnbe") return (CF || ZF) ? 0 : 1;
    if (m == "js") return SF ? 1 : 0;
    if (m == "jns") return SF ? 0 : 1;
    if (m == "jo") return OF ? 1 : 0;
    if (m == "jno") return OF ? 0 : 1;
    if (m == "jp" || m == "jpe") return PF ? 1 : 0;
    if (m == "jnp" || m == "jpo") return PF ? 0 : 1;
    if (m == "jl" || m == "jnge") return (SF != OF) ? 1 : 0;
    if (m == "jge" || m == "jnl") return (SF == OF) ? 1 : 0;
    if (m == "jle" || m == "jng") return (ZF || SF != OF) ? 1 : 0;
    if (m == "jg" || m == "jnle") return (!ZF && SF == OF) ? 1 : 0;
    if (m == "jcxz") return (CX == 0) ? 1 : 0;
    return -1;
}

//=============================================================================
// Execute one Capstone instruction; returns false if unsupported/halt
//=============================================================================

static inline bool sim_exec_insn(SimState& st, Options& opts) {
    const cs_insn* in = st.insn;
    const cs_x86& x86 = in->detail->x86;
    std::string mnem = in->mnemonic;
    // Capstone may fold REP into the mnemonic ("rep movsb") rather than only
    // setting x86.prefix[]. Normalize so string ops and others still match.
    bool rep_prefix = false;
    bool repne_prefix = false;
    if (mnem.starts_with("rep ")) {
        rep_prefix = true;
        mnem = mnem.substr(4);
    } else if (mnem.starts_with("repe ") || mnem.starts_with("repz ")) {
        rep_prefix = true;
        mnem = mnem.substr(mnem.find(' ') + 1);
    } else if (mnem.starts_with("repne ") || mnem.starts_with("repnz ")) {
        repne_prefix = true;
        mnem = mnem.substr(mnem.find(' ') + 1);
    }
    const uint16_t next_ip = static_cast<uint16_t>(IP + in->size);

    // Segment prefixes from Capstone detail
    st.seg_override = 0xFFFF;
    for (int i = 0; i < x86.prefix[0] || i < 4; ++i) {
        // Capstone stores segment override in prefix[1] typically
    }
    if (x86.prefix[1] == 0x2E) st.seg_override = CS;
    else if (x86.prefix[1] == 0x3E) st.seg_override = DS;
    else if (x86.prefix[1] == 0x26) st.seg_override = ES;
    else if (x86.prefix[1] == 0x36) st.seg_override = SS;
    else if (x86.prefix[1] == 0x64) st.seg_override = DS; // FS→DS fallback
    else if (x86.prefix[1] == 0x65) st.seg_override = DS;

    // Also scan raw bytes for override as first byte
    if (in->size > 0) {
        uint8_t b0 = in->bytes[0];
        if (b0 == 0x2E) st.seg_override = CS;
        else if (b0 == 0x3E) st.seg_override = DS;
        else if (b0 == 0x26) st.seg_override = ES;
        else if (b0 == 0x36) st.seg_override = SS;
    }

    auto op = [&](int i) -> const cs_x86_op& { return x86.operands[i]; };
    auto is8 = [&](int i) {
        if (x86.operands[i].type == X86_OP_REG)
            return sim_is_byte_reg(x86.operands[i].reg);
        return x86.operands[i].size == 1;
    };

    // ---- control / flags ----
    if (mnem == "nop" || mnem == "pause") { IP = next_ip; return true; }
    if (mnem == "cli") { IF = 0; IP = next_ip; return true; }
    if (mnem == "sti") { IF = 1; IP = next_ip; return true; }
    if (mnem == "cld") { DF = 0; IP = next_ip; return true; }
    if (mnem == "std") { DF = 1; IP = next_ip; return true; }
    if (mnem == "clc") { CF = 0; IP = next_ip; return true; }
    if (mnem == "stc") { CF = 1; IP = next_ip; return true; }
    if (mnem == "cmc") { CF = CF ? 0 : 1; IP = next_ip; return true; }
    if (mnem == "sahf") {
        FLAGS = static_cast<uint16_t>((FLAGS & 0xFF00) | (AH & 0xD5) | 0x02);
        IP = next_ip; return true;
    }
    if (mnem == "lahf") { AH = static_cast<uint8_t>(FLAGS & 0xFF); IP = next_ip; return true; }

    // ---- mov ----
    if (mnem == "mov" && x86.op_count == 2) {
        bool b = is8(0) || is8(1);
        uint16_t v = 0;
        if (!sim_read_op(st, op(1), v, b)) return false;
        if (!sim_write_op(st, op(0), v, b)) return false;
        IP = next_ip; return true;
    }

    // ---- lea ----
    if (mnem == "lea" && x86.op_count == 2 && op(0).type == X86_OP_REG && op(1).type == X86_OP_MEM) {
        uint16_t seg = 0, off = 0;
        // LEA ignores segment
        uint16_t save = st.seg_override;
        st.seg_override = 0xFFFF;
        if (!sim_ea(st, op(1), seg, off)) return false;
        st.seg_override = save;
        sim_reg_set(op(0).reg, off);
        IP = next_ip; return true;
    }

    // ---- xchg ----
    if (mnem == "xchg" && x86.op_count == 2) {
        bool b = is8(0);
        uint16_t a = 0, c = 0;
        if (!sim_read_op(st, op(0), a, b) || !sim_read_op(st, op(1), c, b)) return false;
        if (!sim_write_op(st, op(0), c, b) || !sim_write_op(st, op(1), a, b)) return false;
        IP = next_ip; return true;
    }

    // ---- push / pop ----
    if (mnem == "push" && x86.op_count == 1) {
        uint16_t v = 0;
        if (op(0).type == X86_OP_REG && op(0).reg == X86_REG_CS) v = CS;
        else if (!sim_read_op(st, op(0), v, false)) return false;
        sim_push(st, v);
        IP = next_ip; return true;
    }
    if (mnem == "pop" && x86.op_count == 1) {
        uint16_t v = sim_pop(st);
        if (!sim_write_op(st, op(0), v, false)) return false;
        IP = next_ip; return true;
    }
    if (mnem == "pushf" || mnem == "pushfd") { sim_push(st, FLAGS); IP = next_ip; return true; }
    if (mnem == "popf" || mnem == "popfd") {
        FLAGS = static_cast<uint16_t>((sim_pop(st) & 0x0FD7) | 0x0002);
        IP = next_ip; return true;
    }
    if (mnem == "pusha" || mnem == "pushaw") {
        uint16_t sp0 = SP;
        sim_push(st, AX); sim_push(st, CX); sim_push(st, DX); sim_push(st, BX);
        sim_push(st, sp0); sim_push(st, BP); sim_push(st, SI); sim_push(st, DI);
        IP = next_ip; return true;
    }
    if (mnem == "popa" || mnem == "popaw") {
        DI = sim_pop(st); SI = sim_pop(st); BP = sim_pop(st);
        (void)sim_pop(st); // SP discarded
        BX = sim_pop(st); DX = sim_pop(st); CX = sim_pop(st); AX = sim_pop(st);
        IP = next_ip; return true;
    }

    // ---- alu binary ----
    auto alu_bin = [&](auto apply, bool write_dst, bool is_cmp) -> bool {
        if (x86.op_count != 2) return false;
        bool b = is8(0);
        uint16_t d = 0, s = 0;
        if (!sim_read_op(st, op(0), d, b) || !sim_read_op(st, op(1), s, b)) return false;
        uint16_t r = apply(d, s, b);
        if (is_cmp) {
            sim_set_cmp(d, s, b);
        } else if (write_dst) {
            if (!sim_write_op(st, op(0), r, b)) return false;
        }
        IP = next_ip;
        return true;
    };

    if (mnem == "add") {
        return alu_bin([&](uint16_t d, uint16_t s, bool b) {
            uint32_t r = static_cast<uint32_t>(d) + s;
            CF = b ? ((r & 0x100) != 0) : ((r & 0x10000) != 0);
            uint16_t res = static_cast<uint16_t>(r);
            if (b) {
                OF = (((d ^ res) & (s ^ res)) & 0x80) ? 1 : 0;
                sim_set_szp8(static_cast<uint8_t>(res));
            } else {
                OF = (((d ^ res) & (s ^ res)) & 0x8000) ? 1 : 0;
                sim_set_szp16(res);
            }
            return res;
        }, true, false);
    }
    if (mnem == "sub") {
        return alu_bin([&](uint16_t d, uint16_t s, bool b) {
            sim_set_cmp(d, s, b);
            return static_cast<uint16_t>(d - s);
        }, true, false);
    }
    if (mnem == "cmp") {
        return alu_bin([&](uint16_t d, uint16_t s, bool b) {
            (void)d; (void)s; (void)b;
            return uint16_t{0};
        }, false, true);
    }
    if (mnem == "xor") {
        return alu_bin([&](uint16_t d, uint16_t s, bool b) {
            uint16_t r = static_cast<uint16_t>(d ^ s);
            CF = 0; OF = 0;
            if (b) sim_set_szp8(static_cast<uint8_t>(r)); else sim_set_szp16(r);
            return r;
        }, true, false);
    }
    if (mnem == "or") {
        return alu_bin([&](uint16_t d, uint16_t s, bool b) {
            uint16_t r = static_cast<uint16_t>(d | s);
            CF = 0; OF = 0;
            if (b) sim_set_szp8(static_cast<uint8_t>(r)); else sim_set_szp16(r);
            return r;
        }, true, false);
    }
    if (mnem == "and" || mnem == "test") {
        bool is_test = (mnem == "test");
        return alu_bin([&](uint16_t d, uint16_t s, bool b) {
            uint16_t r = static_cast<uint16_t>(d & s);
            CF = 0; OF = 0;
            if (b) sim_set_szp8(static_cast<uint8_t>(r)); else sim_set_szp16(r);
            return r;
        }, !is_test, false);
    }
    if (mnem == "adc") {
        return alu_bin([&](uint16_t d, uint16_t s, bool b) {
            uint32_t r = static_cast<uint32_t>(d) + s + CF;
            CF = b ? ((r & 0x100) != 0) : ((r & 0x10000) != 0);
            uint16_t res = static_cast<uint16_t>(r);
            if (b) sim_set_szp8(static_cast<uint8_t>(res)); else sim_set_szp16(res);
            return res;
        }, true, false);
    }
    if (mnem == "sbb") {
        return alu_bin([&](uint16_t d, uint16_t s, bool b) {
            uint32_t r = static_cast<uint32_t>(d) - s - CF;
            CF = b ? ((r & 0x100) != 0) : ((r & 0x10000) != 0);
            uint16_t res = static_cast<uint16_t>(r);
            if (b) sim_set_szp8(static_cast<uint8_t>(res)); else sim_set_szp16(res);
            return res;
        }, true, false);
    }

    // ---- unary ----
    if ((mnem == "inc" || mnem == "dec") && x86.op_count == 1) {
        bool b = is8(0);
        uint16_t d = 0;
        if (!sim_read_op(st, op(0), d, b)) return false;
        uint16_t r = (mnem == "inc") ? static_cast<uint16_t>(d + 1)
                                     : static_cast<uint16_t>(d - 1);
        // INC/DEC do not affect CF
        if (b) {
            OF = ((mnem == "inc") ? (r == 0x80) : (r == 0x7F)) ? 1 : 0;
            sim_set_szp8(static_cast<uint8_t>(r));
        } else {
            OF = ((mnem == "inc") ? (r == 0x8000) : (r == 0x7FFF)) ? 1 : 0;
            sim_set_szp16(r);
        }
        if (!sim_write_op(st, op(0), r, b)) return false;
        IP = next_ip; return true;
    }
    if ((mnem == "neg" || mnem == "not") && x86.op_count == 1) {
        bool b = is8(0);
        uint16_t d = 0;
        if (!sim_read_op(st, op(0), d, b)) return false;
        uint16_t r;
        if (mnem == "not") {
            r = static_cast<uint16_t>(~d);
        } else {
            r = static_cast<uint16_t>(0 - d);
            CF = (d != 0) ? 1 : 0;
            if (b) sim_set_szp8(static_cast<uint8_t>(r)); else sim_set_szp16(r);
        }
        if (!sim_write_op(st, op(0), r, b)) return false;
        IP = next_ip; return true;
    }

    // ---- shifts ----
    // Capstone may emit "rcr al, 1" with op_count 1 (implicit 1) or 2.
    if (mnem == "shl" || mnem == "sal" || mnem == "shr" || mnem == "sar" ||
        mnem == "rol" || mnem == "ror" || mnem == "rcl" || mnem == "rcr") {
        if (x86.op_count < 1) return false;
        bool b = is8(0);
        uint16_t d = 0, cnt = 1;
        if (!sim_read_op(st, op(0), d, b)) return false;
        if (x86.op_count >= 2) {
            if (op(1).type == X86_OP_REG && op(1).reg == X86_REG_CL) cnt = CL;
            else if (op(1).type == X86_OP_IMM) cnt = static_cast<uint16_t>(op(1).imm);
            else return false;
        }
        cnt &= 0x1F;
        uint16_t r = d;
        const uint16_t mask = b ? 0xFF : 0xFFFF;
        const uint16_t msb = b ? 0x80 : 0x8000;
        for (uint16_t i = 0; i < cnt; ++i) {
            unsigned old_cf = CF;
            if (mnem == "shl" || mnem == "sal") {
                CF = (r & msb) ? 1 : 0;
                r = static_cast<uint16_t>((r << 1) & mask);
            } else if (mnem == "shr") {
                CF = r & 1;
                r = static_cast<uint16_t>((r >> 1) & mask);
            } else if (mnem == "sar") {
                CF = r & 1;
                if (b) r = static_cast<uint16_t>(static_cast<int8_t>(r & 0xFF) >> 1) & 0xFF;
                else r = static_cast<uint16_t>(static_cast<int16_t>(r) >> 1);
            } else if (mnem == "rol") {
                CF = (r & msb) ? 1 : 0;
                r = static_cast<uint16_t>(((r << 1) | CF) & mask);
            } else if (mnem == "ror") {
                CF = r & 1;
                r = static_cast<uint16_t>(((r >> 1) | (CF ? msb : 0)) & mask);
            } else if (mnem == "rcl") {
                CF = (r & msb) ? 1 : 0;
                r = static_cast<uint16_t>(((r << 1) | old_cf) & mask);
            } else if (mnem == "rcr") {
                CF = r & 1;
                r = static_cast<uint16_t>(((r >> 1) | (old_cf ? msb : 0)) & mask);
            }
        }
        if (b) { r &= 0xFF; sim_set_szp8(static_cast<uint8_t>(r)); }
        else sim_set_szp16(r);
        if (!sim_write_op(st, op(0), r, b)) return false;
        IP = next_ip; return true;
    }

    // ---- cbw / cwd ----
    if (mnem == "cbw" || mnem == "cbtw") {
        AH = (AL & 0x80) ? 0xFF : 0; IP = next_ip; return true;
    }
    // cwd / cdq / cwde — in 16-bit guest treat as sign-extend AX → DX:AX
    if (mnem == "cwd" || mnem == "cdq" || mnem == "cwtd" || mnem == "cqo") {
        DX = (AX & 0x8000) ? 0xFFFF : 0; IP = next_ip; return true;
    }
    if (mnem == "cwde" || mnem == "cwtl") {
        // 16→32 not modeled; keep AX
        IP = next_ip; return true;
    }

    // ---- lds / les ----
    if ((mnem == "lds" || mnem == "les") && x86.op_count == 2 && op(1).type == X86_OP_MEM) {
        uint16_t seg = 0, off = 0;
        if (!sim_ea(st, op(1), seg, off)) return false;
        uint16_t n_off = st.mem.read16(seg, off);
        uint16_t n_seg = st.mem.read16(seg, static_cast<uint16_t>(off + 2));
        if (!sim_reg_set(op(0).reg, n_off)) return false;
        if (mnem == "lds") DS = n_seg; else ES = n_seg;
        IP = next_ip; return true;
    }

    // ---- jumps (with loop-limit on backward edges) ----
    // Capstone names: jmp (near), ljmp (far), sometimes jmp with far mem op
    if (mnem == "ljmp" || mnem == "jmpf") {
        if (op(0).type == X86_OP_IMM) {
            // far absolute — Capstone may encode as one imm; rare in 16-bit dump
            IP = static_cast<uint16_t>(op(0).imm & 0xFFFF);
            return true;
        }
        if (op(0).type == X86_OP_MEM) {
            uint16_t seg = 0, off = 0;
            if (!sim_ea(st, op(0), seg, off)) return false;
            uint16_t n_ip = st.mem.read16(seg, off);
            uint16_t n_cs = st.mem.read16(seg, static_cast<uint16_t>(off + 2));
            CS = n_cs;
            IP = n_ip;
            return true;
        }
        return false;
    }
    if (mnem == "jmp" && x86.op_count >= 1) {
        if (op(0).type == X86_OP_IMM) {
            uint16_t target = static_cast<uint16_t>(
                op(0).imm - static_cast<uint64_t>(CS) * 16u);
            if (sim_should_skip_backedge(st, opts, IP, target, next_ip)) {
                IP = next_ip; // force continue past the spin
            } else {
                IP = target;
            }
            return true;
        }
        if (op(0).type == X86_OP_MEM) {
            // Near or far indirect
            if (op(0).size == 4) {
                uint16_t seg = 0, off = 0;
                if (!sim_ea(st, op(0), seg, off)) return false;
                uint16_t n_ip = st.mem.read16(seg, off);
                uint16_t n_cs = st.mem.read16(seg, static_cast<uint16_t>(off + 2));
                CS = n_cs;
                IP = n_ip;
                return true;
            }
            uint16_t t = 0;
            if (!sim_read_op(st, op(0), t, false)) return false;
            if (sim_should_skip_backedge(st, opts, IP, t, next_ip))
                IP = next_ip;
            else
                IP = t;
            return true;
        }
        if (op(0).type == X86_OP_REG) {
            uint16_t t = 0;
            if (!sim_read_op(st, op(0), t, false)) return false;
            if (sim_should_skip_backedge(st, opts, IP, t, next_ip))
                IP = next_ip;
            else
                IP = t;
            return true;
        }
        return false;
    }
    if (mnem.size() >= 2 && mnem[0] == 'j' && mnem != "jmp" && mnem != "jecxz") {
        int t = sim_jcc(mnem);
        if (t < 0) return false;
        if (t == 1 && op(0).type == X86_OP_IMM) {
            uint16_t target = static_cast<uint16_t>(
                op(0).imm - static_cast<uint64_t>(CS) * 16u);
            if (sim_should_skip_backedge(st, opts, IP, target, next_ip))
                IP = next_ip;
            else
                IP = target;
        } else {
            IP = next_ip;
        }
        return true;
    }
    // LOOP/CX: always honor CX (finite). Do NOT apply loop-limit — cutting
    // these short corrupts memset/strcpy-style Pascal RTL loops.
    if (mnem == "loop" || mnem == "loope" || mnem == "loopz" ||
        mnem == "loopne" || mnem == "loopnz") {
        CX = static_cast<uint16_t>(CX - 1);
        bool take = (CX != 0);
        if (mnem == "loope" || mnem == "loopz") take = take && ZF;
        if (mnem == "loopne" || mnem == "loopnz") take = take && !ZF;
        if (take && op(0).type == X86_OP_IMM)
            IP = static_cast<uint16_t>(op(0).imm - static_cast<uint64_t>(CS) * 16u);
        else
            IP = next_ip;
        return true;
    }

    // ---- call / ret ----
    if (mnem == "call") {
        if (op(0).type == X86_OP_IMM) {
            sim_push(st, next_ip);
            IP = static_cast<uint16_t>(op(0).imm - static_cast<uint64_t>(CS) * 16u);
            return true;
        }
        if (x86.op_count >= 1 && (op(0).type == X86_OP_MEM || op(0).type == X86_OP_REG)) {
            // near or far — Capstone size 4 mem often far
            if (op(0).type == X86_OP_MEM && op(0).size == 4) {
                uint16_t seg = 0, off = 0;
                if (!sim_ea(st, op(0), seg, off)) return false;
                uint16_t n_ip = st.mem.read16(seg, off);
                uint16_t n_cs = st.mem.read16(seg, static_cast<uint16_t>(off + 2));
                sim_push(st, CS);
                sim_push(st, next_ip);
                CS = n_cs; IP = n_ip;
                return true;
            }
            uint16_t t = 0;
            if (!sim_read_op(st, op(0), t, false)) return false;
            sim_push(st, next_ip);
            IP = t;
            return true;
        }
        return false;
    }
    if (mnem == "ret" || mnem == "retn") {
        IP = sim_pop(st);
        if (x86.op_count == 1 && op(0).type == X86_OP_IMM)
            SP = static_cast<uint16_t>(SP + op(0).imm);
        return true;
    }
    if (mnem == "retf" || mnem == "retfq") {
        IP = sim_pop(st);
        CS = sim_pop(st);
        if (x86.op_count == 1 && op(0).type == X86_OP_IMM)
            SP = static_cast<uint16_t>(SP + op(0).imm);
        return true;
    }

    // ---- int ----
    if (mnem == "int" && x86.op_count >= 1 && op(0).type == X86_OP_IMM) {
        uint8_t n = static_cast<uint8_t>(op(0).imm);
        // Log/hit BPs at the INT instruction, then run the stub so FCB opens etc.
        // still happen (useful for --dump after read). Stop after the handler.
        bool stop_bp = sim_fire_bps_int(st, opts, n);
        sim_int(st, opts, n);
        if (stop_bp && !st.halted) {
            st.halted = true;
            st.halt_reason = "breakpoint (INT)";
            return true;
        }
        if (!st.halted) IP = next_ip;
        return true;
    }
    if (mnem == "into") { IP = next_ip; return true; }
    if (mnem == "iret" || mnem == "iretd") {
        IP = sim_pop(st);
        CS = sim_pop(st);
        FLAGS = sim_pop(st);
        return true;
    }

    // ---- string ops (simplified) ----
    if (mnem == "movsb" || mnem == "movsw" || mnem == "stosb" || mnem == "stosw" ||
        mnem == "lodsb" || mnem == "lodsw" || mnem == "scasb" || mnem == "scasw" ||
        mnem == "cmpsb" || mnem == "cmpsw") {
        bool rep = rep_prefix || repne_prefix;
        for (int pi = 0; pi < 4; ++pi) {
            if (x86.prefix[pi] == 0xF3) { rep = true; rep_prefix = true; }
            if (x86.prefix[pi] == 0xF2) { rep = true; repne_prefix = true; }
        }

        auto once = [&]() {
            int step = (DF ? -1 : 1);
            uint16_t src_seg = (st.seg_override != 0xFFFF) ? st.seg_override : DS;
            if (mnem == "movsb") {
                uint8_t v = st.mem.read8(src_seg, SI);
                st.mem.write8(ES, DI, v);
                SI = static_cast<uint16_t>(SI + step);
                DI = static_cast<uint16_t>(DI + step);
            } else if (mnem == "movsw") {
                uint16_t v = st.mem.read16(src_seg, SI);
                st.mem.write16(ES, DI, v);
                SI = static_cast<uint16_t>(SI + 2 * step);
                DI = static_cast<uint16_t>(DI + 2 * step);
            } else if (mnem == "stosb") {
                st.mem.write8(ES, DI, AL);
                DI = static_cast<uint16_t>(DI + step);
            } else if (mnem == "stosw") {
                st.mem.write16(ES, DI, AX);
                DI = static_cast<uint16_t>(DI + 2 * step);
            } else if (mnem == "lodsb") {
                AL = st.mem.read8(src_seg, SI);
                SI = static_cast<uint16_t>(SI + step);
            } else if (mnem == "lodsw") {
                AX = st.mem.read16(src_seg, SI);
                SI = static_cast<uint16_t>(SI + 2 * step);
            } else if (mnem == "scasb") {
                uint8_t v = st.mem.read8(ES, DI);
                sim_set_cmp(AL, v, true);
                DI = static_cast<uint16_t>(DI + step);
            } else if (mnem == "scasw") {
                uint16_t v = st.mem.read16(ES, DI);
                sim_set_cmp(AX, v, false);
                DI = static_cast<uint16_t>(DI + 2 * step);
            } else if (mnem == "cmpsb") {
                uint8_t a = st.mem.read8(src_seg, SI);
                uint8_t b = st.mem.read8(ES, DI);
                sim_set_cmp(a, b, true);
                SI = static_cast<uint16_t>(SI + step);
                DI = static_cast<uint16_t>(DI + step);
            } else if (mnem == "cmpsw") {
                uint16_t a = st.mem.read16(src_seg, SI);
                uint16_t b = st.mem.read16(ES, DI);
                sim_set_cmp(a, b, false);
                SI = static_cast<uint16_t>(SI + 2 * step);
                DI = static_cast<uint16_t>(DI + 2 * step);
            }
        };

        const bool scan_cmp = (mnem == "scasb" || mnem == "scasw" ||
                               mnem == "cmpsb" || mnem == "cmpsw");
        if (rep) {
            uint32_t guard = 0;
            while (CX != 0 && guard++ < 0x100000) {
                once();
                CX = static_cast<uint16_t>(CX - 1);
                if (scan_cmp && rep_prefix && !ZF) break;
                if (scan_cmp && repne_prefix && ZF) break;
            }
        } else {
            once();
        }
        IP = next_ip; return true;
    }

    // ---- mul / imul / div / idiv ----
    if ((mnem == "mul" || mnem == "imul") && x86.op_count == 1) {
        bool b = is8(0);
        uint16_t s = 0;
        if (!sim_read_op(st, op(0), s, b)) return false;
        if (mnem == "imul") {
            if (b) {
                int16_t r = static_cast<int8_t>(AL) * static_cast<int8_t>(s);
                AX = static_cast<uint16_t>(r);
                CF = OF = (AH == 0x00 || AH == 0xFF) ? 0 : 1;
            } else {
                int32_t r = static_cast<int16_t>(AX) * static_cast<int16_t>(s);
                AX = static_cast<uint16_t>(r);
                DX = static_cast<uint16_t>(static_cast<uint32_t>(r) >> 16);
                int32_t sign_ext = static_cast<int16_t>(AX);
                CF = OF = (r != sign_ext) ? 1 : 0;
            }
        } else if (b) {
            uint16_t r = static_cast<uint16_t>(AL * static_cast<uint8_t>(s));
            AX = r;
            CF = OF = (AH != 0) ? 1 : 0;
        } else {
            uint32_t r = static_cast<uint32_t>(AX) * s;
            AX = static_cast<uint16_t>(r);
            DX = static_cast<uint16_t>(r >> 16);
            CF = OF = (DX != 0) ? 1 : 0;
        }
        IP = next_ip; return true;
    }
    if (mnem == "imul" && x86.op_count == 2) {
        // imul r16, r/m16
        uint16_t d = 0, s = 0;
        if (!sim_read_op(st, op(0), d, false) || !sim_read_op(st, op(1), s, false))
            return false;
        int32_t r = static_cast<int16_t>(d) * static_cast<int16_t>(s);
        sim_write_op(st, op(0), static_cast<uint16_t>(r), false);
        CF = OF = (r != static_cast<int16_t>(r)) ? 1 : 0;
        IP = next_ip; return true;
    }
    if (mnem == "imul" && x86.op_count == 3) {
        uint16_t s = 0;
        if (!sim_read_op(st, op(1), s, false)) return false;
        int32_t imm = static_cast<int32_t>(op(2).imm);
        int32_t r = static_cast<int16_t>(s) * imm;
        sim_write_op(st, op(0), static_cast<uint16_t>(r), false);
        CF = OF = (r != static_cast<int16_t>(r)) ? 1 : 0;
        IP = next_ip; return true;
    }
    if ((mnem == "div" || mnem == "idiv") && x86.op_count == 1) {
        bool b = is8(0);
        uint16_t s = 0;
        if (!sim_read_op(st, op(0), s, b)) return false;
        if (s == 0) {
            st.halted = true;
            st.halt_reason = "divide by zero";
            return true;
        }
        if (mnem == "idiv") {
            if (b) {
                int16_t num = static_cast<int16_t>(AX);
                int8_t den = static_cast<int8_t>(s);
                AL = static_cast<uint8_t>(num / den);
                AH = static_cast<uint8_t>(num % den);
            } else {
                int32_t num = (static_cast<int32_t>(DX) << 16) | AX;
                int16_t den = static_cast<int16_t>(s);
                AX = static_cast<uint16_t>(num / den);
                DX = static_cast<uint16_t>(num % den);
            }
        } else if (b) {
            uint16_t num = AX;
            AL = static_cast<uint8_t>(num / static_cast<uint8_t>(s));
            AH = static_cast<uint8_t>(num % static_cast<uint8_t>(s));
        } else {
            uint32_t num = (static_cast<uint32_t>(DX) << 16) | AX;
            AX = static_cast<uint16_t>(num / s);
            DX = static_cast<uint16_t>(num % s);
        }
        IP = next_ip; return true;
    }

    // ---- in / out ignore ----
    if (mnem == "in" || mnem == "out") { IP = next_ip; return true; }

    // ---- hlt ----
    if (mnem == "hlt") {
        st.halted = true;
        st.halt_reason = "HLT";
        return true;
    }

    return false; // unsupported
}

//=============================================================================
// Main run loop
//=============================================================================

static inline void sim_run_mz(Options& opts,
                              const MZHeader& header,
                              const std::vector<uint8_t>& fileData,
                              const std::vector<RelocEntry>& relocs,
                              size_t header_size_bytes,
                              int64_t load_image_size) {
    SimState st;
    st.image_seg = opts.loadBase;
    st.psp_seg = static_cast<uint16_t>(opts.loadBase - 0x0010);
    st.host_dir = std::filesystem::path(opts.filename).parent_path();
    if (st.host_dir.empty()) st.host_dir = ".";
    st.dta_seg = st.psp_seg;
    st.dta_off = 0x80;

    size_t img_bytes = load_image_size > 0
        ? static_cast<size_t>(load_image_size)
        : (fileData.size() > header_size_bytes
               ? fileData.size() - header_size_bytes
               : 0);

    st.mem.load_mz(st.image_seg, st.psp_seg, fileData,
                   header_size_bytes, img_bytes, relocs);

    // CPU power-on DOS load state
    CS = static_cast<uint16_t>(st.image_seg + header.cs);
    IP = header.ip;
    SS = static_cast<uint16_t>(st.image_seg + header.ss);
    SP = header.sp;
    DS = st.psp_seg;
    ES = st.psp_seg;
    AX = BX = CX = DX = 0;
    SI = DI = BP = 0;
    FLAGS = 0x0202; // IF set-ish + reserved bit1

    if (!opts.simQuiet) {
        std::cout << "Load Image Segment: " << hex_format(st.image_seg, 4) << "\n";
        std::cout << "PSP Segment:        " << hex_format(st.psp_seg, 4) << "\n";
        std::cout << "Host file dir:      " << st.host_dir.string() << "\n";
        std::cout << "Max instructions:   " << opts.maxInsns << "\n";
        std::cout << "Loop limit:         " << opts.loopLimit
                  << (opts.loopLimit == 0 ? " (disabled)" : " back-edges then skip")
                  << "\n";
        if (!opts.breakpoints.empty()) {
            std::cout << "Breakpoints (" << opts.breakpoints.size() << "):\n";
            for (const auto& bp : opts.breakpoints)
                std::cout << "  - " << bp.raw << "\n";
        }
        std::cout << "\nInitial Register State:\n";
        sim_print_regs();
        std::cout << "\n=== Execution ===\n";
        if (!opts.simTrace && opts.breakpoints.empty())
            std::cout << "(use --trace to print each insn, --bp=... to stop on events)\n\n";
        else if (!opts.simTrace)
            std::cout << "(running until breakpoint or max-insns; --trace for full log)\n\n";
        else
            std::cout << "\n";
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_16, &st.cs_handle) != CS_ERR_OK) {
        std::cerr << "Error: Capstone init failed\n";
        return;
    }
    cs_option(st.cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    st.insn = cs_malloc(st.cs_handle);
    if (!st.insn) {
        cs_close(&st.cs_handle);
        std::cerr << "Error: Capstone malloc failed\n";
        return;
    }

    while (!st.halted && st.insn_count < opts.maxInsns) {
        // IP breakpoints before fetch
        if (sim_fire_bps_ip(st, opts)) {
            st.halted = true;
            st.halt_reason = "breakpoint (IP)";
            break;
        }

        uint32_t lin = SimMemory::linear(CS, IP);
        const uint8_t* code = st.mem.ram.data() + lin;
        // Available bytes until end of 1MB or wrap — use 16 max for one insn
        size_t avail = 16;
        if (lin + avail > SimMemory::kSize) avail = SimMemory::kSize - lin;

        const uint8_t* ptr = code;
        size_t size = avail;
        uint64_t addr = static_cast<uint64_t>(CS) * 16u + IP;

        if (!cs_disasm_iter(st.cs_handle, &ptr, &size, &addr, st.insn)) {
            st.halted = true;
            st.halt_reason = std::format("disasm failed at {:04X}:{:04X}", CS, IP);
            std::cout << "  [" << st.halt_reason << "]\n";
            break;
        }

        if (opts.simTrace) {
            std::cout << std::format("{:04X}:{:04X}  {:8} {}\n",
                                     CS, IP, st.insn->mnemonic, st.insn->op_str);
        } else if (!opts.simQuiet && opts.breakpoints.empty() && st.insn_count < 40) {
            // Short startup listing when no BPs (legacy-friendly)
            std::cout << std::format("{:04x}: {} {}",
                                     IP, st.insn->mnemonic, st.insn->op_str);
            if (std::string(st.insn->mnemonic) == "int" && st.insn->size >= 2)
                std::cout << "  " << format_int_annotation(st.insn->bytes[1], AH, AL);
            std::cout << "\n";
        }

        if (!st.insn->detail) {
            st.halted = true;
            st.halt_reason = "no Capstone detail";
            break;
        }

        if (!sim_exec_insn(st, opts)) {
            st.halted = true;
            st.unsupported_stop = true;
            st.halt_reason = std::format("unsupported opcode at {:04X}:{:04X}: {} {}",
                                         CS, IP, st.insn->mnemonic, st.insn->op_str);
            std::cout << "  STOP: " << st.halt_reason << "\n";
            sim_print_regs();
            break;
        }

        st.insn_count++;
    }

    if (!st.halted && st.insn_count >= opts.maxInsns) {
        st.halt_reason = "max-insns reached";
        st.halted = true;
    }

    // Close host files
    for (auto& kv : st.fcb_files)
        if (kv.second.fp) std::fclose(kv.second.fp);
    for (auto& kv : st.handle_files)
        if (kv.second.fp) std::fclose(kv.second.fp);

    std::cout << "\n=== Simulation stopped ===\n";
    std::cout << "Reason: " << st.halt_reason << "\n";
    std::cout << "Instructions executed: " << st.insn_count << "\n";
    std::cout << "INT 21h calls: " << st.int21_count << "\n";
    std::cout << "Loop back-edges skipped: " << st.loops_skipped << "\n";
    if (!opts.breakpoints.empty()) {
        std::cout << "Breakpoint hits:\n";
        for (const auto& bp : opts.breakpoints)
            std::cout << std::format("  {} → {} hit(s)\n", bp.raw, bp.hits);
    }
    std::cout << "Final registers:\n";
    sim_print_regs();

    cs_free(st.insn, 1);
    cs_close(&st.cs_handle);
}

#endif // SIM_H
