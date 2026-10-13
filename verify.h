/**
 * @file verify.h
 * @brief P2 verifier: assemble the whole listing, compare, demote, repeat.
 *
 * One UASM run per round (`uasm -bin -nologo -e100000 -Fl -Fo`) in a private
 * scratch directory. The listing gives each tagged line's offset, so a unit
 * whose size differs, whose bytes differ, or that the assembler rejects is
 * demoted one rung (mnemonic → pin → symbolic db → raw db). All size
 * mismatches of a round are demoted together: sized branches make every
 * line's length independent of label values, so one wrong size does not
 * change another line's size. Range errors (A2053) are demoted tentatively
 * and re-promoted once at the end. After identity the start and mid shift
 * tests insert a `nop`, reassemble and check that every reference field the
 * model knows moved with its target. The relocation-set compare reports
 * which relocated words were printed as segment expressions.
 */
#ifndef DX_VERIFY_H
#define DX_VERIFY_H

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <set>
#include <spawn.h>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "emit_uasm.h"

extern "C" char** environ;

namespace dx
{

/** @brief Output of one assembler run. */
struct AsmRun
{
    bool spawned = false;
    int exit_code = -1;
    std::vector<uint8_t> bin;
    bool have_bin = false;
    std::map<uint32_t, uint32_t> off_of;          ///< tagged linear → listing offset
    std::vector<std::pair<int, std::string>> errors; ///< source line, Axxxx
};

/** @brief Result of a shift test. */
struct ShiftResult
{
    bool ran = false;
    std::string why_not;
    size_t checked = 0;
    size_t broken = 0;
    size_t structural = 0;
    std::string first;
};

/** @brief Result of the verify loop. */
struct VerifyResult
{
    bool identical = false;
    bool assembler_found = false;
    int rounds = 0;
    std::string error;
    size_t n_mnemonic = 0, n_pin = 0, n_symdb = 0, n_rawdb = 0;
    size_t bytes_mnemonic = 0, bytes_pin = 0, bytes_symdb = 0, bytes_rawdb = 0;
    size_t relocs_total = 0, relocs_symbolic = 0, relocs_in_data = 0;
    std::map<std::string, size_t> reasons;
    ShiftResult shift_start;
    ShiftResult shift_mid;
    ShiftResult shift_data;   ///< db 0 inside DGROUP, after its base
    ShiftResult shift_para;   ///< 16 bytes before a relocation-derived base
    int64_t dgroup = -1;      ///< inferred DGROUP base linear, or -1
    size_t far_xfers = 0;     ///< relocated far call/jmp with an in-image target
    size_t far_reached = 0;   ///< ... whose target starts a decoded instruction
};

/**
 * @brief Run @p asm_bin on @p asm_text inside @p dir. Never next to the input.
 *
 * The child gets /dev/null as stdin, its stdout and stderr go to out.msg,
 * and $UASM / $INCLUDE are removed from its environment.
 */
inline AsmRun run_uasm(const std::string& asm_bin, const std::string& dir,
                       const std::string& asm_text)
{
    AsmRun r;
    const std::string asm_path = dir + "/out.asm";
    const std::string bin_path = dir + "/out.bin";
    const std::string lst_path = dir + "/out.lst";
    const std::string msg_path = dir + "/out.msg";
    ::unlink(bin_path.c_str());
    ::unlink(lst_path.c_str());
    ::unlink(msg_path.c_str());
    {
        std::ofstream f(asm_path, std::ios::binary | std::ios::trunc);
        f << asm_text;
        if (!f)
            return r;
    }
    std::string a0 = "uasm", a1 = "-bin", a2 = "-nologo", a3 = "-e100000", a4 = "-Fl" + lst_path,
                a5 = "-Fo", a6 = bin_path, a7 = asm_path;
    char* argv[] = {a0.data(), a1.data(), a2.data(), a3.data(), a4.data(),
                    a5.data(), a6.data(), a7.data(), nullptr};
    posix_spawn_file_actions_t act;
    if (::posix_spawn_file_actions_init(&act) != 0)
        return r;
    ::posix_spawn_file_actions_addopen(&act, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    ::posix_spawn_file_actions_addopen(&act, STDOUT_FILENO, msg_path.c_str(),
                                       O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ::posix_spawn_file_actions_adddup2(&act, STDOUT_FILENO, STDERR_FILENO);
    ::posix_spawn_file_actions_addchdir_np(&act, dir.c_str());
    std::vector<std::string> env;
    for (char** it = ::environ; it && *it; ++it)
    {
        const std::string_view row(*it);
        if (row.starts_with("UASM=") || row.starts_with("INCLUDE="))
            continue;
        env.emplace_back(*it);
    }
    std::vector<char*> envp;
    for (auto& e : env)
        envp.push_back(e.data());
    envp.push_back(nullptr);
    pid_t pid = 0;
    const int sp = ::posix_spawn(&pid, asm_bin.c_str(), &act, nullptr, argv, envp.data());
    ::posix_spawn_file_actions_destroy(&act);
    if (sp != 0)
        return r;
    r.spawned = true;
    int st = 0;
    while (::waitpid(pid, &st, 0) < 0)
    {
        if (errno != EINTR)
            return r;
    }
    r.exit_code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;

    // Errors: "out.asm(N) : Error A2053: ..."
    {
        std::ifstream m(msg_path);
        std::string ln;
        while (std::getline(m, ln))
        {
            // UASM colours its messages; drop ESC [ ... m sequences.
            std::string clean;
            for (size_t k = 0; k < ln.size(); ++k)
            {
                if (ln[k] == '\x1b' && k + 1 < ln.size() && ln[k + 1] == '[')
                {
                    k += 2;
                    while (k < ln.size() && ln[k] != 'm')
                        ++k;
                    continue;
                }
                clean.push_back(ln[k]);
            }
            ln.swap(clean);
            const size_t p = ln.find("out.asm(");
            const size_t e = ln.find(": Error A");
            if (p == std::string::npos || e == std::string::npos)
                continue;
            const int line = std::atoi(ln.c_str() + p + 8);
            r.errors.emplace_back(line, ln.substr(e + 8, 5));
        }
    }
    // Listing: an 8-hex-digit offset at column 0; a tag "; XXXXX: " names the linear.
    {
        std::ifstream l(lst_path);
        std::string ln;
        std::vector<uint32_t> pending;
        auto hexv = [](std::string_view s, uint32_t& v) -> bool
        {
            if (s.empty())
                return false;
            v = 0;
            for (char c : s)
            {
                int d;
                if (c >= '0' && c <= '9')
                    d = c - '0';
                else if (c >= 'A' && c <= 'F')
                    d = c - 'A' + 10;
                else
                    return false;
                v = v * 16 + static_cast<uint32_t>(d);
            }
            return true;
        };
        while (std::getline(l, ln))
        {
            uint32_t off = 0;
            const bool has_off = ln.size() >= 9 && hexv(std::string_view(ln).substr(0, 8), off) &&
                                 (ln[8] == ' ');
            // Offset lines that emit bytes have hex right after two spaces.
            const bool emits = has_off && ln.size() > 10 && ln[9] == ' ' &&
                               std::isxdigit(static_cast<unsigned char>(ln[10]));
            uint32_t tag = 0;
            bool tagged = false;
            for (size_t p = ln.find("; "); p != std::string::npos; p = ln.find("; ", p + 1))
            {
                size_t q = p + 2;
                size_t k = q;
                while (k < ln.size() && std::isxdigit(static_cast<unsigned char>(ln[k])) &&
                       !std::islower(static_cast<unsigned char>(ln[k])))
                    ++k;
                if (k - q >= 5 && k < ln.size() && ln[k] == ':' && hexv(std::string_view(ln).substr(q, k - q), tag))
                {
                    tagged = true;
                    break;
                }
            }
            if (tagged && has_off && emits)
            {
                r.off_of[tag] = off;
                continue;
            }
            if (tagged)
            {
                pending.push_back(tag); // macro invocation: offset on the expansion
                continue;
            }
            if (emits && !pending.empty())
            {
                for (uint32_t t : pending)
                    r.off_of[t] = off;
                pending.clear();
            }
        }
    }
    if (r.exit_code == 0)
    {
        std::ifstream b(bin_path, std::ios::binary);
        if (b)
        {
            r.bin.assign(std::istreambuf_iterator<char>(b), std::istreambuf_iterator<char>());
            r.have_bin = true;
        }
    }
    return r;
}

/** @brief Demote one rung. Returns false when already raw db. */
inline bool demote_unit(UasmEmitter& em, EmitUnit& u, const std::string& why, bool asm_error)
{
    u.reason = why;
    switch (u.rung)
    {
    case Rung::Mnemonic:
        if (!asm_error && !em.pin_text(u).empty())
            u.rung = Rung::Pin;
        else
            u.rung = Rung::SymDb;
        return true;
    case Rung::Pin:
        u.rung = Rung::SymDb;
        return true;
    case Rung::SymDb:
        u.rung = Rung::RawDb;
        return true;
    case Rung::RawDb:
        return false;
    }
    return false;
}

/**
 * @brief Shift test: insert @p text before unit @p at, reassemble, check refs.
 */
inline ShiftResult shift_test(UasmEmitter& em, const std::string& asm_bin, const std::string& dir,
                              int64_t at, const char* text)
{
    ShiftResult s;
    if (at < 0)
    {
        s.why_not = "no insertion point";
        return s;
    }
    const std::string src = em.render({}, at, text);
    AsmRun r = run_uasm(asm_bin, dir, src);
    if (!r.have_bin)
    {
        s.why_not = "shifted listing did not assemble";
        s.ran = true;
        s.broken = 1;
        s.first = r.errors.empty() ? "assembler failed" : ("assembler " + r.errors[0].second);
        return s;
    }
    s.ran = true;
    const uint32_t org = em.org();
    std::vector<std::pair<uint32_t, uint32_t>> map(r.off_of.begin(), r.off_of.end());
    auto newlin = [&](uint32_t lin) -> int64_t
    {
        auto it = std::upper_bound(map.begin(), map.end(), std::make_pair(lin, UINT32_MAX));
        if (it == map.begin())
            return lin;
        --it;
        return static_cast<int64_t>(it->second) + (lin - it->first);
    };
    const std::vector<uint8_t>& img = *em.input().image;
    const uint32_t n = static_cast<uint32_t>(img.size());
    auto rd = [&](int64_t lin, uint8_t sz) -> int64_t
    {
        const int64_t p = lin - org;
        if (p < 0 || p + sz > static_cast<int64_t>(r.bin.size()))
            return -1;
        return sz == 1 ? r.bin[p] : (r.bin[p] | (r.bin[p + 1] << 8));
    };
    for (const EmitUnit& u : em.units())
    {
        if (!u.code || r.off_of.count(u.lin) == 0)
            continue;
        const int64_t nl = r.off_of[u.lin];
        // Structure: bytes outside reference fields are unchanged.
        std::vector<bool> field(u.size, false);
        for (const InsnRef& ref : u.refs)
            for (uint8_t k = 0; k < ref.size; ++k)
                field[ref.off + k] = true;
        bool same = true;
        for (uint32_t k = 0; k < u.size; ++k)
        {
            if (field[k])
                continue;
            if (rd(nl + k, 1) != img[u.lin + k])
            {
                same = false;
                break;
            }
        }
        if (!same)
        {
            ++s.structural;
            ++s.broken;
            if (s.first.empty())
                s.first = std::format("{:05X} instruction stream changed", u.lin);
            continue;
        }
        for (const InsnRef& ref : u.refs)
        {
            const int64_t got = rd(nl + ref.off, ref.size);
            bool ok = true;
            if (ref.kind == RefKind::Rel)
            {
                const int64_t want = newlin(ref.target) - (nl + u.size);
                ++s.checked;
                if (ref.size == 1)
                    ok = want >= -128 && want <= 127 && (want & 0xFF) == got;
                else
                    ok = (want & 0xFFFF) == got;
            }
            else
            {
                const int64_t base = newlin(em.emit_lo());
                if (ref.kind == RefKind::Seg && ref.frame >= n)
                {
                    // Past the image: paragraphs after the rounded-up image end.
                    ++s.checked;
                    const int64_t k = ref.frame / 16 - (n + 15) / 16;
                    ok = ((((newlin(n) - base + 15) >> 4) + k) & 0xFFFF) == got;
                }
                else
                {
                    if (ref.frame < em.emit_lo() || ref.frame >= n)
                        continue; // literal by design (far target outside the image)
                    ++s.checked;
                    const int64_t nf = newlin(ref.frame) - base;
                    if (ref.kind == RefKind::Seg)
                        ok = (nf % 16) == 0 && ((nf / 16) & 0xFFFF) == got;
                    else
                        ok = ((newlin(ref.target) - newlin(ref.frame)) & 0xFFFF) == got;
                }
            }
            if (!ok)
            {
                ++s.broken;
                if (s.first.empty())
                    s.first = std::format("{:05X} {} not adjusted", u.lin,
                                          ref.kind == RefKind::Rel ? "branch"
                                          : ref.kind == RefKind::Seg ? "segment word"
                                                                     : "far offset");
            }
        }
    }
    // Relocated words printed in data as segment expressions.
    for (uint32_t at : em.symbolic_relocs())
    {
        const int ui = em.unit_covering(at);
        if (ui < 0 || em.units()[static_cast<size_t>(ui)].code || r.off_of.count(at) == 0)
            continue;
        const uint32_t fr = (img[at] | (img[at + 1] << 8)) * 16u;
        const int64_t got = rd(r.off_of[at], 2);
        const int64_t base = newlin(em.emit_lo());
        bool ok;
        if (fr >= n)
        {
            const int64_t k = fr / 16 - (n + 15) / 16;
            ok = ((((newlin(n) - base + 15) >> 4) + k) & 0xFFFF) == got;
        }
        else
        {
            const int64_t nf = newlin(fr) - base;
            ok = (nf % 16) == 0 && ((nf / 16) & 0xFFFF) == got;
        }
        ++s.checked;
        if (!ok)
        {
            ++s.broken;
            if (s.first.empty())
                s.first = std::format("{:05X} data segment word not adjusted", at);
        }
    }
    return s;
}

/**
 * @brief Verify loop over @p em. Leaves the rungs that reproduce the image.
 *
 * @param asm_bin Resolved assembler path. Empty means not found.
 * @param dir     Scratch directory (private, removed by the caller).
 * @param max_rounds Demotion rounds before the all-symbolic floor.
 */
inline VerifyResult verify_listing(UasmEmitter& em, const std::string& asm_bin,
                                   const std::string& dir, int max_rounds = 12)
{
    VerifyResult v;
    v.assembler_found = !asm_bin.empty();
    const std::vector<uint8_t>& img = *em.input().image;
    const uint32_t lo = em.emit_lo();
    const uint32_t n = static_cast<uint32_t>(img.size());
    const uint32_t org = em.org();
    auto& U = em.units();
    std::set<size_t> tentative;
    bool repromoted = false;

    auto tally = [&]()
    {
        v.n_mnemonic = v.n_pin = v.n_symdb = v.n_rawdb = 0;
        v.bytes_mnemonic = v.bytes_pin = v.bytes_symdb = v.bytes_rawdb = 0;
        v.reasons.clear();
        for (const EmitUnit& u : U)
        {
            if (!u.code)
                continue;
            switch (u.rung)
            {
            case Rung::Mnemonic: ++v.n_mnemonic; v.bytes_mnemonic += u.size; break;
            case Rung::Pin: ++v.n_pin; v.bytes_pin += u.size; break;
            case Rung::SymDb: ++v.n_symdb; v.bytes_symdb += u.size; break;
            case Rung::RawDb: ++v.n_rawdb; v.bytes_rawdb += u.size; break;
            }
            if (u.rung != Rung::Mnemonic && !u.reason.empty())
                ++v.reasons[u.reason];
        }
        // Relocation-set compare (§10.5).
        const std::set<uint32_t>& sym = em.symbolic_relocs();
        v.relocs_total = 0;
        v.relocs_symbolic = 0;
        v.relocs_in_data = 0;
        for (uint32_t at : em.input().reloc_at)
        {
            if (at < lo || at >= n)
                continue;
            ++v.relocs_total;
            if (sym.count(at))
                ++v.relocs_symbolic;
            else
            {
                const int ui = em.unit_covering(at);
                if (ui < 0 || !U[static_cast<size_t>(ui)].code)
                    ++v.relocs_in_data;
            }
        }
    };

    if (asm_bin.empty())
    {
        // Without an assembler nothing is claimed: every code unit is symbolic db.
        for (EmitUnit& u : U)
            if (u.code && u.rung < Rung::SymDb)
            {
                u.rung = Rung::SymDb;
                u.reason = "uasm not found";
            }
        (void)em.render({});
        tally();
        v.error = "uasm not found";
        return v;
    }

    int floor_stage = 0; // 0 normal, 1 all symdb, 2 all raw
    for (int round = 1;; ++round)
    {
        v.rounds = round;
        const std::string src = em.render({});
        AsmRun r = run_uasm(asm_bin, dir, src);
        if (!r.spawned)
        {
            v.error = "assembler did not start";
            break;
        }
        std::map<size_t, std::pair<std::string, bool>> dem; // unit → reason, asm error
        bool unmapped_error = false;
        bool range_only = true;
        for (const auto& [line, code] : r.errors)
        {
            auto it = em.line_unit().find(line);
            if (it == em.line_unit().end())
            {
                unmapped_error = true;
                continue;
            }
            if (code != "A2053")
                range_only = false;
            dem[it->second] = {"assembler rejected (" + code + ")", true};
        }
        if (!r.errors.empty() && !range_only)
        {
            // Keep only the hard errors this round.
            for (auto it = dem.begin(); it != dem.end();)
                it = (it->second.first.find("A2053") != std::string::npos) ? dem.erase(it) : std::next(it);
        }
        if (unmapped_error && dem.empty())
        {
            if (floor_stage >= 2)
            {
                v.error = "listing does not assemble (error outside any instruction)";
                break;
            }
            ++floor_stage;
            for (EmitUnit& u : U)
                if (u.code)
                {
                    u.rung = floor_stage == 1 ? std::max(u.rung, Rung::SymDb) : Rung::RawDb;
                    u.reason = "fallback floor";
                }
            continue;
        }
        if (dem.empty())
        {
            // Sizes from listing offsets.
            std::vector<std::pair<uint32_t, uint32_t>> tagged(r.off_of.begin(), r.off_of.end());
            for (size_t j = 0; j < tagged.size(); ++j)
            {
                const uint32_t lin = tagged[j].first;
                const int ui = em.unit_at(lin);
                if (ui < 0 || !U[static_cast<size_t>(ui)].code)
                    continue;
                const uint32_t nxt_lin = (j + 1 < tagged.size()) ? tagged[j + 1].first : n;
                const int64_t nxt_off = (j + 1 < tagged.size())
                                            ? static_cast<int64_t>(tagged[j + 1].second)
                                            : (r.have_bin ? static_cast<int64_t>(r.bin.size() + org - em.tail_len())
                                                          : -1);
                if (nxt_off < 0)
                    continue;
                if (nxt_off - tagged[j].second != static_cast<int64_t>(nxt_lin - lin))
                {
                    // An align guard between the two absorbs an upstream change.
                    const EmitUnit& u = U[static_cast<size_t>(ui)];
                    if (nxt_lin != u.lin + u.size || em.align_before(nxt_lin))
                        continue;
                    dem[static_cast<size_t>(ui)] = {"size differs", false};
                }
            }
        }
        if (dem.empty() && r.have_bin)
        {
            const std::vector<uint8_t>& exp = em.expected();
            const size_t want = exp.size();
            if (r.bin == exp)
            {
                if (!tentative.empty() && !repromoted)
                {
                    repromoted = true;
                    for (size_t ui : tentative)
                        if (U[ui].reason.find("A2053") != std::string::npos)
                        {
                            U[ui].rung = Rung::Mnemonic;
                            U[ui].reason.clear();
                        }
                    continue;
                }
                v.identical = true;
                break;
            }
            for (size_t k = 0; k < std::min(r.bin.size(), want); ++k)
            {
                if (r.bin[k] == exp[k])
                    continue;
                const int64_t lin = static_cast<int64_t>(org + k) - em.bias();
                if (lin < lo || lin >= n)
                    continue; // header or tail: literal bytes, handled by the floor
                const int ui = em.unit_covering(static_cast<uint32_t>(lin));
                if (ui >= 0 && U[static_cast<size_t>(ui)].code)
                    dem[static_cast<size_t>(ui)] = {"bytes differ", false};
            }
            if (dem.empty())
            {
                if (floor_stage >= 2)
                {
                    v.error = "mismatch outside any instruction";
                    break;
                }
                ++floor_stage;
                for (EmitUnit& u : U)
                    if (u.code)
                    {
                        u.rung = floor_stage == 1 ? std::max(u.rung, Rung::SymDb) : Rung::RawDb;
                        u.reason = "fallback floor";
                    }
                continue;
            }
        }
        if (dem.empty())
        {
            v.error = "assembler failed without a listing";
            break;
        }
        bool moved = false;
        for (auto& [ui, why] : dem)
        {
            if (why.first.find("A2053") != std::string::npos)
                tentative.insert(ui);
            moved |= demote_unit(em, U[ui], why.first, why.second);
        }
        if (!moved || round >= max_rounds + 4)
        {
            if (floor_stage >= 2)
            {
                v.error = "no progress";
                break;
            }
            ++floor_stage;
            for (EmitUnit& u : U)
                if (u.code)
                {
                    u.rung = floor_stage == 1 ? std::max(u.rung, Rung::SymDb) : Rung::RawDb;
                    u.reason = "fallback floor";
                }
        }
    }
    (void)em.render({});
    tally();
    for (const EmitUnit& u : U)
    {
        if (!u.code)
            continue;
        for (const InsnRef& r : u.refs)
        {
            if (r.kind != RefKind::FarOff || r.target >= n)
                continue;
            ++v.far_xfers;
            const int t = em.unit_at(r.target);
            if (t >= 0 && U[static_cast<size_t>(t)].code)
                ++v.far_reached;
        }
    }
    if (v.identical)
    {
        // Start: after the entry instruction. Mid: before the median code unit.
        std::vector<size_t> code;
        for (size_t i = 0; i < U.size(); ++i)
            if (U[i].code)
                code.push_back(i);
        const int ent = em.unit_at(em.input().entry);
        if (ent >= 0 && U[static_cast<size_t>(ent)].code &&
            static_cast<size_t>(ent) + 1 < U.size())
            v.shift_start = shift_test(em, asm_bin, dir, U[static_cast<size_t>(ent) + 1].lin, "nop");
        else
            v.shift_start.why_not = "entry is not code";
        if (code.size() >= 4)
            v.shift_mid = shift_test(em, asm_bin, dir, U[code[code.size() / 2]].lin, "nop");
        else
            v.shift_mid.why_not = "fewer than 4 instructions";
        if (!em.input().com)
        {
            // DGROUP: the frame most often loaded by mov r16, seg X; mov ds, r16.
            std::map<uint32_t, size_t> votes;
            for (size_t j = 0; j + 1 < code.size(); ++j)
            {
                const EmitUnit& a = U[code[j]];
                const EmitUnit& b = U[code[j + 1]];
                if (a.lin + a.size != b.lin || a.size != 3 || b.size != 2)
                    continue;
                const uint8_t op = img[a.lin];
                if (op < 0xB8 || op > 0xBF || img[b.lin] != 0x8E ||
                    img[b.lin + 1] != static_cast<uint8_t>(0xD8 + (op - 0xB8)))
                    continue;
                for (const InsnRef& r : a.refs)
                    if (r.kind == RefKind::Seg && r.frame < n)
                        ++votes[r.frame];
            }
            uint32_t best = 0;
            size_t bestv = 0;
            for (const auto& [fr, c] : votes)
                if (c > bestv)
                {
                    best = fr;
                    bestv = c;
                }
            if (bestv != 0 && best != em.input().entry_frame && best > lo)
            {
                v.dgroup = best;
                // Insert after the base: the base label stays, every later
                // variable moves by one byte relative to it.
                int64_t at = -1;
                const int ui = em.unit_covering(best);
                if (ui >= 0 && !U[static_cast<size_t>(ui)].code &&
                    best + 2 < U[static_cast<size_t>(ui)].lin + U[static_cast<size_t>(ui)].size)
                    at = best + 2;
                else if (ui >= 0 && static_cast<size_t>(ui) + 1 < U.size())
                    at = U[static_cast<size_t>(ui) + 1].lin;
                v.shift_data = shift_test(em, asm_bin, dir, at, "db 0");
            }
            else
            {
                v.shift_data.why_not = "no separate DGROUP";
            }
            // Paragraph shift: 16 bytes before the median relocation-derived base.
            std::vector<uint32_t> bases;
            for (uint32_t b : em.all_bases())
                if (b > lo && b < n && em.align_before(b))
                    bases.push_back(b);
            if (!bases.empty())
                v.shift_para = shift_test(em, asm_bin, dir, bases[bases.size() / 2], "db 16 dup(0)");
            else
                v.shift_para.why_not = "no relocation-derived base";
        }
        (void)em.render({});
    }
    return v;
}

} // namespace dx

#endif // DX_VERIFY_H
