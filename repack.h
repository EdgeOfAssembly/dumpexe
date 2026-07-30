/**
 * @file repack.h
 * @brief Rebuild a runnable MZ/COM image from dumpexe export .asm (db lines).
 *
 * Default product policy: after TP/JWASM export, also write <stem>.repack.exe
 * (disable with --no-repack). Offline: parse REPACK-V1 header embedded in .asm.
 */
#ifndef REPACK_H
#define REPACK_H

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <format>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "options.h"

//=============================================================================
// Parse db lines → image bytes
//=============================================================================

static inline int repack_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/// Parse one token like 0ABh, 055h, 0FFh into a byte. Returns false on failure.
static inline bool repack_parse_byte_token(std::string_view tok, uint8_t& out)
{
    while (!tok.empty() && std::isspace(static_cast<unsigned char>(tok.front())))
        tok.remove_prefix(1);
    while (!tok.empty() && std::isspace(static_cast<unsigned char>(tok.back())))
        tok.remove_suffix(1);
    if (tok.empty())
        return false;
    if (tok.back() == 'h' || tok.back() == 'H')
        tok.remove_suffix(1);
    if (tok.empty())
        return false;
    // strip leading zeros for parsing but keep hex
    unsigned v = 0;
    for (char c : tok)
    {
        int n = repack_hex_nibble(c);
        if (n < 0)
            return false;
        v = (v << 4) | static_cast<unsigned>(n);
        if (v > 0xFF)
            return false;
    }
    out = static_cast<uint8_t>(v);
    return true;
}

/**
 * @brief Extract all db-encoded bytes from a dumpexe export listing.
 */
static inline bool repack_parse_image_from_asm(std::string_view text,
                                              std::vector<uint8_t>& image,
                                              std::string& err)
{
    image.clear();
    std::string line;
    std::istringstream in{std::string(text)};
    while (std::getline(in, line))
    {
        // trim
        size_t a = 0;
        while (a < line.size() && std::isspace(static_cast<unsigned char>(line[a])))
            ++a;
        if (a >= line.size())
            continue;
        if (line[a] == ';')
            continue;
        // optional leading whitespace already skipped — expect db / DB
        if (line.size() - a < 2)
            continue;
        if (!(line[a] == 'd' || line[a] == 'D') ||
            !(line[a + 1] == 'b' || line[a + 1] == 'B'))
            continue;
        size_t p = a + 2;
        while (p < line.size() && std::isspace(static_cast<unsigned char>(line[p])))
            ++p;
        // cut comment
        size_t semi = line.find(';', p);
        std::string payload =
            (semi == std::string::npos) ? line.substr(p) : line.substr(p, semi - p);
        // split commas
        size_t i = 0;
        while (i < payload.size())
        {
            while (i < payload.size() &&
                   (std::isspace(static_cast<unsigned char>(payload[i])) ||
                    payload[i] == ','))
                ++i;
            if (i >= payload.size())
                break;
            size_t j = i;
            while (j < payload.size() && payload[j] != ',' &&
                   !std::isspace(static_cast<unsigned char>(payload[j])))
                ++j;
            // also allow spaces inside? tokens are 0XXh
            std::string_view tok(payload.data() + i, j - i);
            uint8_t b = 0;
            if (!repack_parse_byte_token(tok, b))
            {
                err = std::format("bad db token near: {}", std::string(tok));
                return false;
            }
            image.push_back(b);
            i = j;
        }
    }
    if (image.empty())
    {
        err = "no db image bytes found in asm";
        return false;
    }
    return true;
}

//=============================================================================
// Embed / extract MZ prefix+suffix for offline repack
//=============================================================================

static inline std::string repack_bytes_to_hex(const uint8_t* p, size_t n)
{
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i)
        s += std::format("{:02x}", p[i]);
    return s;
}

static inline bool repack_hex_to_bytes(std::string_view hex, std::vector<uint8_t>& out)
{
    out.clear();
    if (hex.size() % 2)
        return false;
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        int hi = repack_hex_nibble(hex[i]);
        int lo = repack_hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

/**
 * @brief Build REPACK-V1 comment block so .asm alone can rebuild the EXE later.
 */
static inline std::string repack_embed_meta(const std::vector<uint8_t>& fileData,
                                           size_t image_file_off,
                                           size_t image_len)
{
    if (image_file_off > fileData.size())
        image_file_off = fileData.size();
    size_t img_end = image_file_off + image_len;
    if (img_end > fileData.size())
        img_end = fileData.size();

    const size_t prefix_len = image_file_off;
    const size_t suffix_len = fileData.size() - img_end;

    std::ostringstream o;
    o << "; REPACK-V1 (dumpexe auto — rebuild EXE from this listing)\n";
    o << std::format("; REPACK-PREFIX-LEN {}\n", prefix_len);
    o << std::format("; REPACK-IMAGE-LEN {}\n", image_len);
    o << std::format("; REPACK-SUFFIX-LEN {}\n", suffix_len);
    o << std::format("; REPACK-ORIG-FILE-SIZE {}\n", fileData.size());
    // Chunk hex lines (64 bytes per line) for prefix
    o << "; REPACK-PREFIX-HEX-BEGIN\n";
    for (size_t i = 0; i < prefix_len; i += 64)
    {
        size_t n = std::min(size_t{64}, prefix_len - i);
        o << "; " << repack_bytes_to_hex(fileData.data() + i, n) << "\n";
    }
    o << "; REPACK-PREFIX-HEX-END\n";
    if (suffix_len)
    {
        o << "; REPACK-SUFFIX-HEX-BEGIN\n";
        for (size_t i = 0; i < suffix_len; i += 64)
        {
            size_t n = std::min(size_t{64}, suffix_len - i);
            o << "; " << repack_bytes_to_hex(fileData.data() + img_end + i, n)
              << "\n";
        }
        o << "; REPACK-SUFFIX-HEX-END\n";
    }
    o << ";\n";
    return o.str();
}

static inline bool repack_extract_meta(std::string_view text,
                                       std::vector<uint8_t>& prefix,
                                       std::vector<uint8_t>& suffix,
                                       size_t& expect_image_len,
                                       std::string& err)
{
    prefix.clear();
    suffix.clear();
    expect_image_len = 0;
    bool in_prefix = false, in_suffix = false;
    std::string pref_hex, suf_hex;
    std::istringstream in{std::string(text)};
    std::string line;
    while (std::getline(in, line))
    {
        if (line.rfind("; REPACK-IMAGE-LEN ", 0) == 0)
        {
            expect_image_len = std::stoul(line.substr(18));
            continue;
        }
        if (line.find("REPACK-PREFIX-HEX-BEGIN") != std::string::npos)
        {
            in_prefix = true;
            continue;
        }
        if (line.find("REPACK-PREFIX-HEX-END") != std::string::npos)
        {
            in_prefix = false;
            continue;
        }
        if (line.find("REPACK-SUFFIX-HEX-BEGIN") != std::string::npos)
        {
            in_suffix = true;
            continue;
        }
        if (line.find("REPACK-SUFFIX-HEX-END") != std::string::npos)
        {
            in_suffix = false;
            continue;
        }
        if (in_prefix && line.size() > 2 && line[0] == ';' && line[1] == ' ')
            pref_hex += line.substr(2);
        if (in_suffix && line.size() > 2 && line[0] == ';' && line[1] == ' ')
            suf_hex += line.substr(2);
    }
    // strip whitespace from hex
    auto strip = [](std::string& s)
    {
        std::string t;
        for (char c : s)
            if (std::isxdigit(static_cast<unsigned char>(c)))
                t.push_back(c);
        s.swap(t);
    };
    strip(pref_hex);
    strip(suf_hex);
    if (pref_hex.empty())
    {
        err = "missing REPACK-PREFIX-HEX in asm";
        return false;
    }
    if (!repack_hex_to_bytes(pref_hex, prefix))
    {
        err = "bad REPACK-PREFIX-HEX";
        return false;
    }
    if (!suf_hex.empty() && !repack_hex_to_bytes(suf_hex, suffix))
    {
        err = "bad REPACK-SUFFIX-HEX";
        return false;
    }
    return true;
}

//=============================================================================
// Write EXE
//=============================================================================

static inline std::string repack_default_path(const std::string& input_path)
{
    if (input_path.empty())
        return "out.repack.exe";
    std::string p = input_path;
    while (p.size() > 1 && (p.back() == '/' || p.back() == '\\'))
        p.pop_back();
    size_t slash = p.find_last_of("/\\");
    std::string dir = (slash == std::string::npos) ? std::string() : p.substr(0, slash + 1);
    std::string base = (slash == std::string::npos) ? p : p.substr(slash + 1);
    size_t dot = base.find_last_of('.');
    if (dot != std::string::npos && dot > 0)
        base = base.substr(0, dot);
    return dir + base + ".repack.exe";
}

/**
 * @brief Build EXE bytes = prefix + image + suffix.
 */
static inline std::vector<uint8_t> repack_build_exe(const std::vector<uint8_t>& prefix,
                                                    const std::vector<uint8_t>& image,
                                                    const std::vector<uint8_t>& suffix)
{
    std::vector<uint8_t> out;
    out.reserve(prefix.size() + image.size() + suffix.size());
    out.insert(out.end(), prefix.begin(), prefix.end());
    out.insert(out.end(), image.begin(), image.end());
    out.insert(out.end(), suffix.begin(), suffix.end());
    return out;
}

static inline bool repack_write_file(const std::string& path,
                                     const std::vector<uint8_t>& data,
                                     std::string& err)
{
    std::ofstream f(path, std::ios::binary);
    if (!f)
    {
        err = "cannot write " + path;
        return false;
    }
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    if (!f)
    {
        err = "write failed " + path;
        return false;
    }
    return true;
}

/**
 * @brief Full offline repack: parse asm text → write exe path.
 */
static inline bool repack_from_asm_text(std::string_view text,
                                        const std::string& out_path,
                                        std::string& err,
                                        size_t* out_image_len = nullptr)
{
    std::vector<uint8_t> prefix, suffix, image;
    size_t expect_img = 0;
    if (!repack_extract_meta(text, prefix, suffix, expect_img, err))
        return false;
    if (!repack_parse_image_from_asm(text, image, err))
        return false;
    if (expect_img && image.size() != expect_img)
    {
        err = std::format("image length {} != expected {}", image.size(), expect_img);
        return false;
    }
    if (out_image_len)
        *out_image_len = image.size();
    auto exe = repack_build_exe(prefix, image, suffix);
    return repack_write_file(out_path, exe, err);
}

/**
 * @brief Same-run auto repack using original file + reconstructed image from asm.
 */
static inline bool repack_auto(const Options& opts,
                               const std::string& input_path,
                               const std::vector<uint8_t>& fileData,
                               size_t image_file_off,
                               size_t image_len,
                               std::string_view asm_text,
                               std::string& out_path_written)
{
    if (!opts.writeRepack)
        return true;

    std::string err;
    std::vector<uint8_t> image;
    if (!repack_parse_image_from_asm(asm_text, image, err))
    {
        std::cerr << "repack: " << err << "\n";
        return false;
    }

    // Prefer in-memory prefix/suffix from original file (authoritative)
    if (image_file_off > fileData.size())
        image_file_off = fileData.size();
    size_t img_end = image_file_off + image_len;
    if (img_end > fileData.size())
        img_end = fileData.size();

    std::vector<uint8_t> prefix(fileData.begin(),
                                fileData.begin() + static_cast<std::ptrdiff_t>(image_file_off));
    std::vector<uint8_t> suffix(fileData.begin() + static_cast<std::ptrdiff_t>(img_end),
                                fileData.end());

    if (image.size() != (img_end - image_file_off) && image_len != 0)
    {
        std::cerr << std::format(
            "repack: warning: parsed image {} bytes, original window {} bytes\n",
            image.size(), img_end - image_file_off);
    }

    auto exe = repack_build_exe(prefix, image, suffix);
    std::string path = opts.repackOutputPath.empty()
                           ? repack_default_path(input_path)
                           : opts.repackOutputPath;

    if (!repack_write_file(path, exe, err))
    {
        std::cerr << "repack: " << err << "\n";
        return false;
    }
    out_path_written = path;

    const bool identical =
        exe.size() == fileData.size() &&
        std::equal(exe.begin(), exe.end(), fileData.begin());
    std::cerr << std::format(
        "repack: wrote {} ({} bytes){}\n", path, exe.size(),
        identical ? " [IDENTICAL to input]" : " [differs from input — check export]");
    return true;
}

#endif // REPACK_H
