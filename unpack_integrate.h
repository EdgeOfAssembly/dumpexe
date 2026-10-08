// unpack_integrate.h — write <stem>_UNPACKED and list it after the packed listing.
// Include from dumpexe.cpp after mz_entry_image_ip and mz_cfg_window.

#ifndef UNPACK_INTEGRATE_H
#define UNPACK_INTEGRATE_H

#include "unpack.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

/**
 * @brief True when @p name is a packer dumpexe unpacks during -d / -a.
 *
 * @param name Structural packer string from ToolchainReport::packer.
 * @return true for EXEPACK, LZEXE 0.91/0.90, PKLITE, DIET, and LHarc.
 */
static inline bool dx_packer_supported(const std::string& name)
{
    if (name == "Microsoft EXEPACK")
    {
        return true;
    }
    if (name == "LZEXE 0.91" || name == "LZEXE 0.90")
    {
        return true;
    }
    if (name == "PKLITE" || name.rfind("PKLITE ", 0) == 0)
    {
        return true;
    }
    if (name == "DIET" || name == "LHarc")
    {
        return true;
    }
    return false;
}

/**
 * @brief Path of an unpacked product next to the input.
 *
 * @param input_path Original filename. No directory means the current directory.
 * @param suffix Text after the stem, such as "_UNPACKED.EXE".
 * @return Directory, stem, and suffix joined.
 */
static inline std::string dx_stem_path(const std::string& input_path, const char* suffix)
{
    std::string p = input_path;
    while (p.size() > 1 && (p.back() == '/' || p.back() == '\\'))
    {
        p.pop_back();
    }
    const size_t slash = p.find_last_of("/\\");
    const std::string dir = (slash == std::string::npos) ? std::string() : p.substr(0, slash + 1);
    std::string base = (slash == std::string::npos) ? p : p.substr(slash + 1);
    const size_t dot = base.find_last_of('.');
    if (dot != std::string::npos && dot > 0)
    {
        base = base.substr(0, dot);
    }
    if (base.empty())
    {
        base = "out";
    }
    return dir + base + suffix;
}

/**
 * @brief Result of trying to create an unpacked image.
 */
enum class DxWriteResult
{
    Wrote,  ///< New file created. A symlink was not followed.
    Kept,   ///< Path already existed, including a dangling symlink.
    Failed  ///< Unpack bytes were ready but the file could not be created.
};

/**
 * @brief Write a new unpacked image. An existing file is left unchanged.
 *
 * Uses `open(O_CREAT|O_EXCL|O_NOFOLLOW)`. A dangling symlink is kept and its
 * target is not created.
 *
 * @param path Destination. Not replaced when it already exists.
 * @param data Complete image.
 * @param n Length of @p data.
 * @return Wrote, Kept, or Failed. Failed does not leave a partial file.
 */
static inline DxWriteResult dx_write_unpacked_file(const std::string& path,
                                                   const uint8_t* data,
                                                   size_t n)
{
    if (output_file_exists(path))
    {
        std::cerr << "listing: refuse to overwrite '" << path << "' (kept)\n";
        return DxWriteResult::Kept;
    }

    std::string err;
    const char* bytes = (data == nullptr || n == 0) ? "" : reinterpret_cast<const char*>(data);
    if (!output_create_nofollow(path, bytes, n, err))
    {
        return DxWriteResult::Failed;
    }
    return DxWriteResult::Wrote;
}

/**
 * @brief Multi-pass listing of an unpacked image.
 *
 * The `_UNPACKED` file is written by the caller. This function only lists.
 * An MZ load image over @c opts.maxImageBytes, or a COM image that
 * @c com_listing_image would build over that cap, prints the load-image
 * error and does not disassemble. @c listing_run failure is not a cap failure.
 *
 * @param opts Options for the packed run. @c outputPath is not used.
 *             Repack stays off so the unpacked image is not rewritten.
 * @param bin_path Path passed as the listing source name. Its stem selects
 *                 `<stem>_UNPACKED.asm`.
 * @param image Unpacked file bytes.
 * @return false when the computed listing image is over the cap.
 */
static inline bool dx_list_unpacked(const Options& opts,
                                    const std::string& bin_path,
                                    const std::vector<uint8_t>& image)
{
    Options uopts = opts;
    uopts.outputPath.clear();
    uopts.writeRepack = false;
    uopts.jsonOut = false;

    auto banner = [&]()
    {
        if (opts.showDisasm || opts.showAll)
        {
            std::cout << "=== UNPACKED ===\n";
        }
    };

    if (image.size() >= sizeof(MZHeader))
    {
        MZHeader header{};
        std::memcpy(&header, image.data(), sizeof(header));
        if (mz_signature_ok(header.signature) &&
            validate_header(header, static_cast<int64_t>(image.size())))
        {
            const ExeSizes sizes = calculate_sizes(header, static_cast<int64_t>(image.size()));
            const uint64_t mz_image_bytes = (sizes.loadImageSize > 0)
                ? static_cast<uint64_t>(sizes.loadImageSize)
                : 0ull;
            if (!load_image_within_cap(mz_image_bytes, opts.maxImageBytes))
            {
                return false;
            }
            banner();
            size_t cfg_file_off = 0;
            size_t cfg_len = 0;
            uint16_t cs_seg = 0;
            mz_cfg_window(header, sizes, cfg_file_off, cfg_len, cs_seg, uopts);
            const MzEntryLoc entry = mz_entry_image_ip(header, cfg_len);
            std::vector<RelocEntry> unpacked_relocs;
            load_relocations(header, image, unpacked_relocs);
            const CfgLin entry_base = cfg_listing_entry_base(entry.frame);
            const int listing_rc = listing_run(image, cfg_file_off, cfg_len, entry.linear, cs_seg,
                            static_cast<uint16_t>(header.cs),
                            uopts, bin_path, nullptr, nullptr, false, false,
                            entry.in_window, unpacked_relocs, nullptr,
                            entry_base);
            cfg_set_entry_frame_override(0);
            if (listing_rc != 0)
            {
                return true;
            }
            return true;
        }
    }

    // Unpacked COM listings have always been built with has_psp false, which
    // prefixes 0x100. Cap that length before the vector is allocated.
    const uint64_t com_image_bytes =
        static_cast<uint64_t>(image.size()) + 0x100ull;
    if (!load_image_within_cap(com_image_bytes, opts.maxImageBytes))
    {
        return false;
    }
    banner();
    std::vector<uint8_t> com_image;
    com_listing_image(image, false, com_image);
    if (listing_run(com_image, 0, com_image.size(), COM_ENTRY_IP, uopts.loadBase,
                    uopts.loadBase, uopts, bin_path, nullptr, nullptr, true,
                    false) != 0)
    {
        return true;
    }
    return true;
}

/**
 * @brief After a packed -d/-a listing, unpack and list when the packer is known.
 *
 * Failure to unpack prints one stderr line and leaves any packed listing
 * in place. That path, `--json`, and an empty packer name are not fatal.
 * A load-image cap failure while listing the unpacked bytes is fatal.
 * Writing the `_UNPACKED` file is not capped.
 *
 * @param opts Parsed options.
 * @param fileData Original file bytes.
 * @param packer Structural name. Empty means do not unpack.
 * @return false only when the unpacked listing image is over the cap.
 */
static inline bool dx_after_packed_listing(const Options& opts,
                                           const std::vector<uint8_t>& fileData,
                                           const std::string& packer)
{
    // --uasm may decode in memory. Side files need -d or -a as well.
    if (opts.jsonOut || !(opts.showDisasm || opts.showAll))
    {
        return true;
    }
    if (!opts.toolchainDetect || !dx_packer_supported(packer))
    {
        return true;
    }

    dx_unpack_out unpacked{};
    const int rc = dx_unpack(packer.c_str(), fileData.data(), fileData.size(), &unpacked);
    if (rc != DX_UNPACK_OK || unpacked.data == nullptr || unpacked.size == 0)
    {
        std::cerr << "dumpexe: unpack failed (" << packer << ")\n";
        dx_unpack_free(&unpacked);
        return true;
    }

    const bool mz = unpacked.size >= 2 &&
                    ((unpacked.data[0] == 'M' && unpacked.data[1] == 'Z') ||
                     (unpacked.data[0] == 'Z' && unpacked.data[1] == 'M'));
    const std::string bin_path = dx_stem_path(opts.filename,
                                              mz ? "_UNPACKED.EXE" : "_UNPACKED.COM");
    std::vector<uint8_t> image(unpacked.data, unpacked.data + unpacked.size);
    dx_unpack_free(&unpacked);

    // -o - is stdout only: no .asm and no _UNPACKED image. Both listings
    // still go to stdout (the packed one already did), then one separator.
    const bool stdout_only = (opts.outputPath == "-");
    auto list_unpacked = [&](bool write_asm) -> bool
    {
        Options u = opts;
        u.writeAsmFile = write_asm;
        return dx_list_unpacked(u, bin_path, image);
    };
    if (stdout_only)
    {
        // -o - writes no _UNPACKED files. The address listing still goes to
        // stdout when -d/-a asked for one. --uasm -o - is UASM source only.
        if (!opts.uasm && (opts.showDisasm || opts.showAll))
        {
            return list_unpacked(false);
        }
        return true;
    }

    const DxWriteResult wrote = dx_write_unpacked_file(bin_path, image.data(), image.size());
    if (wrote == DxWriteResult::Failed)
    {
        // The unpack buffer is complete. A create error is not an unpack failure.
        std::cerr << "dumpexe: cannot write '" << bin_path << "'\n";
        return list_unpacked(false);
    }
    if (wrote == DxWriteResult::Kept)
    {
        // Do not pair the kept image with a disassembly of the fresh bytes.
        const std::string asm_path = dx_stem_path(opts.filename, "_UNPACKED.asm");
        if (output_file_exists(asm_path))
        {
            std::cerr << "listing: refuse to overwrite '" << asm_path << "' (kept)\n";
        }
        return list_unpacked(false);
    }

    return list_unpacked(opts.writeAsmFile);
}

#endif
