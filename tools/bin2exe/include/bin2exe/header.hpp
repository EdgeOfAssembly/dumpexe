/**
 * @file header.hpp
 * @brief Build a DOS MZ executable from a flat image.
 *
 * Default mode wraps a COM-sized image so DOS enters it at PSP:0100.
 * Header-copy mode prepends an existing MZ header and does not rewrite it.
 */
#ifndef BIN2EXE_HEADER_HPP
#define BIN2EXE_HEADER_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace bin2exe
{

/** Largest flat image the default COM wrap will accept (classic COM limit). */
inline constexpr std::size_t k_com_image_max = 0xFF00u;

/** Bytes in the synthesized COM-style header (e_cparhdr == 2). */
inline constexpr std::size_t k_com_header_bytes = 32u;

/** Refused MZ header length. Real DOS MZ headers are far smaller. */
inline constexpr std::uint32_t k_mz_header_max = 65536u;

/**
 * @brief Why a build did not produce an image.
 */
enum class status : int
{
    ok = 0,
    empty_image = 1,
    com_too_large = 2,
    page_overflow = 3,
    not_mz = 4,
    header_too_small = 5,
    header_truncated = 6,
    header_too_large = 7
};

/**
 * @brief Owned EXE bytes plus the header-copy length check.
 */
struct build_result
{
    status code = status::ok;
    /** True when the flat image length is not the original file minus the header. */
    bool payload_length_differs = false;
    /**
     * True when bytes after the copied header and flat image were appended
     * from the original file. Callers warn on a length mismatch only when
     * this flag is false.
     */
    bool tail_appended = false;
    /** Original file size minus the copied header. Meaningful for header copy. */
    std::uint64_t original_payload_bytes = 0;
    std::vector<std::uint8_t> bytes{};
};

/**
 * @brief Wrap a flat COM image in a 32-byte MZ header that DOS can run.
 *
 * The header uses CS = SS = 0xFFF0, IP = 0x0100, SP = 0xFFFE, minalloc 0,
 * and maxalloc 0xFFFF. DOS loads the image at PSP+0x10 and adds 0xFFF0 to
 * the segment, which wraps to the PSP, so the first image byte is PSP:0100.
 * DS and ES are the PSP, which is how DOS enters an EXE. The stack is the
 * COM stack at PSP:FFFE. DOS must hand the process a full 64 KiB segment;
 * maxalloc 0xFFFF asks for the largest free block.
 *
 * @param[in] image Flat bytes. Must be non-empty and at most k_com_image_max.
 *
 * @return code == status::ok and bytes holding header plus image, or a
 *         failure code and an empty buffer.
 *
 * @note Relocations are not invented. This is a COM wrap, not a rebuilt
 *       multi-segment EXE header.
 */
[[nodiscard]] build_result wrap_com(std::span<const std::uint8_t> image);

/**
 * @brief Prepend an existing MZ header to a flat image without editing it.
 *
 * Copies e_cparhdr*16 bytes, including the relocation table and any padding.
 * Page counts, SS:SP, CS:IP, minalloc, and the checksum stay as they were.
 *
 * @param[in] exe_prefix    Leading bytes of the original EXE. Must include
 *                          the whole header when the call succeeds. Pass the
 *                          whole file so a matching tail can be copied.
 * @param[in] exe_file_size Full original file length. Bytes of @p exe_prefix
 *                          at and after this length are not part of the file.
 * @param[in] image         Flat load image to append. Must be non-empty.
 * @param[in] carry_tail    When true, append original bytes that follow a
 *                          matching prefix. When false, stop after @p image.
 *
 * @return On success, bytes is the header, then @p image, then a tail when
 *         @p carry_tail is set, @p image is a prefix of the original payload,
 *         and the bytes written so far are a prefix of the original file.
 *         An empty tail is not an append. payload_length_differs is set when
 *         the flat image length disagrees with the original payload even if
 *         a tail was appended. The header bytes are not rewritten.
 *
 * @note Does not exit the process and does not open a destination file.
 *       Relocation entries are not adjusted. A flat image that is not a
 *       prefix of the original payload is copied as-is and the tail is left
 *       behind. @c e_cparhdr == 0 is refused. @c e_cparhdr == 1 (16 bytes)
 *       is accepted only when @c e_crlc is 0 or the relocation table ends
 *       at or before byte 16. A file shorter than the claimed header is
 *       status::header_truncated. Headers of 32 bytes and larger are not
 *       checked for relocation fit.
 */
[[nodiscard]] build_result copy_mz_header(std::span<const std::uint8_t> exe_prefix,
                                          std::uint64_t exe_file_size,
                                          std::span<const std::uint8_t> image,
                                          bool carry_tail);

} /* namespace bin2exe */

#endif /* BIN2EXE_HEADER_HPP */
