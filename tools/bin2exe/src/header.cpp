/**
 * @file header.cpp
 * @brief COM wrap and MZ header copy, including a matching original tail.
 */
#include "bin2exe/header.hpp"

#include "bin2exe/mz_pages.h"

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace bin2exe
{
namespace
{

void store_le16(std::uint8_t *destination, std::uint16_t value)
{
    destination[0] = static_cast<std::uint8_t>(value & 0xFFu);
    destination[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
}

std::uint16_t load_le16(const std::uint8_t *source)
{
    return static_cast<std::uint16_t>(
        static_cast<unsigned>(source[0]) |
        (static_cast<unsigned>(source[1]) << 8));
}

bool looks_like_mz(const std::uint8_t *bytes)
{
    const bool mz = bytes[0] == static_cast<std::uint8_t>('M') &&
                    bytes[1] == static_cast<std::uint8_t>('Z');
    const bool zm = bytes[0] == static_cast<std::uint8_t>('Z') &&
                    bytes[1] == static_cast<std::uint8_t>('M');
    return mz || zm;
}

/**
 * @brief Append original[written:] when the flat image continues the file.
 *
 * @param[in] original      Leading bytes of the original file.
 * @param[in] file_size     Full original length. Bytes at and past this
 *                          offset are not part of the file.
 * @param[in] header_bytes  Copied MZ header length.
 * @param[in] image         Flat image already stored after the header.
 * @param[in,out] built     Header plus image. The tail is inserted on success.
 *
 * @retval true  A non-empty tail was appended.
 * @retval false The image is not a prefix of the original payload, the tail
 *               is empty, or @p original does not hold the tail bytes.
 */
bool append_matching_tail(std::span<const std::uint8_t> original,
                          std::uint64_t file_size,
                          std::size_t header_bytes,
                          std::span<const std::uint8_t> image,
                          std::vector<std::uint8_t> *built)
{
    if (built == nullptr || header_bytes > file_size)
    {
        return false;
    }
    const std::uint64_t payload_bytes = file_size - static_cast<std::uint64_t>(header_bytes);
    if (static_cast<std::uint64_t>(image.size()) > payload_bytes)
    {
        return false;
    }
    const std::uint64_t written =
        static_cast<std::uint64_t>(header_bytes) + static_cast<std::uint64_t>(image.size());
    if (written >= file_size || static_cast<std::uint64_t>(original.size()) < file_size)
    {
        return false;
    }
    if (original.size() < header_bytes + image.size())
    {
        return false;
    }
    /* Flat image must be a prefix of the original payload, not merely the same length. */
    if (std::memcmp(original.data() + header_bytes, image.data(), image.size()) != 0)
    {
        return false;
    }
    /* Header plus image must themselves be a prefix of the original file. */
    if (built->size() < static_cast<std::size_t>(written) ||
        std::memcmp(original.data(), built->data(), static_cast<std::size_t>(written)) != 0)
    {
        return false;
    }
    const auto tail_off = static_cast<std::size_t>(written);
    const auto tail_end = static_cast<std::size_t>(file_size);
    built->insert(built->end(),
                  original.begin() + static_cast<std::ptrdiff_t>(tail_off),
                  original.begin() + static_cast<std::ptrdiff_t>(tail_end));
    return true;
}

} /* namespace */

build_result wrap_com(std::span<const std::uint8_t> image)
{
    build_result result{};
    if (image.empty())
    {
        result.code = status::empty_image;
        return result;
    }
    if (image.size() > k_com_image_max)
    {
        result.code = status::com_too_large;
        return result;
    }

    const auto file_size = static_cast<std::uint32_t>(k_com_header_bytes + image.size());
    std::uint16_t cblp = 0;
    std::uint16_t cp = 0;
    if (mz_page_fields(file_size, &cblp, &cp) != 0)
    {
        result.code = status::page_overflow;
        return result;
    }

    result.bytes.assign(file_size, 0);
    std::uint8_t *header = result.bytes.data();
    header[0] = static_cast<std::uint8_t>('M');
    header[1] = static_cast<std::uint8_t>('Z');
    store_le16(header + 2, cblp);
    store_le16(header + 4, cp);
    store_le16(header + 6, 0);       /* e_crlc */
    store_le16(header + 8, 2);       /* e_cparhdr: 32-byte header */
    store_le16(header + 10, 0);      /* e_minalloc */
    store_le16(header + 12, 0xFFFF); /* e_maxalloc: largest free block */
    /*
     * load_seg = PSP + 0x10. Adding 0xFFF0 wraps CS and SS to the PSP, so
     * IP 0x0100 is the first image byte and SP 0xFFFE is the COM stack.
     * DOS sets DS = ES = PSP before the transfer.
     */
    store_le16(header + 14, 0xFFF0); /* e_ss */
    store_le16(header + 16, 0xFFFE); /* e_sp */
    store_le16(header + 18, 0);      /* e_csum */
    store_le16(header + 20, 0x0100); /* e_ip */
    store_le16(header + 22, 0xFFF0); /* e_cs */
    store_le16(header + 24, 0x001C); /* e_lfarlc; table is empty */
    store_le16(header + 26, 0);      /* e_ovno */
    std::memcpy(header + k_com_header_bytes, image.data(), image.size());
    result.code = status::ok;
    return result;
}

build_result copy_mz_header(std::span<const std::uint8_t> exe_prefix,
                            std::uint64_t exe_file_size,
                            std::span<const std::uint8_t> image,
                            bool carry_tail)
{
    build_result result{};
    if (image.empty())
    {
        result.code = status::empty_image;
        return result;
    }
    if (exe_prefix.size() < k_com_header_bytes || exe_file_size < k_com_header_bytes)
    {
        result.code = status::header_too_small;
        return result;
    }
    if (!looks_like_mz(exe_prefix.data()))
    {
        result.code = status::not_mz;
        return result;
    }

    const std::uint16_t paragraphs = load_le16(exe_prefix.data() + 8);
    if (paragraphs < 2u)
    {
        result.code = status::header_too_small;
        return result;
    }
    const auto header_len = static_cast<std::uint32_t>(paragraphs) * 16u;
    if (header_len > k_mz_header_max)
    {
        result.code = status::header_too_large;
        return result;
    }
    if (exe_file_size < header_len || exe_prefix.size() < header_len)
    {
        result.code = status::header_truncated;
        return result;
    }

    result.original_payload_bytes = exe_file_size - header_len;
    result.payload_length_differs =
        static_cast<std::uint64_t>(image.size()) != result.original_payload_bytes;

    const std::size_t header_bytes = static_cast<std::size_t>(header_len);
    result.bytes.resize(header_bytes + image.size());
    std::memcpy(result.bytes.data(), exe_prefix.data(), header_bytes);
    std::memcpy(result.bytes.data() + header_bytes, image.data(), image.size());
    if (carry_tail)
    {
        result.tail_appended = append_matching_tail(exe_prefix, exe_file_size, header_bytes,
                                                    image, &result.bytes);
    }
    result.code = status::ok;
    return result;
}

} /* namespace bin2exe */
