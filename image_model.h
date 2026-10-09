/**
 * @file image_model.h
 * @brief Load-image addresses, the one segment P1 builds, and entry points.
 *
 * P1 records the image the caller already sliced. It does not parse an MZ
 * header and it does not invent relocations.
 */
#ifndef IMAGE_MODEL_H
#define IMAGE_MODEL_H

#include <compare>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace dx
{

/**
 * @brief Byte offset from the start of the load image.
 *
 * Byte 0 is the first byte of the load image. COM listing bytes are not
 * prefixed with a PSP; the PSP hole is @c Image::virtual_below, not a
 * negative @c Lin.
 */
struct Lin
{
    uint32_t v = 0;

    /** @brief Total order on the linear value. */
    auto operator<=>(const Lin&) const = default;
};

/**
 * @brief Byte offset in the input file.
 */
struct FileOff
{
    uint32_t v = 0;

    /** @brief Total order on the file offset. */
    auto operator<=>(const FileOff&) const = default;
};

/**
 * @brief Raw paragraph value as stored in a file word.
 */
struct Para
{
    uint16_t v = 0;

    /** @brief Total order on the paragraph value. */
    auto operator<=>(const Para&) const = default;
};

/**
 * @brief Segment-relative address.
 *
 * @c frame is a model segment id, or @c kAbsFrame for an absolute segment.
 * It is not a raw paragraph. A negative load frame is not stored here.
 */
struct SegOff
{
    uint16_t frame = 0;
    uint16_t off = 0;

    /** @brief Total order on frame, then offset. */
    auto operator<=>(const SegOff&) const = default;
};

/**
 * @brief Segment id used for an absolute frame (BIOS data, video RAM).
 */
constexpr uint16_t kAbsFrame = 0xFFFFu;

/**
 * @brief Container format of the input the caller already classified.
 */
enum class Fmt : uint8_t
{
    Com = 0,
    ComInExe = 1,
    Mz = 2,
    Sys = 3,
    Ne = 4
};

/**
 * @brief Role of one model segment.
 */
enum class SegKind : uint8_t
{
    Unknown = 0,
    Code = 1,
    Data = 2,
    Stack = 3,
    Psp = 4,
    Bss = 5,
    Overlay = 6
};

/**
 * @brief One segment frame inside an @c Image.
 */
struct Segment
{
    uint16_t id = 0;
    Lin base_lin{};
    uint32_t size = 0;
    Para file_para{};
    SegKind kind = SegKind::Unknown;
    uint8_t evidence = 0;
    bool reloc_derived = false;
    bool below_image = false;
    std::string name;
};

/**
 * @brief Kind of a relocation record. P1 does not invent these.
 */
enum class RelocKind : uint8_t
{
    SegWord = 0,
    FarPtrSeg = 1,
    NeInternal = 2,
    NeImportOrd = 3,
    NeImportName = 4,
    NeOsFixup = 5
};

/**
 * @brief One relocation. @c image_from_load leaves the image vector empty.
 */
struct Reloc
{
    Lin at{};
    RelocKind kind = RelocKind::SegWord;
    uint8_t width = 0;
    Para value{};
    uint16_t table_index = 0;
    uint16_t raw_seg = 0;
    uint16_t raw_off = 0;
    uint16_t ne_module = 0;
    uint16_t ne_ordinal = 0;
};

/**
 * @brief One entry point into the load image.
 */
struct EntryPoint
{
    SegOff where{};

    /**
     * @brief Which header field or user action named this entry.
     */
    enum class Kind : uint8_t
    {
        MzCsIp = 0,
        ComStart = 1,
        SysStrategy = 2,
        SysInterrupt = 3,
        NeEntryTable = 4,
        NeStart = 5,
        Export = 6,
        UserHint = 7
    };

    Kind kind = Kind::MzCsIp;
};

/**
 * @brief Load image plus the segment and entry P1 can build without a parser.
 *
 * @c bytes is the caller slice, copied. COM is not prefixed with a PSP.
 * @c file, @c header_bytes, @c tail, and @c relocs stay empty here.
 */
struct Image
{
    Fmt fmt = Fmt::Mz;
    std::span<const uint8_t> file{};
    std::vector<uint8_t> bytes;
    FileOff image_file_base{};
    uint32_t virtual_below = 0;
    std::vector<Segment> segments;
    std::vector<Reloc> relocs;
    std::vector<EntryPoint> entries;
    std::vector<uint8_t> header_bytes;
    std::vector<uint8_t> tail;
    std::string tail_kind;

    /**
     * @brief One unpack step. P1 does not fill @c unpack_chain.
     */
    struct UnpackStep
    {
        std::string packer;
        std::string sha_in;
        std::string sha_out;
    };

    std::vector<UnpackStep> unpack_chain;
};

/**
 * @brief Build the one-segment image P1 records for an already-sliced load.
 *
 * One segment, id 0, @c base_lin 0, size = @p bytes.size(). Kind is
 * @c Code for @c Fmt::Com and @c Fmt::Mz, otherwise @c Unknown.
 * @c virtual_below is @c 0x100 for @c Fmt::Com and 0 otherwise.
 * Relocations stay empty. The byte vector is a copy of @p bytes, not a
 * PSP-prefixed COM image.
 *
 * A negative @p entry_frame sets @c Segment::below_image. The frame is
 * never cast through @c uint32_t, so a negative frame cannot become a
 * huge linear base. @c base_lin stays 0.
 *
 * The entry @c SegOff is stored with segment id 0 and @c off == @p entry.v
 * only when @p entry_frame >= 0 and @p entry.v fits in 16 bits. Otherwise
 * an entry is still pushed and its offset is @p entry.v truncated to 16
 * bits. @c below_image is set when the frame is negative.
 *
 * @param[in] fmt             Format the caller already decided.
 * @param[in] bytes           Load-image slice. Not parsed as an MZ header.
 * @param[in] image_file_base File offset of @p bytes[0].
 * @param[in] entry           Entry linear inside the load image.
 * @param[in] entry_frame     Paragraph frame of @p entry (`cs * 16`).
 *                            May be negative. Not a @c uint32_t base.
 * @return Image with one segment and one entry. @c relocs is empty.
 * @note Does not read an MZ header and does not invent relocations.
 */
inline Image image_from_load(Fmt fmt,
                             std::span<const uint8_t> bytes,
                             FileOff image_file_base,
                             Lin entry,
                             int32_t entry_frame)
{
    Image image{};
    image.fmt = fmt;
    image.bytes.assign(bytes.begin(), bytes.end());
    image.image_file_base = image_file_base;
    image.virtual_below = (fmt == Fmt::Com) ? 0x100u : 0u;

    Segment segment{};
    segment.id = 0;
    segment.base_lin = Lin{0};
    const std::size_t nbytes = image.bytes.size();
    segment.size = (nbytes > 0xffffffffu)
                       ? 0xffffffffu
                       : static_cast<uint32_t>(nbytes);
    if (fmt == Fmt::Com || fmt == Fmt::Mz)
    {
        segment.kind = SegKind::Code;
    }
    else
    {
        segment.kind = SegKind::Unknown;
    }
    segment.evidence = 0;
    segment.reloc_derived = false;
    segment.file_para = Para{0};
    /* Negative frames stay signed. Casting through uint32_t would wrap. */
    segment.below_image = entry_frame < 0;
    image.segments.push_back(segment);

    EntryPoint entry_point{};
    if (fmt == Fmt::Com)
    {
        entry_point.kind = EntryPoint::Kind::ComStart;
    }
    else
    {
        entry_point.kind = EntryPoint::Kind::MzCsIp;
    }
    entry_point.where.frame = 0;
    const bool offset_fits = entry.v <= 0xffffu;
    if (entry_frame >= 0 && offset_fits)
    {
        entry_point.where.off = static_cast<uint16_t>(entry.v);
    }
    else
    {
        entry_point.where.off = static_cast<uint16_t>(entry.v & 0xffffu);
        if (entry_frame < 0)
        {
            image.segments[0].below_image = true;
        }
    }
    image.entries.push_back(entry_point);
    return image;
}

/**
 * @brief Report whether @p lin addresses a byte of the load image.
 *
 * The virtual PSP hole is not part of @c Image::bytes. @c Lin 0 is the
 * first load-image byte.
 *
 * @param[in] image Image built by @c image_from_load or an equivalent fill.
 * @param[in] lin   Linear address to test.
 * @retval true  @p lin.v is strictly less than @c image.bytes.size().
 * @retval false @p lin is outside the copied load image.
 */
inline bool lin_in_image(const Image& image, Lin lin)
{
    return static_cast<std::size_t>(lin.v) < image.bytes.size();
}

} /* namespace dx */

#endif /* IMAGE_MODEL_H */
