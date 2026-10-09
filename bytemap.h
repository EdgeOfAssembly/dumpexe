/**
 * @file bytemap.h
 * @brief Per-byte claims for code, data, and padding, plus retract.
 *
 * Hint strength never writes a cell. Equal-or-stronger code overlap becomes
 * @c Conflict and does not replace the old item. A weaker overlap is rejected
 * with no write. @c retract(0) is a no-op because unit 0 is not speculative.
 */
#ifndef BYTEMAP_H
#define BYTEMAP_H

#include "facts.h"

#include <cassert>
#include <cstdint>
#include <vector>

namespace dx
{

/**
 * @brief What a byte currently is. A zero-initialized cell is @c Unknown.
 */
enum class BState : uint8_t
{
    Unknown = 0,
    CodeHead = 1,
    CodeTail = 2,
    Data = 3,
    Padding = 4,
    Conflict = 5
};

/**
 * @brief Type of a @c BState::Data cell.
 */
enum class DType : uint8_t
{
    Byte = 0,
    Word = 1,
    Dword = 2,
    FarPtr = 3,
    NearCodePtr = 4,
    NearDataPtr = 5,
    SegWord = 6,
    StrDollar = 7,
    StrAsciiz = 8,
    StrPascal = 9,
    StrFixed = 10,
    Array = 11,
    Struct = 12,
    InlineArg = 13
};

/**
 * @brief Why a @c BState::Padding cell was filled.
 */
enum class PadKind : uint8_t
{
    Align = 0,
    AsmNop = 1,
    ZeroFill = 2,
    CompilerFill = 3
};

/**
 * @brief One image byte. Ordinary fields so value-initialization is Unknown.
 *
 * Not bitfields: a zero-init cell must be @c Unknown with strength 0.
 * @c item is the caller's item id. @c sub holds a @c ConflictKind when
 * @c state is @c Conflict, and is 0 otherwise.
 */
struct ByteCell
{
    BState state = BState::Unknown;
    uint8_t strength = 0;
    uint8_t sub = 0;
    uint8_t dtype_or_pad = 0;
    uint16_t flags = 0;
    uint32_t item = 0;
};

/**
 * @brief Flag bits stored in @c ByteCell::flags.
 */
enum Flag : uint16_t
{
    F_Label = 1u << 0,
    F_MidLabel = 1u << 1,
    F_RelocField = 1u << 2,
    F_SegBoundary = 1u << 3,
    F_Read = 1u << 4,
    F_Written = 1u << 5,
    F_Executed = 1u << 6,
    F_SmcTarget = 1u << 7,
    F_Speculative = 1u << 8,
    F_HintCode = 1u << 9,
    F_HintText = 1u << 10,
    F_Virtual = 1u << 11
};

/**
 * @brief Why two claims could not share a byte.
 */
enum class ConflictKind : uint8_t
{
    Overlap = 0,
    CodeOnData = 1,
    DataOnCode = 2
};

/**
 * @brief Mutable per-byte map. Out-of-range reads return an Unknown cell.
 */
class ByteMap
{
public:
    /**
     * @brief Allocate @p n Unknown cells.
     *
     * @param[in] n Number of image bytes. Zero is an empty map.
     */
    explicit ByteMap(uint32_t n);

    /**
     * @brief Claim @p len bytes of code starting at @p head.
     *
     * @p len must be 1..15 and the whole span must lie in the map.
     * Strength below @c kPromote returns false and writes nothing
     * (no journal row). Success writes @c CodeHead at @p head and
     * @c CodeTail on the rest, all with @p item. @c F_Speculative is set
     * only when @p why.strength is @c Likely.
     *
     * Overlap with existing code: a strictly weaker new strength returns
     * false and changes nothing. Equal or stronger strength marks
     * @c Conflict on the overlapping bytes, keeps the old item, and
     * returns false. Data under an equal-or-stronger code claim becomes
     * @c CodeOnData. Padding loses to any promoting code claim.
     *
     * @param[in] head First byte of the instruction.
     * @param[in] len  Instruction length, 1..15.
     * @param[in] item Caller item id stored on every claimed byte.
     * @param[in] why  Justifying fact. @c why.unit is the journal key.
     * @retval true  The span was Unknown or padding and is now this item.
     * @retval false Rejected, or overlap marked @c Conflict. No new item.
     */
    bool claim_code(Lin head, uint8_t len, uint32_t item, const Fact& why);

    /**
     * @brief Claim @p len bytes of typed data at @p at.
     *
     * Same hint gate as @c claim_code. @p len must be at least 1 and the
     * span must lie in the map. Data on a code byte becomes @c DataOnCode
     * when @p why.strength is greater than or equal to the code strength;
     * a weaker data fact is rejected with no change. An existing data byte
     * rejects the new claim with no change. Padding is replaced.
     *
     * @param[in] at   First data byte.
     * @param[in] len  Byte count. Zero and out-of-range spans fail.
     * @param[in] t    Data type stored in @c ByteCell::dtype_or_pad.
     * @param[in] item Caller item id.
     * @param[in] why  Justifying fact. Hint writes nothing.
     * @retval true  The span is now @c Data for @p item.
     * @retval false Rejected, or code bytes marked @c DataOnCode.
     */
    bool claim_data(Lin at, uint32_t len, DType t, uint32_t item, const Fact& why);

    /**
     * @brief Claim @p len bytes of padding at @p at.
     *
     * Same hint gate as @c claim_code. Padding does not replace code, data,
     * or an existing conflict, whatever the numeric strength is. A weaker
     * padding fact on existing padding is rejected. Equal or stronger
     * padding replaces padding. A later promoting code or data claim
     * replaces padding.
     *
     * @param[in] at  First padding byte.
     * @param[in] len Byte count. Zero and out-of-range spans fail.
     * @param[in] k   Padding kind stored in @c ByteCell::dtype_or_pad.
     * @param[in] why Justifying fact. The cell item is 0 (no item argument).
     * @retval true  The span is now @c Padding.
     * @retval false Rejected. The map is unchanged.
     */
    bool claim_padding(Lin at, uint32_t len, PadKind k, const Fact& why);

    /**
     * @brief Mark @p len bytes from @p at as @c Conflict.
     *
     * Bytes outside the map are ignored. The existing @c item is kept.
     * A @c CodeTail that loses the @c CodeHead of its item is also marked
     * @c Conflict so a tail is never left without its head.
     *
     * @param[in] at  First byte to mark. Out of range marks nothing.
     * @param[in] len Byte count. Zero marks nothing.
     * @param[in] k   Conflict kind stored in @c ByteCell::sub.
     * @param[in] a   Existing claim's fact (recorded, not applied as a new item).
     * @param[in] b   New claim's fact (recorded, not applied as a new item).
     */
    void mark_conflict(Lin at, uint32_t len, ConflictKind k, const Fact& a, const Fact& b);

    /**
     * @brief Undo every journaled claim whose unit is @p unit.
     *
     * Those bytes return to @c Unknown (strength 0) when they are still
     * owned by @p unit. A later claim that replaced them is left alone.
     * The journal rows for @p unit are dropped. Unit 0 is not speculative:
     * @c retract(0) changes nothing.
     *
     * @param[in] unit Speculative unit id. Zero is a no-op.
     */
    void retract(uint32_t unit);

    /**
     * @brief Cell at @p lin, or a permanent Unknown cell if @p lin is outside.
     *
     * @param[in] lin Linear address. Not required to be in range.
     * @return Reference to the cell. The out-of-range object is never a
     *         map cell and stays @c Unknown. Does not throw.
     */
    const ByteCell& at(Lin lin) const;

    /**
     * @brief Number of cells in the map.
     *
     * @return The width passed to the constructor.
     */
    uint32_t size() const;

private:
    /**
     * @brief One successful claim. Retract keys off @c unit.
     */
    struct JournalRow
    {
        uint32_t unit = 0;
        uint32_t begin = 0;
        uint32_t len = 0;
        uint32_t item = 0;
        BState state = BState::Unknown;
    };

    /**
     * @brief One @c mark_conflict call, kept so both facts stay reachable.
     */
    struct ConflictNote
    {
        uint32_t at = 0;
        uint32_t len = 0;
        ConflictKind kind = ConflictKind::Overlap;
        Fact a{};
        Fact b{};
    };

    std::vector<ByteCell> cells_;
    std::vector<uint32_t> unit_of_;
    std::vector<uint8_t> span_;
    std::vector<JournalRow> journal_;
    std::vector<ConflictNote> conflicts_;

    /**
     * @brief True when @p strength may change a cell.
     *
     * @param[in] strength Fact strength.
     * @retval true  @p strength is at least @c kPromote.
     * @retval false @p strength is @c Hint (or below the promote threshold).
     */
    static bool promotes(Strength strength);

    /**
     * @brief True when [at, at+len) lies entirely inside the map.
     *
     * @param[in] at  First index.
     * @param[in] len Byte count. Zero is outside.
     * @retval true  The half-open span is inside @c cells_.
     * @retval false Empty, overflowing, or past the end.
     */
    bool range_inside(uint32_t at, uint32_t len) const;

    /**
     * @brief Flags for a promoting claim. Speculative only when Likely.
     *
     * @param[in] strength Fact strength. Caller already passed the hint gate.
     * @return @c F_Speculative or 0.
     */
    static uint16_t claim_flags(Strength strength);

    /**
     * @brief Turn orphan code tails into @c Conflict.
     *
     * A tail must sit in the span of a live @c CodeHead of the same item.
     * Punching out a head, or a byte in the middle of an item, would
     * otherwise leave a tail that the invariant forbids.
     */
    void repair_orphan_tails();

    /**
     * @brief Check the public invariants.
     *
     * The scan is O(map size). It runs only when @c DX_BYTEMAP_AUDIT is
     * defined, which the model unit test sets. The product build does not,
     * so a walk over a 64 KiB image does not rescan the map per instruction.
     */
    void check_invariants() const;

    /**
     * @brief Mark code/data overlaps inside a rejected claim. No new item.
     *
     * @param[in] begin     First index of the rejected span.
     * @param[in] len       Length of the rejected span.
     * @param[in] why       The new fact.
     * @param[in] from_code True when the new claim was code (data hits are
     *                      @c CodeOnData). False when the new claim was data
     *                      (code hits are @c DataOnCode).
     */
    void conflict_overlaps(uint32_t begin, uint32_t len, const Fact& why, bool from_code);
};

inline ByteMap::ByteMap(uint32_t n)
    : cells_(static_cast<std::size_t>(n)),
      unit_of_(static_cast<std::size_t>(n), 0u),
      span_(static_cast<std::size_t>(n), static_cast<uint8_t>(0))
{
}

inline bool ByteMap::promotes(Strength strength)
{
    return static_cast<uint8_t>(strength) >= static_cast<uint8_t>(kPromote);
}

inline bool ByteMap::range_inside(uint32_t at, uint32_t len) const
{
    if (len == 0u)
    {
        return false;
    }
    const uint64_t sum = static_cast<uint64_t>(at) + static_cast<uint64_t>(len);
    return sum <= static_cast<uint64_t>(cells_.size());
}

inline uint16_t ByteMap::claim_flags(Strength strength)
{
    if (strength == Strength::Likely)
    {
        return static_cast<uint16_t>(F_Speculative);
    }
    return 0;
}

inline void ByteMap::repair_orphan_tails()
{
    const uint32_t n = static_cast<uint32_t>(cells_.size());
    uint32_t active_head = n;
    uint32_t active_end = 0;
    uint32_t active_item = 0;
    uint8_t active_len = 0;
    for (uint32_t i = 0; i < n; ++i)
    {
        const BState state = cells_[i].state;
        if (state == BState::CodeHead)
        {
            active_head = i;
            active_len = span_[i];
            active_item = cells_[i].item;
            active_end = i + static_cast<uint32_t>(active_len);
        }
        else if (state == BState::CodeTail)
        {
            const bool in_item = active_head != n
                                 && i < active_end
                                 && cells_[i].item == active_item
                                 && span_[i] == active_len;
            if (!in_item)
            {
                cells_[i].state = BState::Conflict;
                cells_[i].sub = static_cast<uint8_t>(ConflictKind::Overlap);
                active_head = n;
                active_end = 0;
            }
        }
        else
        {
            active_head = n;
            active_end = 0;
        }
    }
}

inline void ByteMap::check_invariants() const
{
#if !defined(DX_BYTEMAP_AUDIT)
    return;
#else
    const uint32_t n = static_cast<uint32_t>(cells_.size());
    uint32_t active_head = n;
    uint32_t active_end = 0;
    uint32_t active_item = 0;
    uint8_t active_len = 0;
    for (uint32_t i = 0; i < n; ++i)
    {
        const ByteCell& cell = cells_[i];
        if (cell.state == BState::Unknown)
        {
            assert(cell.strength == 0u);
        }
        if (cell.state == BState::CodeHead)
        {
            assert(active_head == n || i >= active_end);
            assert(span_[i] >= 1u && span_[i] <= 15u);
            assert(cell.strength >= static_cast<uint8_t>(kPromote));
            active_head = i;
            active_len = span_[i];
            active_item = cell.item;
            active_end = i + static_cast<uint32_t>(active_len);
        }
        else if (cell.state == BState::CodeTail)
        {
            assert(active_head != n);
            assert(i < active_end);
            assert(cell.item == active_item);
            assert(span_[i] == active_len);
            assert(cell.strength >= static_cast<uint8_t>(kPromote));
        }
        else
        {
            active_head = n;
            active_end = 0;
        }
    }
#endif
}

inline void ByteMap::mark_conflict(Lin at,
                                   uint32_t len,
                                   ConflictKind k,
                                   const Fact& a,
                                   const Fact& b)
{
    if (len == 0u || at.v >= cells_.size())
    {
        return;
    }
    const uint64_t sum = static_cast<uint64_t>(at.v) + static_cast<uint64_t>(len);
    const uint64_t capped = (sum > static_cast<uint64_t>(cells_.size()))
                                ? static_cast<uint64_t>(cells_.size())
                                : sum;
    const uint32_t end = static_cast<uint32_t>(capped);
    for (uint32_t i = at.v; i < end; ++i)
    {
        cells_[i].state = BState::Conflict;
        cells_[i].sub = static_cast<uint8_t>(k);
    }
    repair_orphan_tails();
    ConflictNote note{};
    note.at = at.v;
    note.len = end - at.v;
    note.kind = k;
    note.a = a;
    note.b = b;
    conflicts_.push_back(note);
    check_invariants();
}

inline void ByteMap::conflict_overlaps(uint32_t begin,
                                       uint32_t len,
                                       const Fact& why,
                                       bool from_code)
{
    uint32_t k = 0;
    while (k < len)
    {
        const uint32_t index = begin + k;
        const BState state = cells_[index].state;
        const bool is_code = state == BState::CodeHead || state == BState::CodeTail;
        const bool is_data = state == BState::Data;
        const bool hit = is_code || (from_code && is_data);
        if (!hit)
        {
            ++k;
            continue;
        }
        const ConflictKind kind = is_code
                                      ? (from_code ? ConflictKind::Overlap
                                                   : ConflictKind::DataOnCode)
                                      : ConflictKind::CodeOnData;
        const uint32_t run_at = index;
        uint32_t run_len = 0;
        while (k < len)
        {
            const ByteCell& cell = cells_[begin + k];
            const bool cell_code = cell.state == BState::CodeHead
                                   || cell.state == BState::CodeTail;
            const bool cell_data = cell.state == BState::Data;
            bool same = false;
            ConflictKind cell_kind = ConflictKind::Overlap;
            if (cell_code)
            {
                cell_kind = from_code ? ConflictKind::Overlap
                                      : ConflictKind::DataOnCode;
                same = true;
            }
            else if (from_code && cell_data)
            {
                cell_kind = ConflictKind::CodeOnData;
                same = true;
            }
            if (!same || cell_kind != kind)
            {
                break;
            }
            ++run_len;
            ++k;
        }
        Fact prior = why;
        prior.strength = static_cast<Strength>(cells_[run_at].strength);
        prior.subject = Lin{run_at};
        prior.unit = unit_of_[run_at];
        mark_conflict(Lin{run_at}, run_len, kind, prior, why);
    }
}

inline bool ByteMap::claim_code(Lin head, uint8_t len, uint32_t item, const Fact& why)
{
    if (!promotes(why.strength))
    {
        return false;
    }
    if (len < 1u || len > 15u)
    {
        return false;
    }
    if (!range_inside(head.v, len))
    {
        return false;
    }

    const uint8_t neu = static_cast<uint8_t>(why.strength);
    bool weaker = false;
    bool code_hit = false;
    bool data_hit = false;
    bool blocked = false;
    for (uint32_t k = 0; k < len; ++k)
    {
        const ByteCell& cell = cells_[head.v + k];
        if (cell.state == BState::CodeHead || cell.state == BState::CodeTail)
        {
            code_hit = true;
            if (neu < cell.strength)
            {
                weaker = true;
            }
        }
        else if (cell.state == BState::Data)
        {
            data_hit = true;
            if (neu < cell.strength)
            {
                weaker = true;
            }
        }
        else if (cell.state == BState::Conflict)
        {
            blocked = true;
        }
    }
    if (weaker)
    {
        return false;
    }
    if (code_hit || data_hit || blocked)
    {
        if (code_hit || data_hit)
        {
            conflict_overlaps(head.v, len, why, true);
        }
        check_invariants();
        return false;
    }

    const uint16_t flags = claim_flags(why.strength);
    for (uint32_t k = 0; k < len; ++k)
    {
        const uint32_t index = head.v + k;
        ByteCell cell{};
        cell.state = (k == 0u) ? BState::CodeHead : BState::CodeTail;
        cell.strength = neu;
        cell.sub = 0;
        cell.dtype_or_pad = 0;
        cell.flags = flags;
        cell.item = item;
        cells_[index] = cell;
        unit_of_[index] = why.unit;
        span_[index] = len;
    }
    JournalRow row{};
    row.unit = why.unit;
    row.begin = head.v;
    row.len = len;
    row.item = item;
    row.state = BState::CodeHead;
    journal_.push_back(row);
    check_invariants();
    return true;
}

inline bool ByteMap::claim_data(Lin at, uint32_t len, DType t, uint32_t item, const Fact& why)
{
    if (!promotes(why.strength))
    {
        return false;
    }
    if (!range_inside(at.v, len))
    {
        return false;
    }

    const uint8_t neu = static_cast<uint8_t>(why.strength);
    bool weaker = false;
    bool code_hit = false;
    bool occupied = false;
    for (uint32_t k = 0; k < len; ++k)
    {
        const ByteCell& cell = cells_[at.v + k];
        if (cell.state == BState::CodeHead || cell.state == BState::CodeTail)
        {
            code_hit = true;
            if (neu < cell.strength)
            {
                weaker = true;
            }
        }
        else if (cell.state == BState::Data || cell.state == BState::Conflict)
        {
            occupied = true;
        }
    }
    if (weaker)
    {
        return false;
    }
    if (code_hit)
    {
        conflict_overlaps(at.v, len, why, false);
        check_invariants();
        return false;
    }
    if (occupied)
    {
        return false;
    }

    const uint16_t flags = claim_flags(why.strength);
    const uint8_t dtype = static_cast<uint8_t>(t);
    for (uint32_t k = 0; k < len; ++k)
    {
        const uint32_t index = at.v + k;
        ByteCell cell{};
        cell.state = BState::Data;
        cell.strength = neu;
        cell.sub = 0;
        cell.dtype_or_pad = dtype;
        cell.flags = flags;
        cell.item = item;
        cells_[index] = cell;
        unit_of_[index] = why.unit;
        span_[index] = 0;
    }
    JournalRow row{};
    row.unit = why.unit;
    row.begin = at.v;
    row.len = len;
    row.item = item;
    row.state = BState::Data;
    journal_.push_back(row);
    check_invariants();
    return true;
}

inline bool ByteMap::claim_padding(Lin at, uint32_t len, PadKind k, const Fact& why)
{
    if (!promotes(why.strength))
    {
        return false;
    }
    if (!range_inside(at.v, len))
    {
        return false;
    }

    const uint8_t neu = static_cast<uint8_t>(why.strength);
    for (uint32_t i = 0; i < len; ++i)
    {
        const ByteCell& cell = cells_[at.v + i];
        if (cell.state == BState::CodeHead
            || cell.state == BState::CodeTail
            || cell.state == BState::Data
            || cell.state == BState::Conflict)
        {
            return false;
        }
        if (cell.state == BState::Padding && neu < cell.strength)
        {
            return false;
        }
    }

    const uint16_t flags = claim_flags(why.strength);
    const uint8_t kind = static_cast<uint8_t>(k);
    for (uint32_t i = 0; i < len; ++i)
    {
        const uint32_t index = at.v + i;
        ByteCell cell{};
        cell.state = BState::Padding;
        cell.strength = neu;
        cell.sub = 0;
        cell.dtype_or_pad = kind;
        cell.flags = flags;
        cell.item = 0;
        cells_[index] = cell;
        unit_of_[index] = why.unit;
        span_[index] = 0;
    }
    JournalRow row{};
    row.unit = why.unit;
    row.begin = at.v;
    row.len = len;
    row.item = 0;
    row.state = BState::Padding;
    journal_.push_back(row);
    check_invariants();
    return true;
}

inline void ByteMap::retract(uint32_t unit)
{
    if (unit == 0u)
    {
        return;
    }
    const uint32_t n = static_cast<uint32_t>(cells_.size());
    for (const JournalRow& row : journal_)
    {
        if (row.unit != unit || row.begin >= n)
        {
            continue;
        }
        const uint64_t sum = static_cast<uint64_t>(row.begin) + static_cast<uint64_t>(row.len);
        const uint64_t capped = (sum > static_cast<uint64_t>(n))
                                    ? static_cast<uint64_t>(n)
                                    : sum;
        const uint32_t end = static_cast<uint32_t>(capped);
        for (uint32_t i = row.begin; i < end; ++i)
        {
            if (unit_of_[i] == unit)
            {
                cells_[i] = ByteCell{};
                unit_of_[i] = 0;
                span_[i] = 0;
            }
        }
    }
    std::erase_if(journal_,
                  [unit](const JournalRow& row)
                  {
                      return row.unit == unit;
                  });
    check_invariants();
}

inline const ByteCell& ByteMap::at(Lin lin) const
{
    if (lin.v >= cells_.size())
    {
        static const ByteCell k_unknown{};
        return k_unknown;
    }
    return cells_[lin.v];
}

inline uint32_t ByteMap::size() const
{
    return static_cast<uint32_t>(cells_.size());
}

} /* namespace dx */

#endif /* BYTEMAP_H */
