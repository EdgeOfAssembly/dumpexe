/**
 * @file facts.h
 * @brief Evidence records. A hint is stored here and does not promote bytes.
 */
#ifndef FACTS_H
#define FACTS_H

#include "image_model.h"

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace dx
{

/**
 * @brief How hard a fact is allowed to push on the byte map.
 *
 * @c Hint never changes a cell. @c kPromote is the lowest strength that may.
 */
enum class Strength : uint8_t
{
    Hint = 0,
    Likely = 1,
    Derived = 2,
    Witnessed = 3,
    Proven = 4
};

/**
 * @brief Lowest strength that may change a @c ByteMap cell.
 */
constexpr Strength kPromote = Strength::Likely;

/**
 * @brief Why a fact exists. P1 only records the edges the old walk already has.
 *
 * @c IntScan, @c Fallthrough, and @c Wrap name enqueues the walk already
 * performed. They do not add leaders. @c DirectFlow stays the @c note_insn
 * reason. Existing values are not renumbered.
 */
enum class Why : uint16_t
{
    Entry = 0,
    DirectJmp = 1,
    DirectJcc = 2,
    DirectCall = 3,
    CallFallthroughSpec = 4,
    HintIntScan = 5,
    DirectFlow = 6,
    IntScan = 7,
    Fallthrough = 8,
    Wrap = 9
};

/**
 * @brief One piece of evidence about a linear address.
 *
 * @c unit 0 is not a speculative unit. @c retract(0) ignores it.
 */
struct Fact
{
    Why why = Why::Entry;
    Strength strength = Strength::Hint;
    Lin subject{};
    Lin source{};
    uint32_t unit = 0;
    uint32_t round = 0;
    uint32_t aux = 0;
};

/**
 * @brief Append-only facts in insertion order.
 *
 * @c add records the new position under @c Fact::subject. @c at reads that
 * index and returns matches oldest first.
 */
class FactStore
{
public:
    /**
     * @brief Append @p fact and index it by subject linear.
     *
     * Does not touch a byte map. The index is what @c at searches.
     *
     * @param[in] fact Evidence record copied into the store.
     */
    void add(Fact fact);

    /**
     * @brief Facts whose subject linear equals @p subject, oldest first.
     *
     * Uses the subject index filled by @c add. It does not scan facts
     * whose linear is different.
     *
     * @param[in] subject Query linear. Compared by @c Lin::v.
     * @return Matching facts, oldest first. Empty if none match.
     */
    std::vector<Fact> at(Lin subject) const;

    /**
     * @brief Every fact in insertion order.
     *
     * @return Reference to the store's vector. Valid until the next
     *         non-const call on this store.
     */
    const std::vector<Fact>& all() const;

private:
    std::vector<Fact> facts_;
    /** Insertion-order positions of each @c Lin::v. Not a scan of @c facts_. */
    std::unordered_map<uint32_t, std::vector<std::size_t>> index_;
};

inline void FactStore::add(Fact fact)
{
    const uint32_t key = fact.subject.v;
    const std::size_t pos = facts_.size();
    facts_.push_back(fact);
    index_[key].push_back(pos);
}

inline std::vector<Fact> FactStore::at(Lin subject) const
{
    std::vector<Fact> matched;
    const auto found = index_.find(subject.v);
    if (found == index_.end())
    {
        return matched;
    }
    const std::vector<std::size_t>& positions = found->second;
    matched.reserve(positions.size());
    for (const std::size_t pos : positions)
    {
        matched.push_back(facts_[pos]);
    }
    return matched;
}

inline const std::vector<Fact>& FactStore::all() const
{
    return facts_;
}

} /* namespace dx */

#endif /* FACTS_H */
