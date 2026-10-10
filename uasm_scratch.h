/**
 * @file uasm_scratch.h
 * @brief UASM scratch-directory template and rejected-candidate wording.
 *
 * Pure helpers. They do not spawn an assembler and do not include the CFG.
 */
#ifndef UASM_SCRATCH_H
#define UASM_SCRATCH_H

#include <cstddef>
#include <cstring>
#include <format>
#include <string>
#include <sys/stat.h>

/// Bytes available for an mkdtemp template, including the terminating NUL.
inline constexpr size_t kListingUasmScratchBound = 4096;

/**
 * @brief Build the mkdtemp template for one UASM scratch directory.
 *
 * @p tmpdir is used only when it is non-empty, absolute (leading '/'), and an
 * existing directory. One trailing slash is removed. The template is then
 * `{dir}/dumpexe-uasm-XXXXXX`. A relative path, a missing path, a non-directory,
 * or a joined path that does not fit in #kListingUasmScratchBound or in @p n
 * selects `/tmp/dumpexe-uasm-XXXXXX`.
 *
 * @param[in]  tmpdir TMPDIR value, or nullptr when the variable is unset.
 *                    Not modified. May be nullptr.
 * @param[out] buf    Writable template buffer. When this returns false and
 *                    @p n is non-zero, @p buf is set to an empty string.
 * @param[in]  n      Size of @p buf in bytes, including the terminating NUL.
 *
 * @retval true  @p buf holds a NUL-terminated mkdtemp template.
 * @retval false @p buf is nullptr, or even the /tmp template does not fit.
 *
 * @note Does not create the directory. The caller treats mkdtemp failure as
 *       "not ready" and still destroys nothing.
 * @warning @p buf and @p tmpdir must not overlap.
 */
static inline bool listing_uasm_scratch_template(const char* tmpdir,
                                                 char* buf,
                                                 size_t n)
{
    constexpr char kFallback[] = "/tmp/dumpexe-uasm-XXXXXX";
    constexpr size_t kFallbackLen = sizeof(kFallback) - 1U;
    constexpr char kLeaf[] = "/dumpexe-uasm-XXXXXX";
    constexpr size_t kLeafLen = sizeof(kLeaf) - 1U;

    if (buf == nullptr)
    {
        return false;
    }
    if (n < kFallbackLen + 1U)
    {
        if (n > 0U)
        {
            buf[0] = '\0';
        }
        return false;
    }

    const auto use_fallback = [&]() -> bool
    {
        std::memcpy(buf, kFallback, kFallbackLen + 1U);
        return true;
    };

    // Empty and relative values are not absolute paths.
    if (tmpdir == nullptr || tmpdir[0] != '/')
    {
        return use_fallback();
    }

    size_t raw_len = 0U;
    while (raw_len < kListingUasmScratchBound && tmpdir[raw_len] != '\0')
    {
        ++raw_len;
    }
    // No NUL inside the bound: the joined template cannot fit.
    if (raw_len == 0U || raw_len == kListingUasmScratchBound)
    {
        return use_fallback();
    }

    char dir[kListingUasmScratchBound] = {};
    std::memcpy(dir, tmpdir, raw_len);
    dir[raw_len] = '\0';
    size_t len = raw_len;
    // One trailing slash only. "/" becomes empty and is stat'd as root.
    // A second slash stays so the caller's path is not rewritten further.
    if (dir[len - 1U] == '/')
    {
        dir[len - 1U] = '\0';
        --len;
    }

    const size_t joined = len + kLeafLen;
    if (joined + 1U > kListingUasmScratchBound || joined + 1U > n)
    {
        return use_fallback();
    }

    const char* stat_path = dir;
    if (len == 0U)
    {
        stat_path = "/";
    }
    struct stat st = {};
    if (::stat(stat_path, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        return use_fallback();
    }

    if (len > 0U)
    {
        std::memcpy(buf, dir, len);
    }
    std::memcpy(buf + len, kLeaf, kLeafLen + 1U);
    return true;
}

/**
 * @brief Wording for an assembler-rejected count.
 *
 * The noun is "candidate" only when @p rejected is 1. Every other count,
 * including 0, stays "candidates". A positive @p unverified is appended.
 * This is not the separate "; NOT VERIFIED (0 candidates)" sentence.
 *
 * @param[in] rejected   How many candidates the assembler rejected.
 * @param[in] unverified How many candidates were left unverified.
 *                       Zero omits the unverified clause.
 * @return Phrase beginning with "assembler rejected".
 */
static inline std::string listing_uasm_rejected_clause(size_t rejected,
                                                       size_t unverified)
{
    const char* noun = "candidates";
    if (rejected == 1U)
    {
        noun = "candidate";
    }
    if (unverified > 0U)
    {
        return std::format("assembler rejected {} {}, unverified {}",
                           rejected,
                           noun,
                           unverified);
    }
    return std::format("assembler rejected {} {}", rejected, noun);
}

#endif
