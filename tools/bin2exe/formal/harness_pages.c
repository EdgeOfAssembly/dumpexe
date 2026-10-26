/**
 * @file harness_pages.c
 * @brief CBMC proof that e_cblp and e_cp round-trip a DOS file size.
 */
#include "bin2exe/mz_pages.h"

#include <stdint.h>

#ifdef __CPROVER__
uint32_t nondet_uint32_t(void);
#else
#include <assert.h>
#define __CPROVER_assert(cond, msg) assert(cond)
#define __CPROVER_assume(cond) ((void)(cond))
#endif

int main(void)
{
    uint32_t file_size = 0;
    uint16_t cblp = 0xFFFFu;
    uint16_t cp = 0xFFFFu;
    int in_range = 0;

#ifdef __CPROVER__
    file_size = nondet_uint32_t();
    in_range = nondet_uint32_t() & 1;
#else
    file_size = 37u;
    in_range = 1;
#endif

    if (in_range)
    {
        __CPROVER_assume(file_size > 0u);
        __CPROVER_assume(file_size <= 512u * 65535u);
        const int rc = mz_page_fields(file_size, &cblp, &cp);
        const uint32_t remainder = file_size % 512u;
        const uint32_t pages = (file_size + 511u) / 512u;
        const uint32_t rebuilt = (remainder == 0u)
                                     ? (uint32_t)cp * 512u
                                     : ((uint32_t)cp - 1u) * 512u + (uint32_t)cblp;
        __CPROVER_assert(rc == 0, "in-range size succeeds");
        __CPROVER_assert(cblp == (remainder == 0u ? 0u : remainder), "e_cblp");
        __CPROVER_assert(cp == pages, "e_cp");
        __CPROVER_assert(rebuilt == file_size, "page fields rebuild the size");
    }
    else
    {
        __CPROVER_assume(file_size == 0u || file_size > 512u * 65535u);
        const uint16_t cblp_before = cblp;
        const uint16_t cp_before = cp;
        const int rc = mz_page_fields(file_size, &cblp, &cp);
        __CPROVER_assert(rc == -1, "out-of-range size fails");
        __CPROVER_assert(cblp == cblp_before && cp == cp_before,
                         "failure leaves outputs unchanged");
    }
    return 0;
}
