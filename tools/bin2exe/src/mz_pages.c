/**
 * @file mz_pages.c
 * @brief DOS MZ e_cblp / e_cp from a byte length.
 */
#include "bin2exe/mz_pages.h"

#include <stddef.h>

int mz_page_fields(uint32_t file_size, uint16_t *cblp, uint16_t *cp)
{
    const uint32_t k_page = 512u;
    const uint32_t k_max_pages = 65535u;

    if (cblp == NULL || cp == NULL)
    {
        return -1;
    }
    if (file_size == 0u || file_size > k_page * k_max_pages)
    {
        return -1;
    }

    const uint32_t remainder = file_size % k_page;
    const uint32_t pages = (file_size + (k_page - 1u)) / k_page;
    *cblp = (uint16_t)(remainder == 0u ? 0u : remainder);
    *cp = (uint16_t)pages;
    return 0;
}
