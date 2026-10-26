/**
 * @file mz_pages.h
 * @brief DOS MZ page-count fields (e_cblp, e_cp) from a file size.
 */
#ifndef BIN2EXE_MZ_PAGES_H
#define BIN2EXE_MZ_PAGES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Fill the MZ last-page and page-count fields for a file size.
 *
 * DOS treats e_cblp 0 as a full last 512-byte page. A non-zero e_cblp is
 * the used byte count of the last page, and e_cp counts that partial page.
 *
 * @param[in]  file_size File length in bytes.
 * @param[out] cblp      e_cblp. Unchanged on failure.
 * @param[out] cp        e_cp. Unchanged on failure.
 *
 * @retval  0  Both fields were written.
 * @retval -1  @p cblp or @p cp is NULL, @p file_size is 0, or the size
 *             needs more than 65535 pages (512 * 65535 bytes).
 *
 * @note No allocation. Safe to call from a signal-free single thread or
 *       concurrently on distinct outputs.
 */
int mz_page_fields(uint32_t file_size, uint16_t *cblp, uint16_t *cp);

#ifdef __cplusplus
}
#endif

#endif /* BIN2EXE_MZ_PAGES_H */
