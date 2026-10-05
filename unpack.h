// unpack.h — in-memory unpack of DOS packers detected by dumpexe.
// The decompressors are adapted from Deark (MIT).
// Copyright (C) 2016-2026 Jason Summers <jason1@pobox.com>
// See third_party/deark/COPYING.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef DX_UNPACK_H
#define DX_UNPACK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Success. @c out->data is malloc'd and owned by the caller. */
#define DX_UNPACK_OK 0
/** The packer was not accepted or decompression did not finish. */
#define DX_UNPACK_FAIL 1
/** The unpacked image is larger than DX_UNPACK_MAX_BYTES. */
#define DX_UNPACK_TOO_BIG 2

/**
 * @brief Largest unpacked image that may be returned.
 *
 * A buffer of this size is allowed. One byte more is a failure, not a
 * truncated file.
 */
#define DX_UNPACK_MAX_BYTES ((size_t)16 * 1024u * 1024u)

/** Bytes returned by dx_unpack. */
struct dx_unpack_out
{
    uint8_t *data; /**< Owned image, or NULL. */
    size_t size;   /**< Logical length of @c data. */
    char name[256]; /**< Member name when the packer stored one. */
};

/**
 * @brief Unpack a memory image for a dumpexe structural packer name.
 *
 * Recognized names: Microsoft EXEPACK, LZEXE 0.91, LZEXE 0.90, PKLITE,
 * PKLITE M.mm, DIET, LHarc. Any other name fails.
 *
 * LZEXE 0.91 is produced with 512-byte code alignment. A trailing overlay
 * that is a byte-for-byte copy of the packed file's overlay is removed so
 * the image matches classic unlzexe output.
 *
 * @param packer Structural packer name. Not NULL.
 * @param in Packed file bytes. Not retained. Not NULL.
 * @param n Length of @p in.
 * @param out Receives the image on success. Not NULL.
 *            On failure, @c data is NULL and @c size is 0.
 * @return DX_UNPACK_OK, DX_UNPACK_FAIL, or DX_UNPACK_TOO_BIG.
 *
 * @note Does not call exit or abort, and does not fopen the destination.
 *       The caller writes the file after this returns OK.
 */
int dx_unpack(const char *packer, const uint8_t *in, size_t n,
    struct dx_unpack_out *out);

/**
 * @brief Release an image returned by dx_unpack.
 *
 * Safe when @p out is NULL, already freed, or was never filled.
 *
 * @param out Result structure. @c data is set to NULL.
 */
void dx_unpack_free(struct dx_unpack_out *out);

#ifdef __cplusplus
}
#endif

#endif
