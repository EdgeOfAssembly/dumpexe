// unpack_host.c — drive Deark's EXEPACK, LZEXE, PKLITE, DIET, and LHA modules
// and return one memory image. Deark is MIT; see third_party/deark/COPYING.
// Copyright (C) 2016-2026 Jason Summers <jason1@pobox.com>
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

#include "unpack.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "deark-config.h"
#include "deark-private.h"
#include "dx_capture.h"

void de_module_exepack(deark *c, struct deark_module_info *mi);
void de_module_lzexe(deark *c, struct deark_module_info *mi);
void de_module_pklite(deark *c, struct deark_module_info *mi);
void de_module_diet(deark *c, struct deark_module_info *mi);
void de_module_lha(deark *c, struct deark_module_info *mi);

static struct dx_capture *g_cap = NULL;

void de_vsnprintf(char *buf, size_t buflen, const char *fmt, va_list ap)
{
    if (!buf || buflen == 0)
    {
        return;
    }
    vsnprintf(buf, buflen, fmt, ap);
    buf[buflen - 1] = '\0';
}

i64 de_strtoll(const char *string, char **endptr, int base)
{
    return strtoll(string ? string : "", endptr, base);
}

int de_fseek(FILE *fp, i64 offs, int whence)
{
    if (!fp)
    {
        return -1;
    }
    return fseeko(fp, (off_t)offs, whence);
}

i64 de_ftell(FILE *fp)
{
    if (!fp)
    {
        return -1;
    }
    return (i64)ftello(fp);
}

void de_exitprocess(int status)
{
    struct dx_capture *cap;

    (void)status;
    cap = g_cap;
    if (cap && cap->magic == DX_CAPTURE_MAGIC && cap->jmp_ready)
    {
        /* One jump only. A nested fatal during cleanup must return. */
        cap->jmp_ready = 0;
        longjmp(cap->jmp, 1);
    }
}

FILE *de_fopen_for_write(deark *c, const char *fn, char *errmsg, size_t errmsg_len,
    int overwrite_mode, UI flags)
{
    (void)c;
    (void)fn;
    (void)overwrite_mode;
    (void)flags;
    if (errmsg && errmsg_len > 0)
    {
        de_strlcpy(errmsg, "output is captured in memory", errmsg_len);
    }
    return NULL;
}

int de_fclose(FILE *fp)
{
    if (!fp)
    {
        return 0;
    }
    return fclose(fp);
}

void de_update_file_attribs1(dbuf *f)
{
    (void)f;
}

void de_update_file_attribs2(dbuf *f)
{
    (void)f;
}

int de_zip_create_file(deark *c)
{
    if (c)
    {
        de_err(c, "ZIP output is not available");
    }
    return 0;
}

void de_zip_add_file_to_archive(deark *c, dbuf *f)
{
    (void)f;
    if (c)
    {
        de_err(c, "ZIP output is not available");
    }
}

void de_zip_close_file(deark *c)
{
    (void)c;
}

int de_tar_create_file(deark *c)
{
    if (c)
    {
        de_err(c, "TAR output is not available");
    }
    return 0;
}

void de_tar_start_member_file(deark *c, dbuf *f)
{
    (void)f;
    if (c)
    {
        de_err(c, "TAR output is not available");
    }
}

void de_tar_end_member_file(deark *c, dbuf *f)
{
    (void)c;
    (void)f;
}

void de_tar_close_file(deark *c)
{
    (void)c;
}

int de_cp932_lookup(deark *c, u16 n, UI flags, de_rune *pr1, de_rune *pr2)
{
    (void)c;
    (void)flags;
    if (pr2)
    {
        *pr2 = 0;
    }
    if (!pr1)
    {
        return 0;
    }
    if (n < 0x80)
    {
        *pr1 = (de_rune)n;
        return 1;
    }
    *pr1 = 0xFFFD;
    return 1;
}

void de_set_ext_option(deark *c, const char *name, const char *val)
{
    int n;

    if (!c || !name || !val)
    {
        return;
    }
    n = c->num_ext_options;
    if (n >= DE_MAX_EXT_OPTIONS)
    {
        return;
    }
    c->ext_option[n].name = de_strdup(c, name);
    c->ext_option[n].val = de_strdup(c, val);
    c->num_ext_options++;
}

static void dx_msg_quiet(deark *c, UI flags, const char *s)
{
    (void)c;
    (void)flags;
    (void)s;
}

static void dx_on_fatal(deark *c)
{
    struct dx_capture *cap;

    cap = NULL;
    if (c && c->userdata)
    {
        cap = (struct dx_capture *)c->userdata;
    }
    if (!cap)
    {
        cap = g_cap;
    }
    if (cap && cap->magic == DX_CAPTURE_MAGIC && cap->jmp_ready)
    {
        cap->jmp_ready = 0;
        longjmp(cap->jmp, 1);
    }
}

int dx_capture_active(struct deark_struct *c)
{
    struct dx_capture *cap;

    if (!c || !c->userdata)
    {
        return 0;
    }
    cap = (struct dx_capture *)c->userdata;
    return cap->magic == DX_CAPTURE_MAGIC;
}

static void *dx_xrealloc(void *p, size_t nbytes)
{
    void *n;

    if (nbytes == 0)
    {
        nbytes = 1;
    }
    n = realloc(p, nbytes);
    if (!n)
    {
        de_fatalerror(NULL);
    }
    return n;
}

void dx_capture_track(struct deark_struct *c, struct dbuf_struct *f,
    const char *name, int is_dir)
{
    struct dx_capture *cap;
    struct dx_cap_track *t;
    int next;

    if (!dx_capture_active(c) || !f)
    {
        return;
    }
    cap = (struct dx_capture *)c->userdata;
    if (cap->ntracks >= cap->track_cap)
    {
        next = cap->track_cap > 0 ? cap->track_cap * 2 : 8;
        cap->tracks = dx_xrealloc(cap->tracks,
            (size_t)next * sizeof(struct dx_cap_track));
        cap->track_cap = next;
    }
    t = &cap->tracks[cap->ntracks++];
    t->f = f;
    t->name = strdup(name ? name : "");
    t->is_dir = is_dir ? 1 : 0;
    t->committed = 0;
    if (!t->name)
    {
        de_fatalerror(c);
    }
}

void dx_capture_commit(struct deark_struct *c, struct dbuf_struct *f)
{
    struct dx_capture *cap;
    struct dx_cap_file *dst;
    const struct dx_cap_track *t;
    int i;
    int next;
    size_t nbytes;

    if (!dx_capture_active(c) || !f)
    {
        return;
    }
    cap = (struct dx_capture *)c->userdata;
    t = NULL;
    for (i = 0; i < cap->ntracks; i++)
    {
        if (cap->tracks[i].f == f && !cap->tracks[i].committed)
        {
            t = &cap->tracks[i];
            cap->tracks[i].committed = 1;
            break;
        }
    }
    if (!t)
    {
        return;
    }
    if (f->btype != DBUF_TYPE_MEMBUF || f->len < 0)
    {
        return;
    }
    if ((uint64_t)f->len > (uint64_t)DX_UNPACK_MAX_BYTES)
    {
        de_fatalerror(c);
    }
    nbytes = (size_t)f->len;
    if (cap->count >= cap->cap)
    {
        next = cap->cap > 0 ? cap->cap * 2 : 8;
        cap->files = dx_xrealloc(cap->files, (size_t)next * sizeof(struct dx_cap_file));
        cap->cap = next;
    }
    dst = &cap->files[cap->count];
    memset(dst, 0, sizeof(*dst));
    dst->name = t->name ? strdup(t->name) : strdup("");
    dst->is_dir = t->is_dir;
    dst->size = nbytes;
    if (!dst->name)
    {
        de_fatalerror(c);
    }
    if (nbytes > 0)
    {
        if (!f->membuf_buf)
        {
            free(dst->name);
            dst->name = NULL;
            de_fatalerror(c);
        }
        dst->data = (uint8_t *)malloc(nbytes);
        if (!dst->data)
        {
            free(dst->name);
            dst->name = NULL;
            de_fatalerror(c);
        }
        memcpy(dst->data, f->membuf_buf, nbytes);
    }
    cap->count++;
}

static void dx_capture_free_all(struct dx_capture *cap)
{
    int i;

    if (!cap)
    {
        return;
    }
    for (i = 0; i < cap->count; i++)
    {
        free(cap->files[i].data);
        free(cap->files[i].name);
        cap->files[i].data = NULL;
        cap->files[i].name = NULL;
    }
    free(cap->files);
    cap->files = NULL;
    cap->count = 0;
    cap->cap = 0;
    for (i = 0; i < cap->ntracks; i++)
    {
        free(cap->tracks[i].name);
        cap->tracks[i].name = NULL;
    }
    free(cap->tracks);
    cap->tracks = NULL;
    cap->ntracks = 0;
    cap->track_cap = 0;
}

static void dx_deark_free(deark *c)
{
    int i;

    if (!c)
    {
        return;
    }
    for (i = 0; i < c->num_ext_options; i++)
    {
        de_free(c, c->ext_option[i].name);
        de_free(c, c->ext_option[i].val);
        c->ext_option[i].name = NULL;
        c->ext_option[i].val = NULL;
    }
    c->num_ext_options = 0;
    for (i = 0; i < DE_NUM_PERSISTENT_MEM_ITEMS; i++)
    {
        de_free(c, c->persistent_item[i]);
        c->persistent_item[i] = NULL;
    }
    de_free(NULL, c);
}

static deark *dx_deark_new(struct dx_capture *cap)
{
    deark *c;

    c = de_malloc(NULL, (i64)sizeof(deark));
    c->userdata = cap;
    c->msgfn = dx_msg_quiet;
    c->fatalerrorfn = dx_on_fatal;
    c->show_infomessages = 0;
    c->show_warnings = 0;
    c->filenames_from_file = 1;
    c->max_output_files = 4096;
    c->user_set_max_output_files = 1;
    c->max_output_file_size = (i64)DX_UNPACK_MAX_BYTES;
    c->max_total_output_size = 1024LL * 1024LL * 1024LL;
    c->preserve_file_times_normally = 0;
    c->module_disposition = DE_MODDISP_EXPLICIT;
    c->output_style = DE_OUTPUTSTYLE_DIRECT;
    c->input_filename = "input.bin";
    c->host_is_le = 1;
    if (cap)
    {
        cap->dk = c;
    }
    return c;
}

enum dx_kind
{
    DX_KIND_NONE = 0,
    DX_KIND_EXEPACK,
    DX_KIND_LZ91,
    DX_KIND_LZ90,
    DX_KIND_PKLITE,
    DX_KIND_DIET,
    DX_KIND_LHA
};

static enum dx_kind dx_kind_from_name(const char *packer)
{
    if (strcmp(packer, "Microsoft EXEPACK") == 0)
    {
        return DX_KIND_EXEPACK;
    }
    if (strcmp(packer, "LZEXE 0.91") == 0)
    {
        return DX_KIND_LZ91;
    }
    if (strcmp(packer, "LZEXE 0.90") == 0)
    {
        return DX_KIND_LZ90;
    }
    if (strcmp(packer, "PKLITE") == 0 || strncmp(packer, "PKLITE ", 7) == 0)
    {
        return DX_KIND_PKLITE;
    }
    if (strcmp(packer, "DIET") == 0)
    {
        return DX_KIND_DIET;
    }
    if (strcmp(packer, "LHarc") == 0)
    {
        return DX_KIND_LHA;
    }
    return DX_KIND_NONE;
}

static void dx_fill_module(deark *c, enum dx_kind kind, struct deark_module_info *mi)
{
    memset(mi, 0, sizeof(*mi));
    switch (kind)
    {
    case DX_KIND_EXEPACK:
        de_module_exepack(c, mi);
        break;
    case DX_KIND_LZ91:
    case DX_KIND_LZ90:
        de_module_lzexe(c, mi);
        break;
    case DX_KIND_PKLITE:
        de_module_pklite(c, mi);
        break;
    case DX_KIND_DIET:
        de_module_diet(c, mi);
        break;
    case DX_KIND_LHA:
        de_module_lha(c, mi);
        break;
    case DX_KIND_NONE:
        break;
    }
}

static const char *const k_lha_meth[] = {
    "-lh0-", "-lh1-", "-lh2-", "-lh3-", "-lh4-", "-lh5-", "-lh6-", "-lh7-",
    "-lhd-", "-lz4-", "-lz5-", NULL
};

static int dx_find_meth(const uint8_t *in, size_t n, size_t from, size_t *out_pos)
{
    size_t i;
    size_t m;

    for (i = from; i + 5 <= n; i++)
    {
        for (m = 0; k_lha_meth[m]; m++)
        {
            if (memcmp(in + i, k_lha_meth[m], 5) == 0)
            {
                *out_pos = i;
                return 1;
            }
        }
    }
    return 0;
}

/**
 * Level-0 LHA headers store the method at offset 2. Scan for a real method
 * string and run only when Deark's identifier accepts the slice that starts
 * two bytes earlier.
 */
static int dx_lha_run(deark *c, const uint8_t *in, size_t n)
{
    struct deark_module_info mi;
    size_t pos;

    dx_fill_module(c, DX_KIND_LHA, &mi);
    if (!mi.identify_fn || !mi.run_fn)
    {
        return 0;
    }
    pos = 0;
    while (dx_find_meth(in, n, pos, &pos))
    {
        dbuf *parent;
        dbuf *sub;
        int id;
        size_t start;

        if (pos < 2)
        {
            pos += 1;
            continue;
        }
        start = pos - 2;
        parent = c->infile;
        sub = dbuf_open_input_subfile(parent, (i64)start, (i64)(n - start));
        c->infile = sub;
        id = mi.identify_fn(c);
        c->infile = parent;
        if (id > 0)
        {
            c->infile = sub;
            de_run_module(c, &mi, NULL, DE_MODDISP_EXPLICIT);
            c->infile = parent;
            dbuf_close(sub);
            return 1;
        }
        dbuf_close(sub);
        pos += 1;
    }
    return 0;
}

static int dx_ascii_ieq(const char *a, const char *b)
{
    while (*a && *b)
    {
        unsigned char ca;
        unsigned char cb;

        ca = (unsigned char)*a;
        cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z')
        {
            ca = (unsigned char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z')
        {
            cb = (unsigned char)(cb - 'A' + 'a');
        }
        if (ca != cb)
        {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int dx_name_exe_or_com(const char *name)
{
    const char *base;
    const char *dot;
    const char *p;

    if (!name || !name[0])
    {
        return 0;
    }
    base = name;
    for (p = name; *p; p++)
    {
        if (*p == '/' || *p == '\\' || *p == ':')
        {
            base = p + 1;
        }
    }
    dot = NULL;
    for (p = base; *p; p++)
    {
        if (*p == '.')
        {
            dot = p;
        }
    }
    if (!dot || dot == base)
    {
        return 0;
    }
    return dx_ascii_ieq(dot, ".exe") || dx_ascii_ieq(dot, ".com");
}

static int dx_starts_mz(const uint8_t *p, size_t n)
{
    if (n < 2 || !p)
    {
        return 0;
    }
    if (p[0] == 'M' && p[1] == 'Z')
    {
        return 1;
    }
    if (p[0] == 'Z' && p[1] == 'M')
    {
        return 1;
    }
    return 0;
}

static int dx_pick_output(struct dx_capture *cap, int lha_mode)
{
    int i;
    int files;
    int only;
    int named;

    files = 0;
    only = -1;
    named = -1;
    for (i = 0; i < cap->count; i++)
    {
        struct dx_cap_file *f;

        f = &cap->files[i];
        if (f->is_dir || f->size == 0 || !f->data)
        {
            continue;
        }
        if (f->size > DX_UNPACK_MAX_BYTES)
        {
            return -2;
        }
        if (named < 0 && dx_name_exe_or_com(f->name))
        {
            named = i;
        }
        if (files == 0)
        {
            only = i;
        }
        files++;
    }
    if (lha_mode)
    {
        if (named >= 0)
        {
            return named;
        }
        if (files == 1 && only >= 0 &&
            dx_starts_mz(cap->files[only].data, cap->files[only].size))
        {
            return only;
        }
        return -1;
    }
    for (i = 0; i < cap->count; i++)
    {
        if (!cap->files[i].is_dir && cap->files[i].size > 0 && cap->files[i].data)
        {
            return i;
        }
    }
    return -1;
}

/** Overlay length using the same page rule as Deark fmtutil_collect_exe_info. */
static size_t dx_mz_overlay_len(const uint8_t *in, size_t n)
{
    unsigned int lfb;
    unsigned int nblocks;
    uint64_t end;

    if (!in || n < 6)
    {
        return 0;
    }
    lfb = (unsigned int)in[2] | ((unsigned int)in[3] << 8);
    nblocks = ((unsigned int)in[4] | ((unsigned int)in[5] << 8)) & 0x7ffu;
    end = (uint64_t)nblocks * 512u;
    if (lfb >= 1 && lfb <= 511)
    {
        if (end < 512)
        {
            return 0;
        }
        end = end - 512u + (uint64_t)lfb;
    }
    if (end > (uint64_t)n)
    {
        return 0;
    }
    return (size_t)((uint64_t)n - end);
}

static void dx_strip_lz91_overlay(const uint8_t *in, size_t n, struct dx_unpack_out *out)
{
    size_t ov;

    ov = dx_mz_overlay_len(in, n);
    if (ov == 0 || !out->data || out->size < ov || n < ov)
    {
        return;
    }
    if (memcmp(out->data + (out->size - ov), in + (n - ov), ov) == 0)
    {
        out->size -= ov;
    }
}

static int dx_steal(struct dx_capture *cap, int index, struct dx_unpack_out *out)
{
    struct dx_cap_file *f;

    if (index < 0 || index >= cap->count)
    {
        return DX_UNPACK_FAIL;
    }
    f = &cap->files[index];
    if (!f->data || f->size == 0 || f->size > DX_UNPACK_MAX_BYTES)
    {
        return f->size > DX_UNPACK_MAX_BYTES ? DX_UNPACK_TOO_BIG : DX_UNPACK_FAIL;
    }
    out->data = f->data;
    out->size = f->size;
    f->data = NULL;
    out->name[0] = '\0';
    if (f->name)
    {
        de_strlcpy(out->name, f->name, sizeof(out->name));
    }
    return DX_UNPACK_OK;
}

static int dx_unpack_body(const char *packer, const uint8_t *in, size_t n,
    struct dx_unpack_out *out, struct dx_capture *cap)
{
    deark *c;
    enum dx_kind kind;
    struct deark_module_info mi;
    int rc;
    int pick;
    int ran;

    c = NULL;
    rc = DX_UNPACK_FAIL;
    kind = dx_kind_from_name(packer);
    if (kind == DX_KIND_NONE || n > (size_t)0x7fffffff)
    {
        goto done;
    }

    c = dx_deark_new(cap);
    c->infile = dbuf_create_membuf(c, (i64)n > 0 ? (i64)n : 1, 0);
    if (n > 0)
    {
        dbuf_write(c->infile, in, (i64)n);
    }

    ran = 0;
    if (kind == DX_KIND_LHA)
    {
        ran = dx_lha_run(c, in, n);
    }
    else
    {
        dx_fill_module(c, kind, &mi);
        if (!mi.run_fn)
        {
            goto done;
        }
        if (kind == DX_KIND_LZ91)
        {
            de_set_ext_option(c, "execomp:align", "512");
        }
        de_run_module(c, &mi, NULL, DE_MODDISP_EXPLICIT);
        ran = 1;
    }

    if (!ran || c->error_count || c->serious_error_flag)
    {
        goto done;
    }

    pick = dx_pick_output(cap, kind == DX_KIND_LHA);
    if (pick == -2)
    {
        rc = DX_UNPACK_TOO_BIG;
        goto done;
    }
    rc = dx_steal(cap, pick, out);
    if (rc == DX_UNPACK_OK && kind == DX_KIND_LZ91)
    {
        dx_strip_lz91_overlay(in, n, out);
        if (out->size == 0)
        {
            dx_unpack_free(out);
            rc = DX_UNPACK_FAIL;
        }
    }

done:
    cap->jmp_ready = 0;
    if (c)
    {
        if (c->infile)
        {
            dbuf_close(c->infile);
            c->infile = NULL;
        }
        dx_deark_free(c);
        cap->dk = NULL;
    }
    dx_capture_free_all(cap);
    if (rc != DX_UNPACK_OK)
    {
        dx_unpack_free(out);
    }
    return rc;
}

/* Close infile, then any output dbuf still tracked. jmp_ready is already 0. */
static void dx_close_open_dbufs(struct dx_capture *cap, deark *c)
{
    dbuf *infile;
    int i;

    if (!cap)
    {
        return;
    }
    infile = (c && c->infile) ? c->infile : NULL;
    if (infile)
    {
        for (i = 0; i < cap->ntracks; i++)
        {
            if (cap->tracks[i].f == infile)
            {
                cap->tracks[i].f = NULL;
            }
        }
        dbuf_close(infile);
        c->infile = NULL;
    }
    for (i = 0; i < cap->ntracks; i++)
    {
        dbuf *f;

        f = cap->tracks[i].f;
        cap->tracks[i].f = NULL;
        if (f)
        {
            dbuf_close(f);
        }
    }
}

int dx_unpack(const char *packer, const uint8_t *in, size_t n, struct dx_unpack_out *out)
{
    struct dx_capture cap;
    volatile int jumped;

    if (out)
    {
        out->data = NULL;
        out->size = 0;
        out->name[0] = '\0';
    }
    if (!out || !packer || (!in && n > 0))
    {
        return DX_UNPACK_FAIL;
    }

    memset(&cap, 0, sizeof(cap));
    cap.magic = DX_CAPTURE_MAGIC;
    g_cap = &cap;
    jumped = 0;
    if (setjmp(cap.jmp) != 0)
    {
        jumped = 1;
    }
    if (jumped)
    {
        deark *c;

        cap.jmp_ready = 0;
        g_cap = NULL;
        c = (deark *)cap.dk;
        dx_close_open_dbufs(&cap, c);
        dx_capture_free_all(&cap);
        dx_deark_free(c);
        cap.dk = NULL;
        dx_unpack_free(out);
        return DX_UNPACK_FAIL;
    }

    cap.jmp_ready = 1;
    {
        int rc;

        rc = dx_unpack_body(packer, in, n, out, &cap);
        cap.jmp_ready = 0;
        g_cap = NULL;
        return rc;
    }
}

void dx_unpack_free(struct dx_unpack_out *out)
{
    if (!out)
    {
        return;
    }
    free(out->data);
    out->data = NULL;
    out->size = 0;
    out->name[0] = '\0';
}
