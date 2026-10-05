// dumpexe capture shim for Deark output files.
// Deark itself is Copyright (C) 2016-2026 Jason Summers <jason1@pobox.com>.
// See ../COPYING. This shim keeps extracted bytes in memory so the library
// never fopen()s the destination the caller will write.

#ifndef DX_CAPTURE_H
#define DX_CAPTURE_H

#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>

#define DX_CAPTURE_MAGIC 0x44584331u

struct deark_struct;

struct dx_cap_file
{
    char *name;
    uint8_t *data;
    size_t size;
    int is_dir;
};

struct dx_cap_track
{
    struct dbuf_struct *f;
    char *name;
    int is_dir;
    int committed;
};

struct dx_capture
{
    unsigned magic;
    /* Pointer fields written after setjmp are volatile so longjmp can free them. */
    struct dx_cap_file *volatile files;
    volatile int count;
    volatile int cap;
    struct dx_cap_track *volatile tracks;
    volatile int ntracks;
    volatile int track_cap;
    jmp_buf jmp;
    volatile int jmp_ready;
    /* Deark object for this attempt. Heap memory; the pointer itself is volatile. */
    struct deark_struct *volatile dk;
};

int dx_capture_active(struct deark_struct *c);
void dx_capture_track(struct deark_struct *c, struct dbuf_struct *f,
    const char *name, int is_dir);
void dx_capture_commit(struct deark_struct *c, struct dbuf_struct *f);

#endif
