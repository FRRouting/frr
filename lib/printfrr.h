/*
 * Copyright (c) 2019  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _FRR_PRINTFRR_H
#define _FRR_PRINTFRR_H

#include <stddef.h>
#include <stdarg.h>

#include "compiler.h"
#include "memory.h"

struct fbuf {
	char *buf;
	char *pos;
	size_t len;
};

#define at(a, b) \
	__attribute__((format(printf, a, b)))
#define atn(a, b) \
	at(a, b) __attribute__((nonnull(1) _RET_NONNULL))
#define atm(a, b) \
	atn(a, b) __attribute__((malloc))

/* return value is length needed for the full string (excluding \0) in all
 * cases.  The functions write as much as they can, but continue regardless,
 * so the return value is independent of buffer length.  Both bprintfrr and
 * snprintf also accept NULL as output buffer.
 */

/* bprintfrr does NOT null terminate! use sparingly (only provided since it's
 * the most direct interface) - useful for incrementally building long text
 * (call bprintfrr repeatedly with the same buffer)
 */
ssize_t vbprintfrr(struct fbuf *out, const char *fmt, va_list) at(2, 0);
ssize_t  bprintfrr(struct fbuf *out, const char *fmt, ...)     at(2, 3);

/* these do null terminate like their snprintf cousins */
ssize_t vsnprintfrr(char *out, size_t sz, const char *fmt, va_list) at(3, 0);
ssize_t  snprintfrr(char *out, size_t sz, const char *fmt, ...)     at(3, 4);

/* c = continue / concatenate (append at the end of the string)
 * return value is would-be string length (regardless of buffer length),
 * i.e. includes already written chars */
ssize_t vcsnprintfrr(char *out, size_t sz, const char *fmt, va_list) at(3, 0);
ssize_t  csnprintfrr(char *out, size_t sz, const char *fmt, ...)     at(3, 4);

/* memory allocations don't fail in FRR, so you always get something here.
 * (in case of error, returns a strdup of the format string) */
char *vasprintfrr(struct memtype *mt, const char *fmt, va_list) atm(2, 0);
char  *asprintfrr(struct memtype *mt, const char *fmt, ...)     atm(2, 3);

/* try to use provided buffer (presumably from stack), allocate if it's too
 * short.  Must call XFREE(mt, return value) if return value != out.
 */
char *vasnprintfrr(struct memtype *mt, char *out, size_t sz,
		   const char *fmt, va_list) atn(4, 0);
char  *asnprintfrr(struct memtype *mt, char *out, size_t sz,
		   const char *fmt, ...)     atn(4, 5);

#undef at
#undef atm

struct printfrr_ext {
	const char *match;
	const char *opts;

	union {
		ssize_t (*print_ptr)(struct fbuf *out, const char *fmt, void *);
		ssize_t (*print_int)(struct fbuf *out, const char *fmt, int);
	};
};

void printfrr_ext_reg(const struct printfrr_ext *);
void printfrr_ext_unreg(const struct printfrr_ext *);

#endif
