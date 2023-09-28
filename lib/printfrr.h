// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2019  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_PRINTFRR_H
#define _FRR_PRINTFRR_H

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>

#include "compiler.h"
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

struct fmt_outpos {
	unsigned int off_start, off_end;
};

struct fbuf {
	char *buf;
	char *pos;
	size_t len;

	struct fmt_outpos *outpos;
	size_t outpos_n, outpos_i;
};

#define at(a, b) PRINTFRR(a, b)
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

#define printfrr(fmt, ...)                                                     \
	do {                                                                   \
		char buf[256], *out;                                           \
		out = asnprintfrr(MTYPE_TMP, buf, sizeof(buf), fmt,            \
				  ##__VA_ARGS__);                              \
		fputs(out, stdout);                                            \
		if (out != buf)                                                \
			XFREE(MTYPE_TMP, out);                                 \
	} while (0)

#undef at
#undef atm
#undef atn

/* extension specs must start with a capital letter (this is a restriction
 * for both performance's and human understanding's sake.)
 *
 * Note that the entire thing mostly works because a letter directly following
 * a %p print specifier is extremely unlikely to occur (why would you want to
 * print "0x12345678HELLO"?)  Normally, you'd expect spacing or punctuation
 * after a placeholder.  That also means that neither of those works well for
 * extension purposes, e.g. "%p{foo}" is reasonable to see actually used.
 *
 * TODO: would be nice to support a "%pF%dF" specifier that consumes 2
 * arguments, e.g. to pass an integer + a list of known values...  can be
 * done, but a bit tricky.
 */
#define printfrr_ext_char(ch) ((ch) >= 'A' && (ch) <= 'Z')

struct printfrr_eargs;

struct printfrr_ext {
	/* embedded string to minimize cache line pollution */
	char match[8];

	/* both can be given, if not the code continues searching
	 * (you can do %pX and %dX in 2 different entries)
	 *
	 * return value: number of bytes that would be printed if the buffer
	 * was large enough.  be careful about not under-reporting this;
	 * otherwise asnprintf() & co. will get broken.  Returning -1 means
	 * something went wrong & default %p/%d handling should be executed.
	 *
	 * to consume extra input flags after %pXY, increment *fmt.  It points
	 * at the first character after %pXY at entry.  Convention is to make
	 * those flags lowercase letters or numbers.
	 */
	ssize_t (*print_ptr)(struct fbuf *buf, struct printfrr_eargs *info,
			     const void *);
	ssize_t (*print_int)(struct fbuf *buf, struct printfrr_eargs *info,
			     uintmax_t);
};

/* additional information passed to extended formatters */

struct printfrr_eargs {
	/* position in the format string.  Points to directly after the
	 * extension specifier.  Increment when consuming extra "flag
	 * characters".
	 */
	const char *fmt;

	/* %.1234x / %.*x
	 * not POSIX compatible when used with %p, will cause warnings from
	 * GCC & clang.  Usable with %d.  Not used by the printfrr() itself
	 * for extension specifiers, so essentially available as a "free"
	 * parameter.  -1 if not specified.  Value in the format string
	 * cannot be negative, but negative values can be passed with %.*x
	 */
	int precision;

	/* %1234x / %*x
	 * regular width specification.  Internally handled by printfrr(), set
	 * to 0 if consumed by the extension in order to suppress standard
	 * width/padding behavior.  0 if not specified.
	 *
	 * NB: always positive, even if a negative value is passed in with
	 * %*x.  (The sign is used for the - flag.)
	 */
	int width;

	/* %#x
	 * "alternate representation" flag, not POSIX compatible when used
	 * with %p or %d, will cause warnings from GCC & clang.  Not used by
	 * printfrr() itself for extension specifiers.
	 */
	bool alt_repr;

	/* %-x
	 * left-pad flag.  Internally handled by printfrr() if width is
	 * nonzero.  Only use if the extension sets width to 0.
	 */
	bool leftadj;
};

/* for any extension that needs a buffer length */

static inline ssize_t printfrr_ext_len(struct printfrr_eargs *ea)
{
	ssize_t rv;

	if (ea->precision >= 0)
		rv = ea->precision;
	else if (ea->width >= 0) {
		rv = ea->width;
		ea->width = -1;
	} else
		rv = -1;

	return rv;
}

/* no locking - must be called when single threaded (e.g. at startup.)
 * this restriction hopefully won't be a huge bother considering normal usage
 * scenarios...
 */
void printfrr_ext_reg(const struct printfrr_ext *);

#define printfrr_ext_autoreg_p(matchs, print_fn)                               \
	static ssize_t print_fn(struct fbuf *, struct printfrr_eargs *,        \
				const void *);                                 \
	static const struct printfrr_ext _printext_##print_fn = {              \
		.match = matchs,                                               \
		.print_ptr = print_fn,                                         \
	};                                                                     \
	static void _printreg_##print_fn(void) __attribute__((constructor));   \
	static void _printreg_##print_fn(void)                                 \
	{                                                                      \
		printfrr_ext_reg(&_printext_##print_fn);                       \
	}                                                                      \
	MACRO_REQUIRE_SEMICOLON()

#define printfrr_ext_autoreg_i(matchs, print_fn)                               \
	static ssize_t print_fn(struct fbuf *, struct printfrr_eargs *,        \
				uintmax_t);                                    \
	static const struct printfrr_ext _printext_##print_fn = {              \
		.match = matchs,                                               \
		.print_int = print_fn,                                         \
	};                                                                     \
	static void _printreg_##print_fn(void) __attribute__((constructor));   \
	static void _printreg_##print_fn(void)                                 \
	{                                                                      \
		printfrr_ext_reg(&_printext_##print_fn);                       \
	}                                                                      \
	MACRO_REQUIRE_SEMICOLON()

/* fbuf helper functions - note all 3 of these return the length that would
 * be written regardless of how much space was available in the buffer, as
 * needed for implementing printfrr extensions.  (They also accept NULL buf
 * for that.)
 */

static inline ssize_t bputs(struct fbuf *buf, const char *str)
{
	size_t len = strlen(str);
	size_t ncopy;

	if (!buf)
		return len;

	ncopy = MIN(len, (size_t)(buf->buf + buf->len - buf->pos));
	memcpy(buf->pos, str, ncopy);
	buf->pos += ncopy;

	return len;
}

static inline ssize_t bputch(struct fbuf *buf, char ch)
{
	if (buf && buf->pos < buf->buf + buf->len)
		*buf->pos++ = ch;
	return 1;
}

static inline ssize_t bputhex(struct fbuf *buf, uint8_t val)
{
	static const char hexch[] = "0123456789abcdef";

	if (buf && buf->pos < buf->buf + buf->len)
		*buf->pos++ = hexch[(val >> 4) & 0xf];
	if (buf && buf->pos < buf->buf + buf->len)
		*buf->pos++ = hexch[val & 0xf];
	return 2;
}

/* %pVA extension, equivalent to Linux kernel %pV */

struct va_format {
	const char *fmt;
	va_list *va;
};

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pFB" (struct fbuf *)
#pragma FRR printfrr_ext "%pVA" (struct va_format *)

#pragma FRR printfrr_ext "%pHX" (signed char *)
#pragma FRR printfrr_ext "%pHX" (unsigned char *)
#pragma FRR printfrr_ext "%pHX" (void *)
#pragma FRR printfrr_ext "%pHS" (signed char *)
#pragma FRR printfrr_ext "%pHS" (unsigned char *)
#pragma FRR printfrr_ext "%pHS" (void *)

#pragma FRR printfrr_ext "%pSE" (char *)
#pragma FRR printfrr_ext "%pSQ" (char *)

#pragma FRR printfrr_ext "%pTS" (struct timespec *)
#pragma FRR printfrr_ext "%pTV" (struct timeval *)
#pragma FRR printfrr_ext "%pTT" (time_t *)
#endif

/* when using non-ISO-C compatible extension specifiers... */

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#define FMT_NSTD_BEGIN
#define FMT_NSTD_END
#else /* !_FRR_ATTRIBUTE_PRINTFRR */
#define FMT_NSTD_BEGIN \
	_Pragma("GCC diagnostic push")                                         \
	_Pragma("GCC diagnostic ignored \"-Wformat\"")                         \
	/* end */
#define FMT_NSTD_END \
	_Pragma("GCC diagnostic pop")                                          \
	/* end */
#endif

#define FMT_NSTD(expr)                                                         \
	({                                                                     \
		FMT_NSTD_BEGIN                                                 \
		typeof(expr) _v;                                               \
		_v = expr;                                                     \
		FMT_NSTD_END                                                   \
		_v;                                                            \
	})                                                                     \
	/* end */

#ifdef __cplusplus
}
#endif

#endif
