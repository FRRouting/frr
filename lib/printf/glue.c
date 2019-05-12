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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <string.h>

#include "printfrr.h"

ssize_t bprintfrr(struct fbuf *out, const char *fmt, ...)
{
	ssize_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vbprintfrr(out, fmt, ap);
	va_end(ap);
	return ret;
}

ssize_t vsnprintfrr(char *out, size_t outsz, const char *fmt, va_list ap)
{
	struct fbuf fbb = { .buf = out, .pos = out, .len = outsz - 1, };
	struct fbuf *fb = (out && outsz) ? &fbb : NULL;
	ssize_t ret;

	ret = vbprintfrr(fb, fmt, ap);
	if (fb)
		fb->pos[0] = '\0';
	return ret;
}

ssize_t snprintfrr(char *out, size_t outsz, const char *fmt, ...)
{
	struct fbuf fbb = { .buf = out, .pos = out, .len = outsz - 1, };
	struct fbuf *fb = (out && outsz) ? &fbb : NULL;
	ssize_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vbprintfrr(fb, fmt, ap);
	va_end(ap);
	if (fb)
		fb->pos[0] = '\0';
	return ret;
}

ssize_t vcsnprintfrr(char *out, size_t outsz, const char *fmt, va_list ap)
{
	if (!out || !outsz)
		return vbprintfrr(NULL, fmt, ap);

	struct fbuf fbb = { .buf = out, .pos = out, .len = outsz - 1, };
	ssize_t ret;
	size_t pos;

	pos = strnlen(out, outsz);
	fbb.pos += pos;

	ret = vbprintfrr(&fbb, fmt, ap);
	fbb.pos[0] = '\0';
	return ret >= 0 ? ret + (ssize_t)pos : ret;
}

ssize_t csnprintfrr(char *out, size_t outsz, const char *fmt, ...)
{
	ssize_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vcsnprintfrr(out, outsz, fmt, ap);
	va_end(ap);
	return ret;
}

char *vasnprintfrr(struct memtype *mt, char *out, size_t outsz, const char *fmt,
		   va_list ap)
{
	struct fbuf fb = { .buf = out, .pos = out, .len = outsz - 1, };
	ssize_t len;
	va_list ap2;
	char *ret = out;

	va_copy(ap2, ap);
	len = vbprintfrr(&fb, fmt, ap);
	if (len < 0)
		/* error = malformed format string => try something useful */
		return qstrdup(mt, fmt);

	if ((size_t)len >= outsz - 1) {
		ret = qmalloc(mt, len + 1);
		fb.buf = fb.pos = ret;
		fb.len = len;

		vbprintfrr(&fb, fmt, ap2);
	}
	ret[len] = '\0';
	return ret;
}

char *asnprintfrr(struct memtype *mt, char *out, size_t outsz, const char *fmt,
		  ...)
{
	va_list ap;
	char *ret;

	va_start(ap, fmt);
	ret = vasnprintfrr(mt, out, outsz, fmt, ap);
	va_end(ap);
	return ret;
}

char *vasprintfrr(struct memtype *mt, const char *fmt, va_list ap)
{
	char buf[256];
	char *ret;

	ret = vasnprintfrr(mt, buf, sizeof(buf), fmt, ap);

	if (ret == buf)
		ret = qstrdup(mt, ret);
	return ret;
}

char *asprintfrr(struct memtype *mt, const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	char *ret;

	va_start(ap, fmt);
	ret = vasnprintfrr(mt, buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (ret == buf)
		ret = qstrdup(mt, ret);
	return ret;
}
