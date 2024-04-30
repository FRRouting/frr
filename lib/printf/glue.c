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
#include <wchar.h>

#include "printfrr.h"
#include "printflocal.h"

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
	if (len < 0) {
		va_end(ap2);
		/* error = malformed format string => try something useful */
		return qstrdup(mt, fmt);
	}

	if ((size_t)len >= outsz - 1) {
		ret = qmalloc(mt, len + 1);
		fb.buf = fb.pos = ret;
		fb.len = len;

		vbprintfrr(&fb, fmt, ap2);
	}

	va_end(ap2);
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

/* Q: WTF?
 * A: since printf should be reasonably fast (think debugging logs), the idea
 *    here is to keep things close by each other in a cacheline.  That's why
 *    ext_quick just has the first 2 characters of an extension, and we do a
 *    nice linear continuous sweep.  Only if we find something, we go do more
 *    expensive things.
 *
 * Q: doesn't this need a mutex/lock?
 * A: theoretically, yes, but that's quite expensive and I rather elide that
 *    necessity by putting down some usage rules.  Just call this at startup
 *    while singlethreaded and all is fine.  Ideally, just use constructors
 *    (and make sure dlopen() doesn't mess things up...)
 */
#define MAXEXT 64

struct ext_quick {
	char fmt[2];
};

static uint8_t ext_offsets[26] __attribute__((aligned(32)));
static struct ext_quick entries[MAXEXT] __attribute__((aligned(64)));
static const struct printfrr_ext *exts[MAXEXT] __attribute__((aligned(64)));

void printfrr_ext_reg(const struct printfrr_ext *ext)
{
	uint8_t o;
	ptrdiff_t i;

	if (!printfrr_ext_char(ext->match[0]))
		return;

	o = ext->match[0] - 'A';
	for (i = ext_offsets[o];
			i < MAXEXT && entries[i].fmt[0] &&
			memcmp(entries[i].fmt, ext->match, 2) < 0;
			i++)
		;
	if (i == MAXEXT)
		return;
	for (o++; o <= 'Z' - 'A'; o++)
		ext_offsets[o]++;

	memmove(entries + i + 1, entries + i,
			(MAXEXT - i - 1) * sizeof(entries[0]));
	memmove(exts + i + 1, exts + i,
			(MAXEXT - i - 1) * sizeof(exts[0]));

	memcpy(entries[i].fmt, ext->match, 2);
	exts[i] = ext;
}

ssize_t printfrr_extp(struct fbuf *buf, struct printfrr_eargs *ea,
		      const void *ptr)
{
	const char *fmt = ea->fmt;
	const struct printfrr_ext *ext;
	size_t i;

	for (i = ext_offsets[fmt[0] - 'A']; i < MAXEXT; i++) {
		if (!entries[i].fmt[0] || entries[i].fmt[0] > fmt[0])
			return -1;
		if (entries[i].fmt[1] && entries[i].fmt[1] != fmt[1])
			continue;
		ext = exts[i];
		if (!ext->print_ptr)
			continue;
		if (strncmp(ext->match, fmt, strlen(ext->match)))
			continue;
		ea->fmt += strlen(ext->match);
		return ext->print_ptr(buf, ea, ptr);
	}
	return -1;
}

ssize_t printfrr_exti(struct fbuf *buf, struct printfrr_eargs *ea,
		      uintmax_t num)
{
	const char *fmt = ea->fmt;
	const struct printfrr_ext *ext;
	size_t i;

	for (i = ext_offsets[fmt[0] - 'A']; i < MAXEXT; i++) {
		if (!entries[i].fmt[0] || entries[i].fmt[0] > fmt[0])
			return -1;
		if (entries[i].fmt[1] && entries[i].fmt[1] != fmt[1])
			continue;
		ext = exts[i];
		if (!ext->print_int)
			continue;
		if (strncmp(ext->match, fmt, strlen(ext->match)))
			continue;
		ea->fmt += strlen(ext->match);
		return ext->print_int(buf, ea, num);
	}
	return -1;
}

printfrr_ext_autoreg_p("FB", printfrr_fb);
static ssize_t printfrr_fb(struct fbuf *out, struct printfrr_eargs *ea,
			   const void *ptr)
{
	const struct fbuf *in = ptr;
	ptrdiff_t copy_len;

	if (!in)
		return bputs(out, "NULL");

	if (out) {
		copy_len = MIN(in->pos - in->buf,
			       out->buf + out->len - out->pos);
		if (copy_len > 0) {
			memcpy(out->pos, in->buf, copy_len);
			out->pos += copy_len;
		}
	}

	return in->pos - in->buf;
}

printfrr_ext_autoreg_p("VA", printfrr_va);
static ssize_t printfrr_va(struct fbuf *buf, struct printfrr_eargs *ea,
			   const void *ptr)
{
	const struct va_format *vaf = ptr;
	va_list ap;

	if (!vaf || !vaf->fmt || !vaf->va)
		return bputs(buf, "NULL");

	/* make sure we don't alter the data passed in - especially since
	 * bprintfrr (and thus this) might be called on the same format twice,
	 * when allocating a larger buffer in asnprintfrr()
	 */
	va_copy(ap, *vaf->va);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	/* can't format check this */
	return vbprintfrr(buf, vaf->fmt, ap);
#pragma GCC diagnostic pop
}
