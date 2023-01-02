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

#include "compiler.h"

#include <string.h>
#include <ctype.h>

#include "printfrr.h"

printfrr_ext_autoreg_p("HX", printfrr_hexdump)
static ssize_t printfrr_hexdump(struct fbuf *buf, struct printfrr_eargs *ea,
				const void *ptr)
{
	ssize_t ret = 0;
	ssize_t input_len = printfrr_ext_len(ea);
	char sep = ' ';
	const uint8_t *pos, *end;

	if (ea->fmt[0] == 'c') {
		ea->fmt++;
		sep = ':';
	} else if (ea->fmt[0] == 'n') {
		ea->fmt++;
		sep = '\0';
	}

	if (input_len < 0)
		return 0;

	for (pos = ptr, end = pos + input_len; pos < end; pos++) {
		if (sep && pos != ptr)
			ret += bputch(buf, sep);
		ret += bputhex(buf, *pos);
	}

	return ret;
}

/* string analog for hexdumps / the "this." in ("74 68 69 73 0a  |this.|") */

printfrr_ext_autoreg_p("HS", printfrr_hexdstr)
static ssize_t printfrr_hexdstr(struct fbuf *buf, struct printfrr_eargs *ea,
				const void *ptr)
{
	ssize_t ret = 0;
	ssize_t input_len = printfrr_ext_len(ea);
	const uint8_t *pos, *end;

	if (input_len < 0)
		return 0;

	for (pos = ptr, end = pos + input_len; pos < end; pos++) {
		if (*pos >= 0x20 && *pos < 0x7f)
			ret += bputch(buf, *pos);
		else
			ret += bputch(buf, '.');
	}

	return ret;
}

enum escape_flags {
	ESC_N_R_T	= (1 << 0),	/* use \n \r \t instead of \x0a ...*/
	ESC_SPACE	= (1 << 1),	/* \  */
	ESC_BACKSLASH	= (1 << 2),	/* \\ */
	ESC_DBLQUOTE	= (1 << 3),	/* \" */
	ESC_SGLQUOTE	= (1 << 4),	/* \' */
	ESC_BACKTICK	= (1 << 5),	/* \` */
	ESC_DOLLAR	= (1 << 6),	/* \$ */
	ESC_CLBRACKET	= (1 << 7),	/* \] for RFC5424 syslog */
	ESC_OTHER	= (1 << 8),	/* remaining non-alpha */

	ESC_ALL = ESC_N_R_T | ESC_SPACE | ESC_BACKSLASH | ESC_DBLQUOTE
		| ESC_SGLQUOTE | ESC_DOLLAR | ESC_OTHER,
	ESC_QUOTSTRING = ESC_N_R_T | ESC_BACKSLASH | ESC_DBLQUOTE,
	/* if needed: ESC_SHELL = ... */
};

static ssize_t bquote(struct fbuf *buf, const uint8_t *pos, size_t len,
		      unsigned int flags)
{
	ssize_t ret = 0;
	const uint8_t *end = pos + len;

	for (; pos < end; pos++) {
		/* here's to hoping this might be a bit faster... */
		if (__builtin_expect(!!isalnum(*pos), 1)) {
			ret += bputch(buf, *pos);
			continue;
		}

		switch (*pos) {
		case '%':
		case '+':
		case ',':
		case '-':
		case '.':
		case '/':
		case ':':
		case '@':
		case '_':
			ret += bputch(buf, *pos);
			continue;

		case '\r':
			if (!(flags & ESC_N_R_T))
				break;
			ret += bputch(buf, '\\');
			ret += bputch(buf, 'r');
			continue;
		case '\n':
			if (!(flags & ESC_N_R_T))
				break;
			ret += bputch(buf, '\\');
			ret += bputch(buf, 'n');
			continue;
		case '\t':
			if (!(flags & ESC_N_R_T))
				break;
			ret += bputch(buf, '\\');
			ret += bputch(buf, 't');
			continue;

		case ' ':
			if (flags & ESC_SPACE)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		case '\\':
			if (flags & ESC_BACKSLASH)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		case '"':
			if (flags & ESC_DBLQUOTE)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		case '\'':
			if (flags & ESC_SGLQUOTE)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		case '`':
			if (flags & ESC_BACKTICK)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		case '$':
			if (flags & ESC_DOLLAR)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		case ']':
			if (flags & ESC_CLBRACKET)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		/* remaining: !#&'()*;<=>?[^{|}~ */

		default:
			if (*pos >= 0x20 && *pos < 0x7f) {
				if (flags & ESC_OTHER)
					ret += bputch(buf, '\\');
				ret += bputch(buf, *pos);
				continue;
			}
		}
		ret += bputch(buf, '\\');
		ret += bputch(buf, 'x');
		ret += bputhex(buf, *pos);
	}

	return ret;
}

printfrr_ext_autoreg_p("SE", printfrr_escape)
static ssize_t printfrr_escape(struct fbuf *buf, struct printfrr_eargs *ea,
			       const void *vptr)
{
	ssize_t len = printfrr_ext_len(ea);
	const uint8_t *ptr = vptr;
	bool null_is_empty = false;

	if (ea->fmt[0] == 'n') {
		null_is_empty = true;
		ea->fmt++;
	}

	if (!ptr) {
		if (null_is_empty)
			return 0;
		return bputs(buf, "(null)");
	}

	if (len < 0)
		len = strlen((const char *)ptr);

	return bquote(buf, ptr, len, ESC_ALL);
}

printfrr_ext_autoreg_p("SQ", printfrr_quote)
static ssize_t printfrr_quote(struct fbuf *buf, struct printfrr_eargs *ea,
			      const void *vptr)
{
	ssize_t len = printfrr_ext_len(ea);
	const uint8_t *ptr = vptr;
	ssize_t ret = 0;
	bool null_is_empty = false;
	bool do_quotes = false;
	unsigned int flags = ESC_QUOTSTRING;

	while (ea->fmt[0]) {
		switch (ea->fmt[0]) {
		case 'n':
			null_is_empty = true;
			ea->fmt++;
			continue;
		case 'q':
			do_quotes = true;
			ea->fmt++;
			continue;
		case 's':
			flags |= ESC_CLBRACKET;
			flags &= ~ESC_N_R_T;
			ea->fmt++;
			continue;
		}
		break;
	}

	if (!ptr) {
		if (null_is_empty)
			return bputs(buf, do_quotes ? "\"\"" : "");
		return bputs(buf, "(null)");
	}

	if (len < 0)
		len = strlen((const char *)ptr);

	if (do_quotes)
		ret += bputch(buf, '"');
	ret += bquote(buf, ptr, len, flags);
	if (do_quotes)
		ret += bputch(buf, '"');
	return ret;
}
