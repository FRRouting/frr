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

#include <string.h>

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
