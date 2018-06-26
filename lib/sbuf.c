/*
 * Simple string buffer
 *
 * Copyright (C) 2017 Christian Franke
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <zebra.h>

#include "sbuf.h"
#include "memory.h"

void sbuf_init(struct sbuf *dest, char *buf, size_t size)
{
	dest->fixed = (size > 0);
	if (dest->fixed) {
		dest->buf = buf;
		dest->size = size;
	} else {
		dest->buf = XMALLOC(MTYPE_TMP, 4096);
		dest->size = 4096;
	}

	dest->pos = 0;
	dest->buf[0] = '\0';
}

void sbuf_reset(struct sbuf *dest)
{
	dest->pos = 0;
	dest->buf[0] = '\0';
}

const char *sbuf_buf(struct sbuf *buf)
{
	return buf->buf;
}

void sbuf_free(struct sbuf *buf)
{
	if (!buf->fixed)
		XFREE(MTYPE_TMP, buf->buf);
}

void sbuf_push(struct sbuf *buf, int indent, const char *format, ...)
{
	va_list args;
	int written;

	if (!buf->fixed) {
		int written1, written2;
		size_t new_size;

		written1 = indent;
		va_start(args, format);
		written2 = vsnprintf(NULL, 0, format, args);
		va_end(args);

		new_size = buf->size;
		if (written1 >= 0 && written2 >= 0) {
			while (buf->pos + written1 + written2 >= new_size)
				new_size *= 2;
			if (new_size > buf->size) {
				buf->buf =
					XREALLOC(MTYPE_TMP, buf->buf, new_size);
				buf->size = new_size;
			}
		}
	}

	written = snprintf(buf->buf + buf->pos, buf->size - buf->pos, "%*s",
			   indent, "");

	if (written >= 0)
		buf->pos += written;
	if (buf->pos > buf->size)
		buf->pos = buf->size;

	va_start(args, format);
	written = vsnprintf(buf->buf + buf->pos, buf->size - buf->pos, format,
			    args);
	va_end(args);

	if (written >= 0)
		buf->pos += written;
	if (buf->pos > buf->size)
		buf->pos = buf->size;

	if (buf->pos == buf->size)
		assert(!"Buffer filled up!");
}
