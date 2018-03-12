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
#ifndef SBUF_H
#define SBUF_H

/*
 * sbuf provides a simple string buffer. One application where this comes
 * in handy is the parsing of binary data: If there is an error in the parsing
 * process due to invalid input data, printing an error message explaining what
 * went wrong is definitely useful. However, just printing the actual error,
 * without any information about the previous parsing steps, is usually not very
 * helpful.
 * Using sbuf, the parser can log the whole parsing process into a buffer using
 * a printf like API. When an error ocurrs, all the information about previous
 * parsing steps is there in the log, without any need for backtracking, and can
 * be used to give a detailed and useful error description.
 * When parsing completes successfully without any error, the log can just be
 * discarded unless debugging is turned on, to not spam the log.
 *
 * For the described usecase, the code would look something like this:
 *
 * int sbuf_example(..., char **parser_log)
 * {
 *         struct sbuf logbuf;
 *
 *         sbuf_init(&logbuf, NULL, 0);
 *         sbuf_push(&logbuf, 0, "Starting parser\n");
 *
 *         int rv = do_parse(&logbuf, ...);
 *
 *         *parser_log = sbuf_buf(&logbuf);
 *
 *         return 1;
 * }
 *
 * In this case, sbuf_example uses a string buffer with undefined size, which
 * will
 * be allocated on the heap by sbuf. The caller of sbuf_example is expected to
 * free
 * the string returned in parser_log.
 */

struct sbuf {
	bool fixed;
	char *buf;
	size_t size;
	size_t pos;
	int indent;
};

void sbuf_init(struct sbuf *dest, char *buf, size_t size);
void sbuf_reset(struct sbuf *buf);
const char *sbuf_buf(struct sbuf *buf);
void sbuf_free(struct sbuf *buf);
#include "lib/log.h"
void sbuf_push(struct sbuf *buf, int indent, const char *format, ...)
	PRINTF_ATTRIBUTE(3, 4);

#endif
