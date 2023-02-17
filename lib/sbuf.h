// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Simple string buffer
 *
 * Copyright (C) 2017 Christian Franke
 */
#ifndef SBUF_H
#define SBUF_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * sbuf provides a simple string buffer. One application where this comes
 * in handy is the parsing of binary data: If there is an error in the parsing
 * process due to invalid input data, printing an error message explaining what
 * went wrong is definitely useful. However, just printing the actual error,
 * without any information about the previous parsing steps, is usually not very
 * helpful.
 * Using sbuf, the parser can log the whole parsing process into a buffer using
 * a printf like API. When an error occurs, all the information about previous
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

#define SBUF_DEFAULT_SIZE 8192

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
	PRINTFRR(3, 4);

#ifdef __cplusplus
}
#endif

#endif
