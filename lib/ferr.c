/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
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

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

#include "ferr.h"
#include "vty.h"
#include "jhash.h"
#include "memory.h"

DEFINE_MTYPE_STATIC(LIB, ERRINFO, "error information")

static pthread_key_t errkey;

static void ferr_free(void *arg)
{
	XFREE(MTYPE_ERRINFO, arg);
}

static void err_key_init(void) __attribute__((_CONSTRUCTOR(500)));
static void err_key_init(void)
{
	pthread_key_create(&errkey, ferr_free);
}

static void err_key_fini(void) __attribute__((_DESTRUCTOR(500)));
static void err_key_fini(void)
{
	pthread_key_delete(errkey);
}

const struct ferr *ferr_get_last(ferr_r errval)
{
	struct ferr *last_error = pthread_getspecific(errkey);
	if (!last_error || last_error->kind == 0)
		return NULL;
	return last_error;
}

ferr_r ferr_clear(void)
{
	struct ferr *last_error = pthread_getspecific(errkey);
	if (last_error)
		last_error->kind = 0;
	return ferr_ok();
}

static ferr_r ferr_set_va(const char *file, int line, const char *func,
			  enum ferr_kind kind, const char *pathname,
			  int errno_val, const char *text, va_list va)
{
	struct ferr *error = pthread_getspecific(errkey);

	if (!error) {
		error = XCALLOC(MTYPE_ERRINFO, sizeof(*error));
		if (!error) {
			/* we're screwed */
			zlog_err("out of memory while allocating error info");
			raise(SIGSEGV);
			abort(); /* raise() can return, but raise(SIGSEGV) shall
				    not */
		}

		pthread_setspecific(errkey, error);
	}

	error->file = file;
	error->line = line;
	error->func = func;
	error->kind = kind;

	error->unique_id = jhash(text, strlen(text),
				 jhash(file, strlen(file), 0xd4ed0298));

	error->errno_val = errno_val;
	if (pathname)
		snprintf(error->pathname, sizeof(error->pathname), "%s",
			 pathname);
	else
		error->pathname[0] = '\0';

	vsnprintf(error->message, sizeof(error->message), text, va);
	return -1;
}

ferr_r ferr_set_internal(const char *file, int line, const char *func,
			 enum ferr_kind kind, const char *text, ...)
{
	ferr_r rv;
	va_list va;
	va_start(va, text);
	rv = ferr_set_va(file, line, func, kind, NULL, 0, text, va);
	va_end(va);
	return rv;
}

ferr_r ferr_set_internal_ext(const char *file, int line, const char *func,
			     enum ferr_kind kind, const char *pathname,
			     int errno_val, const char *text, ...)
{
	ferr_r rv;
	va_list va;
	va_start(va, text);
	rv = ferr_set_va(file, line, func, kind, pathname, errno_val, text, va);
	va_end(va);
	return rv;
}

#define REPLACE "$ERR"
void vty_print_error(struct vty *vty, ferr_r err, const char *msg, ...)
{
	char tmpmsg[512], *replacepos;
	const struct ferr *last_error = ferr_get_last(err);

	va_list va;
	va_start(va, msg);
	vsnprintf(tmpmsg, sizeof(tmpmsg), msg, va);
	va_end(va);

	replacepos = strstr(tmpmsg, REPLACE);
	if (!replacepos)
		vty_out(vty, "%s\n", tmpmsg);
	else {
		replacepos[0] = '\0';
		replacepos += sizeof(REPLACE) - 1;
		vty_out(vty, "%s%s%s\n", tmpmsg,
			last_error ? last_error->message : "(no error?)",
			replacepos);
	}
}
