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

#ifndef _FRR_FERR_H
#define _FRR_FERR_H

/***********************************************************
 * scroll down to the end of this file for a full example! *
 ***********************************************************/

#include <stdint.h>
#include <limits.h>
#include <errno.h>

/* return type when this error indication stuff is used.
 *
 * guaranteed to have boolean evaluation to "false" when OK, "true" when error
 * (i.e. can be changed to pointer in the future if neccessary)
 *
 * For checking, always use "if (value)", nothing else.
 * Do _NOT_ use any integer constant (!= 0), or sign check (< 0).
 */
typedef int ferr_r;

/* rough category of error indication */
enum ferr_kind {
	/* no error */
	FERR_OK = 0,

	/* something isn't the way it's supposed to be.
	 * (things that might otherwise be asserts, really)
	 */
	FERR_CODE_BUG,

	/* user-supplied parameters don't make sense or is inconsistent
	 * if you can express a rule for it (e.g. "holdtime > 2 * keepalive"),
	 * it's this category.
	 */
	FERR_CONFIG_INVALID,

	/* user-supplied parameters don't line up with reality
	 * (IP address or interface not available, etc.)
	 * NB: these are really TODOs where the code needs to be fixed to
	 * respond to future changes!
	 */
	FERR_CONFIG_REALITY,

	/* out of some system resource (probably memory)
	 * aka "you didn't spend enough money error" */
	FERR_RESOURCE,

	/* system error (permission denied, etc.) */
	FERR_SYSTEM,

	/* error return from some external library
	 * (FERR_SYSTEM and FERR_LIBRARY are not strongly distinct) */
	FERR_LIBRARY,
};

struct ferr {
	/* code location */
	const char *file;
	const char *func;
	int line;

	enum ferr_kind kind;

	/* unique_id is calculated as a checksum of source filename and error
	 * message format (*before* calling vsnprintf).  Line number and
	 * function name are not used; this keeps the number reasonably static
	 * across changes.
	 */
	uint32_t unique_id;

	char message[384];

	/* valid if != 0.  note "errno" might be preprocessor foobar. */
	int errno_val;
	/* valid if pathname[0] != '\0' */
	char pathname[PATH_MAX];
};

/* get error details.
 *
 * NB: errval/ferr_r does NOT carry the full error information.  It's only
 * passed around for future API flexibility.  ferr_get_last always returns
 * the last error set in the current thread.
 */
const struct ferr *ferr_get_last(ferr_r errval);

/* can optionally be called at strategic locations.
 * always returns 0. */
ferr_r ferr_clear(void);

/* do NOT call these functions directly.  only for macro use! */
ferr_r ferr_set_internal(const char *file, int line, const char *func,
			 enum ferr_kind kind, const char *text, ...);
ferr_r ferr_set_internal_ext(const char *file, int line, const char *func,
			     enum ferr_kind kind, const char *pathname,
			     int errno_val, const char *text, ...);

#define ferr_ok() 0

/* Report an error.
 *
 * If you need to do cleanup (free memory, etc.), save the return value in a
 * variable of type ferr_r.
 *
 * Don't put a \n at the end of the error message.
 */
#define ferr_code_bug(...)                                                     \
	ferr_set_internal(__FILE__, __LINE__, __func__, FERR_CODE_BUG,         \
			  __VA_ARGS__)
#define ferr_cfg_invalid(...)                                                  \
	ferr_set_internal(__FILE__, __LINE__, __func__, FERR_CONFIG_INVALID,   \
			  __VA_ARGS__)
#define ferr_cfg_reality(...)                                                  \
	ferr_set_internal(__FILE__, __LINE__, __func__, FERR_CONFIG_REALITY,   \
			  __VA_ARGS__)
#define ferr_cfg_resource(...)                                                 \
	ferr_set_internal(__FILE__, __LINE__, __func__, FERR_RESOURCE,         \
			  __VA_ARGS__)
#define ferr_system(...)                                                       \
	ferr_set_internal(__FILE__, __LINE__, __func__, FERR_SYSTEM,           \
			  __VA_ARGS__)
#define ferr_library(...)                                                      \
	ferr_set_internal(__FILE__, __LINE__, __func__, FERR_LIBRARY,          \
			  __VA_ARGS__)

/* extended information variants */
#define ferr_system_errno(...)                                                 \
	ferr_set_internal_ext(__FILE__, __LINE__, __func__, FERR_SYSTEM, NULL, \
			      errno, __VA_ARGS__)
#define ferr_system_path_errno(path, ...)                                      \
	ferr_set_internal_ext(__FILE__, __LINE__, __func__, FERR_SYSTEM, path, \
			      errno, __VA_ARGS__)

#include "vty.h"
/* print error message to vty;  $ERR is replaced by the error's message */
void vty_print_error(struct vty *vty, ferr_r err, const char *msg, ...);

#define CMD_FERR_DO(func, action, ...)                                         \
	do {                                                                   \
		ferr_r cmd_retval = func;                                      \
		if (cmd_retval) {                                              \
			vty_print_error(vty, cmd_retval, __VA_ARGS__);         \
			action;                                                \
		}                                                              \
	} while (0)

#define CMD_FERR_RETURN(func, ...)                                             \
	CMD_FERR_DO(func, return CMD_WARNING_CONFIG_FAILED, __VA_ARGS__)
#define CMD_FERR_GOTO(func, label, ...)                                        \
	CMD_FERR_DO(func, goto label, __VA_ARGS__)

/* example: uses bogus #define to keep indent.py happy */
#ifdef THIS_IS_AN_EXAMPLE
ferr_r foo_bar_set(struct object *obj, int bar)
{
	if (bar < 1 || bar >= 100)
		return ferr_config_invalid("bar setting (%d) must be 0<x<100",
					   bar);
	obj->bar = bar;
	if (ioctl(obj->fd, bar))
		return ferr_system_errno("couldn't set bar to %d", bar);

	return ferr_ok();
}

DEFUN("bla")
{
	CMD_FERR_RETURN(foo_bar_set(obj, atoi(argv[1])),
			"command failed: $ERR\n");
	return CMD_SUCCESS;
}

#endif /* THIS_IS_AN_EXAMPLE */

#endif /* _FERR_H */
