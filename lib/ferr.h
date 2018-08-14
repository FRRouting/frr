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
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include "module.h"

struct log_cat {
	struct log_cat *parent;

	const char *name;
	const char *title;
	const char *description;
	const char *suggestion;
};

#define DECLARE_LOGCAT(name)                                                   \
	extern struct log_cat _lc_##name;

#define DEFINE_LOGCAT_ATTR(cname, attr, cparent, ctitle, ...)                  \
	attr struct log_cat _lc_##cname                                        \
		__attribute__((section(".data.logcats"))) = {                  \
			.name = #cname,                                        \
			.parent = &_lc_ ## cparent,                            \
			.title = ctitle, ## __VA_ARGS__                        \
	};                                                                     \

#define DEFINE_LOGCAT(name, parent, title, ...)                                \
	DEFINE_LOGCAT_ATTR(name, , parent, title,## __VA_ARGS__)
#define DEFINE_LOGCAT_STATIC(name, parent, title, ...)                         \
	DEFINE_LOGCAT_ATTR(name, static, parent, title,## __VA_ARGS__)

#define _lc_NOPARENT NULL

extern struct log_cat _lc_ROOT;
DECLARE_LOGCAT(OK)
DECLARE_LOGCAT(CODE_BUG)
DECLARE_LOGCAT(CONFIG_INVALID)
DECLARE_LOGCAT(CONFIG_REALITY)
DECLARE_LOGCAT(RESOURCE)
DECLARE_LOGCAT(SYSTEM)
DECLARE_LOGCAT(LIBRARY)
DECLARE_LOGCAT(NET_INVALID_INPUT)
DECLARE_LOGCAT(SYS_INVALID_INPUT)

struct log_ref {
	/* message core properties */
	const char *fmtstring;
	int priority;

	/* code location */
	int line;
	const char *file;
	const char *func;

	struct log_cat *category;
	size_t count;

	uint32_t unique_id;
	/* base32(crockford) of unique ID */
	char prefix[8];
};

struct log_ref_block {
	struct log_ref_block *next;
	struct log_ref * const * start;
	struct log_ref * const * stop;
};

extern struct log_ref_block *log_ref_blocks, **log_ref_block_last;
extern void log_ref_block_add(struct log_ref_block *block);

extern struct log_ref * const __start_logref_array DSO_LOCAL;
extern struct log_ref * const __stop_logref_array DSO_LOCAL;

#define LOG_REF_INIT() \
	static struct log_ref _dummy_log_ref \
				__attribute((section(".data.logrefs"))) = { \
			.file = __FILE__, .line = __LINE__, .func = "dummy", \
			.fmtstring = "dummy", .category = &_lc_ROOT, \
	} ; \
	static struct log_ref * const _dummy_log_ref_p __attribute__((used, \
				section("logref_array"))) = &_dummy_log_ref; \
	static void __attribute__((used, _CONSTRUCTOR(1100))) \
			_log_ref_init(void) { \
		static struct log_ref_block _log_ref_block = { \
			.start = &__start_logref_array, \
			.stop = &__stop_logref_array, \
		}; \
		log_ref_block_add(&_log_ref_block); \
	}


/* return type when this error indication stuff is used.
 *
 * guaranteed to have boolean evaluation to "false" when OK, "true" when error
 * (i.e. can be changed to pointer in the future if neccessary)
 *
 * For checking, always use "if (value)", nothing else.
 * Do _NOT_ use any integer constant (!= 0), or sign check (< 0).
 */
typedef int ferr_r;

struct ferr {
	/* code location */
	struct log_ref *ref;

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

/*
 * Can optionally be called at strategic locations.
 * Always returns 0.
 */
ferr_r ferr_clear(void);

/* do NOT call these functions directly.  only for macro use! */
ferr_r ferr_set_internal(struct log_ref *ref, ...);
ferr_r ferr_set_internal_ext(struct log_ref *ref, const char *pathname,
			     int errno_val, ...);

#define ferr_ok() 0

/* Report an error.
 *
 * If you need to do cleanup (free memory, etc.), save the return value in a
 * variable of type ferr_r.
 *
 * Don't put a \n at the end of the error message.
 */
#define ferr_code_bug(msg, ...) ({                                             \
		_zlog_makeref(&_lc_CODE_BUG, LOG_ERR, msg);                    \
		ferr_set_internal(&log_ref, ##__VA_ARGS__);                    \
	})
#define ferr_cfg_invalid(msg, ...) ({                                          \
		_zlog_makeref(&_lc_CONFIG_INVALID, LOG_ERR, msg);              \
		ferr_set_internal(&log_ref, ##__VA_ARGS__);                    \
	})
#define ferr_cfg_reality(msg, ...) ({                                          \
		_zlog_makeref(&_lc_CONFIG_REALITY, LOG_ERR, msg);              \
		ferr_set_internal(&log_ref, ##__VA_ARGS__);                    \
	})
#define ferr_cfg_resource(msg, ...) ({                                         \
		_zlog_makeref(&_lc_RESOURCE, LOG_ERR, msg);                    \
		ferr_set_internal(&log_ref, ##__VA_ARGS__);                    \
	})
#define ferr_system(msg, ...) ({                                               \
		_zlog_makeref(&_lc_SYSTEM, LOG_ERR, msg);                      \
		ferr_set_internal(&log_ref, ##__VA_ARGS__);                    \
	})
#define ferr_library(msg, ...) ({                                              \
		_zlog_makeref(&_lc_LIBRARY, LOG_ERR, msg);                     \
		ferr_set_internal(&log_ref, ##__VA_ARGS__);                    \
	})

/* extended information variants */
#define ferr_system_errno(msg, ...) ({                                         \
		_zlog_makeref(&_lc_SYSTEM, LOG_ERR, msg);                      \
		ferr_set_internal_ext(&log_ref, NULL, errno, ##__VA_ARGS__);   \
	})
#define ferr_system_path_errno(msg, ...) ({                                    \
		_zlog_makeref(&_lc_SYSTEM, LOG_ERR, msg);                      \
		ferr_set_internal_ext(&log_ref, path, errno, ##__VA_ARGS__);   \
	})

struct vty;

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
