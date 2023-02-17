// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_FERR_H
#define _FRR_FERR_H

/***********************************************************
 * scroll down to the end of this file for a full example! *
 ***********************************************************/

#include <stdint.h>
#include <limits.h>
#include <errno.h>

#include "vty.h"

#ifdef __cplusplus
extern "C" {
#endif

/* return type when this error indication stuff is used.
 *
 * guaranteed to have boolean evaluation to "false" when OK, "true" when error
 * (i.e. can be changed to pointer in the future if necessary)
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

/* Numeric ranges assigned to daemons for use as error codes. */
#define BABEL_FERR_START    0x01000001
#define BABEL_FRRR_END      0x01FFFFFF
#define BGP_FERR_START      0x02000001
#define BGP_FERR_END        0x02FFFFFF
#define EIGRP_FERR_START    0x03000001
#define EIGRP_FERR_END      0x03FFFFFF
#define ISIS_FERR_START     0x04000001
#define ISIS_FERR_END       0x04FFFFFF
#define LDP_FERR_START      0x05000001
#define LDP_FERR_END        0x05FFFFFF
#define LIB_FERR_START      0x06000001
#define LIB_FERR_END        0x06FFFFFF
#define NHRP_FERR_START     0x07000001
#define NHRP_FERR_END       0x07FFFFFF
#define OSPF_FERR_START     0x08000001
#define OSPF_FERR_END       0x08FFFFFF
#define OSPFV3_FERR_START   0x09000001
#define OSPFV3_FERR_END     0x09FFFFFF
#define PBR_FERR_START      0x0A000001
#define PBR_FERR_END        0x0AFFFFFF
#define PIM_FERR_START      0x0B000001
#define PIM_FERR_STOP       0x0BFFFFFF
#define RIP_FERR_START      0x0C000001
#define RIP_FERR_STOP       0x0CFFFFFF
#define RIPNG_FERR_START    0x0D000001
#define RIPNG_FERR_STOP     0x0DFFFFFF
#define SHARP_FERR_START    0x0E000001
#define SHARP_FERR_END      0x0EFFFFFF
#define VTYSH_FERR_START    0x0F000001
#define VTYSH_FRR_END       0x0FFFFFFF
#define WATCHFRR_FERR_START 0x10000001
#define WATCHFRR_FERR_END   0x10FFFFFF
#define PATH_FERR_START     0x11000001
#define PATH_FERR_END       0x11FFFFFF
#define ZEBRA_FERR_START    0xF1000001
#define ZEBRA_FERR_END      0xF1FFFFFF
#define END_FERR            0xFFFFFFFF

struct log_ref {
	/* Unique error code displayed to end user as a reference. -1 means
	 * this is an uncoded error that does not have reference material. */
	uint32_t code;
	/* Ultra brief title */
	const char *title;
	/* Brief description of error */
	const char *description;
	/* Remedial suggestion */
	const char *suggestion;
};

void log_ref_add(struct log_ref *ref);
struct log_ref *log_ref_get(uint32_t code);
void log_ref_display(struct vty *vty, uint32_t code, bool json);

/*
 * This function should be called by the
 * code in libfrr.c
 */
void log_ref_init(void);
void log_ref_fini(void);
void log_ref_vty_init(void);

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
ferr_r ferr_set_internal(const char *file, int line, const char *func,
			 enum ferr_kind kind, const char *text, ...)
	PRINTFRR(5, 6);
ferr_r ferr_set_internal_ext(const char *file, int line, const char *func,
			     enum ferr_kind kind, const char *pathname,
			     int errno_val, const char *text, ...)
	PRINTFRR(7, 8);

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
void vty_print_error(struct vty *vty, ferr_r err, const char *msg, ...)
	PRINTFRR(3, 4);

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

#ifdef __cplusplus
}
#endif

#endif /* _FERR_H */
