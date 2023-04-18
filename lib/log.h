// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra logging funcions.
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_LOG_H
#define _ZEBRA_LOG_H

#include <syslog.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>

#include "lib/hook.h"
#include "lib/zlog.h"
#include "lib/zlog_targets.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Here is some guidance on logging levels to use:
 *
 * LOG_DEBUG	- For all messages that are enabled by optional debugging
 *		  features, typically preceded by "if (IS...DEBUG...)"
 * LOG_INFO	- Information that may be of interest, but everything seems
 *		  to be working properly.
 * LOG_NOTICE	- Only for message pertaining to daemon startup or shutdown.
 * LOG_WARNING	- Warning conditions: unexpected events, but the daemon believes
 *		  it can continue to operate correctly.
 * LOG_ERR	- Error situations indicating malfunctions.  Probably require
 *		  attention.
 *
 * Note: LOG_CRIT, LOG_ALERT, and LOG_EMERG are currently not used anywhere,
 * please use LOG_ERR instead.
 */

extern void zlog_rotate(void);

/* Message structure. */
struct message {
	int key;
	const char *str;
};

extern void zlog_thread_info(int log_level);

#define ZLOG_FILTERS_MAX 100      /* Max # of filters at once */
#define ZLOG_FILTER_LENGTH_MAX 80 /* 80 character filter limit */

struct zlog_cfg_filterfile {
	struct zlog_cfg_file parent;
};

extern void zlog_filterfile_init(struct zlog_cfg_filterfile *zcf);
extern void zlog_filterfile_fini(struct zlog_cfg_filterfile *zcf);

/* Add/Del/Dump log filters */
extern void zlog_filter_clear(void);
extern int zlog_filter_add(const char *filter);
extern int zlog_filter_del(const char *filter);
extern int zlog_filter_dump(char *buf, size_t max_size);

const char *lookup_msg(const struct message *mz, int kz, const char *nf);

/* Safe version of strerror -- never returns NULL. */
extern const char *safe_strerror(int errnum);

/* To be called when a fatal signal is caught. */
extern void zlog_signal(int signo, const char *action, void *siginfo,
			void *program_counter);

/* Log a backtrace. */
extern void zlog_backtrace(int priority);

/* Log a backtrace, but in an async-signal-safe way.  Should not be
   called unless the program is about to exit or abort, since it messes
   up the state of zlog file pointers.  If program_counter is non-NULL,
   that is logged in addition to the current backtrace. */
extern void zlog_backtrace_sigsafe(int priority, void *program_counter);

/* Puts a current timestamp in buf and returns the number of characters
   written (not including the terminating NUL).  The purpose of
   this function is to avoid calls to localtime appearing all over the code.
   It caches the most recent localtime result and can therefore
   avoid multiple calls within the same second.  If buflen is too small,
   *buf will be set to '\0', and 0 will be returned. */
#define FRR_TIMESTAMP_LEN 40
extern size_t frr_timestamp(int timestamp_precision /* # subsecond digits */,
			    char *buf, size_t buflen);

extern void zlog_hexdump(const void *mem, size_t len);
extern const char *zlog_sanitize(char *buf, size_t bufsz, const void *in,
				 size_t inlen);

/* Note: whenever a new route-type or zserv-command is added the
 * corresponding {command,route}_types[] table in lib/log.c MUST be
 * updated! */

/* Map a route type to a string.  For example, ZEBRA_ROUTE_RIPNG -> "ripng". */
extern const char *zebra_route_string(unsigned int route_type);
/* Map a route type to a char.  For example, ZEBRA_ROUTE_RIPNG -> 'R'. */
extern char zebra_route_char(unsigned int route_type);
/* Map a zserv command type to the same string,
 * e.g. ZEBRA_INTERFACE_ADD -> "ZEBRA_INTERFACE_ADD" */
/* Map a protocol name to its number. e.g. ZEBRA_ROUTE_BGP->9*/
extern int proto_name2num(const char *s);
/* Map redistribute X argument to protocol number.
 * unlike proto_name2num, this accepts shorthands and takes
 * an AFI value to restrict input */
extern int proto_redistnum(int afi, const char *s);

extern const char *zserv_command_string(unsigned int command);
extern const char *zserv_gr_client_cap_string(unsigned int zcc);

#define OSPF_LOG(level, cond, fmt, ...)                                        \
	do {                                                                   \
		if (cond)                                                      \
			zlog_##level(fmt, ##__VA_ARGS__);                      \
	} while (0)

#define OSPF_LOG_ERR(fmt, ...) OSPF_LOG(err, true, fmt, ##__VA_ARGS__)

#define OSPF_LOG_WARN(fmt, ...) OSPF_LOG(warn, true, fmt, ##__VA_ARGS__)

#define OSPF_LOG_INFO(fmt, ...) OSPF_LOG(info, true, fmt, ##__VA_ARGS__)

#define OSPF_LOG_DEBUG(cond, fmt, ...) OSPF_LOG(debug, cond, fmt, ##__VA_ARGS__)

#define OSPF_LOG_NOTICE(fmt, ...) OSPF_LOG(notice, true, fmt, ##__VA_ARGS__)

/* structure useful for avoiding repeated rendering of the same timestamp */
struct timestamp_control {
	size_t len;			/* length of rendered timestamp */
	int precision;			/* configuration parameter */
	int already_rendered;		/* should be initialized to 0 */
	char buf[FRR_TIMESTAMP_LEN];	/* will contain the rendered timestamp
					 */
};

/* Defines for use in command construction: */

#define LOG_LEVEL_DESC                                                         \
	"System is unusable\n"                                                 \
	"Immediate action needed\n"                                            \
	"Critical conditions\n"                                                \
	"Error conditions\n"                                                   \
	"Warning conditions\n"                                                 \
	"Normal but significant conditions\n"                                  \
	"Informational messages\n"                                             \
	"Debugging messages\n"

#define LOG_FACILITY_DESC                                                      \
	"Kernel\n"                                                             \
	"User process\n"                                                       \
	"Mail system\n"                                                        \
	"System daemons\n"                                                     \
	"Authorization system\n"                                               \
	"Syslog itself\n"                                                      \
	"Line printer system\n"                                                \
	"USENET news\n"                                                        \
	"Unix-to-Unix copy system\n"                                           \
	"Cron/at facility\n"                                                   \
	"Local use\n"                                                          \
	"Local use\n"                                                          \
	"Local use\n"                                                          \
	"Local use\n"                                                          \
	"Local use\n"                                                          \
	"Local use\n"                                                          \
	"Local use\n"                                                          \
	"Local use\n"

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_LOG_H */
