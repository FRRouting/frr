/*
 * Zebra logging funcions.
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_LOG_H
#define _ZEBRA_LOG_H

#include <syslog.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include "lib/hook.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Hook for external logging function */
DECLARE_HOOK(zebra_ext_log, (int priority, const char *format, va_list args),
	     (priority, format, args));

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

/* If maxlvl is set to ZLOG_DISABLED, then no messages will be sent
   to that logging destination. */
#define ZLOG_DISABLED	(LOG_EMERG-1)

typedef enum {
	ZLOG_DEST_SYSLOG = 0,
	ZLOG_DEST_STDOUT,
	ZLOG_DEST_MONITOR,
	ZLOG_DEST_FILE
} zlog_dest_t;
#define ZLOG_NUM_DESTS		(ZLOG_DEST_FILE+1)

extern bool zlog_startup_stderr;

/* Message structure. */
struct message {
	int key;
	const char *str;
};

/* Open zlog function */
extern void openzlog(const char *progname, const char *protoname,
		     uint16_t instance, int syslog_options,
		     int syslog_facility);

/* Close zlog function. */
extern void closezlog(void);

/* Handy zlog functions. */
extern void zlog_err(const char *format, ...) PRINTFRR(1, 2);
extern void zlog_warn(const char *format, ...) PRINTFRR(1, 2);
extern void zlog_info(const char *format, ...) PRINTFRR(1, 2);
extern void zlog_notice(const char *format, ...) PRINTFRR(1, 2);
extern void zlog_debug(const char *format, ...) PRINTFRR(1, 2);
extern void zlog(int priority, const char *format, ...) PRINTFRR(2, 3);

/* For logs which have error codes associated with them */
#define flog_err(ferr_id, format, ...)                                        \
	zlog_err("[EC %" PRIu32 "] " format, ferr_id, ##__VA_ARGS__)
#define flog_err_sys(ferr_id, format, ...)                                     \
	flog_err(ferr_id, format, ##__VA_ARGS__)
#define flog_warn(ferr_id, format, ...)                                        \
	zlog_warn("[EC %" PRIu32 "] " format, ferr_id, ##__VA_ARGS__)
#define flog(priority, ferr_id, format, ...)                                   \
	zlog(priority, "[EC %" PRIu32 "] " format, ferr_id, ##__VA_ARGS__)

extern void zlog_thread_info(int log_level);

/* Set logging level for the given destination.  If the log_level
   argument is ZLOG_DISABLED, then the destination is disabled.
   This function should not be used for file logging (use zlog_set_file
   or zlog_reset_file instead). */
extern void zlog_set_level(zlog_dest_t, int log_level);

/* Set logging to the given filename at the specified level. */
extern int zlog_set_file(const char *filename, int log_level);
/* Disable file logging. */
extern int zlog_reset_file(void);

/* Rotate log. */
extern int zlog_rotate(void);

#define ZLOG_FILTERS_MAX 100      /* Max # of filters at once */
#define ZLOG_FILTER_LENGTH_MAX 80 /* 80 character filter limit */

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
#define QUAGGA_TIMESTAMP_LEN 40
extern size_t quagga_timestamp(int timestamp_precision /* # subsecond digits */,
			       char *buf, size_t buflen);

extern void zlog_hexdump(const void *mem, unsigned int len);
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


extern int vzlog_test(int priority);

/* structure useful for avoiding repeated rendering of the same timestamp */
struct timestamp_control {
	size_t len;			/* length of rendered timestamp */
	int precision;			/* configuration parameter */
	int already_rendered;		/* should be initialized to 0 */
	char buf[QUAGGA_TIMESTAMP_LEN]; /* will contain the rendered timestamp
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
