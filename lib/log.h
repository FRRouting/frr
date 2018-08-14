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

/* GCC have printf type attribute check.  */
#ifdef __GNUC__
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* __GNUC__ */

/* Handy zlog functions. */
extern void zlog_err(const char *format, ...) PRINTF_ATTRIBUTE(1, 2);
extern void zlog_warn(const char *format, ...) PRINTF_ATTRIBUTE(1, 2);
extern void zlog_info(const char *format, ...) PRINTF_ATTRIBUTE(1, 2);
extern void zlog_notice(const char *format, ...) PRINTF_ATTRIBUTE(1, 2);
extern void zlog_debug(const char *format, ...) PRINTF_ATTRIBUTE(1, 2);

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

const char *lookup_msg(const struct message *mz, int kz, const char *nf);

/* Safe version of strerror -- never returns NULL. */
extern const char *safe_strerror(int errnum);

/* To be called when a fatal signal is caught. */
extern void zlog_signal(int signo, const char *action
#ifdef SA_SIGINFO
			,
			siginfo_t *siginfo, void *program_counter
#endif
			);

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

#endif /* _ZEBRA_LOG_H */
