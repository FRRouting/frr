// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#ifndef LOG_H
#define LOG_H

<<<<<<< HEAD
#include <stdarg.h>

extern const char	*log_procname;

void	 logit(int, const char *, ...)
		__attribute__((__format__ (printf, 2, 3)));
void	 vlog(int, const char *, va_list)
		__attribute__((__format__ (printf, 2, 0)));
void	 log_warn(const char *, ...)
		__attribute__((__format__ (printf, 1, 2)));
void	 log_warnx(const char *, ...)
		__attribute__((__format__ (printf, 1, 2)));
void	 log_info(const char *, ...)
		__attribute__((__format__ (printf, 1, 2)));
void	 log_notice(const char *, ...)
		__attribute__((__format__ (printf, 1, 2)));
void	 log_debug(const char *, ...)
		__attribute__((__format__ (printf, 1, 2)));
void	 fatal(const char *)
		__attribute__ ((noreturn))
		__attribute__((__format__ (printf, 1, 0)));
void	 fatalx(const char *)
		__attribute__ ((noreturn))
		__attribute__((__format__ (printf, 1, 0)));
=======
#include "log.h"
#include "assert.h"

extern const char	*log_procname;

#define log_warnx	zlog_err	/* yes this is poorly named */
#define log_warn	zlog_warn
#define log_info	zlog_info
#define log_notice	zlog_notice	/* not used anywhere */
#define log_debug	zlog_debug

#define fatal(msg)                                                             \
	do {                                                                   \
		assertf(0, "fatal in %s: %pSQq (%m)", log_procname,            \
			(const char *)msg);                                    \
		__builtin_unreachable();                                       \
	} while (0)                                                            \
	/* end */
#define fatalx(msg)                                                            \
	do {                                                                   \
		assertf(0, "fatal in %s: %pSQq", log_procname,                 \
			(const char *)msg);                                    \
		__builtin_unreachable();                                       \
	} while (0)                                                            \
	/* end */
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

#endif /* LOG_H */
