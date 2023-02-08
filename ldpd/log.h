// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#ifndef LOG_H
#define LOG_H

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

#endif /* LOG_H */
