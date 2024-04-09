// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#ifndef LOG_H
#define LOG_H

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

#endif /* LOG_H */
