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

#ifndef _ZEBRA_LOG_PRIVATE_H
#define _ZEBRA_LOG_PRIVATE_H

#include "log.h"

struct zlog {
	const char *ident; /* daemon name (first arg to openlog) */
	const char *protoname;
	unsigned short instance;
	int maxlvl[ZLOG_NUM_DESTS]; /* maximum priority to send to associated
				       logging destination */
	int default_lvl;	    /* maxlvl to use if none is specified */
	FILE *fp;
	char *filename;
	int facility;	/* as per syslog facility */
	int record_priority; /* should messages logged through stdio include the
				priority of the message? */
	int syslog_options;  /* 2nd arg to openlog */
	int timestamp_precision; /* # of digits of subsecond precision */
};

/* Default logging strucutre. */
extern struct zlog *zlog_default;

extern const char *zlog_priority[];

/* Generic function for zlog. */
extern void vzlog(int priority, const char *format, va_list args);
extern void zlog(int priority, const char *format, ...) PRINTF_ATTRIBUTE(2, 3);

#endif /* _ZEBRA_LOG_PRIVATE_H */
