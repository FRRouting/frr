/*********************************************************************
 * Copyright 2017-2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * log.c: implements an abstraction between loggers interface. Implement all
 * log backends in this file.
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */

#include <zebra.h>

#include "bfd.h"

#include "lib/log_int.h"

void log_msg(int level, const char *fmt, va_list vl);


static int log_fg;
static int log_level = BLOG_DEBUG;

void log_init(int foreground, enum blog_level level,
	      struct frr_daemon_info *fdi)
{
	log_fg = foreground;
	log_level = level;

	openzlog(fdi->progname, fdi->logname, 0,
		 LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
}

void log_msg(int level, const char *fmt, va_list vl)
{
	if (level < log_level)
		return;

	switch (level) {
	case BLOG_DEBUG:
		vzlog(LOG_DEBUG, fmt, vl);
		break;

	case BLOG_INFO:
		vzlog(LOG_INFO, fmt, vl);
		break;

	case BLOG_WARNING:
		vzlog(LOG_WARNING, fmt, vl);
		break;

	case BLOG_ERROR:
		vzlog(LOG_ERR, fmt, vl);
		break;

	case BLOG_FATAL:
		vzlog(LOG_EMERG, fmt, vl);
		break;

	default:
		vfprintf(stderr, fmt, vl);
		break;
	}
}

void log_info(const char *fmt, ...)
{
	va_list vl;

	va_start(vl, fmt);
	log_msg(BLOG_INFO, fmt, vl);
	va_end(vl);
}

void log_debug(const char *fmt, ...)
{
	va_list vl;

	va_start(vl, fmt);
	log_msg(BLOG_DEBUG, fmt, vl);
	va_end(vl);
}

void log_error(const char *fmt, ...)
{
	va_list vl;

	va_start(vl, fmt);
	log_msg(BLOG_ERROR, fmt, vl);
	va_end(vl);
}

void log_warning(const char *fmt, ...)
{
	va_list vl;

	va_start(vl, fmt);
	log_msg(BLOG_WARNING, fmt, vl);
	va_end(vl);
}

void log_fatal(const char *fmt, ...)
{
	va_list vl;

	va_start(vl, fmt);
	log_msg(BLOG_FATAL, fmt, vl);
	va_end(vl);

	exit(1);
}
