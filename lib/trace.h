/* Tracing macros
 *
 * Wraps tracepoint macros for different tracing systems to allow switching
 * between them at compile time.
 *
 * This should not be included directly by source files wishing to provide
 * tracepoints. Instead, write a header that defines LTTng tracepoints and
 * which includes this header, and include your new header in your source. USDT
 * probes do not need tracepoint definitions, but are less capable than LTTng
 * tracepoints.
 *
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
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
 */

#ifndef _TRACE_H_
#define _TRACE_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

/*
 * Provided here:
 * - frrtrace(n, provider, name, ...args...)
 * - frrtrace_enabled(provider, name)
 * - frrtracelog(level, msg, ...)
 *
 * Use frrtrace() to define tracepoints. n is the number of arguments; this is
 * needed because USDT probe definitions use DTRACE_PROBEn macros, so the
 * number of args must be passed in order to expand the correct macro.
 *
 * frrtrace_enabled() maps to tracepoint_enabled() under LTTng and is always
 * true when using USDT. In the future it could be mapped to USDT semaphores
 * but this is not implemented at present.
 *
 * frrtracelog() maps to tracelog() under LTTng and should only be used in zlog
 * core code, to propagate zlog messages to LTTng. It expands to nothing
 * otherwise.
 */

#if defined(HAVE_LTTNG)

#define frrtrace(nargs, provider, name, ...) \
	tracepoint(provider, name, ## __VA_ARGS__)
#define frrtrace_enabled(...) tracepoint_enabled(__VA_ARGS__)
#define frrtracelog(...) tracelog(__VA_ARGS__)

#elif defined(HAVE_USDT)

#include "sys/sdt.h"

#define frrtrace(nargs, provider, name, ...) \
	DTRACE_PROBE##nargs(provider, name, ## __VA_ARGS__)
#define frrtrace_enabled(...) true
#define frrtracelog(...)

#else

#define frrtrace(nargs, provider, name, ...) (void)0
#define frrtrace_enabled(...) false
#define frrtracelog(...) (void)0

#endif

#endif /* _TRACE_H_ */
