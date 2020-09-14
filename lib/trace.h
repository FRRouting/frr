/* Tracing
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

#if !defined(_TRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifdef HAVE_LTTNG

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_libfrr

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./trace.h"

/* tracepoint definitions go here */

#include <lttng/tracepoint.h>
#include <lttng/tracepoint-event.h>

#else /* HAVE_LTTNG */

#define tracepoint(...)
#define tracef(...)
#define tracelog(...)
#define tracepoint_enabled(...) true

#endif /* HAVE_LTTNG */

#endif /* _TRACE_H */
