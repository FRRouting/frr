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

#if !defined(_LIBFRR_TRACE_H_) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _LIBFRR_TRACE_H_

#include "trace.h"

#ifdef HAVE_LTTNG

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_libfrr

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./libfrr_trace.h"

#include <lttng/tracepoint.h>

#include "hash.h"
#include "thread.h"
#include "memory.h"
#include "linklist.h"
#include "table.h"

/* clang-format off */

TRACEPOINT_EVENT(
	frr_libfrr,
	hash_get,
	TP_ARGS(struct hash *, hash, void *, data),
	TP_FIELDS(
		ctf_string(name, hash->name ? hash->name : "(unnamed)")
		ctf_integer(unsigned int, index_size, hash->size)
		ctf_integer(unsigned long, item_count, hash->count)
		ctf_integer_hex(intptr_t, data_ptr, data)
	)
)

TRACEPOINT_LOGLEVEL(frr_libfrr, hash_get, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_libfrr,
	hash_insert,
	TP_ARGS(struct hash *, hash, void *, data, unsigned int, key),
	TP_FIELDS(
		ctf_string(name, hash->name ? hash->name : "(unnamed)")
		ctf_integer(unsigned int, key, hash->size)
		ctf_integer(unsigned int, index_size, hash->size)
		ctf_integer(unsigned long, item_count, hash->count)
		ctf_integer_hex(intptr_t, data_ptr, data)
	)
)

TRACEPOINT_LOGLEVEL(frr_libfrr, hash_insert, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_libfrr,
	hash_release,
	TP_ARGS(struct hash *, hash, void *, data, void *, released_item),
	TP_FIELDS(
		ctf_string(name, hash->name ? hash->name : "(unnamed)")
		ctf_integer(unsigned int, index_size, hash->size)
		ctf_integer(unsigned long, item_count, hash->count)
		ctf_integer_hex(intptr_t, data_ptr, data)
		ctf_integer_hex(intptr_t, released_item, data)
	)
)

TRACEPOINT_LOGLEVEL(frr_libfrr, hash_release, TRACE_INFO)

#define THREAD_SCHEDULE_ARGS                                                   \
	TP_ARGS(struct thread_master *, master, const char *, funcname,        \
		const char *, schedfrom, int, fromln, struct thread **,        \
		thread_ptr, int, fd, int, val, void *, arg, long, time)

TRACEPOINT_EVENT_CLASS(
	frr_libfrr,
	thread_operation,
	THREAD_SCHEDULE_ARGS,
	TP_FIELDS(
		ctf_string(threadmaster_name, master->name)
		ctf_string(function_name, funcname ? funcname : "(unknown function)")
		ctf_string(scheduled_from, schedfrom ? schedfrom : "(unknown file)")
		ctf_integer(int, scheduled_on_line, fromln)
		ctf_integer_hex(intptr_t, thread_addr, thread_ptr ? *thread_ptr : NULL)
		ctf_integer(int, file_descriptor, fd)
		ctf_integer(int, event_value, val)
		ctf_integer_hex(intptr_t, argument_ptr, arg)
		ctf_integer(long, timer, time)
	)
)

#define THREAD_OPERATION_TRACEPOINT_INSTANCE(name)                             \
	TRACEPOINT_EVENT_INSTANCE(frr_libfrr, thread_operation, name,          \
				  THREAD_SCHEDULE_ARGS)                        \
	TRACEPOINT_LOGLEVEL(frr_libfrr, name, TRACE_INFO)

THREAD_OPERATION_TRACEPOINT_INSTANCE(schedule_timer)
THREAD_OPERATION_TRACEPOINT_INSTANCE(schedule_event)
THREAD_OPERATION_TRACEPOINT_INSTANCE(schedule_read)
THREAD_OPERATION_TRACEPOINT_INSTANCE(schedule_write)
THREAD_OPERATION_TRACEPOINT_INSTANCE(thread_cancel)
THREAD_OPERATION_TRACEPOINT_INSTANCE(thread_cancel_async)
THREAD_OPERATION_TRACEPOINT_INSTANCE(thread_call)

TRACEPOINT_EVENT(
	frr_libfrr,
	frr_pthread_run,
	TP_ARGS(
		char *, name
	),
	TP_FIELDS(
		ctf_string(frr_pthread_name, name)
	)
)

TRACEPOINT_EVENT(
	frr_libfrr,
	frr_pthread_stop,
	TP_ARGS(
		char *, name
	),
	TP_FIELDS(
		ctf_string(frr_pthread_name, name)
	)
)

TRACEPOINT_EVENT(
	frr_libfrr,
	memalloc,
	TP_ARGS(
		struct memtype *, mt, void *, ptr, size_t, size
	),
	TP_FIELDS(
		ctf_string(memtype, mt->name)
		ctf_integer(size_t, size, size)
		ctf_integer_hex(intptr_t, ptr, ptr)
	)
)

TRACEPOINT_EVENT(
	frr_libfrr,
	memfree,
	TP_ARGS(
		struct memtype *, mt, void *, ptr
	),
	TP_FIELDS(
		ctf_string(memtype, mt->name)
		ctf_integer_hex(intptr_t, ptr, ptr)
	)
)

TRACEPOINT_EVENT(
	frr_libfrr,
	list_add,
	TP_ARGS(
		struct list *, list, const void *, ptr
	),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, list, list)
		ctf_integer(unsigned int, count, list->count)
		ctf_integer_hex(intptr_t, ptr, ptr)
	)
)

TRACEPOINT_EVENT(
	frr_libfrr,
	list_remove,
	TP_ARGS(
		struct list *, list, const void *, ptr
	),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, list, list)
		ctf_integer(unsigned int, count, list->count)
		ctf_integer_hex(intptr_t, ptr, ptr)
	)
)

TRACEPOINT_EVENT(
	frr_libfrr,
	list_delete_node,
	TP_ARGS(
		struct list *, list, const void *, node
	),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, list, list)
		ctf_integer(unsigned int, count, list->count)
		ctf_integer_hex(intptr_t, node, node)
	)
)

TRACEPOINT_EVENT(
	frr_libfrr,
	list_sort,
	TP_ARGS(
		struct list *, list
	),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, list, list)
		ctf_integer(unsigned int, count, list->count)
	)
)

TRACEPOINT_EVENT(
	frr_libfrr,
	route_node_get,
	TP_ARGS(
		struct route_table *, table, char *, prefix
	),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, table, table)
		ctf_string(prefix, prefix)
	)
)

/* clang-format on */

#include <lttng/tracepoint-event.h>
#include <lttng/tracelog.h>

#endif /* HAVE_LTTNG */

#endif /* _LIBFRR_TRACE_H_ */
