// SPDX-License-Identifier: GPL-2.0-or-later
/* Tracing
 *
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
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
#include "frrevent.h"
#include "memory.h"
#include "linklist.h"
#include "table.h"

/* clang-format off */

/*
 * BFD client-library (lib/bfd.c) session lifecycle tracepoints.
 *
 * Field legend (shared across the events below):
 *   bsp_ptr    : pointer of the struct bfd_session_params (per-session id)
 *   ifname     : outgoing interface recorded on the session params ("*" if unset)
 *   vrf_id     : VRF id recorded on the session params
 *   family     : AF_INET (2) or AF_INET6 (10)
 *   dst / src  : 16-byte in6_addr; for AF_INET only the first 4 bytes are meaningful
 *   lastev     : 0 = BSE_UNINSTALL, 1 = BSE_INSTALL (enum bfd_session_event in bfd.c)
 *   installed  : bsp->installed at the sampling point
 *   ev_pending : bsp->installev was non-NULL, i.e. a queued event is being
 *                cancelled by _bfd_sess_remove()
 *   command    : ZAPI command that hit the wire, or 0 for the DEREGISTER
 *                early-out. ZEBRA_BFD_DEST_REGISTER=27, DEREGISTER=28, UPDATE=29
 *   rv         : return value of zclient_bfd_command()
 */

TRACEPOINT_EVENT(
	frr_libfrr,
	bfd_sess_send,
	TP_ARGS(
		void *, bsp,
		const char *, ifname,
		uint32_t, vrf_id,
		uint8_t, family,
		const void *, dst,
		const void *, src,
		uint8_t, lastev,
		int32_t, command,
		int, rv,
		uint8_t, installed_out
	),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, bsp_ptr, bsp)
		ctf_string(ifname, ifname ? ifname : "*")
		ctf_integer(uint32_t, vrf_id, vrf_id)
		ctf_integer(uint8_t, family, family)
		ctf_array(uint8_t, dst, dst ? (const uint8_t *)dst : (const uint8_t[16]){0}, 16)
		ctf_array(uint8_t, src, src ? (const uint8_t *)src : (const uint8_t[16]){0}, 16)
		ctf_integer(uint8_t, lastev, lastev)
		ctf_integer(int32_t, command, command)
		ctf_integer(int, rv, rv)
		ctf_integer(uint8_t, installed_out, installed_out)
	)
)
TRACEPOINT_LOGLEVEL(frr_libfrr, bfd_sess_send, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_libfrr,
	bfd_sess_remove,
	TP_ARGS(
		void *, bsp,
		const char *, ifname,
		uint32_t, vrf_id,
		uint8_t, family,
		const void *, dst,
		uint8_t, installed,
		uint8_t, ev_pending
	),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, bsp_ptr, bsp)
		ctf_string(ifname, ifname ? ifname : "*")
		ctf_integer(uint32_t, vrf_id, vrf_id)
		ctf_integer(uint8_t, family, family)
		ctf_array(uint8_t, dst, dst ? (const uint8_t *)dst : (const uint8_t[16]){0}, 16)
		ctf_integer(uint8_t, installed, installed)
		ctf_integer(uint8_t, ev_pending, ev_pending)
	)
)
TRACEPOINT_LOGLEVEL(frr_libfrr, bfd_sess_remove, TRACE_INFO)

/*
 * Fired by _bfd_sess_valid() when a single-hop IPv6 link-local session is
 * deferred because its outgoing interface is not yet known (the #5131052 fix).
 * One event per deferral tells us exactly which session/VRF is being held back
 * and how often, before it later installs with a unique per-interface key.
 */
TRACEPOINT_EVENT(
	frr_libfrr,
	bfd_sess_defer_linklocal_without_intf,
	TP_ARGS(
		void *, bsp,
		uint32_t, vrf_id,
		uint8_t, family,
		const void *, dst,
		const void *, src
	),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, bsp_ptr, bsp)
		ctf_integer(uint32_t, vrf_id, vrf_id)
		ctf_integer(uint8_t, family, family)
		ctf_array(uint8_t, dst, dst ? (const uint8_t *)dst : (const uint8_t[16]){0}, 16)
		ctf_array(uint8_t, src, src ? (const uint8_t *)src : (const uint8_t[16]){0}, 16)
	)
)
TRACEPOINT_LOGLEVEL(frr_libfrr, bfd_sess_defer_linklocal_without_intf, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_libfrr,
	hash_get,
	TP_ARGS(struct hash *, hash, void *, data),
	TP_FIELDS(
		ctf_string(name, hash->name ? hash->name : "(unnamed)")
		ctf_integer(unsigned int, index_size, hash->size)
		ctf_integer(unsigned long, item_count, hash->count)
		ctf_integer_hex(intptr_t, data_ptr, (intptr_t)data)
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
		ctf_integer_hex(intptr_t, data_ptr, (intptr_t)data)
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
		ctf_integer_hex(intptr_t, data_ptr, (intptr_t)data)
		ctf_integer_hex(intptr_t, released_item, (intptr_t)data)
	)
)

TRACEPOINT_LOGLEVEL(frr_libfrr, hash_release, TRACE_INFO)

#define THREAD_SCHEDULE_ARGS                                                   \
	TP_ARGS(const char *, loopname, const char *, funcname,        \
		const char *, schedfrom, int, fromln, struct event **,        \
		thread_ptr, int, fd, int, val, void *, arg, long, time)

TRACEPOINT_EVENT_CLASS(
	frr_libfrr,
	thread_operation,
	THREAD_SCHEDULE_ARGS,
	TP_FIELDS(
		ctf_string(threadmaster_name, loopname)
		ctf_string(function_name, funcname ? funcname : "(unknown function)")
		ctf_string(scheduled_from, schedfrom ? schedfrom : "(unknown file)")
		ctf_integer(int, scheduled_on_line, fromln)
		ctf_integer_hex(intptr_t, thread_addr, thread_ptr ? (intptr_t)(void *)(*thread_ptr) : (intptr_t)NULL)
		ctf_integer(int, file_descriptor, fd)
		ctf_integer(int, event_value, val)
		ctf_integer_hex(intptr_t, argument_ptr, (intptr_t)arg)
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
THREAD_OPERATION_TRACEPOINT_INSTANCE(event_cancel)
THREAD_OPERATION_TRACEPOINT_INSTANCE(event_cancel_async)
THREAD_OPERATION_TRACEPOINT_INSTANCE(event_call)

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
		ctf_integer_hex(intptr_t, ptr, (intptr_t)ptr)
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
		ctf_integer_hex(intptr_t, ptr, (intptr_t)ptr)
	)
)

TRACEPOINT_EVENT(
	frr_libfrr,
	list_add,
	TP_ARGS(
		struct list *, list, const void *, ptr
	),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, list, (intptr_t)list)
		ctf_integer(unsigned int, count, list->count)
		ctf_integer_hex(intptr_t, ptr, (intptr_t)ptr)
	)
)

TRACEPOINT_EVENT(
	frr_libfrr,
	list_remove,
	TP_ARGS(
		struct list *, list, const void *, ptr
	),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, list, (intptr_t)list)
		ctf_integer(unsigned int, count, list->count)
		ctf_integer_hex(intptr_t, ptr, (intptr_t)ptr)
	)
)

TRACEPOINT_EVENT(
	frr_libfrr,
	list_delete_node,
	TP_ARGS(
		struct list *, list, const void *, node
	),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, list, (intptr_t)list)
		ctf_integer(unsigned int, count, list->count)
		ctf_integer_hex(intptr_t, node, (intptr_t)node)
	)
)

TRACEPOINT_EVENT(
	frr_libfrr,
	list_sort,
	TP_ARGS(
		struct list *, list
	),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, list, (intptr_t)list)
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
		ctf_integer_hex(intptr_t, table, (intptr_t)table)
		ctf_string(prefix, prefix)
	)
)

/* clang-format on */

#include <lttng/tracepoint-event.h>
#include <lttng/tracelog.h>

#endif /* HAVE_LTTNG */

#endif /* _LIBFRR_TRACE_H_ */
