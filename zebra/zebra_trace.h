// SPDX-License-Identifier: GPL-2.0-or-later
/* Tracing for zebra
 *
 * Copyright (C) 2020  NVIDIA Corporation
 * Donald Sharp
 */

#if !defined(__ZEBRA_TRACE_H__) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define __ZEBRA_TRACE_H__

#include "lib/trace.h"

#ifdef HAVE_LTTNG

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_zebra

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "zebra/zebra_trace.h"

#include <lttng/tracepoint.h>

#include <lib/ns.h>
#include <lib/table.h>

#include <zebra/zebra_ns.h>

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_request_intf_addr,
	TP_ARGS(struct nlsock *, netlink_cmd,
		int, family,
		int, type,
		uint32_t, filter_mask),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, netlink_cmd, netlink_cmd)
		ctf_integer(int, family, family)
		ctf_integer(int, type, type)
		ctf_integer(uint32_t, filter_mask, filter_mask)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_interface,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_nexthop_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_route_change_read_unicast,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_rule_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_tc_qdisc_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_tc_class_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)


TRACEPOINT_EVENT(
	frr_zebra,
	netlink_tc_filter_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* __ZEBRA_TRACE_H__ */
