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

/*
 * Loc 1: zebra_gr_process_client
 * Loc 2: zebra_gr_delete_stale_route_table_afi
 */
TRACEPOINT_EVENT(frr_zebra, gr_client_not_found,
		 TP_ARGS(vrf_id_t, vrf_id, uint8_t, afi, uint8_t, loc),
		 TP_FIELDS(ctf_integer(vrf_id_t, vrf_id, vrf_id) ctf_integer(uint8_t, afi, afi)
				   ctf_integer(uint8_t, location, loc)))
TRACEPOINT_LOGLEVEL(frr_zebra, gr_client_not_found, TRACE_INFO)

TRACEPOINT_EVENT(frr_zebra, gr_client_capability,
		 TP_ARGS(uint8_t, cap, vrf_id_t, vrf_id, uint32_t, gr_instance_count),
		 TP_FIELDS(ctf_integer(int, capability, cap) ctf_integer(vrf_id_t, vrf_id, vrf_id)
				   ctf_integer(uint32_t, gr_instance_count, gr_instance_count)))
TRACEPOINT_LOGLEVEL(frr_zebra, gr_client_capability, TRACE_INFO)

TRACEPOINT_EVENT(frr_zebra, gr_client_stale_time,
		 TP_ARGS(uint8_t, cap, vrf_id_t, vrf_id, uint32_t, stale_removal_time),
		 TP_FIELDS(ctf_integer(int, capability, cap) ctf_integer(vrf_id_t, vrf_id, vrf_id)
				   ctf_integer(uint32_t, stale_removal_time, stale_removal_time)))
TRACEPOINT_LOGLEVEL(frr_zebra, stale_removal_time, TRACE_INFO)

TRACEPOINT_EVENT(frr_zebra, gr_client_update,
		 TP_ARGS(uint8_t, cap, vrf_id_t, vrf_id, uint8_t, afi, uint8_t, safi),
		 TP_FIELDS(ctf_integer(int, capability, cap) ctf_integer(vrf_id_t, vrf_id, vrf_id)
				   ctf_integer(uint8_t, afi, afi) ctf_integer(uint8_t, safi, safi)))
TRACEPOINT_LOGLEVEL(frr_zebra, gr_client_update, TRACE_INFO)

TRACEPOINT_EVENT(frr_zebra, gr_process_client_stale_routes,
		 TP_ARGS(const char *, proto, const char *, vrf, uint8_t, afi, bool, pending),
		 TP_FIELDS(ctf_string(client, proto) ctf_string(vrf, vrf)
				   ctf_integer(uint8_t, afi, afi)
					   ctf_integer(bool, gr_pending, pending)))
TRACEPOINT_LOGLEVEL(frr_zebra, gr_process_client_stale_routes, TRACE_INFO)

TRACEPOINT_EVENT(frr_zebra, gr_delete_stale_route_table_afi, TP_ARGS(char *, vrf, uint8_t, afi),
		 TP_FIELDS(ctf_string(vrf, vrf) ctf_integer(uint8_t, afi, afi)))
TRACEPOINT_LOGLEVEL(frr_zebra, gr_delete_stale_route_table_afi, TRACE_INFO)

TRACEPOINT_EVENT(frr_zebra, gr_evpn_stale_entries_cleanup,
		 TP_ARGS(const char *, vrf, uint64_t, gr_cleanup_time),
		 TP_FIELDS(ctf_string(vrf, vrf)
				   ctf_integer(uint64_t, gr_cleanup_time, gr_cleanup_time)))
TRACEPOINT_LOGLEVEL(frr_zebra, gr_evpn_stale_entries_cleanup, TRACE_INFO)

/* clang-format on */
#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* __ZEBRA_TRACE_H__ */
