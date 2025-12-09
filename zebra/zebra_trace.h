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
#include "zebra/interface.h"
#include "zebra/zebra_dplane.h"

/* clang-format off */

TRACEPOINT_EVENT(
	frr_zebra,
	if_add_del_update,
	TP_ARGS(struct interface *, ifp, uint8_t, loc),
	TP_FIELDS(
		ctf_integer(unsigned int, vrfid, ifp->vrf->vrf_id)
		ctf_string(interface_name, ifp->name)
		ctf_integer(ifindex_t, ifindex, ifp->ifindex)
		ctf_integer(uint8_t, ifstatus, ifp->status)
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_add_del_update, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_protodown,
	TP_ARGS(const struct interface *, ifp, bool, new_down, uint32_t, old_bitfield, uint32_t,
		new_bitfield, uint8_t, loc),
	TP_FIELDS(
		ctf_string(interface_name, ifp->name)
		ctf_integer(ifindex_t, ifindex, ifp->ifindex)
		ctf_integer(bool, protodown, new_down)
		ctf_integer(uint32_t, old_bitfield, old_bitfield)
		ctf_integer(uint32_t, new_bitfield, new_bitfield)
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_protodown, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_upd_ctx_dplane_result,
	TP_ARGS(struct interface *, ifp, bool, down, bool, pd_reason_val,
		enum dplane_op_e, oper, uint8_t, loc),
	TP_FIELDS(
		ctf_integer(uint32_t, oper, oper)
		ctf_string(interface_name, ifp->name)
		ctf_integer(ifindex_t, ifindex, ifp->ifindex)
		ctf_integer(bool, down, down)
		ctf_integer(bool, pd_reason_val, pd_reason_val)
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_upd_ctx_dplane_result, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_vrf_change,
	TP_ARGS(ifindex_t, ifindex, const char *, name, uint32_t, tableid, uint8_t, loc),
	TP_FIELDS(
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_string(vrf_name, name)
		ctf_integer(uint32_t, tableid, tableid)
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_vrf_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_dplane_result,
	TP_ARGS(enum dplane_op_e, oper, enum zebra_dplane_result, dplane_result, ns_id_t,
		ns_id, struct interface *, ifp),
	TP_FIELDS(
		ctf_integer(uint32_t, oper, oper)
		ctf_string(interface_name, ifp ? ifp->name : " ")
		ctf_integer(ifindex_t, ifindex, ifp ? ifp->ifindex : -1)
		ctf_integer(uint32_t, dplane_result, dplane_result)
		ctf_integer(ns_id_t, ns_id, ns_id)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_dplane_result, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_dplane_ifp_handling,
	TP_ARGS(const char *, name, ifindex_t, ifindex, uint8_t, loc),
	TP_FIELDS(
		ctf_string(interface_name, name)
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_dplane_ifp_handling, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra, if_dplane_ifp_handling_new,
	TP_ARGS(const char *, name, ifindex_t, ifindex, vrf_id_t, vrf_id, enum zebra_iftype,
		zif_type, enum zebra_slave_iftype, zif_slave_type, ifindex_t, master_ifindex,
		uint64_t, flags, uint8_t, loc),
	TP_FIELDS(
		ctf_string(interface_name, name)
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_integer(uint16_t, zif_type, zif_type)
		ctf_integer(uint16_t, zif_slave_type, zif_slave_type)
		ctf_integer(ifindex_t, master_ifindex, master_ifindex)
		ctf_integer(uint64_t, flags, flags)
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_dplane_ifp_handling_new, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_dplane_ifp_handling_vrf_change,
	TP_ARGS(const char *, name, ifindex_t, ifindex, vrf_id_t, old_vrf_id, vrf_id_t,
		vrf_id),
	TP_FIELDS(
		ctf_string(interface_name, name)
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_integer(vrf_id_t, old_vrf_id, old_vrf_id)
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_dplane_ifp_handling_vrf_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_ip_addr_add_del,
	TP_ARGS(const char *, name, struct prefix *, address, uint8_t, loc),
	TP_FIELDS(
		ctf_string(ifname, name)
		ctf_array(unsigned char, address, address, sizeof(struct prefix))
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_ip_addr_add_del, TRACE_INFO)

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

TRACEPOINT_EVENT(
	frr_zebra,
	get_iflink_speed,
	TP_ARGS(const char *, ifname, int, error, const char *, strerr, uint8_t, location),
	TP_FIELDS(
		ctf_string(ifname, ifname)
		ctf_integer(int, error, error)
		ctf_string(strerr, strerr)
		ctf_integer(uint8_t, location, location)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, get_iflink_speed, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	ip_prefix_send_to_client,
	TP_ARGS(vrf_id_t, vrf_id, uint16_t, cmd, struct prefix *, p),
	TP_FIELDS(
		ctf_integer(int, vrfid, vrf_id)
		ctf_integer(uint16_t, cmd, cmd)
		ctf_integer(unsigned int, prefix_len, p->prefixlen)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, ip_prefix_send_to_client, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	rib_process_subq_dequeue,
	TP_ARGS(int, qindex),
	TP_FIELDS(
		ctf_integer(int, qindex, qindex)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, rib_process_subq_dequeue, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	rib_uninstall_kernel_route,
	TP_ARGS(const char *, prefix, struct nhg_hash_entry *, nhe, int, ret),
	TP_FIELDS(
		ctf_string(prefix, prefix)
		ctf_integer(uint32_t, nhe_id, nhe->id)
		ctf_integer(uint32_t, nhe_flags, nhe->flags)
		ctf_integer(int, dplane_status, ret)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, rib_uninstall_kernel_route, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zread_route_add,
	TP_ARGS(struct zapi_route, api, char *, pfx, vrf_id_t, vrf_id, const char *, nexthop),
	TP_FIELDS(
		ctf_integer(int, api_flag, api.flags)
		ctf_integer(int, api_msg, api.message)
		ctf_integer(int, api_safi, api.safi)
		ctf_integer(unsigned int, nhg_id, api.nhgid)
		ctf_string(prefix, pfx)
		ctf_integer(int, vrf_id, vrf_id)
		ctf_string(nexthops, nexthop)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zread_route_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zread_route_del,
	TP_ARGS(struct zapi_route, api, char *, pfx, uint32_t, table_id),
	TP_FIELDS(
		ctf_integer(int, api_flag, api.flags)
		ctf_integer(int, api_msg, api.message)
		ctf_integer(int, api_safi, api.safi)
		ctf_string(prefix, pfx)
		ctf_integer(int, table_id, table_id)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zread_route_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zsend_redistribute_route,
	TP_ARGS(uint32_t, cmd, struct zserv *, client, struct zapi_route, api,
		const char *, nexthop),
	TP_FIELDS(
		ctf_string(cmd, zserv_command_string(cmd))
		ctf_integer(uint8_t, client_proto, client->proto)
		ctf_integer(uint8_t, api_type, api.type)
		ctf_integer(uint32_t, vrfid, api.vrf_id)
		ctf_integer(unsigned int, prefix_len, api.prefix.prefixlen)
		ctf_string(nexthops, nexthop)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zsend_redistribute_route, TRACE_INFO)

/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* __ZEBRA_TRACE_H__ */
