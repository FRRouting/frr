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
#include "zebra/zebra_evpn_mac.h"

#ifdef HAVE_NETLINK
#include "zebra/rt_netlink.h"
#include <linux/netlink.h>
#include <linux/neighbour.h>
#endif /* HAVE_NETLINK */

#define INTF_INVALID_INDEX 4294967295
#define INTF_INVALID_NAME  "not-found"

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

TRACEPOINT_EVENT(
	frr_zebra,
	if_down_nhg_dependents,
	TP_ARGS(const struct interface *, ifp, struct nhg_hash_entry *, nhe),
	TP_FIELDS(
		ctf_string(ifp, ifp->name)
		ctf_integer(unsigned int, ifindex, ifp->ifindex)
		ctf_integer(uint32_t, nhe_id, nhe->id)
		ctf_integer(uint32_t, nhe_flags, nhe->flags)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_down_nhg_dependents, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	nhg_ctx_process_new_nhe,
	TP_ARGS(uint32_t, nhe_id),
	TP_FIELDS(
		ctf_integer(uint32_t, nhe_id, nhe_id)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, nhg_ctx_process_new_nhe, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_interface_nhg_reinstall,
	TP_ARGS(const struct interface *, ifp, struct nhg_hash_entry *, nhe, uint8_t, loc),
	TP_FIELDS(
		ctf_string(ifp, ifp->name)
		ctf_integer(unsigned int, ifindex, ifp->ifindex)
		ctf_integer(uint32_t, nhe_id, nhe->id)
		ctf_integer(uint32_t, nhe_flags, nhe->flags)
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_interface_nhg_reinstall, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_nhg_dep,
	TP_ARGS(uint32_t, nhe_id, uint32_t, dep_id),
	TP_FIELDS(
		ctf_integer(uint32_t, nhe_id, nhe_id)
		ctf_integer(uint32_t, dep_id, dep_id)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_dep, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_nhg_dplane_result,
	TP_ARGS(enum dplane_op_e, op, uint32_t, nhe_id, enum zebra_dplane_result, status),
	TP_FIELDS(
		ctf_integer(uint32_t, op, op)
		ctf_integer(uint32_t, nhe_id, nhe_id)
		ctf_integer(uint32_t, status, status)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_dplane_result, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_nhg_free_nhe_refcount,
	TP_ARGS(struct nhg_hash_entry *, nhe),
	TP_FIELDS(
		ctf_integer(uint32_t, nhe_id, nhe->id)
		ctf_integer(uint32_t, nhe_flags, nhe->flags)
		ctf_integer(int, ref_cnt, nhe->refcnt)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_free_nhe_refcount, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_nhg_id_counter_wrapped,
	TP_ARGS(int, id),
	TP_FIELDS(
		ctf_integer(int, counter_id, id)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_id_counter_wrapped, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_nhg_install_kernel,
	TP_ARGS(struct nhg_hash_entry *, nhe, uint8_t, loc),
	TP_FIELDS(
		ctf_integer(uint32_t, nhe_id, nhe->id)
		ctf_integer(uint32_t, nhe_flags, nhe->flags)
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_install_kernel, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_nhg_intf_lkup_failed,
	TP_ARGS(struct nhg_hash_entry *, nhe),
	TP_FIELDS(
		ctf_integer(int, if_index, nhe->nhg.nexthop->ifindex)
		ctf_integer(int, vrf_id, nhe->nhg.nexthop->vrf_id)
		ctf_integer_hex(uint32_t, nhe_id, nhe->id)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_intf_lkup_failed, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_nhg_nhe2grp_internal_failure,
	TP_ARGS(int, id),
	TP_FIELDS(
		ctf_integer(int, depend_id, id)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_nhe2grp_internal_failure, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_nhg_uninstall_kernel,
	TP_ARGS(struct nhg_hash_entry *, nhe, int, ret),
	TP_FIELDS(
		ctf_integer(uint32_t, nhe_id, nhe->id)
		ctf_integer(uint32_t, nhe_flags, nhe->flags)
		ctf_integer(int, dplane_status, ret)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_uninstall_kernel, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zread_nhg_add,
	TP_ARGS(uint32_t, id, uint16_t, proto, struct nexthop_group *, nhg, const char *, nexthop),
	TP_FIELDS(
		ctf_integer(uint32_t, id, id)
		ctf_integer(uint16_t, proto, proto)
		ctf_integer(int, vrf_id, nhg->nexthop->vrf_id)
		ctf_integer(int, if_index, nhg->nexthop->ifindex)
		ctf_integer(int, type, nhg->nexthop->type)
		ctf_string(nexthops, nexthop)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zread_nhg_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zread_nhg_del,
	TP_ARGS(uint32_t, id, uint16_t, proto),
	TP_FIELDS(
		ctf_integer(uint32_t, id, id)
		ctf_integer(uint16_t, proto, proto)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zread_nhg_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	dplane_vtep_add_del,
	TP_ARGS(const struct interface *, ifp, const struct ipaddr *, ip, vni_t, vni, uint8_t, loc),
	TP_FIELDS(
		ctf_string(ifp, ifp->name)
		ctf_integer(unsigned int, ifindex, ifp->ifindex)
		ctf_integer(int, vni, vni)
		ctf_array(unsigned char, ip_addr, ip, sizeof(struct ipaddr))
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, dplane_vtep_add_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	get_srv6_sid,
	TP_ARGS(const char *, ctx_str, struct in6_addr *, sid_value, const char *, locator_name),
	TP_FIELDS(
		ctf_string(ctx_str, ctx_str)
		ctf_array(unsigned char, sid_value, sid_value ? sid_value : &in6addr_any, sizeof(struct in6_addr))
		ctf_string(locator_name, locator_name ? locator_name : "")
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, get_srv6_sid, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	get_srv6_sid_explicit,
	TP_ARGS(const char *, ctx_str, struct in6_addr *, sid_value, uint8_t, loc),
	TP_FIELDS(
		ctf_string(ctx_str, ctx_str)
		ctf_array(unsigned char, sid_value, sid_value, sizeof(struct in6_addr))
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, get_srv6_sid_explicit, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	release_srv6_sid,
	TP_ARGS(struct in6_addr *, sid_value, const char *, ctx_str, uint8_t, proto, uint16_t, instance, uint16_t, client_list_count),
	TP_FIELDS(
		ctf_array(unsigned char, sid_value, sid_value, sizeof(struct in6_addr))
		ctf_string(ctx_str, ctx_str)
		ctf_integer(uint8_t, proto, proto)
		ctf_integer(uint16_t, instance, instance)
		ctf_integer(uint16_t, client_list_count, client_list_count)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, release_srv6_sid, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	release_srv6_sid_func_explicit,
	TP_ARGS(struct prefix_ipv6 *, prefix, uint32_t, sid_func),
	TP_FIELDS(
		ctf_array(unsigned char, block_prefix, prefix, sizeof(struct prefix_ipv6))
		ctf_integer(uint32_t, sid_func, sid_func)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, release_srv6_sid_func_explicit, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	srv6_manager_get_sid_internal,
	TP_ARGS(const char *, ctx_str, struct in6_addr *, sid_value, const char *, locator_name, int, ret, uint8_t, loc),
	TP_FIELDS(
		ctf_string(ctx_str, ctx_str)
		ctf_array(unsigned char, sid_value, sid_value ? sid_value : &in6addr_any, sizeof(struct in6_addr))
		ctf_string(locator_name, locator_name ? locator_name : "")
		ctf_integer(int, ret, ret)
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, srv6_manager_get_sid_internal, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	srv6_manager_release_sid_internal,
	TP_ARGS(const char *, ctx_str, const char *, locator_name),
	TP_FIELDS(
		ctf_string(ctx_str, ctx_str)
		ctf_string(locator_name, locator_name ? locator_name : "")
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, srv6_manager_release_sid_internal, TRACE_INFO)

#ifdef HAVE_NETLINK

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_macfdb_change,
	TP_ARGS(
		struct nlmsghdr *, h,
		struct ndmsg *, ndm,
		uint32_t, nhg_id,
		vni_t, vni,
		const struct ethaddr *, mac,
		const struct ipaddr *, vtep_ip),
	TP_FIELDS(
		ctf_string(nl_msg_type, nlmsg_type2str(h->nlmsg_type) ?
			   nlmsg_type2str(h->nlmsg_type) : "(Invalid Msg Type)")
		ctf_integer(unsigned int, ndm_ifindex, ndm->ndm_ifindex)
		ctf_integer(int, ndm_state, ndm->ndm_state)
		ctf_integer(uint32_t, ndm_flags, ndm->ndm_flags)
		ctf_integer(uint32_t, nhg, nhg_id)
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
		ctf_array(unsigned char, vtep_ip, vtep_ip, sizeof(struct ipaddr))
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_macfdb_change, TRACE_INFO)

#endif /* HAVE_NETLINK */

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_intf_err,
	TP_ARGS(const char *, ifname, ifindex_t, ifindex, uint8_t, location),
	TP_FIELDS(
		ctf_string(ifname, ifname)
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_integer(uint8_t, location, location)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_intf_err, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_neigh_update_msg_encode,
	TP_ARGS(
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		uint32_t, nhg_id,
		uint8_t, flags,
		uint16_t, state,
		uint8_t, family,
		uint8_t, type,
		uint32_t, op),
	TP_FIELDS(
		ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
		ctf_integer(uint32_t, nhg, nhg_id)
		ctf_integer(uint8_t, flags, flags)
		ctf_integer(uint16_t, state, state)
		ctf_integer(uint8_t, family, family)
		ctf_integer(uint8_t, type, type)
		ctf_integer(uint32_t, op, op)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_neigh_update_msg_encode, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_nexthop_change_err,
	TP_ARGS(uint16_t, nlmsg_type, uint32_t, nhg_id),
	TP_FIELDS(
		ctf_integer(uint16_t, nlmsg_type, nlmsg_type)
		ctf_integer(uint32_t, nhg_id, nhg_id)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_nexthop_change_err, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_nexthop_msg_encode,
	TP_ARGS(const struct nexthop *, nh, uint32_t, nhg_id),
	TP_FIELDS(
		ctf_integer(uint32_t, nh_index, nh->ifindex)
		ctf_integer(uint32_t, nh_vrfid, nh->vrf_id)
		ctf_integer(uint32_t, nhg_id, nhg_id)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_nexthop_msg_encode, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_nexthop_msg_encode_err,
	TP_ARGS(uint32_t, nhg_id, const char *, zroute_type, uint8_t, location),
	TP_FIELDS(
		ctf_integer(uint32_t, nhg_id, nhg_id)
		ctf_string(zroute_type, zroute_type)
		ctf_integer(uint8_t, location, location)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_nexthop_msg_encode_err, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_msg_err,
	TP_ARGS(const char *, msg_type, uint32_t, data, uint8_t, location),
	TP_FIELDS(
		ctf_string(msg_type, msg_type)
		ctf_integer(uint32_t, data, data)
		ctf_integer(uint8_t, location, location)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_msg_err, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_send_msg,
	TP_ARGS(const struct nlsock *, nl, struct msghdr, msg),
	TP_FIELDS(
		ctf_string(nl_name, nl->name)
		ctf_integer(uint32_t, msg_len, msg.msg_namelen)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_send_msg, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_route_multipath_msg_encode,
	TP_ARGS(
		const struct prefix *, p,
		int, cmd,
		uint32_t, nhg_id,
		const char *, nexthop),
	TP_FIELDS(
		ctf_string(family, (p->family == AF_INET) ? "AF_INET" : "AF_INET6")
		ctf_array(unsigned char, pfx, p, sizeof(struct prefix))
		ctf_integer(unsigned int, pfxlen, p->prefixlen)
		ctf_integer(uint8_t, cmd, cmd)
		ctf_integer(uint32_t, nhg_id, nhg_id)
		ctf_string(nexthops, nexthop)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_route_multipath_msg_encode, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_vrf_change,
	TP_ARGS(const char *, name, uint8_t, location),
	TP_FIELDS(
		ctf_string(name, name)
		ctf_integer(uint8_t, location, location)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_vrf_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_br_vxlan_upd,
	TP_ARGS(
		struct interface *, ifp,
		vlanid_t, vid),
	TP_FIELDS(
		ctf_string(interface_name, ifp->name)
		ctf_integer(ifindex_t, ifindex, ifp->ifindex)
		ctf_integer(vlanid_t, access_vlan_id, vid)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_br_vxlan_upd, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	vxlan_vni_state_change,
	TP_ARGS(
		uint16_t, id,
		struct zebra_if *, zif,
		vni_t, vni,
		uint8_t, state),
	TP_FIELDS(
		ctf_integer(int, id, id)
		ctf_integer(int, vni, vni)
		ctf_integer(uint8_t, state, state)
		ctf_string(zif_name, zif->ifp->name)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, vxlan_vni_state_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_advertise_gw_macip,
	TP_ARGS(
		int, advertise,
		vni_t, vni,
		int, curr_advertise_gw_macip),
	TP_FIELDS(
		ctf_integer(int, advertise, advertise)
		ctf_integer(vni_t, vni, vni)
		ctf_integer(int, curr_advertise_gw_macip, curr_advertise_gw_macip)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_advertise_gw_macip, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_handle_vni_transition,
	TP_ARGS(
		vni_t, vni,
		uint8_t, loc),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_handle_vni_transition, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_remote_macip_add,
	TP_ARGS(
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		vni_t, vni,
		struct ipaddr*, vtep_ip,
		uint8_t, flags,
		esi_t *, esi),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
		ctf_array(unsigned char, vtep_ip, vtep_ip, sizeof(struct ipaddr))
		ctf_integer(uint8_t, flags, flags)
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_remote_macip_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_remote_macip_del,
	TP_ARGS(
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		vni_t, vni,
		const struct ipaddr *, vtep_ip,
		uint16_t, ipa_len),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
		ctf_array(unsigned char, vtep_ip, vtep_ip, sizeof(struct ipaddr))
		ctf_integer(int, ip_len, ipa_len)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_remote_macip_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_remote_vtep_add,
	TP_ARGS(
		const struct ipaddr *, vtep_ip,
		vni_t, vni,
		int, flood_control),
	TP_FIELDS(
		ctf_array(unsigned char, vtep_ip, vtep_ip,
			  sizeof(struct ipaddr))
		ctf_integer(vni_t, vni, vni)
		ctf_integer(int, flood_control, flood_control)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_remote_vtep_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_remote_vtep_del,
	TP_ARGS(
		const struct ipaddr *, vtep_ip,
		vni_t, vni,
		uint8_t, client_proto),
	TP_FIELDS(
		ctf_array(unsigned char, vtep_ip, vtep_ip,
			  sizeof(struct ipaddr))
		ctf_integer(vni_t, vni, vni)
		ctf_integer(uint8_t, client_proto, client_proto)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_remote_vtep_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_sg_send,
	TP_ARGS(const char *, sg_str, uint16_t, cmd),
	TP_FIELDS(
		ctf_string(SG, sg_str)
		ctf_integer(uint16_t, action, cmd)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_sg_send, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_sg_new,
	TP_ARGS(const char *, sg),
	TP_FIELDS(
		ctf_string(new_vxlan_sg_create, sg)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_sg_new, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_sg_del,
	TP_ARGS(const char *, sg),
	TP_FIELDS(
		ctf_string(vxlan_sg_del, sg)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_sg_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	evpn_dplane_remote_nh_add,
	TP_ARGS(
		struct ethaddr *, mac,
		struct ipaddr *, ip,
		vrf_id_t, vrf_id,
		const struct interface *, ifp),
	TP_FIELDS(
		ctf_array(unsigned char, rmac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, nh_ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(int, vrf_id, vrf_id)
		ctf_integer(unsigned int, ifindex, ifp->ifindex)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, evpn_dplane_remote_nh_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	evpn_dplane_remote_nh_del,
	TP_ARGS(
		struct ethaddr *, mac,
		struct ipaddr *, ip,
		const struct interface *, ifp),
	TP_FIELDS(
		ctf_array(unsigned char, rmac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, nh_ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(unsigned int, ifindex, ifp->ifindex)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, evpn_dplane_remote_nh_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	evpn_dplane_remote_rmac_add,
	TP_ARGS(
		struct zebra_mac *, zrmac,
		struct ipaddr*, vtep_ip,
		vni_t, vni,
		vlanid_t, vid,
		const struct interface *, vxlan_if),
	TP_FIELDS(
		ctf_array(unsigned char, rmac, &zrmac->macaddr,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, vtep_ip, vtep_ip,
			  sizeof(struct ipaddr))
		ctf_integer(vni_t, vni, vni)
		ctf_integer(uint16_t, vlan_id, vid)
		ctf_integer(unsigned int, vxlan_if, vxlan_if->ifindex)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, evpn_dplane_remote_rmac_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	evpn_dplane_remote_rmac_del,
	TP_ARGS(
		struct zebra_mac *, zrmac,
		struct ipaddr *, vtep_ip,
		vni_t, vni,
		vlanid_t, vid,
		const struct interface *, vxlan_if),
	TP_FIELDS(
		ctf_array(unsigned char, rmac, &zrmac->macaddr,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, vtep_ip, vtep_ip,
			  sizeof(struct ipaddr))
		ctf_integer(vni_t, vni, vni)
		ctf_integer(uint16_t, vlan_id, vid)
		ctf_integer(unsigned int, vxlan_if, vxlan_if->ifindex)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, evpn_dplane_remote_rmac_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	l3vni_remote_rmac,
	TP_ARGS(
		uint8_t, loc,
		vni_t, vni,
		const struct ipaddr *, ip,
		const struct ethaddr *, rmac),
	TP_FIELDS(
		ctf_integer(uint8_t, location, loc)
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, vtep_ip, ip,
			  sizeof(struct ipaddr))
		ctf_array(unsigned char, rmac, rmac,
			  sizeof(struct ethaddr))
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, l3vni_remote_rmac, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	l3vni_remote_rmac_update,
	TP_ARGS(
		vni_t, vni,
		struct ipaddr *, old_vtep_ip,
		struct ipaddr *, ip,
		const struct ethaddr *, rmac),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, old_vtep_ip, old_vtep_ip,
			  sizeof(struct ipaddr))
		ctf_array(unsigned char, new_vtep, ip,
			  sizeof(struct ipaddr))
		ctf_array(unsigned char, rmac, rmac,
			  sizeof(struct ethaddr))
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, l3vni_remote_rmac_update, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	l3vni_remote_vtep_nh_upd,
	TP_ARGS(
		vni_t, vni,
		const struct ipaddr *, ip,
		struct ipaddr *, new_vtep_ip,
		struct ethaddr, mac),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, old_vtep, ip,
			  sizeof(struct ipaddr))
		ctf_array(unsigned char, new_vtep_ip, new_vtep_ip,
			  sizeof(struct ipaddr))
		ctf_array(unsigned char, rmac, &mac,
			  sizeof(struct ethaddr))
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, l3vni_remote_vtep_nh_upd, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	remote_nh_add_rmac_change,
	TP_ARGS(
		vni_t, vni,
		const struct ethaddr *, oldmac,
		const struct ethaddr *, newmac,
		const struct ipaddr *, vtep_ip,
		uint8_t, refcnt),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, oldmac, oldmac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, newmac, newmac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, vtep_ip, vtep_ip,
			  sizeof(struct ipaddr))
		ctf_integer(uint8_t, refcnt, refcnt)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, remote_nh_add_rmac_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	send_l3vni_oper_to_client,
	TP_ARGS(
		vrf_id_t, vrf_id,
		vni_t, vni,
		uint8_t, loc),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_integer(vni_t, vni, vni)
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, send_l3vni_oper_to_client, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zevpn_build_l2vni_hash,
	TP_ARGS(
		vni_t, vni,
		char *, if_name,
		ifindex_t, ifindex,
		struct ipaddr *, vtep_ip),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_string(interface, if_name)
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_array(unsigned char, vtep_ip, vtep_ip,
			  sizeof(struct ipaddr))
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zevpn_build_l2vni_hash, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zevpn_build_l3vni_hash,
	TP_ARGS(
		vni_t, vni,
		const char *, svi_if_name,
		const char *, mac_vlan_if_name),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_string(svi_interface, svi_if_name)
		ctf_string(mac_vlan_interface, mac_vlan_if_name)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zevpn_build_l3vni_hash, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zevpn_build_vni_hash,
	TP_ARGS(
		vni_t, vni,
		char *, if_name,
		ifindex_t, ifindex,
		uint8_t, loc),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_string(interface, if_name)
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_integer(uint8_t, location, loc)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, zevpn_build_vni_hash, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	building_vni_table,
	TP_ARGS(
		const char *, type,
		char *, if_name),
	TP_FIELDS(
		ctf_string(interface_type, type)
		ctf_string(interface, if_name)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, building_vni_table, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	intf_in_different_ns,
	TP_ARGS(
		char *, if_name,
		ifindex_t, ifindex),
	TP_FIELDS(
		ctf_string(interface, if_name)
		ctf_integer(ifindex_t, ifindex, ifindex)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, intf_in_different_ns, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_netlink_parse_error,
	TP_ARGS(
		uint8_t, location),
	TP_FIELDS(
		ctf_integer(uint8_t, location, location)
	)
)

TRACEPOINT_LOGLEVEL(frr_zebra, if_netlink_parse_error, TRACE_INFO)

/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* __ZEBRA_TRACE_H__ */
