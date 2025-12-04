// SPDX-License-Identifier: GPL-2.0-or-later
/* Tracing for BGP
 *
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
 */

#if !defined(_BGP_TRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _BGP_TRACE_H

#include "lib/trace.h"

#ifdef HAVE_LTTNG

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_bgp

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "bgpd/bgp_trace.h"

#include <lttng/tracepoint.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "lib/stream.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_mh.h"


/* clang-format off */

TRACEPOINT_EVENT_CLASS(
	frr_bgp,
	packet_process,
	TP_ARGS(struct peer *, peer, bgp_size_t, size),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
	)
)

#define PKT_PROCESS_TRACEPOINT_INSTANCE(name)                                  \
	TRACEPOINT_EVENT_INSTANCE(                                             \
		frr_bgp, packet_process, name,                                 \
		TP_ARGS(struct peer *, peer, bgp_size_t, size))                \
	TRACEPOINT_LOGLEVEL(frr_bgp, name, TRACE_INFO)

PKT_PROCESS_TRACEPOINT_INSTANCE(open_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(keepalive_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(update_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(notification_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(capability_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(refresh_process)

TRACEPOINT_EVENT(
	frr_bgp,
	packet_read,
	TP_ARGS(struct peer_connection *, connection, struct stream *, pkt),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(connection->peer))
		ctf_sequence_hex(uint8_t, packet, pkt->data, size_t,
				 STREAM_READABLE(pkt))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, packet_read, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	process_update,
	TP_ARGS(struct peer *, peer, char *, pfx, uint32_t, addpath_id, afi_t,
		afi, safi_t, safi, struct attr *, attr),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_string(prefix, pfx)
		ctf_integer(uint32_t, addpath_id, addpath_id)
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_integer_hex(intptr_t, attribute_ptr, attr)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, process_update, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	input_filter,
	TP_ARGS(struct peer *, peer, char *, pfx, afi_t, afi, safi_t, safi,
		const char *, result),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_string(prefix, pfx)
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_string(action, result)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, input_filter, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	output_filter,
	TP_ARGS(struct peer *, peer, char *, pfx, afi_t, afi, safi_t, safi,
		const char *, result),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_string(prefix, pfx)
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_string(action, result)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, output_filter, TRACE_INFO)

/* BMP tracepoints */

/* BMP mirrors a packet to all mirror-enabled targets */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_mirror_packet,
	TP_ARGS(struct peer *, peer, uint8_t, type, struct stream *, pkt),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_integer(uint8_t, type, type)
		ctf_sequence_hex(uint8_t, packet, pkt->data, size_t,
				 STREAM_READABLE(pkt))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_mirror_packet, TRACE_INFO)


/* BMP sends an EOR */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_eor,
	TP_ARGS(afi_t, afi, safi_t, safi, uint8_t, flags, uint8_t, peer_type_flag,
		struct bgp *, bgp),
	TP_FIELDS(
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_integer(uint8_t, flags, flags)
		ctf_integer(uint8_t, peer_type_flag, peer_type_flag)
		ctf_string(bgp, bgp->name_pretty)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_eor, TRACE_INFO)


/* BMP updates its copy of the last OPEN a peer sent */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_update_saved_open,
	TP_ARGS(struct peer *, peer, struct stream *, pkt),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_sequence_hex(uint8_t, packet, pkt->data, size_t,
				 STREAM_READABLE(pkt))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_update_saved_open, TRACE_DEBUG)


/* BMP is notified of a peer status change internally */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_peer_status_changed,
	TP_ARGS(struct peer *, peer),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_peer_status_changed, TRACE_DEBUG)


/*
 * BMP is notified that a peer has transitioned in the opposite direction of
 * Established internally
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_peer_backward_transition,
	TP_ARGS(struct peer *, peer),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_peer_backward, TRACE_DEBUG)


/*
 * BMP is hooked for a route process
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_process,
	TP_ARGS(struct peer *, peer, char *, pfx, afi_t,
		afi, safi_t, safi, bool, withdraw),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_string(prefix, pfx)
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_integer(bool, withdraw, withdraw)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_process, TRACE_DEBUG)

/*
 * BMP is hooked for a nexthop tracking event
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bmp_nht_path_valid,
	TP_ARGS(struct bgp *, bgp, char *, pfx, struct bgp_path_info *,
		path, bool, valid),
	TP_FIELDS(
		ctf_string(bgp, bgp->name_pretty)
		ctf_string(prefix, pfx)
		ctf_string(path, PEER_HOSTNAME(path->peer))
		ctf_integer(bool, valid, valid)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, bmp_nht_path_valid, TRACE_DEBUG)

/*
 * bgp_dest_lock/bgp_dest_unlock
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bgp_dest_lock,
	TP_ARGS(struct bgp_dest *, dest),
	TP_FIELDS(
		ctf_string(prefix, bgp_dest_get_prefix_str(dest))
		ctf_integer(unsigned int, count, bgp_dest_get_lock_count(dest))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_dest_lock, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_dest_unlock,
	TP_ARGS(struct bgp_dest *, dest),
	TP_FIELDS(
		ctf_string(prefix, bgp_dest_get_prefix_str(dest))
		ctf_integer(unsigned int, count, bgp_dest_get_lock_count(dest))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_dest_unlock, TRACE_INFO)

/*
 * peer_lock/peer_unlock
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bgp_peer_lock,
	TP_ARGS(struct peer *, peer,
		const char *, name),
	TP_FIELDS(
		ctf_string(caller, name)
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_integer(unsigned int, count, peer->lock)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_peer_lock, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_peer_unlock,
	TP_ARGS(struct peer *, peer,
		const char *, name),
	TP_FIELDS(
		ctf_string(caller, name)
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_integer(unsigned int, count, peer->lock)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_peer_unlock, TRACE_INFO)

/*
 * bgp_path_info_add/bgp_path_info_free
 */
TRACEPOINT_EVENT(
	frr_bgp,
	bgp_path_info_add,
	TP_ARGS(struct bgp_dest *, dest,
		struct bgp_path_info *, bpi,
		const char *, name),
	TP_FIELDS(
		ctf_string(caller, name)
		ctf_string(prefix, bgp_dest_get_prefix_str(dest))
		ctf_string(peer, PEER_HOSTNAME(bpi->peer))
		ctf_integer(unsigned int, dest_lock,
			    bgp_dest_get_lock_count(dest))
		ctf_integer(unsigned int, peer_lock, bpi->peer->lock)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_path_info_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_path_info_free,
	TP_ARGS(struct bgp_path_info *, bpi,
		const char *, name),
	TP_FIELDS(
		ctf_string(caller, name)
		ctf_string(prefix, bgp_dest_get_prefix_str(bpi->net))
		ctf_string(peer, PEER_HOSTNAME(bpi->peer))
		ctf_integer(unsigned int, dest_lock,
			    bgp_dest_get_lock_count(bpi->net))
		ctf_integer(unsigned int, peer_lock, bpi->peer->lock)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_path_info_free, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mac_ip_zsend,
	TP_ARGS(int, add, struct bgpevpn *, vpn,
		const struct prefix_evpn *, pfx,
		struct ipaddr *, vtep, esi_t *, esi),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_integer(vni_t, vni, (vpn ? vpn->vni : 0))
		ctf_integer(uint32_t, eth_tag, &pfx->prefix.macip_addr.eth_tag)
		ctf_array(unsigned char, mac, &pfx->prefix.macip_addr.mac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, &pfx->prefix.macip_addr.ip,
			sizeof(struct ipaddr))
		ctf_array(unsigned char, vtep, vtep, sizeof(struct ipaddr))
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mac_ip_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_bum_vtep_zsend,
	TP_ARGS(int, add, struct bgpevpn *, vpn,
		const struct prefix_evpn *, pfx),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_integer(vni_t, vni, (vpn ? vpn->vni : 0))
		ctf_integer_network_hex(unsigned int, vtep,
			pfx->prefix.imet_addr.ip.ipaddr_v4.s_addr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_bum_vtep_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_vtep_zsend,
	TP_ARGS(bool, add, struct bgp_evpn_es *, es,
		struct bgp_evpn_es_vtep *, es_vtep),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_string(esi, es->esi_str)
		ctf_string(vtep, es_vtep->vtep_str)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_vtep_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_nhg_zsend,
	TP_ARGS(bool, add, bool, type_v4, uint32_t, nhg_id,
		struct bgp_evpn_es_vrf *, es_vrf),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_string(type, type_v4 ? "v4" : "v6")
		ctf_integer(unsigned int, nhg, nhg_id)
		ctf_string(esi, es_vrf->es->esi_str)
		ctf_integer(int, vrf, es_vrf->bgp_vrf->vrf_id)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_nhg_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_nh_zsend,
	TP_ARGS(uint32_t, nhg_id, struct bgp_evpn_es_vtep *, vtep,
		struct bgp_evpn_es_vrf *, es_vrf),
	TP_FIELDS(
		ctf_integer(unsigned int, nhg, nhg_id)
		ctf_string(vtep, vtep->vtep_str)
		ctf_integer(int, svi, es_vrf->bgp_vrf->l3vni_svi_ifindex)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_nh_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_nh_rmac_zsend,
	TP_ARGS(bool, add, struct bgp_evpn_nh *, nh),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_integer(int, vrf, nh->bgp_vrf->vrf_id)
		ctf_string(nh, nh->nh_str)
		ctf_array(unsigned char, rmac, &nh->rmac,
			sizeof(struct ethaddr))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_nh_rmac_zsend, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_es_add_zrecv,
	TP_ARGS(esi_t *, esi, struct in_addr, vtep,
		uint8_t, active, uint8_t, bypass, uint16_t, df_pref),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_integer(uint8_t, active, active)
		ctf_integer(uint8_t, bypass, bypass)
		ctf_integer(uint16_t, df_pref, df_pref)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_es_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_es_del_zrecv,
	TP_ARGS(esi_t *, esi),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_es_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_es_evi_add_zrecv,
	TP_ARGS(esi_t *, esi, vni_t, vni),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_es_evi_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_es_evi_del_zrecv,
	TP_ARGS(esi_t *, esi, vni_t, vni),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_es_evi_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_es_evi_vtep_add,
	TP_ARGS(esi_t *, esi, vni_t, vni, struct in_addr, vtep,
		uint8_t, ead_es),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_integer(uint8_t, ead_es, ead_es)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_es_evi_vtep_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_es_evi_vtep_del,
	TP_ARGS(esi_t *, esi, vni_t, vni, struct in_addr, vtep,
		uint8_t, ead_es),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
		ctf_integer(uint8_t, ead_es, ead_es)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_es_evi_vtep_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_ead_es_evi_route_upd,
	TP_ARGS(esi_t *, esi, vni_t, vni,
		uint8_t, route_type,
		struct in_addr, vtep),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
		ctf_integer(uint8_t, route_type, route_type)
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_ead_es_evi_route_upd, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_mh_local_ead_es_evi_route_del,
	TP_ARGS(esi_t *, esi, vni_t, vni,
		uint8_t, route_type,
		struct in_addr, vtep),
	TP_FIELDS(
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(vni_t, vni, vni)
		ctf_integer(uint8_t, route_type, route_type)
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_mh_local_ead_es_evi_route_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_vni_add_zrecv,
	TP_ARGS(vni_t, vni, struct ipaddr *, vtep, vrf_id_t, vrf,
			struct in_addr, mc_grp),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, vtep, vtep, sizeof(struct ipaddr))
		ctf_integer_network_hex(unsigned int, mc_grp,
			mc_grp.s_addr)
		ctf_integer(int, vrf, vrf)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_vni_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_vni_del_zrecv,
	TP_ARGS(vni_t, vni),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_vni_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_macip_add_zrecv,
	TP_ARGS(vni_t, vni, struct ethaddr *, mac,
		struct ipaddr *, ip, uint32_t, flags,
		uint32_t, seqnum, esi_t *, esi),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			sizeof(struct ipaddr))
		ctf_integer(uint32_t, flags, flags)
		ctf_integer(uint32_t, seq, seqnum)
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_macip_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_macip_del_zrecv,
	TP_ARGS(vni_t, vni, struct ethaddr *, mac, struct ipaddr *, ip,
			int, state),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			sizeof(struct ipaddr))
		ctf_integer(int, state, state)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_macip_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_advertise_type5,
	TP_ARGS(vrf_id_t, vrf, const struct prefix_evpn *, pfx,
		struct ethaddr *, rmac, struct ipaddr *, vtep),
	TP_FIELDS(
		ctf_integer(int, vrf_id, vrf)
		ctf_array(unsigned char, ip, &pfx->prefix.prefix_addr.ip,
			sizeof(struct ipaddr))
		ctf_array(unsigned char, rmac, rmac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, vtep, vtep, sizeof(struct ipaddr))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_advertise_type5, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_withdraw_type5,
	TP_ARGS(vrf_id_t, vrf, const struct prefix_evpn *, pfx),
	TP_FIELDS(
		ctf_integer(int, vrf_id, vrf)
		ctf_array(unsigned char, ip, &pfx->prefix.prefix_addr.ip,
			sizeof(struct ipaddr))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_withdraw_type5, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_l3vni_add_zrecv,
	TP_ARGS(vni_t, vni, vrf_id_t, vrf,
			struct ethaddr *, svi_rmac,
			struct ethaddr *, vrr_rmac, int, filter,
			struct ipaddr *, vtep, int, svi_ifindex,
			bool, anycast_mac),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_integer(int, vrf, vrf)
		ctf_array(unsigned char, svi_rmac, svi_rmac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, vrr_rmac, vrr_rmac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, vtep, vtep, sizeof(struct ipaddr))
		ctf_integer(int, filter, filter)
		ctf_integer(int, svi_ifindex, svi_ifindex)
		ctf_string(anycast_mac, anycast_mac ? "y" : "n")
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_l3vni_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_local_l3vni_del_zrecv,
	TP_ARGS(vni_t, vni, vrf_id_t, vrf),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_integer(int, vrf, vrf)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_local_l3vni_del_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	eor_send,
	TP_ARGS(char *, bgp_name, uint8_t, afi, uint8_t, safi,
		char *, peer_name),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_integer(uint8_t, afi, afi)
		ctf_integer(uint8_t, safi, safi)
		ctf_string(peer, peer_name)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, eor_send, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	eor_received,
	TP_ARGS(char *, bgp_name, uint8_t, afi, uint8_t, safi,
		char *, peer_name),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_integer(uint8_t, afi, afi)
		ctf_integer(uint8_t, safi, safi)
		ctf_string(peer, peer_name)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, eor_received, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	gr_bgp_state,
	TP_ARGS(char *, bgp_name, bool, all_peers_admin_down, bool, bgp_in_gr,
		uint8_t, global_gr_mode, bool, gr_cfgd_at_nbr_lvl),
	TP_FIELDS(ctf_string(bgp_instance, bgp_name)
		ctf_integer(bool, all_peers_admin_down, all_peers_admin_down)
		ctf_integer(bool, bgp_in_gr, bgp_in_gr)
		ctf_integer(uint8_t, global_gr_mode, global_gr_mode)
		ctf_integer(bool, gr_cfgd_at_nbr_lvl, gr_cfgd_at_nbr_lvl)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, gr_bgp_state, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	session_state_change,
	TP_ARGS(struct peer *, peer, uint8_t, location),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_integer(uint8_t, location, location)
		ctf_integer(enum bgp_fsm_status, old_status, peer->connection->ostatus)
		ctf_integer(enum bgp_fsm_status, new_status, peer->connection->status)
		ctf_integer(enum bgp_fsm_events, event, peer->cur_event)
		ctf_integer(uint32_t, vrf_id, peer->bgp->vrf_id)
		ctf_integer(int, fd, peer->connection->fd)
		ctf_integer(uint32_t, established_peers, peer->bgp->established_peers)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, session_state_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	connection_attempt,
	TP_ARGS(struct peer *, peer, int, status),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_integer(int, status, status)
		ctf_integer(enum bgp_fsm_status, current_status, peer->connection->status)
		ctf_integer(uint32_t, vrf_id, peer->bgp->vrf_id)
		ctf_integer(int, fd, peer->connection->fd)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, connection_attempt, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	fsm_event,
	TP_ARGS(struct peer *, peer, enum bgp_fsm_events, event, enum bgp_fsm_status, current_status, enum bgp_fsm_status, next_status, int, fd),
	TP_FIELDS(
		ctf_string(peer, PEER_HOSTNAME(peer))
		ctf_integer(enum bgp_fsm_events, event, event)
		ctf_integer(enum bgp_fsm_status, current_status, current_status)
		ctf_integer(enum bgp_fsm_status, next_status, next_status)
		ctf_integer(int, fd, fd)
		ctf_integer(uint32_t, vrf_id, peer->bgp->vrf_id)
	)
)

TRACEPOINT_LOGLEVEL(frr_bgp, fsm_event, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_err_str,
	TP_ARGS(char *, peer_host,
	  uint64_t, peer_flags,
	  uint8_t, location),
	TP_FIELDS(
		ctf_string(peer, peer_host)
		ctf_integer(uint64_t, peer_flags, peer_flags)
		ctf_integer(uint8_t, location, location)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_err_str, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	evpn_ignore_suppress_route,
	TP_ARGS(struct bgp_dest *, dest, struct peer *, peer),
	TP_FIELDS(
		ctf_string(prefix, bgp_dest_get_prefix_str(dest))
		ctf_string(peer, PEER_HOSTNAME(peer))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, evpn_ignore_suppress_route, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_process_local_ip_prefix_zrecv,
	TP_ARGS(struct prefix *, prefix, int, cmd, vrf_id_t, vrf_id),
	TP_FIELDS(
		ctf_array(unsigned char, prefix, prefix, sizeof(struct prefix))
		ctf_integer(int, cmd, cmd)
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_process_local_ip_prefix_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_vxlan_flood_control,
	TP_ARGS(struct bgp *, bgp, enum vxlan_flood_control, flood_ctrl),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, bgp->vrf_id)
		ctf_integer(enum vxlan_flood_control, flood_ctrl, flood_ctrl)
		ctf_integer(uint8_t, flood_enabled, flood_ctrl == VXLAN_FLOOD_HEAD_END_REPL)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_vxlan_flood_control, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_route_notify_owner,
	TP_ARGS(enum zapi_route_notify_owner, route_status, struct bgp_dest *, dest, struct prefix *, prefix),
	TP_FIELDS(
		ctf_integer(enum zapi_route_notify_owner, route_status, route_status)
		ctf_integer(uint32_t, dest_flags, dest->flags)
		ctf_array(unsigned char, prefix, prefix, sizeof(struct prefix))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_route_notify_owner, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_evpn_advertise_type,
	TP_ARGS(struct bgp *, bgp, int, advertise, vni_t, vni, uint8_t, location),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, bgp->vrf_id)
		ctf_integer(int, advertise, advertise)
		ctf_integer(vni_t, vni, vni)
		ctf_integer(uint8_t, location, location)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_evpn_advertise_type, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_dup_addr_detection,
	TP_ARGS(struct bgp *, bgp),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, bgp->vrf_id)
		ctf_integer(bool, dup_addr_detect, bgp->evpn_info->dup_addr_detect)
		ctf_integer(uint32_t, dad_max_moves, bgp->evpn_info->dad_max_moves)
		ctf_integer(uint32_t, dad_time, bgp->evpn_info->dad_time)
		ctf_integer(bool, dad_freeze, bgp->evpn_info->dad_freeze)
		ctf_integer(uint32_t, dad_freeze_time, bgp->evpn_info->dad_freeze_time)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_dup_addr_detection, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_zebra_radv_operation,
	TP_ARGS(uint8_t, location, vrf_id_t, vrf_id, const char *, peer_host),
	TP_FIELDS(
		ctf_integer(uint8_t, location, location)
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_string(peer_host, peer_host)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_zebra_radv_operation, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_ifp_oper,
	TP_ARGS(struct interface *, ifp, uint8_t, loc),
	TP_FIELDS(
		ctf_integer(vrf_id_t, vrf_id, ifp->vrf->vrf_id)
		ctf_string(interface, ifp->name)
		ctf_integer(uint8_t, location, loc)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_ifp_oper, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_redistribute_add_zrecv,
	TP_ARGS(struct bgp *, bgp, struct prefix *, pfx, ifindex_t, ifindex,
		enum nexthop_types_t, nhtype, uint8_t, distance,
		enum blackhole_type, bhtype, uint32_t, metric,
		uint8_t, type,
		unsigned short, instance,
		route_tag_t, tag),
	TP_FIELDS(
		ctf_integer(uint32_t, vrf_id, bgp->vrf_id)
		ctf_array(unsigned char, prefix, pfx, sizeof(struct prefix))
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_integer(enum nexthop_types_t, nhtype, nhtype)
		ctf_integer(uint8_t, distance, distance)
		ctf_integer(enum blackhole_type, bhtype, bhtype)
		ctf_integer(uint32_t, metric, metric)
		ctf_integer(uint8_t, type, type)
		ctf_integer(unsigned short, instance, instance)
		ctf_integer(route_tag_t, tag, tag)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_redistribute_add_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	bgp_redistribute_delete_zrecv,
	TP_ARGS(struct bgp *, bgp, struct prefix *, pfx, uint8_t, type,
		unsigned short, instance),
	TP_FIELDS(
		ctf_integer(uint32_t, vrf_id, bgp->vrf_id)
		ctf_array(unsigned char, prefix, pfx, sizeof(struct prefix))
		ctf_integer(uint8_t, type, type)
		ctf_integer(unsigned short, instance, instance)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, bgp_redistribute_delete_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	interface_address_oper_zrecv,
	TP_ARGS(vrf_id_t, vrf_id, char *, name,
		struct prefix *, address,
		uint8_t, loc),
	TP_FIELDS(
		ctf_integer(int, vrf_id, vrf_id)
		ctf_string(ifname, name)
		ctf_array(unsigned char, address, address, sizeof(struct prefix))
		ctf_integer(uint8_t, location, loc)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, interface_address_oper_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	router_id_update_zrecv,
	TP_ARGS(vrf_id_t, vrf_id, struct prefix *, router_id),
	TP_FIELDS(
		ctf_integer(int, vrf_id, vrf_id)
		ctf_array(unsigned char, router_id, router_id, sizeof(struct prefix))
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, router_id_update_zrecv, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	ug_bgp_aggregate_install,
	TP_ARGS(const struct prefix *, prefix, uint8_t, afi, uint8_t, safi,
		uint8_t, origin),
	TP_FIELDS(
		ctf_array(unsigned char, prefix, prefix, sizeof(struct prefix))
		ctf_integer(uint8_t, afi, afi)
		ctf_integer(uint8_t, safi, safi)
		ctf_integer(uint8_t, origin, origin)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, ug_bgp_aggregate_install, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	ug_create_delete,
	TP_ARGS(uint8_t, operation, uint64_t, updgrp_id),
	TP_FIELDS(
		ctf_integer(uint8_t, operation, operation)
		ctf_integer(uint64_t, updgrp_id, updgrp_id)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, ug_create_delete, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	ug_subgroup_create_delete,
	TP_ARGS(uint8_t, operation, uint64_t, updgrp_id, uint64_t, subgroup_id),
	TP_FIELDS(
		ctf_integer(uint8_t, operation, operation)
		ctf_integer(uint64_t, updgrp_id, updgrp_id)
		ctf_integer(uint64_t, subgroup_id, subgroup_id)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, ug_subgroup_create_delete, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	ug_subgroup_add_remove_peer,
	TP_ARGS(uint8_t, operation, char *, peer_host, uint8_t, pafi, uint8_t, psafi, uint32_t, pafid,
		uint64_t, subgroup_id, uint32_t, peer_count),
	TP_FIELDS(
		ctf_integer(uint8_t, operation, operation)
		ctf_string(peer, peer_host)
		ctf_integer(uint8_t, pafi, pafi)
		ctf_integer(uint8_t, psafi, psafi)
		ctf_integer(uint32_t, pafid, pafid)
		ctf_integer(uint64_t, subgroup_id, subgroup_id)
		ctf_integer(uint32_t, peer_count, peer_count)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, ug_subgroup_add_remove_peer, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	ug_subgroup_merge,
	TP_ARGS(uint64_t, updgrp_id, uint64_t, subgroup_id, uint32_t, peer_count,
		uint64_t, target_updgrp_id, uint64_t, target_subgroup_id, const char *, reason),
	TP_FIELDS(
		ctf_integer(uint64_t, updgrp_id, updgrp_id)
		ctf_integer(uint64_t, subgroup_id, subgroup_id)
		ctf_integer(uint32_t, peer_count, peer_count)
		ctf_integer(uint64_t, target_updgrp_id, target_updgrp_id)
		ctf_integer(uint64_t, target_subgroup_id, target_subgroup_id)
		ctf_string(reason, reason)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, ug_subgroup_merge, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_bgp,
	ug_subgroup_split_peer,
	TP_ARGS(uint64_t, old_updgrp_id, uint64_t, old_subgroup_id, uint32_t, old_peer_count,
		char *, peer_host, uint64_t, new_updgrp_id, uint64_t, new_subgroup_id),
	TP_FIELDS(
		ctf_integer(uint64_t, old_updgrp_id, old_updgrp_id)
		ctf_integer(uint64_t, old_subgroup_id, old_subgroup_id)
		ctf_integer(uint32_t, old_peer_count, old_peer_count)
		ctf_string(peer, peer_host)
		ctf_integer(uint64_t, new_updgrp_id, new_updgrp_id)
		ctf_integer(uint64_t, new_subgroup_id, new_subgroup_id)
	)
)
TRACEPOINT_LOGLEVEL(frr_bgp, ug_subgroup_split_peer, TRACE_INFO)

/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* _BGP_TRACE_H */
