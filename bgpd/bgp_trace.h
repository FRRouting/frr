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
	TP_ARGS(afi_t, afi, safi_t, safi, uint8_t, flags),
	TP_FIELDS(
		ctf_integer(afi_t, afi, afi)
		ctf_integer(safi_t, safi, safi)
		ctf_integer(uint8_t, flags, flags)
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
		struct in_addr, vtep, esi_t *, esi),
	TP_FIELDS(
		ctf_string(action, add ? "add" : "del")
		ctf_integer(vni_t, vni, vpn->vni)
		ctf_array(unsigned char, mac, &pfx->prefix.macip_addr.mac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, &pfx->prefix.macip_addr.ip,
			sizeof(struct ipaddr))
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
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
		ctf_integer(vni_t, vni, vpn->vni)
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
	evpn_local_vni_add_zrecv,
	TP_ARGS(vni_t, vni, struct in_addr, vtep, vrf_id_t, vrf,
			struct in_addr, mc_grp),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
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
	evpn_local_l3vni_add_zrecv,
	TP_ARGS(vni_t, vni, vrf_id_t, vrf,
			struct ethaddr *, svi_rmac,
			struct ethaddr *, vrr_rmac, int, filter,
			struct in_addr, vtep, int, svi_ifindex,
			bool, anycast_mac),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_integer(int, vrf, vrf)
		ctf_array(unsigned char, svi_rmac, svi_rmac,
			sizeof(struct ethaddr))
		ctf_array(unsigned char, vrr_rmac, vrr_rmac,
			sizeof(struct ethaddr))
		ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
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
/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* _BGP_TRACE_H */
