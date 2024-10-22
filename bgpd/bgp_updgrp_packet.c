// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * bgp_updgrp_packet.c: BGP update group packet handling routines
 *
 * @copyright Copyright (C) 2014 Cumulus Networks, Inc.
 *
 * @author Avneesh Sachdev <avneesh@sproute.net>
 * @author Rajesh Varadarajan <rajesh@sproute.net>
 * @author Pradosh Mohapatra <pradosh@sproute.net>
 */

#include <zebra.h>

#include "prefix.h"
#include "frrevent.h"
#include "buffer.h"
#include "stream.h"
#include "command.h"
#include "sockunion.h"
#include "network.h"
#include "memory.h"
#include "filter.h"
#include "routemap.h"
#include "log.h"
#include "plist.h"
#include "linklist.h"
#include "workqueue.h"
#include "hash.h"
#include "queue.h"
#include "mpls.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_addpath.h"

/********************
 * PRIVATE FUNCTIONS
 ********************/

/********************
 * PUBLIC FUNCTIONS
 ********************/
struct bpacket *bpacket_alloc(void)
{
	struct bpacket *pkt;

	pkt = XCALLOC(MTYPE_BGP_PACKET, sizeof(struct bpacket));

	return pkt;
}

void bpacket_free(struct bpacket *pkt)
{
	if (pkt->buffer)
		stream_free(pkt->buffer);
	pkt->buffer = NULL;
	XFREE(MTYPE_BGP_PACKET, pkt);
}

void bpacket_queue_init(struct bpacket_queue *q)
{
	TAILQ_INIT(&(q->pkts));
}

/*
 * bpacket_queue_add_packet
 *
 * Internal function of bpacket_queue - and adds a
 * packet entry to the end of the list.
 *
 * Users of bpacket_queue should use bpacket_queue_add instead.
 */
static void bpacket_queue_add_packet(struct bpacket_queue *q,
				     struct bpacket *pkt)
{
	struct bpacket *last_pkt;

	if (TAILQ_EMPTY(&(q->pkts)))
		TAILQ_INSERT_TAIL(&(q->pkts), pkt, pkt_train);
	else {
		last_pkt = bpacket_queue_last(q);
		TAILQ_INSERT_AFTER(&(q->pkts), last_pkt, pkt, pkt_train);
	}
	q->curr_count++;
	if (q->hwm_count < q->curr_count)
		q->hwm_count = q->curr_count;
}

/*
 * Adds a packet to the bpacket_queue.
 *
 * The stream passed is consumed by this function. So, the caller should
 * not free or use the stream after
 * invoking this function.
 */
struct bpacket *bpacket_queue_add(struct bpacket_queue *q, struct stream *s,
				  struct bpacket_attr_vec_arr *vecarrp)
{
	struct bpacket *pkt;
	struct bpacket *last_pkt;


	pkt = bpacket_alloc();
	if (TAILQ_EMPTY(&(q->pkts))) {
		pkt->ver = 1;
		pkt->buffer = s;
		if (vecarrp)
			memcpy(&pkt->arr, vecarrp,
			       sizeof(struct bpacket_attr_vec_arr));
		else
			bpacket_attr_vec_arr_reset(&pkt->arr);
		bpacket_queue_add_packet(q, pkt);
		return pkt;
	}

	/*
	 * Fill in the new information into the current sentinel and create a
	 * new sentinel.
	 */
	last_pkt = bpacket_queue_last(q);
	assert(last_pkt->buffer == NULL);
	last_pkt->buffer = s;
	if (vecarrp)
		memcpy(&last_pkt->arr, vecarrp,
		       sizeof(struct bpacket_attr_vec_arr));
	else
		bpacket_attr_vec_arr_reset(&last_pkt->arr);

	pkt->ver = last_pkt->ver;
	pkt->ver++;
	bpacket_queue_add_packet(q, pkt);

	return last_pkt;
}

struct bpacket *bpacket_queue_first(struct bpacket_queue *q)
{
	return (TAILQ_FIRST(&(q->pkts)));
}

struct bpacket *bpacket_queue_last(struct bpacket_queue *q)
{
	return TAILQ_LAST(&(q->pkts), pkt_queue);
}

struct bpacket *bpacket_queue_remove(struct bpacket_queue *q)
{
	struct bpacket *first;

	first = bpacket_queue_first(q);
	if (first) {
		TAILQ_REMOVE(&(q->pkts), first, pkt_train);
		q->curr_count--;
	}
	return first;
}

unsigned int bpacket_queue_length(struct bpacket_queue *q)
{
	return q->curr_count - 1;
}

unsigned int bpacket_queue_hwm_length(struct bpacket_queue *q)
{
	return q->hwm_count - 1;
}

bool bpacket_queue_is_full(struct bgp *bgp, struct bpacket_queue *q)
{
	if (q->curr_count >= bgp->default_subgroup_pkt_queue_max)
		return true;
	return false;
}

void bpacket_add_peer(struct bpacket *pkt, struct peer_af *paf)
{
	if (!pkt || !paf)
		return;

	LIST_INSERT_HEAD(&(pkt->peers), paf, pkt_train);
	paf->next_pkt_to_send = pkt;
}

/*
 * bpacket_queue_cleanup
 */
void bpacket_queue_cleanup(struct bpacket_queue *q)
{
	struct bpacket *pkt;

	while ((pkt = bpacket_queue_remove(q))) {
		bpacket_free(pkt);
	}
}

/*
 * bpacket_queue_compact
 *
 * Delete packets that do not need to be transmitted to any peer from
 * the queue.
 *
 * @return the number of packets deleted.
 */
static int bpacket_queue_compact(struct bpacket_queue *q)
{
	int num_deleted;
	struct bpacket *pkt, *removed_pkt;

	num_deleted = 0;

	while (1) {
		pkt = bpacket_queue_first(q);
		if (!pkt)
			break;

		/*
		 * Don't delete the sentinel.
		 */
		if (!pkt->buffer)
			break;

		if (!LIST_EMPTY(&(pkt->peers)))
			break;

		removed_pkt = bpacket_queue_remove(q);
		assert(pkt == removed_pkt);
		bpacket_free(removed_pkt);

		num_deleted++;
	}

	return num_deleted;
}

void bpacket_queue_advance_peer(struct peer_af *paf)
{
	struct bpacket *pkt;
	struct bpacket *old_pkt;

	old_pkt = paf->next_pkt_to_send;
	if (old_pkt->buffer == NULL)
		/* Already at end of list */
		return;

	LIST_REMOVE(paf, pkt_train);
	pkt = TAILQ_NEXT(old_pkt, pkt_train);
	bpacket_add_peer(pkt, paf);

	if (!bpacket_queue_compact(PAF_PKTQ(paf)))
		return;

	/*
	 * Deleted one or more packets. Check if we can now merge this
	 * peer's subgroup into another subgroup.
	 */
	update_subgroup_check_merge(paf->subgroup, "advanced peer in queue");
}

/*
 * bpacket_queue_remove_peer
 *
 * Remove the peer from the packet queue of the subgroup it belongs
 * to.
 */
void bpacket_queue_remove_peer(struct peer_af *paf)
{
	struct bpacket_queue *q;

	q = PAF_PKTQ(paf);
	assert(q);

	LIST_REMOVE(paf, pkt_train);
	paf->next_pkt_to_send = NULL;

	bpacket_queue_compact(q);
}

unsigned int bpacket_queue_virtual_length(struct peer_af *paf)
{
	struct bpacket *pkt;
	struct bpacket *last;
	struct bpacket_queue *q;

	pkt = paf->next_pkt_to_send;
	if (!pkt || (pkt->buffer == NULL))
		/* Already at end of list */
		return 0;

	q = PAF_PKTQ(paf);
	if (TAILQ_EMPTY(&(q->pkts)))
		return 0;

	last = TAILQ_LAST(&(q->pkts), pkt_queue);
	if (last->ver >= pkt->ver)
		return last->ver - pkt->ver;

	/* sequence # rolled over */
	return (UINT_MAX - pkt->ver + 1) + last->ver;
}

/*
 * Dump the bpacket queue
 */
void bpacket_queue_show_vty(struct bpacket_queue *q, struct vty *vty)
{
	struct bpacket *pkt;
	struct peer_af *paf;

	pkt = bpacket_queue_first(q);
	while (pkt) {
		vty_out(vty, "  Packet %p ver %u buffer %p\n", pkt, pkt->ver,
			pkt->buffer);

		LIST_FOREACH (paf, &(pkt->peers), pkt_train) {
			vty_out(vty, "      - %s\n", paf->peer->host);
		}
		pkt = bpacket_next(pkt);
	}
	return;
}

struct stream *bpacket_reformat_for_peer(struct bpacket *pkt,
					 struct peer_af *paf)
{
	struct stream *s = NULL;
	bpacket_attr_vec *vec;
	struct peer *peer;
	struct bgp_filter *filter;

	s = stream_dup(pkt->buffer);
	peer = PAF_PEER(paf);

	vec = &pkt->arr.entries[BGP_ATTR_VEC_NH];

	if (!CHECK_FLAG(vec->flags, BPKT_ATTRVEC_FLAGS_UPDATED))
		return s;

	uint8_t nhlen;
	afi_t nhafi;
	int route_map_sets_nh;

	nhlen = stream_getc_from(s, vec->offset);
	filter = &peer->filter[paf->afi][paf->safi];

	if (peer_cap_enhe(peer, paf->afi, paf->safi))
		nhafi = AFI_IP6;
	else
		nhafi = BGP_NEXTHOP_AFI_FROM_NHLEN(nhlen);

	if (nhafi == AFI_IP) {
		struct in_addr v4nh, *mod_v4nh;
		int nh_modified = 0;
		size_t offset_nh = vec->offset + 1;

		route_map_sets_nh =
			(CHECK_FLAG(vec->flags,
				    BPKT_ATTRVEC_FLAGS_RMAP_IPV4_NH_CHANGED) ||
			 CHECK_FLAG(vec->flags,
				    BPKT_ATTRVEC_FLAGS_RMAP_VPNV4_NH_CHANGED) ||
			 CHECK_FLAG(vec->flags,
				    BPKT_ATTRVEC_FLAGS_RMAP_NH_PEER_ADDRESS));

		switch (nhlen) {
		case BGP_ATTR_NHLEN_IPV4:
			break;
		case BGP_ATTR_NHLEN_VPNV4:
			offset_nh += 8;
			break;
		default:
			/* TODO: handle IPv6 nexthops */
			flog_warn(
				EC_BGP_INVALID_NEXTHOP_LENGTH,
				"%s: %s: invalid MP nexthop length (AFI IP): %u",
				__func__, peer->host, nhlen);
			stream_free(s);
			return NULL;
		}

		stream_get_from(&v4nh, s, offset_nh, IPV4_MAX_BYTELEN);
		mod_v4nh = &v4nh;

		/*
		 * If route-map has set the nexthop, that is normally
		 * used; if it is specified as peer-address, the peering
		 * address is picked up. Otherwise, if NH is unavailable
		 * from attribute, the peering addr is picked up; the
		 * "NH unavailable" case also covers next-hop-self and
		 * some other scenarios - see subgroup_announce_check().
		 * In all other cases, use the nexthop carried in the
		 * attribute unless it is EBGP non-multiaccess and there
		 * is no next-hop-unchanged setting or the peer is EBGP
		 * and the route-map that changed the next-hop value
		 * was applied inbound rather than outbound. Updates to
		 * an EBGP peer should only modify the next-hop if it
		 * was set in an outbound route-map to that peer.
		 * Note: It is assumed route-map cannot set the nexthop
		 * to an invalid value.
		 */
		if (route_map_sets_nh
		    && ((peer->sort != BGP_PEER_EBGP)
			|| ROUTE_MAP_OUT(filter))) {
			if (CHECK_FLAG(
				    vec->flags,
				    BPKT_ATTRVEC_FLAGS_RMAP_NH_PEER_ADDRESS)) {
				mod_v4nh = &peer->nexthop.v4;
				nh_modified = 1;
			}
		} else if (v4nh.s_addr == INADDR_ANY) {
			mod_v4nh = &peer->nexthop.v4;
			nh_modified = 1;
		} else if (peer->sort == BGP_PEER_EBGP
			   && (bgp_multiaccess_check_v4(v4nh, peer) == 0)
			   && !CHECK_FLAG(vec->flags,
					  BPKT_ATTRVEC_FLAGS_RMAP_NH_UNCHANGED)
			   && !peer_af_flag_check(
				   peer, paf->afi, paf->safi,
				   PEER_FLAG_NEXTHOP_UNCHANGED)) {
			/* NOTE: not handling case where NH has new AFI
			 */
			mod_v4nh = &peer->nexthop.v4;
			nh_modified = 1;
		}

		if (nh_modified) /* allow for VPN RD */
			stream_put_in_addr_at(s, offset_nh, mod_v4nh);

		if (bgp_debug_update(peer, NULL, NULL, 0))
			zlog_debug("u%" PRIu64 ":s%" PRIu64
				   " %s send UPDATE w/ nexthop %pI4%s",
				   PAF_SUBGRP(paf)->update_group->id,
				   PAF_SUBGRP(paf)->id, peer->host, mod_v4nh,
				   (nhlen == BGP_ATTR_NHLEN_VPNV4 ? " and RD"
								  : ""));
	} else if (nhafi == AFI_IP6) {
		struct in6_addr v6nhglobal, *mod_v6nhg;
		struct in6_addr v6nhlocal, *mod_v6nhl;
		int gnh_modified, lnh_modified;
		size_t offset_nhglobal = vec->offset + 1;
		size_t offset_nhlocal = vec->offset + 1;

		gnh_modified = lnh_modified = 0;
		mod_v6nhg = &v6nhglobal;
		mod_v6nhl = &v6nhlocal;

		route_map_sets_nh =
			(CHECK_FLAG(vec->flags,
				    BPKT_ATTRVEC_FLAGS_RMAP_IPV6_GNH_CHANGED) ||
			 CHECK_FLAG(
				 vec->flags,
				 BPKT_ATTRVEC_FLAGS_RMAP_VPNV6_GNH_CHANGED) ||
			 CHECK_FLAG(vec->flags,
				    BPKT_ATTRVEC_FLAGS_RMAP_NH_PEER_ADDRESS));

		/*
		 * The logic here is rather similar to that for IPv4, the
		 * additional work being to handle 1 or 2 nexthops.
		 * Also, 3rd party nexthop is not propagated for EBGP
		 * right now.
		 */
		switch (nhlen) {
		case BGP_ATTR_NHLEN_IPV6_GLOBAL:
			break;
		case BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL:
			offset_nhlocal += IPV6_MAX_BYTELEN;
			break;
		case BGP_ATTR_NHLEN_VPNV6_GLOBAL:
			offset_nhglobal += 8;
			break;
		case BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL:
			offset_nhglobal += 8;
			offset_nhlocal += 8 * 2 + IPV6_MAX_BYTELEN;
			break;
		default:
			/* TODO: handle IPv4 nexthops */
			flog_warn(
				EC_BGP_INVALID_NEXTHOP_LENGTH,
				"%s: %s: invalid MP nexthop length (AFI IP6): %u",
				__func__, peer->host, nhlen);
			stream_free(s);
			return NULL;
		}

		stream_get_from(&v6nhglobal, s, offset_nhglobal,
				IPV6_MAX_BYTELEN);

		/*
		 * Updates to an EBGP peer should only modify the
		 * next-hop if it was set in an outbound route-map
		 * to that peer.
		 */
		if (route_map_sets_nh
		    && ((peer->sort != BGP_PEER_EBGP)
			|| ROUTE_MAP_OUT(filter))) {
			if (CHECK_FLAG(
				    vec->flags,
				    BPKT_ATTRVEC_FLAGS_RMAP_NH_PEER_ADDRESS)) {
				mod_v6nhg = &peer->nexthop.v6_global;
				gnh_modified = 1;
			}
		} else if (IN6_IS_ADDR_UNSPECIFIED(&v6nhglobal)) {
			mod_v6nhg = &peer->nexthop.v6_global;
			gnh_modified = 1;
		} else if ((peer->sort == BGP_PEER_EBGP)
			   && (!bgp_multiaccess_check_v6(v6nhglobal, peer))
			   && !CHECK_FLAG(vec->flags,
					  BPKT_ATTRVEC_FLAGS_RMAP_NH_UNCHANGED)
			   && !peer_af_flag_check(
				   peer, paf->afi, paf->safi,
				   PEER_FLAG_NEXTHOP_UNCHANGED)) {
			/* NOTE: not handling case where NH has new AFI
			 */
			mod_v6nhg = &peer->nexthop.v6_global;
			gnh_modified = 1;
		}

		if (IN6_IS_ADDR_UNSPECIFIED(mod_v6nhg)) {
			if (peer->nexthop.v4.s_addr != INADDR_ANY) {
				ipv4_to_ipv4_mapped_ipv6(mod_v6nhg,
							 peer->nexthop.v4);
			}
		}

		if (IS_MAPPED_IPV6(&peer->nexthop.v6_global)) {
			mod_v6nhg = &peer->nexthop.v6_global;
			gnh_modified = 1;
		}

		if (nhlen == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL
		    || nhlen == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL) {
			stream_get_from(&v6nhlocal, s, offset_nhlocal,
					IPV6_MAX_BYTELEN);
			if (IN6_IS_ADDR_UNSPECIFIED(&v6nhlocal)) {
				mod_v6nhl = &peer->nexthop.v6_local;
				lnh_modified = 1;
			}
		}

		if (gnh_modified)
			stream_put_in6_addr_at(s, offset_nhglobal, mod_v6nhg);
		if (lnh_modified)
			stream_put_in6_addr_at(s, offset_nhlocal, mod_v6nhl);

		if (bgp_debug_update(peer, NULL, NULL, 0)) {
			if (nhlen == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL
			    || nhlen == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL)
				zlog_debug(
					"u%" PRIu64 ":s%" PRIu64
					" %s send UPDATE w/ mp_nexthops %pI6, %pI6%s",
					PAF_SUBGRP(paf)->update_group->id,
					PAF_SUBGRP(paf)->id, peer->host,
					mod_v6nhg, mod_v6nhl,
					(nhlen == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL
						 ? " and RD"
						 : ""));
			else
				zlog_debug(
					"u%" PRIu64 ":s%" PRIu64
					" %s send UPDATE w/ mp_nexthop %pI6%s",
					PAF_SUBGRP(paf)->update_group->id,
					PAF_SUBGRP(paf)->id, peer->host,
					mod_v6nhg,
					(nhlen == BGP_ATTR_NHLEN_VPNV6_GLOBAL
						 ? " and RD"
						 : ""));
		}
	} else if (paf->afi == AFI_L2VPN) {
		struct in_addr v4nh, *mod_v4nh;
		int nh_modified = 0;

		stream_get_from(&v4nh, s, vec->offset + 1, 4);
		mod_v4nh = &v4nh;

		/* No route-map changes allowed for EVPN nexthops. */
		if (v4nh.s_addr == INADDR_ANY) {
			mod_v4nh = &peer->nexthop.v4;
			nh_modified = 1;
		}

		if (nh_modified)
			stream_put_in_addr_at(s, vec->offset + 1, mod_v4nh);

		if (bgp_debug_update(peer, NULL, NULL, 0))
			zlog_debug("u%" PRIu64 ":s%" PRIu64
				   " %s send UPDATE w/ nexthop %pI4",
				   PAF_SUBGRP(paf)->update_group->id,
				   PAF_SUBGRP(paf)->id, peer->host, mod_v4nh);
	}

	return s;
}

/*
 * Update the vecarr offsets to go beyond 'pos' bytes, i.e. add 'pos'
 * to each offset.
 */
static void bpacket_attr_vec_arr_update(struct bpacket_attr_vec_arr *vecarr,
					size_t pos)
{
	int i;

	if (!vecarr)
		return;

	for (i = 0; i < BGP_ATTR_VEC_MAX; i++)
		vecarr->entries[i].offset += pos;
}

/*
 * Return if there are packets to build for this subgroup.
 */
bool subgroup_packets_to_build(struct update_subgroup *subgrp)
{
	struct bgp_advertise *adv;

	if (!subgrp)
		return false;

	adv = bgp_adv_fifo_first(&subgrp->sync->withdraw);
	if (adv)
		return true;

	adv = bgp_adv_fifo_first(&subgrp->sync->update);
	if (adv)
		return true;

	return false;
}

/* Make BGP update packet.  */
struct bpacket *subgroup_update_packet(struct update_subgroup *subgrp)
{
	struct bpacket_attr_vec_arr vecarr;
	struct bpacket *pkt;
	struct peer *peer;
	struct stream *s;
	struct stream *snlri;
	struct stream *packet;
	struct bgp_adj_out *adj;
	struct bgp_advertise *adv;
	struct bgp_dest *dest = NULL;
	struct bgp_path_info *path = NULL;
	bgp_size_t total_attr_len = 0;
	unsigned long attrlen_pos = 0;
	size_t mpattrlen_pos = 0;
	size_t mpattr_pos = 0;
	afi_t afi;
	safi_t safi;
	int space_remaining = 0;
	int space_needed = 0;
	char send_attr_str[BUFSIZ];
	int send_attr_printed = 0;
	int num_pfx = 0;
	bool addpath_capable = false;
	int addpath_overhead = 0;
	uint32_t addpath_tx_id = 0;
	struct prefix_rd *prd = NULL;
	mpls_label_t label = MPLS_INVALID_LABEL, *label_pnt = NULL;
	uint8_t num_labels = 0;

	if (!subgrp)
		return NULL;

	if (bpacket_queue_is_full(SUBGRP_INST(subgrp), SUBGRP_PKTQ(subgrp)))
		return NULL;

	peer = SUBGRP_PEER(subgrp);
	afi = SUBGRP_AFI(subgrp);
	safi = SUBGRP_SAFI(subgrp);
	s = subgrp->work;
	stream_reset(s);
	snlri = subgrp->scratch;
	stream_reset(snlri);

	bpacket_attr_vec_arr_reset(&vecarr);

	addpath_capable = bgp_addpath_encode_tx(peer, afi, safi);
	addpath_overhead = addpath_capable ? BGP_ADDPATH_ID_LEN : 0;

	adv = bgp_adv_fifo_first(&subgrp->sync->update);
	while (adv) {
		const struct prefix *dest_p;

		assert(adv->dest);
		dest = adv->dest;
		dest_p = bgp_dest_get_prefix(dest);
		adj = adv->adj;
		addpath_tx_id = adj->addpath_tx_id;
		path = adv->pathi;

		space_remaining = STREAM_CONCAT_REMAIN(s, snlri, STREAM_SIZE(s))
				  - BGP_MAX_PACKET_SIZE_OVERFLOW;
		space_needed =
			BGP_NLRI_LENGTH + addpath_overhead
			+ bgp_packet_mpattr_prefix_size(afi, safi, dest_p);

		/* When remaining space can't include NLRI and it's length.  */
		if (space_remaining < space_needed)
			break;

		/* If packet is empty, set attribute. */
		if (stream_empty(s)) {
			struct peer *from = NULL;

			if (path)
				from = path->peer;

			/* 1: Write the BGP message header - 16 bytes marker, 2
			 * bytes length,
			 * one byte message type.
			 */
			bgp_packet_set_marker(s, BGP_MSG_UPDATE);

			/* 2: withdrawn routes length */
			stream_putw(s, 0);

			/* 3: total attributes length - attrlen_pos stores the
			 * position */
			attrlen_pos = stream_get_endp(s);
			stream_putw(s, 0);

			/* 4: if there is MP_REACH_NLRI attribute, that should
			 * be the first
			 * attribute, according to
			 * draft-ietf-idr-error-handling. Save the
			 * position.
			 */
			mpattr_pos = stream_get_endp(s);

			/* 5: Encode all the attributes, except MP_REACH_NLRI
			 * attr. */
			total_attr_len = bgp_packet_attribute(NULL, peer, s, adv->baa->attr,
							      &vecarr, NULL, afi, safi, from, NULL,
							      NULL, 0, 0, 0);

			space_remaining =
				STREAM_CONCAT_REMAIN(s, snlri, STREAM_SIZE(s))
				- BGP_MAX_PACKET_SIZE_OVERFLOW;
			space_needed = BGP_NLRI_LENGTH + addpath_overhead
				       + bgp_packet_mpattr_prefix_size(
					       afi, safi, dest_p);

			/* If the attributes alone do not leave any room for
			 * NLRI then
			 * return */
			if (space_remaining < space_needed) {
				flog_err(
					EC_BGP_UPDGRP_ATTR_LEN,
					"u%" PRIu64 ":s%" PRIu64" attributes too long, cannot send UPDATE",
					subgrp->update_group->id, subgrp->id);

				/* Flush the FIFO update queue */
				while (adv)
					adv = bgp_advertise_clean_subgroup(
						subgrp, adj);
				return NULL;
			}

			if (BGP_DEBUG(update, UPDATE_OUT)
			    || BGP_DEBUG(update, UPDATE_PREFIX)) {
				memset(send_attr_str, 0, BUFSIZ);
				send_attr_printed = 0;
				bgp_dump_attr(adv->baa->attr, send_attr_str,
					      sizeof(send_attr_str));
			}
		}

		if ((afi == AFI_IP && safi == SAFI_UNICAST)
		    && !peer_cap_enhe(peer, afi, safi))
			stream_put_prefix_addpath(s, dest_p, addpath_capable,
						  addpath_tx_id);
		else {
			/* Encode the prefix in MP_REACH_NLRI attribute */
			if (dest->pdest)
				prd = (struct prefix_rd *)bgp_dest_get_prefix(
					dest->pdest);

			if (safi == SAFI_LABELED_UNICAST) {
				label = bgp_adv_label(dest, path, peer, afi,
						      safi);
				label_pnt = &label;
				num_labels = 1;
			} else if (safi == SAFI_MPLS_VPN && path &&
				   CHECK_FLAG(path->flags,
					      BGP_PATH_MPLSVPN_NH_LABEL_BIND) &&
				   path->mplsvpn.bmnc.nh_label_bind_cache &&
				   path->peer && path->peer != peer &&
				   path->sub_type != BGP_ROUTE_IMPORTED &&
				   path->sub_type != BGP_ROUTE_STATIC &&
				   bgp_mplsvpn_path_uses_valid_mpls_label(
					   path) &&
				   bgp_path_info_nexthop_changed(path, peer,
								 afi)) {
				/* Redistributed mpls vpn route between distinct
				 * peers from 'pi->peer' to 'to',
				 * and an mpls label is used in this path,
				 * and there is a nh label bind entry,
				 * then get appropriate mpls local label. When
				 * called here, 'get_label()' returns a valid
				 * label.
				 */
				label = bgp_mplsvpn_nh_label_bind_get_label(
					path);
				label_pnt = &label;
				num_labels = 1;
			} else {
				num_labels = BGP_PATH_INFO_NUM_LABELS(path);
				label_pnt =
					num_labels
						? &path->extra->labels->label[0]
						: NULL;
			}

			if (stream_empty(snlri))
				mpattrlen_pos = bgp_packet_mpattr_start(
					snlri, peer, afi, safi, &vecarr,
					adv->baa->attr);

			bgp_packet_mpattr_prefix(snlri, afi, safi, dest_p, prd,
						 label_pnt, num_labels,
						 addpath_capable, addpath_tx_id,
						 adv->baa->attr);
		}

		num_pfx++;

		if (bgp_debug_update(NULL, dest_p, subgrp->update_group, 0)) {
			char pfx_buf[BGP_PRD_PATH_STRLEN];

			if (!send_attr_printed) {
				zlog_debug("u%" PRIu64 ":s%" PRIu64" send UPDATE w/ attr: %s",
					   subgrp->update_group->id, subgrp->id,
					   send_attr_str);
				if (!stream_empty(snlri)) {
					iana_afi_t pkt_afi;
					iana_safi_t pkt_safi;

					pkt_afi = afi_int2iana(afi);
					pkt_safi = safi_int2iana(safi);
					zlog_debug(
						"u%" PRIu64 ":s%" PRIu64
						" send MP_REACH for afi/safi %s/%s",
						subgrp->update_group->id,
						subgrp->id,
						iana_afi2str(pkt_afi),
						iana_safi2str(pkt_safi));
				}

				send_attr_printed = 1;
			}

			bgp_debug_rdpfxpath2str(afi, safi, prd, dest_p,
						label_pnt, num_labels,
						addpath_capable, addpath_tx_id,
						bgp_attr_get_evpn_overlay(
							adv->baa->attr),
						pfx_buf, sizeof(pfx_buf));
			zlog_debug("u%" PRIu64 ":s%" PRIu64 " send UPDATE %s",
				   subgrp->update_group->id, subgrp->id,
				   pfx_buf);
		}

		/* Synchnorize attribute.  */
		if (adj->attr)
			bgp_attr_unintern(&adj->attr);
		else
			subgrp->scount++;

		adj->attr = bgp_attr_intern(adv->baa->attr);
		adv = bgp_advertise_clean_subgroup(subgrp, adj);
	}

	if (!stream_empty(s)) {
		if (!stream_empty(snlri)) {
			bgp_packet_mpattr_end(snlri, mpattrlen_pos);
			total_attr_len += stream_get_endp(snlri);
		}

		/* set the total attribute length correctly */
		stream_putw_at(s, attrlen_pos, total_attr_len);

		if (!stream_empty(snlri)) {
			packet = stream_dupcat(s, snlri, mpattr_pos);
			bpacket_attr_vec_arr_update(&vecarr, mpattr_pos);
		} else
			packet = stream_dup(s);
		bgp_packet_set_size(packet);
		if (bgp_debug_update(NULL, NULL, subgrp->update_group, 0))
			zlog_debug(
				"u%" PRIu64 ":s%" PRIu64
				" send UPDATE len %zd (max message len: %hu) numpfx %d",
				subgrp->update_group->id, subgrp->id,
				(stream_get_endp(packet)
				 - stream_get_getp(packet)),
				peer->max_packet_size, num_pfx);
		pkt = bpacket_queue_add(SUBGRP_PKTQ(subgrp), packet, &vecarr);
		stream_reset(s);
		stream_reset(snlri);
		return pkt;
	}
	return NULL;
}

/* Make BGP withdraw packet.  */
/* For ipv4 unicast:
   16-octet marker | 2-octet length | 1-octet type |
    2-octet withdrawn route length | withdrawn prefixes | 2-octet attrlen (=0)
*/
/* For other afi/safis:
   16-octet marker | 2-octet length | 1-octet type |
    2-octet withdrawn route length (=0) | 2-octet attrlen |
     mp_unreach attr type | attr len | afi | safi | withdrawn prefixes
*/
struct bpacket *subgroup_withdraw_packet(struct update_subgroup *subgrp)
{
	struct bpacket *pkt;
	struct stream *s;
	struct bgp_adj_out *adj;
	struct bgp_advertise *adv;
	struct peer *peer;
	struct bgp_dest *dest;
	bgp_size_t unfeasible_len;
	bgp_size_t total_attr_len;
	size_t mp_start = 0;
	size_t attrlen_pos = 0;
	size_t mplen_pos = 0;
	uint8_t first_time = 1;
	afi_t afi;
	safi_t safi;
	int space_remaining = 0;
	int space_needed = 0;
	int num_pfx = 0;
	bool addpath_capable = false;
	int addpath_overhead = 0;
	uint32_t addpath_tx_id = 0;
	const struct prefix_rd *prd = NULL;


	if (!subgrp)
		return NULL;

	if (bpacket_queue_is_full(SUBGRP_INST(subgrp), SUBGRP_PKTQ(subgrp)))
		return NULL;

	peer = SUBGRP_PEER(subgrp);
	afi = SUBGRP_AFI(subgrp);
	safi = SUBGRP_SAFI(subgrp);
	s = subgrp->work;
	stream_reset(s);
	addpath_capable = bgp_addpath_encode_tx(peer, afi, safi);
	addpath_overhead = addpath_capable ? BGP_ADDPATH_ID_LEN : 0;

	while ((adv = bgp_adv_fifo_first(&subgrp->sync->withdraw)) != NULL) {
		const struct prefix *dest_p;

		assert(adv->dest);
		adj = adv->adj;
		dest = adv->dest;
		dest_p = bgp_dest_get_prefix(dest);
		addpath_tx_id = adj->addpath_tx_id;

		space_remaining =
			STREAM_WRITEABLE(s) - BGP_MAX_PACKET_SIZE_OVERFLOW;
		space_needed =
			BGP_NLRI_LENGTH + addpath_overhead + BGP_TOTAL_ATTR_LEN
			+ bgp_packet_mpattr_prefix_size(afi, safi, dest_p);

		if (space_remaining < space_needed)
			break;

		if (stream_empty(s)) {
			bgp_packet_set_marker(s, BGP_MSG_UPDATE);
			stream_putw(s, 0); /* unfeasible routes length */
		} else
			first_time = 0;

		if (afi == AFI_IP && safi == SAFI_UNICAST
		    && !peer_cap_enhe(peer, afi, safi))
			stream_put_prefix_addpath(s, dest_p, addpath_capable,
						  addpath_tx_id);
		else {
			if (dest->pdest)
				prd = (struct prefix_rd *)bgp_dest_get_prefix(
					dest->pdest);

			/* If first time, format the MP_UNREACH header
			 */
			if (first_time) {
				iana_afi_t pkt_afi;
				iana_safi_t pkt_safi;

				pkt_afi = afi_int2iana(afi);
				pkt_safi = safi_int2iana(safi);

				attrlen_pos = stream_get_endp(s);
				/* total attr length = 0 for now.
				 * reevaluate later */
				stream_putw(s, 0);
				mp_start = stream_get_endp(s);
				mplen_pos = bgp_packet_mpunreach_start(s, afi,
								       safi);
				if (bgp_debug_update(NULL, NULL,
						     subgrp->update_group, 0))
					zlog_debug(
						"u%" PRIu64 ":s%" PRIu64
						" send MP_UNREACH for afi/safi %s/%s",
						subgrp->update_group->id,
						subgrp->id,
						iana_afi2str(pkt_afi),
						iana_safi2str(pkt_safi));
			}

			bgp_packet_mpunreach_prefix(s, dest_p, afi, safi, prd,
						    NULL, 0, addpath_capable,
						    addpath_tx_id, NULL);
		}

		num_pfx++;

		if (bgp_debug_update(NULL, dest_p, subgrp->update_group, 0)) {
			char pfx_buf[BGP_PRD_PATH_STRLEN];

			bgp_debug_rdpfxpath2str(afi, safi, prd, dest_p, NULL, 0,
						addpath_capable, addpath_tx_id,
						NULL, pfx_buf, sizeof(pfx_buf));
			zlog_debug("u%" PRIu64 ":s%" PRIu64" send UPDATE %s -- unreachable",
				   subgrp->update_group->id, subgrp->id,
				   pfx_buf);
		}

		subgrp->scount--;

		bgp_adj_out_remove_subgroup(dest, adj, subgrp);
	}

	if (!stream_empty(s)) {
		if (afi == AFI_IP && safi == SAFI_UNICAST
		    && !peer_cap_enhe(peer, afi, safi)) {
			unfeasible_len = stream_get_endp(s) - BGP_HEADER_SIZE
					 - BGP_UNFEASIBLE_LEN;
			stream_putw_at(s, BGP_HEADER_SIZE, unfeasible_len);
			stream_putw(s, 0);
		} else {
			/* Set the mp_unreach attr's length */
			bgp_packet_mpunreach_end(s, mplen_pos);

			/* Set total path attribute length. */
			total_attr_len = stream_get_endp(s) - mp_start;
			stream_putw_at(s, attrlen_pos, total_attr_len);
		}
		bgp_packet_set_size(s);
		if (bgp_debug_update(NULL, NULL, subgrp->update_group, 0))
			zlog_debug("u%" PRIu64 ":s%" PRIu64" send UPDATE (withdraw) len %zd numpfx %d",
				   subgrp->update_group->id, subgrp->id,
				   (stream_get_endp(s) - stream_get_getp(s)),
				   num_pfx);
		pkt = bpacket_queue_add(SUBGRP_PKTQ(subgrp), stream_dup(s),
					NULL);
		stream_reset(s);
		return pkt;
	}

	return NULL;
}

void subgroup_default_update_packet(struct update_subgroup *subgrp,
				    struct attr *attr, struct peer *from)
{
	struct stream *s;
	struct peer *peer;
	struct prefix p;
	unsigned long pos;
	bgp_size_t total_attr_len;
	afi_t afi;
	safi_t safi;
	struct bpacket_attr_vec_arr vecarr;
	bool addpath_capable = false;
	mpls_label_t label = MPLS_LABEL_IMPLICIT_NULL;
	uint8_t num_labels = 0;

	if (DISABLE_BGP_ANNOUNCE)
		return;

	if (!subgrp)
		return;

	peer = SUBGRP_PEER(subgrp);
	afi = SUBGRP_AFI(subgrp);
	safi = SUBGRP_SAFI(subgrp);
	bpacket_attr_vec_arr_reset(&vecarr);
	addpath_capable = bgp_addpath_encode_tx(peer, afi, safi);

	if (safi == SAFI_LABELED_UNICAST) {
		label = mpls_lse_encode((afi == AFI_IP)
						? MPLS_LABEL_IPV4_EXPLICIT_NULL
						: MPLS_LABEL_IPV6_EXPLICIT_NULL,
					0, 0, 1);
		bgp_set_valid_label(&label);
		num_labels = 1;
	}

	memset(&p, 0, sizeof(p));
	p.family = afi2family(afi);
	p.prefixlen = 0;

	/* Logging the attribute. */
	if (bgp_debug_update(NULL, &p, subgrp->update_group, 0)) {
		char attrstr[BUFSIZ];
		/* ' with addpath ID '          17
		 * max strlen of uint32       + 10
		 * +/- (just in case)         +  1
		 * null terminator            +  1
		 * ============================ 29 */
		char tx_id_buf[30];

		attrstr[0] = '\0';

		bgp_dump_attr(attr, attrstr, sizeof(attrstr));

		if (addpath_capable)
			snprintf(tx_id_buf, sizeof(tx_id_buf),
				 " with addpath ID %u",
				 BGP_ADDPATH_TX_ID_FOR_DEFAULT_ORIGINATE);
		else
			tx_id_buf[0] = '\0';

		zlog_debug("u%" PRIu64 ":s%" PRIu64 " send UPDATE %pFX%s %s",
			   (SUBGRP_UPDGRP(subgrp))->id, subgrp->id, &p,
			   tx_id_buf, attrstr);
	}

	s = stream_new(peer->max_packet_size);

	/* Make BGP update packet. */
	bgp_packet_set_marker(s, BGP_MSG_UPDATE);

	/* Unfeasible Routes Length. */
	stream_putw(s, 0);

	/* Make place for total attribute length.  */
	pos = stream_get_endp(s);
	stream_putw(s, 0);
	total_attr_len = bgp_packet_attribute(NULL, peer, s, attr, &vecarr, &p, afi, safi, from,
					      NULL, &label, num_labels, addpath_capable,
					      BGP_ADDPATH_TX_ID_FOR_DEFAULT_ORIGINATE);

	/* Set Total Path Attribute Length. */
	stream_putw_at(s, pos, total_attr_len);

	/* NLRI set. */
	if (p.family == AF_INET && safi == SAFI_UNICAST
	    && !peer_cap_enhe(peer, afi, safi))
		stream_put_prefix_addpath(
			s, &p, addpath_capable,
			BGP_ADDPATH_TX_ID_FOR_DEFAULT_ORIGINATE);

	/* Set size. */
	bgp_packet_set_size(s);

	(void)bpacket_queue_add(SUBGRP_PKTQ(subgrp), s, &vecarr);
	subgroup_trigger_write(subgrp);

	if (!CHECK_FLAG(subgrp->sflags,
			SUBGRP_STATUS_PEER_DEFAULT_ORIGINATED)) {
		subgrp->scount++;
		SET_FLAG(subgrp->sflags, SUBGRP_STATUS_PEER_DEFAULT_ORIGINATED);
	}
}

void subgroup_default_withdraw_packet(struct update_subgroup *subgrp)
{
	struct peer *peer;
	struct stream *s;
	struct prefix p;
	unsigned long attrlen_pos = 0;
	unsigned long cp;
	bgp_size_t unfeasible_len;
	bgp_size_t total_attr_len = 0;
	size_t mp_start = 0;
	size_t mplen_pos = 0;
	afi_t afi;
	safi_t safi;
	bool addpath_capable = false;

	if (DISABLE_BGP_ANNOUNCE)
		return;

	peer = SUBGRP_PEER(subgrp);
	afi = SUBGRP_AFI(subgrp);
	safi = SUBGRP_SAFI(subgrp);
	addpath_capable = bgp_addpath_encode_tx(peer, afi, safi);

	memset(&p, 0, sizeof(p));
	p.family = afi2family(afi);
	p.prefixlen = 0;

	if (bgp_debug_update(NULL, &p, subgrp->update_group, 0)) {
		/* ' with addpath ID '          17
		 * max strlen of uint32       + 10
		 * +/- (just in case)         +  1
		 * null terminator            +  1
		 * ============================ 29 */
		char tx_id_buf[30];

		if (addpath_capable)
			snprintf(tx_id_buf, sizeof(tx_id_buf),
				 " with addpath ID %u",
				 BGP_ADDPATH_TX_ID_FOR_DEFAULT_ORIGINATE);

		zlog_debug("u%" PRIu64 ":s%" PRIu64
			   " send UPDATE %pFX%s -- unreachable",
			   (SUBGRP_UPDGRP(subgrp))->id, subgrp->id, &p,
			   tx_id_buf);
	}

	s = stream_new(peer->max_packet_size);

	/* Make BGP update packet. */
	bgp_packet_set_marker(s, BGP_MSG_UPDATE);

	/* Unfeasible Routes Length. */;
	cp = stream_get_endp(s);
	stream_putw(s, 0);

	/* Withdrawn Routes. */
	if (p.family == AF_INET && safi == SAFI_UNICAST
	    && !peer_cap_enhe(peer, afi, safi)) {
		stream_put_prefix_addpath(
			s, &p, addpath_capable,
			BGP_ADDPATH_TX_ID_FOR_DEFAULT_ORIGINATE);

		unfeasible_len = stream_get_endp(s) - cp - 2;

		/* Set unfeasible len.  */
		stream_putw_at(s, cp, unfeasible_len);

		/* Set total path attribute length. */
		stream_putw(s, 0);
	} else {
		attrlen_pos = stream_get_endp(s);
		stream_putw(s, 0);
		mp_start = stream_get_endp(s);
		mplen_pos = bgp_packet_mpunreach_start(s, afi, safi);
		bgp_packet_mpunreach_prefix(
			s, &p, afi, safi, NULL, NULL, 0, addpath_capable,
			BGP_ADDPATH_TX_ID_FOR_DEFAULT_ORIGINATE, NULL);

		/* Set the mp_unreach attr's length */
		bgp_packet_mpunreach_end(s, mplen_pos);

		/* Set total path attribute length. */
		total_attr_len = stream_get_endp(s) - mp_start;
		stream_putw_at(s, attrlen_pos, total_attr_len);
	}

	bgp_packet_set_size(s);

	(void)bpacket_queue_add(SUBGRP_PKTQ(subgrp), s, NULL);
	subgroup_trigger_write(subgrp);

	if (CHECK_FLAG(subgrp->sflags, SUBGRP_STATUS_PEER_DEFAULT_ORIGINATED)) {
		subgrp->scount--;
		UNSET_FLAG(subgrp->sflags,
			   SUBGRP_STATUS_PEER_DEFAULT_ORIGINATED);
	}
}

static void
bpacket_vec_arr_inherit_attr_flags(struct bpacket_attr_vec_arr *vecarr,
				   enum bpacket_attr_vec_type type,
				   struct attr *attr)
{
	if (CHECK_FLAG(attr->rmap_change_flags,
		       BATTR_RMAP_NEXTHOP_PEER_ADDRESS))
		SET_FLAG(vecarr->entries[BGP_ATTR_VEC_NH].flags,
			 BPKT_ATTRVEC_FLAGS_RMAP_NH_PEER_ADDRESS);

	if (CHECK_FLAG(attr->rmap_change_flags, BATTR_REFLECTED))
		SET_FLAG(vecarr->entries[BGP_ATTR_VEC_NH].flags,
			 BPKT_ATTRVEC_FLAGS_REFLECTED);

	if (CHECK_FLAG(attr->rmap_change_flags, BATTR_RMAP_NEXTHOP_UNCHANGED))
		SET_FLAG(vecarr->entries[BGP_ATTR_VEC_NH].flags,
			 BPKT_ATTRVEC_FLAGS_RMAP_NH_UNCHANGED);

	if (CHECK_FLAG(attr->rmap_change_flags, BATTR_RMAP_IPV4_NHOP_CHANGED))
		SET_FLAG(vecarr->entries[BGP_ATTR_VEC_NH].flags,
			 BPKT_ATTRVEC_FLAGS_RMAP_IPV4_NH_CHANGED);

	if (CHECK_FLAG(attr->rmap_change_flags,
		       BATTR_RMAP_IPV6_GLOBAL_NHOP_CHANGED))
		SET_FLAG(vecarr->entries[BGP_ATTR_VEC_NH].flags,
			 BPKT_ATTRVEC_FLAGS_RMAP_IPV6_GNH_CHANGED);

	if (CHECK_FLAG(attr->rmap_change_flags, BATTR_RMAP_VPNV4_NHOP_CHANGED))
		SET_FLAG(vecarr->entries[BGP_ATTR_VEC_NH].flags,
			 BPKT_ATTRVEC_FLAGS_RMAP_VPNV4_NH_CHANGED);

	if (CHECK_FLAG(attr->rmap_change_flags,
		       BATTR_RMAP_VPNV6_GLOBAL_NHOP_CHANGED))
		SET_FLAG(vecarr->entries[BGP_ATTR_VEC_NH].flags,
			 BPKT_ATTRVEC_FLAGS_RMAP_VPNV6_GNH_CHANGED);

	if (CHECK_FLAG(attr->rmap_change_flags,
		       BATTR_RMAP_IPV6_LL_NHOP_CHANGED))
		SET_FLAG(vecarr->entries[BGP_ATTR_VEC_NH].flags,
			 BPKT_ATTRVEC_FLAGS_RMAP_IPV6_LNH_CHANGED);
}

/* Reset the Attributes vector array. The vector array is used to override
 * certain output parameters in the packet for a particular peer
 */
void bpacket_attr_vec_arr_reset(struct bpacket_attr_vec_arr *vecarr)
{
	int i;

	if (!vecarr)
		return;

	i = 0;
	while (i < BGP_ATTR_VEC_MAX) {
		vecarr->entries[i].flags = 0;
		vecarr->entries[i].offset = 0;
		i++;
	}
}

/* Setup a particular node entry in the vecarr */
void bpacket_attr_vec_arr_set_vec(struct bpacket_attr_vec_arr *vecarr,
				  enum bpacket_attr_vec_type type,
				  struct stream *s, struct attr *attr)
{
	if (!vecarr)
		return;
	assert(type < BGP_ATTR_VEC_MAX);

	SET_FLAG(vecarr->entries[type].flags, BPKT_ATTRVEC_FLAGS_UPDATED);
	vecarr->entries[type].offset = stream_get_endp(s);
	if (attr)
		bpacket_vec_arr_inherit_attr_flags(vecarr, type, attr);
}
