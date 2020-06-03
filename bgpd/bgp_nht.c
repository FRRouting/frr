/* BGP Nexthop tracking
 * Copyright (C) 2013 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "thread.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "log.h"
#include "memory.h"
#include "nexthop.h"
#include "vrf.h"
#include "filter.h"
#include "nexthop_group.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_rd.h"

extern struct zclient *zclient;

static void register_zebra_rnh(struct bgp_nexthop_cache *bnc,
			       int is_bgp_static_route);
static void unregister_zebra_rnh(struct bgp_nexthop_cache *bnc,
				 int is_bgp_static_route);
static void evaluate_paths(struct bgp_nexthop_cache *bnc);
static int make_prefix(int afi, struct bgp_path_info *pi, struct prefix *p);

static int bgp_isvalid_nexthop(struct bgp_nexthop_cache *bnc)
{
	return (bgp_zebra_num_connects() == 0
		|| (bnc && CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID)));
}

static int bgp_isvalid_labeled_nexthop(struct bgp_nexthop_cache *bnc)
{
	return (bgp_zebra_num_connects() == 0
		|| (bnc && CHECK_FLAG(bnc->flags, BGP_NEXTHOP_LABELED_VALID)));
}

static void bgp_unlink_nexthop_check(struct bgp_nexthop_cache *bnc)
{
	if (LIST_EMPTY(&(bnc->paths)) && !bnc->nht_info) {
		if (BGP_DEBUG(nht, NHT)) {
			char buf[PREFIX2STR_BUFFER];
			zlog_debug("bgp_unlink_nexthop: freeing bnc %s(%s)",
				   bnc_str(bnc, buf, PREFIX2STR_BUFFER),
				   bnc->bgp->name_pretty);
		}
		unregister_zebra_rnh(bnc,
				     CHECK_FLAG(bnc->flags, BGP_STATIC_ROUTE));
		bgp_node_set_bgp_nexthop_info(bnc->node, NULL);
		bgp_unlock_node(bnc->node);
		bnc->node = NULL;
		bnc_free(bnc);
	}
}

void bgp_unlink_nexthop(struct bgp_path_info *path)
{
	struct bgp_nexthop_cache *bnc = path->nexthop;

	if (!bnc)
		return;

	path_nh_map(path, NULL, false);

	bgp_unlink_nexthop_check(bnc);
}

void bgp_unlink_nexthop_by_peer(struct peer *peer)
{
	struct prefix p;
	struct bgp_node *rn;
	struct bgp_nexthop_cache *bnc;
	afi_t afi = family2afi(peer->su.sa.sa_family);

	if (!sockunion2hostprefix(&peer->su, &p))
		return;

	rn = bgp_node_get(peer->bgp->nexthop_cache_table[afi], &p);

	bnc = bgp_node_get_bgp_nexthop_info(rn);
	if (!bnc)
		return;

	/* cleanup the peer reference */
	bnc->nht_info = NULL;

	bgp_unlink_nexthop_check(bnc);
}

/*
 * A route and its nexthop might belong to different VRFs. Therefore,
 * we need both the bgp_route and bgp_nexthop pointers.
 */
int bgp_find_or_add_nexthop(struct bgp *bgp_route, struct bgp *bgp_nexthop,
			    afi_t afi, struct bgp_path_info *pi,
			    struct peer *peer, int connected)
{
	struct bgp_node *rn;
	struct bgp_nexthop_cache *bnc;
	struct prefix p;
	int is_bgp_static_route = 0;
	const struct prefix *bnc_p;

	if (pi) {
		is_bgp_static_route = ((pi->type == ZEBRA_ROUTE_BGP)
				       && (pi->sub_type == BGP_ROUTE_STATIC))
					      ? 1
					      : 0;

		/* Since Extended Next-hop Encoding (RFC5549) support, we want
		   to derive
		   address-family from the next-hop. */
		if (!is_bgp_static_route)
			afi = BGP_ATTR_NEXTHOP_AFI_IP6(pi->attr) ? AFI_IP6
								 : AFI_IP;

		/* This will return true if the global IPv6 NH is a link local
		 * addr */
		if (make_prefix(afi, pi, &p) < 0)
			return 1;
	} else if (peer) {
		if (!sockunion2hostprefix(&peer->su, &p)) {
			if (BGP_DEBUG(nht, NHT)) {
				zlog_debug(
					"%s: Attempting to register with unknown AFI %d (not %d or %d)",
					__func__, afi, AFI_IP, AFI_IP6);
			}
			return 0;
		}
	} else
		return 0;

	if (is_bgp_static_route)
		rn = bgp_node_get(bgp_nexthop->import_check_table[afi], &p);
	else
		rn = bgp_node_get(bgp_nexthop->nexthop_cache_table[afi], &p);

	bnc = bgp_node_get_bgp_nexthop_info(rn);
	if (!bnc) {
		bnc = bnc_new();
		bgp_node_set_bgp_nexthop_info(rn, bnc);
		bnc->node = rn;
		bnc->bgp = bgp_nexthop;
		bgp_lock_node(rn);
		if (BGP_DEBUG(nht, NHT)) {
			char buf[PREFIX2STR_BUFFER];

			zlog_debug("Allocated bnc %s(%s) peer %p",
				   bnc_str(bnc, buf, PREFIX2STR_BUFFER),
				   bnc->bgp->name_pretty, peer);
		}
	}

	bnc_p = bgp_node_get_prefix(bnc->node);

	bgp_unlock_node(rn);
	if (is_bgp_static_route) {
		SET_FLAG(bnc->flags, BGP_STATIC_ROUTE);

		/* If we're toggling the type, re-register */
		if ((CHECK_FLAG(bgp_route->flags, BGP_FLAG_IMPORT_CHECK))
		    && !CHECK_FLAG(bnc->flags, BGP_STATIC_ROUTE_EXACT_MATCH)) {
			SET_FLAG(bnc->flags, BGP_STATIC_ROUTE_EXACT_MATCH);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		} else if ((!CHECK_FLAG(bgp_route->flags,
					BGP_FLAG_IMPORT_CHECK))
			   && CHECK_FLAG(bnc->flags,
					 BGP_STATIC_ROUTE_EXACT_MATCH)) {
			UNSET_FLAG(bnc->flags, BGP_STATIC_ROUTE_EXACT_MATCH);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		}
	}
	/* When nexthop is already known, but now requires 'connected'
	 * resolution,
	 * re-register it. The reverse scenario where the nexthop currently
	 * requires
	 * 'connected' resolution does not need a re-register (i.e., we treat
	 * 'connected-required' as an override) except in the scenario where
	 * this
	 * is actually a case of tracking a peer for connectivity (e.g., after
	 * disable connected-check).
	 * NOTE: We don't track the number of paths separately for 'connected-
	 * required' vs 'connected-not-required' as this change is not a common
	 * scenario.
	 */
	else if (connected && !CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED)) {
		SET_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
	} else if (peer && !connected
		   && CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED)) {
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
	}
	if (bgp_route->inst_type == BGP_INSTANCE_TYPE_VIEW) {
		SET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		SET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
	} else if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED)
		   && !is_default_host_route(bnc_p))
		register_zebra_rnh(bnc, is_bgp_static_route);

	if (pi && pi->nexthop != bnc) {
		/* Unlink from existing nexthop cache, if any. This will also
		 * free
		 * the nexthop cache entry, if appropriate.
		 */
		bgp_unlink_nexthop(pi);

		/* updates NHT pi list reference */
		path_nh_map(pi, bnc, true);

		if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID) && bnc->metric)
			(bgp_path_info_extra_get(pi))->igpmetric = bnc->metric;
		else if (pi->extra)
			pi->extra->igpmetric = 0;
	} else if (peer)
		bnc->nht_info = (void *)peer; /* NHT peer reference */

	/*
	 * We are cheating here.  Views have no associated underlying
	 * ability to detect nexthops.  So when we have a view
	 * just tell everyone the nexthop is valid
	 */
	if (bgp_route->inst_type == BGP_INSTANCE_TYPE_VIEW)
		return 1;
	else
		return (bgp_isvalid_nexthop(bnc));
}

void bgp_delete_connected_nexthop(afi_t afi, struct peer *peer)
{
	struct bgp_node *rn;
	struct bgp_nexthop_cache *bnc;
	struct prefix p;

	if (!peer)
		return;

	if (!sockunion2hostprefix(&peer->su, &p))
		return;

	rn = bgp_node_lookup(
		peer->bgp->nexthop_cache_table[family2afi(p.family)], &p);
	if (!rn) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug(
				"Cannot find connected NHT node for peer %s(%s)",
				peer->host, peer->bgp->name_pretty);
		return;
	}

	bnc = bgp_node_get_bgp_nexthop_info(rn);
	if (!bnc) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug(
				"Cannot find connected NHT node for peer %s(%s) on route_node as expected",
				peer->host, peer->bgp->name_pretty);
		bgp_unlock_node(rn);
		return;
	}
	bgp_unlock_node(rn);

	if (bnc->nht_info != peer) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug(
				"Connected NHT %p node for peer %s(%s) points to %p",
				bnc, peer->host, bnc->bgp->name_pretty,
				bnc->nht_info);
		return;
	}

	bnc->nht_info = NULL;

	if (LIST_EMPTY(&(bnc->paths))) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug(
				"Freeing connected NHT node %p for peer %s(%s)",
				bnc, peer->host, bnc->bgp->name_pretty);
		unregister_zebra_rnh(bnc, 0);
		bgp_node_set_bgp_nexthop_info(bnc->node, NULL);
		bgp_unlock_node(bnc->node);
		bnc_free(bnc);
	}
}

void bgp_parse_nexthop_update(int command, vrf_id_t vrf_id)
{
	struct bgp_node *rn = NULL;
	struct bgp_nexthop_cache *bnc;
	struct nexthop *nexthop;
	struct nexthop *oldnh;
	struct nexthop *nhlist_head = NULL;
	struct nexthop *nhlist_tail = NULL;
	int i;
	struct bgp *bgp;
	struct zapi_route nhr;

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp) {
		flog_err(
			EC_BGP_NH_UPD,
			"parse nexthop update: instance not found for vrf_id %u",
			vrf_id);
		return;
	}

	if (!zapi_nexthop_update_decode(zclient->ibuf, &nhr)) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug("%s[%s]: Failure to decode nexthop update",
				   __func__, bgp->name_pretty);
		return;
	}

	if (command == ZEBRA_NEXTHOP_UPDATE)
		rn = bgp_node_lookup(
			bgp->nexthop_cache_table[family2afi(nhr.prefix.family)],
			&nhr.prefix);
	else if (command == ZEBRA_IMPORT_CHECK_UPDATE)
		rn = bgp_node_lookup(
			bgp->import_check_table[family2afi(nhr.prefix.family)],
			&nhr.prefix);

	if (!rn) {
		if (BGP_DEBUG(nht, NHT)) {
			char buf[PREFIX2STR_BUFFER];
			prefix2str(&nhr.prefix, buf, sizeof(buf));
			zlog_debug("parse nexthop update(%s(%s)): rn not found",
				   buf, bgp->name_pretty);
		}
		return;
	}

	bnc = bgp_node_get_bgp_nexthop_info(rn);
	if (!bnc) {
		if (BGP_DEBUG(nht, NHT)) {
			char buf[PREFIX2STR_BUFFER];

			prefix2str(&nhr.prefix, buf, sizeof(buf));
			zlog_debug(
				"parse nexthop update(%s(%s)): bnc node info not found",
				buf, bgp->name_pretty);
		}
		bgp_unlock_node(rn);
		return;
	}

	bgp_unlock_node(rn);
	bnc->last_update = bgp_clock();
	bnc->change_flags = 0;

	/* debug print the input */
	if (BGP_DEBUG(nht, NHT)) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(&nhr.prefix, buf, sizeof(buf));
		zlog_debug(
			"%s(%u): Rcvd NH update %s - metric %d/%d #nhops %d/%d flags 0x%x",
			bnc->bgp->name_pretty, vrf_id, buf, nhr.metric,
			bnc->metric, nhr.nexthop_num, bnc->nexthop_num,
			bnc->flags);
	}

	if (nhr.metric != bnc->metric)
		bnc->change_flags |= BGP_NEXTHOP_METRIC_CHANGED;

	if (nhr.nexthop_num != bnc->nexthop_num)
		bnc->change_flags |= BGP_NEXTHOP_CHANGED;

	if (nhr.nexthop_num) {
		struct peer *peer = bnc->nht_info;

		/* notify bgp fsm if nbr ip goes from invalid->valid */
		if (!bnc->nexthop_num)
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);

		bnc->flags |= BGP_NEXTHOP_VALID;
		bnc->metric = nhr.metric;
		bnc->nexthop_num = nhr.nexthop_num;

		bnc->flags &= ~BGP_NEXTHOP_LABELED_VALID; /* check below */

		for (i = 0; i < nhr.nexthop_num; i++) {
			int num_labels = 0;

			nexthop = nexthop_from_zapi_nexthop(&nhr.nexthops[i]);

			/*
			 * Turn on RA for the v6 nexthops
			 * we receive from bgp.  This is to allow us
			 * to work with v4 routing over v6 nexthops
			 */
			if (peer && !peer->ifp
			    && CHECK_FLAG(peer->flags,
					  PEER_FLAG_CAPABILITY_ENHE)
			    && nhr.prefix.family == AF_INET6
			    && nexthop->type != NEXTHOP_TYPE_BLACKHOLE) {
				struct interface *ifp;

				ifp = if_lookup_by_index(nexthop->ifindex,
							 nexthop->vrf_id);
				if (ifp)
					zclient_send_interface_radv_req(
						zclient, nexthop->vrf_id, ifp,
						true,
						BGP_UNNUM_DEFAULT_RA_INTERVAL);
			}
			/* There is at least one label-switched path */
			if (nexthop->nh_label &&
				nexthop->nh_label->num_labels) {

				bnc->flags |= BGP_NEXTHOP_LABELED_VALID;
				num_labels = nexthop->nh_label->num_labels;
			}

			if (BGP_DEBUG(nht, NHT)) {
				char buf[NEXTHOP_STRLEN];
				zlog_debug(
					"    nhop via %s (%d labels)",
					nexthop2str(nexthop, buf, sizeof(buf)),
					num_labels);
			}

			if (nhlist_tail) {
				nhlist_tail->next = nexthop;
				nhlist_tail = nexthop;
			} else {
				nhlist_tail = nexthop;
				nhlist_head = nexthop;
			}

			/* No need to evaluate the nexthop if we have already
			 * determined
			 * that there has been a change.
			 */
			if (bnc->change_flags & BGP_NEXTHOP_CHANGED)
				continue;

			for (oldnh = bnc->nexthop; oldnh; oldnh = oldnh->next)
				if (nexthop_same(oldnh, nexthop))
					break;

			if (!oldnh)
				bnc->change_flags |= BGP_NEXTHOP_CHANGED;
		}
		bnc_nexthop_free(bnc);
		bnc->nexthop = nhlist_head;
	} else {
		bnc->flags &= ~BGP_NEXTHOP_VALID;
		bnc->nexthop_num = nhr.nexthop_num;

		/* notify bgp fsm if nbr ip goes from valid->invalid */
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);

		bnc_nexthop_free(bnc);
		bnc->nexthop = NULL;
	}

	evaluate_paths(bnc);
}

/*
 * Cleanup nexthop registration and status information for BGP nexthops
 * pertaining to this VRF. This is invoked upon VRF deletion.
 */
void bgp_cleanup_nexthops(struct bgp *bgp)
{
	afi_t afi;
	struct bgp_node *rn;
	struct bgp_nexthop_cache *bnc;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		if (!bgp->nexthop_cache_table[afi])
			continue;

		for (rn = bgp_table_top(bgp->nexthop_cache_table[afi]); rn;
		     rn = bgp_route_next(rn)) {
			bnc = bgp_node_get_bgp_nexthop_info(rn);
			if (!bnc)
				continue;

			/* Clear relevant flags. */
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);
		}
	}
}

/**
 * make_prefix - make a prefix structure from the path (essentially
 * path's node.
 */
static int make_prefix(int afi, struct bgp_path_info *pi, struct prefix *p)
{

	int is_bgp_static = ((pi->type == ZEBRA_ROUTE_BGP)
			     && (pi->sub_type == BGP_ROUTE_STATIC))
				    ? 1
				    : 0;
	struct bgp_node *net = pi->net;
	const struct prefix *p_orig = bgp_node_get_prefix(net);

	if (p_orig->family == AF_FLOWSPEC) {
		if (!pi->peer)
			return -1;
		return bgp_flowspec_get_first_nh(pi->peer->bgp,
						 pi, p);
	}
	memset(p, 0, sizeof(struct prefix));
	switch (afi) {
	case AFI_IP:
		p->family = AF_INET;
		if (is_bgp_static) {
			p->u.prefix4 = p_orig->u.prefix4;
			p->prefixlen = p_orig->prefixlen;
		} else {
			p->u.prefix4 = pi->attr->nexthop;
			p->prefixlen = IPV4_MAX_BITLEN;
		}
		break;
	case AFI_IP6:
		p->family = AF_INET6;

		if (is_bgp_static) {
			p->u.prefix6 = p_orig->u.prefix6;
			p->prefixlen = p_orig->prefixlen;
		} else {
			/* If we receive MP_REACH nexthop with ::(LL)
			 * or LL(LL), use LL address as nexthop cache.
			 */
			if (pi->attr->mp_nexthop_len
				    == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL
			    && (IN6_IS_ADDR_UNSPECIFIED(
					&pi->attr->mp_nexthop_global)
				|| IN6_IS_ADDR_LINKLOCAL(
					&pi->attr->mp_nexthop_global)))
				p->u.prefix6 = pi->attr->mp_nexthop_local;
			else
				p->u.prefix6 = pi->attr->mp_nexthop_global;
			p->prefixlen = IPV6_MAX_BITLEN;
		}
		break;
	default:
		if (BGP_DEBUG(nht, NHT)) {
			zlog_debug(
				"%s: Attempting to make prefix with unknown AFI %d (not %d or %d)",
				__func__, afi, AFI_IP, AFI_IP6);
		}
		break;
	}
	return 0;
}

/**
 * sendmsg_zebra_rnh -- Format and send a nexthop register/Unregister
 *   command to Zebra.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc -- the nexthop structure.
 *   int command -- command to send to zebra
 * RETURNS:
 *   void.
 */
static void sendmsg_zebra_rnh(struct bgp_nexthop_cache *bnc, int command)
{
	const struct prefix *p;
	bool exact_match = false;
	int ret;

	if (!zclient)
		return;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bnc->bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: No zebra instance to talk to, not installing NHT entry",
				__func__);
		return;
	}

	if (!bgp_zebra_num_connects()) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: We have not connected yet, cannot send nexthops",
				__func__);
	}
	p = bgp_node_get_prefix(bnc->node);
	if ((command == ZEBRA_NEXTHOP_REGISTER
	     || command == ZEBRA_IMPORT_ROUTE_REGISTER)
	    && (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED)
		|| CHECK_FLAG(bnc->flags, BGP_STATIC_ROUTE_EXACT_MATCH)))
		exact_match = true;

	if (BGP_DEBUG(zebra, ZEBRA)) {
		char buf[PREFIX2STR_BUFFER];

		prefix2str(p, buf, PREFIX2STR_BUFFER);
		zlog_debug("%s: sending cmd %s for %s (vrf %s)",
			__func__, zserv_command_string(command), buf,
			bnc->bgp->name_pretty);
	}

	ret = zclient_send_rnh(zclient, command, p, exact_match,
			       bnc->bgp->vrf_id);
	/* TBD: handle the failure */
	if (ret < 0)
		flog_warn(EC_BGP_ZEBRA_SEND,
			  "sendmsg_nexthop: zclient_send_message() failed");

	if ((command == ZEBRA_NEXTHOP_REGISTER)
	    || (command == ZEBRA_IMPORT_ROUTE_REGISTER))
		SET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
	else if ((command == ZEBRA_NEXTHOP_UNREGISTER)
		 || (command == ZEBRA_IMPORT_ROUTE_UNREGISTER))
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
	return;
}

/**
 * register_zebra_rnh - register a NH/route with Zebra for notification
 *    when the route or the route to the nexthop changes.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc
 * RETURNS:
 *   void.
 */
static void register_zebra_rnh(struct bgp_nexthop_cache *bnc,
			       int is_bgp_import_route)
{
	/* Check if we have already registered */
	if (bnc->flags & BGP_NEXTHOP_REGISTERED)
		return;
	if (is_bgp_import_route)
		sendmsg_zebra_rnh(bnc, ZEBRA_IMPORT_ROUTE_REGISTER);
	else
		sendmsg_zebra_rnh(bnc, ZEBRA_NEXTHOP_REGISTER);
}

/**
 * unregister_zebra_rnh -- Unregister the route/nexthop from Zebra.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc
 * RETURNS:
 *   void.
 */
static void unregister_zebra_rnh(struct bgp_nexthop_cache *bnc,
				 int is_bgp_import_route)
{
	/* Check if we have already registered */
	if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED))
		return;

	if (is_bgp_import_route)
		sendmsg_zebra_rnh(bnc, ZEBRA_IMPORT_ROUTE_UNREGISTER);
	else
		sendmsg_zebra_rnh(bnc, ZEBRA_NEXTHOP_UNREGISTER);
}

/**
 * evaluate_paths - Evaluate the paths/nets associated with a nexthop.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc -- the nexthop structure.
 * RETURNS:
 *   void.
 */
static void evaluate_paths(struct bgp_nexthop_cache *bnc)
{
	struct bgp_node *rn;
	struct bgp_path_info *path;
	int afi;
	struct peer *peer = (struct peer *)bnc->nht_info;
	struct bgp_table *table;
	safi_t safi;
	struct bgp *bgp_path;
	const struct prefix *p;

	if (BGP_DEBUG(nht, NHT)) {
		char buf[PREFIX2STR_BUFFER];
		bnc_str(bnc, buf, PREFIX2STR_BUFFER);
		zlog_debug(
			"NH update for %s %s flags 0x%x chgflags 0x%x - evaluate paths",
			buf, bnc->bgp->name_pretty, bnc->flags,
			bnc->change_flags);
	}

	LIST_FOREACH (path, &(bnc->paths), nh_thread) {
		if (!(path->type == ZEBRA_ROUTE_BGP
		      && ((path->sub_type == BGP_ROUTE_NORMAL)
			  || (path->sub_type == BGP_ROUTE_STATIC)
			  || (path->sub_type == BGP_ROUTE_IMPORTED))))
			continue;

		rn = path->net;
		assert(rn && bgp_node_table(rn));
		p = bgp_node_get_prefix(rn);
		afi = family2afi(p->family);
		table = bgp_node_table(rn);
		safi = table->safi;

		/*
		 * handle routes from other VRFs (they can have a
		 * nexthop in THIS VRF). bgp_path is the bgp instance
		 * that owns the route referencing this nexthop.
		 */
		bgp_path = table->bgp;

		/*
		 * Path becomes valid/invalid depending on whether the nexthop
		 * reachable/unreachable.
		 *
		 * In case of unicast routes that were imported from vpn
		 * and that have labels, they are valid only if there are
		 * nexthops with labels
		 */

		bool bnc_is_valid_nexthop = false;
		bool path_valid = false;

		if (safi == SAFI_UNICAST &&
			path->sub_type == BGP_ROUTE_IMPORTED &&
			path->extra &&
			path->extra->num_labels) {

			bnc_is_valid_nexthop =
				bgp_isvalid_labeled_nexthop(bnc) ? true : false;
		} else {
			if (bgp_update_martian_nexthop(
				    bnc->bgp, afi, safi, path->type,
				    path->sub_type, path->attr, rn)) {
				if (BGP_DEBUG(nht, NHT))
					zlog_debug(
						"%s: prefix %pRN (vrf %s), ignoring path due to martian or self-next-hop",
						__func__, rn, bgp_path->name);
			} else
				bnc_is_valid_nexthop =
					bgp_isvalid_nexthop(bnc) ? true : false;
		}

		if (BGP_DEBUG(nht, NHT)) {
			char buf1[RD_ADDRSTRLEN];

			if (rn->prn) {
				prefix_rd2str((struct prefix_rd *)&rn->prn->p,
					buf1, sizeof(buf1));
				zlog_debug(
					"... eval path %d/%d %pRN RD %s %s flags 0x%x",
					afi, safi, rn, buf1,
					bgp_path->name_pretty, path->flags);
			} else
				zlog_debug(
					"... eval path %d/%d %pRN %s flags 0x%x",
					afi, safi, rn, bgp_path->name_pretty,
					path->flags);
		}

		/* Skip paths marked for removal or as history. */
		if (CHECK_FLAG(path->flags, BGP_PATH_REMOVED)
		    || CHECK_FLAG(path->flags, BGP_PATH_HISTORY))
			continue;

		/* Copy the metric to the path. Will be used for bestpath
		 * computation */
		if (bgp_isvalid_nexthop(bnc) && bnc->metric)
			(bgp_path_info_extra_get(path))->igpmetric =
				bnc->metric;
		else if (path->extra)
			path->extra->igpmetric = 0;

		if (CHECK_FLAG(bnc->change_flags, BGP_NEXTHOP_METRIC_CHANGED)
		    || CHECK_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED))
			SET_FLAG(path->flags, BGP_PATH_IGP_CHANGED);

		path_valid = !!CHECK_FLAG(path->flags, BGP_PATH_VALID);
		if (path_valid != bnc_is_valid_nexthop) {
			if (path_valid) {
				/* No longer valid, clear flag; also for EVPN
				 * routes, unimport from VRFs if needed.
				 */
				bgp_aggregate_decrement(bgp_path, p, path, afi,
							safi);
				bgp_path_info_unset_flag(rn, path,
							 BGP_PATH_VALID);
				if (safi == SAFI_EVPN &&
				    bgp_evpn_is_prefix_nht_supported(&rn->p))
					bgp_evpn_unimport_route(bgp_path,
						afi, safi, &rn->p, path);
			} else {
				/* Path becomes valid, set flag; also for EVPN
				 * routes, import from VRFs if needed.
				 */
				bgp_path_info_set_flag(rn, path,
						       BGP_PATH_VALID);
				bgp_aggregate_increment(bgp_path, p, path, afi,
							safi);
				if (safi == SAFI_EVPN &&
				    bgp_evpn_is_prefix_nht_supported(&rn->p))
					bgp_evpn_import_route(bgp_path,
						afi, safi, &rn->p, path);
			}
		}

		bgp_process(bgp_path, rn, afi, safi);
	}

	if (peer) {
		int valid_nexthops = bgp_isvalid_nexthop(bnc);

		if (valid_nexthops)
			peer->last_reset = PEER_DOWN_WAITING_OPEN;
		else
			peer->last_reset = PEER_DOWN_WAITING_NHT;

		if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED)) {
			if (BGP_DEBUG(nht, NHT))
				zlog_debug(
					"%s: Updating peer (%s(%s)) status with NHT",
					__func__, peer->host,
					peer->bgp->name_pretty);
			bgp_fsm_event_update(peer, valid_nexthops);
			SET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);
		}
	}

	RESET_FLAG(bnc->change_flags);
}

/**
 * path_nh_map - make or break path-to-nexthop association.
 * ARGUMENTS:
 *   path - pointer to the path structure
 *   bnc - pointer to the nexthop structure
 *   make - if set, make the association. if unset, just break the existing
 *          association.
 */
void path_nh_map(struct bgp_path_info *path, struct bgp_nexthop_cache *bnc,
		 bool make)
{
	if (path->nexthop) {
		LIST_REMOVE(path, nh_thread);
		path->nexthop->path_count--;
		path->nexthop = NULL;
	}
	if (make) {
		LIST_INSERT_HEAD(&(bnc->paths), path, nh_thread);
		path->nexthop = bnc;
		path->nexthop->path_count++;
	}
}

/*
 * This function is called to register nexthops to zebra
 * as that we may have tried to install the nexthops
 * before we actually have a zebra connection
 */
void bgp_nht_register_nexthops(struct bgp *bgp)
{
	struct bgp_node *rn;
	struct bgp_nexthop_cache *bnc;
	afi_t afi;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		if (!bgp->nexthop_cache_table[afi])
			continue;

		for (rn = bgp_table_top(bgp->nexthop_cache_table[afi]); rn;
		     rn = bgp_route_next(rn)) {
			bnc = bgp_node_get_bgp_nexthop_info(rn);

			if (!bnc)
				continue;

			register_zebra_rnh(bnc, 0);
		}
	}
}

void bgp_nht_reg_enhe_cap_intfs(struct peer *peer)
{
	struct bgp *bgp;
	struct bgp_node *rn;
	struct bgp_nexthop_cache *bnc;
	struct nexthop *nhop;
	struct interface *ifp;
	struct prefix p;

	if (peer->ifp)
		return;

	bgp = peer->bgp;

	if (!bgp->nexthop_cache_table[AFI_IP6])
		return;

	if (!sockunion2hostprefix(&peer->su, &p)) {
		zlog_warn("%s: Unable to convert sockunion to prefix for %s",
			  __func__, peer->host);
		return;
	}

	if (p.family != AF_INET6)
		return;
	rn = bgp_node_lookup(bgp->nexthop_cache_table[AFI_IP6], &p);
	if (!rn)
		return;

	bnc = bgp_node_get_bgp_nexthop_info(rn);
	if (!bnc)
		return;

	if (peer != bnc->nht_info)
		return;

	for (nhop = bnc->nexthop; nhop; nhop = nhop->next) {
		ifp = if_lookup_by_index(nhop->ifindex, nhop->vrf_id);

		if (!ifp)
			continue;

		zclient_send_interface_radv_req(zclient,
						nhop->vrf_id,
						ifp, true,
						BGP_UNNUM_DEFAULT_RA_INTERVAL);
	}
}

void bgp_nht_dereg_enhe_cap_intfs(struct peer *peer)
{
	struct bgp *bgp;
	struct bgp_node *rn;
	struct bgp_nexthop_cache *bnc;
	struct nexthop *nhop;
	struct interface *ifp;
	struct prefix p;

	if (peer->ifp)
		return;

	bgp = peer->bgp;

	if (!bgp->nexthop_cache_table[AFI_IP6])
		return;

	if (!sockunion2hostprefix(&peer->su, &p)) {
		zlog_warn("%s: Unable to convert sockunion to prefix for %s",
			  __func__, peer->host);
		return;
	}

	if (p.family != AF_INET6)
		return;

	rn = bgp_node_lookup(bgp->nexthop_cache_table[AFI_IP6], &p);
	if (!rn)
		return;

	bnc = bgp_node_get_bgp_nexthop_info(rn);
	if (!bnc)
		return;

	if (peer != bnc->nht_info)
		return;

	for (nhop = bnc->nexthop; nhop; nhop = nhop->next) {
		ifp = if_lookup_by_index(nhop->ifindex, nhop->vrf_id);

		if (!ifp)
			continue;

		zclient_send_interface_radv_req(zclient, nhop->vrf_id, ifp, 0,
						0);
	}

}

/****************************************************************************
 * L3 NHGs are used for fast failover of nexthops in the dplane. These are
 * the APIs for allocating L3 NHG ids. Management of the L3 NHG itself is
 * left to the application using it.
 * PS: Currently EVPN host routes is the only app using L3 NHG for fast
 * failover of remote ES links.
 ***************************************************************************/
static bitfield_t bgp_nh_id_bitmap;
static uint32_t bgp_l3nhg_start;

/* XXX - currently we do nothing on the callbacks */
static void bgp_l3nhg_add_cb(const char *name)
{
}
static void bgp_l3nhg_add_nexthop_cb(const struct nexthop_group_cmd *nhgc,
					 const struct nexthop *nhop)
{
}
static void bgp_l3nhg_del_nexthop_cb(const struct nexthop_group_cmd *nhgc,
					 const struct nexthop *nhop)
{
}
static void bgp_l3nhg_del_cb(const char *name)
{
}

static void bgp_l3nhg_zebra_init(void)
{
	static bool bgp_l3nhg_zebra_inited;
	if (bgp_l3nhg_zebra_inited)
		return;

	bgp_l3nhg_zebra_inited = true;
	bgp_l3nhg_start = zclient_get_nhg_start(ZEBRA_ROUTE_BGP);
	nexthop_group_init(bgp_l3nhg_add_cb, bgp_l3nhg_add_nexthop_cb,
			   bgp_l3nhg_del_nexthop_cb, bgp_l3nhg_del_cb, NULL);
}


#define min(A,B) ((A) < (B) ? (A) : (B))
void bgp_l3nhg_init(void)
{
	uint32_t id_max;

	id_max = min(ZEBRA_NHG_PROTO_SPACING-1, 16*1024);
	bf_init(bgp_nh_id_bitmap, id_max);
	bf_assign_zero_index(bgp_nh_id_bitmap);

	if (BGP_DEBUG(nht, NHT) || BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("bgp l3_nhg range %u - %u",
			bgp_l3nhg_start + 1,
			bgp_l3nhg_start + id_max);
}

void bgp_l3nhg_finish(void)
{
	bf_free(bgp_nh_id_bitmap);
}

uint32_t bgp_l3nhg_id_alloc(void)
{
	uint32_t nhg_id = 0;

	bgp_l3nhg_zebra_init();
	bf_assign_index(bgp_nh_id_bitmap, nhg_id);
	if (nhg_id)
		nhg_id += bgp_l3nhg_start;

	return nhg_id;
}

void bgp_l3nhg_id_free(uint32_t nhg_id)
{
	if (!nhg_id || (nhg_id <= bgp_l3nhg_start))
		return;

	nhg_id -= bgp_l3nhg_start;

	bf_release_index(bgp_nh_id_bitmap, nhg_id);
}

