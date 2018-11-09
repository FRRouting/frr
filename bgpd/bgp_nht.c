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

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_flowspec_util.h"

extern struct zclient *zclient;

static void register_zebra_rnh(struct bgp_nexthop_cache *bnc,
			       int is_bgp_static_route);
static void unregister_zebra_rnh(struct bgp_nexthop_cache *bnc,
				 int is_bgp_static_route);
static int make_prefix(int afi, struct bgp_path_info *pi, struct prefix *p);

DEFINE_MTYPE_STATIC(BGPD, BGP_NEXTHOP_LEAK_LABEL,
		    "Bgp Nexthop Label used for VRF route leak");

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

static struct bgp_leak_mpls *bgp_nht_lookup_leak_mpls(
						struct bgp_nexthop_cache *bnc,
						struct bgp_path_info_extra *extra,
						bool create)
{
	struct listnode *node, *next;
	struct bgp_leak_mpls *blm;

	if (!bnc || !bnc->leak_mpls ||
	    !extra || extra->num_labels != 1)
		return NULL;
	for (ALL_LIST_ELEMENTS(bnc->leak_mpls, node, next, blm))
		if (blm->label_origin == extra->label[0])
			return blm;
	if (!create)
		return NULL;
	blm = XCALLOC(MTYPE_BGP_NEXTHOP_LEAK_LABEL,
		      sizeof(struct bgp_leak_mpls));
	blm->label_origin = extra->label[0];
	blm->bnc = bnc;
	listnode_add(bnc->leak_mpls, blm);
	return blm;
}

static int bgp_nht_handle_label(struct bgp_leak_mpls *blm,
				struct bgp_path_info *path)
{
	int bnc_is_valid_nexthop = 1;

	if (blm->label_new == 0) {
		bnc_is_valid_nexthop = 0;
		if (!(blm->flags &
		      BGP_LEAK_MPLS_ALLOC_WIP)) {
			blm->flags |=
				BGP_LEAK_MPLS_ALLOC_WIP;
			bgp_lp_get(LP_TYPE_VRF_VETH, blm,
				   bgp_vpn_leak_mpls_callback);
		}
	} else {
		if (!bgp_is_valid_label(&path->extra->label_route_leak) ||
		    decode_label(&path->extra->label_route_leak)
		    != blm->label_new) {
			blm->refcnt++;
			/* insert new mpls value */
			encode_label(blm->label_new,
				     &path->extra->label_route_leak);
			bgp_set_valid_label(&path->extra->label_route_leak);
		}
	}
	return bnc_is_valid_nexthop;
}


static void bgp_nht_leak_mpls_detach(struct bgp_path_info_extra *extra,
				     struct bgp_nexthop_cache *bnc)
{
	struct bgp_leak_mpls *blm;

	if (!bnc)
		return;

	blm = bgp_nht_lookup_leak_mpls(bnc, extra, 0);
	/* suppress additional mpls entry */
	if (!blm)
		return;
	if (blm->label_new &&
	    bgp_is_valid_label(&extra->label_route_leak) &&
	    decode_label(&extra->label_route_leak) == blm->label_new) {
		blm->refcnt--;
		extra->label_route_leak = 0;
		if (!blm->refcnt) {
			/* flush MPLS LSP entry */
			bgp_zebra_send_mpls_label(ZEBRA_MPLS_LABELS_DELETE,
						  blm->label_new,
						  blm->label_out,
						  &blm->nhop);
			/* flush allocated label */
			bgp_lp_release(LP_TYPE_VRF_VETH, blm, blm->label_new);
			/* flush blm */
			listnode_delete(bnc->leak_mpls, blm);
			XFREE(MTYPE_BGP_NEXTHOP_LEAK_LABEL, blm);
			blm = NULL;
		}
	}
}

static struct bgp_nexthop_cache *bgp_lookup_bnc_per_route(struct list *route,
							  vrf_id_t vrfid_route)
{
	struct listnode *node, *next;
	struct bgp_nexthop_cache *bnc;

	if (!route)
		return NULL;
	for (ALL_LIST_ELEMENTS(route, node, next, bnc)) {
		if (!bnc->bgp_route)
			continue;
		if (bnc->bgp_route->vrf_id == vrfid_route)
			return (bnc);
	}
	return NULL;
}

int bgp_find_nexthop(struct bgp_path_info *path, int connected)
{
	struct bgp_nexthop_cache *bnc = path->nexthop;

	if (!bnc)
		return 0;

	/*
	 * We are cheating here.  Views have no associated underlying
	 * ability to detect nexthops.  So when we have a view
	 * just tell everyone the nexthop is valid
	 */
	if (path->peer && path->peer->bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
		return 1;

	if (connected && !(CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED)))
		return 0;

	return (bgp_isvalid_nexthop(bnc));
}

static void bgp_unlink_nexthop_check(struct bgp_nexthop_cache *bnc)
{
	if (LIST_EMPTY(&(bnc->paths)) && !bnc->nht_info) {
		struct bgp_node *rn = bnc->node;

		if (BGP_DEBUG(nht, NHT)) {
			char buf[PREFIX2STR_BUFFER];
			zlog_debug("bgp_unlink_nexthop: freeing bnc %s",
				   bnc_str(bnc, buf, PREFIX2STR_BUFFER));
		}
		unregister_zebra_rnh(bnc,
				     CHECK_FLAG(bnc->flags, BGP_STATIC_ROUTE));
		listnode_delete(rn->info, bnc);
		if (list_isempty((struct list *)rn->info))
			list_delete((struct list **)&rn->info);
		bgp_unlock_node(rn);
		bnc_free(bnc);
	}
}

void bgp_unlink_nexthop(struct bgp_path_info *path)
{
	struct bgp_nexthop_cache *bnc = path->nexthop;
	struct bgp_node *rn;

	if (!bnc)
		return;
	rn = bnc->node;
	path_nh_map(path, NULL, false);

	bgp_unlink_nexthop_check(bnc);
	if (rn->info && list_isempty((struct list *)rn->info))
		list_delete((struct list **)&rn->info);
}

void bgp_unlink_nexthop_by_peer(struct peer *peer)
{
	struct prefix p;
	struct bgp_node *rn;
	struct bgp_nexthop_cache *bnc;
	struct listnode *node, *next;

	afi_t afi = family2afi(peer->su.sa.sa_family);

	if (!sockunion2hostprefix(&peer->su, &p))
		return;

	rn = bgp_node_get(peer->bgp->nexthop_cache_table[afi], &p);

	bnc = bgp_node_get_bgp_nexthop_info(rn);
	if (!bnc)
		return;

	for (ALL_LIST_ELEMENTS((struct list *)rn->info, node, next, bnc)) {
		/* cleanup the peer reference */
		bnc->nht_info = NULL;
		bgp_unlink_nexthop_check(bnc);
	}
	if (rn->info && list_isempty((struct list *)rn->info))
		list_delete((struct list **)&rn->info);
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
	struct bgp_nexthop_cache *bnc = NULL;
	struct prefix p;
	int is_bgp_static_route = 0;

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

		/* This will return TRUE if the global IPv6 NH is a link local
		 * addr */
		if (make_prefix(afi, pi, &p) < 0)
			return 1;
	} else if (peer) {
		if (!sockunion2hostprefix(&peer->su, &p)) {
			if (BGP_DEBUG(nht, NHT)) {
				zlog_debug(
					"%s: Attempting to register with unknown AFI %d (not %d or %d)",
					__FUNCTION__, afi, AFI_IP, AFI_IP6);
			}
			return 0;
		}
	} else
		return 0;

	if (is_bgp_static_route)
		rn = bgp_node_get(bgp_nexthop->import_check_table[afi], &p);
	else
		rn = bgp_node_get(bgp_nexthop->nexthop_cache_table[afi], &p);

	if (rn->info)
		bnc = bgp_lookup_bnc_per_route(rn->info, bgp_route->vrf_id);
	if (!rn->info || !bnc) {
		bnc = bnc_new();
		if (!rn->info)
			rn->info = list_new();
		listnode_add((struct list *)rn->info, bnc);
		bnc->node = rn;
		bnc->bgp = bgp_nexthop;
		bnc->bgp_route = bgp_route;
		bnc->leak_mpls = list_new();
		bgp_lock_node(rn);
		if (BGP_DEBUG(nht, NHT)) {
			char buf[PREFIX2STR_BUFFER];

			zlog_debug("Allocated bnc %s peer %p",
				   bnc_str(bnc, buf, PREFIX2STR_BUFFER), peer);
		}
	}

	bgp_unlock_node(rn);
	if (is_bgp_static_route) {
		SET_FLAG(bnc->flags, BGP_STATIC_ROUTE);

		/* If we're toggling the type, re-register */
		if ((bgp_flag_check(bgp_route, BGP_FLAG_IMPORT_CHECK))
		    && !CHECK_FLAG(bnc->flags, BGP_STATIC_ROUTE_EXACT_MATCH)) {
			SET_FLAG(bnc->flags, BGP_STATIC_ROUTE_EXACT_MATCH);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		} else if ((!bgp_flag_check(bgp_route, BGP_FLAG_IMPORT_CHECK))
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
	} else if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED))
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

	if (pi && (bnc->flags & BGP_NEXTHOP_RECURSION_IFACE) &&
	    CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID) &&
	    CHECK_FLAG(bnc->flags, BGP_NEXTHOP_LABELED_VALID)) {
		struct bgp_leak_mpls *blm;

		blm = bgp_nht_lookup_leak_mpls(bnc, pi->extra, 1);
		if (blm->label_new == 0) {
			if (!(blm->flags & BGP_LEAK_MPLS_ALLOC_WIP)) {
				blm->flags |= BGP_LEAK_MPLS_ALLOC_WIP;
				bgp_lp_get(LP_TYPE_VRF_VETH, blm,
					   bgp_vpn_leak_mpls_callback);
				bnc->flags &= ~BGP_NEXTHOP_VALID;
			}
		} else {
			/* insert new mpls value */
			encode_label(blm->label_new,
				     &pi->extra->label_route_leak);
			bgp_set_valid_label(&pi->extra->label_route_leak);
		}
	}
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
	struct listnode *node, *next;

	if (!peer)
		return;

	if (!sockunion2hostprefix(&peer->su, &p))
		return;

	rn = bgp_node_lookup(
		peer->bgp->nexthop_cache_table[family2afi(p.family)], &p);
	if (!rn) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug("Cannot find connected NHT node for peer %s",
				   peer->host);
		return;
	}

	for (ALL_LIST_ELEMENTS((struct list *)rn->info, node, next, bnc)) {
		if (bnc->nht_info != peer) {
			if (BGP_DEBUG(nht, NHT))
				zlog_debug(
					   "Connected NHT %p node for peer %s points to %p",
					   bnc, peer->host, bnc->nht_info);
			continue;
		}
		bnc->nht_info = NULL;

		if (LIST_EMPTY(&(bnc->paths))) {
			if (BGP_DEBUG(nht, NHT))
				zlog_debug("Freeing connected NHT node %p for peer %s",
					   bnc, peer->host);
			unregister_zebra_rnh(bnc, 0);
			listnode_delete(bnc->node->info, bnc);
			bnc_free(bnc);
		}
	}
	bgp_unlock_node(rn);
}

void bgp_parse_nexthop_update(int command, vrf_id_t vrf_id)
{
	struct bgp_node *rn = NULL;
	struct bgp_nexthop_cache *bnc = NULL;
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
			zlog_debug("%s: Failure to decode nexthop update",
				   __PRETTY_FUNCTION__);
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

	if (rn->info)
		bnc = bgp_lookup_bnc_per_route(rn->info, nhr.vrf_id_route);
	if (!rn || !rn->info || !bnc) {
		if (BGP_DEBUG(nht, NHT)) {
			char buf[PREFIX2STR_BUFFER];
			prefix2str(&nhr.prefix, buf, sizeof(buf));
			zlog_debug("parse nexthop update(%s): rn not found",
				   buf);
		}
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
			"%u: Rcvd NH update %s - metric %d/%d #nhops %d/%d flags 0x%x",
			vrf_id, buf, nhr.metric, bnc->metric, nhr.nexthop_num,
			bnc->nexthop_num, bnc->flags);
	}

	if (nhr.metric != bnc->metric)
		bnc->change_flags |= BGP_NEXTHOP_METRIC_CHANGED;

	if (nhr.nexthop_num != bnc->nexthop_num)
		bnc->change_flags |= BGP_NEXTHOP_CHANGED;

	if (nhr.nexthop_num) {
		struct peer *peer = bnc->nht_info;
		bool recursive = false;

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
			    && nhr.prefix.family == AF_INET6) {
				struct interface *ifp;

				ifp = if_lookup_by_index(nexthop->ifindex,
							 nexthop->vrf_id);
				zclient_send_interface_radv_req(
					zclient, nexthop->vrf_id, ifp, true,
					BGP_UNNUM_DEFAULT_RA_INTERVAL);
			}

			/* recursion through interface */
			if (nexthop->resolved &&
			    nexthop->resolved->type == NEXTHOP_TYPE_IFINDEX)
				recursive = true;

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
				if ((bnc->flags & BGP_NEXTHOP_RECURSION_IFACE)
				    && nexthop->resolved)
					zlog_debug(
						   "    recursive via %s",
						   nexthop2str(
							 nexthop->resolved,
							 buf, sizeof(buf)));
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
				if (nexthop_same_no_recurse(oldnh, nexthop) &&
				    nexthop_same_recurse(oldnh, nexthop) &&
				    nexthop_labels_match(oldnh, nexthop))
					break;

			if (!oldnh)
				bnc->change_flags |= BGP_NEXTHOP_CHANGED;
		}
		if (recursive)
			bnc->flags |= BGP_NEXTHOP_RECURSION_IFACE;
		else
			bnc->flags &= ~BGP_NEXTHOP_RECURSION_IFACE;

		bnc_nexthop_free(bnc);
		bnc->nexthop = nhlist_head;
	} else {
		bnc->flags &= ~BGP_NEXTHOP_VALID;
		bnc->nexthop_num = nhr.nexthop_num;

		/* notify bgp fsm if nbr ip goes from valid->invalid */
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);

		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_RECURSION_IFACE);

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
	struct prefix *p_orig = &net->p;

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
			p->u.prefix4 = pi->net->p.u.prefix4;
			p->prefixlen = pi->net->p.prefixlen;
		} else {
			p->u.prefix4 = pi->attr->nexthop;
			p->prefixlen = IPV4_MAX_BITLEN;
		}
		break;
	case AFI_IP6:
		p->family = AF_INET6;

		if (is_bgp_static) {
			p->u.prefix6 = pi->net->p.u.prefix6;
			p->prefixlen = pi->net->p.prefixlen;
		} else {
			p->u.prefix6 = pi->attr->mp_nexthop_global;
			p->prefixlen = IPV6_MAX_BITLEN;
		}
		break;
	default:
		if (BGP_DEBUG(nht, NHT)) {
			zlog_debug(
				"%s: Attempting to make prefix with unknown AFI %d (not %d or %d)",
				__FUNCTION__, afi, AFI_IP, AFI_IP6);
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
	struct prefix *p;
	bool exact_match = false;
	int ret;

	if (!zclient)
		return;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bnc->bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: No zebra instance to talk to, not installing NHT entry",
				   __PRETTY_FUNCTION__);
		return;
	}

	if (!bgp_zebra_num_connects()) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: We have not connected yet, cannot send nexthops",
				   __PRETTY_FUNCTION__);
	}
	p = &(bnc->node->p);
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
			bnc->bgp->name);
	}

	ret = zclient_send_rnh(zclient, command, p, exact_match,
			       bnc->bgp->vrf_id, bnc->bgp_route->vrf_id);
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
void evaluate_paths(struct bgp_nexthop_cache *bnc)
{
	struct bgp_node *rn;
	struct bgp_path_info *path;
	int afi;
	struct peer *peer = (struct peer *)bnc->nht_info;
	struct bgp_table *table;
	safi_t safi;
	struct bgp *bgp_path;

	if (BGP_DEBUG(nht, NHT)) {
		char buf[PREFIX2STR_BUFFER];
		bnc_str(bnc, buf, PREFIX2STR_BUFFER);
		zlog_debug(
			"NH update for %s - flags 0x%x chgflags 0x%x - evaluate paths",
			buf, bnc->flags, bnc->change_flags);
	}

	LIST_FOREACH (path, &(bnc->paths), nh_thread) {
		if (!(path->type == ZEBRA_ROUTE_BGP
		      && ((path->sub_type == BGP_ROUTE_NORMAL)
			  || (path->sub_type == BGP_ROUTE_STATIC)
			  || (path->sub_type == BGP_ROUTE_IMPORTED))))
			continue;

		rn = path->net;
		assert(rn && bgp_node_table(rn));
		afi = family2afi(rn->p.family);
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

		int bnc_is_valid_nexthop = 0;

		if (safi == SAFI_UNICAST &&
			path->sub_type == BGP_ROUTE_IMPORTED &&
			path->extra &&
			path->extra->num_labels) {

			bnc_is_valid_nexthop =
				bgp_isvalid_labeled_nexthop(bnc) ? 1 : 0;
			if (!bnc->nexthop_num &&
			    (bnc->change_flags & BGP_NEXTHOP_CHANGED)) {
				bgp_nht_leak_mpls_detach(path->extra, bnc);
				bnc_is_valid_nexthop = 0;
			} else if ((bnc->flags & BGP_NEXTHOP_RECURSION_IFACE)
				   && bnc->nexthop_num)
				bnc_is_valid_nexthop = 1;
			if ((bnc->flags & BGP_NEXTHOP_RECURSION_IFACE) &&
			    bnc_is_valid_nexthop && bnc->nexthop_num) {
				struct bgp_leak_mpls *blm;

				blm = bgp_nht_lookup_leak_mpls(bnc,
							       path->extra,
							       1);
				bnc_is_valid_nexthop =
					bgp_nht_handle_label(blm, path);
			}
		} else {
			bnc_is_valid_nexthop =
				bgp_isvalid_nexthop(bnc) ? 1 : 0;
		}

		if (BGP_DEBUG(nht, NHT)) {
			char buf[PREFIX_STRLEN];

			prefix2str(&rn->p, buf, PREFIX_STRLEN);
			zlog_debug("%s: prefix %s (vrf %s) %svalid",
				__func__, buf, bgp_path->name,
				(bnc_is_valid_nexthop ? "" : "not "));
		}

		if ((CHECK_FLAG(path->flags, BGP_PATH_VALID) ? 1 : 0)
		    != bnc_is_valid_nexthop) {
			if (CHECK_FLAG(path->flags, BGP_PATH_VALID)) {
				bgp_aggregate_decrement(bgp_path, &rn->p,
							path, afi, safi);
				bgp_path_info_unset_flag(rn, path,
							 BGP_PATH_VALID);
			} else {
				bgp_path_info_set_flag(rn, path,
						       BGP_PATH_VALID);
				bgp_aggregate_increment(bgp_path, &rn->p,
							path, afi, safi);
			}
		}

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

		bgp_process(bgp_path, rn, afi, safi);
	}

	if (peer && !CHECK_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED)) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug("%s: Updating peer (%s) status with NHT",
				   __FUNCTION__, peer->host);
		bgp_fsm_nht_update(peer, bgp_isvalid_nexthop(bnc));
		SET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);
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
		bgp_nht_leak_mpls_detach(path->extra, path->nexthop);
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

void bgp_nht_register_enhe_capability_interfaces(struct peer *peer)
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
		if (BGP_DEBUG(nht, NHT))
			zlog_debug("%s: Unable to convert prefix to sockunion",
				   __PRETTY_FUNCTION__);
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
		ifp = if_lookup_by_index(nhop->ifindex,
					 nhop->vrf_id);
		zclient_send_interface_radv_req(zclient,
						nhop->vrf_id,
						ifp, true,
						BGP_UNNUM_DEFAULT_RA_INTERVAL);
	}
}
