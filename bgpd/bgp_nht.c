// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Nexthop tracking
 * Copyright (C) 2013 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include "command.h"
#include "frrevent.h"
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
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_ecommunity.h"

extern struct zclient *zclient;

static void register_zebra_rnh(struct bgp_nexthop_cache *bnc);
static void unregister_zebra_rnh(struct bgp_nexthop_cache *bnc);
static int make_prefix(int afi, struct bgp_path_info *pi, struct prefix *p);
static void bgp_nht_ifp_initial(struct event *thread);

static int bgp_isvalid_nexthop(struct bgp_nexthop_cache *bnc)
{
	return (bgp_zebra_num_connects() == 0
		|| (bnc && CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID)
		    && bnc->nexthop_num > 0));
}

static int bgp_isvalid_nexthop_for_ebgp(struct bgp_nexthop_cache *bnc,
					struct bgp_path_info *path)
{
	struct interface *ifp = NULL;
	struct nexthop *nexthop;
	struct bgp_interface *iifp;
	struct peer *peer;

	if (!path->extra || !path->extra->vrfleak ||
	    !path->extra->vrfleak->peer_orig)
		return false;

	peer = path->extra->vrfleak->peer_orig;

	/* only connected ebgp peers are valid */
	if (peer->sort != BGP_PEER_EBGP || peer->ttl != BGP_DEFAULT_TTL ||
	    CHECK_FLAG(peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK) ||
	    CHECK_FLAG(peer->bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK))
		return false;

	for (nexthop = bnc->nexthop; nexthop; nexthop = nexthop->next) {
		if (nexthop->type == NEXTHOP_TYPE_IFINDEX ||
		    nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX ||
		    nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX) {
			ifp = if_lookup_by_index(bnc->ifindex_ipv6_ll
							 ? bnc->ifindex_ipv6_ll
							 : nexthop->ifindex,
						 bnc->bgp->vrf_id);
		}
		if (!ifp)
			continue;
		iifp = ifp->info;
		if (CHECK_FLAG(iifp->flags, BGP_INTERFACE_MPLS_BGP_FORWARDING))
			return true;
	}
	return false;
}

static int bgp_isvalid_nexthop_for_mplsovergre(struct bgp_nexthop_cache *bnc,
					       struct bgp_path_info *path)
{
	struct interface *ifp = NULL;
	struct nexthop *nexthop;

	for (nexthop = bnc->nexthop; nexthop; nexthop = nexthop->next) {
		if (nexthop->type != NEXTHOP_TYPE_BLACKHOLE) {
			ifp = if_lookup_by_index(bnc->ifindex_ipv6_ll
							 ? bnc->ifindex_ipv6_ll
							 : nexthop->ifindex,
						 bnc->bgp->vrf_id);
			if (ifp && (ifp->ll_type == ZEBRA_LLT_IPGRE ||
				    ifp->ll_type == ZEBRA_LLT_IP6GRE))
				break;
		}
	}
	if (!ifp)
		return false;

	if (CHECK_FLAG(path->attr->rmap_change_flags,
		       BATTR_RMAP_L3VPN_ACCEPT_GRE))
		return true;

	return false;
}

static int bgp_isvalid_nexthop_for_mpls(struct bgp_nexthop_cache *bnc,
					struct bgp_path_info *path)
{
	return (bnc && (bnc->nexthop_num > 0 &&
			(CHECK_FLAG(path->flags, BGP_PATH_ACCEPT_OWN) ||
			 CHECK_FLAG(bnc->flags, BGP_NEXTHOP_LABELED_VALID) ||
			 bgp_isvalid_nexthop_for_ebgp(bnc, path) ||
			 bgp_isvalid_nexthop_for_mplsovergre(bnc, path))));
}

static bool bgp_isvalid_nexthop_for_l3vpn(struct bgp_nexthop_cache *bnc,
					  struct bgp_path_info *path)
{
	if (bgp_zebra_num_connects() == 0)
		return 1;

	if (path->attr->srv6_l3vpn || path->attr->srv6_vpn) {
		/* In the case of SRv6-VPN, we need to track the reachability to the
		 * SID (in other words, IPv6 address). We check that the SID is
		 * available in the BGP update; then if it is available, we check
		 * for the nexthop reachability.
		 */
		if (bnc && (bnc->nexthop_num > 0 && bgp_isvalid_nexthop(bnc)))
			return 1;
		return 0;
	}
	/*
	 * In the case of MPLS-VPN, the label is learned from LDP or other
	 * protocols, and nexthop tracking is enabled for the label.
	 * The value is recorded as BGP_NEXTHOP_LABELED_VALID.
	 * - Otherwise check for mpls-gre acceptance
	 */
	return bgp_isvalid_nexthop_for_mpls(bnc, path);
}

static void bgp_unlink_nexthop_check(struct bgp_nexthop_cache *bnc)
{
	if (LIST_EMPTY(&(bnc->paths)) && !bnc->nht_info) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug("%s: freeing bnc %pFX(%d)(%u)(%s)", __func__,
				   &bnc->prefix, bnc->ifindex_ipv6_ll,
				   bnc->srte_color, bnc->bgp->name_pretty);
		/* only unregister if this is the last nh for this prefix*/
		if (!bnc_existing_for_prefix(bnc))
			unregister_zebra_rnh(bnc);
		bnc_free(bnc);
	}
}

void bgp_unlink_nexthop(struct bgp_path_info *path)
{
	struct bgp_nexthop_cache *bnc = path->nexthop;

	bgp_mplsvpn_path_nh_label_unlink(path);
	bgp_mplsvpn_path_nh_label_bind_unlink(path);

	if (!bnc)
		return;

	path_nh_map(path, NULL, false);

	bgp_unlink_nexthop_check(bnc);
}

void bgp_replace_nexthop_by_peer(struct peer *from, struct peer *to)
{
	struct prefix pp;
	struct prefix pt;
	struct bgp_nexthop_cache *bncp, *bnct;
	afi_t afi;
	ifindex_t ifindex = 0;

	if (!sockunion2hostprefix(&from->connection->su, &pp))
		return;

	/*
	 * Gather the ifindex for if up/down events to be
	 * tagged into this fun
	 */
	if (from->conf_if &&
	    IN6_IS_ADDR_LINKLOCAL(&from->connection->su.sin6.sin6_addr))
		ifindex = from->connection->su.sin6.sin6_scope_id;

	afi = family2afi(pp.family);
	bncp = bnc_find(&from->bgp->nexthop_cache_table[afi], &pp, 0, ifindex);

	if (!sockunion2hostprefix(&to->connection->su, &pt))
		return;

	/*
	 * Gather the ifindex for if up/down events to be
	 * tagged into this fun
	 */
	ifindex = 0;
	if (to->conf_if &&
	    IN6_IS_ADDR_LINKLOCAL(&to->connection->su.sin6.sin6_addr))
		ifindex = to->connection->su.sin6.sin6_scope_id;
	bnct = bnc_find(&to->bgp->nexthop_cache_table[afi], &pt, 0, ifindex);

	if (bnct != bncp)
		return;

	if (bnct)
		bnct->nht_info = to;
}

/*
 * Returns the bnc whose bnc->nht_info matches the LL peer by
 * looping through the IPv6 nexthop table
 */
static struct bgp_nexthop_cache *
bgp_find_ipv6_nexthop_matching_peer(struct peer *peer)
{
	struct bgp_nexthop_cache *bnc;

	frr_each (bgp_nexthop_cache, &peer->bgp->nexthop_cache_table[AFI_IP6],
		  bnc) {
		if (bnc->nht_info == peer) {
			if (BGP_DEBUG(nht, NHT)) {
				zlog_debug(
					"Found bnc: %pFX(%u)(%u)(%p) for peer: %s(%s) %p",
					&bnc->prefix, bnc->ifindex_ipv6_ll,
					bnc->srte_color, bnc, peer->host,
					peer->bgp->name_pretty, peer);
			}
			return bnc;
		}
	}

	if (BGP_DEBUG(nht, NHT))
		zlog_debug(
			"Could not find bnc for peer %s(%s) %p in v6 nexthop table",
			peer->host, peer->bgp->name_pretty, peer);

	return NULL;
}

void bgp_unlink_nexthop_by_peer(struct peer *peer)
{
	struct prefix p;
	struct bgp_nexthop_cache *bnc;
	afi_t afi = family2afi(peer->connection->su.sa.sa_family);
	ifindex_t ifindex = 0;

	if (!sockunion2hostprefix(&peer->connection->su, &p)) {
		/*
		 * In scenarios where unnumbered BGP session is brought
		 * down by shutting down the interface before unconfiguring
		 * the BGP neighbor, neighbor information in peer->su.sa
		 * will be cleared when the interface is shutdown. So
		 * during the deletion of unnumbered bgp peer, above check
		 * will return true. Therefore, in this case,BGP needs to
		 * find the bnc whose bnc->nht_info matches the
		 * peer being deleted and free it.
		 */
		bnc = bgp_find_ipv6_nexthop_matching_peer(peer);
	} else {
		/*
		 * Gather the ifindex for if up/down events to be
		 * tagged into this fun
		 */
		if (afi == AFI_IP6 &&
		    IN6_IS_ADDR_LINKLOCAL(&peer->connection->su.sin6.sin6_addr))
			ifindex = peer->connection->su.sin6.sin6_scope_id;
		bnc = bnc_find(&peer->bgp->nexthop_cache_table[afi], &p, 0,
			       ifindex);
	}

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
			    afi_t afi, safi_t safi, struct bgp_path_info *pi,
			    struct peer *peer, int connected,
			    const struct prefix *orig_prefix)
{
	struct bgp_nexthop_cache_head *tree = NULL;
	struct bgp_nexthop_cache *bnc;
	struct bgp_path_info *bpi_ultimate;
	struct prefix p;
	uint32_t srte_color = 0;
	int is_bgp_static_route = 0;
	ifindex_t ifindex = 0;

	if (pi) {
		is_bgp_static_route = ((pi->type == ZEBRA_ROUTE_BGP)
				       && (pi->sub_type == BGP_ROUTE_STATIC))
					      ? 1
					      : 0;

		/* Since Extended Next-hop Encoding (RFC5549) support, we want
		   to derive
		   address-family from the next-hop. */
		if (!is_bgp_static_route)
			afi = BGP_ATTR_MP_NEXTHOP_LEN_IP6(pi->attr) ? AFI_IP6
								    : AFI_IP;

		/* Validation for the ipv4 mapped ipv6 nexthop. */
		if (IS_MAPPED_IPV6(&pi->attr->mp_nexthop_global)) {
			afi = AFI_IP;
		}

		/* This will return true if the global IPv6 NH is a link local
		 * addr */
		if (make_prefix(afi, pi, &p) < 0)
			return 1;

		/*
		 * If it's a V6 nexthop, path is learnt from a v6 LL peer,
		 * and if the NH prefix matches peer's LL address then
		 * set the ifindex to peer's interface index so that
		 * correct nexthop can be found in nexthop tree.
		 *
		 * NH could be set to different v6 LL address (compared to
		 * peer's LL) using route-map. In such a scenario, do not set
		 * the ifindex.
		 */
		if (afi == AFI_IP6 &&
		    IN6_IS_ADDR_LINKLOCAL(
			    &pi->peer->connection->su.sin6.sin6_addr) &&
		    IPV6_ADDR_SAME(&pi->peer->connection->su.sin6.sin6_addr,
				   &p.u.prefix6))
			ifindex = pi->peer->connection->su.sin6.sin6_scope_id;

		if (!is_bgp_static_route && orig_prefix && prefix_same(&p, orig_prefix) &&
		    CHECK_FLAG(bgp_route->flags, BGP_FLAG_IMPORT_CHECK)) {
			if (BGP_DEBUG(nht, NHT)) {
				zlog_debug("%s(%pFX): prefix loops through itself (import-check enabled)",
					   __func__, &p);
			}
			return 0;
		}

		srte_color = bgp_attr_get_color(pi->attr);

	} else if (peer) {
		/*
		 * Gather the ifindex for if up/down events to be
		 * tagged into this fun
		 */
		if (afi == AFI_IP6 && peer->conf_if &&
		    IN6_IS_ADDR_LINKLOCAL(&peer->connection->su.sin6.sin6_addr)) {
			ifindex = peer->connection->su.sin6.sin6_scope_id;
			if (ifindex == 0) {
				if (BGP_DEBUG(nht, NHT)) {
					zlog_debug(
						"%s: Unable to locate ifindex, waiting till we have one",
						peer->conf_if);
				}
				return 0;
			}
		}

		if (!sockunion2hostprefix(&peer->connection->su, &p)) {
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
		tree = &bgp_nexthop->import_check_table[afi];
	else
		tree = &bgp_nexthop->nexthop_cache_table[afi];

	bnc = bnc_find(tree, &p, srte_color, ifindex);
	if (!bnc) {
		bnc = bnc_new(tree, &p, srte_color, ifindex);
		bnc->afi = afi;
		bnc->bgp = bgp_nexthop;
		if (BGP_DEBUG(nht, NHT))
			zlog_debug("Allocated bnc %pFX(%d)(%u)(%s) peer %p",
				   &bnc->prefix, bnc->ifindex_ipv6_ll,
				   bnc->srte_color, bnc->bgp->name_pretty,
				   peer);
	} else {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug("Found existing bnc %pFX(%d)(%s) flags 0x%x ifindex %d #paths %d peer %p, resolved prefix %pFX",
				   &bnc->prefix, bnc->ifindex_ipv6_ll,
				   bnc->bgp->name_pretty, bnc->flags,
				   bnc->ifindex_ipv6_ll, bnc->path_count,
				   bnc->nht_info, &bnc->resolved_prefix);
	}

	if (pi && is_route_parent_evpn(pi))
		bnc->is_evpn_gwip_nexthop = true;

	if (is_bgp_static_route && !CHECK_FLAG(bnc->flags, BGP_STATIC_ROUTE)) {
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
	if (peer && (bnc->ifindex_ipv6_ll != ifindex)) {
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		bnc->ifindex_ipv6_ll = ifindex;
	}
	if (bgp_route->inst_type == BGP_INSTANCE_TYPE_VIEW) {
		SET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		SET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
	} else if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED)
		   && !is_default_host_route(&bnc->prefix))
		register_zebra_rnh(bnc);

	if (pi && pi->nexthop != bnc) {
		/* Unlink from existing nexthop cache, if any. This will also
		 * free
		 * the nexthop cache entry, if appropriate.
		 */
		bgp_unlink_nexthop(pi);

		/* updates NHT pi list reference */
		path_nh_map(pi, bnc, true);

		bpi_ultimate = bgp_get_imported_bpi_ultimate(pi);
		if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID) && bnc->metric)
			(bgp_path_info_extra_get(bpi_ultimate))->igpmetric =
				bnc->metric;
		else if (bpi_ultimate->extra)
			bpi_ultimate->extra->igpmetric = 0;

		SET_FLAG(bnc->flags, BGP_NEXTHOP_ULTIMATE);
	} else if (peer) {
		/*
		 * Let's not accidentally save the peer data for a peer
		 * we are going to throw away in a second or so.
		 * When we come back around we'll fix up this
		 * data properly in replace_nexthop_by_peer
		 */
		if (CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			bnc->nht_info = (void *)peer; /* NHT peer reference */
	}

	/*
	 * We are cheating here.  Views have no associated underlying
	 * ability to detect nexthops.  So when we have a view
	 * just tell everyone the nexthop is valid
	 */
	if (bgp_route->inst_type == BGP_INSTANCE_TYPE_VIEW)
		return 1;
	else if (safi == SAFI_UNICAST && pi &&
		 pi->sub_type == BGP_ROUTE_IMPORTED &&
		 CHECK_FLAG(bnc->flags, BGP_NEXTHOP_ULTIMATE))
		return bgp_isvalid_nexthop(bnc);
	else if (safi == SAFI_UNICAST && pi &&
		 pi->sub_type == BGP_ROUTE_IMPORTED &&
		 BGP_PATH_INFO_NUM_LABELS(pi) && !bnc->is_evpn_gwip_nexthop)
		return bgp_isvalid_nexthop_for_l3vpn(bnc, pi);
	else if (safi == SAFI_MPLS_VPN && pi &&
		 pi->sub_type != BGP_ROUTE_IMPORTED)
		/* avoid not redistributing mpls vpn routes */
		return 1;
	else
		/* mpls-vpn routes with BGP_ROUTE_IMPORTED subtype */
		return (bgp_isvalid_nexthop(bnc));
}

void bgp_delete_connected_nexthop(afi_t afi, struct peer *peer)
{
	struct bgp_nexthop_cache *bnc;
	struct prefix p;
	ifindex_t ifindex = 0;

	if (!peer)
		return;

	/*
	 * In case the below check evaluates true and if
	 * the bnc has not been freed at this point, then
	 * we might have to do something similar to what's
	 * done in bgp_unlink_nexthop_by_peer(). Since
	 * bgp_unlink_nexthop_by_peer() loops through the
	 * nodes of V6 nexthop cache to find the bnc, it is
	 * currently not being called here.
	 */
	if (!sockunion2hostprefix(&peer->connection->su, &p))
		return;
	/*
	 * Gather the ifindex for if up/down events to be
	 * tagged into this fun
	 */
	if (afi == AFI_IP6 &&
	    IN6_IS_ADDR_LINKLOCAL(&peer->connection->su.sin6.sin6_addr))
		ifindex = peer->connection->su.sin6.sin6_scope_id;
	bnc = bnc_find(&peer->bgp->nexthop_cache_table[family2afi(p.family)],
		       &p, 0, ifindex);
	if (!bnc) {
		if (BGP_DEBUG(nht, NHT))
			zlog_debug(
				"Cannot find connected NHT node for peer %s(%s)",
				peer->host, peer->bgp->name_pretty);
		return;
	}

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
		unregister_zebra_rnh(bnc);
		bnc_free(bnc);
	}
}

static void bgp_process_nexthop_update(struct bgp_nexthop_cache *bnc,
				       struct zapi_route *nhr,
				       bool import_check)
{
	struct nexthop *nexthop;
	struct nexthop *oldnh;
	struct nexthop *nhlist_head = NULL;
	struct nexthop *nhlist_tail = NULL;
	int i;
	bool evpn_resolved = false;

	bnc->last_update = monotime(NULL);
	bnc->change_flags = 0;

	/* debug print the input */
	if (BGP_DEBUG(nht, NHT)) {
		char bnc_buf[BNC_FLAG_DUMP_SIZE];

		zlog_debug(
			"%s(%u): Rcvd NH update %pFX(%u)(%u) - metric %d/%d #nhops %d/%d flags %s",
			bnc->bgp->name_pretty, bnc->bgp->vrf_id, &nhr->prefix,
			bnc->ifindex_ipv6_ll, bnc->srte_color, nhr->metric,
			bnc->metric, nhr->nexthop_num, bnc->nexthop_num,
			bgp_nexthop_dump_bnc_flags(bnc, bnc_buf,
						   sizeof(bnc_buf)));
	}

	if (nhr->metric != bnc->metric)
		SET_FLAG(bnc->change_flags, BGP_NEXTHOP_METRIC_CHANGED);

	if (nhr->nexthop_num != bnc->nexthop_num)
		SET_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED);

	if (import_check && (nhr->type == ZEBRA_ROUTE_BGP ||
			     !prefix_same(&bnc->prefix, &nhr->prefix))) {
		SET_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_LABELED_VALID);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_EVPN_INCOMPLETE);

		bnc_nexthop_free(bnc);
		bnc->nexthop = NULL;

		if (BGP_DEBUG(nht, NHT))
			zlog_debug(
				"%s: Import Check does not resolve to the same prefix for %pFX received %pFX or matching route is BGP",
				__func__, &bnc->prefix, &nhr->prefix);
	} else if (nhr->nexthop_num) {
		struct peer *peer = bnc->nht_info;

		prefix_copy(&bnc->resolved_prefix, &nhr->prefix);

		/* notify bgp fsm if nbr ip goes from invalid->valid */
		if (!bnc->nexthop_num)
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);

		if (!bnc->is_evpn_gwip_nexthop)
			SET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		bnc->metric = nhr->metric;
		bnc->nexthop_num = nhr->nexthop_num;

		UNSET_FLAG(bnc->flags,
			   BGP_NEXTHOP_LABELED_VALID); /* check below */

		for (i = 0; i < nhr->nexthop_num; i++) {
			int num_labels = 0;

			nexthop = nexthop_from_zapi_nexthop(&nhr->nexthops[i]);

			/*
			 * Turn on RA for the v6 nexthops
			 * we receive from bgp.  This is to allow us
			 * to work with v4 routing over v6 nexthops
			 */
			if (peer && !peer->ifp &&
			    CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE) &&
			    !CHECK_FLAG(bnc->bgp->flags,
					BGP_FLAG_IPV6_NO_AUTO_RA) &&
			    nhr->prefix.family == AF_INET6 &&
			    nexthop->type != NEXTHOP_TYPE_BLACKHOLE) {
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
				SET_FLAG(bnc->flags, BGP_NEXTHOP_LABELED_VALID);
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
			if (CHECK_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED))
				continue;

			for (oldnh = bnc->nexthop; oldnh; oldnh = oldnh->next)
				if (nexthop_same(oldnh, nexthop))
					break;

			if (!oldnh)
				SET_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED);
		}
		bnc_nexthop_free(bnc);
		bnc->nexthop = nhlist_head;

		/*
		 * Gateway IP nexthop is L3 reachable. Mark it as
		 * BGP_NEXTHOP_VALID only if it is recursively resolved with a
		 * remote EVPN RT-2.
		 * Else, mark it as BGP_NEXTHOP_EVPN_INCOMPLETE.
		 * When its mapping with EVPN RT-2 is established, unset
		 * BGP_NEXTHOP_EVPN_INCOMPLETE and set BGP_NEXTHOP_VALID.
		 */
		if (bnc->is_evpn_gwip_nexthop) {
			evpn_resolved = bgp_evpn_is_gateway_ip_resolved(bnc);

			if (BGP_DEBUG(nht, NHT))
				zlog_debug(
					"EVPN gateway IP %pFX recursive MAC/IP lookup %s",
					&bnc->prefix,
					(evpn_resolved ? "successful"
						       : "failed"));

			if (evpn_resolved) {
				SET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
				UNSET_FLAG(bnc->flags,
					   BGP_NEXTHOP_EVPN_INCOMPLETE);
				SET_FLAG(bnc->change_flags,
					 BGP_NEXTHOP_MACIP_CHANGED);
			} else {
				SET_FLAG(bnc->flags,
					 BGP_NEXTHOP_EVPN_INCOMPLETE);
				UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
			}
		}
	} else {
		memset(&bnc->resolved_prefix, 0, sizeof(bnc->resolved_prefix));
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_EVPN_INCOMPLETE);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_LABELED_VALID);
		bnc->nexthop_num = nhr->nexthop_num;

		/* notify bgp fsm if nbr ip goes from valid->invalid */
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);

		bnc_nexthop_free(bnc);
		bnc->nexthop = NULL;
	}

	evaluate_paths(bnc);
}

static void bgp_nht_ifp_table_handle(struct bgp *bgp,
				     struct bgp_nexthop_cache_head *table,
				     struct interface *ifp, bool up)
{
	struct bgp_nexthop_cache *bnc;
	struct nexthop *nhop;
	uint16_t other_nh_count;
	bool nhop_ll_found = false;
	bool nhop_found = false;

	if (ifp->ifindex == IFINDEX_INTERNAL) {
		zlog_warn("%s: The interface %s ignored", __func__, ifp->name);
		return;
	}

	frr_each (bgp_nexthop_cache, table, bnc) {
		other_nh_count = 0;
		nhop_ll_found = bnc->ifindex_ipv6_ll == ifp->ifindex;
		for (nhop = bnc->nexthop; nhop; nhop = nhop->next) {
			if (nhop->ifindex == bnc->ifindex_ipv6_ll)
				continue;

			if (nhop->ifindex != ifp->ifindex) {
				other_nh_count++;
				continue;
			}
			if (nhop->vrf_id != ifp->vrf->vrf_id) {
				other_nh_count++;
				continue;
			}
			nhop_found = true;
		}

		if (!nhop_found && !nhop_ll_found)
			/* The event interface does not match the nexthop cache
			 * entry */
			continue;

		if (!up && other_nh_count > 0)
			/* Down event ignored in case of multiple next-hop
			 * interfaces. The other might interfaces might be still
			 * up. The cases where all interfaces are down or a bnc
			 * is invalid are processed by a separate zebra rnh
			 * messages.
			 */
			continue;

		if (!nhop_ll_found) {
			evaluate_paths(bnc);
			continue;
		}

		bnc->last_update = monotime(NULL);
		bnc->change_flags = 0;

		/*
		 * For interface based routes ( ala the v6 LL routes
		 * that this was written for ) the metric received
		 * for the connected route is 0 not 1.
		 */
		bnc->metric = 0;
		if (up) {
			SET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
			SET_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED);
			/* change nexthop number only for ll */
			bnc->nexthop_num = 1;
		} else {
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
			SET_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED);
			bnc->nexthop_num = 0;
		}

		evaluate_paths(bnc);
	}
}
static void bgp_nht_ifp_handle(struct interface *ifp, bool up)
{
	struct bgp *bgp;

	bgp = ifp->vrf->info;
	if (!bgp)
		return;

	bgp_nht_ifp_table_handle(bgp, &bgp->nexthop_cache_table[AFI_IP], ifp,
				 up);
	bgp_nht_ifp_table_handle(bgp, &bgp->import_check_table[AFI_IP], ifp,
				 up);
	bgp_nht_ifp_table_handle(bgp, &bgp->nexthop_cache_table[AFI_IP6], ifp,
				 up);
	bgp_nht_ifp_table_handle(bgp, &bgp->import_check_table[AFI_IP6], ifp,
				 up);
}

void bgp_nht_ifp_up(struct interface *ifp)
{
	bgp_nht_ifp_handle(ifp, true);
}

void bgp_nht_ifp_down(struct interface *ifp)
{
	bgp_nht_ifp_handle(ifp, false);
}

static void bgp_nht_ifp_initial(struct event *thread)
{
	ifindex_t ifindex = EVENT_VAL(thread);
	struct bgp *bgp = EVENT_ARG(thread);
	struct interface *ifp = if_lookup_by_index(ifindex, bgp->vrf_id);

	if (!ifp)
		return;

	if (BGP_DEBUG(nht, NHT))
		zlog_debug(
			"Handle NHT initial update for Intf %s(%d) status %s",
			ifp->name, ifp->ifindex, if_is_up(ifp) ? "up" : "down");

	if (if_is_up(ifp))
		bgp_nht_ifp_up(ifp);
	else
		bgp_nht_ifp_down(ifp);
}

/*
 * So the bnc code has the ability to handle interface up/down
 * events to properly handle v6 LL peering.
 * What is happening here:
 * The event system for peering expects the nht code to
 * report on the tracking events after we move to active
 * So let's give the system a chance to report on that event
 * in a manner that is expected.
 */
void bgp_nht_interface_events(struct peer *peer)
{
	struct bgp *bgp = peer->bgp;
	struct bgp_nexthop_cache_head *table;
	struct bgp_nexthop_cache *bnc;
	struct prefix p;
	ifindex_t ifindex = 0;

	if (!IN6_IS_ADDR_LINKLOCAL(&peer->connection->su.sin6.sin6_addr))
		return;

	if (!sockunion2hostprefix(&peer->connection->su, &p))
		return;
	/*
	 * Gather the ifindex for if up/down events to be
	 * tagged into this fun
	 */
	if (peer->conf_if &&
	    IN6_IS_ADDR_LINKLOCAL(&peer->connection->su.sin6.sin6_addr))
		ifindex = peer->connection->su.sin6.sin6_scope_id;

	table = &bgp->nexthop_cache_table[AFI_IP6];
	bnc = bnc_find(table, &p, 0, ifindex);
	if (!bnc)
		return;

	if (bnc->ifindex_ipv6_ll)
		event_add_event(bm->master, bgp_nht_ifp_initial, bnc->bgp,
				bnc->ifindex_ipv6_ll, NULL);
}

void bgp_nexthop_update(struct vrf *vrf, struct prefix *match,
			struct zapi_route *nhr)
{
	struct bgp_nexthop_cache_head *tree = NULL;
	struct bgp_nexthop_cache *bnc_nhc, *bnc_import;
	struct bgp *bgp, *bgp_default;
	struct bgp_path_info *pi;
	struct bgp_dest *dest;
	safi_t safi;
	afi_t afi;

	if (!vrf->info) {
		flog_err(EC_BGP_NH_UPD,
			 "parse nexthop update: instance not found for vrf_id %u",
			 vrf->vrf_id);
		return;
	}

	bgp = (struct bgp *)vrf->info;
	afi = family2afi(match->family);
	tree = &bgp->nexthop_cache_table[afi];

	bnc_nhc = bnc_find(tree, match, nhr->srte_color, 0);
	if (bnc_nhc)
		bgp_process_nexthop_update(bnc_nhc, nhr, false);
	else if (BGP_DEBUG(nht, NHT))
		zlog_debug("parse nexthop update %pFX(%u)(%s): bnc info not found for nexthop cache",
			   &nhr->prefix, nhr->srte_color,
			   bgp->name_pretty);

	tree = &bgp->import_check_table[afi];

	bnc_import = bnc_find(tree, match, nhr->srte_color, 0);
	if (bnc_import) {
		bgp_process_nexthop_update(bnc_import, nhr, true);

		bgp_default = bgp_get_default();
		safi = nhr->safi;
		if (bgp != bgp_default && bgp->rib[afi][safi]) {
			dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi,
						match, NULL);

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next)
				if (pi->peer == bgp->peer_self &&
				    pi->type == ZEBRA_ROUTE_BGP &&
				    pi->sub_type == BGP_ROUTE_STATIC)
					vpn_leak_from_vrf_update(bgp_default,
								 bgp, pi);
		}
	} else if (BGP_DEBUG(nht, NHT))
		zlog_debug("parse nexthop update %pFX(%u)(%s): bnc info not found for import check",
			   &nhr->prefix, nhr->srte_color,
			   bgp->name_pretty);

	/*
	 * HACK: if any BGP route is dependant on an SR-policy that doesn't
	 * exist, zebra will never send NH updates relative to that policy. In
	 * that case, whenever we receive an update about a colorless NH, update
	 * the corresponding colorful NHs that share the same endpoint but that
	 * are inactive. This ugly hack should work around the problem at the
	 * cost of a performance pernalty. Long term, what should be done is to
	 * make zebra's RNH subsystem aware of SR-TE colors (like bgpd is),
	 * which should provide a better infrastructure to solve this issue in
	 * a more efficient and elegant way.
	 */
	if (nhr->srte_color == 0) {
		struct bgp_nexthop_cache *bnc_iter;

		frr_each (bgp_nexthop_cache, &bgp->nexthop_cache_table[afi],
			  bnc_iter) {
			if (!prefix_same(match, &bnc_iter->prefix) ||
			    bnc_iter->srte_color == 0)
				continue;

			bgp_process_nexthop_update(bnc_iter, nhr, false);
		}
	}
}

/*
 * Cleanup nexthop registration and status information for BGP nexthops
 * pertaining to this VRF. This is invoked upon VRF deletion.
 */
void bgp_cleanup_nexthops(struct bgp *bgp)
{
	for (afi_t afi = AFI_IP; afi < AFI_MAX; afi++) {
		struct bgp_nexthop_cache *bnc;

		frr_each (bgp_nexthop_cache, &bgp->nexthop_cache_table[afi],
			  bnc) {
			/* Clear relevant flags. */
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_VALID);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED);
			UNSET_FLAG(bnc->flags, BGP_NEXTHOP_EVPN_INCOMPLETE);
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
	struct bgp_dest *net = pi->net;
	const struct prefix *p_orig = bgp_dest_get_prefix(net);
	struct in_addr ipv4;

	if (p_orig->family == AF_FLOWSPEC) {
		if (!pi->peer)
			return -1;
		return bgp_flowspec_get_first_nh(pi->peer->bgp,
						 pi, p, afi);
	}
	memset(p, 0, sizeof(struct prefix));
	switch (afi) {
	case AFI_IP:
		p->family = AF_INET;
		if (is_bgp_static) {
			p->u.prefix4 = p_orig->u.prefix4;
			p->prefixlen = p_orig->prefixlen;
		} else {
			if (IS_MAPPED_IPV6(&pi->attr->mp_nexthop_global)) {
				ipv4_mapped_ipv6_to_ipv4(
					&pi->attr->mp_nexthop_global, &ipv4);
				p->u.prefix4 = ipv4;
				p->prefixlen = IPV4_MAX_BITLEN;
			} else {
				if (p_orig->family == AF_EVPN)
					p->u.prefix4 =
						pi->attr->mp_nexthop_global_in;
				else
					p->u.prefix4 = pi->attr->nexthop;
				p->prefixlen = IPV4_MAX_BITLEN;
			}
		}
		break;
	case AFI_IP6:
		p->family = AF_INET6;
		if (pi->attr->srv6_l3vpn) {
			IPV6_ADDR_COPY(&(p->u.prefix6),
				       &(pi->attr->srv6_l3vpn->sid));
			p->prefixlen = IPV6_MAX_BITLEN;
		} else if (is_bgp_static) {
			p->u.prefix6 = p_orig->u.prefix6;
			p->prefixlen = p_orig->prefixlen;
		} else {
			/* If we receive MP_REACH nexthop with ::(LL)
			 * or LL(LL), use LL address as nexthop cache.
			 */
			if (pi->attr &&
			    pi->attr->mp_nexthop_len ==
				    BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL &&
			    (IN6_IS_ADDR_UNSPECIFIED(
				     &pi->attr->mp_nexthop_global) ||
			     IN6_IS_ADDR_LINKLOCAL(&pi->attr->mp_nexthop_global)))
				p->u.prefix6 = pi->attr->mp_nexthop_local;
			/* If we receive MR_REACH with (GA)::(LL)
			 * then check for route-map to choose GA or LL
			 */
			else if (pi->attr &&
				 pi->attr->mp_nexthop_len ==
					 BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) {
				if (CHECK_FLAG(pi->attr->nh_flags,
					       BGP_ATTR_NH_MP_PREFER_GLOBAL))
					p->u.prefix6 =
						pi->attr->mp_nexthop_global;
				else
					p->u.prefix6 =
						pi->attr->mp_nexthop_local;
			} else
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
	bool exact_match = false;
	bool resolve_via_default = false;
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
	if (command == ZEBRA_NEXTHOP_REGISTER) {
		if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED))
			exact_match = true;
		if (CHECK_FLAG(bnc->flags, BGP_STATIC_ROUTE_EXACT_MATCH))
			resolve_via_default = true;
	}

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%s: sending cmd %s for %pFX (vrf %s)", __func__,
			   zserv_command_string(command), &bnc->prefix,
			   bnc->bgp->name_pretty);

	ret = zclient_send_rnh(zclient, command, &bnc->prefix, SAFI_UNICAST,
			       exact_match, resolve_via_default,
			       bnc->bgp->vrf_id);
	if (ret == ZCLIENT_SEND_FAILURE) {
		flog_warn(EC_BGP_ZEBRA_SEND,
			  "sendmsg_nexthop: zclient_send_message() failed");
		return;
	}

	if (command == ZEBRA_NEXTHOP_REGISTER)
		SET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
	else if (command == ZEBRA_NEXTHOP_UNREGISTER)
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
static void register_zebra_rnh(struct bgp_nexthop_cache *bnc)
{
	/* Check if we have already registered */
	if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED))
		return;

	if (bnc->ifindex_ipv6_ll) {
		SET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		return;
	}

	sendmsg_zebra_rnh(bnc, ZEBRA_NEXTHOP_REGISTER);
}

/**
 * unregister_zebra_rnh -- Unregister the route/nexthop from Zebra.
 * ARGUMENTS:
 *   struct bgp_nexthop_cache *bnc
 * RETURNS:
 *   void.
 */
static void unregister_zebra_rnh(struct bgp_nexthop_cache *bnc)
{
	struct bgp_nexthop_cache *import;
	struct bgp_nexthop_cache *nexthop;

	struct bgp *bgp = bnc->bgp;

	/* Check if we have already registered */
	if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED))
		return;

	if (bnc->ifindex_ipv6_ll) {
		UNSET_FLAG(bnc->flags, BGP_NEXTHOP_REGISTERED);
		return;
	}

	import = bnc_find(&bgp->import_check_table[bnc->afi], &bnc->prefix, 0,
			  0);
	nexthop = bnc_find(&bgp->nexthop_cache_table[bnc->afi], &bnc->prefix, 0,
			   0);

	/*
	 * If this entry has both a import and a nexthop entry
	 * then let's not send the unregister quite as of yet
	 * wait until we only have 1 left
	 */
	if (import && nexthop)
		return;

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
	struct bgp_dest *dest;
	struct bgp_path_info *path;
	struct bgp_path_info *bpi_ultimate;
	int afi;
	struct peer *peer = (struct peer *)bnc->nht_info;
	struct bgp_table *table;
	safi_t safi;
	struct bgp *bgp_path;
	const struct prefix *p;

	if (BGP_DEBUG(nht, NHT)) {
		char bnc_buf[BNC_FLAG_DUMP_SIZE];
		char chg_buf[BNC_FLAG_DUMP_SIZE];

		zlog_debug(
			"NH update for %pFX(%d)(%u)(%s) - flags %s chgflags %s- evaluate paths",
			&bnc->prefix, bnc->ifindex_ipv6_ll, bnc->srte_color,
			bnc->bgp->name_pretty,
			bgp_nexthop_dump_bnc_flags(bnc, bnc_buf,
						   sizeof(bnc_buf)),
			bgp_nexthop_dump_bnc_change_flags(bnc, chg_buf,
							  sizeof(bnc_buf)));
	}

	LIST_FOREACH (path, &(bnc->paths), nh_thread) {
		if (path->type == ZEBRA_ROUTE_BGP &&
		    (path->sub_type == BGP_ROUTE_NORMAL ||
		     path->sub_type == BGP_ROUTE_STATIC ||
		     path->sub_type == BGP_ROUTE_IMPORTED))
			/* evaluate the path */
			;
		else if (path->sub_type == BGP_ROUTE_REDISTRIBUTE) {
			/* evaluate the path for redistributed routes
			 * except those from VNC
			 */
			if ((path->type == ZEBRA_ROUTE_VNC) ||
			    (path->type == ZEBRA_ROUTE_VNC_DIRECT))
				continue;
		} else
			/* don't evaluate the path */
			continue;

		dest = path->net;
		assert(dest && bgp_dest_table(dest));
		p = bgp_dest_get_prefix(dest);
		afi = family2afi(p->family);
		table = bgp_dest_table(dest);
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
		 *
		 * If the nexthop is EVPN gateway-IP,
		 * do not check for a valid label.
		 */

		bool bnc_is_valid_nexthop = false;
		bool path_valid = false;
		struct bgp_route_evpn *bre =
			bgp_attr_get_evpn_overlay(path->attr);

		if (safi == SAFI_UNICAST &&
		    path->sub_type == BGP_ROUTE_IMPORTED &&
		    BGP_PATH_INFO_NUM_LABELS(path) &&
		    !(bre && bre->type == OVERLAY_INDEX_GATEWAY_IP)) {
			bnc_is_valid_nexthop =
				bgp_isvalid_nexthop_for_l3vpn(bnc, path)
					? true
					: false;
		} else if (safi == SAFI_MPLS_VPN &&
			   path->sub_type != BGP_ROUTE_IMPORTED) {
			/* avoid not redistributing mpls vpn routes */
			bnc_is_valid_nexthop = true;
		} else {
			/* mpls-vpn routes with BGP_ROUTE_IMPORTED subtype */
			if (bgp_update_martian_nexthop(
				    bnc->bgp, afi, safi, path->type,
				    path->sub_type, path->attr, dest)) {
				if (BGP_DEBUG(nht, NHT))
					zlog_debug(
						"%s: prefix %pBD (vrf %s), ignoring path due to martian or self-next-hop",
						__func__, dest, bgp_path->name);
			} else
				bnc_is_valid_nexthop =
					bgp_isvalid_nexthop(bnc) ? true : false;
		}

		if (BGP_DEBUG(nht, NHT)) {

			if (dest->pdest) {
				char rd_buf[RD_ADDRSTRLEN];

				prefix_rd2str(
					(struct prefix_rd *)bgp_dest_get_prefix(
						dest->pdest),
					rd_buf, sizeof(rd_buf),
					bgp_get_asnotation(bnc->bgp));
				zlog_debug(
					"... eval path %d/%d %pBD RD %s %s flags 0x%x",
					afi, safi, dest, rd_buf,
					bgp_path->name_pretty, path->flags);
			} else
				zlog_debug(
					"... eval path %d/%d %pBD %s flags 0x%x",
					afi, safi, dest, bgp_path->name_pretty,
					path->flags);
		}

		/* Skip paths marked for removal or as history. */
		if (CHECK_FLAG(path->flags, BGP_PATH_REMOVED)
		    || CHECK_FLAG(path->flags, BGP_PATH_HISTORY))
			continue;

		/* Copy the metric to the path. Will be used for bestpath
		 * computation */
		bpi_ultimate = bgp_get_imported_bpi_ultimate(path);
		if (bgp_isvalid_nexthop(bnc) && bnc->metric)
			(bgp_path_info_extra_get(bpi_ultimate))->igpmetric =
				bnc->metric;
		else if (bpi_ultimate->extra)
			bpi_ultimate->extra->igpmetric = 0;

		if (CHECK_FLAG(bnc->change_flags, BGP_NEXTHOP_METRIC_CHANGED) ||
		    CHECK_FLAG(bnc->change_flags, BGP_NEXTHOP_CHANGED) ||
		    bgp_attr_get_color(path->attr))
			SET_FLAG(path->flags, BGP_PATH_IGP_CHANGED);

		path_valid = CHECK_FLAG(path->flags, BGP_PATH_VALID);
		if (path->type == ZEBRA_ROUTE_BGP &&
		    path->sub_type == BGP_ROUTE_STATIC &&
		    !CHECK_FLAG(bgp_path->flags, BGP_FLAG_IMPORT_CHECK))
			/* static routes with 'no bgp network import-check' are
			 * always valid. if nht is called with static routes,
			 * the vpn exportation needs to be triggered
			 */
			vpn_leak_from_vrf_update(bgp_get_default(), bgp_path,
						 path);
		else if (path->sub_type == BGP_ROUTE_REDISTRIBUTE &&
			 safi == SAFI_UNICAST &&
			 (bgp_path->inst_type == BGP_INSTANCE_TYPE_VRF ||
			  bgp_path->inst_type == BGP_INSTANCE_TYPE_DEFAULT))
			/* redistribute routes are always valid
			 * if nht is called with redistribute routes, the vpn
			 * exportation needs to be triggered
			 */
			vpn_leak_from_vrf_update(bgp_get_default(), bgp_path,
						 path);
		else if (path_valid != bnc_is_valid_nexthop) {
			if (path_valid) {
				/* No longer valid, clear flag; also for EVPN
				 * routes, unimport from VRFs if needed.
				 */
				bgp_aggregate_decrement(bgp_path, p, path, afi,
							safi);
				bgp_path_info_unset_flag(dest, path,
							 BGP_PATH_VALID);
				if (safi == SAFI_EVPN &&
				    bgp_evpn_is_prefix_nht_supported(bgp_dest_get_prefix(dest)))
					bgp_evpn_unimport_route(bgp_path,
						afi, safi, bgp_dest_get_prefix(dest), path);
				if (safi == SAFI_UNICAST &&
				    (bgp_path->inst_type !=
				     BGP_INSTANCE_TYPE_VIEW))
					vpn_leak_from_vrf_withdraw(
						bgp_get_default(), bgp_path,
						path);
			} else {
				/* Path becomes valid, set flag; also for EVPN
				 * routes, import from VRFs if needed.
				 */
				bgp_path_info_set_flag(dest, path,
						       BGP_PATH_VALID);
				bgp_aggregate_increment(bgp_path, p, path, afi,
							safi);
				if (safi == SAFI_EVPN &&
				    bgp_evpn_is_prefix_nht_supported(bgp_dest_get_prefix(dest)))
					bgp_evpn_import_route(bgp_path,
						afi, safi, bgp_dest_get_prefix(dest), path);
				if (safi == SAFI_UNICAST &&
				    (bgp_path->inst_type !=
				     BGP_INSTANCE_TYPE_VIEW))
					vpn_leak_from_vrf_update(
						bgp_get_default(), bgp_path,
						path);
			}
		}

		bgp_process(bgp_path, dest, path, afi, safi);
	}

	if (peer) {
		int valid_nexthops = bgp_isvalid_nexthop(bnc);

		if (valid_nexthops) {
			/*
			 * Peering cannot occur across a blackhole nexthop
			 */
			if (bnc->nexthop_num == 1 && bnc->nexthop
			    && bnc->nexthop->type == NEXTHOP_TYPE_BLACKHOLE) {
				peer->last_reset = PEER_DOWN_WAITING_NHT;
				valid_nexthops = 0;
			} else
				peer->last_reset = PEER_DOWN_WAITING_OPEN;
		} else
			peer->last_reset = PEER_DOWN_WAITING_NHT;

		if (!CHECK_FLAG(bnc->flags, BGP_NEXTHOP_PEER_NOTIFIED)) {
			if (BGP_DEBUG(nht, NHT))
				zlog_debug(
					"%s: Updating peer (%s(%s)) status with NHT nexthops %d",
					__func__, peer->host,
					peer->bgp->name_pretty,
					!!valid_nexthops);
			bgp_fsm_nht_update(peer->connection, peer,
					   !!valid_nexthops);
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
	for (afi_t afi = AFI_IP; afi < AFI_MAX; afi++) {
		struct bgp_nexthop_cache *bnc;

		frr_each (bgp_nexthop_cache, &bgp->nexthop_cache_table[afi],
			  bnc) {
			register_zebra_rnh(bnc);
		}
	}
}

void bgp_nht_reg_enhe_cap_intfs(struct peer *peer)
{
	struct bgp *bgp;
	struct bgp_nexthop_cache *bnc;
	struct nexthop *nhop;
	struct interface *ifp;
	struct prefix p;
	ifindex_t ifindex = 0;

	if (peer->ifp)
		return;

	bgp = peer->bgp;

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA))
		return;

	if (!sockunion2hostprefix(&peer->connection->su, &p)) {
		zlog_warn("%s: Unable to convert sockunion to prefix for %s",
			  __func__, peer->host);
		return;
	}

	if (p.family != AF_INET6)
		return;
	/*
	 * Gather the ifindex for if up/down events to be
	 * tagged into this fun
	 */
	if (peer->conf_if &&
	    IN6_IS_ADDR_LINKLOCAL(&peer->connection->su.sin6.sin6_addr))
		ifindex = peer->connection->su.sin6.sin6_scope_id;

	bnc = bnc_find(&bgp->nexthop_cache_table[AFI_IP6], &p, 0, ifindex);
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
	struct bgp_nexthop_cache *bnc;
	struct nexthop *nhop;
	struct interface *ifp;
	struct prefix p;
	ifindex_t ifindex = 0;

	if (peer->ifp)
		return;

	bgp = peer->bgp;

	if (!sockunion2hostprefix(&peer->connection->su, &p)) {
		zlog_warn("%s: Unable to convert sockunion to prefix for %s",
			  __func__, peer->host);
		return;
	}

	if (p.family != AF_INET6)
		return;
	/*
	 * Gather the ifindex for if up/down events to be
	 * tagged into this fun
	 */
	if (peer->conf_if &&
	    IN6_IS_ADDR_LINKLOCAL(&peer->connection->su.sin6.sin6_addr))
		ifindex = peer->connection->su.sin6.sin6_scope_id;

	bnc = bnc_find(&bgp->nexthop_cache_table[AFI_IP6], &p, 0, ifindex);
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
