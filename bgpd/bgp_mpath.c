// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Multipath
 * Copyright (C) 2010 Google Inc.
 *               2024 Nvidia Corporation
 *                    Donald Sharp
 *
 * This file is part of FRR
 */

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "sockunion.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"
#include "jhash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_nhc.h"
#include "bgpd/bgp_zebra.h"

/*
 * bgp_maximum_paths_set
 *
 * Record maximum-paths configuration for BGP instance
 */
int bgp_maximum_paths_set(struct bgp *bgp, afi_t afi, safi_t safi, int peertype,
			  uint16_t maxpaths, bool same_clusterlen)
{
	if (!bgp || (afi >= AFI_MAX) || (safi >= SAFI_MAX))
		return -1;

	switch (peertype) {
	case BGP_PEER_IBGP:
		bgp->maxpaths[afi][safi].maxpaths_ibgp = maxpaths;
		bgp->maxpaths[afi][safi].same_clusterlen = same_clusterlen;
		break;
	case BGP_PEER_EBGP:
		bgp->maxpaths[afi][safi].maxpaths_ebgp = maxpaths;
		break;
	default:
		return -1;
	}

	return 0;
}

/*
 * bgp_maximum_paths_unset
 *
 * Remove maximum-paths configuration from BGP instance
 */
int bgp_maximum_paths_unset(struct bgp *bgp, afi_t afi, safi_t safi,
			    int peertype)
{
	if (!bgp || (afi >= AFI_MAX) || (safi >= SAFI_MAX))
		return -1;

	switch (peertype) {
	case BGP_PEER_IBGP:
		bgp->maxpaths[afi][safi].maxpaths_ibgp = multipath_num;
		bgp->maxpaths[afi][safi].same_clusterlen = false;
		break;
	case BGP_PEER_EBGP:
		bgp->maxpaths[afi][safi].maxpaths_ebgp = multipath_num;
		break;
	default:
		return -1;
	}

	return 0;
}

/*
 * bgp_interface_same
 *
 * Return true if ifindex for ifp1 and ifp2 are the same, else return false.
 */
static int bgp_interface_same(struct interface *ifp1, struct interface *ifp2)
{
	if (!ifp1 && !ifp2)
		return 1;

	if (!ifp1 && ifp2)
		return 0;

	if (ifp1 && !ifp2)
		return 0;

	return (ifp1->ifindex == ifp2->ifindex);
}


/*
 * bgp_path_info_nexthop_cmp
 *
 * Compare the nexthops of two paths. Return value is less than, equal to,
 * or greater than zero if bpi1 is respectively less than, equal to,
 * or greater than bpi2.
 */
int bgp_path_info_nexthop_cmp(struct bgp_path_info *bpi1,
			      struct bgp_path_info *bpi2)
{
	int compare;
	struct in6_addr addr1, addr2;

	compare = IPV4_ADDR_CMP(&bpi1->attr->nexthop, &bpi2->attr->nexthop);
	if (!compare) {
		if (bpi1->attr->mp_nexthop_len == bpi2->attr->mp_nexthop_len) {
			switch (bpi1->attr->mp_nexthop_len) {
			case BGP_ATTR_NHLEN_IPV4:
			case BGP_ATTR_NHLEN_VPNV4:
				compare = IPV4_ADDR_CMP(
					&bpi1->attr->mp_nexthop_global_in,
					&bpi2->attr->mp_nexthop_global_in);
				break;
			case BGP_ATTR_NHLEN_IPV6_GLOBAL:
			case BGP_ATTR_NHLEN_VPNV6_GLOBAL:
				compare = IPV6_ADDR_CMP(
					&bpi1->attr->mp_nexthop_global,
					&bpi2->attr->mp_nexthop_global);
				break;
			case BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL:
				addr1 = (CHECK_FLAG(bpi1->attr->nh_flags,
						    BGP_ATTR_NH_MP_PREFER_GLOBAL))
						? bpi1->attr->mp_nexthop_global
						: bpi1->attr->mp_nexthop_local;
				addr2 = (CHECK_FLAG(bpi2->attr->nh_flags,
						    BGP_ATTR_NH_MP_PREFER_GLOBAL))
						? bpi2->attr->mp_nexthop_global
						: bpi2->attr->mp_nexthop_local;

				if (!CHECK_FLAG(bpi1->attr->nh_flags,
						BGP_ATTR_NH_MP_PREFER_GLOBAL) &&
				    !CHECK_FLAG(bpi2->attr->nh_flags,
						BGP_ATTR_NH_MP_PREFER_GLOBAL))
					compare = !bgp_interface_same(
						bpi1->peer->ifp,
						bpi2->peer->ifp);

				if (!compare)
					compare = IPV6_ADDR_CMP(&addr1, &addr2);
				break;
			}
		}

		/* This can happen if one IPv6 peer sends you global and
		 * link-local
		 * nexthops but another IPv6 peer only sends you global
		 */
		else if (bpi1->attr->mp_nexthop_len
				 == BGP_ATTR_NHLEN_IPV6_GLOBAL
			 || bpi1->attr->mp_nexthop_len
				    == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) {
			compare = IPV6_ADDR_CMP(&bpi1->attr->mp_nexthop_global,
						&bpi2->attr->mp_nexthop_global);
			if (!compare) {
				if (bpi1->attr->mp_nexthop_len
				    < bpi2->attr->mp_nexthop_len)
					compare = -1;
				else
					compare = 1;
			}
		}
	}

	/*
	 * If both nexthops are same then check
	 * if they belong to same VRF
	 */
	if (!compare && bpi1->attr->nh_type != NEXTHOP_TYPE_BLACKHOLE) {
		if (bpi1->extra && bpi1->extra->vrfleak &&
		    bpi1->extra->vrfleak->bgp_orig && bpi2->extra &&
		    bpi2->extra->vrfleak && bpi2->extra->vrfleak->bgp_orig) {
			if (bpi1->extra->vrfleak->bgp_orig->vrf_id !=
			    bpi2->extra->vrfleak->bgp_orig->vrf_id) {
				compare = 1;
			}
		}
	}

	return compare;
}

/*
 * bgp_path_info_mpath_new
 *
 * Allocate and zero memory for a new bgp_path_info_mpath element
 */
static struct bgp_path_info_mpath *bgp_path_info_mpath_new(void)
{
	struct bgp_path_info_mpath *new_mpath;

	new_mpath = XCALLOC(MTYPE_BGP_MPATH_INFO,
			    sizeof(struct bgp_path_info_mpath));

	new_mpath->mp_count = 1;
	return new_mpath;
}

/*
 * bgp_path_info_mpath_free
 *
 * Release resources for a bgp_path_info_mpath element and zero out pointer
 */
void bgp_path_info_mpath_free(struct bgp_path_info_mpath **mpath)
{
	if (mpath && *mpath) {
		if ((*mpath)->mp_attr)
			bgp_attr_unintern(&(*mpath)->mp_attr);
		(*mpath)->mp_attr = NULL;

		XFREE(MTYPE_BGP_MPATH_INFO, *mpath);
	}
}

/*
 * bgp_path_info_mpath_get
 *
 * Fetch the mpath element for the given bgp_dest. Used for
 * doing lazy allocation.
 */
static struct bgp_path_info_mpath *bgp_path_info_mpath_get(struct bgp_dest *dest)
{
	struct bgp_path_info_mpath *mpath;

	if (!dest)
		return NULL;

	if (!dest->mpath) {
		mpath = bgp_path_info_mpath_new();
		dest->mpath = mpath;
		mpath->mp_dest = dest;
	}
	return dest->mpath;
}

/*
 * bgp_path_info_mpath_next
 *
 * Given a bgp_path_info, return the next multipath entry
 */
struct bgp_path_info *bgp_path_info_mpath_next(struct bgp_path_info *path)
{
	path = path->next;

	while (path) {
		if (CHECK_FLAG(path->flags, BGP_PATH_MULTIPATH))
			return path;

		path = path->next;
	}

	return NULL;
}

/*
 * bgp_path_info_mpath_first
 *
 * Given bestpath bgp_path_info, return the first multipath entry.
 */
struct bgp_path_info *bgp_path_info_mpath_first(struct bgp_path_info *path)
{
	return bgp_path_info_mpath_next(path);
}

/*
 * bgp_path_info_mpath_count
 *
 * Given the bgp_dest, return the number of multipath entries
 */
uint32_t bgp_path_info_mpath_count(struct bgp_dest *dest)
{
	if (!dest || !dest->mpath)
		return 1;

	return dest->mpath->mp_count;
}

/*
 * bgp_path_info_mpath_count_set
 *
 * Sets the count of multipaths into bgp_dest's mpath element
 */
static void bgp_path_info_mpath_count_set(struct bgp_dest *dest, uint16_t count)
{
	struct bgp_path_info_mpath *mpath;
	if (!count && (!dest || !dest->mpath))
		return;
	mpath = bgp_path_info_mpath_get(dest);
	if (!mpath)
		return;
	mpath->mp_count = count;
}

/*
 * bgp_path_info_mpath_lb_update
 *
 * Update cumulative info related to link-bandwidth
 *
 * This is set on mpath of the bgp_dest,
 * we should UNSET the flags when removing
 * to ensure nothing accidentally happens
 */
static void bgp_path_info_mpath_lb_update(struct bgp_dest *dest, bool set, bool all_paths_lb,
					  uint64_t cum_bw)
{
	struct bgp_path_info_mpath *mpath;

	if (!dest)
		return;

	mpath = dest->mpath;
	if (mpath == NULL) {
		if (!set || (cum_bw == 0 && !all_paths_lb))
			return;

		mpath = bgp_path_info_mpath_get(dest);
		if (!mpath)
			return;
	}
	if (set) {
		if (cum_bw)
			SET_FLAG(mpath->mp_flags, BGP_MP_LB_PRESENT);
		else
			UNSET_FLAG(mpath->mp_flags, BGP_MP_LB_PRESENT);
		if (all_paths_lb)
			SET_FLAG(mpath->mp_flags, BGP_MP_LB_ALL);
		else
			UNSET_FLAG(mpath->mp_flags, BGP_MP_LB_ALL);
		mpath->cum_bw = cum_bw;
	} else {
		mpath->mp_flags = 0;
		mpath->cum_bw = 0;
	}
}

/*
 * bgp_path_info_mpath_attr
 *
 * Given bgp_dest, return aggregated attribute set used
 * for advertising the multipath route
 */
struct attr *bgp_path_info_mpath_attr(struct bgp_dest *dest)
{
	if (!dest || !dest->mpath)
		return NULL;
	return dest->mpath->mp_attr;
}

/*
 * bgp_path_info_chkwtd
 *
 * Return if we should attempt to do weighted ECMP or not
 * Pass the bgp_dest in.
 */
enum bgp_wecmp_behavior bgp_path_info_mpath_chkwtd(struct bgp *bgp, struct bgp_dest *dest)
{
	enum bgp_wecmp_behavior default_val = BGP_WECMP_BEHAVIOR_NONE;

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_USE_RECURSIVE_WEIGHT))
		default_val = BGP_WECMP_BEHAVIOR_USE_RECURSIVE_VALUE;

	/* Check if not multipath */
	if (!dest || !dest->mpath)
		return default_val;

	struct bgp_path_info *path = bgp_dest_get_bgp_path_info(dest);

	/* If link bandwidth is to be ignored, check if we have Next-Next Hop Nodes
	 * characteristic and do weighted ECMP based on that.
	 */
	if (bgp->lb_handling == BGP_LINK_BW_IGNORE_BW) {
		if (bgp_attr_exists(path->attr, BGP_ATTR_NHC))
			return BGP_WECMP_BEHAVIOR_NNHN_COUNT;
	}

	/* All paths in multipath should have associated weight (bandwidth)
	 * unless told explicitly otherwise.
	 */
	if (bgp->lb_handling != BGP_LINK_BW_SKIP_MISSING &&
	    bgp->lb_handling != BGP_LINK_BW_DEFWT_4_MISSING) {
		if (CHECK_FLAG(dest->mpath->mp_flags, BGP_MP_LB_ALL))
			return BGP_WECMP_BEHAVIOR_LINK_BW;
		else
			return default_val;
	}

	if (CHECK_FLAG(dest->mpath->mp_flags, BGP_MP_LB_PRESENT))
		return BGP_WECMP_BEHAVIOR_LINK_BW;

	return default_val;
}

/*
 * bgp_path_info_mpath_attr
 *
 * Given bgp_dest, return cumulative bandwidth
 * computed for all multipaths with bandwidth info
 */
uint64_t bgp_path_info_mpath_cumbw(struct bgp_dest *dest)
{
	if (!dest || !dest->mpath)
		return 0;
	return dest->mpath->cum_bw;
}

/*
 * bgp_path_info_mpath_attr_set
 *
 * Sets the aggregated attribute into bgp_dest's mpath element
 */
static void bgp_path_info_mpath_attr_set(struct bgp_dest *dest, struct attr *attr)
{
	struct bgp_path_info_mpath *mpath;
	if (!attr && (!dest || !dest->mpath))
		return;
	mpath = bgp_path_info_mpath_get(dest);
	if (!mpath)
		return;
	mpath->mp_attr = attr;
}

/*
 * bgp_path_info_mpath_update
 *
 * Compare and sync up the multipath flags with what was chosen
 * in best selection
 */

/*
 * Forwarding identity of a path, used to keep duplicate nexthops from
 * consuming a maxpaths slot.
 *
 * This must never be coarser than the identity zebra ends up programming:
 * merging two nexthops that would have become distinct forwarding entries
 * loses a path, whereas letting a duplicate through only costs a slot that
 * zebra reclaims later.
 */
struct bgp_mpath_nh_key {
	enum nexthop_types_t type;
	vrf_id_t vrf_id;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} gate;
	/*
	 * An EVPN gateway-IP route carries the forwarding address in
	 * attr->nexthop and the VTEP in mp_nexthop_global_in, so both have
	 * to be part of the identity.
	 */
	struct in_addr mp_gate_v4;
	/*
	 * On the type-5 route in the EVPN table both of those are the VTEP,
	 * and the gateway IP is held only in the overlay index.
	 */
	struct ipaddr gw_ip;
	ifindex_t ifindex;
	struct in6_addr sid;
	mpls_label_t labels[BGP_MAX_LABELS];
	/*
	 * Under weighted ECMP each nexthop takes the weight of its own path,
	 * and zebra keeps two nexthops apart when only their weights differ.
	 */
	uint64_t weight;
	/*
	 * Set when the forwarding identity cannot be settled here, which
	 * keeps the path from matching anything else.
	 */
	const void *indeterminate;
	uint8_t num_labels;
	bool is_evpn;
	bool gw_ip_overlay;
};

PREDECL_HASH(bgp_mpath_nh);

struct bgp_mpath_nh_entry {
	struct bgp_mpath_nh_item itm;
	struct bgp_mpath_nh_key key;
};

static void bgp_mpath_nh_key_make(struct bgp *bgp, struct bgp_path_info *pi,
				  struct bgp_mpath_nh_key *key)
{
	struct attr *attr = pi->attr;
	struct bgp_route_evpn *bre = bgp_attr_get_evpn_overlay(attr);
	struct bgp_attr_srv6_l3service *srv6_l3service;
	struct bgp_attr_srv6_vpn *srv6_vpn;
	uint8_t num_labels = BGP_PATH_INFO_NUM_LABELS(pi);

	/*
	 * The key is hashed and compared as raw bytes, so padding has to be
	 * zeroed rather than left indeterminate.
	 */
	memset(key, 0, sizeof(*key));

	key->is_evpn = !!is_route_parent_evpn(pi);
	key->gw_ip_overlay = bre && bre->type == OVERLAY_INDEX_GATEWAY_IP;
	if (key->gw_ip_overlay) {
		key->gw_ip.ipa_type = bre->gw_ip.ipa_type;
		if (IS_IPADDR_V4(&bre->gw_ip))
			key->gw_ip.ipaddr_v4 = bre->gw_ip.ipaddr_v4;
		else if (IS_IPADDR_V6(&bre->gw_ip))
			key->gw_ip.ipaddr_v6 = bre->gw_ip.ipaddr_v6;
	}

	if (pi->extra && pi->extra->vrfleak && pi->extra->vrfleak->bgp_orig)
		key->vrf_id = pi->extra->vrfleak->bgp_orig->vrf_id;
	else
		key->vrf_id = bgp->vrf_id;

	if (BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr)) {
		ifindex_t ifindex = IFINDEX_INTERNAL;
		struct in6_addr *nexthop;

		/*
		 * Resolve the nexthop exactly as the announce path does. A
		 * link-local address is only unique per interface, and which
		 * of the global, link-local or peer address applies is not
		 * obvious from the attribute alone.
		 */
		nexthop = bgp_path_info_to_ipv6_nexthop(pi, &ifindex);
		key->type = NEXTHOP_TYPE_IPV6;
		if (nexthop) {
			key->gate.ipv6 = *nexthop;
			key->ifindex = ifindex;
			/*
			 * The same link-local address can be in use on
			 * several interfaces at once, so it only identifies a
			 * nexthop together with one. When the attribute
			 * carries no ifindex the interface is settled much
			 * later, as the route is handed to zebra, from peer
			 * state the path does not record. Two sessions over
			 * different interfaces advertising one link-local
			 * address would therefore look alike here while zebra
			 * goes on to program two distinct interface-scoped
			 * nexthops. Keep such a path out of the comparison: a
			 * slot spent on it is reclaimed later, whereas
			 * merging the two would drop a usable ECMP path.
			 */
			if (!ifindex && IN6_IS_ADDR_LINKLOCAL(nexthop))
				key->indeterminate = pi;
		}
	} else {
		key->type = NEXTHOP_TYPE_IPV4;
		key->gate.ipv4 = attr->nexthop;
		key->mp_gate_v4 = attr->mp_nexthop_global_in;
	}

	if (num_labels) {
		key->num_labels = num_labels;
		memcpy(key->labels, pi->extra->labels->label, num_labels * sizeof(mpls_label_t));
	}

	srv6_l3service = bgp_attr_get_srv6_l3service(attr);
	srv6_vpn = bgp_attr_get_srv6_vpn(attr);
	if (srv6_l3service)
		key->sid = srv6_l3service->sid;
	else if (srv6_vpn)
		key->sid = srv6_vpn->sid;

	/*
	 * Take the weight from the same place bgp_path_info_mpath_chkwtd()
	 * does: the next-next hop node count of the NHC attribute when link
	 * bandwidth is ignored, and the link bandwidth otherwise.
	 */
	if (bgp->lb_handling == BGP_LINK_BW_IGNORE_BW) {
		if (bgp_attr_exists(attr, BGP_ATTR_NHC))
			key->weight = bgp_nhc_nnhn_count(bgp_attr_get_nhc(attr));
	} else {
		key->weight = bgp_path_info_get_link_bw(pi);
	}
}

static uint32_t bgp_mpath_nh_hash_key(const struct bgp_mpath_nh_entry *entry)
{
	return jhash(&entry->key, sizeof(entry->key), 0x5a5a55aa);
}

static int bgp_mpath_nh_hash_cmp(const struct bgp_mpath_nh_entry *a,
				 const struct bgp_mpath_nh_entry *b)
{
	return memcmp(&a->key, &b->key, sizeof(a->key));
}

DECLARE_HASH(bgp_mpath_nh, struct bgp_mpath_nh_entry, itm, bgp_mpath_nh_hash_cmp,
	     bgp_mpath_nh_hash_key);

void bgp_path_info_mpath_update(struct bgp *bgp, struct bgp_dest *dest,
				struct bgp_path_info *new_best, struct bgp_path_info *old_best,
				uint32_t num_candidates, struct bgp_maxpaths_cfg *mpath_cfg)
{
	uint16_t maxpaths, mpath_count, old_mpath_count;
	uint64_t bwval;
	uint64_t cum_bw, old_cum_bw;
	struct bgp_path_info *cur_iterator = NULL;
	bool mpath_changed, debug;
	bool all_paths_lb;
	char path_buf[PATH_ADDPATH_STR_BUFFER];
	bool old_mpath, new_mpath;
	struct bgp_mpath_nh_head nh_dedup;
	struct bgp_mpath_nh_entry dedup_items[MULTIPATH_NUM];
	unsigned int dedup_idx = 0;
	bool do_dedup;

	mpath_changed = false;
	maxpaths = multipath_num;
	mpath_count = 0;
	old_mpath_count = 0;
	old_cum_bw = cum_bw = 0;
	debug = bgp_debug_bestpath(dest);

	if (old_best) {
		old_mpath_count = bgp_path_info_mpath_count(dest);
		/* Only mark old best as multipath when we have a new best path.
		 * When new_best is NULL (e.g. only path became invalid/holddown),
		 * the old path is not "another ECMP path" and should not show
		 * as multipath.
		 */
		if (new_best && old_mpath_count == 1)
			SET_FLAG(old_best->flags, BGP_PATH_MULTIPATH);
		old_cum_bw = bgp_path_info_mpath_cumbw(dest);
		bgp_path_info_mpath_count_set(dest, 0);
		bgp_path_info_mpath_lb_update(dest, false, false, 0);
		bgp_path_info_mpath_free(&dest->mpath);
		dest->mpath = NULL;
	}

	if (new_best) {
		maxpaths = (new_best->peer->sort == BGP_PEER_IBGP) ? mpath_cfg->maxpaths_ibgp
								   : mpath_cfg->maxpaths_ebgp;
		cur_iterator = new_best;
	}

	if (debug)
		zlog_debug("%pBD(%s): starting mpath update, newbest %s num candidates %d old-mpath-count %d old-cum-bw %" PRIu64
			   " maxpaths set %u",
			   dest, bgp->name_pretty, new_best ? new_best->peer->host : "NONE",
			   num_candidates, old_mpath_count, old_cum_bw, maxpaths);

	/*
	 * We perform an ordered walk through both lists in parallel.
	 * The reason for the ordered walk is that if there are paths
	 * that were previously multipaths and are still multipaths, the walk
	 * should encounter them in both lists at the same time. Otherwise
	 * there will be paths that are in one list or another, and we
	 * will deal with these separately.
	 *
	 * Note that new_best might be somewhere in the mp_list, so we need
	 * to skip over it
	 */
	all_paths_lb = true; /* We'll reset if any path doesn't have LB. */

	/*
	 * A lone candidate is the bestpath itself and cannot duplicate
	 * anything, so skip the table entirely rather than pay for the
	 * bucket allocation on every prefix.
	 */
	do_dedup = num_candidates > 1;
	if (do_dedup)
		bgp_mpath_nh_init(&nh_dedup);

	while (cur_iterator) {
		old_mpath = CHECK_FLAG(cur_iterator->flags, BGP_PATH_MULTIPATH);
		new_mpath = CHECK_FLAG(cur_iterator->flags, BGP_PATH_MULTIPATH_NEW);

		UNSET_FLAG(cur_iterator->flags, BGP_PATH_MULTIPATH_NEW);
		/*
		 * If the current mpath count is equal to the number of
		 * maxpaths that can be used then we can bail, after
		 * we clean up the flags associated with the rest of the
		 * bestpaths
		 */
		if (mpath_count >= maxpaths) {
			while (cur_iterator) {
				UNSET_FLAG(cur_iterator->flags, BGP_PATH_MULTIPATH);
				UNSET_FLAG(cur_iterator->flags, BGP_PATH_MULTIPATH_NEW);

				cur_iterator = cur_iterator->next;
			}

			if (debug)
				zlog_debug("%pBD(%s): Mpath count %u is equal to maximum paths allowed, finished comparison for MPATHS",
					   dest, bgp->name_pretty, mpath_count);

			break;
		}

		if (debug)
			zlog_debug("%pBD(%s): Candidate %s old_mpath: %u new_mpath: %u, Nexthop %pI4 current mpath count: %u",
				   dest, bgp->name_pretty, cur_iterator->peer->host, old_mpath,
				   new_mpath, &cur_iterator->attr->nexthop, mpath_count);
		/*
		 * A path resolving to a nexthop we have already selected adds
		 * nothing to the forwarding entry, so it must not spend one of
		 * the maxpaths slots. Demoting it to "not a new multipath"
		 * lets the handling below do the flag and counter cleanup.
		 *
		 * new_best is walked first against an empty table, so the
		 * bestpath is always accepted and always seeds the table.
		 */
		if (do_dedup && new_mpath && dedup_idx < array_size(dedup_items)) {
			struct bgp_mpath_nh_entry *entry = &dedup_items[dedup_idx];

			bgp_mpath_nh_key_make(bgp, cur_iterator, &entry->key);

			if (bgp_mpath_nh_find(&nh_dedup, entry)) {
				if (debug)
					zlog_debug("%pBD(%s): %s nexthop %pI4 is already selected, not counting it as a multipath",
						   dest, bgp->name_pretty, cur_iterator->peer->host,
						   &cur_iterator->attr->nexthop);
				new_mpath = false;
			} else {
				bgp_mpath_nh_add(&nh_dedup, entry);
				dedup_idx++;
			}
		}

		/*
		 * There is nothing to do if the cur_iterator is neither a old path
		 * or a new path
		 */
		if (!old_mpath && !new_mpath) {
			UNSET_FLAG(cur_iterator->flags, BGP_PATH_MULTIPATH);
			cur_iterator = cur_iterator->next;
			continue;
		}

		if (new_mpath) {
			mpath_count++;

			if (cur_iterator != new_best)
				SET_FLAG(cur_iterator->flags, BGP_PATH_MULTIPATH);

			if (!old_mpath)
				mpath_changed = true;

			if (ecommunity_linkbw_present(bgp_attr_get_ecommunity(cur_iterator->attr),
						      &bwval) ||
			    ecommunity_linkbw_present(bgp_attr_get_ipv6_ecommunity(
							      cur_iterator->attr),
						      &bwval))
				cum_bw += bwval;
			else
				all_paths_lb = false;

			if (debug) {
				bgp_path_info_path_with_addpath_rx_str(cur_iterator, path_buf,
								       sizeof(path_buf));
				zlog_debug("%pBD(%s): add mpath %s nexthop %pI4, cur count %d cum_bw: %" PRIu64
					   " all_paths_lb: %u",
					   dest, bgp->name_pretty, path_buf,
					   &cur_iterator->attr->nexthop, mpath_count, cum_bw,
					   all_paths_lb);
			}
		} else {
			/*
			 * We know that old_mpath is true and new_mpath is false in this path
			 */
			mpath_changed = true;
			UNSET_FLAG(cur_iterator->flags, BGP_PATH_MULTIPATH);
		}

		cur_iterator = cur_iterator->next;
	}

	if (do_dedup) {
		while (bgp_mpath_nh_pop(&nh_dedup))
			;
		bgp_mpath_nh_fini(&nh_dedup);
	}

	if (new_best) {
		if (mpath_count > 1) {
			bgp_path_info_mpath_count_set(dest, mpath_count);
			bgp_path_info_mpath_lb_update(dest, true, all_paths_lb, cum_bw);
		}
		if (debug)
			zlog_debug("%pBD(%s): New mpath count (incl newbest) %d mpath-change %s all_paths_lb %d cum_bw %" PRIu64,
				   dest, bgp->name_pretty, mpath_count,
				   mpath_changed ? "YES" : "NO", all_paths_lb,
				   cum_bw);

		if (mpath_count == 1) {
			UNSET_FLAG(new_best->flags, BGP_PATH_MULTIPATH);
			if (dest->mpath)
				bgp_path_info_mpath_free(&dest->mpath);
		}
		if (mpath_changed || (bgp_path_info_mpath_count(dest) != old_mpath_count))
			SET_FLAG(new_best->flags, BGP_PATH_MULTIPATH_CHG);
		if ((mpath_count) != old_mpath_count || old_cum_bw != cum_bw)
			SET_FLAG(new_best->flags, BGP_PATH_LINK_BW_CHG);
	}
}

/*
 * bgp_path_info_mpath_aggregate_update
 *
 * Set the multipath aggregate attribute. We need to see if the
 * aggregate has changed and then set the ATTR_CHANGED flag on the
 * bestpath info so that a peer update will be generated. The
 * change is detected by generating the current attribute,
 * interning it, and then comparing the interned pointer with the
 * current value. We can skip this generate/compare step if there
 * is no change in multipath selection and no attribute change in
 * any multipath.
 */
void bgp_path_info_mpath_aggregate_update(struct bgp_path_info *new_best,
					  struct bgp_path_info *old_best)
{
	struct bgp_path_info *mpinfo;
	struct aspath *aspath;
	struct aspath *asmerge;
	struct attr *new_attr, *old_attr;
	uint8_t origin;
	struct community *community, *commerge;
	struct ecommunity *ecomm, *ecommerge;
	struct lcommunity *lcomm, *lcommerge;
	struct attr attr = {0};

	if (old_best && (old_best != new_best) &&
	    (old_attr = bgp_path_info_mpath_attr(old_best->net))) {
		bgp_attr_unintern(&old_attr);
		bgp_path_info_mpath_attr_set(old_best->net, NULL);
	}

	if (!new_best)
		return;

	if (bgp_path_info_mpath_count(new_best->net) == 1) {
		if ((new_attr = bgp_path_info_mpath_attr(new_best->net))) {
			bgp_attr_unintern(&new_attr);
			bgp_path_info_mpath_attr_set(new_best->net, NULL);
			SET_FLAG(new_best->flags, BGP_PATH_ATTR_CHANGED);
		}
		return;
	}

	bgp_attr_dup_into(&attr, new_best->attr);

	if (new_best->peer
	    && CHECK_FLAG(new_best->peer->bgp->flags,
			  BGP_FLAG_MULTIPATH_RELAX_AS_SET)) {

		/* aggregate attribute from multipath constituents */
		aspath = aspath_dup(attr.aspath);
		origin = attr.origin;
		community =
			bgp_attr_get_community(&attr)
				? community_dup(bgp_attr_get_community(&attr))
				: NULL;
		ecomm = (bgp_attr_get_ecommunity(&attr))
				? ecommunity_dup(bgp_attr_get_ecommunity(&attr))
				: NULL;
		lcomm = (bgp_attr_get_lcommunity(&attr))
				? lcommunity_dup(bgp_attr_get_lcommunity(&attr))
				: NULL;

		for (mpinfo = bgp_path_info_mpath_first(new_best); mpinfo;
		     mpinfo = bgp_path_info_mpath_next(mpinfo)) {
			asmerge =
				aspath_aggregate(aspath, mpinfo->attr->aspath);
			aspath_free(aspath);
			aspath = asmerge;

			if (origin < mpinfo->attr->origin)
				origin = mpinfo->attr->origin;

			if (bgp_attr_get_community(mpinfo->attr)) {
				if (community) {
					commerge = community_merge(
						community,
						bgp_attr_get_community(
							mpinfo->attr));
					community =
						community_uniq_sort(commerge);
					community_free(&commerge);
				} else
					community = community_dup(
						bgp_attr_get_community(
							mpinfo->attr));
			}

			if (bgp_attr_get_ecommunity(mpinfo->attr)) {
				if (ecomm) {
					ecommerge = ecommunity_merge(
						ecomm, bgp_attr_get_ecommunity(
							       mpinfo->attr));
					ecomm = ecommunity_uniq_sort(ecommerge);
					ecommunity_free(&ecommerge);
				} else
					ecomm = ecommunity_dup(
						bgp_attr_get_ecommunity(
							mpinfo->attr));
			}
			if (bgp_attr_get_lcommunity(mpinfo->attr)) {
				if (lcomm) {
					lcommerge = lcommunity_merge(
						lcomm, bgp_attr_get_lcommunity(
							       mpinfo->attr));
					lcomm = lcommunity_uniq_sort(lcommerge);
					lcommunity_free(&lcommerge);
				} else
					lcomm = lcommunity_dup(
						bgp_attr_get_lcommunity(
							mpinfo->attr));
			}
		}

		attr.aspath = aspath;
		attr.origin = origin;
		if (community)
			bgp_attr_set_community(&attr, community);
		if (ecomm)
			bgp_attr_set_ecommunity(&attr, ecomm);
		if (lcomm)
			bgp_attr_set_lcommunity(&attr, lcomm);

		/* Zap multipath attr nexthop so we set nexthop to self */
		attr.nexthop.s_addr = INADDR_ANY;
		memset(&attr.mp_nexthop_global, 0, sizeof(struct in6_addr));

		/* TODO: should we set ATOMIC_AGGREGATE and AGGREGATOR? */
	}

	new_attr = bgp_attr_intern(&attr);

	if (new_attr != bgp_path_info_mpath_attr(new_best->net)) {
		if ((old_attr = bgp_path_info_mpath_attr(new_best->net)))
			bgp_attr_unintern(&old_attr);
		bgp_path_info_mpath_attr_set(new_best->net, new_attr);
		SET_FLAG(new_best->flags, BGP_PATH_ATTR_CHANGED);
	} else
		bgp_attr_unintern(&new_attr);
}
