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
#include "linklist.h"
#include "sockunion.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_mpath.h"

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
 * Fetch the mpath element for the given bgp_path_info. Used for
 * doing lazy allocation.
 */
static struct bgp_path_info_mpath *
bgp_path_info_mpath_get(struct bgp_path_info *path)
{
	struct bgp_path_info_mpath *mpath;

	if (!path)
		return NULL;

	if (!path->mpath) {
		mpath = bgp_path_info_mpath_new();
		path->mpath = mpath;
		mpath->mp_info = path;
	}
	return path->mpath;
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
 * Given the bestpath bgp_path_info, return the number of multipath entries
 */
uint32_t bgp_path_info_mpath_count(struct bgp_path_info *path)
{
	if (!path->mpath)
		return 1;

	return path->mpath->mp_count;
}

/*
 * bgp_path_info_mpath_count_set
 *
 * Sets the count of multipaths into bestpath's mpath element
 */
static void bgp_path_info_mpath_count_set(struct bgp_path_info *path,
					  uint16_t count)
{
	struct bgp_path_info_mpath *mpath;
	if (!count && !path->mpath)
		return;
	mpath = bgp_path_info_mpath_get(path);
	if (!mpath)
		return;
	mpath->mp_count = count;
}

/*
 * bgp_path_info_mpath_lb_update
 *
 * Update cumulative info related to link-bandwidth
 *
 * This is only set on the first mpath of the list
 * as such we should UNSET the flags when removing
 * to ensure nothing accidently happens
 */
static void bgp_path_info_mpath_lb_update(struct bgp_path_info *path, bool set,
					  bool all_paths_lb, uint64_t cum_bw)
{
	struct bgp_path_info_mpath *mpath;

	mpath = path->mpath;
	if (mpath == NULL) {
		if (!set || (cum_bw == 0 && !all_paths_lb))
			return;

		mpath = bgp_path_info_mpath_get(path);
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
 * Given bestpath bgp_path_info, return aggregated attribute set used
 * for advertising the multipath route
 */
struct attr *bgp_path_info_mpath_attr(struct bgp_path_info *path)
{
	if (!path->mpath)
		return NULL;
	return path->mpath->mp_attr;
}

/*
 * bgp_path_info_chkwtd
 *
 * Return if we should attempt to do weighted ECMP or not
 * The path passed in is the bestpath.
 */
bool bgp_path_info_mpath_chkwtd(struct bgp *bgp, struct bgp_path_info *path)
{
	/* Check if told to ignore weights or not multipath */
	if (bgp->lb_handling == BGP_LINK_BW_IGNORE_BW || !path->mpath)
		return false;

	/* All paths in multipath should have associated weight (bandwidth)
	 * unless told explicitly otherwise.
	 */
	if (bgp->lb_handling != BGP_LINK_BW_SKIP_MISSING &&
	    bgp->lb_handling != BGP_LINK_BW_DEFWT_4_MISSING)
		return CHECK_FLAG(path->mpath->mp_flags, BGP_MP_LB_ALL);

	/* At least one path should have bandwidth. */
	return CHECK_FLAG(path->mpath->mp_flags, BGP_MP_LB_PRESENT);
}

/*
 * bgp_path_info_mpath_attr
 *
 * Given bestpath bgp_path_info, return cumulative bandwidth
 * computed for all multipaths with bandwidth info
 */
uint64_t bgp_path_info_mpath_cumbw(struct bgp_path_info *path)
{
	if (!path->mpath)
		return 0;
	return path->mpath->cum_bw;
}

/*
 * bgp_path_info_mpath_attr_set
 *
 * Sets the aggregated attribute into bestpath's mpath element
 */
static void bgp_path_info_mpath_attr_set(struct bgp_path_info *path,
					 struct attr *attr)
{
	struct bgp_path_info_mpath *mpath;
	if (!attr && !path->mpath)
		return;
	mpath = bgp_path_info_mpath_get(path);
	if (!mpath)
		return;
	mpath->mp_attr = attr;
}

/*
 * bgp_path_info_mpath_update
 *
 * Compare and sync up the multipath flags with what was choosen
 * in best selection
 */
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

	mpath_changed = false;
	maxpaths = multipath_num;
	mpath_count = 0;
	old_mpath_count = 0;
	old_cum_bw = cum_bw = 0;
	debug = bgp_debug_bestpath(dest);

	if (old_best) {
		old_mpath_count = bgp_path_info_mpath_count(old_best);
		if (old_mpath_count == 1)
			SET_FLAG(old_best->flags, BGP_PATH_MULTIPATH);
		old_cum_bw = bgp_path_info_mpath_cumbw(old_best);
		bgp_path_info_mpath_count_set(old_best, 0);
		bgp_path_info_mpath_lb_update(old_best, false, false, 0);
		bgp_path_info_mpath_free(&old_best->mpath);
		old_best->mpath = NULL;
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
				zlog_debug("%pBD(%s): Mpath count %u is equal to maximum paths allowed, finished comparision for MPATHS",
					   dest, bgp->name_pretty, mpath_count);

			break;
		}

		if (debug)
			zlog_debug("%pBD(%s): Candidate %s old_mpath: %u new_mpath: %u, Nexthop %pI4 current mpath count: %u",
				   dest, bgp->name_pretty, cur_iterator->peer->host, old_mpath,
				   new_mpath, &cur_iterator->attr->nexthop, mpath_count);
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
				zlog_debug("%pBD: add mpath %s nexthop %pI4, cur count %d cum_bw: %" PRIu64
					   " all_paths_lb: %u",
					   dest, path_buf, &cur_iterator->attr->nexthop,
					   mpath_count, cum_bw, all_paths_lb);
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

	if (new_best) {
		if (mpath_count > 1 || new_best->mpath) {
			bgp_path_info_mpath_count_set(new_best, mpath_count);
			bgp_path_info_mpath_lb_update(new_best, true, all_paths_lb, cum_bw);
		}
		if (debug)
			zlog_debug("%pBD(%s): New mpath count (incl newbest) %d mpath-change %s all_paths_lb %d cum_bw %" PRIu64,
				   dest, bgp->name_pretty, mpath_count,
				   mpath_changed ? "YES" : "NO", all_paths_lb,
				   cum_bw);

		if (mpath_count == 1)
			UNSET_FLAG(new_best->flags, BGP_PATH_MULTIPATH);
		if (mpath_changed
		    || (bgp_path_info_mpath_count(new_best) != old_mpath_count))
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

	if (old_best && (old_best != new_best)
	    && (old_attr = bgp_path_info_mpath_attr(old_best))) {
		bgp_attr_unintern(&old_attr);
		bgp_path_info_mpath_attr_set(old_best, NULL);
	}

	if (!new_best)
		return;

	if (bgp_path_info_mpath_count(new_best) == 1) {
		if ((new_attr = bgp_path_info_mpath_attr(new_best))) {
			bgp_attr_unintern(&new_attr);
			bgp_path_info_mpath_attr_set(new_best, NULL);
			SET_FLAG(new_best->flags, BGP_PATH_ATTR_CHANGED);
		}
		return;
	}

	attr = *new_best->attr;

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

	if (new_attr != bgp_path_info_mpath_attr(new_best)) {
		if ((old_attr = bgp_path_info_mpath_attr(new_best)))
			bgp_attr_unintern(&old_attr);
		bgp_path_info_mpath_attr_set(new_best, new_attr);
		SET_FLAG(new_best->flags, BGP_PATH_ATTR_CHANGED);
	} else
		bgp_attr_unintern(&new_attr);
}
