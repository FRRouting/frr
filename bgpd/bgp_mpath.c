// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Multipath
 * Copyright (C) 2010 Google Inc.
 *
 * This file is part of Quagga
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
				addr1 = (bpi1->attr->mp_nexthop_prefer_global)
						? bpi1->attr->mp_nexthop_global
						: bpi1->attr->mp_nexthop_local;
				addr2 = (bpi2->attr->mp_nexthop_prefer_global)
						? bpi2->attr->mp_nexthop_global
						: bpi2->attr->mp_nexthop_local;

				if (!bpi1->attr->mp_nexthop_prefer_global
				    && !bpi2->attr->mp_nexthop_prefer_global)
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
 * bgp_path_info_mpath_cmp
 *
 * This function determines our multipath list ordering. By ordering
 * the list we can deterministically select which paths are included
 * in the multipath set. The ordering also helps in detecting changes
 * in the multipath selection so we can detect whether to send an
 * update to zebra.
 *
 * The order of paths is determined first by received nexthop, and then
 * by peer address if the nexthops are the same.
 */
static int bgp_path_info_mpath_cmp(void *val1, void *val2)
{
	struct bgp_path_info *bpi1, *bpi2;
	int compare;

	bpi1 = val1;
	bpi2 = val2;

	compare = bgp_path_info_nexthop_cmp(bpi1, bpi2);

	if (!compare) {
		if (!bpi1->peer->su_remote && !bpi2->peer->su_remote)
			compare = 0;
		else if (!bpi1->peer->su_remote)
			compare = 1;
		else if (!bpi2->peer->su_remote)
			compare = -1;
		else
			compare = sockunion_cmp(bpi1->peer->su_remote,
						bpi2->peer->su_remote);
	}

	return compare;
}

/*
 * bgp_mp_list_init
 *
 * Initialize the mp_list, which holds the list of multipaths
 * selected by bgp_best_selection
 */
void bgp_mp_list_init(struct list *mp_list)
{
	assert(mp_list);
	memset(mp_list, 0, sizeof(struct list));
	mp_list->cmp = bgp_path_info_mpath_cmp;
}

/*
 * bgp_mp_list_clear
 *
 * Clears all entries out of the mp_list
 */
void bgp_mp_list_clear(struct list *mp_list)
{
	assert(mp_list);
	list_delete_all_node(mp_list);
}

/*
 * bgp_mp_list_add
 *
 * Adds a multipath entry to the mp_list
 */
void bgp_mp_list_add(struct list *mp_list, struct bgp_path_info *mpinfo)
{
	assert(mp_list && mpinfo);
	listnode_add_sort(mp_list, mpinfo);
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
 * bgp_path_info_mpath_enqueue
 *
 * Enqueue a path onto the multipath list given the previous multipath
 * list entry
 */
static void bgp_path_info_mpath_enqueue(struct bgp_path_info *prev_info,
					struct bgp_path_info *path)
{
	struct bgp_path_info_mpath *prev, *mpath;

	prev = bgp_path_info_mpath_get(prev_info);
	mpath = bgp_path_info_mpath_get(path);
	if (!prev || !mpath)
		return;

	mpath->mp_next = prev->mp_next;
	mpath->mp_prev = prev;
	if (prev->mp_next)
		prev->mp_next->mp_prev = mpath;
	prev->mp_next = mpath;

	SET_FLAG(path->flags, BGP_PATH_MULTIPATH);
}

/*
 * bgp_path_info_mpath_dequeue
 *
 * Remove a path from the multipath list
 */
void bgp_path_info_mpath_dequeue(struct bgp_path_info *path)
{
	struct bgp_path_info_mpath *mpath = path->mpath;
	if (!mpath)
		return;
	if (mpath->mp_prev)
		mpath->mp_prev->mp_next = mpath->mp_next;
	if (mpath->mp_next)
		mpath->mp_next->mp_prev = mpath->mp_prev;
	mpath->mp_next = mpath->mp_prev = NULL;
	UNSET_FLAG(path->flags, BGP_PATH_MULTIPATH);
}

/*
 * bgp_path_info_mpath_next
 *
 * Given a bgp_path_info, return the next multipath entry
 */
struct bgp_path_info *bgp_path_info_mpath_next(struct bgp_path_info *path)
{
	if (!path->mpath || !path->mpath->mp_next)
		return NULL;
	return path->mpath->mp_next->mp_info;
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
		return 0;
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
		return (path->mpath->mp_flags & BGP_MP_LB_ALL);

	/* At least one path should have bandwidth. */
	return (path->mpath->mp_flags & BGP_MP_LB_PRESENT);
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
 * Compare and sync up the multipath list with the mp_list generated by
 * bgp_best_selection
 */
void bgp_path_info_mpath_update(struct bgp *bgp, struct bgp_dest *dest,
				struct bgp_path_info *new_best,
				struct bgp_path_info *old_best,
				struct list *mp_list,
				struct bgp_maxpaths_cfg *mpath_cfg)
{
	uint16_t maxpaths, mpath_count, old_mpath_count;
	uint32_t bwval;
	uint64_t cum_bw, old_cum_bw;
	struct listnode *mp_node, *mp_next_node;
	struct bgp_path_info *cur_mpath, *new_mpath, *next_mpath, *prev_mpath;
	int mpath_changed, debug;
	bool all_paths_lb;
	char path_buf[PATH_ADDPATH_STR_BUFFER];

	mpath_changed = 0;
	maxpaths = multipath_num;
	mpath_count = 0;
	cur_mpath = NULL;
	old_mpath_count = 0;
	old_cum_bw = cum_bw = 0;
	prev_mpath = new_best;
	mp_node = listhead(mp_list);
	debug = bgp_debug_bestpath(dest);

	if (new_best) {
		mpath_count++;
		if (new_best != old_best)
			bgp_path_info_mpath_dequeue(new_best);
		maxpaths = (new_best->peer->sort == BGP_PEER_IBGP)
				   ? mpath_cfg->maxpaths_ibgp
				   : mpath_cfg->maxpaths_ebgp;
	}

	if (old_best) {
		cur_mpath = bgp_path_info_mpath_first(old_best);
		old_mpath_count = bgp_path_info_mpath_count(old_best);
		old_cum_bw = bgp_path_info_mpath_cumbw(old_best);
		bgp_path_info_mpath_count_set(old_best, 0);
		bgp_path_info_mpath_lb_update(old_best, false, false, 0);
		bgp_path_info_mpath_dequeue(old_best);
	}

	if (debug)
		zlog_debug(
			"%pRN(%s): starting mpath update, newbest %s num candidates %d old-mpath-count %d old-cum-bw %" PRIu64,
			bgp_dest_to_rnode(dest), bgp->name_pretty,
			new_best ? new_best->peer->host : "NONE",
			mp_list ? listcount(mp_list) : 0, old_mpath_count,
			old_cum_bw);

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
	while (mp_node || cur_mpath) {
		struct bgp_path_info *tmp_info;

		/*
		 * We can bail out of this loop if all existing paths on the
		 * multipath list have been visited (for cleanup purposes) and
		 * the maxpath requirement is fulfulled
		 */
		if (!cur_mpath && (mpath_count >= maxpaths))
			break;

		mp_next_node = mp_node ? listnextnode(mp_node) : NULL;
		next_mpath =
			cur_mpath ? bgp_path_info_mpath_next(cur_mpath) : NULL;
		tmp_info = mp_node ? listgetdata(mp_node) : NULL;

		if (debug)
			zlog_debug(
				"%pRN(%s): comparing candidate %s with existing mpath %s",
				bgp_dest_to_rnode(dest), bgp->name_pretty,
				tmp_info ? tmp_info->peer->host : "NONE",
				cur_mpath ? cur_mpath->peer->host : "NONE");

		/*
		 * If equal, the path was a multipath and is still a multipath.
		 * Insert onto new multipath list if maxpaths allows.
		 */
		if (mp_node && (listgetdata(mp_node) == cur_mpath)) {
			list_delete_node(mp_list, mp_node);
			bgp_path_info_mpath_dequeue(cur_mpath);
			if ((mpath_count < maxpaths)
			    && prev_mpath
			    && bgp_path_info_nexthop_cmp(prev_mpath,
							 cur_mpath)) {
				bgp_path_info_mpath_enqueue(prev_mpath,
							    cur_mpath);
				prev_mpath = cur_mpath;
				mpath_count++;
				if (ecommunity_linkbw_present(
					    bgp_attr_get_ecommunity(
						    cur_mpath->attr),
					    &bwval))
					cum_bw += bwval;
				else
					all_paths_lb = false;
				if (debug) {
					bgp_path_info_path_with_addpath_rx_str(
						cur_mpath, path_buf,
						sizeof(path_buf));
					zlog_debug(
						"%pRN: %s is still multipath, cur count %d",
						bgp_dest_to_rnode(dest),
						path_buf, mpath_count);
				}
			} else {
				mpath_changed = 1;
				if (debug) {
					bgp_path_info_path_with_addpath_rx_str(
						cur_mpath, path_buf,
						sizeof(path_buf));
					zlog_debug(
						"%pRN: remove mpath %s nexthop %pI4, cur count %d",
						bgp_dest_to_rnode(dest),
						path_buf,
						&cur_mpath->attr->nexthop,
						mpath_count);
				}
			}
			mp_node = mp_next_node;
			cur_mpath = next_mpath;
			continue;
		}

		if (cur_mpath
		    && (!mp_node
			|| (bgp_path_info_mpath_cmp(cur_mpath,
						    listgetdata(mp_node))
			    < 0))) {
			/*
			 * If here, we have an old multipath and either the
			 * mp_list
			 * is finished or the next mp_node points to a later
			 * multipath, so we need to purge this path from the
			 * multipath list
			 */
			bgp_path_info_mpath_dequeue(cur_mpath);
			mpath_changed = 1;
			if (debug) {
				bgp_path_info_path_with_addpath_rx_str(
					cur_mpath, path_buf, sizeof(path_buf));
				zlog_debug(
					"%pRN: remove mpath %s nexthop %pI4, cur count %d",
					bgp_dest_to_rnode(dest), path_buf,
					&cur_mpath->attr->nexthop, mpath_count);
			}
			cur_mpath = next_mpath;
		} else {
			/*
			 * If here, we have a path on the mp_list that was not
			 * previously
			 * a multipath (due to non-equivalance or maxpaths
			 * exceeded),
			 * or the matching multipath is sorted later in the
			 * multipath
			 * list. Before we enqueue the path on the new multipath
			 * list,
			 * make sure its not on the old_best multipath list or
			 * referenced
			 * via next_mpath:
			 * - If next_mpath points to this new path, update
			 * next_mpath to
			 *   point to the multipath after this one
			 * - Dequeue the path from the multipath list just to
			 * make sure
			 */
			new_mpath = listgetdata(mp_node);
			list_delete_node(mp_list, mp_node);
			assert(new_mpath);
			assert(prev_mpath);
			if ((mpath_count < maxpaths) && (new_mpath != new_best)
			    && bgp_path_info_nexthop_cmp(prev_mpath,
							 new_mpath)) {
				bgp_path_info_mpath_dequeue(new_mpath);

				bgp_path_info_mpath_enqueue(prev_mpath,
							    new_mpath);
				prev_mpath = new_mpath;
				mpath_changed = 1;
				mpath_count++;
				if (ecommunity_linkbw_present(
					    bgp_attr_get_ecommunity(
						    new_mpath->attr),
					    &bwval))
					cum_bw += bwval;
				else
					all_paths_lb = false;
				if (debug) {
					bgp_path_info_path_with_addpath_rx_str(
						new_mpath, path_buf,
						sizeof(path_buf));
					zlog_debug(
						"%pRN: add mpath %s nexthop %pI4, cur count %d",
						bgp_dest_to_rnode(dest),
						path_buf,
						&new_mpath->attr->nexthop,
						mpath_count);
				}
			}
			mp_node = mp_next_node;
		}
	}

	if (new_best) {
		bgp_path_info_mpath_count_set(new_best, mpath_count - 1);
		if (mpath_count <= 1 ||
		    !ecommunity_linkbw_present(
			    bgp_attr_get_ecommunity(new_best->attr), &bwval))
			all_paths_lb = false;
		else
			cum_bw += bwval;
		bgp_path_info_mpath_lb_update(new_best, true,
					      all_paths_lb, cum_bw);

		if (debug)
			zlog_debug(
				"%pRN(%s): New mpath count (incl newbest) %d mpath-change %s all_paths_lb %d cum_bw %" PRIu64,
				bgp_dest_to_rnode(dest), bgp->name_pretty,
				mpath_count, mpath_changed ? "YES" : "NO",
				all_paths_lb, cum_bw);

		if (mpath_changed
		    || (bgp_path_info_mpath_count(new_best) != old_mpath_count))
			SET_FLAG(new_best->flags, BGP_PATH_MULTIPATH_CHG);
		if ((mpath_count - 1) != old_mpath_count ||
		    old_cum_bw != cum_bw)
			SET_FLAG(new_best->flags, BGP_PATH_LINK_BW_CHG);
	}
}

/*
 * bgp_mp_dmed_deselect
 *
 * Clean up multipath information for BGP_PATH_DMED_SELECTED path that
 * is not selected as best path
 */
void bgp_mp_dmed_deselect(struct bgp_path_info *dmed_best)
{
	struct bgp_path_info *mpinfo, *mpnext;

	if (!dmed_best)
		return;

	for (mpinfo = bgp_path_info_mpath_first(dmed_best); mpinfo;
	     mpinfo = mpnext) {
		mpnext = bgp_path_info_mpath_next(mpinfo);
		bgp_path_info_mpath_dequeue(mpinfo);
	}

	bgp_path_info_mpath_count_set(dmed_best, 0);
	UNSET_FLAG(dmed_best->flags, BGP_PATH_MULTIPATH_CHG);
	UNSET_FLAG(dmed_best->flags, BGP_PATH_LINK_BW_CHG);
	assert(bgp_path_info_mpath_first(dmed_best) == NULL);
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

	if (!bgp_path_info_mpath_count(new_best)) {
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
