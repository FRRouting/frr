// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Chirag Shah
 */
#include <zebra.h>
#include "network.h"
#include "zclient.h"
#include "stream.h"
#include "nexthop.h"
#include "if.h"
#include "hash.h"
#include "jhash.h"

#include "lib/printfrr.h"

#include "pimd.h"
#include "pimd/pim_nht.h"
#include "pim_instance.h"
#include "log.h"
#include "pim_time.h"
#include "pim_oil.h"
#include "pim_ifchannel.h"
#include "pim_mroute.h"
#include "pim_zebra.h"
#include "pim_upstream.h"
#include "pim_join.h"
#include "pim_jp_agg.h"
#include "pim_zebra.h"
#include "pim_zlookup.h"
#include "pim_rp.h"
#include "pim_addr.h"
#include "pim_register.h"
#include "pim_vxlan.h"

/**
 * pim_sendmsg_zebra_rnh -- Format and send a nexthop register/Unregister
 *   command to Zebra.
 */
void pim_sendmsg_zebra_rnh(struct pim_instance *pim, struct zclient *zclient,
			   struct pim_nexthop_cache *pnc, int command)
{
	struct prefix p;
	int ret;

	pim_addr_to_prefix(&p, pnc->rpf.rpf_addr);
	ret = zclient_send_rnh(zclient, command, &p, SAFI_UNICAST, false, false,
			       pim->vrf->vrf_id);
	if (ret == ZCLIENT_SEND_FAILURE)
		zlog_warn("sendmsg_nexthop: zclient_send_message() failed");

	if (PIM_DEBUG_PIM_NHT)
		zlog_debug(
			"%s: NHT %sregistered addr %pFX(%s) with Zebra ret:%d ",
			__func__,
			(command == ZEBRA_NEXTHOP_REGISTER) ? " " : "de", &p,
			pim->vrf->name, ret);

	return;
}

struct pim_nexthop_cache *pim_nexthop_cache_find(struct pim_instance *pim,
						 struct pim_rpf *rpf)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;

	lookup.rpf.rpf_addr = rpf->rpf_addr;
	pnc = hash_lookup(pim->rpf_hash, &lookup);

	return pnc;
}

static struct pim_nexthop_cache *pim_nexthop_cache_add(struct pim_instance *pim,
						       struct pim_rpf *rpf_addr)
{
	struct pim_nexthop_cache *pnc;
	char hash_name[64];

	pnc = XCALLOC(MTYPE_PIM_NEXTHOP_CACHE,
		      sizeof(struct pim_nexthop_cache));
	pnc->rpf.rpf_addr = rpf_addr->rpf_addr;

	pnc = hash_get(pim->rpf_hash, pnc, hash_alloc_intern);

	pnc->rp_list = list_new();
	pnc->rp_list->cmp = pim_rp_list_cmp;

	snprintfrr(hash_name, sizeof(hash_name), "PNC %pPA(%s) Upstream Hash",
		   &pnc->rpf.rpf_addr, pim->vrf->name);
	pnc->upstream_hash = hash_create_size(8192, pim_upstream_hash_key,
					      pim_upstream_equal, hash_name);

	return pnc;
}

static struct pim_nexthop_cache *pim_nht_get(struct pim_instance *pim,
					     pim_addr addr)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_rpf rpf;
	struct zclient *zclient = NULL;

	zclient = pim_zebra_zclient_get();
	memset(&rpf, 0, sizeof(rpf));
	rpf.rpf_addr = addr;

	pnc = pim_nexthop_cache_find(pim, &rpf);
	if (!pnc) {
		pnc = pim_nexthop_cache_add(pim, &rpf);
		pim_sendmsg_zebra_rnh(pim, zclient, pnc,
				      ZEBRA_NEXTHOP_REGISTER);
		if (PIM_DEBUG_PIM_NHT_DETAIL)
			zlog_debug(
				"%s: NHT cache and zebra notification added for %pPA(%s)",
				__func__, &addr, pim->vrf->name);
	}

	return pnc;
}

/* TBD: this does several distinct things and should probably be split up.
 * (checking state vs. returning pnc vs. adding upstream vs. adding rp)
 */
int pim_find_or_track_nexthop(struct pim_instance *pim, pim_addr addr,
			      struct pim_upstream *up, struct rp_info *rp,
			      struct pim_nexthop_cache *out_pnc)
{
	struct pim_nexthop_cache *pnc;
	struct listnode *ch_node = NULL;

	pnc = pim_nht_get(pim, addr);

	assertf(up || rp, "addr=%pPA", &addr);

	if (rp != NULL) {
		ch_node = listnode_lookup(pnc->rp_list, rp);
		if (ch_node == NULL)
			listnode_add_sort(pnc->rp_list, rp);
	}

	if (up != NULL)
		(void)hash_get(pnc->upstream_hash, up, hash_alloc_intern);

	if (CHECK_FLAG(pnc->flags, PIM_NEXTHOP_VALID)) {
		if (out_pnc)
			memcpy(out_pnc, pnc, sizeof(struct pim_nexthop_cache));
		return 1;
	}

	return 0;
}

void pim_nht_bsr_add(struct pim_instance *pim, pim_addr addr)
{
	struct pim_nexthop_cache *pnc;

	pnc = pim_nht_get(pim, addr);

	pnc->bsr_count++;
}

bool pim_nht_candrp_add(struct pim_instance *pim, pim_addr addr)
{
	struct pim_nexthop_cache *pnc;

	pnc = pim_nht_get(pim, addr);

	pnc->candrp_count++;
	return CHECK_FLAG(pnc->flags, PIM_NEXTHOP_VALID);
}

static void pim_nht_drop_maybe(struct pim_instance *pim,
			       struct pim_nexthop_cache *pnc)
{
	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("%s: NHT %pPA(%s) rp_list count:%d upstream count:%ld BSR count:%u Cand-RP count:%u",
			   __func__, &pnc->rpf.rpf_addr, pim->vrf->name,
			   pnc->rp_list->count, pnc->upstream_hash->count,
			   pnc->bsr_count, pnc->candrp_count);

	if (pnc->rp_list->count == 0 && pnc->upstream_hash->count == 0 &&
	    pnc->bsr_count == 0 && pnc->candrp_count == 0) {
		struct zclient *zclient = pim_zebra_zclient_get();

		pim_sendmsg_zebra_rnh(pim, zclient, pnc,
				      ZEBRA_NEXTHOP_UNREGISTER);

		list_delete(&pnc->rp_list);
		hash_free(pnc->upstream_hash);

		hash_release(pim->rpf_hash, pnc);
		if (pnc->nexthop)
			nexthops_free(pnc->nexthop);
		XFREE(MTYPE_PIM_NEXTHOP_CACHE, pnc);
	}
}

void pim_delete_tracked_nexthop(struct pim_instance *pim, pim_addr addr,
				struct pim_upstream *up, struct rp_info *rp)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;
	struct pim_upstream *upstream = NULL;

	/* Remove from RPF hash if it is the last entry */
	lookup.rpf.rpf_addr = addr;
	pnc = hash_lookup(pim->rpf_hash, &lookup);
	if (!pnc) {
		zlog_warn("attempting to delete nonexistent NHT entry %pPA",
			  &addr);
		return;
	}

	if (rp) {
		/* Release the (*, G)upstream from pnc->upstream_hash,
		 * whose Group belongs to the RP getting deleted
		 */
		frr_each (rb_pim_upstream, &pim->upstream_head, upstream) {
			struct prefix grp;
			struct rp_info *trp_info;

			if (!pim_addr_is_any(upstream->sg.src))
				continue;

			pim_addr_to_prefix(&grp, upstream->sg.grp);
			trp_info = pim_rp_find_match_group(pim, &grp);
			if (trp_info == rp)
				hash_release(pnc->upstream_hash, upstream);
		}
		listnode_delete(pnc->rp_list, rp);
	}

	if (up)
		hash_release(pnc->upstream_hash, up);

	pim_nht_drop_maybe(pim, pnc);
}

void pim_nht_bsr_del(struct pim_instance *pim, pim_addr addr)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;

	/*
	 * Nothing to do here if the address to unregister
	 * is 0.0.0.0 as that the BSR has not been registered
	 * for tracking yet.
	 */
	if (pim_addr_is_any(addr))
		return;

	lookup.rpf.rpf_addr = addr;

	pnc = hash_lookup(pim->rpf_hash, &lookup);

	if (!pnc) {
		zlog_warn("attempting to delete nonexistent NHT BSR entry %pPA",
			  &addr);
		return;
	}

	assertf(pnc->bsr_count > 0, "addr=%pPA", &addr);
	pnc->bsr_count--;

	pim_nht_drop_maybe(pim, pnc);
}

void pim_nht_candrp_del(struct pim_instance *pim, pim_addr addr)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;

	lookup.rpf.rpf_addr = addr;

	pnc = hash_lookup(pim->rpf_hash, &lookup);

	if (!pnc) {
		zlog_warn("attempting to delete nonexistent NHT C-RP entry %pPA",
			  &addr);
		return;
	}

	assertf(pnc->candrp_count > 0, "addr=%pPA", &addr);
	pnc->candrp_count--;

	pim_nht_drop_maybe(pim, pnc);
}

bool pim_nht_bsr_rpf_check(struct pim_instance *pim, pim_addr bsr_addr,
			   struct interface *src_ifp, pim_addr src_ip)
{
	struct pim_nexthop_cache *pnc = NULL;
	struct pim_nexthop_cache lookup;
	struct pim_neighbor *nbr = NULL;
	struct nexthop *nh;
	struct interface *ifp;

	lookup.rpf.rpf_addr = bsr_addr;

	pnc = hash_lookup(pim->rpf_hash, &lookup);
	if (!pnc || !CHECK_FLAG(pnc->flags, PIM_NEXTHOP_ANSWER_RECEIVED)) {
		/* BSM from a new freshly registered BSR - do a synchronous
		 * zebra query since otherwise we'd drop the first packet,
		 * leading to additional delay in picking up BSM data
		 */

		/* FIXME: this should really be moved into a generic NHT
		 * function that does "add and get immediate result" or maybe
		 * "check cache or get immediate result." But until that can
		 * be worked in, here's a copy of the code below :(
		 */
		struct pim_zlookup_nexthop nexthop_tab[router->multipath];
		ifindex_t i;
		struct interface *ifp = NULL;
		int num_ifindex;

		memset(nexthop_tab, 0, sizeof(nexthop_tab));
		num_ifindex = zclient_lookup_nexthop(
			pim, nexthop_tab, router->multipath, bsr_addr,
			PIM_NEXTHOP_LOOKUP_MAX);

		if (num_ifindex <= 0)
			return false;

		for (i = 0; i < num_ifindex; i++) {
			struct pim_zlookup_nexthop *znh = &nexthop_tab[i];

			/* pim_zlookup_nexthop has no ->type */

			/* 1:1 match code below with znh instead of nh */
			ifp = if_lookup_by_index(znh->ifindex,
						 pim->vrf->vrf_id);

			if (!ifp || !ifp->info)
				continue;

			if (if_is_loopback(ifp) && if_is_loopback(src_ifp))
				return true;

			nbr = pim_neighbor_find(ifp, znh->nexthop_addr, true);
			if (!nbr)
				continue;
			/* Are we on the correct interface? */
			if (znh->ifindex == src_ifp->ifindex) {
				/* Do we have the correct NH ? */
				if (!pim_addr_cmp(znh->nexthop_addr, src_ip))
					return true;
				/*
				 * check If the packet came from the neighbor,
				 * and the dst is a secondary address on the connected interface
				 */
				return (!pim_addr_cmp(nbr->source_addr, src_ip) &&
					pim_if_connected_to_source(ifp, znh->nexthop_addr));
			}
			return false;
		}
		return false;
	}

	if (!CHECK_FLAG(pnc->flags, PIM_NEXTHOP_VALID))
		return false;

	/* if we accept BSMs from more than one ECMP nexthop, this will cause
	 * BSM message "multiplication" for each ECMP hop.  i.e. if you have
	 * 4-way ECMP and 4 hops you end up with 256 copies of each BSM
	 * message.
	 *
	 * so...  only accept the first (IPv4) valid nexthop as source.
	 */

	for (nh = pnc->nexthop; nh; nh = nh->next) {
		pim_addr nhaddr;

		switch (nh->type) {
#if PIM_IPV == 4
		case NEXTHOP_TYPE_IPV4:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;

			fallthrough;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			nhaddr = nh->gate.ipv4;
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			continue;
#else
		case NEXTHOP_TYPE_IPV6:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;

			fallthrough;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			nhaddr = nh->gate.ipv6;
			break;
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			continue;
#endif
		case NEXTHOP_TYPE_IFINDEX:
			nhaddr = bsr_addr;
			break;

		case NEXTHOP_TYPE_BLACKHOLE:
			continue;
		}

		ifp = if_lookup_by_index(nh->ifindex, pim->vrf->vrf_id);
		if (!ifp || !ifp->info)
			continue;

		if (if_is_loopback(ifp) && if_is_loopback(src_ifp))
			return true;

		/* MRIB (IGP) may be pointing at a router where PIM is down */
		nbr = pim_neighbor_find(ifp, nhaddr, true);
		if (!nbr)
			continue;

		/* Are we on the correct interface? */
		if (nh->ifindex == src_ifp->ifindex) {
			/* Do we have the correct NH ? */
			if (!pim_addr_cmp(nhaddr, src_ip))
				return true;
			/*
			 * check If the packet came from the neighbor,
			 * and the dst is a secondary address on the connected interface
			 */
			return (!pim_addr_cmp(nbr->source_addr, src_ip) &&
				pim_if_connected_to_source(ifp, nhaddr));
		}
		return false;
	}
	return false;
}

void pim_rp_nexthop_del(struct rp_info *rp_info)
{
	rp_info->rp.source_nexthop.interface = NULL;
	rp_info->rp.source_nexthop.mrib_nexthop_addr = PIMADDR_ANY;
	rp_info->rp.source_nexthop.mrib_metric_preference =
		router->infinite_assert_metric.metric_preference;
	rp_info->rp.source_nexthop.mrib_route_metric =
		router->infinite_assert_metric.route_metric;
}

/* Update RP nexthop info based on Nexthop update received from Zebra.*/
static void pim_update_rp_nh(struct pim_instance *pim,
			     struct pim_nexthop_cache *pnc)
{
	struct listnode *node = NULL;
	struct rp_info *rp_info = NULL;
	struct interface *ifp;

	/*Traverse RP list and update each RP Nexthop info */
	for (ALL_LIST_ELEMENTS_RO(pnc->rp_list, node, rp_info)) {
		if (pim_rpf_addr_is_inaddr_any(&rp_info->rp))
			continue;

		ifp = rp_info->rp.source_nexthop.interface;
		// Compute PIM RPF using cached nexthop
		if (!pim_ecmp_nexthop_lookup(pim, &rp_info->rp.source_nexthop,
					     rp_info->rp.rpf_addr,
					     &rp_info->group, 1))
			pim_rp_nexthop_del(rp_info);

		/*
		 * If we transition from no path to a path
		 * we need to search through all the vxlan's
		 * that use this rp and send NULL registers
		 * for all the vxlan S,G streams
		 */
		if (!ifp && rp_info->rp.source_nexthop.interface)
			pim_vxlan_rp_info_is_alive(pim, &rp_info->rp);
	}
}

/* Update Upstream nexthop info based on Nexthop update received from Zebra.*/
static int pim_update_upstream_nh_helper(struct hash_bucket *bucket, void *arg)
{
	struct pim_instance *pim = (struct pim_instance *)arg;
	struct pim_upstream *up = (struct pim_upstream *)bucket->data;

	enum pim_rpf_result rpf_result;
	struct pim_rpf old;

	old.source_nexthop.interface = up->rpf.source_nexthop.interface;
	rpf_result = pim_rpf_update(pim, up, &old, __func__);

	/* update kernel multicast forwarding cache (MFC); if the
	 * RPF nbr is now unreachable the MFC has already been updated
	 * by pim_rpf_clear
	 */
	if (rpf_result == PIM_RPF_CHANGED)
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);

	if (rpf_result == PIM_RPF_CHANGED ||
		(rpf_result == PIM_RPF_FAILURE && old.source_nexthop.interface))
		pim_zebra_upstream_rpf_changed(pim, up, &old);

	/*
	 * If we are a VXLAN source and we are transitioning from not
	 * having an outgoing interface to having an outgoing interface
	 * let's immediately send the null pim register
	 */
	if (!old.source_nexthop.interface && up->rpf.source_nexthop.interface &&
	    PIM_UPSTREAM_FLAG_TEST_SRC_VXLAN_ORIG(up->flags) &&
	    (up->reg_state == PIM_REG_NOINFO || up->reg_state == PIM_REG_JOIN)) {
		pim_null_register_send(up);
	}

	if (PIM_DEBUG_PIM_NHT) {
		zlog_debug("%s: NHT upstream %s(%s) old ifp %s new ifp %s rpf_result: %d",
			   __func__, up->sg_str, pim->vrf->name,
			   old.source_nexthop.interface ? old.source_nexthop
								  .interface->name
							: "Unknown",
			   up->rpf.source_nexthop.interface ? up->rpf.source_nexthop
								      .interface->name
							    : "Unknown",
			   rpf_result);
	}

	return HASHWALK_CONTINUE;
}

static int pim_update_upstream_nh(struct pim_instance *pim,
				  struct pim_nexthop_cache *pnc)
{
	hash_walk(pnc->upstream_hash, pim_update_upstream_nh_helper, pim);

	pim_zebra_update_all_interfaces(pim);

	return 0;
}

static int pim_upstream_nh_if_update_helper(struct hash_bucket *bucket,
					    void *arg)
{
	struct pim_nexthop_cache *pnc = bucket->data;
	struct pnc_hash_walk_data *pwd = arg;
	struct pim_instance *pim = pwd->pim;
	struct interface *ifp = pwd->ifp;
	struct nexthop *nh_node = NULL;
	ifindex_t first_ifindex;

	for (nh_node = pnc->nexthop; nh_node; nh_node = nh_node->next) {
		first_ifindex = nh_node->ifindex;
		if (ifp != if_lookup_by_index(first_ifindex, pim->vrf->vrf_id))
			continue;

		if (pnc->upstream_hash->count) {
			pim_update_upstream_nh(pim, pnc);
			break;
		}
	}

	return HASHWALK_CONTINUE;
}

void pim_upstream_nh_if_update(struct pim_instance *pim, struct interface *ifp)
{
	struct pnc_hash_walk_data pwd;

	pwd.pim = pim;
	pwd.ifp = ifp;

	hash_walk(pim->rpf_hash, pim_upstream_nh_if_update_helper, &pwd);
}

uint32_t pim_compute_ecmp_hash(struct prefix *src, struct prefix *grp)
{
	uint32_t hash_val;

	if (!src)
		return 0;

	hash_val = prefix_hash_key(src);
	if (grp)
		hash_val ^= prefix_hash_key(grp);
	return hash_val;
}

static int pim_ecmp_nexthop_search(struct pim_instance *pim,
				   struct pim_nexthop_cache *pnc,
				   struct pim_nexthop *nexthop, pim_addr src,
				   struct prefix *grp, int neighbor_needed)
{
	struct pim_neighbor *nbrs[router->multipath], *nbr = NULL;
	struct interface *ifps[router->multipath];
	struct nexthop *nh_node = NULL;
	ifindex_t first_ifindex;
	struct interface *ifp = NULL;
	uint32_t hash_val = 0, mod_val = 0;
	uint16_t nh_iter = 0, found = 0;
	uint32_t i, num_nbrs = 0;
	struct pim_interface *pim_ifp;

	if (!pnc || !pnc->nexthop_num || !nexthop)
		return 0;

	pim_addr nh_addr = nexthop->mrib_nexthop_addr;
	pim_addr grp_addr = pim_addr_from_prefix(grp);

	memset(&nbrs, 0, sizeof(nbrs));
	memset(&ifps, 0, sizeof(ifps));


	// Current Nexthop is VALID, check to stay on the current path.
	if (nexthop->interface && nexthop->interface->info &&
	    (!pim_addr_is_any(nh_addr))) {
		/* User configured knob to explicitly switch
		   to new path is disabled or current path
		   metric is less than nexthop update.
		 */

		if (pim->ecmp_rebalance_enable == 0) {
			uint8_t curr_route_valid = 0;
			// Check if current nexthop is present in new updated
			// Nexthop list.
			// If the current nexthop is not valid, candidate to
			// choose new Nexthop.
			for (nh_node = pnc->nexthop; nh_node;
			     nh_node = nh_node->next) {
				curr_route_valid = (nexthop->interface->ifindex
						    == nh_node->ifindex);
				if (curr_route_valid)
					break;
			}

			if (curr_route_valid &&
			    !pim_if_connected_to_source(nexthop->interface,
							src)) {
				nbr = pim_neighbor_find(
					nexthop->interface,
					nexthop->mrib_nexthop_addr, true);
				if (!nbr
				    && !if_is_loopback(nexthop->interface)) {
					if (PIM_DEBUG_PIM_NHT)
						zlog_debug(
							"%s: current nexthop does not have nbr ",
							__func__);
				} else {
					/* update metric even if the upstream
					 * neighbor stays unchanged
					 */
					nexthop->mrib_metric_preference =
						pnc->distance;
					nexthop->mrib_route_metric =
						pnc->metric;
					if (PIM_DEBUG_PIM_NHT)
						zlog_debug(
							"%s: (%pPA,%pPA)(%s) current nexthop %s is valid, skipping new path selection",
							__func__, &src,
							&grp_addr,
							pim->vrf->name,
							nexthop->interface->name);
					return 1;
				}
			}
		}
	}

	/*
	 * Look up all interfaces and neighbors,
	 * store for later usage
	 */
	for (nh_node = pnc->nexthop, i = 0; nh_node;
	     nh_node = nh_node->next, i++) {
		ifps[i] =
			if_lookup_by_index(nh_node->ifindex, pim->vrf->vrf_id);
		if (ifps[i]) {
#if PIM_IPV == 4
			pim_addr nhaddr = nh_node->gate.ipv4;
#else
			pim_addr nhaddr = nh_node->gate.ipv6;
#endif
			nbrs[i] = pim_neighbor_find(ifps[i], nhaddr, true);
			if (nbrs[i] || pim_if_connected_to_source(ifps[i], src))
				num_nbrs++;
		}
	}
	if (pim->ecmp_enable) {
		struct prefix src_pfx;
		uint32_t consider = pnc->nexthop_num;

		if (neighbor_needed && num_nbrs < consider)
			consider = num_nbrs;

		if (consider == 0)
			return 0;

		// PIM ECMP flag is enable then choose ECMP path.
		pim_addr_to_prefix(&src_pfx, src);
		hash_val = pim_compute_ecmp_hash(&src_pfx, grp);
		mod_val = hash_val % consider;
	}

	for (nh_node = pnc->nexthop; nh_node && (found == 0);
	     nh_node = nh_node->next) {
		first_ifindex = nh_node->ifindex;
		ifp = ifps[nh_iter];
		if (!ifp) {
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug(
					"%s %s: could not find interface for ifindex %d (address %pPA(%s))",
					__FILE__, __func__, first_ifindex, &src,
					pim->vrf->name);
			if (nh_iter == mod_val)
				mod_val++; // Select nexthpath
			nh_iter++;
			continue;
		}

		pim_ifp = ifp->info;

		if (!pim_ifp || !pim_ifp->pim_enable) {
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug(
					"%s: pim not enabled on input interface %s(%s) (ifindex=%d, RPF for source %pPA)",
					__func__, ifp->name, pim->vrf->name,
					first_ifindex, &src);
			if (nh_iter == mod_val)
				mod_val++; // Select nexthpath
			nh_iter++;
			continue;
		}

		if (neighbor_needed && !pim_if_connected_to_source(ifp, src)) {
			nbr = nbrs[nh_iter];
			if (!nbr && !if_is_loopback(ifp)) {
				if (PIM_DEBUG_PIM_NHT)
					zlog_debug(
						"%s: pim nbr not found on input interface %s(%s)",
						__func__, ifp->name,
						pim->vrf->name);
				if (nh_iter == mod_val)
					mod_val++; // Select nexthpath
				nh_iter++;
				continue;
			}
		}

		if (nh_iter == mod_val) {
			nexthop->interface = ifp;
#if PIM_IPV == 4
			nexthop->mrib_nexthop_addr = nh_node->gate.ipv4;
#else
			nexthop->mrib_nexthop_addr = nh_node->gate.ipv6;
#endif
			nexthop->mrib_metric_preference = pnc->distance;
			nexthop->mrib_route_metric = pnc->metric;
			nexthop->last_lookup = src;
			nexthop->last_lookup_time = pim_time_monotonic_usec();
			nexthop->nbr = nbr;
			found = 1;
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug(
					"%s: (%pPA,%pPA)(%s) selected nhop interface %s addr %pPAs mod_val %u iter %d ecmp %d",
					__func__, &src, &grp_addr,
					pim->vrf->name, ifp->name, &nh_addr,
					mod_val, nh_iter, pim->ecmp_enable);
		}
		nh_iter++;
	}

	if (found)
		return 1;
	else
		return 0;
}

/* This API is used to parse Registered address nexthop update coming from Zebra
 */
void pim_nexthop_update(struct vrf *vrf, struct prefix *match,
			struct zapi_route *nhr)
{
	struct nexthop *nexthop;
	struct nexthop *nhlist_head = NULL;
	struct nexthop *nhlist_tail = NULL;
	int i;
	struct pim_rpf rpf;
	struct pim_nexthop_cache *pnc = NULL;
	struct interface *ifp = NULL;
	struct pim_instance *pim;

	pim = vrf->info;

	rpf.rpf_addr = pim_addr_from_prefix(match);
	pnc = pim_nexthop_cache_find(pim, &rpf);
	if (!pnc) {
		if (PIM_DEBUG_PIM_NHT)
			zlog_debug(
				"%s: Skipping NHT update, addr %pPA is not in local cached DB.",
				__func__, &rpf.rpf_addr);
		return;
	}

	pnc->last_update = pim_time_monotonic_usec();

	if (nhr->nexthop_num) {
		pnc->nexthop_num = 0;

		for (i = 0; i < nhr->nexthop_num; i++) {
			nexthop = nexthop_from_zapi_nexthop(&nhr->nexthops[i]);
			switch (nexthop->type) {
			case NEXTHOP_TYPE_IFINDEX:
				/*
				 * Connected route (i.e. no nexthop), use
				 * RPF address from nexthop cache (i.e.
				 * destination) as PIM nexthop.
				 */
#if PIM_IPV == 4
				nexthop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
				nexthop->gate.ipv4 = pnc->rpf.rpf_addr;
#else
				nexthop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
				nexthop->gate.ipv6 = pnc->rpf.rpf_addr;
#endif
				break;
#if PIM_IPV == 4
			/* RFC5549 IPv4-over-IPv6 nexthop handling:
			 * if we get an IPv6 nexthop in IPv4 PIM, hunt down a
			 * PIM neighbor and use that instead.
			 */
			case NEXTHOP_TYPE_IPV6_IFINDEX: {
				struct interface *ifp1 = NULL;
				struct pim_neighbor *nbr = NULL;

				ifp1 = if_lookup_by_index(nexthop->ifindex,
							  pim->vrf->vrf_id);

				if (!ifp1)
					nbr = NULL;
				else
					/* FIXME: should really use nbr's
					 * secondary address list here
					 */
					nbr = pim_neighbor_find_if(ifp1);

				/* Overwrite with Nbr address as NH addr */
				if (nbr)
					nexthop->gate.ipv4 = nbr->source_addr;
				else
					// Mark nexthop address to 0 until PIM
					// Nbr is resolved.
					nexthop->gate.ipv4 = PIMADDR_ANY;

				break;
			}
#else
			case NEXTHOP_TYPE_IPV6_IFINDEX:
#endif
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
			case NEXTHOP_TYPE_BLACKHOLE:
				/* nothing to do for the other nexthop types */
				break;
			}

			ifp = if_lookup_by_index(nexthop->ifindex,
						 pim->vrf->vrf_id);
			if (!ifp) {
				if (PIM_DEBUG_PIM_NHT) {
					char buf[NEXTHOP_STRLEN];
					zlog_debug(
						"%s: could not find interface for ifindex %d(%s) (addr %s)",
						__func__, nexthop->ifindex,
						pim->vrf->name,
						nexthop2str(nexthop, buf,
							    sizeof(buf)));
				}
				nexthop_free(nexthop);
				continue;
			}

			if (PIM_DEBUG_PIM_NHT) {
#if PIM_IPV == 4
				pim_addr nhaddr = nexthop->gate.ipv4;
#else
				pim_addr nhaddr = nexthop->gate.ipv6;
#endif
				zlog_debug("%s: NHT addr %pFX(%s) %d-nhop via %pPA(%s) type %d distance:%u metric:%u ",
					   __func__, match, pim->vrf->name,
					   i + 1, &nhaddr, ifp->name,
					   nexthop->type, nhr->distance,
					   nhr->metric);
			}

			if (!ifp->info) {
				/*
				 * Though Multicast is not enabled on this
				 * Interface store it in database otheriwse we
				 * may miss this update and this will not cause
				 * any issue, because while choosing the path we
				 * are ommitting the Interfaces which are not
				 * multicast enabled
				 */
				if (PIM_DEBUG_PIM_NHT) {
					char buf[NEXTHOP_STRLEN];

					zlog_debug(
						"%s: multicast not enabled on input interface %s(%s) (ifindex=%d, addr %s)",
						__func__, ifp->name,
						pim->vrf->name,
						nexthop->ifindex,
						nexthop2str(nexthop, buf,
							    sizeof(buf)));
				}
			}

			if (nhlist_tail) {
				nhlist_tail->next = nexthop;
				nhlist_tail = nexthop;
			} else {
				nhlist_tail = nexthop;
				nhlist_head = nexthop;
			}

			// Keep track of all nexthops, even PIM-disabled ones.
			pnc->nexthop_num++;
		}
		/* Reset existing pnc->nexthop before assigning new list */
		nexthops_free(pnc->nexthop);
		pnc->nexthop = nhlist_head;
		if (pnc->nexthop_num) {
			pnc->flags |= PIM_NEXTHOP_VALID;
			pnc->distance = nhr->distance;
			pnc->metric = nhr->metric;
		}
	} else {
		pnc->flags &= ~PIM_NEXTHOP_VALID;
		pnc->nexthop_num = nhr->nexthop_num;
		nexthops_free(pnc->nexthop);
		pnc->nexthop = NULL;
	}
	SET_FLAG(pnc->flags, PIM_NEXTHOP_ANSWER_RECEIVED);

	if (PIM_DEBUG_PIM_NHT)
		zlog_debug("%s: NHT Update for %pFX(%s) num_nh %d num_pim_nh %d vrf:%u up %ld rp %d",
			   __func__, match, pim->vrf->name, nhr->nexthop_num,
			   pnc->nexthop_num, vrf->vrf_id,
			   pnc->upstream_hash->count, listcount(pnc->rp_list));

	pim_rpf_set_refresh_time(pim);

	if (listcount(pnc->rp_list))
		pim_update_rp_nh(pim, pnc);
	if (pnc->upstream_hash->count)
		pim_update_upstream_nh(pim, pnc);

	if (pnc->candrp_count)
		pim_crp_nht_update(pim, pnc);
}

int pim_ecmp_nexthop_lookup(struct pim_instance *pim,
			    struct pim_nexthop *nexthop, pim_addr src,
			    struct prefix *grp, int neighbor_needed)
{
	struct pim_nexthop_cache *pnc;
	struct pim_zlookup_nexthop nexthop_tab[router->multipath];
	struct pim_neighbor *nbrs[router->multipath], *nbr = NULL;
	struct pim_rpf rpf;
	int num_ifindex;
	struct interface *ifps[router->multipath], *ifp;
	int first_ifindex;
	int found = 0;
	uint16_t i = 0;
	uint32_t hash_val = 0, mod_val = 0;
	uint32_t num_nbrs = 0;
	struct pim_interface *pim_ifp;

	if (PIM_DEBUG_PIM_NHT_DETAIL)
		zlog_debug("%s: Looking up: %pPA(%s), last lookup time: %lld",
			   __func__, &src, pim->vrf->name,
			   nexthop->last_lookup_time);

	rpf.rpf_addr = src;

	pnc = pim_nexthop_cache_find(pim, &rpf);
	if (pnc) {
		if (CHECK_FLAG(pnc->flags, PIM_NEXTHOP_ANSWER_RECEIVED))
		    return pim_ecmp_nexthop_search(pim, pnc, nexthop, src, grp,
						   neighbor_needed);
	}

	memset(nexthop_tab, 0,
	       sizeof(struct pim_zlookup_nexthop) * router->multipath);
	num_ifindex =
		zclient_lookup_nexthop(pim, nexthop_tab, router->multipath, src,
				       PIM_NEXTHOP_LOOKUP_MAX);
	if (num_ifindex < 1) {
		if (PIM_DEBUG_PIM_NHT)
			zlog_warn(
				"%s: could not find nexthop ifindex for address %pPA(%s)",
				__func__, &src, pim->vrf->name);
		return 0;
	}

	memset(&nbrs, 0, sizeof(nbrs));
	memset(&ifps, 0, sizeof(ifps));

	/*
	 * Look up all interfaces and neighbors,
	 * store for later usage
	 */
	for (i = 0; i < num_ifindex; i++) {
		ifps[i] = if_lookup_by_index(nexthop_tab[i].ifindex,
					     pim->vrf->vrf_id);
		if (ifps[i]) {
			nbrs[i] = pim_neighbor_find(
				ifps[i], nexthop_tab[i].nexthop_addr, true);

			if (nbrs[i] || pim_if_connected_to_source(ifps[i], src))
				num_nbrs++;
		}
	}

	// If PIM ECMP enable then choose ECMP path.
	if (pim->ecmp_enable) {
		struct prefix src_pfx;
		uint32_t consider = num_ifindex;

		if (neighbor_needed && num_nbrs < consider)
			consider = num_nbrs;

		if (consider == 0)
			return 0;

		pim_addr_to_prefix(&src_pfx, src);
		hash_val = pim_compute_ecmp_hash(&src_pfx, grp);
		mod_val = hash_val % consider;
		if (PIM_DEBUG_PIM_NHT_DETAIL)
			zlog_debug("%s: hash_val %u mod_val %u", __func__,
				   hash_val, mod_val);
	}

	i = 0;
	while (!found && (i < num_ifindex)) {
		first_ifindex = nexthop_tab[i].ifindex;

		ifp = ifps[i];
		if (!ifp) {
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug(
					"%s %s: could not find interface for ifindex %d (address %pPA(%s))",
					__FILE__, __func__, first_ifindex, &src,
					pim->vrf->name);
			if (i == mod_val)
				mod_val++;
			i++;
			continue;
		}

		pim_ifp = ifp->info;

		if (!pim_ifp || !pim_ifp->pim_enable) {
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug(
					"%s: pim not enabled on input interface %s(%s) (ifindex=%d, RPF for source %pPA)",
					__func__, ifp->name, pim->vrf->name,
					first_ifindex, &src);
			if (i == mod_val)
				mod_val++;
			i++;
			continue;
		}
		if (neighbor_needed && !pim_if_connected_to_source(ifp, src)) {
			nbr = nbrs[i];
			if (PIM_DEBUG_PIM_NHT_DETAIL)
				zlog_debug("ifp name: %s(%s), pim nbr: %p",
					   ifp->name, pim->vrf->name, nbr);
			if (!nbr && !if_is_loopback(ifp)) {
				if (i == mod_val)
					mod_val++;
				if (PIM_DEBUG_PIM_NHT)
					zlog_debug(
						"%s: NBR (%pPA) not found on input interface %s(%s) (RPF for source %pPA)",
						__func__,
						&nexthop_tab[i].nexthop_addr,
						ifp->name, pim->vrf->name,
						&src);
				i++;
				continue;
			}
		}

		if (i == mod_val) {
			if (PIM_DEBUG_PIM_NHT)
				zlog_debug(
					"%s: found nhop %pPA for addr %pPA interface %s(%s) metric %d dist %d",
					__func__, &nexthop_tab[i].nexthop_addr,
					&src, ifp->name, pim->vrf->name,
					nexthop_tab[i].route_metric,
					nexthop_tab[i].protocol_distance);
			/* update nexthop data */
			nexthop->interface = ifp;
			nexthop->mrib_nexthop_addr =
				nexthop_tab[i].nexthop_addr;
			nexthop->mrib_metric_preference =
				nexthop_tab[i].protocol_distance;
			nexthop->mrib_route_metric =
				nexthop_tab[i].route_metric;
			nexthop->last_lookup = src;
			nexthop->last_lookup_time = pim_time_monotonic_usec();
			nexthop->nbr = nbr;
			found = 1;
		}
		i++;
	}

	if (found)
		return 1;
	else
		return 0;
}

int pim_ecmp_fib_lookup_if_vif_index(struct pim_instance *pim, pim_addr src,
				     struct prefix *grp)
{
	struct pim_nexthop nhop;
	int vif_index;
	ifindex_t ifindex;

	memset(&nhop, 0, sizeof(nhop));
	if (!pim_ecmp_nexthop_lookup(pim, &nhop, src, grp, 1)) {
		if (PIM_DEBUG_PIM_NHT)
			zlog_debug(
				"%s: could not find nexthop ifindex for address %pPA(%s)",
				__func__, &src, pim->vrf->name);
		return -1;
	}

	ifindex = nhop.interface->ifindex;
	if (PIM_DEBUG_PIM_NHT)
		zlog_debug(
			"%s: found nexthop ifindex=%d (interface %s(%s)) for address %pPA",
			__func__, ifindex,
			ifindex2ifname(ifindex, pim->vrf->vrf_id),
			pim->vrf->name, &src);

	vif_index = pim_if_find_vifindex_by_ifindex(pim, ifindex);

	if (vif_index < 0) {
		if (PIM_DEBUG_PIM_NHT) {
			zlog_debug(
				"%s: low vif_index=%d(%s) < 1 nexthop for address %pPA",
				__func__, vif_index, pim->vrf->name, &src);
		}
		return -2;
	}

	return vif_index;
}
