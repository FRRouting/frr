// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "if.h"

#include "log.h"
#include "prefix.h"
#include "memory.h"
#include "jhash.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_rpf.h"
#include "pim_pim.h"
#include "pim_str.h"
#include "pim_iface.h"
#include "pim_neighbor.h"
#include "pim_zlookup.h"
#include "pim_ifchannel.h"
#include "pim_time.h"
#include "pim_nht.h"
#include "pim_oil.h"
#include "pim_mlag.h"

static pim_addr pim_rpf_find_rpf_addr(struct pim_upstream *up);

void pim_rpf_set_refresh_time(struct pim_instance *pim)
{
	pim->last_route_change_time = pim_time_monotonic_usec();
	if (PIM_DEBUG_PIM_TRACE_DETAIL)
		zlog_debug("%s: vrf(%s) New last route change time: %" PRId64,
			   __func__, pim->vrf->name,
			   pim->last_route_change_time);
}

bool pim_nexthop_lookup(struct pim_instance *pim, struct pim_nexthop *nexthop,
			pim_addr addr, int neighbor_needed)
{
	struct pim_zlookup_nexthop nexthop_tab[router->multipath];
	struct pim_neighbor *nbr = NULL;
	int num_ifindex;
	struct interface *ifp = NULL;
	ifindex_t first_ifindex = 0;
	int found = 0;
	int i = 0;
	struct pim_interface *pim_ifp;

#if PIM_IPV == 4
	/*
	 * We should not attempt to lookup a
	 * 255.255.255.255 address, since
	 * it will never work
	 */
	if (pim_addr_is_any(addr))
		return false;
#endif

	if ((!pim_addr_cmp(nexthop->last_lookup, addr)) &&
	    (nexthop->last_lookup_time > pim->last_route_change_time)) {
		if (PIM_DEBUG_PIM_NHT)
			zlog_debug(
				"%s: Using last lookup for %pPAs at %lld, %" PRId64
				" addr %pPAs",
				__func__, &addr, nexthop->last_lookup_time,
				pim->last_route_change_time,
				&nexthop->mrib_nexthop_addr);
		pim->nexthop_lookups_avoided++;
		return true;
	} else {
		if (PIM_DEBUG_PIM_NHT)
			zlog_debug(
				"%s: Looking up: %pPAs, last lookup time: %lld, %" PRId64,
				__func__, &addr, nexthop->last_lookup_time,
				pim->last_route_change_time);
	}

	memset(nexthop_tab, 0,
	       sizeof(struct pim_zlookup_nexthop) * router->multipath);
	num_ifindex =
		zclient_lookup_nexthop(pim, nexthop_tab, router->multipath,
				       addr, PIM_NEXTHOP_LOOKUP_MAX);
	if (num_ifindex < 1) {
		if (PIM_DEBUG_PIM_NHT)
			zlog_debug(
				"%s %s: could not find nexthop ifindex for address %pPAs",
				__FILE__, __func__, &addr);
		return false;
	}

	while (!found && (i < num_ifindex)) {
		first_ifindex = nexthop_tab[i].ifindex;

		ifp = if_lookup_by_index(first_ifindex, pim->vrf->vrf_id);
		if (!ifp) {
			if (PIM_DEBUG_ZEBRA)
				zlog_debug(
					"%s %s: could not find interface for ifindex %d (address %pPAs)",
					__FILE__, __func__, first_ifindex,
					&addr);
			i++;
			continue;
		}

		pim_ifp = ifp->info;
		if (!pim_ifp || !pim_ifp->pim_enable) {
			if (PIM_DEBUG_ZEBRA)
				zlog_debug(
					"%s: pim not enabled on input interface %s (ifindex=%d, RPF for source %pPAs)",
					__func__, ifp->name, first_ifindex,
					&addr);
			i++;
		} else if (neighbor_needed &&
			   !pim_if_connected_to_source(ifp, addr)) {
			nbr = pim_neighbor_find(
				ifp, nexthop_tab[i].nexthop_addr, true);
			if (PIM_DEBUG_PIM_TRACE_DETAIL)
				zlog_debug("ifp name: %s, pim nbr: %p",
					   ifp->name, nbr);
			if (!nbr && !if_is_loopback(ifp))
				i++;
			else
				found = 1;
		} else
			found = 1;
	}

	if (found) {
		if (PIM_DEBUG_ZEBRA)
			zlog_debug(
				"%s %s: found nexthop %pPAs for address %pPAs: interface %s ifindex=%d metric=%d pref=%d",
				__FILE__, __func__,
				&nexthop_tab[i].nexthop_addr, &addr, ifp->name,
				first_ifindex, nexthop_tab[i].route_metric,
				nexthop_tab[i].protocol_distance);

		/* update nexthop data */
		nexthop->interface = ifp;
		nexthop->mrib_nexthop_addr = nexthop_tab[i].nexthop_addr;
		nexthop->mrib_metric_preference =
			nexthop_tab[i].protocol_distance;
		nexthop->mrib_route_metric = nexthop_tab[i].route_metric;
		nexthop->last_lookup = addr;
		nexthop->last_lookup_time = pim_time_monotonic_usec();
		nexthop->nbr = nbr;
		return true;
	} else
		return false;
}

static int nexthop_mismatch(const struct pim_nexthop *nh1,
			    const struct pim_nexthop *nh2)
{
	return (nh1->interface != nh2->interface) ||
	       (pim_addr_cmp(nh1->mrib_nexthop_addr, nh2->mrib_nexthop_addr)) ||
	       (nh1->mrib_metric_preference != nh2->mrib_metric_preference) ||
	       (nh1->mrib_route_metric != nh2->mrib_route_metric);
}

static void pim_rpf_cost_change(struct pim_instance *pim,
		struct pim_upstream *up, uint32_t old_cost)
{
	struct pim_rpf *rpf = &up->rpf;
	uint32_t new_cost;

	new_cost = pim_up_mlag_local_cost(up);
	if (PIM_DEBUG_MLAG)
		zlog_debug(
			"%s: Cost_to_rp of upstream-%s changed to:%u, from:%u",
			__func__, up->sg_str, new_cost, old_cost);

	if (old_cost == new_cost)
		return;

	/* Cost changed, it might Impact MLAG DF election, update */
	if (PIM_DEBUG_MLAG)
		zlog_debug(
			"%s: Cost_to_rp of upstream-%s changed to:%u",
			__func__, up->sg_str,
			rpf->source_nexthop.mrib_route_metric);

	if (pim_up_mlag_is_local(up))
		pim_mlag_up_local_add(pim, up);
}

enum pim_rpf_result pim_rpf_update(struct pim_instance *pim,
		struct pim_upstream *up, struct pim_rpf *old,
		const char *caller)
{
	struct pim_rpf *rpf = &up->rpf;
	struct pim_rpf saved;
	pim_addr src;
	struct prefix grp;
	bool neigh_needed = true;
	uint32_t saved_mrib_route_metric;

	if (PIM_UPSTREAM_FLAG_TEST_STATIC_IIF(up->flags))
		return PIM_RPF_OK;

	if (pim_addr_is_any(up->upstream_addr)) {
		zlog_debug("%s(%s): RP is not configured yet for %s",
			__func__, caller, up->sg_str);
		return PIM_RPF_OK;
	}

	saved.source_nexthop = rpf->source_nexthop;
	saved.rpf_addr = rpf->rpf_addr;
	saved_mrib_route_metric = pim_up_mlag_local_cost(up);
	if (old) {
		old->source_nexthop = saved.source_nexthop;
		old->rpf_addr = saved.rpf_addr;
	}

	src = up->upstream_addr; // RP or Src address
	pim_addr_to_prefix(&grp, up->sg.grp);

	if ((pim_addr_is_any(up->sg.src) && I_am_RP(pim, up->sg.grp)) ||
	    PIM_UPSTREAM_FLAG_TEST_FHR(up->flags))
		neigh_needed = false;
	pim_find_or_track_nexthop(pim, up->upstream_addr, up, NULL, NULL);
	if (!pim_ecmp_nexthop_lookup(pim, &rpf->source_nexthop, src, &grp,
				     neigh_needed)) {
		/* Route is Deleted in Zebra, reset the stored NH data */
		pim_upstream_rpf_clear(pim, up);
		pim_rpf_cost_change(pim, up, saved_mrib_route_metric);
		return PIM_RPF_FAILURE;
	}

	rpf->rpf_addr = pim_rpf_find_rpf_addr(up);

	if (pim_rpf_addr_is_inaddr_any(rpf) && PIM_DEBUG_ZEBRA) {
		/* RPF'(S,G) not found */
		zlog_debug("%s(%s): RPF'%s not found: won't send join upstream",
			   __func__, caller, up->sg_str);
		/* warning only */
	}

	/* detect change in pim_nexthop */
	if (nexthop_mismatch(&rpf->source_nexthop, &saved.source_nexthop)) {

		if (PIM_DEBUG_ZEBRA)
			zlog_debug("%s(%s): (S,G)=%s source nexthop now is: interface=%s address=%pPAs pref=%d metric=%d",
		 __func__, caller,
		 up->sg_str,
		 rpf->source_nexthop.interface ? rpf->source_nexthop.interface->name : "<ifname?>",
		 &rpf->source_nexthop.mrib_nexthop_addr,
		 rpf->source_nexthop.mrib_metric_preference,
		 rpf->source_nexthop.mrib_route_metric);

		pim_upstream_update_join_desired(pim, up);
		pim_upstream_update_could_assert(up);
		pim_upstream_update_my_assert_metric(up);
	}

	/* detect change in RPF_interface(S) */
	if (saved.source_nexthop.interface != rpf->source_nexthop.interface) {

		if (PIM_DEBUG_ZEBRA) {
			zlog_debug("%s(%s): (S,G)=%s RPF_interface(S) changed from %s to %s",
		 __func__, caller,
		 up->sg_str,
		 saved.source_nexthop.interface ? saved.source_nexthop.interface->name : "<oldif?>",
		 rpf->source_nexthop.interface ? rpf->source_nexthop.interface->name : "<newif?>");
			/* warning only */
		}

		pim_upstream_rpf_interface_changed(
			up, saved.source_nexthop.interface);
	}

	/* detect change in RPF'(S,G) */
	if (pim_addr_cmp(saved.rpf_addr, rpf->rpf_addr) ||
	    saved.source_nexthop.interface != rpf->source_nexthop.interface) {
		pim_rpf_cost_change(pim, up, saved_mrib_route_metric);
		return PIM_RPF_CHANGED;
	}

	if (PIM_DEBUG_MLAG)
		zlog_debug(
			"%s(%s): Cost_to_rp of upstream-%s changed to:%u",
			__func__, caller, up->sg_str,
			rpf->source_nexthop.mrib_route_metric);

	pim_rpf_cost_change(pim, up, saved_mrib_route_metric);

	return PIM_RPF_OK;
}

/*
 * In the case of RP deletion and RP unreachablity,
 * uninstall the mroute in the kernel and clear the
 * rpf information in the pim upstream and pim channel
 * oil data structure.
 */
void pim_upstream_rpf_clear(struct pim_instance *pim,
			    struct pim_upstream *up)
{
	if (up->rpf.source_nexthop.interface) {
		pim_upstream_switch(pim, up, PIM_UPSTREAM_NOTJOINED);
		up->rpf.source_nexthop.interface = NULL;
		up->rpf.source_nexthop.mrib_nexthop_addr = PIMADDR_ANY;
		up->rpf.source_nexthop.mrib_metric_preference =
			router->infinite_assert_metric.metric_preference;
		up->rpf.source_nexthop.mrib_route_metric =
			router->infinite_assert_metric.route_metric;
		up->rpf.rpf_addr = PIMADDR_ANY;
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);
	}
}

/*
  RFC 4601: 4.1.6.  State Summarization Macros

     neighbor RPF'(S,G) {
	 if ( I_Am_Assert_Loser(S, G, RPF_interface(S) )) {
	      return AssertWinner(S, G, RPF_interface(S) )
	 } else {
	      return NBR( RPF_interface(S), MRIB.next_hop( S ) )
	 }
     }

  RPF'(*,G) and RPF'(S,G) indicate the neighbor from which data
  packets should be coming and to which joins should be sent on the RP
  tree and SPT, respectively.
*/
static pim_addr pim_rpf_find_rpf_addr(struct pim_upstream *up)
{
	struct pim_ifchannel *rpf_ch;
	struct pim_neighbor *neigh;
	pim_addr rpf_addr;

	if (!up->rpf.source_nexthop.interface) {
		zlog_warn("%s: missing RPF interface for upstream (S,G)=%s",
			  __func__, up->sg_str);

		return PIMADDR_ANY;
	}

	rpf_ch = pim_ifchannel_find(up->rpf.source_nexthop.interface, &up->sg);
	if (rpf_ch) {
		if (rpf_ch->ifassert_state == PIM_IFASSERT_I_AM_LOSER) {
			return rpf_ch->ifassert_winner;
		}
	}

	/* return NBR( RPF_interface(S), MRIB.next_hop( S ) ) */

	neigh = pim_if_find_neighbor(up->rpf.source_nexthop.interface,
				     up->rpf.source_nexthop.mrib_nexthop_addr);
	if (neigh)
		rpf_addr = neigh->source_addr;
	else
		rpf_addr = PIMADDR_ANY;

	return rpf_addr;
}

int pim_rpf_addr_is_inaddr_any(struct pim_rpf *rpf)
{
	return pim_addr_is_any(rpf->rpf_addr);
}

int pim_rpf_is_same(struct pim_rpf *rpf1, struct pim_rpf *rpf2)
{
	if (rpf1->source_nexthop.interface == rpf2->source_nexthop.interface)
		return 1;

	return 0;
}

unsigned int pim_rpf_hash_key(const void *arg)
{
	const struct pim_nexthop_cache *r = arg;

#if PIM_IPV == 4
	return jhash_1word(r->rpf.rpf_addr.s_addr, 0);
#else
	return jhash2(r->rpf.rpf_addr.s6_addr32,
		      array_size(r->rpf.rpf_addr.s6_addr32), 0);
#endif
}

bool pim_rpf_equal(const void *arg1, const void *arg2)
{
	const struct pim_nexthop_cache *r1 =
		(const struct pim_nexthop_cache *)arg1;
	const struct pim_nexthop_cache *r2 =
		(const struct pim_nexthop_cache *)arg2;

	return (!pim_addr_cmp(r1->rpf.rpf_addr, r2->rpf.rpf_addr));
}
