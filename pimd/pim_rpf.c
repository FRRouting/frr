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

	pim_nht_find_or_track(pim, up->upstream_addr, up, NULL, NULL);
	if (!pim_nht_lookup_ecmp(pim, &rpf->source_nexthop, src, &grp, neigh_needed)) {
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

bool pim_route_lookup(struct pim_instance *pim, pim_addr addr, uint32_t asn, struct pim_nexthop *pn)
{
	struct interface *ifp;
	struct zroute_info *ri;
	struct zroute_nh_info *rni;
	bool found = false;

	/* Zero out pim next hop response.*/
	memset(pn, 0, sizeof(*pn));

	/* Search route information. */
	ri = zclient_route_lookup(pim, &addr);
	if (ri == NULL) {
		if (PIM_DEBUG_ZEBRA)
			zlog_debug("%s: could not find route for address %pPA", __func__, &addr);
		return false;
	}

	/*
	 * AS check (in case AS number was provided).
	 *
	 * This code path checks for the following MSDP rule:
	 *
	 * > For a direct peering inter-domain environment to be successful, the
	 * > first AS in the MBGP best path to the originating RP should be the
	 * > same as the AS of the MSDP peer.
	 *
	 * RFC 4611 Section 2.1. Peering between PIM Border Routers.
	 */
	if (asn) {
		long long first_asn;

		/*
		 * We expect a BGP route so if no AS Path information is
		 * available it means this is not a BGP route.
		 */
		if (ri->ri_type != ZEBRA_ROUTE_BGP) {
			if (PIM_DEBUG_ZEBRA)
				zlog_debug("%s: expected BGP route for %pPA (got %d)", __func__,
					   &addr, ri->ri_type);
			goto free_and_exit;
		}

		errno = 0;
		first_asn = strtoll((char *)ri->ri_opaque, NULL, 10);
		/* Check for number conversion failures. */
		if (first_asn == LLONG_MIN || first_asn == LLONG_MAX) {
			zlog_warn("%s: AS number overflow/underflow %s", __func__, ri->ri_opaque);
			goto free_and_exit;
		}
		if (first_asn == 0 && errno != 0) {
			zlog_warn("%s: AS number conversion failed: %s", __func__, strerror(errno));
			goto free_and_exit;
		}

		/* AS did not match. */
		if (first_asn != asn) {
			if (PIM_DEBUG_ZEBRA)
				zlog_debug("%s: next hop AS did not match for address %pPA (%u != %lld)",
					   __func__, &addr, asn, first_asn);
			goto free_and_exit;
		}

		/* Proceed to validate next hop. */
		if (PIM_DEBUG_ZEBRA)
			zlog_debug("%s: next hop AS matched for address %pPA (AS %u)", __func__,
				   &addr, asn);
	}

	SLIST_FOREACH (rni, &ri->ri_nhlist, rni_entry) {
		ifp = if_lookup_by_index(rni->rni_ifindex, pim->vrf->vrf_id);
		if (ifp == NULL) {
			if (PIM_DEBUG_ZEBRA)
				zlog_debug("%s: could not find interface for ifindex %d (address %pPA)",
					   __func__, rni->rni_ifindex, &addr);
			continue;
		}
		if (ifp->info == NULL) {
			if (PIM_DEBUG_ZEBRA)
				zlog_debug("%s: multicast not enabled on input interface %s (ifindex=%d, RPF for source %pPA)",
					   __func__, ifp->name, rni->rni_ifindex, &addr);
			continue;
		}

		/* Fill next hop parameter and return. */
		switch (rni->rni_type) {
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			if (PIM_DEBUG_ZEBRA)
				zlog_debug("%s: found nexthop %pI4 for address %pPA: interface %s ifindex=%d metric=%d pref=%d",
					   __func__, &rni->rni_addr.v4, &addr, ifp->name,
					   rni->rni_ifindex, ri->ri_metric, ri->ri_distance);

#if PIM_IPV == 4
			pn->mrib_nexthop_addr = rni->rni_addr.v4;
#endif
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			if (PIM_DEBUG_ZEBRA)
				zlog_debug("%s: found nexthop %pI6 for address %pPA: interface %s ifindex=%d metric=%d pref=%d",
					   __func__, &rni->rni_addr.v6, &addr, ifp->name,
					   rni->rni_ifindex, ri->ri_metric, ri->ri_distance);

#if PIM_IPV == 6
			pn->mrib_nexthop_addr = rni->rni_addr.v6;
#endif
			break;
		case NEXTHOP_TYPE_IFINDEX:
			break;

		default:
			zlog_warn("%s: invalid next hop address type %d", __func__, rni->rni_type);
			continue;
		}

		pn->interface = ifp;
		pn->mrib_metric_preference = ri->ri_distance;
		pn->mrib_route_metric = ri->ri_metric;
		pn->last_lookup = addr;
		pn->last_lookup_time = pim_time_monotonic_usec();

		found = true;
		break;
	}

free_and_exit:
	zroute_info_free(&ri);
	return found;
}
