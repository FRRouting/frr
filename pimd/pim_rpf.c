/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "if.h"

#include "log.h"
#include "prefix.h"
#include "memory.h"
#include "jhash.h"

#include "pimd.h"
#include "pim_rpf.h"
#include "pim_pim.h"
#include "pim_str.h"
#include "pim_iface.h"
#include "pim_zlookup.h"
#include "pim_ifchannel.h"
#include "pim_time.h"
#include "pim_nht.h"
#include "pim_oil.h"

static struct in_addr pim_rpf_find_rpf_addr(struct pim_upstream *up);

void pim_rpf_set_refresh_time(struct pim_instance *pim)
{
	pim->last_route_change_time = pim_time_monotonic_usec();
	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s: vrf(%s) New last route change time: %" PRId64,
			   __PRETTY_FUNCTION__, pim->vrf->name,
			   pim->last_route_change_time);
}

bool pim_nexthop_lookup(struct pim_instance *pim, struct pim_nexthop *nexthop,
			struct in_addr addr, int neighbor_needed)
{
	struct pim_zlookup_nexthop nexthop_tab[MULTIPATH_NUM];
	struct pim_neighbor *nbr = NULL;
	int num_ifindex;
	struct interface *ifp = NULL;
	ifindex_t first_ifindex = 0;
	int found = 0;
	int i = 0;

	/*
	 * We should not attempt to lookup a
	 * 255.255.255.255 address, since
	 * it will never work
	 */
	if (addr.s_addr == INADDR_NONE)
		return false;

	if ((nexthop->last_lookup.s_addr == addr.s_addr)
	    && (nexthop->last_lookup_time > pim->last_route_change_time)) {
		if (PIM_DEBUG_PIM_NHT) {
			char addr_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<addr?>", addr, addr_str,
				       sizeof(addr_str));
			char nexthop_str[PREFIX_STRLEN];
			pim_addr_dump("<nexthop?>", &nexthop->mrib_nexthop_addr,
				      nexthop_str, sizeof(nexthop_str));
			zlog_debug(
				"%s: Using last lookup for %s at %lld, %" PRId64 " addr %s",
				__PRETTY_FUNCTION__, addr_str,
				nexthop->last_lookup_time,
				pim->last_route_change_time, nexthop_str);
		}
		pim->nexthop_lookups_avoided++;
		return true;
	} else {
		if (PIM_DEBUG_PIM_NHT) {
			char addr_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<addr?>", addr, addr_str,
				       sizeof(addr_str));
			zlog_debug(
				"%s: Looking up: %s, last lookup time: %lld, %" PRId64,
				__PRETTY_FUNCTION__, addr_str,
				nexthop->last_lookup_time,
				pim->last_route_change_time);
		}
	}

	memset(nexthop_tab, 0,
	       sizeof(struct pim_zlookup_nexthop) * MULTIPATH_NUM);
	num_ifindex = zclient_lookup_nexthop(pim, nexthop_tab, MULTIPATH_NUM,
					     addr, PIM_NEXTHOP_LOOKUP_MAX);
	if (num_ifindex < 1) {
		char addr_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<addr?>", addr, addr_str, sizeof(addr_str));
		zlog_warn(
			"%s %s: could not find nexthop ifindex for address %s",
			__FILE__, __PRETTY_FUNCTION__, addr_str);
		return false;
	}

	while (!found && (i < num_ifindex)) {
		first_ifindex = nexthop_tab[i].ifindex;

		ifp = if_lookup_by_index(first_ifindex, pim->vrf_id);
		if (!ifp) {
			if (PIM_DEBUG_ZEBRA) {
				char addr_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<addr?>", addr, addr_str,
					       sizeof(addr_str));
				zlog_debug(
					"%s %s: could not find interface for ifindex %d (address %s)",
					__FILE__, __PRETTY_FUNCTION__,
					first_ifindex, addr_str);
			}
			i++;
			continue;
		}

		if (!ifp->info) {
			if (PIM_DEBUG_ZEBRA) {
				char addr_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<addr?>", addr, addr_str,
					       sizeof(addr_str));
				zlog_debug(
					"%s: multicast not enabled on input interface %s (ifindex=%d, RPF for source %s)",
					__PRETTY_FUNCTION__, ifp->name,
					first_ifindex, addr_str);
			}
			i++;
		} else if (neighbor_needed
			   && !pim_if_connected_to_source(ifp, addr)) {
			nbr = pim_neighbor_find(
				ifp, nexthop_tab[i].nexthop_addr.u.prefix4);
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
		if (PIM_DEBUG_ZEBRA) {
			char nexthop_str[PREFIX_STRLEN];
			char addr_str[INET_ADDRSTRLEN];
			pim_addr_dump("<nexthop?>",
				      &nexthop_tab[i].nexthop_addr, nexthop_str,
				      sizeof(nexthop_str));
			pim_inet4_dump("<addr?>", addr, addr_str,
				       sizeof(addr_str));
			zlog_debug(
				"%s %s: found nexthop %s for address %s: interface %s ifindex=%d metric=%d pref=%d",
				__FILE__, __PRETTY_FUNCTION__, nexthop_str,
				addr_str, ifp->name, first_ifindex,
				nexthop_tab[i].route_metric,
				nexthop_tab[i].protocol_distance);
		}
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
	return (nh1->interface != nh2->interface)
	       || (nh1->mrib_nexthop_addr.u.prefix4.s_addr
		   != nh2->mrib_nexthop_addr.u.prefix4.s_addr)
	       || (nh1->mrib_metric_preference != nh2->mrib_metric_preference)
	       || (nh1->mrib_route_metric != nh2->mrib_route_metric);
}

enum pim_rpf_result pim_rpf_update(struct pim_instance *pim,
				   struct pim_upstream *up, struct pim_rpf *old)
{
	struct pim_rpf *rpf = &up->rpf;
	struct pim_rpf saved;
	struct prefix nht_p;
	struct prefix src, grp;
	bool neigh_needed = true;

	if (PIM_UPSTREAM_FLAG_TEST_STATIC_IIF(up->flags))
		return PIM_RPF_OK;

	if (up->upstream_addr.s_addr == INADDR_ANY) {
		zlog_debug("%s: RP is not configured yet for %s",
			__PRETTY_FUNCTION__, up->sg_str);
		return PIM_RPF_OK;
	}

	saved.source_nexthop = rpf->source_nexthop;
	saved.rpf_addr = rpf->rpf_addr;

	nht_p.family = AF_INET;
	nht_p.prefixlen = IPV4_MAX_BITLEN;
	nht_p.u.prefix4.s_addr = up->upstream_addr.s_addr;

	src.family = AF_INET;
	src.prefixlen = IPV4_MAX_BITLEN;
	src.u.prefix4 = up->upstream_addr; // RP or Src address
	grp.family = AF_INET;
	grp.prefixlen = IPV4_MAX_BITLEN;
	grp.u.prefix4 = up->sg.grp;

	if ((up->sg.src.s_addr == INADDR_ANY && I_am_RP(pim, up->sg.grp)) ||
	    PIM_UPSTREAM_FLAG_TEST_FHR(up->flags))
		neigh_needed = false;
	pim_find_or_track_nexthop(pim, &nht_p, up, NULL, false, NULL);
	if (!pim_ecmp_nexthop_lookup(pim, &rpf->source_nexthop, &src, &grp,
				     neigh_needed))
		return PIM_RPF_FAILURE;

	rpf->rpf_addr.family = AF_INET;
	rpf->rpf_addr.u.prefix4 = pim_rpf_find_rpf_addr(up);
	if (pim_rpf_addr_is_inaddr_any(rpf) && PIM_DEBUG_ZEBRA) {
		/* RPF'(S,G) not found */
		zlog_debug("%s %s: RPF'%s not found: won't send join upstream",
			   __FILE__, __PRETTY_FUNCTION__, up->sg_str);
		/* warning only */
	}

	/* detect change in pim_nexthop */
	if (nexthop_mismatch(&rpf->source_nexthop, &saved.source_nexthop)) {

		if (PIM_DEBUG_ZEBRA) {
			char nhaddr_str[PREFIX_STRLEN];
			pim_addr_dump("<addr?>",
				      &rpf->source_nexthop.mrib_nexthop_addr,
				      nhaddr_str, sizeof(nhaddr_str));
			zlog_debug("%s %s: (S,G)=%s source nexthop now is: interface=%s address=%s pref=%d metric=%d",
		 __FILE__, __PRETTY_FUNCTION__,
		 up->sg_str,
		 rpf->source_nexthop.interface ? rpf->source_nexthop.interface->name : "<ifname?>",
		 nhaddr_str,
		 rpf->source_nexthop.mrib_metric_preference,
		 rpf->source_nexthop.mrib_route_metric);
		}

		pim_upstream_update_join_desired(pim, up);
		pim_upstream_update_could_assert(up);
		pim_upstream_update_my_assert_metric(up);
	}

	/* detect change in RPF_interface(S) */
	if (saved.source_nexthop.interface != rpf->source_nexthop.interface) {

		if (PIM_DEBUG_ZEBRA) {
			zlog_debug("%s %s: (S,G)=%s RPF_interface(S) changed from %s to %s",
		 __FILE__, __PRETTY_FUNCTION__,
		 up->sg_str,
		 saved.source_nexthop.interface ? saved.source_nexthop.interface->name : "<oldif?>",
		 rpf->source_nexthop.interface ? rpf->source_nexthop.interface->name : "<newif?>");
			/* warning only */
		}

		pim_upstream_rpf_interface_changed(
			up, saved.source_nexthop.interface);
	}

	/* detect change in RPF'(S,G) */
	if (saved.rpf_addr.u.prefix4.s_addr != rpf->rpf_addr.u.prefix4.s_addr
	    || saved.source_nexthop
			       .interface != rpf->source_nexthop.interface) {

		/* return old rpf to caller ? */
		if (old) {
			old->source_nexthop = saved.source_nexthop;
			old->rpf_addr = saved.rpf_addr;
		}
		return PIM_RPF_CHANGED;
	}

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
		if (up->channel_oil)
			pim_channel_oil_change_iif(pim, up->channel_oil,
						   MAXVIFS,
						   __PRETTY_FUNCTION__);

		pim_upstream_switch(pim, up, PIM_UPSTREAM_NOTJOINED);
		up->rpf.source_nexthop.interface = NULL;
		up->rpf.source_nexthop.mrib_nexthop_addr.u.prefix4.s_addr =
			PIM_NET_INADDR_ANY;
		up->rpf.source_nexthop.mrib_metric_preference =
			router->infinite_assert_metric.metric_preference;
		up->rpf.source_nexthop.mrib_route_metric =
			router->infinite_assert_metric.route_metric;
		up->rpf.rpf_addr.u.prefix4.s_addr = PIM_NET_INADDR_ANY;
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
static struct in_addr pim_rpf_find_rpf_addr(struct pim_upstream *up)
{
	struct pim_ifchannel *rpf_ch;
	struct pim_neighbor *neigh;
	struct in_addr rpf_addr;

	if (!up->rpf.source_nexthop.interface) {
		zlog_warn("%s: missing RPF interface for upstream (S,G)=%s",
			  __PRETTY_FUNCTION__, up->sg_str);

		rpf_addr.s_addr = PIM_NET_INADDR_ANY;
		return rpf_addr;
	}

	rpf_ch = pim_ifchannel_find(up->rpf.source_nexthop.interface, &up->sg);
	if (rpf_ch) {
		if (rpf_ch->ifassert_state == PIM_IFASSERT_I_AM_LOSER) {
			return rpf_ch->ifassert_winner;
		}
	}

	/* return NBR( RPF_interface(S), MRIB.next_hop( S ) ) */

	neigh = pim_if_find_neighbor(
		up->rpf.source_nexthop.interface,
		up->rpf.source_nexthop.mrib_nexthop_addr.u.prefix4);
	if (neigh)
		rpf_addr = neigh->source_addr;
	else
		rpf_addr.s_addr = PIM_NET_INADDR_ANY;

	return rpf_addr;
}

int pim_rpf_addr_is_inaddr_none(struct pim_rpf *rpf)
{
	switch (rpf->rpf_addr.family) {
	case AF_INET:
		return rpf->rpf_addr.u.prefix4.s_addr == INADDR_NONE;
		break;
	case AF_INET6:
		zlog_warn("%s: v6 Unimplmeneted", __PRETTY_FUNCTION__);
		return 1;
		break;
	default:
		return 0;
		break;
	}

	return 0;
}

int pim_rpf_addr_is_inaddr_any(struct pim_rpf *rpf)
{
	switch (rpf->rpf_addr.family) {
	case AF_INET:
		return rpf->rpf_addr.u.prefix4.s_addr == INADDR_ANY;
		break;
	case AF_INET6:
		zlog_warn("%s: v6 Unimplmented", __PRETTY_FUNCTION__);
		return 1;
		break;
	default:
		return 0;
		break;
	}

	return 0;
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

	return jhash_1word(r->rpf.rpf_addr.u.prefix4.s_addr, 0);
}

bool pim_rpf_equal(const void *arg1, const void *arg2)
{
	const struct pim_nexthop_cache *r1 =
		(const struct pim_nexthop_cache *)arg1;
	const struct pim_nexthop_cache *r2 =
		(const struct pim_nexthop_cache *)arg2;

	return prefix_same(&r1->rpf.rpf_addr, &r2->rpf.rpf_addr);
}
