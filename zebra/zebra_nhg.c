/* Zebra Nexthop Group Code.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Donald Sharp
 *                    Stephen Worley
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <zebra.h>

#include "lib/nexthop.h"
#include "lib/nexthop_group_private.h"
#include "lib/routemap.h"
#include "lib/mpls.h"

#include "zebra/connected.h"
#include "zebra/debug.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_routemap.h"
#include "zebra/rt.h"

static void nexthop_set_resolved(afi_t afi, const struct nexthop *newhop,
				 struct nexthop *nexthop)
{
	struct nexthop *resolved_hop;
	uint8_t num_labels = 0;
	mpls_label_t labels[MPLS_MAX_LABELS];
	enum lsp_types_t label_type = ZEBRA_LSP_NONE;
	int i = 0;

	resolved_hop = nexthop_new();
	SET_FLAG(resolved_hop->flags, NEXTHOP_FLAG_ACTIVE);

	resolved_hop->vrf_id = nexthop->vrf_id;
	switch (newhop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		/* If the resolving route specifies a gateway, use it */
		resolved_hop->type = newhop->type;
		resolved_hop->gate.ipv4 = newhop->gate.ipv4;

		if (newhop->ifindex) {
			resolved_hop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			resolved_hop->ifindex = newhop->ifindex;
		}
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		resolved_hop->type = newhop->type;
		resolved_hop->gate.ipv6 = newhop->gate.ipv6;

		if (newhop->ifindex) {
			resolved_hop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			resolved_hop->ifindex = newhop->ifindex;
		}
		break;
	case NEXTHOP_TYPE_IFINDEX:
		/* If the resolving route is an interface route,
		 * it means the gateway we are looking up is connected
		 * to that interface. (The actual network is _not_ onlink).
		 * Therefore, the resolved route should have the original
		 * gateway as nexthop as it is directly connected.
		 *
		 * On Linux, we have to set the onlink netlink flag because
		 * otherwise, the kernel won't accept the route.
		 */
		resolved_hop->flags |= NEXTHOP_FLAG_ONLINK;
		if (afi == AFI_IP) {
			resolved_hop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			resolved_hop->gate.ipv4 = nexthop->gate.ipv4;
		} else if (afi == AFI_IP6) {
			resolved_hop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			resolved_hop->gate.ipv6 = nexthop->gate.ipv6;
		}
		resolved_hop->ifindex = newhop->ifindex;
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		resolved_hop->type = NEXTHOP_TYPE_BLACKHOLE;
		resolved_hop->bh_type = newhop->bh_type;
		break;
	}

	if (newhop->flags & NEXTHOP_FLAG_ONLINK)
		resolved_hop->flags |= NEXTHOP_FLAG_ONLINK;

	/* Copy labels of the resolved route and the parent resolving to it */
	if (newhop->nh_label) {
		for (i = 0; i < newhop->nh_label->num_labels; i++)
			labels[num_labels++] = newhop->nh_label->label[i];
		label_type = newhop->nh_label_type;
	}

	if (nexthop->nh_label) {
		for (i = 0; i < nexthop->nh_label->num_labels; i++)
			labels[num_labels++] = nexthop->nh_label->label[i];

		/* If the parent has labels, use its type */
		label_type = nexthop->nh_label_type;
	}

	if (num_labels)
		nexthop_add_labels(resolved_hop, label_type, num_labels,
				   labels);

	resolved_hop->rparent = nexthop;
	_nexthop_add(&nexthop->resolved, resolved_hop);
}

/*
 * Given a nexthop we need to properly recursively resolve
 * the route.  As such, do a table lookup to find and match
 * if at all possible.  Set the nexthop->ifindex as appropriate
 */
static int nexthop_active(afi_t afi, struct route_entry *re,
			  struct nexthop *nexthop, struct route_node *top)
{
	struct prefix p;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *match = NULL;
	int resolved;
	struct nexthop *newhop;
	struct interface *ifp;
	rib_dest_t *dest;
	struct zebra_vrf *zvrf;

	if ((nexthop->type == NEXTHOP_TYPE_IPV4)
	    || nexthop->type == NEXTHOP_TYPE_IPV6)
		nexthop->ifindex = 0;

	UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
	nexthops_free(nexthop->resolved);
	nexthop->resolved = NULL;
	re->nexthop_mtu = 0;

	/*
	 * If the kernel has sent us a route, then
	 * by golly gee whiz it's a good route.
	 */
	if (re->type == ZEBRA_ROUTE_KERNEL || re->type == ZEBRA_ROUTE_SYSTEM)
		return 1;

	/*
	 * Check to see if we should trust the passed in information
	 * for UNNUMBERED interfaces as that we won't find the GW
	 * address in the routing table.
	 * This check should suffice to handle IPv4 or IPv6 routes
	 * sourced from EVPN routes which are installed with the
	 * next hop as the remote VTEP IP.
	 */
	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK)) {
		ifp = if_lookup_by_index(nexthop->ifindex, nexthop->vrf_id);
		if (!ifp) {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"\t%s: Onlink and interface: %u[%u] does not exist",
					__PRETTY_FUNCTION__, nexthop->ifindex,
					nexthop->vrf_id);
			return 0;
		}
		if (connected_is_unnumbered(ifp)) {
			if (if_is_operative(ifp))
				return 1;
			else {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED)
					zlog_debug(
						"\t%s: Onlink and interface %s is not operative",
						__PRETTY_FUNCTION__, ifp->name);
				return 0;
			}
		}
		if (!if_is_operative(ifp)) {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"\t%s: Interface %s is not unnumbered",
					__PRETTY_FUNCTION__, ifp->name);
			return 0;
		}
	}

	/* Make lookup prefix. */
	memset(&p, 0, sizeof(struct prefix));
	switch (afi) {
	case AFI_IP:
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_PREFIXLEN;
		p.u.prefix4 = nexthop->gate.ipv4;
		break;
	case AFI_IP6:
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_PREFIXLEN;
		p.u.prefix6 = nexthop->gate.ipv6;
		break;
	default:
		assert(afi != AFI_IP && afi != AFI_IP6);
		break;
	}
	/* Lookup table.  */
	table = zebra_vrf_table(afi, SAFI_UNICAST, nexthop->vrf_id);
	/* get zvrf */
	zvrf = zebra_vrf_lookup_by_id(nexthop->vrf_id);
	if (!table || !zvrf) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("\t%s: Table not found",
				   __PRETTY_FUNCTION__);
		return 0;
	}

	rn = route_node_match(table, (struct prefix *)&p);
	while (rn) {
		route_unlock_node(rn);

		/* Lookup should halt if we've matched against ourselves ('top',
		 * if specified) - i.e., we cannot have a nexthop NH1 is
		 * resolved by a route NH1. The exception is if the route is a
		 * host route.
		 */
		if (top && rn == top)
			if (((afi == AFI_IP) && (rn->p.prefixlen != 32))
			    || ((afi == AFI_IP6) && (rn->p.prefixlen != 128))) {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED)
					zlog_debug(
						"\t%s: Matched against ourself and prefix length is not max bit length",
						__PRETTY_FUNCTION__);
				return 0;
			}

		/* Pick up selected route. */
		/* However, do not resolve over default route unless explicitly
		 * allowed. */
		if (is_default_prefix(&rn->p)
		    && !rnh_resolve_via_default(zvrf, p.family)) {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"\t:%s: Resolved against default route",
					__PRETTY_FUNCTION__);
			return 0;
		}

		dest = rib_dest_from_rnode(rn);
		if (dest && dest->selected_fib
		    && !CHECK_FLAG(dest->selected_fib->status,
				   ROUTE_ENTRY_REMOVED)
		    && dest->selected_fib->type != ZEBRA_ROUTE_TABLE)
			match = dest->selected_fib;

		/* If there is no selected route or matched route is EGP, go up
		   tree. */
		if (!match) {
			do {
				rn = rn->parent;
			} while (rn && rn->info == NULL);
			if (rn)
				route_lock_node(rn);

			continue;
		}

		if (match->type == ZEBRA_ROUTE_CONNECT) {
			/* Directly point connected route. */
			newhop = match->ng.nexthop;
			if (newhop) {
				if (nexthop->type == NEXTHOP_TYPE_IPV4
				    || nexthop->type == NEXTHOP_TYPE_IPV6)
					nexthop->ifindex = newhop->ifindex;
			}
			return 1;
		} else if (CHECK_FLAG(re->flags, ZEBRA_FLAG_ALLOW_RECURSION)) {
			resolved = 0;
			for (ALL_NEXTHOPS(match->ng, newhop)) {
				if (!CHECK_FLAG(match->status,
						ROUTE_ENTRY_INSTALLED))
					continue;
				if (CHECK_FLAG(newhop->flags,
					       NEXTHOP_FLAG_RECURSIVE))
					continue;

				SET_FLAG(nexthop->flags,
					 NEXTHOP_FLAG_RECURSIVE);
				nexthop_set_resolved(afi, newhop, nexthop);
				resolved = 1;
			}
			if (resolved)
				re->nexthop_mtu = match->mtu;
			if (!resolved && IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug("\t%s: Recursion failed to find",
					   __PRETTY_FUNCTION__);
			return resolved;
		} else if (re->type == ZEBRA_ROUTE_STATIC) {
			resolved = 0;
			for (ALL_NEXTHOPS(match->ng, newhop)) {
				if (!CHECK_FLAG(match->status,
						ROUTE_ENTRY_INSTALLED))
					continue;
				if (CHECK_FLAG(newhop->flags,
					       NEXTHOP_FLAG_RECURSIVE))
					continue;

				SET_FLAG(nexthop->flags,
					 NEXTHOP_FLAG_RECURSIVE);
				nexthop_set_resolved(afi, newhop, nexthop);
				resolved = 1;
			}
			if (resolved)
				re->nexthop_mtu = match->mtu;

			if (!resolved && IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"\t%s: Static route unable to resolve",
					__PRETTY_FUNCTION__);
			return resolved;
		} else {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
				zlog_debug(
					"\t%s: Route Type %s has not turned on recursion",
					__PRETTY_FUNCTION__,
					zebra_route_string(re->type));
				if (re->type == ZEBRA_ROUTE_BGP
				    && !CHECK_FLAG(re->flags, ZEBRA_FLAG_IBGP))
					zlog_debug(
						"\tEBGP: see \"disable-ebgp-connected-route-check\" or \"disable-connected-check\"");
			}
			return 0;
		}
	}
	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("\t%s: Nexthop did not lookup in table",
			   __PRETTY_FUNCTION__);
	return 0;
}

/* This function verifies reachability of one given nexthop, which can be
 * numbered or unnumbered, IPv4 or IPv6. The result is unconditionally stored
 * in nexthop->flags field. The nexthop->ifindex will be updated
 * appropriately as well.  An existing route map can turn
 * (otherwise active) nexthop into inactive, but not vice versa.
 *
 * The return value is the final value of 'ACTIVE' flag.
 */
static unsigned nexthop_active_check(struct route_node *rn,
				     struct route_entry *re,
				     struct nexthop *nexthop)
{
	struct interface *ifp;
	route_map_result_t ret = RMAP_PERMITMATCH;
	int family;
	char buf[SRCDEST2STR_BUFFER];
	const struct prefix *p, *src_p;
	struct zebra_vrf *zvrf;

	srcdest_rnode_prefixes(rn, &p, &src_p);

	if (rn->p.family == AF_INET)
		family = AFI_IP;
	else if (rn->p.family == AF_INET6)
		family = AFI_IP6;
	else
		family = 0;
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:
		ifp = if_lookup_by_index(nexthop->ifindex, nexthop->vrf_id);
		if (ifp && if_is_operative(ifp))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		family = AFI_IP;
		if (nexthop_active(AFI_IP, re, nexthop, rn))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	case NEXTHOP_TYPE_IPV6:
		family = AFI_IP6;
		if (nexthop_active(AFI_IP6, re, nexthop, rn))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		/* RFC 5549, v4 prefix with v6 NH */
		if (rn->p.family != AF_INET)
			family = AFI_IP6;
		if (IN6_IS_ADDR_LINKLOCAL(&nexthop->gate.ipv6)) {
			ifp = if_lookup_by_index(nexthop->ifindex,
						 nexthop->vrf_id);
			if (ifp && if_is_operative(ifp))
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
			else
				UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		} else {
			if (nexthop_active(AFI_IP6, re, nexthop, rn))
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
			else
				UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		}
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	default:
		break;
	}
	if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("\t%s: Unable to find a active nexthop",
				   __PRETTY_FUNCTION__);
		return 0;
	}

	/* XXX: What exactly do those checks do? Do we support
	 * e.g. IPv4 routes with IPv6 nexthops or vice versa?
	 */
	if (RIB_SYSTEM_ROUTE(re) || (family == AFI_IP && p->family != AF_INET)
	    || (family == AFI_IP6 && p->family != AF_INET6))
		return CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);

	/* The original code didn't determine the family correctly
	 * e.g. for NEXTHOP_TYPE_IFINDEX. Retrieve the correct afi
	 * from the rib_table_info in those cases.
	 * Possibly it may be better to use only the rib_table_info
	 * in every case.
	 */
	if (!family) {
		rib_table_info_t *info;

		info = srcdest_rnode_table_info(rn);
		family = info->afi;
	}

	memset(&nexthop->rmap_src.ipv6, 0, sizeof(union g_addr));

	zvrf = zebra_vrf_lookup_by_id(nexthop->vrf_id);
	if (!zvrf) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("\t%s: zvrf is NULL", __PRETTY_FUNCTION__);
		return CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}

	/* It'll get set if required inside */
	ret = zebra_route_map_check(family, re->type, re->instance, p, nexthop,
				    zvrf, re->tag);
	if (ret == RMAP_DENYMATCH) {
		if (IS_ZEBRA_DEBUG_RIB) {
			srcdest_rnode2str(rn, buf, sizeof(buf));
			zlog_debug(
				"%u:%s: Filtering out with NH out %s due to route map",
				re->vrf_id, buf,
				ifindex2ifname(nexthop->ifindex,
					       nexthop->vrf_id));
		}
		UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}
	return CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
}

/*
 * Iterate over all nexthops of the given RIB entry and refresh their
 * ACTIVE flag. re->nexthop_active_num is updated accordingly. If any
 * nexthop is found to toggle the ACTIVE flag, the whole re structure
 * is flagged with ROUTE_ENTRY_CHANGED.
 *
 * Return value is the new number of active nexthops.
 */
int nexthop_active_update(struct route_node *rn, struct route_entry *re)
{
	struct nexthop *nexthop;
	union g_addr prev_src;
	unsigned int prev_active, new_active;
	ifindex_t prev_index;

	re->nexthop_active_num = 0;
	UNSET_FLAG(re->status, ROUTE_ENTRY_CHANGED);

	for (nexthop = re->ng.nexthop; nexthop; nexthop = nexthop->next) {
		/* No protocol daemon provides src and so we're skipping
		 * tracking it */
		prev_src = nexthop->rmap_src;
		prev_active = CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		prev_index = nexthop->ifindex;
		/*
		 * We need to respect the multipath_num here
		 * as that what we should be able to install from
		 * a multipath perpsective should not be a data plane
		 * decision point.
		 */
		new_active = nexthop_active_check(rn, re, nexthop);
		if (new_active
		    && re->nexthop_active_num >= zrouter.multipath_num) {
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
			new_active = 0;
		}
		if (new_active)
			re->nexthop_active_num++;
		/* Don't allow src setting on IPv6 addr for now */
		if (prev_active != new_active || prev_index != nexthop->ifindex
		    || ((nexthop->type >= NEXTHOP_TYPE_IFINDEX
			 && nexthop->type < NEXTHOP_TYPE_IPV6)
			&& prev_src.ipv4.s_addr
				   != nexthop->rmap_src.ipv4.s_addr)
		    || ((nexthop->type >= NEXTHOP_TYPE_IPV6
			 && nexthop->type < NEXTHOP_TYPE_BLACKHOLE)
			&& !(IPV6_ADDR_SAME(&prev_src.ipv6,
					    &nexthop->rmap_src.ipv6)))
		    || CHECK_FLAG(re->status, ROUTE_ENTRY_LABELS_CHANGED))
			SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
	}

	return re->nexthop_active_num;
}

