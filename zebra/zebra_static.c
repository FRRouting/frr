/*
 * Static Routing Information code
 * Copyright (C) 2016 Cumulus Networks
 *               Donald Sharp
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include <lib/nexthop.h>
#include <lib/memory.h>
#include <lib/srcdest_table.h>
#include <lib/if.h>

#include "vty.h"
#include "zebra/debug.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_static.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_memory.h"

/* Install static route into rib. */
void static_install_route(afi_t afi, safi_t safi, struct prefix *p,
			  struct prefix_ipv6 *src_p, struct static_route *si)
{
	struct route_entry *re;
	struct route_node *rn;
	struct route_table *table;
	struct prefix nh_p;
	struct nexthop *nexthop = NULL;
	enum blackhole_type bh_type = 0;

	/* Lookup table.  */
	table = zebra_vrf_table(afi, safi, si->vrf_id);
	if (!table)
		return;

	memset(&nh_p, 0, sizeof(nh_p));
	if (si->type == STATIC_BLACKHOLE) {
		switch (si->bh_type) {
		case STATIC_BLACKHOLE_DROP:
		case STATIC_BLACKHOLE_NULL:
			bh_type = BLACKHOLE_NULL;
			break;
		case STATIC_BLACKHOLE_REJECT:
			bh_type = BLACKHOLE_REJECT;
			break;
		}
	}

	/* Lookup existing route */
	rn = srcdest_rnode_get(table, p, src_p);
	RNODE_FOREACH_RE (rn, re) {
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		if (re->type == ZEBRA_ROUTE_STATIC
		    && re->distance == si->distance)
			break;
	}

	if (re) {
		/* if tag value changed , update old value in RIB */
		if (re->tag != si->tag)
			re->tag = si->tag;

		/* Same distance static route is there.  Update it with new
		   nexthop. */
		route_unlock_node(rn);
		switch (si->type) {
		case STATIC_IPV4_GATEWAY:
			nexthop = route_entry_nexthop_ipv4_add(
				re, &si->addr.ipv4, NULL);
			nh_p.family = AF_INET;
			nh_p.prefixlen = IPV4_MAX_BITLEN;
			nh_p.u.prefix4 = si->addr.ipv4;
			zebra_register_rnh_static_nh(si->nh_vrf_id, &nh_p, rn);
			break;
		case STATIC_IPV4_GATEWAY_IFNAME:
			nexthop = route_entry_nexthop_ipv4_ifindex_add(
				re, &si->addr.ipv4, NULL, si->ifindex);
			break;
		case STATIC_IFNAME:
			nexthop = route_entry_nexthop_ifindex_add(re,
								  si->ifindex);
			break;
		case STATIC_BLACKHOLE:
			nexthop = route_entry_nexthop_blackhole_add(
				re, bh_type);
			break;
		case STATIC_IPV6_GATEWAY:
			nexthop = route_entry_nexthop_ipv6_add(re,
							       &si->addr.ipv6);
			nh_p.family = AF_INET6;
			nh_p.prefixlen = IPV6_MAX_BITLEN;
			nh_p.u.prefix6 = si->addr.ipv6;
			zebra_register_rnh_static_nh(si->nh_vrf_id, &nh_p, rn);
			break;
		case STATIC_IPV6_GATEWAY_IFNAME:
			nexthop = route_entry_nexthop_ipv6_ifindex_add(
				re, &si->addr.ipv6, si->ifindex);
			break;
		}
		/* Update label(s), if present. */
		if (si->snh_label.num_labels)
			nexthop_add_labels(nexthop, ZEBRA_LSP_STATIC,
					   si->snh_label.num_labels,
					   &si->snh_label.label[0]);

		if (IS_ZEBRA_DEBUG_RIB) {
			char buf[INET6_ADDRSTRLEN];
			if (IS_ZEBRA_DEBUG_RIB) {
				inet_ntop(p->family, &p->u.prefix, buf,
					  INET6_ADDRSTRLEN);
				zlog_debug(
					"%u:%s/%d: Modifying route rn %p, re %p (type %d)",
					si->vrf_id, buf, p->prefixlen, rn, re,
					re->type);
			}
		}

		re->uptime = time(NULL);
		/* Schedule route for processing or invoke NHT, as appropriate.
		 */
		if (si->type == STATIC_IPV4_GATEWAY
		    || si->type == STATIC_IPV6_GATEWAY)
			zebra_evaluate_rnh(si->nh_vrf_id, nh_p.family, 1,
					   RNH_NEXTHOP_TYPE, &nh_p);
		else
			rib_queue_add(rn);
	} else {
		/* This is new static route. */
		re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));

		re->type = ZEBRA_ROUTE_STATIC;
		re->instance = 0;
		re->distance = si->distance;
		re->metric = 0;
		re->mtu = 0;
		re->vrf_id = si->vrf_id;
		re->nh_vrf_id = si->nh_vrf_id;
		re->table =
			(si->vrf_id != VRF_DEFAULT)
				? (zebra_vrf_lookup_by_id(si->vrf_id))->table_id
				: zebrad.rtm_table_default;
		re->nexthop_num = 0;
		re->tag = si->tag;

		switch (si->type) {
		case STATIC_IPV4_GATEWAY:
			nexthop = route_entry_nexthop_ipv4_add(
				re, &si->addr.ipv4, NULL);
			nh_p.family = AF_INET;
			nh_p.prefixlen = IPV4_MAX_BITLEN;
			nh_p.u.prefix4 = si->addr.ipv4;
			zebra_register_rnh_static_nh(si->nh_vrf_id, &nh_p, rn);
			break;
		case STATIC_IPV4_GATEWAY_IFNAME:
			nexthop = route_entry_nexthop_ipv4_ifindex_add(
				re, &si->addr.ipv4, NULL, si->ifindex);
			break;
		case STATIC_IFNAME:
			nexthop = route_entry_nexthop_ifindex_add(re,
								  si->ifindex);
			break;
		case STATIC_BLACKHOLE:
			nexthop = route_entry_nexthop_blackhole_add(
				re, bh_type);
			break;
		case STATIC_IPV6_GATEWAY:
			nexthop = route_entry_nexthop_ipv6_add(re,
							       &si->addr.ipv6);
			nh_p.family = AF_INET6;
			nh_p.prefixlen = IPV6_MAX_BITLEN;
			nh_p.u.prefix6 = si->addr.ipv6;
			zebra_register_rnh_static_nh(si->nh_vrf_id, &nh_p, rn);
			break;
		case STATIC_IPV6_GATEWAY_IFNAME:
			nexthop = route_entry_nexthop_ipv6_ifindex_add(
				re, &si->addr.ipv6, si->ifindex);
			break;
		}
		/* Update label(s), if present. */
		if (si->snh_label.num_labels)
			nexthop_add_labels(nexthop, ZEBRA_LSP_STATIC,
					   si->snh_label.num_labels,
					   &si->snh_label.label[0]);

		if (IS_ZEBRA_DEBUG_RIB) {
			char buf[INET6_ADDRSTRLEN];
			if (IS_ZEBRA_DEBUG_RIB) {
				inet_ntop(p->family, &p->u.prefix, buf,
					  INET6_ADDRSTRLEN);
				zlog_debug(
					"%u:%s/%d: Inserting route rn %p, re %p (type %d)",
					si->vrf_id, buf, p->prefixlen, rn, re,
					re->type);
			}
		}
		re->uptime = time(NULL);
		/* Link this re to the tree. Schedule for processing or invoke
		 * NHT,
		 * as appropriate.
		 */
		if (si->type == STATIC_IPV4_GATEWAY
		    || si->type == STATIC_IPV6_GATEWAY) {
			rib_addnode(rn, re, 0);
			zebra_evaluate_rnh(si->nh_vrf_id, nh_p.family, 1,
					   RNH_NEXTHOP_TYPE, &nh_p);
		} else
			rib_addnode(rn, re, 1);
	}
}

/* this works correctly with IFNAME<>IFINDEX because a static route on a
 * non-active interface will have IFINDEX_INTERNAL and thus compare false
 */
static int static_nexthop_same(struct nexthop *nexthop, struct static_route *si)
{
	if (nexthop->type == NEXTHOP_TYPE_BLACKHOLE
	    && si->type == STATIC_BLACKHOLE)
		return 1;

	if (nexthop->type == NEXTHOP_TYPE_IPV4
	    && si->type == STATIC_IPV4_GATEWAY
	    && IPV4_ADDR_SAME(&nexthop->gate.ipv4, &si->addr.ipv4))
		return 1;
	else if (nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX
		 && si->type == STATIC_IPV4_GATEWAY_IFNAME
		 && IPV4_ADDR_SAME(&nexthop->gate.ipv4, &si->addr.ipv4)
		 && nexthop->ifindex == si->ifindex)
		return 1;
	else if (nexthop->type == NEXTHOP_TYPE_IFINDEX
		 && si->type == STATIC_IFNAME
		 && nexthop->ifindex == si->ifindex)
		return 1;
	else if (nexthop->type == NEXTHOP_TYPE_IPV6
		 && si->type == STATIC_IPV6_GATEWAY
		 && IPV6_ADDR_SAME(&nexthop->gate.ipv6, &si->addr.ipv6))
		return 1;
	else if (nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX
		 && si->type == STATIC_IPV6_GATEWAY_IFNAME
		 && IPV6_ADDR_SAME(&nexthop->gate.ipv6, &si->addr.ipv6)
		 && nexthop->ifindex == si->ifindex)
		return 1;

	return 0;
}

/* Uninstall static route from RIB. */
void static_uninstall_route(afi_t afi, safi_t safi, struct prefix *p,
			    struct prefix_ipv6 *src_p, struct static_route *si)
{
	struct route_node *rn;
	struct route_entry *re;
	struct nexthop *nexthop;
	struct route_table *table;
	struct prefix nh_p;

	/* Lookup table.  */
	table = zebra_vrf_table(afi, safi, si->vrf_id);
	if (!table)
		return;

	/* Lookup existing route with type and distance. */
	rn = srcdest_rnode_lookup(table, p, src_p);
	if (!rn)
		return;

	RNODE_FOREACH_RE (rn, re) {
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		if (re->type == ZEBRA_ROUTE_STATIC
		    && re->distance == si->distance && re->tag == si->tag)
			break;
	}

	if (!re) {
		route_unlock_node(rn);
		return;
	}

	/* Lookup nexthop. */
	for (nexthop = re->nexthop; nexthop; nexthop = nexthop->next)
		if (static_nexthop_same(nexthop, si))
			break;

	/* Can't find nexthop. */
	if (!nexthop) {
		route_unlock_node(rn);
		return;
	}

	/* Check nexthop. */
	if (re->nexthop_num == 1)
		rib_delnode(rn, re);
	else {
		/* Mark this nexthop as inactive and reinstall the route. Then,
		 * delete
		 * the nexthop. There is no need to re-evaluate the route for
		 * this
		 * scenario.
		 */
		if (IS_ZEBRA_DEBUG_RIB) {
			char buf[INET6_ADDRSTRLEN];
			if (IS_ZEBRA_DEBUG_RIB) {
				inet_ntop(p->family, &p->u.prefix, buf,
					  INET6_ADDRSTRLEN);
				zlog_debug(
					"%u:%s/%d: Modifying route rn %p, re %p (type %d)",
					si->vrf_id, buf, p->prefixlen, rn, re,
					re->type);
			}
		}
		UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)) {
			rib_dest_t *dest = rib_dest_from_rnode(rn);

			/* If there are other active nexthops, do an update. */
			if (re->nexthop_active_num > 1) {
				/* Update route in kernel if it's in fib */
				if (dest->selected_fib)
					rib_install_kernel(rn, re, re);
				/* Update redistribution if it's selected */
				if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED))
					redistribute_update(
						p, (struct prefix *)src_p, re,
						NULL);
			} else {
				/* Remove from redistribute if selected route
				 * becomes inactive */
				if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED))
					redistribute_delete(
						p, (struct prefix *)src_p, re);
				/* Remove from kernel if fib route becomes
				 * inactive */
				if (dest->selected_fib)
					rib_uninstall_kernel(rn, re);
			}
		}

		if (afi == AFI_IP) {
			/* Delete the nexthop and dereg from NHT */
			nh_p.family = AF_INET;
			nh_p.prefixlen = IPV4_MAX_BITLEN;
			nh_p.u.prefix4 = nexthop->gate.ipv4;
		} else {
			nh_p.family = AF_INET6;
			nh_p.prefixlen = IPV6_MAX_BITLEN;
			nh_p.u.prefix6 = nexthop->gate.ipv6;
		}
		route_entry_nexthop_delete(re, nexthop);
		zebra_deregister_rnh_static_nh(si->vrf_id, &nh_p, rn);
		nexthop_free(nexthop);
	}
	/* Unlock node. */
	route_unlock_node(rn);
}

int static_add_route(afi_t afi, safi_t safi, u_char type, struct prefix *p,
		     struct prefix_ipv6 *src_p, union g_addr *gate,
		     const char *ifname, enum static_blackhole_type bh_type,
		     route_tag_t tag, u_char distance, struct zebra_vrf *zvrf,
		     struct zebra_vrf *nh_zvrf,
		     struct static_nh_label *snh_label)
{
	struct route_node *rn;
	struct static_route *si;
	struct static_route *pp;
	struct static_route *cp;
	struct static_route *update = NULL;
	struct route_table *stable = zvrf->stable[afi][safi];

	if (!stable)
		return -1;

	if (!gate
	    && (type == STATIC_IPV4_GATEWAY
		|| type == STATIC_IPV4_GATEWAY_IFNAME
		|| type == STATIC_IPV6_GATEWAY
		|| type == STATIC_IPV6_GATEWAY_IFNAME))
		return -1;

	if (!ifname
	    && (type == STATIC_IFNAME
		|| type == STATIC_IPV4_GATEWAY_IFNAME
		|| type == STATIC_IPV6_GATEWAY_IFNAME))
		return -1;

	/* Lookup static route prefix. */
	rn = srcdest_rnode_get(stable, p, src_p);

	/* Do nothing if there is a same static route.  */
	for (si = rn->info; si; si = si->next) {
		if (type == si->type
		    && (!gate || ((afi == AFI_IP
				   && IPV4_ADDR_SAME(&gate->ipv4, &si->addr.ipv4))
				  || (afi == AFI_IP6
				      && IPV6_ADDR_SAME(gate, &si->addr.ipv6))))
		    && (!strcmp (ifname ? ifname : "", si->ifname))) {
			if ((distance == si->distance) && (tag == si->tag)
			    && !memcmp(&si->snh_label, snh_label,
				       sizeof(struct static_nh_label))
			    && si->bh_type == bh_type) {
				route_unlock_node(rn);
				return 0;
			} else
				update = si;
		}
	}

	/* Distance or tag or label changed, delete existing first. */
	if (update)
		static_delete_route(afi, safi, type, p, src_p, gate, ifname,
				    update->tag, update->distance, zvrf,
				    &update->snh_label);

	/* Make new static route structure. */
	si = XCALLOC(MTYPE_STATIC_ROUTE, sizeof(struct static_route));

	si->type = type;
	si->distance = distance;
	si->bh_type = bh_type;
	si->tag = tag;
	si->vrf_id = zvrf_id(zvrf);
	si->nh_vrf_id = zvrf_id(nh_zvrf);

	if (ifname)
		strlcpy(si->ifname, ifname, sizeof(si->ifname));
	si->ifindex = IFINDEX_INTERNAL;

	switch (type) {
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		si->addr.ipv4 = gate->ipv4;
		break;
	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		si->addr.ipv6 = gate->ipv6;
		break;
	case STATIC_IFNAME:
		break;
	}

	/* Save labels, if any. */
	memcpy(&si->snh_label, snh_label, sizeof(struct static_nh_label));

	/* Add new static route information to the tree with sort by
	   distance value and gateway address. */
	for (pp = NULL, cp = rn->info; cp; pp = cp, cp = cp->next) {
		if (si->distance < cp->distance)
			break;
		if (si->distance > cp->distance)
			continue;
		if (si->type == STATIC_IPV4_GATEWAY
		    && cp->type == STATIC_IPV4_GATEWAY) {
			if (ntohl(si->addr.ipv4.s_addr)
			    < ntohl(cp->addr.ipv4.s_addr))
				break;
			if (ntohl(si->addr.ipv4.s_addr)
			    > ntohl(cp->addr.ipv4.s_addr))
				continue;
		}
	}

	/* Make linked list. */
	if (pp)
		pp->next = si;
	else
		rn->info = si;
	if (cp)
		cp->prev = si;
	si->prev = pp;
	si->next = cp;

	/* check whether interface exists in system & install if it does */
	if (!ifname)
		static_install_route(afi, safi, p, src_p, si);
	else {
		struct interface *ifp;

		ifp = if_lookup_by_name(ifname, zvrf_id(nh_zvrf));
		if (ifp && ifp->ifindex != IFINDEX_INTERNAL) {
			si->ifindex = ifp->ifindex;
			static_install_route(afi, safi, p, src_p, si);
		}
	}

	return 1;
}

int static_delete_route(afi_t afi, safi_t safi, u_char type, struct prefix *p,
			struct prefix_ipv6 *src_p, union g_addr *gate,
			const char *ifname, route_tag_t tag, u_char distance,
			struct zebra_vrf *zvrf,
			struct static_nh_label *snh_label)
{
	struct route_node *rn;
	struct static_route *si;
	struct route_table *stable;

	/* Lookup table.  */
	stable = zebra_vrf_static_table(afi, safi, zvrf);
	if (!stable)
		return -1;

	/* Lookup static route prefix. */
	rn = srcdest_rnode_lookup(stable, p, src_p);
	if (!rn)
		return 0;

	/* Find same static route is the tree */
	for (si = rn->info; si; si = si->next)
		if (type == si->type
		    && (!gate || ((afi == AFI_IP
				   && IPV4_ADDR_SAME(&gate->ipv4, &si->addr.ipv4))
				  || (afi == AFI_IP6
				      && IPV6_ADDR_SAME(gate, &si->addr.ipv6))))
		    && (!strcmp(ifname ? ifname : "", si->ifname))
		    && (!tag || (tag == si->tag))
		    && (!snh_label->num_labels
			|| !memcmp(&si->snh_label, snh_label,
				   sizeof(struct static_nh_label))))
			break;

	/* Can't find static route. */
	if (!si) {
		route_unlock_node(rn);
		return 0;
	}

	/* Uninstall from rib. */
	if (!si->ifname[0] || si->ifindex != IFINDEX_INTERNAL)
		static_uninstall_route(afi, safi, p, src_p, si);

	/* Unlink static route from linked list. */
	if (si->prev)
		si->prev->next = si->next;
	else
		rn->info = si->next;
	if (si->next)
		si->next->prev = si->prev;
	route_unlock_node(rn);

	/* Free static route configuration. */
	XFREE(MTYPE_STATIC_ROUTE, si);

	route_unlock_node(rn);

	return 1;
}

static void static_ifindex_update_af(struct interface *ifp, bool up,
				     afi_t afi, safi_t safi)
{
	struct route_table *stable;
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(ifp->vrf_id);
	struct route_node *rn;
	struct static_route *si;
	struct prefix *p, *src_pp;
	struct prefix_ipv6 *src_p;

	stable = zebra_vrf_static_table(afi, safi, zvrf);
	if (!stable)
		return;

	for (rn = route_top(stable); rn; rn = srcdest_route_next(rn)) {
		srcdest_rnode_prefixes(rn, &p, &src_pp);
		src_p = (struct prefix_ipv6 *)src_pp;

		for (si = rn->info; si; si = si->next) {
			if (!si->ifname[0])
				continue;
			if (up) {
				if (strcmp(si->ifname, ifp->name))
					continue;
				si->ifindex = ifp->ifindex;
				static_install_route(afi, safi, p, src_p, si);
			} else {
				if (si->ifindex != ifp->ifindex)
					continue;
				static_uninstall_route(afi, safi, p, src_p,
						       si);
				si->ifindex = IFINDEX_INTERNAL;
			}
		}
	}
}

/* called from if_{add,delete}_update, i.e. when ifindex becomes [in]valid */
void static_ifindex_update(struct interface *ifp, bool up)
{
	static_ifindex_update_af(ifp, up, AFI_IP, SAFI_UNICAST);
	static_ifindex_update_af(ifp, up, AFI_IP, SAFI_MULTICAST);
	static_ifindex_update_af(ifp, up, AFI_IP6, SAFI_UNICAST);
	static_ifindex_update_af(ifp, up, AFI_IP6, SAFI_MULTICAST);
}
