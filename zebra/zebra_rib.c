/* Routing Information Base.
 * Copyright (C) 1997, 98, 99, 2001 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
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
#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "zebra_memory.h"
#include "command.h"
#include "log.h"
#include "log_int.h"
#include "sockunion.h"
#include "linklist.h"
#include "thread.h"
#include "workqueue.h"
#include "prefix.h"
#include "routemap.h"
#include "nexthop.h"
#include "vrf.h"
#include "mpls.h"
#include "srcdest_table.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zebra_ns.h"
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "zebra/debug.h"
#include "zebra/zebra_rnh.h"
#include "zebra/interface.h"
#include "zebra/connected.h"

DEFINE_HOOK(rib_update, (struct route_node * rn, const char *reason),
	    (rn, reason))

/* Should we allow non Quagga processes to delete our routes */
extern int allow_delete;

/* Hold time for RIB process, should be very minimal.
 * it is useful to able to set it otherwise for testing, hence exported
 * as global here for test-rig code.
 */
int rib_process_hold_time = 10;

/* Each route type's string and default distance value. */
static const struct {
	int key;
	int distance;
} route_info[ZEBRA_ROUTE_MAX] = {
		[ZEBRA_ROUTE_SYSTEM] = {ZEBRA_ROUTE_SYSTEM, 0},
		[ZEBRA_ROUTE_KERNEL] = {ZEBRA_ROUTE_KERNEL, 0},
		[ZEBRA_ROUTE_CONNECT] = {ZEBRA_ROUTE_CONNECT, 0},
		[ZEBRA_ROUTE_STATIC] = {ZEBRA_ROUTE_STATIC, 1},
		[ZEBRA_ROUTE_RIP] = {ZEBRA_ROUTE_RIP, 120},
		[ZEBRA_ROUTE_RIPNG] = {ZEBRA_ROUTE_RIPNG, 120},
		[ZEBRA_ROUTE_OSPF] = {ZEBRA_ROUTE_OSPF, 110},
		[ZEBRA_ROUTE_OSPF6] = {ZEBRA_ROUTE_OSPF6, 110},
		[ZEBRA_ROUTE_ISIS] = {ZEBRA_ROUTE_ISIS, 115},
		[ZEBRA_ROUTE_BGP] = {ZEBRA_ROUTE_BGP, 20 /* IBGP is 200. */},
		[ZEBRA_ROUTE_NHRP] = {ZEBRA_ROUTE_NHRP, 10},
	/* no entry/default: 150 */
};

/* RPF lookup behaviour */
static enum multicast_mode ipv4_multicast_mode = MCAST_NO_CONFIG;


static void __attribute__((format(printf, 5, 6)))
_rnode_zlog(const char *_func, vrf_id_t vrf_id, struct route_node *rn,
	    int priority, const char *msgfmt, ...)
{
	char buf[SRCDEST2STR_BUFFER + sizeof(" (MRIB)")];
	char msgbuf[512];
	va_list ap;

	va_start(ap, msgfmt);
	vsnprintf(msgbuf, sizeof(msgbuf), msgfmt, ap);
	va_end(ap);

	if (rn) {
		rib_table_info_t *info = srcdest_rnode_table_info(rn);
		srcdest_rnode2str(rn, buf, sizeof(buf));

		if (info->safi == SAFI_MULTICAST)
			strcat(buf, " (MRIB)");
	} else {
		snprintf(buf, sizeof(buf), "{(route_node *) NULL}");
	}

	zlog(priority, "%s: %d:%s: %s", _func, vrf_id, buf, msgbuf);
}

#define rnode_debug(node, vrf_id, ...)                                         \
	_rnode_zlog(__func__, vrf_id, node, LOG_DEBUG, __VA_ARGS__)
#define rnode_info(node, ...)                                                  \
	_rnode_zlog(__func__, vrf_id, node, LOG_INFO, __VA_ARGS__)

u_char route_distance(int type)
{
	u_char distance;

	if ((unsigned)type >= array_size(route_info))
		distance = 150;
	else
		distance = route_info[type].distance;

	return distance;
}

int is_zebra_valid_kernel_table(u_int32_t table_id)
{
	if ((table_id > ZEBRA_KERNEL_TABLE_MAX))
		return 0;

#ifdef linux
	if ((table_id == RT_TABLE_UNSPEC) || (table_id == RT_TABLE_LOCAL)
	    || (table_id == RT_TABLE_COMPAT))
		return 0;
#endif

	return 1;
}

int is_zebra_main_routing_table(u_int32_t table_id)
{
	if ((table_id == RT_TABLE_MAIN)
	    || (table_id == zebrad.rtm_table_default))
		return 1;
	return 0;
}

int zebra_check_addr(struct prefix *p)
{
	if (p->family == AF_INET) {
		u_int32_t addr;

		addr = p->u.prefix4.s_addr;
		addr = ntohl(addr);

		if (IPV4_NET127(addr) || IN_CLASSD(addr)
		    || IPV4_LINKLOCAL(addr))
			return 0;
	}
	if (p->family == AF_INET6) {
		if (IN6_IS_ADDR_LOOPBACK(&p->u.prefix6))
			return 0;
		if (IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6))
			return 0;
	}
	return 1;
}

/* Add nexthop to the end of a rib node's nexthop list */
void route_entry_nexthop_add(struct route_entry *re, struct nexthop *nexthop)
{
	nexthop_add(&re->nexthop, nexthop);
	re->nexthop_num++;
}


/**
 * copy_nexthop - copy a nexthop to the rib structure.
 */
void route_entry_copy_nexthops(struct route_entry *re, struct nexthop *nh)
{
	assert(!re->nexthop);
	copy_nexthops(&re->nexthop, nh, NULL);
	for (struct nexthop *nexthop = nh; nexthop; nexthop = nexthop->next)
		re->nexthop_num++;
}

/* Delete specified nexthop from the list. */
void route_entry_nexthop_delete(struct route_entry *re, struct nexthop *nexthop)
{
	if (nexthop->next)
		nexthop->next->prev = nexthop->prev;
	if (nexthop->prev)
		nexthop->prev->next = nexthop->next;
	else
		re->nexthop = nexthop->next;
	re->nexthop_num--;
}


struct nexthop *route_entry_nexthop_ifindex_add(struct route_entry *re,
						ifindex_t ifindex)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->type = NEXTHOP_TYPE_IFINDEX;
	nexthop->ifindex = ifindex;

	route_entry_nexthop_add(re, nexthop);

	return nexthop;
}

struct nexthop *route_entry_nexthop_ipv4_add(struct route_entry *re,
					     struct in_addr *ipv4,
					     struct in_addr *src)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->type = NEXTHOP_TYPE_IPV4;
	nexthop->gate.ipv4 = *ipv4;
	if (src)
		nexthop->src.ipv4 = *src;

	route_entry_nexthop_add(re, nexthop);

	return nexthop;
}

struct nexthop *route_entry_nexthop_ipv4_ifindex_add(struct route_entry *re,
						     struct in_addr *ipv4,
						     struct in_addr *src,
						     ifindex_t ifindex)
{
	struct nexthop *nexthop;
	struct interface *ifp;

	nexthop = nexthop_new();
	nexthop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
	nexthop->gate.ipv4 = *ipv4;
	if (src)
		nexthop->src.ipv4 = *src;
	nexthop->ifindex = ifindex;
	ifp = if_lookup_by_index(nexthop->ifindex, VRF_DEFAULT);
	/*Pending: need to think if null ifp here is ok during bootup?
	  There was a crash because ifp here was coming to be NULL */
	if (ifp)
		if (connected_is_unnumbered(ifp)) {
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK);
		}

	route_entry_nexthop_add(re, nexthop);

	return nexthop;
}

struct nexthop *route_entry_nexthop_ipv6_add(struct route_entry *re,
					     struct in6_addr *ipv6)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->type = NEXTHOP_TYPE_IPV6;
	nexthop->gate.ipv6 = *ipv6;

	route_entry_nexthop_add(re, nexthop);

	return nexthop;
}

struct nexthop *route_entry_nexthop_ipv6_ifindex_add(struct route_entry *re,
						     struct in6_addr *ipv6,
						     ifindex_t ifindex)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
	nexthop->gate.ipv6 = *ipv6;
	nexthop->ifindex = ifindex;

	route_entry_nexthop_add(re, nexthop);

	return nexthop;
}

struct nexthop *route_entry_nexthop_blackhole_add(struct route_entry *re,
						  enum blackhole_type bh_type)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->type = NEXTHOP_TYPE_BLACKHOLE;
	nexthop->bh_type = bh_type;

	route_entry_nexthop_add(re, nexthop);

	return nexthop;
}

static void nexthop_set_resolved(afi_t afi, struct nexthop *newhop,
				 struct nexthop *nexthop)
{
	struct nexthop *resolved_hop;

	resolved_hop = nexthop_new();
	SET_FLAG(resolved_hop->flags, NEXTHOP_FLAG_ACTIVE);
	/* If the resolving route specifies a gateway, use it */
	if (newhop->type == NEXTHOP_TYPE_IPV4
	    || newhop->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
		resolved_hop->type = newhop->type;
		resolved_hop->gate.ipv4 = newhop->gate.ipv4;

		if (newhop->ifindex) {
			resolved_hop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			resolved_hop->ifindex = newhop->ifindex;
			if (newhop->flags & NEXTHOP_FLAG_ONLINK)
				resolved_hop->flags |= NEXTHOP_FLAG_ONLINK;
		}
	}
	if (newhop->type == NEXTHOP_TYPE_IPV6
	    || newhop->type == NEXTHOP_TYPE_IPV6_IFINDEX) {
		resolved_hop->type = newhop->type;
		resolved_hop->gate.ipv6 = newhop->gate.ipv6;

		if (newhop->ifindex) {
			resolved_hop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			resolved_hop->ifindex = newhop->ifindex;
		}
	}

	/* If the resolving route is an interface route,
	 * it means the gateway we are looking up is connected
	 * to that interface. (The actual network is _not_ onlink).
	 * Therefore, the resolved route should have the original
	 * gateway as nexthop as it is directly connected.
	 *
	 * On Linux, we have to set the onlink netlink flag because
	 * otherwise, the kernel won't accept the route.
	 */
	if (newhop->type == NEXTHOP_TYPE_IFINDEX) {
		resolved_hop->flags |= NEXTHOP_FLAG_ONLINK;
		if (afi == AFI_IP) {
			resolved_hop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			resolved_hop->gate.ipv4 = nexthop->gate.ipv4;
		} else if (afi == AFI_IP6) {
			resolved_hop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			resolved_hop->gate.ipv6 = nexthop->gate.ipv6;
		}
		resolved_hop->ifindex = newhop->ifindex;
	}

	resolved_hop->rparent = nexthop;
	nexthop_add(&nexthop->resolved, resolved_hop);
}

/* If force flag is not set, do not modify falgs at all for uninstall
   the route from FIB. */
static int nexthop_active(afi_t afi, struct route_entry *re,
			  struct nexthop *nexthop, int set,
			  struct route_node *top)
{
	struct prefix p;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *match;
	int resolved;
	struct nexthop *newhop;
	struct interface *ifp;

	if ((nexthop->type == NEXTHOP_TYPE_IPV4)
	    || nexthop->type == NEXTHOP_TYPE_IPV6)
		nexthop->ifindex = 0;

	if (set) {
		UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
		zebra_deregister_rnh_static_nexthops(re->vrf_id,
						     nexthop->resolved, top);
		nexthops_free(nexthop->resolved);
		nexthop->resolved = NULL;
		re->nexthop_mtu = 0;
	}

	/* Skip nexthops that have been filtered out due to route-map */
	/* The nexthops are specific to this route and so the same */
	/* nexthop for a different route may not have this flag set */
	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FILTERED))
		return 0;

	/*
	 * Check to see if we should trust the passed in information
	 * for UNNUMBERED interfaces as that we won't find the GW
	 * address in the routing table.
	 */
	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK)) {
		ifp = if_lookup_by_index(nexthop->ifindex, VRF_DEFAULT);
		if (ifp && connected_is_unnumbered(ifp)) {
			if (if_is_operative(ifp))
				return 1;
			else
				return 0;
		} else
			return 0;
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
	table = zebra_vrf_table(afi, SAFI_UNICAST, re->vrf_id);
	if (!table)
		return 0;

	rn = route_node_match(table, (struct prefix *)&p);
	while (rn) {
		route_unlock_node(rn);

		/* If lookup self prefix return immediately. */
		if (rn == top)
			return 0;

		/* Pick up selected route. */
		/* However, do not resolve over default route unless explicitly
		 * allowed. */
		if (is_default_prefix(&rn->p)
		    && !nh_resolve_via_default(p.family))
			return 0;

		RNODE_FOREACH_RE(rn, match)
		{
			if (CHECK_FLAG(match->status, ROUTE_ENTRY_REMOVED))
				continue;

			/* if the next hop is imported from another table, skip
			 * it */
			if (match->type == ZEBRA_ROUTE_TABLE)
				continue;
			if (CHECK_FLAG(match->status, ROUTE_ENTRY_SELECTED_FIB))
				break;
		}

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
			newhop = match->nexthop;
			if (newhop) {
				if (nexthop->type == NEXTHOP_TYPE_IPV4
				    || nexthop->type == NEXTHOP_TYPE_IPV6)
					nexthop->ifindex = newhop->ifindex;
			}
			return 1;
		} else if (CHECK_FLAG(re->flags, ZEBRA_FLAG_INTERNAL)) {
			resolved = 0;
			for (ALL_NEXTHOPS(match->nexthop, newhop)) {
				if (newhop->type == NEXTHOP_TYPE_BLACKHOLE)
					continue;
				if (!CHECK_FLAG(newhop->flags,
						NEXTHOP_FLAG_FIB))
					continue;
				if (CHECK_FLAG(newhop->flags,
					       NEXTHOP_FLAG_RECURSIVE))
					continue;

				if (set) {
					SET_FLAG(nexthop->flags,
						 NEXTHOP_FLAG_RECURSIVE);
					SET_FLAG(re->status,
						 ROUTE_ENTRY_NEXTHOPS_CHANGED);
					nexthop_set_resolved(afi, newhop,
							     nexthop);
				}
				resolved = 1;
			}
			if (resolved && set)
				re->nexthop_mtu = match->mtu;
			return resolved;
		} else if (re->type == ZEBRA_ROUTE_STATIC) {
			resolved = 0;
			for (ALL_NEXTHOPS(match->nexthop, newhop)) {
				if (newhop->type == NEXTHOP_TYPE_BLACKHOLE)
					continue;
				if (!CHECK_FLAG(newhop->flags,
						NEXTHOP_FLAG_FIB))
					continue;

				if (set) {
					SET_FLAG(nexthop->flags,
						 NEXTHOP_FLAG_RECURSIVE);
					nexthop_set_resolved(afi, newhop,
							     nexthop);
				}
				resolved = 1;
			}
			if (resolved && set)
				re->nexthop_mtu = match->mtu;
			return resolved;
		} else {
			return 0;
		}
	}
	return 0;
}

struct route_entry *rib_match(afi_t afi, safi_t safi, vrf_id_t vrf_id,
			      union g_addr *addr, struct route_node **rn_out)
{
	struct prefix p;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *match;
	struct nexthop *newhop;

	/* Lookup table.  */
	table = zebra_vrf_table(afi, safi, vrf_id);
	if (!table)
		return 0;

	memset(&p, 0, sizeof(struct prefix));
	p.family = afi;
	if (afi == AFI_IP) {
		p.u.prefix4 = addr->ipv4;
		p.prefixlen = IPV4_MAX_PREFIXLEN;
	} else {
		p.u.prefix6 = addr->ipv6;
		p.prefixlen = IPV6_MAX_PREFIXLEN;
	}

	rn = route_node_match(table, (struct prefix *)&p);

	while (rn) {
		route_unlock_node(rn);

		/* Pick up selected route. */
		RNODE_FOREACH_RE(rn, match)
		{
			if (CHECK_FLAG(match->status, ROUTE_ENTRY_REMOVED))
				continue;
			if (CHECK_FLAG(match->status, ROUTE_ENTRY_SELECTED_FIB))
				break;
		}

		/* If there is no selected route or matched route is EGP, go up
		   tree. */
		if (!match) {
			do {
				rn = rn->parent;
			} while (rn && rn->info == NULL);
			if (rn)
				route_lock_node(rn);
		} else {
			if (match->type != ZEBRA_ROUTE_CONNECT) {
				int found = 0;
				for (ALL_NEXTHOPS(match->nexthop, newhop))
					if (CHECK_FLAG(newhop->flags,
						       NEXTHOP_FLAG_FIB)) {
						found = 1;
						break;
					}
				if (!found)
					return NULL;
			}

			if (rn_out)
				*rn_out = rn;
			return match;
		}
	}
	return NULL;
}

struct route_entry *rib_match_ipv4_multicast(vrf_id_t vrf_id,
					     struct in_addr addr,
					     struct route_node **rn_out)
{
	struct route_entry *re = NULL, *mre = NULL, *ure = NULL;
	struct route_node *m_rn = NULL, *u_rn = NULL;
	union g_addr gaddr = {.ipv4 = addr};

	switch (ipv4_multicast_mode) {
	case MCAST_MRIB_ONLY:
		return rib_match(AFI_IP, SAFI_MULTICAST, vrf_id, &gaddr,
				 rn_out);
	case MCAST_URIB_ONLY:
		return rib_match(AFI_IP, SAFI_UNICAST, vrf_id, &gaddr, rn_out);
	case MCAST_NO_CONFIG:
	case MCAST_MIX_MRIB_FIRST:
		re = mre = rib_match(AFI_IP, SAFI_MULTICAST, vrf_id, &gaddr,
				     &m_rn);
		if (!mre)
			re = ure = rib_match(AFI_IP, SAFI_UNICAST, vrf_id,
					     &gaddr, &u_rn);
		break;
	case MCAST_MIX_DISTANCE:
		mre = rib_match(AFI_IP, SAFI_MULTICAST, vrf_id, &gaddr, &m_rn);
		ure = rib_match(AFI_IP, SAFI_UNICAST, vrf_id, &gaddr, &u_rn);
		if (mre && ure)
			re = ure->distance < mre->distance ? ure : mre;
		else if (mre)
			re = mre;
		else if (ure)
			re = ure;
		break;
	case MCAST_MIX_PFXLEN:
		mre = rib_match(AFI_IP, SAFI_MULTICAST, vrf_id, &gaddr, &m_rn);
		ure = rib_match(AFI_IP, SAFI_UNICAST, vrf_id, &gaddr, &u_rn);
		if (mre && ure)
			re = u_rn->p.prefixlen > m_rn->p.prefixlen ? ure : mre;
		else if (mre)
			re = mre;
		else if (ure)
			re = ure;
		break;
	}

	if (rn_out)
		*rn_out = (re == mre) ? m_rn : u_rn;

	if (IS_ZEBRA_DEBUG_RIB) {
		char buf[BUFSIZ];
		inet_ntop(AF_INET, &addr, buf, BUFSIZ);

		zlog_debug("%s: %s: found %s, using %s", __func__, buf,
			   mre ? (ure ? "MRIB+URIB" : "MRIB")
			       : ure ? "URIB" : "nothing",
			   re == ure ? "URIB" : re == mre ? "MRIB" : "none");
	}
	return re;
}

void multicast_mode_ipv4_set(enum multicast_mode mode)
{
	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: multicast lookup mode set (%d)", __func__,
			   mode);
	ipv4_multicast_mode = mode;
}

enum multicast_mode multicast_mode_ipv4_get(void)
{
	return ipv4_multicast_mode;
}

struct route_entry *rib_lookup_ipv4(struct prefix_ipv4 *p, vrf_id_t vrf_id)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *match;
	struct nexthop *nexthop;

	/* Lookup table.  */
	table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, vrf_id);
	if (!table)
		return 0;

	rn = route_node_lookup(table, (struct prefix *)p);

	/* No route for this prefix. */
	if (!rn)
		return NULL;

	/* Unlock node. */
	route_unlock_node(rn);

	RNODE_FOREACH_RE(rn, match)
	{
		if (CHECK_FLAG(match->status, ROUTE_ENTRY_REMOVED))
			continue;
		if (CHECK_FLAG(match->status, ROUTE_ENTRY_SELECTED_FIB))
			break;
	}

	if (!match)
		return NULL;

	if (match->type == ZEBRA_ROUTE_CONNECT)
		return match;

	for (ALL_NEXTHOPS(match->nexthop, nexthop))
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
			return match;

	return NULL;
}

/*
 * This clone function, unlike its original rib_lookup_ipv4(), checks
 * if specified IPv4 route record (prefix/mask -> gate) exists in
 * the whole RIB and has ROUTE_ENTRY_SELECTED_FIB set.
 *
 * Return values:
 * -1: error
 * 0: exact match found
 * 1: a match was found with a different gate
 * 2: connected route found
 * 3: no matches found
 */
int rib_lookup_ipv4_route(struct prefix_ipv4 *p, union sockunion *qgate,
			  vrf_id_t vrf_id)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *match;
	struct nexthop *nexthop;
	int nexthops_active;

	/* Lookup table.  */
	table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, vrf_id);
	if (!table)
		return ZEBRA_RIB_LOOKUP_ERROR;

	/* Scan the RIB table for exactly matching RIB entry. */
	rn = route_node_lookup(table, (struct prefix *)p);

	/* No route for this prefix. */
	if (!rn)
		return ZEBRA_RIB_NOTFOUND;

	/* Unlock node. */
	route_unlock_node(rn);

	/* Find out if a "selected" RR for the discovered RIB entry exists ever.
	 */
	RNODE_FOREACH_RE(rn, match)
	{
		if (CHECK_FLAG(match->status, ROUTE_ENTRY_REMOVED))
			continue;
		if (CHECK_FLAG(match->status, ROUTE_ENTRY_SELECTED_FIB))
			break;
	}

	/* None such found :( */
	if (!match)
		return ZEBRA_RIB_NOTFOUND;

	if (match->type == ZEBRA_ROUTE_CONNECT)
		return ZEBRA_RIB_FOUND_CONNECTED;

	/* Ok, we have a cood candidate, let's check it's nexthop list... */
	nexthops_active = 0;
	for (ALL_NEXTHOPS(match->nexthop, nexthop))
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)) {
			nexthops_active = 1;
			if (nexthop->gate.ipv4.s_addr == sockunion2ip(qgate))
				return ZEBRA_RIB_FOUND_EXACT;
			if (IS_ZEBRA_DEBUG_RIB) {
				char gate_buf[INET_ADDRSTRLEN],
					qgate_buf[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &nexthop->gate.ipv4.s_addr,
					  gate_buf, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &sockunion2ip(qgate),
					  qgate_buf, INET_ADDRSTRLEN);
				zlog_debug("%s: qgate == %s, %s == %s",
					   __func__, qgate_buf,
					   nexthop->rparent ? "rgate" : "gate",
					   gate_buf);
			}
		}

	if (nexthops_active)
		return ZEBRA_RIB_FOUND_NOGATE;

	return ZEBRA_RIB_NOTFOUND;
}

#define RIB_SYSTEM_ROUTE(R)                                                    \
	((R)->type == ZEBRA_ROUTE_KERNEL || (R)->type == ZEBRA_ROUTE_CONNECT)

/* This function verifies reachability of one given nexthop, which can be
 * numbered or unnumbered, IPv4 or IPv6. The result is unconditionally stored
 * in nexthop->flags field. If the 4th parameter, 'set', is non-zero,
 * nexthop->ifindex will be updated appropriately as well.
 * An existing route map can turn (otherwise active) nexthop into inactive, but
 * not vice versa.
 *
 * The return value is the final value of 'ACTIVE' flag.
 */

static unsigned nexthop_active_check(struct route_node *rn,
				     struct route_entry *re,
				     struct nexthop *nexthop, int set)
{
	struct interface *ifp;
	route_map_result_t ret = RMAP_MATCH;
	int family;
	char buf[SRCDEST2STR_BUFFER];
	struct prefix *p, *src_p;
	srcdest_rnode_prefixes(rn, &p, &src_p);

	if (rn->p.family == AF_INET)
		family = AFI_IP;
	else if (rn->p.family == AF_INET6)
		family = AFI_IP6;
	else
		family = 0;
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:
		ifp = if_lookup_by_index(nexthop->ifindex, re->vrf_id);
		if (ifp && if_is_operative(ifp))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		family = AFI_IP;
		if (nexthop_active(AFI_IP, re, nexthop, set, rn))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	case NEXTHOP_TYPE_IPV6:
		family = AFI_IP6;
		if (nexthop_active(AFI_IP6, re, nexthop, set, rn))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		/* RFC 5549, v4 prefix with v6 NH */
		if (rn->p.family != AF_INET)
			family = AFI_IP6;
		if (IN6_IS_ADDR_LINKLOCAL(&nexthop->gate.ipv6)) {
			ifp = if_lookup_by_index(nexthop->ifindex, re->vrf_id);
			if (ifp && if_is_operative(ifp))
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
			else
				UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		} else {
			if (nexthop_active(AFI_IP6, re, nexthop, set, rn))
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
	if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
		return 0;

	/* XXX: What exactly do those checks do? Do we support
	 * e.g. IPv4 routes with IPv6 nexthops or vice versa? */
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

	/* It'll get set if required inside */
	ret = zebra_route_map_check(family, re->type, p, nexthop, re->vrf_id,
				    re->tag);
	if (ret == RMAP_DENYMATCH) {
		if (IS_ZEBRA_DEBUG_RIB) {
			srcdest_rnode2str(rn, buf, sizeof(buf));
			zlog_debug(
				"%u:%s: Filtering out with NH out %s due to route map",
				re->vrf_id, buf,
				ifindex2ifname(nexthop->ifindex, re->vrf_id));
		}
		UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}
	return CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
}

/* Iterate over all nexthops of the given RIB entry and refresh their
 * ACTIVE flag. re->nexthop_active_num is updated accordingly. If any
 * nexthop is found to toggle the ACTIVE flag, the whole re structure
 * is flagged with ROUTE_ENTRY_CHANGED. The 4th 'set' argument is
 * transparently passed to nexthop_active_check().
 *
 * Return value is the new number of active nexthops.
 */

static int nexthop_active_update(struct route_node *rn, struct route_entry *re,
				 int set)
{
	struct nexthop *nexthop;
	union g_addr prev_src;
	unsigned int prev_active, new_active, old_num_nh;
	ifindex_t prev_index;
	old_num_nh = re->nexthop_active_num;

	re->nexthop_active_num = 0;
	UNSET_FLAG(re->status, ROUTE_ENTRY_CHANGED);

	for (nexthop = re->nexthop; nexthop; nexthop = nexthop->next) {
		/* No protocol daemon provides src and so we're skipping
		 * tracking it */
		prev_src = nexthop->rmap_src;
		prev_active = CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		prev_index = nexthop->ifindex;
		if ((new_active = nexthop_active_check(rn, re, nexthop, set)))
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
					    &nexthop->rmap_src.ipv6)))) {
			SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
			SET_FLAG(re->status, ROUTE_ENTRY_NEXTHOPS_CHANGED);
		}
	}

	if (old_num_nh != re->nexthop_active_num)
		SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);

	if (CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED)) {
		SET_FLAG(re->status, ROUTE_ENTRY_NEXTHOPS_CHANGED);
	}

	return re->nexthop_active_num;
}

/*
 * Is this RIB labeled-unicast? It must be of type BGP and all paths
 * (nexthops) must have a label.
 */
int zebra_rib_labeled_unicast(struct route_entry *re)
{
	struct nexthop *nexthop = NULL;

	if (re->type != ZEBRA_ROUTE_BGP)
		return 0;

	for (ALL_NEXTHOPS(re->nexthop, nexthop))
		if (!nexthop->nh_label || !nexthop->nh_label->num_labels)
			return 0;

	return 1;
}

/* Update flag indicates whether this is a "replace" or not. Currently, this
 * is only used for IPv4.
 */
int rib_install_kernel(struct route_node *rn, struct route_entry *re,
		       struct route_entry *old)
{
	int ret = 0;
	struct nexthop *nexthop;
	rib_table_info_t *info = srcdest_rnode_table_info(rn);
	struct prefix *p, *src_p;
	struct zebra_vrf *zvrf = vrf_info_lookup(re->vrf_id);

	srcdest_rnode_prefixes(rn, &p, &src_p);

	if (info->safi != SAFI_UNICAST) {
		for (ALL_NEXTHOPS(re->nexthop, nexthop))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
		return ret;
	}

	/*
	 * Make sure we update the FPM any time we send new information to
	 * the kernel.
	 */
	hook_call(rib_update, rn, "installing in kernel");
	ret = kernel_route_rib(p, src_p, old, re);
	zvrf->installs++;

	/* If install succeeds, update FIB flag for nexthops. */
	if (!ret) {
		for (ALL_NEXTHOPS(re->nexthop, nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
			else
				UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
		}
	}

	return ret;
}

/* Uninstall the route from kernel. */
int rib_uninstall_kernel(struct route_node *rn, struct route_entry *re)
{
	int ret = 0;
	struct nexthop *nexthop;
	rib_table_info_t *info = srcdest_rnode_table_info(rn);
	struct prefix *p, *src_p;
	struct zebra_vrf *zvrf = vrf_info_lookup(re->vrf_id);

	srcdest_rnode_prefixes(rn, &p, &src_p);

	if (info->safi != SAFI_UNICAST) {
		for (ALL_NEXTHOPS(re->nexthop, nexthop))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
		return ret;
	}

	/*
	 * Make sure we update the FPM any time we send new information to
	 * the kernel.
	 */
	hook_call(rib_update, rn, "uninstalling from kernel");
	ret = kernel_route_rib(p, src_p, re, NULL);
	zvrf->removals++;

	for (ALL_NEXTHOPS(re->nexthop, nexthop))
		UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);

	return ret;
}

/* Uninstall the route from kernel. */
static void rib_uninstall(struct route_node *rn, struct route_entry *re)
{
	rib_table_info_t *info = srcdest_rnode_table_info(rn);

	if (CHECK_FLAG(re->status, ROUTE_ENTRY_SELECTED_FIB)) {
		if (info->safi == SAFI_UNICAST)
			hook_call(rib_update, rn, "rib_uninstall");

		if (!RIB_SYSTEM_ROUTE(re))
			rib_uninstall_kernel(rn, re);

		/* If labeled-unicast route, uninstall transit LSP. */
		if (zebra_rib_labeled_unicast(re))
			zebra_mpls_lsp_uninstall(info->zvrf, rn, re);

		UNSET_FLAG(re->status, ROUTE_ENTRY_SELECTED_FIB);
	}

	if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED)) {
		struct prefix *p, *src_p;
		srcdest_rnode_prefixes(rn, &p, &src_p);

		redistribute_delete(p, src_p, re);
		UNSET_FLAG(re->flags, ZEBRA_FLAG_SELECTED);
	}
}

/*
 * rib_can_delete_dest
 *
 * Returns TRUE if the given dest can be deleted from the table.
 */
static int rib_can_delete_dest(rib_dest_t *dest)
{
	if (dest->routes) {
		return 0;
	}

	/*
	 * Don't delete the dest if we have to update the FPM about this
	 * prefix.
	 */
	if (CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_FPM)
	    || CHECK_FLAG(dest->flags, RIB_DEST_SENT_TO_FPM))
		return 0;

	return 1;
}

/*
 * rib_gc_dest
 *
 * Garbage collect the rib dest corresponding to the given route node
 * if appropriate.
 *
 * Returns TRUE if the dest was deleted, FALSE otherwise.
 */
int rib_gc_dest(struct route_node *rn)
{
	rib_dest_t *dest;

	dest = rib_dest_from_rnode(rn);
	if (!dest)
		return 0;

	if (!rib_can_delete_dest(dest))
		return 0;

	if (IS_ZEBRA_DEBUG_RIB) {
		struct zebra_vrf *zvrf;

		zvrf = rib_dest_vrf(dest);
		rnode_debug(rn, zvrf_id(zvrf), "removing dest from table");
	}

	dest->rnode = NULL;
	XFREE(MTYPE_RIB_DEST, dest);
	rn->info = NULL;

	/*
	 * Release the one reference that we keep on the route node.
	 */
	route_unlock_node(rn);
	return 1;
}

static void rib_process_add_fib(struct zebra_vrf *zvrf, struct route_node *rn,
				struct route_entry *new)
{
	hook_call(rib_update, rn, "new route selected");

	/* Update real nexthop. This may actually determine if nexthop is active
	 * or not. */
	if (!nexthop_active_update(rn, new, 1)) {
		UNSET_FLAG(new->status, ROUTE_ENTRY_CHANGED);
		return;
	}

	SET_FLAG(new->status, ROUTE_ENTRY_SELECTED_FIB);
	if (IS_ZEBRA_DEBUG_RIB) {
		char buf[SRCDEST2STR_BUFFER];
		srcdest_rnode2str(rn, buf, sizeof(buf));
		zlog_debug("%u:%s: Adding route rn %p, re %p (type %d)",
			   zvrf_id(zvrf), buf, rn, new, new->type);
	}

	/* If labeled-unicast route, install transit LSP. */
	if (zebra_rib_labeled_unicast(new))
		zebra_mpls_lsp_install(zvrf, rn, new);

	if (!RIB_SYSTEM_ROUTE(new)) {
		if (rib_install_kernel(rn, new, NULL)) {
			char buf[SRCDEST2STR_BUFFER];
			srcdest_rnode2str(rn, buf, sizeof(buf));
			zlog_warn("%u:%s: Route install failed", zvrf_id(zvrf),
				  buf);
		}
	}

	UNSET_FLAG(new->status, ROUTE_ENTRY_CHANGED);
}

static void rib_process_del_fib(struct zebra_vrf *zvrf, struct route_node *rn,
				struct route_entry *old)
{
	hook_call(rib_update, rn, "removing existing route");

	/* Uninstall from kernel. */
	if (IS_ZEBRA_DEBUG_RIB) {
		char buf[SRCDEST2STR_BUFFER];
		srcdest_rnode2str(rn, buf, sizeof(buf));
		zlog_debug("%u:%s: Deleting route rn %p, re %p (type %d)",
			   zvrf_id(zvrf), buf, rn, old, old->type);
	}

	/* If labeled-unicast route, uninstall transit LSP. */
	if (zebra_rib_labeled_unicast(old))
		zebra_mpls_lsp_uninstall(zvrf, rn, old);

	if (!RIB_SYSTEM_ROUTE(old))
		rib_uninstall_kernel(rn, old);

	UNSET_FLAG(old->status, ROUTE_ENTRY_SELECTED_FIB);

	/* Update nexthop for route, reset changed flag. */
	nexthop_active_update(rn, old, 1);
	UNSET_FLAG(old->status, ROUTE_ENTRY_CHANGED);
}

static void rib_process_update_fib(struct zebra_vrf *zvrf,
				   struct route_node *rn,
				   struct route_entry *old,
				   struct route_entry *new)
{
	struct nexthop *nexthop = NULL;
	int nh_active = 0;
	int installed = 1;

	/*
	 * We have to install or update if a new route has been selected or
	 * something has changed.
	 */
	if (new != old || CHECK_FLAG(new->status, ROUTE_ENTRY_CHANGED)) {
		hook_call(rib_update, rn, "updating existing route");

		/* Update the nexthop; we could determine here that nexthop is
		 * inactive. */
		if (nexthop_active_update(rn, new, 1))
			nh_active = 1;

		/* If nexthop is active, install the selected route, if
		 * appropriate. If
		 * the install succeeds, cleanup flags for prior route, if
		 * different from
		 * newly selected.
		 */
		if (nh_active) {
			if (IS_ZEBRA_DEBUG_RIB) {
				char buf[SRCDEST2STR_BUFFER];
				srcdest_rnode2str(rn, buf, sizeof(buf));
				if (new != old)
					zlog_debug(
						"%u:%s: Updating route rn %p, re %p (type %d) "
						"old %p (type %d)",
						zvrf_id(zvrf), buf, rn, new,
						new->type, old, old->type);
				else
					zlog_debug(
						"%u:%s: Updating route rn %p, re %p (type %d)",
						zvrf_id(zvrf), buf, rn, new,
						new->type);
			}

			/* If labeled-unicast route, uninstall transit LSP. */
			if (zebra_rib_labeled_unicast(old))
				zebra_mpls_lsp_uninstall(zvrf, rn, old);

			/* Non-system route should be installed. */
			if (!RIB_SYSTEM_ROUTE(new)) {
				/* If labeled-unicast route, install transit
				 * LSP. */
				if (zebra_rib_labeled_unicast(new))
					zebra_mpls_lsp_install(zvrf, rn, new);

				if (rib_install_kernel(rn, new, old)) {
					char buf[SRCDEST2STR_BUFFER];
					srcdest_rnode2str(rn, buf, sizeof(buf));
					installed = 0;
					zlog_warn("%u:%s: Route install failed",
						  zvrf_id(zvrf), buf);
				}
			}

			/* If install succeeded or system route, cleanup flags
			 * for prior route. */
			if (installed && new != old) {
				if (RIB_SYSTEM_ROUTE(new)) {
					if (!RIB_SYSTEM_ROUTE(old))
						rib_uninstall_kernel(rn, old);
				} else {
					for (nexthop = old->nexthop; nexthop;
					     nexthop = nexthop->next)
						UNSET_FLAG(nexthop->flags,
							   NEXTHOP_FLAG_FIB);
				}
			}

			/* Update for redistribution. */
			if (installed)
				SET_FLAG(new->status, ROUTE_ENTRY_SELECTED_FIB);
		}

		/*
		 * If nexthop for selected route is not active or install
		 * failed, we
		 * may need to uninstall and delete for redistribution.
		 */
		if (!nh_active || !installed) {
			if (IS_ZEBRA_DEBUG_RIB) {
				char buf[SRCDEST2STR_BUFFER];
				srcdest_rnode2str(rn, buf, sizeof(buf));
				if (new != old)
					zlog_debug(
						"%u:%s: Deleting route rn %p, re %p (type %d) "
						"old %p (type %d) - %s",
						zvrf_id(zvrf), buf, rn, new,
						new->type, old, old->type,
						nh_active ? "install failed"
							  : "nexthop inactive");
				else
					zlog_debug(
						"%u:%s: Deleting route rn %p, re %p (type %d) - %s",
						zvrf_id(zvrf), buf, rn, new,
						new->type,
						nh_active ? "install failed"
							  : "nexthop inactive");
			}

			/* If labeled-unicast route, uninstall transit LSP. */
			if (zebra_rib_labeled_unicast(old))
				zebra_mpls_lsp_uninstall(zvrf, rn, old);

			if (!RIB_SYSTEM_ROUTE(old))
				rib_uninstall_kernel(rn, old);
			UNSET_FLAG(new->status, ROUTE_ENTRY_SELECTED_FIB);
		}
	} else {
		/*
		 * Same route selected; check if in the FIB and if not,
		 * re-install. This
		 * is housekeeping code to deal with race conditions in kernel
		 * with linux
		 * netlink reporting interface up before IPv4 or IPv6 protocol
		 * is ready
		 * to add routes.
		 */
		if (!RIB_SYSTEM_ROUTE(new)) {
			int in_fib = 0;

			for (ALL_NEXTHOPS(new->nexthop, nexthop))
				if (CHECK_FLAG(nexthop->flags,
					       NEXTHOP_FLAG_FIB)) {
					in_fib = 1;
					break;
				}
			if (!in_fib)
				rib_install_kernel(rn, new, NULL);
		}
	}

	/* Update prior route. */
	if (new != old) {
		UNSET_FLAG(old->status, ROUTE_ENTRY_SELECTED_FIB);

		/* Set real nexthop. */
		nexthop_active_update(rn, old, 1);
		UNSET_FLAG(old->status, ROUTE_ENTRY_CHANGED);
	}

	/* Clear changed flag. */
	UNSET_FLAG(new->status, ROUTE_ENTRY_CHANGED);
}

/* Check if 'alternate' RIB entry is better than 'current'. */
static struct route_entry *rib_choose_best(struct route_entry *current,
					   struct route_entry *alternate)
{
	if (current == NULL)
		return alternate;

	/* filter route selection in following order:
	 * - connected beats other types
	 * - lower distance beats higher
	 * - lower metric beats higher for equal distance
	 * - last, hence oldest, route wins tie break.
	 */

	/* Connected routes. Pick the last connected
	 * route of the set of lowest metric connected routes.
	 */
	if (alternate->type == ZEBRA_ROUTE_CONNECT) {
		if (current->type != ZEBRA_ROUTE_CONNECT
		    || alternate->metric <= current->metric)
			return alternate;

		return current;
	}

	if (current->type == ZEBRA_ROUTE_CONNECT)
		return current;

	/* higher distance loses */
	if (alternate->distance < current->distance)
		return alternate;
	if (current->distance < alternate->distance)
		return current;

	/* metric tie-breaks equal distance */
	if (alternate->metric <= current->metric)
		return alternate;

	return current;
}

/* Core function for processing routing information base. */
static void rib_process(struct route_node *rn)
{
	struct route_entry *re;
	struct route_entry *next;
	struct route_entry *old_selected = NULL;
	struct route_entry *new_selected = NULL;
	struct route_entry *old_fib = NULL;
	struct route_entry *new_fib = NULL;
	struct route_entry *best = NULL;
	char buf[SRCDEST2STR_BUFFER];
	rib_dest_t *dest;
	struct zebra_vrf *zvrf = NULL;
	struct prefix *p, *src_p;
	srcdest_rnode_prefixes(rn, &p, &src_p);
	vrf_id_t vrf_id = VRF_UNKNOWN;

	assert(rn);

	dest = rib_dest_from_rnode(rn);
	if (dest) {
		zvrf = rib_dest_vrf(dest);
		vrf_id = zvrf_id(zvrf);
	}

	if (IS_ZEBRA_DEBUG_RIB)
		srcdest_rnode2str(rn, buf, sizeof(buf));

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("%u:%s: Processing rn %p", vrf_id, buf, rn);

	RNODE_FOREACH_RE_SAFE(rn, re, next)
	{
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug(
				"%u:%s: Examine re %p (type %d) status %x flags %x "
				"dist %d metric %d",
				vrf_id, buf, re, re->type, re->status,
				re->flags, re->distance, re->metric);

		UNSET_FLAG(re->status, ROUTE_ENTRY_NEXTHOPS_CHANGED);

		/* Currently selected re. */
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED)) {
			assert(old_selected == NULL);
			old_selected = re;
		}
		/* Currently in fib */
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_SELECTED_FIB)) {
			assert(old_fib == NULL);
			old_fib = re;
		}

		/* Skip deleted entries from selection */
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		/* Skip unreachable nexthop. */
		/* This first call to nexthop_active_update is merely to
		 * determine if
		 * there's any change to nexthops associated with this RIB
		 * entry. Now,
		 * rib_process() can be invoked due to an external event such as
		 * link
		 * down or due to next-hop-tracking evaluation. In the latter
		 * case,
		 * a decision has already been made that the NHs have changed.
		 * So, no
		 * need to invoke a potentially expensive call again. Further,
		 * since
		 * the change might be in a recursive NH which is not caught in
		 * the nexthop_active_update() code. Thus, we might miss changes
		 * to
		 * recursive NHs.
		 */
		if (!CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED)
		    && !nexthop_active_update(rn, re, 0)) {
			if (re->type == ZEBRA_ROUTE_TABLE) {
				/* XXX: HERE BE DRAGONS!!!!!
				 * In all honesty, I have not yet figured out
				 * what this part
				 * does or why the ROUTE_ENTRY_CHANGED test
				 * above is correct
				 * or why we need to delete a route here, and
				 * also not whether
				 * this concerns both selected and fib route, or
				 * only selected
				 * or only fib */
				/* This entry was denied by the 'ip protocol
				 * table' route-map, we
				 * need to delete it */
				if (re != old_selected) {
					if (IS_ZEBRA_DEBUG_RIB)
						zlog_debug(
							"%s: %s: imported via import-table but denied "
							"by the ip protocol table route-map",
							__func__, buf);
					rib_unlink(rn, re);
				} else
					SET_FLAG(re->status,
						 ROUTE_ENTRY_REMOVED);
			}

			continue;
		}

		/* Infinite distance. */
		if (re->distance == DISTANCE_INFINITY) {
			UNSET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
			continue;
		}

		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_FIB_OVERRIDE)) {
			best = rib_choose_best(new_fib, re);
			if (new_fib && best != new_fib)
				UNSET_FLAG(new_fib->status,
					   ROUTE_ENTRY_CHANGED);
			new_fib = best;
		} else {
			best = rib_choose_best(new_selected, re);
			if (new_selected && best != new_selected)
				UNSET_FLAG(new_selected->status,
					   ROUTE_ENTRY_CHANGED);
			new_selected = best;
		}
		if (best != re)
			UNSET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
	} /* RNODE_FOREACH_RE */

	/* If no FIB override route, use the selected route also for FIB */
	if (new_fib == NULL)
		new_fib = new_selected;

	/* After the cycle is finished, the following pointers will be set:
	 * old_selected --- RE entry currently having SELECTED
	 * new_selected --- RE entry that is newly SELECTED
	 * old_fib      --- RE entry currently in kernel FIB
	 * new_fib      --- RE entry that is newly to be in kernel FIB
	 *
	 * new_selected will get SELECTED flag, and is going to be redistributed
	 * the zclients. new_fib (which can be new_selected) will be installed
	 * in kernel.
	 */

	if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
		zlog_debug(
			"%u:%s: After processing: old_selected %p new_selected %p old_fib %p new_fib %p",
			vrf_id, buf, (void *)old_selected, (void *)new_selected,
			(void *)old_fib, (void *)new_fib);
	}

	/* Buffer ROUTE_ENTRY_CHANGED here, because it will get cleared if
	 * fib == selected */
	bool selected_changed = new_selected && CHECK_FLAG(new_selected->status,
							   ROUTE_ENTRY_CHANGED);

	/* Update fib according to selection results */
	if (new_fib && old_fib)
		rib_process_update_fib(zvrf, rn, old_fib, new_fib);
	else if (new_fib)
		rib_process_add_fib(zvrf, rn, new_fib);
	else if (old_fib)
		rib_process_del_fib(zvrf, rn, old_fib);

	/* Redistribute SELECTED entry */
	if (old_selected != new_selected || selected_changed) {
		struct nexthop *nexthop;

		/* Check if we have a FIB route for the destination, otherwise,
		 * don't redistribute it */
		for (ALL_NEXTHOPS(new_fib ? new_fib->nexthop : NULL, nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)) {
				break;
			}
		}
		if (!nexthop)
			new_selected = NULL;

		if (new_selected && new_selected != new_fib) {
			nexthop_active_update(rn, new_selected, 1);
			UNSET_FLAG(new_selected->status, ROUTE_ENTRY_CHANGED);
		}

		if (old_selected) {
			if (!new_selected)
				redistribute_delete(p, src_p, old_selected);
			if (old_selected != new_selected)
				UNSET_FLAG(old_selected->flags,
					   ZEBRA_FLAG_SELECTED);
		}

		if (new_selected) {
			/* Install new or replace existing redistributed entry
			 */
			SET_FLAG(new_selected->flags, ZEBRA_FLAG_SELECTED);
			redistribute_update(p, src_p, new_selected,
					    old_selected);
		}
	}

	/* Remove all RE entries queued for removal */
	RNODE_FOREACH_RE_SAFE(rn, re, next)
	{
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)) {
			if (IS_ZEBRA_DEBUG_RIB) {
				rnode_debug(rn, vrf_id, "rn %p, removing re %p",
					    (void *)rn, (void *)re);
			}
			rib_unlink(rn, re);
		}
	}

	/*
	 * Check if the dest can be deleted now.
	 */
	rib_gc_dest(rn);
}

/* Take a list of route_node structs and return 1, if there was a record
 * picked from it and processed by rib_process(). Don't process more,
 * than one RN record; operate only in the specified sub-queue.
 */
static unsigned int process_subq(struct list *subq, u_char qindex)
{
	struct listnode *lnode = listhead(subq);
	struct route_node *rnode;
	rib_dest_t *dest;
	struct zebra_vrf *zvrf = NULL;

	if (!lnode)
		return 0;

	rnode = listgetdata(lnode);
	dest = rib_dest_from_rnode(rnode);
	if (dest)
		zvrf = rib_dest_vrf(dest);

	rib_process(rnode);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
		char buf[SRCDEST2STR_BUFFER];
		srcdest_rnode2str(rnode, buf, sizeof(buf));
		zlog_debug("%u:%s: rn %p dequeued from sub-queue %u",
			   zvrf ? zvrf_id(zvrf) : 0, buf, rnode, qindex);
	}

	if (rnode->info)
		UNSET_FLAG(rib_dest_from_rnode(rnode)->flags,
			   RIB_ROUTE_QUEUED(qindex));

#if 0
  else
    {
      zlog_debug ("%s: called for route_node (%p, %d) with no ribs",
                  __func__, rnode, rnode->lock);
      zlog_backtrace(LOG_DEBUG);
    }
#endif
	route_unlock_node(rnode);
	list_delete_node(subq, lnode);
	return 1;
}

/*
 * All meta queues have been processed. Trigger next-hop evaluation.
 */
static void meta_queue_process_complete(struct work_queue *dummy)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	/* Evaluate nexthops for those VRFs which underwent route processing.
	 * This
	 * should limit the evaluation to the necessary VRFs in most common
	 * situations.
	 */
	RB_FOREACH(vrf, vrf_id_head, &vrfs_by_id)
	{
		zvrf = vrf->info;
		if (zvrf == NULL || !(zvrf->flags & ZEBRA_VRF_RIB_SCHEDULED))
			continue;

		zvrf->flags &= ~ZEBRA_VRF_RIB_SCHEDULED;
		zebra_evaluate_rnh(zvrf_id(zvrf), AF_INET, 0, RNH_NEXTHOP_TYPE,
				   NULL);
		zebra_evaluate_rnh(zvrf_id(zvrf), AF_INET, 0,
				   RNH_IMPORT_CHECK_TYPE, NULL);
		zebra_evaluate_rnh(zvrf_id(zvrf), AF_INET6, 0, RNH_NEXTHOP_TYPE,
				   NULL);
		zebra_evaluate_rnh(zvrf_id(zvrf), AF_INET6, 0,
				   RNH_IMPORT_CHECK_TYPE, NULL);
	}

	/* Schedule LSPs for processing, if needed. */
	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (mpls_should_lsps_be_processed(zvrf)) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"%u: Scheduling all LSPs upon RIB completion",
				zvrf_id(zvrf));
		zebra_mpls_lsp_schedule(zvrf);
		mpls_unmark_lsps_for_processing(zvrf);
	}
}

/* Dispatch the meta queue by picking, processing and unlocking the next RN from
 * a non-empty sub-queue with lowest priority. wq is equal to zebra->ribq and
 * data
 * is pointed to the meta queue structure.
 */
static wq_item_status meta_queue_process(struct work_queue *dummy, void *data)
{
	struct meta_queue *mq = data;
	unsigned i;

	for (i = 0; i < MQ_SIZE; i++)
		if (process_subq(mq->subq[i], i)) {
			mq->size--;
			break;
		}
	return mq->size ? WQ_REQUEUE : WQ_SUCCESS;
}

/*
 * Map from rib types to queue type (priority) in meta queue
 */
static const u_char meta_queue_map[ZEBRA_ROUTE_MAX] = {
		[ZEBRA_ROUTE_SYSTEM] = 4,
		[ZEBRA_ROUTE_KERNEL] = 0,
		[ZEBRA_ROUTE_CONNECT] = 0,
		[ZEBRA_ROUTE_STATIC] = 1,
		[ZEBRA_ROUTE_RIP] = 2,
		[ZEBRA_ROUTE_RIPNG] = 2,
		[ZEBRA_ROUTE_OSPF] = 2,
		[ZEBRA_ROUTE_OSPF6] = 2,
		[ZEBRA_ROUTE_ISIS] = 2,
		[ZEBRA_ROUTE_BGP] = 3,
		[ZEBRA_ROUTE_PIM] = 4, // Shouldn't happen but for safety
		[ZEBRA_ROUTE_EIGRP] = 2,
		[ZEBRA_ROUTE_NHRP] = 2,
		[ZEBRA_ROUTE_HSLS] = 4,
		[ZEBRA_ROUTE_OLSR] = 4,
		[ZEBRA_ROUTE_TABLE] = 1,
		[ZEBRA_ROUTE_LDP] = 4,
		[ZEBRA_ROUTE_VNC] = 3,
		[ZEBRA_ROUTE_VNC_DIRECT] = 3,
		[ZEBRA_ROUTE_VNC_DIRECT_RH] = 3,
		[ZEBRA_ROUTE_BGP_DIRECT] = 3,
		[ZEBRA_ROUTE_BGP_DIRECT_EXT] = 3,
		[ZEBRA_ROUTE_BABEL] = 2,
		[ZEBRA_ROUTE_ALL] = 4, // Shouldn't happen but for safety
};

/* Look into the RN and queue it into one or more priority queues,
 * increasing the size for each data push done.
 */
static void rib_meta_queue_add(struct meta_queue *mq, struct route_node *rn)
{
	struct route_entry *re;

	RNODE_FOREACH_RE(rn, re)
	{
		u_char qindex = meta_queue_map[re->type];
		struct zebra_vrf *zvrf;

		/* Invariant: at this point we always have rn->info set. */
		if (CHECK_FLAG(rib_dest_from_rnode(rn)->flags,
			       RIB_ROUTE_QUEUED(qindex))) {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				rnode_debug(
					rn, re->vrf_id,
					"rn %p is already queued in sub-queue %u",
					(void *)rn, qindex);
			continue;
		}

		SET_FLAG(rib_dest_from_rnode(rn)->flags,
			 RIB_ROUTE_QUEUED(qindex));
		listnode_add(mq->subq[qindex], rn);
		route_lock_node(rn);
		mq->size++;

		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			rnode_debug(rn, re->vrf_id,
				    "queued rn %p into sub-queue %u",
				    (void *)rn, qindex);

		zvrf = zebra_vrf_lookup_by_id(re->vrf_id);
		if (zvrf)
			zvrf->flags |= ZEBRA_VRF_RIB_SCHEDULED;
	}
}

/* Add route_node to work queue and schedule processing */
void rib_queue_add(struct route_node *rn)
{
	assert(rn);

	/* Pointless to queue a route_node with no RIB entries to add or remove
	 */
	if (!rnode_to_ribs(rn)) {
		zlog_debug("%s: called for route_node (%p, %d) with no ribs",
			   __func__, (void *)rn, rn->lock);
		zlog_backtrace(LOG_DEBUG);
		return;
	}

	if (zebrad.ribq == NULL) {
		zlog_err("%s: work_queue does not exist!", __func__);
		return;
	}

	/*
	 * The RIB queue should normally be either empty or holding the only
	 * work_queue_item element. In the latter case this element would
	 * hold a pointer to the meta queue structure, which must be used to
	 * actually queue the route nodes to process. So create the MQ
	 * holder, if necessary, then push the work into it in any case.
	 * This semantics was introduced after 0.99.9 release.
	 */
	if (work_queue_empty(zebrad.ribq))
		work_queue_add(zebrad.ribq, zebrad.mq);

	rib_meta_queue_add(zebrad.mq, rn);

	return;
}

/* Create new meta queue.
   A destructor function doesn't seem to be necessary here.
 */
static struct meta_queue *meta_queue_new(void)
{
	struct meta_queue *new;
	unsigned i;

	new = XCALLOC(MTYPE_WORK_QUEUE, sizeof(struct meta_queue));
	assert(new);

	for (i = 0; i < MQ_SIZE; i++) {
		new->subq[i] = list_new();
		assert(new->subq[i]);
	}

	return new;
}

void meta_queue_free(struct meta_queue *mq)
{
	unsigned i;

	for (i = 0; i < MQ_SIZE; i++)
		list_delete(mq->subq[i]);

	XFREE(MTYPE_WORK_QUEUE, mq);
}

/* initialise zebra rib work queue */
static void rib_queue_init(struct zebra_t *zebra)
{
	assert(zebra);

	if (!(zebra->ribq =
		      work_queue_new(zebra->master, "route_node processing"))) {
		zlog_err("%s: could not initialise work queue!", __func__);
		return;
	}

	/* fill in the work queue spec */
	zebra->ribq->spec.workfunc = &meta_queue_process;
	zebra->ribq->spec.errorfunc = NULL;
	zebra->ribq->spec.completion_func = &meta_queue_process_complete;
	/* XXX: TODO: These should be runtime configurable via vty */
	zebra->ribq->spec.max_retries = 3;
	zebra->ribq->spec.hold = rib_process_hold_time;

	if (!(zebra->mq = meta_queue_new())) {
		zlog_err("%s: could not initialise meta queue!", __func__);
		return;
	}
	return;
}

/* RIB updates are processed via a queue of pointers to route_nodes.
 *
 * The queue length is bounded by the maximal size of the routing table,
 * as a route_node will not be requeued, if already queued.
 *
 * REs are submitted via rib_addnode or rib_delnode which set minimal
 * state, or static_install_route (when an existing RE is updated)
 * and then submit route_node to queue for best-path selection later.
 * Order of add/delete state changes are preserved for any given RE.
 *
 * Deleted REs are reaped during best-path selection.
 *
 * rib_addnode
 * |-> rib_link or unset ROUTE_ENTRY_REMOVE      |->Update kernel with
 *       |-------->|                             |  best RE, if required
 *                 |                             |
 * static_install->|->rib_addqueue...... -> rib_process
 *                 |                             |
 *       |-------->|                             |-> rib_unlink
 *       |-> set ROUTE_ENTRY_REMOVE              |
 * rib_delnode                                  (RE freed)
 *
 * The 'info' pointer of a route_node points to a rib_dest_t
 * ('dest'). Queueing state for a route_node is kept on the dest. The
 * dest is created on-demand by rib_link() and is kept around at least
 * as long as there are ribs hanging off it (@see rib_gc_dest()).
 *
 * Refcounting (aka "locking" throughout the GNU Zebra and Quagga code):
 *
 * - route_nodes: refcounted by:
 *   - dest attached to route_node:
 *     - managed by: rib_link/rib_gc_dest
 *   - route_node processing queue
 *     - managed by: rib_addqueue, rib_process.
 *
 */

/* Add RE to head of the route node. */
static void rib_link(struct route_node *rn, struct route_entry *re, int process)
{
	struct route_entry *head;
	rib_dest_t *dest;
	afi_t afi;
	const char *rmap_name;

	assert(re && rn);

	dest = rib_dest_from_rnode(rn);
	if (!dest) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			rnode_debug(rn, re->vrf_id, "rn %p adding dest", rn);

		dest = XCALLOC(MTYPE_RIB_DEST, sizeof(rib_dest_t));
		route_lock_node(rn); /* rn route table reference */
		rn->info = dest;
		dest->rnode = rn;
	}

	head = dest->routes;
	if (head) {
		head->prev = re;
	}
	re->next = head;
	dest->routes = re;

	afi = (rn->p.family == AF_INET)
		      ? AFI_IP
		      : (rn->p.family == AF_INET6) ? AFI_IP6 : AFI_MAX;
	if (is_zebra_import_table_enabled(afi, re->table)) {
		rmap_name = zebra_get_import_table_route_map(afi, re->table);
		zebra_add_import_table_entry(rn, re, rmap_name);
	} else if (process)
		rib_queue_add(rn);
}

void rib_addnode(struct route_node *rn, struct route_entry *re, int process)
{
	/* RE node has been un-removed before route-node is processed.
	 * route_node must hence already be on the queue for processing..
	 */
	if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)) {
		if (IS_ZEBRA_DEBUG_RIB)
			rnode_debug(rn, re->vrf_id, "rn %p, un-removed re %p",
				    (void *)rn, (void *)re);

		UNSET_FLAG(re->status, ROUTE_ENTRY_REMOVED);
		return;
	}
	rib_link(rn, re, process);
}

/*
 * rib_unlink
 *
 * Detach a rib structure from a route_node.
 *
 * Note that a call to rib_unlink() should be followed by a call to
 * rib_gc_dest() at some point. This allows a rib_dest_t that is no
 * longer required to be deleted.
 */
void rib_unlink(struct route_node *rn, struct route_entry *re)
{
	rib_dest_t *dest;

	assert(rn && re);

	if (IS_ZEBRA_DEBUG_RIB)
		rnode_debug(rn, re->vrf_id, "rn %p, re %p", (void *)rn,
			    (void *)re);

	dest = rib_dest_from_rnode(rn);

	if (re->next)
		re->next->prev = re->prev;

	if (re->prev)
		re->prev->next = re->next;
	else {
		dest->routes = re->next;
	}

	/* free RE and nexthops */
	zebra_deregister_rnh_static_nexthops(re->vrf_id, re->nexthop, rn);
	nexthops_free(re->nexthop);
	XFREE(MTYPE_RE, re);
}

void rib_delnode(struct route_node *rn, struct route_entry *re)
{
	afi_t afi;

	if (IS_ZEBRA_DEBUG_RIB)
		rnode_debug(rn, re->vrf_id, "rn %p, re %p, removing",
			    (void *)rn, (void *)re);
	SET_FLAG(re->status, ROUTE_ENTRY_REMOVED);

	afi = (rn->p.family == AF_INET)
		      ? AFI_IP
		      : (rn->p.family == AF_INET6) ? AFI_IP6 : AFI_MAX;
	if (is_zebra_import_table_enabled(afi, re->table)) {
		zebra_del_import_table_entry(rn, re);
		/* Just clean up if non main table */
		if (IS_ZEBRA_DEBUG_RIB) {
			char buf[SRCDEST2STR_BUFFER];
			srcdest_rnode2str(rn, buf, sizeof(buf));
			zlog_debug(
				"%u:%s: Freeing route rn %p, re %p (type %d)",
				re->vrf_id, buf, rn, re, re->type);
		}

		rib_unlink(rn, re);
	} else {
		rib_queue_add(rn);
	}
}

/* This function dumps the contents of a given RE entry into
 * standard debug log. Calling function name and IP prefix in
 * question are passed as 1st and 2nd arguments.
 */

void _route_entry_dump(const char *func, union prefixconstptr pp,
		       union prefixconstptr src_pp,
		       const struct route_entry *re)
{
	const struct prefix *p = pp.p;
	const struct prefix *src_p = src_pp.p;
	bool is_srcdst = src_p && src_p->prefixlen;
	char straddr[PREFIX_STRLEN];
	char srcaddr[PREFIX_STRLEN];
	struct nexthop *nexthop;

	zlog_debug("%s: dumping RE entry %p for %s%s%s vrf %u", func,
		   (const void *)re, prefix2str(pp, straddr, sizeof(straddr)),
		   is_srcdst ? " from " : "",
		   is_srcdst ? prefix2str(src_pp, srcaddr, sizeof(srcaddr))
			     : "",
		   re->vrf_id);
	zlog_debug("%s: uptime == %lu, type == %u, instance == %d, table == %d",
		   func, (unsigned long)re->uptime, re->type, re->instance,
		   re->table);
	zlog_debug(
		"%s: metric == %u, mtu == %u, distance == %u, flags == %u, status == %u",
		func, re->metric, re->mtu, re->distance, re->flags, re->status);
	zlog_debug("%s: nexthop_num == %u, nexthop_active_num == %u", func,
		   re->nexthop_num, re->nexthop_active_num);

	for (ALL_NEXTHOPS(re->nexthop, nexthop)) {
		inet_ntop(p->family, &nexthop->gate, straddr, INET6_ADDRSTRLEN);
		zlog_debug("%s: %s %s[%u] with flags %s%s%s", func,
			   (nexthop->rparent ? "  NH" : "NH"), straddr,
			   nexthop->ifindex,
			   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)
				    ? "ACTIVE "
				    : ""),
			   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)
				    ? "FIB "
				    : ""),
			   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE)
				    ? "RECURSIVE"
				    : ""));
	}
	zlog_debug("%s: dump complete", func);
}

/* This is an exported helper to rtm_read() to dump the strange
 * RE entry found by rib_lookup_ipv4_route()
 */

void rib_lookup_and_dump(struct prefix_ipv4 *p, vrf_id_t vrf_id)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	char prefix_buf[INET_ADDRSTRLEN];

	/* Lookup table.  */
	table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, vrf_id);
	if (!table) {
		zlog_err("%s: zebra_vrf_table() returned NULL", __func__);
		return;
	}

	/* Scan the RIB table for exactly matching RE entry. */
	rn = route_node_lookup(table, (struct prefix *)p);

	/* No route for this prefix. */
	if (!rn) {
		zlog_debug("%s: lookup failed for %s", __func__,
			   prefix2str((struct prefix *)p, prefix_buf,
				      sizeof(prefix_buf)));
		return;
	}

	/* Unlock node. */
	route_unlock_node(rn);

	/* let's go */
	RNODE_FOREACH_RE(rn, re)
	{
		zlog_debug("%s: rn %p, re %p: %s, %s", __func__, (void *)rn,
			   (void *)re,
			   (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)
				    ? "removed"
				    : "NOT removed"),
			   (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED)
				    ? "selected"
				    : "NOT selected"));
		route_entry_dump(p, NULL, re);
	}
}

/* Check if requested address assignment will fail due to another
 * route being installed by zebra in FIB already. Take necessary
 * actions, if needed: remove such a route from FIB and deSELECT
 * corresponding RE entry. Then put affected RN into RIBQ head.
 */
void rib_lookup_and_pushup(struct prefix_ipv4 *p, vrf_id_t vrf_id)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	unsigned changed = 0;

	if (NULL == (table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, vrf_id))) {
		zlog_err("%s: zebra_vrf_table() returned NULL", __func__);
		return;
	}

	/* No matches would be the simplest case. */
	if (NULL == (rn = route_node_lookup(table, (struct prefix *)p)))
		return;

	/* Unlock node. */
	route_unlock_node(rn);

	/* Check all RE entries. In case any changes have to be done, requeue
	 * the RN into RIBQ head. If the routing message about the new connected
	 * route (generated by the IP address we are going to assign very soon)
	 * comes before the RIBQ is processed, the new RE entry will join
	 * RIBQ record already on head. This is necessary for proper
	 * revalidation
	 * of the rest of the RE.
	 */
	RNODE_FOREACH_RE(rn, re)
	{
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_SELECTED_FIB)
		    && !RIB_SYSTEM_ROUTE(re)) {
			changed = 1;
			if (IS_ZEBRA_DEBUG_RIB) {
				char buf[PREFIX_STRLEN];
				zlog_debug(
					"%u:%s: freeing way for connected prefix",
					re->vrf_id,
					prefix2str(&rn->p, buf, sizeof(buf)));
				route_entry_dump(&rn->p, NULL, re);
			}
			rib_uninstall(rn, re);
		}
	}
	if (changed)
		rib_queue_add(rn);
}

int rib_add_multipath(afi_t afi, safi_t safi, struct prefix *p,
		      struct prefix_ipv6 *src_p, struct route_entry *re)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *same;
	struct nexthop *nexthop;
	int ret = 0;
	int family;

	if (!re)
		return 0;

	if (p->family == AF_INET)
		family = AFI_IP;
	else
		family = AFI_IP6;

	assert(!src_p || family == AFI_IP6);

	/* Lookup table.  */
	table = zebra_vrf_table_with_table_id(family, safi, re->vrf_id,
					      re->table);
	if (!table)
		return 0;

	/* Make it sure prefixlen is applied to the prefix. */
	apply_mask(p);
	if (src_p)
		apply_mask_ipv6(src_p);

	/* Set default distance by route type. */
	if (re->distance == 0) {
		re->distance = route_info[re->type].distance;

		/* iBGP distance is 200. */
		if (re->type == ZEBRA_ROUTE_BGP
		    && CHECK_FLAG(re->flags, ZEBRA_FLAG_IBGP))
			re->distance = 200;
	}

	/* Lookup route node.*/
	rn = srcdest_rnode_get(table, p, src_p);

	/* If same type of route are installed, treat it as a implicit
	   withdraw. */
	RNODE_FOREACH_RE(rn, same)
	{
		if (CHECK_FLAG(same->status, ROUTE_ENTRY_REMOVED))
			continue;

		if (same->type == re->type && same->instance == re->instance
		    && same->table == re->table && !RIB_SYSTEM_ROUTE(same))
			break;
	}

	/* If this route is kernel route, set FIB flag to the route. */
	if (RIB_SYSTEM_ROUTE(re))
		for (nexthop = re->nexthop; nexthop; nexthop = nexthop->next)
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);

	/* Link new re to node.*/
	if (IS_ZEBRA_DEBUG_RIB) {
		rnode_debug(
			rn, re->vrf_id,
			"Inserting route rn %p, re %p (type %d) existing %p",
			(void *)rn, (void *)re, re->type, (void *)same);

		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			route_entry_dump(p, src_p, re);
	}
	rib_addnode(rn, re, 1);
	ret = 1;

	/* Free implicit route.*/
	if (same) {
		rib_delnode(rn, same);
		ret = -1;
	}

	route_unlock_node(rn);
	return ret;
}

void rib_delete(afi_t afi, safi_t safi, vrf_id_t vrf_id, int type,
		u_short instance, int flags, struct prefix *p,
		struct prefix_ipv6 *src_p, const struct nexthop *nh,
		u_int32_t table_id, u_int32_t metric)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	struct route_entry *fib = NULL;
	struct route_entry *same = NULL;
	struct nexthop *rtnh;
	char buf2[INET6_ADDRSTRLEN];

	assert(!src_p || afi == AFI_IP6);

	/* Lookup table.  */
	table = zebra_vrf_table_with_table_id(afi, safi, vrf_id, table_id);
	if (!table)
		return;

	/* Apply mask. */
	apply_mask(p);
	if (src_p)
		apply_mask_ipv6(src_p);

	/* Lookup route node. */
	rn = srcdest_rnode_lookup(table, p, src_p);
	if (!rn) {
		char dst_buf[PREFIX_STRLEN], src_buf[PREFIX_STRLEN];

		prefix2str(p, dst_buf, sizeof(dst_buf));
		if (src_p && src_p->prefixlen)
			prefix2str(src_p, src_buf, sizeof(src_buf));
		else
			src_buf[0] = '\0';

		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("%u:%s%s%s doesn't exist in rib", vrf_id,
				   dst_buf,
				   (src_buf[0] != '\0') ? " from " : "",
				   src_buf);
		return;
	}

	/* Lookup same type route. */
	RNODE_FOREACH_RE(rn, re)
	{
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		if (CHECK_FLAG(re->status, ROUTE_ENTRY_SELECTED_FIB))
			fib = re;

		if (re->type != type)
			continue;
		if (re->instance != instance)
			continue;
		if (re->type == ZEBRA_ROUTE_KERNEL &&
		    re->metric != metric)
			continue;
		if (re->type == ZEBRA_ROUTE_CONNECT && (rtnh = re->nexthop)
		    && rtnh->type == NEXTHOP_TYPE_IFINDEX && nh) {
			if (rtnh->ifindex != nh->ifindex)
				continue;
			same = re;
			break;
		}
		/* Make sure that the route found has the same gateway. */
		else {
			if (nh == NULL) {
				same = re;
				break;
			}
			for (ALL_NEXTHOPS(re->nexthop, rtnh))
				if (nexthop_same_no_recurse(rtnh, nh)) {
					same = re;
					break;
				}
			if (same)
				break;
		}
	}
	/* If same type of route can't be found and this message is from
	   kernel. */
	if (!same) {
		if (fib && type == ZEBRA_ROUTE_KERNEL
		    && CHECK_FLAG(flags, ZEBRA_FLAG_SELFROUTE)) {
			if (IS_ZEBRA_DEBUG_RIB) {
				rnode_debug(
					rn, vrf_id,
					"rn %p, re %p (type %d) was deleted from kernel, adding",
					rn, fib, fib->type);
			}
			if (allow_delete) {
				/* Unset flags. */
				for (rtnh = fib->nexthop; rtnh;
				     rtnh = rtnh->next)
					UNSET_FLAG(rtnh->flags,
						   NEXTHOP_FLAG_FIB);

				UNSET_FLAG(fib->status,
					   ROUTE_ENTRY_SELECTED_FIB);
			} else {
				/* This means someone else, other than Zebra,
				 * has deleted
				 * a Zebra router from the kernel. We will add
				 * it back */
				rib_install_kernel(rn, fib, NULL);
			}
		} else {
			if (IS_ZEBRA_DEBUG_RIB) {
				if (nh)
					rnode_debug(
						rn, vrf_id,
						"via %s ifindex %d type %d "
						"doesn't exist in rib",
						inet_ntop(
							family2afi(afi),
							&nh->gate, buf2,
							INET_ADDRSTRLEN), /* FIXME
									     */
						nh->ifindex, type);
				else
					rnode_debug(
						rn, vrf_id,
						"type %d doesn't exist in rib",
						type);
			}
			route_unlock_node(rn);
			return;
		}
	}

	if (same)
		rib_delnode(rn, same);

	route_unlock_node(rn);
	return;
}


int rib_add(afi_t afi, safi_t safi, vrf_id_t vrf_id, int type, u_short instance,
	    int flags, struct prefix *p, struct prefix_ipv6 *src_p,
	    const struct nexthop *nh, u_int32_t table_id, u_int32_t metric,
	    u_int32_t mtu, u_char distance)
{
	struct route_entry *re;
	struct route_entry *same = NULL;
	struct route_table *table;
	struct route_node *rn;
	struct nexthop *rtnh;

	assert(!src_p || afi == AFI_IP6);

	/* Lookup table.  */
	table = zebra_vrf_table_with_table_id(afi, safi, vrf_id, table_id);
	if (!table)
		return 0;

	/* Make sure mask is applied. */
	apply_mask(p);
	if (src_p)
		apply_mask_ipv6(src_p);

	/* Set default distance by route type. */
	if (distance == 0) {
		if ((unsigned)type >= array_size(route_info))
			distance = 150;
		else
			distance = route_info[type].distance;

		/* iBGP distance is 200. */
		if (type == ZEBRA_ROUTE_BGP
		    && CHECK_FLAG(flags, ZEBRA_FLAG_IBGP))
			distance = 200;
	}

	/* Lookup route node.*/
	rn = srcdest_rnode_get(table, p, src_p);

	/* If same type of route are installed, treat it as a implicit
	   withdraw. */
	RNODE_FOREACH_RE(rn, re)
	{
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		if (re->type != type)
			continue;
		if (re->instance != instance)
			continue;
		if (re->type == ZEBRA_ROUTE_KERNEL &&
		    re->metric != metric)
			continue;
		if (!RIB_SYSTEM_ROUTE(re)) {
			same = re;
			break;
		}
		/* Duplicate system route comes in. */
		rtnh = re->nexthop;
		if (nexthop_same_no_recurse(rtnh, nh))
			return 0;
		/*
		 * Nexthop is different. Remove the old route unless it's
		 * a connected route. This exception is necessary because
		 * of IPv6 link-local routes and unnumbered interfaces on
		 * Linux.
		 */
		else if (type != ZEBRA_ROUTE_CONNECT)
			same = re;
	}

	/* Allocate new re structure. */
	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));

	re->type = type;
	re->instance = instance;
	re->distance = distance;
	re->flags = flags;
	re->metric = metric;
	re->mtu = mtu;
	re->table = table_id;
	re->vrf_id = vrf_id;
	re->nexthop_num = 0;
	re->uptime = time(NULL);

	rtnh = nexthop_new();
	*rtnh = *nh;
	route_entry_nexthop_add(re, rtnh);

	/* If this route is kernel route, set FIB flag to the route. */
	if (RIB_SYSTEM_ROUTE(re))
		for (rtnh = re->nexthop; rtnh; rtnh = rtnh->next)
			SET_FLAG(rtnh->flags, NEXTHOP_FLAG_FIB);

	/* Link new rib to node.*/
	if (IS_ZEBRA_DEBUG_RIB) {
		rnode_debug(
			rn, vrf_id,
			"Inserting route rn %p, re %p (type %d) existing %p",
			(void *)rn, (void *)re, re->type, (void *)same);

		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			route_entry_dump(p, src_p, re);
	}
	rib_addnode(rn, re, 1);

	/* Free implicit route.*/
	if (same)
		rib_delnode(rn, same);

	route_unlock_node(rn);
	return 0;
}

/* Schedule routes of a particular table (address-family) based on event. */
static void rib_update_table(struct route_table *table,
			     rib_update_event_t event)
{
	struct route_node *rn;
	struct route_entry *re, *next;

	/* Walk all routes and queue for processing, if appropriate for
	 * the trigger event.
	 */
	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		switch (event) {
		case RIB_UPDATE_IF_CHANGE:
			/* Examine all routes that won't get processed by the
			 * protocol or
			 * triggered by nexthop evaluation (NHT). This would be
			 * system,
			 * kernel and certain static routes. Note that NHT will
			 * get
			 * triggered upon an interface event as connected routes
			 * always
			 * get queued for processing.
			 */
			RNODE_FOREACH_RE_SAFE(rn, re, next)
			{
				if (re->type == ZEBRA_ROUTE_OSPF
				    || re->type == ZEBRA_ROUTE_OSPF6
				    || re->type == ZEBRA_ROUTE_BGP)
					continue; /* protocol will handle. */
				else if (re->type == ZEBRA_ROUTE_STATIC) {
					struct nexthop *nh;
					for (nh = re->nexthop; nh;
					     nh = nh->next)
						if (!(nh->type
							      == NEXTHOP_TYPE_IPV4
						      || nh->type
								 == NEXTHOP_TYPE_IPV6))
							break;

					/* If we only have nexthops to a
					 * gateway, NHT will
					 * take care.
					 */
					if (nh)
						rib_queue_add(rn);
				} else
					rib_queue_add(rn);
			}
			break;

		case RIB_UPDATE_RMAP_CHANGE:
		case RIB_UPDATE_OTHER:
			/* Right now, examine all routes. Can restrict to a
			 * protocol in
			 * some cases (TODO).
			 */
			if (rnode_to_ribs(rn))
				rib_queue_add(rn);
			break;

		default:
			break;
		}
	}
}

/* RIB update function. */
void rib_update(vrf_id_t vrf_id, rib_update_event_t event)
{
	struct route_table *table;

	/* Process routes of interested address-families. */
	table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, vrf_id);
	if (table)
		rib_update_table(table, event);

	table = zebra_vrf_table(AFI_IP6, SAFI_UNICAST, vrf_id);
	if (table)
		rib_update_table(table, event);
}

/* Remove all routes which comes from non main table.  */
static void rib_weed_table(struct route_table *table)
{
	struct route_node *rn;
	struct route_entry *re;
	struct route_entry *next;

	if (table)
		for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
			RNODE_FOREACH_RE_SAFE(rn, re, next)
			{
				if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
					continue;

				if (re->table != zebrad.rtm_table_default
				    && re->table != RT_TABLE_MAIN)
					rib_delnode(rn, re);
			}
}

/* Delete all routes from non main table. */
void rib_weed_tables(void)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH(vrf, vrf_id_head, &vrfs_by_id)
	if ((zvrf = vrf->info) != NULL) {
		rib_weed_table(zvrf->table[AFI_IP][SAFI_UNICAST]);
		rib_weed_table(zvrf->table[AFI_IP6][SAFI_UNICAST]);
	}
}

/* Delete self installed routes after zebra is relaunched.  */
static void rib_sweep_table(struct route_table *table)
{
	struct route_node *rn;
	struct route_entry *re;
	struct route_entry *next;
	struct nexthop *nexthop;
	int ret = 0;

	if (!table)
		return;

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		RNODE_FOREACH_RE_SAFE(rn, re, next)
		{
			if (IS_ZEBRA_DEBUG_RIB)
				route_entry_dump(&rn->p, NULL, re);

			if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
				continue;

			if (!CHECK_FLAG(re->flags, ZEBRA_FLAG_SELFROUTE))
				continue;

			/*
			 * So we are starting up and have received
			 * routes from the kernel that we have installed
			 * from a previous run of zebra but not cleaned
			 * up ( say a kill -9 )
			 * But since we haven't actually installed
			 * them yet( we received them from the kernel )
			 * we don't think they are active.
			 * So let's pretend they are active to actually
			 * remove them.
			 * In all honesty I'm not sure if we should
			 * mark them as active when we receive them
			 * This is startup only so probably ok.
			 *
			 * If we ever decide to move rib_sweep_table
			 * to a different spot (ie startup )
			 * this decision needs to be revisited
			 */
			for (ALL_NEXTHOPS(re->nexthop, nexthop))
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);

			ret = rib_uninstall_kernel(rn, re);
			if (!ret)
				rib_delnode(rn, re);
		}
	}
}

/* Sweep all RIB tables.  */
void rib_sweep_route(void)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH(vrf, vrf_id_head, &vrfs_by_id) {
		if ((zvrf = vrf->info) == NULL)
			continue;

		rib_sweep_table(zvrf->table[AFI_IP][SAFI_UNICAST]);
		rib_sweep_table(zvrf->table[AFI_IP6][SAFI_UNICAST]);
	}
}

/* Remove specific by protocol routes from 'table'. */
static unsigned long rib_score_proto_table(u_char proto, u_short instance,
					   struct route_table *table)
{
	struct route_node *rn;
	struct route_entry *re;
	struct route_entry *next;
	unsigned long n = 0;

	if (table)
		for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
			RNODE_FOREACH_RE_SAFE(rn, re, next)
			{
				if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
					continue;
				if (re->type == proto
				    && re->instance == instance) {
					rib_delnode(rn, re);
					n++;
				}
			}
	return n;
}

/* Remove specific by protocol routes. */
unsigned long rib_score_proto(u_char proto, u_short instance)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	unsigned long cnt = 0;

	RB_FOREACH(vrf, vrf_id_head, &vrfs_by_id)
	if ((zvrf = vrf->info) != NULL)
		cnt += rib_score_proto_table(proto, instance,
					     zvrf->table[AFI_IP][SAFI_UNICAST])
		       + rib_score_proto_table(
				 proto, instance,
				 zvrf->table[AFI_IP6][SAFI_UNICAST]);

	return cnt;
}

/* Close RIB and clean up kernel routes. */
void rib_close_table(struct route_table *table)
{
	struct route_node *rn;
	rib_table_info_t *info;
	struct route_entry *re;

	if (!table)
		return;

	info = table->info;

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
		RNODE_FOREACH_RE(rn, re)
		{
			if (!CHECK_FLAG(re->status,
					ROUTE_ENTRY_SELECTED_FIB))
				continue;

			if (info->safi == SAFI_UNICAST)
				hook_call(rib_update, rn, NULL);

			if (!RIB_SYSTEM_ROUTE(re))
				rib_uninstall_kernel(rn, re);
		}
}

/* Routing information base initialize. */
void rib_init(void)
{
	rib_queue_init(&zebrad);
}

/*
 * vrf_id_get_next
 *
 * Get the first vrf id that is greater than the given vrf id if any.
 *
 * Returns TRUE if a vrf id was found, FALSE otherwise.
 */
static inline int vrf_id_get_next(vrf_id_t vrf_id, vrf_id_t *next_id_p)
{
	struct vrf *vrf;

	vrf = vrf_lookup_by_id(vrf_id);
	if (vrf) {
		vrf = RB_NEXT(vrf_id_head, vrf);
		if (vrf) {
			*next_id_p = vrf->vrf_id;
			return 1;
		}
	}

	return 0;
}

/*
 * rib_tables_iter_next
 *
 * Returns the next table in the iteration.
 */
struct route_table *rib_tables_iter_next(rib_tables_iter_t *iter)
{
	struct route_table *table;

	/*
	 * Array that helps us go over all AFI/SAFI combinations via one
	 * index.
	 */
	static struct {
		afi_t afi;
		safi_t safi;
	} afi_safis[] = {
		{AFI_IP, SAFI_UNICAST},		{AFI_IP, SAFI_MULTICAST},
		{AFI_IP, SAFI_LABELED_UNICAST}, {AFI_IP6, SAFI_UNICAST},
		{AFI_IP6, SAFI_MULTICAST},      {AFI_IP6, SAFI_LABELED_UNICAST},
	};

	table = NULL;

	switch (iter->state) {

	case RIB_TABLES_ITER_S_INIT:
		iter->vrf_id = VRF_DEFAULT;
		iter->afi_safi_ix = -1;

	/* Fall through */

	case RIB_TABLES_ITER_S_ITERATING:
		iter->afi_safi_ix++;
		while (1) {

			while (iter->afi_safi_ix
			       < (int)ZEBRA_NUM_OF(afi_safis)) {
				table = zebra_vrf_table(
					afi_safis[iter->afi_safi_ix].afi,
					afi_safis[iter->afi_safi_ix].safi,
					iter->vrf_id);
				if (table)
					break;

				iter->afi_safi_ix++;
			}

			/*
			 * Found another table in this vrf.
			 */
			if (table)
				break;

			/*
			 * Done with all tables in the current vrf, go to the
			 * next
			 * one.
			 */
			if (!vrf_id_get_next(iter->vrf_id, &iter->vrf_id))
				break;

			iter->afi_safi_ix = 0;
		}

		break;

	case RIB_TABLES_ITER_S_DONE:
		return NULL;
	}

	if (table)
		iter->state = RIB_TABLES_ITER_S_ITERATING;
	else
		iter->state = RIB_TABLES_ITER_S_DONE;

	return table;
}
