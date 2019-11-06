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

#include "command.h"
#include "if.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "mpls.h"
#include "nexthop.h"
#include "prefix.h"
#include "prefix.h"
#include "routemap.h"
#include "sockunion.h"
#include "srcdest_table.h"
#include "table.h"
#include "thread.h"
#include "vrf.h"
#include "workqueue.h"
#include "nexthop_group_private.h"
#include "frr_pthread.h"

#include "zebra/zebra_router.h"
#include "zebra/connected.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/redistribute.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_dplane.h"

DEFINE_MTYPE_STATIC(ZEBRA, RIB_UPDATE_CTX, "Rib update context object");

/*
 * Event, list, and mutex for delivery of dataplane results
 */
static pthread_mutex_t dplane_mutex;
static struct thread *t_dplane;
static struct dplane_ctx_q rib_dplane_q;

DEFINE_HOOK(rib_update, (struct route_node * rn, const char *reason),
	    (rn, reason))

/* Should we allow non Quagga processes to delete our routes */
extern int allow_delete;

/* Each route type's string and default distance value. */
static const struct {
	int key;
	uint8_t distance;
	uint8_t meta_q_map;
} route_info[ZEBRA_ROUTE_MAX] = {
	[ZEBRA_ROUTE_NHG] = {ZEBRA_ROUTE_NHG, 255 /* Uneeded for nhg's */, 0},
	[ZEBRA_ROUTE_SYSTEM] = {ZEBRA_ROUTE_SYSTEM, 0, 5},
	[ZEBRA_ROUTE_KERNEL] = {ZEBRA_ROUTE_KERNEL, 0, 1},
	[ZEBRA_ROUTE_CONNECT] = {ZEBRA_ROUTE_CONNECT, 0, 1},
	[ZEBRA_ROUTE_STATIC] = {ZEBRA_ROUTE_STATIC, 1, 2},
	[ZEBRA_ROUTE_RIP] = {ZEBRA_ROUTE_RIP, 120, 3},
	[ZEBRA_ROUTE_RIPNG] = {ZEBRA_ROUTE_RIPNG, 120, 3},
	[ZEBRA_ROUTE_OSPF] = {ZEBRA_ROUTE_OSPF, 110, 3},
	[ZEBRA_ROUTE_OSPF6] = {ZEBRA_ROUTE_OSPF6, 110, 3},
	[ZEBRA_ROUTE_ISIS] = {ZEBRA_ROUTE_ISIS, 115, 3},
	[ZEBRA_ROUTE_BGP] = {ZEBRA_ROUTE_BGP, 20 /* IBGP is 200. */, 4},
	[ZEBRA_ROUTE_PIM] = {ZEBRA_ROUTE_PIM, 255, 5},
	[ZEBRA_ROUTE_EIGRP] = {ZEBRA_ROUTE_EIGRP, 90, 3},
	[ZEBRA_ROUTE_NHRP] = {ZEBRA_ROUTE_NHRP, 10, 3},
	[ZEBRA_ROUTE_HSLS] = {ZEBRA_ROUTE_HSLS, 255, 5},
	[ZEBRA_ROUTE_OLSR] = {ZEBRA_ROUTE_OLSR, 255, 5},
	[ZEBRA_ROUTE_TABLE] = {ZEBRA_ROUTE_TABLE, 150, 2},
	[ZEBRA_ROUTE_LDP] = {ZEBRA_ROUTE_LDP, 150, 5},
	[ZEBRA_ROUTE_VNC] = {ZEBRA_ROUTE_VNC, 20, 4},
	[ZEBRA_ROUTE_VNC_DIRECT] = {ZEBRA_ROUTE_VNC_DIRECT, 20, 4},
	[ZEBRA_ROUTE_VNC_DIRECT_RH] = {ZEBRA_ROUTE_VNC_DIRECT_RH, 20, 4},
	[ZEBRA_ROUTE_BGP_DIRECT] = {ZEBRA_ROUTE_BGP_DIRECT, 20, 4},
	[ZEBRA_ROUTE_BGP_DIRECT_EXT] = {ZEBRA_ROUTE_BGP_DIRECT_EXT, 20, 4},
	[ZEBRA_ROUTE_BABEL] = {ZEBRA_ROUTE_BABEL, 100, 3},
	[ZEBRA_ROUTE_SHARP] = {ZEBRA_ROUTE_SHARP, 150, 5},
	[ZEBRA_ROUTE_PBR] = {ZEBRA_ROUTE_PBR, 200, 5},
	[ZEBRA_ROUTE_BFD] = {ZEBRA_ROUTE_BFD, 255, 5},
	[ZEBRA_ROUTE_OPENFABRIC] = {ZEBRA_ROUTE_OPENFABRIC, 115, 3},
	[ZEBRA_ROUTE_VRRP] = {ZEBRA_ROUTE_VRRP, 255, 5}
	/* Any new route type added to zebra, should be mirrored here */

	/* no entry/default: 150 */
};

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
			strlcat(buf, " (MRIB)", sizeof(buf));
	} else {
		snprintf(buf, sizeof(buf), "{(route_node *) NULL}");
	}

	zlog(priority, "%s: %d:%s: %s", _func, vrf_id, buf, msgbuf);
}

#define rnode_debug(node, vrf_id, ...)                                         \
	_rnode_zlog(__func__, vrf_id, node, LOG_DEBUG, __VA_ARGS__)
#define rnode_info(node, ...)                                                  \
	_rnode_zlog(__func__, vrf_id, node, LOG_INFO, __VA_ARGS__)

uint8_t route_distance(int type)
{
	uint8_t distance;

	if ((unsigned)type >= array_size(route_info))
		distance = 150;
	else
		distance = route_info[type].distance;

	return distance;
}

int is_zebra_valid_kernel_table(uint32_t table_id)
{
#ifdef linux
	if ((table_id == RT_TABLE_UNSPEC) || (table_id == RT_TABLE_LOCAL)
	    || (table_id == RT_TABLE_COMPAT))
		return 0;
#endif

	return 1;
}

int is_zebra_main_routing_table(uint32_t table_id)
{
	if (table_id == RT_TABLE_MAIN)
		return 1;
	return 0;
}

int zebra_check_addr(const struct prefix *p)
{
	if (p->family == AF_INET) {
		uint32_t addr;

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
	_nexthop_group_add_sorted(re->ng, nexthop);
}


/**
 * copy_nexthop - copy a nexthop to the rib structure.
 */
void route_entry_copy_nexthops(struct route_entry *re, struct nexthop *nh)
{
	assert(!re->ng->nexthop);
	copy_nexthops(&re->ng->nexthop, nh, NULL);
}

/* Delete specified nexthop from the list. */
void route_entry_nexthop_delete(struct route_entry *re, struct nexthop *nexthop)
{
	if (nexthop->next)
		nexthop->next->prev = nexthop->prev;
	if (nexthop->prev)
		nexthop->prev->next = nexthop->next;
	else
		re->ng->nexthop = nexthop->next;
}


struct nexthop *route_entry_nexthop_ifindex_add(struct route_entry *re,
						ifindex_t ifindex,
						vrf_id_t nh_vrf_id)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->type = NEXTHOP_TYPE_IFINDEX;
	nexthop->ifindex = ifindex;
	nexthop->vrf_id = nh_vrf_id;

	route_entry_nexthop_add(re, nexthop);

	return nexthop;
}

struct nexthop *route_entry_nexthop_ipv4_add(struct route_entry *re,
					     struct in_addr *ipv4,
					     struct in_addr *src,
					     vrf_id_t nh_vrf_id)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->type = NEXTHOP_TYPE_IPV4;
	nexthop->vrf_id = nh_vrf_id;
	nexthop->gate.ipv4 = *ipv4;
	if (src)
		nexthop->src.ipv4 = *src;

	route_entry_nexthop_add(re, nexthop);

	return nexthop;
}

struct nexthop *route_entry_nexthop_ipv4_ifindex_add(struct route_entry *re,
						     struct in_addr *ipv4,
						     struct in_addr *src,
						     ifindex_t ifindex,
						     vrf_id_t nh_vrf_id)
{
	struct nexthop *nexthop;
	struct interface *ifp;

	nexthop = nexthop_new();
	nexthop->vrf_id = nh_vrf_id;
	nexthop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
	nexthop->gate.ipv4 = *ipv4;
	if (src)
		nexthop->src.ipv4 = *src;
	nexthop->ifindex = ifindex;
	ifp = if_lookup_by_index(nexthop->ifindex, nh_vrf_id);
	/*Pending: need to think if null ifp here is ok during bootup?
	  There was a crash because ifp here was coming to be NULL */
	if (ifp)
		if (connected_is_unnumbered(ifp))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK);

	route_entry_nexthop_add(re, nexthop);

	return nexthop;
}

struct nexthop *route_entry_nexthop_ipv6_add(struct route_entry *re,
					     struct in6_addr *ipv6,
					     vrf_id_t nh_vrf_id)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->vrf_id = nh_vrf_id;
	nexthop->type = NEXTHOP_TYPE_IPV6;
	nexthop->gate.ipv6 = *ipv6;

	route_entry_nexthop_add(re, nexthop);

	return nexthop;
}

struct nexthop *route_entry_nexthop_ipv6_ifindex_add(struct route_entry *re,
						     struct in6_addr *ipv6,
						     ifindex_t ifindex,
						     vrf_id_t nh_vrf_id)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->vrf_id = nh_vrf_id;
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
	nexthop->vrf_id = VRF_DEFAULT;
	nexthop->type = NEXTHOP_TYPE_BLACKHOLE;
	nexthop->bh_type = bh_type;

	route_entry_nexthop_add(re, nexthop);

	return nexthop;
}

struct route_entry *rib_match(afi_t afi, safi_t safi, vrf_id_t vrf_id,
			      union g_addr *addr, struct route_node **rn_out)
{
	struct prefix p;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *match = NULL;

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
		rib_dest_t *dest;

		route_unlock_node(rn);

		dest = rib_dest_from_rnode(rn);
		if (dest && dest->selected_fib
		    && !CHECK_FLAG(dest->selected_fib->status,
				   ROUTE_ENTRY_REMOVED))
			match = dest->selected_fib;

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
				if (!CHECK_FLAG(match->status,
						ROUTE_ENTRY_INSTALLED))
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

	switch (zrouter.ipv4_multicast_mode) {
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

		zlog_debug("%s: %s: vrf: %u found %s, using %s",
			   __func__, buf, vrf_id,
			   mre ? (ure ? "MRIB+URIB" : "MRIB")
			       : ure ? "URIB" : "nothing",
			   re == ure ? "URIB" : re == mre ? "MRIB" : "none");
	}
	return re;
}

struct route_entry *rib_lookup_ipv4(struct prefix_ipv4 *p, vrf_id_t vrf_id)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *match = NULL;
	rib_dest_t *dest;

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
	dest = rib_dest_from_rnode(rn);

	if (dest && dest->selected_fib
	    && !CHECK_FLAG(dest->selected_fib->status, ROUTE_ENTRY_REMOVED))
		match = dest->selected_fib;

	if (!match)
		return NULL;

	if (match->type == ZEBRA_ROUTE_CONNECT)
		return match;

	if (CHECK_FLAG(match->status, ROUTE_ENTRY_INSTALLED))
		return match;

	return NULL;
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

	for (ALL_NEXTHOPS_PTR(re->ng, nexthop))
		if (!nexthop->nh_label || !nexthop->nh_label->num_labels)
			return 0;

	return 1;
}

/* Update flag indicates whether this is a "replace" or not. Currently, this
 * is only used for IPv4.
 */
void rib_install_kernel(struct route_node *rn, struct route_entry *re,
			struct route_entry *old)
{
	struct nexthop *nexthop;
	rib_table_info_t *info = srcdest_rnode_table_info(rn);
	struct zebra_vrf *zvrf = vrf_info_lookup(re->vrf_id);
	const struct prefix *p, *src_p;
	enum zebra_dplane_result ret;

	rib_dest_t *dest = rib_dest_from_rnode(rn);

	srcdest_rnode_prefixes(rn, &p, &src_p);

	if (info->safi != SAFI_UNICAST) {
		for (ALL_NEXTHOPS_PTR(re->ng, nexthop))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
		return;
	}


	/*
	 * Install the resolved nexthop object first.
	 */
	zebra_nhg_install_kernel(zebra_nhg_lookup_id(re->nhe_id));

	/*
	 * If this is a replace to a new RE let the originator of the RE
	 * know that they've lost
	 */
	if (old && (old != re) && (old->type != re->type))
		zsend_route_notify_owner(old, p, ZAPI_ROUTE_BETTER_ADMIN_WON);

	/* Update fib selection */
	dest->selected_fib = re;

	/*
	 * Make sure we update the FPM any time we send new information to
	 * the kernel.
	 */
	hook_call(rib_update, rn, "installing in kernel");

	/* Send add or update */
	if (old)
		ret = dplane_route_update(rn, re, old);
	else
		ret = dplane_route_add(rn, re);

	switch (ret) {
	case ZEBRA_DPLANE_REQUEST_QUEUED:
		SET_FLAG(re->status, ROUTE_ENTRY_QUEUED);

		if (old) {
			SET_FLAG(old->status, ROUTE_ENTRY_QUEUED);

			/* Free old FIB nexthop group */
			if (old->fib_ng.nexthop) {
				nexthops_free(old->fib_ng.nexthop);
				old->fib_ng.nexthop = NULL;
			}

			if (!RIB_SYSTEM_ROUTE(old)) {
				/* Clear old route's FIB flags */
				for (ALL_NEXTHOPS_PTR(old->ng, nexthop)) {
					UNSET_FLAG(nexthop->flags,
						   NEXTHOP_FLAG_FIB);
				}
			}
		}

		if (zvrf)
			zvrf->installs_queued++;
		break;
	case ZEBRA_DPLANE_REQUEST_FAILURE:
	{
		char str[SRCDEST2STR_BUFFER];

		srcdest_rnode2str(rn, str, sizeof(str));
		flog_err(EC_ZEBRA_DP_INSTALL_FAIL,
			 "%u:%s: Failed to enqueue dataplane install",
			 re->vrf_id, str);
		break;
	}
	case ZEBRA_DPLANE_REQUEST_SUCCESS:
		if (zvrf)
			zvrf->installs++;
		break;
	}

	return;
}

/* Uninstall the route from kernel. */
void rib_uninstall_kernel(struct route_node *rn, struct route_entry *re)
{
	struct nexthop *nexthop;
	rib_table_info_t *info = srcdest_rnode_table_info(rn);
	struct zebra_vrf *zvrf = vrf_info_lookup(re->vrf_id);

	if (info->safi != SAFI_UNICAST) {
		UNSET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
		for (ALL_NEXTHOPS_PTR(re->ng, nexthop))
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
		return;
	}

	/*
	 * Make sure we update the FPM any time we send new information to
	 * the dataplane.
	 */
	hook_call(rib_update, rn, "uninstalling from kernel");

	switch (dplane_route_delete(rn, re)) {
	case ZEBRA_DPLANE_REQUEST_QUEUED:
		if (zvrf)
			zvrf->removals_queued++;
		break;
	case ZEBRA_DPLANE_REQUEST_FAILURE:
	{
		char str[SRCDEST2STR_BUFFER];

		srcdest_rnode2str(rn, str, sizeof(str));
		flog_err(EC_ZEBRA_DP_INSTALL_FAIL,
			 "%u:%s: Failed to enqueue dataplane uninstall",
			 re->vrf_id, str);
		break;
	}
	case ZEBRA_DPLANE_REQUEST_SUCCESS:
		if (zvrf)
			zvrf->removals++;
		break;
	}

	return;
}

/* Uninstall the route from kernel. */
static void rib_uninstall(struct route_node *rn, struct route_entry *re)
{
	rib_table_info_t *info = srcdest_rnode_table_info(rn);
	rib_dest_t *dest = rib_dest_from_rnode(rn);
	struct nexthop *nexthop;

	if (dest && dest->selected_fib == re) {
		if (info->safi == SAFI_UNICAST)
			hook_call(rib_update, rn, "rib_uninstall");

		/* If labeled-unicast route, uninstall transit LSP. */
		if (zebra_rib_labeled_unicast(re))
			zebra_mpls_lsp_uninstall(info->zvrf, rn, re);

		rib_uninstall_kernel(rn, re);

		dest->selected_fib = NULL;

		/* Free FIB nexthop group, if present */
		if (re->fib_ng.nexthop) {
			nexthops_free(re->fib_ng.nexthop);
			re->fib_ng.nexthop = NULL;
		}

		for (ALL_NEXTHOPS_PTR(re->ng, nexthop))
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
	}

	if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED)) {
		const struct prefix *p, *src_p;

		srcdest_rnode_prefixes(rn, &p, &src_p);

		redistribute_delete(p, src_p, re, NULL);
		UNSET_FLAG(re->flags, ZEBRA_FLAG_SELECTED);
	}
}

/*
 * rib_can_delete_dest
 *
 * Returns true if the given dest can be deleted from the table.
 */
static int rib_can_delete_dest(rib_dest_t *dest)
{
	if (re_list_first(&dest->routes)) {
		return 0;
	}

	/*
	 * Unresolved rnh's are stored on the default route's list
	 *
	 * dest->rnode can also be the source prefix node in an
	 * ipv6 sourcedest table.  Fortunately the prefix of a
	 * source prefix node can never be the default prefix.
	 */
	if (is_default_prefix(&dest->rnode->p))
		return 0;

	/*
	 * Don't delete the dest if we have to update the FPM about this
	 * prefix.
	 */
	if (CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_FPM)
	    || CHECK_FLAG(dest->flags, RIB_DEST_SENT_TO_FPM))
		return 0;

	return 1;
}

void zebra_rib_evaluate_rn_nexthops(struct route_node *rn, uint32_t seq)
{
	rib_dest_t *dest = rib_dest_from_rnode(rn);
	struct rnh *rnh;

	/*
	 * We are storing the rnh's associated withb
	 * the tracked nexthop as a list of the rn's.
	 * Unresolved rnh's are placed at the top
	 * of the tree list.( 0.0.0.0/0 for v4 and 0::0/0 for v6 )
	 * As such for each rn we need to walk up the tree
	 * and see if any rnh's need to see if they
	 * would match a more specific route
	 */
	while (rn) {
		if (IS_ZEBRA_DEBUG_NHT_DETAILED) {
			char buf[PREFIX_STRLEN];

			zlog_debug("%s: %s Being examined for Nexthop Tracking Count: %zd",
				   __PRETTY_FUNCTION__,
				   srcdest_rnode2str(rn, buf, sizeof(buf)),
				   dest ? rnh_list_count(&dest->nht) : 0);
		}
		if (!dest) {
			rn = rn->parent;
			if (rn)
				dest = rib_dest_from_rnode(rn);
			continue;
		}
		/*
		 * If we have any rnh's stored in the nht list
		 * then we know that this route node was used for
		 * nht resolution and as such we need to call the
		 * nexthop tracking evaluation code
		 */
		frr_each_safe(rnh_list, &dest->nht, rnh) {
			struct zebra_vrf *zvrf =
				zebra_vrf_lookup_by_id(rnh->vrf_id);
			struct prefix *p = &rnh->node->p;

			if (IS_ZEBRA_DEBUG_NHT_DETAILED) {
				char buf1[PREFIX_STRLEN];
				char buf2[PREFIX_STRLEN];

				zlog_debug("%u:%s has Nexthop(%s) Type: %s depending on it, evaluating %u:%u",
					   zvrf->vrf->vrf_id,
					   srcdest_rnode2str(rn, buf1,
						      sizeof(buf1)),
					   prefix2str(p, buf2, sizeof(buf2)),
					   rnh_type2str(rnh->type),
					   seq, rnh->seqno);
			}

			/*
			 * If we have evaluated this node on this pass
			 * already, due to following the tree up
			 * then we know that we can move onto the next
			 * rnh to process.
			 *
			 * Additionally we call zebra_evaluate_rnh
			 * when we gc the dest.  In this case we know
			 * that there must be no other re's where
			 * we were originally as such we know that
			 * that sequence number is ok to respect.
			 */
			if (rnh->seqno == seq) {
				if (IS_ZEBRA_DEBUG_NHT_DETAILED)
					zlog_debug(
						"\tNode processed and moved already");
				continue;
			}

			rnh->seqno = seq;
			zebra_evaluate_rnh(zvrf, family2afi(p->family), 0,
					   rnh->type, p);
		}

		rn = rn->parent;
		if (rn)
			dest = rib_dest_from_rnode(rn);
	}
}

/*
 * rib_gc_dest
 *
 * Garbage collect the rib dest corresponding to the given route node
 * if appropriate.
 *
 * Returns true if the dest was deleted, false otherwise.
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

	zebra_rib_evaluate_rn_nexthops(rn, zebra_router_get_next_sequence());

	dest->rnode = NULL;
	rnh_list_fini(&dest->nht);
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
	if (!nexthop_group_active_nexthop_num(new->ng)) {
		UNSET_FLAG(new->status, ROUTE_ENTRY_CHANGED);
		return;
	}

	if (IS_ZEBRA_DEBUG_RIB) {
		char buf[SRCDEST2STR_BUFFER];
		srcdest_rnode2str(rn, buf, sizeof(buf));
		zlog_debug("%u:%s: Adding route rn %p, re %p (%s)",
			   zvrf_id(zvrf), buf, rn, new,
			   zebra_route_string(new->type));
	}

	/* If labeled-unicast route, install transit LSP. */
	if (zebra_rib_labeled_unicast(new))
		zebra_mpls_lsp_install(zvrf, rn, new);

	rib_install_kernel(rn, new, NULL);

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
		zlog_debug("%u:%s: Deleting route rn %p, re %p (%s)",
			   zvrf_id(zvrf), buf, rn, old,
			   zebra_route_string(old->type));
	}

	/* If labeled-unicast route, uninstall transit LSP. */
	if (zebra_rib_labeled_unicast(old))
		zebra_mpls_lsp_uninstall(zvrf, rn, old);

	rib_uninstall_kernel(rn, old);

	/* Update nexthop for route, reset changed flag. */
	/* Note: this code also handles the Linux case when an interface goes
	 * down, causing the kernel to delete routes without sending DELROUTE
	 * notifications
	 */
	if (RIB_KERNEL_ROUTE(old))
		SET_FLAG(old->status, ROUTE_ENTRY_REMOVED);
	else
		UNSET_FLAG(old->status, ROUTE_ENTRY_CHANGED);
}

static void rib_process_update_fib(struct zebra_vrf *zvrf,
				   struct route_node *rn,
				   struct route_entry *old,
				   struct route_entry *new)
{
	int nh_active = 0;

	/*
	 * We have to install or update if a new route has been selected or
	 * something has changed.
	 */
	if (new != old || CHECK_FLAG(new->status, ROUTE_ENTRY_CHANGED)) {
		hook_call(rib_update, rn, "updating existing route");

		/* Update the nexthop; we could determine here that nexthop is
		 * inactive. */
		if (nexthop_group_active_nexthop_num(new->ng))
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
						"%u:%s: Updating route rn %p, re %p (%s) old %p (%s)",
						zvrf_id(zvrf), buf, rn, new,
						zebra_route_string(new->type),
						old,
						zebra_route_string(old->type));
				else
					zlog_debug(
						"%u:%s: Updating route rn %p, re %p (%s)",
						zvrf_id(zvrf), buf, rn, new,
						zebra_route_string(new->type));
			}

			/* If labeled-unicast route, uninstall transit LSP. */
			if (zebra_rib_labeled_unicast(old))
				zebra_mpls_lsp_uninstall(zvrf, rn, old);

			/*
			 * Non-system route should be installed.
			 * If labeled-unicast route, install transit
			 * LSP.
			 */
			if (zebra_rib_labeled_unicast(new))
				zebra_mpls_lsp_install(zvrf, rn, new);

			rib_install_kernel(rn, new, old);
		}

		/*
		 * If nexthop for selected route is not active or install
		 * failed, we
		 * may need to uninstall and delete for redistribution.
		 */
		if (!nh_active) {
			if (IS_ZEBRA_DEBUG_RIB) {
				char buf[SRCDEST2STR_BUFFER];
				srcdest_rnode2str(rn, buf, sizeof(buf));
				if (new != old)
					zlog_debug(
						"%u:%s: Deleting route rn %p, re %p (%s) old %p (%s) - nexthop inactive",
						zvrf_id(zvrf), buf, rn, new,
						zebra_route_string(new->type),
						old,
						zebra_route_string(old->type));
				else
					zlog_debug(
						"%u:%s: Deleting route rn %p, re %p (%s) - nexthop inactive",
						zvrf_id(zvrf), buf, rn, new,
						zebra_route_string(new->type));
			}

			/* If labeled-unicast route, uninstall transit LSP. */
			if (zebra_rib_labeled_unicast(old))
				zebra_mpls_lsp_uninstall(zvrf, rn, old);

			rib_uninstall_kernel(rn, old);
		}
	} else {
		/*
		 * Same route selected; check if in the FIB and if not,
		 * re-install. This is housekeeping code to deal with
		 * race conditions in kernel with linux netlink reporting
		 * interface up before IPv4 or IPv6 protocol is ready
		 * to add routes.
		 */
		if (!CHECK_FLAG(new->status, ROUTE_ENTRY_INSTALLED) ||
		    RIB_SYSTEM_ROUTE(new))
			rib_install_kernel(rn, new, NULL);
	}

	/* Update prior route. */
	if (new != old)
		UNSET_FLAG(old->status, ROUTE_ENTRY_CHANGED);

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
	 * - if both connected, loopback or vrf wins
	 * - lower distance beats higher
	 * - lower metric beats higher for equal distance
	 * - last, hence oldest, route wins tie break.
	 */

	/* Connected routes. Check to see if either are a vrf
	 * or loopback interface.  If not, pick the last connected
	 * route of the set of lowest metric connected routes.
	 */
	if (alternate->type == ZEBRA_ROUTE_CONNECT) {
		if (current->type != ZEBRA_ROUTE_CONNECT)
			return alternate;

		/* both are connected.  are either loop or vrf? */
		struct nexthop *nexthop = NULL;

		for (ALL_NEXTHOPS_PTR(alternate->ng, nexthop)) {
			struct interface *ifp = if_lookup_by_index(
				nexthop->ifindex, alternate->vrf_id);

			if (ifp && if_is_loopback_or_vrf(ifp))
				return alternate;
		}

		for (ALL_NEXTHOPS_PTR(current->ng, nexthop)) {
			struct interface *ifp = if_lookup_by_index(
				nexthop->ifindex, current->vrf_id);

			if (ifp && if_is_loopback_or_vrf(ifp))
				return current;
		}

		/* Neither are loop or vrf so pick best metric  */
		if (alternate->metric <= current->metric)
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

/* Core function for processing nexthop group contexts's off metaq */
static void rib_nhg_process(struct nhg_ctx *ctx)
{
	nhg_ctx_process(ctx);
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
	const struct prefix *p, *src_p;

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

	/*
	 * we can have rn's that have a NULL info pointer
	 * (dest).  As such let's not let the deref happen
	 * additionally we know RNODE_FOREACH_RE_SAFE
	 * will not iterate so we are ok.
	 */
	if (dest)
		old_fib = dest->selected_fib;

	RNODE_FOREACH_RE_SAFE (rn, re, next) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug(
				"%u:%s: Examine re %p (%s) status %x flags %x dist %d metric %d",
				vrf_id, buf, re, zebra_route_string(re->type),
				re->status, re->flags, re->distance,
				re->metric);

		/* Currently selected re. */
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED)) {
			assert(old_selected == NULL);
			old_selected = re;
		}

		/* Skip deleted entries from selection */
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		/* Skip unreachable nexthop. */
		/* This first call to nexthop_active_update is merely to
		 * determine if there's any change to nexthops associated
		 * with this RIB entry. Now, rib_process() can be invoked due
		 * to an external event such as link down or due to
		 * next-hop-tracking evaluation. In the latter case,
		 * a decision has already been made that the NHs have changed.
		 * So, no need to invoke a potentially expensive call again.
		 * Further, since the change might be in a recursive NH which
		 * is not caught in the nexthop_active_update() code. Thus, we
		 * might miss changes to recursive NHs.
		 */
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED)
		    && !nexthop_active_update(rn, re)) {
			if (re->type == ZEBRA_ROUTE_TABLE) {
				/* XXX: HERE BE DRAGONS!!!!!
				 * In all honesty, I have not yet figured out
				 * what this part does or why the
				 * ROUTE_ENTRY_CHANGED test above is correct
				 * or why we need to delete a route here, and
				 * also not whether this concerns both selected
				 * and fib route, or only selected
				 * or only fib
				 *
				 * This entry was denied by the 'ip protocol
				 * table' route-map, we need to delete it */
				if (re != old_selected) {
					if (IS_ZEBRA_DEBUG_RIB)
						zlog_debug(
							"%s: %u:%s: imported via import-table but denied "
							"by the ip protocol table route-map",
							__func__, vrf_id, buf);
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

	/* Update SELECTED entry */
	if (old_selected != new_selected || selected_changed) {

		if (new_selected && new_selected != new_fib)
			UNSET_FLAG(new_selected->status, ROUTE_ENTRY_CHANGED);

		if (new_selected)
			SET_FLAG(new_selected->flags, ZEBRA_FLAG_SELECTED);

		if (old_selected) {
			/*
			 * If we're removing the old entry, we should tell
			 * redist subscribers about that *if* they aren't
			 * going to see a redist for the new entry.
			 */
			if (!new_selected || CHECK_FLAG(old_selected->status,
							ROUTE_ENTRY_REMOVED))
				redistribute_delete(p, src_p,
						    old_selected,
						    new_selected);

			if (old_selected != new_selected)
				UNSET_FLAG(old_selected->flags,
					   ZEBRA_FLAG_SELECTED);
		}
	}

	/* Remove all RE entries queued for removal */
	RNODE_FOREACH_RE_SAFE (rn, re, next) {
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

static void zebra_rib_evaluate_mpls(struct route_node *rn)
{
	rib_dest_t *dest = rib_dest_from_rnode(rn);
	struct zebra_vrf *zvrf = vrf_info_lookup(VRF_DEFAULT);

	if (!dest)
		return;

	if (CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_LSPS)) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"%u: Scheduling all LSPs upon RIB completion",
				zvrf_id(zvrf));
		zebra_mpls_lsp_schedule(zvrf);
		mpls_unmark_lsps_for_processing(rn);
	}
}

/*
 * Utility to match route with dplane context data
 */
static bool rib_route_match_ctx(const struct route_entry *re,
				const struct zebra_dplane_ctx *ctx,
				bool is_update)
{
	bool result = false;

	if (is_update) {
		/*
		 * In 'update' case, we test info about the 'previous' or
		 * 'old' route
		 */
		if ((re->type == dplane_ctx_get_old_type(ctx)) &&
		    (re->instance == dplane_ctx_get_old_instance(ctx))) {
			result = true;

			/* TODO -- we're using this extra test, but it's not
			 * exactly clear why.
			 */
			if (re->type == ZEBRA_ROUTE_STATIC &&
			    (re->distance != dplane_ctx_get_old_distance(ctx) ||
			     re->tag != dplane_ctx_get_old_tag(ctx))) {
				result = false;
			}
		}

	} else {
		/*
		 * Ordinary, single-route case using primary context info
		 */
		if ((dplane_ctx_get_op(ctx) != DPLANE_OP_ROUTE_DELETE) &&
		    CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)) {
			/* Skip route that's been deleted */
			goto done;
		}

		if ((re->type == dplane_ctx_get_type(ctx)) &&
		    (re->instance == dplane_ctx_get_instance(ctx))) {
			result = true;

			/* TODO -- we're using this extra test, but it's not
			 * exactly clear why.
			 */
			if (re->type == ZEBRA_ROUTE_STATIC &&
			    (re->distance != dplane_ctx_get_distance(ctx) ||
			     re->tag != dplane_ctx_get_tag(ctx))) {
				result = false;
			}
		}
	}

done:

	return (result);
}

static void zebra_rib_fixup_system(struct route_node *rn)
{
	struct route_entry *re;

	RNODE_FOREACH_RE(rn, re) {
		struct nexthop *nhop;

		if (!RIB_SYSTEM_ROUTE(re))
			continue;

		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		SET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
		UNSET_FLAG(re->status, ROUTE_ENTRY_QUEUED);

		for (ALL_NEXTHOPS_PTR(re->ng, nhop)) {
			if (CHECK_FLAG(nhop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			SET_FLAG(nhop->flags, NEXTHOP_FLAG_FIB);
		}
	}
}

/*
 * Update a route from a dplane context. This consolidates common code
 * that can be used in processing of results from FIB updates, and in
 * async notification processing.
 * The return is 'true' if the installed nexthops changed; 'false' otherwise.
 */
static bool rib_update_re_from_ctx(struct route_entry *re,
				   struct route_node *rn,
				   struct zebra_dplane_ctx *ctx)
{
	char dest_str[PREFIX_STRLEN] = "";
	char nh_str[NEXTHOP_STRLEN];
	struct nexthop *nexthop, *ctx_nexthop;
	bool matched;
	const struct nexthop_group *ctxnhg;
	bool is_selected = false; /* Is 're' currently the selected re? */
	bool changed_p = false; /* Change to nexthops? */
	rib_dest_t *dest;

	/* Note well: only capturing the prefix string if debug is enabled here;
	 * unconditional log messages will have to generate the string.
	 */
	if (IS_ZEBRA_DEBUG_RIB)
		prefix2str(&(rn->p), dest_str, sizeof(dest_str));

	dest = rib_dest_from_rnode(rn);
	if (dest)
		is_selected = (re == dest->selected_fib);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("update_from_ctx: %u:%s: %sSELECTED",
			   re->vrf_id, dest_str, (is_selected ? "" : "NOT "));

	/* Update zebra's nexthop FIB flag for each nexthop that was installed.
	 * If the installed set differs from the set requested by the rib/owner,
	 * we use the fib-specific nexthop-group to record the actual FIB
	 * status.
	 */

	/* Check both fib group and notif group for equivalence.
	 *
	 * Let's assume the nexthops are ordered here to save time.
	 */
	if (nexthop_group_equal(&re->fib_ng, dplane_ctx_get_ng(ctx)) == false) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
			zlog_debug(
				"%u:%s update_from_ctx: notif nh and fib nh mismatch",
				re->vrf_id, dest_str);
		}

		matched = false;
	} else
		matched = true;

	/* If the new FIB set matches the existing FIB set, we're done. */
	if (matched) {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("%u:%s update_from_ctx(): existing fib nhg, no change",
				   re->vrf_id, dest_str);
		goto done;

	} else if (re->fib_ng.nexthop) {
		/*
		 * Free stale fib list and move on to check the rib nhg.
		 */
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("%u:%s update_from_ctx(): replacing fib nhg",
				   re->vrf_id, dest_str);
		nexthops_free(re->fib_ng.nexthop);
		re->fib_ng.nexthop = NULL;

		/* Note that the installed nexthops have changed */
		changed_p = true;
	} else {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("%u:%s update_from_ctx(): no fib nhg",
				   re->vrf_id, dest_str);
	}

	/*
	 * Compare with the rib nexthop group. The comparison here is different:
	 * the RIB group may be a superset of the list installed in the FIB. We
	 * walk the RIB group, looking for the 'installable' candidate
	 * nexthops, and then check those against the set
	 * that is actually installed.
	 *
	 * Assume nexthops are ordered here as well.
	 */
	matched = true;

	ctx_nexthop = dplane_ctx_get_ng(ctx)->nexthop;

	/* Get the first `installed` one to check against.
	 * If the dataplane doesn't set these to be what was actually installed,
	 * it will just be whatever was in re->ng?
	 */
	if (CHECK_FLAG(ctx_nexthop->flags, NEXTHOP_FLAG_RECURSIVE)
	    || !CHECK_FLAG(ctx_nexthop->flags, NEXTHOP_FLAG_ACTIVE))
		ctx_nexthop = nexthop_next_active_resolved(ctx_nexthop);

	for (ALL_NEXTHOPS_PTR(re->ng, nexthop)) {

		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			continue;

		if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
			continue;

		/* Check for a FIB nexthop corresponding to the RIB nexthop */
		if (nexthop_same(ctx_nexthop, nexthop) == false) {
			/* If the FIB doesn't know about the nexthop,
			 * it's not installed
			 */
			if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
				nexthop2str(nexthop, nh_str, sizeof(nh_str));
				zlog_debug(
					"update_from_ctx: no notif match for rib nh %s",
					nh_str);
			}
			matched = false;

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
				changed_p = true;

			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);

			/* Keep checking nexthops */
			continue;
		}

		if (CHECK_FLAG(ctx_nexthop->flags, NEXTHOP_FLAG_FIB)) {
			if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
				changed_p = true;

			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
		} else {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
				changed_p = true;

			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
		}

		ctx_nexthop = nexthop_next_active_resolved(ctx_nexthop);
	}

	/* If all nexthops were processed, we're done */
	if (matched) {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("%u:%s update_from_ctx(): rib nhg matched, changed '%s'",
				   re->vrf_id, dest_str,
				   (changed_p ? "true" : "false"));
		goto done;
	}

	/* FIB nexthop set differs from the RIB set:
	 * create a fib-specific nexthop-group
	 */
	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%u:%s update_from_ctx(): changed %s, adding new fib nhg",
			   re->vrf_id, dest_str,
			   (changed_p ? "true" : "false"));

	ctxnhg = dplane_ctx_get_ng(ctx);

	if (ctxnhg->nexthop)
		copy_nexthops(&(re->fib_ng.nexthop), ctxnhg->nexthop, NULL);
	else {
		/* Bit of a special case when the fib has _no_ installed
		 * nexthops.
		 */
		nexthop = nexthop_new();
		nexthop->type = NEXTHOP_TYPE_IPV4;
		_nexthop_add(&(re->fib_ng.nexthop), nexthop);
	}

done:
	return changed_p;
}

/*
 * Helper to locate a zebra route-node from a dplane context. This is used
 * when processing dplane results, e.g. Note well: the route-node is returned
 * with a ref held - route_unlock_node() must be called eventually.
 */
static struct route_node *
rib_find_rn_from_ctx(const struct zebra_dplane_ctx *ctx)
{
	struct route_table *table = NULL;
	struct route_node *rn = NULL;
	const struct prefix *dest_pfx, *src_pfx;

	/* Locate rn and re(s) from ctx */

	table = zebra_vrf_lookup_table_with_table_id(
		dplane_ctx_get_afi(ctx), dplane_ctx_get_safi(ctx),
		dplane_ctx_get_vrf(ctx), dplane_ctx_get_table(ctx));
	if (table == NULL) {
		if (IS_ZEBRA_DEBUG_DPLANE) {
			zlog_debug("Failed to find route for ctx: no table for afi %d, safi %d, vrf %u",
				   dplane_ctx_get_afi(ctx),
				   dplane_ctx_get_safi(ctx),
				   dplane_ctx_get_vrf(ctx));
		}
		goto done;
	}

	dest_pfx = dplane_ctx_get_dest(ctx);
	src_pfx = dplane_ctx_get_src(ctx);

	rn = srcdest_rnode_get(table, dest_pfx,
			       src_pfx ? (struct prefix_ipv6 *)src_pfx : NULL);

done:
	return rn;
}



/*
 * Route-update results processing after async dataplane update.
 */
static void rib_process_result(struct zebra_dplane_ctx *ctx)
{
	struct zebra_vrf *zvrf = NULL;
	struct route_node *rn = NULL;
	struct route_entry *re = NULL, *old_re = NULL, *rib;
	bool is_update = false;
	char dest_str[PREFIX_STRLEN] = "";
	enum dplane_op_e op;
	enum zebra_dplane_result status;
	const struct prefix *dest_pfx, *src_pfx;
	uint32_t seq;
	bool fib_changed = false;

	zvrf = vrf_info_lookup(dplane_ctx_get_vrf(ctx));
	dest_pfx = dplane_ctx_get_dest(ctx);

	/* Note well: only capturing the prefix string if debug is enabled here;
	 * unconditional log messages will have to generate the string.
	 */
	if (IS_ZEBRA_DEBUG_DPLANE)
		prefix2str(dest_pfx, dest_str, sizeof(dest_str));

	/* Locate rn and re(s) from ctx */
	rn = rib_find_rn_from_ctx(ctx);
	if (rn == NULL) {
		if (IS_ZEBRA_DEBUG_DPLANE) {
			zlog_debug("Failed to process dplane results: no route for %u:%s",
				   dplane_ctx_get_vrf(ctx), dest_str);
		}
		goto done;
	}

	srcdest_rnode_prefixes(rn, &dest_pfx, &src_pfx);

	op = dplane_ctx_get_op(ctx);
	status = dplane_ctx_get_status(ctx);

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("%u:%s Processing dplane ctx %p, op %s result %s",
			   dplane_ctx_get_vrf(ctx), dest_str, ctx,
			   dplane_op2str(op), dplane_res2str(status));

	/*
	 * Update is a bit of a special case, where we may have both old and new
	 * routes to post-process.
	 */
	is_update = dplane_ctx_is_update(ctx);

	/*
	 * Take a pass through the routes, look for matches with the context
	 * info.
	 */
	RNODE_FOREACH_RE(rn, rib) {

		if (re == NULL) {
			if (rib_route_match_ctx(rib, ctx, false))
				re = rib;
		}

		/* Check for old route match */
		if (is_update && (old_re == NULL)) {
			if (rib_route_match_ctx(rib, ctx, true /*is_update*/))
				old_re = rib;
		}

		/* Have we found the routes we need to work on? */
		if (re && ((!is_update || old_re)))
			break;
	}

	seq = dplane_ctx_get_seq(ctx);

	/*
	 * Check sequence number(s) to detect stale results before continuing
	 */
	if (re) {
		if (re->dplane_sequence != seq) {
			if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
				zlog_debug("%u:%s Stale dplane result for re %p",
					   dplane_ctx_get_vrf(ctx),
					   dest_str, re);
		} else
			UNSET_FLAG(re->status, ROUTE_ENTRY_QUEUED);
	}

	if (old_re) {
		if (old_re->dplane_sequence != dplane_ctx_get_old_seq(ctx)) {
			if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
				zlog_debug("%u:%s Stale dplane result for old_re %p",
					   dplane_ctx_get_vrf(ctx),
					   dest_str, old_re);
		} else
			UNSET_FLAG(old_re->status, ROUTE_ENTRY_QUEUED);
	}

	switch (op) {
	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
		if (status == ZEBRA_DPLANE_REQUEST_SUCCESS) {
			if (re) {
				UNSET_FLAG(re->status, ROUTE_ENTRY_FAILED);
				SET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
			}
			/*
			 * On an update operation from the same route type
			 * context retrieval currently has no way to know
			 * which was the old and which was the new.
			 * So don't unset our flags that we just set.
			 * We know redistribution is ok because the
			 * old_re in this case is used for nothing
			 * more than knowing whom to contact if necessary.
			 */
			if (old_re && old_re != re) {
				UNSET_FLAG(old_re->status, ROUTE_ENTRY_FAILED);
				UNSET_FLAG(old_re->status,
					   ROUTE_ENTRY_INSTALLED);
			}

			/* Update zebra route based on the results in
			 * the context struct.
			 */
			if (re) {
				fib_changed =
					rib_update_re_from_ctx(re, rn, ctx);

				if (!fib_changed) {
					if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
						zlog_debug("%u:%s no fib change for re",
							   dplane_ctx_get_vrf(
								   ctx),
							   dest_str);
				}

				/* Redistribute */
				redistribute_update(dest_pfx, src_pfx,
						    re, old_re);
			}

			/*
			 * System routes are weird in that they
			 * allow multiple to be installed that match
			 * to the same prefix, so after we get the
			 * result we need to clean them up so that
			 * we can actually use them.
			 */
			if ((re && RIB_SYSTEM_ROUTE(re)) ||
			    (old_re && RIB_SYSTEM_ROUTE(old_re)))
				zebra_rib_fixup_system(rn);

			if (zvrf)
				zvrf->installs++;

			/* Notify route owner */
			zsend_route_notify_owner_ctx(ctx, ZAPI_ROUTE_INSTALLED);

		} else {
			if (re) {
				SET_FLAG(re->status, ROUTE_ENTRY_FAILED);
				UNSET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
			} if (old_re)
				SET_FLAG(old_re->status, ROUTE_ENTRY_FAILED);
			if (re)
				zsend_route_notify_owner(re, dest_pfx,
							 ZAPI_ROUTE_FAIL_INSTALL);

			zlog_warn("%u:%s: Route install failed",
				  dplane_ctx_get_vrf(ctx),
				  prefix2str(dest_pfx,
					     dest_str, sizeof(dest_str)));
		}
		break;
	case DPLANE_OP_ROUTE_DELETE:
		if (re)
			SET_FLAG(re->status, ROUTE_ENTRY_FAILED);
		/*
		 * In the delete case, the zebra core datastructs were
		 * updated (or removed) at the time the delete was issued,
		 * so we're just notifying the route owner.
		 */
		if (status == ZEBRA_DPLANE_REQUEST_SUCCESS) {
			if (re) {
				UNSET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
				UNSET_FLAG(re->status, ROUTE_ENTRY_FAILED);
			}
			zsend_route_notify_owner_ctx(ctx, ZAPI_ROUTE_REMOVED);

			if (zvrf)
				zvrf->removals++;
		} else {
			if (re)
				SET_FLAG(re->status, ROUTE_ENTRY_FAILED);
			zsend_route_notify_owner_ctx(ctx,
						     ZAPI_ROUTE_REMOVE_FAIL);

			zlog_warn("%u:%s: Route Deletion failure",
				  dplane_ctx_get_vrf(ctx),
				  prefix2str(dest_pfx,
					     dest_str, sizeof(dest_str)));
		}

		/*
		 * System routes are weird in that they
		 * allow multiple to be installed that match
		 * to the same prefix, so after we get the
		 * result we need to clean them up so that
		 * we can actually use them.
		 */
		if ((re && RIB_SYSTEM_ROUTE(re)) ||
		    (old_re && RIB_SYSTEM_ROUTE(old_re)))
			zebra_rib_fixup_system(rn);
		break;
	default:
		break;
	}

	zebra_rib_evaluate_rn_nexthops(rn, seq);
	zebra_rib_evaluate_mpls(rn);
done:

	if (rn)
		route_unlock_node(rn);

	/* Return context to dataplane module */
	dplane_ctx_fini(&ctx);
}

/*
 * Handle notification from async dataplane: the dataplane has detected
 * some change to a route, and notifies zebra so that the control plane
 * can reflect that change.
 */
static void rib_process_dplane_notify(struct zebra_dplane_ctx *ctx)
{
	struct route_node *rn = NULL;
	struct route_entry *re = NULL;
	struct nexthop *nexthop;
	char dest_str[PREFIX_STRLEN] = "";
	const struct prefix *dest_pfx, *src_pfx;
	rib_dest_t *dest;
	bool fib_changed = false;
	bool debug_p = IS_ZEBRA_DEBUG_DPLANE | IS_ZEBRA_DEBUG_RIB;
	int start_count, end_count;
	dest_pfx = dplane_ctx_get_dest(ctx);

	/* Note well: only capturing the prefix string if debug is enabled here;
	 * unconditional log messages will have to generate the string.
	 */
	if (debug_p)
		prefix2str(dest_pfx, dest_str, sizeof(dest_str));

	/* Locate rn and re(s) from ctx */
	rn = rib_find_rn_from_ctx(ctx);
	if (rn == NULL) {
		if (debug_p) {
			zlog_debug("Failed to process dplane notification: no routes for %u:%s",
				   dplane_ctx_get_vrf(ctx), dest_str);
		}
		goto done;
	}

	dest = rib_dest_from_rnode(rn);
	srcdest_rnode_prefixes(rn, &dest_pfx, &src_pfx);

	if (debug_p)
		zlog_debug("%u:%s Processing dplane notif ctx %p",
			   dplane_ctx_get_vrf(ctx), dest_str, ctx);

	/*
	 * Take a pass through the routes, look for matches with the context
	 * info.
	 */
	RNODE_FOREACH_RE(rn, re) {
		if (rib_route_match_ctx(re, ctx, false /*!update*/))
			break;
	}

	/* No match? Nothing we can do */
	if (re == NULL) {
		if (debug_p)
			zlog_debug("%u:%s Unable to process dplane notification: no entry for type %s",
				   dplane_ctx_get_vrf(ctx), dest_str,
				   zebra_route_string(
					   dplane_ctx_get_type(ctx)));

		goto done;
	}

	/* Ensure we clear the QUEUED flag */
	UNSET_FLAG(re->status, ROUTE_ENTRY_QUEUED);

	/* Is this a notification that ... matters? We only really care about
	 * the route that is currently selected for installation.
	 */
	if (re != dest->selected_fib) {
		/* TODO -- don't skip processing entirely? We might like to
		 * at least report on the event.
		 */
		if (debug_p)
			zlog_debug("%u:%s dplane notif, but type %s not selected_fib",
				   dplane_ctx_get_vrf(ctx), dest_str,
				   zebra_route_string(
					   dplane_ctx_get_type(ctx)));
		goto done;
	}

	/* We'll want to determine whether the installation status of the
	 * route has changed: we'll check the status before processing,
	 * and then again if there's been a change.
	 */
	start_count = 0;
	for (ALL_NEXTHOPS_PTR(rib_active_nhg(re), nexthop)) {
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
			start_count++;
	}

	/* Update zebra's nexthop FIB flags based on the context struct's
	 * nexthops.
	 */
	fib_changed = rib_update_re_from_ctx(re, rn, ctx);

	if (!fib_changed) {
		if (debug_p)
			zlog_debug("%u:%s No change from dplane notification",
				   dplane_ctx_get_vrf(ctx), dest_str);

		goto done;
	}

	/*
	 * Perform follow-up work if the actual status of the prefix
	 * changed.
	 */

	end_count = 0;
	for (ALL_NEXTHOPS_PTR(rib_active_nhg(re), nexthop)) {
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
			end_count++;
	}

	/* Various fib transitions: changed nexthops; from installed to
	 * not-installed; or not-installed to installed.
	 */
	if (start_count > 0 && end_count > 0) {
		if (debug_p)
			zlog_debug("%u:%s applied nexthop changes from dplane notification",
				   dplane_ctx_get_vrf(ctx), dest_str);

		/* Changed nexthops - update kernel/others */
		dplane_route_notif_update(rn, re,
					  DPLANE_OP_ROUTE_UPDATE, ctx);

	} else if (start_count == 0 && end_count > 0) {
		if (debug_p)
			zlog_debug("%u:%s installed transition from dplane notification",
				   dplane_ctx_get_vrf(ctx), dest_str);

		/* We expect this to be the selected route, so we want
		 * to tell others about this transition.
		 */
		SET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);

		/* Changed nexthops - update kernel/others */
		dplane_route_notif_update(rn, re, DPLANE_OP_ROUTE_INSTALL, ctx);

		/* Redistribute, lsp, and nht update */
		redistribute_update(dest_pfx, src_pfx, re, NULL);

		zebra_rib_evaluate_rn_nexthops(
			rn, zebra_router_get_next_sequence());

		zebra_rib_evaluate_mpls(rn);

	} else if (start_count > 0 && end_count == 0) {
		if (debug_p)
			zlog_debug("%u:%s un-installed transition from dplane notification",
				   dplane_ctx_get_vrf(ctx), dest_str);

		/* Transition from _something_ installed to _nothing_
		 * installed.
		 */
		/* We expect this to be the selected route, so we want
		 * to tell others about this transistion.
		 */
		UNSET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);

		/* Changed nexthops - update kernel/others */
		dplane_route_notif_update(rn, re, DPLANE_OP_ROUTE_DELETE, ctx);

		/* Redistribute, lsp, and nht update */
		redistribute_delete(dest_pfx, src_pfx, re, NULL);

		zebra_rib_evaluate_rn_nexthops(
			rn, zebra_router_get_next_sequence());

		zebra_rib_evaluate_mpls(rn);
	}

done:
	if (rn)
		route_unlock_node(rn);

	/* Return context to dataplane module */
	dplane_ctx_fini(&ctx);
}

static void process_subq_nhg(struct listnode *lnode)
{
	struct nhg_ctx *ctx = NULL;
	uint8_t qindex = route_info[ZEBRA_ROUTE_NHG].meta_q_map;

	ctx = listgetdata(lnode);

	if (!ctx)
		return;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("NHG Context id=%u dequeued from sub-queue %u",
			   ctx->id, qindex);

	rib_nhg_process(ctx);
}

static void process_subq_route(struct listnode *lnode, uint8_t qindex)
{
	struct route_node *rnode = NULL;
	rib_dest_t *dest = NULL;
	struct zebra_vrf *zvrf = NULL;

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
}

/* Take a list of route_node structs and return 1, if there was a record
 * picked from it and processed by rib_process(). Don't process more,
 * than one RN record; operate only in the specified sub-queue.
 */
static unsigned int process_subq(struct list *subq, uint8_t qindex)
{
	struct listnode *lnode = listhead(subq);

	if (!lnode)
		return 0;

	if (qindex == route_info[ZEBRA_ROUTE_NHG].meta_q_map)
		process_subq_nhg(lnode);
	else
		process_subq_route(lnode, qindex);

	list_delete_node(subq, lnode);

	return 1;
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
	uint32_t queue_len, queue_limit;

	/* Ensure there's room for more dataplane updates */
	queue_limit = dplane_get_in_queue_limit();
	queue_len = dplane_get_in_queue_len();
	if (queue_len > queue_limit) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("rib queue: dplane queue len %u, limit %u, retrying",
				   queue_len, queue_limit);

		/* Ensure that the meta-queue is actually enqueued */
		if (work_queue_empty(zrouter.ribq))
			work_queue_add(zrouter.ribq, zrouter.mq);

		return WQ_QUEUE_BLOCKED;
	}

	for (i = 0; i < MQ_SIZE; i++)
		if (process_subq(mq->subq[i], i)) {
			mq->size--;
			break;
		}
	return mq->size ? WQ_REQUEUE : WQ_SUCCESS;
}


/*
 * Look into the RN and queue it into the highest priority queue
 * at this point in time for processing.
 *
 * We will enqueue a route node only once per invocation.
 *
 * There are two possibilities here that should be kept in mind.
 * If the original invocation has not been pulled off for processing
 * yet, A subsuquent invocation can have a route entry with a better
 * meta queue index value and we can have a situation where
 * we might have the same node enqueued 2 times.  Not necessarily
 * an optimal situation but it should be ok.
 *
 * The other possibility is that the original invocation has not
 * been pulled off for processing yet, A subsusquent invocation
 * doesn't have a route_entry with a better meta-queue and the
 * original metaqueue index value will win and we'll end up with
 * the route node enqueued once.
 */
static int rib_meta_queue_add(struct meta_queue *mq, void *data)
{
	struct route_node *rn = NULL;
	struct route_entry *re = NULL, *curr_re = NULL;
	uint8_t qindex = MQ_SIZE, curr_qindex = MQ_SIZE;

	rn = (struct route_node *)data;

	RNODE_FOREACH_RE (rn, curr_re) {
		curr_qindex = route_info[curr_re->type].meta_q_map;

		if (curr_qindex <= qindex) {
			re = curr_re;
			qindex = curr_qindex;
		}
	}

	if (!re)
		return -1;

	/* Invariant: at this point we always have rn->info set. */
	if (CHECK_FLAG(rib_dest_from_rnode(rn)->flags,
		       RIB_ROUTE_QUEUED(qindex))) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			rnode_debug(rn, re->vrf_id,
				    "rn %p is already queued in sub-queue %u",
				    (void *)rn, qindex);
		return -1;
	}

	SET_FLAG(rib_dest_from_rnode(rn)->flags, RIB_ROUTE_QUEUED(qindex));
	listnode_add(mq->subq[qindex], rn);
	route_lock_node(rn);
	mq->size++;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		rnode_debug(rn, re->vrf_id, "queued rn %p into sub-queue %u",
			    (void *)rn, qindex);

	return 0;
}

static int rib_meta_queue_nhg_add(struct meta_queue *mq, void *data)
{
	struct nhg_ctx *ctx = NULL;
	uint8_t qindex = route_info[ZEBRA_ROUTE_NHG].meta_q_map;

	ctx = (struct nhg_ctx *)data;

	if (!ctx)
		return -1;

	listnode_add(mq->subq[qindex], ctx);
	mq->size++;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("NHG Context id=%u queued into sub-queue %u",
			   ctx->id, qindex);

	return 0;
}

static int mq_add_handler(void *data,
			  int (*mq_add_func)(struct meta_queue *mq, void *data))
{
	if (zrouter.ribq == NULL) {
		flog_err(EC_ZEBRA_WQ_NONEXISTENT,
			 "%s: work_queue does not exist!", __func__);
		return -1;
	}

	/*
	 * The RIB queue should normally be either empty or holding the only
	 * work_queue_item element. In the latter case this element would
	 * hold a pointer to the meta queue structure, which must be used to
	 * actually queue the route nodes to process. So create the MQ
	 * holder, if necessary, then push the work into it in any case.
	 * This semantics was introduced after 0.99.9 release.
	 */
	if (work_queue_empty(zrouter.ribq))
		work_queue_add(zrouter.ribq, zrouter.mq);

	return mq_add_func(zrouter.mq, data);
}

/* Add route_node to work queue and schedule processing */
int rib_queue_add(struct route_node *rn)
{
	assert(rn);

	/* Pointless to queue a route_node with no RIB entries to add or remove
	 */
	if (!rnode_to_ribs(rn)) {
		zlog_debug("%s: called for route_node (%p, %d) with no ribs",
			   __func__, (void *)rn, rn->lock);
		zlog_backtrace(LOG_DEBUG);
		return -1;
	}

	return mq_add_handler(rn, &rib_meta_queue_add);
}

int rib_queue_nhg_add(struct nhg_ctx *ctx)
{
	assert(ctx);

	return mq_add_handler(ctx, &rib_meta_queue_nhg_add);
}

/* Create new meta queue.
   A destructor function doesn't seem to be necessary here.
 */
static struct meta_queue *meta_queue_new(void)
{
	struct meta_queue *new;
	unsigned i;

	new = XCALLOC(MTYPE_WORK_QUEUE, sizeof(struct meta_queue));

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
		list_delete(&mq->subq[i]);

	XFREE(MTYPE_WORK_QUEUE, mq);
}

/* initialise zebra rib work queue */
static void rib_queue_init(void)
{
	if (!(zrouter.ribq = work_queue_new(zrouter.master,
					    "route_node processing"))) {
		flog_err(EC_ZEBRA_WQ_NONEXISTENT,
			 "%s: could not initialise work queue!", __func__);
		return;
	}

	/* fill in the work queue spec */
	zrouter.ribq->spec.workfunc = &meta_queue_process;
	zrouter.ribq->spec.errorfunc = NULL;
	zrouter.ribq->spec.completion_func = NULL;
	/* XXX: TODO: These should be runtime configurable via vty */
	zrouter.ribq->spec.max_retries = 3;
	zrouter.ribq->spec.hold = ZEBRA_RIB_PROCESS_HOLD_TIME;
	zrouter.ribq->spec.retry = ZEBRA_RIB_PROCESS_RETRY_TIME;

	if (!(zrouter.mq = meta_queue_new())) {
		flog_err(EC_ZEBRA_WQ_NONEXISTENT,
			 "%s: could not initialise meta queue!", __func__);
		return;
	}
	return;
}

rib_dest_t *zebra_rib_create_dest(struct route_node *rn)
{
	rib_dest_t *dest;

	dest = XCALLOC(MTYPE_RIB_DEST, sizeof(rib_dest_t));
	rnh_list_init(&dest->nht);
	route_lock_node(rn); /* rn route table reference */
	rn->info = dest;
	dest->rnode = rn;

	return dest;
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
	rib_dest_t *dest;
	afi_t afi;
	const char *rmap_name;

	assert(re && rn);

	dest = rib_dest_from_rnode(rn);
	if (!dest) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			rnode_debug(rn, re->vrf_id, "rn %p adding dest", rn);

		dest = zebra_rib_create_dest(rn);
	}

	re_list_add_head(&dest->routes, re);

	afi = (rn->p.family == AF_INET)
		      ? AFI_IP
		      : (rn->p.family == AF_INET6) ? AFI_IP6 : AFI_MAX;
	if (is_zebra_import_table_enabled(afi, re->vrf_id, re->table)) {
		struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(re->vrf_id);

		rmap_name = zebra_get_import_table_route_map(afi, re->table);
		zebra_add_import_table_entry(zvrf, rn, re, rmap_name);
	} else if (process)
		rib_queue_add(rn);
}

static void rib_addnode(struct route_node *rn,
			struct route_entry *re, int process)
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
	struct nhg_hash_entry *nhe = NULL;

	assert(rn && re);

	if (IS_ZEBRA_DEBUG_RIB)
		rnode_debug(rn, re->vrf_id, "rn %p, re %p", (void *)rn,
			    (void *)re);

	dest = rib_dest_from_rnode(rn);

	re_list_del(&dest->routes, re);

	if (dest->selected_fib == re)
		dest->selected_fib = NULL;

	if (re->nhe_id) {
		nhe = zebra_nhg_lookup_id(re->nhe_id);
		if (nhe)
			zebra_nhg_decrement_ref(nhe);
	} else if (re->ng)
		nexthop_group_delete(&re->ng);

	nexthops_free(re->fib_ng.nexthop);

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
	if (is_zebra_import_table_enabled(afi, re->vrf_id, re->table)) {
		struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(re->vrf_id);

		zebra_del_import_table_entry(zvrf, rn, re);
		/* Just clean up if non main table */
		if (IS_ZEBRA_DEBUG_RIB) {
			char buf[SRCDEST2STR_BUFFER];
			srcdest_rnode2str(rn, buf, sizeof(buf));
			zlog_debug("%u:%s: Freeing route rn %p, re %p (%s)",
				   re->vrf_id, buf, rn, re,
				   zebra_route_string(re->type));
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
	const struct prefix *src_p = src_pp.p;
	bool is_srcdst = src_p && src_p->prefixlen;
	char straddr[PREFIX_STRLEN];
	char srcaddr[PREFIX_STRLEN];
	char nhname[PREFIX_STRLEN];
	struct nexthop *nexthop;

	zlog_debug("%s: dumping RE entry %p for %s%s%s vrf %u", func,
		   (const void *)re, prefix2str(pp, straddr, sizeof(straddr)),
		   is_srcdst ? " from " : "",
		   is_srcdst ? prefix2str(src_pp, srcaddr, sizeof(srcaddr))
			     : "",
		   re->vrf_id);
	zlog_debug("%s: uptime == %lu, type == %u, instance == %d, table == %d",
		   straddr, (unsigned long)re->uptime, re->type, re->instance,
		   re->table);
	zlog_debug(
		"%s: metric == %u, mtu == %u, distance == %u, flags == %u, status == %u",
		straddr, re->metric, re->mtu, re->distance, re->flags, re->status);
	zlog_debug("%s: nexthop_num == %u, nexthop_active_num == %u", straddr,
		   nexthop_group_nexthop_num(re->ng),
		   nexthop_group_active_nexthop_num(re->ng));

	for (ALL_NEXTHOPS_PTR(re->ng, nexthop)) {
		struct interface *ifp;
		struct vrf *vrf = vrf_lookup_by_id(nexthop->vrf_id);

		switch (nexthop->type) {
		case NEXTHOP_TYPE_BLACKHOLE:
			sprintf(nhname, "Blackhole");
			break;
		case NEXTHOP_TYPE_IFINDEX:
			ifp = if_lookup_by_index(nexthop->ifindex,
						 nexthop->vrf_id);
			sprintf(nhname, "%s", ifp ? ifp->name : "Unknown");
			break;
		case NEXTHOP_TYPE_IPV4:
			/* fallthrough */
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			inet_ntop(AF_INET, &nexthop->gate, nhname,
				  INET6_ADDRSTRLEN);
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			inet_ntop(AF_INET6, &nexthop->gate, nhname,
				  INET6_ADDRSTRLEN);
			break;
		}
		zlog_debug("%s: %s %s[%u] vrf %s(%u) with flags %s%s%s%s%s%s",
			   straddr, (nexthop->rparent ? "  NH" : "NH"), nhname,
			   nexthop->ifindex, vrf ? vrf->name : "Unknown",
			   nexthop->vrf_id,
			   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)
				    ? "ACTIVE "
				    : ""),
			   (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED)
				    ? "FIB "
				    : ""),
			   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE)
				    ? "RECURSIVE "
				    : ""),
			   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK)
				    ? "ONLINK "
				    : ""),
			   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_MATCHED)
				    ? "MATCHED "
				    : ""),
			   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE)
				    ? "DUPLICATE "
				    : ""));
	}
	zlog_debug("%s: dump complete", straddr);
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
		flog_err(EC_ZEBRA_TABLE_LOOKUP_FAILED,
			 "%s:%u zebra_vrf_table() returned NULL", __func__,
			 vrf_id);
		return;
	}

	/* Scan the RIB table for exactly matching RE entry. */
	rn = route_node_lookup(table, (struct prefix *)p);

	/* No route for this prefix. */
	if (!rn) {
		zlog_debug("%s:%u lookup failed for %s", __func__, vrf_id,
			   prefix2str((struct prefix *)p, prefix_buf,
				      sizeof(prefix_buf)));
		return;
	}

	/* Unlock node. */
	route_unlock_node(rn);

	/* let's go */
	RNODE_FOREACH_RE (rn, re) {
		zlog_debug("%s:%u rn %p, re %p: %s, %s",
			   __func__, vrf_id,
			   (void *)rn, (void *)re,
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
	rib_dest_t *dest;

	if (NULL == (table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, vrf_id))) {
		flog_err(EC_ZEBRA_TABLE_LOOKUP_FAILED,
			 "%s:%u zebra_vrf_table() returned NULL", __func__,
			 vrf_id);
		return;
	}

	/* No matches would be the simplest case. */
	if (NULL == (rn = route_node_lookup(table, (struct prefix *)p)))
		return;

	/* Unlock node. */
	route_unlock_node(rn);

	dest = rib_dest_from_rnode(rn);
	/* Check all RE entries. In case any changes have to be done, requeue
	 * the RN into RIBQ head. If the routing message about the new connected
	 * route (generated by the IP address we are going to assign very soon)
	 * comes before the RIBQ is processed, the new RE entry will join
	 * RIBQ record already on head. This is necessary for proper
	 * revalidation
	 * of the rest of the RE.
	 */
	if (dest->selected_fib) {
		if (IS_ZEBRA_DEBUG_RIB) {
			char buf[PREFIX_STRLEN];

			zlog_debug("%u:%s: freeing way for connected prefix",
				   dest->selected_fib->vrf_id,
				   prefix2str(&rn->p, buf, sizeof(buf)));
			route_entry_dump(&rn->p, NULL, dest->selected_fib);
		}
		rib_uninstall(rn, dest->selected_fib);
		rib_queue_add(rn);
	}
}

int rib_add_multipath(afi_t afi, safi_t safi, struct prefix *p,
		      struct prefix_ipv6 *src_p, struct route_entry *re)
{
	struct nhg_hash_entry *nhe = NULL;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *same = NULL;
	int ret = 0;

	if (!re)
		return 0;

	assert(!src_p || !src_p->prefixlen || afi == AFI_IP6);

	/* Lookup table.  */
	table = zebra_vrf_get_table_with_table_id(afi, safi, re->vrf_id,
						  re->table);
	if (!table) {
		if (re->ng)
			nexthop_group_delete(&re->ng);
		XFREE(MTYPE_RE, re);
		return 0;
	}

	if (re->nhe_id) {
		nhe = zebra_nhg_lookup_id(re->nhe_id);

		if (!nhe) {
			flog_err(
				EC_ZEBRA_TABLE_LOOKUP_FAILED,
				"Zebra failed to find the nexthop hash entry for id=%u in a route entry",
				re->nhe_id);
			XFREE(MTYPE_RE, re);
			return -1;
		}
	} else {
		nhe = zebra_nhg_rib_find(0, re->ng, afi);

		/*
		 * The nexthops got copied over into an nhe,
		 * so free them now.
		 */
		nexthop_group_delete(&re->ng);

		if (!nhe) {
			char buf[PREFIX_STRLEN] = "";
			char buf2[PREFIX_STRLEN] = "";

			flog_err(
				EC_ZEBRA_TABLE_LOOKUP_FAILED,
				"Zebra failed to find or create a nexthop hash entry for %s%s%s",
				prefix2str(p, buf, sizeof(buf)),
				src_p ? " from " : "",
				src_p ? prefix2str(src_p, buf2, sizeof(buf2))
				      : "");

			XFREE(MTYPE_RE, re);
			return -1;
		}
	}

	/*
	 * Attach the re to the nhe's nexthop group.
	 *
	 * TODO: This will need to change when we start getting IDs from upper
	 * level protocols, as the refcnt might be wrong, since it checks
	 * if old_id != new_id.
	 */
	zebra_nhg_re_update_ref(re, nhe);

	/* Make it sure prefixlen is applied to the prefix. */
	apply_mask(p);
	if (src_p)
		apply_mask_ipv6(src_p);

	/* Set default distance by route type. */
	if (re->distance == 0)
		re->distance = route_distance(re->type);

	/* Lookup route node.*/
	rn = srcdest_rnode_get(table, p, src_p);

	/*
	 * If same type of route are installed, treat it as a implicit
	 * withdraw.
	 * If the user has specified the No route replace semantics
	 * for the install don't do a route replace.
	 */
	RNODE_FOREACH_RE (rn, same) {
		if (CHECK_FLAG(same->status, ROUTE_ENTRY_REMOVED))
			continue;

		if (same->type != re->type)
			continue;
		if (same->instance != re->instance)
			continue;
		if (same->type == ZEBRA_ROUTE_KERNEL
		    && same->metric != re->metric)
			continue;

		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_RR_USE_DISTANCE) &&
		    same->distance != re->distance)
			continue;

		/*
		 * We should allow duplicate connected routes
		 * because of IPv6 link-local routes and unnumbered
		 * interfaces on Linux.
		 */
		if (same->type != ZEBRA_ROUTE_CONNECT)
			break;
	}

	/* If this route is kernel/connected route, notify the dataplane. */
	if (RIB_SYSTEM_ROUTE(re)) {
		/* Notify dataplane */
		dplane_sys_route_add(rn, re);
	}

	/* Link new re to node.*/
	if (IS_ZEBRA_DEBUG_RIB) {
		rnode_debug(rn, re->vrf_id,
			    "Inserting route rn %p, re %p (%s) existing %p",
			    rn, re, zebra_route_string(re->type), same);

		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			route_entry_dump(p, src_p, re);
	}

	SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
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
		unsigned short instance, int flags, struct prefix *p,
		struct prefix_ipv6 *src_p, const struct nexthop *nh,
		uint32_t nhe_id, uint32_t table_id, uint32_t metric,
		uint8_t distance, bool fromkernel)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	struct route_entry *fib = NULL;
	struct route_entry *same = NULL;
	struct nexthop *rtnh;
	char buf2[INET6_ADDRSTRLEN];
	rib_dest_t *dest;

	assert(!src_p || !src_p->prefixlen || afi == AFI_IP6);

	/* Lookup table.  */
	table = zebra_vrf_lookup_table_with_table_id(afi, safi, vrf_id,
						     table_id);
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

		if (IS_ZEBRA_DEBUG_RIB) {
			struct vrf *vrf = vrf_lookup_by_id(vrf_id);

			zlog_debug("%s[%d]:%s%s%s doesn't exist in rib",
				   vrf->name, table_id, dst_buf,
				   (src_buf[0] != '\0') ? " from " : "",
				   src_buf);
		}
		return;
	}

	dest = rib_dest_from_rnode(rn);
	fib = dest->selected_fib;

	/* Lookup same type route. */
	RNODE_FOREACH_RE (rn, re) {
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		if (re->type != type)
			continue;
		if (re->instance != instance)
			continue;
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_RR_USE_DISTANCE) &&
		    distance != re->distance)
			continue;

		if (re->type == ZEBRA_ROUTE_KERNEL && re->metric != metric)
			continue;
		if (re->type == ZEBRA_ROUTE_CONNECT && (rtnh = re->ng->nexthop)
		    && rtnh->type == NEXTHOP_TYPE_IFINDEX && nh) {
			if (rtnh->ifindex != nh->ifindex)
				continue;
			same = re;
			break;
		}

		/* Make sure that the route found has the same gateway. */
		if (nhe_id && re->nhe_id == nhe_id) {
			same = re;
			break;
		}

		if (nh == NULL) {
			same = re;
			break;
		}
		for (ALL_NEXTHOPS_PTR(re->ng, rtnh)) {
			/*
			 * No guarantee all kernel send nh with labels
			 * on delete.
			 */
			if (nexthop_same_no_labels(rtnh, nh)) {
				same = re;
				break;
			}
		}

		if (same)
			break;
	}
	/* If same type of route can't be found and this message is from
	   kernel. */
	if (!same) {
		/*
		 * In the past(HA!) we could get here because
		 * we were receiving a route delete from the
		 * kernel and we're not marking the proto
		 * as coming from it's appropriate originator.
		 * Now that we are properly noticing the fact
		 * that the kernel has deleted our route we
		 * are not going to get called in this path
		 * I am going to leave this here because
		 * this might still work this way on non-linux
		 * platforms as well as some weird state I have
		 * not properly thought of yet.
		 * If we can show that this code path is
		 * dead then we can remove it.
		 */
		if (fib && CHECK_FLAG(flags, ZEBRA_FLAG_SELFROUTE)) {
			if (IS_ZEBRA_DEBUG_RIB) {
				rnode_debug(rn, vrf_id,
					    "rn %p, re %p (%s) was deleted from kernel, adding",
					    rn, fib,
					    zebra_route_string(fib->type));
			}
			if (allow_delete) {
				UNSET_FLAG(fib->status, ROUTE_ENTRY_INSTALLED);
				/* Unset flags. */
				for (rtnh = fib->ng->nexthop; rtnh;
				     rtnh = rtnh->next)
					UNSET_FLAG(rtnh->flags,
						   NEXTHOP_FLAG_FIB);

				/*
				 * This is a non FRR route
				 * as such we should mark
				 * it as deleted
				 */
				dest->selected_fib = NULL;
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
						inet_ntop(afi2family(afi),
							  &nh->gate, buf2,
							  sizeof(buf2)),
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

	if (same) {
		if (fromkernel && CHECK_FLAG(flags, ZEBRA_FLAG_SELFROUTE)
		    && !allow_delete) {
			rib_install_kernel(rn, same, NULL);
			route_unlock_node(rn);

			return;
		}

		/* Special handling for IPv4 or IPv6 routes sourced from
		 * EVPN - the nexthop (and associated MAC) need to be
		 * uninstalled if no more refs.
		 */
		if (CHECK_FLAG(flags, ZEBRA_FLAG_EVPN_ROUTE)) {
			struct nexthop *tmp_nh;

			for (ALL_NEXTHOPS_PTR(re->ng, tmp_nh)) {
				struct ipaddr vtep_ip;

				memset(&vtep_ip, 0, sizeof(struct ipaddr));
				if (afi == AFI_IP) {
					vtep_ip.ipa_type = IPADDR_V4;
					memcpy(&(vtep_ip.ipaddr_v4),
					       &(tmp_nh->gate.ipv4),
					       sizeof(struct in_addr));
				} else {
					vtep_ip.ipa_type = IPADDR_V6;
					memcpy(&(vtep_ip.ipaddr_v6),
					       &(tmp_nh->gate.ipv6),
					       sizeof(struct in6_addr));
				}
				zebra_vxlan_evpn_vrf_route_del(re->vrf_id,
							       &vtep_ip, p);
			}
		}

		/* Notify dplane if system route changes */
		if (RIB_SYSTEM_ROUTE(re))
			dplane_sys_route_del(rn, same);

		rib_delnode(rn, same);
	}

	route_unlock_node(rn);
	return;
}


int rib_add(afi_t afi, safi_t safi, vrf_id_t vrf_id, int type,
	    unsigned short instance, int flags, struct prefix *p,
	    struct prefix_ipv6 *src_p, const struct nexthop *nh,
	    uint32_t nhe_id, uint32_t table_id, uint32_t metric, uint32_t mtu,
	    uint8_t distance, route_tag_t tag)
{
	struct route_entry *re = NULL;
	struct nexthop *nexthop = NULL;

	/* Allocate new route_entry structure. */
	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));
	re->type = type;
	re->instance = instance;
	re->distance = distance;
	re->flags = flags;
	re->metric = metric;
	re->mtu = mtu;
	re->table = table_id;
	re->vrf_id = vrf_id;
	re->uptime = monotime(NULL);
	re->tag = tag;
	re->nhe_id = nhe_id;

	if (!nhe_id) {
		re->ng = nexthop_group_new();

		/* Add nexthop. */
		nexthop = nexthop_new();
		*nexthop = *nh;
		route_entry_nexthop_add(re, nexthop);
	}

	return rib_add_multipath(afi, safi, p, src_p, re);
}

static const char *rib_update_event2str(rib_update_event_t event)
{
	const char *ret = "UNKNOWN";

	switch (event) {
	case RIB_UPDATE_KERNEL:
		ret = "RIB_UPDATE_KERNEL";
		break;
	case RIB_UPDATE_RMAP_CHANGE:
		ret = "RIB_UPDATE_RMAP_CHANGE";
		break;
	case RIB_UPDATE_OTHER:
		ret = "RIB_UPDATE_OTHER";
		break;
	case RIB_UPDATE_MAX:
		break;
	}

	return ret;
}


/* Schedule route nodes to be processed if they match the type */
static void rib_update_route_node(struct route_node *rn, int type)
{
	struct route_entry *re, *next;
	bool re_changed = false;

	RNODE_FOREACH_RE_SAFE (rn, re, next) {
		if (type == ZEBRA_ROUTE_ALL || type == re->type) {
			SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
			re_changed = true;
		}
	}

	if (re_changed)
		rib_queue_add(rn);
}

/* Schedule routes of a particular table (address-family) based on event. */
void rib_update_table(struct route_table *table, rib_update_event_t event)
{
	struct route_node *rn;

	if (IS_ZEBRA_DEBUG_EVENT) {
		struct zebra_vrf *zvrf;
		struct vrf *vrf;

		zvrf = table->info ? ((rib_table_info_t *)table->info)->zvrf
				   : NULL;
		vrf = zvrf ? zvrf->vrf : NULL;

		zlog_debug("%s: %s VRF %s Table %u event %s", __func__,
			   table->info ? afi2str(
				   ((rib_table_info_t *)table->info)->afi)
				       : "Unknown",
			   vrf ? vrf->name : "Unknown",
			   zvrf ? zvrf->table_id : 0,
			   rib_update_event2str(event));
	}

	/* Walk all routes and queue for processing, if appropriate for
	 * the trigger event.
	 */
	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		/*
		 * If we are looking at a route node and the node
		 * has already been queued  we don't
		 * need to queue it up again
		 */
		if (rn->info
		    && CHECK_FLAG(rib_dest_from_rnode(rn)->flags,
				  RIB_ROUTE_ANY_QUEUED))
			continue;

		switch (event) {
		case RIB_UPDATE_KERNEL:
			rib_update_route_node(rn, ZEBRA_ROUTE_KERNEL);
			break;
		case RIB_UPDATE_RMAP_CHANGE:
		case RIB_UPDATE_OTHER:
			rib_update_route_node(rn, ZEBRA_ROUTE_ALL);
			break;
		default:
			break;
		}
	}
}

static void rib_update_handle_vrf(vrf_id_t vrf_id, rib_update_event_t event)
{
	struct route_table *table;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s: Handling VRF %s event %s", __func__,
			   vrf_id_to_name(vrf_id), rib_update_event2str(event));

	/* Process routes of interested address-families. */
	table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, vrf_id);
	if (table)
		rib_update_table(table, event);

	table = zebra_vrf_table(AFI_IP6, SAFI_UNICAST, vrf_id);
	if (table)
		rib_update_table(table, event);
}

static void rib_update_handle_vrf_all(rib_update_event_t event)
{
	struct zebra_router_table *zrt;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s: Handling VRF (ALL) event %s", __func__,
			   rib_update_event2str(event));

	/* Just iterate over all the route tables, rather than vrf lookups */
	RB_FOREACH (zrt, zebra_router_table_head, &zrouter.tables)
		rib_update_table(zrt->table, event);
}

struct rib_update_ctx {
	rib_update_event_t event;
	bool vrf_all;
	vrf_id_t vrf_id;
};

static struct rib_update_ctx *rib_update_ctx_init(vrf_id_t vrf_id,
						  rib_update_event_t event)
{
	struct rib_update_ctx *ctx;

	ctx = XCALLOC(MTYPE_RIB_UPDATE_CTX, sizeof(struct rib_update_ctx));

	ctx->event = event;
	ctx->vrf_id = vrf_id;

	return ctx;
}

static void rib_update_ctx_fini(struct rib_update_ctx **ctx)
{
	XFREE(MTYPE_RIB_UPDATE_CTX, *ctx);

	*ctx = NULL;
}

static int rib_update_handler(struct thread *thread)
{
	struct rib_update_ctx *ctx;

	ctx = THREAD_ARG(thread);

	if (ctx->vrf_all)
		rib_update_handle_vrf_all(ctx->event);
	else
		rib_update_handle_vrf(ctx->vrf_id, ctx->event);

	rib_update_ctx_fini(&ctx);

	return 0;
}

/*
 * Thread list to ensure we don't schedule a ton of events
 * if interfaces are flapping for instance.
 */
static struct thread *t_rib_update_threads[RIB_UPDATE_MAX];

/* Schedule a RIB update event for specific vrf */
void rib_update_vrf(vrf_id_t vrf_id, rib_update_event_t event)
{
	struct rib_update_ctx *ctx;

	ctx = rib_update_ctx_init(vrf_id, event);

	/* Don't worry about making sure multiple rib updates for specific vrf
	 * are scheduled at once for now. If it becomes a problem, we can use a
	 * lookup of some sort to keep track of running threads via t_vrf_id
	 * like how we are doing it in t_rib_update_threads[].
	 */
	thread_add_event(zrouter.master, rib_update_handler, ctx, 0, NULL);

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s: Scheduled VRF %s, event %s", __func__,
			   vrf_id_to_name(ctx->vrf_id),
			   rib_update_event2str(event));
}

/* Schedule a RIB update event for all vrfs */
void rib_update(rib_update_event_t event)
{
	struct rib_update_ctx *ctx;

	ctx = rib_update_ctx_init(0, event);

	ctx->vrf_all = true;

	if (!thread_add_event(zrouter.master, rib_update_handler, ctx, 0,
			      &t_rib_update_threads[event]))
		rib_update_ctx_fini(&ctx); /* Already scheduled */
	else if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s: Schedued VRF (ALL), event %s", __func__,
			   rib_update_event2str(event));
}

/* Delete self installed routes after zebra is relaunched.  */
void rib_sweep_table(struct route_table *table)
{
	struct route_node *rn;
	struct route_entry *re;
	struct route_entry *next;
	struct nexthop *nexthop;

	if (!table)
		return;

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		RNODE_FOREACH_RE_SAFE (rn, re, next) {

			if (IS_ZEBRA_DEBUG_RIB)
				route_entry_dump(&rn->p, NULL, re);

			if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
				continue;

			if (!CHECK_FLAG(re->flags, ZEBRA_FLAG_SELFROUTE))
				continue;

			/*
			 * If routes are older than startup_time then
			 * we know we read them in from the kernel.
			 * As such we can safely remove them.
			 */
			if (zrouter.startup_time < re->uptime)
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
			SET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
			for (ALL_NEXTHOPS_PTR(re->ng, nexthop))
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);

			rib_uninstall_kernel(rn, re);
			rib_delnode(rn, re);
		}
	}
}

/* Sweep all RIB tables.  */
int rib_sweep_route(struct thread *t)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		if ((zvrf = vrf->info) == NULL)
			continue;

		rib_sweep_table(zvrf->table[AFI_IP][SAFI_UNICAST]);
		rib_sweep_table(zvrf->table[AFI_IP6][SAFI_UNICAST]);
	}

	zebra_router_sweep_route();
	zebra_router_sweep_nhgs();

	return 0;
}

/* Remove specific by protocol routes from 'table'. */
unsigned long rib_score_proto_table(uint8_t proto, unsigned short instance,
				    struct route_table *table)
{
	struct route_node *rn;
	struct route_entry *re;
	struct route_entry *next;
	unsigned long n = 0;

	if (table)
		for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
			RNODE_FOREACH_RE_SAFE (rn, re, next) {
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
unsigned long rib_score_proto(uint8_t proto, unsigned short instance)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	struct other_route_table *ort;
	unsigned long cnt = 0;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		zvrf = vrf->info;
		if (!zvrf)
			continue;

		cnt += rib_score_proto_table(proto, instance,
					     zvrf->table[AFI_IP][SAFI_UNICAST])
		       + rib_score_proto_table(
			       proto, instance,
			       zvrf->table[AFI_IP6][SAFI_UNICAST]);

		frr_each(otable, &zvrf->other_tables, ort) cnt +=
			rib_score_proto_table(proto, instance, ort->table);
	}

	return cnt;
}

/* Close RIB and clean up kernel routes. */
void rib_close_table(struct route_table *table)
{
	struct route_node *rn;
	rib_table_info_t *info;
	rib_dest_t *dest;

	if (!table)
		return;

	info = route_table_get_info(table);

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		dest = rib_dest_from_rnode(rn);

		if (dest && dest->selected_fib) {
			if (info->safi == SAFI_UNICAST)
				hook_call(rib_update, rn, NULL);

			rib_uninstall_kernel(rn, dest->selected_fib);
			dest->selected_fib = NULL;
		}
	}
}

/*
 * Handler for async dataplane results after a pseudowire installation
 */
static int handle_pw_result(struct zebra_dplane_ctx *ctx)
{
	struct zebra_pw *pw;
	struct zebra_vrf *vrf;

	/* The pseudowire code assumes success - we act on an error
	 * result for installation attempts here.
	 */
	if (dplane_ctx_get_op(ctx) != DPLANE_OP_PW_INSTALL)
		goto done;

	if (dplane_ctx_get_status(ctx) != ZEBRA_DPLANE_REQUEST_SUCCESS) {
		vrf = zebra_vrf_lookup_by_id(dplane_ctx_get_vrf(ctx));
		pw = zebra_pw_find(vrf, dplane_ctx_get_ifname(ctx));
		if (pw)
			zebra_pw_install_failure(pw);
	}

done:

	return 0;
}


/*
 * Handle results from the dataplane system. Dequeue update context
 * structs, dispatch to appropriate internal handlers.
 */
static int rib_process_dplane_results(struct thread *thread)
{
	struct zebra_dplane_ctx *ctx;
	struct dplane_ctx_q ctxlist;
	bool shut_p = false;

	/* Dequeue a list of completed updates with one lock/unlock cycle */

	do {
		TAILQ_INIT(&ctxlist);

		/* Take lock controlling queue of results */
		frr_with_mutex(&dplane_mutex) {
			/* Dequeue list of context structs */
			dplane_ctx_list_append(&ctxlist, &rib_dplane_q);
		}

		/* Dequeue context block */
		ctx = dplane_ctx_dequeue(&ctxlist);

		/* If we've emptied the results queue, we're done */
		if (ctx == NULL)
			break;

		/* If zebra is shutting down, avoid processing results,
		 * just drain the results queue.
		 */
		shut_p = atomic_load_explicit(&zrouter.in_shutdown,
					      memory_order_relaxed);
		if (shut_p) {
			while (ctx) {
				dplane_ctx_fini(&ctx);

				ctx = dplane_ctx_dequeue(&ctxlist);
			}

			continue;
		}

		while (ctx) {
			switch (dplane_ctx_get_op(ctx)) {
			case DPLANE_OP_ROUTE_INSTALL:
			case DPLANE_OP_ROUTE_UPDATE:
			case DPLANE_OP_ROUTE_DELETE:
			{
				/* Bit of special case for route updates
				 * that were generated by async notifications:
				 * we don't want to continue processing these
				 * in the rib.
				 */
				if (dplane_ctx_get_notif_provider(ctx) == 0)
					rib_process_result(ctx);
				else
					dplane_ctx_fini(&ctx);
			}
			break;

			case DPLANE_OP_ROUTE_NOTIFY:
				rib_process_dplane_notify(ctx);
				break;

			case DPLANE_OP_NH_INSTALL:
			case DPLANE_OP_NH_UPDATE:
			case DPLANE_OP_NH_DELETE:
				zebra_nhg_dplane_result(ctx);
				break;

			case DPLANE_OP_LSP_INSTALL:
			case DPLANE_OP_LSP_UPDATE:
			case DPLANE_OP_LSP_DELETE:
			{
				/* Bit of special case for LSP updates
				 * that were generated by async notifications:
				 * we don't want to continue processing these.
				 */
				if (dplane_ctx_get_notif_provider(ctx) == 0)
					zebra_mpls_lsp_dplane_result(ctx);
				else
					dplane_ctx_fini(&ctx);
			}
			break;

			case DPLANE_OP_LSP_NOTIFY:
				zebra_mpls_process_dplane_notify(ctx);
				break;

			case DPLANE_OP_PW_INSTALL:
			case DPLANE_OP_PW_UNINSTALL:
				handle_pw_result(ctx);
				break;

			case DPLANE_OP_SYS_ROUTE_ADD:
			case DPLANE_OP_SYS_ROUTE_DELETE:
				/* No further processing in zebra for these. */
				dplane_ctx_fini(&ctx);
				break;

			case DPLANE_OP_MAC_INSTALL:
			case DPLANE_OP_MAC_DELETE:
				zebra_vxlan_handle_result(ctx);
				break;

			/* Some op codes not handled here */
			case DPLANE_OP_ADDR_INSTALL:
			case DPLANE_OP_ADDR_UNINSTALL:
			case DPLANE_OP_NEIGH_INSTALL:
			case DPLANE_OP_NEIGH_UPDATE:
			case DPLANE_OP_NEIGH_DELETE:
			case DPLANE_OP_VTEP_ADD:
			case DPLANE_OP_VTEP_DELETE:
			case DPLANE_OP_NONE:
				/* Don't expect this: just return the struct? */
				dplane_ctx_fini(&ctx);
				break;

			} /* Dispatch by op code */

			ctx = dplane_ctx_dequeue(&ctxlist);
		}

	} while (1);

	return 0;
}

/*
 * Results are returned from the dataplane subsystem, in the context of
 * the dataplane pthread. We enqueue the results here for processing by
 * the main thread later.
 */
static int rib_dplane_results(struct dplane_ctx_q *ctxlist)
{
	/* Take lock controlling queue of results */
	frr_with_mutex(&dplane_mutex) {
		/* Enqueue context blocks */
		dplane_ctx_list_append(&rib_dplane_q, ctxlist);
	}

	/* Ensure event is signalled to zebra main pthread */
	thread_add_event(zrouter.master, rib_process_dplane_results, NULL, 0,
			 &t_dplane);

	return 0;
}

/*
 * Ensure there are no empty slots in the route_info array.
 * Every route type in zebra should be present there.
 */
static void check_route_info(void)
{
	int len = array_size(route_info);

	/*
	 * ZEBRA_ROUTE_SYSTEM is special cased since
	 * its key is 0 anyway.
	 *
	 * ZEBRA_ROUTE_ALL is also ignored.
	 */
	for (int i = 0; i < len; i++) {
		if (i == ZEBRA_ROUTE_SYSTEM || i == ZEBRA_ROUTE_ALL)
			continue;
		assert(route_info[i].key);
		assert(route_info[i].meta_q_map < MQ_SIZE);
	}
}

/* Routing information base initialize. */
void rib_init(void)
{
	check_route_info();

	rib_queue_init();

	/* Init dataplane, and register for results */
	pthread_mutex_init(&dplane_mutex, NULL);
	TAILQ_INIT(&rib_dplane_q);
	zebra_dplane_init(rib_dplane_results);
}

/*
 * vrf_id_get_next
 *
 * Get the first vrf id that is greater than the given vrf id if any.
 *
 * Returns true if a vrf id was found, false otherwise.
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
			       < (int)array_size(afi_safis)) {
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
