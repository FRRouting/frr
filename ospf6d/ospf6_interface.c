// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#include <zebra.h>

#include "memory.h"
#include "if.h"
#include "log.h"
#include "command.h"
#include "frrevent.h"
#include "prefix.h"
#include "plist.h"
#include "zclient.h"

#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_top.h"
#include "ospf6_network.h"
#include "ospf6_message.h"
#include "ospf6_route.h"
#include "ospf6_area.h"
#include "ospf6_abr.h"
#include "ospf6_nssa.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6_spf.h"
#include "ospf6d.h"
#include "ospf6_bfd.h"
#include "ospf6_zebra.h"
#include "ospf6_gr.h"
#include "lib/json.h"
#include "ospf6_proto.h"
#include "lib/keychain.h"
#include "ospf6_auth_trailer.h"
#include "ospf6d/ospf6_interface_clippy.c"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_IF, "OSPF6 interface");
DEFINE_MTYPE(OSPF6D, OSPF6_AUTH_KEYCHAIN, "OSPF6 auth keychain");
DEFINE_MTYPE(OSPF6D, OSPF6_AUTH_MANUAL_KEY, "OSPF6 auth key");
DEFINE_MTYPE_STATIC(OSPF6D, CFG_PLIST_NAME, "configured prefix list names");
DEFINE_QOBJ_TYPE(ospf6_interface);
DEFINE_HOOK(ospf6_interface_change,
	    (struct ospf6_interface * oi, int state, int old_state),
	    (oi, state, old_state));

unsigned char conf_debug_ospf6_interface = 0;

const char *const ospf6_interface_state_str[] = {
	"None",		"Down",	   "Loopback", "Waiting", "PointToPoint",
	"PtMultipoint", "DROther", "BDR",      "DR",	  NULL
};

int ospf6_interface_neighbor_count(struct ospf6_interface *oi)
{
	int count = 0;
	struct ospf6_neighbor *nbr = NULL;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, node, nbr)) {
		/* Down state is not shown. */
		if (nbr->state == OSPF6_NEIGHBOR_DOWN)
			continue;
		count++;
	}

	return count;
}

struct ospf6_interface *ospf6_interface_lookup_by_ifindex(ifindex_t ifindex,
							  vrf_id_t vrf_id)
{
	struct ospf6_interface *oi;
	struct interface *ifp;

	ifp = if_lookup_by_index(ifindex, vrf_id);
	if (ifp == NULL)
		return (struct ospf6_interface *)NULL;

	oi = (struct ospf6_interface *)ifp->info;
	return oi;
}

/* schedule routing table recalculation */
static void ospf6_interface_lsdb_hook(struct ospf6_lsa *lsa, unsigned int reason)
{
	struct ospf6_interface *oi;

	if (lsa == NULL)
		return;

	oi = lsa->lsdb->data;
	switch (ntohs(lsa->header->type)) {
	case OSPF6_LSTYPE_LINK:
		if (oi->state == OSPF6_INTERFACE_DR)
			OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT(oi);
		if (oi->area)
			ospf6_spf_schedule(oi->area->ospf6, reason);
		break;

	default:
		break;
	}
}

static void ospf6_interface_lsdb_hook_add(struct ospf6_lsa *lsa)
{
	ospf6_interface_lsdb_hook(lsa, ospf6_lsadd_to_spf_reason(lsa));
}

static void ospf6_interface_lsdb_hook_remove(struct ospf6_lsa *lsa)
{
	ospf6_interface_lsdb_hook(lsa, ospf6_lsremove_to_spf_reason(lsa));
}

static uint8_t ospf6_default_iftype(struct interface *ifp)
{
	if (if_is_pointopoint(ifp))
		return OSPF_IFTYPE_POINTOPOINT;
	else if (if_is_loopback(ifp))
		return OSPF_IFTYPE_LOOPBACK;
	else
		return OSPF_IFTYPE_BROADCAST;
}

static uint32_t ospf6_interface_get_cost(struct ospf6_interface *oi)
{
	/* If all else fails, use default OSPF cost */
	uint32_t cost;
	uint32_t bw, refbw;
	struct ospf6 *ospf6;

	/* interface speed and bw can be 0 in some platforms,
	 * use ospf default bw. If bw is configured then it would
	 * be used.
	 */
	if (!oi->interface->bandwidth && oi->interface->speed) {
		bw = oi->interface->speed;
	} else {
		bw = oi->interface->bandwidth ? oi->interface->bandwidth
					      : OSPF6_INTERFACE_BANDWIDTH;
	}

	ospf6 = oi->interface->vrf->info;
	refbw = ospf6 ? ospf6->ref_bandwidth : OSPF6_REFERENCE_BANDWIDTH;

	/* A specified ip ospf cost overrides a calculated one. */
	if (CHECK_FLAG(oi->flag, OSPF6_INTERFACE_NOAUTOCOST))
		cost = oi->cost;
	else {
		cost = (uint32_t)((double)refbw / (double)bw + (double)0.5);
		if (cost < 1)
			cost = 1;

		/* If the interface type is point-to-multipoint or the interface
		 * is in the state Loopback, the global scope IPv6 addresses
		 * associated with the interface (if any) are copied into the
		 * intra-area-prefix-LSA with the PrefixOptions LA-bit set, the
		 * PrefixLength set to 128, and the metric set to 0.
		 */
		if (if_is_loopback(oi->interface))
			cost = 0;
	}

	return cost;
}

static void ospf6_interface_force_recalculate_cost(struct ospf6_interface *oi)
{
	/* update cost held in route_connected list in ospf6_interface */
	ospf6_interface_connected_route_update(oi->interface);

	/* execute LSA hooks */
	if (oi->area) {
		OSPF6_LINK_LSA_SCHEDULE(oi);
		OSPF6_ROUTER_LSA_SCHEDULE(oi->area);
		OSPF6_NETWORK_LSA_SCHEDULE(oi);
		OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT(oi);
		OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB(oi->area);
	}
}

static void ospf6_interface_recalculate_cost(struct ospf6_interface *oi)
{
	uint32_t newcost;

	newcost = ospf6_interface_get_cost(oi);
	if (newcost == oi->cost)
		return;
	oi->cost = newcost;

	ospf6_interface_force_recalculate_cost(oi);
}

/* Create new ospf6 interface structure */
struct ospf6_interface *ospf6_interface_create(struct interface *ifp)
{
	struct ospf6_interface *oi;
	unsigned int iobuflen;

	oi = XCALLOC(MTYPE_OSPF6_IF, sizeof(struct ospf6_interface));

	oi->obuf = ospf6_fifo_new();

	oi->area = (struct ospf6_area *)NULL;
	oi->neighbor_list = list_new();
	oi->neighbor_list->cmp = ospf6_neighbor_cmp;
	oi->linklocal_addr = (struct in6_addr *)NULL;
	oi->instance_id = OSPF6_INTERFACE_INSTANCE_ID;
	oi->transdelay = OSPF6_INTERFACE_TRANSDELAY;
	oi->priority = OSPF6_INTERFACE_PRIORITY;

	oi->hello_interval = OSPF_HELLO_INTERVAL_DEFAULT;
	oi->gr.hello_delay.interval = OSPF_HELLO_DELAY_DEFAULT;
	oi->dead_interval = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;
	oi->rxmt_interval = OSPF_RETRANSMIT_INTERVAL_DEFAULT;
	oi->type = ospf6_default_iftype(ifp);
	oi->state = OSPF6_INTERFACE_DOWN;
	oi->flag = 0;
	oi->mtu_ignore = 0;
	oi->c_ifmtu = 0;

	/* Try to adjust I/O buffer size with IfMtu */
	oi->ifmtu = ifp->mtu6;
	iobuflen = ospf6_iobuf_size(ifp->mtu6);
	if (oi->ifmtu > iobuflen) {
		if (IS_OSPF6_DEBUG_INTERFACE)
			zlog_debug("Interface %s: IfMtu is adjusted to I/O buffer size: %d.",
				   ifp->name, iobuflen);
		oi->ifmtu = iobuflen;
	}

	QOBJ_REG(oi, ospf6_interface);

	oi->lsupdate_list = ospf6_lsdb_create(oi);
	oi->lsack_list = ospf6_lsdb_create(oi);
	oi->lsdb = ospf6_lsdb_create(oi);
	oi->lsdb->hook_add = ospf6_interface_lsdb_hook_add;
	oi->lsdb->hook_remove = ospf6_interface_lsdb_hook_remove;
	oi->lsdb_self = ospf6_lsdb_create(oi);

	oi->route_connected = OSPF6_ROUTE_TABLE_CREATE(INTERFACE,
						       CONNECTED_ROUTES);
	oi->route_connected->scope = oi;

	/* link both */
	oi->interface = ifp;
	ifp->info = oi;

	/* Compute cost. */
	oi->cost = ospf6_interface_get_cost(oi);

	oi->at_data.flags = 0;

	return oi;
}

void ospf6_interface_delete(struct ospf6_interface *oi)
{
	struct listnode *node, *nnode;
	struct ospf6_neighbor *on;

	QOBJ_UNREG(oi);

	ospf6_fifo_free(oi->obuf);

	for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on))
		ospf6_neighbor_delete(on);

	list_delete(&oi->neighbor_list);

	EVENT_OFF(oi->thread_send_hello);
	EVENT_OFF(oi->thread_send_lsupdate);
	EVENT_OFF(oi->thread_send_lsack);
	EVENT_OFF(oi->thread_sso);
	EVENT_OFF(oi->thread_wait_timer);

	ospf6_lsdb_remove_all(oi->lsdb);
	ospf6_lsdb_remove_all(oi->lsupdate_list);
	ospf6_lsdb_remove_all(oi->lsack_list);

	ospf6_lsdb_delete(oi->lsdb);
	ospf6_lsdb_delete(oi->lsdb_self);

	ospf6_lsdb_delete(oi->lsupdate_list);
	ospf6_lsdb_delete(oi->lsack_list);

	ospf6_route_table_delete(oi->route_connected);

	/* cut link */
	oi->interface->info = NULL;

	/* plist_name */
	if (oi->plist_name)
		XFREE(MTYPE_CFG_PLIST_NAME, oi->plist_name);

	/* disable from area list if possible */
	ospf6_area_interface_delete(oi);

	if (oi->at_data.auth_key)
		XFREE(MTYPE_OSPF6_AUTH_MANUAL_KEY, oi->at_data.auth_key);

	/* Free BFD allocated data. */
	XFREE(MTYPE_TMP, oi->bfd_config.profile);

	XFREE(MTYPE_OSPF6_IF, oi);
}

void ospf6_interface_enable(struct ospf6_interface *oi)
{
	UNSET_FLAG(oi->flag, OSPF6_INTERFACE_DISABLE);
	ospf6_interface_state_update(oi->interface);
}

void ospf6_interface_disable(struct ospf6_interface *oi)
{
	SET_FLAG(oi->flag, OSPF6_INTERFACE_DISABLE);

	event_execute(master, interface_down, oi, 0, NULL);

	ospf6_lsdb_remove_all(oi->lsdb);
	ospf6_lsdb_remove_all(oi->lsdb_self);
	ospf6_lsdb_remove_all(oi->lsupdate_list);
	ospf6_lsdb_remove_all(oi->lsack_list);

	EVENT_OFF(oi->thread_send_hello);
	EVENT_OFF(oi->thread_send_lsupdate);
	EVENT_OFF(oi->thread_send_lsack);
	EVENT_OFF(oi->thread_sso);

	EVENT_OFF(oi->thread_network_lsa);
	EVENT_OFF(oi->thread_link_lsa);
	EVENT_OFF(oi->thread_intra_prefix_lsa);
	EVENT_OFF(oi->thread_as_extern_lsa);
	EVENT_OFF(oi->thread_wait_timer);

	oi->gr.hello_delay.elapsed_seconds = 0;
	EVENT_OFF(oi->gr.hello_delay.t_grace_send);
}

static struct in6_addr *
ospf6_interface_get_linklocal_address(struct interface *ifp)
{
	struct connected *c;
	struct in6_addr *l = (struct in6_addr *)NULL;

	/* for each connected address */
	frr_each (if_connected, ifp->connected, c) {
		/* if family not AF_INET6, ignore */
		if (c->address->family != AF_INET6)
			continue;

		/* linklocal scope check */
		if (IN6_IS_ADDR_LINKLOCAL(&c->address->u.prefix6))
			l = &c->address->u.prefix6;
	}
	return l;
}

void ospf6_interface_state_update(struct interface *ifp)
{
	struct ospf6_interface *oi;
	unsigned int iobuflen;

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		return;
	if (CHECK_FLAG(oi->flag, OSPF6_INTERFACE_DISABLE))
		return;

	/* Adjust the mtu values if the kernel told us something new */
	if (ifp->mtu6 != oi->ifmtu) {
		/* If nothing configured, accept it and check for buffer size */
		if (!oi->c_ifmtu) {
			oi->ifmtu = ifp->mtu6;
			iobuflen = ospf6_iobuf_size(ifp->mtu6);
			if (oi->ifmtu > iobuflen) {
				if (IS_OSPF6_DEBUG_INTERFACE)
					zlog_debug("Interface %s: IfMtu is adjusted to I/O buffer size: %d.",
						   ifp->name, iobuflen);
				oi->ifmtu = iobuflen;
			}
		} else if (oi->c_ifmtu > ifp->mtu6) {
			oi->ifmtu = ifp->mtu6;
			zlog_warn("Configured mtu %u on %s overridden by kernel %u",
				  oi->c_ifmtu, ifp->name, ifp->mtu6);
		} else
			oi->ifmtu = oi->c_ifmtu;
	}

	if (if_is_operative(ifp) &&
	    (ospf6_interface_get_linklocal_address(oi->interface) ||
	     if_is_loopback(oi->interface)))
		event_execute(master, interface_up, oi, 0, NULL);
	else
		event_execute(master, interface_down, oi, 0, NULL);

	return;
}

void ospf6_interface_connected_route_update(struct interface *ifp)
{
	struct ospf6_interface *oi;
	struct connected *c;
	struct in6_addr nh_addr;

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		return;

	/* reset linklocal pointer */
	oi->linklocal_addr = ospf6_interface_get_linklocal_address(ifp);

	/* if area is null, do not make connected-route list */
	if (oi->area == NULL)
		return;

	if (CHECK_FLAG(oi->flag, OSPF6_INTERFACE_DISABLE))
		return;

	/* update "route to advertise" interface route table */
	ospf6_route_remove_all(oi->route_connected);

	frr_each (if_connected, ifp->connected, c) {
		if (c->address->family != AF_INET6)
			continue;

		CONTINUE_IF_ADDRESS_LINKLOCAL(IS_OSPF6_DEBUG_INTERFACE,
					      c->address);
		CONTINUE_IF_ADDRESS_UNSPECIFIED(IS_OSPF6_DEBUG_INTERFACE,
						c->address);
		CONTINUE_IF_ADDRESS_LOOPBACK(IS_OSPF6_DEBUG_INTERFACE,
					     c->address);
		CONTINUE_IF_ADDRESS_V4COMPAT(IS_OSPF6_DEBUG_INTERFACE,
					     c->address);
		CONTINUE_IF_ADDRESS_V4MAPPED(IS_OSPF6_DEBUG_INTERFACE,
					     c->address);

		/* apply filter */
		if (oi->plist_name) {
			struct prefix_list *plist;
			enum prefix_list_type ret;

			plist = prefix_list_lookup(AFI_IP6, oi->plist_name);
			ret = prefix_list_apply(plist, (void *)c->address);
			if (ret == PREFIX_DENY) {
				if (IS_OSPF6_DEBUG_INTERFACE)
					zlog_debug("%pFX on %s filtered by prefix-list %s ",
						   c->address,
						   oi->interface->name,
						   oi->plist_name);
				continue;
			}
		}

		if (oi->type == OSPF_IFTYPE_LOOPBACK ||
		    oi->type == OSPF_IFTYPE_POINTOMULTIPOINT ||
		    oi->type == OSPF_IFTYPE_POINTOPOINT) {
			struct ospf6_route *la_route;

			la_route = ospf6_route_create(oi->area->ospf6);
			la_route->prefix = *c->address;
			la_route->prefix.prefixlen = 128;
			la_route->prefix_options |= OSPF6_PREFIX_OPTION_LA;

			la_route->type = OSPF6_DEST_TYPE_NETWORK;
			la_route->path.area_id = oi->area->area_id;
			la_route->path.type = OSPF6_PATH_TYPE_INTRA;
			la_route->path.cost = 0;
			inet_pton(AF_INET6, "::1", &nh_addr);
			ospf6_route_add_nexthop(la_route, oi->interface->ifindex,
						&nh_addr);
			ospf6_route_add(la_route, oi->route_connected);
		}

		if (oi->type == OSPF_IFTYPE_POINTOMULTIPOINT &&
		    !oi->p2xp_connected_pfx_include)
			continue;
		if (oi->type == OSPF_IFTYPE_POINTOPOINT &&
		    oi->p2xp_connected_pfx_exclude)
			continue;

		struct ospf6_route *route;

		route = ospf6_route_create(oi->area->ospf6);
		memcpy(&route->prefix, c->address, sizeof(struct prefix));
		apply_mask(&route->prefix);
		route->type = OSPF6_DEST_TYPE_NETWORK;
		route->path.area_id = oi->area->area_id;
		route->path.type = OSPF6_PATH_TYPE_INTRA;
		route->path.cost = oi->cost;
		inet_pton(AF_INET6, "::1", &nh_addr);
		ospf6_route_add_nexthop(route, oi->interface->ifindex, &nh_addr);
		ospf6_route_add(route, oi->route_connected);
	}

	/* create new Link-LSA */
	OSPF6_LINK_LSA_SCHEDULE(oi);
	OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT(oi);
	OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB(oi->area);
}

static int ospf6_interface_state_change(uint8_t next_state,
					struct ospf6_interface *oi)
{
	uint8_t prev_state;
	struct ospf6 *ospf6;

	prev_state = oi->state;
	oi->state = next_state;

	if (prev_state == next_state)
		return -1;

	if (!oi->area)
		return -1;

	/* log */
	if (IS_OSPF6_DEBUG_INTERFACE) {
		zlog_debug("Interface state change %s: %s -> %s",
			   oi->interface->name,
			   ospf6_interface_state_str[prev_state],
			   ospf6_interface_state_str[next_state]);
	}
	oi->state_change++;

	ospf6 = oi->area->ospf6;

	if ((prev_state == OSPF6_INTERFACE_DR ||
	     prev_state == OSPF6_INTERFACE_BDR) &&
	    (next_state != OSPF6_INTERFACE_DR &&
	     next_state != OSPF6_INTERFACE_BDR))
		ospf6_sso(oi->interface->ifindex, &alldrouters6,
			  IPV6_LEAVE_GROUP, ospf6->fd);

	if ((prev_state != OSPF6_INTERFACE_DR &&
	     prev_state != OSPF6_INTERFACE_BDR) &&
	    (next_state == OSPF6_INTERFACE_DR ||
	     next_state == OSPF6_INTERFACE_BDR))
		ospf6_sso(oi->interface->ifindex, &alldrouters6,
			  IPV6_JOIN_GROUP, ospf6->fd);

	OSPF6_ROUTER_LSA_SCHEDULE(oi->area);
	OSPF6_LINK_LSA_SCHEDULE(oi);
	if (next_state == OSPF6_INTERFACE_DOWN) {
		OSPF6_NETWORK_LSA_EXECUTE(oi);
		OSPF6_INTRA_PREFIX_LSA_EXECUTE_TRANSIT(oi);
		OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB(oi->area);
	} else if (prev_state == OSPF6_INTERFACE_DR ||
		   next_state == OSPF6_INTERFACE_DR) {
		OSPF6_NETWORK_LSA_SCHEDULE(oi);
		OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT(oi);
		OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB(oi->area);
	}

	if (next_state == OSPF6_INTERFACE_POINTTOPOINT ||
	    next_state == OSPF6_INTERFACE_POINTTOMULTIPOINT)
		ospf6_if_p2xp_up(oi);

	hook_call(ospf6_interface_change, oi, next_state, prev_state);

	return 0;
}


/* DR Election, RFC2328 section 9.4 */

#define IS_ELIGIBLE(n)                                                         \
	((n)->state >= OSPF6_NEIGHBOR_TWOWAY && (n)->priority != 0)

static struct ospf6_neighbor *better_bdrouter(struct ospf6_neighbor *a,
					      struct ospf6_neighbor *b)
{
	if ((a == NULL || !IS_ELIGIBLE(a) || a->drouter == a->router_id) &&
	    (b == NULL || !IS_ELIGIBLE(b) || b->drouter == b->router_id))
		return NULL;
	else if (a == NULL || !IS_ELIGIBLE(a) || a->drouter == a->router_id)
		return b;
	else if (b == NULL || !IS_ELIGIBLE(b) || b->drouter == b->router_id)
		return a;

	if (a->bdrouter == a->router_id && b->bdrouter != b->router_id)
		return a;
	if (a->bdrouter != a->router_id && b->bdrouter == b->router_id)
		return b;

	if (a->priority > b->priority)
		return a;
	if (a->priority < b->priority)
		return b;

	if (ntohl(a->router_id) > ntohl(b->router_id))
		return a;
	if (ntohl(a->router_id) < ntohl(b->router_id))
		return b;

	zlog_warn("Router-ID duplicate ?");
	return a;
}

static struct ospf6_neighbor *better_drouter(struct ospf6_neighbor *a,
					     struct ospf6_neighbor *b)
{
	if ((a == NULL || !IS_ELIGIBLE(a) || a->drouter != a->router_id) &&
	    (b == NULL || !IS_ELIGIBLE(b) || b->drouter != b->router_id))
		return NULL;
	else if (a == NULL || !IS_ELIGIBLE(a) || a->drouter != a->router_id)
		return b;
	else if (b == NULL || !IS_ELIGIBLE(b) || b->drouter != b->router_id)
		return a;

	if (a->drouter == a->router_id && b->drouter != b->router_id)
		return a;
	if (a->drouter != a->router_id && b->drouter == b->router_id)
		return b;

	if (a->priority > b->priority)
		return a;
	if (a->priority < b->priority)
		return b;

	if (ntohl(a->router_id) > ntohl(b->router_id))
		return a;
	if (ntohl(a->router_id) < ntohl(b->router_id))
		return b;

	zlog_warn("Router-ID duplicate ?");
	return a;
}

uint8_t dr_election(struct ospf6_interface *oi)
{
	struct ospf6 *ospf6 = oi->area->ospf6;
	struct listnode *node, *nnode;
	struct ospf6_neighbor *on, *drouter, *bdrouter, myself;
	struct ospf6_neighbor *best_drouter, *best_bdrouter;
	uint8_t next_state = 0;

	drouter = bdrouter = NULL;
	best_drouter = best_bdrouter = NULL;

	/* pseudo neighbor myself, including noting current DR/BDR (1) */
	memset(&myself, 0, sizeof(myself));
	inet_ntop(AF_INET, &ospf6->router_id, myself.name, sizeof(myself.name));
	myself.state = OSPF6_NEIGHBOR_TWOWAY;
	myself.drouter = oi->drouter;
	myself.bdrouter = oi->bdrouter;
	myself.priority = oi->priority;
	myself.router_id = ospf6->router_id;

	/* Electing BDR (2) */
	for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on))
		bdrouter = better_bdrouter(bdrouter, on);

	best_bdrouter = bdrouter;
	bdrouter = better_bdrouter(best_bdrouter, &myself);

	/* Electing DR (3) */
	for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on))
		drouter = better_drouter(drouter, on);

	best_drouter = drouter;
	drouter = better_drouter(best_drouter, &myself);
	if (drouter == NULL)
		drouter = bdrouter;

	/* the router itself is newly/no longer DR/BDR (4) */
	if ((drouter == &myself && myself.drouter != myself.router_id) ||
	    (drouter != &myself && myself.drouter == myself.router_id) ||
	    (bdrouter == &myself && myself.bdrouter != myself.router_id) ||
	    (bdrouter != &myself && myself.bdrouter == myself.router_id)) {
		myself.drouter = (drouter ? drouter->router_id : htonl(0));
		myself.bdrouter = (bdrouter ? bdrouter->router_id : htonl(0));

		/* compatible to Electing BDR (2) */
		bdrouter = better_bdrouter(best_bdrouter, &myself);

		/* compatible to Electing DR (3) */
		drouter = better_drouter(best_drouter, &myself);
		if (drouter == NULL)
			drouter = bdrouter;
	}

	/* Set interface state accordingly (5) */
	if (drouter && drouter == &myself)
		next_state = OSPF6_INTERFACE_DR;
	else if (bdrouter && bdrouter == &myself)
		next_state = OSPF6_INTERFACE_BDR;
	else
		next_state = OSPF6_INTERFACE_DROTHER;

	/* If NBMA, schedule Start for each neighbor having priority of 0 (6) */
	/* XXX */

	/* If DR or BDR change, invoke AdjOK? for each neighbor (7) */
	/* RFC 2328 section 12.4. Originating LSAs (3) will be handled
	   accordingly after AdjOK */

	if (oi->drouter != (drouter ? drouter->router_id : htonl(0)) ||
	    oi->bdrouter != (bdrouter ? bdrouter->router_id : htonl(0)) ||
	    ospf6->gr_info.restart_in_progress) {
		if (IS_OSPF6_DEBUG_INTERFACE)
			zlog_debug("DR Election on %s: DR: %s BDR: %s",
				   oi->interface->name,
				   (drouter ? drouter->name : "0.0.0.0"),
				   (bdrouter ? bdrouter->name : "0.0.0.0"));

		for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, node, on)) {
			if (on->state < OSPF6_NEIGHBOR_TWOWAY)
				continue;
			/* Schedule AdjOK. */
			event_add_event(master, adj_ok, on, 0,
					&on->thread_adj_ok);
		}
	}

	oi->drouter = (drouter ? drouter->router_id : htonl(0));
	oi->bdrouter = (bdrouter ? bdrouter->router_id : htonl(0));
	return next_state;
}

#ifdef __FreeBSD__

#include <ifaddrs.h>

static bool ifmaddr_check(ifindex_t ifindex, struct in6_addr *addr)
{
	struct ifmaddrs *ifmap, *ifma;
	struct sockaddr_dl *sdl;
	struct sockaddr_in6 *sin6;
	bool found = false;

	if (getifmaddrs(&ifmap) != 0)
		return false;

	for (ifma = ifmap; ifma; ifma = ifma->ifma_next) {
		if (ifma->ifma_name == NULL || ifma->ifma_addr == NULL)
			continue;
		if (ifma->ifma_name->sa_family != AF_LINK)
			continue;
		if (ifma->ifma_addr->sa_family != AF_INET6)
			continue;
		sdl = (struct sockaddr_dl *)ifma->ifma_name;
		sin6 = (struct sockaddr_in6 *)ifma->ifma_addr;
		if (sdl->sdl_index == ifindex &&
		    memcmp(&sin6->sin6_addr, addr, IPV6_MAX_BYTELEN) == 0) {
			found = true;
			break;
		}
	}

	if (ifmap)
		freeifmaddrs(ifmap);

	return found;
}

#endif /* __FreeBSD__ */

/* Interface State Machine */
void interface_up(struct event *thread)
{
	struct ospf6_interface *oi;
	struct ospf6 *ospf6;

	oi = (struct ospf6_interface *)EVENT_ARG(thread);
	assert(oi && oi->interface);

	if (!oi->type_cfg)
		oi->type = ospf6_default_iftype(oi->interface);

	event_cancel(&oi->thread_sso);

	if (IS_OSPF6_DEBUG_INTERFACE)
		zlog_debug("Interface Event %s: [InterfaceUp]",
			   oi->interface->name);

	/* check physical interface is up */
	if (!if_is_operative(oi->interface)) {
		zlog_warn("Interface %s is down, can't execute [InterfaceUp]",
			  oi->interface->name);
		return;
	}

	/* check interface has a link-local address */
	if (!(ospf6_interface_get_linklocal_address(oi->interface) ||
	      if_is_loopback(oi->interface))) {
		zlog_warn("Interface %s has no link local address, can't execute [InterfaceUp]",
			  oi->interface->name);
		return;
	}

	/* Recompute cost & update connected LSAs */
	ospf6_interface_force_recalculate_cost(oi);

	/* if already enabled, do nothing */
	if (oi->state > OSPF6_INTERFACE_DOWN) {
		if (IS_OSPF6_DEBUG_INTERFACE)
			zlog_debug("Interface %s already enabled",
				   oi->interface->name);
		return;
	}

	/* If no area assigned, return */
	if (oi->area == NULL) {
		zlog_warn("%s: Not scheduling Hello for %s as there is no area assigned yet",
			  __func__, oi->interface->name);
		return;
	}

	/*
	 * RFC 3623 - Section 5 ("Unplanned Outages"):
	 * "The grace-LSAs are encapsulated in Link State Update Packets
	 * and sent out to all interfaces, even though the restarted
	 * router has no adjacencies and no knowledge of previous
	 * adjacencies".
	 */
	if (oi->area->ospf6->gr_info.restart_in_progress &&
	    oi->area->ospf6->gr_info.reason == OSPF6_GR_UNKNOWN_RESTART)
		ospf6_gr_unplanned_start_interface(oi);

#ifdef __FreeBSD__
	/*
	 * There's a delay in FreeBSD between issuing a command to leave a
	 * multicast group and an actual leave. If we execute "no router ospf6"
	 * and "router ospf6" fast enough, we can end up in a situation when OS
	 * performs the leave later than it performs the join and the interface
	 * remains without a multicast group. We have to do the join only after
	 * the interface actually left the group.
	 */
	if (ifmaddr_check(oi->interface->ifindex, &allspfrouters6)) {
		zlog_info("Interface %s is still in all routers group, rescheduling for SSO",
			  oi->interface->name);
		event_add_timer(master, interface_up, oi,
				OSPF6_INTERFACE_SSO_RETRY_INT, &oi->thread_sso);
		return;
	}
#endif /* __FreeBSD__ */

	ospf6 = oi->area->ospf6;

	/* Join AllSPFRouters */
	if (ospf6_sso(oi->interface->ifindex, &allspfrouters6, IPV6_JOIN_GROUP,
		      ospf6->fd) < 0) {
		if (oi->sso_try_cnt++ < OSPF6_INTERFACE_SSO_RETRY_MAX) {
			zlog_info("Scheduling %s for sso retry, trial count: %d",
				  oi->interface->name, oi->sso_try_cnt);
			event_add_timer(master, interface_up, oi,
					OSPF6_INTERFACE_SSO_RETRY_INT,
					&oi->thread_sso);
		}
		return;
	}
	oi->sso_try_cnt = 0; /* Reset on success */

	/* Update interface route */
	ospf6_interface_connected_route_update(oi->interface);

	/* Schedule Hello */
	if (!CHECK_FLAG(oi->flag, OSPF6_INTERFACE_PASSIVE) &&
	    !if_is_loopback(oi->interface)) {
		event_add_timer(master, ospf6_hello_send, oi, 0,
				&oi->thread_send_hello);
	}

	/* decide next interface state */
	if (oi->type == OSPF_IFTYPE_LOOPBACK) {
		ospf6_interface_state_change(OSPF6_INTERFACE_LOOPBACK, oi);
	} else if (oi->type == OSPF_IFTYPE_POINTOPOINT) {
		ospf6_interface_state_change(OSPF6_INTERFACE_POINTTOPOINT, oi);
	} else if (oi->type == OSPF_IFTYPE_POINTOMULTIPOINT) {
		ospf6_interface_state_change(OSPF6_INTERFACE_POINTTOMULTIPOINT,
					     oi);
	} else if (oi->priority == 0)
		ospf6_interface_state_change(OSPF6_INTERFACE_DROTHER, oi);
	else {
		ospf6_interface_state_change(OSPF6_INTERFACE_WAITING, oi);
		event_add_timer(master, wait_timer, oi, oi->dead_interval,
				&oi->thread_wait_timer);
	}
}

void wait_timer(struct event *thread)
{
	struct ospf6_interface *oi;

	oi = (struct ospf6_interface *)EVENT_ARG(thread);
	assert(oi && oi->interface);

	if (IS_OSPF6_DEBUG_INTERFACE)
		zlog_debug("Interface Event %s: [WaitTimer]",
			   oi->interface->name);

	if (oi->state == OSPF6_INTERFACE_WAITING)
		ospf6_interface_state_change(dr_election(oi), oi);
}

void backup_seen(struct event *thread)
{
	struct ospf6_interface *oi;

	oi = (struct ospf6_interface *)EVENT_ARG(thread);
	assert(oi && oi->interface);

	if (IS_OSPF6_DEBUG_INTERFACE)
		zlog_debug("Interface Event %s: [BackupSeen]",
			   oi->interface->name);

	if (oi->state == OSPF6_INTERFACE_WAITING)
		ospf6_interface_state_change(dr_election(oi), oi);
}

void neighbor_change(struct event *thread)
{
	struct ospf6_interface *oi;

	oi = (struct ospf6_interface *)EVENT_ARG(thread);
	assert(oi && oi->interface);

	if (IS_OSPF6_DEBUG_INTERFACE)
		zlog_debug("Interface Event %s: [NeighborChange]",
			   oi->interface->name);

	if (oi->state == OSPF6_INTERFACE_DROTHER ||
	    oi->state == OSPF6_INTERFACE_BDR || oi->state == OSPF6_INTERFACE_DR)
		ospf6_interface_state_change(dr_election(oi), oi);
}

void interface_down(struct event *thread)
{
	struct ospf6_interface *oi;
	struct listnode *node, *nnode;
	struct ospf6_neighbor *on;
	struct ospf6 *ospf6;

	oi = (struct ospf6_interface *)EVENT_ARG(thread);
	assert(oi && oi->interface);

	if (IS_OSPF6_DEBUG_INTERFACE)
		zlog_debug("Interface Event %s: [InterfaceDown]",
			   oi->interface->name);

	/* Stop Hellos */
	EVENT_OFF(oi->thread_send_hello);

	/* Stop trying to set socket options. */
	EVENT_OFF(oi->thread_sso);

	/* Cease the HELPER role for all the neighbours
	 * of this interface.
	 */
	if (ospf6_interface_neighbor_count(oi)) {
		struct listnode *ln;
		struct ospf6_neighbor *nbr = NULL;

		for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, ln, nbr))
			ospf6_gr_helper_exit(nbr, OSPF6_GR_HELPER_TOPO_CHG);
	}

	for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on))
		ospf6_neighbor_delete(on);

	list_delete_all_node(oi->neighbor_list);

	/* When interface state is reset, also reset information about
	 * DR election, as it is no longer valid. */
	oi->drouter = oi->prev_drouter = htonl(0);
	oi->bdrouter = oi->prev_bdrouter = htonl(0);

	if (oi->area == NULL)
		return;

	ospf6 = oi->area->ospf6;
	/* Leave AllSPFRouters */
	if (oi->state > OSPF6_INTERFACE_DOWN)
		ospf6_sso(oi->interface->ifindex, &allspfrouters6,
			  IPV6_LEAVE_GROUP, ospf6->fd);

	/* deal with write fifo */
	ospf6_fifo_flush(oi->obuf);
	if (oi->on_write_q) {
		listnode_delete(ospf6->oi_write_q, oi);
		if (list_isempty(ospf6->oi_write_q))
			event_cancel(&ospf6->t_write);
		oi->on_write_q = 0;
	}

	ospf6_interface_state_change(OSPF6_INTERFACE_DOWN, oi);
}


static const char *ospf6_iftype_str(uint8_t iftype)
{
	switch (iftype) {
	case OSPF_IFTYPE_LOOPBACK:
		return "LOOPBACK";
	case OSPF_IFTYPE_BROADCAST:
		return "BROADCAST";
	case OSPF_IFTYPE_POINTOPOINT:
		return "POINTOPOINT";
	case OSPF_IFTYPE_POINTOMULTIPOINT:
		return "POINTOMULTIPOINT";
	}
	return "UNKNOWN";
}

/* show specified interface structure */
static int ospf6_interface_show(struct vty *vty, struct interface *ifp,
				json_object *json_obj, bool use_json)
{
	struct ospf6_interface *oi;
	struct connected *c;
	struct prefix *p;
	char strbuf[PREFIX2STR_BUFFER], drouter[32], bdrouter[32];
	uint8_t default_iftype;
	struct timeval res, now;
	char duration[32];
	struct ospf6_lsa *lsa, *lsanext;
	json_object *json_arr;
	json_object *json_addr;
	struct json_object *json_auth = NULL;

	default_iftype = ospf6_default_iftype(ifp);

	if (use_json) {
		json_object_string_add(json_obj, "status",
				       (if_is_operative(ifp) ? "up" : "down"));
		json_object_string_add(json_obj, "type",
				       ospf6_iftype_str(default_iftype));
		json_object_int_add(json_obj, "interfaceId", ifp->ifindex);

		if (ifp->info == NULL)
			return 0;

		oi = (struct ospf6_interface *)ifp->info;

		if (if_is_operative(ifp) && oi->type != default_iftype)
			json_object_string_add(json_obj, "operatingAsType",
					       ospf6_iftype_str(oi->type));

	} else {
		vty_out(vty, "%s is %s, type %s\n", ifp->name,
			(if_is_operative(ifp) ? "up" : "down"),
			ospf6_iftype_str(default_iftype));
		vty_out(vty, "  Interface ID: %d\n", ifp->ifindex);

		if (ifp->info == NULL) {
			vty_out(vty, "   OSPF not enabled on this interface\n");
			return 0;
		}
		oi = (struct ospf6_interface *)ifp->info;

		if (if_is_operative(ifp) && oi->type != default_iftype)
			vty_out(vty, "  Operating as type %s\n",
				ospf6_iftype_str(oi->type));
	}

	if (use_json) {
		json_arr = json_object_new_array();
		frr_each (if_connected, ifp->connected, c) {
			json_addr = json_object_new_object();
			p = c->address;
			prefix2str(p, strbuf, sizeof(strbuf));
			switch (p->family) {
			case AF_INET:
				json_object_string_add(json_addr, "type",
						       "inet");
				json_object_string_add(json_addr, "address",
						       strbuf);
				json_object_array_add(json_arr, json_addr);
				break;
			case AF_INET6:
				json_object_string_add(json_addr, "type",
						       "inet6");
				json_object_string_add(json_addr, "address",
						       strbuf);
				json_object_array_add(json_arr, json_addr);
				break;
			default:
				json_object_string_add(json_addr, "type",
						       "unknown");
				json_object_string_add(json_addr, "address",
						       strbuf);
				json_object_array_add(json_arr, json_addr);
				break;
			}
		}
		json_object_object_add(json_obj, "internetAddress", json_arr);
	} else {
		vty_out(vty, "  Internet Address:\n");

		frr_each (if_connected, ifp->connected, c) {
			p = c->address;
			prefix2str(p, strbuf, sizeof(strbuf));
			switch (p->family) {
			case AF_INET:
				vty_out(vty, "    inet : %pFX\n", p);
				break;
			case AF_INET6:
				vty_out(vty, "    inet6: %pFX\n", p);
				break;
			default:
				vty_out(vty, "    ???  : %pFX\n", p);
				break;
			}
		}
	}

	if (use_json) {
		if (oi->area) {
			json_object_boolean_true_add(json_obj, "attachedToArea");
			json_object_int_add(json_obj, "instanceId",
					    oi->instance_id);
			json_object_int_add(json_obj, "interfaceMtu", oi->ifmtu);
			json_object_int_add(json_obj, "autoDetect", ifp->mtu6);
			json_object_string_add(json_obj, "mtuMismatchDetection",
					       oi->mtu_ignore ? "disabled"
							      : "enabled");
			inet_ntop(AF_INET, &oi->area->area_id, strbuf,
				  sizeof(strbuf));
			json_object_string_add(json_obj, "areaId", strbuf);
			json_object_int_add(json_obj, "cost", oi->cost);
		} else
			json_object_boolean_false_add(json_obj,
						      "attachedToArea");

	} else {
		if (oi->area) {
			vty_out(vty,
				"  Instance ID %d, Interface MTU %d (autodetect: %d)\n",
				oi->instance_id, oi->ifmtu, ifp->mtu6);
			vty_out(vty, "  MTU mismatch detection: %s\n",
				oi->mtu_ignore ? "disabled" : "enabled");
			inet_ntop(AF_INET, &oi->area->area_id, strbuf,
				  sizeof(strbuf));
			vty_out(vty, "  Area ID %s, Cost %u\n", strbuf,
				oi->cost);
		} else
			vty_out(vty, "  Not Attached to Area\n");
	}

	if (use_json) {
		json_object_string_add(json_obj, "ospf6InterfaceState",
				       ospf6_interface_state_str[oi->state]);
		json_object_int_add(json_obj, "transmitDelaySec",
				    oi->transdelay);
		json_object_int_add(json_obj, "priority", oi->priority);
		json_object_int_add(json_obj, "timerIntervalsConfigHello",
				    oi->hello_interval);
		json_object_int_add(json_obj, "timerIntervalsConfigDead",
				    oi->dead_interval);
		json_object_int_add(json_obj, "timerIntervalsConfigRetransmit",
				    oi->rxmt_interval);
		json_object_boolean_add(json_obj, "timerPassiveIface",
					!!CHECK_FLAG(oi->flag,
						     OSPF6_INTERFACE_PASSIVE));
	} else {
		vty_out(vty, "  State %s, Transmit Delay %d sec, Priority %d\n",
			ospf6_interface_state_str[oi->state], oi->transdelay,
			oi->priority);
		vty_out(vty, "  Timer intervals configured:\n");
		if (!CHECK_FLAG(oi->flag, OSPF6_INTERFACE_PASSIVE))
			vty_out(vty,
				"   Hello %d(%pTHd), Dead %d, Retransmit %d\n",
				oi->hello_interval, oi->thread_send_hello,
				oi->dead_interval, oi->rxmt_interval);
		else
			vty_out(vty, "   No Hellos (Passive interface)\n");
	}

	inet_ntop(AF_INET, &oi->drouter, drouter, sizeof(drouter));
	inet_ntop(AF_INET, &oi->bdrouter, bdrouter, sizeof(bdrouter));
	if (use_json) {
		json_object_string_add(json_obj, "dr", drouter);
		json_object_string_add(json_obj, "bdr", bdrouter);
		json_object_int_add(json_obj, "numberOfInterfaceScopedLsa",
				    oi->lsdb->count);
	} else {
		vty_out(vty, "  DR: %s BDR: %s\n", drouter, bdrouter);
		vty_out(vty, "  Number of I/F scoped LSAs is %u\n",
			oi->lsdb->count);
	}

	monotime(&now);

	if (use_json) {
		timerclear(&res);
		if (event_is_scheduled(oi->thread_send_lsupdate))
			timersub(&oi->thread_send_lsupdate->u.sands, &now, &res);
		timerstring(&res, duration, sizeof(duration));
		json_object_int_add(json_obj, "pendingLsaLsUpdateCount",
				    oi->lsupdate_list->count);
		json_object_string_add(json_obj, "pendingLsaLsUpdateTime",
				       duration);
		json_object_string_add(json_obj, "lsUpdateSendThread",
				       (event_is_scheduled(
						oi->thread_send_lsupdate)
						? "on"
						: "off"));

		json_arr = json_object_new_array();
		for (ALL_LSDB(oi->lsupdate_list, lsa, lsanext))
			json_object_array_add(json_arr,
					      json_object_new_string(lsa->name));
		json_object_object_add(json_obj, "pendingLsaLsUpdate", json_arr);

		timerclear(&res);
		if (event_is_scheduled(oi->thread_send_lsack))
			timersub(&oi->thread_send_lsack->u.sands, &now, &res);
		timerstring(&res, duration, sizeof(duration));

		json_object_int_add(json_obj, "pendingLsaLsAckCount",
				    oi->lsack_list->count);
		json_object_string_add(json_obj, "pendingLsaLsAckTime",
				       duration);
		json_object_string_add(json_obj, "lsAckSendThread",
				       (event_is_scheduled(oi->thread_send_lsack)
						? "on"
						: "off"));

		json_arr = json_object_new_array();
		for (ALL_LSDB(oi->lsack_list, lsa, lsanext))
			json_object_array_add(json_arr,
					      json_object_new_string(lsa->name));
		json_object_object_add(json_obj, "pendingLsaLsAck", json_arr);

		if (oi->gr.hello_delay.interval != 0)
			json_object_int_add(json_obj, "grHelloDelaySecs",
					    oi->gr.hello_delay.interval);
	} else {
		timerclear(&res);
		if (event_is_scheduled(oi->thread_send_lsupdate))
			timersub(&oi->thread_send_lsupdate->u.sands, &now, &res);
		timerstring(&res, duration, sizeof(duration));
		vty_out(vty,
			"    %d Pending LSAs for LSUpdate in Time %s [thread %s]\n",
			oi->lsupdate_list->count, duration,
			(event_is_scheduled(oi->thread_send_lsupdate) ? "on"
								      : "off"));
		for (ALL_LSDB(oi->lsupdate_list, lsa, lsanext))
			vty_out(vty, "      %s\n", lsa->name);

		timerclear(&res);
		if (event_is_scheduled(oi->thread_send_lsack))
			timersub(&oi->thread_send_lsack->u.sands, &now, &res);
		timerstring(&res, duration, sizeof(duration));
		vty_out(vty,
			"    %d Pending LSAs for LSAck in Time %s [thread %s]\n",
			oi->lsack_list->count, duration,
			(event_is_scheduled(oi->thread_send_lsack) ? "on"
								   : "off"));
		for (ALL_LSDB(oi->lsack_list, lsa, lsanext))
			vty_out(vty, "      %s\n", lsa->name);

		if (oi->gr.hello_delay.interval != 0)
			vty_out(vty, "  Graceful Restart hello delay: %us\n",
				oi->gr.hello_delay.interval);
	}

	/* BFD specific. */
	if (oi->bfd_config.enabled) {
		if (use_json) {
			struct json_object *json_bfd = json_object_new_object();

			json_object_int_add(json_bfd, "detectMultiplier",
					    oi->bfd_config.detection_multiplier);
			json_object_int_add(json_bfd, "rxMinInterval",
					    oi->bfd_config.min_rx);
			json_object_int_add(json_bfd, "txMinInterval",
					    oi->bfd_config.min_tx);
			json_object_object_add(json_obj, "peerBfdInfo",
					       json_bfd);
		} else {
			vty_out(vty,
				"  BFD: Detect Multiplier: %d, Min Rx interval: %d, Min Tx interval: %d\n",
				oi->bfd_config.detection_multiplier,
				oi->bfd_config.min_rx, oi->bfd_config.min_tx);
		}
	}

	if (use_json)
		json_auth = json_object_new_object();
	if (oi->at_data.flags != 0) {
		if (use_json) {
			if (CHECK_FLAG(oi->at_data.flags,
				       OSPF6_AUTH_TRAILER_KEYCHAIN)) {
				json_object_string_add(json_auth, "authType",
						       "keychain");
				json_object_string_add(json_auth, "keychainName",
						       oi->at_data.keychain);
			} else if (CHECK_FLAG(oi->at_data.flags,
					      OSPF6_AUTH_TRAILER_MANUAL_KEY))
				json_object_string_add(json_auth, "authType",
						       "manualkey");
			json_object_int_add(json_auth, "txPktDrop",
					    oi->at_data.tx_drop);
			json_object_int_add(json_auth, "rxPktDrop",
					    oi->at_data.rx_drop);
		} else {
			if (CHECK_FLAG(oi->at_data.flags,
				       OSPF6_AUTH_TRAILER_KEYCHAIN))
				vty_out(vty,
					"  Authentication Trailer is enabled with key-chain %s\n",
					oi->at_data.keychain);
			else if (CHECK_FLAG(oi->at_data.flags,
					    OSPF6_AUTH_TRAILER_MANUAL_KEY))
				vty_out(vty,
					"  Authentication trailer is enabled with manual key\n");
			vty_out(vty,
				"    Packet drop Tx %u, Packet drop Rx %u\n",
				oi->at_data.tx_drop, oi->at_data.rx_drop);
		}
	} else {
		if (use_json)
			json_object_string_add(json_auth, "authType", "NULL");
		else
			vty_out(vty, "  Authentication Trailer is disabled\n");
	}

	if (use_json)
		json_object_object_add(json_obj, "authInfo", json_auth);

	return 0;
}

/* Find the global address to be used as a forwarding address in NSSA LSA.*/
struct in6_addr *ospf6_interface_get_global_address(struct interface *ifp)
{
	struct connected *c;

	/* for each connected address */
	frr_each (if_connected, ifp->connected, c) {
		/* if family not AF_INET6, ignore */
		if (c->address->family != AF_INET6)
			continue;

		if (!IN6_IS_ADDR_LINKLOCAL(&c->address->u.prefix6))
			return &c->address->u.prefix6;
	}

	return NULL;
}


static int show_ospf6_interface_common(struct vty *vty, vrf_id_t vrf_id,
				       int argc, struct cmd_token **argv,
				       int idx_ifname, int intf_idx,
				       int json_idx, bool uj)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct interface *ifp;
	json_object *json;
	json_object *json_int;

	if (uj) {
		json = json_object_new_object();
		if (argc == json_idx) {
			ifp = if_lookup_by_name(argv[idx_ifname]->arg, vrf_id);
			json_int = json_object_new_object();
			if (ifp == NULL) {
				json_object_string_add(json, "noSuchInterface",
						       argv[idx_ifname]->arg);
				vty_json(vty, json);
				json_object_free(json_int);
				return CMD_WARNING;
			}
			ospf6_interface_show(vty, ifp, json_int, uj);
			json_object_object_add(json, ifp->name, json_int);
		} else {
			FOR_ALL_INTERFACES (vrf, ifp) {
				json_int = json_object_new_object();
				ospf6_interface_show(vty, ifp, json_int, uj);
				json_object_object_add(json, ifp->name,
						       json_int);
			}
		}
		vty_json(vty, json);
	} else {
		if (argc == intf_idx) {
			ifp = if_lookup_by_name(argv[idx_ifname]->arg, vrf_id);
			if (ifp == NULL) {
				vty_out(vty, "No such Interface: %s\n",
					argv[idx_ifname]->arg);
				return CMD_WARNING;
			}
			ospf6_interface_show(vty, ifp, NULL, uj);
		} else {
			FOR_ALL_INTERFACES (vrf, ifp)
				ospf6_interface_show(vty, ifp, NULL, uj);
		}
	}
	return CMD_SUCCESS;
}

/* show interface */
DEFUN(show_ipv6_ospf6_interface,
      show_ipv6_ospf6_interface_ifname_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] interface [IFNAME] [json]",
      SHOW_STR
      IP6_STR
      OSPF6_STR
      VRF_CMD_HELP_STR
      "All VRFs\n"
      INTERFACE_STR
      IFNAME_STR
      JSON_STR)
{
	int idx_ifname = 4;
	int intf_idx = 5;
	int json_idx = 6;
	struct listnode *node;
	struct ospf6 *ospf6;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_ifname += 2;
		intf_idx += 2;
		json_idx += 2;
	}

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			show_ospf6_interface_common(vty, ospf6->vrf_id, argc,
						    argv, idx_ifname, intf_idx,
						    json_idx, uj);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

static int ospf6_interface_show_traffic(struct vty *vty,
					struct interface *intf_ifp,
					int display_once, json_object *json,
					bool use_json, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct vrf *vrf = NULL;
	struct ospf6_interface *oi = NULL;
	json_object *json_interface;

	if (!display_once && !use_json) {
		vty_out(vty, "\n");
		vty_out(vty, "%-12s%-17s%-17s%-17s%-17s%-17s\n", "Interface",
			"    HELLO", "    DB-Desc", "   LS-Req", "   LS-Update",
			"   LS-Ack");
		vty_out(vty, "%-10s%-18s%-18s%-17s%-17s%-17s\n", "",
			"      Rx/Tx", "     Rx/Tx", "    Rx/Tx", "    Rx/Tx",
			"    Rx/Tx");
		vty_out(vty,
			"--------------------------------------------------------------------------------------------\n");
	}

	if (intf_ifp == NULL) {
		vrf = vrf_lookup_by_id(vrf_id);
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (ifp->info)
				oi = (struct ospf6_interface *)ifp->info;
			else
				continue;

			if (use_json) {
				json_interface = json_object_new_object();
				json_object_int_add(json_interface, "helloRx",
						    oi->hello_in);
				json_object_int_add(json_interface, "helloTx",
						    oi->hello_out);
				json_object_int_add(json_interface, "dbDescRx",
						    oi->db_desc_in);
				json_object_int_add(json_interface, "dbDescTx",
						    oi->db_desc_out);
				json_object_int_add(json_interface, "lsReqRx",
						    oi->ls_req_in);
				json_object_int_add(json_interface, "lsReqTx",
						    oi->ls_req_out);
				json_object_int_add(json_interface,
						    "lsUpdateRx", oi->ls_upd_in);
				json_object_int_add(json_interface, "lsUpdateTx",
						    oi->ls_upd_out);
				json_object_int_add(json_interface, "lsAckRx",
						    oi->ls_ack_in);
				json_object_int_add(json_interface, "lsAckTx",
						    oi->ls_ack_out);

				json_object_object_add(json, oi->interface->name,
						       json_interface);
			} else
				vty_out(vty,
					"%-10s %8u/%-8u %7u/%-7u %7u/%-7u %7u/%-7u %7u/%-7u\n",
					oi->interface->name, oi->hello_in,
					oi->hello_out, oi->db_desc_in,
					oi->db_desc_out, oi->ls_req_in,
					oi->ls_req_out, oi->ls_upd_in,
					oi->ls_upd_out, oi->ls_ack_in,
					oi->ls_ack_out);
		}
	} else {
		oi = intf_ifp->info;
		if (oi == NULL)
			return CMD_WARNING;

		if (use_json) {
			json_interface = json_object_new_object();
			json_object_int_add(json_interface, "helloRx",
					    oi->hello_in);
			json_object_int_add(json_interface, "helloTx",
					    oi->hello_out);
			json_object_int_add(json_interface, "dbDescRx",
					    oi->db_desc_in);
			json_object_int_add(json_interface, "dbDescTx",
					    oi->db_desc_out);
			json_object_int_add(json_interface, "lsReqRx",
					    oi->ls_req_in);
			json_object_int_add(json_interface, "lsReqTx",
					    oi->ls_req_out);
			json_object_int_add(json_interface, "lsUpdateRx",
					    oi->ls_upd_in);
			json_object_int_add(json_interface, "lsUpdateTx",
					    oi->ls_upd_out);
			json_object_int_add(json_interface, "lsAckRx",
					    oi->ls_ack_in);
			json_object_int_add(json_interface, "lsAckTx",
					    oi->ls_ack_out);

			json_object_object_add(json, oi->interface->name,
					       json_interface);
		} else
			vty_out(vty,
				"%-10s %8u/%-8u %7u/%-7u %7u/%-7u %7u/%-7u %7u/%-7u\n",
				oi->interface->name, oi->hello_in,
				oi->hello_out, oi->db_desc_in, oi->db_desc_out,
				oi->ls_req_in, oi->ls_req_out, oi->ls_upd_in,
				oi->ls_upd_out, oi->ls_ack_in, oi->ls_ack_out);
	}

	return CMD_SUCCESS;
}

static int ospf6_interface_show_traffic_common(struct vty *vty, int argc,
					       struct cmd_token **argv,
					       vrf_id_t vrf_id, bool uj)
{
	int idx_ifname = 0;
	int display_once = 0;
	char *intf_name = NULL;
	struct interface *ifp = NULL;
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	if (argv_find(argv, argc, "IFNAME", &idx_ifname)) {
		intf_name = argv[idx_ifname]->arg;
		ifp = if_lookup_by_name(intf_name, vrf_id);
		if (uj) {
			if (ifp == NULL) {
				json_object_string_add(json, "status",
						       "No Such Interface");
				json_object_string_add(json, "interface",
						       intf_name);
				vty_json(vty, json);
				return CMD_WARNING;
			}
			if (ifp->info == NULL) {
				json_object_string_add(
					json, "status",
					"OSPF not enabled on this interface");
				json_object_string_add(json, "interface",
						       intf_name);
				vty_json(vty, json);
				return 0;
			}
		} else {
			if (ifp == NULL) {
				vty_out(vty, "No such Interface: %s\n",
					intf_name);
				return CMD_WARNING;
			}
			if (ifp->info == NULL) {
				vty_out(vty,
					"   OSPF not enabled on this interface %s\n",
					intf_name);
				return 0;
			}
		}
	}

	ospf6_interface_show_traffic(vty, ifp, display_once, json, uj, vrf_id);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/* show interface */
DEFUN(show_ipv6_ospf6_interface_traffic,
      show_ipv6_ospf6_interface_traffic_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] interface traffic [IFNAME] [json]",
      SHOW_STR
      IP6_STR
      OSPF6_STR
      VRF_CMD_HELP_STR
      "All VRFs\n"
      INTERFACE_STR
      "Protocol Packet counters\n"
      IFNAME_STR
      JSON_STR)
{
	struct ospf6 *ospf6;
	struct listnode *node;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ospf6_interface_show_traffic_common(vty, argc, argv,
							    ospf6->vrf_id, uj);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}


DEFUN(show_ipv6_ospf6_interface_ifname_prefix,
      show_ipv6_ospf6_interface_ifname_prefix_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] interface IFNAME prefix "
          "[<detail|<X:X::X:X|X:X::X:X/M> [<match|detail>]>] [json]",
      SHOW_STR
      IP6_STR
      OSPF6_STR
      VRF_CMD_HELP_STR
      "All VRFs\n"
      INTERFACE_STR IFNAME_STR
      "Display connected prefixes to advertise\n"
      "Display details of the prefixes\n"
      OSPF6_ROUTE_ADDRESS_STR
      OSPF6_ROUTE_PREFIX_STR
      OSPF6_ROUTE_MATCH_STR
      "Display details of the prefixes\n"
      JSON_STR)
{
	int idx_ifname = 4;
	int idx_prefix = 6;
	struct ospf6_interface *oi;
	bool uj = use_json(argc, argv);

	struct ospf6 *ospf6;
	struct listnode *node;
	struct interface *ifp;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_ifname += 2;
		idx_prefix += 2;
	}

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ifp = if_lookup_by_name(argv[idx_ifname]->arg,
						ospf6->vrf_id);
			if (ifp == NULL) {
				vty_out(vty, "No such Interface: %s\n",
					argv[idx_ifname]->arg);
				return CMD_WARNING;
			}

			oi = ifp->info;
			if (oi == NULL ||
			    CHECK_FLAG(oi->flag, OSPF6_INTERFACE_DISABLE)) {
				vty_out(vty,
					"Interface %s not attached to area\n",
					argv[idx_ifname]->arg);
				return CMD_WARNING;
			}

			ospf6_route_table_show(vty, idx_prefix, argc, argv,
					       oi->route_connected, uj);

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_interface_prefix,
      show_ipv6_ospf6_interface_prefix_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] interface prefix "
          "[<detail|<X:X::X:X|X:X::X:X/M> [<match|detail>]>] [json]",
      SHOW_STR
      IP6_STR
      OSPF6_STR
      VRF_CMD_HELP_STR
      "All VRFs\n"
      INTERFACE_STR
      "Display connected prefixes to advertise\n"
      "Display details of the prefixes\n"
      OSPF6_ROUTE_ADDRESS_STR
      OSPF6_ROUTE_PREFIX_STR
      OSPF6_ROUTE_MATCH_STR
      "Display details of the prefixes\n"
      JSON_STR)
{
	struct vrf *vrf = NULL;
	int idx_prefix = 5;
	struct ospf6_interface *oi;
	struct interface *ifp;
	bool uj = use_json(argc, argv);
	struct listnode *node;
	struct ospf6 *ospf6;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0)
		idx_prefix += 2;

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			vrf = vrf_lookup_by_id(ospf6->vrf_id);
			FOR_ALL_INTERFACES (vrf, ifp) {
				oi = (struct ospf6_interface *)ifp->info;
				if (oi == NULL ||
				    CHECK_FLAG(oi->flag,
					       OSPF6_INTERFACE_DISABLE))
					continue;

				ospf6_route_table_show(vty, idx_prefix, argc,
						       argv,
						       oi->route_connected, uj);
			}
			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

void ospf6_interface_start(struct ospf6_interface *oi)
{
	struct ospf6 *ospf6;
	struct ospf6_area *oa;

	if (oi->area_id_format == OSPF6_AREA_FMT_UNSET)
		return;

	if (oi->area) {
		/* Recompute cost */
		ospf6_interface_recalculate_cost(oi);
		return;
	}

	ospf6 = oi->interface->vrf->info;
	if (!ospf6)
		return;

	oa = ospf6_area_lookup(oi->area_id, ospf6);
	if (oa == NULL)
		oa = ospf6_area_create(oi->area_id, ospf6, oi->area_id_format);

	/* attach interface to area */
	listnode_add(oa->if_list, oi);
	oi->area = oa;

	SET_FLAG(oa->flag, OSPF6_AREA_ENABLE);

	/* start up */
	ospf6_interface_enable(oi);

	/* If the router is ABR, originate summary routes */
	if (ospf6_check_and_set_router_abr(ospf6)) {
		ospf6_abr_enable_area(oa);
		ospf6_schedule_abr_task(ospf6);
	}
}

void ospf6_interface_stop(struct ospf6_interface *oi)
{
	struct ospf6_area *oa;

	oa = oi->area;
	if (!oa)
		return;

	ospf6_interface_disable(oi);

	listnode_delete(oa->if_list, oi);
	oi->area = NULL;

	if (oa->if_list->count == 0) {
		UNSET_FLAG(oa->flag, OSPF6_AREA_ENABLE);
		ospf6_abr_disable_area(oa);
	}
}

/* interface variable set command */
DEFUN (ipv6_ospf6_area,
       ipv6_ospf6_area_cmd,
       "ipv6 ospf6 area <A.B.C.D|(0-4294967295)>",
       IP6_STR
       OSPF6_STR
       "Specify the OSPF6 area ID\n"
       "OSPF6 area ID in IPv4 address notation\n"
       "OSPF6 area ID in decimal notation\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
	int idx_ipv4 = 3;
	uint32_t area_id;
	int format;

	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	if (oi->area) {
		vty_out(vty, "%s already attached to Area %s\n",
			oi->interface->name, oi->area->name);
		return CMD_SUCCESS;
	}

	if (str2area_id(argv[idx_ipv4]->arg, &area_id, &format)) {
		vty_out(vty, "Malformed Area-ID: %s\n", argv[idx_ipv4]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	oi->area_id = area_id;
	oi->area_id_format = format;

	ospf6_interface_start(oi);

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_area,
       no_ipv6_ospf6_area_cmd,
       "no ipv6 ospf6 area [<A.B.C.D|(0-4294967295)>]",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Specify the OSPF6 area ID\n"
       "OSPF6 area ID in IPv4 address notation\n"
       "OSPF6 area ID in decimal notation\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;

	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	ospf6_interface_stop(oi);

	oi->area_id = 0;
	oi->area_id_format = OSPF6_AREA_FMT_UNSET;

	return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_ifmtu,
       ipv6_ospf6_ifmtu_cmd,
       "ipv6 ospf6 ifmtu (1-65535)",
       IP6_STR
       OSPF6_STR
       "Interface MTU\n"
       "OSPFv3 Interface MTU\n"
       )
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_number = 3;
	struct ospf6_interface *oi;
	unsigned int ifmtu, iobuflen;
	struct listnode *node, *nnode;
	struct ospf6_neighbor *on;

	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	ifmtu = strtol(argv[idx_number]->arg, NULL, 10);

	if (oi->c_ifmtu == ifmtu)
		return CMD_SUCCESS;

	if (ifp->mtu6 != 0 && ifp->mtu6 < ifmtu) {
		vty_out(vty,
			"%s's ospf6 ifmtu cannot go beyond physical mtu (%d)\n",
			ifp->name, ifp->mtu6);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (oi->ifmtu < ifmtu) {
		iobuflen = ospf6_iobuf_size(ifmtu);
		if (iobuflen < ifmtu) {
			vty_out(vty,
				"%s's ifmtu is adjusted to I/O buffer size (%d).\n",
				ifp->name, iobuflen);
			oi->ifmtu = oi->c_ifmtu = iobuflen;
		} else
			oi->ifmtu = oi->c_ifmtu = ifmtu;
	} else
		oi->ifmtu = oi->c_ifmtu = ifmtu;

	/* re-establish adjacencies */
	for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on)) {
		EVENT_OFF(on->inactivity_timer);
		event_add_event(master, inactivity_timer, on, 0, NULL);
	}

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_ifmtu,
       no_ipv6_ospf6_ifmtu_cmd,
       "no ipv6 ospf6 ifmtu [(1-65535)]",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Interface MTU\n"
       "OSPFv3 Interface MTU\n"
       )
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
	unsigned int iobuflen;
	struct listnode *node, *nnode;
	struct ospf6_neighbor *on;

	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	if (oi->ifmtu < ifp->mtu) {
		iobuflen = ospf6_iobuf_size(ifp->mtu);
		if (iobuflen < ifp->mtu) {
			vty_out(vty,
				"%s's ifmtu is adjusted to I/O buffer size (%d).\n",
				ifp->name, iobuflen);
			oi->ifmtu = iobuflen;
		} else
			oi->ifmtu = ifp->mtu;
	} else
		oi->ifmtu = ifp->mtu;

	oi->c_ifmtu = 0;

	/* re-establish adjacencies */
	for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on)) {
		EVENT_OFF(on->inactivity_timer);
		event_add_event(master, inactivity_timer, on, 0, NULL);
	}

	return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_cost,
       ipv6_ospf6_cost_cmd,
       "ipv6 ospf6 cost (1-65535)",
       IP6_STR
       OSPF6_STR
       "Interface cost\n"
       "Outgoing metric of this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_number = 3;
	struct ospf6_interface *oi;
	unsigned long int lcost;

	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	lcost = strtol(argv[idx_number]->arg, NULL, 10);

	if (lcost > UINT32_MAX) {
		vty_out(vty, "Cost %ld is out of range\n", lcost);
		return CMD_WARNING_CONFIG_FAILED;
	}

	SET_FLAG(oi->flag, OSPF6_INTERFACE_NOAUTOCOST);
	if (oi->cost == lcost)
		return CMD_SUCCESS;

	oi->cost = lcost;
	ospf6_interface_force_recalculate_cost(oi);

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_cost,
       no_ipv6_ospf6_cost_cmd,
       "no ipv6 ospf6 cost [(1-65535)]",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Calculate interface cost from bandwidth\n"
       "Outgoing metric of this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	UNSET_FLAG(oi->flag, OSPF6_INTERFACE_NOAUTOCOST);

	ospf6_interface_recalculate_cost(oi);

	return CMD_SUCCESS;
}

DEFUN (auto_cost_reference_bandwidth,
       auto_cost_reference_bandwidth_cmd,
       "auto-cost reference-bandwidth (1-4294967)",
       "Calculate OSPF interface cost according to bandwidth\n"
       "Use reference bandwidth method to assign OSPF cost\n"
       "The reference bandwidth in terms of Mbits per second\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, o);
	int idx_number = 2;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	struct listnode *i, *j;
	uint32_t refbw;

	refbw = strtol(argv[idx_number]->arg, NULL, 10);
	if (refbw < 1 || refbw > 4294967) {
		vty_out(vty, "reference-bandwidth value is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* If reference bandwidth is changed. */
	if ((refbw) == o->ref_bandwidth)
		return CMD_SUCCESS;

	o->ref_bandwidth = refbw;
	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa))
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi))
			ospf6_interface_recalculate_cost(oi);

	return CMD_SUCCESS;
}

DEFUN (no_auto_cost_reference_bandwidth,
       no_auto_cost_reference_bandwidth_cmd,
       "no auto-cost reference-bandwidth [(1-4294967)]",
       NO_STR
       "Calculate OSPF interface cost according to bandwidth\n"
       "Use reference bandwidth method to assign OSPF cost\n"
       "The reference bandwidth in terms of Mbits per second\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, o);
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	struct listnode *i, *j;

	if (o->ref_bandwidth == OSPF6_REFERENCE_BANDWIDTH)
		return CMD_SUCCESS;

	o->ref_bandwidth = OSPF6_REFERENCE_BANDWIDTH;
	for (ALL_LIST_ELEMENTS_RO(o->area_list, i, oa))
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi))
			ospf6_interface_recalculate_cost(oi);

	return CMD_SUCCESS;
}


DEFUN (ospf6_write_multiplier,
       ospf6_write_multiplier_cmd,
       "write-multiplier (1-100)",
       "Write multiplier\n"
       "Maximum number of interface serviced per write\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, o);
	uint32_t write_oi_count;

	write_oi_count = strtol(argv[1]->arg, NULL, 10);
	if (write_oi_count < 1 || write_oi_count > 100) {
		vty_out(vty, "write-multiplier value is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	o->write_oi_count = write_oi_count;
	return CMD_SUCCESS;
}

DEFUN (no_ospf6_write_multiplier,
       no_ospf6_write_multiplier_cmd,
       "no write-multiplier (1-100)",
       NO_STR
       "Write multiplier\n"
       "Maximum number of interface serviced per write\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, o);

	o->write_oi_count = OSPF6_WRITE_INTERFACE_COUNT_DEFAULT;
	return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_hellointerval,
       ipv6_ospf6_hellointerval_cmd,
       "ipv6 ospf6 hello-interval (1-65535)",
       IP6_STR
       OSPF6_STR
       "Time between HELLO packets\n"
       SECONDS_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_number = 3;
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	oi->hello_interval = strmatch(argv[0]->text, "no")
				     ? OSPF_HELLO_INTERVAL_DEFAULT
				     : strtoul(argv[idx_number]->arg, NULL, 10);

	/*
	 * If the thread is scheduled, send the new hello now.
	 */
	if (event_is_scheduled(oi->thread_send_hello)) {
		EVENT_OFF(oi->thread_send_hello);

		event_add_timer(master, ospf6_hello_send, oi, 0,
				&oi->thread_send_hello);
	}
	return CMD_SUCCESS;
}

ALIAS (ipv6_ospf6_hellointerval,
       no_ipv6_ospf6_hellointerval_cmd,
       "no ipv6 ospf6 hello-interval [(1-65535)]",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Time between HELLO packets\n"
       SECONDS_STR)

/* interface variable set command */
DEFUN (ipv6_ospf6_deadinterval,
       ipv6_ospf6_deadinterval_cmd,
       "ipv6 ospf6 dead-interval (1-65535)",
       IP6_STR
       OSPF6_STR
       "Interval time after which a neighbor is declared down\n"
       SECONDS_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_number = 3;
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	oi->dead_interval = strmatch(argv[0]->arg, "no")
				    ? OSPF_ROUTER_DEAD_INTERVAL_DEFAULT
				    : strtoul(argv[idx_number]->arg, NULL, 10);
	return CMD_SUCCESS;
}

ALIAS (ipv6_ospf6_deadinterval,
       no_ipv6_ospf6_deadinterval_cmd,
       "no ipv6 ospf6 dead-interval [(1-65535)]",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Interval time after which a neighbor is declared down\n"
       SECONDS_STR)

DEFPY(ipv6_ospf6_gr_hdelay,
      ipv6_ospf6_gr_hdelay_cmd,
      "ipv6 ospf6 graceful-restart hello-delay (1-1800)",
      IP6_STR
      OSPF6_STR
      "Graceful Restart parameters\n"
      "Delay the sending of the first hello packets.\n"
      "Delay in seconds\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;

	oi = ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);

	/* Note: new or updated value won't affect ongoing graceful restart. */
	oi->gr.hello_delay.interval = hello_delay;

	return CMD_SUCCESS;
}

DEFPY(no_ipv6_ospf6_gr_hdelay,
      no_ipv6_ospf6_gr_hdelay_cmd,
      "no ipv6 ospf6 graceful-restart hello-delay [(1-1800)]",
      NO_STR
      IP6_STR
      OSPF6_STR
      "Graceful Restart parameters\n"
      "Delay the sending of the first hello packets.\n"
      "Delay in seconds\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;

	oi = ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);

	oi->gr.hello_delay.interval = OSPF_HELLO_DELAY_DEFAULT;
	oi->gr.hello_delay.elapsed_seconds = 0;
	EVENT_OFF(oi->gr.hello_delay.t_grace_send);

	return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_transmitdelay,
       ipv6_ospf6_transmitdelay_cmd,
       "ipv6 ospf6 transmit-delay (1-3600)",
       IP6_STR
       OSPF6_STR
       "Link state transmit delay\n"
       SECONDS_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_number = 3;
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	oi->transdelay = strmatch(argv[0]->text, "no")
				 ? OSPF6_INTERFACE_TRANSDELAY
				 : strtoul(argv[idx_number]->arg, NULL, 10);
	return CMD_SUCCESS;
}

ALIAS (ipv6_ospf6_transmitdelay,
       no_ipv6_ospf6_transmitdelay_cmd,
       "no ipv6 ospf6 transmit-delay [(1-3600)]",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Link state transmit delay\n"
       SECONDS_STR)

/* interface variable set command */
DEFUN (ipv6_ospf6_retransmitinterval,
       ipv6_ospf6_retransmitinterval_cmd,
       "ipv6 ospf6 retransmit-interval (1-65535)",
       IP6_STR
       OSPF6_STR
       "Time between retransmitting lost link state advertisements\n"
       SECONDS_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_number = 3;
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	oi->rxmt_interval = strmatch(argv[0]->text, "no")
				    ? OSPF_RETRANSMIT_INTERVAL_DEFAULT
				    : strtoul(argv[idx_number]->arg, NULL, 10);
	return CMD_SUCCESS;
}

ALIAS (ipv6_ospf6_retransmitinterval,
       no_ipv6_ospf6_retransmitinterval_cmd,
       "no ipv6 ospf6 retransmit-interval [(1-65535)]",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Time between retransmitting lost link state advertisements\n"
       SECONDS_STR)

/* interface variable set command */
DEFUN (ipv6_ospf6_priority,
       ipv6_ospf6_priority_cmd,
       "ipv6 ospf6 priority (0-255)",
       IP6_STR
       OSPF6_STR
       "Router priority\n"
       "Priority value\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_number = 3;
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	oi->priority = strmatch(argv[0]->text, "no")
			       ? OSPF6_INTERFACE_PRIORITY
			       : strtoul(argv[idx_number]->arg, NULL, 10);

	if (oi->area && (oi->state == OSPF6_INTERFACE_DROTHER ||
			 oi->state == OSPF6_INTERFACE_BDR ||
			 oi->state == OSPF6_INTERFACE_DR)) {
		if (ospf6_interface_state_change(dr_election(oi), oi) == -1)
			OSPF6_LINK_LSA_SCHEDULE(oi);
	}

	return CMD_SUCCESS;
}

ALIAS (ipv6_ospf6_priority,
       no_ipv6_ospf6_priority_cmd,
       "no ipv6 ospf6 priority [(0-255)]",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Router priority\n"
       "Priority value\n")

DEFUN (ipv6_ospf6_instance,
       ipv6_ospf6_instance_cmd,
       "ipv6 ospf6 instance-id (0-255)",
       IP6_STR
       OSPF6_STR
       "Instance ID for this interface\n"
       "Instance ID value\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_number = 3;
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	oi->instance_id = strmatch(argv[0]->text, "no")
				  ? OSPF6_INTERFACE_INSTANCE_ID
				  : strtoul(argv[idx_number]->arg, NULL, 10);
	return CMD_SUCCESS;
}

ALIAS (ipv6_ospf6_instance,
       no_ipv6_ospf6_instance_cmd,
       "no ipv6 ospf6 instance-id [(0-255)]",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Instance ID for this interface\n"
       "Instance ID value\n")

DEFUN (ipv6_ospf6_passive,
       ipv6_ospf6_passive_cmd,
       "ipv6 ospf6 passive",
       IP6_STR
       OSPF6_STR
       "Passive interface; no adjacency will be formed on this interface\n"
       )
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
	struct listnode *node, *nnode;
	struct ospf6_neighbor *on;

	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	SET_FLAG(oi->flag, OSPF6_INTERFACE_PASSIVE);
	EVENT_OFF(oi->thread_send_hello);
	EVENT_OFF(oi->thread_sso);

	for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on)) {
		EVENT_OFF(on->inactivity_timer);
		event_add_event(master, inactivity_timer, on, 0, NULL);
	}

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_passive,
       no_ipv6_ospf6_passive_cmd,
       "no ipv6 ospf6 passive",
       NO_STR
       IP6_STR
       OSPF6_STR
       "passive interface: No Adjacency will be formed on this I/F\n"
       )
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	UNSET_FLAG(oi->flag, OSPF6_INTERFACE_PASSIVE);
	EVENT_OFF(oi->thread_send_hello);
	EVENT_OFF(oi->thread_sso);

	/* don't send hellos over loopback interface */
	if (!if_is_loopback(oi->interface))
		event_add_timer(master, ospf6_hello_send, oi, 0,
				&oi->thread_send_hello);

	return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_mtu_ignore,
       ipv6_ospf6_mtu_ignore_cmd,
       "ipv6 ospf6 mtu-ignore",
       IP6_STR
       OSPF6_STR
       "Disable MTU mismatch detection on this interface\n"
       )
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	oi->mtu_ignore = 1;

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_mtu_ignore,
       no_ipv6_ospf6_mtu_ignore_cmd,
       "no ipv6 ospf6 mtu-ignore",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Disable MTU mismatch detection on this interface\n"
       )
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	oi->mtu_ignore = 0;

	return CMD_SUCCESS;
}

DEFUN(ipv6_ospf6_advertise_prefix_list,
      ipv6_ospf6_advertise_prefix_list_cmd,
      "ipv6 ospf6 advertise prefix-list PREFIXLIST6_NAME",
      IP6_STR
      OSPF6_STR
      "Advertising options\n"
      "Filter prefix using prefix-list\n"
      "Prefix list name\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_word = 4;
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	if (oi->plist_name)
		XFREE(MTYPE_CFG_PLIST_NAME, oi->plist_name);
	oi->plist_name = XSTRDUP(MTYPE_CFG_PLIST_NAME, argv[idx_word]->arg);

	ospf6_interface_connected_route_update(oi->interface);

	if (oi->area) {
		OSPF6_LINK_LSA_SCHEDULE(oi);
		if (oi->state == OSPF6_INTERFACE_DR) {
			OSPF6_NETWORK_LSA_SCHEDULE(oi);
			OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT(oi);
		}
		OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB(oi->area);
	}

	return CMD_SUCCESS;
}

DEFUN(no_ipv6_ospf6_advertise_prefix_list,
      no_ipv6_ospf6_advertise_prefix_list_cmd,
      "no ipv6 ospf6 advertise prefix-list [PREFIXLIST6_NAME]",
      NO_STR
      IP6_STR
      OSPF6_STR
      "Advertising options\n"
      "Filter prefix using prefix-list\n"
      "Prefix list name\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	if (oi->plist_name)
		XFREE(MTYPE_CFG_PLIST_NAME, oi->plist_name);

	ospf6_interface_connected_route_update(oi->interface);

	if (oi->area) {
		OSPF6_LINK_LSA_SCHEDULE(oi);
		if (oi->state == OSPF6_INTERFACE_DR) {
			OSPF6_NETWORK_LSA_SCHEDULE(oi);
			OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT(oi);
		}
		OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB(oi->area);
	}

	return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_network,
       ipv6_ospf6_network_cmd,
       "ipv6 ospf6 network <broadcast|point-to-point|point-to-multipoint>",
       IP6_STR
       OSPF6_STR
       "Network type\n"
       "Specify OSPF6 broadcast network\n"
       "Specify OSPF6 point-to-point network\n"
       "Specify OSPF6 point-to-multipoint network\n"
       )
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_network = 3;
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL) {
		oi = ospf6_interface_create(ifp);
	}
	assert(oi);

	oi->type_cfg = true;

	if (strncmp(argv[idx_network]->arg, "b", 1) == 0) {
		if (oi->type == OSPF_IFTYPE_BROADCAST)
			return CMD_SUCCESS;

		oi->type = OSPF_IFTYPE_BROADCAST;
	} else if (strncmp(argv[idx_network]->arg, "point-to-p", 10) == 0) {
		if (oi->type == OSPF_IFTYPE_POINTOPOINT) {
			return CMD_SUCCESS;
		}
		oi->type = OSPF_IFTYPE_POINTOPOINT;
	} else if (strncmp(argv[idx_network]->arg, "point-to-m", 10) == 0) {
		if (oi->type == OSPF_IFTYPE_POINTOMULTIPOINT) {
			return CMD_SUCCESS;
		}
		oi->type = OSPF_IFTYPE_POINTOMULTIPOINT;
	}

	/* Reset the interface */
	event_execute(master, interface_down, oi, 0, NULL);
	event_execute(master, interface_up, oi, 0, NULL);

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_network,
       no_ipv6_ospf6_network_cmd,
       "no ipv6 ospf6 network [<broadcast|point-to-point|point-to-multipoint>]",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Set default network type\n"
       "Specify OSPF6 broadcast network\n"
       "Specify OSPF6 point-to-point network\n"
       "Specify OSPF6 point-to-multipoint network\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
	int type;

	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		return CMD_SUCCESS;

	oi->type_cfg = false;

	type = ospf6_default_iftype(ifp);
	if (oi->type == type) {
		return CMD_SUCCESS;
	}
	oi->type = type;

	/* Reset the interface */
	event_execute(master, interface_down, oi, 0, NULL);
	event_execute(master, interface_up, oi, 0, NULL);

	return CMD_SUCCESS;
}

DEFPY (ipv6_ospf6_p2xp_only_cfg_neigh,
       ipv6_ospf6_p2xp_only_cfg_neigh_cmd,
       "[no] ipv6 ospf6 p2p-p2mp config-neighbors-only",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Point-to-point and Point-to-Multipoint parameters\n"
       "Only form adjacencies with explicitly configured neighbors\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi = ifp->info;

	if (no) {
		if (!oi)
			return CMD_SUCCESS;

		oi->p2xp_only_cfg_neigh = false;
		return CMD_SUCCESS;
	}

	if (!oi)
		oi = ospf6_interface_create(ifp);

	oi->p2xp_only_cfg_neigh = true;
	return CMD_SUCCESS;
}

DEFPY (ipv6_ospf6_p2xp_no_multicast_hello,
       ipv6_ospf6_p2xp_no_multicast_hello_cmd,
       "[no] ipv6 ospf6 p2p-p2mp disable-multicast-hello",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Point-to-point and Point-to-Multipoint parameters\n"
       "Do not send multicast hellos\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi = ifp->info;

	if (no) {
		if (!oi)
			return CMD_SUCCESS;

		oi->p2xp_no_multicast_hello = false;
		return CMD_SUCCESS;
	}

	if (!oi)
		oi = ospf6_interface_create(ifp);

	oi->p2xp_no_multicast_hello = true;
	return CMD_SUCCESS;
}

DEFPY (ipv6_ospf6_p2xp_connected_pfx,
       ipv6_ospf6_p2xp_connected_pfx_cmd,
       "[no] ipv6 ospf6 p2p-p2mp connected-prefixes <include$incl|exclude$excl>",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Point-to-point and Point-to-Multipoint parameters\n"
       "Adjust handling of directly connected prefixes\n"
       "Advertise prefixes and own /128 (default for PtP)\n"
       "Ignore, only advertise own /128 (default for PtMP)\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi = ifp->info;
	bool old_incl, old_excl;

	if (no && !oi)
		return CMD_SUCCESS;

	if (!oi)
		oi = ospf6_interface_create(ifp);

	old_incl = oi->p2xp_connected_pfx_include;
	old_excl = oi->p2xp_connected_pfx_exclude;
	oi->p2xp_connected_pfx_include = false;
	oi->p2xp_connected_pfx_exclude = false;

	if (incl && !no)
		oi->p2xp_connected_pfx_include = true;
	if (excl && !no)
		oi->p2xp_connected_pfx_exclude = true;

	if (oi->p2xp_connected_pfx_include != old_incl ||
	    oi->p2xp_connected_pfx_exclude != old_excl)
		ospf6_interface_connected_route_update(ifp);
	return CMD_SUCCESS;
}

ALIAS (ipv6_ospf6_p2xp_connected_pfx,
       no_ipv6_ospf6_p2xp_connected_pfx_cmd,
       "no ipv6 ospf6 p2p-p2mp connected-prefixes",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Point-to-point and Point-to-Multipoint parameters\n"
       "Adjust handling of directly connected prefixes\n")


static int config_write_ospf6_interface(struct vty *vty, struct vrf *vrf)
{
	struct ospf6_interface *oi;
	struct interface *ifp;
	char buf[INET_ADDRSTRLEN];

	FOR_ALL_INTERFACES (vrf, ifp) {
		oi = (struct ospf6_interface *)ifp->info;
		if (oi == NULL)
			continue;

		if_vty_config_start(vty, ifp);

		if (ifp->desc)
			vty_out(vty, " description %s\n", ifp->desc);
		if (oi->area_id_format != OSPF6_AREA_FMT_UNSET) {
			area_id2str(buf, sizeof(buf), oi->area_id,
				    oi->area_id_format);
			vty_out(vty, " ipv6 ospf6 area %s\n", buf);
		}
		if (oi->c_ifmtu)
			vty_out(vty, " ipv6 ospf6 ifmtu %d\n", oi->c_ifmtu);

		if (CHECK_FLAG(oi->flag, OSPF6_INTERFACE_NOAUTOCOST))
			vty_out(vty, " ipv6 ospf6 cost %d\n", oi->cost);

		if (oi->hello_interval != OSPF6_INTERFACE_HELLO_INTERVAL)
			vty_out(vty, " ipv6 ospf6 hello-interval %d\n",
				oi->hello_interval);

		if (oi->dead_interval != OSPF6_INTERFACE_DEAD_INTERVAL)
			vty_out(vty, " ipv6 ospf6 dead-interval %d\n",
				oi->dead_interval);

		if (oi->rxmt_interval != OSPF6_INTERFACE_RXMT_INTERVAL)
			vty_out(vty, " ipv6 ospf6 retransmit-interval %d\n",
				oi->rxmt_interval);

		if (oi->priority != OSPF6_INTERFACE_PRIORITY)
			vty_out(vty, " ipv6 ospf6 priority %d\n", oi->priority);

		if (oi->transdelay != OSPF6_INTERFACE_TRANSDELAY)
			vty_out(vty, " ipv6 ospf6 transmit-delay %d\n",
				oi->transdelay);

		if (oi->instance_id != OSPF6_INTERFACE_INSTANCE_ID)
			vty_out(vty, " ipv6 ospf6 instance-id %d\n",
				oi->instance_id);

		if (oi->plist_name)
			vty_out(vty, " ipv6 ospf6 advertise prefix-list %s\n",
				oi->plist_name);

		if (CHECK_FLAG(oi->flag, OSPF6_INTERFACE_PASSIVE))
			vty_out(vty, " ipv6 ospf6 passive\n");

		if (oi->mtu_ignore)
			vty_out(vty, " ipv6 ospf6 mtu-ignore\n");

		if (oi->type_cfg && oi->type == OSPF_IFTYPE_POINTOMULTIPOINT)
			vty_out(vty,
				" ipv6 ospf6 network point-to-multipoint\n");
		else if (oi->type_cfg && oi->type == OSPF_IFTYPE_POINTOPOINT)
			vty_out(vty, " ipv6 ospf6 network point-to-point\n");
		else if (oi->type_cfg && oi->type == OSPF_IFTYPE_BROADCAST)
			vty_out(vty, " ipv6 ospf6 network broadcast\n");

		if (oi->gr.hello_delay.interval != OSPF_HELLO_DELAY_DEFAULT)
			vty_out(vty,
				" ipv6 ospf6 graceful-restart hello-delay %u\n",
				oi->gr.hello_delay.interval);
		if (oi->p2xp_only_cfg_neigh)
			vty_out(vty,
				" ipv6 ospf6 p2p-p2mp config-neighbors-only\n");

		if (oi->p2xp_no_multicast_hello)
			vty_out(vty,
				" ipv6 ospf6 p2p-p2mp disable-multicast-hello\n");

		if (oi->p2xp_connected_pfx_include)
			vty_out(vty,
				" ipv6 ospf6 p2p-p2mp connected-prefixes include\n");
		else if (oi->p2xp_connected_pfx_exclude)
			vty_out(vty,
				" ipv6 ospf6 p2p-p2mp connected-prefixes exclude\n");

		config_write_ospf6_p2xp_neighbor(vty, oi);
		ospf6_bfd_write_config(vty, oi);

		ospf6_auth_write_config(vty, &oi->at_data);
		if_vty_config_end(vty);
	}
	return 0;
}

/* Configuration write function for ospfd. */
static int config_write_interface(struct vty *vty)
{
	int write = 0;
	struct vrf *vrf = NULL;

	/* Display all VRF aware OSPF interface configuration */
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		write += config_write_ospf6_interface(vty, vrf);
	}

	return write;
}

static int ospf6_ifp_create(struct interface *ifp)
{
	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug("Zebra Interface add: %s index %d mtu %d", ifp->name,
			   ifp->ifindex, ifp->mtu6);

	if (ifp->info)
		ospf6_interface_start(ifp->info);

	return 0;
}

static int ospf6_ifp_up(struct interface *ifp)
{
	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug("Zebra Interface state change: %s index %d flags %llx metric %d mtu %d bandwidth %d",
			   ifp->name, ifp->ifindex,
			   (unsigned long long)ifp->flags, ifp->metric,
			   ifp->mtu6, ifp->bandwidth);

	ospf6_interface_state_update(ifp);

	return 0;
}

static int ospf6_ifp_down(struct interface *ifp)
{
	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug("Zebra Interface state change: %s index %d flags %llx metric %d mtu %d bandwidth %d",
			   ifp->name, ifp->ifindex,
			   (unsigned long long)ifp->flags, ifp->metric,
			   ifp->mtu6, ifp->bandwidth);

	ospf6_interface_state_update(ifp);

	return 0;
}

static int ospf6_ifp_destroy(struct interface *ifp)
{
	if (if_is_up(ifp))
		zlog_warn("Zebra: got delete of %s, but interface is still up",
			  ifp->name);

	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug("Zebra Interface delete: %s index %d mtu %d",
			   ifp->name, ifp->ifindex, ifp->mtu6);

	if (ifp->info)
		ospf6_interface_stop(ifp->info);

	return 0;
}

void ospf6_interface_init(void)
{
	/* Install interface node. */
	if_cmd_init(config_write_interface);
	hook_register_prio(if_real, 0, ospf6_ifp_create);
	hook_register_prio(if_up, 0, ospf6_ifp_up);
	hook_register_prio(if_down, 0, ospf6_ifp_down);
	hook_register_prio(if_unreal, 0, ospf6_ifp_destroy);

	install_element(VIEW_NODE, &show_ipv6_ospf6_interface_prefix_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_interface_ifname_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_interface_ifname_prefix_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_interface_traffic_cmd);

	install_element(INTERFACE_NODE, &ipv6_ospf6_area_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_area_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_cost_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_cost_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_ifmtu_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_ifmtu_cmd);

	install_element(INTERFACE_NODE, &ipv6_ospf6_deadinterval_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_hellointerval_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_gr_hdelay_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_priority_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_retransmitinterval_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_transmitdelay_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_instance_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_deadinterval_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_hellointerval_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_gr_hdelay_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_priority_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_retransmitinterval_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_transmitdelay_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_instance_cmd);

	install_element(INTERFACE_NODE, &ipv6_ospf6_passive_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_passive_cmd);

	install_element(INTERFACE_NODE, &ipv6_ospf6_mtu_ignore_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_mtu_ignore_cmd);

	install_element(INTERFACE_NODE, &ipv6_ospf6_advertise_prefix_list_cmd);
	install_element(INTERFACE_NODE,
			&no_ipv6_ospf6_advertise_prefix_list_cmd);

	install_element(INTERFACE_NODE, &ipv6_ospf6_network_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_network_cmd);

	install_element(INTERFACE_NODE, &ipv6_ospf6_p2xp_only_cfg_neigh_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_p2xp_no_multicast_hello_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_p2xp_connected_pfx_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_p2xp_connected_pfx_cmd);

	/* reference bandwidth commands */
	install_element(OSPF6_NODE, &auto_cost_reference_bandwidth_cmd);
	install_element(OSPF6_NODE, &no_auto_cost_reference_bandwidth_cmd);
	/* write-multiplier commands */
	install_element(OSPF6_NODE, &ospf6_write_multiplier_cmd);
	install_element(OSPF6_NODE, &no_ospf6_write_multiplier_cmd);
}

/* Clear the specified interface structure */
void ospf6_interface_clear(struct interface *ifp)
{
	struct ospf6_interface *oi;

	if (!if_is_operative(ifp))
		return;

	if (ifp->info == NULL)
		return;

	oi = (struct ospf6_interface *)ifp->info;

	if (IS_OSPF6_DEBUG_INTERFACE)
		zlog_debug("Interface %s: clear by reset", ifp->name);

	/* Reset the interface */
	event_execute(master, interface_down, oi, 0, NULL);
	event_execute(master, interface_up, oi, 0, NULL);
}

/* Clear interface */
DEFUN (clear_ipv6_ospf6_interface,
       clear_ipv6_ospf6_interface_cmd,
       "clear ipv6 ospf6 [vrf NAME] interface [IFNAME]",
       CLEAR_STR
       IP6_STR
       OSPF6_STR
       VRF_CMD_HELP_STR
       INTERFACE_STR
       IFNAME_STR
       )
{
	struct vrf *vrf;
	int idx_vrf = 3;
	int idx_ifname = 4;
	struct interface *ifp;
	const char *vrf_name;

	if (argv_find(argv, argc, "vrf", &idx_vrf))
		vrf_name = argv[idx_vrf + 1]->arg;
	else
		vrf_name = VRF_DEFAULT_NAME;
	vrf = vrf_lookup_by_name(vrf_name);
	if (!vrf) {
		vty_out(vty, "%% VRF %s not found\n", vrf_name);
		return CMD_WARNING;
	}

	if (!argv_find(argv, argc, "IFNAME", &idx_ifname)) {
		/* Clear all the ospfv3 interfaces. */
		FOR_ALL_INTERFACES (vrf, ifp)
			ospf6_interface_clear(ifp);
	} else {
		/* Interface name is specified. */
		ifp = if_lookup_by_name_vrf(argv[idx_ifname]->arg, vrf);
		if (!ifp) {
			vty_out(vty, "No such Interface: %s\n",
				argv[idx_ifname]->arg);
			return CMD_WARNING;
		}
		ospf6_interface_clear(ifp);
	}

	return CMD_SUCCESS;
}

void install_element_ospf6_clear_interface(void)
{
	install_element(ENABLE_NODE, &clear_ipv6_ospf6_interface_cmd);
}

DEFUN (debug_ospf6_interface,
       debug_ospf6_interface_cmd,
       "debug ospf6 interface",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Interface\n"
      )
{
	OSPF6_DEBUG_INTERFACE_ON();
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_interface,
       no_debug_ospf6_interface_cmd,
       "no debug ospf6 interface",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 Interface\n"
      )
{
	OSPF6_DEBUG_INTERFACE_OFF();
	return CMD_SUCCESS;
}

int config_write_ospf6_debug_interface(struct vty *vty)
{
	if (IS_OSPF6_DEBUG_INTERFACE)
		vty_out(vty, "debug ospf6 interface\n");
	return 0;
}

void install_element_ospf6_debug_interface(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_interface_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_interface_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_interface_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_interface_cmd);
}

void ospf6_auth_write_config(struct vty *vty, struct ospf6_auth_data *at_data)
{
	if (CHECK_FLAG(at_data->flags, OSPF6_AUTH_TRAILER_KEYCHAIN))
		vty_out(vty, " ipv6 ospf6 authentication keychain %s\n",
			at_data->keychain);
	else if (CHECK_FLAG(at_data->flags, OSPF6_AUTH_TRAILER_MANUAL_KEY))
		vty_out(vty,
			" ipv6 ospf6 authentication key-id %d hash-algo %s key %s\n",
			at_data->key_id,
			keychain_get_algo_name_by_id(at_data->hash_algo),
			at_data->auth_key);
}

DEFUN(ipv6_ospf6_intf_auth_trailer_keychain,
      ipv6_ospf6_intf_auth_trailer_keychain_cmd,
      "ipv6 ospf6 authentication keychain KEYCHAIN_NAME",
      IP6_STR
      OSPF6_STR
      "Enable authentication on this interface\n"
      "Keychain\n"
      "Keychain name\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int keychain_idx = 4;
	struct ospf6_interface *oi;

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);

	assert(oi);
	if (CHECK_FLAG(oi->at_data.flags, OSPF6_AUTH_TRAILER_MANUAL_KEY)) {
		vty_out(vty,
			"Manual key configured, unconfigure it before configuring key chain\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	SET_FLAG(oi->at_data.flags, OSPF6_AUTH_TRAILER_KEYCHAIN);
	if (oi->at_data.keychain)
		XFREE(MTYPE_OSPF6_AUTH_KEYCHAIN, oi->at_data.keychain);

	oi->at_data.keychain = XSTRDUP(MTYPE_OSPF6_AUTH_KEYCHAIN,
				       argv[keychain_idx]->arg);

	return CMD_SUCCESS;
}

DEFUN(no_ipv6_ospf6_intf_auth_trailer_keychain,
      no_ipv6_ospf6_intf_auth_trailer_keychain_cmd,
      "no ipv6 ospf6 authentication keychain [KEYCHAIN_NAME]",
      NO_STR
      IP6_STR
      OSPF6_STR
      "Enable authentication on this interface\n"
      "Keychain\n"
      "Keychain name\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);

	assert(oi);
	if (!CHECK_FLAG(oi->at_data.flags, OSPF6_AUTH_TRAILER_KEYCHAIN))
		return CMD_SUCCESS;

	if (oi->at_data.keychain) {
		oi->at_data.flags = 0;
		XFREE(MTYPE_OSPF6_AUTH_KEYCHAIN, oi->at_data.keychain);
		oi->at_data.keychain = NULL;
	}

	return CMD_SUCCESS;
}

DEFUN(ipv6_ospf6_intf_auth_trailer_key,
      ipv6_ospf6_intf_auth_trailer_key_cmd,
      "ipv6 ospf6 authentication key-id (1-65535) hash-algo "
      "<md5|hmac-sha-1|hmac-sha-256|hmac-sha-384|hmac-sha-512> "
      "key WORD",
      IP6_STR
      OSPF6_STR
      "Authentication\n"
      "Key ID\n"
      "Key ID value\n"
      "Cryptographic-algorithm\n"
      "Use MD5 algorithm\n"
      "Use HMAC-SHA-1 algorithm\n"
      "Use HMAC-SHA-256 algorithm\n"
      "Use HMAC-SHA-384 algorithm\n"
      "Use HMAC-SHA-512 algorithm\n"
      "Password\n"
      "Password string (key)\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int key_id_idx = 4;
	int hash_algo_idx = 6;
	int password_idx = 8;
	struct ospf6_interface *oi;
	uint8_t hash_algo = KEYCHAIN_ALGO_NULL;

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);

	assert(oi);
	if (CHECK_FLAG(oi->at_data.flags, OSPF6_AUTH_TRAILER_KEYCHAIN)) {
		vty_out(vty,
			"key chain configured, unconfigure it before configuring manual key\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	hash_algo = keychain_get_algo_id_by_name(argv[hash_algo_idx]->arg);
#ifndef CRYPTO_OPENSSL
	if (hash_algo == KEYCHAIN_ALGO_NULL) {
		vty_out(vty,
			"Hash algorithm not supported, compile with --with-crypto=openssl\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
#endif /* CRYPTO_OPENSSL */

	SET_FLAG(oi->at_data.flags, OSPF6_AUTH_TRAILER_MANUAL_KEY);
	oi->at_data.hash_algo = hash_algo;
	oi->at_data.key_id = (uint16_t)strtol(argv[key_id_idx]->arg, NULL, 10);
	if (oi->at_data.auth_key)
		XFREE(MTYPE_OSPF6_AUTH_MANUAL_KEY, oi->at_data.auth_key);
	oi->at_data.auth_key = XSTRDUP(MTYPE_OSPF6_AUTH_MANUAL_KEY,
				       argv[password_idx]->arg);

	return CMD_SUCCESS;
}

DEFUN(no_ipv6_ospf6_intf_auth_trailer_key,
      no_ipv6_ospf6_intf_auth_trailer_key_cmd,
      "no ipv6 ospf6 authentication key-id [(1-65535) hash-algo "
      "<md5|hmac-sha-1|hmac-sha-256|hmac-sha-384|hmac-sha-512> "
      "key WORD]",
      NO_STR
      IP6_STR
      OSPF6_STR
      "Authentication\n"
      "Key ID\n"
      "Key ID value\n"
      "Cryptographic-algorithm\n"
      "Use MD5 algorithm\n"
      "Use HMAC-SHA-1 algorithm\n"
      "Use HMAC-SHA-256 algorithm\n"
      "Use HMAC-SHA-384 algorithm\n"
      "Use HMAC-SHA-512 algorithm\n"
      "Password\n"
      "Password string (key)\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
#ifndef CRYPTO_OPENSSL
	int hash_algo_idx = 7;
	uint8_t hash_algo = KEYCHAIN_ALGO_NULL;
#endif /* CRYPTO_OPENSSL */

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);

	assert(oi);
	if (!CHECK_FLAG(oi->at_data.flags, OSPF6_AUTH_TRAILER_MANUAL_KEY))
		return CMD_SUCCESS;

#ifndef CRYPTO_OPENSSL
	hash_algo = keychain_get_algo_id_by_name(argv[hash_algo_idx]->arg);
	if (hash_algo == KEYCHAIN_ALGO_NULL) {
		vty_out(vty,
			"Hash algorithm not supported, compile with --with-crypto=openssl\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
#endif /* CRYPTO_OPENSSL */

	if (oi->at_data.auth_key) {
		oi->at_data.flags = 0;
		XFREE(MTYPE_OSPF6_AUTH_MANUAL_KEY, oi->at_data.auth_key);
		oi->at_data.auth_key = NULL;
	}

	return CMD_SUCCESS;
}

void ospf6_interface_auth_trailer_cmd_init(void)
{
	/*Install OSPF6 auth trailer commands at interface level */
	install_element(INTERFACE_NODE,
			&ipv6_ospf6_intf_auth_trailer_keychain_cmd);
	install_element(INTERFACE_NODE,
			&no_ipv6_ospf6_intf_auth_trailer_keychain_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_intf_auth_trailer_key_cmd);
	install_element(INTERFACE_NODE,
			&no_ipv6_ospf6_intf_auth_trailer_key_cmd);
}
