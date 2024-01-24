// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Router ID for zebra daemon.
 *
 * Copyright (C) 2004 James R. Leu
 *
 * This file is part of Quagga routing suite.
 */

#include <zebra.h>

#include "if.h"
#include "vty.h"
#include "sockunion.h"
#include "prefix.h"
#include "stream.h"
#include "command.h"
#include "memory.h"
#include "ioctl.h"
#include "connected.h"
#include "network.h"
#include "log.h"
#include "table.h"
#include "rib.h"
#include "vrf.h"

#include "zebra/zebra_router.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_vrf.h"
#include "zebra/router-id.h"
#include "zebra/redistribute.h"

static struct connected *router_id_find_node(struct list *l,
					     struct connected *ifc)
{
	struct listnode *node;
	struct connected *c;

	for (ALL_LIST_ELEMENTS_RO(l, node, c))
		if (prefix_same(ifc->address, c->address))
			return c;

	return NULL;
}

static int router_id_bad_address(struct connected *ifc)
{
	/* non-redistributable addresses shouldn't be used for RIDs either */
	if (!zebra_check_addr(ifc->address))
		return 1;

	return 0;
}

static bool router_id_v6_is_any(struct prefix *p)
{
	return memcmp(&p->u.prefix6, &in6addr_any, sizeof(struct in6_addr))
	       == 0;
}

int router_id_get(afi_t afi, struct prefix *p, struct zebra_vrf *zvrf)
{
	struct listnode *node;
	struct connected *c;
	struct in6_addr *addr = NULL;

	switch (afi) {
	case AFI_IP:
		p->u.prefix4.s_addr = INADDR_ANY;
		p->family = AF_INET;
		p->prefixlen = IPV4_MAX_BITLEN;
		if (zvrf->rid_user_assigned.u.prefix4.s_addr != INADDR_ANY)
			p->u.prefix4.s_addr =
				zvrf->rid_user_assigned.u.prefix4.s_addr;
		else if (!list_isempty(zvrf->rid_lo_sorted_list)) {
			node = listtail(zvrf->rid_lo_sorted_list);
			c = listgetdata(node);
			p->u.prefix4.s_addr = c->address->u.prefix4.s_addr;
		} else if (!list_isempty(zvrf->rid_all_sorted_list)) {
			node = listtail(zvrf->rid_all_sorted_list);
			c = listgetdata(node);
			p->u.prefix4.s_addr = c->address->u.prefix4.s_addr;
		}
		return 0;
	case AFI_IP6:
		p->u.prefix6 = in6addr_any;
		p->family = AF_INET6;
		p->prefixlen = IPV6_MAX_BITLEN;
		if (!router_id_v6_is_any(&zvrf->rid6_user_assigned))
			addr = &zvrf->rid6_user_assigned.u.prefix6;
		else if (!list_isempty(zvrf->rid6_lo_sorted_list)) {
			node = listtail(zvrf->rid6_lo_sorted_list);
			c = listgetdata(node);
			addr = &c->address->u.prefix6;
		} else if (!list_isempty(zvrf->rid6_all_sorted_list)) {
			node = listtail(zvrf->rid6_all_sorted_list);
			c = listgetdata(node);
			addr = &c->address->u.prefix6;
		}
		if (addr)
			memcpy(&p->u.prefix6, addr, sizeof(struct in6_addr));
		return 0;
	case AFI_UNSPEC:
	case AFI_L2VPN:
	case AFI_MAX:
		return -1;
	}

	assert(!"Reached end of function we should never hit");
}

int router_id_set(afi_t afi, struct prefix *p, struct zebra_vrf *zvrf)
{
	struct prefix after, before;
	struct listnode *node;
	struct zserv *client;

	router_id_get(afi, &before, zvrf);

	switch (afi) {
	case AFI_IP:
		zvrf->rid_user_assigned.u.prefix4.s_addr = p->u.prefix4.s_addr;
		break;
	case AFI_IP6:
		zvrf->rid6_user_assigned.u.prefix6 = p->u.prefix6;
		break;
	case AFI_UNSPEC:
	case AFI_L2VPN:
	case AFI_MAX:
		return -1;
	}

	router_id_get(afi, &after, zvrf);

	/*
	 * If we've been told that the router-id is exactly the same
	 * do we need to really do anything here?
	 */
	if (prefix_same(&before, &after))
		return 0;

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client))
		zsend_router_id_update(client, afi, &after, zvrf->vrf->vrf_id);

	return 0;
}

void router_id_add_address(struct connected *ifc)
{
	struct list *l = NULL;
	struct listnode *node;
	struct prefix before;
	struct prefix after;
	struct zserv *client;
	struct zebra_vrf *zvrf = ifc->ifp->vrf->info;
	afi_t afi;
	struct list *rid_lo;
	struct list *rid_all;

	if (router_id_bad_address(ifc))
		return;

	switch (ifc->address->family) {
	case AF_INET:
		afi = AFI_IP;
		rid_lo = zvrf->rid_lo_sorted_list;
		rid_all = zvrf->rid_all_sorted_list;
		break;
	case AF_INET6:
		afi = AFI_IP6;
		rid_lo = zvrf->rid6_lo_sorted_list;
		rid_all = zvrf->rid6_all_sorted_list;
		break;
	default:
		return;
	}

	router_id_get(afi, &before, zvrf);

	l = if_is_loopback(ifc->ifp) ? rid_lo : rid_all;

	if (!router_id_find_node(l, ifc))
		listnode_add_sort(l, ifc);

	router_id_get(afi, &after, zvrf);

	if (prefix_same(&before, &after))
		return;

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client))
		zsend_router_id_update(client, afi, &after, zvrf_id(zvrf));
}

void router_id_del_address(struct connected *ifc)
{
	struct connected *c;
	struct list *l;
	struct prefix after;
	struct prefix before;
	struct listnode *node;
	struct zserv *client;
	struct zebra_vrf *zvrf = ifc->ifp->vrf->info;
	afi_t afi;
	struct list *rid_lo;
	struct list *rid_all;

	if (router_id_bad_address(ifc))
		return;

	switch (ifc->address->family) {
	case AF_INET:
		afi = AFI_IP;
		rid_lo = zvrf->rid_lo_sorted_list;
		rid_all = zvrf->rid_all_sorted_list;
		break;
	case AF_INET6:
		afi = AFI_IP6;
		rid_lo = zvrf->rid6_lo_sorted_list;
		rid_all = zvrf->rid6_all_sorted_list;
		break;
	default:
		return;
	}

	router_id_get(afi, &before, zvrf);

	if (if_is_loopback(ifc->ifp))
		l = rid_lo;
	else
		l = rid_all;

	if ((c = router_id_find_node(l, ifc)))
		listnode_delete(l, c);

	router_id_get(afi, &after, zvrf);

	if (prefix_same(&before, &after))
		return;

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client))
		zsend_router_id_update(client, afi, &after, zvrf_id(zvrf));
}

DEFUN (show_ip_router_id,
       show_ip_router_id_cmd,
       "show [ip|ipv6] router-id [vrf NAME]",
       SHOW_STR
       IP_STR
       IPV6_STR
       "Show the configured router-id\n"
       VRF_CMD_HELP_STR)
{
	int idx = 0;
	vrf_id_t vrf_id = VRF_DEFAULT;
	struct zebra_vrf *zvrf;
	const char *vrf_name = "default";
	char addr_name[INET6_ADDRSTRLEN];
	int is_ipv6 = 0;

	is_ipv6 = argv_find(argv, argc, "ipv6", &idx);

	if (argv_find(argv, argc, "NAME", &idx)) {
		VRF_GET_ID(vrf_id, argv[idx]->arg, false);
		vrf_name = argv[idx]->arg;
	}

	zvrf = zebra_vrf_lookup_by_id(vrf_id);

	if (zvrf != NULL) {
		if (is_ipv6) {
			if (router_id_v6_is_any(&zvrf->rid6_user_assigned))
				return CMD_SUCCESS;
			inet_ntop(AF_INET6, &zvrf->rid6_user_assigned.u.prefix6,
				  addr_name, sizeof(addr_name));
		} else {
			if (zvrf->rid_user_assigned.u.prefix4.s_addr
			    == INADDR_ANY)
				return CMD_SUCCESS;
			inet_ntop(AF_INET, &zvrf->rid_user_assigned.u.prefix4,
				  addr_name, sizeof(addr_name));
		}

		vty_out(vty, "zebra:\n");
		vty_out(vty, "     router-id %s vrf %s\n", addr_name, vrf_name);
	}

	return CMD_SUCCESS;
}

static int router_id_cmp(void *a, void *b)
{
	const struct connected *ifa = (const struct connected *)a;
	const struct connected *ifb = (const struct connected *)b;

	return IPV4_ADDR_CMP(&ifa->address->u.prefix4.s_addr,
			     &ifb->address->u.prefix4.s_addr);
}

static int router_id_v6_cmp(void *a, void *b)
{
	const struct connected *ifa = (const struct connected *)a;
	const struct connected *ifb = (const struct connected *)b;

	return IPV6_ADDR_CMP(&ifa->address->u.prefix6,
			     &ifb->address->u.prefix6);
}

void router_id_cmd_init(void)
{
	install_element(VIEW_NODE, &show_ip_router_id_cmd);
}

void router_id_init(struct zebra_vrf *zvrf)
{
	zvrf->rid_all_sorted_list = &zvrf->_rid_all_sorted_list;
	zvrf->rid_lo_sorted_list = &zvrf->_rid_lo_sorted_list;
	zvrf->rid6_all_sorted_list = &zvrf->_rid6_all_sorted_list;
	zvrf->rid6_lo_sorted_list = &zvrf->_rid6_lo_sorted_list;

	memset(zvrf->rid_all_sorted_list, 0,
	       sizeof(zvrf->_rid_all_sorted_list));
	memset(zvrf->rid_lo_sorted_list, 0, sizeof(zvrf->_rid_lo_sorted_list));
	memset(&zvrf->rid_user_assigned, 0, sizeof(zvrf->rid_user_assigned));
	memset(zvrf->rid6_all_sorted_list, 0,
	       sizeof(zvrf->_rid6_all_sorted_list));
	memset(zvrf->rid6_lo_sorted_list, 0,
	       sizeof(zvrf->_rid6_lo_sorted_list));
	memset(&zvrf->rid6_user_assigned, 0, sizeof(zvrf->rid6_user_assigned));

	zvrf->rid_all_sorted_list->cmp = router_id_cmp;
	zvrf->rid_lo_sorted_list->cmp = router_id_cmp;
	zvrf->rid6_all_sorted_list->cmp = router_id_v6_cmp;
	zvrf->rid6_lo_sorted_list->cmp = router_id_v6_cmp;

	zvrf->rid_user_assigned.family = AF_INET;
	zvrf->rid_user_assigned.prefixlen = IPV4_MAX_BITLEN;
	zvrf->rid6_user_assigned.family = AF_INET6;
	zvrf->rid6_user_assigned.prefixlen = IPV6_MAX_BITLEN;
}
