/*
 * Router ID for zebra daemon.
 *
 * Copyright (C) 2004 James R. Leu
 *
 * This file is part of Quagga routing suite.
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
	default:
		return -1;
	}
}

static int router_id_set(afi_t afi, struct prefix *p, struct zebra_vrf *zvrf)
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
	default:
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

void router_id_write(struct vty *vty, struct zebra_vrf *zvrf)
{
	char space[2];

	memset(space, 0, sizeof(space));

	if (zvrf_id(zvrf) != VRF_DEFAULT)
		snprintf(space, sizeof(space), "%s", " ");

	if (zvrf->rid_user_assigned.u.prefix4.s_addr != INADDR_ANY) {
		vty_out(vty, "%sip router-id %pI4\n", space,
			&zvrf->rid_user_assigned.u.prefix4);
	}
	if (!router_id_v6_is_any(&zvrf->rid6_user_assigned)) {
		vty_out(vty, "%sipv6 router-id %pI6\n", space,
			&zvrf->rid_user_assigned.u.prefix6);
	}
}

DEFUN (ip_router_id,
       ip_router_id_cmd,
       "ip router-id A.B.C.D vrf NAME",
       IP_STR
       "Manually set the router-id\n"
       "IP address to use for router-id\n"
       VRF_CMD_HELP_STR)
{
	int idx = 0;
	struct prefix rid;
	vrf_id_t vrf_id;
	struct zebra_vrf *zvrf;

	argv_find(argv, argc, "A.B.C.D", &idx);

	if (!inet_pton(AF_INET, argv[idx]->arg, &rid.u.prefix4))
		return CMD_WARNING_CONFIG_FAILED;

	rid.prefixlen = IPV4_MAX_BITLEN;
	rid.family = AF_INET;

	argv_find(argv, argc, "NAME", &idx);
	VRF_GET_ID(vrf_id, argv[idx]->arg, false);

	zvrf = vrf_info_lookup(vrf_id);
	router_id_set(AFI_IP, &rid, zvrf);

	return CMD_SUCCESS;
}

ALIAS (ip_router_id,
       router_id_cmd,
       "router-id A.B.C.D vrf NAME",
       "Manually set the router-id\n"
       "IP address to use for router-id\n"
       VRF_CMD_HELP_STR);

DEFUN (ipv6_router_id,
       ipv6_router_id_cmd,
       "ipv6 router-id X:X::X:X vrf NAME",
       IPV6_STR
       "Manually set the router-id\n"
       "IPv6 address to use for router-id\n"
       VRF_CMD_HELP_STR)
{
	int idx = 0;
	struct prefix rid;
	vrf_id_t vrf_id;
	struct zebra_vrf *zvrf;

	argv_find(argv, argc, "X:X::X:X", &idx);

	if (!inet_pton(AF_INET6, argv[idx]->arg, &rid.u.prefix6))
		return CMD_WARNING_CONFIG_FAILED;

	rid.prefixlen = IPV6_MAX_BITLEN;
	rid.family = AF_INET6;

	argv_find(argv, argc, "NAME", &idx);
	VRF_GET_ID(vrf_id, argv[idx]->arg, false);

	zvrf = vrf_info_lookup(vrf_id);
	router_id_set(AFI_IP6, &rid, zvrf);

	return CMD_SUCCESS;
}


DEFUN (ip_router_id_in_vrf,
       ip_router_id_in_vrf_cmd,
       "ip router-id A.B.C.D",
       IP_STR
       "Manually set the router-id\n"
       "IP address to use for router-id\n")
{
	ZEBRA_DECLVAR_CONTEXT_VRF(vrf, zvrf);
	int idx = 0;
	struct prefix rid;

	argv_find(argv, argc, "A.B.C.D", &idx);

	if (!inet_pton(AF_INET, argv[idx]->arg, &rid.u.prefix4))
		return CMD_WARNING_CONFIG_FAILED;

	rid.prefixlen = IPV4_MAX_BITLEN;
	rid.family = AF_INET;

	router_id_set(AFI_IP, &rid, zvrf);

	return CMD_SUCCESS;
}

ALIAS (ip_router_id_in_vrf,
       router_id_in_vrf_cmd,
       "router-id A.B.C.D",
       "Manually set the router-id\n"
       "IP address to use for router-id\n");

DEFUN (ipv6_router_id_in_vrf,
       ipv6_router_id_in_vrf_cmd,
       "ipv6 router-id X:X::X:X",
       IP6_STR
       "Manually set the IPv6 router-id\n"
       "IPV6 address to use for router-id\n")
{
	ZEBRA_DECLVAR_CONTEXT_VRF(vrf, zvrf);
	int idx = 0;
	struct prefix rid;

	argv_find(argv, argc, "X:X::X:X", &idx);

	if (!inet_pton(AF_INET6, argv[idx]->arg, &rid.u.prefix6))
		return CMD_WARNING_CONFIG_FAILED;

	rid.prefixlen = IPV6_MAX_BITLEN;
	rid.family = AF_INET6;

	router_id_set(AFI_IP6, &rid, zvrf);

	return CMD_SUCCESS;
}

DEFUN (no_ip_router_id,
       no_ip_router_id_cmd,
       "no ip router-id [A.B.C.D vrf NAME]",
       NO_STR
       IP_STR
       "Remove the manually configured router-id\n"
       "IP address to use for router-id\n"
       VRF_CMD_HELP_STR)
{
	int idx = 0;
	struct prefix rid;
	vrf_id_t vrf_id = VRF_DEFAULT;
	struct zebra_vrf *zvrf;

	rid.u.prefix4.s_addr = 0;
	rid.prefixlen = 0;
	rid.family = AF_INET;

	if (argv_find(argv, argc, "NAME", &idx))
		VRF_GET_ID(vrf_id, argv[idx]->arg, false);

	zvrf = vrf_info_lookup(vrf_id);
	router_id_set(AFI_IP, &rid, zvrf);

	return CMD_SUCCESS;
}

ALIAS (no_ip_router_id,
       no_router_id_cmd,
       "no router-id [A.B.C.D vrf NAME]",
       NO_STR
       "Remove the manually configured router-id\n"
       "IP address to use for router-id\n"
       VRF_CMD_HELP_STR);

DEFUN (no_ipv6_router_id,
       no_ipv6_router_id_cmd,
       "no ipv6 router-id [X:X::X:X vrf NAME]",
       NO_STR
       IPV6_STR
       "Remove the manually configured IPv6 router-id\n"
       "IPv6 address to use for router-id\n"
       VRF_CMD_HELP_STR)
{
	int idx = 0;
	struct prefix rid;
	vrf_id_t vrf_id = VRF_DEFAULT;
	struct zebra_vrf *zvrf;

	memset(&rid, 0, sizeof(rid));
	rid.family = AF_INET;

	if (argv_find(argv, argc, "NAME", &idx))
		VRF_GET_ID(vrf_id, argv[idx]->arg, false);

	zvrf = vrf_info_lookup(vrf_id);
	router_id_set(AFI_IP6, &rid, zvrf);

	return CMD_SUCCESS;
}

DEFUN (no_ip_router_id_in_vrf,
       no_ip_router_id_in_vrf_cmd,
       "no ip router-id [A.B.C.D]",
       NO_STR
       IP_STR
       "Remove the manually configured router-id\n"
       "IP address to use for router-id\n")
{
	ZEBRA_DECLVAR_CONTEXT_VRF(vrf, zvrf);

	struct prefix rid;

	rid.u.prefix4.s_addr = 0;
	rid.prefixlen = 0;
	rid.family = AF_INET;

	router_id_set(AFI_IP, &rid, zvrf);

	return CMD_SUCCESS;
}

ALIAS (no_ip_router_id_in_vrf,
       no_router_id_in_vrf_cmd,
       "no router-id [A.B.C.D]",
       NO_STR
       "Remove the manually configured router-id\n"
       "IP address to use for router-id\n");

DEFUN (no_ipv6_router_id_in_vrf,
       no_ipv6_router_id_in_vrf_cmd,
       "no ipv6 router-id [X:X::X:X]",
       NO_STR
       IP6_STR
       "Remove the manually configured IPv6 router-id\n"
       "IPv6 address to use for router-id\n")
{
	ZEBRA_DECLVAR_CONTEXT_VRF(vrf, zvrf);

	struct prefix rid;

	memset(&rid, 0, sizeof(rid));
	rid.family = AF_INET;

	router_id_set(AFI_IP6, &rid, zvrf);

	return CMD_SUCCESS;
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

	zvrf = vrf_info_lookup(vrf_id);

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
	install_element(CONFIG_NODE, &ip_router_id_cmd);
	install_element(CONFIG_NODE, &router_id_cmd);
	install_element(CONFIG_NODE, &ipv6_router_id_cmd);
	install_element(CONFIG_NODE, &no_ip_router_id_cmd);
	install_element(CONFIG_NODE, &no_router_id_cmd);
	install_element(CONFIG_NODE, &ip_router_id_in_vrf_cmd);
	install_element(VRF_NODE, &ip_router_id_in_vrf_cmd);
	install_element(CONFIG_NODE, &router_id_in_vrf_cmd);
	install_element(VRF_NODE, &router_id_in_vrf_cmd);
	install_element(CONFIG_NODE, &ipv6_router_id_in_vrf_cmd);
	install_element(VRF_NODE, &ipv6_router_id_in_vrf_cmd);
	install_element(CONFIG_NODE, &no_ipv6_router_id_cmd);
	install_element(CONFIG_NODE, &no_ip_router_id_in_vrf_cmd);
	install_element(VRF_NODE, &no_ip_router_id_in_vrf_cmd);
	install_element(CONFIG_NODE, &no_router_id_in_vrf_cmd);
	install_element(VRF_NODE, &no_router_id_in_vrf_cmd);
	install_element(CONFIG_NODE, &no_ipv6_router_id_in_vrf_cmd);
	install_element(VRF_NODE, &no_ipv6_router_id_in_vrf_cmd);
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
