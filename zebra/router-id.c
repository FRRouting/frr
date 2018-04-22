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
#include "zebra_memory.h"
#include "ioctl.h"
#include "connected.h"
#include "network.h"
#include "log.h"
#include "table.h"
#include "rib.h"
#include "vrf.h"

#include "zebra/zserv.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_vrf.h"
#include "zebra/router-id.h"
#include "zebra/redistribute.h"

/* master zebra server structure */
extern struct zebra_t zebrad;

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
	if (ifc->address->family != AF_INET)
		return 1;

	/* non-redistributable addresses shouldn't be used for RIDs either */
	if (!zebra_check_addr(ifc->address))
		return 1;

	return 0;
}

void router_id_get(struct prefix *p, vrf_id_t vrf_id)
{
	struct listnode *node;
	struct connected *c;
	struct zebra_vrf *zvrf = vrf_info_get(vrf_id);

	p->u.prefix4.s_addr = 0;
	p->family = AF_INET;
	p->prefixlen = 32;

	if (zvrf->rid_user_assigned.u.prefix4.s_addr)
		p->u.prefix4.s_addr = zvrf->rid_user_assigned.u.prefix4.s_addr;
	else if (!list_isempty(zvrf->rid_lo_sorted_list)) {
		node = listtail(zvrf->rid_lo_sorted_list);
		c = listgetdata(node);
		p->u.prefix4.s_addr = c->address->u.prefix4.s_addr;
	} else if (!list_isempty(zvrf->rid_all_sorted_list)) {
		node = listtail(zvrf->rid_all_sorted_list);
		c = listgetdata(node);
		p->u.prefix4.s_addr = c->address->u.prefix4.s_addr;
	}
}

static void router_id_set(struct prefix *p, vrf_id_t vrf_id)
{
	struct prefix p2;
	struct listnode *node;
	struct zserv *client;
	struct zebra_vrf *zvrf;

	if (p->u.prefix4.s_addr == 0) /* unset */
	{
		zvrf = vrf_info_lookup(vrf_id);
		if (!zvrf)
			return;
	} else /* set */
		zvrf = vrf_info_get(vrf_id);

	zvrf->rid_user_assigned.u.prefix4.s_addr = p->u.prefix4.s_addr;

	router_id_get(&p2, vrf_id);

	for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
		zsend_router_id_update(client, &p2, vrf_id);
}

void router_id_add_address(struct connected *ifc)
{
	struct list *l = NULL;
	struct listnode *node;
	struct prefix before;
	struct prefix after;
	struct zserv *client;
	struct zebra_vrf *zvrf = vrf_info_get(ifc->ifp->vrf_id);

	if (router_id_bad_address(ifc))
		return;

	router_id_get(&before, zvrf_id(zvrf));

	if (!strncmp(ifc->ifp->name, "lo", 2)
	    || !strncmp(ifc->ifp->name, "dummy", 5))
		l = zvrf->rid_lo_sorted_list;
	else
		l = zvrf->rid_all_sorted_list;

	if (!router_id_find_node(l, ifc))
		listnode_add_sort(l, ifc);

	router_id_get(&after, zvrf_id(zvrf));

	if (prefix_same(&before, &after))
		return;

	for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
		zsend_router_id_update(client, &after, zvrf_id(zvrf));
}

void router_id_del_address(struct connected *ifc)
{
	struct connected *c;
	struct list *l;
	struct prefix after;
	struct prefix before;
	struct listnode *node;
	struct zserv *client;
	struct zebra_vrf *zvrf = vrf_info_get(ifc->ifp->vrf_id);

	if (router_id_bad_address(ifc))
		return;

	router_id_get(&before, zvrf_id(zvrf));

	if (!strncmp(ifc->ifp->name, "lo", 2)
	    || !strncmp(ifc->ifp->name, "dummy", 5))
		l = zvrf->rid_lo_sorted_list;
	else
		l = zvrf->rid_all_sorted_list;

	if ((c = router_id_find_node(l, ifc)))
		listnode_delete(l, c);

	router_id_get(&after, zvrf_id(zvrf));

	if (prefix_same(&before, &after))
		return;

	for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
		zsend_router_id_update(client, &after, zvrf_id(zvrf));
}

void router_id_write(struct vty *vty)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		if ((zvrf = vrf->info) != NULL)
			if (zvrf->rid_user_assigned.u.prefix4.s_addr) {
				if (zvrf_id(zvrf) == VRF_DEFAULT)
					vty_out(vty, "router-id %s\n",
						inet_ntoa(
							zvrf->rid_user_assigned
								.u.prefix4));
				else
					vty_out(vty, "router-id %s vrf %s\n",
						inet_ntoa(
							zvrf->rid_user_assigned
								.u.prefix4),
						zvrf_name(zvrf));
			}
}

DEFUN (router_id,
       router_id_cmd,
       "router-id A.B.C.D [vrf NAME]",
       "Manually set the router-id\n"
       "IP address to use for router-id\n"
       VRF_CMD_HELP_STR)
{
	int idx_ipv4 = 1;
	int idx_name = 3;

	struct prefix rid;
	vrf_id_t vrf_id = VRF_DEFAULT;

	rid.u.prefix4.s_addr = inet_addr(argv[idx_ipv4]->arg);
	if (!rid.u.prefix4.s_addr)
		return CMD_WARNING_CONFIG_FAILED;

	rid.prefixlen = 32;
	rid.family = AF_INET;

	if (argc > 2)
		VRF_GET_ID(vrf_id, argv[idx_name]->arg);

	router_id_set(&rid, vrf_id);

	return CMD_SUCCESS;
}

DEFUN (no_router_id,
       no_router_id_cmd,
       "no router-id [A.B.C.D [vrf NAME]]",
       NO_STR
       "Remove the manually configured router-id\n"
       "IP address to use for router-id\n"
       VRF_CMD_HELP_STR)
{
	int idx_name = 4;

	struct prefix rid;
	vrf_id_t vrf_id = VRF_DEFAULT;

	rid.u.prefix4.s_addr = 0;
	rid.prefixlen = 0;
	rid.family = AF_INET;

	if (argc > 3)
		VRF_GET_ID(vrf_id, argv[idx_name]->arg);

	router_id_set(&rid, vrf_id);

	return CMD_SUCCESS;
}


static int router_id_cmp(void *a, void *b)
{
	const struct connected *ifa = (const struct connected *)a;
	const struct connected *ifb = (const struct connected *)b;

	return IPV4_ADDR_CMP(&ifa->address->u.prefix4.s_addr,
			     &ifb->address->u.prefix4.s_addr);
}

void router_id_cmd_init(void)
{
	install_element(CONFIG_NODE, &router_id_cmd);
	install_element(CONFIG_NODE, &no_router_id_cmd);
}

void router_id_init(struct zebra_vrf *zvrf)
{
	zvrf->rid_all_sorted_list = &zvrf->_rid_all_sorted_list;
	zvrf->rid_lo_sorted_list = &zvrf->_rid_lo_sorted_list;

	memset(zvrf->rid_all_sorted_list, 0,
	       sizeof(zvrf->_rid_all_sorted_list));
	memset(zvrf->rid_lo_sorted_list, 0, sizeof(zvrf->_rid_lo_sorted_list));
	memset(&zvrf->rid_user_assigned, 0, sizeof(zvrf->rid_user_assigned));

	zvrf->rid_all_sorted_list->cmp = router_id_cmp;
	zvrf->rid_lo_sorted_list->cmp = router_id_cmp;

	zvrf->rid_user_assigned.family = AF_INET;
	zvrf->rid_user_assigned.prefixlen = 32;
}
