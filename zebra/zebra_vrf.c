/*
 * Copyright (C) 2016 CumulusNetworks
 *                    Donald Sharp
 *
 * This file is part of Quagga
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

#include "log.h"
#include "linklist.h"
#include "command.h"
#include "memory.h"
#include "srcdest_table.h"

#include "vty.h"
#include "zebra/debug.h"
#include "zebra/zserv.h"
#include "zebra/rib.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_rnh.h"
#include "zebra/router-id.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_static.h"
#include "zebra/interface.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_vxlan.h"

extern struct zebra_t zebrad;

/* VRF information update. */
static void zebra_vrf_add_update(struct zebra_vrf *zvrf)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_VRF_ADD %s", zvrf_name(zvrf));

	for (ALL_LIST_ELEMENTS(zebrad.client_list, node, nnode, client))
		zsend_vrf_add(client, zvrf);
}

static void zebra_vrf_delete_update(struct zebra_vrf *zvrf)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_VRF_DELETE %s", zvrf_name(zvrf));

	for (ALL_LIST_ELEMENTS(zebrad.client_list, node, nnode, client))
		zsend_vrf_delete(client, zvrf);
}

void zebra_vrf_update_all(struct zserv *client)
{
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		if (vrf->vrf_id)
			zsend_vrf_add(client, vrf_info_lookup(vrf->vrf_id));
	}
}

/* Callback upon creating a new VRF. */
static int zebra_vrf_new(struct vrf *vrf)
{
	struct zebra_vrf *zvrf;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZVRF %s with id %u", vrf->name, vrf->vrf_id);

	zvrf = zebra_vrf_alloc();
	zvrf->zns = zebra_ns_lookup(
		NS_DEFAULT); /* Point to the global (single) NS */
	router_id_init(zvrf);
	vrf->info = zvrf;
	zvrf->vrf = vrf;

	return 0;
}

/* Callback upon enabling a VRF. */
static int zebra_vrf_enable(struct vrf *vrf)
{
	struct zebra_vrf *zvrf = vrf->info;
	struct route_table *stable;
	struct route_node *rn;
	struct static_route *si;
	struct interface *ifp;
	afi_t afi;
	safi_t safi;

	assert(zvrf);

	zebra_vrf_add_update(zvrf);

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
			stable = zvrf->stable[afi][safi];
			if (!stable)
				continue;

			for (rn = route_top(stable); rn; rn = route_next(rn))
				for (si = rn->info; si; si = si->next) {
					si->vrf_id = vrf->vrf_id;
					if (si->ifindex) {
						ifp = if_lookup_by_name(
							si->ifname, si->vrf_id);
						if (ifp)
							si->ifindex =
								ifp->ifindex;
						else
							continue;
					}
					static_install_route(afi, safi, &rn->p,
							     NULL, si);
				}
		}

	return 0;
}

/* Callback upon disabling a VRF. */
static int zebra_vrf_disable(struct vrf *vrf)
{
	struct zebra_vrf *zvrf = vrf->info;
	struct route_table *stable;
	struct route_node *rn;
	struct static_route *si;
	afi_t afi;
	safi_t safi;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("VRF %s id %u is now disabled.", zvrf_name(zvrf),
			   zvrf_id(zvrf));

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
			stable = zvrf->stable[afi][safi];
			if (!stable)
				continue;

			for (rn = route_top(stable); rn; rn = route_next(rn))
				for (si = rn->info; si; si = si->next)
					static_uninstall_route(
						afi, safi, &rn->p, NULL, si);
		}

	return 0;
}

static int zebra_vrf_delete(struct vrf *vrf)
{
	struct zebra_vrf *zvrf = vrf->info;
	struct route_table *table;
	u_int32_t table_id;
	afi_t afi;
	safi_t safi;
	unsigned i;

	assert(zvrf);

	zebra_vrf_delete_update(zvrf);

	/* uninstall everything */
	if (!CHECK_FLAG(zvrf->flags, ZEBRA_VRF_RETAIN)) {
		struct interface *ifp;

		for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
			for (safi = SAFI_UNICAST; safi <= SAFI_MULTICAST;
			     safi++)
				rib_close_table(zvrf->table[afi][safi]);

			if (vrf->vrf_id == VRF_DEFAULT)
				for (table_id = 0;
				     table_id < ZEBRA_KERNEL_TABLE_MAX;
				     table_id++)
					if (zvrf->other_table[afi][table_id])
						rib_close_table(
							zvrf->other_table
								[afi]
								[table_id]);
		}

		/* Cleanup Vxlan table and update kernel */
		zebra_vxlan_close_tables(zvrf);

		zebra_mpls_close_tables(zvrf);
		zebra_pw_exit(zvrf);

		RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name)
			if_nbr_ipv6ll_to_ipv4ll_neigh_del_all(ifp);
	}

	/* clean-up work queues */
	for (i = 0; i < MQ_SIZE; i++) {
		struct listnode *lnode, *nnode;
		struct route_node *rnode;
		rib_dest_t *dest;

		for (ALL_LIST_ELEMENTS(zebrad.mq->subq[i], lnode, nnode,
				       rnode)) {
			dest = rib_dest_from_rnode(rnode);
			if (dest && rib_dest_vrf(dest) == zvrf) {
				route_unlock_node(rnode);
				list_delete_node(zebrad.mq->subq[i], lnode);
				zebrad.mq->size--;
			}
		}
	}

	/* release allocated memory */
	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		void *table_info;

		for (safi = SAFI_UNICAST; safi <= SAFI_MULTICAST; safi++) {
			table = zvrf->table[afi][safi];
			table_info = table->info;
			route_table_finish(table);
			XFREE(MTYPE_RIB_TABLE_INFO, table_info);

			table = zvrf->stable[afi][safi];
			route_table_finish(table);
		}

		for (table_id = 0; table_id < ZEBRA_KERNEL_TABLE_MAX;
		     table_id++)
			if (zvrf->other_table[afi][table_id]) {
				table = zvrf->other_table[afi][table_id];
				table_info = table->info;
				route_table_finish(table);
				XFREE(MTYPE_RIB_TABLE_INFO, table_info);
			}

		route_table_finish(zvrf->rnh_table[afi]);
		route_table_finish(zvrf->import_check_table[afi]);
	}
	list_delete_all_node(zvrf->rid_all_sorted_list);
	list_delete_all_node(zvrf->rid_lo_sorted_list);
	XFREE(MTYPE_ZEBRA_VRF, zvrf);
	vrf->info = NULL;

	return 0;
}

/* Lookup the routing table in a VRF based on both VRF-Id and table-id.
 * NOTE: Table-id is relevant only in the Default VRF.
 */
struct route_table *zebra_vrf_table_with_table_id(afi_t afi, safi_t safi,
						  vrf_id_t vrf_id,
						  u_int32_t table_id)
{
	struct route_table *table = NULL;

	if (afi >= AFI_MAX || safi >= SAFI_MAX)
		return NULL;

	if (vrf_id == VRF_DEFAULT) {
		if (table_id == RT_TABLE_MAIN
		    || table_id == zebrad.rtm_table_default)
			table = zebra_vrf_table(afi, safi, vrf_id);
		else
			table = zebra_vrf_other_route_table(afi, table_id,
							    vrf_id);
	} else
		table = zebra_vrf_table(afi, safi, vrf_id);

	return table;
}

static void zebra_rtable_node_cleanup(struct route_table *table,
				      struct route_node *node)
{
	struct route_entry *re, *next;

	RNODE_FOREACH_RE_SAFE (node, re, next) {
		rib_unlink(node, re);
	}

	if (node->info)
		XFREE(MTYPE_RIB_DEST, node->info);
}

static void zebra_stable_node_cleanup(struct route_table *table,
				      struct route_node *node)
{
	struct static_route *si, *next;

	if (node->info)
		for (si = node->info; si; si = next) {
			next = si->next;
			XFREE(MTYPE_STATIC_ROUTE, si);
		}
}

static void zebra_rnhtable_node_cleanup(struct route_table *table,
					struct route_node *node)
{
	if (node->info)
		zebra_free_rnh(node->info);
}

/*
 * Create a routing table for the specific AFI/SAFI in the given VRF.
 */
static void zebra_vrf_table_create(struct zebra_vrf *zvrf, afi_t afi,
				   safi_t safi)
{
	rib_table_info_t *info;
	struct route_table *table;

	assert(!zvrf->table[afi][safi]);

	if (afi == AFI_IP6)
		table = srcdest_table_init();
	else
		table = route_table_init();
	table->cleanup = zebra_rtable_node_cleanup;
	zvrf->table[afi][safi] = table;

	info = XCALLOC(MTYPE_RIB_TABLE_INFO, sizeof(*info));
	info->zvrf = zvrf;
	info->afi = afi;
	info->safi = safi;
	table->info = info;
}

/* Allocate new zebra VRF. */
struct zebra_vrf *zebra_vrf_alloc(void)
{
	struct zebra_vrf *zvrf;
	afi_t afi;
	safi_t safi;
	struct route_table *table;

	zvrf = XCALLOC(MTYPE_ZEBRA_VRF, sizeof(struct zebra_vrf));

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (safi = SAFI_UNICAST; safi <= SAFI_MULTICAST; safi++) {
			zebra_vrf_table_create(zvrf, afi, safi);
			if (afi == AFI_IP6)
				table = srcdest_table_init();
			else
				table = route_table_init();
			table->cleanup = zebra_stable_node_cleanup;
			zvrf->stable[afi][safi] = table;
		}

		table = route_table_init();
		table->cleanup = zebra_rnhtable_node_cleanup;
		zvrf->rnh_table[afi] = table;

		table = route_table_init();
		table->cleanup = zebra_rnhtable_node_cleanup;
		zvrf->import_check_table[afi] = table;
	}

	zebra_vxlan_init_tables(zvrf);
	zebra_mpls_init_tables(zvrf);
	zebra_pw_init(zvrf);

	return zvrf;
}

/* Lookup VRF by identifier.  */
struct zebra_vrf *zebra_vrf_lookup_by_id(vrf_id_t vrf_id)
{
	return vrf_info_lookup(vrf_id);
}

/* Lookup VRF by name.  */
struct zebra_vrf *zebra_vrf_lookup_by_name(const char *name)
{
	struct vrf *vrf;

	if (!name)
		name = VRF_DEFAULT_NAME;

	vrf = vrf_lookup_by_name(name);
	if (vrf)
		return ((struct zebra_vrf *)vrf->info);

	return NULL;
}

/* Lookup the routing table in an enabled VRF. */
struct route_table *zebra_vrf_table(afi_t afi, safi_t safi, vrf_id_t vrf_id)
{
	struct zebra_vrf *zvrf = vrf_info_lookup(vrf_id);

	if (!zvrf)
		return NULL;

	if (afi >= AFI_MAX || safi >= SAFI_MAX)
		return NULL;

	return zvrf->table[afi][safi];
}

/* Lookup the static routing table in a VRF. */
struct route_table *zebra_vrf_static_table(afi_t afi, safi_t safi,
					   struct zebra_vrf *zvrf)
{
	if (!zvrf)
		return NULL;

	if (afi >= AFI_MAX || safi >= SAFI_MAX)
		return NULL;

	return zvrf->stable[afi][safi];
}

struct route_table *zebra_vrf_other_route_table(afi_t afi, u_int32_t table_id,
						vrf_id_t vrf_id)
{
	struct zebra_vrf *zvrf;
	rib_table_info_t *info;
	struct route_table *table;

	zvrf = vrf_info_lookup(vrf_id);
	if (!zvrf)
		return NULL;

	if (afi >= AFI_MAX)
		return NULL;

	if (table_id >= ZEBRA_KERNEL_TABLE_MAX)
		return NULL;

	if ((vrf_id == VRF_DEFAULT) && (table_id != RT_TABLE_MAIN)
	    && (table_id != zebrad.rtm_table_default)) {
		if (zvrf->other_table[afi][table_id] == NULL) {
			table = (afi == AFI_IP6) ? srcdest_table_init()
						 : route_table_init();
			info = XCALLOC(MTYPE_RIB_TABLE_INFO, sizeof(*info));
			info->zvrf = zvrf;
			info->afi = afi;
			info->safi = SAFI_UNICAST;
			table->info = info;
			zvrf->other_table[afi][table_id] = table;
		}

		return (zvrf->other_table[afi][table_id]);
	}

	return zvrf->table[afi][SAFI_UNICAST];
}

static int vrf_config_write(struct vty *vty)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		zvrf = vrf->info;

		if (!zvrf)
			continue;

		if (strcmp(zvrf_name(zvrf), VRF_DEFAULT_NAME)) {
			vty_out(vty, "vrf %s\n", zvrf_name(zvrf));
			vty_out(vty, "!\n");
		}
	}
	return 0;
}

/* Zebra VRF initialization. */
void zebra_vrf_init(void)
{
	vrf_init(zebra_vrf_new, zebra_vrf_enable, zebra_vrf_disable,
		 zebra_vrf_delete);

	vrf_cmd_init(vrf_config_write);
}
