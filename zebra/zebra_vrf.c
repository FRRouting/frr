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
#include "vrf.h"
#include "vty.h"

#include "zebra/zebra_router.h"
#include "zebra/rtadv.h"
#include "zebra/debug.h"
#include "zebra/zapi_msg.h"
#include "zebra/rib.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_rnh.h"
#include "zebra/router-id.h"
#include "zebra/zebra_memory.h"
#include "zebra/interface.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_netns_notify.h"
#include "zebra/zebra_routemap.h"

static void zebra_vrf_table_create(struct zebra_vrf *zvrf, afi_t afi,
				   safi_t safi);
static void zebra_rnhtable_node_cleanup(struct route_table *table,
					struct route_node *node);

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_VRF, "ZEBRA VRF")
DEFINE_MTYPE_STATIC(ZEBRA, OTHER_TABLE, "Other Table")

/* VRF information update. */
static void zebra_vrf_add_update(struct zebra_vrf *zvrf)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_VRF_ADD %s", zvrf_name(zvrf));

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client))
		zsend_vrf_add(client, zvrf);
}

static void zebra_vrf_delete_update(struct zebra_vrf *zvrf)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_VRF_DELETE %s", zvrf_name(zvrf));

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client))
		zsend_vrf_delete(client, zvrf);
}

void zebra_vrf_update_all(struct zserv *client)
{
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		if (vrf->vrf_id != VRF_UNKNOWN)
			zsend_vrf_add(client, vrf_info_lookup(vrf->vrf_id));
	}
}

/* Callback upon creating a new VRF. */
static int zebra_vrf_new(struct vrf *vrf)
{
	struct zebra_vrf *zvrf;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("VRF %s created, id %u", vrf->name, vrf->vrf_id);

	zvrf = zebra_vrf_alloc();
	vrf->info = zvrf;
	zvrf->vrf = vrf;

	otable_init(&zvrf->other_tables);

	router_id_init(zvrf);
	return 0;
}

/* Callback upon enabling a VRF. */
static int zebra_vrf_enable(struct vrf *vrf)
{
	struct zebra_vrf *zvrf = vrf->info;
	struct route_table *table;
	afi_t afi;
	safi_t safi;

	assert(zvrf);
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("VRF %s id %u is now active", zvrf_name(zvrf),
			   zvrf_id(zvrf));

	if (vrf_is_backend_netns())
		zvrf->zns = zebra_ns_lookup((ns_id_t)vrf->vrf_id);
	else
		zvrf->zns = zebra_ns_lookup(NS_DEFAULT);
#if defined(HAVE_RTADV)
	rtadv_init(zvrf);
#endif

	/* Inform clients that the VRF is now active. This is an
	 * add for the clients.
	 */

	zebra_vrf_add_update(zvrf);
	/* Allocate tables */
	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (safi = SAFI_UNICAST; safi <= SAFI_MULTICAST; safi++)
			zebra_vrf_table_create(zvrf, afi, safi);

		table = route_table_init();
		table->cleanup = zebra_rnhtable_node_cleanup;
		zvrf->rnh_table[afi] = table;

		table = route_table_init();
		table->cleanup = zebra_rnhtable_node_cleanup;
		zvrf->import_check_table[afi] = table;
	}

	/* Kick off any VxLAN-EVPN processing. */
	zebra_vxlan_vrf_enable(zvrf);

	return 0;
}

/* Callback upon disabling a VRF. */
static int zebra_vrf_disable(struct vrf *vrf)
{
	struct zebra_vrf *zvrf = vrf->info;
	struct interface *ifp;
	afi_t afi;
	safi_t safi;
	unsigned i;

	assert(zvrf);
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("VRF %s id %u is now inactive", zvrf_name(zvrf),
			   zvrf_id(zvrf));

	/* Stop any VxLAN-EVPN processing. */
	zebra_vxlan_vrf_disable(zvrf);

#if defined(HAVE_RTADV)
	rtadv_terminate(zvrf);
#endif

	/* Inform clients that the VRF is now inactive. This is a
	 * delete for the clients.
	 */
	zebra_vrf_delete_update(zvrf);

	/* If asked to retain routes, there's nothing more to do. */
	if (CHECK_FLAG(zvrf->flags, ZEBRA_VRF_RETAIN))
		return 0;

	/* Remove all routes. */
	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		route_table_finish(zvrf->rnh_table[afi]);
		zvrf->rnh_table[afi] = NULL;
		route_table_finish(zvrf->import_check_table[afi]);
		zvrf->import_check_table[afi] = NULL;

		for (safi = SAFI_UNICAST; safi <= SAFI_MULTICAST; safi++)
			rib_close_table(zvrf->table[afi][safi]);
	}

	/* Cleanup Vxlan, MPLS and PW tables. */
	zebra_vxlan_cleanup_tables(zvrf);
	zebra_mpls_cleanup_tables(zvrf);
	zebra_pw_exit(zvrf);

	/* Remove link-local IPv4 addresses created for BGP unnumbered peering.
	 */
	FOR_ALL_INTERFACES (vrf, ifp)
		if_nbr_ipv6ll_to_ipv4ll_neigh_del_all(ifp);

	/* clean-up work queues */
	for (i = 0; i < MQ_SIZE; i++) {
		struct listnode *lnode, *nnode;
		struct route_node *rnode;
		rib_dest_t *dest;

		for (ALL_LIST_ELEMENTS(zrouter.mq->subq[i], lnode, nnode,
				       rnode)) {
			dest = rib_dest_from_rnode(rnode);
			if (dest && rib_dest_vrf(dest) == zvrf) {
				route_unlock_node(rnode);
				list_delete_node(zrouter.mq->subq[i], lnode);
				zrouter.mq->size--;
			}
		}
	}

	/* Cleanup (free) routing tables and NHT tables. */
	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		/*
		 * Set the table pointer to NULL as that
		 * we no-longer need a copy of it, nor do we
		 * own this data, the zebra_router structure
		 * owns these tables.  Once we've cleaned up the
		 * table, see rib_close_table above
		 * we no-longer need this pointer.
		 */
		for (safi = SAFI_UNICAST; safi <= SAFI_MULTICAST; safi++) {
			zebra_router_release_table(zvrf, zvrf->table_id, afi,
						   safi);
			zvrf->table[afi][safi] = NULL;
		}
	}

	return 0;
}

static int zebra_vrf_delete(struct vrf *vrf)
{
	struct zebra_vrf *zvrf = vrf->info;
	struct other_route_table *otable;
	struct route_table *table;
	afi_t afi;
	safi_t safi;
	unsigned i;

	assert(zvrf);
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("VRF %s id %u deleted", zvrf_name(zvrf),
			   zvrf_id(zvrf));

	/* clean-up work queues */
	for (i = 0; i < MQ_SIZE; i++) {
		struct listnode *lnode, *nnode;
		struct route_node *rnode;
		rib_dest_t *dest;

		for (ALL_LIST_ELEMENTS(zrouter.mq->subq[i], lnode, nnode,
				       rnode)) {
			dest = rib_dest_from_rnode(rnode);
			if (dest && rib_dest_vrf(dest) == zvrf) {
				route_unlock_node(rnode);
				list_delete_node(zrouter.mq->subq[i], lnode);
				zrouter.mq->size--;
			}
		}
	}

	/* Free Vxlan and MPLS. */
	zebra_vxlan_close_tables(zvrf);
	zebra_mpls_close_tables(zvrf);

	/* release allocated memory */
	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (safi = SAFI_UNICAST; safi <= SAFI_MULTICAST; safi++) {
			table = zvrf->table[afi][safi];
			if (table) {
				zebra_router_release_table(zvrf, zvrf->table_id,
							   afi, safi);
				zvrf->table[afi][safi] = NULL;
			}
		}

		if (zvrf->rnh_table[afi])
			route_table_finish(zvrf->rnh_table[afi]);
		if (zvrf->import_check_table[afi])
			route_table_finish(zvrf->import_check_table[afi]);
	}

	otable = otable_pop(&zvrf->other_tables);
	while (otable) {
		zebra_router_release_table(zvrf, otable->table_id,
					   otable->afi, otable->safi);
		XFREE(MTYPE_OTHER_TABLE, otable);

		otable = otable_pop(&zvrf->other_tables);
	}

	/* Cleanup EVPN states for vrf */
	zebra_vxlan_vrf_delete(zvrf);

	list_delete_all_node(zvrf->rid_all_sorted_list);
	list_delete_all_node(zvrf->rid_lo_sorted_list);

	otable_fini(&zvrf->other_tables);
	XFREE(MTYPE_ZEBRA_VRF, zvrf);
	vrf->info = NULL;

	return 0;
}

static int zebra_vrf_update(struct vrf *vrf)
{
	struct zebra_vrf *zvrf = vrf->info;

	assert(zvrf);
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("VRF %s id %u, name updated", vrf->name,
			   zvrf_id(zvrf));
	zebra_vrf_add_update(zvrf);
	return 0;
}


/* Return if this VRF has any FRR configuration or not.
 * IMPORTANT: This function needs to be updated when additional configuration
 * is added for a VRF.
 */
int zebra_vrf_has_config(struct zebra_vrf *zvrf)
{
	/* EVPN L3-VNI? */
	if (zvrf->l3vni)
		return 1;

	return 0;
}

/* Lookup the routing table in a VRF based on both VRF-Id and table-id.
 * NOTE: Table-id is relevant on two modes:
 * - case VRF backend is default : on default VRF only
 * - case VRF backend is netns : on all VRFs
 */
struct route_table *zebra_vrf_lookup_table_with_table_id(afi_t afi, safi_t safi,
							 vrf_id_t vrf_id,
							 uint32_t table_id)
{
	struct zebra_vrf *zvrf = vrf_info_lookup(vrf_id);
	struct other_route_table ort, *otable;

	if (!zvrf)
		return NULL;

	if (afi >= AFI_MAX || safi >= SAFI_MAX)
		return NULL;

	if (table_id == zvrf->table_id)
		return zebra_vrf_table(afi, safi, vrf_id);

	ort.afi = afi;
	ort.safi = safi;
	ort.table_id = table_id;
	otable = otable_find(&zvrf->other_tables, &ort);

	if (otable)
		return otable->table;

	return NULL;
}

struct route_table *zebra_vrf_get_table_with_table_id(afi_t afi, safi_t safi,
						      vrf_id_t vrf_id,
						      uint32_t table_id)
{
	struct zebra_vrf *zvrf = vrf_info_lookup(vrf_id);
	struct other_route_table *otable;
	struct route_table *table;

	table = zebra_vrf_lookup_table_with_table_id(afi, safi, vrf_id,
						     table_id);

	if (table)
		goto done;

	/* Create it as an `other` table */
	table = zebra_router_get_table(zvrf, table_id, afi, safi);

	otable = XCALLOC(MTYPE_OTHER_TABLE, sizeof(*otable));
	otable->afi = afi;
	otable->safi = safi;
	otable->table_id = table_id;
	otable->table = table;
	otable_add(&zvrf->other_tables, otable);

done:
	return table;
}

void zebra_rtable_node_cleanup(struct route_table *table,
			       struct route_node *node)
{
	struct route_entry *re, *next;

	RNODE_FOREACH_RE_SAFE (node, re, next) {
		rib_unlink(node, re);
	}

	if (node->info) {
		rib_dest_t *dest = node->info;

		rnh_list_fini(&dest->nht);
		XFREE(MTYPE_RIB_DEST, node->info);
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
	struct route_node *rn;
	struct prefix p;

	assert(!zvrf->table[afi][safi]);

	zvrf->table[afi][safi] =
		zebra_router_get_table(zvrf, zvrf->table_id, afi, safi);

	memset(&p, 0, sizeof(p));
	p.family = afi2family(afi);

	rn = srcdest_rnode_get(zvrf->table[afi][safi], &p, NULL);
	zebra_rib_create_dest(rn);
}

/* Allocate new zebra VRF. */
struct zebra_vrf *zebra_vrf_alloc(void)
{
	struct zebra_vrf *zvrf;

	zvrf = XCALLOC(MTYPE_ZEBRA_VRF, sizeof(struct zebra_vrf));

	zebra_vxlan_init_tables(zvrf);
	zebra_mpls_init_tables(zvrf);
	zebra_pw_init(zvrf);
	zvrf->table_id = RT_TABLE_MAIN;
	/* by default table ID is default one */
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

static int vrf_config_write(struct vty *vty)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		zvrf = vrf->info;

		if (!zvrf)
			continue;

		if (zvrf_id(zvrf) == VRF_DEFAULT) {
			if (zvrf->l3vni)
				vty_out(vty, "vni %u%s\n", zvrf->l3vni,
					is_l3vni_for_prefix_routes_only(
						zvrf->l3vni)
						? " prefix-routes-only"
						: "");
			if (zvrf->zebra_rnh_ip_default_route)
				vty_out(vty, "ip nht resolve-via-default\n");

			if (zvrf->zebra_rnh_ipv6_default_route)
				vty_out(vty, "ipv6 nht resolve-via-default\n");
		} else {
			vty_frame(vty, "vrf %s\n", zvrf_name(zvrf));
			if (zvrf->l3vni)
				vty_out(vty, " vni %u%s\n", zvrf->l3vni,
					is_l3vni_for_prefix_routes_only(
						zvrf->l3vni)
						? " prefix-routes-only"
						: "");
			zebra_ns_config_write(vty, (struct ns *)vrf->ns_ctxt);
			if (zvrf->zebra_rnh_ip_default_route)
				vty_out(vty, " ip nht resolve-via-default\n");

			if (zvrf->zebra_rnh_ipv6_default_route)
				vty_out(vty, " ipv6 nht resolve-via-default\n");
		}


		zebra_routemap_config_write_protocol(vty, zvrf);

		if (zvrf_id(zvrf) != VRF_DEFAULT)
			vty_endframe(vty, " exit-vrf\n!\n");
		else
			vty_out(vty, "!\n");
	}
	return 0;
}

/* Zebra VRF initialization. */
void zebra_vrf_init(void)
{
	vrf_init(zebra_vrf_new, zebra_vrf_enable, zebra_vrf_disable,
		 zebra_vrf_delete, zebra_vrf_update);

	vrf_cmd_init(vrf_config_write, &zserv_privs);
}
