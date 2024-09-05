// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2016 CumulusNetworks
 *                    Donald Sharp
 *
 * This file is part of Quagga
 */
#include <zebra.h>

/* for basename */
#include <libgen.h>

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
#include "zebra/interface.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_netns_notify.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_vrf_clippy.c"
#include "zebra/table_manager.h"

static void zebra_vrf_table_create(struct zebra_vrf *zvrf, afi_t afi,
				   safi_t safi);
static void zebra_rnhtable_node_cleanup(struct route_table *table,
					struct route_node *node);

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_VRF, "ZEBRA VRF");
DEFINE_MTYPE_STATIC(ZEBRA, OTHER_TABLE, "Other Table");

/* VRF information update. */
static void zebra_vrf_add_update(struct zebra_vrf *zvrf)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_VRF_ADD %s", zvrf_name(zvrf));

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

		zsend_vrf_add(client, zvrf);
	}
}

static void zebra_vrf_delete_update(struct zebra_vrf *zvrf)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_VRF_DELETE %s", zvrf_name(zvrf));

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

		zsend_vrf_delete(client, zvrf);
	}
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

	zvrf = zebra_vrf_alloc(vrf);
	if (!vrf_is_backend_netns())
		zvrf->zns = zebra_ns_lookup(NS_DEFAULT);

	otable_init(&zvrf->other_tables);

	router_id_init(zvrf);

	/* Initiate Table Manager per ZNS */
	table_manager_enable(zvrf);

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

	rtadv_vrf_init(zvrf);

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
		zvrf->rnh_table_multicast[afi] = table;
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

	assert(zvrf);
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("VRF %s id %u is now inactive", zvrf_name(zvrf),
			   zvrf_id(zvrf));

	/* Stop any VxLAN-EVPN processing. */
	zebra_vxlan_vrf_disable(zvrf);

	rtadv_vrf_terminate(zvrf);

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
		route_table_finish(zvrf->rnh_table_multicast[afi]);
		zvrf->rnh_table_multicast[afi] = NULL;

		for (safi = SAFI_UNICAST; safi <= SAFI_MULTICAST; safi++)
			rib_close_table(zvrf->table[afi][safi]);
	}

	/* Cleanup Vxlan, MPLS and PW tables. */
	zebra_vxlan_cleanup_tables(zvrf);
	zebra_mpls_cleanup_tables(zvrf);
	zebra_pw_exit_vrf(zvrf);

	/* Remove link-local IPv4 addresses created for BGP unnumbered peering.
	 */
	FOR_ALL_INTERFACES (vrf, ifp)
		if_nbr_ipv6ll_to_ipv4ll_neigh_del_all(ifp);

	/* clean-up work queues */
	meta_queue_free(zrouter.mq, zvrf);

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

	assert(zvrf);
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("VRF %s id %u deleted", zvrf_name(zvrf),
			   zvrf_id(zvrf));

	table_manager_disable(zvrf);

	/* clean-up work queues */
	meta_queue_free(zrouter.mq, zvrf);

	/* Free Vxlan and MPLS. */
	zebra_vxlan_close_tables(zvrf);
	zebra_mpls_close_tables(zvrf);

	otable = otable_pop(&zvrf->other_tables);
	while (otable) {
		zebra_router_release_table(zvrf, otable->table_id,
					   otable->afi, otable->safi);
		XFREE(MTYPE_OTHER_TABLE, otable);

		otable = otable_pop(&zvrf->other_tables);
	}

	/* Cleanup EVPN states for vrf */
	zebra_vxlan_vrf_delete(zvrf);
	zebra_routemap_vrf_delete(zvrf);

	list_delete_all_node(zvrf->rid_all_sorted_list);
	list_delete_all_node(zvrf->rid_lo_sorted_list);

	list_delete_all_node(zvrf->rid6_all_sorted_list);
	list_delete_all_node(zvrf->rid6_lo_sorted_list);

	otable_fini(&zvrf->other_tables);
	XFREE(MTYPE_ZEBRA_VRF, zvrf);

	if (vrf->ns_ctxt) {
		ns_delete(vrf->ns_ctxt);
		vrf->ns_ctxt = NULL;
	}

	vrf->info = NULL;

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
struct zebra_vrf *zebra_vrf_alloc(struct vrf *vrf)
{
	struct zebra_vrf *zvrf;

	zvrf = XCALLOC(MTYPE_ZEBRA_VRF, sizeof(struct zebra_vrf));

	zvrf->vrf = vrf;
	vrf->info = zvrf;

	zebra_vxlan_init_tables(zvrf);
	zebra_mpls_init_tables(zvrf);
	zebra_pw_init_vrf(zvrf);
	zvrf->table_id = rt_table_main_id;
	/* by default table ID is default one */

	if (DFLT_ZEBRA_IP_NHT_RESOLVE_VIA_DEFAULT) {
		zvrf->zebra_rnh_ip_default_route = true;
		zvrf->zebra_rnh_ipv6_default_route = true;
	}

	return zvrf;
}

/*
 * Pending: create an efficient table_id (in a tree/hash) based lookup)
 */
vrf_id_t zebra_vrf_lookup_by_table(uint32_t table_id, ns_id_t ns_id)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		zvrf = vrf->info;

		if (zvrf == NULL)
			continue;
		/* case vrf with netns : match the netnsid */
		if (vrf_is_backend_netns()) {
			if (ns_id == zvrf_id(zvrf))
				return zvrf_id(zvrf);
		} else {
			/* VRF is VRF_BACKEND_VRF_LITE */
			if (zvrf->table_id != table_id)
				continue;

			return zvrf_id(zvrf);
		}
	}

	return VRF_DEFAULT;
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

/* if ns_id is different and not VRF_UNKNOWN,
 * then update vrf identifier, and enable VRF
 */
static void vrf_update_vrf_id(ns_id_t ns_id, void *opaqueptr)
{
	ns_id_t vrf_id = (vrf_id_t)ns_id;
	vrf_id_t old_vrf_id;
	struct vrf *vrf = (struct vrf *)opaqueptr;

	if (!vrf)
		return;
	old_vrf_id = vrf->vrf_id;
	if (vrf_id == vrf->vrf_id)
		return;
	if (vrf->vrf_id != VRF_UNKNOWN)
		RB_REMOVE(vrf_id_head, &vrfs_by_id, vrf);
	vrf->vrf_id = vrf_id;
	RB_INSERT(vrf_id_head, &vrfs_by_id, vrf);
	if (old_vrf_id == VRF_UNKNOWN)
		vrf_enable(vrf);
}

int zebra_vrf_netns_handler_create(struct vty *vty, struct vrf *vrf,
				   char *pathname, ns_id_t ns_id,
				   ns_id_t internal_ns_id,
				   ns_id_t rel_def_ns_id)
{
	struct ns *ns = NULL;

	if (!vrf)
		return CMD_WARNING_CONFIG_FAILED;
	if (vrf->vrf_id != VRF_UNKNOWN && vrf->ns_ctxt == NULL) {
		if (vty)
			vty_out(vty,
				"VRF %u is already configured with VRF %s\n",
				vrf->vrf_id, vrf->name);
		else
			zlog_info("VRF %u is already configured with VRF %s",
				  vrf->vrf_id, vrf->name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (vrf->ns_ctxt != NULL) {
		ns = (struct ns *)vrf->ns_ctxt;
		if (!strcmp(ns->name, pathname)) {
			if (vty)
				vty_out(vty,
					"VRF %u already configured with NETNS %s\n",
					vrf->vrf_id, ns->name);
			else
				zlog_info(
					"VRF %u already configured with NETNS %s",
					vrf->vrf_id, ns->name);
			return CMD_WARNING;
		}
	}
	ns = ns_lookup_name(pathname);
	if (ns && ns->vrf_ctxt) {
		struct vrf *vrf2 = (struct vrf *)ns->vrf_ctxt;

		if (vrf2 == vrf)
			return CMD_SUCCESS;
		if (vty)
			vty_out(vty,
				"NS %s is already configured with VRF %u(%s)\n",
				ns->name, vrf2->vrf_id, vrf2->name);
		else
			zlog_info("NS %s is already configured with VRF %u(%s)",
				  ns->name, vrf2->vrf_id, vrf2->name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	ns = ns_get_created(ns, pathname, ns_id);
	ns->internal_ns_id = internal_ns_id;
	ns->relative_default_ns = rel_def_ns_id;
	ns->vrf_ctxt = (void *)vrf;
	vrf->ns_ctxt = (void *)ns;
	/* update VRF netns NAME */
	strlcpy(vrf->data.l.netns_name, basename(pathname), NS_NAMSIZ);

	if (!ns_enable(ns, vrf_update_vrf_id)) {
		if (vty)
			vty_out(vty, "Can not associate NS %u with NETNS %s\n",
				ns->ns_id, ns->name);
		else
			zlog_info("Can not associate NS %u with NETNS %s",
				  ns->ns_id, ns->name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

/* Zebra VRF initialization. */
void zebra_vrf_init(void)
{
	vrf_init(zebra_vrf_new, zebra_vrf_enable, zebra_vrf_disable,
		 zebra_vrf_delete);

	hook_register(zserv_client_close, release_daemon_table_chunks);
}
