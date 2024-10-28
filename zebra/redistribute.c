// SPDX-License-Identifier: GPL-2.0-or-later
/* Redistribution Handler
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "vector.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "zclient.h"
#include "linklist.h"
#include "log.h"
#include "vrf.h"
#include "srcdest_table.h"
#include "frrdistance.h"

#include "zebra/rib.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_routemap.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_neigh.h"

#define ZEBRA_PTM_SUPPORT

/* array holding redistribute info about table redistribution */
/* bit AFI is set if that AFI is redistributing routes from this table */
static int zebra_import_table_used[AFI_MAX][SAFI_MAX][ZEBRA_KERNEL_TABLE_MAX];
static uint32_t zebra_import_table_distance[AFI_MAX][SAFI_MAX][ZEBRA_KERNEL_TABLE_MAX];

int is_zebra_import_table_enabled(afi_t afi, safi_t safi, vrf_id_t vrf_id, uint32_t table_id)
{
	/*
	 * Make sure that what we are called with actualy makes sense
	 */
	if (afi == AFI_MAX)
		return 0;

	if (safi == SAFI_MAX)
		return 0;

	if (is_zebra_valid_kernel_table(table_id) &&
	    table_id < ZEBRA_KERNEL_TABLE_MAX)
		return zebra_import_table_used[afi][safi][table_id];
	return 0;
}

static void zebra_redistribute_default(struct zserv *client, vrf_id_t vrf_id)
{
	int afi;
	struct prefix p;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *newre;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {

		if (!vrf_bitmap_check(&client->redist_default[afi], vrf_id))
			continue;

		/* Lookup table.  */
		table = zebra_vrf_table(afi, SAFI_UNICAST, vrf_id);
		if (!table)
			continue;

		/* Lookup default route. */
		memset(&p, 0, sizeof(p));
		p.family = afi2family(afi);
		rn = route_node_lookup(table, &p);
		if (!rn)
			continue;

		RNODE_FOREACH_RE (rn, newre) {
			if (CHECK_FLAG(newre->flags, ZEBRA_FLAG_SELECTED))
				zsend_redistribute_route(ZEBRA_REDISTRIBUTE_ROUTE_ADD,
							 client, rn, newre, false);
		}

		route_unlock_node(rn);
	}
}

/* Redistribute routes. */
static void zebra_redistribute(struct zserv *client, int type,
			       unsigned short instance, struct zebra_vrf *zvrf,
			       int afi)
{
	struct route_entry *newre;
	struct route_table *table;
	struct route_node *rn;
	bool is_table_direct = false;
	vrf_id_t vrf_id = zvrf_id(zvrf);

	if (type == ZEBRA_ROUTE_TABLE_DIRECT) {
		if (vrf_id == VRF_DEFAULT) {
			table = zebra_router_find_table(zvrf, instance, afi,
							SAFI_UNICAST);
			type = ZEBRA_ROUTE_ALL;
			is_table_direct = true;
		} else
			return;
	} else
		table = zebra_vrf_table(afi, SAFI_UNICAST, vrf_id);

	if (!table)
		return;

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
		RNODE_FOREACH_RE (rn, newre) {
			if (IS_ZEBRA_DEBUG_RIB)
				zlog_debug(
					"%s: client %s %pRN(%u:%u) checking: selected=%d, type=%s, instance=%u, distance=%d, metric=%d zebra_check_addr=%d",
					__func__,
					zebra_route_string(client->proto), rn,
					vrf_id, newre->instance,
					!!CHECK_FLAG(newre->flags,
						     ZEBRA_FLAG_SELECTED),
					zebra_route_string(newre->type),
					newre->instance,
					newre->distance,
					newre->metric,
					zebra_check_addr(&rn->p));

			if (!CHECK_FLAG(newre->flags, ZEBRA_FLAG_SELECTED))
				continue;
			if ((type != ZEBRA_ROUTE_ALL
			     && (newre->type != type
				 || newre->instance != instance)))
				continue;
			if (!zebra_check_addr(&rn->p))
				continue;

			zsend_redistribute_route(ZEBRA_REDISTRIBUTE_ROUTE_ADD,
						 client, rn, newre, is_table_direct);
		}
}

/*
 * Function to return a valid table id value if table-direct is used
 * return 0 otherwise
 * This function can be called only if zebra_redistribute_check returns TRUE
 */
static bool zebra_redistribute_is_table_direct(const struct route_entry *re)
{
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_lookup_by_id(re->vrf_id);
	if (re->vrf_id == VRF_DEFAULT && zvrf->table_id != re->table)
		return true;
	return false;
}

/*
 * Function to check if prefix is candidate for
 * redistribute.
 */
static bool zebra_redistribute_check(const struct route_node *rn,
				     const struct route_entry *re,
				     struct zserv *client)
{
	struct zebra_vrf *zvrf;
	afi_t afi;

	/* Process only if there is valid re */
	if (!re)
		return false;

	afi = family2afi(rn->p.family);
	zvrf = zebra_vrf_lookup_by_id(re->vrf_id);
	if (re->vrf_id == VRF_DEFAULT && zvrf->table_id != re->table) {
		if (re->table &&
		    redist_check_instance(&client->mi_redist
						   [afi][ZEBRA_ROUTE_TABLE_DIRECT],
					  re->table)) {
			/* table-direct redistribution only for route entries which
			 * are on the default vrf, and that have table id different
			 * from the default table.
			 */
			return true;
		}
		return false;
	}

	/* If default route and redistributed */
	if (is_default_prefix(&rn->p) &&
	    vrf_bitmap_check(&client->redist_default[afi], re->vrf_id))
		return true;

	/* If redistribute in enabled for zebra route all */
	if (vrf_bitmap_check(&client->redist[afi][ZEBRA_ROUTE_ALL], re->vrf_id))
		return true;

	/*
	 * If multi-instance then check for route
	 * redistribution for given instance.
	 */
	if (re->instance) {
		if (redist_check_instance(&client->mi_redist[afi][re->type],
					  re->instance))
			return true;
		else
			return false;
	}

	/* If redistribution is enabled for give route type. */
	if (vrf_bitmap_check(&client->redist[afi][re->type], re->vrf_id))
		return true;

	return false;
}

/* Either advertise a route for redistribution to registered clients or */
/* withdraw redistribution if add cannot be done for client */
void redistribute_update(const struct route_node *rn,
			 const struct route_entry *re,
			 const struct route_entry *prev_re)
{
	struct listnode *node, *nnode;
	struct zserv *client;
	bool is_table_direct;

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug(
			"(%u:%u):%pRN(%u): Redist update re %p (%s), old %p (%s)",
			re->vrf_id, re->table, rn, re->instance, re,
			zebra_route_string(re->type), prev_re,
			prev_re ? zebra_route_string(prev_re->type) : "None");

	if (!zebra_check_addr(&rn->p)) {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("Redist update filter prefix %pRN", rn);
		return;
	}


	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		if (zebra_redistribute_check(rn, re, client)) {
			if (IS_ZEBRA_DEBUG_RIB) {
				zlog_debug(
					"%s: client %s %pRN(%u:%u), type=%d, distance=%d, metric=%d",
					__func__,
					zebra_route_string(client->proto), rn,
					re->vrf_id, re->table, re->type,
					re->distance, re->metric);
			}
			is_table_direct = zebra_redistribute_is_table_direct(re);
			zsend_redistribute_route(ZEBRA_REDISTRIBUTE_ROUTE_ADD,
						 client, rn, re,
						 is_table_direct);
		} else if (zebra_redistribute_check(rn, prev_re, client)) {
			is_table_direct = zebra_redistribute_is_table_direct(prev_re);
			zsend_redistribute_route(ZEBRA_REDISTRIBUTE_ROUTE_DEL,
						 client, rn, prev_re,
						 is_table_direct);
		}
	}
}

/*
 * During a route delete, where 'new_re' is NULL, redist a delete to all
 * clients registered for the type of 'old_re'.
 * During a route update, redist a delete to any clients who will not see
 * an update when the new route is installed. There are cases when a client
 * may have seen a redist for 'old_re', but will not see
 * the redist for 'new_re'.
 */
void redistribute_delete(const struct route_node *rn,
			 const struct route_entry *old_re,
			 const struct route_entry *new_re)
{
	struct listnode *node, *nnode;
	struct zserv *client;
	vrf_id_t vrfid;
	bool is_table_direct;

	if (old_re)
		vrfid = old_re->vrf_id;
	else if (new_re)
		vrfid = new_re->vrf_id;
	else
		return;

	if (IS_ZEBRA_DEBUG_RIB) {
		uint8_t old_inst, new_inst;
		uint32_t table = 0;
		struct vrf *vrf = vrf_lookup_by_id(vrfid);

		old_inst = new_inst = 0;

		if (old_re) {
			old_inst = old_re->instance;
			table = old_re->table;
		}
		if (new_re) {
			new_inst = new_re->instance;
			table = new_re->table;
		}

		zlog_debug("(%s:%u):%pRN: Redist del: re %p (%u:%s), new re %p (%u:%s)",
			   VRF_LOGNAME(vrf), table, rn, old_re, old_inst,
			   old_re ? zebra_route_string(old_re->type) : "None",
			   new_re, new_inst,
			   new_re ? zebra_route_string(new_re->type) : "None");
	}

	/* Skip invalid (e.g. linklocal) prefix */
	if (!zebra_check_addr(&rn->p)) {
		if (IS_ZEBRA_DEBUG_RIB) {
			zlog_debug(
				"%u:%pRN: Redist del old: skipping invalid prefix",
				vrfid, rn);
		}
		return;
	}

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;
		/*
		 * Skip this client if it will receive an update for the
		 * 'new' re
		 */
		if (zebra_redistribute_check(rn, new_re, client))
			continue;

		/* Send a delete for the 'old' re to any subscribed client. */
		if (zebra_redistribute_check(rn, old_re, client)) {
			/*
			 * SA is complaining that old_re could be false
			 * SA is wrong because old_re is checked for NULL
			 * in zebra_redistribute_check and false is
			 * returned in that case.  Let's just make SA
			 * happy.
			 */
			assert(old_re);
			is_table_direct = zebra_redistribute_is_table_direct(old_re);
			zsend_redistribute_route(ZEBRA_REDISTRIBUTE_ROUTE_DEL,
						 client, rn, old_re,
						 is_table_direct);
		}
	}
}


void zebra_redistribute_add(ZAPI_HANDLER_ARGS)
{
	afi_t afi = 0;
	int type = 0;
	unsigned short instance;

	STREAM_GETC(msg, afi);
	STREAM_GETC(msg, type);
	STREAM_GETW(msg, instance);

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug(
			"%s: client proto %s afi=%d, wants %s, vrf %s(%u), instance=%d",
			__func__, zebra_route_string(client->proto), afi,
			zebra_route_string(type), VRF_LOGNAME(zvrf->vrf),
			zvrf_id(zvrf), instance);

	if (afi == 0 || afi >= AFI_MAX) {
		flog_warn(EC_ZEBRA_REDISTRIBUTE_UNKNOWN_AF,
			  "%s: Specified afi %d does not exist", __func__, afi);
		return;
	}

	if (type == 0 || type >= ZEBRA_ROUTE_MAX) {
		zlog_debug("%s: Specified Route Type %d does not exist",
			   __func__, type);
		return;
	}

	if (instance) {
		if (!redist_check_instance(&client->mi_redist[afi][type],
					   instance)) {
			redist_add_instance(&client->mi_redist[afi][type],
					    instance);
			zebra_redistribute(client, type, instance, zvrf, afi);
		}
	} else {
		if (!vrf_bitmap_check(&client->redist[afi][type],
				      zvrf_id(zvrf))) {
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug(
					"%s: setting vrf %s(%u) redist bitmap",
					__func__, VRF_LOGNAME(zvrf->vrf),
					zvrf_id(zvrf));
			vrf_bitmap_set(&client->redist[afi][type],
				       zvrf_id(zvrf));
			zebra_redistribute(client, type, 0, zvrf, afi);
		}
	}

stream_failure:
	return;
}

void zebra_redistribute_delete(ZAPI_HANDLER_ARGS)
{
	afi_t afi = 0;
	int type = 0;
	unsigned short instance;

	STREAM_GETC(msg, afi);
	STREAM_GETC(msg, type);
	STREAM_GETW(msg, instance);

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug(
			"%s: client proto %s afi=%d, no longer wants %s, vrf %s(%u), instance=%d",
			__func__, zebra_route_string(client->proto), afi,
			zebra_route_string(type), VRF_LOGNAME(zvrf->vrf),
			zvrf_id(zvrf), instance);


	if (afi == 0 || afi >= AFI_MAX) {
		flog_warn(EC_ZEBRA_REDISTRIBUTE_UNKNOWN_AF,
			  "%s: Specified afi %d does not exist", __func__, afi);
		return;
	}

	if (type == 0 || type >= ZEBRA_ROUTE_MAX) {
		zlog_debug("%s: Specified Route Type %d does not exist",
			   __func__, type);
		return;
	}

	/*
	 * NOTE: no need to withdraw the previously advertised routes. The
	 * clients
	 * themselves should keep track of the received routes from zebra and
	 * withdraw them when necessary.
	 */
	if (instance)
		redist_del_instance(&client->mi_redist[afi][type], instance);
	else
		vrf_bitmap_unset(&client->redist[afi][type], zvrf_id(zvrf));

stream_failure:
	return;
}

void zebra_redistribute_default_add(ZAPI_HANDLER_ARGS)
{
	afi_t afi = 0;

	STREAM_GETC(msg, afi);

	if (afi == 0 || afi >= AFI_MAX) {
		flog_warn(EC_ZEBRA_REDISTRIBUTE_UNKNOWN_AF,
			  "%s: Specified afi %u does not exist", __func__, afi);
		return;
	}

	vrf_bitmap_set(&client->redist_default[afi], zvrf_id(zvrf));
	zebra_redistribute_default(client, zvrf_id(zvrf));

stream_failure:
	return;
}

void zebra_redistribute_default_delete(ZAPI_HANDLER_ARGS)
{
	afi_t afi = 0;

	STREAM_GETC(msg, afi);

	if (afi == 0 || afi >= AFI_MAX) {
		flog_warn(EC_ZEBRA_REDISTRIBUTE_UNKNOWN_AF,
			  "%s: Specified afi %u does not exist", __func__, afi);
		return;
	}

	vrf_bitmap_unset(&client->redist_default[afi], zvrf_id(zvrf));

stream_failure:
	return;
}

/* Interface up information. */
void zebra_interface_up_update(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_UP %s vrf %s(%u)",
			   ifp->name, ifp->vrf->name, ifp->vrf->vrf_id);

	if (ifp->ptm_status || !ifp->ptm_enable) {
		for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode,
				       client)) {
			/* Do not send unsolicited messages to synchronous
			 * clients.
			 */
			if (client->synchronous)
				continue;

			zsend_interface_update(ZEBRA_INTERFACE_UP,
					       client, ifp);
			zsend_interface_link_params(client, ifp);
		}
	}
}

/* Interface down information. */
void zebra_interface_down_update(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_DOWN %s vrf %s(%u)",
			   ifp->name, ifp->vrf->name, ifp->vrf->vrf_id);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

		zsend_interface_update(ZEBRA_INTERFACE_DOWN, client, ifp);
	}

	zebra_neigh_del_all(ifp);
}

/* Interface information update. */
void zebra_interface_add_update(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_ADD %s vrf %s(%u)",
			   ifp->name, ifp->vrf->name, ifp->vrf->vrf_id);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

		client->ifadd_cnt++;
		zsend_interface_add(client, ifp);
		zsend_interface_link_params(client, ifp);
	}
}

void zebra_interface_delete_update(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_DELETE %s vrf %s(%u)",
			   ifp->name, ifp->vrf->name, ifp->vrf->vrf_id);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

		client->ifdel_cnt++;
		zsend_interface_delete(client, ifp);
	}
}

/* Interface address addition. */
void zebra_interface_address_add_update(struct interface *ifp,
					struct connected *ifc)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug(
			"MESSAGE: ZEBRA_INTERFACE_ADDRESS_ADD %pFX on %s vrf %s(%u)",
			ifc->address, ifp->name, ifp->vrf->name,
			ifp->vrf->vrf_id);

	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
		flog_warn(
			EC_ZEBRA_ADVERTISING_UNUSABLE_ADDR,
			"advertising address to clients that is not yet usable.");

	zebra_vxlan_add_del_gw_macip(ifp, ifc->address, 1);

	router_id_add_address(ifc);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

		if (CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL)) {
			client->connected_rt_add_cnt++;
			zsend_interface_address(ZEBRA_INTERFACE_ADDRESS_ADD,
						client, ifp, ifc);
		}
	}
}

/* Interface address deletion. */
void zebra_interface_address_delete_update(struct interface *ifp,
					   struct connected *ifc)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug(
			"MESSAGE: ZEBRA_INTERFACE_ADDRESS_DELETE %pFX on %s vrf %s(%u)",
			ifc->address, ifp->name, ifp->vrf->name,
			ifp->vrf->vrf_id);

	zebra_vxlan_add_del_gw_macip(ifp, ifc->address, 0);

	router_id_del_address(ifc);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

		if (CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL)) {
			client->connected_rt_del_cnt++;
			zsend_interface_address(ZEBRA_INTERFACE_ADDRESS_DELETE,
						client, ifp, ifc);
		}
	}
}

/* Interface VRF change. May need to delete from clients not interested in
 * the new VRF. Note that this function is invoked *prior* to the VRF change.
 */
void zebra_interface_vrf_update_del(struct interface *ifp, vrf_id_t new_vrf_id)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_DELETE %s VRF Id %u -> %u",
			   ifp->name, ifp->vrf->vrf_id, new_vrf_id);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

		/* Need to delete if the client is not interested in the new
		 * VRF. */
		zsend_interface_update(ZEBRA_INTERFACE_DOWN, client, ifp);
		client->ifdel_cnt++;
		zsend_interface_delete(client, ifp);
	}
}

/* Interface VRF change. This function is invoked *post* VRF change and sends an
 * add to clients who are interested in the new VRF but not in the old VRF.
 */
void zebra_interface_vrf_update_add(struct interface *ifp, vrf_id_t old_vrf_id)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_ADD %s VRF Id %u -> %u",
			   ifp->name, old_vrf_id, ifp->vrf->vrf_id);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

		/* Need to add if the client is interested in the new VRF. */
		client->ifadd_cnt++;
		zsend_interface_add(client, ifp);
		zsend_interface_addresses(client, ifp);
	}
}

int zebra_add_import_table_entry(struct zebra_vrf *zvrf, safi_t safi, struct route_node *rn,
				 struct route_entry *re, const char *rmap_name)
{
	struct route_entry *newre;
	struct route_entry *same;
	struct prefix p;
	struct nexthop_group *ng;
	route_map_result_t ret = RMAP_PERMITMATCH;
	afi_t afi;

	afi = family2afi(rn->p.family);
	if (rmap_name)
		ret = zebra_import_table_route_map_check(afi, re, &rn->p,
							 re->nhe->nhg.nexthop,
							 rmap_name);

	if (ret != RMAP_PERMITMATCH) {
		UNSET_FLAG(re->flags, ZEBRA_FLAG_SELECTED);
		zebra_del_import_table_entry(zvrf, safi, rn, re);
		return 0;
	}

	prefix_copy(&p, &rn->p);

	RNODE_FOREACH_RE (rn, same) {
		if (CHECK_FLAG(same->status, ROUTE_ENTRY_REMOVED))
			continue;

		if (same->type == re->type && same->instance == re->instance &&
		    same->table == re->table &&
		    (same->type != ZEBRA_ROUTE_CONNECT &&
		     same->type != ZEBRA_ROUTE_LOCAL))
			break;
	}

	if (same) {
		UNSET_FLAG(same->flags, ZEBRA_FLAG_SELECTED);
		zebra_del_import_table_entry(zvrf, safi, rn, same);
	}

	UNSET_FLAG(re->flags, ZEBRA_FLAG_RR_USE_DISTANCE);

	newre = zebra_rib_route_entry_new(0, ZEBRA_ROUTE_TABLE, re->table, re->flags, re->nhe_id,
					  zvrf->table_id, re->metric, re->mtu,
					  zebra_import_table_distance[afi][safi][re->table],
					  re->tag);

	ng = nexthop_group_new();
	copy_nexthops(&ng->nexthop, re->nhe->nhg.nexthop, NULL);

	rib_add_multipath(afi, safi, &p, NULL, newre, ng, false);
	nexthop_group_delete(&ng);

	return 0;
}

int zebra_del_import_table_entry(struct zebra_vrf *zvrf, safi_t safi, struct route_node *rn,
				 struct route_entry *re)
{
	struct prefix p;
	afi_t afi;

	afi = family2afi(rn->p.family);
	prefix_copy(&p, &rn->p);

	rib_delete(afi, safi, zvrf->vrf->vrf_id, ZEBRA_ROUTE_TABLE, re->table, re->flags, &p, NULL,
		   re->nhe->nhg.nexthop, re->nhe_id, zvrf->table_id, re->metric, re->distance,
		   false);

	return 0;
}

/* Assuming no one calls this with the main routing table */
int zebra_import_table(afi_t afi, safi_t safi, vrf_id_t vrf_id, uint32_t table_id,
		       uint32_t distance, const char *rmap_name, bool add)
{
	struct route_table *table;
	struct route_entry *re;
	struct route_node *rn;
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(vrf_id);

	if (!is_zebra_valid_kernel_table(table_id)
	    || (table_id == rt_table_main_id))
		return -1;

	if (afi >= AFI_MAX)
		return -1;

	if (safi >= SAFI_MAX)
		return -1;

	/* Always import from the URIB sub-table */
	table = zebra_vrf_get_table_with_table_id(afi, SAFI_UNICAST, vrf_id,
						  table_id);
	if (table == NULL) {
		return 0;
	} else if (IS_ZEBRA_DEBUG_RIB) {
		zlog_debug("%s routes from table %d into %s", add ? "Importing" : "Unimporting",
			   table_id, safi2str(safi));
	}

	if (add) {
		if (rmap_name)
			zebra_add_import_table_route_map(afi, safi, rmap_name, table_id);
		else {
			rmap_name = zebra_get_import_table_route_map(afi, safi, table_id);
			if (rmap_name) {
				zebra_del_import_table_route_map(afi, safi, table_id);
				rmap_name = NULL;
			}
		}

		zebra_import_table_used[afi][safi][table_id] = 1;
		zebra_import_table_distance[afi][safi][table_id] = distance;
	} else {
		zebra_import_table_used[afi][safi][table_id] = 0;
		zebra_import_table_distance[afi][safi][table_id] = ZEBRA_TABLE_DISTANCE_DEFAULT;

		rmap_name = zebra_get_import_table_route_map(afi, safi, table_id);
		if (rmap_name) {
			zebra_del_import_table_route_map(afi, safi, table_id);
			rmap_name = NULL;
		}
	}

	for (rn = route_top(table); rn; rn = route_next(rn)) {
		/* For each entry in the non-default routing table,
		 * add the entry in the main table
		 */
		if (!rn->info)
			continue;

		RNODE_FOREACH_RE (rn, re) {
			if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
				continue;
			break;
		}

		if (!re)
			continue;

		if (((afi == AFI_IP) && (rn->p.family == AF_INET))
		    || ((afi == AFI_IP6) && (rn->p.family == AF_INET6))) {
			if (add)
				zebra_add_import_table_entry(zvrf, safi, rn, re, rmap_name);
			else
				zebra_del_import_table_entry(zvrf, safi, rn, re);
		}
	}
	return 0;
}

int zebra_import_table_config(struct vty *vty, vrf_id_t vrf_id)
{
	int i;
	afi_t afi;
	safi_t safi;
	int write = 0;
	char afi_str[AFI_MAX][10] = {"", "ip", "ipv6", "ethernet"};
	const char *rmap_name;

	FOREACH_AFI_SAFI (afi, safi) {
		for (i = 1; i < ZEBRA_KERNEL_TABLE_MAX; i++) {
			if (!is_zebra_import_table_enabled(afi, safi, vrf_id, i))
				continue;

			if (zebra_import_table_distance[afi][safi][i] !=
			    ZEBRA_TABLE_DISTANCE_DEFAULT) {
				vty_out(vty, "%s import-table %d %sdistance %d", afi_str[afi], i,
					(safi == SAFI_MULTICAST ? "mrib " : ""),
					zebra_import_table_distance[afi][safi][i]);
			} else {
				vty_out(vty, "%s import-table %d%s", afi_str[afi], i,
					(safi == SAFI_MULTICAST ? " mrib" : ""));
			}

			rmap_name = zebra_get_import_table_route_map(afi, safi, i);
			if (rmap_name)
				vty_out(vty, " route-map %s", rmap_name);

			vty_out(vty, "\n");
			write = 1;
		}
	}

	return write;
}

static void zebra_import_table_rm_update_vrf_afi(struct zebra_vrf *zvrf, afi_t afi, safi_t safi,
						 int table_id, const char *rmap)
{
	struct route_table *table;
	struct route_entry *re;
	struct route_node *rn;
	const char *rmap_name;

	rmap_name = zebra_get_import_table_route_map(afi, safi, table_id);
	if ((!rmap_name) || (strcmp(rmap_name, rmap) != 0))
		return;

	table = zebra_vrf_get_table_with_table_id(afi, safi, zvrf->vrf->vrf_id, table_id);
	if (!table) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("%s: Table id=%d not found", __func__,
				   table_id);
		return;
	}

	for (rn = route_top(table); rn; rn = route_next(rn)) {
		/*
		 * For each entry in the non-default routing table,
		 * add the entry in the main table
		 */
		if (!rn->info)
			continue;

		RNODE_FOREACH_RE (rn, re) {
			if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
				continue;
			break;
		}

		if (!re)
			continue;

		if (((afi == AFI_IP) && (rn->p.family == AF_INET))
		    || ((afi == AFI_IP6) && (rn->p.family == AF_INET6)))
			zebra_add_import_table_entry(zvrf, safi, rn, re, rmap_name);
	}

	return;
}

static void zebra_import_table_rm_update_vrf(struct zebra_vrf *zvrf,
					     const char *rmap)
{
	afi_t afi;
	safi_t safi;
	int i;

	FOREACH_AFI_SAFI (afi, safi) {
		for (i = 1; i < ZEBRA_KERNEL_TABLE_MAX; i++) {
			if (!is_zebra_import_table_enabled(afi, safi, zvrf->vrf->vrf_id, i))
				continue;

			zebra_import_table_rm_update_vrf_afi(zvrf, afi, safi, i, rmap);
		}
	}
}

void zebra_import_table_rm_update(const char *rmap)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		zvrf = vrf->info;

		if (!zvrf)
			continue;

		zebra_import_table_rm_update_vrf(zvrf, rmap);
	}
}

/* Interface parameters update */
void zebra_interface_parameters_update(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_LINK_PARAMS %s vrf %s(%u)",
			   ifp->name, ifp->vrf->name, ifp->vrf->vrf_id);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

		zsend_interface_link_params(client, ifp);
	}
}
