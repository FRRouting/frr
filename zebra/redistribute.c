/* Redistribution Handler
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include "zebra/rib.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_routemap.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_errors.h"

#define ZEBRA_PTM_SUPPORT

/* array holding redistribute info about table redistribution */
/* bit AFI is set if that AFI is redistributing routes from this table */
static int zebra_import_table_used[AFI_MAX][ZEBRA_KERNEL_TABLE_MAX];
static uint32_t zebra_import_table_distance[AFI_MAX][ZEBRA_KERNEL_TABLE_MAX];

int is_zebra_import_table_enabled(afi_t afi, vrf_id_t vrf_id, uint32_t table_id)
{
	/*
	 * Make sure that what we are called with actualy makes sense
	 */
	if (afi == AFI_MAX)
		return 0;

	if (is_zebra_valid_kernel_table(table_id) &&
	    table_id < ZEBRA_KERNEL_TABLE_MAX)
		return zebra_import_table_used[afi][table_id];
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
			if (CHECK_FLAG(newre->flags, ZEBRA_FLAG_SELECTED)
			    && newre->distance != DISTANCE_INFINITY)
				zsend_redistribute_route(
					ZEBRA_REDISTRIBUTE_ROUTE_ADD, client,
					&rn->p, NULL, newre);
		}

		route_unlock_node(rn);
	}
}

/* Redistribute routes. */
static void zebra_redistribute(struct zserv *client, int type,
			       unsigned short instance, vrf_id_t vrf_id,
			       int afi)
{
	struct route_entry *newre;
	struct route_table *table;
	struct route_node *rn;

	table = zebra_vrf_table(afi, SAFI_UNICAST, vrf_id);
	if (!table)
		return;

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
		RNODE_FOREACH_RE (rn, newre) {
			const struct prefix *dst_p, *src_p;
			char buf[PREFIX_STRLEN];

			srcdest_rnode_prefixes(rn, &dst_p, &src_p);

			if (IS_ZEBRA_DEBUG_RIB)
				zlog_debug(
					"%s: client %s %s(%u) checking: selected=%d, type=%d, distance=%d, metric=%d zebra_check_addr=%d",
					__func__,
					zebra_route_string(client->proto),
					prefix2str(dst_p, buf, sizeof(buf)),
					vrf_id, CHECK_FLAG(newre->flags,
							   ZEBRA_FLAG_SELECTED),
					newre->type, newre->distance,
					newre->metric, zebra_check_addr(dst_p));

			if (!CHECK_FLAG(newre->flags, ZEBRA_FLAG_SELECTED))
				continue;
			if ((type != ZEBRA_ROUTE_ALL
			     && (newre->type != type
				 || newre->instance != instance)))
				continue;
			if (newre->distance == DISTANCE_INFINITY)
				continue;
			if (!zebra_check_addr(dst_p))
				continue;

			zsend_redistribute_route(ZEBRA_REDISTRIBUTE_ROUTE_ADD,
						 client, dst_p, src_p, newre);
		}
}

/* Either advertise a route for redistribution to registered clients or */
/* withdraw redistribution if add cannot be done for client */
void redistribute_update(const struct prefix *p, const struct prefix *src_p,
			 const struct route_entry *re,
			 const struct route_entry *prev_re)
{
	struct listnode *node, *nnode;
	struct zserv *client;
	int send_redistribute;
	int afi;
	char buf[PREFIX_STRLEN];

	if (IS_ZEBRA_DEBUG_RIB) {
		zlog_debug(
			"%u:%s: Redist update re %p (%s), old %p (%s)",
			re->vrf_id, prefix2str(p, buf, sizeof(buf)),
			re, zebra_route_string(re->type), prev_re,
			prev_re ? zebra_route_string(prev_re->type) : "None");
	}

	afi = family2afi(p->family);
	if (!afi) {
		flog_warn(EC_ZEBRA_REDISTRIBUTE_UNKNOWN_AF,
			  "%s: Unknown AFI/SAFI prefix received\n",
			  __FUNCTION__);
		return;
	}
	if (!zebra_check_addr(p)) {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("Redist update filter prefix %s",
				   prefix2str(p, buf, sizeof(buf)));
		return;
	}


	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		send_redistribute = 0;

		if (is_default_prefix(p)
		    && vrf_bitmap_check(client->redist_default[afi],
					re->vrf_id))
			send_redistribute = 1;
		else if (vrf_bitmap_check(client->redist[afi][ZEBRA_ROUTE_ALL],
					  re->vrf_id))
			send_redistribute = 1;
		else if (re->instance
			 && redist_check_instance(
				    &client->mi_redist[afi][re->type],
				    re->instance))
			send_redistribute = 1;
		else if (vrf_bitmap_check(client->redist[afi][re->type],
					  re->vrf_id))
			send_redistribute = 1;

		if (send_redistribute) {
			if (IS_ZEBRA_DEBUG_RIB) {
				zlog_debug(
					   "%s: client %s %s(%u), type=%d, distance=%d, metric=%d",
					   __func__,
					   zebra_route_string(client->proto),
					   prefix2str(p, buf, sizeof(buf)),
					   re->vrf_id, re->type,
					   re->distance, re->metric);
			}
			zsend_redistribute_route(ZEBRA_REDISTRIBUTE_ROUTE_ADD,
						 client, p, src_p, re);
		} else if (prev_re
			   && ((re->instance
				&& redist_check_instance(
					   &client->mi_redist[afi]
							     [prev_re->type],
					   re->instance))
			       || vrf_bitmap_check(
					  client->redist[afi][prev_re->type],
					  re->vrf_id))) {
			zsend_redistribute_route(ZEBRA_REDISTRIBUTE_ROUTE_DEL,
						 client, p, src_p, prev_re);
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
void redistribute_delete(const struct prefix *p, const struct prefix *src_p,
			 const struct route_entry *old_re,
			 const struct route_entry *new_re)
{
	struct listnode *node, *nnode;
	struct zserv *client;
	int afi;
	char buf[PREFIX_STRLEN];
	vrf_id_t vrfid;

	if (old_re)
		vrfid = old_re->vrf_id;
	else if (new_re)
		vrfid = new_re->vrf_id;
	else
		return;

	if (IS_ZEBRA_DEBUG_RIB) {
		zlog_debug(
			"%u:%s: Redist del: re %p (%s), new re %p (%s)",
			vrfid, prefix2str(p, buf, sizeof(buf)),
			old_re,
			old_re ? zebra_route_string(old_re->type) : "None",
			new_re,
			new_re ? zebra_route_string(new_re->type) : "None");
	}

	/* Add DISTANCE_INFINITY check. */
	if (old_re && (old_re->distance == DISTANCE_INFINITY)) {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("\tSkipping due to Infinite Distance");
		return;
	}

	afi = family2afi(p->family);
	if (!afi) {
		flog_warn(EC_ZEBRA_REDISTRIBUTE_UNKNOWN_AF,
			  "%s: Unknown AFI/SAFI prefix received\n",
			  __func__);
		return;
	}

	/* Skip invalid (e.g. linklocal) prefix */
	if (!zebra_check_addr(p)) {
		if (IS_ZEBRA_DEBUG_RIB) {
			zlog_debug(
				"%u:%s: Redist del old: skipping invalid prefix",
				vrfid, prefix2str(p, buf, sizeof(buf)));
		}
		return;
	}

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		if (new_re) {
			/* Skip this client if it will receive an update for the
			 * 'new' re
			 */
			if (is_default_prefix(p)
			    && vrf_bitmap_check(client->redist_default[afi],
						new_re->vrf_id))
				continue;
			else if (vrf_bitmap_check(
					 client->redist[afi][ZEBRA_ROUTE_ALL],
					 new_re->vrf_id))
				continue;
			else if (new_re->instance
				 && redist_check_instance(
					 &client->mi_redist[afi][new_re->type],
					 new_re->instance))
				continue;
			else if (vrf_bitmap_check(
					 client->redist[afi][new_re->type],
					 new_re->vrf_id))
				continue;
		}

		/* Send a delete for the 'old' re to any subscribed client. */
		if (old_re
		    && (vrf_bitmap_check(client->redist[afi][ZEBRA_ROUTE_ALL],
					 old_re->vrf_id)
			|| (old_re->instance
			    && redist_check_instance(
				       &client->mi_redist[afi][old_re->type],
				       old_re->instance))
			|| vrf_bitmap_check(client->redist[afi][old_re->type],
					    old_re->vrf_id))) {
			zsend_redistribute_route(ZEBRA_REDISTRIBUTE_ROUTE_DEL,
						 client, p, src_p, old_re);
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
			"%s: client proto %s afi=%d, wants %s, vrf %u, instance=%d",
			__func__, zebra_route_string(client->proto), afi,
			zebra_route_string(type), zvrf_id(zvrf), instance);

	if (afi == 0 || afi >= AFI_MAX) {
		flog_warn(EC_ZEBRA_REDISTRIBUTE_UNKNOWN_AF,
			  "%s: Specified afi %d does not exist",
			  __PRETTY_FUNCTION__, afi);
		return;
	}

	if (type == 0 || type >= ZEBRA_ROUTE_MAX) {
		zlog_debug("%s: Specified Route Type %d does not exist",
			   __PRETTY_FUNCTION__, type);
		return;
	}

	if (instance) {
		if (!redist_check_instance(&client->mi_redist[afi][type],
					   instance)) {
			redist_add_instance(&client->mi_redist[afi][type],
					    instance);
			zebra_redistribute(client, type, instance,
					   zvrf_id(zvrf), afi);
		}
	} else {
		if (!vrf_bitmap_check(client->redist[afi][type],
				      zvrf_id(zvrf))) {
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("%s: setting vrf %u redist bitmap",
					   __func__, zvrf_id(zvrf));
			vrf_bitmap_set(client->redist[afi][type],
				       zvrf_id(zvrf));
			zebra_redistribute(client, type, 0, zvrf_id(zvrf), afi);
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

	if (afi == 0 || afi >= AFI_MAX) {
		flog_warn(EC_ZEBRA_REDISTRIBUTE_UNKNOWN_AF,
			  "%s: Specified afi %d does not exist",
			  __PRETTY_FUNCTION__, afi);
		return;
	}

	if (type == 0 || type >= ZEBRA_ROUTE_MAX) {
		zlog_debug("%s: Specified Route Type %d does not exist",
			   __PRETTY_FUNCTION__, type);
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
		vrf_bitmap_unset(client->redist[afi][type], zvrf_id(zvrf));

stream_failure:
	return;
}

void zebra_redistribute_default_add(ZAPI_HANDLER_ARGS)
{
	afi_t afi = 0;

	STREAM_GETC(msg, afi);

	if (afi == 0 || afi >= AFI_MAX) {
		flog_warn(EC_ZEBRA_REDISTRIBUTE_UNKNOWN_AF,
			  "%s: Specified afi %u does not exist",
			  __PRETTY_FUNCTION__, afi);
		return;
	}

	vrf_bitmap_set(client->redist_default[afi], zvrf_id(zvrf));
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
			  "%s: Specified afi %u does not exist",
			  __PRETTY_FUNCTION__, afi);
		return;
	}

	vrf_bitmap_unset(client->redist_default[afi], zvrf_id(zvrf));

stream_failure:
	return;
}

/* Interface up information. */
void zebra_interface_up_update(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_UP %s(%u)",
			   ifp->name, ifp->vrf_id);

	if (ifp->ptm_status || !ifp->ptm_enable) {
		for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode,
				       client)) {
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
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_DOWN %s(%u)",
			   ifp->name, ifp->vrf_id);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		zsend_interface_update(ZEBRA_INTERFACE_DOWN, client, ifp);
	}
}

/* Interface information update. */
void zebra_interface_add_update(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_ADD %s(%u)", ifp->name,
			   ifp->vrf_id);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
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
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_DELETE %s(%u)",
			   ifp->name, ifp->vrf_id);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
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
	struct prefix *p;

	if (IS_ZEBRA_DEBUG_EVENT) {
		char buf[PREFIX_STRLEN];

		p = ifc->address;
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_ADDRESS_ADD %s on %s(%u)",
			   prefix2str(p, buf, sizeof(buf)), ifp->name,
			   ifp->vrf_id);
	}

	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
		flog_warn(
			EC_ZEBRA_ADVERTISING_UNUSABLE_ADDR,
			"WARNING: advertising address to clients that is not yet usable.");

	zebra_vxlan_add_del_gw_macip(ifp, ifc->address, 1);

	router_id_add_address(ifc);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client))
		if (CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL)) {
			client->connected_rt_add_cnt++;
			zsend_interface_address(ZEBRA_INTERFACE_ADDRESS_ADD,
						client, ifp, ifc);
		}
}

/* Interface address deletion. */
void zebra_interface_address_delete_update(struct interface *ifp,
					   struct connected *ifc)
{
	struct listnode *node, *nnode;
	struct zserv *client;
	struct prefix *p;

	if (IS_ZEBRA_DEBUG_EVENT) {
		char buf[PREFIX_STRLEN];

		p = ifc->address;
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_ADDRESS_DELETE %s on %s(%u)",
			   prefix2str(p, buf, sizeof(buf)),
			   ifp->name, ifp->vrf_id);
	}

	zebra_vxlan_add_del_gw_macip(ifp, ifc->address, 0);

	router_id_del_address(ifc);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client))
		if (CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL)) {
			client->connected_rt_del_cnt++;
			zsend_interface_address(ZEBRA_INTERFACE_ADDRESS_DELETE,
						client, ifp, ifc);
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
		zlog_debug(
			"MESSAGE: ZEBRA_INTERFACE_VRF_UPDATE/DEL %s VRF Id %u -> %u",
			ifp->name, ifp->vrf_id, new_vrf_id);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Need to delete if the client is not interested in the new
		 * VRF. */
		zsend_interface_update(ZEBRA_INTERFACE_DOWN, client, ifp);
		client->ifdel_cnt++;
		zsend_interface_delete(client, ifp);
		zsend_interface_vrf_update(client, ifp, new_vrf_id);
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
		zlog_debug(
			"MESSAGE: ZEBRA_INTERFACE_VRF_UPDATE/ADD %s VRF Id %u -> %u",
			ifp->name, old_vrf_id, ifp->vrf_id);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Need to add if the client is interested in the new VRF. */
		client->ifadd_cnt++;
		zsend_interface_add(client, ifp);
		zsend_interface_addresses(client, ifp);
	}
}

int zebra_add_import_table_entry(struct zebra_vrf *zvrf, struct route_node *rn,
				 struct route_entry *re, const char *rmap_name)
{
	struct route_entry *newre;
	struct route_entry *same;
	struct prefix p;
	route_map_result_t ret = RMAP_PERMITMATCH;
	afi_t afi;

	afi = family2afi(rn->p.family);
	if (rmap_name)
		ret = zebra_import_table_route_map_check(
			afi, re->type, re->instance, &rn->p, re->ng->nexthop,
			zvrf->vrf->vrf_id, re->tag, rmap_name);

	if (ret != RMAP_PERMITMATCH) {
		UNSET_FLAG(re->flags, ZEBRA_FLAG_SELECTED);
		zebra_del_import_table_entry(zvrf, rn, re);
		return 0;
	}

	prefix_copy(&p, &rn->p);

	RNODE_FOREACH_RE (rn, same) {
		if (CHECK_FLAG(same->status, ROUTE_ENTRY_REMOVED))
			continue;

		if (same->type == re->type && same->instance == re->instance
		    && same->table == re->table
		    && same->type != ZEBRA_ROUTE_CONNECT)
			break;
	}

	if (same) {
		UNSET_FLAG(same->flags, ZEBRA_FLAG_SELECTED);
		zebra_del_import_table_entry(zvrf, rn, same);
	}

	newre = XCALLOC(MTYPE_RE, sizeof(struct route_entry));
	newre->type = ZEBRA_ROUTE_TABLE;
	newre->distance = zebra_import_table_distance[afi][re->table];
	newre->flags = re->flags;
	newre->metric = re->metric;
	newre->mtu = re->mtu;
	newre->table = zvrf->table_id;
	newre->uptime = monotime(NULL);
	newre->instance = re->table;
	newre->ng = nexthop_group_new();
	route_entry_copy_nexthops(newre, re->ng->nexthop);

	rib_add_multipath(afi, SAFI_UNICAST, &p, NULL, newre);

	return 0;
}

int zebra_del_import_table_entry(struct zebra_vrf *zvrf, struct route_node *rn,
				 struct route_entry *re)
{
	struct prefix p;
	afi_t afi;

	afi = family2afi(rn->p.family);
	prefix_copy(&p, &rn->p);

	rib_delete(afi, SAFI_UNICAST, zvrf->vrf->vrf_id, ZEBRA_ROUTE_TABLE,
		   re->table, re->flags, &p, NULL, re->ng->nexthop, re->nhe_id,
		   zvrf->table_id, re->metric, re->distance, false);

	return 0;
}

/* Assuming no one calls this with the main routing table */
int zebra_import_table(afi_t afi, vrf_id_t vrf_id, uint32_t table_id,
		       uint32_t distance, const char *rmap_name, int add)
{
	struct route_table *table;
	struct route_entry *re;
	struct route_node *rn;
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(vrf_id);

	if (!is_zebra_valid_kernel_table(table_id)
	    || (table_id == RT_TABLE_MAIN))
		return (-1);

	if (afi >= AFI_MAX)
		return (-1);

	table = zebra_vrf_get_table_with_table_id(afi, SAFI_UNICAST, vrf_id,
						  table_id);
	if (table == NULL) {
		return 0;
	} else if (IS_ZEBRA_DEBUG_RIB) {
		zlog_debug("%s routes from table %d",
			   add ? "Importing" : "Unimporting", table_id);
	}

	if (add) {
		if (rmap_name)
			zebra_add_import_table_route_map(afi, rmap_name,
							 table_id);
		else {
			rmap_name =
				zebra_get_import_table_route_map(afi, table_id);
			if (rmap_name) {
				zebra_del_import_table_route_map(afi, table_id);
				rmap_name = NULL;
			}
		}

		zebra_import_table_used[afi][table_id] = 1;
		zebra_import_table_distance[afi][table_id] = distance;
	} else {
		zebra_import_table_used[afi][table_id] = 0;
		zebra_import_table_distance[afi][table_id] =
			ZEBRA_TABLE_DISTANCE_DEFAULT;

		rmap_name = zebra_get_import_table_route_map(afi, table_id);
		if (rmap_name) {
			zebra_del_import_table_route_map(afi, table_id);
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
				zebra_add_import_table_entry(zvrf, rn, re,
							     rmap_name);
			else
				zebra_del_import_table_entry(zvrf, rn, re);
		}
	}
	return 0;
}

int zebra_import_table_config(struct vty *vty, vrf_id_t vrf_id)
{
	int i;
	afi_t afi;
	int write = 0;
	char afi_str[AFI_MAX][10] = {"", "ip", "ipv6", "ethernet"};
	const char *rmap_name;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		for (i = 1; i < ZEBRA_KERNEL_TABLE_MAX; i++) {
			if (!is_zebra_import_table_enabled(afi, vrf_id, i))
				continue;

			if (zebra_import_table_distance[afi][i]
			    != ZEBRA_TABLE_DISTANCE_DEFAULT) {
				vty_out(vty, "%s import-table %d distance %d",
					afi_str[afi], i,
					zebra_import_table_distance[afi][i]);
			} else {
				vty_out(vty, "%s import-table %d", afi_str[afi],
					i);
			}

			rmap_name = zebra_get_import_table_route_map(afi, i);
			if (rmap_name)
				vty_out(vty, " route-map %s", rmap_name);

			vty_out(vty, "\n");
			write = 1;
		}
	}

	return write;
}

static void zebra_import_table_rm_update_vrf_afi(struct zebra_vrf *zvrf,
						 afi_t afi, int table_id,
						 const char *rmap)
{
	struct route_table *table;
	struct route_entry *re;
	struct route_node *rn;
	const char *rmap_name;

	rmap_name = zebra_get_import_table_route_map(afi, table_id);
	if ((!rmap_name) || (strcmp(rmap_name, rmap) != 0))
		return;

	table = zebra_vrf_get_table_with_table_id(afi, SAFI_UNICAST,
						  zvrf->vrf->vrf_id, table_id);
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
			zebra_add_import_table_entry(zvrf, rn, re, rmap_name);
	}

	return;
}

static void zebra_import_table_rm_update_vrf(struct zebra_vrf *zvrf,
					     const char *rmap)
{
	afi_t afi;
	int i;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		for (i = 1; i < ZEBRA_KERNEL_TABLE_MAX; i++) {
			if (!is_zebra_import_table_enabled(
				    afi, zvrf->vrf->vrf_id, i))
				continue;

			zebra_import_table_rm_update_vrf_afi(zvrf, afi, i,
							     rmap);
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
		zlog_debug("MESSAGE: ZEBRA_INTERFACE_LINK_PARAMS %s(%u)",
			   ifp->name, ifp->vrf_id);

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client))
		zsend_interface_link_params(client, ifp);
}
