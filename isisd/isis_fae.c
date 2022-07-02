/* IS-IS Flex-Algo Endpoint Registration Tracking
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include "flex_algo.h"
#include "linklist.h"
#include "isisd/isis_fae.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_route.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"
#include "isisd/isis_flex_algo.h"
#include "isisd/isis_fae_cli.h"
#include "isisd/isis_zebra_fae.h"

#ifndef FABRICD

#ifdef EXTREME_FAE_DEBUG
#define ZLOG_EXTREME(fmt, ...) zlog_debug(fmt, __VA_ARGS__)
#else
#define ZLOG_EXTREME(fmt, ...)
#endif

static struct route_node *
isis_fae_route_node_match(const struct isis_area *const area,
			  const struct zapi_fae_query *const query);

static int isis_fae_route_info_reg_add(struct isis_route_info *rinfo,
				       struct fae_db_node *node,
				       uint8_t algorithm);

static bool isis_fae_route_info_reg_del(struct isis_route_info *rinfo,
					const struct fae_db_node *node,
					uint8_t algorithm);

static void
isis_fae_route_node_reg_del(struct isis_area *area,
			    const struct fae_db_node *const node,
			    const struct zapi_fae_query *const query);

static struct zapi_fae_daemon_id _clients[1];
static unsigned _num_clients = 0;

static void ipaddr2prefix(struct prefix *p, const struct ipaddr *const addr)
{
	p->family = ipaddr_family(addr);
	if (p->family == AF_INET) {
		p->prefixlen = IPV4_MAX_BITLEN;
		p->u.prefix4 = addr->ipaddr_v4;
	} else {
		p->prefixlen = IPV6_MAX_BITLEN;
		p->u.prefix6 = addr->ipaddr_v6;
	}
}

/* Expand this later to deal with multiple clients  / restarted client */
static int isis_fae_get_client(const struct zapi_fae_daemon_id *const id)
{
	if (_num_clients == 0) {
		_clients[0].proto = id->proto;
		_clients[0].instance = id->instance;
		_clients[0].session_id = id->session_id;
		_num_clients++;
		return 0;
	}

	if (_clients[0].proto == id->proto
	    && _clients[0].instance == id->instance
	    && _clients[0].session_id == id->session_id)
		return 0;
	return -1;
}

/* This matches only the proto and instance.  Caller should check the
 * session ID.  Expand this later to deal with multiple clients.
 */
static int isis_fae_find_client(const struct zapi_fae_daemon_id *const id)
{
	if (_num_clients == 1 && _clients[0].proto == id->proto
	    && _clients[0].instance == id->instance)
		return 0;
	return -1;
}

/* Expand this later to deal with multiple clients */
static int isis_fae_del_client(int client)
{
	if (_num_clients > 0 && client == 0) {
		_num_clients--;
		return 0;
	}
	return -1;
}

/* Send updates, for all endpoints tracked by this route + algo, to all
 * interested clients.  This function is called in reponse to a route
 * update.
 *
 * @param sr	the segment-routing structure holding the registration
 *		list for this (route_node,algorithm).
 */
void isis_fae_send_update_all(const struct isis_area *const area,
			      const struct isis_route_info *const rinfo,
			      uint8_t algorithm)
{
	struct list *list = rinfo->fae_regs[algorithm];
	struct listnode *node;
	struct fae_db_node *dbnode;

	if (CHECK_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_SR_ALGO))
		return;

	for (ALL_LIST_ELEMENTS_RO(list, node, dbnode)) {
		for (unsigned i = 0; i < dbnode->num_clients; i++) {
			struct zapi_fae_daemon_id *client;

			client = &_clients[dbnode->client[i]];
			isis_zebra_fae_update_send(area, &dbnode->endpoint,
						   rinfo, algorithm, client);
		}
	}
}

/* Allocate the FAE registration tables
 *
 * @param db	pointer to the database to initialize
 */
int isis_fae_alloc_db(struct isis_fae_db *db)
{
	db->active = fae_db_init();
	if (db->active == NULL)
		return -1;
	db->inactive = fae_db_init();
	if (db->inactive == NULL) {
		fae_db_free(db->active);
		db->active = NULL;
		return -1;
	}
	return 0;
}

/* Free the FAE registration tables
 *
 * @param db	pointer to the database to clean up
 */
void isis_fae_free_db(struct isis_fae_db *db)
{
	if (db->active)
		fae_db_free(db->active);
	if (db->inactive)
		fae_db_free(db->inactive);
}

/* Start tracking the specified endpoint.  Look for a matching route.
 * The route node must also have a matching SR algorithm present.
 * If found, insert this registration to the "active" table and add a
 * back-reference from the route.  Otherwise insert into the "inactive"
 * table.
 *
 * @param vrf_id		the VRF used to look up an IS-IS instance
 * @param client_daemon_id	client process
 * @param igp_disc		ISIS-specific information
 * @param query			registration information
 */
int isis_fae_process_register(
	const struct zapi_fae_daemon_id *const client_daemon_id,
	const struct zapi_fae_igp_discriminator *const igp_disc,
	const struct zapi_fae_query *const query)
{
	struct isis_area *area;
	struct route_node *rn = NULL;
	struct fae_db_node *node;
	int is_dup;
	int client;

	if (igp_disc->proto != ZEBRA_ROUTE_ISIS) {
		zlog_debug("unsupported zf_proto %d", igp_disc->proto);
		return -1;
	}

	client = isis_fae_get_client(client_daemon_id);
	if (client < 0) {
		zlog_debug("%s unable to find add/find client", __func__);
		return -1;
	}

	area = isis_fae_area_lookup(igp_disc);
	if (area == NULL)
		return -1;

	if (isis_flex_algo_elected_supported(query->algorithm, area))
		rn = isis_fae_route_node_match(area, query);
	if (rn) {
		struct isis_route_info *rinfo;
		char epstr[INET6_ADDRSTRLEN];

		ipaddr2str(&query->endpoint, epstr, sizeof(epstr));
		ZLOG_EXTREME("%s found a route (p=%pFX) for endpoint %s",
			     __func__, &rn->p, epstr);
		rinfo = rn->info;
		node = fae_db_insert(&area->fae.active[query->algorithm],
				     &query->endpoint, client, &is_dup);
		if (node == NULL) {
			route_unlock_node(rn);
			goto fail;
		}

		if (!is_dup)
			isis_fae_route_info_reg_add(rinfo, node,
						    query->algorithm);

		isis_zebra_fae_update_send(area, &query->endpoint, rinfo,
					   query->algorithm, client_daemon_id);
		route_unlock_node(rn);
		return 0;
	} else {
		node = fae_db_insert(&area->fae.inactive[query->algorithm],
				     &query->endpoint, 0, &is_dup);
	}

fail:
	isis_zebra_fae_update_send(area, &query->endpoint, NULL,
				   query->algorithm, client_daemon_id);
	return -1;
}

/* Stop tracking the specified endpoint.  If this registration is found
 * in the "active" table, look up the route and remove the back-reference.
 * Remove the registration from the database.
 *
 * @param vrf_id	the VRF used to look up an IS-IS instance
 * @param reg		the registration received by isisd
 */
int isis_fae_process_unregister(
	const struct zapi_fae_daemon_id *const client_daemon_id,
	const struct zapi_fae_igp_discriminator *const igp_disc,
	const struct zapi_fae_query *const query)
{
	struct isis_area *area;
	struct fae_db_node *node;
	int client;

	if (igp_disc->proto != ZEBRA_ROUTE_ISIS) {
		zlog_debug("unsupported zf_proto %d", igp_disc->proto);
		return -1;
	}

	area = isis_fae_area_lookup(igp_disc);
	if (area == NULL)
		return -1;

	client = isis_fae_get_client(client_daemon_id);

	node = fae_db_delete(&area->fae.inactive[query->algorithm],
			     &query->endpoint, client);
	if (node) {
		if (node->num_clients == 0)
			fae_db_node_free(node, true);
		ZLOG_EXTREME("%s found inactive registration", __func__);
		goto out;
	}

	node = fae_db_delete(&area->fae.active[query->algorithm],
			     &query->endpoint, client);
	if (node == NULL) {
		zlog_err(
			"Unable to remove FAE registration for endpoint %pI4 client %u",
			&query->endpoint.ip._v4_addr, 0);
		goto out;
	}

	ZLOG_EXTREME("%s found active registration", __func__);
	if (node->num_clients == 0) {
		ZLOG_EXTREME(
			"%s no remaining clients.  Remove from route node.",
			__func__);
		isis_fae_route_node_reg_del(area, node, query);
		fae_db_node_free(node, true);
	}

out:
	return 0;
}

/* Register a new client.  If the client registered previously, clean
 * up its old FAE registrations.
 *
 * @param client_daemon_id	client process
 *
 * @return			0 on success, -1 otherwise.
 */
int isis_fae_process_client_ready(
	const struct zapi_fae_daemon_id *const client_daemon_id)
{
	int client;
	struct isis *isis;
	struct isis_area *area;
	struct listnode *isis_node;
	struct listnode *area_node;

	/* For now, there can be only one client.  If a new client shows up,
	 * assume pathd restarted and clean up the old information.
	 */
	client = isis_fae_find_client(client_daemon_id);
	if (client < 0)
		goto out;

	for (ALL_LIST_ELEMENTS_RO(im->isis, isis_node, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, area_node, area)) {
			struct fae_db_node *node;
			struct fae_db_node *tmp;

			for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
				RB_FOREACH_SAFE (node, fae_db_head,
						 &area->fae.active[i], tmp) {
					fae_db_node_delete(&area->fae.active[i],
							   node, client);
					if (node->num_clients == 0) {
						struct zapi_fae_query query;

						query.algorithm = i;
						query.endpoint = node->endpoint;
						isis_fae_route_node_reg_del(
							area, node, &query);
						fae_db_node_free(node, true);
					}
				}
				RB_FOREACH_SAFE (node, fae_db_head,
						 &area->fae.inactive[i], tmp) {
					fae_db_node_delete(
						&area->fae.inactive[i], node,
						client);
					if (node->num_clients == 0)
						fae_db_node_free(node, true);
				}
			}
		}
	}

	if (isis_fae_del_client(client)) {
		zlog_warn("%s Unable to replace client", __func__);
		return -1;
	}

out:
	if (isis_fae_get_client(client_daemon_id) < 0)
		return -1;

	/* Notify the client of available areas */
	for (ALL_LIST_ELEMENTS_RO(im->isis, isis_node, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, area_node, area)) {
			isis_zebra_fae_ready_unicast_send(area, true,
							  client_daemon_id);
		}
	}
	return 0;
}

/* Walk up the route tree looking for a non-empty node with an SR
 * Prefix-SID for the target flex-algo.  If one is found, move the FAE
 * registrations to the new, more specific, node.
 *
 * @param area	the IS-IS area to search
 * @param rn	the route node just added and the starting point for our
 *		search.
 * @param algo	The Flex-Algo number
 *
 * @return	A pointer to the route node that now holds the endpoint
 *		registration.
 */
struct route_node *isis_fae_promote(struct isis_area *area,
				    struct route_node *rn, uint8_t algo)
{
	struct route_node *cur = rn;
	struct isis_route_info *cur_info;
	struct isis_route_info *rn_info;
	struct list *list;
	struct listnode *node;
	struct listnode *next;
	struct fae_db_node *dbnode;
	bool found_one = false;

	rn_info = rn->info;
	if (CHECK_FLAG(rn_info->flag, ISIS_ROUTE_FLAG_SR_ALGO))
		goto out;

	ZLOG_EXTREME("%s %pFX", __func__, &rn->p);

	cur = rn;
	do {
		cur = cur->parent;
		if (cur) {
			cur_info = cur->info;
			ZLOG_EXTREME("%s checkout route node %pFX info is %s",
				     __func__, &cur->p,
				     cur->info ? "NOT NULL" : "NULL");
		}
	} while (cur
		 && (cur->info == NULL || !cur_info->sr_algo[algo].present));

	if (cur == NULL)
		/* we reached to top without finding another non-empty
		 * node */
		goto out;

	list = cur_info->fae_regs[algo];
	if (list == NULL || list_isempty(list))
		goto out;

	for (ALL_LIST_ELEMENTS(list, node, next, dbnode)) {
		struct prefix endpoint;

		ipaddr2prefix(&endpoint, &dbnode->endpoint);
		ZLOG_EXTREME("%s checking endpoint %pFX in %pFX", __func__,
			     &endpoint, &rn->p);
		if (!prefix_match(&rn->p, &endpoint))
			continue;

		ZLOG_EXTREME("%s promote endpoint %pFX from %pFX to %pFX",
			     __func__, &endpoint, &cur->p, &rn->p);

		found_one = true;
		/* Could find a way that doesn't free/alloc
		 * listnode memory */
		isis_fae_route_info_reg_del(cur_info, dbnode, algo);
		isis_fae_route_info_reg_add(rn_info, dbnode, algo);
	}

out:
	ZLOG_EXTREME("%s return %p", __func__, found_one ? cur : NULL);
	return found_one ? cur : NULL;
}

/* Walk up the route tree looking for a non-empty node with an SR
 * Prefix-SID for the target flex-algo.  If one is found, move the FAE
 * registrations from the doomed route node (param rn) to the parent
 * node.
 *
 * @param area	the IS-IS area to search
 * @param rn	the route node about to be deleted and the starting
 *		point for our search.
 * @param algo	The Flex-Algo number
 *
 * @return	A pointer to the route node that now holds the endpoint
 *		registrations, or NULL if no new home was found for them.
 */
struct route_node *isis_fae_demote(struct isis_area *area,
				   struct route_node *rn, uint8_t algo)
{
	struct route_node *cur = rn;
	struct isis_route_info *cur_info;
	struct isis_route_info *rn_info;
	struct list *list;
	struct listnode *node;
	struct listnode *next;
	struct fae_db_node *dbnode;
	bool found_one = false;

	rn_info = rn->info;
	if (CHECK_FLAG(rn_info->flag, ISIS_ROUTE_FLAG_SR_ALGO))
		goto out;

	ZLOG_EXTREME("%s %pFX algo %u", __func__, &rn->p, algo);

	list = rn_info->fae_regs[algo];
	if (list == NULL || list_isempty(list))
		goto out;

	cur = rn;
	do {
		cur = cur->parent;
		if (cur) {
			cur_info = cur->info;
			ZLOG_EXTREME("%s checkout route node %pFX info is %s",
				     __func__, &cur->p,
				     cur->info ? "NOT NULL" : "NULL");
		}
	} while (cur
		 && (cur->info == NULL || !cur_info->sr_algo[algo].present));

	if (cur == NULL)
		goto out;

	for (ALL_LIST_ELEMENTS(list, node, next, dbnode)) {
		struct prefix endpoint;

		ipaddr2prefix(&endpoint, &dbnode->endpoint);
		ZLOG_EXTREME("%s demote endpoint %pFX from %pFX to %pFX",
			     __func__, &endpoint, &rn->p, &cur->p);

		found_one = true;
		/* Could find a way that doesn't free/alloc
		 * listnode memory */
		isis_fae_route_info_reg_del(rn_info, dbnode, algo);
		isis_fae_route_info_reg_add(cur_info, dbnode, algo);
	}

out:
	ZLOG_EXTREME("%s return %p", __func__, found_one ? cur : NULL);
	return found_one ? cur : NULL;
}

static void isis_fae_check_inactive_one(struct isis_area *area,
					const struct route_node *const rn,
					const struct fae_db_node *const key,
					uint8_t algo)
{
	struct fae_db_node *node;
	bool done = false;

	/* Take advantage of the registration database RB-tree being
	 * ordered by endpoint IP address.  Search for the first entry
	 * >= the route_node prefix's lowest address.  Keep processing
	 * nodes until we find a registration for an endpoint address
	 * that does not match the route_node prefix.
	 */

	node = RB_NFIND(fae_db_head, &area->fae.inactive[algo], key);
	while (node && !done) {
		struct prefix endpoint;
		struct fae_db_node *next;

		ipaddr2prefix(&endpoint, &node->endpoint);
		if (!prefix_match(&rn->p, &endpoint))
			break;

		next = RB_NEXT(fae_db_head, node);
		if (fae_db_move(&area->fae.active[algo],
				&area->fae.inactive[algo], node)
		    != node)
			zlog_warn("%s found a conflicting node for %pFX",
				  __func__, &endpoint);
		else
			isis_fae_route_info_reg_add(rn->info, node, algo);
		node = next;
	}
}

/* Search this area's list of inactive registrations for any that match
 * the prefix in the route node parameter.  Move the registration to
 * the active list and then install a back-reference in the route node.
 *
 * @param area	the IS-IS area to search
 * @param rn	the newly created route node against which inactive
 *		registrations will be compared.
 */
void isis_fae_check_inactive(struct isis_area *area,
			     const struct route_node *const rn)
{
	/* Determine which flex-algo applies here */
	struct isis_route_info *rinfo;
	struct fae_db_node key;
	uint16_t algo;

	rinfo = rn->info;
	if (rinfo == NULL) {
		zlog_debug("%s rinfo is NULL", __func__);
		return;
	}

	if (CHECK_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_SR_ALGO))
		return;

	key.endpoint.ipa_type = PREFIX_FAMILY(&rn->p);
	if (key.endpoint.ipa_type == AF_INET)
		key.endpoint.ipaddr_v4 = rn->p.u.prefix4;
	else if (key.endpoint.ipa_type == AF_INET6)
		key.endpoint.ipaddr_v6 = rn->p.u.prefix6;
	else
		return;

	for (algo = 0; algo < SR_ALGORITHM_COUNT; algo++) {
		if (!rinfo->sr_algo[algo].present)
			continue;
		isis_fae_check_inactive_one(area, rn, &key, algo);
	}
}

static struct route_node *
isis_fae_route_node_match(const struct isis_area *const area,
			  const struct zapi_fae_query *const query)
{
	struct route_node *rn;
	struct prefix endpoint;
	bool found = false;

	ipaddr2prefix(&endpoint, &query->endpoint);
	rn = NULL;
	for (int level = ISIS_LEVEL1; !found && level <= ISIS_LEVELS; level++) {
		struct isis_spftree *spftree;
		struct route_table *route_table;
		struct isis_route_info *rinfo;

		if ((level & area->is_type) == 0)
			continue;

		if (endpoint.family == AF_INET && area->ip_circuits > 0) {
			spftree = area->spftree[SPFTREE_IPV4][level - 1];
			route_table = spftree->route_table;
		} else if (endpoint.family == AF_INET6
			   && area->ipv6_circuits > 0) {
			spftree = area->spftree[SPFTREE_IPV6][level - 1];
			route_table = spftree->route_table;
		} else {
			continue;
		}

		rn = route_node_match(route_table, &endpoint);
		if (rn == NULL)
			continue;

		route_unlock_node(rn);
		do {
			ZLOG_EXTREME("%s checking route node %pFX", __func__,
				     &rn->p);
			rinfo = rn->info;
			if (rinfo && rinfo->sr_algo[query->algorithm].present) {
				found = true;
				route_lock_node(rn);
			} else {
				rn = rn->parent;
			}
		} while (!found && rn);
	}
	return rn;
}

struct isis_area *
isis_fae_area_lookup(const struct zapi_fae_igp_discriminator *const igp_disc)
{
	struct isis_area *area;

	area = isis_area_lookup_by_z_area_id(
		igp_disc->proto_data.isis.z_area_id, igp_disc->vrf_id);
#ifdef EXTREME_FAE_DEBUG
	if (area == NULL)
		zlog_debug("no area z_area_id=%u in vrf %u",
			   igp_disc->proto_data.isis.z_area_id,
			   igp_disc->vrf_id);
#endif
	return area;
}

static int isis_fae_route_info_reg_add(struct isis_route_info *rinfo,
				       struct fae_db_node *node,
				       uint8_t algorithm)
{
	if (rinfo->fae_regs[algorithm] == NULL) {
		rinfo->fae_regs[algorithm] = list_new();
		if (rinfo->fae_regs[algorithm] == NULL)
			return -1;
	}
	listnode_add(rinfo->fae_regs[algorithm], node);
	return 0;
}

/* Delete an FAE database node back-pointer from the route info.
 *
 * @param rinfo		route info to modify
 * @param node		database node to remove from the route info
 * @param algorithm	check endpoint tracking registrations for this Flex-algo
 *
 * @return		true if node deleted, false if the node could not be
 * found.
 */
static bool isis_fae_route_info_reg_del(struct isis_route_info *rinfo,
					const struct fae_db_node *const node,
					uint8_t algorithm)
{
	struct listnode *listnode;

	ZLOG_EXTREME("%s del node %p from route info %p", __func__, node,
		     rinfo);

	if (rinfo->fae_regs[algorithm] == NULL)
		return false;

	listnode = listnode_lookup(rinfo->fae_regs[algorithm], node);
	if (listnode == NULL)
		return false;

	list_delete_node(rinfo->fae_regs[algorithm], listnode);
	if (list_isempty(rinfo->fae_regs[algorithm]))
		list_delete(&rinfo->fae_regs[algorithm]);
	return true;
}

void isis_fae_route_info_reg_move(struct isis_route_info *dst,
				  struct isis_route_info *src)
{
	int i;

	if (CHECK_FLAG(dst->flag, ISIS_ROUTE_FLAG_SR_ALGO))
		return;

	if (CHECK_FLAG(src->flag, ISIS_ROUTE_FLAG_SR_ALGO))
		return;

	for (i = 0; i < SR_ALGORITHM_COUNT; i++) {
		if (src->fae_regs[i] == NULL)
			continue;

		if (dst->fae_regs[i] == NULL) {
			dst->fae_regs[i] = src->fae_regs[i];
			src->fae_regs[i] = NULL;
		} else if (!list_isempty(src->fae_regs[i])) {
			/* concatenate the two lists.  Add new function
			 * to linklist.c?  generic function should
			 * compare flags, cmp() and del() first. */
			dst->fae_regs[i]->tail->next = src->fae_regs[i]->head;
			dst->fae_regs[i]->tail = src->fae_regs[i]->tail;
			dst->fae_regs[i]->count += src->fae_regs[i]->count;
			/* free the src list?  carefully, since everything moved
			 * out */
			memset(&src->fae_regs[i], 0, sizeof(src->fae_regs[i]));
		}
	}
}

void isis_fae_route_info_reg_deactivate(struct isis_area *area,
					struct isis_route_info *rinfo,
					uint8_t algorithm)
{
	struct list *list;
	struct listnode *node;
	struct listnode *next;
	struct fae_db_node *dbnode;

	if (CHECK_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_SR_ALGO))
		return;

	if (rinfo->fae_regs[algorithm] == NULL)
		return;

	list = rinfo->fae_regs[algorithm];
	for (ALL_LIST_ELEMENTS(list, node, next, dbnode)) {
		struct fae_db_node *res;
		char epstr[INET6_ADDRSTRLEN];

		ipaddr2str(&dbnode->endpoint, epstr, sizeof(epstr));
		ZLOG_EXTREME("%s deactivate FAE registration %s algo %d",
			     __func__, epstr, algorithm);
		res = fae_db_move(&area->fae.inactive[algorithm],
				  &area->fae.active[algorithm], dbnode);
		assert(res == dbnode);
		if (res != dbnode)
			zlog_err("%s FAE registration could not be deactivated",
				 __func__);
		else
			list_delete_node(rinfo->fae_regs[algorithm], node);
	}
	list_delete(&rinfo->fae_regs[algorithm]);
}

/* Iterate through the FAE registrations and move each back to the
 * "no-node" table.  Free the fae_regs list.
 *
 * @param rinfo		The struct route_info to clean up.
 */
void isis_fae_route_info_delete(struct isis_area *area,
				struct isis_route_info *rinfo)
{
	int i;


	if (CHECK_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_SR_ALGO))
		return;

	for (i = 0; i < SR_ALGORITHM_COUNT; i++) {
		if (rinfo->fae_regs[i] == NULL)
			continue;

		isis_fae_route_info_reg_deactivate(area, rinfo, i);
	}
}

static void
isis_fae_route_node_reg_del(struct isis_area *area,
			    const struct fae_db_node *const node,
			    const struct zapi_fae_query *const query)
{
	struct route_node *rn;

	rn = isis_fae_route_node_match(area, query);
	if (rn) {
		struct isis_route_info *rinfo;

		rinfo = rn->info;
		if (CHECK_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_SR_ALGO) == 0) {
			isis_fae_route_info_reg_del(rinfo, node,
						    query->algorithm);
		}
		route_unlock_node(rn);
	}
}

void isis_fae_init(void)
{
	isis_fae_cli_init();
}

#endif /* !FABRICD */
