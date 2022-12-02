/*
 * Zebra GR related helper functions.
 *
 * Portions:
 *	Copyright (C) 2019 VMware, Inc.
 *	et al.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <libgen.h>

#include "lib/prefix.h"
#include "lib/command.h"
#include "lib/if.h"
#include "lib/thread.h"
#include "lib/stream.h"
#include "lib/memory.h"
#include "lib/table.h"
#include "lib/network.h"
#include "lib/sockunion.h"
#include "lib/log.h"
#include "lib/zclient.h"
#include "lib/privs.h"
#include "lib/network.h"
#include "lib/buffer.h"
#include "lib/nexthop.h"
#include "lib/vrf.h"
#include "lib/libfrr.h"
#include "lib/sockopt.h"

#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/zapi_msg.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_GR, "GR");

/*
 * Forward declaration.
 */
static struct zserv *zebra_gr_find_stale_client(struct zserv *client);
static void zebra_gr_route_stale_delete_timer_expiry(struct thread *thread);
static int32_t zebra_gr_delete_stale_routes(struct client_gr_info *info);
static void zebra_gr_process_client_stale_routes(struct zserv *client,
						 vrf_id_t vrf_id);

/*
 * Debug macros.
 */
#define LOG_GR(msg, ...)                                                       \
	do {                                                                   \
		if (IS_ZEBRA_DEBUG_EVENT)                                      \
			zlog_debug(msg, ##__VA_ARGS__);                        \
	} while (0)


/*
 * Client connection functions
 */

/*
 * Function to clean all the stale clients,
 * function will also clean up all per instance
 * capabilities that are exchanged.
 */
void zebra_gr_stale_client_cleanup(struct list *client_list)
{
	struct listnode *node, *nnode;
	struct zserv *s_client = NULL;
	struct client_gr_info *info, *ninfo;

	/* Find the stale client */
	for (ALL_LIST_ELEMENTS(client_list, node, nnode, s_client)) {

		LOG_GR("%s: Stale client %s is being deleted", __func__,
		       zebra_route_string(s_client->proto));

		TAILQ_FOREACH_SAFE (info, &s_client->gr_info_queue, gr_info,
				    ninfo) {

			/* Cancel the stale timer */
			if (info->t_stale_removal != NULL) {
				THREAD_OFF(info->t_stale_removal);
				info->t_stale_removal = NULL;
				/* Process the stale routes */
				thread_execute(
				    zrouter.master,
				    zebra_gr_route_stale_delete_timer_expiry,
				    info, 1);
			}
		}
	}
}

/*
 * A helper function to create client info.
 */
static struct client_gr_info *zebra_gr_client_info_create(struct zserv *client)
{
	struct client_gr_info *info;

	info = XCALLOC(MTYPE_ZEBRA_GR, sizeof(struct client_gr_info));

	TAILQ_INSERT_TAIL(&(client->gr_info_queue), info, gr_info);
	return info;
}

/*
 * A helper function to delete and destroy client info.
 */
static void zebra_gr_client_info_delte(struct zserv *client,
				       struct client_gr_info *info)
{
	TAILQ_REMOVE(&(client->gr_info_queue), info, gr_info);

	THREAD_OFF(info->t_stale_removal);

	XFREE(MTYPE_ZEBRA_GR, info->current_prefix);

	LOG_GR("%s: Instance info is being deleted for client %s", __func__,
	       zebra_route_string(client->proto));

	/* Delete all the stale routes. */
	info->do_delete = true;
	zebra_gr_delete_stale_routes(info);

	XFREE(MTYPE_ZEBRA_GR, info);
}

/*
 * Function to handle client when it disconnect.
 */
int32_t zebra_gr_client_disconnect(struct zserv *client)
{
	struct zserv *stale_client;
	struct timeval tv;
	struct client_gr_info *info = NULL;

	/* Find the stale client */
	stale_client = zebra_gr_find_stale_client(client);

	/*
	 * We should never be here.
	 */
	if (stale_client) {
		LOG_GR("%s: Stale client %s exist, we should not be here!",
		       __func__, zebra_route_string(client->proto));
		assert(0);
	}

	client->restart_time = monotime(&tv);

	/* For all the GR instance start the stale removal timer. */
	TAILQ_FOREACH (info, &client->gr_info_queue, gr_info) {
		if (ZEBRA_CLIENT_GR_ENABLED(info->capabilities)
		    && (info->t_stale_removal == NULL)) {
			thread_add_timer(
				zrouter.master,
				zebra_gr_route_stale_delete_timer_expiry, info,
				info->stale_removal_time,
				&info->t_stale_removal);
			info->current_afi = AFI_IP;
			info->stale_client_ptr = client;
			info->stale_client = true;
			LOG_GR("%s: Client %s Stale timer update to %d",
			       __func__, zebra_route_string(client->proto),
			       info->stale_removal_time);
		}
	}

	listnode_add(zrouter.stale_client_list, client);

	return 0;
}

/*
 * Function to delete stale client
 */
static void zebra_gr_delete_stale_client(struct client_gr_info *info)
{
	struct client_gr_info *bgp_info;
	struct zserv *s_client = NULL;

	s_client = info->stale_client_ptr;

	if (!s_client || !info->stale_client)
		return;

	/*
	 * If there are bgp instances with the stale delete timer pending
	 * then stale client is not deleted
	 */
	if ((s_client->gr_instance_count > 0) && info->gr_enable)
		s_client->gr_instance_count--;

	TAILQ_REMOVE(&(s_client->gr_info_queue), info, gr_info);

	LOG_GR("%s: Client %s gr count %d", __func__,
	       zebra_route_string(s_client->proto),
	       s_client->gr_instance_count);

	TAILQ_FOREACH (bgp_info, &s_client->gr_info_queue, gr_info) {
		if (bgp_info->t_stale_removal != NULL)
			return;
	}

	LOG_GR("%s: Client %s is being deleted", __func__,
	       zebra_route_string(s_client->proto));

	TAILQ_INIT(&(s_client->gr_info_queue));
	listnode_delete(zrouter.stale_client_list, s_client);
	if (info->stale_client)
		zserv_client_delete(s_client);
	XFREE(MTYPE_ZEBRA_GR, info);
}

/*
 * Function to find stale client.
 */
static struct zserv *zebra_gr_find_stale_client(struct zserv *client)
{
	struct listnode *node, *nnode;
	struct zserv *stale_client;

	/* Find the stale client */
	for (ALL_LIST_ELEMENTS(zrouter.stale_client_list, node, nnode,
			       stale_client)) {
		if (client->proto == stale_client->proto
		    && client->instance == stale_client->instance) {
			return stale_client;
		}
	}

	return NULL;
}

/*
 * Function to handle reconnect of client post restart.
 */
void zebra_gr_client_reconnect(struct zserv *client)
{
	struct listnode *node, *nnode;
	struct zserv *old_client = NULL;
	struct client_gr_info *info = NULL;

	/* Find the stale client */
	for (ALL_LIST_ELEMENTS(zrouter.stale_client_list, node, nnode,
			       old_client)) {
		if (client->proto == old_client->proto
		    && client->instance == old_client->instance)
			break;
	}

	/* Copy the timers */
	if (!old_client)
		return;

	client->gr_instance_count = old_client->gr_instance_count;
	client->restart_time = old_client->restart_time;

	LOG_GR("%s : old client %s, gr_instance_count %d", __func__,
	       zebra_route_string(old_client->proto),
	       old_client->gr_instance_count);

	if (TAILQ_FIRST(&old_client->gr_info_queue)) {
		TAILQ_CONCAT(&client->gr_info_queue, &old_client->gr_info_queue,
			     gr_info);
		TAILQ_INIT(&old_client->gr_info_queue);
	}

	TAILQ_FOREACH (info, &client->gr_info_queue, gr_info) {
		info->stale_client_ptr = client;
		info->stale_client = false;
	}

	/* Delete the stale client */
	listnode_delete(zrouter.stale_client_list, old_client);
	/* Delete old client */
	zserv_client_delete(old_client);
}

/*
 * Functions to deal with capabilities
 */

/*
 * Update the graceful restart information
 * for the client instance.
 * This function handles all the capabilities that are received.
 */
static void zebra_client_update_info(struct zserv *client, struct zapi_cap *api)
{
	struct client_gr_info *info = NULL;

	/* Find the bgp information for the specified vrf id */
	TAILQ_FOREACH (info, &client->gr_info_queue, gr_info) {
		if (info->vrf_id == api->vrf_id)
			break;
	}


	/*
	 * If the command is delete, then cancel the stale timer and
	 * delete the bgp info
	 */
	switch (api->cap) {
	case ZEBRA_CLIENT_GR_DISABLE:
		if (!info)
			return;

		LOG_GR("%s: Client %s instance GR disabled count %d", __func__,
		       zebra_route_string(client->proto),
		       client->gr_instance_count);

		if ((info->gr_enable) && (client->gr_instance_count > 0))
			client->gr_instance_count--;

		zebra_gr_client_info_delte(client, info);
		break;
	case ZEBRA_CLIENT_GR_CAPABILITIES:
		/* Allocate bgp info */
		if (!info)
			info = zebra_gr_client_info_create(client);

		/* Update other parameters */
		if (!info->gr_enable) {
			client->gr_instance_count++;

			LOG_GR("%s: Cient %s GR enabled count %d", __func__,
			       zebra_route_string(client->proto),
			       client->gr_instance_count);

			info->capabilities = api->cap;
			info->stale_removal_time = api->stale_removal_time;
			info->vrf_id = api->vrf_id;
			info->gr_enable = true;
		}
		break;
	case ZEBRA_CLIENT_RIB_STALE_TIME:
		LOG_GR("%s: Client %s stale time update event", __func__,
		       zebra_route_string(client->proto));

		/* Update the stale removal timer */
		if (info && info->t_stale_removal == NULL) {

			LOG_GR("%s: Stale time: %d is now update to: %d",
			       __func__, info->stale_removal_time,
			       api->stale_removal_time);

			info->stale_removal_time = api->stale_removal_time;
		}

		break;
	case ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE:
		LOG_GR(
		   "%s: Client %s route update complete for AFI %d, SAFI %d",
		   __func__, zebra_route_string(client->proto), api->afi,
		   api->safi);
		if (info)
			info->route_sync[api->afi][api->safi] = true;
		break;
	case ZEBRA_CLIENT_ROUTE_UPDATE_PENDING:
		LOG_GR("%s: Client %s route update pending for AFI %d, SAFI %d",
		       __func__, zebra_route_string(client->proto), api->afi,
		       api->safi);
		if (info)
			info->af_enabled[api->afi][api->safi] = true;
		break;
	}
}

/*
 * Handler for capabilities that are received from client.
 */
static void zebra_client_capabilities_handler(struct zserv *client,
					      struct zapi_cap *api)
{
	switch (api->cap) {
	case ZEBRA_CLIENT_GR_CAPABILITIES:
	case ZEBRA_CLIENT_ROUTE_UPDATE_PENDING:
	case ZEBRA_CLIENT_GR_DISABLE:
	case ZEBRA_CLIENT_RIB_STALE_TIME:
		/*
		 * For all the cases we need to update the client info.
		 */
		zebra_client_update_info(client, api);
		break;
	case ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE:
		/*
		 * After client info has been updated delete all
		 * stale routes
		 */
		zebra_client_update_info(client, api);
		zebra_gr_process_client_stale_routes(client, api->vrf_id);
		break;
	}
}

/*
 * Function to decode and call appropriate functions
 * to handle client capabilities.
 */
void zread_client_capabilities(ZAPI_HANDLER_ARGS)
{
	struct zapi_cap api;
	struct stream *s;

	s = msg;

	if (zapi_capabilities_decode(s, &api)) {
		LOG_GR("%s: Error in reading capabilities for client %s",
		       __func__, zebra_route_string(client->proto));
		return;
	}

	/* GR only for dynamic clients */
	if (client->proto <= ZEBRA_ROUTE_CONNECT) {
		LOG_GR("%s: GR capabilities for client %s not supported",
		       __func__, zebra_route_string(client->proto));
		return;
	}
	/* Call the capabilities handler */
	zebra_client_capabilities_handler(client, &api);
}


/*
 * Stale route handling
 */

/*
 * Delete all the stale routes that have not been refreshed
 * post restart.
 */
static void zebra_gr_route_stale_delete_timer_expiry(struct thread *thread)
{
	struct client_gr_info *info;
	int32_t cnt = 0;
	struct zserv *client;

	info = THREAD_ARG(thread);
	info->t_stale_removal = NULL;
	client = (struct zserv *)info->stale_client_ptr;

	/* Set the flag to indicate all stale route deletion */
	if (thread->u.val == 1)
		info->do_delete = true;

	cnt = zebra_gr_delete_stale_routes(info);

	/* Restart the timer */
	if (cnt > 0) {
		LOG_GR("%s: Client %s processed %d routes. Start timer again",
		       __func__, zebra_route_string(client->proto), cnt);

		thread_add_timer(zrouter.master,
				 zebra_gr_route_stale_delete_timer_expiry, info,
				 ZEBRA_DEFAULT_STALE_UPDATE_DELAY,
				 &info->t_stale_removal);
	} else {
		/* No routes to delete for the VRF */
		LOG_GR("%s: Client %s all stale routes processed", __func__,
		       zebra_route_string(client->proto));

		XFREE(MTYPE_ZEBRA_GR, info->current_prefix);
		info->current_afi = 0;
		zebra_gr_delete_stale_client(info);
	}
}


/*
 * Function to process to check if route entry is stale
 * or has been updated.
 */
static void zebra_gr_process_route_entry(struct zserv *client,
					 struct route_node *rn,
					 struct route_entry *re)
{
	if ((client == NULL) || (rn == NULL) || (re == NULL))
		return;

	/* If the route is not refreshed after restart, delete the entry */
	if (re->uptime < client->restart_time) {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("%s: Client %s stale route %pFX is deleted",
				   __func__, zebra_route_string(client->proto),
				   &rn->p);
		rib_delnode(rn, re);
	}
}

/*
 * This function walks through the route table for all vrf and deletes
 * the stale routes for the restarted client specified by the protocol
 * type
 */
static int32_t zebra_gr_delete_stale_route(struct client_gr_info *info,
					   struct zebra_vrf *zvrf)
{
	struct route_node *rn, *curr;
	struct route_entry *re;
	struct route_entry *next;
	struct route_table *table;
	int32_t n = 0;
	afi_t afi, curr_afi;
	uint8_t proto;
	uint16_t instance;
	struct zserv *s_client;

	if ((info == NULL) || (zvrf == NULL))
		return -1;

	s_client = info->stale_client_ptr;
	if (s_client == NULL) {
		LOG_GR("%s: Stale client not present", __func__);
		return -1;
	}

	proto = s_client->proto;
	instance = s_client->instance;
	curr_afi = info->current_afi;

	LOG_GR("%s: Client %s stale routes are being deleted", __func__,
	       zebra_route_string(proto));

	/* Process routes for all AFI */
	for (afi = curr_afi; afi < AFI_MAX; afi++) {
		table = zvrf->table[afi][SAFI_UNICAST];

		if (table) {
			/*
			 * If the current prefix is NULL then get the first
			 * route entry in the table
			 */
			if (info->current_prefix == NULL) {
				rn = route_top(table);
				if (rn == NULL)
					continue;
				curr = rn;
			} else
				/* Get the next route entry */
				curr = route_table_get_next(
					table, info->current_prefix);

			for (rn = curr; rn; rn = srcdest_route_next(rn)) {
				RNODE_FOREACH_RE_SAFE (rn, re, next) {
					if (CHECK_FLAG(re->status,
						       ROUTE_ENTRY_REMOVED))
						continue;
					/* If the route refresh is received
					 * after restart then do not delete
					 * the route
					 */
					if (re->type == proto
					    && re->instance == instance) {
						zebra_gr_process_route_entry(
							s_client, rn, re);
						n++;
					}

					/* If the max route count is reached
					 * then timer thread will be restarted
					 * Store the current prefix and afi
					 */
					if ((n >= ZEBRA_MAX_STALE_ROUTE_COUNT)
					    && (info->do_delete == false)) {
						info->current_afi = afi;
						info->current_prefix = XCALLOC(
							MTYPE_ZEBRA_GR,
							sizeof(struct prefix));
						prefix_copy(
							info->current_prefix,
							&rn->p);
						return n;
					}
				}
			}
		}
		/*
		 * Reset the current prefix to indicate processing completion
		 * of the current AFI
		 */
		XFREE(MTYPE_ZEBRA_GR, info->current_prefix);
	}
	return 0;
}

/*
 * Delete the stale routes when client is restarted and routes are not
 * refreshed within the stale timeout
 */
static int32_t zebra_gr_delete_stale_routes(struct client_gr_info *info)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	uint64_t cnt = 0;

	if (info == NULL)
		return -1;

	/* Get the current VRF */
	vrf = vrf_lookup_by_id(info->vrf_id);
	if (vrf == NULL) {
		LOG_GR("%s: Invalid VRF %d", __func__, info->vrf_id);
		return -1;
	}

	zvrf = vrf->info;
	if (zvrf == NULL) {
		LOG_GR("%s: Invalid VRF entry %d", __func__, info->vrf_id);
		return -1;
	}

	cnt = zebra_gr_delete_stale_route(info, zvrf);
	return cnt;
}

/*
 * This function checks if route update for all AFI, SAFI is completed
 * and cancels the stale timer
 */
static void zebra_gr_process_client_stale_routes(struct zserv *client,
						 vrf_id_t vrf_id)
{
	struct client_gr_info *info = NULL;
	afi_t afi;
	safi_t safi;

	TAILQ_FOREACH (info, &client->gr_info_queue, gr_info) {
		if (info->vrf_id == vrf_id)
			break;
	}

	if (info == NULL)
		return;

	/* Check if route update completed for all AFI, SAFI */
	FOREACH_AFI_SAFI_NSF (afi, safi) {
		if (info->af_enabled[afi][safi]) {
			if (!info->route_sync[afi][safi]) {
				LOG_GR("%s: Client %s route update not completed for AFI %d, SAFI %d",
				       __func__,
				       zebra_route_string(client->proto), afi,
				       safi);
				return;
			}
		}
	}

	/*
	 * Route update completed for all AFI, SAFI
	 * Cancel the stale timer and process the routes
	 */
	if (info->t_stale_removal) {
		LOG_GR("%s: Client %s canceled stale delete timer vrf %d",
		       __func__, zebra_route_string(client->proto),
		       info->vrf_id);
		THREAD_OFF(info->t_stale_removal);
		thread_execute(zrouter.master,
			       zebra_gr_route_stale_delete_timer_expiry, info,
			       0);
	}
}
