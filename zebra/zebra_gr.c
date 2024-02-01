// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra GR related helper functions.
 *
 * Portions:
 *	Copyright (C) 2019 VMware, Inc.
 *	et al.
 */

#include <zebra.h>
#include <libgen.h>

#include "lib/prefix.h"
#include "lib/command.h"
#include "lib/if.h"
#include "frrevent.h"
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
#include "zebra/zebra_trace.h"
#include "zebra/zebra_vxlan.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_GR, "GR");

struct zebra_gr_afi_clean {
	struct client_gr_info *info;
	afi_t afi;
	uint8_t proto;
	uint8_t instance;
	time_t restart_time;
	struct event *t_gac;
	time_t update_pending_time;
};

/*
 * Forward declaration.
 */
static struct zserv *zebra_gr_find_stale_client(uint8_t proto, uint16_t instance);
static void zebra_gr_route_stale_delete_timer_expiry(struct event *event);
static int32_t zebra_gr_delete_stale_routes(struct client_gr_info *info);
static void zebra_gr_process_client_stale_routes(struct zserv *client,
						 struct client_gr_info *info);
static void zebra_gr_delete_stale_route_table_afi(struct event *event);
static bool zebra_gr_unicast_stale_route_delete(struct route_table *table,
						struct zebra_gr_afi_clean *gac, bool no_max);

/*
 * Debug macros.
 */
#define LOG_GR(msg, ...)                                                                          \
	do {                                                                                      \
		if (IS_ZEBRA_DEBUG_EVENT)                                                         \
			zlog_debug("GR " msg, ##__VA_ARGS__);                                     \
	} while (0)

/*
 * Client connection functions
 */

/*
 * Function to clean all the stale clients,
 * function will also clean up all per instance
 * capabilities that are exchanged.
 */
void zebra_gr_stale_client_cleanup(void)
{
	struct zserv *s_client = NULL;
	struct client_gr_info *info, *ninfo;

	/* Find the stale client */
	frr_each_safe (zserv_stale_client_list, &zrouter.stale_client_list, s_client) {
		LOG_GR("%s: Stale client %s is being deleted", __func__,
		       zebra_route_string(s_client->proto));

		TAILQ_FOREACH_SAFE (info, &s_client->gr_info_queue, gr_info,
				    ninfo) {

			/* Cancel the stale timer */
			if (info->t_stale_removal != NULL) {
				event_cancel(&info->t_stale_removal);
				info->do_delete = true;
				info->stale_client = true;
				/* Process the stale routes */
				event_execute(
					zrouter.master,
					zebra_gr_route_stale_delete_timer_expiry,
					info, 0, NULL);
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

	info->stale_client_ptr = client;

	TAILQ_INSERT_TAIL(&(client->gr_info_queue), info, gr_info);
	info->client_ptr = client;
	return info;
}

/*
 * A helper function to delete and destroy client info.
 */
static void zebra_gr_client_info_delete(struct zserv *client,
					struct client_gr_info *info)
{
	struct vrf *vrf = vrf_lookup_by_id(info->vrf_id);

	TAILQ_REMOVE(&(client->gr_info_queue), info, gr_info);

	event_cancel(&info->t_stale_removal);

	LOG_GR("%s: Instance info is being deleted for client %s vrf %s(%u)",
	       __func__, zebra_route_string(client->proto), VRF_LOGNAME(vrf),
	       info->vrf_id);

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
	stale_client = zebra_gr_find_stale_client(client->proto, client->instance);

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
			struct vrf *vrf = vrf_lookup_by_id(info->vrf_id);

			info->stale_client_ptr = client;
			info->stale_client = true;
			event_add_timer(zrouter.master, zebra_gr_route_stale_delete_timer_expiry,
					info, info->stale_removal_time, &info->t_stale_removal);
			LOG_GR("%s: Client %s vrf %s(%u) Stale timer update to %d",
			       __func__, zebra_route_string(client->proto),
			       VRF_LOGNAME(vrf), info->vrf_id,
			       info->stale_removal_time);
		}
	}

	zserv_stale_client_list_add_tail(&zrouter.stale_client_list, client);

	return 0;
}

/*
 * Function to delete stale client
 */
static void zebra_gr_delete_stale_client(struct client_gr_info *info)
{
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

	if (s_client->gr_instance_count > 0) {
		/* We removed this instance's GR info from the queue; free it now. */
		XFREE(MTYPE_ZEBRA_GR, info);
		return;
	}

	LOG_GR("%s: Stale client %s is being deleted", __func__,
	       zebra_route_string(s_client->proto));

	TAILQ_INIT(&(s_client->gr_info_queue));
	zserv_stale_client_list_del(&zrouter.stale_client_list, s_client);
	if (info->stale_client)
		zserv_client_delete(s_client);
	XFREE(MTYPE_ZEBRA_GR, info);
}

/*
 * Function to find stale client.
 */
static struct zserv *zebra_gr_find_stale_client(uint8_t proto, uint16_t instance)
{
	struct zserv *stale_client;

	/* Find the stale client */
	frr_each (zserv_stale_client_list, &zrouter.stale_client_list, stale_client) {
		if (stale_client->proto == proto && stale_client->instance == instance)
			return stale_client;
	}

	return NULL;
}

/*
 * Function to handle reconnect of client post restart.
 */
void zebra_gr_client_reconnect(struct zserv *client)
{
	struct zserv *old_client = NULL;
	struct client_gr_info *info = NULL;

	/* Find the stale client */
	old_client = zebra_gr_find_stale_client(client->proto, client->instance);

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
	zserv_stale_client_list_del(&zrouter.stale_client_list, old_client);
	/* Delete old client */
	zserv_client_delete(old_client);
}

/*
 * Functions to deal with capabilities
 */

void zebra_gr_client_final_shutdown(struct zserv *client)
{
	struct client_gr_info *info;

	while (!TAILQ_EMPTY(&client->gr_info_queue)) {
		info = TAILQ_FIRST(&client->gr_info_queue);
		zebra_gr_client_info_delete(client, info);
	}
}

/*
 * Function to decode and call appropriate functions
 * to handle client capabilities.
 */
void zread_client_capabilities(ZAPI_HANDLER_ARGS)
{
	struct zapi_cap api;
	struct client_gr_info *info = NULL;
	struct stream *s;
	struct vrf *vrf;

	s = msg;

	if (zapi_capabilities_decode(s, &api)) {
		LOG_GR("%s: Error in reading capabilities for client %s",
		       __func__, zebra_route_string(client->proto));
		return;
	}

	vrf = vrf_lookup_by_id(api.vrf_id);

	/*
	 * If this ever matters uncomment and add safi to the
	 * arrays as needed to track
	 */
	if (api.safi != SAFI_UNICAST && api.safi != SAFI_EVPN)
		return;

	/* GR only for dynamic clients */
	if (client->proto <= ZEBRA_ROUTE_LOCAL) {
		LOG_GR("%s: GR capabilities for client %s not supported",
		       __func__, zebra_route_string(client->proto));
		return;
	}

	/* Find the bgp information for the specified vrf id */
	TAILQ_FOREACH (info, &client->gr_info_queue, gr_info) {
		if (info->vrf_id == api.vrf_id)
			break;
	}

	/*
	 * If the command is delete, then cancel the stale timer and
	 * delete the bgp info
	 */
	switch (api.cap) {
	case ZEBRA_CLIENT_GR_DISABLE:
		if (!info)
			return;

		LOG_GR("%s: Client %s instance GR disabled count %d", __func__,
		       zebra_route_string(client->proto),
		       client->gr_instance_count);

		frrtrace(3, frr_zebra, gr_client_capability, api.cap, api.vrf_id,
			 client->gr_instance_count);

		if ((info->gr_enable) && (client->gr_instance_count > 0))
			client->gr_instance_count--;

		zebra_gr_client_info_delete(client, info);
		break;
	case ZEBRA_CLIENT_GR_CAPABILITIES:
		/* Allocate bgp info */
		if (!info)
			info = zebra_gr_client_info_create(client);

		/* Update other parameters */
		if (!info->gr_enable) {
			client->gr_instance_count++;

			if (!zrouter.gr_stale_cleanup_time_recorded) {
				/*
				 * Record the time at which GR started.
				 * This timestamp will be later used to
				 * cleanup stale routes and EVPN entries.
				 */
				client->restart_time = monotime(NULL);
				zrouter.gr_stale_cleanup_time_recorded = true;
			}

			LOG_GR("%s: Cient %s vrf %s(%u) GR enabled count %d",
			       __func__, zebra_route_string(client->proto),
			       VRF_LOGNAME(vrf), api.vrf_id,
			       client->gr_instance_count);

			frrtrace(3, frr_zebra, gr_client_capability, api.cap, api.vrf_id,
				 client->gr_instance_count);

			info->capabilities = api.cap;
			info->stale_removal_time = api.stale_removal_time;
			info->vrf_id = api.vrf_id;
			info->gr_enable = true;
		}
		break;
	case ZEBRA_CLIENT_RIB_STALE_TIME:
		LOG_GR("%s: Client %s stale time update event", __func__,
		       zebra_route_string(client->proto));

		/* Update the stale removal timer */
		if (info && info->t_stale_removal == NULL) {

			LOG_GR("%s: vrf %s(%u) Stale time: %d is now update to: %d",
			       __func__, VRF_LOGNAME(vrf), info->vrf_id,
			       info->stale_removal_time,
			       api.stale_removal_time);

			frrtrace(3, frr_zebra, gr_client_stale_time, api.cap, api.vrf_id,
				 api.stale_removal_time);

			info->stale_removal_time = api.stale_removal_time;
		}

		break;
	case ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE:
		if (!info) {
			LOG_GR("%s: Client %s route update complete for AFI %d, SAFI %d, no Graceful Restart communication, returning",
			       __func__, zebra_route_string(client->proto),
			       api.afi, api.safi);
			return;
		}

		LOG_GR("%s: Client %s vrf %s(%u) route update complete for AFI %d, SAFI %d",
		       __func__, zebra_route_string(client->proto),
		       VRF_LOGNAME(vrf), info->vrf_id, api.afi, api.safi);

		frrtrace(4, frr_zebra, gr_client_update, api.cap, info->vrf_id, api.afi, api.safi);

		info->route_sync[api.afi] = true;

		/*
		 * Schedule for after anything already in the meta Q
		 */
		rib_add_gr_run(api.afi, api.vrf_id, client->proto, client->instance,
			       client->restart_time, client->update_pending_time, false);
		zebra_gr_process_client_stale_routes(client, info);
		break;
	case ZEBRA_CLIENT_ROUTE_UPDATE_PENDING:
		if (!info) {
			LOG_GR("%s: Client %s route update pending for AFI %d, SAFI %d",
			       __func__, zebra_route_string(client->proto),
			       api.afi, api.safi);
		} else {
			LOG_GR("%s: Client %s vrf %s(%u) route update pending for AFI %d, SAFI %d",
			       __func__, zebra_route_string(client->proto),
			       VRF_LOGNAME(vrf), info->vrf_id, api.afi,
			       api.safi);

			frrtrace(4, frr_zebra, gr_client_update, api.cap, info->vrf_id, api.afi,
				 api.safi);

			info->af_enabled[api.afi] = true;
			if (!zrouter.gr_update_pending_time_recorded) {
				client->update_pending_time = monotime(NULL);
				zrouter.gr_update_pending_time_recorded = true;
			}
		}
		break;
	}
}

/*
 * Stale route handling
 */

static bool zebra_gr_enabled_for_vrf(struct zserv *client, vrf_id_t vrf_id)
{
	struct client_gr_info *info = NULL;

	TAILQ_FOREACH (info, &client->gr_info_queue, gr_info) {
		if (info->vrf_id == vrf_id && info->gr_enable)
			return true;
	}

	return false;
}

/* Cleans up stale ipv4 and ipv6 unicast routes that
 * were imported from default EVPN VRF into GR disabled
 * destination VRF and installed in kernel in that
 * destination VRF.
 */
static void zebra_gr_cleanup_of_non_gr_vrf(struct zebra_gr_afi_clean *gac)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	struct route_table *table;
	afi_t afi;
	struct zserv *client = zserv_find_client(gac->proto, gac->instance);

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		zvrf = vrf->info;
		if (!zvrf)
			continue;

		/*
		 * Skip if this is default EVPN VRF
		 */
		if (zvrf == zebra_vrf_get_evpn())
			continue;

		/*
		 * If GR is enabled for this VRF, then zebra
		 * would have done the stale cleanup when BGP
		 * indicated UPDATE_COMPLETE for this VRF for
		 * all gr-enabled afi-safis. So skip such VRFs.
		 */
		if (zebra_gr_enabled_for_vrf(client, vrf->vrf_id))
			continue;

		for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
			table = zvrf->table[afi][SAFI_UNICAST];
			if (!table)
				continue;

			LOG_GR("EVPN-GR: Cleaning up imported stale afi:%d unicast routes in %s(%u)",
			       afi, vrf->name, vrf->vrf_id);

			/*
			 * Cleanup stale unicast routes
			 */
			zebra_gr_unicast_stale_route_delete(table, gac, true);
		}
	}
}

/*
 * Delete all the stale routes that have not been refreshed
 * post restart.
 */
static void zebra_gr_route_stale_delete_timer_expiry(struct event *event)
{
	struct client_gr_info *info = EVENT_ARG(event);
	struct zserv *client;
	struct vrf *vrf = vrf_lookup_by_id(info->vrf_id);

	info->t_stale_removal = NULL;
	if (zrouter.graceful_restart)
		client = (struct zserv *)info->client_ptr;
	else
		client = (struct zserv *)info->stale_client_ptr;

	LOG_GR("%s: Cleaning up stale routes for client %s vrf %s(%u) ", __func__,
	       zebra_route_string(client->proto), VRF_LOGNAME(vrf), info->vrf_id);

	zebra_gr_delete_stale_routes(info);

	/* If we're shutting down, free synchronously to avoid leaks. */
	if (zebra_router_in_shutdown()) {
		zebra_gr_delete_stale_client(info);
		return;
	}

	/* Schedule GR info and stale client deletion */
	rib_add_gr_run(0, info->vrf_id, client->proto, client->instance, 0, 0, true);
}


/*
 * Function to process to check if route entry is stale
 * or has been updated.
 *
 * Returns true when a node is deleted else false
 */
static bool zebra_gr_process_route_entry(struct route_node *rn,
					 struct route_entry *re,
					 time_t compare_time, uint8_t proto)
{
	struct nexthop *nexthop;

	/* If the route is not refreshed after restart, delete the entry */
	if (re->uptime < compare_time) {
		LOG_GR("GR %s: Client %s stale route %pFX is deleted", __func__,
		       zebra_route_string(proto), &rn->p);
		SET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
		for (ALL_NEXTHOPS(re->nhe->nhg, nexthop))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);

		rib_delnode(rn, re);

		return true;
	}

	return false;
}

static void zebra_gr_delete_stale_info_client(struct event *event)
{
	struct zebra_gr_afi_clean *gac = EVENT_ARG(event);

	if (gac->info->stale_client)
		zebra_gr_delete_stale_client(gac->info);

	XFREE(MTYPE_ZEBRA_GR, gac);
}

static bool zebra_gr_unicast_stale_route_delete(struct route_table *table,
						struct zebra_gr_afi_clean *gac, bool no_max)
{
	struct route_node *rn;
	struct route_entry *re, *next;
	uint32_t n = 0;

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		RNODE_FOREACH_RE_SAFE (rn, re, next) {
			if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
				continue;

			/* If the route refresh is received
			 * after restart then do not delete
			 * the route
			 */

			if (re->type == gac->proto &&
			    re->instance == gac->instance &&
			    zebra_gr_process_route_entry(rn, re,
							 gac->restart_time,
							 gac->proto))
				n++;

			/* If the max route count is reached
			 * then timer thread will be restarted
			 * Store the current prefix and afi
			 */
			if ((n >= ZEBRA_MAX_STALE_ROUTE_COUNT) &&
			    (gac->info->do_delete == false) && !no_max) {
				LOG_GR("GR: Stale routes deleted %d. Restarting timer.", n);
				event_add_timer(
					zrouter.master,
					zebra_gr_delete_stale_route_table_afi,
					gac, ZEBRA_DEFAULT_STALE_UPDATE_DELAY,
					&gac->t_gac);
				return true;
			}
		}
	}
	return false;
}

static void zebra_gr_delete_stale_route_table_afi(struct event *event)
{
	struct zebra_gr_afi_clean *gac = EVENT_ARG(event);
	struct route_table *table;
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(gac->info->vrf_id);

	if (!zvrf)
		goto done;

	LOG_GR("GR: Deleting stale routes for %s, afi %d", zvrf->vrf->name, gac->afi);

	frrtrace(2, frr_zebra, gr_delete_stale_route_table_afi, zvrf->vrf->name, gac->afi);

	if (gac->afi == AFI_L2VPN && zvrf == zebra_vrf_get_evpn()) {
		zebra_gr_cleanup_of_non_gr_vrf(gac);
		zebra_evpn_stale_entries_cleanup(gac->update_pending_time);
		goto done;
	}

	table = zvrf->table[gac->afi][SAFI_UNICAST];
	if (!table)
		goto done;

	/* Return if timer was restarted */
	if (zebra_gr_unicast_stale_route_delete(table, gac, false))
		return;

done:
	XFREE(MTYPE_ZEBRA_GR, gac);
}

/*
 * This function walks through the route table for all vrf and deletes
 * the stale routes for the restarted client specified by the protocol
 * type
 */
static int32_t zebra_gr_delete_stale_route(struct client_gr_info *info,
					   struct zebra_vrf *zvrf)
{
	afi_t afi;
	uint8_t proto;
	uint16_t instance;
	struct zserv *s_client;
	struct zserv *client;
	time_t restart_time;

	if ((info == NULL) || (zvrf == NULL))
		return -1;

	if (zrouter.graceful_restart) {
		client = info->client_ptr;
		if (client == NULL) {
			LOG_GR("%s: client not present", __func__);
			return -1;
		}
		proto = client->proto;
		instance = client->instance;
		restart_time = client->restart_time;
	} else {
		s_client = info->stale_client_ptr;
		if (s_client == NULL) {
			LOG_GR("%s: Stale client not present", __func__);
			return -1;
		}
		proto = s_client->proto;
		instance = s_client->instance;
		restart_time = s_client->restart_time;
	}

	LOG_GR("%s: Client %s %s(%u) stale routes are scheduled for deletion", __func__,
	       zebra_route_string(proto), zvrf->vrf->name, zvrf->vrf->vrf_id);

	/* Process routes for all AFI */
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		/*
		 * Schedule for immediately after anything in the
		 * meta-Q
		 */
		rib_add_gr_run(afi, info->vrf_id, proto, instance, restart_time, restart_time,
			       false);
	}
	return 0;
}

/*
 * Delete the stale routes when client is restarted and routes are not
 * refreshed within the stale timeout
 */
static int32_t zebra_gr_delete_stale_routes(struct client_gr_info *info)
{
	struct zebra_vrf *zvrf;
	uint64_t cnt = 0;

	if (info == NULL)
		return -1;

	zvrf = zebra_vrf_lookup_by_id(info->vrf_id);
	if (zvrf == NULL) {
		LOG_GR("%s: Invalid VRF entry %u", __func__, info->vrf_id);
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
						 struct client_gr_info *info)
{
	afi_t afi;

	if (info == NULL)
		return;

	/* Check if route update completed for all AFI, SAFI */
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		if (info->af_enabled[afi] && !info->route_sync[afi]) {
			struct vrf *vrf = vrf_lookup_by_id(info->vrf_id);

			LOG_GR("%s: Client %s vrf: %s(%u) route update not completed for AFI %d",
			       __func__, zebra_route_string(client->proto),
			       VRF_LOGNAME(vrf), info->vrf_id, afi);
			frrtrace(4, frr_zebra, gr_process_client_stale_routes,
				 zebra_route_string(client->proto), VRF_LOGNAME(vrf), afi, 1);
			return;
		}
	}

	/*
	 * Route update completed for all AFI, SAFI
	 * Also perform the cleanup if FRR itself is gracefully restarting.
	 */
	info->route_sync_done_time = monotime(NULL);
	if (info->t_stale_removal || zrouter.graceful_restart) {
		struct vrf *vrf = vrf_lookup_by_id(info->vrf_id);

		LOG_GR("%s: Client %s route update complete for all AFI/SAFI in vrf %s(%d)",
		       __func__, zebra_route_string(client->proto),
		       VRF_LOGNAME(vrf), info->vrf_id);
		event_cancel(&info->t_stale_removal);

		frrtrace(4, frr_zebra, gr_process_client_stale_routes,
			 zebra_route_string(client->proto), VRF_LOGNAME(vrf), afi, 0);
	}
}

void zebra_gr_process_client(afi_t afi, vrf_id_t vrf_id, uint8_t proto, uint8_t instance,
			     time_t restart_time, time_t update_pending_time,
			     bool stale_client_cleanup)
{
	struct zserv *client = zserv_find_client(proto, instance);
	struct client_gr_info *info = NULL;
	struct zebra_gr_afi_clean *gac;

	if (!client) {
		/*
		 * Active client doesn't exist. May be it's already been
		 * unlinked from zrouter.client_list in zserv_close_client(),
		 * which could happen when client goes down. See if stale client
		 * exists
		 */
		client = zebra_gr_find_stale_client(proto, instance);
		if (!client) {
			LOG_GR("GR: %s: Neither active nor stale client found", __func__);
			frrtrace(3, frr_zebra, gr_client_not_found, vrf_id, afi, 1);
			return;
		}
	}

	TAILQ_FOREACH (info, &client->gr_info_queue, gr_info) {
		if (info->vrf_id == vrf_id)
			break;
	}

	if (info == NULL)
		return;

	gac = XCALLOC(MTYPE_ZEBRA_GR, sizeof(*gac));
	gac->info = info;
	gac->afi = afi;
	gac->proto = proto;
	gac->instance = instance;
	gac->restart_time = restart_time;
	gac->update_pending_time = update_pending_time;

	/*
	 * If stale_client_cleanup is set, then we are being asked to cleanup
	 * the GR info and the stale client.
	 */
	if (stale_client_cleanup)
		event_add_event(zrouter.master, zebra_gr_delete_stale_info_client, gac, 0,
				&gac->t_gac);
	else
		event_add_event(zrouter.master, zebra_gr_delete_stale_route_table_afi, gac, 0,
				&gac->t_gac);
}
