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


/*
 * Forward declaration.
 */
static struct zserv *zebra_gr_find_stale_client(struct zserv *client);
static int zebra_gr_route_stale_delete_timer_expiry(struct thread *thread);

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
 * Function to handle client when it disconnect.
 */
int zebra_gr_client_disconnect(struct zserv *client)
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

	/* For all the GR instance start the starle removal timer. */
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
	if (old_client) {
		client->gr_instance_count = old_client->gr_instance_count;
		client->restart_time = old_client->restart_time;

		LOG_GR("%s : old client %s, gr_instance_count %d", __func__,
		       zebra_route_string(old_client->proto),
		       old_client->gr_instance_count);

		if (TAILQ_FIRST(&old_client->gr_info_queue)) {
			TAILQ_CONCAT(&client->gr_info_queue,
				     &old_client->gr_info_queue, gr_info);
			TAILQ_INIT(&old_client->gr_info_queue);
		}

		TAILQ_FOREACH (info, &client->gr_info_queue, gr_info) {
			info->stale_client_ptr = client;
			info->stale_client = false;
		}

		/* Delete the stale client */
		listnode_delete(zrouter.stale_client_list, old_client);
		/* Delete old client */
		XFREE(MTYPE_TMP, old_client);
	}
}


static int zebra_gr_route_stale_delete_timer_expiry(struct thread *thread)
{
	return 0;
}
