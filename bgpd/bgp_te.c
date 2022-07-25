/* BGP Endpoint End Point Tracking Database
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
#include "lib/zapi_client.h"
#include "lib/zapi_triggered_srte.h"

#include "bgpd/bgp_te.h"

/* Register a new client.  If the client registered previously, the client
 * either restarted or changed configuration
 * - flush BGP TE contexts
 * - if origin == BGP, then re-create BGP TE context
 *
 * @param client_daemon_id	client process
 * @param origin	        protocol_origin
 *
 * @return			0 on success, -1 otherwise.
 */
static int bgp_te_policy_process_client_ready(
		const struct zapi_client_daemon_id *const client_daemon_id,
		const enum srte_protocol_origin *origin)
{
	int client;

	/* For now, there can be only one client.  If a new client shows up,
	 * assume pathd restarted and clean up the old information.
	 */
	client = zapi_client_find_client(client_daemon_id);
	if (client < 0)
		goto out;

	/* BGP TE colored registered contexts are getting flushed */
	if (zapi_client_del_client(client)) {
		zlog_warn("%s Unable to replace client", __func__);
		return -1;
	}

out:
	/* do not continue if decision maker is not BGP */
	if (*origin != SRTE_ORIGIN_BGP)
		return -1;

	if (zapi_client_get_client(client_daemon_id) < 0)
		return -1;

	/* Notify the client of available BGP colored next-hops from BGP updates
	 */
	return 0;
}

int bgp_te_process_tsrte_client_ready(struct stream *s)
{
	int ret;
	struct zapi_client_daemon_id client_daemon_id;
	enum srte_protocol_origin origin;

	ret = zapi_tsrte_client_ready_decode(s, &client_daemon_id,
					     &origin);
	if (ret)
		return -1;
	ret = bgp_te_policy_process_client_ready(&client_daemon_id,
						 &origin);
	return ret;
}
