/**
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
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
#include "prefix.h"
#include "vty.h"
#include "stream.h"
#include "zebra/zserv.h"
#include "zebra/zebra_ptm_redistribute.h"
#include "zebra/zebra_memory.h"

static int zsend_interface_bfd_update(int cmd, struct zserv *client,
				      struct interface *ifp, struct prefix *dp,
				      struct prefix *sp, int status,
				      vrf_id_t vrf_id)
{
	int blen;
	struct stream *s;

	/* Check this client need interface information. */
	if (!client->ifinfo)
		return 0;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, cmd, vrf_id);
	if (ifp)
		stream_putl(s, ifp->ifindex);
	else
		stream_putl(s, 0);

	/* BFD destination prefix information. */
	stream_putc(s, dp->family);
	blen = prefix_blen(dp);
	stream_put(s, &dp->u.prefix, blen);
	stream_putc(s, dp->prefixlen);

	/* BFD status */
	stream_putl(s, status);

	/* BFD source prefix information. */
	stream_putc(s, sp->family);
	blen = prefix_blen(sp);
	stream_put(s, &sp->u.prefix, blen);
	stream_putc(s, sp->prefixlen);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	client->if_bfd_cnt++;
	return zebra_server_send_message(client);
}

void zebra_interface_bfd_update(struct interface *ifp, struct prefix *dp,
				struct prefix *sp, int status, vrf_id_t vrf_id)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	for (ALL_LIST_ELEMENTS(zebrad.client_list, node, nnode, client)) {
		/* Supporting for OSPF, BGP and PIM */
		if (client->proto != ZEBRA_ROUTE_OSPF
		    && client->proto != ZEBRA_ROUTE_BGP
		    && client->proto != ZEBRA_ROUTE_OSPF6
		    && client->proto != ZEBRA_ROUTE_PIM)
			continue;

		/* Notify to the protocol daemons. */
		zsend_interface_bfd_update(ZEBRA_INTERFACE_BFD_DEST_UPDATE,
					   client, ifp, dp, sp, status, vrf_id);
	}
}

static int zsend_bfd_peer_replay(int cmd, struct zserv *client)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, cmd, VRF_DEFAULT);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	client->bfd_peer_replay_cnt++;
	return zebra_server_send_message(client);
}

void zebra_bfd_peer_replay_req(void)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	for (ALL_LIST_ELEMENTS(zebrad.client_list, node, nnode, client)) {
		/* Supporting for BGP */
		if ((client->proto != ZEBRA_ROUTE_BGP)
		    && (client->proto != ZEBRA_ROUTE_OSPF)
		    && (client->proto != ZEBRA_ROUTE_OSPF6)
		    && (client->proto != ZEBRA_ROUTE_PIM))
			continue;

		/* Notify to the protocol daemons. */
		zsend_bfd_peer_replay(ZEBRA_BFD_DEST_REPLAY, client);
	}
}
