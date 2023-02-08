// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 */

#include <zebra.h>
#include "prefix.h"
#include "vty.h"
#include "stream.h"
#include "zebra/zebra_router.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_ptm.h"
#include "zebra/zebra_ptm_redistribute.h"

static int zsend_interface_bfd_update(int cmd, struct zserv *client,
				      struct interface *ifp, struct prefix *dp,
				      struct prefix *sp, int status,
				      vrf_id_t vrf_id)
{
	int blen;
	struct stream *s;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

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

	/* c-bit bullshit */
	stream_putc(s, 0);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	client->if_bfd_cnt++;
	return zserv_send_message(client, s);
}

void zebra_interface_bfd_update(struct interface *ifp, struct prefix *dp,
				struct prefix *sp, int status, vrf_id_t vrf_id)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		if (!IS_BFD_ENABLED_PROTOCOL(client->proto))
			continue;

		/* Notify to the protocol daemons. */
		zsend_interface_bfd_update(ZEBRA_INTERFACE_BFD_DEST_UPDATE,
					   client, ifp, dp, sp, status, vrf_id);
	}
}

static int zsend_bfd_peer_replay(int cmd, struct zserv *client)
{
	struct stream *s;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, cmd, VRF_DEFAULT);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	client->bfd_peer_replay_cnt++;
	return zserv_send_message(client, s);
}

void zebra_bfd_peer_replay_req(void)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		if (!IS_BFD_ENABLED_PROTOCOL(client->proto))
			continue;

		/* Notify to the protocol daemons. */
		zsend_bfd_peer_replay(ZEBRA_BFD_DEST_REPLAY, client);
	}
}
