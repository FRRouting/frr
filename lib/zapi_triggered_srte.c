/* zapi handling for Triggered SR-TE messages
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
#include "zebra.h"
#include "zclient.h"
#include "zapi_client.h"
#include "zapi_triggered_srte.h"

#define _TRIGGERED_SRTE_READY_SIZE                                             \
	(sizeof(struct zapi_client_daemon_id) +    /* srte daemon */           \
	 sizeof(struct zapi_srte_protocol_origin)) /* for bgp */


enum zclient_send_status
zapi_tsrte_client_ready_send(struct zclient *zclient,
			     enum srte_protocol_origin protocol_origin)
{
	struct stream *s = stream_new(_TRIGGERED_SRTE_READY_SIZE);
	enum zclient_send_status status;

	zapi_client_encode_daemon_id(s, zclient);
	stream_putc(s, protocol_origin);
	status = zclient_send_opaque(zclient, TSRTE_CLIENT_READY, s->data,
				   s->endp);

	stream_free(s);

	return status;
}

enum zclient_send_status zapi_tsrte_bgp_ready_send(struct zclient *zclient)
{
	struct stream *s = stream_new(sizeof(struct zapi_client_daemon_id));
	enum zclient_send_status status;

	//	assert(zclient->redist_default == ZEBRA_ROUTE_BGP);
	zapi_client_encode_daemon_id(s, zclient);
	status =
		zclient_send_opaque(zclient, TSRTE_BGP_READY, s->data, s->endp);
	stream_free(s);
	return status;
}

int zapi_tsrte_client_ready_decode(
	struct stream *s, struct zapi_client_daemon_id *client_daemon_id,
	enum srte_protocol_origin *protocol_origin)
{
	int rc;

	rc = zapi_client_decode_daemon_id(s, client_daemon_id);
	if (rc)
		return -1;
	STREAM_GETC(s, (*protocol_origin));
	return 0;
stream_failure:
	return -1;
}
