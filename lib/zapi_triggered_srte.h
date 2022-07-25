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

#ifndef __ZAPI_TRIGGERED_SRTE_H
#define __ZAPI_TRIGGERED_SRTE_H

#include "zapi_client.h"

struct zapi_tsrte_daemon_id {
	uint8_t proto;
	uint16_t instance;
	uint32_t session_id;
};

struct zapi_srte_protocol_origin {
	uint8_t protocol_origin;
};

extern enum zclient_send_status
zapi_tsrte_client_ready_send(struct zclient *zclient,
			     enum srte_protocol_origin protocol_origin);

enum zclient_send_status zapi_tsrte_bgp_ready_send(struct zclient *zclient);

int zapi_tsrte_client_ready_decode(
	struct stream *s, struct zapi_client_daemon_id *client_daemon_id,
	enum srte_protocol_origin *protocol_origin);

#endif /* __ZAPI_TRIGGERED_SRTE_H */
