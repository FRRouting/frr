/* client handling for Flex-Algo and Triggered SRTE
 * Generic Library
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

#ifndef __ZAPI_CLIENT_H
#define __ZAPI_CLIENT_H

#include "zclient.h" /* for enum zclient_send_status */

struct zapi_client_daemon_id {
	uint8_t proto;
	uint16_t instance;
	uint32_t session_id;
};

/* This matches only the proto and instance.  Caller should check the
 * session ID.  Expand this later to deal with multiple clients.
 */
int zapi_client_find_client(const struct zapi_client_daemon_id *const id);

/* Expand this later to deal with multiple clients */
int zapi_client_del_client(int client);

/* Expand this later to deal with multiple clients  / restarted client */
int zapi_client_get_client(const struct zapi_client_daemon_id *const id);


void zapi_client_find_client_from_index(int index,
					struct zapi_client_daemon_id **client);

int zapi_client_decode_daemon_id(struct stream *s,
				 struct zapi_client_daemon_id *di);

void zapi_client_encode_daemon_id(struct stream *s, struct zclient *zclient);

#endif /* __ZAPI_CLIENT_H */
