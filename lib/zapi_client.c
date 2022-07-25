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
#include "zebra.h"
#include "zclient.h"
#include "zapi_client.h"

static struct zapi_client_daemon_id _clients[1];
static unsigned _num_clients = 0;

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Proto    |          Instance             |   Session-ID
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     Session-ID cont'd (32 bits)                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
void zapi_client_encode_daemon_id(struct stream *s, struct zclient *zclient)
{
	stream_putc(s, zclient->redist_default);
	stream_putw(s, zclient->instance);
	stream_putl(s, zclient->session_id);
}

int zapi_client_decode_daemon_id(struct stream *s,
				 struct zapi_client_daemon_id *di)
{
	STREAM_GETC(s, di->proto);
	STREAM_GETW(s, di->instance);
	STREAM_GETL(s, di->session_id);
	return 0;

stream_failure:
	return -1;
}


/* This matches only the proto and instance.  Caller should check the
 * session ID.  Expand this later to deal with multiple clients.
 */
int zapi_client_find_client(const struct zapi_client_daemon_id *const id)
{
	if (_num_clients == 1 && _clients[0].proto == id->proto
	    && _clients[0].instance == id->instance)
		return 0;
	return -1;
}

/* Expand this later to deal with multiple clients */
int zapi_client_del_client(int client)
{
	if (_num_clients > 0 && client == 0) {
		_num_clients--;
		return 0;
	}
	return -1;
}

/* Expand this later to deal with multiple clients  / restarted client */
int zapi_client_get_client(const struct zapi_client_daemon_id *const id)
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

void zapi_client_find_client_from_index(int index,
					struct zapi_client_daemon_id **client)
{
	*client = &_clients[index];
}
