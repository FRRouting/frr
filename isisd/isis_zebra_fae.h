/*
 * IS-IS Rout(e)ing protocol - isis_zebra_fae.h
 *
 * Copyright 2022 6WIND S.A.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef _ZEBRA_ISIS_ZEBRA_FAE_H
#define _ZEBRA_ISIS_ZEBRA_FAE_H

#include "zebra.h"
#include "stream.h"
#include "isisd.h"
#include "isis_route.h"

int isis_zebra_fae_ready_send(const struct isis_area *const area, bool);
int isis_zebra_fae_ready_unicast_send(
	const struct isis_area *const area, bool ready,
	const struct zapi_client_daemon_id *const client_daemon_id);
int isis_zebra_fae_update_send(
	const struct isis_area *const area, const struct ipaddr *const endpoint,
	const struct isis_route_info *const rinfo, uint8_t algorithm,
	const struct zapi_client_daemon_id *const client_daemon_id);
int isis_zebra_fae_process_register(struct stream *s);
int isis_zebra_fae_process_unregister(struct stream *s);
int isis_zebra_fae_process_client_ready(struct stream *s);
void isis_zebra_fae_ready(void);

#endif /* _ZEBRA_ISIS_ZEBRA_H */
