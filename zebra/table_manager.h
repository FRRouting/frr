/* zebra table Manager for routing table identifier management
 * Copyright (C) 2018 6WIND
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

#ifndef _TABLE_MANAGER_H
#define _TABLE_MANAGER_H

#include <stdint.h>

#include "lib/linklist.h"
#include "lib/thread.h"
#include "lib/ns.h"

#include "zebra/zserv.h"

/*
 * Table chunk struct
 * Client daemon which the chunk belongs to can be identified by either
 * proto (daemon protocol) + instance + VRF.
 * If the client then passes a non-empty value to keep field when it requests
 * for chunks, the chunks won't be garbage collected and the client will be
 * responsible of its release.
 * Otherwise, if the keep field is not set (value 0) for the chunk, it will be
 * automatically released when the client disconnects or when it reconnects
 * (in case it died unexpectedly, we can know it's the same because it will have
 * the same proto and instance values)
 */
struct table_manager_chunk {
	vrf_id_t vrf_id;
	uint8_t proto;
	uint16_t instance;
	uint32_t start; /* First table RT ID of the chunk */
	uint32_t end;   /* Last table RT ID of the chunk */
};

/*
 * Main table manager struct
 * Holds a linked list of table chunks.
 */
struct table_manager {
	struct list *lc_list;
};

void table_manager_enable(ns_id_t ns_id);
struct table_manager_chunk *assign_table_chunk(uint8_t proto, uint16_t instance,
					       uint32_t size);
int release_table_chunk(uint8_t proto, uint16_t instance, uint32_t start,
			uint32_t end);
int release_daemon_table_chunks(struct zserv *client);
void table_manager_disable(ns_id_t ns_id);

#endif /* _TABLE_MANAGER_H */
