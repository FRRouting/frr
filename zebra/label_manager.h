/*
 * Label Manager header
 *
 * Copyright (C) 2017 by Bingen Eguzkitza,
 *                       Volta Networks Inc.
 *
 * This file is part of FreeRangeRouting (FRR)
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _LABEL_MANAGER_H
#define _LABEL_MANAGER_H

#include <stdint.h>

#include "lib/linklist.h"
#include "lib/thread.h"

#include "zebra/zserv.h"

#define NO_PROTO 0

/*
 * Label chunk struct
 * Client daemon which the chunk belongs to can be identified by either
 * proto (daemon protocol) + instance.
 * If the client then passes a non-empty value to keep field when it requests
 * for chunks, the chunks won't be garbage collected and the client will be
 * responsible of its release.
 * Otherwise, if the keep field is not set (value 0) for the chunk, it will be
 * automatically released when the client disconnects or when it reconnects
 * (in case it died unexpectedly, we can know it's the same because it will have
 * the same proto and instance values)
 */
struct label_manager_chunk {
	uint8_t proto;
	unsigned short instance;
	uint8_t keep;
	uint32_t start; /* First label of the chunk */
	uint32_t end;   /* Last label of the chunk */
};

/*
 * Main label manager struct
 * Holds a linked list of label chunks.
 */
struct label_manager {
	struct list *lc_list;
};

bool lm_is_external;

int zread_relay_label_manager_request(int cmd, struct zserv *zserv,
				      struct stream *msg, vrf_id_t vrf_id);
void label_manager_init(char *lm_zserv_path);
struct label_manager_chunk *assign_label_chunk(uint8_t proto,
					       unsigned short instance,
					       uint8_t keep, uint32_t size);
int release_label_chunk(uint8_t proto, unsigned short instance, uint32_t start,
			uint32_t end);
int release_daemon_label_chunks(struct zserv *client);
void label_manager_close(void);

#endif /* _LABEL_MANAGER_H */
