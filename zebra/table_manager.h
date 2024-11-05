// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra table Manager for routing table identifier management
 * Copyright (C) 2018 6WIND
 */

#ifndef _TABLE_MANAGER_H
#define _TABLE_MANAGER_H

#include <stdint.h>

#include "lib/linklist.h"
#include "frrevent.h"
#include "lib/ns.h"

#include "zebra/zserv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* routing table identifiers
 *
 */
#if !defined(GNU_LINUX)
/* BSD systems
 */
#define RT_TABLE_ID_MAIN 0
#else
/* Linux Systems
 */
#define RT_TABLE_ID_LOCAL   255
#define RT_TABLE_ID_MAIN    254
#define RT_TABLE_ID_DEFAULT 253
#define RT_TABLE_ID_COMPAT  252
#define RT_TABLE_ID_UNSPEC  0
#endif /* !def(GNU_LINUX) */

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
	uint32_t start;
	uint32_t end;
};

void table_manager_enable(struct zebra_vrf *zvrf);
struct table_manager_chunk *assign_table_chunk(uint8_t proto, uint16_t instance,
					       uint32_t size,
					       struct zebra_vrf *zvrf);
int release_table_chunk(uint8_t proto, uint16_t instance, uint32_t start,
			uint32_t end, struct zebra_vrf *zvrf);
int release_daemon_table_chunks(struct zserv *client);
void table_manager_disable(struct zebra_vrf *zvrf);
void table_manager_range(bool add, struct zebra_vrf *zvrf, uint32_t start,
			 uint32_t end);

#ifdef __cplusplus
}
#endif

#endif /* _TABLE_MANAGER_H */
