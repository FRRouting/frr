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
#include "lib/hook.h"

#include "zebra/zserv.h"

#ifdef __cplusplus
extern "C" {
#endif

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

/* declare hooks for the basic API, so that it can be specialized or served
 * externally. Also declare a hook when those functions have been registered,
 * so that any external module wanting to replace those can react
 */

DECLARE_HOOK(lm_client_connect,
	     (uint8_t proto, uint16_t instance, vrf_id_t vrf_id),
	     (proto, instance, vrf_id));
DECLARE_HOOK(lm_client_disconnect, (uint8_t proto, uint16_t instance),
	     (proto, instance));
DECLARE_HOOK(lm_get_chunk,
	     (struct label_manager_chunk * *lmc, uint8_t proto,
	      uint16_t instance, uint8_t keep, uint32_t size, uint32_t base,
	      vrf_id_t vrf_id),
	     (lmc, proto, instance, keep, size, base, vrf_id));
DECLARE_HOOK(lm_release_chunk,
	     (uint8_t proto, uint16_t instance, uint32_t start, uint32_t end),
	     (proto, instance, start, end));
DECLARE_HOOK(lm_cbs_inited, (), ());


/* declare wrappers to be called in zapi_msg.c (as hooks must be called in
 * source file where they were defined)
 */
void lm_client_connect_call(uint8_t proto, uint16_t instance, vrf_id_t vrf_id);
void lm_get_chunk_call(struct label_manager_chunk **lmc, uint8_t proto,
		       uint16_t instance, uint8_t keep, uint32_t size,
		       uint32_t base, vrf_id_t vrf_id);
void lm_release_chunk_call(uint8_t proto, uint16_t instance, uint32_t start,
			   uint32_t end);

/* API for an external LM to return responses for requests */
int lm_client_connect_response(uint8_t proto, uint16_t instance,
			       vrf_id_t vrf_id, uint8_t result);
int lm_get_chunk_response(struct label_manager_chunk *lmc, uint8_t proto,
			  uint16_t instance, vrf_id_t vrf_id);

/* convenience function to allocate an lmc to be consumed by the above API */
struct label_manager_chunk *create_label_chunk(uint8_t proto,
					       unsigned short instance,
					       uint8_t keep, uint32_t start,
					       uint32_t end);
void delete_label_chunk(void *val);

/* register/unregister callbacks for hooks */
void lm_hooks_register(void);
void lm_hooks_unregister(void);

/*
 * Main label manager struct
 * Holds a linked list of label chunks.
 */
struct label_manager {
	struct list *lc_list;
};

void label_manager_init(void);
struct label_manager_chunk *assign_label_chunk(uint8_t proto,
					       unsigned short instance,
					       uint8_t keep, uint32_t size,
					       uint32_t base);
int release_label_chunk(uint8_t proto, unsigned short instance, uint32_t start,
			uint32_t end);
int lm_client_disconnect_cb(struct zserv *client);
int release_daemon_label_chunks(uint8_t proto, unsigned short instance);
void label_manager_close(void);

#ifdef __cplusplus
}
#endif

#endif /* _LABEL_MANAGER_H */
