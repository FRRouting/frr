// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Label Manager header
 *
 * Copyright (C) 2017 by Bingen Eguzkitza,
 *                       Volta Networks Inc.
 *
 * This file is part of FRRouting (FRR)
 */

#ifndef _LABEL_MANAGER_H
#define _LABEL_MANAGER_H

#include <stdint.h>

#include "lib/linklist.h"
#include "frrevent.h"
#include "lib/hook.h"

#include "zebra/zserv.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NO_PROTO 0

/*
 * Label chunk struct
 * Client daemon which the chunk belongs to can be identified by a tuple of:
 * proto (daemon protocol) + instance + zapi session_id
 * If the client then passes a non-empty value to keep field when it requests
 * for chunks, the chunks won't be garbage collected and the client will be
 * responsible for releasing them.
 * Otherwise, if the keep field is not set (value 0) for the chunk, it will be
 * automatically released when the client disconnects or when it reconnects
 * (in case it died unexpectedly, we can know it's the same because it will have
 * the same proto+instance+session values)
 */
struct label_manager_chunk {
	uint8_t proto;
	unsigned short instance;
	uint32_t session_id;
	uint8_t keep;
	uint8_t is_dynamic; /* Tell if chunk is dynamic or static */
	uint32_t start; /* First label of the chunk */
	uint32_t end;   /* Last label of the chunk */
};

/* declare hooks for the basic API, so that it can be specialized or served
 * externally. Also declare a hook when those functions have been registered,
 * so that any external module wanting to replace those can react
 */

DECLARE_HOOK(lm_client_connect, (struct zserv *client, vrf_id_t vrf_id),
	     (client, vrf_id));
DECLARE_HOOK(lm_client_disconnect, (struct zserv *client), (client));
DECLARE_HOOK(lm_get_chunk,
	     (struct label_manager_chunk * *lmc, struct zserv *client,
	      uint8_t keep, uint32_t size, uint32_t base, vrf_id_t vrf_id),
	     (lmc, client, keep, size, base, vrf_id));
DECLARE_HOOK(lm_release_chunk,
	     (struct zserv *client, uint32_t start, uint32_t end),
	     (client, start, end));
DECLARE_HOOK(lm_write_label_block_config,
	     (struct vty *vty, struct zebra_vrf *zvrf),
	     (vty, zvrf));
DECLARE_HOOK(lm_cbs_inited, (), ());


/* declare wrappers to be called in zapi_msg.c or zebra_mpls_vty.c (as hooks
 * must be called in source file where they were defined)
 */
void lm_client_connect_call(struct zserv *client, vrf_id_t vrf_id);
void lm_get_chunk_call(struct label_manager_chunk **lmc, struct zserv *client,
		       uint8_t keep, uint32_t size, uint32_t base,
		       vrf_id_t vrf_id);
void lm_release_chunk_call(struct zserv *client, uint32_t start,
			   uint32_t end);
int lm_write_label_block_config_call(struct vty *vty, struct zebra_vrf *zvrf);

/* API for an external LM to return responses for requests */
int lm_client_connect_response(uint8_t proto, uint16_t instance,
			       uint32_t session_id, vrf_id_t vrf_id,
			       uint8_t result);

/* convenience function to allocate an lmc to be consumed by the above API */
struct label_manager_chunk *
create_label_chunk(uint8_t proto, unsigned short instance, uint32_t session_id,
		   uint8_t keep, uint32_t start, uint32_t end, bool is_dynamic);
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
	uint32_t dynamic_block_start;
	uint32_t dynamic_block_end;
};

void label_manager_init(void);
void label_manager_terminate(void);

struct label_manager_chunk *
assign_label_chunk(uint8_t proto, unsigned short instance, uint32_t session_id,
		   uint8_t keep, uint32_t size, uint32_t base);
int release_label_chunk(uint8_t proto, unsigned short instance,
			uint32_t session_id, uint32_t start, uint32_t end);
int lm_client_disconnect_cb(struct zserv *client);
int release_daemon_label_chunks(struct zserv *client);
void label_manager_close(void);

#ifdef __cplusplus
}
#endif

#endif /* _LABEL_MANAGER_H */
