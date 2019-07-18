/*
 * Label Manager for FRR
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

#include <zebra.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "lib/log.h"
#include "lib/memory.h"
#include "lib/mpls.h"
#include "lib/network.h"
#include "lib/stream.h"
#include "lib/zclient.h"
#include "lib/libfrr.h"

//#include "zebra/zserv.h"
#include "zebra/zebra_router.h"
#include "zebra/label_manager.h"
#include "zebra/zebra_errors.h"
#include "zebra/zapi_msg.h"
#include "zebra/debug.h"

#define CONNECTION_DELAY 5

struct label_manager lbl_mgr;

DEFINE_MGROUP(LBL_MGR, "Label Manager");
DEFINE_MTYPE_STATIC(LBL_MGR, LM_CHUNK, "Label Manager Chunk");

/* define hooks for the basic API, so that it can be specialized or served
 * externally
 */

DEFINE_HOOK(lm_client_connect,
	    (uint8_t proto, uint16_t instance, vrf_id_t vrf_id),
	    (proto, instance, vrf_id));
DEFINE_HOOK(lm_client_disconnect, (uint8_t proto, uint16_t instance),
	    (proto, instance));
DEFINE_HOOK(lm_get_chunk,
	    (struct label_manager_chunk * *lmc, uint8_t proto,
	     uint16_t instance, uint8_t keep, uint32_t size, uint32_t base,
	     vrf_id_t vrf_id),
	    (lmc, proto, instance, keep, size, base, vrf_id));
DEFINE_HOOK(lm_release_chunk,
	    (uint8_t proto, uint16_t instance, uint32_t start, uint32_t end),
	    (proto, instance, start, end));
DEFINE_HOOK(lm_cbs_inited, (), ());

/* define wrappers to be called in zapi_msg.c (as hooks must be called in
 * source file where they were defined)
 */
void lm_client_connect_call(uint8_t proto, uint16_t instance, vrf_id_t vrf_id)
{
	hook_call(lm_client_connect, proto, instance, vrf_id);
}
void lm_get_chunk_call(struct label_manager_chunk **lmc, uint8_t proto,
		       uint16_t instance, uint8_t keep, uint32_t size,
		       uint32_t base, vrf_id_t vrf_id)
{
	hook_call(lm_get_chunk, lmc, proto, instance, keep, size, base, vrf_id);
}
void lm_release_chunk_call(uint8_t proto, uint16_t instance, uint32_t start,
			   uint32_t end)
{
	hook_call(lm_release_chunk, proto, instance, start, end);
}

/* forward declarations of the static functions to be used for some hooks */
static int label_manager_connect(uint8_t proto, uint16_t instance,
				 vrf_id_t vrf_id);
static int label_manager_disconnect(uint8_t proto, uint16_t instance);
static int label_manager_get_chunk(struct label_manager_chunk **lmc,
				   uint8_t proto, uint16_t instance,
				   uint8_t keep, uint32_t size, uint32_t base,
				   vrf_id_t vrf_id);

void delete_label_chunk(void *val)
{
	XFREE(MTYPE_LM_CHUNK, val);
}

/**
 * Release label chunks from a client.
 *
 * Called on client disconnection or reconnection. It only releases chunks
 * with empty keep value.
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @return Number of chunks released
 */
int release_daemon_label_chunks(uint8_t proto, unsigned short instance)
{
	struct listnode *node;
	struct label_manager_chunk *lmc;
	int count = 0;
	int ret;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Releasing chunks for client proto %s, instance %d",
			   __func__, zebra_route_string(proto), instance);

	for (ALL_LIST_ELEMENTS_RO(lbl_mgr.lc_list, node, lmc)) {
		if (lmc->proto == proto && lmc->instance == instance
		    && lmc->keep == 0) {
			ret = release_label_chunk(lmc->proto, lmc->instance,
						  lmc->start, lmc->end);
			if (ret == 0)
				count++;
		}
	}

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Released %d label chunks", __func__, count);

	return count;
}

int lm_client_disconnect_cb(struct zserv *client)
{
	uint8_t proto = client->proto;
	uint16_t instance = client->instance;

	hook_call(lm_client_disconnect, proto, instance);
	return 0;
}

void lm_hooks_register(void)
{
	hook_register(lm_client_connect, label_manager_connect);
	hook_register(lm_client_disconnect, label_manager_disconnect);
	hook_register(lm_get_chunk, label_manager_get_chunk);
	hook_register(lm_release_chunk, release_label_chunk);
}
void lm_hooks_unregister(void)
{
	hook_unregister(lm_client_connect, label_manager_connect);
	hook_unregister(lm_client_disconnect, label_manager_disconnect);
	hook_unregister(lm_get_chunk, label_manager_get_chunk);
	hook_unregister(lm_release_chunk, release_label_chunk);
}

/**
 * Init label manager (or proxy to an external one)
 */
void label_manager_init(void)
{
	lbl_mgr.lc_list = list_new();
	lbl_mgr.lc_list->del = delete_label_chunk;
	hook_register(zserv_client_close, lm_client_disconnect_cb);

	/* register default hooks for the label manager actions */
	lm_hooks_register();

	/* notify any external module that we are done */
	hook_call(lm_cbs_inited);
}

/* alloc and fill a label chunk */
struct label_manager_chunk *create_label_chunk(uint8_t proto,
					       unsigned short instance,
					       uint8_t keep, uint32_t start,
					       uint32_t end)
{
	/* alloc chunk, fill it and return it */
	struct label_manager_chunk *lmc =
		XCALLOC(MTYPE_LM_CHUNK, sizeof(struct label_manager_chunk));

	lmc->start = start;
	lmc->end = end;
	lmc->proto = proto;
	lmc->instance = instance;
	lmc->keep = keep;

	return lmc;
}

/* attempt to get a specific label chunk */
static struct label_manager_chunk *
assign_specific_label_chunk(uint8_t proto, unsigned short instance,
			    uint8_t keep, uint32_t size, uint32_t base)
{
	struct label_manager_chunk *lmc;
	struct listnode *node, *next = NULL;
	struct listnode *first_node = NULL;
	struct listnode *last_node = NULL;
	struct listnode *insert_node = NULL;

	/* precompute last label from base and size */
	uint32_t end = base + size - 1;

	/* sanities */
	if ((base < MPLS_LABEL_UNRESERVED_MIN)
	    || (end > MPLS_LABEL_UNRESERVED_MAX)) {
		zlog_err("Invalid LM request arguments: base: %u, size: %u",
			 base, size);
		return NULL;
	}

	/* Scan the existing chunks to see if the requested range of labels
	 * falls inside any of such chunks */
	for (ALL_LIST_ELEMENTS_RO(lbl_mgr.lc_list, node, lmc)) {

		/* skip chunks for labels < base */
		if (base > lmc->end)
			continue;

		/* requested range is not covered by any existing, free chunk.
		 * Therefore, need to insert a chunk */
		if ((end < lmc->start) && !first_node) {
			insert_node = node;
			break;
		}

		if (!first_node)
			first_node = node;

		/* if chunk is used, cannot honor request */
		if (lmc->proto != NO_PROTO)
			return NULL;

		if (end < lmc->end) {
			last_node = node;
			break;
		}
	}

	/* insert chunk between existing chunks */
	if (insert_node) {
		lmc = create_label_chunk(proto, instance, keep, base, end);
		listnode_add_before(lbl_mgr.lc_list, insert_node, lmc);
		return lmc;
	}

	if (first_node) {
		/* get node past the last one, if there */
		if (last_node)
			last_node = listnextnode(last_node);

		/* delete node coming after the above chunk whose labels are
		 * included in the previous one */
		for (node = first_node; node && (node != last_node);
		     node = next) {
			next = listnextnode(node);
			list_delete_node(lbl_mgr.lc_list, node);
		}

		lmc = create_label_chunk(proto, instance, keep, base, end);
		if (last_node)
			listnode_add_before(lbl_mgr.lc_list, last_node, lmc);
		else
			listnode_add(lbl_mgr.lc_list, lmc);

		return lmc;
	} else {
		/* create a new chunk past all the existing ones and link at
		 * tail */
		lmc = create_label_chunk(proto, instance, keep, base, end);
		listnode_add(lbl_mgr.lc_list, lmc);
		return lmc;
	}
}

/**
 * Core function, assigns label chunks
 *
 * It first searches through the list to check if there's one available
 * (previously released). Otherwise it creates and assigns a new one
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param keep If set, avoid garbage collection
 * @param size Size of the label chunk
 * @param base Desired starting label of the chunk; if MPLS_LABEL_BASE_ANY it does not apply
 * @return Pointer to the assigned label chunk, or NULL if the request could not be satisfied
 */
struct label_manager_chunk *assign_label_chunk(uint8_t proto,
					       unsigned short instance,
					       uint8_t keep, uint32_t size,
					       uint32_t base)
{
	struct label_manager_chunk *lmc;
	struct listnode *node;
	uint32_t prev_end = 0;

	/* handle chunks request with a specific base label */
	if (base != MPLS_LABEL_BASE_ANY)
		return assign_specific_label_chunk(proto, instance, keep, size,
						   base);

	/* appease scan-build, who gets confused by the use of macros */
	assert(lbl_mgr.lc_list);

	/* first check if there's one available */
	for (ALL_LIST_ELEMENTS_RO(lbl_mgr.lc_list, node, lmc)) {
		if (lmc->proto == NO_PROTO
		    && lmc->end - lmc->start + 1 == size) {
			lmc->proto = proto;
			lmc->instance = instance;
			lmc->keep = keep;
			return lmc;
		}
		/* check if we hadve a "hole" behind us that we can squeeze into
		 */
		if ((lmc->start > prev_end)
		    && (lmc->start - prev_end >= size)) {
			lmc = create_label_chunk(proto, instance, keep,
						 prev_end + 1, prev_end + size);
			listnode_add_before(lbl_mgr.lc_list, node, lmc);
			return lmc;
		}
		prev_end = lmc->end;
	}
	/* otherwise create a new one */
	uint32_t start_free;

	if (list_isempty(lbl_mgr.lc_list))
		start_free = MPLS_LABEL_UNRESERVED_MIN;
	else
		start_free = ((struct label_manager_chunk *)listgetdata(
				      listtail(lbl_mgr.lc_list)))
				     ->end
			     + 1;

	if (start_free > MPLS_LABEL_UNRESERVED_MAX - size + 1) {
		flog_err(EC_ZEBRA_LM_EXHAUSTED_LABELS,
			 "Reached max labels. Start: %u, size: %u", start_free,
			 size);
		return NULL;
	}

	/* create chunk and link at tail */
	lmc = create_label_chunk(proto, instance, keep, start_free,
				 start_free + size - 1);
	listnode_add(lbl_mgr.lc_list, lmc);
	return lmc;
}

/**
 * Core function, release no longer used label chunks
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param start First label of the chunk
 * @param end Last label of the chunk
 * @return 0 on success, -1 otherwise
 */
int release_label_chunk(uint8_t proto, unsigned short instance, uint32_t start,
			uint32_t end)
{
	struct listnode *node;
	struct label_manager_chunk *lmc;
	int ret = -1;

	/* check that size matches */
	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("Releasing label chunk: %u - %u", start, end);
	/* find chunk and disown */
	for (ALL_LIST_ELEMENTS_RO(lbl_mgr.lc_list, node, lmc)) {
		if (lmc->start != start)
			continue;
		if (lmc->end != end)
			continue;
		if (lmc->proto != proto || lmc->instance != instance) {
			flog_err(EC_ZEBRA_LM_DAEMON_MISMATCH,
				 "%s: Daemon mismatch!!", __func__);
			continue;
		}
		lmc->proto = NO_PROTO;
		lmc->instance = 0;
		lmc->keep = 0;
		ret = 0;
		break;
	}
	if (ret != 0)
		flog_err(EC_ZEBRA_LM_UNRELEASED_CHUNK,
			 "%s: Label chunk not released!!", __func__);

	return ret;
}

/* default functions to be called on hooks  */
static int label_manager_connect(uint8_t proto, uint16_t instance,
				 vrf_id_t vrf_id)
{
	/*
	 * Release previous labels of same protocol and instance.
	 * This is done in case it restarted from an unexpected shutdown.
	 */
	release_daemon_label_chunks(proto, instance);
	return lm_client_connect_response(proto, instance, vrf_id, 0);
}
static int label_manager_disconnect(uint8_t proto, uint16_t instance)
{
	release_daemon_label_chunks(proto, instance);
	return 0;
}
static int label_manager_get_chunk(struct label_manager_chunk **lmc,
				   uint8_t proto, uint16_t instance,
				   uint8_t keep, uint32_t size, uint32_t base,
				   vrf_id_t vrf_id)
{
	*lmc = assign_label_chunk(proto, instance, keep, size, base);
	return lm_get_chunk_response(*lmc, proto, instance, vrf_id);
}

/* Respond to a connect request */
int lm_client_connect_response(uint8_t proto, uint16_t instance,
			       vrf_id_t vrf_id, uint8_t result)
{
	struct zserv *client = zserv_find_client(proto, instance);
	if (!client) {
		zlog_err("%s: could not find client for daemon %s instance %u",
			 __func__, zebra_route_string(proto), instance);
		return 1;
	}
	return zsend_label_manager_connect_response(client, vrf_id, result);
}

/* Respond to a get_chunk request */
int lm_get_chunk_response(struct label_manager_chunk *lmc, uint8_t proto,
			  uint16_t instance, vrf_id_t vrf_id)
{
	struct zserv *client = zserv_find_client(proto, instance);
	if (!client) {
		zlog_err("%s: could not find client for daemon %s instance %u",
			 __func__, zebra_route_string(proto), instance);
		return 1;
	}
	return zsend_assign_label_chunk_response(client, vrf_id, proto,
						 instance, lmc);
}

void label_manager_close(void)
{
	list_delete(&lbl_mgr.lc_list);
}
