// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Label Manager for FRR
 *
 * Copyright (C) 2017 by Bingen Eguzkitza,
 *                       Volta Networks Inc.
 *
 * This file is part of FRRouting (FRR)
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

#include "zebra/label_manager_clippy.c"

#define CONNECTION_DELAY 5

struct label_manager lbl_mgr;

DEFINE_MGROUP(LBL_MGR, "Label Manager");
DEFINE_MTYPE_STATIC(LBL_MGR, LM_CHUNK, "Label Manager Chunk");

/* define hooks for the basic API, so that it can be specialized or served
 * externally
 */

DEFINE_HOOK(lm_client_connect, (struct zserv *client, vrf_id_t vrf_id),
	    (client, vrf_id));
DEFINE_HOOK(lm_client_disconnect, (struct zserv *client), (client));
DEFINE_HOOK(lm_get_chunk,
	     (struct label_manager_chunk * *lmc, struct zserv *client,
	      uint8_t keep, uint32_t size, uint32_t base, vrf_id_t vrf_id),
	     (lmc, client, keep, size, base, vrf_id));
DEFINE_HOOK(lm_release_chunk,
	     (struct zserv *client, uint32_t start, uint32_t end),
	     (client, start, end));
/* show running-config needs an API for dynamic-block */
DEFINE_HOOK(lm_write_label_block_config,
	    (struct vty *vty, struct zebra_vrf *zvrf),
	    (vty, zvrf));
DEFINE_HOOK(lm_cbs_inited, (), ());

/* define wrappers to be called in zapi_msg.c or zebra_mpls_vty.c (as hooks
 * must be called in source file where they were defined)
 */
void lm_client_connect_call(struct zserv *client, vrf_id_t vrf_id)
{
	hook_call(lm_client_connect, client, vrf_id);
}
void lm_get_chunk_call(struct label_manager_chunk **lmc, struct zserv *client,
		       uint8_t keep, uint32_t size, uint32_t base,
		       vrf_id_t vrf_id)
{
	hook_call(lm_get_chunk, lmc, client, keep, size, base, vrf_id);
}
void lm_release_chunk_call(struct zserv *client, uint32_t start, uint32_t end)
{
	hook_call(lm_release_chunk, client, start, end);
}

int lm_write_label_block_config_call(struct vty *vty, struct zebra_vrf *zvrf)
{
	return hook_call(lm_write_label_block_config, vty, zvrf);
}

/* forward declarations of the static functions to be used for some hooks */
static int label_manager_connect(struct zserv *client, vrf_id_t vrf_id);
static int label_manager_disconnect(struct zserv *client);
static int label_manager_get_chunk(struct label_manager_chunk **lmc,
				   struct zserv *client, uint8_t keep,
				   uint32_t size, uint32_t base,
				   vrf_id_t vrf_id);
static int label_manager_release_label_chunk(struct zserv *client,
					     uint32_t start, uint32_t end);
static int label_manager_write_label_block_config(struct vty *vty,
						  struct zebra_vrf *zvrf);

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
int release_daemon_label_chunks(struct zserv *client)
{
	struct listnode *node, *nnode;
	struct label_manager_chunk *lmc;
	int count = 0;
	int ret;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Releasing chunks for client proto %s, instance %d, session %u",
			   __func__, zebra_route_string(client->proto),
			   client->instance, client->session_id);

	for (ALL_LIST_ELEMENTS(lbl_mgr.lc_list, node, nnode, lmc)) {
		if (lmc->proto == client->proto &&
		    lmc->instance == client->instance &&
		    lmc->session_id == client->session_id && lmc->keep == 0) {
			ret = release_label_chunk(lmc->proto, lmc->instance,
						  lmc->session_id,
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
	hook_call(lm_client_disconnect, client);
	return 0;
}

void lm_hooks_register(void)
{
	hook_register(lm_client_connect, label_manager_connect);
	hook_register(lm_client_disconnect, label_manager_disconnect);
	hook_register(lm_get_chunk, label_manager_get_chunk);
	hook_register(lm_release_chunk, label_manager_release_label_chunk);
	hook_register(lm_write_label_block_config,
		      label_manager_write_label_block_config);
}
void lm_hooks_unregister(void)
{
	hook_unregister(lm_client_connect, label_manager_connect);
	hook_unregister(lm_client_disconnect, label_manager_disconnect);
	hook_unregister(lm_get_chunk, label_manager_get_chunk);
	hook_unregister(lm_release_chunk, label_manager_release_label_chunk);
	hook_unregister(lm_write_label_block_config,
			label_manager_write_label_block_config);
}

static json_object *lmc_json(struct label_manager_chunk *lmc)
{
	json_object *json = json_object_new_object();

	json_object_string_add(json, "protocol", zebra_route_string(lmc->proto));
	json_object_int_add(json, "instance", lmc->instance);
	json_object_int_add(json, "sessionId", lmc->session_id);
	json_object_int_add(json, "start", lmc->start);
	json_object_int_add(json, "end", lmc->end);
	json_object_boolean_add(json, "dynamic", lmc->is_dynamic);
	return json;
}

DEFPY(show_label_table, show_label_table_cmd, "show debugging label-table [json$uj]",
      SHOW_STR
      DEBUG_STR
      "Display allocated label chunks\n"
      JSON_STR)
{
	struct label_manager_chunk *lmc;
	struct listnode *node;
	json_object *json_array = NULL, *json_global = NULL, *json_dyn_block;

	if (uj) {
		json_array = json_object_new_array();
		json_global = json_object_new_object();
		json_dyn_block = json_object_new_object();
		json_object_int_add(json_dyn_block, "lowerBound",
				    lbl_mgr.dynamic_block_start);
		json_object_int_add(json_dyn_block, "upperBound",
				    lbl_mgr.dynamic_block_end);
		json_object_object_add(json_global, "dynamicBlock",
				       json_dyn_block);
	} else
		vty_out(vty, "Dynamic block: lower-bound %u, upper-bound %u\n",
			lbl_mgr.dynamic_block_start, lbl_mgr.dynamic_block_end);

	for (ALL_LIST_ELEMENTS_RO(lbl_mgr.lc_list, node, lmc)) {
		if (uj) {
			json_object_array_add(json_array, lmc_json(lmc));
			continue;
		}
		vty_out(vty, "Proto %s: [%u/%u]\n",
			zebra_route_string(lmc->proto), lmc->start, lmc->end);
	}
	if (uj) {
		json_object_object_add(json_global, "chunks", json_array);
		vty_json(vty, json_global);
	}
	return CMD_SUCCESS;
}

DEFPY(mpls_label_dynamic_block, mpls_label_dynamic_block_cmd,
      "[no$no] mpls label dynamic-block [(16-1048575)$start (16-1048575)$end]",
      NO_STR
      MPLS_STR
      "Label configuration\n"
      "Configure dynamic label block\n"
      "Start label\n"
      "End label\n")
{
	struct listnode *node;
	struct label_manager_chunk *lmc;

	/* unset dynamic range */
	if (no ||
	    (start == MPLS_LABEL_UNRESERVED_MIN && end == MPLS_LABEL_MAX)) {
		lbl_mgr.dynamic_block_start = MPLS_LABEL_UNRESERVED_MIN;
		lbl_mgr.dynamic_block_end = MPLS_LABEL_MAX;
		return CMD_SUCCESS;
	}
	if (!start || !end) {
		vty_out(vty,
			"%% label dynamic-block, range missing, aborting\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (start > end) {
		vty_out(vty,
			"%% label dynamic-block, wrong range (%ld > %ld), aborting\n",
			start, end);
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (ALL_LIST_ELEMENTS_RO(lbl_mgr.lc_list, node, lmc)) {
		if (lmc->proto == NO_PROTO)
			continue;
		if (!lmc->is_dynamic && lmc->start >= (uint32_t)start &&
		    lmc->end <= (uint32_t)end) {
			vty_out(vty,
				"%% Found a static label chunk [%u-%u] for %s in conflict with the dynamic label block\n",
				lmc->start, lmc->end,
				zebra_route_string(lmc->proto));
			return CMD_WARNING_CONFIG_FAILED;
		} else if (lmc->is_dynamic && (lmc->end > (uint32_t)end ||
					       lmc->start < (uint32_t)start)) {
			vty_out(vty,
				"%% Found a dynamic label chunk [%u-%u] for %s outside the new dynamic label block, consider restart the service\n",
				lmc->start, lmc->end,
				zebra_route_string(lmc->proto));
		}
	}
	lbl_mgr.dynamic_block_start = start;
	lbl_mgr.dynamic_block_end = end;
	return CMD_SUCCESS;
}

static int label_manager_write_label_block_config(struct vty *vty,
						  struct zebra_vrf *zvrf)
{
	if (zvrf_id(zvrf) != VRF_DEFAULT)
		return 0;
	if (lbl_mgr.dynamic_block_start == MPLS_LABEL_UNRESERVED_MIN &&
	    lbl_mgr.dynamic_block_end == MPLS_LABEL_MAX)
		return 0;
	vty_out(vty, "mpls label dynamic-block %u %u\n",
		lbl_mgr.dynamic_block_start, lbl_mgr.dynamic_block_end);
	return 1;
}

/**
 * Init label manager (or proxy to an external one)
 */
void label_manager_init(void)
{
	lbl_mgr.lc_list = list_new();
	lbl_mgr.lc_list->del = delete_label_chunk;
	lbl_mgr.dynamic_block_start = MPLS_LABEL_UNRESERVED_MIN;
	lbl_mgr.dynamic_block_end = MPLS_LABEL_MAX;
	hook_register(zserv_client_close, lm_client_disconnect_cb);

	/* register default hooks for the label manager actions */
	lm_hooks_register();

	/* notify any external module that we are done */
	hook_call(lm_cbs_inited);

	install_element(VIEW_NODE, &show_label_table_cmd);
	install_element(CONFIG_NODE, &mpls_label_dynamic_block_cmd);
}

void label_manager_terminate(void)
{
	list_delete(&lbl_mgr.lc_list);
}

/* alloc and fill a label chunk */
struct label_manager_chunk *
create_label_chunk(uint8_t proto, unsigned short instance, uint32_t session_id,
		   uint8_t keep, uint32_t start, uint32_t end, bool is_dynamic)
{
	/* alloc chunk, fill it and return it */
	struct label_manager_chunk *lmc =
		XCALLOC(MTYPE_LM_CHUNK, sizeof(struct label_manager_chunk));

	lmc->start = start;
	lmc->end = end;
	lmc->proto = proto;
	lmc->instance = instance;
	lmc->session_id = session_id;
	lmc->keep = keep;
	lmc->is_dynamic = is_dynamic;

	return lmc;
}

/* attempt to get a specific label chunk */
static struct label_manager_chunk *
assign_specific_label_chunk(uint8_t proto, unsigned short instance,
			    uint32_t session_id, uint8_t keep, uint32_t size,
			    uint32_t base)
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

	if ((lbl_mgr.dynamic_block_start != MPLS_LABEL_UNRESERVED_MIN ||
	     lbl_mgr.dynamic_block_end != MPLS_LABEL_MAX) &&
	    base >= lbl_mgr.dynamic_block_start &&
	    end <= lbl_mgr.dynamic_block_end) {
		zlog_warn("Invalid LM request arguments: base: %u, size: %u for %s in conflict with the dynamic label block",
			  base, size, zebra_route_string(proto));
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

		if (end <= lmc->end) {
			last_node = node;
			break;
		}
	}

	/* insert chunk between existing chunks */
	if (insert_node) {
		lmc = create_label_chunk(proto, instance, session_id, keep,
					 base, end, false);
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
			struct label_manager_chunk *death;

			next = listnextnode(node);
			death = listgetdata(node);
			list_delete_node(lbl_mgr.lc_list, node);
			delete_label_chunk(death);
		}

		lmc = create_label_chunk(proto, instance, session_id, keep,
					 base, end, false);
		if (last_node)
			listnode_add_before(lbl_mgr.lc_list, last_node, lmc);
		else
			listnode_add(lbl_mgr.lc_list, lmc);

		return lmc;
	} else {
		/* create a new chunk past all the existing ones and link at
		 * tail */
		lmc = create_label_chunk(proto, instance, session_id, keep,
					 base, end, false);
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
struct label_manager_chunk *
assign_label_chunk(uint8_t proto, unsigned short instance, uint32_t session_id,
		   uint8_t keep, uint32_t size, uint32_t base)
{
	struct label_manager_chunk *lmc;
	struct listnode *node;
	uint32_t prev_end = lbl_mgr.dynamic_block_start - 1;
	struct label_manager_chunk *lmc_block_last = NULL;

	/* handle chunks request with a specific base label
	 * - static label requests: BGP hardset value, Pathd
	 * - segment routing label requests
	 */
	if (base != MPLS_LABEL_BASE_ANY)
		return assign_specific_label_chunk(proto, instance, session_id,
						   keep, size, base);

	/* appease scan-build, who gets confused by the use of macros */
	assert(lbl_mgr.lc_list);

	/* first check if there's one available */
	for (ALL_LIST_ELEMENTS_RO(lbl_mgr.lc_list, node, lmc)) {
		if (lmc->start <= prev_end)
			continue;
		if (lmc->proto == NO_PROTO &&
		    lmc->end - lmc->start + 1 == size &&
		    lmc->end <= lbl_mgr.dynamic_block_end) {
			lmc->proto = proto;
			lmc->instance = instance;
			lmc->session_id = session_id;
			lmc->keep = keep;
			lmc->is_dynamic = true;
			return lmc;
		}
		/* check if we hadve a "hole" behind us that we can squeeze into
		 */
		if (lmc->start - prev_end > size &&
		    prev_end + 1 + size <= lbl_mgr.dynamic_block_end) {
			lmc = create_label_chunk(proto, instance, session_id,
						 keep, prev_end + 1,
						 prev_end + size, true);
			listnode_add_before(lbl_mgr.lc_list, node, lmc);
			return lmc;
		}
		prev_end = lmc->end;

		/* check if we have a chunk that goes over the end block */
		if (lmc->end > lbl_mgr.dynamic_block_end)
			continue;
		lmc_block_last = lmc;
	}
	/* otherwise create a new one */
	uint32_t start_free;

	if (lmc_block_last == NULL)
		start_free = lbl_mgr.dynamic_block_start;
	else
		start_free = lmc_block_last->end + 1;

	if (start_free > lbl_mgr.dynamic_block_end - size + 1) {
		flog_err(EC_ZEBRA_LM_EXHAUSTED_LABELS,
			 "Reached max labels. Start: %u, size: %u", start_free,
			 size);
		return NULL;
	}

	/* create chunk and link at tail */
	lmc = create_label_chunk(proto, instance, session_id, keep, start_free,
				 start_free + size - 1, true);
	listnode_add(lbl_mgr.lc_list, lmc);
	return lmc;
}

/**
 * Release label chunks from a client.
 *
 * Called on client disconnection or reconnection. It only releases chunks
 * with empty keep value.
 *
 * @param client Client zapi session
 * @param start First label of the chunk
 * @param end Last label of the chunk
 * @return 0 on success
 */
static int label_manager_release_label_chunk(struct zserv *client,
					     uint32_t start, uint32_t end)
{
	return release_label_chunk(client->proto, client->instance,
				   client->session_id, start, end);
}

/**
 * Core function, release no longer used label chunks
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param session_id Zclient session ID, to identify the zclient session
 * @param start First label of the chunk
 * @param end Last label of the chunk
 * @return 0 on success, -1 otherwise
 */
int release_label_chunk(uint8_t proto, unsigned short instance,
			uint32_t session_id, uint32_t start, uint32_t end)
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
		if (lmc->proto != proto || lmc->instance != instance ||
		    lmc->session_id != session_id) {
			flog_err(EC_ZEBRA_LM_DAEMON_MISMATCH,
				 "%s: Daemon mismatch!!", __func__);
			continue;
		}
		ret = 0;
		break;
	}
	if (lmc) {
		list_delete_node(lbl_mgr.lc_list, node);
		delete_label_chunk(lmc);
	}

	if (ret != 0)
		flog_err(EC_ZEBRA_LM_UNRELEASED_CHUNK,
			 "%s: Label chunk not released!!", __func__);

	return ret;
}

/* default functions to be called on hooks  */
static int label_manager_connect(struct zserv *client, vrf_id_t vrf_id)
{
	/*
	 * Release previous labels of same protocol and instance.
	 * This is done in case it restarted from an unexpected shutdown.
	 */
	release_daemon_label_chunks(client);
	return zsend_label_manager_connect_response(client, vrf_id, 0);
}
static int label_manager_disconnect(struct zserv *client)
{
	release_daemon_label_chunks(client);
	return 0;
}
static int label_manager_get_chunk(struct label_manager_chunk **lmc,
				   struct zserv *client, uint8_t keep,
				   uint32_t size, uint32_t base,
				   vrf_id_t vrf_id)
{
	*lmc = assign_label_chunk(client->proto, client->instance,
				  client->session_id, keep, size, base);
	/* Respond to a get_chunk request */
	if (!*lmc) {
		if (base == MPLS_LABEL_BASE_ANY)
			flog_err(EC_ZEBRA_LM_CANNOT_ASSIGN_CHUNK,
				 "Unable to assign Label Chunk size %u to %s instance %u",
				 size, zebra_route_string(client->proto),
				 client->instance);
		else
			flog_err(EC_ZEBRA_LM_CANNOT_ASSIGN_CHUNK,
				 "Unable to assign Label Chunk %u - %u to %s instance %u",
				 base, base + size - 1,
				 zebra_route_string(client->proto),
				 client->instance);
	} else if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("Assigned Label Chunk %u - %u to %s instance %u",
			   (*lmc)->start, (*lmc)->end,
			   zebra_route_string(client->proto), client->instance);

	return zsend_assign_label_chunk_response(client, vrf_id, *lmc);
}

/* Respond to a connect request */
int lm_client_connect_response(uint8_t proto, uint16_t instance,
			       uint32_t session_id, vrf_id_t vrf_id,
			       uint8_t result)
{
	struct zserv *client = zserv_find_client_session(proto, instance,
							 session_id);
	if (!client) {
		zlog_err("%s: could not find client for daemon %s instance %u session %u",
			 __func__, zebra_route_string(proto), instance,
			 session_id);
		return 1;
	}
	return zsend_label_manager_connect_response(client, vrf_id, result);
}

void label_manager_close(void)
{
	list_delete(&lbl_mgr.lc_list);
}
