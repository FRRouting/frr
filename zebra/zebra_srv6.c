// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 definitions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
 * Copyright (C) 2020  Masakazu Asama
 */

#include <zebra.h>

#include "network.h"
#include "prefix.h"
#include "stream.h"
#include "srv6.h"
#include "zebra/debug.h"
#include "zebra/zapi_msg.h"
#include "zebra/zserv.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_srv6.h"
#include "zebra/zebra_errors.h"
#include "zebra/ge_netlink.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>


DEFINE_MGROUP(SRV6_MGR, "SRv6 Manager");
DEFINE_MTYPE_STATIC(SRV6_MGR, SRV6M_CHUNK, "SRv6 Manager Chunk");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_BLOCK, "SRv6 SID block");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_FUNC, "SRv6 SID function");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_USID_WLIB,
		    "SRv6 uSID Wide LIB information");

/* define hooks for the basic API, so that it can be specialized or served
 * externally
 */

DEFINE_HOOK(srv6_manager_client_connect,
	    (struct zserv *client, vrf_id_t vrf_id),
	    (client, vrf_id));
DEFINE_HOOK(srv6_manager_client_disconnect,
	    (struct zserv *client), (client));
DEFINE_HOOK(srv6_manager_get_chunk,
	    (struct srv6_locator **loc,
	     struct zserv *client,
	     const char *locator_name,
	     vrf_id_t vrf_id),
	    (loc, client, locator_name, vrf_id));
DEFINE_HOOK(srv6_manager_release_chunk,
	    (struct zserv *client,
	     const char *locator_name,
	     vrf_id_t vrf_id),
	    (client, locator_name, vrf_id));

/* define wrappers to be called in zapi_msg.c (as hooks must be called in
 * source file where they were defined)
 */

void srv6_manager_client_connect_call(struct zserv *client, vrf_id_t vrf_id)
{
	hook_call(srv6_manager_client_connect, client, vrf_id);
}

void srv6_manager_get_locator_chunk_call(struct srv6_locator **loc,
					 struct zserv *client,
					 const char *locator_name,
					 vrf_id_t vrf_id)
{
	hook_call(srv6_manager_get_chunk, loc, client, locator_name, vrf_id);
}

void srv6_manager_release_locator_chunk_call(struct zserv *client,
					     const char *locator_name,
					     vrf_id_t vrf_id)
{
	hook_call(srv6_manager_release_chunk, client, locator_name, vrf_id);
}

int srv6_manager_client_disconnect_cb(struct zserv *client)
{
	hook_call(srv6_manager_client_disconnect, client);
	return 0;
}

static int zebra_srv6_cleanup(struct zserv *client)
{
	return 0;
}

/* --- Zebra SRv6 SID format management functions --------------------------- */

void srv6_sid_format_register(struct srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	/* Ensure that the format is registered only once */
	assert(!srv6_sid_format_lookup(format->name));

	listnode_add(srv6->sid_formats, format);
}

void srv6_sid_format_unregister(struct srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	listnode_delete(srv6->sid_formats, format);
}

struct srv6_sid_format *srv6_sid_format_lookup(const char *name)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_sid_format *format;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->sid_formats, node, format))
		if (!strncmp(name, format->name, sizeof(format->name)))
			return format;

	return NULL;
}

/*
 * Helper function to create the SRv6 compressed format `usid-f3216`.
 */
static struct srv6_sid_format *create_srv6_sid_format_usid_f3216(void)
{
	struct srv6_sid_format *format = NULL;

	format = srv6_sid_format_alloc(SRV6_SID_FORMAT_USID_F3216_NAME);

	format->type = SRV6_SID_FORMAT_TYPE_USID;

	/* Define block/node/function length */
	format->block_len = SRV6_SID_FORMAT_USID_F3216_BLOCK_LEN;
	format->node_len = SRV6_SID_FORMAT_USID_F3216_NODE_LEN;
	format->function_len = SRV6_SID_FORMAT_USID_F3216_FUNCTION_LEN;
	format->argument_len = SRV6_SID_FORMAT_USID_F3216_ARGUMENT_LEN;

	/* Define the ranges from which the SID function can be allocated */
	format->config.usid.lib_start = SRV6_SID_FORMAT_USID_F3216_LIB_START;
	format->config.usid.elib_start = SRV6_SID_FORMAT_USID_F3216_ELIB_START;
	format->config.usid.elib_end = SRV6_SID_FORMAT_USID_F3216_ELIB_END;
	format->config.usid.wlib_start = SRV6_SID_FORMAT_USID_F3216_WLIB_START;
	format->config.usid.wlib_end = SRV6_SID_FORMAT_USID_F3216_WLIB_END;
	format->config.usid.ewlib_start = SRV6_SID_FORMAT_USID_F3216_EWLIB_START;

	return format;
}

/*
 * Helper function to create the SRv6 uncompressed format.
 */
static struct srv6_sid_format *create_srv6_sid_format_uncompressed(void)
{
	struct srv6_sid_format *format = NULL;

	format = srv6_sid_format_alloc(SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NAME);

	format->type = SRV6_SID_FORMAT_TYPE_UNCOMPRESSED;

	/* Define block/node/function length */
	format->block_len = SRV6_SID_FORMAT_UNCOMPRESSED_F4024_BLOCK_LEN;
	format->node_len = SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE_LEN;
	format->function_len = SRV6_SID_FORMAT_UNCOMPRESSED_F4024_FUNCTION_LEN;
	format->argument_len = SRV6_SID_FORMAT_UNCOMPRESSED_F4024_ARGUMENT_LEN;

	/* Define the ranges from which the SID function can be allocated */
	format->config.uncompressed.explicit_start =
		SRV6_SID_FORMAT_UNCOMPRESSED_F4024_EXPLICIT_RANGE_START;

	return format;
}

/* --- Zebra SRv6 SID function management functions ---------------------------- */

uint32_t *zebra_srv6_sid_func_alloc(uint32_t func)
{
	uint32_t *sid_func_ptr;

	sid_func_ptr = XCALLOC(MTYPE_ZEBRA_SRV6_SID_FUNC, sizeof(uint32_t));
	*sid_func_ptr = func;

	return sid_func_ptr;
}

void zebra_srv6_sid_func_free(uint32_t *func)
{
	XFREE(MTYPE_ZEBRA_SRV6_SID_FUNC, func);
}

/**
 * Free an SRv6 SID function.
 *
 * @param val SRv6 SID function to be freed
 */
void delete_zebra_srv6_sid_func(void *val)
{
	zebra_srv6_sid_func_free((uint32_t *)val);
}

/* --- Zebra SRv6 SID block management functions ---------------------------- */

static struct zebra_srv6_sid_block *zebra_srv6_sid_block_alloc_internal(void)
{
	struct zebra_srv6_sid_block *block = NULL;

	block = XCALLOC(MTYPE_ZEBRA_SRV6_SID_BLOCK,
			sizeof(struct zebra_srv6_sid_block));

	return block;
}

struct zebra_srv6_sid_block *
zebra_srv6_sid_block_alloc(struct srv6_sid_format *format,
			   struct prefix_ipv6 *prefix)
{
	struct zebra_srv6_sid_block *block;

	block = zebra_srv6_sid_block_alloc_internal();
	block->sid_format = format;
	block->prefix = *prefix;

	if (format) {
		if (format->type == SRV6_SID_FORMAT_TYPE_USID) {
			uint32_t wlib_start, wlib_end, func;

			/* Init uSID LIB */
			block->u.usid.lib.func_allocated = list_new();
			block->u.usid.lib.func_allocated->del =
				delete_zebra_srv6_sid_func;
			block->u.usid.lib.func_released = list_new();
			block->u.usid.lib.func_released->del =
				delete_zebra_srv6_sid_func;
			block->u.usid.lib.first_available_func =
				format->config.usid.lib_start;

			/* Init uSID Wide LIB */
			wlib_start = block->sid_format->config.usid.wlib_start;
			wlib_end = block->sid_format->config.usid.wlib_end;
			block->u.usid.wide_lib =
				XCALLOC(MTYPE_ZEBRA_SRV6_USID_WLIB,
					(wlib_end - wlib_start + 1) *
						sizeof(struct wide_lib));
			for (func = 0; func < wlib_end - wlib_start + 1;
			     func++) {
				block->u.usid.wide_lib[func].func_allocated =
					list_new();
				block->u.usid.wide_lib[func].func_allocated->del =
					delete_zebra_srv6_sid_func;
				block->u.usid.wide_lib[func].func_released =
					list_new();
				block->u.usid.wide_lib[func].func_released->del =
					delete_zebra_srv6_sid_func;
				block->u.usid.wide_lib[func].func = func;
			}
		} else if (format->type == SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
			block->u.uncompressed.func_allocated = list_new();
			block->u.uncompressed.func_allocated->del =
				delete_zebra_srv6_sid_func;
			block->u.uncompressed.func_released = list_new();
			block->u.uncompressed.func_released->del =
				delete_zebra_srv6_sid_func;
			block->u.uncompressed.first_available_func =
				SRV6_SID_FORMAT_UNCOMPRESSED_F4024_FUNC_UNRESERVED_MIN;
		} else {
			/* We should never arrive here */
			assert(0);
		}
	} else {
		block->u.uncompressed.func_allocated = list_new();
		block->u.uncompressed.func_allocated->del =
			delete_zebra_srv6_sid_func;
		block->u.uncompressed.func_released = list_new();
		block->u.uncompressed.func_released->del =
			delete_zebra_srv6_sid_func;
		block->u.uncompressed.first_available_func = 1;
	}

	return block;
}

void zebra_srv6_sid_block_free(struct zebra_srv6_sid_block *block)
{
	if (block->sid_format) {
		if (block->sid_format->type == SRV6_SID_FORMAT_TYPE_USID) {
			uint32_t wlib_start, wlib_end, func;

			/* Free uSID LIB */
			list_delete(&block->u.usid.lib.func_allocated);
			list_delete(&block->u.usid.lib.func_released);

			/* Free uSID Wide LIB */
			wlib_start = block->sid_format->config.usid.wlib_start;
			wlib_end = block->sid_format->config.usid.wlib_end;
			for (func = 0; func < wlib_end - wlib_start + 1;
			     func++) {
				list_delete(&block->u.usid.wide_lib[func]
						     .func_allocated);
				list_delete(&block->u.usid.wide_lib[func]
						     .func_released);
			}
			XFREE(MTYPE_ZEBRA_SRV6_USID_WLIB,
			      block->u.usid.wide_lib);
		} else if (block->sid_format->type ==
			   SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
			list_delete(&block->u.uncompressed.func_allocated);
			list_delete(&block->u.uncompressed.func_released);
		} else {
			/* We should never arrive here */
			assert(0);
		}
	} else {
		list_delete(&block->u.uncompressed.func_allocated);
		list_delete(&block->u.uncompressed.func_released);
	}

	XFREE(MTYPE_ZEBRA_SRV6_SID_BLOCK, block);
}

/**
 * Free an SRv6 SID block.
 *
 * @param val SRv6 SID block to be freed
 */
void delete_zebra_srv6_sid_block(void *val)
{
	zebra_srv6_sid_block_free((struct zebra_srv6_sid_block *)val);
}

struct zebra_srv6_sid_block *
zebra_srv6_sid_block_lookup(struct prefix_ipv6 *prefix)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_sid_block *block;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->sid_blocks, node, block))
		if (prefix_match(prefix, &block->prefix))
			return block;

	return NULL;
}

void zebra_srv6_locator_add(struct srv6_locator *locator)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *tmp;
	struct listnode *node;
	struct zserv *client;

	tmp = zebra_srv6_locator_lookup(locator->name);
	if (!tmp)
		listnode_add(srv6->locators, locator);

	/*
	 * Notify new locator info to zclients.
	 *
	 * The srv6 locators and their prefixes are managed by zserv(zebra).
	 * And an actual configuration the srv6 sid in the srv6 locator is done
	 * by zclient(bgpd, isisd, etc). The configuration of each locator
	 * allocation and specify it by zserv and zclient should be
	 * asynchronous. For that, zclient should be received the event via
	 * ZAPI when a srv6 locator is added on zebra.
	 * Basically, in SRv6, adding/removing SRv6 locators is performed less
	 * frequently than adding rib entries, so a broad to all zclients will
	 * not degrade the overall performance of FRRouting.
	 */
	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client))
		zsend_zebra_srv6_locator_add(client, locator);
}

void zebra_srv6_locator_delete(struct srv6_locator *locator)
{
	struct listnode *n;
	struct srv6_locator_chunk *c;
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zserv *client;

	/*
	 * Notify deleted locator info to zclients if needed.
	 *
	 * zclient(bgpd,isisd,etc) allocates a sid from srv6 locator chunk and
	 * uses it for its own purpose. For example, in the case of BGP L3VPN,
	 * the SID assigned to vpn unicast rib will be given.
	 * And when the locator is deleted by zserv(zebra), those SIDs need to
	 * be withdrawn. The zclient must initiate the withdrawal of the SIDs
	 * by ZEBRA_SRV6_LOCATOR_DELETE, and this notification is sent to the
	 * owner of each chunk.
	 */
	for (ALL_LIST_ELEMENTS_RO((struct list *)locator->chunks, n, c)) {
		if (c->proto == ZEBRA_ROUTE_SYSTEM)
			continue;
		client = zserv_find_client(c->proto, c->instance);
		if (!client) {
			zlog_warn(
				"%s: Not found zclient(proto=%u, instance=%u).",
				__func__, c->proto, c->instance);
			continue;
		}
		zsend_zebra_srv6_locator_delete(client, locator);
	}

	listnode_delete(srv6->locators, locator);
	srv6_locator_free(locator);
}

struct srv6_locator *zebra_srv6_locator_lookup(const char *name)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator))
		if (!strncmp(name, locator->name, SRV6_LOCNAME_SIZE))
			return locator;
	return NULL;
}

void zebra_notify_srv6_locator_add(struct srv6_locator *locator)
{
	struct listnode *node;
	struct zserv *client;

	/*
	 * Notify new locator info to zclients.
	 *
	 * The srv6 locators and their prefixes are managed by zserv(zebra).
	 * And an actual configuration the srv6 sid in the srv6 locator is done
	 * by zclient(bgpd, isisd, etc). The configuration of each locator
	 * allocation and specify it by zserv and zclient should be
	 * asynchronous. For that, zclient should be received the event via
	 * ZAPI when a srv6 locator is added on zebra.
	 * Basically, in SRv6, adding/removing SRv6 locators is performed less
	 * frequently than adding rib entries, so a broad to all zclients will
	 * not degrade the overall performance of FRRouting.
	 */
	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client))
		zsend_zebra_srv6_locator_add(client, locator);
}

void zebra_notify_srv6_locator_delete(struct srv6_locator *locator)
{
	struct listnode *n;
	struct srv6_locator_chunk *c;
	struct zserv *client;

	/*
	 * Notify deleted locator info to zclients if needed.
	 *
	 * zclient(bgpd,isisd,etc) allocates a sid from srv6 locator chunk and
	 * uses it for its own purpose. For example, in the case of BGP L3VPN,
	 * the SID assigned to vpn unicast rib will be given.
	 * And when the locator is deleted by zserv(zebra), those SIDs need to
	 * be withdrawn. The zclient must initiate the withdrawal of the SIDs
	 * by ZEBRA_SRV6_LOCATOR_DELETE, and this notification is sent to the
	 * owner of each chunk.
	 */
	for (ALL_LIST_ELEMENTS_RO((struct list *)locator->chunks, n, c)) {
		if (c->proto == ZEBRA_ROUTE_SYSTEM)
			continue;
		client = zserv_find_client(c->proto, c->instance);
		if (!client) {
			zlog_warn("Not found zclient(proto=%u, instance=%u).",
				  c->proto, c->instance);
			continue;
		}
		zsend_zebra_srv6_locator_delete(client, locator);
	}
}

struct zebra_srv6 srv6;

struct zebra_srv6 *zebra_srv6_get_default(void)
{
	static bool first_execution = true;
	struct srv6_sid_format *format_usidf3216;
	struct srv6_sid_format *format_uncompressed;

	if (first_execution) {
		first_execution = false;
		srv6.locators = list_new();

		/* Initialize list of SID formats */
		srv6.sid_formats = list_new();
		srv6.sid_formats->del = delete_srv6_sid_format;

		/* Create SID format `usid-f3216` */
		format_usidf3216 = create_srv6_sid_format_usid_f3216();
		srv6_sid_format_register(format_usidf3216);

		/* Create SID format `uncompressed` */
		format_uncompressed = create_srv6_sid_format_uncompressed();
		srv6_sid_format_register(format_uncompressed);

		/* Init list to store SRv6 SID blocks */
		srv6.sid_blocks = list_new();
		srv6.sid_blocks->del = delete_zebra_srv6_sid_block;
	}
	return &srv6;
}

/**
 * Core function, assigns srv6-locator chunks
 *
 * It first searches through the list to check if there's one available
 * (previously released). Otherwise it creates and assigns a new one
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param session_id SessionID of client
 * @param name Name of SRv6-locator
 * @return Pointer to the assigned srv6-locator chunk,
 *         or NULL if the request could not be satisfied
 */
static struct srv6_locator *
assign_srv6_locator_chunk(uint8_t proto,
			  uint16_t instance,
			  uint32_t session_id,
			  const char *locator_name)
{
	bool chunk_found = false;
	struct listnode *node = NULL;
	struct srv6_locator *loc = NULL;
	struct srv6_locator_chunk *chunk = NULL;

	loc = zebra_srv6_locator_lookup(locator_name);
	if (!loc) {
		zlog_info("%s: locator %s was not found",
			  __func__, locator_name);
		return NULL;
	}

	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->chunks, node, chunk)) {
		if (chunk->proto != NO_PROTO && chunk->proto != proto)
			continue;
		chunk_found = true;
		break;
	}

	if (!chunk_found) {
		zlog_info("%s: locator is already owned", __func__);
		return NULL;
	}

	chunk->proto = proto;
	chunk->instance = instance;
	chunk->session_id = session_id;
	return loc;
}

static int zebra_srv6_manager_get_locator_chunk(struct srv6_locator **loc,
						struct zserv *client,
						const char *locator_name,
						vrf_id_t vrf_id)
{
	int ret = 0;

	*loc = assign_srv6_locator_chunk(client->proto, client->instance,
					 client->session_id, locator_name);

	if (!*loc)
		zlog_err("Unable to assign locator chunk to %s instance %u",
			 zebra_route_string(client->proto), client->instance);
	else if (IS_ZEBRA_DEBUG_PACKET)
		zlog_info("Assigned locator chunk %s to %s instance %u",
			  (*loc)->name, zebra_route_string(client->proto),
			  client->instance);

	if (*loc && (*loc)->status_up)
		ret = zsend_srv6_manager_get_locator_chunk_response(client,
								    vrf_id,
								    *loc);
	return ret;
}

/**
 * Core function, release no longer used srv6-locator chunks
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param session_id Zclient session ID, to identify the zclient session
 * @param locator_name SRv6-locator name, to identify the actual locator
 * @return 0 on success, -1 otherwise
 */
static int release_srv6_locator_chunk(uint8_t proto, uint16_t instance,
				      uint32_t session_id,
				      const char *locator_name)
{
	int ret = -1;
	struct listnode *node;
	struct srv6_locator_chunk *chunk;
	struct srv6_locator *loc = NULL;

	loc = zebra_srv6_locator_lookup(locator_name);
	if (!loc)
		return -1;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Releasing srv6-locator on %s", __func__,
			   locator_name);

	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->chunks, node, chunk)) {
		if (chunk->proto != proto ||
		    chunk->instance != instance ||
		    chunk->session_id != session_id)
			continue;
		chunk->proto = NO_PROTO;
		chunk->instance = 0;
		chunk->session_id = 0;
		chunk->keep = 0;
		ret = 0;
		break;
	}

	if (ret != 0)
		flog_err(EC_ZEBRA_SRV6M_UNRELEASED_LOCATOR_CHUNK,
			 "%s: SRv6 locator chunk not released", __func__);

	return ret;
}

static int zebra_srv6_manager_release_locator_chunk(struct zserv *client,
						    const char *locator_name,
						    vrf_id_t vrf_id)
{
	if (vrf_id != VRF_DEFAULT) {
		zlog_err("SRv6 locator doesn't support vrf");
		return -1;
	}

	return release_srv6_locator_chunk(client->proto, client->instance,
					  client->session_id, locator_name);
}

/**
 * Release srv6-locator chunks from a client.
 *
 * Called on client disconnection or reconnection. It only releases chunks
 * with empty keep value.
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @return Number of chunks released
 */
int release_daemon_srv6_locator_chunks(struct zserv *client)
{
	int ret;
	int count = 0;
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *loc_node;
	struct listnode *chunk_node;
	struct srv6_locator *loc;
	struct srv6_locator_chunk *chunk;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Releasing chunks for client proto %s, instance %d, session %u",
			   __func__, zebra_route_string(client->proto),
			   client->instance, client->session_id);

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, loc_node, loc)) {
		for (ALL_LIST_ELEMENTS_RO(loc->chunks, chunk_node, chunk)) {
			if (chunk->proto == client->proto &&
			    chunk->instance == client->instance &&
			    chunk->session_id == client->session_id &&
			    chunk->keep == 0) {
				ret = release_srv6_locator_chunk(
						chunk->proto, chunk->instance,
						chunk->session_id, loc->name);
				if (ret == 0)
					count++;
			}
		}
	}

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Released %d srv6-locator chunks",
			   __func__, count);

	return count;
}

void zebra_srv6_encap_src_addr_set(struct in6_addr *encap_src_addr)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	if (!encap_src_addr)
		return;

	memcpy(&srv6->encap_src_addr, encap_src_addr, sizeof(struct in6_addr));
}

void zebra_srv6_encap_src_addr_unset(void)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	memset(&srv6->encap_src_addr, 0, sizeof(struct in6_addr));
}

void zebra_srv6_terminate(void)
{
	struct srv6_locator *locator;
	struct srv6_sid_format *format;
	struct zebra_srv6_sid_block *block;

	if (srv6.locators) {
		while (listcount(srv6.locators)) {
			locator = listnode_head(srv6.locators);

			listnode_delete(srv6.locators, locator);
			srv6_locator_free(locator);
		}

		list_delete(&srv6.locators);
	}

	/* Free SRv6 SID blocks */
	if (srv6.sid_blocks) {
		while (listcount(srv6.sid_blocks)) {
			block = listnode_head(srv6.sid_blocks);

			listnode_delete(srv6.sid_blocks, block);
			zebra_srv6_sid_block_free(block);
		}

		list_delete(&srv6.sid_blocks);
	}

	/* Free SRv6 SID formats */
	if (srv6.sid_formats) {
		while (listcount(srv6.sid_formats)) {
			format = listnode_head(srv6.sid_formats);

			srv6_sid_format_unregister(format);
			srv6_sid_format_free(format);
		}

		list_delete(&srv6.sid_formats);
	}
}

void zebra_srv6_init(void)
{
	hook_register(zserv_client_close, zebra_srv6_cleanup);
	hook_register(srv6_manager_get_chunk,
		      zebra_srv6_manager_get_locator_chunk);
	hook_register(srv6_manager_release_chunk,
		      zebra_srv6_manager_release_locator_chunk);
}

bool zebra_srv6_is_enable(void)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	return listcount(srv6->locators);
}
