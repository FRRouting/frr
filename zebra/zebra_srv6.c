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


DEFINE_QOBJ_TYPE(zebra_srv6_locator);
DEFINE_QOBJ_TYPE(zebra_srv6_sid_format);
DEFINE_MGROUP(SRV6_MGR, "SRv6 Manager");
DEFINE_MTYPE_STATIC(SRV6_MGR, SRV6M_CHUNK, "SRv6 Manager Chunk");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_LOCATOR, "Zebra SRv6 locator");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_FORMAT, "SRv6 SID format");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_BLOCK, "SRv6 SID block");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_FUNC, "Zebra SRv6 SID function");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_USID_WLIB,
		    "Zebra SRv6 uSID Wide LIB information");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID, "Zebra SRv6 SID");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_CTX, "Zebra SRv6 SID context");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_OWNER, "Zebra SRv6 SID owner");

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

DEFINE_HOOK(srv6_manager_get_sid,
	    (struct zebra_srv6_sid **sid, struct zserv *client,
	     struct srv6_sid_ctx *ctx, struct in6_addr *sid_value,
	     const char *locator_name),
	    (sid, client, ctx, sid_value, locator_name));
DEFINE_HOOK(srv6_manager_release_sid,
	    (struct zserv *client, struct srv6_sid_ctx *ctx), (client, ctx));
DEFINE_HOOK(srv6_manager_get_locator,
	    (struct zebra_srv6_locator **locator, struct zserv *client,
	     const char *locator_name),
	    (locator, client, locator_name));

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

void srv6_manager_get_sid_call(struct zebra_srv6_sid **sid,
			       struct zserv *client, struct srv6_sid_ctx *ctx,
			       struct in6_addr *sid_value,
			       const char *locator_name)
{
	hook_call(srv6_manager_get_sid, sid, client, ctx, sid_value,
		  locator_name);
}

void srv6_manager_release_sid_call(struct zserv *client,
				   struct srv6_sid_ctx *ctx)
{
	hook_call(srv6_manager_release_sid, client, ctx);
}

void srv6_manager_get_locator_call(struct zebra_srv6_locator **locator,
				   struct zserv *client,
				   const char *locator_name)
{
	hook_call(srv6_manager_get_locator, locator, client, locator_name);
}

static int zebra_srv6_cleanup(struct zserv *client)
{
	release_daemon_srv6_sids(client);
	return 0;
}

/* --- SRv6 SID owner management functions -------------------------------- */

void zebra_srv6_sid_owner_free(struct zebra_srv6_sid_owner *owner)
{
	XFREE(MTYPE_ZEBRA_SRV6_SID_OWNER, owner);
}

/**
 * Free an SRv6 SID owner object.
 *
 * @param val SRv6 SID owner to be freed
 */
void delete_zebra_srv6_sid_owner(void *val)
{
	zebra_srv6_sid_owner_free((struct zebra_srv6_sid_owner *)val);
}

/**
 * Check whether an SRv6 SID is owned by a specific protocol daemon or not.
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param sid SRv6 SID to verify
 * @return True if the SID is owned by the protocol daemon, False otherwise
 */
bool sid_is_owned_by_proto(uint8_t proto, unsigned short instance,
			   struct zebra_srv6_sid *sid)
{
	struct zebra_srv6_sid_owner *owner;
	struct listnode *node;

	if (!sid)
		return false;

	for (ALL_LIST_ELEMENTS_RO(sid->owners, node, owner)) {
		if (owner->proto == proto && owner->instance == instance)
			return true;
	}

	return false;
}

/**
 * Add a client daemon the owners list of an SRv6 SID.
 *
 * @param SID to which the owner needs to be added
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @return True if success, False otherwise
 */
bool zebra_srv6_sid_owner_add(struct zebra_srv6_sid *sid, uint8_t proto,
			      unsigned short instance)
{
	struct zebra_srv6_sid_owner *owner;

	if (!sid)
		return false;

	owner = XCALLOC(MTYPE_ZEBRA_SRV6_SID_OWNER,
			sizeof(struct zebra_srv6_sid_owner));
	owner->proto = proto;
	owner->instance = instance;

	listnode_add(sid->owners, owner);

	return true;
}

/**
 * Remove a client daemon from the owners list of an SRv6 SID.
 *
 * @param SID to which the owner needs to be removed
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @return True if success, False otherwise
 */
bool zebra_srv6_sid_owner_del(struct zebra_srv6_sid *sid, uint8_t proto,
			      unsigned short instance, uint32_t session_id)
{
	struct zebra_srv6_sid_owner *owner;
	struct listnode *node, *nnode;

	if (!sid)
		return false;

	for (ALL_LIST_ELEMENTS(sid->owners, node, nnode, owner)) {
		if (owner->proto == proto && owner->instance == instance) {
			listnode_delete(sid->owners, owner);
			zebra_srv6_sid_owner_free(owner);
		}
	}

	return true;
}

/* --- Zebra SRv6 SID context management functions -------------------------- */

struct zebra_srv6_sid_ctx *zebra_srv6_sid_ctx_alloc(void)
{
	struct zebra_srv6_sid_ctx *ctx = NULL;

	ctx = XCALLOC(MTYPE_ZEBRA_SRV6_SID_CTX,
		      sizeof(struct zebra_srv6_sid_ctx));

	return ctx;
}

void zebra_srv6_sid_ctx_free(struct zebra_srv6_sid_ctx *ctx)
{
	XFREE(MTYPE_ZEBRA_SRV6_SID_CTX, ctx);
}

/**
 * Free an SRv6 SID context.
 *
 * @param val SRv6 SID context to be freed
 */
void delete_zebra_srv6_sid_ctx(void *val)
{
	zebra_srv6_sid_ctx_free((struct zebra_srv6_sid_ctx *)val);
}

/* --- Zebra SRv6 SID format management functions --------------------------- */

struct zebra_srv6_sid_format *zebra_srv6_sid_format_alloc(const char *name)
{
	struct zebra_srv6_sid_format *format = NULL;

	format = XCALLOC(MTYPE_ZEBRA_SRV6_SID_FORMAT,
			 sizeof(struct zebra_srv6_sid_format));
	strlcpy(format->name, name, sizeof(format->name));

	QOBJ_REG(format, zebra_srv6_sid_format);
	return format;
}

void zebra_srv6_sid_format_free(struct zebra_srv6_sid_format *format)
{
	if (format) {
		QOBJ_UNREG(format);
		XFREE(MTYPE_ZEBRA_SRV6_SID_FORMAT, format);
	}
}

/**
 * Free an SRv6 SID format.
 *
 * @param val SRv6 SID format to be freed
 */
void delete_zebra_srv6_sid_format(void *val)
{
	zebra_srv6_sid_format_free((struct zebra_srv6_sid_format *)val);
}

void zebra_srv6_sid_format_add(struct zebra_srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	if (!zebra_srv6_sid_format_lookup(format->name))
		listnode_add(srv6->sid_formats, format);
}

void zebra_srv6_sid_format_delete(struct zebra_srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	listnode_delete(srv6->sid_formats, format);
	zebra_srv6_sid_format_free(format);
}

struct zebra_srv6_sid_format *zebra_srv6_sid_format_lookup(const char *name)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_sid_format *format;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->sid_formats, node, format))
		if (!strncmp(name, format->name, sizeof(format->name)))
			return format;

	return NULL;
}

/*
 * Called when a SID format is modified by the user.
 *
 * After modifying a SID format, the SIDs that are using that format may no
 * longer be valid.
 * This function walks through the list of locators that are using the SID format
 * and notifies the zclients that the locator has changed, so that the zclients
 * can withdraw/uninstall the old SIDs, allocate/advertise/program the new SIDs.
 */
void zebra_srv6_sid_format_changed_cb(struct zebra_srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_locator *locator;
	struct listnode *node;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: SID format %s has changed. Notifying zclients.",
			   __func__, format->name);

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator))
		if (locator->sid_format == format) {
			if (IS_ZEBRA_DEBUG_PACKET)
				zlog_debug("%s: Locator %s has changed because its format (%s) has been modified. Notifying zclients.",
					   __func__, locator->locator.name,
					   format->name);

			/* Notify zclients that the locator is no longer valid */
			zebra_notify_srv6_locator_delete(locator);

			/* Update the locator based on the new SID format */
			locator->locator.block_bits_length = format->block_len;
			locator->locator.node_bits_length = format->node_len;
			locator->locator.function_bits_length =
				format->function_len;
			locator->locator.argument_bits_length =
				format->argument_len;
			if (format->type ==
			    ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID)
				SET_FLAG(locator->locator.flags,
					 SRV6_LOCATOR_USID);
			else
				UNSET_FLAG(locator->locator.flags,
					   SRV6_LOCATOR_USID);

			/* Notify zclients about the new locator */
			zebra_notify_srv6_locator_add(locator);
		}
}

/*
 * Helper function to create the SRv6 compressed format `usid-f3216`.
 */
static struct zebra_srv6_sid_format *create_srv6_sid_format_usid_f3216(void)
{
	struct zebra_srv6_sid_format *format = NULL;

	format = zebra_srv6_sid_format_alloc(
		ZEBRA_SRV6_SID_FORMAT_USID_F3216_NAME);

	format->type = ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID;

	/* Define block/node/function length */
	format->block_len = ZEBRA_SRV6_SID_FORMAT_USID_F3216_BLOCK_LEN;
	format->node_len = ZEBRA_SRV6_SID_FORMAT_USID_F3216_NODE_LEN;
	format->function_len = ZEBRA_SRV6_SID_FORMAT_USID_F3216_FUNCTION_LEN;
	format->argument_len = ZEBRA_SRV6_SID_FORMAT_USID_F3216_ARGUMENT_LEN;

	/* Define the ranges from which the function is allocated */
	format->config.usid.lib_start =
		ZEBRA_SRV6_SID_FORMAT_USID_F3216_LIB_START;
	format->config.usid.elib_start =
		ZEBRA_SRV6_SID_FORMAT_USID_F3216_ELIB_START;
	format->config.usid.elib_end = ZEBRA_SRV6_SID_FORMAT_USID_F3216_ELIB_END;
	format->config.usid.wlib_start =
		ZEBRA_SRV6_SID_FORMAT_USID_F3216_WLIB_START;
	format->config.usid.wlib_end = ZEBRA_SRV6_SID_FORMAT_USID_F3216_WLIB_END;
	format->config.usid.ewlib_start =
		ZEBRA_SRV6_SID_FORMAT_USID_F3216_EWLIB_START;

	return format;
}

/*
 * Helper function to create the SRv6 uncompressed format.
 */
static struct zebra_srv6_sid_format *create_srv6_sid_format_uncompressed(void)
{
	struct zebra_srv6_sid_format *format = NULL;

	format = zebra_srv6_sid_format_alloc(
		ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_NAME);

	format->type = ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED;

	/* Define block/node/function length */
	format->block_len = ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_BLOCK_LEN;
	format->node_len = ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_NODE_LEN;
	format->function_len = ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_FUNCTION_LEN;
	format->argument_len = ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_ARGUMENT_LEN;

	/* Define the ranges from which the function is allocated */
	format->config.uncompressed.explicit_start =
		ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_EXPLICIT_RANGE_START;

	return format;
}

/* --- Zebra SRv6 SID function management functions ---------------------------- */

uint32_t *zebra_srv6_sid_func_alloc(void)
{
	return XCALLOC(MTYPE_ZEBRA_SRV6_SID_FUNC, sizeof(uint32_t));
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
zebra_srv6_sid_block_alloc(struct zebra_srv6_sid_format *format)
{
	struct zebra_srv6_sid_block *block;

	block = zebra_srv6_sid_block_alloc_internal();
	block->sid_format = format;

	if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID) {
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
		block->u.usid.wide_lib = XCALLOC(MTYPE_ZEBRA_SRV6_USID_WLIB,
						 (wlib_end - wlib_start +
						  1) * sizeof(struct wide_lib));
		for (func = 0; func < wlib_end - wlib_start + 1; func++) {
			block->u.usid.wide_lib[func].func_allocated = list_new();
			block->u.usid.wide_lib[func].func_allocated->del =
				delete_zebra_srv6_sid_func;
			block->u.usid.wide_lib[func].func_released = list_new();
			block->u.usid.wide_lib[func].func_released->del =
				delete_zebra_srv6_sid_func;
		}
	} else if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
		block->u.uncompressed.func_allocated = list_new();
		block->u.uncompressed.func_allocated->del =
			delete_zebra_srv6_sid_func;
		block->u.uncompressed.func_released = list_new();
		block->u.uncompressed.func_released->del =
			delete_zebra_srv6_sid_func;
		block->u.uncompressed.first_available_func =
			ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_FUNC_UNRESERVED_MIN;
	} else {
		/* We should never arrive here */
		assert(0);
	}

	return block;
}

void zebra_srv6_sid_block_free(struct zebra_srv6_sid_block *block)
{
	/*
	 * We expect the zebra_srv6_sid_block_free function to be called only
	 * when the block is no longer referenced by anyone
	 */
	assert(block->refcnt == 0);

	if (block->sid_format->type ==
	    ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID) {
		uint32_t wlib_start, wlib_end, func;

		/* Free uSID LIB */
		list_delete(&block->u.usid.lib.func_allocated);
		list_delete(&block->u.usid.lib.func_released);

		/* Free uSID Wide LIB */
		wlib_start = block->sid_format->config.usid.wlib_start;
		wlib_end = block->sid_format->config.usid.wlib_end;
		for (func = 0; func < wlib_end - wlib_start + 1; func++) {
			list_delete(
				&block->u.usid.wide_lib[func].func_allocated);
			list_delete(&block->u.usid.wide_lib[func].func_released);
		}
		XFREE(MTYPE_ZEBRA_SRV6_USID_WLIB, block->u.usid.wide_lib);
	} else if (block->sid_format->type ==
		   ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
		list_delete(&block->u.uncompressed.func_allocated);
		list_delete(&block->u.uncompressed.func_released);
	} else {
		/* We should never arrive here */
		assert(0);
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

/* --- Zebra SRv6 SID management functions ---------------------------------- */

/**
 * Alloc and fill an SRv6 SID.
 *
 * @param ctx Context associated with the SID to be created
 * @param sid_value IPv6 address associated with the SID to be created
 * @param locator Parent locator of the SID to be created
 * @param sid_block Block from which the SID value has been allocated
 * @param sid_func Function part of the SID to be created
 * @param alloc_mode Allocation mode of the Function (dynamic vs explicit)
 * @return The requested SID
 */
struct zebra_srv6_sid *
zebra_srv6_sid_alloc(struct zebra_srv6_sid_ctx *ctx, struct in6_addr *sid_value,
		     struct zebra_srv6_locator *locator,
		     struct zebra_srv6_sid_block *sid_block, uint32_t sid_func,
		     enum srv6_sid_alloc_mode alloc_mode)
{
	struct zebra_srv6_sid *sid;

	if (!ctx || !sid_value)
		return NULL;

	sid = XCALLOC(MTYPE_ZEBRA_SRV6_SID, sizeof(struct zebra_srv6_sid));
	sid->ctx = ctx;
	sid->value = *sid_value;
	sid->locator = locator;
	sid->block = sid_block;
	sid->func = sid_func;
	sid->alloc_mode = alloc_mode;
	sid->owners = list_new();
	sid->owners->del = delete_zebra_srv6_sid_owner;

	return sid;
}

void zebra_srv6_sid_free(struct zebra_srv6_sid *sid)
{
	list_delete(&sid->owners);
	XFREE(MTYPE_ZEBRA_SRV6_SID, sid);
}

/**
 * Free an SRv6 SID.
 *
 * @param val SRv6 SID to be freed
 */
void delete_zebra_srv6_sid(void *val)
{
	zebra_srv6_sid_free((struct zebra_srv6_sid *)val);
}

/* --- Zebra SRv6 locator management functions ------------------------------ */

struct zebra_srv6_locator *zebra_srv6_locator_alloc(const char *name)
{
	struct zebra_srv6_locator *locator = NULL;

	locator = XCALLOC(MTYPE_ZEBRA_SRV6_LOCATOR,
			  sizeof(struct zebra_srv6_locator));
	strlcpy(locator->locator.name, name, sizeof(locator->locator.name));
	locator->locator.chunks = list_new();
	locator->locator.chunks->del = srv6_locator_chunk_list_free;

	QOBJ_REG(locator, zebra_srv6_locator);
	return locator;
}

void zebra_srv6_locator_free(struct zebra_srv6_locator *locator)
{
	if (!locator)
		return;

	QOBJ_UNREG(locator);
	list_delete(&locator->locator.chunks);
	XFREE(MTYPE_ZEBRA_SRV6_LOCATOR, locator);
}

void zebra_srv6_locator_add(struct zebra_srv6_locator *locator)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_locator *tmp;
	struct listnode *node;
	struct zserv *client;

	tmp = zebra_srv6_locator_lookup(locator->locator.name);
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
		zsend_zebra_srv6_locator_add(client, &locator->locator);
}

void zebra_srv6_locator_delete(struct zebra_srv6_locator *locator)
{
	struct listnode *n;
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zserv *client;

	/*
	 * Notify deleted locator info to zclients.
	 *
	 * zclient(bgpd,isisd,etc) allocates a sid and
	 * uses it for its own purpose. For example, in the case of BGP L3VPN,
	 * the SID assigned to vpn unicast rib will be given.
	 * And when the locator is deleted by zserv(zebra), those SIDs need to
	 * be withdrawn. The zclient must initiate the withdrawal of the SIDs
	 * by ZEBRA_SRV6_LOCATOR_DELETE, and this notification is sent to the
	 * owner of each chunk.
	 */
	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, n, client))
		zsend_zebra_srv6_locator_delete(client, &locator->locator);

	listnode_delete(srv6->locators, locator);
	zebra_srv6_locator_free(locator);
}

struct zebra_srv6_locator *zebra_srv6_locator_lookup(const char *name)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_locator *locator;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator))
		if (!strncmp(name, locator->locator.name, SRV6_LOCNAME_SIZE))
			return locator;
	return NULL;
}

void zebra_notify_srv6_locator_add(struct zebra_srv6_locator *locator)
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
		zsend_zebra_srv6_locator_add(client, &locator->locator);
}

void zebra_notify_srv6_locator_delete(struct zebra_srv6_locator *locator)
{
	struct listnode *n;
	struct zserv *client;

	/*
	 * Notify deleted locator info to zclients.
	 *
	 * zclient(bgpd,isisd,etc) allocates a sid and
	 * uses it for its own purpose. For example, in the case of BGP L3VPN,
	 * the SID assigned to vpn unicast rib will be given.
	 * And when the locator is deleted by zserv(zebra), those SIDs need to
	 * be withdrawn. The zclient must initiate the withdrawal of the SIDs
	 * by ZEBRA_SRV6_LOCATOR_DELETE, and this notification is sent to the
	 * all zclients.
	 */
	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, n, client))
		zsend_zebra_srv6_locator_delete(client, &locator->locator);
}

struct zebra_srv6 srv6;

struct zebra_srv6 *zebra_srv6_get_default(void)
{
	static bool first_execution = true;
	struct zebra_srv6_sid_format *format_usidf3216;
	struct zebra_srv6_sid_format *format_uncompressed;

	if (first_execution) {
		first_execution = false;
		srv6.locators = list_new();

		/* Initialize list of sid formats */
		srv6.sid_formats = list_new();
		srv6.sid_formats->del = delete_zebra_srv6_sid_format;

		/* Create SID format `usid-f3216` */
		format_usidf3216 = create_srv6_sid_format_usid_f3216();
		zebra_srv6_sid_format_add(format_usidf3216);

		/* Create SID format `uncompressed` */
		format_uncompressed = create_srv6_sid_format_uncompressed();
		zebra_srv6_sid_format_add(format_uncompressed);

		/* Init list to store SRv6 SIDs */
		srv6.sids = list_new();
		srv6.sids->del = delete_zebra_srv6_sid_ctx;

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
	struct zebra_srv6_locator *loc = NULL;
	struct srv6_locator_chunk *chunk = NULL;

	loc = zebra_srv6_locator_lookup(locator_name);
	if (!loc) {
		zlog_info("%s: locator %s was not found",
			  __func__, locator_name);
		return NULL;
	}

	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->locator.chunks, node,
				  chunk)) {
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
	return &loc->locator;
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
	struct zebra_srv6_locator *loc = NULL;

	loc = zebra_srv6_locator_lookup(locator_name);
	if (!loc)
		return -1;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Releasing srv6-locator on %s", __func__,
			   locator_name);

	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->locator.chunks, node,
				  chunk)) {
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

/* --- SRv6 SID Allocation/Release functions -------------------------------- */

/**
 * Return the SRv6 SID obtained composing the LOCATOR and FUNCTION.
 *
 * @param sid_value SRv6 SID address returned
 * @param locator Parent locator of the SRv6 SID
 * @param sid_func Function part of the SID
 * @return True if success, False otherwise
 */
static bool zebra_srv6_sid_compose(struct in6_addr *sid_value,
				   struct zebra_srv6_locator *locator,
				   uint32_t sid_func)
{
	uint8_t offset, func_len;
	struct zebra_srv6_sid_format *format = locator->sid_format;

	if (!sid_value || !locator)
		return false;

	offset = format->block_len + format->node_len;
	func_len = format->function_len;

	*sid_value = locator->locator.prefix.prefix;
	for (uint8_t idx = 0; idx < func_len; idx++) {
		uint8_t tidx = offset + idx;

		sid_value->s6_addr[tidx / 8] &= ~(0x1 << (7 - tidx % 8));
		if (sid_func >> (func_len - 1 - idx) & 0x1)
			sid_value->s6_addr[tidx / 8] |= 0x1 << (7 - tidx % 8);
	}

	return true;
}

/**
 * Return the LOCATOR and FUNCTION of an SRv6 SID.
 *
 * @param sid_value SRv6 SID address to be decomposed
 * @param sid_block Parent block of the SRv6 SID
 * @param locator Parent locator of the SRv6 SID
 * @param sid_func Function part of the SID
 * @param sid_wide_func Wide function of the SID
 * @return True if success, False otherwise
 */
static bool zebra_srv6_sid_decompose(struct in6_addr *sid_value,
				     struct zebra_srv6_sid_block **sid_block,
				     struct zebra_srv6_locator **locator,
				     uint32_t *sid_func, uint32_t *sid_wide_func)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_locator *l;
	struct zebra_srv6_sid_block *b;
	struct zebra_srv6_sid_format *format;
	struct listnode *node;
	struct prefix_ipv6 tmp_prefix;
	uint8_t offset, func_len;

	if (!sid_value || !sid_func)
		return false;

	*sid_func = 0;
	*sid_wide_func = 0;

	/*
	 * Build a temporary prefix_ipv6 object representing the SRv6 SID.
	 * This temporary prefix object is used below by the prefix_match
	 * function to check if the SID belongs to a specific locator.
	 */
	tmp_prefix.family = AF_INET6;
	tmp_prefix.prefixlen = IPV6_MAX_BITLEN;
	tmp_prefix.prefix = *sid_value;

	/*
	 * Lookup the parent locator of the SID and return the LOCATOR and
	 * the FUNCTION of the SID.
	 */
	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, l)) {
		/*
		 * Check if the LOCATOR prefix includes the temporary prefix
		 * representing the SID.
		 */
		if (prefix_match((struct prefix *)&l->locator.prefix,
				 (struct prefix *)&tmp_prefix)) {
			format = l->sid_format;

			/* skip locators with unspecified format */
			if (!format)
				continue;

			offset = format->block_len + format->node_len;
			func_len = format->function_len;

			for (uint8_t idx = 0; idx < func_len; idx++) {
				uint8_t tidx = offset + idx;
				*sid_func |= (sid_value->s6_addr[tidx / 8] &
					      (0x1 << (7 - tidx % 8)))
					     << (((func_len - 1 - idx) / 8) * 8);
			}

			/*
			 * If function comes from the Wide LIB range, we also
			 * need to get the Wide function.
			 */
			if (*sid_func >= format->config.usid.wlib_start &&
			    *sid_func <= format->config.usid.wlib_end) {
				format = l->sid_format;

				offset = format->block_len + format->node_len +
					 format->function_len;

				for (uint8_t idx = 0; idx < 16; idx++) {
					uint8_t tidx = offset + idx;
					*sid_wide_func |=
						(sid_value->s6_addr[tidx / 8] &
						 (0x1 << (7 - tidx % 8)))
						<< (((16 - 1 - idx) / 8) * 8);
				}
			}

			*locator = l;
			*sid_block = l->sid_block;

			return true;
		}
	}

	/*
	 * If we arrive here, the SID does not belong to any locator.
	 * Then, let's try to find the parent block from which the SID
	 * has been allocated.
	 */

	/*
	 * Lookup the parent block of the SID and return the BLOCK and
	 * the FUNCTION of the SID.
	 */
	for (ALL_LIST_ELEMENTS_RO(srv6->sid_blocks, node, b)) {
		/*
		 * Check if the BLOCK prefix includes the temporary prefix
		 * representing the SID
		 */
		if (prefix_match((struct prefix *)&b->prefix,
				 (struct prefix *)&tmp_prefix)) {
			format = b->sid_format;

			offset = format->block_len + format->node_len;
			func_len = format->function_len;

			for (uint8_t idx = 0; idx < func_len; idx++) {
				uint8_t tidx = offset + idx;
				*sid_func |= (sid_value->s6_addr[tidx / 8] &
					      (0x1 << (7 - tidx % 8)))
					     << ((func_len - 1 - idx) / 8);
			}

			/*
			 * If function comes from the Wide LIB range, we also
			 * need to get the Wide function.
			 */
			if (*sid_func >= format->config.usid.wlib_start &&
			    *sid_func <= format->config.usid.wlib_end) {
				format = b->sid_format;

				offset = format->block_len + format->node_len +
					 format->function_len;

				for (uint8_t idx = 0; idx < 16; idx++) {
					uint8_t tidx = offset + idx;
					*sid_wide_func |=
						(sid_value->s6_addr[tidx / 8] &
						 (0x1 << (7 - tidx % 8)))
						<< (((16 - 1 - idx) / 8) * 8);
				}
			}

			*sid_block = b;

			return true;
		}
	}

	return false;
}

/**
 * Handle explicit SID allocation request.
 *
 * Explicit allocation allocates a specific SID.
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param session_id Zclient session ID, to identify the zclient session
 * @param ctx Context associated with the SID to be allocated
 * @param sid_value SRv6 SID address associated with the SID to be
 * allocated explicitly
 *
 * @return Pointer to the allocated SRv6 SID, or NULL if the request
 * could not be satisfied
 */
static struct zebra_srv6_sid *
assign_explicit_srv6_sid(uint8_t proto, unsigned short instance,
			 uint32_t session_id, struct srv6_sid_ctx *ctx,
			 struct in6_addr *sid_value)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_sid *sid = NULL;
	struct zebra_srv6_sid_ctx *s = NULL;
	struct zebra_srv6_sid_ctx *zctx;
	struct listnode *node;
	uint32_t sid_func = 0, sid_func_wide = 0;
	uint32_t *sid_func_ptr = NULL;
	struct zebra_srv6_locator *locator = NULL;
	struct zebra_srv6_sid_block *block = NULL;
	struct zebra_srv6_sid_format *format;
	char buf[256];
	bool is_alloc_from_wide_lib = false;

	if (!ctx || !sid_value)
		return NULL;

	/* Check if we already have a SID associated with the provided context */
	for (ALL_LIST_ELEMENTS_RO(srv6->sids, node, s)) {
		if (memcmp(&s->ctx, ctx, sizeof(struct srv6_sid_ctx)) == 0) {
			zlog_err("%s: cannot alloc SID %pI6 for ctx %s: ctx already associated with SID %pI6",
				 __func__, sid_value,
				 srv6_sid_ctx2str(buf, sizeof(buf), &s->ctx),
				 &s->sid->value);
			return NULL;
		}
	}

	/* Get parent LOCATOR and FUNCTION of the provided SID */
	if (!zebra_srv6_sid_decompose(sid_value, &block, &locator, &sid_func,
				      &sid_func_wide)) {
		zlog_err("%s: invalid SM request arguments: parent block/locator not found for SID %pI6",
			 __func__, sid_value);
		return NULL;
	}

	format = block->sid_format;
	assert(format);

	if (ctx->behavior == ZEBRA_SEG6_LOCAL_ACTION_END) {
		zlog_err("%s: invalid SM request arguments: explicit SID allocation not allowed for End/uN behavior",
			 __func__);
		return NULL;
	}

	/*
	 * Verify that the explicit SID requested for allocation is valid
	 * (i.e., it comes from one of the ranges reserved for explicit allocation,
	 * has not already been allocated, ...).
	 */
	if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID) {
		uint32_t elib_start = format->config.usid.elib_start;
		uint32_t elib_end = format->config.usid.elib_end;
		uint32_t wlib_start = format->config.usid.wlib_start;
		uint32_t wlib_end = format->config.usid.wlib_end;
		uint32_t ewlib_start = format->config.usid.ewlib_start;
		uint32_t ewlib_end = wlib_end;

		if (!(sid_func >= elib_start || sid_func <= elib_end) &&
		    !(sid_func >= ewlib_start || sid_func <= ewlib_end)) {
			zlog_err("%s: invalid SM request arguments: SID function %u out of ELIB (%u - %u) and EWLIB (%u - %u) ranges",
				 __func__, sid_func, elib_start, elib_end,
				 ewlib_start, ewlib_end);
			return NULL;
		}

		if (sid_func >= wlib_start && sid_func <= wlib_end) {
			/* SID function comes from the Wide LIB range */

			for (ALL_LIST_ELEMENTS_RO(block->u.usid
							  .wide_lib[sid_func -
								    wlib_start]
							  .func_allocated,
						  node, sid_func_ptr))
				if (*sid_func_ptr == sid_func_wide)
					break;

			if (sid_func_ptr) {
				zlog_err("%s: invalid SM request arguments: SID wide function %u already assigned",
					 __func__, sid_func_wide);
				return NULL;
			}

			is_alloc_from_wide_lib = true;
		} else {
			/* SID function comes from the LIB range */

			for (ALL_LIST_ELEMENTS_RO(block->u.usid.lib.func_allocated,
						  node, sid_func_ptr))
				if (*sid_func_ptr == sid_func)
					break;

			if (sid_func_ptr) {
				zlog_err("%s: invalid SM request arguments: SID function %u already assigned",
					 __func__, sid_func);
				return NULL;
			}
		}
	} else if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
		uint32_t explicit_start =
			format->config.uncompressed.explicit_start;
		uint32_t explicit_end =
			(uint32_t)((1 << format->function_len) - 1);

		if (!(sid_func >= explicit_start && sid_func <= explicit_end)) {
			zlog_err("%s: invalid SM request arguments: SID function %u out of explicit range (%u - %u)",
				 __func__, sid_func, explicit_start,
				 explicit_end);
			return NULL;
		}

		for (ALL_LIST_ELEMENTS_RO(block->u.uncompressed.func_allocated,
					  node, sid_func_ptr))
			if (*sid_func_ptr == sid_func)
				break;

		if (sid_func_ptr) {
			zlog_err("%s: invalid SM request arguments: SID function %u already assigned",
				 __func__, sid_func);
			return NULL;
		}
	} else {
		/* We should never arrive here */
		zlog_err("%s: unknown SID format type: %u", __func__,
			 format->type);
		assert(0);
	}

	/* The SID requested for explicit allocation is valid; let's allocate it! */

	zctx = zebra_srv6_sid_ctx_alloc();
	zctx->ctx = *ctx;

	sid = zebra_srv6_sid_alloc(zctx, sid_value, locator, block, sid_func,
				   SRV6_SID_ALLOC_MODE_EXPLICIT);
	if (!sid) {
		flog_err(EC_ZEBRA_SM_CANNOT_ASSIGN_SID,
			 "%s: failed to create SRv6 SID %s (%pI6)", __func__,
			 srv6_sid_ctx2str(buf, sizeof(buf), ctx), sid_value);
		return NULL;
	}
	zebra_srv6_sid_owner_add(sid, proto, instance);
	sid->ctx = zctx;
	zctx->sid = sid;
	listnode_add(srv6->sids, zctx);

	/* Mark the SID function as used by adding it to the func_allocated list */
	sid_func_ptr = zebra_srv6_sid_func_alloc();
	if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID) {
		uint32_t wlib_start = format->config.usid.wlib_start;

		if (is_alloc_from_wide_lib) {
			*sid_func_ptr = sid_func_wide;
			listnode_add(block->u.usid
					     .wide_lib[sid_func - wlib_start]
					     .func_allocated,
				     sid_func_ptr);
			block->u.usid.wide_lib[sid_func - wlib_start]
				.num_func_allocated++;
		} else {
			*sid_func_ptr = sid_func;
			listnode_add(block->u.usid.lib.func_allocated,
				     sid_func_ptr);
			block->u.usid.lib.num_func_allocated++;
		}
	} else if (format &&
		   format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
		*sid_func_ptr = sid_func;
		listnode_add(block->u.uncompressed.func_allocated, sid_func_ptr);
		block->u.uncompressed.num_func_allocated++;
	}

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: created new SRv6 SID %pI6 for context %s to %s instance %u",
			   __func__, &sid->value,
			   srv6_sid_ctx2str(buf, sizeof(buf), ctx),
			   zebra_route_string(proto), instance);

	return sid;
}

/**
 * Handle dynamic SID allocation request.
 *
 * Dynamic allocation allocates any available SID.
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param session_id Zclient session ID, to identify the zclient session
 * @param ctx Context associated with the SRv6 SID
 * @param locator Parent locator to allocate the SID from
 *
 * @return Pointer to the assigned SRv6 SID, or NULL if the request could not
 * be satisfied
 */
static struct zebra_srv6_sid *
assign_dynamic_srv6_sid(uint8_t proto, unsigned short instance,
			uint32_t session_id, struct srv6_sid_ctx *ctx,
			struct zebra_srv6_locator *locator)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_sid_block *block;
	struct zebra_srv6_sid_format *format;
	struct zebra_srv6_sid *sid;
	struct zebra_srv6_sid_ctx *s = NULL;
	struct zebra_srv6_sid_ctx *zctx;
	struct listnode *node;
	struct in6_addr sid_value;
	uint32_t sid_func = 0;
	uint32_t *sid_func_ptr;
	char buf[256];

	if (!ctx || !locator)
		return NULL;

	block = locator->sid_block;
	format = locator->sid_format;

	/*
	 * If we already have a SID for the provided context, we share the existing
	 * SID instead of allocating a new one.
	 */
	for (ALL_LIST_ELEMENTS_RO(srv6->sids, node, s)) {
		if (memcmp(&s->ctx, ctx, sizeof(struct srv6_sid_ctx)) == 0) {
			if (IS_ZEBRA_DEBUG_PACKET)
				zlog_debug("%s: sharing existing SID %s %pI6 with proto=%u, instance=%u, sessionId=%u",
					   __func__,
					   srv6_sid_ctx2str(buf, sizeof(buf),
							    ctx),
					   &s->sid->value, proto, instance,
					   session_id);
			zebra_srv6_sid_owner_add(s->sid, proto, instance);
			return s->sid;
		}
	}

	/* Allocate SID from the corresponding range depending on the SID format type and behavior */
	if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID) {
		if (ctx->behavior == ZEBRA_SEG6_LOCAL_ACTION_END) {
			/* Case 1: format is uSID and behavior is uN => allocate SID from GIB range */
			sid_value = locator->locator.prefix.prefix;
		} else {
			/* Case 2: format is uSID and behavior is not uN => allocate SID from LIB range */

			uint32_t first_available_func =
				block->u.usid.lib.first_available_func;

			uint32_t elib_start = format->config.usid.elib_start;

			/* Check if we ran out of available function IDs */
			if (first_available_func >= elib_start) {
				zlog_warn("%s: SRv6: Warning, SRv6 Dynamic LIB is depleted",
					  __func__);
				return NULL;
			}

			if (listcount(block->u.usid.lib.func_released) != 0) {
				/*
				 * First, let's check if there's any function that was previously
				 * allocated and released that we can reuse now.
				 */
				sid_func_ptr = listnode_head(
					block->u.usid.lib.func_released);
				sid_func = *sid_func_ptr;
				listnode_delete(block->u.usid.lib.func_released,
						sid_func_ptr);
				zebra_srv6_sid_func_free(sid_func_ptr);
			} else {
				/*
				 * If there are no released functions, then we allocate the first
				 * function from the pool of available functions.
				 */
				sid_func = first_available_func;
				first_available_func++;
			}

			block->u.usid.lib.num_func_allocated++;

			if (first_available_func == elib_start)
				zlog_warn("%s: SRv6: Warning, SRv6 Dynamic LIB is depleted and next SID request will fail",
					  __func__);

			block->u.usid.lib.first_available_func =
				first_available_func;

			/* Compose SID as the LOCATOR followed by the FUNCTION */
			zebra_srv6_sid_compose(&sid_value, locator, sid_func);
		}
	} else if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
		/* Case 3: format is uncompressed => allocate SID from Dynamic range */

		uint32_t dynamic_end =
			format->config.uncompressed.explicit_start - 1;

		uint32_t first_available_func =
			block->u.uncompressed.first_available_func;

		/* Check if we ran out of available function IDs */
		if (first_available_func > dynamic_end) {
			zlog_warn("%s: SRv6: Warning, SRv6 SID Dynamic alloc space is depleted",
				  __func__);
			return NULL;
		}

		if (listcount(block->u.uncompressed.func_released) != 0) {
			/*
			 * First, let's check if there's any function that was previously
			 * allocated and released that we can reuse now.
			 */
			sid_func_ptr = listnode_head(
				block->u.uncompressed.func_released);
			sid_func = *sid_func_ptr;
			listnode_delete(block->u.uncompressed.func_released,
					sid_func_ptr);
			zebra_srv6_sid_func_free(sid_func_ptr);
		} else {
			/*
			 * If there are no released functions, then we allocate the first
			 * function from the pool of available functions.
			 */
			sid_func = first_available_func;
			first_available_func++;
		}

		block->u.uncompressed.num_func_allocated++;

		if (first_available_func > dynamic_end)
			zlog_warn("%s: SRv6: Warning, SRv6 SID alloc space is depleted and next SID request will fail",
				  __func__);

		block->u.uncompressed.first_available_func =
			first_available_func;

		/* Compose SID as the LOCATOR followed by the FUNCTION */
		zebra_srv6_sid_compose(&sid_value, locator, sid_func);
	} else {
		if (format)
			zlog_err("%s: Unknown SID format type: %u", __func__,
				 format->type);
		/* We should never arrive here */
		assert(0);
	}

	/* Allocate memory and return the SID */
	zctx = zebra_srv6_sid_ctx_alloc();
	zctx->ctx = *ctx;

	sid = zebra_srv6_sid_alloc(zctx, &sid_value, locator, block, sid_func,
				   SRV6_SID_ALLOC_MODE_DYNAMIC);
	if (!sid) {
		flog_err(EC_ZEBRA_SM_CANNOT_ASSIGN_SID,
			 "%s: failed to create SRv6 SID ctx %s (%pI6)", __func__,
			 srv6_sid_ctx2str(buf, sizeof(buf), ctx), &sid_value);
		return NULL;
	}
	zebra_srv6_sid_owner_add(sid, proto, instance);
	sid->ctx = zctx;
	zctx->sid = sid;
	listnode_add(srv6->sids, zctx);

	return sid;
}

/**
 * Core function, assigns SRv6 SIDs.
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param session_id Zclient session ID, to identify the zclient session
 * @param alloc_mode SID allocation mode (explicit vs dynamic)
 * @param ctx Context associated with the SRv6 SID
 * @param sid_value SRv6 SID value for explicit SID allocation
 * @param locator_name Name of the parent SRv6 locator for dynamic SID allocation
 * @return Pointer to the assigned SRv6 SID, or NULL if the request could not be satisfied
 */
struct zebra_srv6_sid *
assign_srv6_sid(uint8_t proto, unsigned short instance, uint32_t session_id,
		enum srv6_sid_alloc_mode alloc_mode, struct srv6_sid_ctx *ctx,
		struct in6_addr *sid_value, const char *locator_name)
{
	struct zebra_srv6_locator *locator;
	struct zebra_srv6_sid *sid = NULL;
	char buf[256];

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: received SRv6 SID alloc request (proto=%u, instance=%u, sessionId=%u): SID ctx %s (%pI6), mode=%s",
			   __func__, proto, instance, session_id,
			   srv6_sid_ctx2str(buf, sizeof(buf), ctx), sid_value,
			   srv6_sid_alloc_mode2str(alloc_mode));

	switch (alloc_mode) {
	case SRV6_SID_ALLOC_MODE_EXPLICIT:
		/*
		 * Handle SIDs request with a specific SID FUNCTION
		 * (explicit allocation)
		 */
		if (!sid_value) {
			zlog_err("%s: invalid SM request arguments: missing SRv6 SID value, necessary for explicit allocation",
				 __func__);
			return NULL;
		}

		sid = assign_explicit_srv6_sid(proto, instance, session_id, ctx,
					       sid_value);

		break;
	case SRV6_SID_ALLOC_MODE_DYNAMIC:
		/*
		 * Handle SIDs request with any available SID FUNCTION
		 * (dynamic allocation)
		 */
		if (!locator_name) {
			zlog_err("%s: invalid SM request arguments: missing SRv6 locator, necessary for dynamic allocation",
				 __func__);
			return NULL;
		}

		locator = zebra_srv6_locator_lookup(locator_name);
		if (!locator) {
			zlog_err("%s: invalid SM request arguments: SRv6 locator '%s' does not exist",
				 __func__, locator_name);
			return NULL;
		}

		if (!locator->sid_format) {
			zlog_err("%s: invalid SM request arguments: format of SRv6 locator '%s' not specified",
				 __func__, locator_name);
			return NULL;
		}

		sid = assign_dynamic_srv6_sid(proto, instance, session_id, ctx,
					      locator);

		break;
	case SRV6_SID_ALLOC_MODE_MAX:
	case SRV6_SID_ALLOC_MODE_UNSPEC:
	default:
		flog_err(EC_ZEBRA_SM_CANNOT_ASSIGN_SID,
			 "%s: SRv6 Manager: Unrecognized alloc mode %u",
			 __func__, alloc_mode);
		/* We should never arrive here */
		assert(0);
	}

	return sid;
}

/**
 * Core function, release a explicit SRv6 SID.
 *
 * @param ctx Context associated with the SRv6 SID
 * @return 0 on success, -1 otherwise
 */
static int release_explicit_srv6_sid(struct zebra_srv6_sid_ctx *ctx)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *node;
	uint32_t *sid_func_ptr = NULL;
	struct zebra_srv6_sid_block *block = ctx->sid->block;
	struct zebra_srv6_sid_format *format = block->sid_format;
	uint32_t sid_func = ctx->sid->func;

	if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID) {
		uint32_t elib_start = format->config.usid.elib_start;
		uint32_t elib_end = format->config.usid.elib_end;
		uint32_t ewlib_start = format->config.usid.ewlib_start;
		uint32_t ewlib_end = format->config.usid.wlib_end;
		uint32_t sid_wide_func = ctx->sid->wide_func;
		uint32_t *sid_wide_func_ptr = NULL;

		/* Ensure that FUNC falls within one of the valid allocation ranges */
		if (!(sid_func >= elib_start && sid_func <= elib_end) &&
		    !(sid_func >= ewlib_start && sid_func <= ewlib_end)) {
			zlog_warn("%s: function %u is outside ELIB [%u/%u] and EWLIB alloc ranges [%u/%u]",
				  __func__, sid_func, elib_start, elib_end,
				  ewlib_start, ewlib_end);
			return -1;
		}

		if ((sid_func >= elib_start) && (sid_func <= elib_end)) {
			/* SID allocated from ELIB range */

			for (ALL_LIST_ELEMENTS_RO(block->u.usid.lib.func_allocated,
						  node, sid_func_ptr))
				if (*sid_func_ptr == sid_func)
					break;

			if (!sid_func_ptr) {
				zlog_warn("%s: failed to release SID function %u, function is not allocated",
					  __func__, sid_func);
				return -1;
			}

			listnode_delete(block->u.usid.lib.func_allocated,
					sid_func_ptr);
			XFREE(MTYPE_ZEBRA_SRV6_SID_FUNC, sid_func_ptr);
		} else {
			/* SID allocated from EWLIB range */

			/* Lookup SID wide function in Wide LIB and release */
			for (ALL_LIST_ELEMENTS_RO(block->u.usid
							  .wide_lib[sid_func]
							  .func_allocated,
						  node, sid_wide_func_ptr))
				if (*sid_wide_func_ptr == sid_wide_func)
					break;

			if (!sid_wide_func_ptr) {
				zlog_warn("%s: failed to release SID wide function %u, function is not allocated",
					  __func__, sid_func);
				return -1;
			}
			listnode_delete(block->u.usid.wide_lib[sid_func]
						.func_allocated,
					sid_wide_func_ptr);
			XFREE(MTYPE_ZEBRA_SRV6_SID_FUNC, sid_wide_func_ptr);
		}
	} else if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
		uint32_t explicit_start =
			format->config.uncompressed.explicit_start;
		uint32_t explicit_end =
			(uint32_t)((1 << format->function_len) - 1);

		/* Ensure that FUNC falls within one of the valid allocation ranges */
		if (!(sid_func >= explicit_start && sid_func <= explicit_end)) {
			zlog_warn("%s: function %u is outside explicit alloc range [%u/%u]",
				  __func__, sid_func, 0, explicit_end);
			return -1;
		}

		for (ALL_LIST_ELEMENTS_RO(block->u.uncompressed.func_allocated,
					  node, sid_func_ptr))
			if (*sid_func_ptr == sid_func)
				break;

		if (!sid_func_ptr) {
			zlog_warn("%s: failed to release SID function %u, function is not allocated",
				  __func__, sid_func);
			return -1;
		}

		listnode_delete(block->u.uncompressed.func_allocated,
				sid_func_ptr);
		XFREE(MTYPE_ZEBRA_SRV6_SID_FUNC, sid_func_ptr);
	}

	/* Free the SID */
	delete_zebra_srv6_sid(ctx->sid);
	ctx->sid = NULL;

	/* Remove the SID context from the list and free memory */
	listnode_delete(srv6->sids, ctx);
	delete_zebra_srv6_sid_ctx(ctx);

	return 0;
}

/**
 * Core function, release a dynamic SRv6 SID.
 *
 * @param ctx Context associated with the SRv6 SID
 * @return 0 on success, -1 otherwise
 */
static int release_dynamic_srv6_sid(struct zebra_srv6_sid_ctx *ctx)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *node, *nnode;
	uint32_t *sid_func_ptr = NULL;
	struct zebra_srv6_sid_block *block = ctx->sid->block;
	struct zebra_srv6_sid_format *format = block->sid_format;
	uint32_t sid_func = ctx->sid->func;

	if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID) {
		uint32_t lib_start = format->config.usid.lib_start;
		uint32_t elib_start = format->config.usid.elib_start;

		/*
		 * sid_func=0 indicates that the SID has been allocated from the GIB.
		 */
		if (sid_func == 0)
			return 0;

		/* Ensure that FUNC falls within the Dynamic LIB */
		if (!(sid_func >= lib_start && sid_func < elib_start)) {
			zlog_warn("%s: function %u is outside valid alloc range [%u/%u]",
				  __func__, sid_func, 0, elib_start - 1);
			return -1;
		}

		if (sid_func == block->u.usid.lib.first_available_func - 1) {
			/*
			 * The released SID function immediately precedes the `first_available_func`.
			 * Reset first_available_func to the first available position.
			 */

			block->u.usid.lib.first_available_func -= 1;

			bool found;

			do {
				found = false;
				for (ALL_LIST_ELEMENTS(block->u.usid.lib
							       .func_released,
						       node, nnode,
						       sid_func_ptr))
					if (*sid_func_ptr ==
					    block->u.usid.lib.first_available_func -
						    1) {
						listnode_delete(block->u.usid
									.lib
									.func_released,
								sid_func_ptr);
						XFREE(MTYPE_ZEBRA_SRV6_SID_FUNC,
						      sid_func_ptr);
						block->u.usid.lib
							.first_available_func -=
							1;
						found = true;
						break;
					}
			} while (found);
		} else {
			/*
			 * The released SID function does not immediately precede the `first_available_func`.
			 * Add the released function to the func_released array to indicate
			 * that it is available again for allocation.
			 */
			sid_func_ptr = XCALLOC(MTYPE_ZEBRA_SRV6_SID_FUNC,
					       sizeof(uint32_t));
			*sid_func_ptr = sid_func;
			listnode_add_head(block->u.usid.lib.func_released,
					  sid_func_ptr);
		}
	} else if (format->type == ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
		uint32_t dynamic_start =
			ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_FUNC_UNRESERVED_MIN;
		uint32_t dynamic_end =
			format->config.uncompressed.explicit_start - 1;

		/* Ensure that FUNC falls within one of the valid allocation ranges */
		if (!(sid_func >= dynamic_start && sid_func <= dynamic_end)) {
			zlog_warn("%s: function %u is outside dynamic range [%u/%u]",
				  __func__, sid_func,
				  ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_FUNC_UNRESERVED_MIN,
				  dynamic_end);
			return -1;
		}

		/* Reset first_available_func to the first available position */
		if (sid_func == block->u.uncompressed.first_available_func - 1) {
			block->u.uncompressed.first_available_func -= 1;

			bool found;

			do {
				found = false;
				for (ALL_LIST_ELEMENTS(block->u.uncompressed
							       .func_released,
						       node, nnode,
						       sid_func_ptr))
					if (*sid_func_ptr ==
					    block->u.uncompressed
							    .first_available_func -
						    1) {
						listnode_delete(block->u.uncompressed
									.func_released,
								sid_func_ptr);
						XFREE(MTYPE_ZEBRA_SRV6_SID_FUNC,
						      sid_func_ptr);
						block->u.uncompressed
							.first_available_func -=
							1;
						found = true;
						break;
					}
			} while (found);
		} else {
			/*
			 * Add the released function to the func_released array to indicate
			 * that it is available again for allocation.
			 */
			sid_func_ptr = XCALLOC(MTYPE_ZEBRA_SRV6_SID_FUNC,
					       sizeof(uint32_t));
			*sid_func_ptr = sid_func;
			listnode_add_head(block->u.uncompressed.func_released,
					  sid_func_ptr);
		}
	}

	/* Free the SID */
	delete_zebra_srv6_sid(ctx->sid);
	ctx->sid = NULL;

	/* Remove the SID context from the list and free memory */
	listnode_delete(srv6->sids, ctx);
	delete_zebra_srv6_sid_ctx(ctx);

	return 0;
}

/**
 * Core function, release an SRv6 SID.
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param session_id Zclient session ID, to identify the zclient session
 * @param ctx Context associated with the SRv6 SID
 * @return 0 on success, -1 otherwise
 */
int release_srv6_sid(uint8_t proto, unsigned short instance,
		     uint32_t session_id, struct zebra_srv6_sid_ctx *ctx)
{
	char buf[256];

	if (!ctx->sid)
		return -1;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: releasing SRv6 SID %pI6 associated with ctx %s",
			   __func__, &ctx->sid->value,
			   srv6_sid_ctx2str(buf, sizeof(buf), &ctx->ctx));

	if (!sid_is_owned_by_proto(proto, instance, ctx->sid)) {
		flog_err(EC_ZEBRA_SM_DAEMON_MISMATCH, "%s: Daemon mismatch!!",
			 __func__);
		return -1;
	}

	zebra_srv6_sid_owner_del(ctx->sid, proto, instance, session_id);
	if (listcount(ctx->sid->owners) == 0) {
		/* The SID is no longer in use by anyone; let's release it. */
		if (ctx->sid->alloc_mode == SRV6_SID_ALLOC_MODE_EXPLICIT)
			release_explicit_srv6_sid(ctx);
		else if (ctx->sid->alloc_mode == SRV6_SID_ALLOC_MODE_DYNAMIC)
			release_dynamic_srv6_sid(ctx);
		else
			assert(0);
	}

	return 0;
}

/**
 * Handle a get SRv6 Locator request received from a client.
 *
 * It looks up the requested locator and send it to the client.
 *
 * @param locator SRv6 locator returned by this function
 * @param client Client that sent the Get SRv6 Locator request
 * @param locator_name Name of the locator to look up
 *
 * @return 0 on success
 */
static int srv6_manager_get_srv6_locator(struct zebra_srv6_locator **locator,
					 struct zserv *client,
					 const char *locator_name)
{
	*locator = zebra_srv6_locator_lookup(locator_name);
	if (!*locator || !(*locator)->sid_format)
		return -1;

	return zsend_srv6_manager_get_locator_response(client, *locator);
}

/* Respond to a get_sid request */
int srv6_manager_get_sid_response(struct zebra_srv6_sid *sid,
				  struct zserv *client)
{
	char buf[256];

	if (!sid)
		flog_err(EC_ZEBRA_SM_CANNOT_ASSIGN_SID,
			 "Unable to assign SRv6 SID to %s instance %u",
			 zebra_route_string(client->proto), client->instance);
	else if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("Assigned SRv6 SID %pI6 for ctx %s to %s instance %u",
			   &sid->value,
			   srv6_sid_ctx2str(buf, sizeof(buf), &sid->ctx->ctx),
			   zebra_route_string(client->proto), client->instance);

	return zsend_assign_srv6_sid_response(client, sid);
}

/**
 * Handle a get SID request received from a client.
 *
 * It allocates a SID for a given context.
 * If the sid_value parameter is non-null, the request is considered an explicit
 * allocation request and SRv6 Manager assigns the requested SID value
 * (if it is not already assigned to another context).
 * If the sid_value parameter is null, the request is considered a dynamic allocation
 * request, and SRv6 Manager assigns the first available SID value.
 * Notify the client that the SID allocation was successful or failed.
 *
 * @param sid SID returned by this function
 * @param client Client that sent the Get SID request
 * @param ctx Context associated with the SID to be created
 * @param sid_value IPv6 address associated with the SID to be created (for explicit allocation)
 * @param locator_name Name of the parent locator of the SID to be created (for dynamic allocation)
 *
 * @return 0 on success, -1 otherwise
 */
static int srv6_manager_get_sid(struct zebra_srv6_sid **sid,
				struct zserv *client, struct srv6_sid_ctx *ctx,
				struct in6_addr *sid_value,
				const char *locator_name)
{
	char buf[256];

	enum srv6_sid_alloc_mode alloc_mode =
		(sid_value) ? SRV6_SID_ALLOC_MODE_EXPLICIT
			    : SRV6_SID_ALLOC_MODE_DYNAMIC;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: getting SRv6 SID for ctx %s, sid_value=%pI6, locator_name=%s",
			   __func__, srv6_sid_ctx2str(buf, sizeof(buf), ctx),
			   sid_value, locator_name);

	*sid = assign_srv6_sid(client->proto, client->instance,
			       client->session_id, alloc_mode, ctx, sid_value,
			       locator_name);
	if (!(*sid)) {
		zlog_warn("%s: not assigned SRv6 SID for ctx %s, sid_value=%pI6, locator_name=%s",
			  __func__, srv6_sid_ctx2str(buf, sizeof(buf), ctx),
			  sid_value, locator_name);
	} else {
		if (IS_ZEBRA_DEBUG_PACKET)
			zlog_debug("%s: assigned SRv6 SID for ctx %s: sid_value=%pI6 (func=%u) (proto=%u, instance=%u, sessionId=%u)",
				   __func__,
				   srv6_sid_ctx2str(buf, sizeof(buf), ctx),
				   &(*sid)->value, (*sid)->func, client->proto,
				   client->instance, client->session_id);
	}

	return srv6_manager_get_sid_response(*sid, client);
}

/**
 * Release SRv6 SIDs from a client.
 *
 * Called on client disconnection or reconnection.
 *
 * @param client The client to release SIDs from
 * @return Number of SIDs released
 */
int release_daemon_srv6_sids(struct zserv *client)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *node, *nnode;
	struct zebra_srv6_sid_ctx *ctx;
	int count = 0;
	int ret;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: releasing SRv6 SIDs for client proto %s, instance %d, session %u",
			   __func__, zebra_route_string(client->proto),
			   client->instance, client->session_id);

	/* Iterate over the SIDs and remove SIDs owned by the client daemon */
	for (ALL_LIST_ELEMENTS(srv6->sids, node, nnode, ctx)) {
		if (!sid_is_owned_by_proto(client->proto, client->instance,
					   ctx->sid))
			continue;

		ret = release_srv6_sid(client->proto, client->instance,
				       client->session_id, ctx);
		if (ret == 0)
			count++;
	}

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: released %d SRv6 SIDs", __func__, count);

	return count;
}

/**
 * Release SRv6 SIDs from a client.
 *
 * Called on client disconnection or reconnection.
 *
 * @param client Client zapi session
 * @param ctx Context associated with the SRv6 SID
 * @return 0 on success
 */
static int srv6_manager_release_srv6_sid(struct zserv *client,
					 struct srv6_sid_ctx *ctx)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_sid_ctx *zctx;
	struct listnode *node, *nnode;
	char buf[256];

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: releasing SRv6 SID associated with ctx %s",
			   __func__, srv6_sid_ctx2str(buf, sizeof(buf), ctx));

	/* Lookup Zebra SID context and release it */
	for (ALL_LIST_ELEMENTS(srv6->sids, node, nnode, zctx))
		if (memcmp(&zctx->ctx, ctx, sizeof(struct srv6_sid_ctx)) == 0)
			return release_srv6_sid(client->proto, client->instance,
						client->session_id, zctx);

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: no SID associated with ctx %s", __func__,
			   srv6_sid_ctx2str(buf, sizeof(buf), ctx));

	return -1;
}

void zebra_srv6_terminate(void)
{
	struct zebra_srv6_locator *locator;
	struct zebra_srv6_sid_format *format;
	struct zebra_srv6_sid_block *block;
	struct zebra_srv6_sid_ctx *sid_ctx;

	if (srv6.locators) {
		while (listcount(srv6.locators)) {
			locator = listnode_head(srv6.locators);

			listnode_delete(srv6.locators, locator);
			zebra_srv6_locator_free(locator);
		}

		list_delete(&srv6.locators);
	}

	/* Free SRv6 SID formats */
	if (srv6.sid_formats) {
		while (listcount(srv6.sid_formats)) {
			format = listnode_head(srv6.sid_formats);

			listnode_delete(srv6.sid_formats, format);
			zebra_srv6_sid_format_free(format);
		}

		list_delete(&srv6.sid_formats);
	}

	/* Free SRv6 SIDs */
	if (srv6.sids) {
		while (listcount(srv6.sids)) {
			sid_ctx = listnode_head(srv6.sids);

			listnode_delete(srv6.sids, sid_ctx);
			zebra_srv6_sid_ctx_free(sid_ctx);
		}

		list_delete(&srv6.sids);
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
}

void zebra_srv6_init(void)
{
	hook_register(zserv_client_close, zebra_srv6_cleanup);
	hook_register(srv6_manager_get_chunk,
		      zebra_srv6_manager_get_locator_chunk);
	hook_register(srv6_manager_release_chunk,
		      zebra_srv6_manager_release_locator_chunk);

	hook_register(srv6_manager_get_sid, srv6_manager_get_sid);
	hook_register(srv6_manager_release_sid, srv6_manager_release_srv6_sid);
	hook_register(srv6_manager_get_locator, srv6_manager_get_srv6_locator);
}

bool zebra_srv6_is_enable(void)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	return listcount(srv6->locators);
}
