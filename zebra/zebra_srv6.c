// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 definitions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
 * Copyright (C) 2020  Masakazu Asama
 */

#include <zebra.h>

#include <linux/rtnetlink.h>

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
#include "zebra/zebra_ns.h"
#include "zebra/kernel_netlink.h"
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

static bool zebra_srv6_check_sr0_created_done;

void zebra_srv6_check_sr0_created(void)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	int buflen = NL_PKT_BUF_SIZE;
	char buf[NL_PKT_BUF_SIZE] = {};
	struct rtattr *rta_info;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[];
	} *req = (void *)&buf[0];

	if (zebra_srv6_check_sr0_created_done)
		return;

	if (!zns || zns->netlink_cmd.sock == -1)
		goto netlink_error;

	memset(req, 0, sizeof(*req));
	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
	req->n.nlmsg_type = RTM_NEWLINK;
	req->ifi.ifi_change = 0xFFFFFFFF;
	req->ifi.ifi_flags = IFF_UP;
	req->n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	if (!nl_attr_put(&req->n, buflen, IFLA_IFNAME, "sr0", 3))
		goto netlink_error;

	rta_info = nl_attr_nest(&req->n, buflen, IFLA_LINKINFO);
	if (!rta_info)
		goto netlink_error;

	if (!nl_attr_put(&req->n, buflen, IFLA_INFO_KIND, "dummy", 5))
		goto netlink_error;

	nl_attr_nest_end(&req->n, rta_info);

	netlink_talk(netlink_talk_filter, &req->n, &zns->netlink_cmd, zns,
		     0);

	zebra_srv6_check_sr0_created_done = true;

	return;
 netlink_error:
	flog_err(EC_ZEBRA_SRV6_SR0_CREATION_ERROR,
		 "%s: SRv6 sr0 failed to be created: netlink_error", __func__);
}

/* --- Zebra SRv6 SID format management functions --------------------------- */

void zebra_srv6_sid_format_register(struct srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	/* Ensure that the format is registered only once */
	assert(!zebra_srv6_sid_format_lookup(format->name));

	listnode_add(srv6->sid_formats, format);
}

void zebra_srv6_sid_format_unregister(struct srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	listnode_delete(srv6->sid_formats, format);
}

struct srv6_sid_format *zebra_srv6_sid_format_lookup(const char *name)
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

	format = srv6_sid_format_alloc(ZEBRA_SRV6_SID_FORMAT_USID_F3216_NAME);

	format->type = SRV6_SID_FORMAT_TYPE_USID;

	/* Define block/node/function length */
	format->block_len = ZEBRA_SRV6_SID_FORMAT_USID_F3216_BLOCK_LEN;
	format->node_len = ZEBRA_SRV6_SID_FORMAT_USID_F3216_NODE_LEN;
	format->function_len = ZEBRA_SRV6_SID_FORMAT_USID_F3216_FUNCTION_LEN;
	format->argument_len = ZEBRA_SRV6_SID_FORMAT_USID_F3216_ARGUMENT_LEN;

	/* Define the ranges from which the SID function can be allocated */
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
static struct srv6_sid_format *create_srv6_sid_format_uncompressed(void)
{
	struct srv6_sid_format *format = NULL;

	format = srv6_sid_format_alloc(
		ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NAME);

	format->type = ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED;

	/* Define block/node/function length */
	format->block_len = ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_BLOCK_LEN;
	format->node_len = ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE_LEN;
	format->function_len =
		ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_FUNCTION_LEN;
	format->argument_len =
		ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_ARGUMENT_LEN;

	/* Define the ranges from which the SID function can be allocated */
	format->config.uncompressed.explicit_start =
		ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_EXPLICIT_RANGE_START;

	return format;
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
		zebra_srv6_sid_format_register(format_usidf3216);

		/* Create SID format `uncompressed` */
		format_uncompressed = create_srv6_sid_format_uncompressed();
		zebra_srv6_sid_format_register(format_uncompressed);
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

	if (srv6.locators) {
		while (listcount(srv6.locators)) {
			locator = listnode_head(srv6.locators);

			listnode_delete(srv6.locators, locator);
			srv6_locator_free(locator);
		}

		list_delete(&srv6.locators);
	}

	/* Free SRv6 SID formats */
	if (srv6.sid_formats) {
		while (listcount(srv6.sid_formats)) {
			format = listnode_head(srv6.sid_formats);

			zebra_srv6_sid_format_unregister(format);
			srv6_sid_format_free(format);
		}

		list_delete(&srv6.sid_formats);
	}
}

void zebra_srv6_init(void)
{
	zebra_srv6_check_sr0_created_done = false;
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
