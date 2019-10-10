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

#define CONNECTION_DELAY 5

struct label_manager lbl_mgr;

extern struct zebra_privs_t zserv_privs;

DEFINE_MGROUP(LBL_MGR, "Label Manager");
DEFINE_MTYPE_STATIC(LBL_MGR, LM_CHUNK, "Label Manager Chunk");

/* In case this zebra daemon is not acting as label manager,
 * it will be a proxy to relay messages to external label manager
 * This zclient thus is to connect to it
 */
static struct stream *obuf;
static struct zclient *zclient;
bool lm_is_external;

static void delete_label_chunk(void *val)
{
	XFREE(MTYPE_LM_CHUNK, val);
}

static int relay_response_back(void)
{
	int ret = 0;
	struct stream *src, *dst;
	uint16_t size = 0;
	uint8_t marker;
	uint8_t version;
	vrf_id_t vrf_id;
	uint16_t resp_cmd;
	uint8_t proto;
	const char *proto_str;
	unsigned short instance;
	struct zserv *zserv;

	/* sanity */
	if (!zclient || zclient->sock < 0)
		return -1;

	/* input buffer with msg from label manager */
	src = zclient->ibuf;

	stream_reset(src);

	/* parse header */
	ret = zclient_read_header(src, zclient->sock, &size, &marker, &version,
				  &vrf_id, &resp_cmd);
	if (ret < 0) {
		if (errno != EAGAIN)
			flog_err(EC_ZEBRA_LM_RESPONSE,
				 "Error reading Label Manager response: %s",
				 strerror(errno));
		return -1;
	}

	/* do not relay a msg that has nothing to do with LM */
	switch (resp_cmd) {
	case ZEBRA_LABEL_MANAGER_CONNECT:
	case ZEBRA_LABEL_MANAGER_CONNECT_ASYNC: /* should not be seen */
	case ZEBRA_GET_LABEL_CHUNK:
	case ZEBRA_RELEASE_LABEL_CHUNK:
		break;
	default:
		zlog_debug("Not relaying '%s' response (size %d) from LM",
			   zserv_command_string(resp_cmd), size);
		return -1;
	}

	zlog_debug("Received '%s' response (size %d) from LM",
		   zserv_command_string(resp_cmd), size);

	if (size == 0)
		return -1;

	/* Get the 'proto' field of the message */
	proto = stream_getc(src);

	/* Get the 'instance' field of the message */
	instance = stream_getw(src);

	proto_str = zebra_route_string(proto);

	/* lookup the client to relay the msg to */
	zserv = zserv_find_client(proto, instance);
	if (!zserv) {
		flog_err(
			EC_ZEBRA_LM_NO_SUCH_CLIENT,
			"Error relaying LM response: can't find client %s, instance %u",
			proto_str, instance);
		return -1;
	}
	zlog_debug("Found client to relay LM response to client %s instance %u",
		   proto_str, instance);

	/* copy msg into output buffer */
	dst = obuf;
	stream_copy(dst, src);

	/* send response back */
	ret = writen(zserv->sock, dst->data, stream_get_endp(dst));
	if (ret <= 0) {
		flog_err(EC_ZEBRA_LM_RELAY_FAILED,
			 "Error relaying LM response to %s instance %u: %s",
			 proto_str, instance, strerror(errno));
		return -1;
	}
	zlog_debug("Relayed LM response (%d bytes) to %s instance %u", ret,
		   proto_str, instance);

	return 0;
}

static int lm_zclient_read(struct thread *t)
{
	int ret;

	zclient->t_read = NULL;

	/* read response and send it back */
	ret = relay_response_back();

	/* re-arm read */
	thread_add_read(zclient->master, lm_zclient_read, NULL,
			zclient->sock, &zclient->t_read);
	return ret;
}

static int reply_error(int cmd, struct zserv *zserv, vrf_id_t vrf_id)
{
	int ret;
	struct stream *s;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, cmd, vrf_id);

	/* proto */
	stream_putc(s, zserv->proto);
	/* instance */
	stream_putw(s, zserv->instance);
	/* result */
	stream_putc(s, 1);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	ret = writen(zserv->sock, s->data, stream_get_endp(s));

	stream_free(s);
	return ret;
}
/**
 * Receive a request to get or release a label chunk and forward it to external
 * label manager.
 *
 * It's called from zserv in case it's not an actual label manager, but just a
 * proxy.
 *
 * @param cmd Type of request (connect, get or release)
 * @param zserv
 * @return 0 on success, -1 otherwise
 */
int zread_relay_label_manager_request(int cmd, struct zserv *zserv,
				      struct stream *msg, vrf_id_t vrf_id)
{
	struct stream *dst;
	int ret = 0;
	uint8_t proto;
	const char *proto_str;
	unsigned short instance;

	if (zclient->sock < 0) {
		flog_err(EC_ZEBRA_LM_NO_SOCKET,
			 "Unable to relay LM request: no socket");
		reply_error(cmd, zserv, vrf_id);
		return -1;
	}

	/* peek msg to get proto and instance id. This zebra, which acts as
	 * a proxy needs to have such values for each client in order to
	 * relay responses back to it.
	 */

	/* Get the 'proto' field of incoming msg */
	proto = stream_getc(msg);

	/* Get the 'instance' field of incoming msg */
	instance = stream_getw(msg);

	/* stringify proto */
	proto_str = zebra_route_string(proto);

	/* check & set client proto if unset */
	if (zserv->proto && zserv->proto != proto) {
		flog_warn(EC_ZEBRAING_LM_PROTO_MISMATCH,
			  "Client proto(%u) != msg proto(%u)", zserv->proto,
			  proto);
		return -1;
	}

	/* check & set client instance if unset */
	if (zserv->instance && zserv->instance != instance) {
		flog_err(EC_ZEBRA_LM_BAD_INSTANCE,
			 "Client instance(%u) != msg instance(%u)",
			 zserv->instance, instance);
		return -1;
	}

	/* recall proto and instance */
	zserv->instance = instance;
	zserv->proto = proto;

	/* in case there's any incoming message enqueued, read and forward it */
	if (zserv->is_synchronous)
		while (ret == 0)
			ret = relay_response_back();

	/* get the msg buffer used toward the 'master' Label Manager */
	dst = zclient->obuf;

	/* copy the message */
	stream_copy(dst, msg);

	/* Send request to external label manager */
	ret = writen(zclient->sock, dst->data, stream_get_endp(dst));
	if (ret <= 0) {
		flog_err(EC_ZEBRA_LM_RELAY_FAILED,
			 "Error relaying LM request from %s instance %u: %s",
			 proto_str, instance, strerror(errno));
		reply_error(cmd, zserv, vrf_id);
		return -1;
	}
	zlog_debug("Relayed LM request (%d bytes) from %s instance %u", ret,
		   proto_str, instance);


	/* Release label chunk has no response */
	if (cmd == ZEBRA_RELEASE_LABEL_CHUNK)
		return 0;

	/* make sure we listen to the response */
	if (!zclient->t_read)
		thread_add_read(zclient->master, lm_zclient_read, NULL,
				zclient->sock, &zclient->t_read);

	return 0;
}

static int lm_zclient_connect(struct thread *t)
{
	zclient->t_connect = NULL;

	if (zclient->sock >= 0)
		return 0;

	if (zclient_socket_connect(zclient) < 0) {
		flog_err(EC_ZEBRA_LM_CLIENT_CONNECTION_FAILED,
			 "Error connecting synchronous zclient!");
		thread_add_timer(zrouter.master, lm_zclient_connect, zclient,
				 CONNECTION_DELAY, &zclient->t_connect);
		return -1;
	}

	/* make socket non-blocking */
	(void)set_nonblocking(zclient->sock);

	return 0;
}

/**
 * Function to initialize zclient in case this is not an actual
 * label manager, but just a proxy to an external one.
 *
 * @param lm_zserv_path Path to zserv socket of external label manager
 */
static void lm_zclient_init(char *lm_zserv_path)
{
	if (lm_zserv_path)
		frr_zclient_addr(&zclient_addr, &zclient_addr_len,
				 lm_zserv_path);

	/* Set default values. */
	zclient = zclient_new(zrouter.master, &zclient_options_default);
	zclient->privs = &zserv_privs;
	zclient->sock = -1;
	zclient->t_connect = NULL;
	lm_zclient_connect(NULL);
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
	uint8_t proto = client->proto;
	uint16_t instance = client->instance;
	struct listnode *node;
	struct label_manager_chunk *lmc;
	int count = 0;
	int ret;

	for (ALL_LIST_ELEMENTS_RO(lbl_mgr.lc_list, node, lmc)) {
		if (lmc->proto == proto && lmc->instance == instance
		    && lmc->keep == 0) {
			ret = release_label_chunk(lmc->proto, lmc->instance,
						  lmc->start, lmc->end);
			if (ret == 0)
				count++;
		}
	}

	zlog_debug("%s: Released %d label chunks", __func__, count);

	return count;
}

/**
 * Init label manager (or proxy to an external one)
 */
void label_manager_init(char *lm_zserv_path)
{
	/* this is an actual label manager */
	if (!lm_zserv_path) {
		zlog_debug("Initializing internal label manager");
		lm_is_external = false;
		lbl_mgr.lc_list = list_new();
		lbl_mgr.lc_list->del = delete_label_chunk;
	} else { /* it's acting just as a proxy */
		zlog_debug("Initializing external label manager at %s",
			   lm_zserv_path);
		lm_is_external = true;
		lm_zclient_init(lm_zserv_path);
	}

	obuf = stream_new(ZEBRA_MAX_PACKET_SIZ);

	hook_register(zserv_client_close, release_daemon_label_chunks);
}

/* alloc and fill a label chunk */
static struct label_manager_chunk *
create_label_chunk(uint8_t proto, unsigned short instance, uint8_t keep,
		   uint32_t start, uint32_t end)
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
struct label_manager_chunk *
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


void label_manager_close(void)
{
	list_delete(&lbl_mgr.lc_list);
	stream_free(obuf);
}
