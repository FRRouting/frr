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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "zebra.h"
#include "zserv.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/mpls.h"
#include "lib/network.h"
#include "lib/stream.h"
#include "lib/zclient.h"
#include "lib/libfrr.h"

#include "label_manager.h"

#define CONNECTION_DELAY 5

struct label_manager lbl_mgr;

extern struct zebra_privs_t zserv_privs;

DEFINE_MGROUP(LBL_MGR, "Label Manager");
DEFINE_MTYPE_STATIC(LBL_MGR, LM_CHUNK, "Label Manager Chunk");

/* In case this zebra daemon is not acting as label manager,
 * it will be a proxy to relay messages to external label manager
 * This zclient thus is to connect to it
 */
static struct zclient *zclient;
bool lm_is_external;

static void delete_label_chunk(void *val)
{
	XFREE(MTYPE_LM_CHUNK, val);
}

static int relay_response_back(struct zserv *zserv)
{
	int ret = 0;
	struct stream *src, *dst;
	u_int16_t size = 0;
	u_char marker;
	u_char version;
	vrf_id_t vrf_id;
	u_int16_t resp_cmd;

	src = zclient->ibuf;
	dst = zserv->obuf;

	stream_reset(src);

	ret = zclient_read_header(src, zclient->sock, &size, &marker, &version,
				  &vrf_id, &resp_cmd);
	if (ret < 0 && errno != EAGAIN) {
		zlog_err("%s: Error reading Label Manager response: %s",
			 __func__, strerror(errno));
		return -1;
	}
	zlog_debug("%s: Label Manager response received, %d bytes", __func__,
		   size);
	if (size == 0)
		return -1;

	/* send response back */
	stream_copy(dst, src);
	ret = writen(zserv->sock, dst->data, stream_get_endp(dst));
	if (ret <= 0) {
		zlog_err("%s: Error sending Label Manager response back: %s",
			 __func__, strerror(errno));
		return -1;
	}
	zlog_debug("%s: Label Manager response (%d bytes) sent back", __func__,
		   ret);

	return 0;
}

static int lm_zclient_read(struct thread *t)
{
	struct zserv *zserv;
	int ret;

	/* Get socket to zebra. */
	zserv = THREAD_ARG(t);
	zclient->t_read = NULL;

	/* read response and send it back */
	ret = relay_response_back(zserv);

	return ret;
}

static int reply_error(int cmd, struct zserv *zserv, vrf_id_t vrf_id)
{
	struct stream *s;

	s = zserv->obuf;
	stream_reset(s);

	zclient_create_header(s, cmd, vrf_id);

	/* result */
	stream_putc(s, 1);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return writen(zserv->sock, s->data, stream_get_endp(s));
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
				      vrf_id_t vrf_id)
{
	struct stream *src, *dst;
	int ret = 0;

	if (zclient->sock < 0) {
		zlog_err(
			"%s: Error relaying label chunk request: no zclient socket",
			__func__);
		reply_error(cmd, zserv, vrf_id);
		return -1;
	}

	/* in case there's any incoming message enqueued, read and forward it */
	while (ret == 0)
		ret = relay_response_back(zserv);

	/* Send request to external label manager */
	src = zserv->ibuf;
	dst = zclient->obuf;

	stream_copy(dst, src);

	ret = writen(zclient->sock, dst->data, stream_get_endp(dst));
	if (ret <= 0) {
		zlog_err("%s: Error relaying label chunk request: %s", __func__,
			 strerror(errno));
		reply_error(cmd, zserv, vrf_id);
		return -1;
	}
	zlog_debug("%s: Label chunk request relayed. %d bytes sent", __func__,
		   ret);

	/* Release label chunk has no response */
	if (cmd == ZEBRA_RELEASE_LABEL_CHUNK)
		return 0;

	/* make sure we listen to the response */
	if (!zclient->t_read)
		thread_add_read(zclient->master, lm_zclient_read, zserv,
				zclient->sock, &zclient->t_read);

	return 0;
}

static int lm_zclient_connect(struct thread *t)
{
	zclient->t_connect = NULL;

	if (zclient->sock >= 0)
		return 0;

	if (zclient_socket_connect(zclient) < 0) {
		zlog_err("Error connecting synchronous zclient!");
		thread_add_timer(zebrad.master, lm_zclient_connect, zclient,
				 CONNECTION_DELAY, &zclient->t_connect);
		return -1;
	}

	/* make socket non-blocking */
	if (set_nonblocking(zclient->sock) < 0)
		zlog_warn("%s: set_nonblocking(%d) failed", __func__,
			  zclient->sock);

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
	zclient = zclient_new_notify(zebrad.master, &zclient_options_default);
	zclient->privs = &zserv_privs;
	zclient->sock = -1;
	zclient->t_connect = NULL;
	lm_zclient_connect(NULL);
}

/**
 * Init label manager (or proxy to an external one)
 */
void label_manager_init(char *lm_zserv_path)
{
	/* this is an actual label manager */
	if (!lm_zserv_path) {
		zlog_debug("Initializing own label manager");
		lm_is_external = false;
		lbl_mgr.lc_list = list_new();
		lbl_mgr.lc_list->del = delete_label_chunk;
	} else { /* it's acting just as a proxy */
		zlog_debug("Initializing external label manager at %s",
			   lm_zserv_path);
		lm_is_external = true;
		lm_zclient_init(lm_zserv_path);
	}
}

/**
 * Core function, assigns label cunks
 *
 * It first searches through the list to check if there's one available
 * (previously released). Otherwise it creates and assigns a new one
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param keep If set, avoid garbage collection
 * @para size Size of the label chunk
 * @return Pointer to the assigned label chunk
 */
struct label_manager_chunk *assign_label_chunk(u_char proto, u_short instance,
					       u_char keep, uint32_t size)
{
	struct label_manager_chunk *lmc;
	struct listnode *node;

	/* first check if there's one available */
	for (ALL_LIST_ELEMENTS_RO(lbl_mgr.lc_list, node, lmc)) {
		if (lmc->proto == NO_PROTO
		    && lmc->end - lmc->start + 1 == size) {
			lmc->proto = proto;
			lmc->instance = instance;
			lmc->keep = keep;
			return lmc;
		}
	}
	/* otherwise create a new one */
	lmc = XCALLOC(MTYPE_LM_CHUNK, sizeof(struct label_manager_chunk));
	if (!lmc)
		return NULL;

	if (list_isempty(lbl_mgr.lc_list))
		lmc->start = MPLS_MIN_UNRESERVED_LABEL;
	else
		lmc->start = ((struct label_manager_chunk *)listgetdata(
				      listtail(lbl_mgr.lc_list)))
				     ->end
			     + 1;
	if (lmc->start > MPLS_MAX_UNRESERVED_LABEL - size + 1) {
		zlog_err("Reached max labels. Start: %u, size: %u", lmc->start,
			 size);
		XFREE(MTYPE_LM_CHUNK, lmc);
		return NULL;
	}
	lmc->end = lmc->start + size - 1;
	lmc->proto = proto;
	lmc->instance = instance;
	lmc->keep = keep;
	listnode_add(lbl_mgr.lc_list, lmc);

	return lmc;
}

/**
 * Core function, release no longer used label cunks
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param start First label of the chunk
 * @param end Last label of the chunk
 * @return 0 on success, -1 otherwise
 */
int release_label_chunk(u_char proto, u_short instance, uint32_t start,
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
			zlog_err("%s: Daemon mismatch!!", __func__);
			continue;
		}
		lmc->proto = NO_PROTO;
		lmc->instance = 0;
		lmc->keep = 0;
		ret = 0;
		break;
	}
	if (ret != 0)
		zlog_err("%s: Label chunk not released!!", __func__);

	return ret;
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
int release_daemon_chunks(u_char proto, u_short instance)
{
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

void label_manager_close()
{
	list_delete_and_null(&lbl_mgr.lc_list);
}
