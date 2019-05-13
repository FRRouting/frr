/*
 * Zebra PM Echo - Zebra Path Monitoring proxy functions
 * Copyright (C) 6WIND 2019
 *
 * This file is part of FRR.
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

#include <sys/un.h> /* for sockaddr_un */
#include <net/if.h>

#include "pm_lib.h"
#include "buffer.h"
#include "command.h"
#include "if.h"
#include "network.h"
#include "ptm_lib.h"
#include "rib.h"
#include "stream.h"
#include "version.h"
#include "vrf.h"
#include "vty.h"
#include "lib_errors.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_pm.h"
#include "zebra/zserv.h"
#include "zebra_vrf.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_router.h"
/*
 * Data structures.
 */
struct pm_process {
	struct zserv *pp_zs;
	pid_t pp_pid;

	TAILQ_ENTRY(pm_process) pp_entry;
};
TAILQ_HEAD(pm_ppqueue, pm_process) pm_ppqueue;

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_PM_PROCESS,
		    "PM process registration table.");

/*
 * Prototypes.
 */
static struct pm_process *pp_new(pid_t pid, struct zserv *zs);
static struct pm_process *pp_lookup_byzs(struct zserv *zs);
static void pp_free(struct pm_process *pp);
static void pp_free_all(void);

static void zebra_pm_send_pmd(struct stream *msg);
static void zebra_pm_send_clients(struct stream *msg);
static int _zebra_pm_client_deregister(struct zserv *zs);
static void _zebra_pm_reroute(struct zserv *zs, struct zebra_vrf *zvrf,
			       struct stream *msg, uint32_t command);


/*
 * Process PID registration.
 */
static struct pm_process *pp_new(pid_t pid, struct zserv *zs)
{
	struct pm_process *pp;

#ifdef PM_DEBUG
	/* Sanity check: more than one client can't have the same PID. */
	TAILQ_FOREACH(pp, &pm_ppqueue, pp_entry) {
		if (pp->pp_pid == pid && pp->pp_zs != zs)
			zlog_err("%s:%d pid and client pointer doesn't match",
				 __FILE__, __LINE__);
	}
#endif /* PM_DEBUG */

	/* Lookup for duplicates. */
	pp = pp_lookup_byzs(zs);
	if (pp != NULL)
		return pp;

	/* Allocate and register new process. */
	pp = XCALLOC(MTYPE_ZEBRA_PM_PROCESS, sizeof(*pp));
	if (pp == NULL)
		return NULL;

	pp->pp_pid = pid;
	pp->pp_zs = zs;
	TAILQ_INSERT_HEAD(&pm_ppqueue, pp, pp_entry);

	return pp;
}

static struct pm_process *pp_lookup_byzs(struct zserv *zs)
{
	struct pm_process *pp;

	TAILQ_FOREACH(pp, &pm_ppqueue, pp_entry) {
		if (pp->pp_zs != zs)
			continue;

		break;
	}

	return pp;
}

static void pp_free(struct pm_process *pp)
{
	if (pp == NULL)
		return;

	TAILQ_REMOVE(&pm_ppqueue, pp, pp_entry);
	XFREE(MTYPE_ZEBRA_PM_PROCESS, pp);
}

static void pp_free_all(void)
{
	struct pm_process *pp;

	while (!TAILQ_EMPTY(&pm_ppqueue)) {
		pp = TAILQ_FIRST(&pm_ppqueue);
		pp_free(pp);
	}
}


static void zebra_pm_send_pmd(struct stream *msg)
{
	struct listnode *node;
	struct zserv *client;
	struct stream *msgc;

	/* Create copy for replication. */
	msgc = stream_dup(msg);
	if (msgc == NULL) {
		zlog_debug("%s: not enough memory", __func__);
		return;
	}

	/* Send message to running PMd daemons. */
	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (client->proto != ZEBRA_ROUTE_PM)
			continue;

		zserv_send_message(client, msg);

		/* Allocate more messages. */
		msg = stream_dup(msgc);
		if (msg == NULL) {
			zlog_debug("%s: not enough memory", __func__);
			return;
		}
	}

	stream_free(msgc);
	stream_free(msg);
}

static void zebra_pm_send_clients(struct stream *msg)
{
	struct listnode *node;
	struct zserv *client;
	struct stream *msgc;

	/* Create copy for replication. */
	msgc = stream_dup(msg);
	if (msgc == NULL) {
		zlog_debug("%s: not enough memory", __func__);
		return;
	}

	/* Send message to all running client daemons. */
	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (!IS_PM_ENABLED_PROTOCOL(client->proto))
			continue;

		zserv_send_message(client, msg);

		/* Allocate more messages. */
		msg = stream_dup(msgc);
		if (msg == NULL) {
			zlog_debug("%s: not enough memory", __func__);
			return;
		}
	}

	stream_free(msgc);
	stream_free(msg);
}

static int _zebra_pm_client_deregister(struct zserv *zs)
{
	struct stream *msg;
	struct pm_process *pp;

	if (!IS_PM_ENABLED_PROTOCOL(zs->proto))
		return 0;

	/* Find daemon pid by zebra connection pointer. */
	pp = pp_lookup_byzs(zs);
	if (pp == NULL) {
		zlog_err("%s:%d failed to find process pid registration",
			 __FILE__, __LINE__);
		return -1;
	}

	/* Generate, send message and free() daemon related data. */
	msg = stream_new(ZEBRA_MAX_PACKET_SIZ);
	if (msg == NULL) {
		zlog_debug("%s: not enough memory", __func__);
		return 0;
	}

	/*
	 * The message type will be PM_DEST_REPLY so we can use only
	 * one callback at the `pmd` side, however the real command
	 * number will be included right after the zebra header.
	 */
	zclient_create_header(msg, ZEBRA_PM_DEST_REPLAY, 0);
	stream_putl(msg, ZEBRA_PM_CLIENT_DEREGISTER);

	/* Put process PID. */
	stream_putl(msg, pp->pp_pid);

	/* Update the data pointers. */
	stream_putw_at(msg, 0, stream_get_endp(msg));

	zebra_pm_send_pmd(msg);

	pp_free(pp);

	return 0;
}

void zebra_pm_init(void)
{
	/* Initialize the pm process information list. */
	TAILQ_INIT(&pm_ppqueue);

	/*
	 * Send deregistration messages to PMD daemon when some other
	 * daemon closes. This will help avoid sending daemons
	 * unnecessary notification messages.
	 */
	hook_register(zserv_client_close, _zebra_pm_client_deregister);
}

void zebra_pm_finish(void)
{
	/* Remove the client disconnect hook and free all memory. */
	hook_unregister(zserv_client_close, _zebra_pm_client_deregister);
	pp_free_all();
}


/*
 * Message handling.
 */
static void _zebra_pm_reroute(struct zserv *zs, struct zebra_vrf *zvrf,
			       struct stream *msg, uint32_t command)
{
	struct stream *msgc;
	size_t zmsglen, zhdrlen;
	pid_t ppid;

	/*
	 * Don't modify message in the zebra API. In order to do that we
	 * need to allocate a new message stream and copy the message
	 * provided by zebra.
	 */
	msgc = stream_new(ZEBRA_MAX_PACKET_SIZ);
	if (msgc == NULL) {
		zlog_debug("%s: not enough memory", __func__);
		return;
	}

	/* Calculate our header size plus the message contents. */
	zhdrlen = ZEBRA_HEADER_SIZE + sizeof(uint32_t);
	zmsglen = msg->endp - msg->getp;
	memcpy(msgc->data + zhdrlen, msg->data + msg->getp, zmsglen);

	/*
	 * The message type will be PM_DEST_REPLY so we can use only
	 * one callback at the `pmd` side, however the real command
	 * number will be included right after the zebra header.
	 */
	zclient_create_header(msgc, ZEBRA_PM_DEST_REPLAY, zvrf->vrf->vrf_id);
	stream_putl(msgc, command);

	/* Update the data pointers. */
	msgc->getp = 0;
	msgc->endp = zhdrlen + zmsglen;
	stream_putw_at(msgc, 0, stream_get_endp(msgc));

	zebra_pm_send_pmd(msgc);

	/* Registrate process PID for shutdown hook. */
	STREAM_GETL(msg, ppid);
	pp_new(ppid, zs);

	return;

stream_failure:
	zlog_err("%s:%d failed to registrate client pid", __FILE__, __LINE__);
}

void zebra_pm_dst_register(ZAPI_HANDLER_ARGS)
{
	if (hdr->command == ZEBRA_BFD_DEST_UPDATE)
		client->bfd_peer_upd8_cnt++;
	else
		client->bfd_peer_add_cnt++;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("pm_dst_register msg from client %s: length=%d",
			   zebra_route_string(client->proto), hdr->length);

	_zebra_pm_reroute(client, zvrf, msg, ZEBRA_PM_DEST_REGISTER);
}

void zebra_pm_dst_deregister(ZAPI_HANDLER_ARGS)
{
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("pm_dst_deregister msg from client %s: length=%d",
			   zebra_route_string(client->proto), hdr->length);

	_zebra_pm_reroute(client, zvrf, msg, ZEBRA_PM_DEST_DEREGISTER);
}

void zebra_pm_client_register(ZAPI_HANDLER_ARGS)
{
	client->bfd_peer_del_cnt++;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("pm_client_register msg from client %s: length=%d",
			   zebra_route_string(client->proto), hdr->length);

	_zebra_pm_reroute(client, zvrf, msg, ZEBRA_PM_CLIENT_REGISTER);
}

void zebra_pm_dst_replay(ZAPI_HANDLER_ARGS)
{
	struct stream *msgc;
	size_t zmsglen, zhdrlen;
	uint32_t cmd;

	/*
	 * NOTE:
	 * Replay messages are meant to be replayed to
	 * the client daemons. These messages are composed and
	 * originated from the `pmd` daemon.
	 */
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("pm_dst_update msg from client %s: length=%d",
			   zebra_route_string(client->proto), hdr->length);

	/*
	 * Client messages must be re-routed, otherwise do the `pmd`
	 * special treatment.
	 */
	if (client->proto != ZEBRA_ROUTE_PM) {
		_zebra_pm_reroute(client, zvrf, msg, ZEBRA_PM_DEST_REPLAY);
		return;
	}

	/* Figure out if this is an DEST_UPDATE or DEST_REPLAY. */
	if (stream_getl2(msg, &cmd) == false) {
		zlog_err("%s: expected at least 4 bytes (command)", __func__);
		return;
	}

	/*
	 * Don't modify message in the zebra API. In order to do that we
	 * need to allocate a new message stream and copy the message
	 * provided by zebra.
	 */
	msgc = stream_new(ZEBRA_MAX_PACKET_SIZ);
	if (msgc == NULL) {
		zlog_debug("%s: not enough memory", __func__);
		return;
	}

	/* Calculate our header size plus the message contents. */
	if (cmd != ZEBRA_PM_DEST_REPLAY) {
		zhdrlen = ZEBRA_HEADER_SIZE;
		zmsglen = msg->endp - msg->getp;
		memcpy(msgc->data + zhdrlen, msg->data + msg->getp, zmsglen);

		zclient_create_header(msgc, cmd, zvrf_id(zvrf));

		msgc->getp = 0;
		msgc->endp = zhdrlen + zmsglen;
	} else
		zclient_create_header(msgc, cmd, zvrf_id(zvrf));

	/* Update the data pointers. */
	stream_putw_at(msgc, 0, stream_get_endp(msgc));

	zebra_pm_send_clients(msgc);
}
