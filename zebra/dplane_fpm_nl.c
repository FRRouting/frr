// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra dataplane plugin for Forwarding Plane Manager (FPM) using netlink.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#ifdef HAVE_CONFIG_H
#include "config.h" /* Include this explicitly */
#endif

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <string.h>

#include "lib/zebra.h"

#include <linux/rtnetlink.h>

#include "lib/json.h"
#include "lib/libfrr.h"
#include "lib/frratomic.h"
#include "lib/command.h"
#include "lib/memory.h"
#include "lib/network.h"
#include "lib/ns.h"
#include "lib/frr_pthread.h"
#include "lib/termtable.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"
#include "fpm/fpm.h"

#include "zebra/dplane_fpm_nl_clippy.c"

#define SOUTHBOUND_DEFAULT_ADDR INADDR_LOOPBACK

/*
 * Time in seconds that if the other end is not responding
 * something terrible has gone wrong.  Let's fix that.
 */
#define DPLANE_FPM_NL_WEDGIE_TIME 15

/**
 * FPM header:
 * {
 *   version: 1 byte (always 1),
 *   type: 1 byte (1 for netlink, 2 protobuf),
 *   len: 2 bytes (network order),
 * }
 *
 * This header is used with any format to tell the users how many bytes to
 * expect.
 */
#define FPM_HEADER_SIZE 4

static const char *prov_name = "dplane_fpm_nl";

struct fpm_nl_ctx {
	/* data plane connection. */
	int socket;
	bool disabled;
	bool connecting;
	bool use_nhg;
	bool use_route_replace;
	struct sockaddr_storage addr;

	/* data plane buffers. */
	struct stream *ibuf;
	struct stream *obuf;
	pthread_mutex_t obuf_mutex;

	/*
	 * data plane context queue:
	 * When a FPM server connection becomes a bottleneck, we must keep the
	 * data plane contexts until we get a chance to process them.
	 */
	struct dplane_ctx_list_head ctxqueue;
	pthread_mutex_t ctxqueue_mutex;

	/* data plane events. */
	struct zebra_dplane_provider *prov;
	struct frr_pthread *fthread;
	struct event *t_connect;
	struct event *t_read;
	struct event *t_write;
	struct event *t_event;
	struct event *t_nhg;
	struct event *t_dequeue;
	struct event *t_wedged;

	/* zebra events. */
	struct event *t_lspreset;
	struct event *t_lspwalk;
	struct event *t_nhgreset;
	struct event *t_nhgwalk;
	struct event *t_ribreset;
	struct event *t_ribwalk;
	struct event *t_rmacreset;
	struct event *t_rmacwalk;

	/* Statistic counters. */
	struct {
		/* Amount of bytes read into ibuf. */
		_Atomic uint32_t bytes_read;
		/* Amount of bytes written from obuf. */
		_Atomic uint32_t bytes_sent;
		/* Output buffer current usage. */
		_Atomic uint32_t obuf_bytes;
		/* Output buffer peak usage. */
		_Atomic uint32_t obuf_peak;

		/* Amount of connection closes. */
		_Atomic uint32_t connection_closes;
		/* Amount of connection errors. */
		_Atomic uint32_t connection_errors;

		/* Amount of user configurations: FNE_RECONNECT. */
		_Atomic uint32_t user_configures;
		/* Amount of user disable requests: FNE_DISABLE. */
		_Atomic uint32_t user_disables;

		/* Amount of data plane context processed. */
		_Atomic uint32_t dplane_contexts;
		/* Peak amount of data plane contexts enqueued. */
		_Atomic uint32_t ctxqueue_len_peak;

		/* Amount of buffer full events. */
		_Atomic uint32_t buffer_full;
	} counters;
} *gfnc;

enum fpm_nl_events {
	/* Ask for FPM to reconnect the external server. */
	FNE_RECONNECT,
	/* Disable FPM. */
	FNE_DISABLE,
	/* Reset counters. */
	FNE_RESET_COUNTERS,
	/* Toggle next hop group feature. */
	FNE_TOGGLE_NHG,
	/* Reconnect request by our own code to avoid races. */
	FNE_INTERNAL_RECONNECT,

	/* LSP walk finished. */
	FNE_LSP_FINISHED,
	/* Next hop groups walk finished. */
	FNE_NHG_FINISHED,
	/* RIB walk finished. */
	FNE_RIB_FINISHED,
	/* RMAC walk finished. */
	FNE_RMAC_FINISHED,
};

#define FPM_RECONNECT(fnc)                                                     \
	event_add_event((fnc)->fthread->master, fpm_process_event, (fnc),      \
			FNE_INTERNAL_RECONNECT, &(fnc)->t_event)

#define WALK_FINISH(fnc, ev)                                                   \
	event_add_event((fnc)->fthread->master, fpm_process_event, (fnc),      \
			(ev), NULL)

/*
 * Prototypes.
 */
static void fpm_process_event(struct event *t);
static int fpm_nl_enqueue(struct fpm_nl_ctx *fnc, struct zebra_dplane_ctx *ctx);
static void fpm_lsp_send(struct event *t);
static void fpm_lsp_reset(struct event *t);
static void fpm_nhg_send(struct event *t);
static void fpm_nhg_reset(struct event *t);
static void fpm_rib_send(struct event *t);
static void fpm_rib_reset(struct event *t);
static void fpm_rmac_send(struct event *t);
static void fpm_rmac_reset(struct event *t);

/*
 * CLI.
 */
#define FPM_STR "Forwarding Plane Manager configuration\n"

DEFUN(fpm_set_address, fpm_set_address_cmd,
      "fpm address <A.B.C.D|X:X::X:X> [port (1-65535)]",
      FPM_STR
      "FPM remote listening server address\n"
      "Remote IPv4 FPM server\n"
      "Remote IPv6 FPM server\n"
      "FPM remote listening server port\n"
      "Remote FPM server port\n")
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	uint16_t port = 0;
	uint8_t naddr[INET6_BUFSIZ];

	if (argc == 5)
		port = strtol(argv[4]->arg, NULL, 10);

	/* Handle IPv4 addresses. */
	if (inet_pton(AF_INET, argv[2]->arg, naddr) == 1) {
		sin = (struct sockaddr_in *)&gfnc->addr;

		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_port =
			port ? htons(port) : htons(FPM_DEFAULT_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sin->sin_len = sizeof(*sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		memcpy(&sin->sin_addr, naddr, sizeof(sin->sin_addr));

		goto ask_reconnect;
	}

	/* Handle IPv6 addresses. */
	if (inet_pton(AF_INET6, argv[2]->arg, naddr) != 1) {
		vty_out(vty, "%% Invalid address: %s\n", argv[2]->arg);
		return CMD_WARNING;
	}

	sin6 = (struct sockaddr_in6 *)&gfnc->addr;
	memset(sin6, 0, sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = port ? htons(port) : htons(FPM_DEFAULT_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	sin6->sin6_len = sizeof(*sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
	memcpy(&sin6->sin6_addr, naddr, sizeof(sin6->sin6_addr));

ask_reconnect:
	event_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			FNE_RECONNECT, &gfnc->t_event);
	return CMD_SUCCESS;
}

DEFUN(no_fpm_set_address, no_fpm_set_address_cmd,
      "no fpm address [<A.B.C.D|X:X::X:X> [port <1-65535>]]",
      NO_STR
      FPM_STR
      "FPM remote listening server address\n"
      "Remote IPv4 FPM server\n"
      "Remote IPv6 FPM server\n"
      "FPM remote listening server port\n"
      "Remote FPM server port\n")
{
	event_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			FNE_DISABLE, &gfnc->t_event);
	return CMD_SUCCESS;
}

DEFUN(fpm_use_nhg, fpm_use_nhg_cmd,
      "fpm use-next-hop-groups",
      FPM_STR
      "Use netlink next hop groups feature.\n")
{
	/* Already enabled. */
	if (gfnc->use_nhg)
		return CMD_SUCCESS;

	event_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			FNE_TOGGLE_NHG, &gfnc->t_nhg);

	return CMD_SUCCESS;
}

DEFUN(no_fpm_use_nhg, no_fpm_use_nhg_cmd,
      "no fpm use-next-hop-groups",
      NO_STR
      FPM_STR
      "Use netlink next hop groups feature.\n")
{
	/* Already disabled. */
	if (!gfnc->use_nhg)
		return CMD_SUCCESS;

	event_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			FNE_TOGGLE_NHG, &gfnc->t_nhg);

	return CMD_SUCCESS;
}

DEFUN(fpm_use_route_replace, fpm_use_route_replace_cmd,
      "fpm use-route-replace",
      FPM_STR
      "Use netlink route replace semantics\n")
{
	gfnc->use_route_replace = true;
	return CMD_SUCCESS;
}

DEFUN(no_fpm_use_route_replace, no_fpm_use_route_replace_cmd,
      "no fpm use-route-replace",
      NO_STR
      FPM_STR
      "Use netlink route replace semantics\n")
{
	gfnc->use_route_replace = false;
	return CMD_SUCCESS;
}

DEFUN(fpm_reset_counters, fpm_reset_counters_cmd,
      "clear fpm counters",
      CLEAR_STR
      FPM_STR
      "FPM statistic counters\n")
{
	event_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			FNE_RESET_COUNTERS, &gfnc->t_event);
	return CMD_SUCCESS;
}

DEFPY(fpm_show_status,
      fpm_show_status_cmd,
      "show fpm status [json]$json",
      SHOW_STR FPM_STR "FPM status\n" JSON_STR)
{
	struct json_object *j;
	bool connected;
	uint16_t port;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	char buf[BUFSIZ];

	connected = gfnc->socket > 0 ? true : false;

	switch (gfnc->addr.ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)&gfnc->addr;
		snprintfrr(buf, sizeof(buf), "%pI4", &sin->sin_addr);
		port = ntohs(sin->sin_port);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)&gfnc->addr;
		snprintfrr(buf, sizeof(buf), "%pI6", &sin6->sin6_addr);
		port = ntohs(sin6->sin6_port);
		break;
	default:
		strlcpy(buf, "Unknown", sizeof(buf));
		port = FPM_DEFAULT_PORT;
		break;
	}

	if (json) {
		j = json_object_new_object();

		json_object_boolean_add(j, "connected", connected);
		json_object_boolean_add(j, "useNHG", gfnc->use_nhg);
		json_object_boolean_add(j, "useRouteReplace",
					gfnc->use_route_replace);
		json_object_boolean_add(j, "disabled", gfnc->disabled);
		json_object_string_add(j, "address", buf);
		json_object_int_add(j, "port", port);

		vty_json(vty, j);
	} else {
		struct ttable *table = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		char *out;

		ttable_rowseps(table, 0, BOTTOM, true, '-');
		ttable_add_row(table, "Address to connect to|%s", buf);
		ttable_add_row(table, "Port|%u", port);
		ttable_add_row(table, "Connected|%s", connected ? "Yes" : "No");
		ttable_add_row(table, "Use Nexthop Groups|%s",
			       gfnc->use_nhg ? "Yes" : "No");
		ttable_add_row(table, "Use Route Replace Semantics|%s",
			       gfnc->use_route_replace ? "Yes" : "No");
		ttable_add_row(table, "Disabled|%s",
			       gfnc->disabled ? "Yes" : "No");

		out = ttable_dump(table, "\n");
		vty_out(vty, "%s\n", out);
		XFREE(MTYPE_TMP_TTABLE, out);

		ttable_del(table);
	}

	return CMD_SUCCESS;
}

DEFUN(fpm_show_counters, fpm_show_counters_cmd,
      "show fpm counters",
      SHOW_STR
      FPM_STR
      "FPM statistic counters\n")
{
	uint32_t curr_queue_len;

	frr_with_mutex (&gfnc->ctxqueue_mutex) {
		curr_queue_len = dplane_ctx_queue_count(&gfnc->ctxqueue);
	}

	vty_out(vty, "%30s\n%30s\n", "FPM counters", "============");

#define SHOW_COUNTER(label, counter) \
	vty_out(vty, "%28s: %u\n", (label), (counter))

	SHOW_COUNTER("Input bytes", gfnc->counters.bytes_read);
	SHOW_COUNTER("Output bytes", gfnc->counters.bytes_sent);
	SHOW_COUNTER("Output buffer current size", gfnc->counters.obuf_bytes);
	SHOW_COUNTER("Output buffer peak size", gfnc->counters.obuf_peak);
	SHOW_COUNTER("Connection closes", gfnc->counters.connection_closes);
	SHOW_COUNTER("Connection errors", gfnc->counters.connection_errors);
	SHOW_COUNTER("Data plane items processed",
		     gfnc->counters.dplane_contexts);
	SHOW_COUNTER("Data plane items enqueued", curr_queue_len);
	SHOW_COUNTER("Data plane items queue peak",
		     gfnc->counters.ctxqueue_len_peak);
	SHOW_COUNTER("Buffer full hits", gfnc->counters.buffer_full);
	SHOW_COUNTER("User FPM configurations", gfnc->counters.user_configures);
	SHOW_COUNTER("User FPM disable requests", gfnc->counters.user_disables);

#undef SHOW_COUNTER

	return CMD_SUCCESS;
}

DEFUN(fpm_show_counters_json, fpm_show_counters_json_cmd,
      "show fpm counters json",
      SHOW_STR
      FPM_STR
      "FPM statistic counters\n"
      JSON_STR)
{
	uint32_t curr_queue_len;

	frr_with_mutex (&gfnc->ctxqueue_mutex) {
		curr_queue_len = dplane_ctx_queue_count(&gfnc->ctxqueue);
	}

	struct json_object *jo;

	jo = json_object_new_object();
	json_object_int_add(jo, "bytes-read", gfnc->counters.bytes_read);
	json_object_int_add(jo, "bytes-sent", gfnc->counters.bytes_sent);
	json_object_int_add(jo, "obuf-bytes", gfnc->counters.obuf_bytes);
	json_object_int_add(jo, "obuf-bytes-peak", gfnc->counters.obuf_peak);
	json_object_int_add(jo, "connection-closes",
			    gfnc->counters.connection_closes);
	json_object_int_add(jo, "connection-errors",
			    gfnc->counters.connection_errors);
	json_object_int_add(jo, "data-plane-contexts",
			    gfnc->counters.dplane_contexts);
	json_object_int_add(jo, "data-plane-contexts-queue", curr_queue_len);
	json_object_int_add(jo, "data-plane-contexts-queue-peak",
			    gfnc->counters.ctxqueue_len_peak);
	json_object_int_add(jo, "buffer-full-hits", gfnc->counters.buffer_full);
	json_object_int_add(jo, "user-configures",
			    gfnc->counters.user_configures);
	json_object_int_add(jo, "user-disables", gfnc->counters.user_disables);
	vty_json(vty, jo);

	return CMD_SUCCESS;
}

static int fpm_write_config(struct vty *vty)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int written = 0;

	if (gfnc->disabled)
		return written;

	switch (gfnc->addr.ss_family) {
	case AF_INET:
		written = 1;
		sin = (struct sockaddr_in *)&gfnc->addr;
		vty_out(vty, "fpm address %pI4", &sin->sin_addr);
		if (sin->sin_port != htons(FPM_DEFAULT_PORT))
			vty_out(vty, " port %d", ntohs(sin->sin_port));

		vty_out(vty, "\n");
		break;
	case AF_INET6:
		written = 1;
		sin6 = (struct sockaddr_in6 *)&gfnc->addr;
		vty_out(vty, "fpm address %pI6", &sin6->sin6_addr);
		if (sin6->sin6_port != htons(FPM_DEFAULT_PORT))
			vty_out(vty, " port %d", ntohs(sin6->sin6_port));

		vty_out(vty, "\n");
		break;

	default:
		break;
	}

	if (!gfnc->use_nhg) {
		vty_out(vty, "no fpm use-next-hop-groups\n");
		written = 1;
	}

	if (!gfnc->use_route_replace) {
		vty_out(vty, "no fpm use-route-replace\n");
		written = 1;
	}

	return written;
}

static struct cmd_node fpm_node = {
	.name = "fpm",
	.node = FPM_NODE,
	.prompt = "",
	.config_write = fpm_write_config,
};

/*
 * FPM functions.
 */
static void fpm_connect(struct event *t);

static void fpm_reconnect(struct fpm_nl_ctx *fnc)
{
	/* Cancel all zebra threads first. */
	event_cancel_async(zrouter.master, &fnc->t_lspreset, NULL);
	event_cancel_async(zrouter.master, &fnc->t_lspwalk, NULL);
	event_cancel_async(zrouter.master, &fnc->t_nhgreset, NULL);
	event_cancel_async(zrouter.master, &fnc->t_nhgwalk, NULL);
	event_cancel_async(zrouter.master, &fnc->t_ribreset, NULL);
	event_cancel_async(zrouter.master, &fnc->t_ribwalk, NULL);
	event_cancel_async(zrouter.master, &fnc->t_rmacreset, NULL);
	event_cancel_async(zrouter.master, &fnc->t_rmacwalk, NULL);

	/*
	 * Grab the lock to empty the streams (data plane might try to
	 * enqueue updates while we are closing).
	 */
	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	/* Avoid calling close on `-1`. */
	if (fnc->socket != -1) {
		close(fnc->socket);
		fnc->socket = -1;
	}

	stream_reset(fnc->ibuf);
	stream_reset(fnc->obuf);
	EVENT_OFF(fnc->t_read);
	EVENT_OFF(fnc->t_write);

	/* FPM is disabled, don't attempt to connect. */
	if (fnc->disabled)
		return;

	event_add_timer(fnc->fthread->master, fpm_connect, fnc, 3,
			&fnc->t_connect);
}

static void fpm_read(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	fpm_msg_hdr_t fpm;
	ssize_t rv;
	char buf[65535];
	struct nlmsghdr *hdr;
	struct zebra_dplane_ctx *ctx;
	size_t available_bytes;
	size_t hdr_available_bytes;

	/* Let's ignore the input at the moment. */
	rv = stream_read_try(fnc->ibuf, fnc->socket,
			     STREAM_WRITEABLE(fnc->ibuf));
	if (rv == 0) {
		atomic_fetch_add_explicit(&fnc->counters.connection_closes, 1,
					  memory_order_relaxed);

		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: connection closed", __func__);

		FPM_RECONNECT(fnc);
		return;
	}
	if (rv == -1) {
		atomic_fetch_add_explicit(&fnc->counters.connection_errors, 1,
					  memory_order_relaxed);
		zlog_warn("%s: connection failure: %s", __func__,
			  strerror(errno));
		FPM_RECONNECT(fnc);
		return;
	}

	/* Schedule the next read */
	event_add_read(fnc->fthread->master, fpm_read, fnc, fnc->socket,
		       &fnc->t_read);

	/* We've got an interruption. */
	if (rv == -2)
		return;


	/* Account all bytes read. */
	atomic_fetch_add_explicit(&fnc->counters.bytes_read, rv,
				  memory_order_relaxed);

	available_bytes = STREAM_READABLE(fnc->ibuf);
	while (available_bytes) {
		if (available_bytes < (ssize_t)FPM_MSG_HDR_LEN) {
			stream_pulldown(fnc->ibuf);
			return;
		}

		fpm.version = stream_getc(fnc->ibuf);
		fpm.msg_type = stream_getc(fnc->ibuf);
		fpm.msg_len = stream_getw(fnc->ibuf);

		if (fpm.version != FPM_PROTO_VERSION &&
		    fpm.msg_type != FPM_MSG_TYPE_NETLINK) {
			stream_reset(fnc->ibuf);
			zlog_warn(
				"%s: Received version/msg_type %u/%u, expected 1/1",
				__func__, fpm.version, fpm.msg_type);

			FPM_RECONNECT(fnc);
			return;
		}

		/*
		 * If the passed in length doesn't even fill in the header
		 * something is wrong and reset.
		 */
		if (fpm.msg_len < FPM_MSG_HDR_LEN) {
			zlog_warn(
				"%s: Received message length: %u that does not even fill the FPM header",
				__func__, fpm.msg_len);
			FPM_RECONNECT(fnc);
			return;
		}

		/*
		 * If we have not received the whole payload, reset the stream
		 * back to the beginning of the header and move it to the
		 * top.
		 */
		if (fpm.msg_len > available_bytes) {
			stream_rewind_getp(fnc->ibuf, FPM_MSG_HDR_LEN);
			stream_pulldown(fnc->ibuf);
			return;
		}

		available_bytes -= FPM_MSG_HDR_LEN;

		/*
		 * Place the data from the stream into a buffer
		 */
		hdr = (struct nlmsghdr *)buf;
		stream_get(buf, fnc->ibuf, fpm.msg_len - FPM_MSG_HDR_LEN);
		hdr_available_bytes = fpm.msg_len - FPM_MSG_HDR_LEN;
		available_bytes -= hdr_available_bytes;

		if (hdr->nlmsg_len > fpm.msg_len) {
			zlog_warn(
				"%s: Received a inner header length of %u that is greater than the fpm total length of %u",
				__func__, hdr->nlmsg_len, fpm.msg_len);
			FPM_RECONNECT(fnc);
		}
		/* Not enough bytes available. */
		if (hdr->nlmsg_len > hdr_available_bytes) {
			zlog_warn(
				"%s: [seq=%u] invalid message length %u (> %zu)",
				__func__, hdr->nlmsg_seq, hdr->nlmsg_len,
				available_bytes);
			continue;
		}

		if (!(hdr->nlmsg_flags & NLM_F_REQUEST)) {
			if (IS_ZEBRA_DEBUG_FPM)
				zlog_debug(
					"%s: [seq=%u] not a request, skipping",
					__func__, hdr->nlmsg_seq);

			/*
			 * This request is a bust, go to the next one
			 */
			continue;
		}

		switch (hdr->nlmsg_type) {
		case RTM_NEWROUTE:
			/* Sanity check: need at least route msg header size. */
			if (hdr->nlmsg_len < sizeof(struct rtmsg)) {
				zlog_warn("%s: [seq=%u] invalid message length %u (< %zu)",
					  __func__, hdr->nlmsg_seq,
					  hdr->nlmsg_len, sizeof(struct rtmsg));
				break;
			}

			ctx = dplane_ctx_alloc();
			dplane_ctx_route_init(ctx, DPLANE_OP_ROUTE_NOTIFY, NULL,
					      NULL);
			if (netlink_route_change_read_unicast_internal(
				    hdr, 0, false, ctx) != 1) {
				dplane_ctx_fini(&ctx);
				stream_pulldown(fnc->ibuf);
				/*
				 * Let's continue to read other messages
				 * Even if we ignore this one.
				 */
			}
			break;
		default:
			if (IS_ZEBRA_DEBUG_FPM)
				zlog_debug(
					"%s: Received message type %u which is not currently handled",
					__func__, hdr->nlmsg_type);
			break;
		}
	}

	stream_reset(fnc->ibuf);
}

static void fpm_write(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	socklen_t statuslen;
	ssize_t bwritten;
	int rv, status;
	size_t btotal;

	if (fnc->connecting == true) {
		status = 0;
		statuslen = sizeof(status);

		rv = getsockopt(fnc->socket, SOL_SOCKET, SO_ERROR, &status,
				&statuslen);
		if (rv == -1 || status != 0) {
			if (rv != -1)
				zlog_warn("%s: connection failed: %s", __func__,
					  strerror(status));
			else
				zlog_warn("%s: SO_ERROR failed: %s", __func__,
					  strerror(status));

			atomic_fetch_add_explicit(
				&fnc->counters.connection_errors, 1,
				memory_order_relaxed);

			FPM_RECONNECT(fnc);
			return;
		}

		fnc->connecting = false;

		/*
		 * Starting with LSPs walk all FPM objects, marking them
		 * as unsent and then replaying them.
		 */
		event_add_timer(zrouter.master, fpm_lsp_reset, fnc, 0,
				&fnc->t_lspreset);

		/* Permit receiving messages now. */
		event_add_read(fnc->fthread->master, fpm_read, fnc, fnc->socket,
			       &fnc->t_read);
	}

	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	while (true) {
		/* Stream is empty: reset pointers and return. */
		if (STREAM_READABLE(fnc->obuf) == 0) {
			stream_reset(fnc->obuf);
			break;
		}

		/* Try to write all at once. */
		btotal = stream_get_endp(fnc->obuf) -
			stream_get_getp(fnc->obuf);
		bwritten = write(fnc->socket, stream_pnt(fnc->obuf), btotal);
		if (bwritten == 0) {
			atomic_fetch_add_explicit(
				&fnc->counters.connection_closes, 1,
				memory_order_relaxed);

			if (IS_ZEBRA_DEBUG_FPM)
				zlog_debug("%s: connection closed", __func__);
			break;
		}
		if (bwritten == -1) {
			/* Attempt to continue if blocked by a signal. */
			if (errno == EINTR)
				continue;
			/* Receiver is probably slow, lets give it some time. */
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;

			atomic_fetch_add_explicit(
				&fnc->counters.connection_errors, 1,
				memory_order_relaxed);
			zlog_warn("%s: connection failure: %s", __func__,
				  strerror(errno));

			FPM_RECONNECT(fnc);
			return;
		}

		/* Account all bytes sent. */
		atomic_fetch_add_explicit(&fnc->counters.bytes_sent, bwritten,
					  memory_order_relaxed);

		/* Account number of bytes free. */
		atomic_fetch_sub_explicit(&fnc->counters.obuf_bytes, bwritten,
					  memory_order_relaxed);

		stream_forward_getp(fnc->obuf, (size_t)bwritten);
	}

	/* Stream is not empty yet, we must schedule more writes. */
	if (STREAM_READABLE(fnc->obuf)) {
		stream_pulldown(fnc->obuf);
		event_add_write(fnc->fthread->master, fpm_write, fnc,
				fnc->socket, &fnc->t_write);
		return;
	}
}

static void fpm_connect(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	struct sockaddr_in *sin = (struct sockaddr_in *)&fnc->addr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&fnc->addr;
	socklen_t slen;
	int rv, sock;
	char addrstr[INET6_ADDRSTRLEN];

	sock = socket(fnc->addr.ss_family, SOCK_STREAM, 0);
	if (sock == -1) {
		zlog_err("%s: fpm socket failed: %s", __func__,
			 strerror(errno));
		event_add_timer(fnc->fthread->master, fpm_connect, fnc, 3,
				&fnc->t_connect);
		return;
	}

	set_nonblocking(sock);

	if (fnc->addr.ss_family == AF_INET) {
		inet_ntop(AF_INET, &sin->sin_addr, addrstr, sizeof(addrstr));
		slen = sizeof(*sin);
	} else {
		inet_ntop(AF_INET6, &sin6->sin6_addr, addrstr, sizeof(addrstr));
		slen = sizeof(*sin6);
	}

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug("%s: attempting to connect to %s:%d", __func__,
			   addrstr, ntohs(sin->sin_port));

	rv = connect(sock, (struct sockaddr *)&fnc->addr, slen);
	if (rv == -1 && errno != EINPROGRESS) {
		atomic_fetch_add_explicit(&fnc->counters.connection_errors, 1,
					  memory_order_relaxed);
		close(sock);
		zlog_warn("%s: fpm connection failed: %s", __func__,
			  strerror(errno));
		event_add_timer(fnc->fthread->master, fpm_connect, fnc, 3,
				&fnc->t_connect);
		return;
	}

	fnc->connecting = (errno == EINPROGRESS);
	fnc->socket = sock;
	if (!fnc->connecting)
		event_add_read(fnc->fthread->master, fpm_read, fnc, sock,
			       &fnc->t_read);
	event_add_write(fnc->fthread->master, fpm_write, fnc, sock,
			&fnc->t_write);

	/*
	 * Starting with LSPs walk all FPM objects, marking them
	 * as unsent and then replaying them.
	 *
	 * If we are not connected, then delay the objects reset/send.
	 */
	if (!fnc->connecting)
		event_add_timer(zrouter.master, fpm_lsp_reset, fnc, 0,
				&fnc->t_lspreset);
}

/**
 * Encode data plane operation context into netlink and enqueue it in the FPM
 * output buffer.
 *
 * @param fnc the netlink FPM context.
 * @param ctx the data plane operation context data.
 * @return 0 on success or -1 on not enough space.
 */
static int fpm_nl_enqueue(struct fpm_nl_ctx *fnc, struct zebra_dplane_ctx *ctx)
{
	uint8_t nl_buf[NL_PKT_BUF_SIZE];
	size_t nl_buf_len;
	ssize_t rv;
	uint64_t obytes, obytes_peak;
	enum dplane_op_e op = dplane_ctx_get_op(ctx);

	/*
	 * If we were configured to not use next hop groups, then quit as soon
	 * as possible.
	 */
	if ((!fnc->use_nhg) &&
	    (op == DPLANE_OP_NH_DELETE || op == DPLANE_OP_NH_INSTALL || op == DPLANE_OP_NH_UPDATE ||
	     op == DPLANE_OP_PIC_CONTEXT_DELETE || op == DPLANE_OP_PIC_CONTEXT_INSTALL ||
	     op == DPLANE_OP_PIC_CONTEXT_UPDATE))
		return 0;

	nl_buf_len = 0;

	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	/*
	 * If route replace is enabled then directly encode the install which
	 * is going to use `NLM_F_REPLACE` (instead of delete/add operations).
	 */
	if (fnc->use_route_replace && op == DPLANE_OP_ROUTE_UPDATE)
		op = DPLANE_OP_ROUTE_INSTALL;

	switch (op) {
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
		rv = netlink_route_multipath_msg_encode(RTM_DELROUTE, ctx,
							nl_buf, sizeof(nl_buf),
							true, fnc->use_nhg,
							false);
		if (rv <= 0) {
			zlog_err(
				"%s: netlink_route_multipath_msg_encode failed",
				__func__);
			return 0;
		}

		nl_buf_len = (size_t)rv;

		/* UPDATE operations need a INSTALL, otherwise just quit. */
		if (op == DPLANE_OP_ROUTE_DELETE)
			break;

		fallthrough;
	case DPLANE_OP_ROUTE_INSTALL:
		rv = netlink_route_multipath_msg_encode(RTM_NEWROUTE, ctx,
							&nl_buf[nl_buf_len],
							sizeof(nl_buf) -
								nl_buf_len,
							true, fnc->use_nhg,
							fnc->use_route_replace);
		if (rv <= 0) {
			zlog_err(
				"%s: netlink_route_multipath_msg_encode failed",
				__func__);
			return 0;
		}

		nl_buf_len += (size_t)rv;
		break;

	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
		rv = netlink_macfdb_update_ctx(ctx, nl_buf, sizeof(nl_buf));
		if (rv <= 0) {
			zlog_err("%s: netlink_macfdb_update_ctx failed",
				 __func__);
			return 0;
		}

		nl_buf_len = (size_t)rv;
		break;

	case DPLANE_OP_NH_DELETE:
		rv = netlink_nexthop_msg_encode(RTM_DELNEXTHOP, ctx, nl_buf,
						sizeof(nl_buf), true);
		if (rv <= 0) {
			zlog_err("%s: netlink_nexthop_msg_encode failed",
				 __func__);
			return 0;
		}

		nl_buf_len = (size_t)rv;
		break;
	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
		rv = netlink_nexthop_msg_encode(RTM_NEWNEXTHOP, ctx, nl_buf,
						sizeof(nl_buf), true);
		if (rv <= 0) {
			zlog_err("%s: netlink_nexthop_msg_encode failed",
				 __func__);
			return 0;
		}

		nl_buf_len = (size_t)rv;
		break;

	case DPLANE_OP_LSP_INSTALL:
	case DPLANE_OP_LSP_UPDATE:
	case DPLANE_OP_LSP_DELETE:
		rv = netlink_lsp_msg_encoder(ctx, nl_buf, sizeof(nl_buf));
		if (rv <= 0) {
			zlog_err("%s: netlink_lsp_msg_encoder failed",
				 __func__);
			return 0;
		}

		nl_buf_len += (size_t)rv;
		break;

	/* Un-handled by FPM at this time. */
	case DPLANE_OP_PW_INSTALL:
	case DPLANE_OP_PW_UNINSTALL:
	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
	case DPLANE_OP_ROUTE_NOTIFY:
	case DPLANE_OP_LSP_NOTIFY:
	case DPLANE_OP_RULE_ADD:
	case DPLANE_OP_RULE_DELETE:
	case DPLANE_OP_RULE_UPDATE:
	case DPLANE_OP_NEIGH_DISCOVER:
	case DPLANE_OP_BR_PORT_UPDATE:
	case DPLANE_OP_IPTABLE_ADD:
	case DPLANE_OP_IPTABLE_DELETE:
	case DPLANE_OP_IPSET_ADD:
	case DPLANE_OP_IPSET_DELETE:
	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE:
	case DPLANE_OP_NEIGH_IP_INSTALL:
	case DPLANE_OP_NEIGH_IP_DELETE:
	case DPLANE_OP_NEIGH_TABLE_UPDATE:
	case DPLANE_OP_GRE_SET:
	case DPLANE_OP_INTF_ADDR_ADD:
	case DPLANE_OP_INTF_ADDR_DEL:
	case DPLANE_OP_INTF_NETCONFIG:
	case DPLANE_OP_INTF_INSTALL:
	case DPLANE_OP_INTF_UPDATE:
	case DPLANE_OP_INTF_DELETE:
	case DPLANE_OP_TC_QDISC_INSTALL:
	case DPLANE_OP_TC_QDISC_UNINSTALL:
	case DPLANE_OP_TC_CLASS_ADD:
	case DPLANE_OP_TC_CLASS_DELETE:
	case DPLANE_OP_TC_CLASS_UPDATE:
	case DPLANE_OP_TC_FILTER_ADD:
	case DPLANE_OP_TC_FILTER_DELETE:
	case DPLANE_OP_TC_FILTER_UPDATE:
	case DPLANE_OP_SRV6_ENCAP_SRCADDR_SET:
	case DPLANE_OP_NONE:
	case DPLANE_OP_STARTUP_STAGE:
	case DPLANE_OP_VLAN_INSTALL:
	case DPLANE_OP_PIC_CONTEXT_DELETE:
	case DPLANE_OP_PIC_CONTEXT_INSTALL:
	case DPLANE_OP_PIC_CONTEXT_UPDATE:
		break;

	}

	/* Skip empty enqueues. */
	if (nl_buf_len == 0)
		return 0;

	/* We must know if someday a message goes beyond 65KiB. */
	assert((nl_buf_len + FPM_HEADER_SIZE) <= UINT16_MAX);

	/* Check if we have enough buffer space. */
	if (STREAM_WRITEABLE(fnc->obuf) < (nl_buf_len + FPM_HEADER_SIZE)) {
		atomic_fetch_add_explicit(&fnc->counters.buffer_full, 1,
					  memory_order_relaxed);

		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug(
				"%s: buffer full: wants to write %zu but has %zu",
				__func__, nl_buf_len + FPM_HEADER_SIZE,
				STREAM_WRITEABLE(fnc->obuf));

		return -1;
	}

	/*
	 * Fill in the FPM header information.
	 *
	 * See FPM_HEADER_SIZE definition for more information.
	 */
	stream_putc(fnc->obuf, 1);
	stream_putc(fnc->obuf, 1);
	stream_putw(fnc->obuf, nl_buf_len + FPM_HEADER_SIZE);

	/* Write current data. */
	stream_write(fnc->obuf, nl_buf, (size_t)nl_buf_len);

	/* Account number of bytes waiting to be written. */
	atomic_fetch_add_explicit(&fnc->counters.obuf_bytes,
				  nl_buf_len + FPM_HEADER_SIZE,
				  memory_order_relaxed);
	obytes = atomic_load_explicit(&fnc->counters.obuf_bytes,
				      memory_order_relaxed);
	obytes_peak = atomic_load_explicit(&fnc->counters.obuf_peak,
					   memory_order_relaxed);
	if (obytes_peak < obytes)
		atomic_store_explicit(&fnc->counters.obuf_peak, obytes,
				      memory_order_relaxed);

	/* Tell the thread to start writing. */
	event_add_write(fnc->fthread->master, fpm_write, fnc, fnc->socket,
			&fnc->t_write);

	return 0;
}

/*
 * LSP walk/send functions
 */
struct fpm_lsp_arg {
	struct zebra_dplane_ctx *ctx;
	struct fpm_nl_ctx *fnc;
	bool complete;
};

static int fpm_lsp_send_cb(struct hash_bucket *bucket, void *arg)
{
	struct zebra_lsp *lsp = bucket->data;
	struct fpm_lsp_arg *fla = arg;

	/* Skip entries which have already been sent */
	if (CHECK_FLAG(lsp->flags, LSP_FLAG_FPM))
		return HASHWALK_CONTINUE;

	dplane_ctx_reset(fla->ctx);
	dplane_ctx_lsp_init(fla->ctx, DPLANE_OP_LSP_INSTALL, lsp);

	if (fpm_nl_enqueue(fla->fnc, fla->ctx) == -1) {
		fla->complete = false;
		return HASHWALK_ABORT;
	}

	/* Mark entry as sent */
	SET_FLAG(lsp->flags, LSP_FLAG_FPM);
	return HASHWALK_CONTINUE;
}

static void fpm_lsp_send(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);
	struct fpm_lsp_arg fla;

	fla.fnc = fnc;
	fla.ctx = dplane_ctx_alloc();
	fla.complete = true;

	hash_walk(zvrf->lsp_table, fpm_lsp_send_cb, &fla);

	dplane_ctx_fini(&fla.ctx);

	if (fla.complete) {
		WALK_FINISH(fnc, FNE_LSP_FINISHED);

		/* Now move onto routes */
		event_add_timer(zrouter.master, fpm_nhg_reset, fnc, 0,
				&fnc->t_nhgreset);
	} else {
		/* Didn't finish - reschedule LSP walk */
		event_add_timer(zrouter.master, fpm_lsp_send, fnc, 0,
				&fnc->t_lspwalk);
	}
}

/*
 * Next hop walk/send functions.
 */
struct fpm_nhg_arg {
	struct zebra_dplane_ctx *ctx;
	struct fpm_nl_ctx *fnc;
	bool complete;
};

static int fpm_nhg_send_cb(struct hash_bucket *bucket, void *arg)
{
	struct nhg_hash_entry *nhe = bucket->data;
	struct fpm_nhg_arg *fna = arg;

	/* This entry was already sent, skip it. */
	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_FPM))
		return HASHWALK_CONTINUE;

	/* Reset ctx to reuse allocated memory, take a snapshot and send it. */
	dplane_ctx_reset(fna->ctx);
	dplane_ctx_nexthop_init(fna->ctx, DPLANE_OP_NH_INSTALL, nhe);
	if (fpm_nl_enqueue(fna->fnc, fna->ctx) == -1) {
		/* Our buffers are full, lets give it some cycles. */
		fna->complete = false;
		return HASHWALK_ABORT;
	}

	/* Mark group as sent, so it doesn't get sent again. */
	SET_FLAG(nhe->flags, NEXTHOP_GROUP_FPM);

	return HASHWALK_CONTINUE;
}

static void fpm_nhg_send(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	struct fpm_nhg_arg fna;

	fna.fnc = fnc;
	fna.ctx = dplane_ctx_alloc();
	fna.complete = true;

	/* Send next hops. */
	if (fnc->use_nhg)
		hash_walk(zrouter.nhgs_id, fpm_nhg_send_cb, &fna);

	/* `free()` allocated memory. */
	dplane_ctx_fini(&fna.ctx);

	/* We are done sending next hops, lets install the routes now. */
	if (fna.complete) {
		WALK_FINISH(fnc, FNE_NHG_FINISHED);
		event_add_timer(zrouter.master, fpm_rib_reset, fnc, 0,
				&fnc->t_ribreset);
	} else /* Otherwise reschedule next hop group again. */
		event_add_timer(zrouter.master, fpm_nhg_send, fnc, 0,
				&fnc->t_nhgwalk);
}

/**
 * Send all RIB installed routes to the connected data plane.
 */
static void fpm_rib_send(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	rib_dest_t *dest;
	struct route_node *rn;
	struct route_table *rt;
	struct zebra_dplane_ctx *ctx;
	rib_tables_iter_t rt_iter;

	/* Allocate temporary context for all transactions. */
	ctx = dplane_ctx_alloc();

	rt_iter.state = RIB_TABLES_ITER_S_INIT;
	while ((rt = rib_tables_iter_next(&rt_iter))) {
		for (rn = route_top(rt); rn; rn = srcdest_route_next(rn)) {
			dest = rib_dest_from_rnode(rn);
			/* Skip bad route entries. */
			if (dest == NULL || dest->selected_fib == NULL)
				continue;

			/* Check for already sent routes. */
			if (CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_FPM))
				continue;

			/* Enqueue route install. */
			dplane_ctx_reset(ctx);
			dplane_ctx_route_init(ctx, DPLANE_OP_ROUTE_INSTALL, rn,
					      dest->selected_fib);
			if (fpm_nl_enqueue(fnc, ctx) == -1) {
				/* Free the temporary allocated context. */
				dplane_ctx_fini(&ctx);

				event_add_timer(zrouter.master, fpm_rib_send,
						fnc, 1, &fnc->t_ribwalk);
				return;
			}

			/* Mark as sent. */
			SET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
		}
	}

	/* Free the temporary allocated context. */
	dplane_ctx_fini(&ctx);

	/* All RIB routes sent! */
	WALK_FINISH(fnc, FNE_RIB_FINISHED);

	/* Schedule next event: RMAC reset. */
	event_add_event(zrouter.master, fpm_rmac_reset, fnc, 0,
			&fnc->t_rmacreset);
}

/*
 * The next three functions will handle RMAC enqueue.
 */
struct fpm_rmac_arg {
	struct zebra_dplane_ctx *ctx;
	struct fpm_nl_ctx *fnc;
	struct zebra_l3vni *zl3vni;
	bool complete;
};

static void fpm_enqueue_rmac_table(struct hash_bucket *bucket, void *arg)
{
	struct fpm_rmac_arg *fra = arg;
	struct zebra_mac *zrmac = bucket->data;
	struct zebra_if *zif = fra->zl3vni->vxlan_if->info;
	struct zebra_vxlan_vni *vni;
	struct zebra_if *br_zif;
	vlanid_t vid;
	bool sticky;

	/* Entry already sent. */
	if (CHECK_FLAG(zrmac->flags, ZEBRA_MAC_FPM_SENT) || !fra->complete)
		return;

	sticky = !!CHECK_FLAG(zrmac->flags,
			      (ZEBRA_MAC_STICKY | ZEBRA_MAC_REMOTE_DEF_GW));
	br_zif = (struct zebra_if *)(zif->brslave_info.br_if->info);
	vni = zebra_vxlan_if_vni_find(zif, fra->zl3vni->vni);
	vid = IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif) ? vni->access_vlan : 0;

	dplane_ctx_reset(fra->ctx);
	dplane_ctx_set_op(fra->ctx, DPLANE_OP_MAC_INSTALL);
	dplane_mac_init(fra->ctx, fra->zl3vni->vxlan_if,
			zif->brslave_info.br_if, vid, &zrmac->macaddr, vni->vni,
			zrmac->fwd_info.r_vtep_ip, sticky, 0 /*nhg*/,
			0 /*update_flags*/);
	if (fpm_nl_enqueue(fra->fnc, fra->ctx) == -1) {
		event_add_timer(zrouter.master, fpm_rmac_send, fra->fnc, 1,
				&fra->fnc->t_rmacwalk);
		fra->complete = false;
	}
}

static void fpm_enqueue_l3vni_table(struct hash_bucket *bucket, void *arg)
{
	struct fpm_rmac_arg *fra = arg;
	struct zebra_l3vni *zl3vni = bucket->data;

	fra->zl3vni = zl3vni;
	hash_iterate(zl3vni->rmac_table, fpm_enqueue_rmac_table, fra);
}

static void fpm_rmac_send(struct event *t)
{
	struct fpm_rmac_arg fra;

	fra.fnc = EVENT_ARG(t);
	fra.ctx = dplane_ctx_alloc();
	fra.complete = true;
	hash_iterate(zrouter.l3vni_table, fpm_enqueue_l3vni_table, &fra);
	dplane_ctx_fini(&fra.ctx);

	/* RMAC walk completed. */
	if (fra.complete)
		WALK_FINISH(fra.fnc, FNE_RMAC_FINISHED);
}

/*
 * Resets the next hop FPM flags so we send all next hops again.
 */
static void fpm_nhg_reset_cb(struct hash_bucket *bucket, void *arg)
{
	struct nhg_hash_entry *nhe = bucket->data;

	/* Unset FPM installation flag so it gets installed again. */
	UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_FPM);
}

static void fpm_nhg_reset(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);

	hash_iterate(zrouter.nhgs_id, fpm_nhg_reset_cb, NULL);

	/* Schedule next step: send next hop groups. */
	event_add_event(zrouter.master, fpm_nhg_send, fnc, 0, &fnc->t_nhgwalk);
}

/*
 * Resets the LSP FPM flag so we send all LSPs again.
 */
static void fpm_lsp_reset_cb(struct hash_bucket *bucket, void *arg)
{
	struct zebra_lsp *lsp = bucket->data;

	UNSET_FLAG(lsp->flags, LSP_FLAG_FPM);
}

static void fpm_lsp_reset(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	hash_iterate(zvrf->lsp_table, fpm_lsp_reset_cb, NULL);

	/* Schedule next step: send LSPs */
	event_add_event(zrouter.master, fpm_lsp_send, fnc, 0, &fnc->t_lspwalk);
}

/**
 * Resets the RIB FPM flags so we send all routes again.
 */
static void fpm_rib_reset(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	rib_dest_t *dest;
	struct route_node *rn;
	struct route_table *rt;
	rib_tables_iter_t rt_iter;

	rt_iter.state = RIB_TABLES_ITER_S_INIT;
	while ((rt = rib_tables_iter_next(&rt_iter))) {
		for (rn = route_top(rt); rn; rn = srcdest_route_next(rn)) {
			dest = rib_dest_from_rnode(rn);
			/* Skip bad route entries. */
			if (dest == NULL)
				continue;

			UNSET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
		}
	}

	/* Schedule next step: send RIB routes. */
	event_add_event(zrouter.master, fpm_rib_send, fnc, 0, &fnc->t_ribwalk);
}

/*
 * The next three function will handle RMAC table reset.
 */
static void fpm_unset_rmac_table(struct hash_bucket *bucket, void *arg)
{
	struct zebra_mac *zrmac = bucket->data;

	UNSET_FLAG(zrmac->flags, ZEBRA_MAC_FPM_SENT);
}

static void fpm_unset_l3vni_table(struct hash_bucket *bucket, void *arg)
{
	struct zebra_l3vni *zl3vni = bucket->data;

	hash_iterate(zl3vni->rmac_table, fpm_unset_rmac_table, zl3vni);
}

static void fpm_rmac_reset(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);

	hash_iterate(zrouter.l3vni_table, fpm_unset_l3vni_table, NULL);

	/* Schedule next event: send RMAC entries. */
	event_add_event(zrouter.master, fpm_rmac_send, fnc, 0,
			&fnc->t_rmacwalk);
}

static void fpm_process_wedged(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);

	zlog_warn("%s: Connection unable to write to peer for over %u seconds, resetting",
		  __func__, DPLANE_FPM_NL_WEDGIE_TIME);

	atomic_fetch_add_explicit(&fnc->counters.connection_errors, 1,
				  memory_order_relaxed);
	FPM_RECONNECT(fnc);
}

static void fpm_process_queue(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	struct zebra_dplane_ctx *ctx;
	bool no_bufs = false;
	uint64_t processed_contexts = 0;

	while (true) {
		size_t writeable_amount;

		frr_with_mutex (&fnc->obuf_mutex) {
			writeable_amount = STREAM_WRITEABLE(fnc->obuf);
		}

		/* No space available yet. */
		if (writeable_amount < NL_PKT_BUF_SIZE) {
			no_bufs = true;
			break;
		}

		/* Dequeue next item or quit processing. */
		frr_with_mutex (&fnc->ctxqueue_mutex) {
			ctx = dplane_ctx_dequeue(&fnc->ctxqueue);
		}
		if (ctx == NULL)
			break;

		/*
		 * Intentionally ignoring the return value
		 * as that we are ensuring that we can write to
		 * the output data in the STREAM_WRITEABLE
		 * check above, so we can ignore the return
		 */
		if (fnc->socket != -1)
			(void)fpm_nl_enqueue(fnc, ctx);

		/* Account the processed entries. */
		processed_contexts++;

		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(fnc->prov, ctx);
	}

	/* Update count of processed contexts */
	atomic_fetch_add_explicit(&fnc->counters.dplane_contexts,
				  processed_contexts, memory_order_relaxed);

	/* Re-schedule if we ran out of buffer space */
	if (no_bufs) {
		if (processed_contexts)
			event_add_event(fnc->fthread->master, fpm_process_queue, fnc, 0,
					&fnc->t_dequeue);
		else
			event_add_timer_msec(fnc->fthread->master, fpm_process_queue, fnc, 10,
					     &fnc->t_dequeue);
		event_add_timer(fnc->fthread->master, fpm_process_wedged, fnc,
				DPLANE_FPM_NL_WEDGIE_TIME, &fnc->t_wedged);
	} else
		EVENT_OFF(fnc->t_wedged);

	/*
	 * Let the dataplane thread know if there are items in the
	 * output queue to be processed. Otherwise they may sit
	 * until the dataplane thread gets scheduled for new,
	 * unrelated work.
	 */
	if (processed_contexts)
		dplane_provider_work_ready();
}

/**
 * Handles external (e.g. CLI, data plane or others) events.
 */
static void fpm_process_event(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	enum fpm_nl_events event = EVENT_VAL(t);

	switch (event) {
	case FNE_DISABLE:
		zlog_info("%s: manual FPM disable event", __func__);
		fnc->disabled = true;
		atomic_fetch_add_explicit(&fnc->counters.user_disables, 1,
					  memory_order_relaxed);

		/* Call reconnect to disable timers and clean up context. */
		fpm_reconnect(fnc);
		break;

	case FNE_RECONNECT:
		zlog_info("%s: manual FPM reconnect event", __func__);
		fnc->disabled = false;
		atomic_fetch_add_explicit(&fnc->counters.user_configures, 1,
					  memory_order_relaxed);
		fpm_reconnect(fnc);
		break;

	case FNE_RESET_COUNTERS:
		zlog_info("%s: manual FPM counters reset event", __func__);
		memset(&fnc->counters, 0, sizeof(fnc->counters));
		break;

	case FNE_TOGGLE_NHG:
		zlog_info("%s: toggle next hop groups support", __func__);
		fnc->use_nhg = !fnc->use_nhg;
		fpm_reconnect(fnc);
		break;

	case FNE_INTERNAL_RECONNECT:
		fpm_reconnect(fnc);
		break;

	case FNE_NHG_FINISHED:
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: next hop groups walk finished",
				   __func__);
		break;
	case FNE_RIB_FINISHED:
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: RIB walk finished", __func__);
		break;
	case FNE_RMAC_FINISHED:
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: RMAC walk finished", __func__);
		break;
	case FNE_LSP_FINISHED:
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: LSP walk finished", __func__);
		break;
	}
}

/*
 * Data plane functions.
 */
static int fpm_nl_start(struct zebra_dplane_provider *prov)
{
	struct fpm_nl_ctx *fnc;

	fnc = dplane_provider_get_data(prov);
	fnc->fthread = frr_pthread_new(NULL, prov_name, prov_name);
	assert(frr_pthread_run(fnc->fthread, NULL) == 0);
	fnc->ibuf = stream_new(NL_PKT_BUF_SIZE);
	fnc->obuf = stream_new(NL_PKT_BUF_SIZE * 128);
	pthread_mutex_init(&fnc->obuf_mutex, NULL);
	fnc->socket = -1;
	fnc->disabled = true;
	fnc->prov = prov;
	dplane_ctx_q_init(&fnc->ctxqueue);
	pthread_mutex_init(&fnc->ctxqueue_mutex, NULL);

	/* Set default values. */
	fnc->use_nhg = true;
	fnc->use_route_replace = true;

	return 0;
}

static int fpm_nl_finish_early(struct fpm_nl_ctx *fnc)
{
	/* Disable all events and close socket. */
	EVENT_OFF(fnc->t_lspreset);
	EVENT_OFF(fnc->t_lspwalk);
	EVENT_OFF(fnc->t_nhgreset);
	EVENT_OFF(fnc->t_nhgwalk);
	EVENT_OFF(fnc->t_ribreset);
	EVENT_OFF(fnc->t_ribwalk);
	EVENT_OFF(fnc->t_rmacreset);
	EVENT_OFF(fnc->t_rmacwalk);
	EVENT_OFF(fnc->t_event);
	EVENT_OFF(fnc->t_nhg);
	event_cancel_async(fnc->fthread->master, &fnc->t_read, NULL);
	event_cancel_async(fnc->fthread->master, &fnc->t_write, NULL);
	event_cancel_async(fnc->fthread->master, &fnc->t_connect, NULL);

	if (fnc->socket != -1) {
		close(fnc->socket);
		fnc->socket = -1;
	}

	return 0;
}

static int fpm_nl_finish_late(struct fpm_nl_ctx *fnc)
{
	/* Stop the running thread. */
	frr_pthread_stop(fnc->fthread, NULL);

	/* Free all allocated resources. */
	pthread_mutex_destroy(&fnc->obuf_mutex);
	pthread_mutex_destroy(&fnc->ctxqueue_mutex);
	stream_free(fnc->ibuf);
	stream_free(fnc->obuf);
	free(gfnc);
	gfnc = NULL;

	return 0;
}

static int fpm_nl_finish(struct zebra_dplane_provider *prov, bool early)
{
	struct fpm_nl_ctx *fnc;

	fnc = dplane_provider_get_data(prov);
	if (early)
		return fpm_nl_finish_early(fnc);

	return fpm_nl_finish_late(fnc);
}

static int fpm_nl_process(struct zebra_dplane_provider *prov)
{
	struct zebra_dplane_ctx *ctx;
	struct fpm_nl_ctx *fnc;
	int counter, limit;
	uint64_t cur_queue = 0, peak_queue = 0, stored_peak_queue;

	fnc = dplane_provider_get_data(prov);
	limit = dplane_provider_get_work_limit(prov);

	frr_with_mutex (&fnc->ctxqueue_mutex) {
		cur_queue = dplane_ctx_queue_count(&fnc->ctxqueue);
	}

	if (cur_queue >= (uint64_t)limit) {
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: Already at a limit(%" PRIu64
				   ") of internal work, hold off",
				   __func__, cur_queue);
		limit = 0;
	} else if (cur_queue != 0) {
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: current queue is %" PRIu64
				   ", limiting to lesser amount of %" PRIu64,
				   __func__, cur_queue, limit - cur_queue);
		limit -= cur_queue;
	}

	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (ctx == NULL)
			break;

		/*
		 * Skip all notifications if not connected, we'll walk the RIB
		 * anyway.
		 */
		if (fnc->socket != -1 && fnc->connecting == false) {
			frr_with_mutex (&fnc->ctxqueue_mutex) {
				dplane_ctx_enqueue_tail(&fnc->ctxqueue, ctx);
				cur_queue =
					dplane_ctx_queue_count(&fnc->ctxqueue);
			}

			if (peak_queue < cur_queue)
				peak_queue = cur_queue;
			continue;
		}

		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(prov, ctx);
	}

	/* Update peak queue length, if we just observed a new peak */
	stored_peak_queue = atomic_load_explicit(
		&fnc->counters.ctxqueue_len_peak, memory_order_relaxed);
	if (stored_peak_queue < peak_queue)
		atomic_store_explicit(&fnc->counters.ctxqueue_len_peak,
				      peak_queue, memory_order_relaxed);

	if (cur_queue > 0)
		event_add_event(fnc->fthread->master, fpm_process_queue, fnc, 0,
				&fnc->t_dequeue);

	/* Ensure dataplane thread is rescheduled if we hit the work limit */
	if (counter >= limit)
		dplane_provider_work_ready();

	return 0;
}

static int fpm_nl_new(struct event_loop *tm)
{
	struct zebra_dplane_provider *prov = NULL;
	int rv;

	gfnc = calloc(1, sizeof(*gfnc));
	rv = dplane_provider_register(prov_name, DPLANE_PRIO_POSTPROCESS,
				      DPLANE_PROV_FLAG_THREADED, fpm_nl_start,
				      fpm_nl_process, fpm_nl_finish, gfnc,
				      &prov);

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("%s register status: %d", prov_name, rv);

	install_node(&fpm_node);
	install_element(ENABLE_NODE, &fpm_show_status_cmd);
	install_element(ENABLE_NODE, &fpm_show_counters_cmd);
	install_element(ENABLE_NODE, &fpm_show_counters_json_cmd);
	install_element(ENABLE_NODE, &fpm_reset_counters_cmd);
	install_element(CONFIG_NODE, &fpm_set_address_cmd);
	install_element(CONFIG_NODE, &no_fpm_set_address_cmd);
	install_element(CONFIG_NODE, &fpm_use_nhg_cmd);
	install_element(CONFIG_NODE, &no_fpm_use_nhg_cmd);
	install_element(CONFIG_NODE, &fpm_use_route_replace_cmd);
	install_element(CONFIG_NODE, &no_fpm_use_route_replace_cmd);

	return 0;
}

static int fpm_nl_init(void)
{
	hook_register(frr_late_init, fpm_nl_new);
	return 0;
}

FRR_MODULE_SETUP(
	.name = "dplane_fpm_nl",
	.version = "0.0.1",
	.description = "Data plane plugin for FPM using netlink.",
	.init = fpm_nl_init,
);
