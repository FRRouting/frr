// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra's client library.
 * Copyright (C) 1999 Kunihiro Ishiguro
 * Copyright (C) 2005 Andrew J. Schorr
 */

#include <zebra.h>

#include "prefix.h"
#include "stream.h"
#include "buffer.h"
#include "network.h"
#include "vrf.h"
#include "vrf_int.h"
#include "if.h"
#include "log.h"
#include "frrevent.h"
#include "zclient.h"
#include "memory.h"
#include "table.h"
#include "nexthop.h"
#include "mpls.h"
#include "sockopt.h"
#include "pbr.h"
#include "tc.h"
#include "nexthop_group.h"
#include "lib_errors.h"
#include "srte.h"
#include "printfrr.h"
#include "srv6.h"

DEFINE_MTYPE_STATIC(LIB, ZCLIENT, "Zclient");
DEFINE_MTYPE_STATIC(LIB, REDIST_INST, "Redistribution instance IDs");

/* Zebra client events. */
enum zclient_event { ZCLIENT_SCHEDULE, ZCLIENT_READ, ZCLIENT_CONNECT };

/* Prototype for event manager. */
static void zclient_event(enum zclient_event, struct zclient *);

static void zebra_interface_if_set_value(struct stream *s,
					 struct interface *ifp);

const struct zclient_options zclient_options_default = {
	.synchronous = false,
	.auxiliary = false,
};

const struct zclient_options zclient_options_sync = {
	.synchronous = true,
	.auxiliary = true,
};

const struct zclient_options zclient_options_auxiliary = {
	.synchronous = false,
	.auxiliary = true,
};

struct sockaddr_storage zclient_addr;
socklen_t zclient_addr_len;

/* This file local debug flag. */
static int zclient_debug;

/* Allocate zclient structure. */
struct zclient *zclient_new(struct event_loop *master,
			    const struct zclient_options *opt,
			    zclient_handler *const *handlers, size_t n_handlers)
{
	struct zclient *zclient;
	size_t stream_size =
		MAX(ZEBRA_MAX_PACKET_SIZ, sizeof(struct zapi_route));

	zclient = XCALLOC(MTYPE_ZCLIENT, sizeof(struct zclient));

	zclient->ibuf = stream_new(stream_size);
	zclient->obuf = stream_new(stream_size);
	zclient->wb = buffer_new(0);
	zclient->master = master;

	zclient->handlers = handlers;
	zclient->n_handlers = n_handlers;

	zclient->synchronous = opt->synchronous;
	zclient->auxiliary = opt->auxiliary;

	return zclient;
}

/* This function is only called when exiting, because
   many parts of the code do not check for I/O errors, so they could
   reference an invalid pointer if the structure was ever freed.

   Free zclient structure. */
void zclient_free(struct zclient *zclient)
{
	if (zclient->ibuf)
		stream_free(zclient->ibuf);
	if (zclient->obuf)
		stream_free(zclient->obuf);
	if (zclient->wb)
		buffer_free(zclient->wb);

	XFREE(MTYPE_ZCLIENT, zclient);
}

unsigned short *redist_check_instance(struct redist_proto *red,
				      unsigned short instance)
{
	struct listnode *node;
	unsigned short *id;

	if (!red->instances)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(red->instances, node, id))
		if (*id == instance)
			return id;

	return NULL;
}

void redist_add_instance(struct redist_proto *red, unsigned short instance)
{
	unsigned short *in;

	red->enabled = 1;

	if (!red->instances)
		red->instances = list_new();

	in = XMALLOC(MTYPE_REDIST_INST, sizeof(unsigned short));
	*in = instance;
	listnode_add(red->instances, in);
}

void redist_del_instance(struct redist_proto *red, unsigned short instance)
{
	unsigned short *id;

	id = redist_check_instance(red, instance);
	if (!id)
		return;

	listnode_delete(red->instances, id);
	XFREE(MTYPE_REDIST_INST, id);
	if (!red->instances->count) {
		red->enabled = 0;
		list_delete(&red->instances);
	}
}

void redist_del_all_instances(struct redist_proto *red)
{
	struct listnode *ln, *nn;
	unsigned short *id;

	if (!red->instances)
		return;

	for (ALL_LIST_ELEMENTS(red->instances, ln, nn, id))
		redist_del_instance(red, *id);
}

/* Stop zebra client services. */
void zclient_stop(struct zclient *zclient)
{
	afi_t afi;
	int i;

	if (zclient_debug)
		zlog_debug("zclient %p stopped", zclient);

	/* Stop threads. */
	EVENT_OFF(zclient->t_read);
	EVENT_OFF(zclient->t_connect);
	EVENT_OFF(zclient->t_write);

	/* Reset streams. */
	stream_reset(zclient->ibuf);
	stream_reset(zclient->obuf);

	/* Empty the write buffer. */
	buffer_reset(zclient->wb);

	/* Close socket. */
	if (zclient->sock >= 0) {
		close(zclient->sock);
		zclient->sock = -1;
	}
	zclient->fail = 0;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
			vrf_bitmap_free(&zclient->redist[afi][i]);
			zclient->redist[afi][i] = VRF_BITMAP_NULL;
		}
		redist_del_instance(
			&zclient->mi_redist[afi][zclient->redist_default],
			zclient->instance);

		vrf_bitmap_free(&zclient->default_information[afi]);
		zclient->default_information[afi] = VRF_BITMAP_NULL;
	}
}

void zclient_reset(struct zclient *zclient)
{
	afi_t afi;

	zclient_stop(zclient);

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		redist_del_instance(
			&zclient->mi_redist[afi][zclient->redist_default],
			zclient->instance);

	zclient_init(zclient, zclient->redist_default, zclient->instance,
		     zclient->privs);
}

/**
 * Connect to zebra daemon.
 * @param zclient a pointer to zclient structure
 * @return socket fd just to make sure that connection established
 * @see zclient_init
 * @see zclient_new
 */
int zclient_socket_connect(struct zclient *zclient)
{
	int sock;
	int ret;

	/* We should think about IPv6 connection. */
	sock = socket(zclient_addr.ss_family, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	set_cloexec(sock);
	setsockopt_so_sendbuf(sock, 1048576);

	/* Connect to zebra. */
	ret = connect(sock, (struct sockaddr *)&zclient_addr, zclient_addr_len);
	if (ret < 0) {
		if (zclient_debug)
			zlog_debug("%s connect failure: %d(%s)", __func__,
				   errno, safe_strerror(errno));
		close(sock);
		return -1;
	}

	zclient->sock = sock;
	return sock;
}

static enum zclient_send_status zclient_failed(struct zclient *zclient)
{
	zclient->fail++;
	zclient_stop(zclient);
	zclient_event(ZCLIENT_CONNECT, zclient);
	return ZCLIENT_SEND_FAILURE;
}

static void zclient_flush_data(struct event *thread)
{
	struct zclient *zclient = EVENT_ARG(thread);

	zclient->t_write = NULL;
	if (zclient->sock < 0)
		return;
	switch (buffer_flush_available(zclient->wb, zclient->sock)) {
	case BUFFER_ERROR:
		flog_err(
			EC_LIB_ZAPI_SOCKET,
			"%s: buffer_flush_available failed on zclient fd %d, closing",
			__func__, zclient->sock);
		zclient_failed(zclient);
		return;
	case BUFFER_PENDING:
		zclient->t_write = NULL;
		event_add_write(zclient->master, zclient_flush_data, zclient,
				zclient->sock, &zclient->t_write);
		break;
	case BUFFER_EMPTY:
		/* Currently only Sharpd and Bgpd has callbacks defined */
		if (zclient->zebra_buffer_write_ready)
			(*zclient->zebra_buffer_write_ready)();
		break;
	}
}

/*
 * Returns:
 * ZCLIENT_SEND_FAILED   - is a failure
 * ZCLIENT_SEND_SUCCESS  - means we sent data to zebra
 * ZCLIENT_SEND_BUFFERED - means we are buffering
 */
enum zclient_send_status zclient_send_message(struct zclient *zclient)
{
	if (zclient->sock < 0)
		return ZCLIENT_SEND_FAILURE;
	switch (buffer_write(zclient->wb, zclient->sock,
			     STREAM_DATA(zclient->obuf),
			     stream_get_endp(zclient->obuf))) {
	case BUFFER_ERROR:
		flog_err(EC_LIB_ZAPI_SOCKET,
			 "%s: buffer_write failed to zclient fd %d, closing",
			 __func__, zclient->sock);
		return zclient_failed(zclient);
	case BUFFER_EMPTY:
		EVENT_OFF(zclient->t_write);
		return ZCLIENT_SEND_SUCCESS;
	case BUFFER_PENDING:
		event_add_write(zclient->master, zclient_flush_data, zclient,
				zclient->sock, &zclient->t_write);
		return ZCLIENT_SEND_BUFFERED;
	}

	/* should not get here */
	return ZCLIENT_SEND_SUCCESS;
}

/*
 * If we add more data to this structure please ensure that
 * struct zmsghdr in lib/zclient.h is updated as appropriate.
 */
void zclient_create_header(struct stream *s, uint16_t command, vrf_id_t vrf_id)
{
	/* length placeholder, caller can update */
	stream_putw(s, ZEBRA_HEADER_SIZE);
	stream_putc(s, ZEBRA_HEADER_MARKER);
	stream_putc(s, ZSERV_VERSION);
	stream_putl(s, vrf_id);
	stream_putw(s, command);
}

int zclient_read_header(struct stream *s, int sock, uint16_t *size,
			uint8_t *marker, uint8_t *version, vrf_id_t *vrf_id,
			uint16_t *cmd)
{
	if (stream_read(s, sock, ZEBRA_HEADER_SIZE) != ZEBRA_HEADER_SIZE)
		return -1;

	STREAM_GETW(s, *size);
	*size -= ZEBRA_HEADER_SIZE;
	STREAM_GETC(s, *marker);
	STREAM_GETC(s, *version);
	STREAM_GETL(s, *vrf_id);
	STREAM_GETW(s, *cmd);

	if (*version != ZSERV_VERSION || *marker != ZEBRA_HEADER_MARKER) {
		flog_err(
			EC_LIB_ZAPI_MISSMATCH,
			"%s: socket %d version mismatch, marker %d, version %d",
			__func__, sock, *marker, *version);
		return -1;
	}

	if (*size && stream_read(s, sock, *size) != *size)
		return -1;

	return 0;
stream_failure:
	return -1;
}

bool zapi_parse_header(struct stream *zmsg, struct zmsghdr *hdr)
{
	STREAM_GETW(zmsg, hdr->length);
	STREAM_GETC(zmsg, hdr->marker);
	STREAM_GETC(zmsg, hdr->version);
	STREAM_GETL(zmsg, hdr->vrf_id);
	STREAM_GETW(zmsg, hdr->command);
	return true;
stream_failure:
	return false;
}

/* Send simple Zebra message. */
static enum zclient_send_status zebra_message_send(struct zclient *zclient,
						   int command, vrf_id_t vrf_id)
{
	struct stream *s;

	/* Get zclient output buffer. */
	s = zclient->obuf;
	stream_reset(s);

	/* Send very simple command only Zebra message. */
	zclient_create_header(s, command, vrf_id);

	return zclient_send_message(zclient);
}

enum zclient_send_status zclient_send_hello(struct zclient *zclient)
{
	struct stream *s;

	if (zclient->redist_default || zclient->synchronous) {
		s = zclient->obuf;
		stream_reset(s);

		/* The VRF ID in the HELLO message is always 0. */
		zclient_create_header(s, ZEBRA_HELLO, VRF_DEFAULT);
		stream_putc(s, zclient->redist_default);
		stream_putw(s, zclient->instance);
		stream_putl(s, zclient->session_id);
		if (zclient->synchronous)
			stream_putc(s, 1);
		else
			stream_putc(s, 0);

		stream_putw_at(s, 0, stream_get_endp(s));
		return zclient_send_message(zclient);
	}

	return ZCLIENT_SEND_SUCCESS;
}

enum zclient_send_status zclient_send_vrf_label(struct zclient *zclient,
						vrf_id_t vrf_id, afi_t afi,
						mpls_label_t label,
						enum lsp_types_t ltype)
{
	struct stream *s;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_VRF_LABEL, vrf_id);
	stream_putl(s, label);
	stream_putc(s, afi);
	stream_putc(s, ltype);
	stream_putw_at(s, 0, stream_get_endp(s));
	return zclient_send_message(zclient);
}

enum zclient_send_status zclient_send_localsid(struct zclient *zclient,
		const struct in6_addr *sid, vrf_id_t vrf_id,
		enum seg6local_action_t action,
		const struct seg6local_context *context)
{
	struct prefix_ipv6 p = {};
	struct zapi_route api = {};
	struct zapi_nexthop *znh;
	struct interface *ifp;

	ifp = if_get_vrf_loopback(vrf_id);
	if (ifp == NULL)
		return ZCLIENT_SEND_FAILURE;

	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	p.prefix = *sid;

	api.vrf_id = VRF_DEFAULT;
	api.type = zclient->redist_default;
	api.instance = 0;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, &p, sizeof(p));

	if (action == ZEBRA_SEG6_LOCAL_ACTION_UNSPEC)
		return zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);

	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);

	znh = &api.nexthops[0];

	memset(znh, 0, sizeof(*znh));

	znh->type = NEXTHOP_TYPE_IFINDEX;
	znh->ifindex = ifp->ifindex;
	SET_FLAG(znh->flags, ZAPI_NEXTHOP_FLAG_SEG6LOCAL);
	znh->seg6local_action = action;
	memcpy(&znh->seg6local_ctx, context, sizeof(struct seg6local_context));

	api.nexthop_num = 1;

	return zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

/* Send register requests to zebra daemon for the information in a VRF. */
void zclient_send_reg_requests(struct zclient *zclient, vrf_id_t vrf_id)
{
	int i;
	afi_t afi;

	/* If not connected to the zebra yet. */
	if (zclient->sock < 0)
		return;

	if (zclient_debug)
		zlog_debug("%s: send register messages for VRF %u", __func__,
			   vrf_id);

	/* We need router-id information. */
	zclient_send_router_id_update(zclient, ZEBRA_ROUTER_ID_ADD, AFI_IP,
				      vrf_id);

	/* We need interface information. */
	zebra_message_send(zclient, ZEBRA_INTERFACE_ADD, vrf_id);

	/* Set unwanted redistribute route. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		vrf_bitmap_set(&zclient->redist[afi][zclient->redist_default],
			       vrf_id);

	/* Flush all redistribute request. */
	if (vrf_id == VRF_DEFAULT) {
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
				if (!zclient->mi_redist[afi][i].enabled)
					continue;

				struct listnode *node;
				unsigned short *id;

				for (ALL_LIST_ELEMENTS_RO(
					     zclient->mi_redist[afi][i]
						     .instances,
					     node, id))
					if (!(i == zclient->redist_default
					      && *id == zclient->instance))
						zebra_redistribute_send(
							ZEBRA_REDISTRIBUTE_ADD,
							zclient, afi, i, *id,
							VRF_DEFAULT);
			}
		}
	}

	/* Resend all redistribute request. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			if (i != zclient->redist_default &&
			    vrf_bitmap_check(&zclient->redist[afi][i], vrf_id))
				zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD,
							zclient, afi, i, 0,
							vrf_id);

		/* If default information is needed. */
		if (vrf_bitmap_check(&zclient->default_information[afi],
				     vrf_id))
			zebra_redistribute_default_send(
				ZEBRA_REDISTRIBUTE_DEFAULT_ADD, zclient, afi,
				vrf_id);
	}
}

/* Send unregister requests to zebra daemon for the information in a VRF. */
void zclient_send_dereg_requests(struct zclient *zclient, vrf_id_t vrf_id)
{
	int i;
	afi_t afi;

	/* If not connected to the zebra yet. */
	if (zclient->sock < 0)
		return;

	if (zclient_debug)
		zlog_debug("%s: send deregister messages for VRF %u", __func__,
			   vrf_id);

	/* We need router-id information. */
	zclient_send_router_id_update(zclient, ZEBRA_ROUTER_ID_DELETE, AFI_IP,
				      vrf_id);

	zebra_message_send(zclient, ZEBRA_INTERFACE_DELETE, vrf_id);

	/* Set unwanted redistribute route. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		vrf_bitmap_unset(&zclient->redist[afi][zclient->redist_default],
				 vrf_id);

	/* Flush all redistribute request. */
	if (vrf_id == VRF_DEFAULT) {
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
				if (!zclient->mi_redist[afi][i].enabled)
					continue;

				struct listnode *node;
				unsigned short *id;

				for (ALL_LIST_ELEMENTS_RO(
					     zclient->mi_redist[afi][i]
						     .instances,
					     node, id))
					if (!(i == zclient->redist_default
					      && *id == zclient->instance))
						zebra_redistribute_send(
							ZEBRA_REDISTRIBUTE_DELETE,
							zclient, afi, i, *id,
							VRF_DEFAULT);
			}
		}
	}

	/* Flush all redistribute request. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			if (i != zclient->redist_default &&
			    vrf_bitmap_check(&zclient->redist[afi][i], vrf_id))
				zebra_redistribute_send(
					ZEBRA_REDISTRIBUTE_DELETE, zclient, afi,
					i, 0, vrf_id);

		/* If default information is needed. */
		if (vrf_bitmap_check(&zclient->default_information[afi],
				     vrf_id))
			zebra_redistribute_default_send(
				ZEBRA_REDISTRIBUTE_DEFAULT_DELETE, zclient, afi,
				vrf_id);
	}
}

enum zclient_send_status
zclient_send_router_id_update(struct zclient *zclient,
			      zebra_message_types_t type, afi_t afi,
			      vrf_id_t vrf_id)
{
	struct stream *s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, type, vrf_id);
	stream_putw(s, afi);
	stream_putw_at(s, 0, stream_get_endp(s));
	return zclient_send_message(zclient);
}

/* Send request to zebra daemon to start or stop RA. */
enum zclient_send_status
zclient_send_interface_radv_req(struct zclient *zclient, vrf_id_t vrf_id,
				struct interface *ifp, int enable,
				uint32_t ra_interval)
{
	struct stream *s;

	/* If not connected to the zebra yet. */
	if (zclient->sock < 0)
		return ZCLIENT_SEND_FAILURE;

	/* Form and send message. */
	s = zclient->obuf;
	stream_reset(s);

	if (enable)
		zclient_create_header(s, ZEBRA_INTERFACE_ENABLE_RADV, vrf_id);
	else
		zclient_create_header(s, ZEBRA_INTERFACE_DISABLE_RADV, vrf_id);

	stream_putl(s, ifp->ifindex);
	stream_putl(s, ra_interval);

	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

enum zclient_send_status
zclient_send_interface_protodown(struct zclient *zclient, vrf_id_t vrf_id,
				 struct interface *ifp, bool down)
{
	struct stream *s;

	if (zclient->sock < 0)
		return ZCLIENT_SEND_FAILURE;

	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_INTERFACE_SET_PROTODOWN, vrf_id);
	stream_putl(s, ifp->ifindex);
	stream_putc(s, !!down);
	stream_putw_at(s, 0, stream_get_endp(s));
	return zclient_send_message(zclient);
}

/* Make connection to zebra daemon. */
int zclient_start(struct zclient *zclient)
{
	if (zclient_debug)
		zlog_info("zclient_start is called");

	/* If already connected to the zebra. */
	if (zclient->sock >= 0)
		return 0;

	/* Check connect thread. */
	if (zclient->t_connect)
		return 0;

	if (zclient_socket_connect(zclient) < 0) {
		if (zclient_debug)
			zlog_debug("zclient connection fail");
		zclient->fail++;
		zclient_event(ZCLIENT_CONNECT, zclient);
		return -1;
	}

	if (set_nonblocking(zclient->sock) < 0)
		flog_err(EC_LIB_ZAPI_SOCKET, "%s: set_nonblocking(%d) failed",
			 __func__, zclient->sock);

	/* Clear fail count. */
	zclient->fail = 0;
	if (zclient_debug)
		zlog_debug("zclient connect success with socket [%d]",
			   zclient->sock);

	/* Create read thread. */
	zclient_event(ZCLIENT_READ, zclient);

	zclient_send_hello(zclient);

	zebra_message_send(zclient, ZEBRA_INTERFACE_ADD, VRF_DEFAULT);

	/* Inform the successful connection. */
	if (zclient->zebra_connected)
		(*zclient->zebra_connected)(zclient);

	return 0;
}

/* Initialize zebra client.  Argument redist_default is unwanted
   redistribute route type. */
void zclient_init(struct zclient *zclient, int redist_default,
		  unsigned short instance, struct zebra_privs_t *privs)
{
	int afi, i;

	/* Set -1 to the default socket value. */
	zclient->sock = -1;
	zclient->privs = privs;

	/* Clear redistribution flags. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			vrf_bitmap_init(&zclient->redist[afi][i]);

	/* Set unwanted redistribute route.  bgpd does not need BGP route
	   redistribution. */
	zclient->redist_default = redist_default;
	zclient->instance = instance;
	/* Pending: make afi(s) an arg. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		redist_add_instance(&zclient->mi_redist[afi][redist_default],
				    instance);

		/* Set default-information redistribute to zero. */
		vrf_bitmap_init(&zclient->default_information[afi]);
	}

	if (zclient_debug)
		zlog_debug("scheduling zclient connection");

	zclient_event(ZCLIENT_SCHEDULE, zclient);
}

/* This function is a wrapper function for calling zclient_start from
   timer or event thread. */
static void zclient_connect(struct event *t)
{
	struct zclient *zclient;

	zclient = EVENT_ARG(t);
	zclient->t_connect = NULL;

	if (zclient_debug)
		zlog_debug("zclient_connect is called");

	zclient_start(zclient);
}

enum zclient_send_status zclient_send_rnh(struct zclient *zclient, int command,
					  const struct prefix *p, safi_t safi,
					  bool connected, bool resolve_via_def,
					  vrf_id_t vrf_id)
{
	struct stream *s;

	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, command, vrf_id);
	stream_putc(s, (connected) ? 1 : 0);
	stream_putc(s, (resolve_via_def) ? 1 : 0);
	stream_putw(s, safi);
	stream_putw(s, PREFIX_FAMILY(p));
	stream_putc(s, p->prefixlen);
	switch (PREFIX_FAMILY(p)) {
	case AF_INET:
		stream_put_in_addr(s, &p->u.prefix4);
		break;
	case AF_INET6:
		stream_put(s, &(p->u.prefix6), 16);
		break;
	default:
		break;
	}
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/*
 * "xdr_encode"-like interface that allows daemon (client) to send
 * a message to zebra server for a route that needs to be
 * added/deleted to the kernel. Info about the route is specified
 * by the caller in a struct zapi_route. zapi_route_encode() then writes
 * the info down the zclient socket using the stream_* functions.
 *
 * The corresponding read ("xdr_decode") function on the server
 * side is zapi_route_decode().
 *
 * If ZAPI_MESSAGE_DISTANCE is set, the distance value is written as a 1
 * byte value.
 *
 * If ZAPI_MESSAGE_METRIC is set, the metric value is written as a 4
 * byte value.
 *
 * If ZAPI_MESSAGE_TAG is set, the tag value is written as a 4 byte value
 *
 * If ZAPI_MESSAGE_MTU is set, the mtu value is written as a 4 byte value
 *
 * XXX: No attention paid to alignment.
 */
enum zclient_send_status
zclient_route_send(uint8_t cmd, struct zclient *zclient, struct zapi_route *api)
{
	if (zapi_route_encode(cmd, zclient->obuf, api) < 0)
		return ZCLIENT_SEND_FAILURE;
	return zclient_send_message(zclient);
}

static int zapi_nexthop_labels_cmp(const struct zapi_nexthop *next1,
				   const struct zapi_nexthop *next2)
{
	if (next1->label_num > next2->label_num)
		return 1;

	if (next1->label_num < next2->label_num)
		return -1;

	return memcmp(next1->labels, next2->labels, next1->label_num);
}

static int zapi_nexthop_srv6_cmp(const struct zapi_nexthop *next1,
				 const struct zapi_nexthop *next2)
{
	int ret = 0;

	ret = memcmp(&next1->seg6_segs, &next2->seg6_segs,
		     sizeof(struct in6_addr));
	if (ret != 0)
		return ret;

	if (next1->seg6local_action > next2->seg6local_action)
		return 1;

	if (next1->seg6local_action < next2->seg6local_action)
		return -1;

	return memcmp(&next1->seg6local_ctx, &next2->seg6local_ctx,
		      sizeof(struct seg6local_context));
}

static int zapi_nexthop_cmp_no_labels(const struct zapi_nexthop *next1,
				      const struct zapi_nexthop *next2)
{
	int ret = 0;

	if (next1->vrf_id < next2->vrf_id)
		return -1;

	if (next1->vrf_id > next2->vrf_id)
		return 1;

	if (next1->type < next2->type)
		return -1;

	if (next1->type > next2->type)
		return 1;

	if (next1->weight < next2->weight)
		return -1;

	if (next1->weight > next2->weight)
		return 1;

	switch (next1->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV6:
		ret = nexthop_g_addr_cmp(next1->type, &next1->gate,
					 &next2->gate);
		if (ret != 0)
			return ret;
		break;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		ret = nexthop_g_addr_cmp(next1->type, &next1->gate,
					 &next2->gate);
		if (ret != 0)
			return ret;
		fallthrough;
	case NEXTHOP_TYPE_IFINDEX:
		if (next1->ifindex < next2->ifindex)
			return -1;

		if (next1->ifindex > next2->ifindex)
			return 1;
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		if (next1->bh_type < next2->bh_type)
			return -1;

		if (next1->bh_type > next2->bh_type)
			return 1;
		break;
	}

	if (next1->srte_color < next2->srte_color)
		return -1;
	if (next1->srte_color > next2->srte_color)
		return 1;

	if (CHECK_FLAG(next1->flags, NEXTHOP_FLAG_HAS_BACKUP) ||
	    CHECK_FLAG(next2->flags, NEXTHOP_FLAG_HAS_BACKUP)) {

		if (!CHECK_FLAG(next1->flags, NEXTHOP_FLAG_HAS_BACKUP) &&
		    CHECK_FLAG(next2->flags, NEXTHOP_FLAG_HAS_BACKUP))
			return -1;

		if (CHECK_FLAG(next1->flags, NEXTHOP_FLAG_HAS_BACKUP) &&
		    !CHECK_FLAG(next2->flags, NEXTHOP_FLAG_HAS_BACKUP))
			return 1;

		if (next1->backup_num > 0 || next2->backup_num > 0) {

			if (next1->backup_num < next2->backup_num)
				return -1;

			if (next1->backup_num > next2->backup_num)
				return 1;

			ret = memcmp(next1->backup_idx,
				     next2->backup_idx, next1->backup_num);
			if (ret != 0)
				return ret;
		}
	}

	return 0;
}

static int zapi_nexthop_cmp(const void *item1, const void *item2)
{
	int ret = 0;

	const struct zapi_nexthop *next1 = item1;
	const struct zapi_nexthop *next2 = item2;

	ret = zapi_nexthop_cmp_no_labels(next1, next2);
	if (ret != 0)
		return ret;

	ret = zapi_nexthop_labels_cmp(next1, next2);
	if (ret != 0)
		return ret;

	ret = zapi_nexthop_srv6_cmp(next1, next2);

	return ret;
}

static void zapi_nexthop_group_sort(struct zapi_nexthop *nh_grp,
				    uint16_t nexthop_num)
{
	qsort(nh_grp, nexthop_num, sizeof(struct zapi_nexthop),
	      &zapi_nexthop_cmp);
}

/*
 * Encode a single zapi nexthop
 */
int zapi_nexthop_encode(struct stream *s, const struct zapi_nexthop *api_nh,
			uint32_t api_flags, uint32_t api_message)
{
	int i, ret = 0;
	int nh_flags = api_nh->flags;

	stream_putl(s, api_nh->vrf_id);
	stream_putc(s, api_nh->type);

	/* If needed, set 'labelled nexthop' flag */
	if (api_nh->label_num > 0) {
		SET_FLAG(nh_flags, ZAPI_NEXTHOP_FLAG_LABEL);

		/* Validate label count */
		if (api_nh->label_num > MPLS_MAX_LABELS) {
			ret = -1;
			goto done;
		}
	}

	/* If present, set 'weight' flag before encoding flags */
	if (api_nh->weight)
		SET_FLAG(nh_flags, ZAPI_NEXTHOP_FLAG_WEIGHT);

	/* Note that we're only encoding a single octet */
	stream_putc(s, nh_flags);

	switch (api_nh->type) {
	case NEXTHOP_TYPE_BLACKHOLE:
		stream_putc(s, api_nh->bh_type);
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		stream_put_in_addr(s, &api_nh->gate.ipv4);
		stream_putl(s, api_nh->ifindex);
		break;
	case NEXTHOP_TYPE_IFINDEX:
		stream_putl(s, api_nh->ifindex);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		stream_write(s, (uint8_t *)&api_nh->gate.ipv6,
			     16);
		stream_putl(s, api_nh->ifindex);
		break;
	}

	/* We only encode labels if we have >0 - we use
	 * the per-nexthop flag above to signal that the count
	 * is present in the payload.
	 */
	if (api_nh->label_num > 0) {
		stream_putc(s, api_nh->label_num);
		stream_putc(s, api_nh->label_type);
		stream_put(s, &api_nh->labels[0],
			   api_nh->label_num * sizeof(mpls_label_t));
	}

	if (api_nh->weight)
		stream_putq(s, api_nh->weight);

	/* Router MAC for EVPN routes. */
	if (CHECK_FLAG(nh_flags, ZAPI_NEXTHOP_FLAG_EVPN))
		stream_put(s, &(api_nh->rmac),
			   sizeof(struct ethaddr));

	/* Color for Segment Routing TE. */
	if (CHECK_FLAG(api_message, ZAPI_MESSAGE_SRTE))
		stream_putl(s, api_nh->srte_color);

	/* Index of backup nexthop */
	if (CHECK_FLAG(nh_flags, ZAPI_NEXTHOP_FLAG_HAS_BACKUP)) {
		/* Validate backup count */
		if (api_nh->backup_num > NEXTHOP_MAX_BACKUPS) {
			ret = -1;
			goto done;
		}

		stream_putc(s, api_nh->backup_num);
		for (i = 0; i < api_nh->backup_num; i++)
			stream_putc(s, api_nh->backup_idx[i]);
	}

	if (CHECK_FLAG(nh_flags, ZAPI_NEXTHOP_FLAG_SEG6LOCAL)) {
		stream_putl(s, api_nh->seg6local_action);
		stream_write(s, &api_nh->seg6local_ctx,
			     sizeof(struct seg6local_context));
	}

	if (CHECK_FLAG(nh_flags, ZAPI_NEXTHOP_FLAG_SEG6)) {
		stream_putc(s, api_nh->seg_num);
		stream_put(s, &api_nh->seg6_segs[0],
			   api_nh->seg_num * sizeof(struct in6_addr));
	}
done:
	return ret;
}

int zapi_srv6_locator_chunk_encode(struct stream *s,
				   const struct srv6_locator_chunk *c)
{
	stream_putw(s, strlen(c->locator_name));
	stream_put(s, c->locator_name, strlen(c->locator_name));
	stream_putw(s, c->prefix.prefixlen);
	stream_put(s, &c->prefix.prefix, sizeof(c->prefix.prefix));
	stream_putc(s, c->block_bits_length);
	stream_putc(s, c->node_bits_length);
	stream_putc(s, c->function_bits_length);
	stream_putc(s, c->argument_bits_length);
	stream_putc(s, c->flags);
	return 0;
}

int zapi_srv6_locator_chunk_decode(struct stream *s,
				   struct srv6_locator_chunk *c)
{
	uint16_t len = 0;

	c->prefix.family = AF_INET6;

	STREAM_GETW(s, len);
	if (len > SRV6_LOCNAME_SIZE)
		goto stream_failure;

	STREAM_GET(c->locator_name, s, len);
	STREAM_GETW(s, c->prefix.prefixlen);
	STREAM_GET(&c->prefix.prefix, s, sizeof(c->prefix.prefix));
	STREAM_GETC(s, c->block_bits_length);
	STREAM_GETC(s, c->node_bits_length);
	STREAM_GETC(s, c->function_bits_length);
	STREAM_GETC(s, c->argument_bits_length);
	STREAM_GETC(s, c->flags);
	return 0;

stream_failure:
	return -1;
}

int zapi_srv6_locator_encode(struct stream *s, const struct srv6_locator *l)
{
	stream_putw(s, strlen(l->name));
	stream_put(s, l->name, strlen(l->name));
	stream_putw(s, l->prefix.prefixlen);
	stream_put(s, &l->prefix.prefix, sizeof(l->prefix.prefix));
	stream_putc(s, l->flags);
	return 0;
}

int zapi_srv6_locator_decode(struct stream *s, struct srv6_locator *l)
{
	uint16_t len = 0;

	STREAM_GETW(s, len);
	if (len > SRV6_LOCNAME_SIZE)
		goto stream_failure;

	STREAM_GET(l->name, s, len);
	STREAM_GETW(s, l->prefix.prefixlen);
	STREAM_GET(&l->prefix.prefix, s, sizeof(l->prefix.prefix));
	l->prefix.family = AF_INET6;
	STREAM_GETC(s, l->flags);
	return 0;

stream_failure:
	return -1;
}

static int zapi_nhg_encode(struct stream *s, int cmd, struct zapi_nhg *api_nhg)
{
	int i;

	if (cmd != ZEBRA_NHG_DEL && cmd != ZEBRA_NHG_ADD) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: Specified zapi NHG command (%d) doesn't exist",
			 __func__, cmd);
		return -1;
	}

	if (api_nhg->nexthop_num >= MULTIPATH_NUM ||
	    api_nhg->backup_nexthop_num >= MULTIPATH_NUM) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: zapi NHG encode with invalid input", __func__);
		return -1;
	}

	stream_reset(s);
	zclient_create_header(s, cmd, VRF_DEFAULT);

	stream_putw(s, api_nhg->proto);
	stream_putl(s, api_nhg->id);

	stream_putw(s, api_nhg->resilience.buckets);
	stream_putl(s, api_nhg->resilience.idle_timer);
	stream_putl(s, api_nhg->resilience.unbalanced_timer);

	if (cmd == ZEBRA_NHG_ADD) {
		/* Nexthops */
		zapi_nexthop_group_sort(api_nhg->nexthops,
					api_nhg->nexthop_num);

		stream_putw(s, api_nhg->nexthop_num);

		for (i = 0; i < api_nhg->nexthop_num; i++)
			zapi_nexthop_encode(s, &api_nhg->nexthops[i], 0, 0);

		/* Backup nexthops */
		stream_putw(s, api_nhg->backup_nexthop_num);

		for (i = 0; i < api_nhg->backup_nexthop_num; i++)
			zapi_nexthop_encode(s, &api_nhg->backup_nexthops[i], 0,
					    0);
	}

	stream_putw_at(s, 0, stream_get_endp(s));

	return 0;
}

enum zclient_send_status zclient_nhg_send(struct zclient *zclient, int cmd,
					  struct zapi_nhg *api_nhg)
{
	api_nhg->proto = zclient->redist_default;

	if (zapi_nhg_encode(zclient->obuf, cmd, api_nhg))
		return -1;

	return zclient_send_message(zclient);
}

int zapi_route_encode(uint8_t cmd, struct stream *s, struct zapi_route *api)
{
	struct zapi_nexthop *api_nh;
	int i;
	int psize;

	stream_reset(s);
	zclient_create_header(s, cmd, api->vrf_id);

	if (api->type >= ZEBRA_ROUTE_MAX) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: Specified route type (%u) is not a legal value",
			 __func__, api->type);
		return -1;
	}
	stream_putc(s, api->type);

	stream_putw(s, api->instance);
	stream_putl(s, api->flags);
	stream_putl(s, api->message);

	if (api->safi < SAFI_UNICAST || api->safi >= SAFI_MAX) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: Specified route SAFI (%u) is not a legal value",
			 __func__, api->safi);
		return -1;
	}
	stream_putc(s, api->safi);

	/* Put prefix information. */
	stream_putc(s, api->prefix.family);
	psize = PSIZE(api->prefix.prefixlen);
	stream_putc(s, api->prefix.prefixlen);
	stream_write(s, &api->prefix.u.prefix, psize);

	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_SRCPFX)) {
		psize = PSIZE(api->src_prefix.prefixlen);
		stream_putc(s, api->src_prefix.prefixlen);
		stream_write(s, (uint8_t *)&api->src_prefix.prefix, psize);
	}

	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_NHG))
		stream_putl(s, api->nhgid);

	/* Nexthops.  */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP)) {
		/* limit the number of nexthops if necessary */
		if (api->nexthop_num > MULTIPATH_NUM) {
			flog_err(
				EC_LIB_ZAPI_ENCODE,
				"%s: prefix %pFX: can't encode %u nexthops (maximum is %u)",
				__func__, &api->prefix, api->nexthop_num,
				MULTIPATH_NUM);
			return -1;
		}

		/* We canonicalize the nexthops by sorting them; this allows
		 * zebra to resolve the list of nexthops to a nexthop-group
		 * more efficiently.
		 */
		zapi_nexthop_group_sort(api->nexthops, api->nexthop_num);

		stream_putw(s, api->nexthop_num);

		for (i = 0; i < api->nexthop_num; i++) {
			api_nh = &api->nexthops[i];

			/* MPLS labels for BGP-LU or Segment Routing */
			if (api_nh->label_num > MPLS_MAX_LABELS) {
				flog_err(
					EC_LIB_ZAPI_ENCODE,
					"%s: prefix %pFX: can't encode %u labels (maximum is %u)",
					__func__, &api->prefix,
					api_nh->label_num, MPLS_MAX_LABELS);
				return -1;
			}

			if (zapi_nexthop_encode(s, api_nh, api->flags,
						api->message)
			    != 0)
				return -1;
		}
	}

	/* Backup nexthops  */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_BACKUP_NEXTHOPS)) {
		/* limit the number of nexthops if necessary */
		if (api->backup_nexthop_num > MULTIPATH_NUM) {
			flog_err(
				EC_LIB_ZAPI_ENCODE,
				"%s: prefix %pFX: can't encode %u backup nexthops (maximum is %u)",
				__func__, &api->prefix, api->backup_nexthop_num,
				MULTIPATH_NUM);
			return -1;
		}

		/* Note that we do not sort the list of backup nexthops -
		 * this list is treated as an array and indexed by each
		 * primary nexthop that is associated with a backup.
		 */

		stream_putw(s, api->backup_nexthop_num);

		for (i = 0; i < api->backup_nexthop_num; i++) {
			api_nh = &api->backup_nexthops[i];

			/* MPLS labels for BGP-LU or Segment Routing */
			if (api_nh->label_num > MPLS_MAX_LABELS) {
				flog_err(
					EC_LIB_ZAPI_ENCODE,
					"%s: prefix %pFX: backup: can't encode %u labels (maximum is %u)",
					__func__, &api->prefix,
					api_nh->label_num, MPLS_MAX_LABELS);
				return -1;
			}

			if (zapi_nexthop_encode(s, api_nh, api->flags,
						api->message)
			    != 0)
				return -1;
		}
	}

	/* Attributes. */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_DISTANCE))
		stream_putc(s, api->distance);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_METRIC))
		stream_putl(s, api->metric);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_TAG))
		stream_putl(s, api->tag);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_MTU))
		stream_putl(s, api->mtu);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_TABLEID))
		stream_putl(s, api->tableid);

	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_OPAQUE)) {
		if (api->opaque.length > ZAPI_MESSAGE_OPAQUE_LENGTH) {
			flog_err(
				EC_LIB_ZAPI_ENCODE,
				"%s: opaque length %u is greater than allowed value",
				__func__, api->opaque.length);
			return -1;
		}

		stream_putw(s, api->opaque.length);
		stream_write(s, api->opaque.data, api->opaque.length);
	}
	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return 0;
}

/*
 * Decode a single zapi nexthop object
 */
int zapi_nexthop_decode(struct stream *s, struct zapi_nexthop *api_nh,
			uint32_t api_flags, uint32_t api_message)
{
	int i, ret = -1;

	STREAM_GETL(s, api_nh->vrf_id);
	STREAM_GETC(s, api_nh->type);

	/* Note that we're only using a single octet of flags */
	STREAM_GETC(s, api_nh->flags);

	switch (api_nh->type) {
	case NEXTHOP_TYPE_BLACKHOLE:
		STREAM_GETC(s, api_nh->bh_type);
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		STREAM_GET(&api_nh->gate.ipv4.s_addr, s,
			   IPV4_MAX_BYTELEN);
		STREAM_GETL(s, api_nh->ifindex);
		break;
	case NEXTHOP_TYPE_IFINDEX:
		STREAM_GETL(s, api_nh->ifindex);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		STREAM_GET(&api_nh->gate.ipv6, s, 16);
		STREAM_GETL(s, api_nh->ifindex);
		break;
	}

	/* MPLS labels for BGP-LU or Segment Routing */
	if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_LABEL)) {
		STREAM_GETC(s, api_nh->label_num);
		STREAM_GETC(s, api_nh->label_type);
		if (api_nh->label_num > MPLS_MAX_LABELS) {
			flog_err(
				EC_LIB_ZAPI_ENCODE,
				"%s: invalid number of MPLS labels (%u)",
				__func__, api_nh->label_num);
			return -1;
		}

		STREAM_GET(&api_nh->labels[0], s,
			   api_nh->label_num * sizeof(mpls_label_t));
	}

	if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_WEIGHT))
		STREAM_GETQ(s, api_nh->weight);

	/* Router MAC for EVPN routes. */
	if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_EVPN))
		STREAM_GET(&(api_nh->rmac), s,
			   sizeof(struct ethaddr));

	/* Color for Segment Routing TE. */
	if (CHECK_FLAG(api_message, ZAPI_MESSAGE_SRTE))
		STREAM_GETL(s, api_nh->srte_color);

	/* Backup nexthop index */
	if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_HAS_BACKUP)) {
		STREAM_GETC(s, api_nh->backup_num);

		if (api_nh->backup_num > NEXTHOP_MAX_BACKUPS)
			return -1;

		for (i = 0; i < api_nh->backup_num; i++)
			STREAM_GETC(s, api_nh->backup_idx[i]);
	}

	if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_SEG6LOCAL)) {
		STREAM_GETL(s, api_nh->seg6local_action);
		STREAM_GET(&api_nh->seg6local_ctx, s,
			   sizeof(struct seg6local_context));
	}

	if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_SEG6)) {
		STREAM_GETC(s, api_nh->seg_num);
		if (api_nh->seg_num > SRV6_MAX_SIDS) {
			flog_err(EC_LIB_ZAPI_ENCODE,
				 "%s: invalid number of SRv6 Segs (%u)",
				 __func__, api_nh->seg_num);
			return -1;
		}

		STREAM_GET(&api_nh->seg6_segs[0], s,
			   api_nh->seg_num * sizeof(struct in6_addr));
	}

	/* Success */
	ret = 0;

stream_failure:

	return ret;
}

int zapi_route_decode(struct stream *s, struct zapi_route *api)
{
	struct zapi_nexthop *api_nh;
	int i;

	memset(api, 0, sizeof(*api));

	/* Type, flags, message. */
	STREAM_GETC(s, api->type);
	if (api->type >= ZEBRA_ROUTE_MAX) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: Specified route type: %d is not a legal value",
			 __func__, api->type);
		return -1;
	}

	STREAM_GETW(s, api->instance);
	STREAM_GETL(s, api->flags);
	STREAM_GETL(s, api->message);
	STREAM_GETC(s, api->safi);
	if (api->safi < SAFI_UNICAST || api->safi >= SAFI_MAX) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: Specified route SAFI (%u) is not a legal value",
			 __func__, api->safi);
		return -1;
	}

	/* Prefix. */
	STREAM_GETC(s, api->prefix.family);
	STREAM_GETC(s, api->prefix.prefixlen);
	switch (api->prefix.family) {
	case AF_INET:
		if (api->prefix.prefixlen > IPV4_MAX_BITLEN) {
			flog_err(
				EC_LIB_ZAPI_ENCODE,
				"%s: V4 prefixlen is %d which should not be more than 32",
				__func__, api->prefix.prefixlen);
			return -1;
		}
		break;
	case AF_INET6:
		if (api->prefix.prefixlen > IPV6_MAX_BITLEN) {
			flog_err(
				EC_LIB_ZAPI_ENCODE,
				"%s: v6 prefixlen is %d which should not be more than 128",
				__func__, api->prefix.prefixlen);
			return -1;
		}
		break;
	default:
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: Specified family %d is not v4 or v6", __func__,
			 api->prefix.family);
		return -1;
	}
	STREAM_GET(&api->prefix.u.prefix, s, PSIZE(api->prefix.prefixlen));

	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_SRCPFX)) {
		api->src_prefix.family = AF_INET6;
		STREAM_GETC(s, api->src_prefix.prefixlen);
		if (api->src_prefix.prefixlen > IPV6_MAX_BITLEN) {
			flog_err(
				EC_LIB_ZAPI_ENCODE,
				"%s: SRC Prefix prefixlen received: %d is too large",
				__func__, api->src_prefix.prefixlen);
			return -1;
		}
		STREAM_GET(&api->src_prefix.prefix, s,
			   PSIZE(api->src_prefix.prefixlen));

		if (api->prefix.family != AF_INET6
		    || api->src_prefix.prefixlen == 0) {
			flog_err(
				EC_LIB_ZAPI_ENCODE,
				"%s: SRC prefix specified in some manner that makes no sense",
				__func__);
			return -1;
		}
	}

	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_NHG))
		STREAM_GETL(s, api->nhgid);

	/* Nexthops. */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP)) {
		STREAM_GETW(s, api->nexthop_num);
		if (api->nexthop_num > MULTIPATH_NUM) {
			flog_err(EC_LIB_ZAPI_ENCODE,
				 "%s: invalid number of nexthops (%u)",
				 __func__, api->nexthop_num);
			return -1;
		}

		for (i = 0; i < api->nexthop_num; i++) {
			api_nh = &api->nexthops[i];

			if (zapi_nexthop_decode(s, api_nh, api->flags,
						api->message)
			    != 0)
				return -1;
		}
	}

	/* Backup nexthops. */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_BACKUP_NEXTHOPS)) {
		STREAM_GETW(s, api->backup_nexthop_num);
		if (api->backup_nexthop_num > MULTIPATH_NUM) {
			flog_err(EC_LIB_ZAPI_ENCODE,
				 "%s: invalid number of backup nexthops (%u)",
				 __func__, api->backup_nexthop_num);
			return -1;
		}

		for (i = 0; i < api->backup_nexthop_num; i++) {
			api_nh = &api->backup_nexthops[i];

			if (zapi_nexthop_decode(s, api_nh, api->flags,
						api->message)
			    != 0)
				return -1;
		}
	}

	/* Attributes. */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_DISTANCE))
		STREAM_GETC(s, api->distance);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_METRIC))
		STREAM_GETL(s, api->metric);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_TAG))
		STREAM_GETL(s, api->tag);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_MTU))
		STREAM_GETL(s, api->mtu);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_TABLEID))
		STREAM_GETL(s, api->tableid);

	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_OPAQUE)) {
		STREAM_GETW(s, api->opaque.length);
		if (api->opaque.length > ZAPI_MESSAGE_OPAQUE_LENGTH) {
			flog_err(
				EC_LIB_ZAPI_ENCODE,
				"%s: opaque length %u is greater than allowed value",
				__func__, api->opaque.length);
			return -1;
		}

		STREAM_GET(api->opaque.data, s, api->opaque.length);
	}

	return 0;
stream_failure:
	return -1;
}

static void zapi_encode_prefix(struct stream *s, struct prefix *p,
			       uint8_t family)
{
	struct prefix any;

	if (!p) {
		memset(&any, 0, sizeof(any));
		any.family = family;
		p = &any;
	}

	stream_putc(s, p->family);
	stream_putc(s, p->prefixlen);
	stream_put(s, &p->u.prefix, prefix_blen(p));
}

static bool zapi_decode_prefix(struct stream *s, struct prefix *p)
{
	STREAM_GETC(s, p->family);
	STREAM_GETC(s, p->prefixlen);
	STREAM_GET(&(p->u.prefix), s, prefix_blen(p));
	return true;

stream_failure:
	return false;
}

static void zapi_encode_sockunion(struct stream *s, const union sockunion *su)
{
	int family = sockunion_family(su);
	size_t addrlen = family2addrsize(family);

	/*
	 * Must know length to encode
	 */
	assert(addrlen);

	stream_putc(s, (uint8_t)family);

	stream_write(s, sockunion_get_addr(su), addrlen);
}

static bool zapi_decode_sockunion(struct stream *s, union sockunion *su)
{
	uint8_t family;
	size_t addrlen;
	uint8_t buf[sizeof(union sockunion)];

	memset(su, 0, sizeof(*su));

	STREAM_GETC(s, family);
	sockunion_family(su) = family;

	addrlen = family2addrsize(family);
	if (!addrlen)
		return false;

	if (addrlen > sizeof(buf))
		return false;

	STREAM_GET(buf, s, addrlen);
	sockunion_set(su, family, buf, addrlen);
	return true;

stream_failure:
	return false;
}

/*
 * Encode filter subsection of pbr_rule
 */
static void zapi_pbr_rule_filter_encode(struct stream *s, struct pbr_filter *f)
{
	assert(f->src_ip.family == f->dst_ip.family);
	assert((f->src_ip.family == AF_INET) || (f->src_ip.family == AF_INET6));

	stream_putl(s, f->filter_bm);

	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_IP_PROTOCOL))
		stream_putc(s, f->ip_proto);

	/* addresses */
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_SRC_IP))
		zapi_encode_prefix(s, &f->src_ip, f->src_ip.family);
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_DST_IP))
		zapi_encode_prefix(s, &f->dst_ip, f->dst_ip.family);

	/* port numbers */
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_SRC_PORT))
		stream_putw(s, f->src_port);
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_DST_PORT))
		stream_putw(s, f->dst_port);

	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_DSCP))
		stream_putc(s, f->dsfield & PBR_DSFIELD_DSCP);
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_ECN))
		stream_putc(s, f->dsfield & PBR_DSFIELD_ECN);

	/* vlan */
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_PCP))
		stream_putc(s, f->pcp);
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_VLAN_ID))
		stream_putw(s, f->vlan_id);
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_VLAN_FLAGS))
		stream_putw(s, f->vlan_flags);


	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_FWMARK))
		stream_putl(s, f->fwmark);
}

static bool zapi_pbr_rule_filter_decode(struct stream *s, struct pbr_filter *f)
{
	uint8_t dscp = 0;
	uint8_t ecn = 0;

	STREAM_GETL(s, f->filter_bm);

	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_IP_PROTOCOL))
		STREAM_GETC(s, f->ip_proto);

	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_SRC_IP))
		if (!zapi_decode_prefix(s, &(f->src_ip)))
			goto stream_failure;
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_DST_IP))
		if (!zapi_decode_prefix(s, &(f->dst_ip)))
			goto stream_failure;

	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_SRC_PORT))
		STREAM_GETW(s, f->src_port);
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_DST_PORT))
		STREAM_GETW(s, f->dst_port);

	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_DSCP))
		STREAM_GETC(s, dscp);
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_ECN))
		STREAM_GETC(s, ecn);
	f->dsfield = (dscp & PBR_DSFIELD_DSCP) | (ecn & PBR_DSFIELD_ECN);

	/* vlan */
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_PCP))
		STREAM_GETC(s, f->pcp);
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_VLAN_ID))
		STREAM_GETW(s, f->vlan_id);
	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_VLAN_FLAGS))
		STREAM_GETW(s, f->vlan_flags);

	if (CHECK_FLAG(f->filter_bm, PBR_FILTER_FWMARK))
		STREAM_GETL(s, f->fwmark);

	return true;

stream_failure:
	return false;
}

static void zapi_pbr_rule_action_encode(struct stream *s, struct pbr_action *a)
{
	stream_putl(s, a->flags);

	if (CHECK_FLAG(a->flags, PBR_ACTION_TABLE))
		stream_putl(s, a->table);
	if (CHECK_FLAG(a->flags, PBR_ACTION_QUEUE_ID))
		stream_putl(s, a->queue_id);

	/* L3 */
	if (CHECK_FLAG(a->flags, PBR_ACTION_SRC_IP))
		zapi_encode_sockunion(s, &a->src_ip);
	if (CHECK_FLAG(a->flags, PBR_ACTION_DST_IP))
		zapi_encode_sockunion(s, &a->dst_ip);
	if (CHECK_FLAG(a->flags, PBR_ACTION_SRC_PORT))
		stream_putw(s, a->src_port);
	if (CHECK_FLAG(a->flags, PBR_ACTION_DST_PORT))
		stream_putw(s, a->dst_port);

	if (CHECK_FLAG(a->flags, PBR_ACTION_DSCP))
		stream_putc(s, a->dscp & PBR_DSFIELD_DSCP);
	if (CHECK_FLAG(a->flags, PBR_ACTION_ECN))
		stream_putc(s, a->ecn & PBR_DSFIELD_ECN);

	/* L2 */
	if (CHECK_FLAG(a->flags, PBR_ACTION_PCP))
		stream_putc(s, a->pcp);
	if (CHECK_FLAG(a->flags, PBR_ACTION_VLAN_ID))
		stream_putw(s, a->vlan_id);
}

static bool zapi_pbr_rule_action_decode(struct stream *s, struct pbr_action *a)
{
	STREAM_GETL(s, a->flags);

	if (CHECK_FLAG(a->flags, PBR_ACTION_TABLE))
		STREAM_GETL(s, a->table);
	if (CHECK_FLAG(a->flags, PBR_ACTION_QUEUE_ID))
		STREAM_GETL(s, a->queue_id);

	/* L3 */
	if (CHECK_FLAG(a->flags, PBR_ACTION_SRC_IP)) {
		if (!zapi_decode_sockunion(s, &(a->src_ip)))
			goto stream_failure;
	}
	if (CHECK_FLAG(a->flags, PBR_ACTION_DST_IP))
		if (!zapi_decode_sockunion(s, &(a->dst_ip)))
			goto stream_failure;

	if (CHECK_FLAG(a->flags, PBR_ACTION_SRC_PORT))
		STREAM_GETW(s, a->src_port);
	if (CHECK_FLAG(a->flags, PBR_ACTION_DST_PORT))
		STREAM_GETW(s, a->dst_port);

	if (CHECK_FLAG(a->flags, PBR_ACTION_DSCP)) {
		STREAM_GETC(s, a->dscp);
		a->dscp &= PBR_DSFIELD_DSCP;
	}
	if (CHECK_FLAG(a->flags, PBR_ACTION_ECN)) {
		STREAM_GETC(s, a->ecn);
		a->ecn &= PBR_DSFIELD_ECN;
	}

	/* L2 */
	if (CHECK_FLAG(a->flags, PBR_ACTION_PCP))
		STREAM_GETC(s, a->pcp);
	if (CHECK_FLAG(a->flags, PBR_ACTION_VLAN_ID))
		STREAM_GETW(s, a->vlan_id);

	return true;

stream_failure:
	return false;
}

int zapi_pbr_rule_encode(struct stream *s, struct pbr_rule *r)
{
	/*
	 * PBR record count is always 1
	 */
	stream_putl(s, 1);

	stream_putc(s, r->family);
	stream_putl(s, r->seq);
	stream_putl(s, r->priority);
	stream_putl(s, r->unique);

	zapi_pbr_rule_filter_encode(s, &(r->filter));
	zapi_pbr_rule_action_encode(s, &(r->action));

	stream_put(s, r->ifname, IFNAMSIZ);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return 0;
}

bool zapi_pbr_rule_decode(struct stream *s, struct pbr_rule *r)
{
	/* NB caller has already read 4-byte rule count */

	memset(r, 0, sizeof(*r));

	STREAM_GETC(s, r->family);
	STREAM_GETL(s, r->seq);
	STREAM_GETL(s, r->priority);
	STREAM_GETL(s, r->unique);

	if (!zapi_pbr_rule_filter_decode(s, &(r->filter)))
		goto stream_failure;
	if (!zapi_pbr_rule_action_decode(s, &(r->action)))
		goto stream_failure;

	STREAM_GET(r->ifname, s, IFNAMSIZ);
	return true;

stream_failure:
	return false;
}

int zapi_tc_qdisc_encode(uint8_t cmd, struct stream *s, struct tc_qdisc *qdisc)
{
	stream_reset(s);
	zclient_create_header(s, cmd, VRF_DEFAULT);


	stream_putl(s, 1);

	stream_putl(s, qdisc->ifindex);
	stream_putl(s, qdisc->kind);

	stream_putw_at(s, 0, stream_get_endp(s));

	return 0;
}

int zapi_tc_class_encode(uint8_t cmd, struct stream *s, struct tc_class *class)
{
	stream_reset(s);
	zclient_create_header(s, cmd, VRF_DEFAULT);

	stream_putl(s, 1);

	stream_putl(s, class->ifindex);
	stream_putl(s, class->handle);
	stream_putl(s, class->kind);

	switch (class->kind) {
	case TC_QDISC_HTB:
		stream_putq(s, class->u.htb.rate);
		stream_putq(s, class->u.htb.ceil);
		break;
	case TC_QDISC_UNSPEC:
	case TC_QDISC_NOQUEUE:
		/* not implemented */
		break;
	}
	stream_putw_at(s, 0, stream_get_endp(s));

	return 0;
}

int zapi_tc_filter_encode(uint8_t cmd, struct stream *s,
			  struct tc_filter *filter)
{
	stream_reset(s);
	zclient_create_header(s, cmd, VRF_DEFAULT);

	stream_putl(s, 1);

	stream_putl(s, filter->ifindex);
	stream_putl(s, filter->handle);
	stream_putl(s, filter->priority);
	stream_putl(s, filter->protocol);
	stream_putl(s, filter->kind);

	switch (filter->kind) {
	case TC_FILTER_FLOWER:
		stream_putl(s, filter->u.flower.filter_bm);
		if (filter->u.flower.filter_bm & TC_FLOWER_IP_PROTOCOL)
			stream_putc(s, filter->u.flower.ip_proto);
		if (filter->u.flower.filter_bm & TC_FLOWER_SRC_IP)
			zapi_encode_prefix(s, &filter->u.flower.src_ip,
					   filter->u.flower.src_ip.family);
		if (filter->u.flower.filter_bm & TC_FLOWER_SRC_PORT) {
			stream_putw(s, filter->u.flower.src_port_min);
			stream_putw(s, filter->u.flower.src_port_max);
		}
		if (filter->u.flower.filter_bm & TC_FLOWER_DST_IP)
			zapi_encode_prefix(s, &filter->u.flower.dst_ip,
					   filter->u.flower.dst_ip.family);
		if (filter->u.flower.filter_bm & TC_FLOWER_DST_PORT) {
			stream_putw(s, filter->u.flower.dst_port_min);
			stream_putw(s, filter->u.flower.dst_port_max);
		}
		if (filter->u.flower.filter_bm & TC_FLOWER_DSFIELD) {
			stream_putc(s, filter->u.flower.dsfield);
			stream_putc(s, filter->u.flower.dsfield_mask);
		}
		stream_putl(s, filter->u.flower.classid);
		break;
	case TC_FILTER_UNSPEC:
	case TC_FILTER_BPF:
	case TC_FILTER_FLOW:
	case TC_FILTER_U32:
		/* not implemented */
		break;
	}

	stream_putw_at(s, 0, stream_get_endp(s));

	return 0;
}

bool zapi_nhg_notify_decode(struct stream *s, uint32_t *id,
			    enum zapi_nhg_notify_owner *note)
{
	uint32_t read_id;

	STREAM_GET(note, s, sizeof(*note));
	STREAM_GETL(s, read_id);

	*id = read_id;

	return true;

stream_failure:
	return false;
}

bool zapi_route_notify_decode(struct stream *s, struct prefix *p,
			      uint32_t *tableid,
			      enum zapi_route_notify_owner *note,
			      afi_t *afi, safi_t *safi)
{
	uint32_t t;
	afi_t afi_val;
	safi_t safi_val;

	STREAM_GET(note, s, sizeof(*note));

	STREAM_GETC(s, p->family);
	STREAM_GETC(s, p->prefixlen);
	STREAM_GET(&p->u.prefix, s, prefix_blen(p));
	STREAM_GETL(s, t);
	STREAM_GETC(s, afi_val);
	STREAM_GETC(s, safi_val);

	*tableid = t;

	if (afi)
		*afi = afi_val;
	if (safi)
		*safi = safi_val;

	return true;

stream_failure:
	return false;
}

bool zapi_rule_notify_decode(struct stream *s, uint32_t *seqno,
			     uint32_t *priority, uint32_t *unique, char *ifname,
			     enum zapi_rule_notify_owner *note)
{
	uint32_t prio, seq, uni;

	STREAM_GET(note, s, sizeof(*note));

	STREAM_GETL(s, seq);
	STREAM_GETL(s, prio);
	STREAM_GETL(s, uni);
	STREAM_GET(ifname, s, IFNAMSIZ);

	if (zclient_debug)
		zlog_debug("%s: %u %u %u %s", __func__, seq, prio, uni, ifname);
	*seqno = seq;
	*priority = prio;
	*unique = uni;

	return true;

stream_failure:
	return false;
}

bool zapi_ipset_notify_decode(struct stream *s, uint32_t *unique,
			      enum zapi_ipset_notify_owner *note)
{
	uint32_t uni;
	uint16_t notew;

	STREAM_GETW(s, notew);

	STREAM_GETL(s, uni);

	if (zclient_debug)
		zlog_debug("%s: %u", __func__, uni);
	*unique = uni;
	*note = (enum zapi_ipset_notify_owner)notew;
	return true;

stream_failure:
	return false;
}

bool zapi_ipset_entry_notify_decode(struct stream *s, uint32_t *unique,
				    char *ipset_name,
				    enum zapi_ipset_entry_notify_owner *note)
{
	uint32_t uni;
	uint16_t notew;

	STREAM_GETW(s, notew);

	STREAM_GETL(s, uni);

	STREAM_GET(ipset_name, s, ZEBRA_IPSET_NAME_SIZE);

	if (zclient_debug)
		zlog_debug("%s: %u", __func__, uni);
	*unique = uni;
	*note = (enum zapi_ipset_entry_notify_owner)notew;

	return true;

stream_failure:
	return false;
}

bool zapi_iptable_notify_decode(struct stream *s,
		uint32_t *unique,
		enum zapi_iptable_notify_owner *note)
{
	uint32_t uni;
	uint16_t notew;

	STREAM_GETW(s, notew);

	STREAM_GETL(s, uni);

	if (zclient_debug)
		zlog_debug("%s: %u", __func__, uni);
	*unique = uni;
	*note = (enum zapi_iptable_notify_owner)notew;

	return true;

stream_failure:
	return false;
}

struct nexthop *nexthop_from_zapi_nexthop(const struct zapi_nexthop *znh)
{
	struct nexthop *n = nexthop_new();

	n->type = znh->type;
	n->vrf_id = znh->vrf_id;
	n->ifindex = znh->ifindex;
	n->gate = znh->gate;
	n->srte_color = znh->srte_color;

	/*
	 * This function currently handles labels
	 */
	if (znh->label_num) {
		nexthop_add_labels(n, ZEBRA_LSP_NONE, znh->label_num,
				   znh->labels);
	}

	if (CHECK_FLAG(znh->flags, ZAPI_NEXTHOP_FLAG_HAS_BACKUP)) {
		SET_FLAG(n->flags, NEXTHOP_FLAG_HAS_BACKUP);
		n->backup_num = znh->backup_num;
		memcpy(n->backup_idx, znh->backup_idx, n->backup_num);
	}

	if (znh->seg6local_action != ZEBRA_SEG6_LOCAL_ACTION_UNSPEC)
		nexthop_add_srv6_seg6local(n, znh->seg6local_action,
					   &znh->seg6local_ctx);

	if (znh->seg_num && !sid_zero_ipv6(znh->seg6_segs))
		nexthop_add_srv6_seg6(n, &znh->seg6_segs[0], znh->seg_num);

	return n;
}

/*
 * Convert nexthop to zapi nexthop
 */
int zapi_nexthop_from_nexthop(struct zapi_nexthop *znh,
			      const struct nexthop *nh)
{
	int i;

	memset(znh, 0, sizeof(*znh));

	znh->type = nh->type;
	znh->vrf_id = nh->vrf_id;
	znh->weight = nh->weight;
	znh->ifindex = nh->ifindex;
	znh->gate = nh->gate;
	znh->srte_color = nh->srte_color;

	if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_ONLINK))
		SET_FLAG(znh->flags, ZAPI_NEXTHOP_FLAG_ONLINK);

	if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_EVPN))
		SET_FLAG(znh->flags, ZAPI_NEXTHOP_FLAG_EVPN);

	if (nh->nh_label && (nh->nh_label->num_labels > 0)) {

		/* Validate */
		if (nh->nh_label->num_labels > MPLS_MAX_LABELS)
			return -1;

		for (i = 0; i < nh->nh_label->num_labels; i++)
			znh->labels[i] = nh->nh_label->label[i];

		znh->label_num = i;
		znh->label_type = nh->nh_label_type;
		SET_FLAG(znh->flags, ZAPI_NEXTHOP_FLAG_LABEL);
	}

	if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_HAS_BACKUP)) {
		if (nh->backup_num > NEXTHOP_MAX_BACKUPS)
			return -1;

		SET_FLAG(znh->flags, ZAPI_NEXTHOP_FLAG_HAS_BACKUP);
		znh->backup_num = nh->backup_num;
		memcpy(znh->backup_idx, nh->backup_idx, znh->backup_num);
	}

	if (nh->nh_srv6) {
		if (nh->nh_srv6->seg6local_action !=
		    ZEBRA_SEG6_LOCAL_ACTION_UNSPEC) {
			SET_FLAG(znh->flags, ZAPI_NEXTHOP_FLAG_SEG6LOCAL);
			znh->seg6local_action = nh->nh_srv6->seg6local_action;
			memcpy(&znh->seg6local_ctx,
			       &nh->nh_srv6->seg6local_ctx,
			       sizeof(struct seg6local_context));
		}

		if (nh->nh_srv6->seg6_segs && nh->nh_srv6->seg6_segs->num_segs &&
		    !sid_zero(nh->nh_srv6->seg6_segs)) {
			SET_FLAG(znh->flags, ZAPI_NEXTHOP_FLAG_SEG6);
			znh->seg_num = nh->nh_srv6->seg6_segs->num_segs;
			for (i = 0; i < nh->nh_srv6->seg6_segs->num_segs; i++)
				memcpy(&znh->seg6_segs[i],
				       &nh->nh_srv6->seg6_segs->seg[i],
				       sizeof(struct in6_addr));
		}
	}

	return 0;
}

/*
 * Wrapper that converts backup nexthop
 */
int zapi_backup_nexthop_from_nexthop(struct zapi_nexthop *znh,
				     const struct nexthop *nh)
{
	int ret;

	/* Ensure that zapi flags are correct: backups don't have backups */
	ret = zapi_nexthop_from_nexthop(znh, nh);
	if (ret == 0)
		UNSET_FLAG(znh->flags, ZAPI_NEXTHOP_FLAG_HAS_BACKUP);

	return ret;
}

/*
 * Format some info about a zapi nexthop, for debug or logging.
 */
const char *zapi_nexthop2str(const struct zapi_nexthop *znh, char *buf,
			     int bufsize)
{
	char tmp[INET6_ADDRSTRLEN];

	switch (znh->type) {
	case NEXTHOP_TYPE_IFINDEX:
		snprintf(buf, bufsize, "if %u", znh->ifindex);
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		inet_ntop(AF_INET, &znh->gate.ipv4, tmp, sizeof(tmp));
		snprintf(buf, bufsize, "%s if %u", tmp, znh->ifindex);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		inet_ntop(AF_INET6, &znh->gate.ipv6, tmp, sizeof(tmp));
		snprintf(buf, bufsize, "%s if %u", tmp, znh->ifindex);
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		snprintf(buf, bufsize, "blackhole");
		break;
	default:
		snprintf(buf, bufsize, "unknown");
		break;
	}

	return buf;
}

/*
 * Decode the nexthop-tracking update message
 */
static bool zapi_nexthop_update_decode(struct stream *s, struct prefix *match,
				       struct zapi_route *nhr)
{
	uint32_t i;

	memset(nhr, 0, sizeof(*nhr));

	STREAM_GETL(s, nhr->message);
	STREAM_GETW(s, nhr->safi);
	STREAM_GETW(s, match->family);
	STREAM_GETC(s, match->prefixlen);
	/*
	 * What we got told to match against
	 */
	switch (match->family) {
	case AF_INET:
		STREAM_GET(&match->u.prefix4.s_addr, s, IPV4_MAX_BYTELEN);
		break;
	case AF_INET6:
		STREAM_GET(&match->u.prefix6, s, IPV6_MAX_BYTELEN);
		break;
	}
	/*
	 * What we matched against
	 */
	STREAM_GETW(s, nhr->prefix.family);
	STREAM_GETC(s, nhr->prefix.prefixlen);
	switch (nhr->prefix.family) {
	case AF_INET:
		STREAM_GET(&nhr->prefix.u.prefix4.s_addr, s, IPV4_MAX_BYTELEN);
		break;
	case AF_INET6:
		STREAM_GET(&nhr->prefix.u.prefix6, s, IPV6_MAX_BYTELEN);
		break;
	default:
		break;
	}
	if (CHECK_FLAG(nhr->message, ZAPI_MESSAGE_SRTE))
		STREAM_GETL(s, nhr->srte_color);

	STREAM_GETC(s, nhr->type);
	STREAM_GETW(s, nhr->instance);
	STREAM_GETC(s, nhr->distance);
	STREAM_GETL(s, nhr->metric);
	STREAM_GETC(s, nhr->nexthop_num);

	for (i = 0; i < nhr->nexthop_num; i++) {
		if (zapi_nexthop_decode(s, &(nhr->nexthops[i]), 0, 0) != 0)
			return false;
	}

	return true;
stream_failure:
	return false;
}

bool zapi_error_decode(struct stream *s, enum zebra_error_types *error)
{
	memset(error, 0, sizeof(*error));

	STREAM_GET(error, s, sizeof(*error));

	if (zclient_debug)
		zlog_debug("%s: type: %s", __func__,
			   zebra_error_type2str(*error));

	return true;
stream_failure:
	return false;
}

/*
 * send a ZEBRA_REDISTRIBUTE_ADD or ZEBRA_REDISTRIBUTE_DELETE
 * for the route type (ZEBRA_ROUTE_KERNEL etc.). The zebra server will
 * then set/unset redist[type] in the client handle (a struct zserv) for the
 * sending client
 */
enum zclient_send_status
zebra_redistribute_send(int command, struct zclient *zclient, afi_t afi,
			int type, unsigned short instance, vrf_id_t vrf_id)
{
	struct stream *s;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, command, vrf_id);
	stream_putc(s, afi);
	stream_putc(s, type);
	stream_putw(s, instance);

	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

enum zclient_send_status
zebra_redistribute_default_send(int command, struct zclient *zclient, afi_t afi,
				vrf_id_t vrf_id)
{
	struct stream *s;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, command, vrf_id);
	stream_putc(s, afi);

	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/* Send route notify request to zebra */
int zebra_route_notify_send(int command, struct zclient *zclient, bool set)
{
	struct stream *s;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, command, 0);
	stream_putc(s, !!set);

	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/* Get prefix in ZServ format; family should be filled in on prefix */
static int zclient_stream_get_prefix(struct stream *s, struct prefix *p)
{
	size_t plen = prefix_blen(p);
	uint8_t c;
	p->prefixlen = 0;

	if (plen == 0)
		return -1;

	STREAM_GET(&p->u.prefix, s, plen);
	STREAM_GETC(s, c);
	p->prefixlen = MIN(plen * 8, c);

	return 0;
stream_failure:
	return -1;
}

/* Router-id update from zebra daemon. */
int zebra_router_id_update_read(struct stream *s, struct prefix *rid)
{
	/* Fetch interface address. */
	STREAM_GETC(s, rid->family);

	return zclient_stream_get_prefix(s, rid);

stream_failure:
	return -1;
}

/* Interface addition from zebra daemon. */
/*
 * The format of the message sent with type ZEBRA_INTERFACE_ADD or
 * ZEBRA_INTERFACE_DELETE from zebra to the client is:
 *     0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  ifname                                                       |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  ifindex                                                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  status       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  if_flags                                                     |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  metric                                                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  speed                                                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  ifmtu                                                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  ifmtu6                                                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  bandwidth                                                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  parent ifindex                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Link Layer Type                                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Harware Address Length                                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Hardware Address      if HW length different from 0          |
 * |   ...                  max INTERFACE_HWADDR_MAX               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Link_params? |  Whether a link-params follows: 1 or 0.
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Link_params    0 or 1 INTERFACE_LINK_PARAMS_SIZE sized       |
 * |   ....          (struct if_link_params).                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

static int zclient_vrf_add(ZAPI_CALLBACK_ARGS)
{
	struct vrf *vrf;
	char vrfname_tmp[VRF_NAMSIZ + 1] = {};
	struct vrf_data data;

	STREAM_GET(&data, zclient->ibuf, sizeof(struct vrf_data));
	/* Read interface name. */
	STREAM_GET(vrfname_tmp, zclient->ibuf, VRF_NAMSIZ);

	if (strlen(vrfname_tmp) == 0)
		goto stream_failure;

	/* Lookup/create vrf by name, then vrf_id. */
	vrf = vrf_get(vrf_id, vrfname_tmp);

	/* If there's already a VRF with this name, don't create vrf */
	if (!vrf)
		return 0;

	vrf->data.l.table_id = data.l.table_id;
	memcpy(vrf->data.l.netns_name, data.l.netns_name, NS_NAMSIZ);
	vrf_enable(vrf);

	return 0;
stream_failure:
	return -1;
}

static int zclient_vrf_delete(ZAPI_CALLBACK_ARGS)
{
	struct vrf *vrf;

	/* Lookup vrf by vrf_id. */
	vrf = vrf_lookup_by_id(vrf_id);

	/*
	 * If a routing protocol doesn't know about a
	 * vrf that is about to be deleted.  There is
	 * no point in attempting to delete it.
	 */
	if (!vrf)
		return 0;

	vrf_delete(vrf);
	return 0;
}

static int zclient_interface_add(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;
	char ifname_tmp[IFNAMSIZ + 1] = {};
	struct stream *s = zclient->ibuf;
	struct vrf *vrf;

	/* Read interface name. */
	STREAM_GET(ifname_tmp, s, IFNAMSIZ);

	/* Lookup/create interface by name. */
	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf) {
		zlog_debug(
			"Rx'd interface add from Zebra, but VRF %u does not exist",
			vrf_id);
		return -1;
	}

	ifp = if_get_by_name(ifname_tmp, vrf_id, vrf->name);

	zebra_interface_if_set_value(s, ifp);

	if_new_via_zapi(ifp);

	return 0;
stream_failure:
	return -1;
}

/*
 * Read interface up/down msg (ZEBRA_INTERFACE_UP/ZEBRA_INTERFACE_DOWN)
 * from zebra server.  The format of this message is the same as
 * that sent for ZEBRA_INTERFACE_ADD/ZEBRA_INTERFACE_DELETE,
 * except that no sockaddr_dl is sent at the tail of the message.
 */
struct interface *zebra_interface_state_read(struct stream *s, vrf_id_t vrf_id)
{
	struct interface *ifp;
	char ifname_tmp[IFNAMSIZ + 1] = {};

	/* Read interface name. */
	STREAM_GET(ifname_tmp, s, IFNAMSIZ);

	/* Lookup this by interface index. */
	ifp = if_lookup_by_name(ifname_tmp, vrf_id);
	if (ifp == NULL) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "INTERFACE_STATE: Cannot find IF %s in VRF %d",
			 ifname_tmp, vrf_id);
		return NULL;
	}

	zebra_interface_if_set_value(s, ifp);

	return ifp;
stream_failure:
	return NULL;
}

static int zclient_interface_delete(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;
	struct stream *s = zclient->ibuf;

	ifp = zebra_interface_state_read(s, vrf_id);

	if (ifp == NULL)
		return 0;

	if_destroy_via_zapi(ifp);
	return 0;
}

static int zclient_interface_up(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;
	struct stream *s = zclient->ibuf;

	ifp = zebra_interface_state_read(s, vrf_id);

	if (!ifp)
		return 0;

	if_up_via_zapi(ifp);
	return 0;
}

static int zclient_interface_down(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;
	struct stream *s = zclient->ibuf;

	ifp = zebra_interface_state_read(s, vrf_id);

	if (!ifp)
		return 0;

	if_down_via_zapi(ifp);
	return 0;
}

static int zclient_handle_error(ZAPI_CALLBACK_ARGS)
{
	enum zebra_error_types error;
	struct stream *s = zclient->ibuf;

	zapi_error_decode(s, &error);

	if (zclient->handle_error)
		(*zclient->handle_error)(error);
	return 0;
}

static int link_params_set_value(struct stream *s, struct interface *ifp)
{
	uint8_t link_params_enabled, nb_ext_adm_grp;
	struct if_link_params *iflp;
	uint32_t bwclassnum, bitmap_data;

	iflp = if_link_params_get(ifp);

	if (iflp == NULL)
		iflp = if_link_params_init(ifp);

	STREAM_GETC(s, link_params_enabled);
	if (!link_params_enabled) {
		if_link_params_free(ifp);
		return 0;
	}

	STREAM_GETL(s, iflp->lp_status);
	STREAM_GETL(s, iflp->te_metric);
	STREAM_GETF(s, iflp->max_bw);
	STREAM_GETF(s, iflp->max_rsv_bw);
	STREAM_GETL(s, bwclassnum);
	{
		unsigned int i;
		for (i = 0; i < bwclassnum && i < MAX_CLASS_TYPE; i++)
			STREAM_GETF(s, iflp->unrsv_bw[i]);
		if (i < bwclassnum)
			flog_err(
				EC_LIB_ZAPI_MISSMATCH,
				"%s: received %d > %d (MAX_CLASS_TYPE) bw entries - outdated library?",
				__func__, bwclassnum, MAX_CLASS_TYPE);
	}
	STREAM_GETL(s, iflp->admin_grp);

	/* Extended Administrative Group */
	admin_group_clear(&iflp->ext_admin_grp);
	STREAM_GETC(s, nb_ext_adm_grp);
	for (size_t i = 0; i < nb_ext_adm_grp; i++) {
		STREAM_GETL(s, bitmap_data);
		admin_group_bulk_set(&iflp->ext_admin_grp, bitmap_data, i);
	}

	STREAM_GETL(s, iflp->rmt_as);
	iflp->rmt_ip.s_addr = stream_get_ipv4(s);

	STREAM_GETL(s, iflp->av_delay);
	STREAM_GETL(s, iflp->min_delay);
	STREAM_GETL(s, iflp->max_delay);
	STREAM_GETL(s, iflp->delay_var);

	STREAM_GETF(s, iflp->pkt_loss);
	STREAM_GETF(s, iflp->res_bw);
	STREAM_GETF(s, iflp->ava_bw);
	STREAM_GETF(s, iflp->use_bw);

	return 0;
stream_failure:
	return -1;
}

struct interface *zebra_interface_link_params_read(struct stream *s,
						   vrf_id_t vrf_id,
						   bool *changed)
{
	struct if_link_params *iflp;
	struct if_link_params iflp_prev = {0};
	ifindex_t ifindex;
	bool iflp_prev_set = false;

	STREAM_GETL(s, ifindex);

	struct interface *ifp = if_lookup_by_index(ifindex, vrf_id);

	if (ifp == NULL) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: unknown ifindex %u, shouldn't happen", __func__,
			 ifindex);
		return NULL;
	}

	iflp = if_link_params_get(ifp);

	if (iflp) {
		iflp_prev_set = true;
		admin_group_init(&iflp_prev.ext_admin_grp);
		if_link_params_copy(&iflp_prev, iflp);
	}

	/* read the link_params from stream
	 * Free ifp->link_params if the stream has no params
	 * to means that link-params are not enabled on links.
	 */
	if (link_params_set_value(s, ifp) != 0)
		goto stream_failure;

	if (changed != NULL) {
		iflp = if_link_params_get(ifp);

		if (iflp_prev_set && iflp) {
			if (if_link_params_cmp(&iflp_prev, iflp))
				*changed = false;
			else
				*changed = true;
		} else if (!iflp_prev_set && !iflp)
			*changed = false;
		else
			*changed = true;
	}

	if (iflp_prev_set)
		admin_group_term(&iflp_prev.ext_admin_grp);

	return ifp;

stream_failure:
	if (iflp_prev_set)
		admin_group_term(&iflp_prev.ext_admin_grp);
	return NULL;
}

static void zebra_interface_if_set_value(struct stream *s,
					 struct interface *ifp)
{
	uint8_t link_params_status = 0;
	ifindex_t old_ifindex, new_ifindex;

	old_ifindex = ifp->oldifindex;
	/* Read interface's index. */
	STREAM_GETL(s, new_ifindex);
	if_set_index(ifp, new_ifindex);
	STREAM_GETC(s, ifp->status);

	/* Read interface's value. */
	STREAM_GETQ(s, ifp->flags);
	STREAM_GETC(s, ifp->ptm_enable);
	STREAM_GETC(s, ifp->ptm_status);
	STREAM_GETL(s, ifp->metric);
	STREAM_GETL(s, ifp->speed);
	STREAM_GETL(s, ifp->txqlen);
	STREAM_GETL(s, ifp->mtu);
	STREAM_GETL(s, ifp->mtu6);
	STREAM_GETL(s, ifp->bandwidth);
	STREAM_GETL(s, ifp->link_ifindex);
	STREAM_GETL(s, ifp->ll_type);
	STREAM_GETL(s, ifp->hw_addr_len);
	if (ifp->hw_addr_len)
		STREAM_GET(ifp->hw_addr, s,
			   MIN(ifp->hw_addr_len, INTERFACE_HWADDR_MAX));

	/* Read Traffic Engineering status */
	link_params_status = stream_getc(s);
	/* Then, Traffic Engineering parameters if any */
	if (link_params_status)
		link_params_set_value(s, ifp);

	nexthop_group_interface_state_change(ifp, old_ifindex);

	return;
stream_failure:
	zlog_err("Could not parse interface values; aborting");
	assert(!"Failed to parse interface values");
}

size_t zebra_interface_link_params_write(struct stream *s,
					 struct interface *ifp)
{
	size_t w, nb_ext_adm_grp;
	struct if_link_params *iflp;
	int i;


	if (s == NULL || ifp == NULL)
		return 0;

	iflp = ifp->link_params;
	w = 0;

	/* encode if link_params is enabled */
	if (iflp) {
		w += stream_putc(s, true);
	} else {
		w += stream_putc(s, false);
		return w;
	}

	w += stream_putl(s, iflp->lp_status);

	w += stream_putl(s, iflp->te_metric);
	w += stream_putf(s, iflp->max_bw);
	w += stream_putf(s, iflp->max_rsv_bw);

	w += stream_putl(s, MAX_CLASS_TYPE);
	for (i = 0; i < MAX_CLASS_TYPE; i++)
		w += stream_putf(s, iflp->unrsv_bw[i]);

	w += stream_putl(s, iflp->admin_grp);

	/* Extended Administrative Group */
	nb_ext_adm_grp = admin_group_nb_words(&iflp->ext_admin_grp);
	w += stream_putc(s, nb_ext_adm_grp);
	for (size_t i = 0; i < nb_ext_adm_grp; i++)
		stream_putl(s, admin_group_get_offset(&iflp->ext_admin_grp, i));

	w += stream_putl(s, iflp->rmt_as);
	w += stream_put_in_addr(s, &iflp->rmt_ip);

	w += stream_putl(s, iflp->av_delay);
	w += stream_putl(s, iflp->min_delay);
	w += stream_putl(s, iflp->max_delay);
	w += stream_putl(s, iflp->delay_var);

	w += stream_putf(s, iflp->pkt_loss);
	w += stream_putf(s, iflp->res_bw);
	w += stream_putf(s, iflp->ava_bw);
	w += stream_putf(s, iflp->use_bw);

	return w;
}

/*
 * format of message for address addition is:
 *    0
 *  0 1 2 3 4 5 6 7
 * +-+-+-+-+-+-+-+-+
 * |   type        |  ZEBRA_INTERFACE_ADDRESS_ADD or
 * +-+-+-+-+-+-+-+-+  ZEBRA_INTERFACE_ADDRES_DELETE
 * |               |
 * +               +
 * |   ifindex     |
 * +               +
 * |               |
 * +               +
 * |               |
 * +-+-+-+-+-+-+-+-+
 * |   ifc_flags   |  flags for connected address
 * +-+-+-+-+-+-+-+-+
 * |  addr_family  |
 * +-+-+-+-+-+-+-+-+
 * |    addr...    |
 * :               :
 * |               |
 * +-+-+-+-+-+-+-+-+
 * |    addr_len   |  len of addr. E.g., addr_len = 4 for ipv4 addrs.
 * +-+-+-+-+-+-+-+-+
 * |     daddr..   |
 * :               :
 * |               |
 * +-+-+-+-+-+-+-+-+
 */

static int memconstant(const void *s, int c, size_t n)
{
	const uint8_t *p = s;

	while (n-- > 0)
		if (*p++ != c)
			return 0;
	return 1;
}


struct connected *zebra_interface_address_read(int type, struct stream *s,
					       vrf_id_t vrf_id)
{
	ifindex_t ifindex;
	struct interface *ifp;
	struct connected *ifc;
	struct prefix p, d, *dp;
	int plen;
	uint8_t ifc_flags;

	memset(&p, 0, sizeof(p));
	memset(&d, 0, sizeof(d));

	/* Get interface index. */
	STREAM_GETL(s, ifindex);

	/* Lookup index. */
	ifp = if_lookup_by_index(ifindex, vrf_id);
	if (ifp == NULL) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "INTERFACE_ADDRESS_%s: Cannot find IF %u in VRF %d",
			 (type == ZEBRA_INTERFACE_ADDRESS_ADD) ? "ADD" : "DEL",
			 ifindex, vrf_id);
		return NULL;
	}

	/* Fetch flag. */
	STREAM_GETC(s, ifc_flags);

	/* Fetch interface address. */
	STREAM_GETC(s, d.family);
	p.family = d.family;
	plen = prefix_blen(&d);

	if (zclient_stream_get_prefix(s, &p) != 0)
		goto stream_failure;

	/* Fetch destination address. */
	STREAM_GET(&d.u.prefix, s, plen);

	/* N.B. NULL destination pointers are encoded as all zeroes */
	dp = memconstant(&d.u.prefix, 0, plen) ? NULL : &d;

	if (type == ZEBRA_INTERFACE_ADDRESS_ADD) {
		ifc = connected_lookup_prefix_exact(ifp, &p);
		if (!ifc) {
			/* N.B. NULL destination pointers are encoded as all
			 * zeroes */
			ifc = connected_add_by_prefix(ifp, &p, dp);
		}
		if (ifc) {
			ifc->flags = ifc_flags;
			if (ifc->destination)
				ifc->destination->prefixlen =
					ifc->address->prefixlen;
			else if (CHECK_FLAG(ifc->flags, ZEBRA_IFA_PEER)) {
				/* carp interfaces on OpenBSD with 0.0.0.0/0 as
				 * "peer" */
				flog_err(
					EC_LIB_ZAPI_ENCODE,
					"interface %s address %pFX with peer flag set, but no peer address!",
					ifp->name, ifc->address);
				UNSET_FLAG(ifc->flags, ZEBRA_IFA_PEER);
			}
		}
	} else {
		assert(type == ZEBRA_INTERFACE_ADDRESS_DELETE);
		ifc = connected_delete_by_prefix(ifp, &p);
	}

	return ifc;

stream_failure:
	return NULL;
}

/*
 * format of message for neighbor connected address is:
 *    0
 *  0 1 2 3 4 5 6 7
 * +-+-+-+-+-+-+-+-+
 * |   type        |  ZEBRA_INTERFACE_NBR_ADDRESS_ADD or
 * +-+-+-+-+-+-+-+-+  ZEBRA_INTERFACE_NBR_ADDRES_DELETE
 * |               |
 * +               +
 * |   ifindex     |
 * +               +
 * |               |
 * +               +
 * |               |
 * +-+-+-+-+-+-+-+-+
 * |  addr_family  |
 * +-+-+-+-+-+-+-+-+
 * |    addr...    |
 * :               :
 * |               |
 * +-+-+-+-+-+-+-+-+
 * |    addr_len   |  len of addr.
 * +-+-+-+-+-+-+-+-+
 */
struct nbr_connected *
zebra_interface_nbr_address_read(int type, struct stream *s, vrf_id_t vrf_id)
{
	unsigned int ifindex;
	struct interface *ifp;
	struct prefix p;
	struct nbr_connected *ifc;

	/* Get interface index. */
	STREAM_GETL(s, ifindex);

	/* Lookup index. */
	ifp = if_lookup_by_index(ifindex, vrf_id);
	if (ifp == NULL) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "INTERFACE_NBR_%s: Cannot find IF %u in VRF %d",
			 (type == ZEBRA_INTERFACE_NBR_ADDRESS_ADD) ? "ADD"
								   : "DELETE",
			 ifindex, vrf_id);
		return NULL;
	}

	STREAM_GETC(s, p.family);
	STREAM_GET(&p.u.prefix, s, prefix_blen(&p));
	STREAM_GETC(s, p.prefixlen);

	if (type == ZEBRA_INTERFACE_NBR_ADDRESS_ADD) {
		/* Currently only supporting P2P links, so any new RA source
		   address is
		   considered as the replacement of the previously learnt
		   Link-Local address. */
		if (!(ifc = listnode_head(ifp->nbr_connected))) {
			ifc = nbr_connected_new();
			ifc->address = prefix_new();
			ifc->ifp = ifp;
			listnode_add(ifp->nbr_connected, ifc);
		}

		prefix_copy(ifc->address, &p);
	} else {
		assert(type == ZEBRA_INTERFACE_NBR_ADDRESS_DELETE);

		ifc = nbr_connected_check(ifp, &p);
		if (ifc)
			listnode_delete(ifp->nbr_connected, ifc);
	}

	return ifc;

stream_failure:
	return NULL;
}

/* filter unwanted messages until the expected one arrives */
static int zclient_read_sync_response(struct zclient *zclient,
				      uint16_t expected_cmd)
{
	struct stream *s;
	uint16_t size = -1;
	uint8_t marker;
	uint8_t version;
	vrf_id_t vrf_id;
	uint16_t cmd;
	fd_set readfds;
	int ret;

	ret = 0;
	cmd = expected_cmd + 1;
	while (ret == 0 && cmd != expected_cmd) {
		s = zclient->ibuf;
		stream_reset(s);

		/* wait until response arrives */
		FD_ZERO(&readfds);
		FD_SET(zclient->sock, &readfds);
		select(zclient->sock + 1, &readfds, NULL, NULL, NULL);
		if (!FD_ISSET(zclient->sock, &readfds))
			continue;
		/* read response */
		ret = zclient_read_header(s, zclient->sock, &size, &marker,
					  &version, &vrf_id, &cmd);
		if (zclient_debug)
			zlog_debug("%s: Response (%d bytes) received", __func__,
				   size);
	}
	if (ret != 0) {
		flog_err(EC_LIB_ZAPI_ENCODE, "%s: Invalid Sync Message Reply",
			 __func__);
		return -1;
	}

	return 0;
}
/**
 * Connect to label manager in a synchronous way
 *
 * It first writes the request to zclient output buffer and then
 * immediately reads the answer from the input buffer.
 *
 * @param zclient Zclient used to connect to label manager (zebra)
 * @param async Synchronous (0) or asynchronous (1) operation
 * @result Result of response
 */
int lm_label_manager_connect(struct zclient *zclient, int async)
{
	int ret;
	struct stream *s;
	uint8_t result;
	uint16_t cmd = async ? ZEBRA_LABEL_MANAGER_CONNECT_ASYNC :
			       ZEBRA_LABEL_MANAGER_CONNECT;

	if (zclient_debug)
		zlog_debug("Connecting to Label Manager (LM)");

	if (zclient->sock < 0) {
		zlog_debug("%s: invalid zclient socket", __func__);
		return -1;
	}

	/* send request */
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, cmd, VRF_DEFAULT);

	/* proto */
	stream_putc(s, zclient->redist_default);
	/* instance */
	stream_putw(s, zclient->instance);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	ret = writen(zclient->sock, s->data, stream_get_endp(s));
	if (ret < 0) {
		flog_err(EC_LIB_ZAPI_SOCKET, "Can't write to zclient sock");
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}
	if (ret == 0) {
		flog_err(EC_LIB_ZAPI_SOCKET, "Zclient sock closed");
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}
	if (zclient_debug)
		zlog_debug("LM connect request sent (%d bytes)", ret);

	if (async)
		return 0;

	/* read response */
	if (zclient_read_sync_response(zclient, cmd)
	    != 0)
		return -1;

	s = zclient->ibuf;

	/* read instance and proto */
	uint8_t proto;
	uint16_t instance;

	STREAM_GETC(s, proto);
	STREAM_GETW(s, instance);

	/* sanity */
	if (proto != zclient->redist_default)
		flog_err(
			EC_LIB_ZAPI_ENCODE,
			"Wrong proto (%u) in LM connect response. Should be %u",
			proto, zclient->redist_default);
	if (instance != zclient->instance)
		flog_err(
			EC_LIB_ZAPI_ENCODE,
			"Wrong instId (%u) in LM connect response. Should be %u",
			instance, zclient->instance);

	/* result code */
	STREAM_GETC(s, result);
	if (zclient_debug)
		zlog_debug("LM connect-response received, result %u", result);

	return (int)result;

stream_failure:
	return -1;
}

/**
 * Function to request a srv6-locator chunk in an asynchronous way
 *
 * @param zclient Zclient used to connect to table manager (zebra)
 * @param locator_name Name of SRv6-locator
 * @result 0 on success, -1 otherwise
 */
int srv6_manager_get_locator_chunk(struct zclient *zclient,
				   const char *locator_name)
{
	struct stream *s;
	const size_t len = strlen(locator_name);

	if (zclient_debug)
		zlog_debug("Getting SRv6-Locator Chunk %s", locator_name);

	if (zclient->sock < 0)
		return -1;

	/* send request */
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_SRV6_MANAGER_GET_LOCATOR_CHUNK,
			      VRF_DEFAULT);

	/* locator_name */
	stream_putw(s, len);
	stream_put(s, locator_name, len);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/**
 * Function to release a srv6-locator chunk
 *
 * @param zclient Zclient used to connect to table manager (zebra)
 * @param locator_name Name of SRv6-locator
 * @result 0 on success, -1 otherwise
 */
int srv6_manager_release_locator_chunk(struct zclient *zclient,
				       const char *locator_name)
{
	struct stream *s;
	const size_t len = strlen(locator_name);

	if (zclient_debug)
		zlog_debug("Releasing SRv6-Locator Chunk %s", locator_name);

	if (zclient->sock < 0)
		return -1;

	/* send request */
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_SRV6_MANAGER_RELEASE_LOCATOR_CHUNK,
			      VRF_DEFAULT);

	/* locator_name */
	stream_putw(s, len);
	stream_put(s, locator_name, len);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/*
 * Asynchronous label chunk request
 *
 * @param zclient Zclient used to connect to label manager (zebra)
 * @param keep Avoid garbage collection
 * @param chunk_size Amount of labels requested
 * @param base Base for the label chunk. if MPLS_LABEL_BASE_ANY we do not care
 * @result 0 on success, -1 otherwise
 */
enum zclient_send_status zclient_send_get_label_chunk(struct zclient *zclient,
						      uint8_t keep,
						      uint32_t chunk_size,
						      uint32_t base)
{
	struct stream *s;

	if (zclient_debug)
		zlog_debug("Getting Label Chunk");

	if (zclient->sock < 0)
		return ZCLIENT_SEND_FAILURE;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_GET_LABEL_CHUNK, VRF_DEFAULT);
	/* proto */
	stream_putc(s, zclient->redist_default);
	/* instance */
	stream_putw(s, zclient->instance);
	stream_putc(s, keep);
	stream_putl(s, chunk_size);
	stream_putl(s, base);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/**
 * Function to request a label chunk in a synchronous way
 *
 * It first writes the request to zclient output buffer and then
 * immediately reads the answer from the input buffer.
 *
 * @param zclient Zclient used to connect to label manager (zebra)
 * @param keep Avoid garbage collection
 * @param chunk_size Amount of labels requested
 * @param start To write first assigned chunk label to
 * @param end To write last assigned chunk label to
 * @result 0 on success, -1 otherwise
 */
int lm_get_label_chunk(struct zclient *zclient, uint8_t keep, uint32_t base,
		       uint32_t chunk_size, uint32_t *start, uint32_t *end)
{
	int ret;
	struct stream *s;
	uint8_t response_keep;

	if (zclient_debug)
		zlog_debug("Getting Label Chunk");

	if (zclient->sock < 0)
		return -1;

	/* send request */
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_GET_LABEL_CHUNK, VRF_DEFAULT);
	/* proto */
	stream_putc(s, zclient->redist_default);
	/* instance */
	stream_putw(s, zclient->instance);
	/* keep */
	stream_putc(s, keep);
	/* chunk size */
	stream_putl(s, chunk_size);
	/* requested chunk base */
	stream_putl(s, base);
	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	ret = writen(zclient->sock, s->data, stream_get_endp(s));
	if (ret < 0) {
		flog_err(EC_LIB_ZAPI_SOCKET, "Can't write to zclient sock");
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}
	if (ret == 0) {
		flog_err(EC_LIB_ZAPI_SOCKET, "Zclient sock closed");
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}
	if (zclient_debug)
		zlog_debug("Label chunk request (%d bytes) sent", ret);

	/* read response */
	if (zclient_read_sync_response(zclient, ZEBRA_GET_LABEL_CHUNK) != 0)
		return -1;

	/* parse response */
	s = zclient->ibuf;

	/* read proto and instance */
	uint8_t proto;
	uint8_t instance;

	STREAM_GETC(s, proto);
	STREAM_GETW(s, instance);

	/* sanities */
	if (proto != zclient->redist_default)
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "Wrong proto (%u) in get chunk response. Should be %u",
			 proto, zclient->redist_default);
	if (instance != zclient->instance)
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "Wrong instId (%u) in get chunk response Should be %u",
			 instance, zclient->instance);

	/* if we requested a specific chunk and it could not be allocated, the
	 * response message will end here
	 */
	if (!STREAM_READABLE(s)) {
		zlog_info("Unable to assign Label Chunk to %s instance %u",
			  zebra_route_string(proto), instance);
		return -1;
	}

	/* keep */
	STREAM_GETC(s, response_keep);
	/* start and end labels */
	STREAM_GETL(s, *start);
	STREAM_GETL(s, *end);

	/* not owning this response */
	if (keep != response_keep) {
		flog_err(
			EC_LIB_ZAPI_ENCODE,
			"Invalid Label chunk: %u - %u, keeps mismatch %u != %u",
			*start, *end, keep, response_keep);
	}
	/* sanity */
	if (*start > *end || *start < MPLS_LABEL_UNRESERVED_MIN
	    || *end > MPLS_LABEL_UNRESERVED_MAX) {
		flog_err(EC_LIB_ZAPI_ENCODE, "Invalid Label chunk: %u - %u",
			 *start, *end);
		return -1;
	}

	if (zclient_debug)
		zlog_debug("Label Chunk assign: %u - %u (%u)", *start, *end,
			   response_keep);

	return 0;

stream_failure:
	return -1;
}

/**
 * Function to release a label chunk
 *
 * @param zclient Zclient used to connect to label manager (zebra)
 * @param start First label of chunk
 * @param end Last label of chunk
 * @result 0 on success, -1 otherwise
 */
int lm_release_label_chunk(struct zclient *zclient, uint32_t start,
			   uint32_t end)
{
	int ret;
	struct stream *s;

	if (zclient_debug)
		zlog_debug("Releasing Label Chunk %u - %u", start, end);

	if (zclient->sock < 0)
		return -1;

	/* send request */
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_RELEASE_LABEL_CHUNK, VRF_DEFAULT);

	/* proto */
	stream_putc(s, zclient->redist_default);
	/* instance */
	stream_putw(s, zclient->instance);
	/* start */
	stream_putl(s, start);
	/* end */
	stream_putl(s, end);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	ret = writen(zclient->sock, s->data, stream_get_endp(s));
	if (ret < 0) {
		flog_err(EC_LIB_ZAPI_SOCKET, "Can't write to zclient sock");
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}
	if (ret == 0) {
		flog_err(EC_LIB_ZAPI_SOCKET, "Zclient sock connection closed");
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}

	return 0;
}

/**
 * Connect to table manager in a synchronous way
 *
 * It first writes the request to zclient output buffer and then
 * immediately reads the answer from the input buffer.
 *
 * @param zclient Zclient used to connect to table manager (zebra)
 * @result Result of response
 */
int tm_table_manager_connect(struct zclient *zclient)
{
	int ret;
	struct stream *s;
	uint8_t result;

	if (zclient_debug)
		zlog_debug("Connecting to Table Manager");

	if (zclient->sock < 0)
		return ZCLIENT_SEND_FAILURE;

	/* send request */
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_TABLE_MANAGER_CONNECT, VRF_DEFAULT);

	/* proto */
	stream_putc(s, zclient->redist_default);
	/* instance */
	stream_putw(s, zclient->instance);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	ret = zclient_send_message(zclient);
	if (ret == ZCLIENT_SEND_FAILURE)
		return -1;

	if (zclient_debug)
		zlog_debug("%s: Table manager connect request sent", __func__);

	/* read response */
	if (zclient_read_sync_response(zclient, ZEBRA_TABLE_MANAGER_CONNECT)
	    != 0)
		return -1;

	/* result */
	s = zclient->ibuf;
	STREAM_GETC(s, result);
	if (zclient_debug)
		zlog_debug(
			"%s: Table Manager connect response received, result %u",
			__func__, result);

	return (int)result;
stream_failure:
	return -1;
}

/**
 * Function to request a table chunk in a synchronous way
 *
 * It first writes the request to zclient output buffer and then
 * immediately reads the answer from the input buffer.
 *
 * @param zclient Zclient used to connect to table manager (zebra)
 * @param chunk_size Amount of table requested
 * @param start to write first assigned chunk table RT ID to
 * @param end To write last assigned chunk table RT ID to
 * @result 0 on success, -1 otherwise
 */
int tm_get_table_chunk(struct zclient *zclient, uint32_t chunk_size,
		       uint32_t *start, uint32_t *end)
{
	int ret;
	struct stream *s;

	if (zclient_debug)
		zlog_debug("Getting Table Chunk");

	if (zclient->sock < 0)
		return -1;

	/* send request */
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_GET_TABLE_CHUNK, VRF_DEFAULT);
	/* chunk size */
	stream_putl(s, chunk_size);
	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	ret = writen(zclient->sock, s->data, stream_get_endp(s));
	if (ret < 0) {
		flog_err(EC_LIB_ZAPI_SOCKET, "%s: can't write to zclient->sock",
			 __func__);
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}
	if (ret == 0) {
		flog_err(EC_LIB_ZAPI_SOCKET,
			 "%s: zclient->sock connection closed", __func__);
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}
	if (zclient_debug)
		zlog_debug("%s: Table chunk request (%d bytes) sent", __func__,
			   ret);

	/* read response */
	if (zclient_read_sync_response(zclient, ZEBRA_GET_TABLE_CHUNK) != 0)
		return -1;

	s = zclient->ibuf;
	/* start and end table IDs */
	STREAM_GETL(s, *start);
	STREAM_GETL(s, *end);

	if (zclient_debug)
		zlog_debug("Table Chunk assign: %u - %u ", *start, *end);

	return 0;
stream_failure:
	return -1;
}

/**
 * Function to release a table chunk
 *
 * @param zclient Zclient used to connect to table manager (zebra)
 * @param start First label of table
 * @param end Last label of chunk
 * @result 0 on success, -1 otherwise
 */
int tm_release_table_chunk(struct zclient *zclient, uint32_t start,
			   uint32_t end)
{
	struct stream *s;

	if (zclient_debug)
		zlog_debug("Releasing Table Chunk");

	if (zclient->sock < 0)
		return -1;

	/* send request */
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_RELEASE_TABLE_CHUNK, VRF_DEFAULT);

	/* start */
	stream_putl(s, start);
	/* end */
	stream_putl(s, end);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (zclient_send_message(zclient) == ZCLIENT_SEND_FAILURE)
		return -1;

	return 0;
}

enum zclient_send_status zebra_send_sr_policy(struct zclient *zclient, int cmd,
					      struct zapi_sr_policy *zp)
{
	if (zapi_sr_policy_encode(zclient->obuf, cmd, zp) < 0)
		return ZCLIENT_SEND_FAILURE;
	return zclient_send_message(zclient);
}

int zapi_sr_policy_encode(struct stream *s, int cmd, struct zapi_sr_policy *zp)
{
	struct zapi_srte_tunnel *zt = &zp->segment_list;

	stream_reset(s);

	zclient_create_header(s, cmd, VRF_DEFAULT);
	stream_putl(s, zp->color);
	stream_put_ipaddr(s, &zp->endpoint);
	stream_write(s, &zp->name, SRTE_POLICY_NAME_MAX_LENGTH);

	stream_putc(s, zt->type);
	stream_putl(s, zt->local_label);

	if (zt->label_num > MPLS_MAX_LABELS) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: label %u: can't encode %u labels (maximum is %u)",
			 __func__, zt->local_label, zt->label_num,
			 MPLS_MAX_LABELS);
		return -1;
	}
	stream_putw(s, zt->label_num);

	for (int i = 0; i < zt->label_num; i++)
		stream_putl(s, zt->labels[i]);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return 0;
}

int zapi_sr_policy_decode(struct stream *s, struct zapi_sr_policy *zp)
{
	memset(zp, 0, sizeof(*zp));

	struct zapi_srte_tunnel *zt = &zp->segment_list;

	STREAM_GETL(s, zp->color);
	STREAM_GET_IPADDR(s, &zp->endpoint);
	STREAM_GET(&zp->name, s, SRTE_POLICY_NAME_MAX_LENGTH);

	/* segment list of active candidate path */
	STREAM_GETC(s, zt->type);
	STREAM_GETL(s, zt->local_label);
	STREAM_GETW(s, zt->label_num);
	if (zt->label_num > MPLS_MAX_LABELS) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: label %u: can't decode %u labels (maximum is %u)",
			 __func__, zt->local_label, zt->label_num,
			 MPLS_MAX_LABELS);
		return -1;
	}
	for (int i = 0; i < zt->label_num; i++)
		STREAM_GETL(s, zt->labels[i]);

	return 0;

stream_failure:
	return -1;
}

int zapi_sr_policy_notify_status_decode(struct stream *s,
					struct zapi_sr_policy *zp)
{
	memset(zp, 0, sizeof(*zp));

	STREAM_GETL(s, zp->color);
	STREAM_GET_IPADDR(s, &zp->endpoint);
	STREAM_GET(&zp->name, s, SRTE_POLICY_NAME_MAX_LENGTH);
	STREAM_GETL(s, zp->status);

	return 0;

stream_failure:
	return -1;
}

enum zclient_send_status zebra_send_mpls_labels(struct zclient *zclient,
						int cmd, struct zapi_labels *zl)
{
	if (zapi_labels_encode(zclient->obuf, cmd, zl) < 0)
		return ZCLIENT_SEND_FAILURE;
	return zclient_send_message(zclient);
}

int zapi_labels_encode(struct stream *s, int cmd, struct zapi_labels *zl)
{
	struct zapi_nexthop *znh;

	stream_reset(s);

	zclient_create_header(s, cmd, VRF_DEFAULT);
	stream_putc(s, zl->message);
	stream_putc(s, zl->type);
	stream_putl(s, zl->local_label);

	if (CHECK_FLAG(zl->message, ZAPI_LABELS_FTN)) {
		stream_putw(s, zl->route.prefix.family);
		stream_put_prefix(s, &zl->route.prefix);
		stream_putc(s, zl->route.type);
		stream_putw(s, zl->route.instance);
	}

	if (zl->nexthop_num > MULTIPATH_NUM) {
		flog_err(
			EC_LIB_ZAPI_ENCODE,
			"%s: label %u: can't encode %u nexthops (maximum is %u)",
			__func__, zl->local_label, zl->nexthop_num,
			MULTIPATH_NUM);
		return -1;
	}
	stream_putw(s, zl->nexthop_num);

	for (int i = 0; i < zl->nexthop_num; i++) {
		znh = &zl->nexthops[i];

		if (zapi_nexthop_encode(s, znh, 0, 0) < 0)
			return -1;
	}

	if (CHECK_FLAG(zl->message, ZAPI_LABELS_HAS_BACKUPS)) {

		if (zl->backup_nexthop_num > MULTIPATH_NUM) {
			flog_err(
				EC_LIB_ZAPI_ENCODE,
				"%s: label %u: can't encode %u nexthops (maximum is %u)",
				__func__, zl->local_label, zl->nexthop_num,
				MULTIPATH_NUM);
			return -1;
		}
		stream_putw(s, zl->backup_nexthop_num);

		for (int i = 0; i < zl->backup_nexthop_num; i++) {
			znh = &zl->backup_nexthops[i];

			if (zapi_nexthop_encode(s, znh, 0, 0) < 0)
				return -1;
		}

	}

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return 0;
}

int zapi_labels_decode(struct stream *s, struct zapi_labels *zl)
{
	struct zapi_nexthop *znh;

	memset(zl, 0, sizeof(*zl));

	/* Get data. */
	STREAM_GETC(s, zl->message);
	STREAM_GETC(s, zl->type);
	STREAM_GETL(s, zl->local_label);

	if (CHECK_FLAG(zl->message, ZAPI_LABELS_FTN)) {
		size_t psize;

		STREAM_GETW(s, zl->route.prefix.family);
		STREAM_GETC(s, zl->route.prefix.prefixlen);

		psize = PSIZE(zl->route.prefix.prefixlen);
		switch (zl->route.prefix.family) {
		case AF_INET:
			if (zl->route.prefix.prefixlen > IPV4_MAX_BITLEN) {
				zlog_debug(
					"%s: Specified prefix length %d is greater than a v4 address can support",
					__func__, zl->route.prefix.prefixlen);
				return -1;
			}
			STREAM_GET(&zl->route.prefix.u.prefix4.s_addr, s,
				   psize);
			break;
		case AF_INET6:
			if (zl->route.prefix.prefixlen > IPV6_MAX_BITLEN) {
				zlog_debug(
					"%s: Specified prefix length %d is greater than a v6 address can support",
					__func__, zl->route.prefix.prefixlen);
				return -1;
			}
			STREAM_GET(&zl->route.prefix.u.prefix6, s, psize);
			break;
		default:
			flog_err(EC_LIB_ZAPI_ENCODE,
				 "%s: Specified family %u is not v4 or v6",
				 __func__, zl->route.prefix.family);
			return -1;
		}

		STREAM_GETC(s, zl->route.type);
		STREAM_GETW(s, zl->route.instance);
	}

	STREAM_GETW(s, zl->nexthop_num);

	if (zl->nexthop_num > MULTIPATH_NUM) {
		flog_warn(
			EC_LIB_ZAPI_ENCODE,
			"%s: Prefix %pFX has %d nexthops, but we can only use the first %d",
			__func__, &zl->route.prefix, zl->nexthop_num,
			MULTIPATH_NUM);
	}

	zl->nexthop_num = MIN(MULTIPATH_NUM, zl->nexthop_num);

	for (int i = 0; i < zl->nexthop_num; i++) {
		znh = &zl->nexthops[i];

		if (zapi_nexthop_decode(s, znh, 0, 0) < 0)
			return -1;

		if (znh->type == NEXTHOP_TYPE_BLACKHOLE) {
			flog_warn(
				EC_LIB_ZAPI_ENCODE,
				"%s: Prefix %pFX has a blackhole nexthop which we cannot use for a label",
				__func__, &zl->route.prefix);
			return -1;
		}
	}

	if (CHECK_FLAG(zl->message, ZAPI_LABELS_HAS_BACKUPS)) {
		STREAM_GETW(s, zl->backup_nexthop_num);

		if (zl->backup_nexthop_num > MULTIPATH_NUM) {
			flog_warn(
				EC_LIB_ZAPI_ENCODE,
				"%s: Prefix %pFX has %d backup nexthops, but we can only use the first %d",
				__func__, &zl->route.prefix,
				zl->backup_nexthop_num,	MULTIPATH_NUM);
		}

		zl->backup_nexthop_num = MIN(MULTIPATH_NUM,
					     zl->backup_nexthop_num);

		for (int i = 0; i < zl->backup_nexthop_num; i++) {
			znh = &zl->backup_nexthops[i];

			if (zapi_nexthop_decode(s, znh, 0, 0) < 0)
				return -1;

			if (znh->type == NEXTHOP_TYPE_BLACKHOLE) {
				flog_warn(
					EC_LIB_ZAPI_ENCODE,
					"%s: Prefix %pFX has a backup blackhole nexthop which we cannot use for a label",
					__func__, &zl->route.prefix);
				return -1;
			}
		}
	}

	return 0;
stream_failure:
	return -1;
}

enum zclient_send_status zebra_send_pw(struct zclient *zclient, int command,
				       struct zapi_pw *pw)
{
	struct stream *s;

	/* Reset stream. */
	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, command, VRF_DEFAULT);
	stream_write(s, pw->ifname, IFNAMSIZ);
	stream_putl(s, pw->ifindex);

	/* Put type */
	stream_putl(s, pw->type);

	/* Put nexthop */
	stream_putl(s, pw->af);
	switch (pw->af) {
	case AF_INET:
		stream_put_in_addr(s, &pw->nexthop.ipv4);
		break;
	case AF_INET6:
		stream_write(s, (uint8_t *)&pw->nexthop.ipv6, 16);
		break;
	default:
		flog_err(EC_LIB_ZAPI_ENCODE, "%s: unknown af", __func__);
		return ZCLIENT_SEND_FAILURE;
	}

	/* Put labels */
	stream_putl(s, pw->local_label);
	stream_putl(s, pw->remote_label);

	/* Put flags */
	stream_putc(s, pw->flags);

	/* Protocol specific fields */
	stream_write(s, &pw->data, sizeof(union pw_protocol_fields));

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/*
 * Receive PW status update from Zebra and send it to LDE process.
 */
int zebra_read_pw_status_update(ZAPI_CALLBACK_ARGS, struct zapi_pw_status *pw)
{
	struct stream *s;

	memset(pw, 0, sizeof(struct zapi_pw_status));
	s = zclient->ibuf;

	/* Get data. */
	stream_get(pw->ifname, s, IFNAMSIZ);
	STREAM_GETL(s, pw->ifindex);
	STREAM_GETL(s, pw->status);

	return 0;
stream_failure:
	return -1;
}

static int zclient_capability_decode(ZAPI_CALLBACK_ARGS)
{
	struct zclient_capabilities cap;
	struct stream *s = zclient->ibuf;
	int vrf_backend;
	uint8_t mpls_enabled;

	STREAM_GETL(s, vrf_backend);

	if (vrf_backend < 0 || vrf_configure_backend(vrf_backend)) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: Garbage VRF backend type: %d", __func__,
			 vrf_backend);
		goto stream_failure;
	}


	memset(&cap, 0, sizeof(cap));
	STREAM_GETC(s, mpls_enabled);
	cap.mpls_enabled = !!mpls_enabled;
	STREAM_GETL(s, cap.ecmp);
	STREAM_GETC(s, cap.role);
	STREAM_GETC(s, cap.v6_with_v4_nexthop);

	if (zclient->zebra_capabilities)
		(*zclient->zebra_capabilities)(&cap);

stream_failure:
	return 0;
}

enum zclient_send_status zclient_send_mlag_register(struct zclient *client,
						    uint32_t bit_map)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_MLAG_CLIENT_REGISTER, VRF_DEFAULT);
	stream_putl(s, bit_map);

	stream_putw_at(s, 0, stream_get_endp(s));
	return zclient_send_message(client);
}

enum zclient_send_status zclient_send_mlag_deregister(struct zclient *client)
{
	return zebra_message_send(client, ZEBRA_MLAG_CLIENT_UNREGISTER,
				  VRF_DEFAULT);
}

enum zclient_send_status zclient_send_mlag_data(struct zclient *client,
						struct stream *client_s)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_MLAG_FORWARD_MSG, VRF_DEFAULT);
	stream_put(s, client_s->data, client_s->endp);

	stream_putw_at(s, 0, stream_get_endp(s));
	return zclient_send_message(client);
}

/*
 * Init/header setup for opaque zapi messages
 */
enum zclient_send_status zapi_opaque_init(struct zclient *zclient,
					  uint32_t type, uint16_t flags)
{
	struct stream *s;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_OPAQUE_MESSAGE, VRF_DEFAULT);

	/* Send sub-type and flags */
	stream_putl(s, type);
	stream_putw(s, flags);

	/* Source daemon identifiers */
	stream_putc(s, zclient->redist_default);
	stream_putw(s, zclient->instance);
	stream_putl(s, zclient->session_id);

	return ZCLIENT_SEND_SUCCESS;
}

/*
 * Init, header setup for opaque unicast messages.
 */
enum zclient_send_status
zapi_opaque_unicast_init(struct zclient *zclient, uint32_t type, uint16_t flags,
			 uint8_t proto, uint16_t instance, uint32_t session_id)
{
	struct stream *s;

	s = zclient->obuf;

	/* Common init */
	zapi_opaque_init(zclient, type, flags | ZAPI_OPAQUE_FLAG_UNICAST);

	/* Send destination client info */
	stream_putc(s, proto);
	stream_putw(s, instance);
	stream_putl(s, session_id);

	return ZCLIENT_SEND_SUCCESS;
}

/*
 * Send an OPAQUE message, contents opaque to zebra. The message header
 * is a message subtype.
 */
enum zclient_send_status zclient_send_opaque(struct zclient *zclient,
					     uint32_t type, const uint8_t *data,
					     size_t datasize)
{
	struct stream *s;
	uint16_t flags = 0;

	/* Check buffer size */
	if (STREAM_SIZE(zclient->obuf) <
	    (ZEBRA_HEADER_SIZE + sizeof(type) + datasize))
		return ZCLIENT_SEND_FAILURE;

	s = zclient->obuf;

	zapi_opaque_init(zclient, type, flags);

	/* Send opaque data */
	if (datasize > 0)
		stream_write(s, data, datasize);

	/* Put length into the header at the start of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/*
 * Send an OPAQUE message to a specific zclient. The contents are opaque
 * to zebra.
 */
enum zclient_send_status
zclient_send_opaque_unicast(struct zclient *zclient, uint32_t type,
			    uint8_t proto, uint16_t instance,
			    uint32_t session_id, const uint8_t *data,
			    size_t datasize)
{
	struct stream *s;
	uint16_t flags = 0;

	/* Check buffer size */
	if (STREAM_SIZE(zclient->obuf) <
	    (ZEBRA_HEADER_SIZE + sizeof(struct zapi_opaque_msg) + datasize))
		return ZCLIENT_SEND_FAILURE;

	s = zclient->obuf;

	/* Common init */
	zapi_opaque_unicast_init(zclient, type, flags, proto, instance,
				 session_id);

	/* Send opaque data */
	if (datasize > 0)
		stream_write(s, data, datasize);

	/* Put length into the header at the start of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/*
 * Decode incoming opaque message into info struct
 */
int zclient_opaque_decode(struct stream *s, struct zapi_opaque_msg *info)
{
	memset(info, 0, sizeof(*info));

	/* Decode subtype and flags */
	STREAM_GETL(s, info->type);
	STREAM_GETW(s, info->flags);

	/* Decode sending daemon info */
	STREAM_GETC(s, info->src_proto);
	STREAM_GETW(s, info->src_instance);
	STREAM_GETL(s, info->src_session_id);

	/* Decode unicast destination info, if present */
	if (CHECK_FLAG(info->flags, ZAPI_OPAQUE_FLAG_UNICAST)) {
		STREAM_GETC(s, info->dest_proto);
		STREAM_GETW(s, info->dest_instance);
		STREAM_GETL(s, info->dest_session_id);
	}

	info->len = STREAM_READABLE(s);

	return 0;

stream_failure:

	return -1;
}

/*
 * Send a registration request for opaque messages with a specified subtype.
 */
enum zclient_send_status zclient_register_opaque(struct zclient *zclient,
						 uint32_t type)
{
	struct stream *s;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_OPAQUE_REGISTER, VRF_DEFAULT);

	/* Send sub-type */
	stream_putl(s, type);

	/* Add zclient info */
	stream_putc(s, zclient->redist_default);
	stream_putw(s, zclient->instance);
	stream_putl(s, zclient->session_id);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/*
 * Send an un-registration request for a specified opaque subtype.
 */
enum zclient_send_status zclient_unregister_opaque(struct zclient *zclient,
						   uint32_t type)
{
	struct stream *s;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_OPAQUE_UNREGISTER, VRF_DEFAULT);

	/* Send sub-type */
	stream_putl(s, type);

	/* Add zclient info */
	stream_putc(s, zclient->redist_default);
	stream_putw(s, zclient->instance);
	stream_putl(s, zclient->session_id);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/* Utility to decode opaque registration info */
int zapi_opaque_reg_decode(struct stream *s, struct zapi_opaque_reg_info *info)
{
	STREAM_GETL(s, info->type);
	STREAM_GETC(s, info->proto);
	STREAM_GETW(s, info->instance);
	STREAM_GETL(s, info->session_id);

	return 0;

stream_failure:

	return -1;
}

/* Utility to decode client close notify info */
int zapi_client_close_notify_decode(struct stream *s,
				    struct zapi_client_close_info *info)
{
	memset(info, 0, sizeof(*info));

	STREAM_GETC(s, info->proto);
	STREAM_GETW(s, info->instance);
	STREAM_GETL(s, info->session_id);

	return 0;

stream_failure:

	return -1;
}

static int zclient_nexthop_update(ZAPI_CALLBACK_ARGS)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct prefix match;
	struct zapi_route route;

	if (!vrf) {
		zlog_warn("nexthop update for unknown VRF ID %u", vrf_id);
		return 0;
	}

	if (!zapi_nexthop_update_decode(zclient->ibuf, &match, &route)) {
		zlog_err("failed to decode nexthop update");
		return -1;
	}

	if (zclient->nexthop_update)
		zclient->nexthop_update(vrf, &match, &route);

	return 0;
}

static zclient_handler *const lib_handlers[] = {
	/* fundamentals */
	[ZEBRA_CAPABILITIES] = zclient_capability_decode,
	[ZEBRA_ERROR] = zclient_handle_error,

	/* VRF & interface code is shared in lib */
	[ZEBRA_VRF_ADD] = zclient_vrf_add,
	[ZEBRA_VRF_DELETE] = zclient_vrf_delete,
	[ZEBRA_INTERFACE_ADD] = zclient_interface_add,
	[ZEBRA_INTERFACE_DELETE] = zclient_interface_delete,
	[ZEBRA_INTERFACE_UP] = zclient_interface_up,
	[ZEBRA_INTERFACE_DOWN] = zclient_interface_down,

	/* NHT pre-decode */
	[ZEBRA_NEXTHOP_UPDATE] = zclient_nexthop_update,

	/* BFD */
	[ZEBRA_BFD_DEST_REPLAY] = zclient_bfd_session_replay,
	[ZEBRA_INTERFACE_BFD_DEST_UPDATE] = zclient_bfd_session_update,
};

/* Zebra client message read function. */
static void zclient_read(struct event *thread)
{
	size_t already;
	uint16_t length, command;
	uint8_t marker, version;
	vrf_id_t vrf_id;
	struct zclient *zclient;

	/* Get socket to zebra. */
	zclient = EVENT_ARG(thread);
	zclient->t_read = NULL;

	/* Read zebra header (if we don't have it already). */
	already = stream_get_endp(zclient->ibuf);
	if (already < ZEBRA_HEADER_SIZE) {
		ssize_t nbyte;
		if (((nbyte = stream_read_try(zclient->ibuf, zclient->sock,
					      ZEBRA_HEADER_SIZE - already))
		     == 0)
		    || (nbyte == -1)) {
			if (zclient_debug)
				zlog_debug(
					"zclient connection closed socket [%d].",
					zclient->sock);
			zclient_failed(zclient);
			return;
		}
		if (nbyte != (ssize_t)(ZEBRA_HEADER_SIZE - already)) {
			zclient_event(ZCLIENT_READ, zclient);
			return;
		}
		already = ZEBRA_HEADER_SIZE;
	}

	/* Reset to read from the beginning of the incoming packet. */
	stream_set_getp(zclient->ibuf, 0);

	/* Fetch header values. */
	length = stream_getw(zclient->ibuf);
	marker = stream_getc(zclient->ibuf);
	version = stream_getc(zclient->ibuf);
	vrf_id = stream_getl(zclient->ibuf);
	command = stream_getw(zclient->ibuf);

	if (marker != ZEBRA_HEADER_MARKER || version != ZSERV_VERSION) {
		flog_err(
			EC_LIB_ZAPI_MISSMATCH,
			"%s: socket %d version mismatch, marker %d, version %d",
			__func__, zclient->sock, marker, version);
		zclient_failed(zclient);
		return;
	}

	if (length < ZEBRA_HEADER_SIZE) {
		flog_err(EC_LIB_ZAPI_MISSMATCH,
			 "%s: socket %d message length %u is less than %d ",
			 __func__, zclient->sock, length, ZEBRA_HEADER_SIZE);
		zclient_failed(zclient);
		return;
	}

	/* Length check. */
	if (length > STREAM_SIZE(zclient->ibuf)) {
		struct stream *ns;
		flog_err(
			EC_LIB_ZAPI_ENCODE,
			"%s: message size %u exceeds buffer size %lu, expanding...",
			__func__, length,
			(unsigned long)STREAM_SIZE(zclient->ibuf));
		ns = stream_new(length);
		stream_copy(ns, zclient->ibuf);
		stream_free(zclient->ibuf);
		zclient->ibuf = ns;
	}

	/* Read rest of zebra packet. */
	if (already < length) {
		ssize_t nbyte;
		if (((nbyte = stream_read_try(zclient->ibuf, zclient->sock,
					      length - already))
		     == 0)
		    || (nbyte == -1)) {
			if (zclient_debug)
				zlog_debug(
					"zclient connection closed socket [%d].",
					zclient->sock);
			zclient_failed(zclient);
			return;
		}
		if (nbyte != (ssize_t)(length - already)) {
			/* Try again later. */
			zclient_event(ZCLIENT_READ, zclient);
			return;
		}
	}

	length -= ZEBRA_HEADER_SIZE;

	if (zclient_debug)
		zlog_debug("zclient %p command %s VRF %u", zclient,
			   zserv_command_string(command), vrf_id);

	if (!zclient->auxiliary && command < array_size(lib_handlers) &&
	    lib_handlers[command])
		lib_handlers[command](command, zclient, length, vrf_id);
	if (command < zclient->n_handlers && zclient->handlers[command])
		zclient->handlers[command](command, zclient, length, vrf_id);

	if (zclient->sock < 0)
		/* Connection was closed during packet processing. */
		return;

	/* Register read thread. */
	stream_reset(zclient->ibuf);
	zclient_event(ZCLIENT_READ, zclient);
}

void zclient_redistribute(int command, struct zclient *zclient, afi_t afi,
			  int type, unsigned short instance, vrf_id_t vrf_id)
{

	if (instance) {
		if (command == ZEBRA_REDISTRIBUTE_ADD) {
			if (redist_check_instance(
				    &zclient->mi_redist[afi][type], instance))
				return;
			redist_add_instance(&zclient->mi_redist[afi][type],
					    instance);
		} else {
			if (!redist_check_instance(
				    &zclient->mi_redist[afi][type], instance))
				return;
			redist_del_instance(&zclient->mi_redist[afi][type],
					    instance);
		}

	} else {
		if (command == ZEBRA_REDISTRIBUTE_ADD) {
			if (vrf_bitmap_check(&zclient->redist[afi][type],
					     vrf_id))
				return;
			vrf_bitmap_set(&zclient->redist[afi][type], vrf_id);
		} else {
			if (!vrf_bitmap_check(&zclient->redist[afi][type],
					      vrf_id))
				return;
			vrf_bitmap_unset(&zclient->redist[afi][type], vrf_id);
		}
	}

	if (zclient->sock > 0)
		zebra_redistribute_send(command, zclient, afi, type, instance,
					vrf_id);
}


void zclient_redistribute_default(int command, struct zclient *zclient,
				  afi_t afi, vrf_id_t vrf_id)
{

	if (command == ZEBRA_REDISTRIBUTE_DEFAULT_ADD) {
		if (vrf_bitmap_check(&zclient->default_information[afi],
				     vrf_id))
			return;
		vrf_bitmap_set(&zclient->default_information[afi], vrf_id);
	} else {
		if (!vrf_bitmap_check(&zclient->default_information[afi],
				      vrf_id))
			return;
		vrf_bitmap_unset(&zclient->default_information[afi], vrf_id);
	}

	if (zclient->sock > 0)
		zebra_redistribute_default_send(command, zclient, afi, vrf_id);
}

static void zclient_event(enum zclient_event event, struct zclient *zclient)
{
	switch (event) {
	case ZCLIENT_SCHEDULE:
		event_add_event(zclient->master, zclient_connect, zclient, 0,
				&zclient->t_connect);
		break;
	case ZCLIENT_CONNECT:
		if (zclient_debug)
			zlog_debug(
				"zclient connect failures: %d schedule interval is now %d",
				zclient->fail, zclient->fail < 3 ? 10 : 60);
		event_add_timer(zclient->master, zclient_connect, zclient,
				zclient->fail < 3 ? 10 : 60,
				&zclient->t_connect);
		break;
	case ZCLIENT_READ:
		zclient->t_read = NULL;
		event_add_read(zclient->master, zclient_read, zclient,
			       zclient->sock, &zclient->t_read);
		break;
	}
}

enum zclient_send_status zclient_interface_set_arp(struct zclient *client,
						   struct interface *ifp,
						   bool arp_enable)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_INTERFACE_SET_ARP, ifp->vrf->vrf_id);

	stream_putl(s, ifp->ifindex);
	stream_putc(s, arp_enable);

	stream_putw_at(s, 0, stream_get_endp(s));
	return zclient_send_message(client);
}

enum zclient_send_status zclient_interface_set_master(struct zclient *client,
						      struct interface *master,
						      struct interface *slave)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_INTERFACE_SET_MASTER,
			      master->vrf->vrf_id);

	stream_putl(s, master->vrf->vrf_id);
	stream_putl(s, master->ifindex);
	stream_putl(s, slave->vrf->vrf_id);
	stream_putl(s, slave->ifindex);

	stream_putw_at(s, 0, stream_get_endp(s));
	return zclient_send_message(client);
}

/*
 * Send capabilities message to zebra
 */
enum zclient_send_status zclient_capabilities_send(uint32_t cmd,
						   struct zclient *zclient,
						   struct zapi_cap *api)
{

	struct stream *s;

	if (zclient == NULL)
		return ZCLIENT_SEND_FAILURE;

	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, cmd, 0);
	stream_putl(s, api->cap);

	switch (api->cap) {
	case ZEBRA_CLIENT_GR_CAPABILITIES:
	case ZEBRA_CLIENT_RIB_STALE_TIME:
		stream_putl(s, api->stale_removal_time);
		stream_putl(s, api->vrf_id);
		break;
	case ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE:
	case ZEBRA_CLIENT_ROUTE_UPDATE_PENDING:
		stream_putl(s, api->afi);
		stream_putl(s, api->safi);
		stream_putl(s, api->vrf_id);
		break;
	case ZEBRA_CLIENT_GR_DISABLE:
		stream_putl(s, api->vrf_id);
		break;
	}

	/* Put length at the first point of the stream */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/*
 * Process capabilities message from zebra
 */
int32_t zapi_capabilities_decode(struct stream *s, struct zapi_cap *api)
{

	memset(api, 0, sizeof(*api));

	api->safi = SAFI_UNICAST;

	STREAM_GETL(s, api->cap);
	switch (api->cap) {
	case ZEBRA_CLIENT_GR_CAPABILITIES:
	case ZEBRA_CLIENT_RIB_STALE_TIME:
		STREAM_GETL(s, api->stale_removal_time);
		STREAM_GETL(s, api->vrf_id);
		break;
	case ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE:
	case ZEBRA_CLIENT_ROUTE_UPDATE_PENDING:
		STREAM_GETL(s, api->afi);
		STREAM_GETL(s, api->safi);
		STREAM_GETL(s, api->vrf_id);
		break;
	case ZEBRA_CLIENT_GR_DISABLE:
		STREAM_GETL(s, api->vrf_id);
		break;
	}
stream_failure:
	return 0;
}

enum zclient_send_status
zclient_send_neigh_discovery_req(struct zclient *zclient,
				 const struct interface *ifp,
				 const struct prefix *p)
{
	struct stream *s;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_NEIGH_DISCOVER, ifp->vrf->vrf_id);
	stream_putl(s, ifp->ifindex);

	stream_putc(s, p->family);
	stream_putc(s, p->prefixlen);
	stream_put(s, &p->u.prefix, prefix_blen(p));

	stream_putw_at(s, 0, stream_get_endp(s));
	return zclient_send_message(zclient);
}

/*
 * Get a starting nhg point for a routing protocol
 */
uint32_t zclient_get_nhg_start(uint32_t proto)
{
	assert(proto < ZEBRA_ROUTE_MAX);

	return ZEBRA_NHG_PROTO_SPACING * proto;
}

char *zclient_dump_route_flags(uint32_t flags, char *buf, size_t len)
{
	if (flags == 0) {
		snprintfrr(buf, len, "None ");
		return buf;
	}

	snprintfrr(buf, len, "%s%s%s%s%s%s%s%s%s%s%s",
		   CHECK_FLAG(flags, ZEBRA_FLAG_ALLOW_RECURSION) ? "Recursion "
								 : "",

		   CHECK_FLAG(flags, ZEBRA_FLAG_SELFROUTE) ? "Self " : "",
		   CHECK_FLAG(flags, ZEBRA_FLAG_IBGP) ? "iBGP " : "",
		   CHECK_FLAG(flags, ZEBRA_FLAG_SELECTED) ? "Selected " : "",
		   CHECK_FLAG(flags, ZEBRA_FLAG_FIB_OVERRIDE) ? "Override " : "",
		   CHECK_FLAG(flags, ZEBRA_FLAG_EVPN_ROUTE) ? "Evpn " : "",
		   CHECK_FLAG(flags, ZEBRA_FLAG_RR_USE_DISTANCE) ? "RR Distance "
								 : "",

		   CHECK_FLAG(flags, ZEBRA_FLAG_TRAPPED) ? "Trapped " : "",
		   CHECK_FLAG(flags, ZEBRA_FLAG_OFFLOADED) ? "Offloaded " : "",
		   CHECK_FLAG(flags, ZEBRA_FLAG_OFFLOAD_FAILED)
			   ? "Offload Failed "
			   : "",
		   CHECK_FLAG(flags, ZEBRA_FLAG_OUTOFSYNC) ? "OutOfSync " : "");

	return buf;
}

char *zclient_evpn_dump_macip_flags(uint8_t flags, char *buf, size_t len)
{
	if (flags == 0) {
		snprintfrr(buf, len, "None ");
		return buf;
	}

	snprintfrr(
		buf, len, "%s%s%s%s%s%s%s",
		CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY) ? "Sticky MAC " : "",
		CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW) ? "Gateway MAC " : "",
		CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG) ? "Router "
								: "",
		CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_OVERRIDE_FLAG) ? "Override "
								  : "",
		CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_SVI_IP) ? "SVI MAC " : "",
		CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_PROXY_ADVERT) ? "Proxy "
								 : "",
		CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_SYNC_PATH) ? "Sync " : "");

	return buf;
}

static int zclient_neigh_ip_read_entry(struct stream *s, struct ipaddr *add)
{
	uint8_t family;

	STREAM_GETC(s, family);
	if (family != AF_INET && family != AF_INET6)
		return -1;

	STREAM_GET(&add->ip.addr, s, family2addrsize(family));
	add->ipa_type = family;
	return 0;
 stream_failure:
	return -1;
}

int zclient_neigh_ip_encode(struct stream *s, uint16_t cmd, union sockunion *in,
			    union sockunion *out, struct interface *ifp,
			    int ndm_state, int ip_len)
{
	int ret = 0;

	zclient_create_header(s, cmd, ifp->vrf->vrf_id);
	stream_putc(s, sockunion_family(in));
	stream_write(s, sockunion_get_addr(in), sockunion_get_addrlen(in));
	if (out && sockunion_family(out) != AF_UNSPEC) {
		stream_putc(s, sockunion_family(out));
		stream_write(s, sockunion_get_addr(out),
			     sockunion_get_addrlen(out));
	} else
		stream_putc(s, AF_UNSPEC);
	stream_putl(s, ip_len);
	stream_putl(s, ifp->ifindex);
	if (out)
		stream_putl(s, ndm_state);
	else
		stream_putl(s, ZEBRA_NEIGH_STATE_FAILED);
	return ret;
}

int zclient_neigh_ip_decode(struct stream *s, struct zapi_neigh_ip *api)
{
	int ret;

	ret = zclient_neigh_ip_read_entry(s, &api->ip_in);
	if (ret < 0)
		return -1;
	zclient_neigh_ip_read_entry(s, &api->ip_out);

	STREAM_GETL(s, api->ip_len);
	STREAM_GETL(s, api->index);
	STREAM_GETL(s, api->ndm_state);
	return 0;
 stream_failure:
	return -1;
}

int zclient_send_zebra_gre_request(struct zclient *client,
				   struct interface *ifp)
{
	struct stream *s;

	if (!client || client->sock < 0) {
		zlog_err("%s : zclient not ready", __func__);
		return -1;
	}
	s = client->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_GRE_GET, ifp->vrf->vrf_id);
	stream_putl(s, ifp->ifindex);
	stream_putw_at(s, 0, stream_get_endp(s));
	zclient_send_message(client);
	return 0;
}


/*
 * Opaque notification features
 */

/*
 * Common encode helper for opaque notifications, both registration
 * and async notification messages.
 */
static int opaque_notif_encode_common(struct stream *s, uint32_t msg_type,
				      bool request, bool reg, uint8_t proto,
				      uint16_t instance, uint32_t session_id)
{
	int ret = 0;
	uint8_t val = 0;

	stream_reset(s);

	zclient_create_header(s, ZEBRA_OPAQUE_NOTIFY, VRF_DEFAULT);

	/* Notification or request */
	if (request)
		val = 1;
	stream_putc(s, val);

	if (reg)
		val = 1;
	else
		val = 0;
	stream_putc(s, val);

	stream_putl(s, msg_type);

	stream_putc(s, proto);
	stream_putw(s, instance);
	stream_putl(s, session_id);

	/* And capture message length */
	stream_putw_at(s, 0, stream_get_endp(s));

	return ret;
}

/*
 * Encode a zapi opaque message type notification into buffer 's'
 */
int zclient_opaque_notif_encode(struct stream *s, uint32_t msg_type, bool reg,
				uint8_t proto, uint16_t instance,
				uint32_t session_id)
{
	return opaque_notif_encode_common(s, msg_type, false /* !request */,
					  reg, proto, instance, session_id);
}

/*
 * Decode an incoming zapi opaque message type notification
 */
int zclient_opaque_notif_decode(struct stream *s,
				struct zapi_opaque_notif_info *info)
{
	uint8_t val;

	memset(info, 0, sizeof(*info));

	STREAM_GETC(s, val); /* Registration or notification */
	info->request = (val != 0);

	STREAM_GETC(s, val);
	info->reg = (val != 0);

	STREAM_GETL(s, info->msg_type);

	STREAM_GETC(s, info->proto);
	STREAM_GETW(s, info->instance);
	STREAM_GETL(s, info->session_id);

	return 0;

stream_failure:
	return -1;
}

/*
 * Encode and send a zapi opaque message type notification request to zebra
 */
enum zclient_send_status zclient_opaque_request_notify(struct zclient *zclient,
						       uint32_t msgtype)
{
	struct stream *s;

	if (!zclient || zclient->sock < 0)
		return ZCLIENT_SEND_FAILURE;

	s = zclient->obuf;

	opaque_notif_encode_common(s, msgtype, true /* request */,
				   true /* register */, zclient->redist_default,
				   zclient->instance, zclient->session_id);

	return zclient_send_message(zclient);
}

/*
 * Encode and send a request to drop notifications for an opaque message type.
 */
enum zclient_send_status zclient_opaque_drop_notify(struct zclient *zclient,
						    uint32_t msgtype)
{
	struct stream *s;

	if (!zclient || zclient->sock < 0)
		return ZCLIENT_SEND_FAILURE;

	s = zclient->obuf;

	opaque_notif_encode_common(s, msgtype, true /* req */,
				   false /* unreg */, zclient->redist_default,
				   zclient->instance, zclient->session_id);

	return zclient_send_message(zclient);
}

void zclient_register_neigh(struct zclient *zclient, vrf_id_t vrf_id, afi_t afi,
			    bool reg)
{
	struct stream *s;

	if (!zclient || zclient->sock < 0)
		return;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s,
			      reg ? ZEBRA_NEIGH_REGISTER
				  : ZEBRA_NEIGH_UNREGISTER,
			      vrf_id);
	stream_putw(s, afi);
	stream_putw_at(s, 0, stream_get_endp(s));
	zclient_send_message(zclient);
}
