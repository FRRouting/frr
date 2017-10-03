/* Zebra's client library.
 * Copyright (C) 1999 Kunihiro Ishiguro
 * Copyright (C) 2005 Andrew J. Schorr
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "thread.h"
#include "zclient.h"
#include "memory.h"
#include "table.h"
#include "nexthop.h"
#include "mpls.h"

DEFINE_MTYPE_STATIC(LIB, ZCLIENT, "Zclient")
DEFINE_MTYPE_STATIC(LIB, REDIST_INST, "Redistribution instance IDs")

/* Zebra client events. */
enum event { ZCLIENT_SCHEDULE, ZCLIENT_READ, ZCLIENT_CONNECT };

/* Prototype for event manager. */
static void zclient_event(enum event, struct zclient *);

struct sockaddr_storage zclient_addr;
socklen_t zclient_addr_len;

/* This file local debug flag. */
int zclient_debug = 0;

/* Allocate zclient structure. */
struct zclient *zclient_new(struct thread_master *master)
{
	struct zclient *zclient;
	zclient = XCALLOC(MTYPE_ZCLIENT, sizeof(struct zclient));

	zclient->ibuf = stream_new(ZEBRA_MAX_PACKET_SIZ);
	zclient->obuf = stream_new(ZEBRA_MAX_PACKET_SIZ);
	zclient->wb = buffer_new(0);
	zclient->master = master;

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

u_short *redist_check_instance(struct redist_proto *red, u_short instance)
{
	struct listnode *node;
	u_short *id;

	if (!red->instances)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(red->instances, node, id))
		if (*id == instance)
			return id;

	return NULL;
}

void redist_add_instance(struct redist_proto *red, u_short instance)
{
	u_short *in;

	red->enabled = 1;

	if (!red->instances)
		red->instances = list_new();

	in = XMALLOC(MTYPE_REDIST_INST, sizeof(u_short));
	*in = instance;
	listnode_add(red->instances, in);
}

void redist_del_instance(struct redist_proto *red, u_short instance)
{
	u_short *id;

	id = redist_check_instance(red, instance);
	if (!id)
		return;

	listnode_delete(red->instances, id);
	XFREE(MTYPE_REDIST_INST, id);
	if (!red->instances->count) {
		red->enabled = 0;
		list_delete_and_null(&red->instances);
	}
}

/* Stop zebra client services. */
void zclient_stop(struct zclient *zclient)
{
	afi_t afi;
	int i;

	if (zclient_debug)
		zlog_debug("zclient stopped");

	/* Stop threads. */
	THREAD_OFF(zclient->t_read);
	THREAD_OFF(zclient->t_connect);
	THREAD_OFF(zclient->t_write);

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
			vrf_bitmap_free(zclient->redist[afi][i]);
			zclient->redist[afi][i] = VRF_BITMAP_NULL;
		}
		redist_del_instance(
			&zclient->mi_redist[afi][zclient->redist_default],
			zclient->instance);
	}

	vrf_bitmap_free(zclient->default_information);
	zclient->default_information = VRF_BITMAP_NULL;
}

void zclient_reset(struct zclient *zclient)
{
	afi_t afi;

	zclient_stop(zclient);

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		redist_del_instance(
			&zclient->mi_redist[afi][zclient->redist_default],
			zclient->instance);

	zclient_init(zclient, zclient->redist_default, zclient->instance);
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

	/* Connect to zebra. */
	ret = connect(sock, (struct sockaddr *)&zclient_addr,
			zclient_addr_len);
	if (ret < 0) {
		if (zclient_debug)
			zlog_warn("%s connect failure: %d(%s)",
				  __PRETTY_FUNCTION__, errno,
				  safe_strerror(errno));
		close(sock);
		return -1;
	}

	zclient->sock = sock;
	return sock;
}

static int zclient_failed(struct zclient *zclient)
{
	zclient->fail++;
	zclient_stop(zclient);
	zclient_event(ZCLIENT_CONNECT, zclient);
	return -1;
}

static int zclient_flush_data(struct thread *thread)
{
	struct zclient *zclient = THREAD_ARG(thread);

	zclient->t_write = NULL;
	if (zclient->sock < 0)
		return -1;
	switch (buffer_flush_available(zclient->wb, zclient->sock)) {
	case BUFFER_ERROR:
		zlog_warn(
			"%s: buffer_flush_available failed on zclient fd %d, closing",
			__func__, zclient->sock);
		return zclient_failed(zclient);
		break;
	case BUFFER_PENDING:
		zclient->t_write = NULL;
		thread_add_write(zclient->master, zclient_flush_data, zclient,
				 zclient->sock, &zclient->t_write);
		break;
	case BUFFER_EMPTY:
		break;
	}
	return 0;
}

int zclient_send_message(struct zclient *zclient)
{
	if (zclient->sock < 0)
		return -1;
	switch (buffer_write(zclient->wb, zclient->sock,
			     STREAM_DATA(zclient->obuf),
			     stream_get_endp(zclient->obuf))) {
	case BUFFER_ERROR:
		zlog_warn("%s: buffer_write failed to zclient fd %d, closing",
			  __func__, zclient->sock);
		return zclient_failed(zclient);
		break;
	case BUFFER_EMPTY:
		THREAD_OFF(zclient->t_write);
		break;
	case BUFFER_PENDING:
		thread_add_write(zclient->master, zclient_flush_data, zclient,
				 zclient->sock, &zclient->t_write);
		break;
	}
	return 0;
}

void zclient_create_header(struct stream *s, uint16_t command, vrf_id_t vrf_id)
{
	/* length placeholder, caller can update */
	stream_putw(s, ZEBRA_HEADER_SIZE);
	stream_putc(s, ZEBRA_HEADER_MARKER);
	stream_putc(s, ZSERV_VERSION);
	stream_putw(s, vrf_id);
	stream_putw(s, command);
}

int zclient_read_header(struct stream *s, int sock, u_int16_t *size,
			u_char *marker, u_char *version, vrf_id_t *vrf_id,
			u_int16_t *cmd)
{
	if (stream_read(s, sock, ZEBRA_HEADER_SIZE) != ZEBRA_HEADER_SIZE)
		return -1;

	*size = stream_getw(s) - ZEBRA_HEADER_SIZE;
	*marker = stream_getc(s);
	*version = stream_getc(s);
	*vrf_id = stream_getw(s);
	*cmd = stream_getw(s);

	if (*version != ZSERV_VERSION || *marker != ZEBRA_HEADER_MARKER) {
		zlog_err(
			"%s: socket %d version mismatch, marker %d, version %d",
			__func__, sock, *marker, *version);
		return -1;
	}

	if (*size && stream_read(s, sock, *size) != *size)
		return -1;

	return 0;
}

/* Send simple Zebra message. */
static int zebra_message_send(struct zclient *zclient, int command,
			      vrf_id_t vrf_id)
{
	struct stream *s;

	/* Get zclient output buffer. */
	s = zclient->obuf;
	stream_reset(s);

	/* Send very simple command only Zebra message. */
	zclient_create_header(s, command, vrf_id);

	return zclient_send_message(zclient);
}

static int zebra_hello_send(struct zclient *zclient)
{
	struct stream *s;

	if (zclient->redist_default) {
		s = zclient->obuf;
		stream_reset(s);

		/* The VRF ID in the HELLO message is always 0. */
		zclient_create_header(s, ZEBRA_HELLO, VRF_DEFAULT);
		stream_putc(s, zclient->redist_default);
		stream_putw(s, zclient->instance);
		stream_putw_at(s, 0, stream_get_endp(s));
		return zclient_send_message(zclient);
	}

	return 0;
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
	zebra_message_send(zclient, ZEBRA_ROUTER_ID_ADD, vrf_id);

	/* We need interface information. */
	zebra_message_send(zclient, ZEBRA_INTERFACE_ADD, vrf_id);

	/* Set unwanted redistribute route. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		vrf_bitmap_set(zclient->redist[afi][zclient->redist_default],
			       vrf_id);

	/* Flush all redistribute request. */
	if (vrf_id == VRF_DEFAULT)
		for (afi = AFI_IP; afi < AFI_MAX; afi++)
			for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
				if (zclient->mi_redist[afi][i].enabled) {
					struct listnode *node;
					u_short *id;

					for (ALL_LIST_ELEMENTS_RO(
						     zclient->mi_redist[afi][i]
							     .instances,
						     node, id))
						if (!(i == zclient->redist_default
						      && *id == zclient->instance))
							zebra_redistribute_send(
								ZEBRA_REDISTRIBUTE_ADD,
								zclient, afi, i,
								*id,
								VRF_DEFAULT);
				}

	/* Flush all redistribute request. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			if (i != zclient->redist_default
			    && vrf_bitmap_check(zclient->redist[afi][i],
						vrf_id))
				zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD,
							zclient, afi, i, 0,
							vrf_id);

	/* If default information is needed. */
	if (vrf_bitmap_check(zclient->default_information, VRF_DEFAULT))
		zebra_message_send(zclient, ZEBRA_REDISTRIBUTE_DEFAULT_ADD,
				   vrf_id);
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
	zebra_message_send(zclient, ZEBRA_ROUTER_ID_DELETE, vrf_id);

	/* We need interface information. */
	zebra_message_send(zclient, ZEBRA_INTERFACE_DELETE, vrf_id);

	/* Set unwanted redistribute route. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		vrf_bitmap_set(zclient->redist[afi][zclient->redist_default],
			       vrf_id);

	/* Flush all redistribute request. */
	if (vrf_id == VRF_DEFAULT)
		for (afi = AFI_IP; afi < AFI_MAX; afi++)
			for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
				if (zclient->mi_redist[afi][i].enabled) {
					struct listnode *node;
					u_short *id;

					for (ALL_LIST_ELEMENTS_RO(
						     zclient->mi_redist[afi][i]
							     .instances,
						     node, id))
						if (!(i == zclient->redist_default
						      && *id == zclient->instance))
							zebra_redistribute_send(
								ZEBRA_REDISTRIBUTE_DELETE,
								zclient, afi, i,
								*id,
								VRF_DEFAULT);
				}

	/* Flush all redistribute request. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			if (i != zclient->redist_default
			    && vrf_bitmap_check(zclient->redist[afi][i],
						vrf_id))
				zebra_redistribute_send(
					ZEBRA_REDISTRIBUTE_DELETE, zclient, afi,
					i, 0, vrf_id);

	/* If default information is needed. */
	if (vrf_bitmap_check(zclient->default_information, VRF_DEFAULT))
		zebra_message_send(zclient, ZEBRA_REDISTRIBUTE_DEFAULT_DELETE,
				   vrf_id);
}

/* Send request to zebra daemon to start or stop RA. */
void zclient_send_interface_radv_req(struct zclient *zclient, vrf_id_t vrf_id,
				     struct interface *ifp, int enable,
				     int ra_interval)
{
	struct stream *s;

	/* If not connected to the zebra yet. */
	if (zclient->sock < 0)
		return;

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

	zclient_send_message(zclient);
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
		zlog_warn("%s: set_nonblocking(%d) failed", __func__,
			  zclient->sock);

	/* Clear fail count. */
	zclient->fail = 0;
	if (zclient_debug)
		zlog_debug("zclient connect success with socket [%d]",
			   zclient->sock);

	/* Create read thread. */
	zclient_event(ZCLIENT_READ, zclient);

	zebra_hello_send(zclient);

	/* Inform the successful connection. */
	if (zclient->zebra_connected)
		(*zclient->zebra_connected)(zclient);

	return 0;
}

/* Initialize zebra client.  Argument redist_default is unwanted
   redistribute route type. */
void zclient_init(struct zclient *zclient, int redist_default, u_short instance)
{
	int afi, i;

	/* Set -1 to the default socket value. */
	zclient->sock = -1;

	/* Clear redistribution flags. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			zclient->redist[afi][i] = vrf_bitmap_init();

	/* Set unwanted redistribute route.  bgpd does not need BGP route
	   redistribution. */
	zclient->redist_default = redist_default;
	zclient->instance = instance;
	/* Pending: make afi(s) an arg. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		redist_add_instance(&zclient->mi_redist[afi][redist_default],
				    instance);

	/* Set default-information redistribute to zero. */
	zclient->default_information = vrf_bitmap_init();
	;

	if (zclient_debug)
		zlog_debug("zclient_start is called");

	zclient_event(ZCLIENT_SCHEDULE, zclient);
}

/* This function is a wrapper function for calling zclient_start from
   timer or event thread. */
static int zclient_connect(struct thread *t)
{
	struct zclient *zclient;

	zclient = THREAD_ARG(t);
	zclient->t_connect = NULL;

	if (zclient_debug)
		zlog_debug("zclient_connect is called");

	return zclient_start(zclient);
}

/*
 * "xdr_encode"-like interface that allows daemon (client) to send
 * a message to zebra server for a route that needs to be
 * added/deleted to the kernel. Info about the route is specified
 * by the caller in a struct zapi_ipv4. zapi_ipv4_read() then writes
 * the info down the zclient socket using the stream_* functions.
 *
 * The corresponding read ("xdr_decode") function on the server
 * side is zread_ipv4_add()/zread_ipv4_delete().
 *
 *  0 1 2 3 4 5 6 7 8 9 A B C D E F 0 1 2 3 4 5 6 7 8 9 A B C D E F
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Length (2)         |    Command    | Route Type    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | ZEBRA Flags   | Message Flags | Prefix length |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Destination IPv4 Prefix for route                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Nexthop count |
 * +-+-+-+-+-+-+-+-+
 *
 *
 * A number of IPv4 nexthop(s) or nexthop interface index(es) are then
 * described, as per the Nexthop count. Each nexthop described as:
 *
 * +-+-+-+-+-+-+-+-+
 * | Nexthop Type  |  Set to one of ZEBRA_NEXTHOP_*
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       IPv4 Nexthop address or Interface Index number          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Alternatively, if the route is a blackhole route, then Nexthop count
 * is set to 1 and a nexthop of type NEXTHOP_TYPE_BLACKHOLE is the sole
 * nexthop.
 *
 * The original struct zapi_ipv4, zapi_ipv4_route() and zread_ipv4_*()
 * infrastructure was built around the traditional (32-bit "gate OR
 * ifindex") nexthop data unit. A special encoding can be used to feed
 * onlink (64-bit "gate AND ifindex") nexthops into zapi_ipv4_route()
 * using the same zapi_ipv4 structure. This is done by setting zapi_ipv4
 * fields as follows:
 *  - .message |= ZAPI_MESSAGE_NEXTHOP | ZAPI_MESSAGE_ONLINK
 *  - .nexthop_num == .ifindex_num
 *  - .nexthop and .ifindex are filled with gate and ifindex parts of
 *    each compound nexthop, both in the same order
 *
 * zapi_ipv4_route() will produce two nexthop data units for each such
 * interleaved 64-bit nexthop. On the zserv side of the socket it will be
 * mapped to a singlle NEXTHOP_TYPE_IPV4_IFINDEX_OL RIB nexthop structure.
 *
 * If ZAPI_MESSAGE_DISTANCE is set, the distance value is written as a 1
 * byte value.
 *
 * If ZAPI_MESSAGE_METRIC is set, the metric value is written as an 8
 * byte value.
 *
 * If ZAPI_MESSAGE_TAG is set, the tag value is written as a 4 byte value
 *
 * If ZAPI_MESSAGE_MTU is set, the mtu value is written as a 4 byte value
 *
 * XXX: No attention paid to alignment.
 */
int zapi_ipv4_route(u_char cmd, struct zclient *zclient, struct prefix_ipv4 *p,
		    struct zapi_ipv4 *api)
{
	int i;
	int psize;
	struct stream *s;

	/* Reset stream. */
	s = zclient->obuf;
	stream_reset(s);

	/* Some checks for labeled-unicast. The current expectation is that each
	 * nexthop is accompanied by a label in the case of labeled-unicast.
	 */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_LABEL)
	    && CHECK_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP)) {
		/* We expect prefixes installed with labels and the number to
		 * match
		 * the number of nexthops.
		 */
		assert(api->label_num == api->nexthop_num);
	}

	zclient_create_header(s, cmd, api->vrf_id);

	/* Put type and nexthop. */
	stream_putc(s, api->type);
	stream_putw(s, api->instance);
	stream_putl(s, api->flags);
	stream_putc(s, api->message);
	stream_putw(s, api->safi);

	/* Put prefix information. */
	psize = PSIZE(p->prefixlen);
	stream_putc(s, p->prefixlen);
	stream_write(s, (u_char *)&p->prefix, psize);

	/* Nexthop, ifindex, distance and metric information. */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP)) {
		stream_putc(s, api->nexthop_num + api->ifindex_num);

		for (i = 0; i < api->nexthop_num; i++) {
			stream_putc(s, NEXTHOP_TYPE_IPV4);
			stream_put_in_addr(s, api->nexthop[i]);
			/* For labeled-unicast, each nexthop is followed by
			 * label. */
			if (CHECK_FLAG(api->message, ZAPI_MESSAGE_LABEL))
				stream_putl(s, api->label[i]);
		}
		for (i = 0; i < api->ifindex_num; i++) {
			stream_putc(s, NEXTHOP_TYPE_IFINDEX);
			stream_putl(s, api->ifindex[i]);
		}
	}

	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_DISTANCE))
		stream_putc(s, api->distance);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_METRIC))
		stream_putl(s, api->metric);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_TAG))
		stream_putl(s, api->tag);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_MTU))
		stream_putl(s, api->mtu);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

int zapi_ipv4_route_ipv6_nexthop(u_char cmd, struct zclient *zclient,
				 struct prefix_ipv4 *p, struct zapi_ipv6 *api)
{
	int i;
	int psize;
	struct stream *s;

	/* Reset stream. */
	s = zclient->obuf;
	stream_reset(s);

	/* Some checks for labeled-unicast. The current expectation is that each
	 * nexthop is accompanied by a label in the case of labeled-unicast.
	 */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_LABEL)
	    && CHECK_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP)) {
		/* We expect prefixes installed with labels and the number to
		 * match
		 * the number of nexthops.
		 */
		assert(api->label_num == api->nexthop_num);
	}

	zclient_create_header(s, cmd, api->vrf_id);

	/* Put type and nexthop. */
	stream_putc(s, api->type);
	stream_putw(s, api->instance);
	stream_putl(s, api->flags);
	stream_putc(s, api->message);
	stream_putw(s, api->safi);

	/* Put prefix information. */
	psize = PSIZE(p->prefixlen);
	stream_putc(s, p->prefixlen);
	stream_write(s, (u_char *)&p->prefix, psize);

	/* Nexthop, ifindex, distance and metric information. */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP)) {
		stream_putc(s, api->nexthop_num + api->ifindex_num);

		for (i = 0; i < api->nexthop_num; i++) {
			stream_putc(s, NEXTHOP_TYPE_IPV6);
			stream_write(s, (u_char *)api->nexthop[i], 16);
			/* For labeled-unicast, each nexthop is followed by
			 * label. */
			if (CHECK_FLAG(api->message, ZAPI_MESSAGE_LABEL))
				stream_putl(s, api->label[i]);
		}
		for (i = 0; i < api->ifindex_num; i++) {
			stream_putc(s, NEXTHOP_TYPE_IFINDEX);
			stream_putl(s, api->ifindex[i]);
		}
	}

	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_DISTANCE))
		stream_putc(s, api->distance);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_METRIC))
		stream_putl(s, api->metric);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_TAG))
		stream_putl(s, api->tag);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_MTU))
		stream_putl(s, api->mtu);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

int zapi_ipv6_route(u_char cmd, struct zclient *zclient, struct prefix_ipv6 *p,
		    struct prefix_ipv6 *src_p, struct zapi_ipv6 *api)
{
	int i;
	int psize;
	struct stream *s;

	/* either we have !SRCPFX && src_p == NULL, or SRCPFX && src_p != NULL
	 */
	assert(!(api->message & ZAPI_MESSAGE_SRCPFX) == !src_p);

	/* Reset stream. */
	s = zclient->obuf;
	stream_reset(s);

	/* Some checks for labeled-unicast. The current expectation is that each
	 * nexthop is accompanied by a label in the case of labeled-unicast.
	 */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_LABEL)
	    && CHECK_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP)) {
		/* We expect prefixes installed with labels and the number to
		 * match
		 * the number of nexthops.
		 */
		assert(api->label_num == api->nexthop_num);
	}

	zclient_create_header(s, cmd, api->vrf_id);

	/* Put type and nexthop. */
	stream_putc(s, api->type);
	stream_putw(s, api->instance);
	stream_putl(s, api->flags);
	stream_putc(s, api->message);
	stream_putw(s, api->safi);

	/* Put prefix information. */
	psize = PSIZE(p->prefixlen);
	stream_putc(s, p->prefixlen);
	stream_write(s, (u_char *)&p->prefix, psize);

	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_SRCPFX)) {
		psize = PSIZE(src_p->prefixlen);
		stream_putc(s, src_p->prefixlen);
		stream_write(s, (u_char *)&src_p->prefix, psize);
	}

	/* Nexthop, ifindex, distance and metric information. */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP)) {
		stream_putc(s, api->nexthop_num + api->ifindex_num);

		for (i = 0; i < api->nexthop_num; i++) {
			stream_putc(s, NEXTHOP_TYPE_IPV6);
			stream_write(s, (u_char *)api->nexthop[i], 16);
			/* For labeled-unicast, each nexthop is followed by
			 * label. */
			if (CHECK_FLAG(api->message, ZAPI_MESSAGE_LABEL))
				stream_putl(s, api->label[i]);
		}
		for (i = 0; i < api->ifindex_num; i++) {
			stream_putc(s, NEXTHOP_TYPE_IFINDEX);
			stream_putl(s, api->ifindex[i]);
		}
	}

	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_DISTANCE))
		stream_putc(s, api->distance);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_METRIC))
		stream_putl(s, api->metric);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_TAG))
		stream_putl(s, api->tag);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_MTU))
		stream_putl(s, api->mtu);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

int zclient_route_send(u_char cmd, struct zclient *zclient,
		       struct zapi_route *api)
{
	if (zapi_route_encode(cmd, zclient->obuf, api) < 0)
		return -1;
	return zclient_send_message(zclient);
}

int zapi_route_encode(u_char cmd, struct stream *s, struct zapi_route *api)
{
	struct zapi_nexthop *api_nh;
	int i;
	int psize;

	stream_reset(s);
	zclient_create_header(s, cmd, api->vrf_id);

	stream_putc(s, api->type);
	stream_putw(s, api->instance);
	stream_putl(s, api->flags);
	stream_putc(s, api->message);
	stream_putw(s, api->safi);

	/* Put prefix information. */
	stream_putc(s, api->prefix.family);
	psize = PSIZE(api->prefix.prefixlen);
	stream_putc(s, api->prefix.prefixlen);
	stream_write(s, (u_char *)&api->prefix.u.prefix, psize);

	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_SRCPFX)) {
		psize = PSIZE(api->src_prefix.prefixlen);
		stream_putc(s, api->src_prefix.prefixlen);
		stream_write(s, (u_char *)&api->src_prefix.prefix, psize);
	}

	/* Nexthops.  */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP)) {
		/* limit the number of nexthops if necessary */
		if (api->nexthop_num > MULTIPATH_NUM) {
			char buf[PREFIX2STR_BUFFER];

			prefix2str(&api->prefix, buf, sizeof(buf));
			zlog_warn(
				"%s: prefix %s: can't encode %u nexthops "
				"(maximum is %u)",
				__func__, buf, api->nexthop_num, MULTIPATH_NUM);
			return -1;
		}

		stream_putw(s, api->nexthop_num);

		for (i = 0; i < api->nexthop_num; i++) {
			api_nh = &api->nexthops[i];

			stream_putc(s, api_nh->type);
			switch (api_nh->type) {
			case NEXTHOP_TYPE_BLACKHOLE:
				stream_putc(s, api_nh->bh_type);
				break;
			case NEXTHOP_TYPE_IPV4:
				stream_put_in_addr(s, &api_nh->gate.ipv4);
				break;
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				stream_put_in_addr(s, &api_nh->gate.ipv4);
				stream_putl(s, api_nh->ifindex);
				break;
			case NEXTHOP_TYPE_IFINDEX:
				stream_putl(s, api_nh->ifindex);
				break;
			case NEXTHOP_TYPE_IPV6:
				stream_write(s, (u_char *)&api_nh->gate.ipv6,
					     16);
				break;
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				stream_write(s, (u_char *)&api_nh->gate.ipv6,
					     16);
				stream_putl(s, api_nh->ifindex);
				break;
			}

			/* MPLS labels for BGP-LU or Segment Routing */
			if (CHECK_FLAG(api->message, ZAPI_MESSAGE_LABEL)) {
				if (api_nh->label_num > MPLS_MAX_LABELS) {
					char buf[PREFIX2STR_BUFFER];
					prefix2str(&api->prefix, buf,
						   sizeof(buf));
					zlog_err(
						"%s: prefix %s: can't encode "
						"%u labels (maximum is %u)",
						__func__, buf,
						api_nh->label_num,
						MPLS_MAX_LABELS);
					return -1;
				}

				stream_putc(s, api_nh->label_num);
				stream_put(s, &api_nh->labels[0],
					   api_nh->label_num
						   * sizeof(mpls_label_t));
			}
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

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return 0;
}

int zapi_route_decode(struct stream *s, struct zapi_route *api)
{
	struct zapi_nexthop *api_nh;
	int i;

	memset(api, 0, sizeof(*api));

	/* Type, flags, message. */
	api->type = stream_getc(s);
	api->instance = stream_getw(s);
	api->flags = stream_getl(s);
	api->message = stream_getc(s);
	api->safi = stream_getw(s);

	/* Prefix. */
	api->prefix.family = stream_getc(s);
	switch (api->prefix.family) {
	case AF_INET:
		api->prefix.prefixlen = MIN(IPV4_MAX_PREFIXLEN, stream_getc(s));
		break;
	case AF_INET6:
		api->prefix.prefixlen = MIN(IPV6_MAX_PREFIXLEN, stream_getc(s));
		break;
	}
	stream_get(&api->prefix.u.prefix, s, PSIZE(api->prefix.prefixlen));
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_SRCPFX)) {
		api->src_prefix.family = AF_INET6;
		api->src_prefix.prefixlen = stream_getc(s);
		stream_get(&api->src_prefix.prefix, s,
			   PSIZE(api->src_prefix.prefixlen));

		if (api->prefix.family != AF_INET6
		    || api->src_prefix.prefixlen == 0)
			UNSET_FLAG(api->message, ZAPI_MESSAGE_SRCPFX);
	}

	/* Nexthops. */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP)) {
		api->nexthop_num = stream_getw(s);
		if (api->nexthop_num > MULTIPATH_NUM) {
			zlog_warn("%s: invalid number of nexthops (%u)",
				  __func__, api->nexthop_num);
			return -1;
		}

		for (i = 0; i < api->nexthop_num; i++) {
			api_nh = &api->nexthops[i];

			api_nh->type = stream_getc(s);
			switch (api_nh->type) {
			case NEXTHOP_TYPE_BLACKHOLE:
				api_nh->bh_type = stream_getc(s);
				break;
			case NEXTHOP_TYPE_IPV4:
				api_nh->gate.ipv4.s_addr = stream_get_ipv4(s);
				break;
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				api_nh->gate.ipv4.s_addr = stream_get_ipv4(s);
				api_nh->ifindex = stream_getl(s);
				break;
			case NEXTHOP_TYPE_IFINDEX:
				api_nh->ifindex = stream_getl(s);
				break;
			case NEXTHOP_TYPE_IPV6:
				stream_get(&api_nh->gate.ipv6, s, 16);
				break;
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				stream_get(&api_nh->gate.ipv6, s, 16);
				api_nh->ifindex = stream_getl(s);
				break;
			}

			/* MPLS labels for BGP-LU or Segment Routing */
			if (CHECK_FLAG(api->message, ZAPI_MESSAGE_LABEL)) {
				api_nh->label_num = stream_getc(s);

				if (api_nh->label_num > MPLS_MAX_LABELS) {
					zlog_warn(
						"%s: invalid number of MPLS "
						"labels (%u)",
						__func__, api_nh->label_num);
					return -1;
				}

				stream_get(&api_nh->labels[0], s,
					   api_nh->label_num
						   * sizeof(mpls_label_t));
			}
		}
	}

	/* Attributes. */
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_DISTANCE))
		api->distance = stream_getc(s);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_METRIC))
		api->metric = stream_getl(s);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_TAG))
		api->tag = stream_getl(s);
	if (CHECK_FLAG(api->message, ZAPI_MESSAGE_MTU))
		api->mtu = stream_getl(s);

	return 0;
}

/*
 * send a ZEBRA_REDISTRIBUTE_ADD or ZEBRA_REDISTRIBUTE_DELETE
 * for the route type (ZEBRA_ROUTE_KERNEL etc.). The zebra server will
 * then set/unset redist[type] in the client handle (a struct zserv) for the
 * sending client
 */
int zebra_redistribute_send(int command, struct zclient *zclient, afi_t afi,
			    int type, u_short instance, vrf_id_t vrf_id)
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

/* Get prefix in ZServ format; family should be filled in on prefix */
static void zclient_stream_get_prefix(struct stream *s, struct prefix *p)
{
	size_t plen = prefix_blen(p);
	u_char c;
	p->prefixlen = 0;

	if (plen == 0)
		return;

	stream_get(&p->u.prefix, s, plen);
	c = stream_getc(s);
	p->prefixlen = MIN(plen * 8, c);
}

/* Router-id update from zebra daemon. */
void zebra_router_id_update_read(struct stream *s, struct prefix *rid)
{
	/* Fetch interface address. */
	rid->family = stream_getc(s);

	zclient_stream_get_prefix(s, rid);
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
 * |  Link Layer Type                                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Harware Address Length                                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Hardware Address      if HW lenght different from 0          |
 * |   ...                  max INTERFACE_HWADDR_MAX               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Link_params? |  Whether a link-params follows: 1 or 0.
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Link_params    0 or 1 INTERFACE_LINK_PARAMS_SIZE sized       |
 * |   ....          (struct if_link_params).                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

static void zclient_vrf_add(struct zclient *zclient, vrf_id_t vrf_id)
{
	struct vrf *vrf;
	char vrfname_tmp[VRF_NAMSIZ];
	struct vrf_data data;

	stream_get(&data, zclient->ibuf, sizeof(struct vrf_data));
	/* Read interface name. */
	stream_get(vrfname_tmp, zclient->ibuf, VRF_NAMSIZ);

	/* Lookup/create vrf by vrf_id. */
	vrf = vrf_get(vrf_id, vrfname_tmp);
	vrf->data = data;

	vrf_enable(vrf);
}

static void zclient_vrf_delete(struct zclient *zclient, vrf_id_t vrf_id)
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
		return;

	vrf_delete(vrf);
}

struct interface *zebra_interface_add_read(struct stream *s, vrf_id_t vrf_id)
{
	struct interface *ifp;
	char ifname_tmp[INTERFACE_NAMSIZ];

	/* Read interface name. */
	stream_get(ifname_tmp, s, INTERFACE_NAMSIZ);

	/* Lookup/create interface by name. */
	ifp = if_get_by_name(ifname_tmp, vrf_id, 0);

	zebra_interface_if_set_value(s, ifp);

	return ifp;
}

/*
 * Read interface up/down msg (ZEBRA_INTERFACE_UP/ZEBRA_INTERFACE_DOWN)
 * from zebra server.  The format of this message is the same as
 * that sent for ZEBRA_INTERFACE_ADD/ZEBRA_INTERFACE_DELETE (see
 * comments for zebra_interface_add_read), except that no sockaddr_dl
 * is sent at the tail of the message.
 */
struct interface *zebra_interface_state_read(struct stream *s, vrf_id_t vrf_id)
{
	struct interface *ifp;
	char ifname_tmp[INTERFACE_NAMSIZ];

	/* Read interface name. */
	stream_get(ifname_tmp, s, INTERFACE_NAMSIZ);

	/* Lookup this by interface index. */
	ifp = if_lookup_by_name(ifname_tmp, vrf_id);
	if (ifp == NULL) {
		zlog_warn("INTERFACE_STATE: Cannot find IF %s in VRF %d",
			  ifname_tmp, vrf_id);
		return NULL;
	}

	zebra_interface_if_set_value(s, ifp);

	return ifp;
}

static void link_params_set_value(struct stream *s, struct if_link_params *iflp)
{

	if (iflp == NULL)
		return;

	iflp->lp_status = stream_getl(s);
	iflp->te_metric = stream_getl(s);
	iflp->max_bw = stream_getf(s);
	iflp->max_rsv_bw = stream_getf(s);
	uint32_t bwclassnum = stream_getl(s);
	{
		unsigned int i;
		for (i = 0; i < bwclassnum && i < MAX_CLASS_TYPE; i++)
			iflp->unrsv_bw[i] = stream_getf(s);
		if (i < bwclassnum)
			zlog_err(
				"%s: received %d > %d (MAX_CLASS_TYPE) bw entries"
				" - outdated library?",
				__func__, bwclassnum, MAX_CLASS_TYPE);
	}
	iflp->admin_grp = stream_getl(s);
	iflp->rmt_as = stream_getl(s);
	iflp->rmt_ip.s_addr = stream_get_ipv4(s);

	iflp->av_delay = stream_getl(s);
	iflp->min_delay = stream_getl(s);
	iflp->max_delay = stream_getl(s);
	iflp->delay_var = stream_getl(s);

	iflp->pkt_loss = stream_getf(s);
	iflp->res_bw = stream_getf(s);
	iflp->ava_bw = stream_getf(s);
	iflp->use_bw = stream_getf(s);
}

struct interface *zebra_interface_link_params_read(struct stream *s)
{
	struct if_link_params *iflp;
	ifindex_t ifindex;

	assert(s);

	ifindex = stream_getl(s);

	struct interface *ifp = if_lookup_by_index(ifindex, VRF_DEFAULT);

	if (ifp == NULL) {
		zlog_err("%s: unknown ifindex %u, shouldn't happen", __func__,
			 ifindex);
		return NULL;
	}

	if ((iflp = if_link_params_get(ifp)) == NULL)
		return NULL;

	link_params_set_value(s, iflp);

	return ifp;
}

void zebra_interface_if_set_value(struct stream *s, struct interface *ifp)
{
	u_char link_params_status = 0;

	/* Read interface's index. */
	ifp->ifindex = stream_getl(s);
	ifp->status = stream_getc(s);

	/* Read interface's value. */
	ifp->flags = stream_getq(s);
	ifp->ptm_enable = stream_getc(s);
	ifp->ptm_status = stream_getc(s);
	ifp->metric = stream_getl(s);
	ifp->speed = stream_getl(s);
	ifp->mtu = stream_getl(s);
	ifp->mtu6 = stream_getl(s);
	ifp->bandwidth = stream_getl(s);
	ifp->ll_type = stream_getl(s);
	ifp->hw_addr_len = stream_getl(s);
	if (ifp->hw_addr_len)
		stream_get(ifp->hw_addr, s,
			   MIN(ifp->hw_addr_len, INTERFACE_HWADDR_MAX));

	/* Read Traffic Engineering status */
	link_params_status = stream_getc(s);
	/* Then, Traffic Engineering parameters if any */
	if (link_params_status) {
		struct if_link_params *iflp = if_link_params_get(ifp);
		link_params_set_value(s, iflp);
	}
}

size_t zebra_interface_link_params_write(struct stream *s,
					 struct interface *ifp)
{
	size_t w;
	struct if_link_params *iflp;
	int i;

	if (s == NULL || ifp == NULL || ifp->link_params == NULL)
		return 0;

	iflp = ifp->link_params;
	w = 0;

	w += stream_putl(s, iflp->lp_status);

	w += stream_putl(s, iflp->te_metric);
	w += stream_putf(s, iflp->max_bw);
	w += stream_putf(s, iflp->max_rsv_bw);

	w += stream_putl(s, MAX_CLASS_TYPE);
	for (i = 0; i < MAX_CLASS_TYPE; i++)
		w += stream_putf(s, iflp->unrsv_bw[i]);

	w += stream_putl(s, iflp->admin_grp);
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
 * format of message for address additon is:
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
	const u_char *p = s;

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
	u_char ifc_flags;

	memset(&p, 0, sizeof(p));
	memset(&d, 0, sizeof(d));

	/* Get interface index. */
	ifindex = stream_getl(s);

	/* Lookup index. */
	ifp = if_lookup_by_index(ifindex, vrf_id);
	if (ifp == NULL) {
		zlog_warn("INTERFACE_ADDRESS_%s: Cannot find IF %u in VRF %d",
			  (type == ZEBRA_INTERFACE_ADDRESS_ADD) ? "ADD" : "DEL",
			  ifindex, vrf_id);
		return NULL;
	}

	/* Fetch flag. */
	ifc_flags = stream_getc(s);

	/* Fetch interface address. */
	d.family = p.family = stream_getc(s);
	plen = prefix_blen(&d);

	zclient_stream_get_prefix(s, &p);

	/* Fetch destination address. */
	stream_get(&d.u.prefix, s, plen);

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
				char buf[PREFIX_STRLEN];
				zlog_warn(
					"warning: interface %s address %s "
					"with peer flag set, but no peer address!",
					ifp->name, prefix2str(ifc->address, buf,
							      sizeof buf));
				UNSET_FLAG(ifc->flags, ZEBRA_IFA_PEER);
			}
		}
	} else {
		assert(type == ZEBRA_INTERFACE_ADDRESS_DELETE);
		ifc = connected_delete_by_prefix(ifp, &p);
	}

	return ifc;
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
	ifindex = stream_getl(s);

	/* Lookup index. */
	ifp = if_lookup_by_index(ifindex, vrf_id);
	if (ifp == NULL) {
		zlog_warn("INTERFACE_NBR_%s: Cannot find IF %u in VRF %d",
			  (type == ZEBRA_INTERFACE_NBR_ADDRESS_ADD) ? "ADD"
								    : "DELETE",
			  ifindex, vrf_id);
		return NULL;
	}

	p.family = stream_getc(s);
	stream_get(&p.u.prefix, s, prefix_blen(&p));
	p.prefixlen = stream_getc(s);

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
}

struct interface *zebra_interface_vrf_update_read(struct stream *s,
						  vrf_id_t vrf_id,
						  vrf_id_t *new_vrf_id)
{
	unsigned int ifindex;
	struct interface *ifp;
	vrf_id_t new_id = VRF_DEFAULT;

	/* Get interface index. */
	ifindex = stream_getl(s);

	/* Lookup interface. */
	ifp = if_lookup_by_index(ifindex, vrf_id);
	if (ifp == NULL) {
		zlog_warn("INTERFACE_VRF_UPDATE: Cannot find IF %u in VRF %d",
			  ifindex, vrf_id);
		return NULL;
	}

	/* Fetch new VRF Id. */
	new_id = stream_getw(s);

	*new_vrf_id = new_id;
	return ifp;
}

/* filter unwanted messages until the expected one arrives */
static int zclient_read_sync_response(struct zclient *zclient,
				      u_int16_t expected_cmd)
{
	struct stream *s;
	u_int16_t size = -1;
	u_char marker;
	u_char version;
	vrf_id_t vrf_id;
	u_int16_t cmd;
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
		zlog_err("%s: Invalid Sync Message Reply", __func__);
		return -1;
	}

	return 0;
}
/**
 * Connect to label manager in a syncronous way
 *
 * It first writes the request to zcient output buffer and then
 * immediately reads the answer from the input buffer.
 *
 * @param zclient Zclient used to connect to label manager (zebra)
 * @result Result of response
 */
int lm_label_manager_connect(struct zclient *zclient)
{
	int ret;
	struct stream *s;
	u_char result;

	if (zclient_debug)
		zlog_debug("Connecting to Label Manager");

	if (zclient->sock < 0)
		return -1;

	/* send request */
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_LABEL_MANAGER_CONNECT, VRF_DEFAULT);

	/* proto */
	stream_putc(s, zclient->redist_default);
	/* instance */
	stream_putw(s, zclient->instance);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	ret = writen(zclient->sock, s->data, stream_get_endp(s));
	if (ret < 0) {
		zlog_err("%s: can't write to zclient->sock", __func__);
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}
	if (ret == 0) {
		zlog_err("%s: zclient->sock connection closed", __func__);
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}
	if (zclient_debug)
		zlog_debug("%s: Label manager connect request (%d bytes) sent",
			   __func__, ret);

	/* read response */
	if (zclient_read_sync_response(zclient, ZEBRA_LABEL_MANAGER_CONNECT)
	    != 0)
		return -1;

	/* result */
	s = zclient->ibuf;
	result = stream_getc(s);
	if (zclient_debug)
		zlog_debug(
			"%s: Label Manager connect response received, result %u",
			__func__, result);

	return (int)result;
}

/**
 * Function to request a label chunk in a syncronous way
 *
 * It first writes the request to zlcient output buffer and then
 * immediately reads the answer from the input buffer.
 *
 * @param zclient Zclient used to connect to label manager (zebra)
 * @param keep Avoid garbage collection
 * @param chunk_size Amount of labels requested
 * @param start To write first assigned chunk label to
 * @param end To write last assigned chunk label to
 * @result 0 on success, -1 otherwise
 */
int lm_get_label_chunk(struct zclient *zclient, u_char keep,
		       uint32_t chunk_size, uint32_t *start, uint32_t *end)
{
	int ret;
	struct stream *s;
	u_char response_keep;

	if (zclient_debug)
		zlog_debug("Getting Label Chunk");

	if (zclient->sock < 0)
		return -1;

	/* send request */
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_GET_LABEL_CHUNK, VRF_DEFAULT);
	/* keep */
	stream_putc(s, keep);
	/* chunk size */
	stream_putl(s, chunk_size);
	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	ret = writen(zclient->sock, s->data, stream_get_endp(s));
	if (ret < 0) {
		zlog_err("%s: can't write to zclient->sock", __func__);
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}
	if (ret == 0) {
		zlog_err("%s: zclient->sock connection closed", __func__);
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}
	if (zclient_debug)
		zlog_debug("%s: Label chunk request (%d bytes) sent", __func__,
			   ret);

	/* read response */
	if (zclient_read_sync_response(zclient, ZEBRA_GET_LABEL_CHUNK) != 0)
		return -1;

	s = zclient->ibuf;
	/* keep */
	response_keep = stream_getc(s);
	/* start and end labels */
	*start = stream_getl(s);
	*end = stream_getl(s);

	/* not owning this response */
	if (keep != response_keep) {
		zlog_err(
			"%s: Invalid Label chunk: %u - %u, keeps mismatch %u != %u",
			__func__, *start, *end, keep, response_keep);
	}
	/* sanity */
	if (*start > *end || *start < MPLS_MIN_UNRESERVED_LABEL
	    || *end > MPLS_MAX_UNRESERVED_LABEL) {
		zlog_err("%s: Invalid Label chunk: %u - %u", __func__, *start,
			 *end);
		return -1;
	}

	if (zclient_debug)
		zlog_debug("Label Chunk assign: %u - %u (%u) ", *start, *end,
			   response_keep);

	return 0;
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
		zlog_debug("Releasing Label Chunk");

	if (zclient->sock < 0)
		return -1;

	/* send request */
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_RELEASE_LABEL_CHUNK, VRF_DEFAULT);

	/* start */
	stream_putl(s, start);
	/* end */
	stream_putl(s, end);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	ret = writen(zclient->sock, s->data, stream_get_endp(s));
	if (ret < 0) {
		zlog_err("%s: can't write to zclient->sock", __func__);
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}
	if (ret == 0) {
		zlog_err("%s: zclient->sock connection closed", __func__);
		close(zclient->sock);
		zclient->sock = -1;
		return -1;
	}

	return 0;
}

int zebra_send_pw(struct zclient *zclient, int command, struct zapi_pw *pw)
{
	struct stream *s;

	/* Reset stream. */
	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, command, VRF_DEFAULT);
	stream_write(s, pw->ifname, IF_NAMESIZE);
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
		stream_write(s, (u_char *)&pw->nexthop.ipv6, 16);
		break;
	default:
		zlog_err("%s: unknown af", __func__);
		return -1;
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
void zebra_read_pw_status_update(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id,
				 struct zapi_pw_status *pw)
{
	struct stream *s;

	memset(pw, 0, sizeof(struct zapi_pw_status));
	s = zclient->ibuf;

	/* Get data. */
	stream_get(pw->ifname, s, IF_NAMESIZE);
	pw->ifindex = stream_getl(s);
	pw->status = stream_getl(s);
}

/* Zebra client message read function. */
static int zclient_read(struct thread *thread)
{
	size_t already;
	uint16_t length, command;
	uint8_t marker, version;
	vrf_id_t vrf_id;
	struct zclient *zclient;

	/* Get socket to zebra. */
	zclient = THREAD_ARG(thread);
	zclient->t_read = NULL;

	/* Read zebra header (if we don't have it already). */
	if ((already = stream_get_endp(zclient->ibuf)) < ZEBRA_HEADER_SIZE) {
		ssize_t nbyte;
		if (((nbyte = stream_read_try(zclient->ibuf, zclient->sock,
					      ZEBRA_HEADER_SIZE - already))
		     == 0)
		    || (nbyte == -1)) {
			if (zclient_debug)
				zlog_debug(
					"zclient connection closed socket [%d].",
					zclient->sock);
			return zclient_failed(zclient);
		}
		if (nbyte != (ssize_t)(ZEBRA_HEADER_SIZE - already)) {
			/* Try again later. */
			zclient_event(ZCLIENT_READ, zclient);
			return 0;
		}
		already = ZEBRA_HEADER_SIZE;
	}

	/* Reset to read from the beginning of the incoming packet. */
	stream_set_getp(zclient->ibuf, 0);

	/* Fetch header values. */
	length = stream_getw(zclient->ibuf);
	marker = stream_getc(zclient->ibuf);
	version = stream_getc(zclient->ibuf);
	vrf_id = stream_getw(zclient->ibuf);
	command = stream_getw(zclient->ibuf);

	if (marker != ZEBRA_HEADER_MARKER || version != ZSERV_VERSION) {
		zlog_err(
			"%s: socket %d version mismatch, marker %d, version %d",
			__func__, zclient->sock, marker, version);
		return zclient_failed(zclient);
	}

	if (length < ZEBRA_HEADER_SIZE) {
		zlog_err("%s: socket %d message length %u is less than %d ",
			 __func__, zclient->sock, length, ZEBRA_HEADER_SIZE);
		return zclient_failed(zclient);
	}

	/* Length check. */
	if (length > STREAM_SIZE(zclient->ibuf)) {
		struct stream *ns;
		zlog_warn(
			"%s: message size %u exceeds buffer size %lu, expanding...",
			__func__, length, (u_long)STREAM_SIZE(zclient->ibuf));
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
			return zclient_failed(zclient);
		}
		if (nbyte != (ssize_t)(length - already)) {
			/* Try again later. */
			zclient_event(ZCLIENT_READ, zclient);
			return 0;
		}
	}

	length -= ZEBRA_HEADER_SIZE;

	if (zclient_debug)
		zlog_debug("zclient 0x%p command 0x%x VRF %u\n",
			   (void *)zclient, command, vrf_id);

	switch (command) {
	case ZEBRA_ROUTER_ID_UPDATE:
		if (zclient->router_id_update)
			(*zclient->router_id_update)(command, zclient, length,
						     vrf_id);
		break;
	case ZEBRA_VRF_ADD:
		zclient_vrf_add(zclient, vrf_id);
		break;
	case ZEBRA_VRF_DELETE:
		zclient_vrf_delete(zclient, vrf_id);
		break;
	case ZEBRA_INTERFACE_ADD:
		if (zclient->interface_add)
			(*zclient->interface_add)(command, zclient, length,
						  vrf_id);
		break;
	case ZEBRA_INTERFACE_DELETE:
		if (zclient->interface_delete)
			(*zclient->interface_delete)(command, zclient, length,
						     vrf_id);
		break;
	case ZEBRA_INTERFACE_ADDRESS_ADD:
		if (zclient->interface_address_add)
			(*zclient->interface_address_add)(command, zclient,
							  length, vrf_id);
		break;
	case ZEBRA_INTERFACE_ADDRESS_DELETE:
		if (zclient->interface_address_delete)
			(*zclient->interface_address_delete)(command, zclient,
							     length, vrf_id);
		break;
	case ZEBRA_INTERFACE_BFD_DEST_UPDATE:
		if (zclient->interface_bfd_dest_update)
			(*zclient->interface_bfd_dest_update)(command, zclient,
							      length, vrf_id);
		break;
	case ZEBRA_INTERFACE_NBR_ADDRESS_ADD:
		if (zclient->interface_nbr_address_add)
			(*zclient->interface_nbr_address_add)(command, zclient,
							      length, vrf_id);
		break;
	case ZEBRA_INTERFACE_NBR_ADDRESS_DELETE:
		if (zclient->interface_nbr_address_delete)
			(*zclient->interface_nbr_address_delete)(
				command, zclient, length, vrf_id);
		break;
	case ZEBRA_INTERFACE_UP:
		if (zclient->interface_up)
			(*zclient->interface_up)(command, zclient, length,
						 vrf_id);
		break;
	case ZEBRA_INTERFACE_DOWN:
		if (zclient->interface_down)
			(*zclient->interface_down)(command, zclient, length,
						   vrf_id);
		break;
	case ZEBRA_INTERFACE_VRF_UPDATE:
		if (zclient->interface_vrf_update)
			(*zclient->interface_vrf_update)(command, zclient,
							 length, vrf_id);
		break;
	case ZEBRA_NEXTHOP_UPDATE:
		if (zclient_debug)
			zlog_debug("zclient rcvd nexthop update\n");
		if (zclient->nexthop_update)
			(*zclient->nexthop_update)(command, zclient, length,
						   vrf_id);
		break;
	case ZEBRA_IMPORT_CHECK_UPDATE:
		if (zclient_debug)
			zlog_debug("zclient rcvd import check update\n");
		if (zclient->import_check_update)
			(*zclient->import_check_update)(command, zclient,
							length, vrf_id);
		break;
	case ZEBRA_BFD_DEST_REPLAY:
		if (zclient->bfd_dest_replay)
			(*zclient->bfd_dest_replay)(command, zclient, length,
						    vrf_id);
		break;
	case ZEBRA_REDISTRIBUTE_ROUTE_ADD:
		if (zclient->redistribute_route_add)
			(*zclient->redistribute_route_add)(command, zclient,
							   length, vrf_id);
		break;
	case ZEBRA_REDISTRIBUTE_ROUTE_DEL:
		if (zclient->redistribute_route_del)
			(*zclient->redistribute_route_del)(command, zclient,
							   length, vrf_id);
		break;
	case ZEBRA_INTERFACE_LINK_PARAMS:
		if (zclient->interface_link_params)
			(*zclient->interface_link_params)(command, zclient,
							  length);
		break;
	case ZEBRA_FEC_UPDATE:
		if (zclient_debug)
			zlog_debug("zclient rcvd fec update\n");
		if (zclient->fec_update)
			(*zclient->fec_update)(command, zclient, length);
		break;
	case ZEBRA_VNI_ADD:
		if (zclient->local_vni_add)
			(*zclient->local_vni_add)(command, zclient, length,
						  vrf_id);
		break;
	case ZEBRA_VNI_DEL:
		if (zclient->local_vni_del)
			(*zclient->local_vni_del)(command, zclient, length,
						  vrf_id);
		break;
	case ZEBRA_MACIP_ADD:
		if (zclient->local_macip_add)
			(*zclient->local_macip_add)(command, zclient, length,
						    vrf_id);
		break;
	case ZEBRA_MACIP_DEL:
		if (zclient->local_macip_del)
			(*zclient->local_macip_del)(command, zclient, length,
						    vrf_id);
		break;
	case ZEBRA_PW_STATUS_UPDATE:
		if (zclient->pw_status_update)
			(*zclient->pw_status_update)(command, zclient, length,
						     vrf_id);
		break;
	default:
		break;
	}

	if (zclient->sock < 0)
		/* Connection was closed during packet processing. */
		return -1;

	/* Register read thread. */
	stream_reset(zclient->ibuf);
	zclient_event(ZCLIENT_READ, zclient);

	return 0;
}

void zclient_redistribute(int command, struct zclient *zclient, afi_t afi,
			  int type, u_short instance, vrf_id_t vrf_id)
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
			if (vrf_bitmap_check(zclient->redist[afi][type],
					     vrf_id))
				return;
			vrf_bitmap_set(zclient->redist[afi][type], vrf_id);
		} else {
			if (!vrf_bitmap_check(zclient->redist[afi][type],
					      vrf_id))
				return;
			vrf_bitmap_unset(zclient->redist[afi][type], vrf_id);
		}
	}

	if (zclient->sock > 0)
		zebra_redistribute_send(command, zclient, afi, type, instance,
					vrf_id);
}


void zclient_redistribute_default(int command, struct zclient *zclient,
				  vrf_id_t vrf_id)
{

	if (command == ZEBRA_REDISTRIBUTE_DEFAULT_ADD) {
		if (vrf_bitmap_check(zclient->default_information, vrf_id))
			return;
		vrf_bitmap_set(zclient->default_information, vrf_id);
	} else {
		if (!vrf_bitmap_check(zclient->default_information, vrf_id))
			return;
		vrf_bitmap_unset(zclient->default_information, vrf_id);
	}

	if (zclient->sock > 0)
		zebra_message_send(zclient, command, vrf_id);
}

static void zclient_event(enum event event, struct zclient *zclient)
{
	switch (event) {
	case ZCLIENT_SCHEDULE:
		thread_add_event(zclient->master, zclient_connect, zclient, 0,
				 &zclient->t_connect);
		break;
	case ZCLIENT_CONNECT:
		if (zclient_debug)
			zlog_debug(
				"zclient connect failures: %d schedule interval is now %d",
				zclient->fail, zclient->fail < 3 ? 10 : 60);
		thread_add_timer(zclient->master, zclient_connect, zclient,
				 zclient->fail < 3 ? 10 : 60,
				 &zclient->t_connect);
		break;
	case ZCLIENT_READ:
		zclient->t_read = NULL;
		thread_add_read(zclient->master, zclient_read, zclient,
				zclient->sock, &zclient->t_read);
		break;
	}
}

void zclient_interface_set_master(struct zclient *client,
				  struct interface *master,
				  struct interface *slave)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_INTERFACE_SET_MASTER, master->vrf_id);

	stream_putw(s, master->vrf_id);
	stream_putl(s, master->ifindex);
	stream_putw(s, slave->vrf_id);
	stream_putl(s, slave->ifindex);

	stream_putw_at(s, 0, stream_get_endp(s));
	zclient_send_message(client);
}
