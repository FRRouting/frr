/* Zebra daemon server routine.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
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
#include "command.h"
#include "if.h"
#include "thread.h"
#include "stream.h"
#include "memory.h"
#include "zebra_memory.h"
#include "table.h"
#include "rib.h"
#include "network.h"
#include "sockunion.h"
#include "log.h"
#include "zclient.h"
#include "privs.h"
#include "network.h"
#include "buffer.h"
#include "nexthop.h"
#include "vrf.h"

#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/router-id.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/ipforward.h"
#include "zebra/zebra_rnh.h"
#include "zebra/rt_netlink.h"
#include "zebra/interface.h"
#include "zebra/zebra_ptm.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_mroute.h"
#include "zebra/label_manager.h"
#include "zebra/zebra_vxlan.h"

/* Event list of zebra. */
enum event { ZEBRA_SERV, ZEBRA_READ, ZEBRA_WRITE };

static void zebra_event(enum event event, int sock, struct zserv *client);

extern struct zebra_privs_t zserv_privs;

static void zebra_client_close(struct zserv *client);

static int zserv_delayed_close(struct thread *thread)
{
	struct zserv *client = THREAD_ARG(thread);

	client->t_suicide = NULL;
	zebra_client_close(client);
	return 0;
}

static int zserv_flush_data(struct thread *thread)
{
	struct zserv *client = THREAD_ARG(thread);

	client->t_write = NULL;
	if (client->t_suicide) {
		zebra_client_close(client);
		return -1;
	}
	switch (buffer_flush_available(client->wb, client->sock)) {
	case BUFFER_ERROR:
		zlog_warn(
			"%s: buffer_flush_available failed on zserv client fd %d, "
			"closing",
			__func__, client->sock);
		zebra_client_close(client);
		client = NULL;
		break;
	case BUFFER_PENDING:
		client->t_write = NULL;
		thread_add_write(zebrad.master, zserv_flush_data, client,
				 client->sock, &client->t_write);
		break;
	case BUFFER_EMPTY:
		break;
	}

	if (client)
		client->last_write_time = monotime(NULL);
	return 0;
}

int zebra_server_send_message(struct zserv *client)
{
	if (client->t_suicide)
		return -1;

	if (client->is_synchronous)
		return 0;

	stream_set_getp(client->obuf, 0);
	client->last_write_cmd = stream_getw_from(client->obuf, 6);
	switch (buffer_write(client->wb, client->sock,
			     STREAM_DATA(client->obuf),
			     stream_get_endp(client->obuf))) {
	case BUFFER_ERROR:
		zlog_warn(
			"%s: buffer_write failed to zserv client fd %d, closing",
			__func__, client->sock);
		/* Schedule a delayed close since many of the functions that
		   call this
		   one do not check the return code.  They do not allow for the
		   possibility that an I/O error may have caused the client to
		   be
		   deleted. */
		client->t_suicide = NULL;
		thread_add_event(zebrad.master, zserv_delayed_close, client, 0,
				 &client->t_suicide);
		return -1;
	case BUFFER_EMPTY:
		THREAD_OFF(client->t_write);
		break;
	case BUFFER_PENDING:
		thread_add_write(zebrad.master, zserv_flush_data, client,
				 client->sock, &client->t_write);
		break;
	}

	client->last_write_time = monotime(NULL);
	return 0;
}

void zserv_create_header(struct stream *s, uint16_t cmd, vrf_id_t vrf_id)
{
	/* length placeholder, caller can update */
	stream_putw(s, ZEBRA_HEADER_SIZE);
	stream_putc(s, ZEBRA_HEADER_MARKER);
	stream_putc(s, ZSERV_VERSION);
	stream_putw(s, vrf_id);
	stream_putw(s, cmd);
}

static void zserv_encode_interface(struct stream *s, struct interface *ifp)
{
	/* Interface information. */
	stream_put(s, ifp->name, INTERFACE_NAMSIZ);
	stream_putl(s, ifp->ifindex);
	stream_putc(s, ifp->status);
	stream_putq(s, ifp->flags);
	stream_putc(s, ifp->ptm_enable);
	stream_putc(s, ifp->ptm_status);
	stream_putl(s, ifp->metric);
	stream_putl(s, ifp->speed);
	stream_putl(s, ifp->mtu);
	stream_putl(s, ifp->mtu6);
	stream_putl(s, ifp->bandwidth);
	stream_putl(s, ifp->ll_type);
	stream_putl(s, ifp->hw_addr_len);
	if (ifp->hw_addr_len)
		stream_put(s, ifp->hw_addr, ifp->hw_addr_len);

	/* Then, Traffic Engineering parameters if any */
	if (HAS_LINK_PARAMS(ifp) && IS_LINK_PARAMS_SET(ifp->link_params)) {
		stream_putc(s, 1);
		zebra_interface_link_params_write(s, ifp);
	} else
		stream_putc(s, 0);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));
}

static void zserv_encode_vrf(struct stream *s, struct zebra_vrf *zvrf)
{
	struct vrf_data data;

	data.l.table_id = zvrf->table_id;
	/* Pass the tableid */
	stream_put(s, &data, sizeof(struct vrf_data));
	/* Interface information. */
	stream_put(s, zvrf_name(zvrf), VRF_NAMSIZ);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));
}

/* Interface is added. Send ZEBRA_INTERFACE_ADD to client. */
/*
 * This function is called in the following situations:
 * - in response to a 3-byte ZEBRA_INTERFACE_ADD request
 *   from the client.
 * - at startup, when zebra figures out the available interfaces
 * - when an interface is added (where support for
 *   RTM_IFANNOUNCE or AF_NETLINK sockets is available), or when
 *   an interface is marked IFF_UP (i.e., an RTM_IFINFO message is
 *   received)
 */
int zsend_interface_add(struct zserv *client, struct interface *ifp)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, ZEBRA_INTERFACE_ADD, ifp->vrf_id);
	zserv_encode_interface(s, ifp);

	client->ifadd_cnt++;
	return zebra_server_send_message(client);
}

/* Interface deletion from zebra daemon. */
int zsend_interface_delete(struct zserv *client, struct interface *ifp)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, ZEBRA_INTERFACE_DELETE, ifp->vrf_id);
	zserv_encode_interface(s, ifp);

	client->ifdel_cnt++;
	return zebra_server_send_message(client);
}

int zsend_vrf_add(struct zserv *client, struct zebra_vrf *zvrf)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, ZEBRA_VRF_ADD, zvrf_id(zvrf));
	zserv_encode_vrf(s, zvrf);

	client->vrfadd_cnt++;
	return zebra_server_send_message(client);
}

/* VRF deletion from zebra daemon. */
int zsend_vrf_delete(struct zserv *client, struct zebra_vrf *zvrf)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, ZEBRA_VRF_DELETE, zvrf_id(zvrf));
	zserv_encode_vrf(s, zvrf);

	client->vrfdel_cnt++;
	return zebra_server_send_message(client);
}

int zsend_interface_link_params(struct zserv *client, struct interface *ifp)
{
	struct stream *s;

	/* Check this client need interface information. */
	if (!client->ifinfo)
		return 0;

	if (!ifp->link_params)
		return 0;
	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, ZEBRA_INTERFACE_LINK_PARAMS, ifp->vrf_id);

	/* Add Interface Index */
	stream_putl(s, ifp->ifindex);

	/* Then TE Link Parameters */
	if (zebra_interface_link_params_write(s, ifp) == 0)
		return 0;

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zebra_server_send_message(client);
}

/* Interface address is added/deleted. Send ZEBRA_INTERFACE_ADDRESS_ADD or
 * ZEBRA_INTERFACE_ADDRESS_DELETE to the client.
 *
 * A ZEBRA_INTERFACE_ADDRESS_ADD is sent in the following situations:
 * - in response to a 3-byte ZEBRA_INTERFACE_ADD request
 *   from the client, after the ZEBRA_INTERFACE_ADD has been
 *   sent from zebra to the client
 * - redistribute new address info to all clients in the following situations
 *    - at startup, when zebra figures out the available interfaces
 *    - when an interface is added (where support for
 *      RTM_IFANNOUNCE or AF_NETLINK sockets is available), or when
 *      an interface is marked IFF_UP (i.e., an RTM_IFINFO message is
 *      received)
 *    - for the vty commands "ip address A.B.C.D/M [<secondary>|<label LINE>]"
 *      and "no bandwidth <1-10000000>", "ipv6 address X:X::X:X/M"
 *    - when an RTM_NEWADDR message is received from the kernel,
 *
 * The call tree that triggers ZEBRA_INTERFACE_ADDRESS_DELETE:
 *
 *                   zsend_interface_address(DELETE)
 *                           ^
 *                           |
 *          zebra_interface_address_delete_update
 *             ^                        ^      ^
 *             |                        |      if_delete_update
 *             |                        |
 *         ip_address_uninstall        connected_delete_ipv4
 *         [ipv6_addresss_uninstall]   [connected_delete_ipv6]
 *             ^                        ^
 *             |                        |
 *             |                  RTM_NEWADDR on routing/netlink socket
 *             |
 *         vty commands:
 *     "no ip address A.B.C.D/M [label LINE]"
 *     "no ip address A.B.C.D/M secondary"
 *     ["no ipv6 address X:X::X:X/M"]
 *
 */
int zsend_interface_address(int cmd, struct zserv *client,
			    struct interface *ifp, struct connected *ifc)
{
	int blen;
	struct stream *s;
	struct prefix *p;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, cmd, ifp->vrf_id);
	stream_putl(s, ifp->ifindex);

	/* Interface address flag. */
	stream_putc(s, ifc->flags);

	/* Prefix information. */
	p = ifc->address;
	stream_putc(s, p->family);
	blen = prefix_blen(p);
	stream_put(s, &p->u.prefix, blen);

	/*
	 * XXX gnu version does not send prefixlen for
	 * ZEBRA_INTERFACE_ADDRESS_DELETE
	 * but zebra_interface_address_delete_read() in the gnu version
	 * expects to find it
	 */
	stream_putc(s, p->prefixlen);

	/* Destination. */
	p = ifc->destination;
	if (p)
		stream_put(s, &p->u.prefix, blen);
	else
		stream_put(s, NULL, blen);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	client->connected_rt_add_cnt++;
	return zebra_server_send_message(client);
}

static int zsend_interface_nbr_address(int cmd, struct zserv *client,
				       struct interface *ifp,
				       struct nbr_connected *ifc)
{
	int blen;
	struct stream *s;
	struct prefix *p;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, cmd, ifp->vrf_id);
	stream_putl(s, ifp->ifindex);

	/* Prefix information. */
	p = ifc->address;
	stream_putc(s, p->family);
	blen = prefix_blen(p);
	stream_put(s, &p->u.prefix, blen);

	/*
	 * XXX gnu version does not send prefixlen for
	 * ZEBRA_INTERFACE_ADDRESS_DELETE
	 * but zebra_interface_address_delete_read() in the gnu version
	 * expects to find it
	 */
	stream_putc(s, p->prefixlen);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zebra_server_send_message(client);
}

/* Interface address addition. */
static void zebra_interface_nbr_address_add_update(struct interface *ifp,
						   struct nbr_connected *ifc)
{
	struct listnode *node, *nnode;
	struct zserv *client;
	struct prefix *p;

	if (IS_ZEBRA_DEBUG_EVENT) {
		char buf[INET6_ADDRSTRLEN];

		p = ifc->address;
		zlog_debug(
			"MESSAGE: ZEBRA_INTERFACE_NBR_ADDRESS_ADD %s/%d on %s",
			inet_ntop(p->family, &p->u.prefix, buf,
				  INET6_ADDRSTRLEN),
			p->prefixlen, ifc->ifp->name);
	}

	for (ALL_LIST_ELEMENTS(zebrad.client_list, node, nnode, client))
		zsend_interface_nbr_address(ZEBRA_INTERFACE_NBR_ADDRESS_ADD,
					    client, ifp, ifc);
}

/* Interface address deletion. */
static void zebra_interface_nbr_address_delete_update(struct interface *ifp,
						      struct nbr_connected *ifc)
{
	struct listnode *node, *nnode;
	struct zserv *client;
	struct prefix *p;

	if (IS_ZEBRA_DEBUG_EVENT) {
		char buf[INET6_ADDRSTRLEN];

		p = ifc->address;
		zlog_debug(
			"MESSAGE: ZEBRA_INTERFACE_NBR_ADDRESS_DELETE %s/%d on %s",
			inet_ntop(p->family, &p->u.prefix, buf,
				  INET6_ADDRSTRLEN),
			p->prefixlen, ifc->ifp->name);
	}

	for (ALL_LIST_ELEMENTS(zebrad.client_list, node, nnode, client))
		zsend_interface_nbr_address(ZEBRA_INTERFACE_NBR_ADDRESS_DELETE,
					    client, ifp, ifc);
}

/* Send addresses on interface to client */
int zsend_interface_addresses(struct zserv *client, struct interface *ifp)
{
	struct listnode *cnode, *cnnode;
	struct connected *c;
	struct nbr_connected *nc;

	/* Send interface addresses. */
	for (ALL_LIST_ELEMENTS(ifp->connected, cnode, cnnode, c)) {
		if (!CHECK_FLAG(c->conf, ZEBRA_IFC_REAL))
			continue;

		if (zsend_interface_address(ZEBRA_INTERFACE_ADDRESS_ADD, client,
					    ifp, c)
		    < 0)
			return -1;
	}

	/* Send interface neighbors. */
	for (ALL_LIST_ELEMENTS(ifp->nbr_connected, cnode, cnnode, nc)) {
		if (zsend_interface_nbr_address(ZEBRA_INTERFACE_NBR_ADDRESS_ADD,
						client, ifp, nc)
		    < 0)
			return -1;
	}

	return 0;
}

/* Notify client about interface moving from one VRF to another.
 * Whether client is interested in old and new VRF is checked by caller.
 */
int zsend_interface_vrf_update(struct zserv *client, struct interface *ifp,
			       vrf_id_t vrf_id)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, ZEBRA_INTERFACE_VRF_UPDATE, ifp->vrf_id);

	/* Fill in the ifIndex of the interface and its new VRF (id) */
	stream_putl(s, ifp->ifindex);
	stream_putw(s, vrf_id);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	client->if_vrfchg_cnt++;
	return zebra_server_send_message(client);
}

/* Add new nbr connected IPv6 address */
void nbr_connected_add_ipv6(struct interface *ifp, struct in6_addr *address)
{
	struct nbr_connected *ifc;
	struct prefix p;

	p.family = AF_INET6;
	IPV6_ADDR_COPY(&p.u.prefix, address);
	p.prefixlen = IPV6_MAX_PREFIXLEN;

	if (!(ifc = listnode_head(ifp->nbr_connected))) {
		/* new addition */
		ifc = nbr_connected_new();
		ifc->address = prefix_new();
		ifc->ifp = ifp;
		listnode_add(ifp->nbr_connected, ifc);
	}

	prefix_copy(ifc->address, &p);

	zebra_interface_nbr_address_add_update(ifp, ifc);

	if_nbr_ipv6ll_to_ipv4ll_neigh_update(ifp, address, 1);
}

void nbr_connected_delete_ipv6(struct interface *ifp, struct in6_addr *address)
{
	struct nbr_connected *ifc;
	struct prefix p;

	p.family = AF_INET6;
	IPV6_ADDR_COPY(&p.u.prefix, address);
	p.prefixlen = IPV6_MAX_PREFIXLEN;

	ifc = nbr_connected_check(ifp, &p);
	if (!ifc)
		return;

	listnode_delete(ifp->nbr_connected, ifc);

	zebra_interface_nbr_address_delete_update(ifp, ifc);

	if_nbr_ipv6ll_to_ipv4ll_neigh_update(ifp, address, 0);

	nbr_connected_free(ifc);
}

/*
 * The cmd passed to zsend_interface_update  may be ZEBRA_INTERFACE_UP or
 * ZEBRA_INTERFACE_DOWN.
 *
 * The ZEBRA_INTERFACE_UP message is sent from the zebra server to
 * the clients in one of 2 situations:
 *   - an if_up is detected e.g., as a result of an RTM_IFINFO message
 *   - a vty command modifying the bandwidth of an interface is received.
 * The ZEBRA_INTERFACE_DOWN message is sent when an if_down is detected.
 */
int zsend_interface_update(int cmd, struct zserv *client, struct interface *ifp)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, cmd, ifp->vrf_id);
	zserv_encode_interface(s, ifp);

	if (cmd == ZEBRA_INTERFACE_UP)
		client->ifup_cnt++;
	else
		client->ifdown_cnt++;

	return zebra_server_send_message(client);
}

/*
 * This is the new function to announce and withdraw redistributed routes, used
 * by Zebra. This is the old zsend_route_multipath() function. That function
 * was duplicating code to send a lot of information that was essentially thrown
 * away or ignored by the receiver. This is the leaner function that is not a
 * duplicate of the zapi_ipv4_route_add/del.
 *
 * The primary difference is that this function merely sends a single NH instead
 * of
 * all the nexthops.
 */
int zsend_redistribute_route(int add, struct zserv *client, struct prefix *p,
			     struct prefix *src_p, struct route_entry *re)
{
	afi_t afi;
	int cmd;
	int psize;
	struct stream *s;
	struct nexthop *nexthop;
	unsigned long nhnummark = 0, messmark = 0;
	int nhnum = 0;
	u_char zapi_flags = 0;
	struct nexthop dummy_nh;

	afi = family2afi(p->family);
	if (add) {
		switch (afi) {
		case AFI_IP:
			cmd = ZEBRA_REDISTRIBUTE_IPV4_ADD;
			client->redist_v4_add_cnt++;
			break;
		case AFI_IP6:
			cmd = ZEBRA_REDISTRIBUTE_IPV6_ADD;
			client->redist_v6_add_cnt++;
			break;
		default:
			return -1;
		}
	} else {
		switch (afi) {
		case AFI_IP:
			cmd = ZEBRA_REDISTRIBUTE_IPV4_DEL;
			client->redist_v4_del_cnt++;
			break;
		case AFI_IP6:
			cmd = ZEBRA_REDISTRIBUTE_IPV6_DEL;
			client->redist_v6_del_cnt++;
			break;
		default:
			return -1;
		}
	}

	s = client->obuf;
	stream_reset(s);
	memset(&dummy_nh, 0, sizeof(struct nexthop));

	zserv_create_header(s, cmd, re->vrf_id);

	/* Put type and nexthop. */
	stream_putc(s, re->type);
	stream_putw(s, re->instance);
	stream_putl(s, re->flags);

	/* marker for message flags field */
	messmark = stream_get_endp(s);
	stream_putc(s, 0);

	/* Prefix. */
	psize = PSIZE(p->prefixlen);
	stream_putc(s, p->prefixlen);
	stream_write(s, (u_char *)&p->u.prefix, psize);

	if (src_p) {
		SET_FLAG(zapi_flags, ZAPI_MESSAGE_SRCPFX);
		psize = PSIZE(src_p->prefixlen);
		stream_putc(s, src_p->prefixlen);
		stream_write(s, (u_char *)&src_p->u.prefix, psize);
	}

	for (nexthop = re->nexthop; nexthop; nexthop = nexthop->next) {
		/* We don't send any nexthops when there's a multipath */
		if (re->nexthop_active_num > 1
		    && client->proto != ZEBRA_ROUTE_LDP) {
			SET_FLAG(zapi_flags, ZAPI_MESSAGE_NEXTHOP);
			SET_FLAG(zapi_flags, ZAPI_MESSAGE_IFINDEX);

			stream_putc(s, 1);
			if (p->family == AF_INET) {
				stream_put_in_addr(s, &dummy_nh.gate.ipv4);
			} else if (p->family == AF_INET6) {
				stream_write(s, (u_char *)&dummy_nh.gate.ipv6,
					     16);
			} else {
				/* We don't handle anything else now, abort */
				zlog_err(
					"%s: Unable to redistribute route of unknown family, %d\n",
					__func__, p->family);
				return -1;
			}
			stream_putc(s, 1);
			stream_putl(s, 0); /* dummy ifindex */
			break;
		}

		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)) {
			SET_FLAG(zapi_flags, ZAPI_MESSAGE_NEXTHOP);
			SET_FLAG(zapi_flags, ZAPI_MESSAGE_IFINDEX);
			if (nhnummark == 0) {
				nhnummark = stream_get_endp(s);
				stream_putc(s, 1); /* placeholder */
			}
			nhnum++;

			switch (nexthop->type) {
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				stream_put_in_addr(s, &nexthop->gate.ipv4);
				break;
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				/* Only BGP supports IPv4 prefix with IPv6 NH,
				 * so kill this */
				if (p->family == AF_INET)
					stream_put_in_addr(s,
							   &dummy_nh.gate.ipv4);
				else
					stream_write(
						s,
						(u_char *)&nexthop->gate.ipv6,
						16);
				break;
			default:
				if (cmd == ZEBRA_REDISTRIBUTE_IPV4_ADD
				    || cmd == ZEBRA_REDISTRIBUTE_IPV4_DEL) {
					struct in_addr empty;
					memset(&empty, 0,
					       sizeof(struct in_addr));
					stream_write(s, (u_char *)&empty,
						     IPV4_MAX_BYTELEN);
				} else {
					struct in6_addr empty;
					memset(&empty, 0,
					       sizeof(struct in6_addr));
					stream_write(s, (u_char *)&empty,
						     IPV6_MAX_BYTELEN);
				}
			}

			/* Interface index. */
			stream_putc(s, 1);
			stream_putl(s, nexthop->ifindex);

			/* ldpd needs all nexthops */
			if (client->proto != ZEBRA_ROUTE_LDP)
				break;
		}
	}

	/* Distance */
	SET_FLAG(zapi_flags, ZAPI_MESSAGE_DISTANCE);
	stream_putc(s, re->distance);

	/* Metric */
	SET_FLAG(zapi_flags, ZAPI_MESSAGE_METRIC);
	stream_putl(s, re->metric);

	/* Tag */
	if (re->tag) {
		SET_FLAG(zapi_flags, ZAPI_MESSAGE_TAG);
		stream_putl(s, re->tag);
	}

	/* MTU */
	SET_FLAG(zapi_flags, ZAPI_MESSAGE_MTU);
	stream_putl(s, re->mtu);

	/* write real message flags value */
	stream_putc_at(s, messmark, zapi_flags);

	/* Write next-hop number */
	if (nhnummark)
		stream_putc_at(s, nhnummark, nhnum);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zebra_server_send_message(client);
}

static int zsend_write_nexthop(struct stream *s, struct nexthop *nexthop)
{
	stream_putc(s, nexthop->type);
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		stream_put_in_addr(s, &nexthop->gate.ipv4);
		stream_putl(s, nexthop->ifindex);
		break;
	case NEXTHOP_TYPE_IPV6:
		stream_put(s, &nexthop->gate.ipv6, 16);
		break;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		stream_put(s, &nexthop->gate.ipv6, 16);
		stream_putl(s, nexthop->ifindex);
		break;
	case NEXTHOP_TYPE_IFINDEX:
		stream_putl(s, nexthop->ifindex);
		break;
	default:
		/* do nothing */
		break;
	}
	return 1;
}

/* Nexthop register */
static int zserv_rnh_register(struct zserv *client, int sock, u_short length,
			      rnh_type_t type, struct zebra_vrf *zvrf)
{
	struct rnh *rnh;
	struct stream *s;
	struct prefix p;
	u_short l = 0;
	u_char flags = 0;

	if (IS_ZEBRA_DEBUG_NHT)
		zlog_debug(
			"rnh_register msg from client %s: length=%d, type=%s\n",
			zebra_route_string(client->proto), length,
			(type == RNH_NEXTHOP_TYPE) ? "nexthop" : "route");

	s = client->ibuf;

	client->nh_reg_time = monotime(NULL);

	while (l < length) {
		flags = stream_getc(s);
		p.family = stream_getw(s);
		p.prefixlen = stream_getc(s);
		l += 4;
		if (p.family == AF_INET) {
			p.u.prefix4.s_addr = stream_get_ipv4(s);
			l += IPV4_MAX_BYTELEN;
		} else if (p.family == AF_INET6) {
			stream_get(&p.u.prefix6, s, IPV6_MAX_BYTELEN);
			l += IPV6_MAX_BYTELEN;
		} else {
			zlog_err(
				"rnh_register: Received unknown family type %d\n",
				p.family);
			return -1;
		}
		rnh = zebra_add_rnh(&p, zvrf_id(zvrf), type);
		if (type == RNH_NEXTHOP_TYPE) {
			if (flags
			    && !CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED))
				SET_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED);
			else if (!flags
				 && CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED))
				UNSET_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED);
		} else if (type == RNH_IMPORT_CHECK_TYPE) {
			if (flags
			    && !CHECK_FLAG(rnh->flags, ZEBRA_NHT_EXACT_MATCH))
				SET_FLAG(rnh->flags, ZEBRA_NHT_EXACT_MATCH);
			else if (!flags
				 && CHECK_FLAG(rnh->flags,
					       ZEBRA_NHT_EXACT_MATCH))
				UNSET_FLAG(rnh->flags, ZEBRA_NHT_EXACT_MATCH);
		}

		zebra_add_rnh_client(rnh, client, type, zvrf_id(zvrf));
		/* Anything not AF_INET/INET6 has been filtered out above */
		zebra_evaluate_rnh(zvrf_id(zvrf), p.family, 1, type, &p);
	}
	return 0;
}

/* Nexthop register */
static int zserv_rnh_unregister(struct zserv *client, int sock, u_short length,
				rnh_type_t type, struct zebra_vrf *zvrf)
{
	struct rnh *rnh;
	struct stream *s;
	struct prefix p;
	u_short l = 0;

	if (IS_ZEBRA_DEBUG_NHT)
		zlog_debug("rnh_unregister msg from client %s: length=%d\n",
			   zebra_route_string(client->proto), length);

	s = client->ibuf;

	while (l < length) {
		(void)stream_getc(
			s); // Connected or not.  Not used in this function
		p.family = stream_getw(s);
		p.prefixlen = stream_getc(s);
		l += 4;
		if (p.family == AF_INET) {
			p.u.prefix4.s_addr = stream_get_ipv4(s);
			l += IPV4_MAX_BYTELEN;
		} else if (p.family == AF_INET6) {
			stream_get(&p.u.prefix6, s, IPV6_MAX_BYTELEN);
			l += IPV6_MAX_BYTELEN;
		} else {
			zlog_err(
				"rnh_register: Received unknown family type %d\n",
				p.family);
			return -1;
		}
		rnh = zebra_lookup_rnh(&p, zvrf_id(zvrf), type);
		if (rnh) {
			client->nh_dereg_time = monotime(NULL);
			zebra_remove_rnh_client(rnh, client, type);
		}
	}
	return 0;
}

#define ZEBRA_MIN_FEC_LENGTH 5

/* FEC register */
static int zserv_fec_register(struct zserv *client, int sock, u_short length)
{
	struct stream *s;
	struct zebra_vrf *zvrf;
	u_short l = 0;
	struct prefix p;
	u_int16_t flags;
	u_int32_t label_index = MPLS_INVALID_LABEL_INDEX;

	s = client->ibuf;
	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (!zvrf)
		return 0; // unexpected

	/*
	 * The minimum amount of data that can be sent for one fec
	 * registration
	 */
	if (length < ZEBRA_MIN_FEC_LENGTH) {
		zlog_err(
			"fec_register: Received a fec register of length %d, it is of insufficient size to properly decode",
			length);
		return -1;
	}

	while (l < length) {
		flags = stream_getw(s);
		p.family = stream_getw(s);
		if (p.family != AF_INET && p.family != AF_INET6) {
			zlog_err(
				"fec_register: Received unknown family type %d\n",
				p.family);
			return -1;
		}
		p.prefixlen = stream_getc(s);
		l += 5;
		stream_get(&p.u.prefix, s, PSIZE(p.prefixlen));
		l += PSIZE(p.prefixlen);
		if (flags & ZEBRA_FEC_REGISTER_LABEL_INDEX) {
			label_index = stream_getl(s);
			l += 4;
		} else
			label_index = MPLS_INVALID_LABEL_INDEX;
		zebra_mpls_fec_register(zvrf, &p, label_index, client);
	}

	return 0;
}

/* FEC unregister */
static int zserv_fec_unregister(struct zserv *client, int sock, u_short length)
{
	struct stream *s;
	struct zebra_vrf *zvrf;
	u_short l = 0;
	struct prefix p;
	// u_int16_t flags;

	s = client->ibuf;
	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (!zvrf)
		return 0; // unexpected

	/*
	 * The minimum amount of data that can be sent for one
	 * fec unregistration
	 */
	if (length < ZEBRA_MIN_FEC_LENGTH) {
		zlog_err(
			"fec_unregister: Received a fec unregister of length %d, it is of insufficient size to properly decode",
			length);
		return -1;
	}

	while (l < length) {
		// flags = stream_getw(s);
		(void)stream_getw(s);
		p.family = stream_getw(s);
		if (p.family != AF_INET && p.family != AF_INET6) {
			zlog_err(
				"fec_unregister: Received unknown family type %d\n",
				p.family);
			return -1;
		}
		p.prefixlen = stream_getc(s);
		l += 5;
		stream_get(&p.u.prefix, s, PSIZE(p.prefixlen));
		l += PSIZE(p.prefixlen);
		zebra_mpls_fec_unregister(zvrf, &p, client);
	}

	return 0;
}

/*
  Modified version of zsend_ipv4_nexthop_lookup():
  Query unicast rib if nexthop is not found on mrib.
  Returns both route metric and protocol distance.
*/
static int zsend_ipv4_nexthop_lookup_mrib(struct zserv *client,
					  struct in_addr addr,
					  struct route_entry *re,
					  struct zebra_vrf *zvrf)
{
	struct stream *s;
	unsigned long nump;
	u_char num;
	struct nexthop *nexthop;

	/* Get output stream. */
	s = client->obuf;
	stream_reset(s);

	/* Fill in result. */
	zserv_create_header(s, ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB, zvrf_id(zvrf));
	stream_put_in_addr(s, &addr);

	if (re) {
		stream_putc(s, re->distance);
		stream_putl(s, re->metric);
		num = 0;
		nump = stream_get_endp(
			s);	/* remember position for nexthop_num */
		stream_putc(s, 0); /* reserve room for nexthop_num */
		/* Only non-recursive routes are elegible to resolve the nexthop
		 * we
		 * are looking up. Therefore, we will just iterate over the top
		 * chain of nexthops. */
		for (nexthop = re->nexthop; nexthop; nexthop = nexthop->next)
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
				num += zsend_write_nexthop(s, nexthop);

		stream_putc_at(s, nump, num); /* store nexthop_num */
	} else {
		stream_putc(s, 0); /* distance */
		stream_putl(s, 0); /* metric */
		stream_putc(s, 0); /* nexthop_num */
	}

	stream_putw_at(s, 0, stream_get_endp(s));

	return zebra_server_send_message(client);
}

/* Router-id is updated. Send ZEBRA_ROUTER_ID_ADD to client. */
int zsend_router_id_update(struct zserv *client, struct prefix *p,
			   vrf_id_t vrf_id)
{
	struct stream *s;
	int blen;

	/* Check this client need interface information. */
	if (!vrf_bitmap_check(client->ridinfo, vrf_id))
		return 0;

	s = client->obuf;
	stream_reset(s);

	/* Message type. */
	zserv_create_header(s, ZEBRA_ROUTER_ID_UPDATE, vrf_id);

	/* Prefix information. */
	stream_putc(s, p->family);
	blen = prefix_blen(p);
	stream_put(s, &p->u.prefix, blen);
	stream_putc(s, p->prefixlen);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zebra_server_send_message(client);
}

/* Register zebra server interface information.  Send current all
   interface and address information. */
static int zread_interface_add(struct zserv *client, u_short length,
			       struct zebra_vrf *zvrf)
{
	struct vrf *vrf;
	struct listnode *ifnode, *ifnnode;
	struct interface *ifp;

	/* Interface information is needed. */
	vrf_bitmap_set(client->ifinfo, zvrf_id(zvrf));

	RB_FOREACH(vrf, vrf_id_head, &vrfs_by_id)
	{
		for (ALL_LIST_ELEMENTS(vrf->iflist, ifnode, ifnnode, ifp)) {
			/* Skip pseudo interface. */
			if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE))
				continue;

			if (zsend_interface_add(client, ifp) < 0)
				return -1;

			if (zsend_interface_addresses(client, ifp) < 0)
				return -1;
		}
	}
	return 0;
}

/* Unregister zebra server interface information. */
static int zread_interface_delete(struct zserv *client, u_short length,
				  struct zebra_vrf *zvrf)
{
	vrf_bitmap_unset(client->ifinfo, zvrf_id(zvrf));
	return 0;
}

void zserv_nexthop_num_warn(const char *caller, const struct prefix *p,
			    const unsigned int nexthop_num)
{
	if (nexthop_num > multipath_num) {
		char buff[PREFIX2STR_BUFFER];
		prefix2str(p, buff, sizeof(buff));
		zlog_warn(
			"%s: Prefix %s has %d nexthops, but we can only use the first %d",
			caller, buff, nexthop_num, multipath_num);
	}
}

/* This function support multiple nexthop. */
/*
 * Parse the ZEBRA_IPV4_ROUTE_ADD sent from client. Update re and
 * add kernel route.
 */
static int zread_ipv4_add(struct zserv *client, u_short length,
			  struct zebra_vrf *zvrf)
{
	int i;
	struct route_entry *re;
	struct prefix p;
	u_char message;
	struct in_addr nhop_addr;
	u_char nexthop_num;
	u_char nexthop_type;
	struct stream *s;
	ifindex_t ifindex;
	safi_t safi;
	int ret;
	mpls_label_t label;
	struct nexthop *nexthop;

	/* Get input stream.  */
	s = client->ibuf;

	/* Allocate new re. */
	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));

	/* Type, flags, message. */
	re->type = stream_getc(s);
	re->instance = stream_getw(s);
	re->flags = stream_getl(s);
	message = stream_getc(s);
	safi = stream_getw(s);
	re->uptime = time(NULL);

	/* IPv4 prefix. */
	memset(&p, 0, sizeof(struct prefix_ipv4));
	p.family = AF_INET;
	p.prefixlen = stream_getc(s);
	stream_get(&p.u.prefix4, s, PSIZE(p.prefixlen));

	/* VRF ID */
	re->vrf_id = zvrf_id(zvrf);

	/* Nexthop parse. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_NEXTHOP)) {
		nexthop_num = stream_getc(s);
		zserv_nexthop_num_warn(__func__, (const struct prefix *)&p,
				       nexthop_num);

		for (i = 0; i < nexthop_num; i++) {
			nexthop_type = stream_getc(s);

			switch (nexthop_type) {
			case NEXTHOP_TYPE_IFINDEX:
				ifindex = stream_getl(s);
				route_entry_nexthop_ifindex_add(re, ifindex);
				break;
			case NEXTHOP_TYPE_IPV4:
				nhop_addr.s_addr = stream_get_ipv4(s);
				nexthop = route_entry_nexthop_ipv4_add(
					re, &nhop_addr, NULL);
				/* For labeled-unicast, each nexthop is followed
				 * by label. */
				if (CHECK_FLAG(message, ZAPI_MESSAGE_LABEL)) {
					label = (mpls_label_t)stream_getl(s);
					nexthop_add_labels(
						nexthop, nexthop->nh_label_type,
						1, &label);
				}
				break;
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				nhop_addr.s_addr = stream_get_ipv4(s);
				ifindex = stream_getl(s);
				route_entry_nexthop_ipv4_ifindex_add(
					re, &nhop_addr, NULL, ifindex);
				break;
			case NEXTHOP_TYPE_IPV6:
				stream_forward_getp(s, IPV6_MAX_BYTELEN);
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				route_entry_nexthop_blackhole_add(re);
				break;
			}
		}
	}

	/* Distance. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_DISTANCE))
		re->distance = stream_getc(s);

	/* Metric. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_METRIC))
		re->metric = stream_getl(s);

	/* Tag */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_TAG))
		re->tag = stream_getl(s);
	else
		re->tag = 0;

	if (CHECK_FLAG(message, ZAPI_MESSAGE_MTU))
		re->mtu = stream_getl(s);
	else
		re->mtu = 0;

	/* Table */
	re->table = zvrf->table_id;

	ret = rib_add_multipath(AFI_IP, safi, &p, NULL, re);

	/* Stats */
	if (ret > 0)
		client->v4_route_add_cnt++;
	else if (ret < 0)
		client->v4_route_upd8_cnt++;
	return 0;
}

/* Zebra server IPv4 prefix delete function. */
static int zread_ipv4_delete(struct zserv *client, u_short length,
			     struct zebra_vrf *zvrf)
{
	int i;
	struct stream *s;
	struct zapi_ipv4 api;
	struct in_addr nexthop;
	union g_addr *nexthop_p;
	unsigned long ifindex;
	struct prefix p;
	u_char nexthop_num;
	u_char nexthop_type;
	u_int32_t table_id;

	s = client->ibuf;
	ifindex = 0;
	nexthop.s_addr = 0;
	nexthop_p = NULL;

	/* Type, flags, message. */
	api.type = stream_getc(s);
	api.instance = stream_getw(s);
	api.flags = stream_getl(s);
	api.message = stream_getc(s);
	api.safi = stream_getw(s);

	/* IPv4 prefix. */
	memset(&p, 0, sizeof(struct prefix));
	p.family = AF_INET;
	p.prefixlen = stream_getc(s);
	stream_get(&p.u.prefix4, s, PSIZE(p.prefixlen));

	/* Nexthop, ifindex, distance, metric. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP)) {
		nexthop_num = stream_getc(s);

		for (i = 0; i < nexthop_num; i++) {
			nexthop_type = stream_getc(s);

			switch (nexthop_type) {
			case NEXTHOP_TYPE_IFINDEX:
				ifindex = stream_getl(s);
				break;
			case NEXTHOP_TYPE_IPV4:
				nexthop.s_addr = stream_get_ipv4(s);
				/* For labeled-unicast, each nexthop is followed
				 * by label, but
				 * we don't care for delete.
				 */
				if (CHECK_FLAG(api.message, ZAPI_MESSAGE_LABEL))
					stream_forward_getp(s,
							    sizeof(u_int32_t));
				nexthop_p = (union g_addr *)&nexthop;
				break;
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				nexthop.s_addr = stream_get_ipv4(s);
				nexthop_p = (union g_addr *)&nexthop;
				ifindex = stream_getl(s);
				break;
			case NEXTHOP_TYPE_IPV6:
				stream_forward_getp(s, IPV6_MAX_BYTELEN);
				break;
			}
		}
	}

	/* Distance. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_DISTANCE))
		api.distance = stream_getc(s);
	else
		api.distance = 0;

	/* Metric. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_METRIC))
		api.metric = stream_getl(s);
	else
		api.metric = 0;

	/* tag */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_TAG))
		api.tag = stream_getl(s);
	else
		api.tag = 0;

	table_id = zvrf->table_id;

	rib_delete(AFI_IP, api.safi, zvrf_id(zvrf), api.type, api.instance,
		   api.flags, &p, NULL, nexthop_p, ifindex, table_id);
	client->v4_route_del_cnt++;
	return 0;
}

/* MRIB Nexthop lookup for IPv4. */
static int zread_ipv4_nexthop_lookup_mrib(struct zserv *client, u_short length,
					  struct zebra_vrf *zvrf)
{
	struct in_addr addr;
	struct route_entry *re;

	addr.s_addr = stream_get_ipv4(client->ibuf);
	re = rib_match_ipv4_multicast(zvrf_id(zvrf), addr, NULL);
	return zsend_ipv4_nexthop_lookup_mrib(client, addr, re, zvrf);
}

/* Zebra server IPv6 prefix add function. */
static int zread_ipv4_route_ipv6_nexthop_add(struct zserv *client,
					     u_short length,
					     struct zebra_vrf *zvrf)
{
	unsigned int i;
	struct stream *s;
	struct in6_addr nhop_addr;
	struct route_entry *re;
	u_char message;
	u_char nexthop_num;
	u_char nexthop_type;
	struct prefix p;
	safi_t safi;
	static struct in6_addr nexthops[MULTIPATH_NUM];
	static unsigned int ifindices[MULTIPATH_NUM];
	int ret;
	static mpls_label_t labels[MULTIPATH_NUM];
	mpls_label_t label;
	struct nexthop *nexthop;

	/* Get input stream.  */
	s = client->ibuf;

	memset(&nhop_addr, 0, sizeof(struct in6_addr));

	/* Allocate new re. */
	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));

	/* Type, flags, message. */
	re->type = stream_getc(s);
	re->instance = stream_getw(s);
	re->flags = stream_getl(s);
	message = stream_getc(s);
	safi = stream_getw(s);
	re->uptime = time(NULL);

	/* IPv4 prefix. */
	memset(&p, 0, sizeof(struct prefix_ipv4));
	p.family = AF_INET;
	p.prefixlen = stream_getc(s);
	stream_get(&p.u.prefix4, s, PSIZE(p.prefixlen));

	/* VRF ID */
	re->vrf_id = zvrf_id(zvrf);

	/* We need to give nh-addr, nh-ifindex with the same next-hop object
	 * to the re to ensure that IPv6 multipathing works; need to coalesce
	 * these. Clients should send the same number of paired set of
	 * next-hop-addr/next-hop-ifindices. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_NEXTHOP)) {
		unsigned int nh_count = 0;
		unsigned int if_count = 0;
		unsigned int max_nh_if = 0;

		nexthop_num = stream_getc(s);
		zserv_nexthop_num_warn(__func__, (const struct prefix *)&p,
				       nexthop_num);
		for (i = 0; i < nexthop_num; i++) {
			nexthop_type = stream_getc(s);

			switch (nexthop_type) {
			case NEXTHOP_TYPE_IPV6:
				stream_get(&nhop_addr, s, 16);
				if (nh_count < MULTIPATH_NUM) {
					/* For labeled-unicast, each nexthop is
					 * followed by label. */
					if (CHECK_FLAG(message,
						       ZAPI_MESSAGE_LABEL)) {
						label = (mpls_label_t)
							stream_getl(s);
						labels[nh_count] = label;
					}
					nexthops[nh_count] = nhop_addr;
					nh_count++;
				}
				break;
			case NEXTHOP_TYPE_IFINDEX:
				if (if_count < multipath_num) {
					ifindices[if_count++] = stream_getl(s);
				}
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				route_entry_nexthop_blackhole_add(re);
				break;
			}
		}

		max_nh_if = (nh_count > if_count) ? nh_count : if_count;
		for (i = 0; i < max_nh_if; i++) {
			if ((i < nh_count)
			    && !IN6_IS_ADDR_UNSPECIFIED(&nexthops[i])) {
				if ((i < if_count) && ifindices[i])
					nexthop =
						route_entry_nexthop_ipv6_ifindex_add(
							re, &nexthops[i],
							ifindices[i]);
				else
					nexthop = route_entry_nexthop_ipv6_add(
						re, &nexthops[i]);

				if (CHECK_FLAG(message, ZAPI_MESSAGE_LABEL))
					nexthop_add_labels(
						nexthop, nexthop->nh_label_type,
						1, &labels[i]);
			} else {
				if ((i < if_count) && ifindices[i])
					route_entry_nexthop_ifindex_add(
						re, ifindices[i]);
			}
		}
	}

	/* Distance. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_DISTANCE))
		re->distance = stream_getc(s);

	/* Metric. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_METRIC))
		re->metric = stream_getl(s);

	/* Tag */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_TAG))
		re->tag = stream_getl(s);
	else
		re->tag = 0;

	if (CHECK_FLAG(message, ZAPI_MESSAGE_MTU))
		re->mtu = stream_getl(s);
	else
		re->mtu = 0;

	/* Table */
	re->table = zvrf->table_id;

	ret = rib_add_multipath(AFI_IP6, safi, &p, NULL, re);
	/* Stats */
	if (ret > 0)
		client->v4_route_add_cnt++;
	else if (ret < 0)
		client->v4_route_upd8_cnt++;

	return 0;
}

static int zread_ipv6_add(struct zserv *client, u_short length,
			  struct zebra_vrf *zvrf)
{
	unsigned int i;
	struct stream *s;
	struct in6_addr nhop_addr;
	struct route_entry *re;
	u_char message;
	u_char nexthop_num;
	u_char nexthop_type;
	struct prefix p;
	struct prefix_ipv6 src_p, *src_pp;
	safi_t safi;
	static struct in6_addr nexthops[MULTIPATH_NUM];
	static unsigned int ifindices[MULTIPATH_NUM];
	int ret;
	static mpls_label_t labels[MULTIPATH_NUM];
	mpls_label_t label;
	struct nexthop *nexthop;

	/* Get input stream.  */
	s = client->ibuf;

	memset(&nhop_addr, 0, sizeof(struct in6_addr));

	/* Allocate new re. */
	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));

	/* Type, flags, message. */
	re->type = stream_getc(s);
	re->instance = stream_getw(s);
	re->flags = stream_getl(s);
	message = stream_getc(s);
	safi = stream_getw(s);
	re->uptime = time(NULL);

	/* IPv6 prefix. */
	memset(&p, 0, sizeof(struct prefix_ipv6));
	p.family = AF_INET6;
	p.prefixlen = stream_getc(s);
	stream_get(&p.u.prefix6, s, PSIZE(p.prefixlen));

	if (CHECK_FLAG(message, ZAPI_MESSAGE_SRCPFX)) {
		memset(&src_p, 0, sizeof(struct prefix_ipv6));
		src_p.family = AF_INET6;
		src_p.prefixlen = stream_getc(s);
		stream_get(&src_p.prefix, s, PSIZE(src_p.prefixlen));
		src_pp = &src_p;
	} else
		src_pp = NULL;

	/* We need to give nh-addr, nh-ifindex with the same next-hop object
	 * to the re to ensure that IPv6 multipathing works; need to coalesce
	 * these. Clients should send the same number of paired set of
	 * next-hop-addr/next-hop-ifindices. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_NEXTHOP)) {
		unsigned int nh_count = 0;
		unsigned int if_count = 0;
		unsigned int max_nh_if = 0;

		nexthop_num = stream_getc(s);
		zserv_nexthop_num_warn(__func__, (const struct prefix *)&p,
				       nexthop_num);
		for (i = 0; i < nexthop_num; i++) {
			nexthop_type = stream_getc(s);

			switch (nexthop_type) {
			case NEXTHOP_TYPE_IPV6:
				stream_get(&nhop_addr, s, 16);
				if (nh_count < MULTIPATH_NUM) {
					/* For labeled-unicast, each nexthop is
					 * followed by label. */
					if (CHECK_FLAG(message,
						       ZAPI_MESSAGE_LABEL)) {
						label = (mpls_label_t)
							stream_getl(s);
						labels[nh_count] = label;
					}
					nexthops[nh_count++] = nhop_addr;
				}
				break;
			case NEXTHOP_TYPE_IFINDEX:
				if (if_count < multipath_num) {
					ifindices[if_count++] = stream_getl(s);
				}
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				route_entry_nexthop_blackhole_add(re);
				break;
			}
		}

		max_nh_if = (nh_count > if_count) ? nh_count : if_count;
		for (i = 0; i < max_nh_if; i++) {
			if ((i < nh_count)
			    && !IN6_IS_ADDR_UNSPECIFIED(&nexthops[i])) {
				if ((i < if_count) && ifindices[i])
					nexthop =
						route_entry_nexthop_ipv6_ifindex_add(
							re, &nexthops[i],
							ifindices[i]);
				else
					nexthop = route_entry_nexthop_ipv6_add(
						re, &nexthops[i]);
				if (CHECK_FLAG(message, ZAPI_MESSAGE_LABEL))
					nexthop_add_labels(
						nexthop, nexthop->nh_label_type,
						1, &labels[i]);
			} else {
				if ((i < if_count) && ifindices[i])
					route_entry_nexthop_ifindex_add(
						re, ifindices[i]);
			}
		}
	}

	/* Distance. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_DISTANCE))
		re->distance = stream_getc(s);

	/* Metric. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_METRIC))
		re->metric = stream_getl(s);

	/* Tag */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_TAG))
		re->tag = stream_getl(s);
	else
		re->tag = 0;

	if (CHECK_FLAG(message, ZAPI_MESSAGE_MTU))
		re->mtu = stream_getl(s);
	else
		re->mtu = 0;

	/* VRF ID */
	re->vrf_id = zvrf_id(zvrf);
	re->table = zvrf->table_id;

	ret = rib_add_multipath(AFI_IP6, safi, &p, src_pp, re);
	/* Stats */
	if (ret > 0)
		client->v6_route_add_cnt++;
	else if (ret < 0)
		client->v6_route_upd8_cnt++;

	return 0;
}

/* Zebra server IPv6 prefix delete function. */
static int zread_ipv6_delete(struct zserv *client, u_short length,
			     struct zebra_vrf *zvrf)
{
	int i;
	struct stream *s;
	struct zapi_ipv6 api;
	struct in6_addr nexthop;
	union g_addr *pnexthop = NULL;
	unsigned long ifindex;
	struct prefix p;
	struct prefix_ipv6 src_p, *src_pp;

	s = client->ibuf;
	ifindex = 0;
	memset(&nexthop, 0, sizeof(struct in6_addr));

	/* Type, flags, message. */
	api.type = stream_getc(s);
	api.instance = stream_getw(s);
	api.flags = stream_getl(s);
	api.message = stream_getc(s);
	api.safi = stream_getw(s);

	/* IPv4 prefix. */
	memset(&p, 0, sizeof(struct prefix_ipv6));
	p.family = AF_INET6;
	p.prefixlen = stream_getc(s);
	stream_get(&p.u.prefix6, s, PSIZE(p.prefixlen));

	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX)) {
		memset(&src_p, 0, sizeof(struct prefix_ipv6));
		src_p.family = AF_INET6;
		src_p.prefixlen = stream_getc(s);
		stream_get(&src_p.prefix, s, PSIZE(src_p.prefixlen));
		src_pp = &src_p;
	} else
		src_pp = NULL;

	/* Nexthop, ifindex, distance, metric. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP)) {
		u_char nexthop_type;

		api.nexthop_num = stream_getc(s);
		for (i = 0; i < api.nexthop_num; i++) {
			nexthop_type = stream_getc(s);

			switch (nexthop_type) {
			case NEXTHOP_TYPE_IPV6:
				stream_get(&nexthop, s, 16);
				/* For labeled-unicast, each nexthop is followed
				 * by label, but
				 * we don't care for delete.
				 */
				if (CHECK_FLAG(api.message, ZAPI_MESSAGE_LABEL))
					stream_forward_getp(s,
							    sizeof(u_int32_t));
				pnexthop = (union g_addr *)&nexthop;
				break;
			case NEXTHOP_TYPE_IFINDEX:
				ifindex = stream_getl(s);
				break;
			}
		}
	}

	/* Distance. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_DISTANCE))
		api.distance = stream_getc(s);
	else
		api.distance = 0;

	/* Metric. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_METRIC))
		api.metric = stream_getl(s);
	else
		api.metric = 0;

	/* tag */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_TAG))
		api.tag = stream_getl(s);
	else
		api.tag = 0;

	if (IN6_IS_ADDR_UNSPECIFIED(&nexthop))
		rib_delete(AFI_IP6, api.safi, zvrf_id(zvrf), api.type,
			   api.instance, api.flags, &p, src_pp, NULL, ifindex,
			   client->rtm_table);
	else
		rib_delete(AFI_IP6, api.safi, zvrf_id(zvrf), api.type,
			   api.instance, api.flags, &p, src_pp, pnexthop,
			   ifindex, client->rtm_table);

	client->v6_route_del_cnt++;
	return 0;
}

/* Register zebra server router-id information.  Send current router-id */
static int zread_router_id_add(struct zserv *client, u_short length,
			       struct zebra_vrf *zvrf)
{
	struct prefix p;

	/* Router-id information is needed. */
	vrf_bitmap_set(client->ridinfo, zvrf_id(zvrf));

	router_id_get(&p, zvrf_id(zvrf));

	return zsend_router_id_update(client, &p, zvrf_id(zvrf));
}

/* Unregister zebra server router-id information. */
static int zread_router_id_delete(struct zserv *client, u_short length,
				  struct zebra_vrf *zvrf)
{
	vrf_bitmap_unset(client->ridinfo, zvrf_id(zvrf));
	return 0;
}

/* Tie up route-type and client->sock */
static void zread_hello(struct zserv *client)
{
	/* type of protocol (lib/zebra.h) */
	u_char proto;
	u_short instance;

	proto = stream_getc(client->ibuf);
	instance = stream_getw(client->ibuf);

	/* accept only dynamic routing protocols */
	if ((proto < ZEBRA_ROUTE_MAX) && (proto > ZEBRA_ROUTE_STATIC)) {
		zlog_notice(
			"client %d says hello and bids fair to announce only %s routes",
			client->sock, zebra_route_string(proto));
		if (instance)
			zlog_notice("client protocol instance %d", instance);

		client->proto = proto;
		client->instance = instance;
	}
}

/* Unregister all information in a VRF. */
static int zread_vrf_unregister(struct zserv *client, u_short length,
				struct zebra_vrf *zvrf)
{
	int i;
	afi_t afi;

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			vrf_bitmap_unset(client->redist[afi][i], zvrf_id(zvrf));
	vrf_bitmap_unset(client->redist_default, zvrf_id(zvrf));
	vrf_bitmap_unset(client->ifinfo, zvrf_id(zvrf));
	vrf_bitmap_unset(client->ridinfo, zvrf_id(zvrf));

	return 0;
}

static void zread_mpls_labels(int command, struct zserv *client, u_short length,
			      vrf_id_t vrf_id)
{
	struct stream *s;
	enum lsp_types_t type;
	struct prefix prefix;
	enum nexthop_types_t gtype;
	union g_addr gate;
	ifindex_t ifindex;
	mpls_label_t in_label, out_label;
	u_int8_t distance;
	struct zebra_vrf *zvrf;

	zvrf = vrf_info_lookup(vrf_id);
	if (!zvrf)
		return;

	/* Get input stream.  */
	s = client->ibuf;

	/* Get data. */
	type = stream_getc(s);
	prefix.family = stream_getl(s);
	switch (prefix.family) {
	case AF_INET:
		prefix.u.prefix4.s_addr = stream_get_ipv4(s);
		prefix.prefixlen = stream_getc(s);
		gate.ipv4.s_addr = stream_get_ipv4(s);
		break;
	case AF_INET6:
		stream_get(&prefix.u.prefix6, s, 16);
		prefix.prefixlen = stream_getc(s);
		stream_get(&gate.ipv6, s, 16);
		break;
	default:
		return;
	}
	ifindex = stream_getl(s);
	distance = stream_getc(s);
	in_label = stream_getl(s);
	out_label = stream_getl(s);

	switch (prefix.family) {
	case AF_INET:
		if (ifindex)
			gtype = NEXTHOP_TYPE_IPV4_IFINDEX;
		else
			gtype = NEXTHOP_TYPE_IPV4;
		break;
	case AF_INET6:
		if (ifindex)
			gtype = NEXTHOP_TYPE_IPV6_IFINDEX;
		else
			gtype = NEXTHOP_TYPE_IPV6;
		break;
	default:
		return;
	}

	if (!mpls_enabled)
		return;

	if (command == ZEBRA_MPLS_LABELS_ADD) {
		mpls_lsp_install(zvrf, type, in_label, out_label, gtype, &gate,
				 ifindex);
		if (out_label != MPLS_IMP_NULL_LABEL)
			mpls_ftn_update(1, zvrf, type, &prefix, gtype, &gate,
					ifindex, distance, out_label);
	} else if (command == ZEBRA_MPLS_LABELS_DELETE) {
		mpls_lsp_uninstall(zvrf, type, in_label, gtype, &gate, ifindex);
		if (out_label != MPLS_IMP_NULL_LABEL)
			mpls_ftn_update(0, zvrf, type, &prefix, gtype, &gate,
					ifindex, distance, out_label);
	}
}
/* Send response to a label manager connect request to client */
static int zsend_label_manager_connect_response(struct zserv *client,
						vrf_id_t vrf_id, u_short result)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, ZEBRA_LABEL_MANAGER_CONNECT, vrf_id);

	/* result */
	stream_putc(s, result);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return writen(client->sock, s->data, stream_get_endp(s));
}

static void zread_label_manager_connect(struct zserv *client, vrf_id_t vrf_id)
{
	struct stream *s;
	/* type of protocol (lib/zebra.h) */
	u_char proto;
	u_short instance;

	/* Get input stream.  */
	s = client->ibuf;

	/* Get data. */
	proto = stream_getc(s);
	instance = stream_getw(s);

	/* accept only dynamic routing protocols */
	if ((proto >= ZEBRA_ROUTE_MAX) || (proto <= ZEBRA_ROUTE_STATIC)) {
		zlog_err("client %d has wrong protocol %s", client->sock,
			 zebra_route_string(proto));
		zsend_label_manager_connect_response(client, vrf_id, 1);
		return;
	}
	zlog_notice("client %d with instance %u connected as %s", client->sock,
		    instance, zebra_route_string(proto));
	client->proto = proto;
	client->instance = instance;

	/*
	  Release previous labels of same protocol and instance.
	  This is done in case it restarted from an unexpected shutdown.
	*/
	release_daemon_chunks(proto, instance);

	zlog_debug(
		" Label Manager client connected: sock %d, proto %s, instance %u",
		client->sock, zebra_route_string(proto), instance);
	/* send response back */
	zsend_label_manager_connect_response(client, vrf_id, 0);
}
/* Send response to a get label chunk request to client */
static int zsend_assign_label_chunk_response(struct zserv *client,
					     vrf_id_t vrf_id,
					     struct label_manager_chunk *lmc)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zserv_create_header(s, ZEBRA_GET_LABEL_CHUNK, vrf_id);

	if (lmc) {
		/* keep */
		stream_putc(s, lmc->keep);
		/* start and end labels */
		stream_putl(s, lmc->start);
		stream_putl(s, lmc->end);
	}

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return writen(client->sock, s->data, stream_get_endp(s));
}

static void zread_get_label_chunk(struct zserv *client, vrf_id_t vrf_id)
{
	struct stream *s;
	u_char keep;
	uint32_t size;
	struct label_manager_chunk *lmc;

	/* Get input stream.  */
	s = client->ibuf;

	/* Get data. */
	keep = stream_getc(s);
	size = stream_getl(s);

	lmc = assign_label_chunk(client->proto, client->instance, keep, size);
	if (!lmc)
		zlog_err("%s: Unable to assign Label Chunk of size %u",
			 __func__, size);
	else
		zlog_debug("Assigned Label Chunk %u - %u to %u", lmc->start,
			   lmc->end, keep);
	/* send response back */
	zsend_assign_label_chunk_response(client, vrf_id, lmc);
}

static void zread_release_label_chunk(struct zserv *client)
{
	struct stream *s;
	uint32_t start, end;

	/* Get input stream.  */
	s = client->ibuf;

	/* Get data. */
	start = stream_getl(s);
	end = stream_getl(s);

	release_label_chunk(client->proto, client->instance, start, end);
}
static void zread_label_manager_request(int cmd, struct zserv *client,
					vrf_id_t vrf_id)
{
	/* to avoid sending other messages like ZERBA_INTERFACE_UP */
	if (cmd == ZEBRA_LABEL_MANAGER_CONNECT)
		client->is_synchronous = 1;

	/* external label manager */
	if (lm_is_external)
		zread_relay_label_manager_request(cmd, client, vrf_id);
	/* this is a label manager */
	else {
		if (cmd == ZEBRA_LABEL_MANAGER_CONNECT)
			zread_label_manager_connect(client, vrf_id);
		else {
			/* Sanity: don't allow 'unidentified' requests */
			if (!client->proto) {
				zlog_err(
					"Got label request from an unidentified client");
				return;
			}
			if (cmd == ZEBRA_GET_LABEL_CHUNK)
				zread_get_label_chunk(client, vrf_id);
			else if (cmd == ZEBRA_RELEASE_LABEL_CHUNK)
				zread_release_label_chunk(client);
		}
	}
}

/* Cleanup registered nexthops (across VRFs) upon client disconnect. */
static void zebra_client_close_cleanup_rnh(struct zserv *client)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH(vrf, vrf_id_head, &vrfs_by_id)
	{
		if ((zvrf = vrf->info) != NULL) {
			zebra_cleanup_rnh_client(zvrf_id(zvrf), AF_INET, client,
						 RNH_NEXTHOP_TYPE);
			zebra_cleanup_rnh_client(zvrf_id(zvrf), AF_INET6,
						 client, RNH_NEXTHOP_TYPE);
			zebra_cleanup_rnh_client(zvrf_id(zvrf), AF_INET, client,
						 RNH_IMPORT_CHECK_TYPE);
			zebra_cleanup_rnh_client(zvrf_id(zvrf), AF_INET6,
						 client, RNH_IMPORT_CHECK_TYPE);
			if (client->proto == ZEBRA_ROUTE_LDP) {
				hash_iterate(zvrf->lsp_table,
					     mpls_ldp_lsp_uninstall_all,
					     zvrf->lsp_table);
				mpls_ldp_ftn_uninstall_all(zvrf, AFI_IP);
				mpls_ldp_ftn_uninstall_all(zvrf, AFI_IP6);
			}
		}
	}
}

/* Close zebra client. */
static void zebra_client_close(struct zserv *client)
{
	/* Send client de-registration to BFD */
	zebra_ptm_bfd_client_deregister(client->proto);

	/* Cleanup any registered nexthops - across all VRFs. */
	zebra_client_close_cleanup_rnh(client);

	/* Release Label Manager chunks */
	release_daemon_chunks(client->proto, client->instance);

	/* Cleanup any FECs registered by this client. */
	zebra_mpls_cleanup_fecs_for_client(vrf_info_lookup(VRF_DEFAULT),
					   client);

	/* Close file descriptor. */
	if (client->sock) {
		unsigned long nroutes;

		close(client->sock);
		nroutes = rib_score_proto(client->proto, client->instance);
		zlog_notice(
			"client %d disconnected. %lu %s routes removed from the rib",
			client->sock, nroutes,
			zebra_route_string(client->proto));
		client->sock = -1;
	}

	/* Free stream buffers. */
	if (client->ibuf)
		stream_free(client->ibuf);
	if (client->obuf)
		stream_free(client->obuf);
	if (client->wb)
		buffer_free(client->wb);

	/* Release threads. */
	if (client->t_read)
		thread_cancel(client->t_read);
	if (client->t_write)
		thread_cancel(client->t_write);
	if (client->t_suicide)
		thread_cancel(client->t_suicide);

	/* Free bitmaps. */
	for (afi_t afi = AFI_IP; afi < AFI_MAX; afi++)
		for (int i = 0; i < ZEBRA_ROUTE_MAX; i++)
			vrf_bitmap_free(client->redist[afi][i]);

	vrf_bitmap_free(client->redist_default);
	vrf_bitmap_free(client->ifinfo);
	vrf_bitmap_free(client->ridinfo);

	/* Free client structure. */
	listnode_delete(zebrad.client_list, client);
	XFREE(MTYPE_TMP, client);
}

/* Make new client. */
static void zebra_client_create(int sock)
{
	struct zserv *client;
	int i;
	afi_t afi;

	client = XCALLOC(MTYPE_TMP, sizeof(struct zserv));

	/* Make client input/output buffer. */
	client->sock = sock;
	client->ibuf = stream_new(ZEBRA_MAX_PACKET_SIZ);
	client->obuf = stream_new(ZEBRA_MAX_PACKET_SIZ);
	client->wb = buffer_new(0);

	/* Set table number. */
	client->rtm_table = zebrad.rtm_table_default;

	client->connect_time = monotime(NULL);
	/* Initialize flags */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			client->redist[afi][i] = vrf_bitmap_init();
	client->redist_default = vrf_bitmap_init();
	client->ifinfo = vrf_bitmap_init();
	client->ridinfo = vrf_bitmap_init();

	/* by default, it's not a synchronous client */
	client->is_synchronous = 0;

	/* Add this client to linked list. */
	listnode_add(zebrad.client_list, client);

	/* Make new read thread. */
	zebra_event(ZEBRA_READ, sock, client);

	zebra_vrf_update_all(client);
}

/* Handler of zebra service request. */
static int zebra_client_read(struct thread *thread)
{
	int sock;
	struct zserv *client;
	size_t already;
	uint16_t length, command;
	uint8_t marker, version;
	vrf_id_t vrf_id;
	struct zebra_vrf *zvrf;

	/* Get thread data.  Reset reading thread because I'm running. */
	sock = THREAD_FD(thread);
	client = THREAD_ARG(thread);
	client->t_read = NULL;

	if (client->t_suicide) {
		zebra_client_close(client);
		return -1;
	}

	/* Read length and command (if we don't have it already). */
	if ((already = stream_get_endp(client->ibuf)) < ZEBRA_HEADER_SIZE) {
		ssize_t nbyte;
		if (((nbyte = stream_read_try(client->ibuf, sock,
					      ZEBRA_HEADER_SIZE - already))
		     == 0)
		    || (nbyte == -1)) {
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("connection closed socket [%d]",
					   sock);
			zebra_client_close(client);
			return -1;
		}
		if (nbyte != (ssize_t)(ZEBRA_HEADER_SIZE - already)) {
			/* Try again later. */
			zebra_event(ZEBRA_READ, sock, client);
			return 0;
		}
		already = ZEBRA_HEADER_SIZE;
	}

	/* Reset to read from the beginning of the incoming packet. */
	stream_set_getp(client->ibuf, 0);

	/* Fetch header values */
	length = stream_getw(client->ibuf);
	marker = stream_getc(client->ibuf);
	version = stream_getc(client->ibuf);
	vrf_id = stream_getw(client->ibuf);
	command = stream_getw(client->ibuf);

	if (marker != ZEBRA_HEADER_MARKER || version != ZSERV_VERSION) {
		zlog_err(
			"%s: socket %d version mismatch, marker %d, version %d",
			__func__, sock, marker, version);
		zebra_client_close(client);
		return -1;
	}
	if (length < ZEBRA_HEADER_SIZE) {
		zlog_warn(
			"%s: socket %d message length %u is less than header size %d",
			__func__, sock, length, ZEBRA_HEADER_SIZE);
		zebra_client_close(client);
		return -1;
	}
	if (length > STREAM_SIZE(client->ibuf)) {
		zlog_warn(
			"%s: socket %d message length %u exceeds buffer size %lu",
			__func__, sock, length,
			(u_long)STREAM_SIZE(client->ibuf));
		zebra_client_close(client);
		return -1;
	}

	/* Read rest of data. */
	if (already < length) {
		ssize_t nbyte;
		if (((nbyte = stream_read_try(client->ibuf, sock,
					      length - already))
		     == 0)
		    || (nbyte == -1)) {
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug(
					"connection closed [%d] when reading zebra data",
					sock);
			zebra_client_close(client);
			return -1;
		}
		if (nbyte != (ssize_t)(length - already)) {
			/* Try again later. */
			zebra_event(ZEBRA_READ, sock, client);
			return 0;
		}
	}

	length -= ZEBRA_HEADER_SIZE;

	/* Debug packet information. */
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("zebra message comes from socket [%d]", sock);

	if (IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV)
		zlog_debug("zebra message received [%s] %d in VRF %u",
			   zserv_command_string(command), length, vrf_id);

	client->last_read_time = monotime(NULL);
	client->last_read_cmd = command;

	zvrf = zebra_vrf_lookup_by_id(vrf_id);
	if (!zvrf) {
		if (IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV)
			zlog_debug("zebra received unknown VRF[%u]", vrf_id);
		goto zclient_read_out;
	}

	switch (command) {
	case ZEBRA_ROUTER_ID_ADD:
		zread_router_id_add(client, length, zvrf);
		break;
	case ZEBRA_ROUTER_ID_DELETE:
		zread_router_id_delete(client, length, zvrf);
		break;
	case ZEBRA_INTERFACE_ADD:
		zread_interface_add(client, length, zvrf);
		break;
	case ZEBRA_INTERFACE_DELETE:
		zread_interface_delete(client, length, zvrf);
		break;
	case ZEBRA_IPV4_ROUTE_ADD:
		zread_ipv4_add(client, length, zvrf);
		break;
	case ZEBRA_IPV4_ROUTE_DELETE:
		zread_ipv4_delete(client, length, zvrf);
		break;
	case ZEBRA_IPV4_ROUTE_IPV6_NEXTHOP_ADD:
		zread_ipv4_route_ipv6_nexthop_add(client, length, zvrf);
		break;
	case ZEBRA_IPV4_NEXTHOP_ADD:
		zread_ipv4_add(client, length,
			       zvrf); /* LB: r1.0 merge - id was 1 */
		break;
	case ZEBRA_IPV4_NEXTHOP_DELETE:
		zread_ipv4_delete(client, length,
				  zvrf); /* LB: r1.0 merge - id was 1 */
		break;
	case ZEBRA_IPV6_ROUTE_ADD:
		zread_ipv6_add(client, length, zvrf);
		break;
	case ZEBRA_IPV6_ROUTE_DELETE:
		zread_ipv6_delete(client, length, zvrf);
		break;
	case ZEBRA_REDISTRIBUTE_ADD:
		zebra_redistribute_add(command, client, length, zvrf);
		break;
	case ZEBRA_REDISTRIBUTE_DELETE:
		zebra_redistribute_delete(command, client, length, zvrf);
		break;
	case ZEBRA_REDISTRIBUTE_DEFAULT_ADD:
		zebra_redistribute_default_add(command, client, length, zvrf);
		break;
	case ZEBRA_REDISTRIBUTE_DEFAULT_DELETE:
		zebra_redistribute_default_delete(command, client, length,
						  zvrf);
		break;
	case ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB:
		zread_ipv4_nexthop_lookup_mrib(client, length, zvrf);
		break;
	case ZEBRA_HELLO:
		zread_hello(client);
		break;
	case ZEBRA_NEXTHOP_REGISTER:
		zserv_rnh_register(client, sock, length, RNH_NEXTHOP_TYPE,
				   zvrf);
		break;
	case ZEBRA_NEXTHOP_UNREGISTER:
		zserv_rnh_unregister(client, sock, length, RNH_NEXTHOP_TYPE,
				     zvrf);
		break;
	case ZEBRA_IMPORT_ROUTE_REGISTER:
		zserv_rnh_register(client, sock, length, RNH_IMPORT_CHECK_TYPE,
				   zvrf);
		break;
	case ZEBRA_IMPORT_ROUTE_UNREGISTER:
		zserv_rnh_unregister(client, sock, length,
				     RNH_IMPORT_CHECK_TYPE, zvrf);
		break;
	case ZEBRA_BFD_DEST_UPDATE:
	case ZEBRA_BFD_DEST_REGISTER:
		zebra_ptm_bfd_dst_register(client, sock, length, command, zvrf);
		break;
	case ZEBRA_BFD_DEST_DEREGISTER:
		zebra_ptm_bfd_dst_deregister(client, sock, length, zvrf);
		break;
	case ZEBRA_VRF_UNREGISTER:
		zread_vrf_unregister(client, length, zvrf);
		break;
	case ZEBRA_BFD_CLIENT_REGISTER:
		zebra_ptm_bfd_client_register(client, sock, length);
		break;
	case ZEBRA_INTERFACE_ENABLE_RADV:
#if defined(HAVE_RTADV)
		zebra_interface_radv_set(client, sock, length, zvrf, 1);
#endif
		break;
	case ZEBRA_INTERFACE_DISABLE_RADV:
#if defined(HAVE_RTADV)
		zebra_interface_radv_set(client, sock, length, zvrf, 0);
#endif
		break;
	case ZEBRA_MPLS_LABELS_ADD:
	case ZEBRA_MPLS_LABELS_DELETE:
		zread_mpls_labels(command, client, length, vrf_id);
		break;
	case ZEBRA_IPMR_ROUTE_STATS:
		zebra_ipmr_route_stats(client, sock, length, zvrf);
		break;
	case ZEBRA_LABEL_MANAGER_CONNECT:
	case ZEBRA_GET_LABEL_CHUNK:
	case ZEBRA_RELEASE_LABEL_CHUNK:
		zread_label_manager_request(command, client, vrf_id);
		break;
	case ZEBRA_FEC_REGISTER:
		zserv_fec_register(client, sock, length);
		break;
	case ZEBRA_FEC_UNREGISTER:
		zserv_fec_unregister(client, sock, length);
		break;
	case ZEBRA_ADVERTISE_ALL_VNI:
		zebra_vxlan_advertise_all_vni(client, sock, length, zvrf);
		break;
	case ZEBRA_REMOTE_VTEP_ADD:
		zebra_vxlan_remote_vtep_add(client, sock, length, zvrf);
		break;
	case ZEBRA_REMOTE_VTEP_DEL:
		zebra_vxlan_remote_vtep_del(client, sock, length, zvrf);
		break;
	case ZEBRA_REMOTE_MACIP_ADD:
		zebra_vxlan_remote_macip_add(client, sock, length, zvrf);
		break;
	case ZEBRA_REMOTE_MACIP_DEL:
		zebra_vxlan_remote_macip_del(client, sock, length, zvrf);
		break;
	default:
		zlog_info("Zebra received unknown command %d", command);
		break;
	}

	if (client->t_suicide) {
		/* No need to wait for thread callback, just kill immediately.
		 */
		zebra_client_close(client);
		return -1;
	}

zclient_read_out:
	stream_reset(client->ibuf);
	zebra_event(ZEBRA_READ, sock, client);
	return 0;
}


/* Accept code of zebra server socket. */
static int zebra_accept(struct thread *thread)
{
	int accept_sock;
	int client_sock;
	struct sockaddr_in client;
	socklen_t len;

	accept_sock = THREAD_FD(thread);

	/* Reregister myself. */
	zebra_event(ZEBRA_SERV, accept_sock, NULL);

	len = sizeof(struct sockaddr_in);
	client_sock = accept(accept_sock, (struct sockaddr *)&client, &len);

	if (client_sock < 0) {
		zlog_warn("Can't accept zebra socket: %s",
			  safe_strerror(errno));
		return -1;
	}

	/* Make client socket non-blocking.  */
	set_nonblocking(client_sock);

	/* Create new zebra client. */
	zebra_client_create(client_sock);

	return 0;
}

#ifdef HAVE_TCP_ZEBRA
/* Make zebra's server socket. */
static void zebra_serv()
{
	int ret;
	int accept_sock;
	struct sockaddr_in addr;

	accept_sock = socket(AF_INET, SOCK_STREAM, 0);

	if (accept_sock < 0) {
		zlog_warn("Can't create zserv stream socket: %s",
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provice full functionality due to above error");
		return;
	}

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(ZEBRA_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sockopt_reuseaddr(accept_sock);
	sockopt_reuseport(accept_sock);

	if (zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("Can't raise privileges");

	ret = bind(accept_sock, (struct sockaddr *)&addr,
		   sizeof(struct sockaddr_in));
	if (ret < 0) {
		zlog_warn("Can't bind to stream socket: %s",
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provice full functionality due to above error");
		close(accept_sock); /* Avoid sd leak. */
		return;
	}

	if (zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges");

	ret = listen(accept_sock, 1);
	if (ret < 0) {
		zlog_warn("Can't listen to stream socket: %s",
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provice full functionality due to above error");
		close(accept_sock); /* Avoid sd leak. */
		return;
	}

	zebra_event(ZEBRA_SERV, accept_sock, NULL);
}
#else /* HAVE_TCP_ZEBRA */

/* For sockaddr_un. */
#include <sys/un.h>

/* zebra server UNIX domain socket. */
static void zebra_serv_un(const char *path)
{
	int ret;
	int sock, len;
	struct sockaddr_un serv;
	mode_t old_mask;

	/* First of all, unlink existing socket */
	unlink(path);

	/* Set umask */
	old_mask = umask(0077);

	/* Make UNIX domain socket. */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		zlog_warn("Can't create zserv unix socket: %s",
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provide full functionality due to above error");
		return;
	}

	/* Make server socket. */
	memset(&serv, 0, sizeof(struct sockaddr_un));
	serv.sun_family = AF_UNIX;
	strncpy(serv.sun_path, path, strlen(path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = serv.sun_len = SUN_LEN(&serv);
#else
	len = sizeof(serv.sun_family) + strlen(serv.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	ret = bind(sock, (struct sockaddr *)&serv, len);
	if (ret < 0) {
		zlog_warn("Can't bind to unix socket %s: %s", path,
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provide full functionality due to above error");
		close(sock);
		return;
	}

	ret = listen(sock, 5);
	if (ret < 0) {
		zlog_warn("Can't listen to unix socket %s: %s", path,
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provide full functionality due to above error");
		close(sock);
		return;
	}

	umask(old_mask);

	zebra_event(ZEBRA_SERV, sock, NULL);
}
#endif /* HAVE_TCP_ZEBRA */


static void zebra_event(enum event event, int sock, struct zserv *client)
{
	switch (event) {
	case ZEBRA_SERV:
		thread_add_read(zebrad.master, zebra_accept, client, sock,
				NULL);
		break;
	case ZEBRA_READ:
		client->t_read = NULL;
		thread_add_read(zebrad.master, zebra_client_read, client, sock,
				&client->t_read);
		break;
	case ZEBRA_WRITE:
		/**/
		break;
	}
}

#define ZEBRA_TIME_BUF 32
static char *zserv_time_buf(time_t *time1, char *buf, int buflen)
{
	struct tm *tm;
	time_t now;

	assert(buf != NULL);
	assert(buflen >= ZEBRA_TIME_BUF);
	assert(time1 != NULL);

	if (!*time1) {
		snprintf(buf, buflen, "never   ");
		return (buf);
	}

	now = monotime(NULL);
	now -= *time1;
	tm = gmtime(&now);

/* Making formatted timer strings. */
#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

	if (now < ONE_DAY_SECOND)
		snprintf(buf, buflen, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min,
			 tm->tm_sec);
	else if (now < ONE_WEEK_SECOND)
		snprintf(buf, buflen, "%dd%02dh%02dm", tm->tm_yday, tm->tm_hour,
			 tm->tm_min);
	else
		snprintf(buf, buflen, "%02dw%dd%02dh", tm->tm_yday / 7,
			 tm->tm_yday - ((tm->tm_yday / 7) * 7), tm->tm_hour);
	return buf;
}

static void zebra_show_client_detail(struct vty *vty, struct zserv *client)
{
	char cbuf[ZEBRA_TIME_BUF], rbuf[ZEBRA_TIME_BUF];
	char wbuf[ZEBRA_TIME_BUF], nhbuf[ZEBRA_TIME_BUF], mbuf[ZEBRA_TIME_BUF];

	vty_out(vty, "Client: %s", zebra_route_string(client->proto));
	if (client->instance)
		vty_out(vty, " Instance: %d", client->instance);
	vty_out(vty, "\n");

	vty_out(vty, "------------------------ \n");
	vty_out(vty, "FD: %d \n", client->sock);
	vty_out(vty, "Route Table ID: %d \n", client->rtm_table);

	vty_out(vty, "Connect Time: %s \n",
		zserv_time_buf(&client->connect_time, cbuf, ZEBRA_TIME_BUF));
	if (client->nh_reg_time) {
		vty_out(vty, "Nexthop Registry Time: %s \n",
			zserv_time_buf(&client->nh_reg_time, nhbuf,
				       ZEBRA_TIME_BUF));
		if (client->nh_last_upd_time)
			vty_out(vty, "Nexthop Last Update Time: %s \n",
				zserv_time_buf(&client->nh_last_upd_time, mbuf,
					       ZEBRA_TIME_BUF));
		else
			vty_out(vty, "No Nexthop Update sent\n");
	} else
		vty_out(vty, "Not registered for Nexthop Updates\n");

	vty_out(vty, "Last Msg Rx Time: %s \n",
		zserv_time_buf(&client->last_read_time, rbuf, ZEBRA_TIME_BUF));
	vty_out(vty, "Last Msg Tx Time: %s \n",
		zserv_time_buf(&client->last_write_time, wbuf, ZEBRA_TIME_BUF));
	if (client->last_read_time)
		vty_out(vty, "Last Rcvd Cmd: %s \n",
			zserv_command_string(client->last_read_cmd));
	if (client->last_write_time)
		vty_out(vty, "Last Sent Cmd: %s \n",
			zserv_command_string(client->last_write_cmd));
	vty_out(vty, "\n");

	vty_out(vty, "Type        Add        Update     Del \n");
	vty_out(vty, "================================================== \n");
	vty_out(vty, "IPv4        %-12d%-12d%-12d\n", client->v4_route_add_cnt,
		client->v4_route_upd8_cnt, client->v4_route_del_cnt);
	vty_out(vty, "IPv6        %-12d%-12d%-12d\n", client->v6_route_add_cnt,
		client->v6_route_upd8_cnt, client->v6_route_del_cnt);
	vty_out(vty, "Redist:v4   %-12d%-12d%-12d\n", client->redist_v4_add_cnt,
		0, client->redist_v4_del_cnt);
	vty_out(vty, "Redist:v6   %-12d%-12d%-12d\n", client->redist_v6_add_cnt,
		0, client->redist_v6_del_cnt);
	vty_out(vty, "Connected   %-12d%-12d%-12d\n", client->ifadd_cnt, 0,
		client->ifdel_cnt);
	vty_out(vty, "BFD peer    %-12d%-12d%-12d\n", client->bfd_peer_add_cnt,
		client->bfd_peer_upd8_cnt, client->bfd_peer_del_cnt);
	vty_out(vty, "Interface Up Notifications: %d\n", client->ifup_cnt);
	vty_out(vty, "Interface Down Notifications: %d\n", client->ifdown_cnt);
	vty_out(vty, "VNI add notifications: %d\n", client->vniadd_cnt);
	vty_out(vty, "VNI delete notifications: %d\n", client->vnidel_cnt);
	vty_out(vty, "MAC-IP add notifications: %d\n", client->macipadd_cnt);
	vty_out(vty, "MAC-IP delete notifications: %d\n", client->macipdel_cnt);

	vty_out(vty, "\n");
	return;
}

static void zebra_show_client_brief(struct vty *vty, struct zserv *client)
{
	char cbuf[ZEBRA_TIME_BUF], rbuf[ZEBRA_TIME_BUF];
	char wbuf[ZEBRA_TIME_BUF];

	vty_out(vty, "%-8s%12s %12s%12s%8d/%-8d%8d/%-8d\n",
		zebra_route_string(client->proto),
		zserv_time_buf(&client->connect_time, cbuf, ZEBRA_TIME_BUF),
		zserv_time_buf(&client->last_read_time, rbuf, ZEBRA_TIME_BUF),
		zserv_time_buf(&client->last_write_time, wbuf, ZEBRA_TIME_BUF),
		client->v4_route_add_cnt + client->v4_route_upd8_cnt,
		client->v4_route_del_cnt,
		client->v6_route_add_cnt + client->v6_route_upd8_cnt,
		client->v6_route_del_cnt);
}

struct zserv *zebra_find_client(u_char proto)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	for (ALL_LIST_ELEMENTS(zebrad.client_list, node, nnode, client)) {
		if (client->proto == proto)
			return client;
	}

	return NULL;
}

#ifdef HAVE_NETLINK
/* Display default rtm_table for all clients. */
DEFUN (show_table,
       show_table_cmd,
       "show table",
       SHOW_STR
       "default routing table to use for all clients\n")
{
	vty_out(vty, "table %d\n", zebrad.rtm_table_default);
	return CMD_SUCCESS;
}

DEFUN (config_table,
       config_table_cmd,
       "table TABLENO",
       "Configure target kernel routing table\n"
       "TABLE integer\n")
{
	zebrad.rtm_table_default = strtol(argv[1]->arg, (char **)0, 10);
	return CMD_SUCCESS;
}

DEFUN (no_config_table,
       no_config_table_cmd,
       "no table [TABLENO]",
       NO_STR
       "Configure target kernel routing table\n"
       "TABLE integer\n")
{
	zebrad.rtm_table_default = 0;
	return CMD_SUCCESS;
}
#endif

DEFUN (ip_forwarding,
       ip_forwarding_cmd,
       "ip forwarding",
       IP_STR
       "Turn on IP forwarding")
{
	int ret;

	ret = ipforward();
	if (ret == 0)
		ret = ipforward_on();

	if (ret == 0) {
		vty_out(vty, "Can't turn on IP forwarding\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_ip_forwarding,
       no_ip_forwarding_cmd,
       "no ip forwarding",
       NO_STR
       IP_STR
       "Turn off IP forwarding")
{
	int ret;

	ret = ipforward();
	if (ret != 0)
		ret = ipforward_off();

	if (ret != 0) {
		vty_out(vty, "Can't turn off IP forwarding\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (show_zebra,
       show_zebra_cmd,
       "show zebra",
       SHOW_STR
       "Zebra information\n")
{
	struct vrf *vrf;

	vty_out(vty,
		"                            Route      Route      Neighbor   LSP        LSP\n");
	vty_out(vty,
		"VRF                         Installs   Removals    Updates   Installs   Removals\n");
	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name)
	{
		struct zebra_vrf *zvrf = vrf->info;
		vty_out(vty,
			"%-25s %10" PRIu64 " %10" PRIu64 " %10" PRIu64
			" %10" PRIu64 " %10" PRIu64 "\n",
			vrf->name, zvrf->installs, zvrf->removals,
			zvrf->neigh_updates, zvrf->lsp_installs,
			zvrf->lsp_removals);
	}

	return CMD_SUCCESS;
}

/* This command is for debugging purpose. */
DEFUN (show_zebra_client,
       show_zebra_client_cmd,
       "show zebra client",
       SHOW_STR
       "Zebra information\n"
       "Client information\n")
{
	struct listnode *node;
	struct zserv *client;

	for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
		zebra_show_client_detail(vty, client);

	return CMD_SUCCESS;
}

/* This command is for debugging purpose. */
DEFUN (show_zebra_client_summary,
       show_zebra_client_summary_cmd,
       "show zebra client summary",
       SHOW_STR
       "Zebra information brief\n"
       "Client information brief\n"
       "Brief Summary\n")
{
	struct listnode *node;
	struct zserv *client;

	vty_out(vty,
		"Name    Connect Time    Last Read  Last Write  IPv4 Routes       IPv6 Routes    \n");
	vty_out(vty,
		"--------------------------------------------------------------------------------\n");

	for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
		zebra_show_client_brief(vty, client);

	vty_out(vty, "Routes column shows (added+updated)/deleted\n");
	return CMD_SUCCESS;
}

/* Table configuration write function. */
static int config_write_table(struct vty *vty)
{
	if (zebrad.rtm_table_default)
		vty_out(vty, "table %d\n", zebrad.rtm_table_default);
	return 0;
}

/* table node for routing tables. */
static struct cmd_node table_node = {TABLE_NODE,
				     "", /* This node has no interface. */
				     1};

/* Only display ip forwarding is enabled or not. */
DEFUN (show_ip_forwarding,
       show_ip_forwarding_cmd,
       "show ip forwarding",
       SHOW_STR
       IP_STR
       "IP forwarding status\n")
{
	int ret;

	ret = ipforward();

	if (ret == 0)
		vty_out(vty, "IP forwarding is off\n");
	else
		vty_out(vty, "IP forwarding is on\n");
	return CMD_SUCCESS;
}

/* Only display ipv6 forwarding is enabled or not. */
DEFUN (show_ipv6_forwarding,
       show_ipv6_forwarding_cmd,
       "show ipv6 forwarding",
       SHOW_STR
       "IPv6 information\n"
       "Forwarding status\n")
{
	int ret;

	ret = ipforward_ipv6();

	switch (ret) {
	case -1:
		vty_out(vty, "ipv6 forwarding is unknown\n");
		break;
	case 0:
		vty_out(vty, "ipv6 forwarding is %s\n", "off");
		break;
	case 1:
		vty_out(vty, "ipv6 forwarding is %s\n", "on");
		break;
	default:
		vty_out(vty, "ipv6 forwarding is %s\n", "off");
		break;
	}
	return CMD_SUCCESS;
}

DEFUN (ipv6_forwarding,
       ipv6_forwarding_cmd,
       "ipv6 forwarding",
       IPV6_STR
       "Turn on IPv6 forwarding")
{
	int ret;

	ret = ipforward_ipv6();
	if (ret == 0)
		ret = ipforward_ipv6_on();

	if (ret == 0) {
		vty_out(vty, "Can't turn on IPv6 forwarding\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_forwarding,
       no_ipv6_forwarding_cmd,
       "no ipv6 forwarding",
       NO_STR
       IPV6_STR
       "Turn off IPv6 forwarding")
{
	int ret;

	ret = ipforward_ipv6();
	if (ret != 0)
		ret = ipforward_ipv6_off();

	if (ret != 0) {
		vty_out(vty, "Can't turn off IPv6 forwarding\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

/* IPForwarding configuration write function. */
static int config_write_forwarding(struct vty *vty)
{
	/* FIXME: Find better place for that. */
	router_id_write(vty);

	if (!ipforward())
		vty_out(vty, "no ip forwarding\n");
	if (!ipforward_ipv6())
		vty_out(vty, "no ipv6 forwarding\n");
	vty_out(vty, "!\n");
	return 0;
}

/* table node for routing tables. */
static struct cmd_node forwarding_node = {FORWARDING_NODE,
					  "", /* This node has no interface. */
					  1};

/* Initialisation of zebra and installation of commands. */
void zebra_init(void)
{
	/* Client list init. */
	zebrad.client_list = list_new();

	/* Install configuration write function. */
	install_node(&table_node, config_write_table);
	install_node(&forwarding_node, config_write_forwarding);

	install_element(VIEW_NODE, &show_ip_forwarding_cmd);
	install_element(CONFIG_NODE, &ip_forwarding_cmd);
	install_element(CONFIG_NODE, &no_ip_forwarding_cmd);
	install_element(ENABLE_NODE, &show_zebra_cmd);
	install_element(ENABLE_NODE, &show_zebra_client_cmd);
	install_element(ENABLE_NODE, &show_zebra_client_summary_cmd);

#ifdef HAVE_NETLINK
	install_element(VIEW_NODE, &show_table_cmd);
	install_element(CONFIG_NODE, &config_table_cmd);
	install_element(CONFIG_NODE, &no_config_table_cmd);
#endif /* HAVE_NETLINK */

	install_element(VIEW_NODE, &show_ipv6_forwarding_cmd);
	install_element(CONFIG_NODE, &ipv6_forwarding_cmd);
	install_element(CONFIG_NODE, &no_ipv6_forwarding_cmd);

	/* Route-map */
	zebra_route_map_init();
}

/* Make zebra server socket, wiping any existing one (see bug #403). */
void zebra_zserv_socket_init(char *path)
{
#ifdef HAVE_TCP_ZEBRA
	zebra_serv();
#else
	zebra_serv_un(path ? path : ZEBRA_SERV_PATH);
#endif /* HAVE_TCP_ZEBRA */
}
