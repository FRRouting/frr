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
#include <sys/un.h>

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
#include "libfrr.h"
#include "sockopt.h"

#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/router-id.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/zebra_rnh.h"
#include "zebra/rt_netlink.h"
#include "zebra/interface.h"
#include "zebra/zebra_ptm.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_mroute.h"
#include "zebra/label_manager.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/rt.h"

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

	zclient_create_header(s, ZEBRA_INTERFACE_ADD, ifp->vrf_id);
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

	zclient_create_header(s, ZEBRA_INTERFACE_DELETE, ifp->vrf_id);
	zserv_encode_interface(s, ifp);

	client->ifdel_cnt++;
	return zebra_server_send_message(client);
}

int zsend_vrf_add(struct zserv *client, struct zebra_vrf *zvrf)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_VRF_ADD, zvrf_id(zvrf));
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

	zclient_create_header(s, ZEBRA_VRF_DELETE, zvrf_id(zvrf));
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

	zclient_create_header(s, ZEBRA_INTERFACE_LINK_PARAMS, ifp->vrf_id);

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

	zclient_create_header(s, cmd, ifp->vrf_id);
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

	zclient_create_header(s, cmd, ifp->vrf_id);
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

	zclient_create_header(s, ZEBRA_INTERFACE_VRF_UPDATE, ifp->vrf_id);

	/* Fill in the ifIndex of the interface and its new VRF (id) */
	stream_putl(s, ifp->ifindex);
	stream_putl(s, vrf_id);

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

	zclient_create_header(s, cmd, ifp->vrf_id);
	zserv_encode_interface(s, ifp);

	if (cmd == ZEBRA_INTERFACE_UP)
		client->ifup_cnt++;
	else
		client->ifdown_cnt++;

	return zebra_server_send_message(client);
}

int zsend_redistribute_route(int cmd, struct zserv *client, struct prefix *p,
			     struct prefix *src_p, struct route_entry *re)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct nexthop *nexthop;
	int count = 0;

	memset(&api, 0, sizeof(api));
	api.vrf_id = re->vrf_id;
	api.nh_vrf_id = re->nh_vrf_id;
	api.type = re->type;
	api.instance = re->instance;
	api.flags = re->flags;

	/* Prefix. */
	api.prefix = *p;
	if (src_p) {
		SET_FLAG(api.message, ZAPI_MESSAGE_SRCPFX);
		memcpy(&api.src_prefix, src_p, sizeof(api.src_prefix));
	}

	/* Nexthops. */
	if (re->nexthop_active_num) {
		SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
		api.nexthop_num = re->nexthop_active_num;
	}
	for (nexthop = re->nexthop; nexthop; nexthop = nexthop->next) {
		if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
			continue;

		api_nh = &api.nexthops[count];
		api_nh->type = nexthop->type;
		switch (nexthop->type) {
		case NEXTHOP_TYPE_BLACKHOLE:
			api_nh->bh_type = nexthop->bh_type;
			break;
		case NEXTHOP_TYPE_IPV4:
			api_nh->gate.ipv4 = nexthop->gate.ipv4;
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			api_nh->gate.ipv4 = nexthop->gate.ipv4;
			api_nh->ifindex = nexthop->ifindex;
			break;
		case NEXTHOP_TYPE_IFINDEX:
			api_nh->ifindex = nexthop->ifindex;
			break;
		case NEXTHOP_TYPE_IPV6:
			api_nh->gate.ipv6 = nexthop->gate.ipv6;
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			api_nh->gate.ipv6 = nexthop->gate.ipv6;
			api_nh->ifindex = nexthop->ifindex;
		}
		count++;
	}

	/* Attributes. */
	SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
	api.distance = re->distance;
	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = re->metric;
	if (re->tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = re->tag;
	}
	SET_FLAG(api.message, ZAPI_MESSAGE_MTU);
	api.mtu = re->mtu;

	/* Encode route and send. */
	if (zapi_route_encode(cmd, client->obuf, &api) < 0)
		return -1;
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
static int zserv_rnh_register(struct zserv *client, u_short length,
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
		STREAM_GETC(s, flags);
		STREAM_GETW(s, p.family);
		STREAM_GETC(s, p.prefixlen);
		l += 4;
		if (p.family == AF_INET) {
			if (p.prefixlen > IPV4_MAX_BITLEN) {
				zlog_warn("%s: Specified prefix length %d is too large for a v4 address",
					  __PRETTY_FUNCTION__, p.prefixlen);
				return -1;
			}
			STREAM_GET(&p.u.prefix4.s_addr, s, IPV4_MAX_BYTELEN);
			l += IPV4_MAX_BYTELEN;
		} else if (p.family == AF_INET6) {
			if (p.prefixlen > IPV6_MAX_BITLEN) {
				zlog_warn("%s: Specified prefix length %d is to large for a v6 address",
					  __PRETTY_FUNCTION__, p.prefixlen);
				return -1;
			}
			STREAM_GET(&p.u.prefix6, s, IPV6_MAX_BYTELEN);
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
			else if (!flags && CHECK_FLAG(rnh->flags,
						      ZEBRA_NHT_EXACT_MATCH))
				UNSET_FLAG(rnh->flags, ZEBRA_NHT_EXACT_MATCH);
		}

		zebra_add_rnh_client(rnh, client, type, zvrf_id(zvrf));
		/* Anything not AF_INET/INET6 has been filtered out above */
		zebra_evaluate_rnh(zvrf_id(zvrf), p.family, 1, type, &p);
	}

stream_failure:
	return 0;
}

/* Nexthop register */
static int zserv_rnh_unregister(struct zserv *client, u_short length,
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
		uint8_t flags;

		STREAM_GETC(s, flags);
		if (flags != 0)
			goto stream_failure;

		STREAM_GETW(s, p.family);
		STREAM_GETC(s, p.prefixlen);
		l += 4;
		if (p.family == AF_INET) {
			if (p.prefixlen > IPV4_MAX_BITLEN) {
				zlog_warn("%s: Specified prefix length %d is to large for a v4 address",
					  __PRETTY_FUNCTION__, p.prefixlen);
				return -1;
			}
			STREAM_GET(&p.u.prefix4.s_addr, s, IPV4_MAX_BYTELEN);
			l += IPV4_MAX_BYTELEN;
		} else if (p.family == AF_INET6) {
			if (p.prefixlen > IPV6_MAX_BITLEN) {
				zlog_warn("%s: Specified prefix length %d is to large for a v6 address",
					  __PRETTY_FUNCTION__, p.prefixlen);
				return -1;
			}
			STREAM_GET(&p.u.prefix6, s, IPV6_MAX_BYTELEN);
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
stream_failure:
	return 0;
}

#define ZEBRA_MIN_FEC_LENGTH 5

/* FEC register */
static int zserv_fec_register(struct zserv *client, u_short length)
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
		STREAM_GETW(s, flags);
		memset(&p, 0, sizeof(p));
		STREAM_GETW(s, p.family);
		if (p.family != AF_INET && p.family != AF_INET6) {
			zlog_err(
				"fec_register: Received unknown family type %d\n",
				p.family);
			return -1;
		}
		STREAM_GETC(s, p.prefixlen);
		if ((p.family == AF_INET && p.prefixlen > IPV4_MAX_BITLEN) ||
		    (p.family == AF_INET6 && p.prefixlen > IPV6_MAX_BITLEN)) {
			zlog_warn("%s: Specified prefix length: %d is to long for %d",
				  __PRETTY_FUNCTION__, p.prefixlen, p.family);
			return -1;
		}
		l += 5;
		STREAM_GET(&p.u.prefix, s, PSIZE(p.prefixlen));
		l += PSIZE(p.prefixlen);
		if (flags & ZEBRA_FEC_REGISTER_LABEL_INDEX) {
			STREAM_GETL(s, label_index);
			l += 4;
		} else
			label_index = MPLS_INVALID_LABEL_INDEX;
		zebra_mpls_fec_register(zvrf, &p, label_index, client);
	}

stream_failure:
	return 0;
}

/* FEC unregister */
static int zserv_fec_unregister(struct zserv *client, u_short length)
{
	struct stream *s;
	struct zebra_vrf *zvrf;
	u_short l = 0;
	struct prefix p;
	uint16_t flags;

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
		STREAM_GETW(s, flags);
		if (flags != 0)
			goto stream_failure;

		memset(&p, 0, sizeof(p));
		STREAM_GETW(s, p.family);
		if (p.family != AF_INET && p.family != AF_INET6) {
			zlog_err(
				"fec_unregister: Received unknown family type %d\n",
				p.family);
			return -1;
		}
		STREAM_GETC(s, p.prefixlen);
		if ((p.family == AF_INET && p.prefixlen > IPV4_MAX_BITLEN) ||
		    (p.family == AF_INET6 && p.prefixlen > IPV6_MAX_BITLEN)) {
			zlog_warn("%s: Received prefix length %d which is greater than %d can support",
				  __PRETTY_FUNCTION__, p.prefixlen, p.family);
			return -1;
		}
		l += 5;
		STREAM_GET(&p.u.prefix, s, PSIZE(p.prefixlen));
		l += PSIZE(p.prefixlen);
		zebra_mpls_fec_unregister(zvrf, &p, client);
	}

stream_failure:
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
	zclient_create_header(s, ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB, zvrf_id(zvrf));
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

int zsend_route_notify_owner(u_char proto, u_short instance,
			     vrf_id_t vrf_id, struct prefix *p,
			     enum zapi_route_notify_owner note)
{
	struct zserv *client;
	struct stream *s;
	uint8_t blen;

	client = zebra_find_client(proto, instance);
	if (!client || !client->notify_owner) {
		if (IS_ZEBRA_DEBUG_PACKET) {
			char buff[PREFIX_STRLEN];

			zlog_debug("Not Notifying Owner: %u about prefix %s",
				   proto, prefix2str(p, buff, sizeof(buff)));
		}
		return 0;
	}

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_ROUTE_NOTIFY_OWNER, vrf_id);

	stream_put(s, &note, sizeof(note));

	stream_putc(s, p->family);

	blen = prefix_blen(p);
	stream_putc(s, p->prefixlen);
	stream_put(s, &p->u.prefix, blen);

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
	zclient_create_header(s, ZEBRA_ROUTER_ID_UPDATE, vrf_id);

	/* Prefix information. */
	stream_putc(s, p->family);
	blen = prefix_blen(p);
	stream_put(s, &p->u.prefix, blen);
	stream_putc(s, p->prefixlen);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zebra_server_send_message(client);
}

/*
 * Function used by Zebra to send a PW status update to LDP daemon
 */
int zsend_pw_update(struct zserv *client, struct zebra_pw *pw)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_PW_STATUS_UPDATE, pw->vrf_id);
	stream_write(s, pw->ifname, IF_NAMESIZE);
	stream_putl(s, pw->ifindex);
	stream_putl(s, pw->status);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zebra_server_send_message(client);
}

/* Register zebra server interface information.  Send current all
   interface and address information. */
static int zread_interface_add(struct zserv *client, u_short length,
			       struct zebra_vrf *zvrf)
{
	struct vrf *vrf;
	struct interface *ifp;

	/* Interface information is needed. */
	vrf_bitmap_set(client->ifinfo, zvrf_id(zvrf));

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		FOR_ALL_INTERFACES (vrf, ifp) {
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

static int zread_route_add(struct zserv *client, u_short length,
			   struct zebra_vrf *zvrf)
{
	struct stream *s;
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	afi_t afi;
	struct prefix_ipv6 *src_p = NULL;
	struct route_entry *re;
	struct nexthop *nexthop = NULL;
	int i, ret;
	vrf_id_t vrf_id = 0;

	s = client->ibuf;
	if (zapi_route_decode(s, &api) < 0)
		return -1;

	/* Allocate new route. */
	vrf_id = zvrf_id(zvrf);
	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));
	re->type = api.type;
	re->instance = api.instance;
	re->flags = api.flags;
	re->uptime = time(NULL);
	re->vrf_id = vrf_id;
	re->nh_vrf_id = api.nh_vrf_id;
	re->table = zvrf->table_id;

	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP)) {
		for (i = 0; i < api.nexthop_num; i++) {
			api_nh = &api.nexthops[i];
			ifindex_t ifindex = 0;

			switch (api_nh->type) {
			case NEXTHOP_TYPE_IFINDEX:
				nexthop = route_entry_nexthop_ifindex_add(
					re, api_nh->ifindex);
				break;
			case NEXTHOP_TYPE_IPV4:
				nexthop = route_entry_nexthop_ipv4_add(
					re, &api_nh->gate.ipv4, NULL);
				break;
			case NEXTHOP_TYPE_IPV4_IFINDEX: {

				struct ipaddr vtep_ip;

				memset(&vtep_ip, 0, sizeof(struct ipaddr));
				if (CHECK_FLAG(api.flags,
					       ZEBRA_FLAG_EVPN_ROUTE)) {
					ifindex =
						get_l3vni_svi_ifindex(vrf_id);
				} else {
					ifindex = api_nh->ifindex;
				}

				nexthop = route_entry_nexthop_ipv4_ifindex_add(
					re, &api_nh->gate.ipv4, NULL,
					ifindex);

				/* if this an EVPN route entry,
				   program the nh as neigh
				 */
				if (CHECK_FLAG(api.flags,
					       ZEBRA_FLAG_EVPN_ROUTE)) {
					SET_FLAG(nexthop->flags,
						 NEXTHOP_FLAG_EVPN_RVTEP);
					vtep_ip.ipa_type = IPADDR_V4;
					memcpy(&(vtep_ip.ipaddr_v4),
					       &(api_nh->gate.ipv4),
					       sizeof(struct in_addr));
					zebra_vxlan_evpn_vrf_route_add(
								vrf_id,
								&api.rmac,
								&vtep_ip,
								&api.prefix);
				}
				break;
			}
			case NEXTHOP_TYPE_IPV6:
				nexthop = route_entry_nexthop_ipv6_add(
					re, &api_nh->gate.ipv6);
				break;
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				nexthop = route_entry_nexthop_ipv6_ifindex_add(
					re, &api_nh->gate.ipv6,
					api_nh->ifindex);
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				nexthop = route_entry_nexthop_blackhole_add(
					re, api_nh->bh_type);
				break;
			}

			if (!nexthop) {
				zlog_warn("%s: Nexthops Specified: %d but we failed to properly create one",
					  __PRETTY_FUNCTION__, api.nexthop_num);
				nexthops_free(re->nexthop);
				XFREE(MTYPE_RE, re);
				return -1;
			}
			/* MPLS labels for BGP-LU or Segment Routing */
			if (CHECK_FLAG(api.message, ZAPI_MESSAGE_LABEL)
			    && api_nh->type != NEXTHOP_TYPE_IFINDEX
			    && api_nh->type != NEXTHOP_TYPE_BLACKHOLE) {
				enum lsp_types_t label_type;

				label_type =
					lsp_type_from_re_type(client->proto);
				nexthop_add_labels(nexthop, label_type,
						   api_nh->label_num,
						   &api_nh->labels[0]);
			}
		}
	}

	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_DISTANCE))
		re->distance = api.distance;
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_METRIC))
		re->metric = api.metric;
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_TAG))
		re->tag = api.tag;
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_MTU))
		re->mtu = api.mtu;

	afi = family2afi(api.prefix.family);
	if (afi != AFI_IP6 && CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX)) {
		zlog_warn("%s: Received SRC Prefix but afi is not v6",
			  __PRETTY_FUNCTION__);
		nexthops_free(re->nexthop);
		XFREE(MTYPE_RE, re);
		return -1;
	}
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		src_p = &api.src_prefix;

	ret = rib_add_multipath(afi, api.safi, &api.prefix, src_p, re);

	/* Stats */
	switch (api.prefix.family) {
	case AF_INET:
		if (ret > 0)
			client->v4_route_add_cnt++;
		else if (ret < 0)
			client->v4_route_upd8_cnt++;
		break;
	case AF_INET6:
		if (ret > 0)
			client->v6_route_add_cnt++;
		else if (ret < 0)
			client->v6_route_upd8_cnt++;
		break;
	}

	return 0;
}

static int zread_route_del(struct zserv *client, u_short length,
			   struct zebra_vrf *zvrf)
{
	struct stream *s;
	struct zapi_route api;
	afi_t afi;
	struct prefix_ipv6 *src_p = NULL;

	s = client->ibuf;
	if (zapi_route_decode(s, &api) < 0)
		return -1;

	afi = family2afi(api.prefix.family);
	if (afi != AFI_IP6 && CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX)) {
		zlog_warn("%s: Received a src prefix while afi is not v6",
			  __PRETTY_FUNCTION__);
		return -1;
	}
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		src_p = &api.src_prefix;

	rib_delete(afi, api.safi, zvrf_id(zvrf), api.type, api.instance,
		   api.flags, &api.prefix, src_p, NULL, zvrf->table_id,
		   api.metric, false, &api.rmac);

	/* Stats */
	switch (api.prefix.family) {
	case AF_INET:
		client->v4_route_del_cnt++;
		break;
	case AF_INET6:
		client->v6_route_del_cnt++;
		break;
	}

	return 0;
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
	enum lsp_types_t label_type = ZEBRA_LSP_NONE;
	mpls_label_t label;
	struct nexthop *nexthop;
	enum blackhole_type bh_type = BLACKHOLE_NULL;

	/* Get input stream.  */
	s = client->ibuf;

	/* Allocate new re. */
	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));

	/* Type, flags, message. */
	STREAM_GETC(s, re->type);
	if (re->type > ZEBRA_ROUTE_MAX) {
		zlog_warn("%s: Specified route type %d is not a legal value\n",
			  __PRETTY_FUNCTION__, re->type);
		XFREE(MTYPE_RE, re);
		return -1;
	}
	STREAM_GETW(s, re->instance);
	STREAM_GETL(s, re->flags);
	STREAM_GETC(s, message);
	STREAM_GETW(s, safi);
	re->uptime = time(NULL);

	/* IPv4 prefix. */
	memset(&p, 0, sizeof(struct prefix_ipv4));
	p.family = AF_INET;
	STREAM_GETC(s, p.prefixlen);
	if (p.prefixlen > IPV4_MAX_BITLEN) {
		zlog_warn("%s: Specified prefix length %d is greater than what v4 can be",
			  __PRETTY_FUNCTION__, p.prefixlen);
		XFREE(MTYPE_RE, re);
		return -1;
	}
	STREAM_GET(&p.u.prefix4, s, PSIZE(p.prefixlen));

	/* VRF ID */
	re->vrf_id = zvrf_id(zvrf);
	re->nh_vrf_id = zvrf_id(zvrf);

	/* Nexthop parse. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_NEXTHOP)) {
		STREAM_GETC(s, nexthop_num);
		zserv_nexthop_num_warn(__func__, (const struct prefix *)&p,
				       nexthop_num);

		if (CHECK_FLAG(message, ZAPI_MESSAGE_LABEL))
			label_type = lsp_type_from_re_type(client->proto);

		for (i = 0; i < nexthop_num; i++) {
			STREAM_GETC(s, nexthop_type);

			switch (nexthop_type) {
			case NEXTHOP_TYPE_IFINDEX:
				STREAM_GETL(s, ifindex);
				route_entry_nexthop_ifindex_add(re, ifindex);
				break;
			case NEXTHOP_TYPE_IPV4:
				STREAM_GET(&nhop_addr.s_addr, s,
					   IPV4_MAX_BYTELEN);
				nexthop = route_entry_nexthop_ipv4_add(
					re, &nhop_addr, NULL);
				/* For labeled-unicast, each nexthop is followed
				 * by label. */
				if (CHECK_FLAG(message, ZAPI_MESSAGE_LABEL)) {
					STREAM_GETL(s, label);
					nexthop_add_labels(nexthop, label_type,
							   1, &label);
				}
				break;
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				STREAM_GET(&nhop_addr.s_addr, s,
					   IPV4_MAX_BYTELEN);
				STREAM_GETL(s, ifindex);
				route_entry_nexthop_ipv4_ifindex_add(
					re, &nhop_addr, NULL, ifindex);
				break;
			case NEXTHOP_TYPE_IPV6:
				zlog_warn("%s: Please use ZEBRA_ROUTE_ADD if you want to pass v6 nexthops",
					  __PRETTY_FUNCTION__);
				nexthops_free(re->nexthop);
				XFREE(MTYPE_RE, re);
				return -1;
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				route_entry_nexthop_blackhole_add(re, bh_type);
				break;
			default:
				zlog_warn("%s: Specified nexthop type: %d does not exist",
					  __PRETTY_FUNCTION__, nexthop_type);
				nexthops_free(re->nexthop);
				XFREE(MTYPE_RE, re);
				return -1;
			}
		}
	}

	/* Distance. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_DISTANCE))
		STREAM_GETC(s, re->distance);

	/* Metric. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_METRIC))
		STREAM_GETL(s, re->metric);

	/* Tag */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_TAG))
		STREAM_GETL(s, re->tag);
	else
		re->tag = 0;

	if (CHECK_FLAG(message, ZAPI_MESSAGE_MTU))
		STREAM_GETL(s, re->mtu);
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

stream_failure:
	nexthops_free(re->nexthop);
	XFREE(MTYPE_RE, re);
	return -1;
}

/* Zebra server IPv4 prefix delete function. */
static int zread_ipv4_delete(struct zserv *client, u_short length,
			     struct zebra_vrf *zvrf)
{
	struct stream *s;
	struct zapi_ipv4 api;
	struct prefix p;
	u_int32_t table_id;

	s = client->ibuf;

	/* Type, flags, message. */
	STREAM_GETC(s, api.type);
	STREAM_GETW(s, api.instance);
	STREAM_GETL(s, api.flags);
	STREAM_GETC(s, api.message);
	STREAM_GETW(s, api.safi);

	/* IPv4 prefix. */
	memset(&p, 0, sizeof(struct prefix));
	p.family = AF_INET;
	STREAM_GETC(s, p.prefixlen);
	if (p.prefixlen > IPV4_MAX_BITLEN) {
		zlog_warn("%s: Passed in prefixlen %d is impossible",
			  __PRETTY_FUNCTION__, p.prefixlen);
		return -1;
	}
	STREAM_GET(&p.u.prefix4, s, PSIZE(p.prefixlen));

	table_id = zvrf->table_id;

	rib_delete(AFI_IP, api.safi, zvrf_id(zvrf), api.type, api.instance,
		   api.flags, &p, NULL, NULL, table_id, 0, false, NULL);
	client->v4_route_del_cnt++;

stream_failure:
	return 0;
}

/* MRIB Nexthop lookup for IPv4. */
static int zread_ipv4_nexthop_lookup_mrib(struct zserv *client, u_short length,
					  struct zebra_vrf *zvrf)
{
	struct in_addr addr;
	struct route_entry *re;

	STREAM_GET(&addr.s_addr, client->ibuf, IPV4_MAX_BYTELEN);
	re = rib_match_ipv4_multicast(zvrf_id(zvrf), addr, NULL);
	return zsend_ipv4_nexthop_lookup_mrib(client, addr, re, zvrf);

stream_failure:
	return -1;
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
	enum lsp_types_t label_type = ZEBRA_LSP_NONE;
	mpls_label_t label;
	struct nexthop *nexthop;
	enum blackhole_type bh_type = BLACKHOLE_NULL;

	/* Get input stream.  */
	s = client->ibuf;

	memset(&nhop_addr, 0, sizeof(struct in6_addr));

	/* Allocate new re. */
	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));

	/* Type, flags, message. */
	STREAM_GETC(s, re->type);
	if (re->type > ZEBRA_ROUTE_MAX) {
		zlog_warn("%s: Specified route type: %d is not a legal value\n",
			  __PRETTY_FUNCTION__, re->type);
		XFREE(MTYPE_RE, re);
		return -1;
	}
	STREAM_GETW(s, re->instance);
	STREAM_GETL(s, re->flags);
	STREAM_GETC(s, message);
	STREAM_GETW(s, safi);
	re->uptime = time(NULL);

	/* IPv4 prefix. */
	memset(&p, 0, sizeof(struct prefix_ipv4));
	p.family = AF_INET;
	STREAM_GETC(s, p.prefixlen);
	if (p.prefixlen > IPV4_MAX_BITLEN) {
		zlog_warn("%s: Prefix Length %d is greater than what a v4 address can use",
			  __PRETTY_FUNCTION__, p.prefixlen);
		XFREE(MTYPE_RE, re);
		return -1;
	}
	STREAM_GET(&p.u.prefix4, s, PSIZE(p.prefixlen));

	/* VRF ID */
	re->vrf_id = zvrf_id(zvrf);
	re->nh_vrf_id = zvrf_id(zvrf);

	/* We need to give nh-addr, nh-ifindex with the same next-hop object
	 * to the re to ensure that IPv6 multipathing works; need to coalesce
	 * these. Clients should send the same number of paired set of
	 * next-hop-addr/next-hop-ifindices. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_NEXTHOP)) {
		unsigned int nh_count = 0;
		unsigned int if_count = 0;
		unsigned int max_nh_if = 0;

		STREAM_GETC(s, nexthop_num);
		zserv_nexthop_num_warn(__func__, (const struct prefix *)&p,
				       nexthop_num);

		if (CHECK_FLAG(message, ZAPI_MESSAGE_LABEL))
			label_type = lsp_type_from_re_type(client->proto);

		for (i = 0; i < nexthop_num; i++) {
			STREAM_GETC(s, nexthop_type);

			switch (nexthop_type) {
			case NEXTHOP_TYPE_IPV6:
				STREAM_GET(&nhop_addr, s, 16);
				if (nh_count < MULTIPATH_NUM) {
					/* For labeled-unicast, each nexthop is
					 * followed by label. */
					if (CHECK_FLAG(message,
						       ZAPI_MESSAGE_LABEL)) {
						STREAM_GETL(s, label);
						labels[nh_count] = label;
					}
					nexthops[nh_count] = nhop_addr;
					nh_count++;
				}
				break;
			case NEXTHOP_TYPE_IFINDEX:
				if (if_count < multipath_num) {
					STREAM_GETL(s, ifindices[if_count++]);
				}
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				route_entry_nexthop_blackhole_add(re, bh_type);
				break;
			default:
				zlog_warn("%s: Please use ZEBRA_ROUTE_ADD if you want to pass non v6 nexthops",
					  __PRETTY_FUNCTION__);
				nexthops_free(re->nexthop);
				XFREE(MTYPE_RE, re);
				return -1;
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
					nexthop_add_labels(nexthop, label_type,
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
		STREAM_GETC(s, re->distance);

	/* Metric. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_METRIC))
		STREAM_GETL(s, re->metric);

	/* Tag */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_TAG))
		STREAM_GETL(s, re->tag);
	else
		re->tag = 0;

	if (CHECK_FLAG(message, ZAPI_MESSAGE_MTU))
		STREAM_GETL(s, re->mtu);
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

stream_failure:
	nexthops_free(re->nexthop);
	XFREE(MTYPE_RE, re);
	return -1;
}

static int zread_ipv6_add(struct zserv *client, u_short length,
			  struct zebra_vrf *zvrf)
{
	unsigned int i;
	struct stream *s;
	struct in6_addr nhop_addr;
	ifindex_t ifindex;
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
	enum lsp_types_t label_type = ZEBRA_LSP_NONE;
	mpls_label_t label;
	struct nexthop *nexthop;
	enum blackhole_type bh_type = BLACKHOLE_NULL;

	/* Get input stream.  */
	s = client->ibuf;

	memset(&nhop_addr, 0, sizeof(struct in6_addr));

	/* Allocate new re. */
	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));

	/* Type, flags, message. */
	STREAM_GETC(s, re->type);
	if (re->type > ZEBRA_ROUTE_MAX) {
		zlog_warn("%s: Specified route type: %d is not a legal value\n",
			  __PRETTY_FUNCTION__, re->type);
		XFREE(MTYPE_RE, re);
		return -1;
	}
	STREAM_GETW(s, re->instance);
	STREAM_GETL(s, re->flags);
	STREAM_GETC(s, message);
	STREAM_GETW(s, safi);
	re->uptime = time(NULL);

	/* IPv6 prefix. */
	memset(&p, 0, sizeof(p));
	p.family = AF_INET6;
	STREAM_GETC(s, p.prefixlen);
	if (p.prefixlen > IPV6_MAX_BITLEN) {
		zlog_warn("%s: Specified prefix length %d is to large for v6 prefix",
			  __PRETTY_FUNCTION__, p.prefixlen);
		XFREE(MTYPE_RE, re);
		return -1;
	}
	STREAM_GET(&p.u.prefix6, s, PSIZE(p.prefixlen));

	if (CHECK_FLAG(message, ZAPI_MESSAGE_SRCPFX)) {
		memset(&src_p, 0, sizeof(src_p));
		src_p.family = AF_INET6;
		STREAM_GETC(s, src_p.prefixlen);
		if (src_p.prefixlen > IPV6_MAX_BITLEN) {
			zlog_warn("%s: Specified src prefix length %d is to large for v6 prefix",
				  __PRETTY_FUNCTION__, src_p.prefixlen);
			XFREE(MTYPE_RE, re);
			return -1;
		}
		STREAM_GET(&src_p.prefix, s, PSIZE(src_p.prefixlen));
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

		STREAM_GETC(s, nexthop_num);
		zserv_nexthop_num_warn(__func__, (const struct prefix *)&p,
				       nexthop_num);

		if (CHECK_FLAG(message, ZAPI_MESSAGE_LABEL))
			label_type = lsp_type_from_re_type(client->proto);

		for (i = 0; i < nexthop_num; i++) {
			STREAM_GETC(s, nexthop_type);

			switch (nexthop_type) {
			case NEXTHOP_TYPE_IPV6:
				STREAM_GET(&nhop_addr, s, 16);
				if (nh_count < MULTIPATH_NUM) {
					/* For labeled-unicast, each nexthop is
					 * followed by label. */
					if (CHECK_FLAG(message,
						       ZAPI_MESSAGE_LABEL)) {
						STREAM_GETL(s, label);
						labels[nh_count] = label;
					}
					nexthops[nh_count++] = nhop_addr;
				}
				break;
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				STREAM_GET(&nhop_addr, s, 16);
				STREAM_GETL(s, ifindex);
				route_entry_nexthop_ipv6_ifindex_add(
					re, &nhop_addr, ifindex);
				break;
			case NEXTHOP_TYPE_IFINDEX:
				if (if_count < multipath_num) {
					STREAM_GETL(s, ifindices[if_count++]);
				}
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				route_entry_nexthop_blackhole_add(re, bh_type);
				break;
			default:
				zlog_warn("%s: Please use ZEBRA_ROUTE_ADD if you want to pass non v6 nexthops",
					  __PRETTY_FUNCTION__);
				nexthops_free(re->nexthop);
				XFREE(MTYPE_RE, re);
				return -1;
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
					nexthop_add_labels(nexthop, label_type,
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
		STREAM_GETC(s, re->distance);

	/* Metric. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_METRIC))
		STREAM_GETL(s, re->metric);

	/* Tag */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_TAG))
		STREAM_GETL(s, re->tag);
	else
		re->tag = 0;

	if (CHECK_FLAG(message, ZAPI_MESSAGE_MTU))
		STREAM_GETL(s, re->mtu);
	else
		re->mtu = 0;

	/* VRF ID */
	re->vrf_id = zvrf_id(zvrf);
	re->nh_vrf_id = zvrf_id(zvrf);

	re->table = zvrf->table_id;

	ret = rib_add_multipath(AFI_IP6, safi, &p, src_pp, re);
	/* Stats */
	if (ret > 0)
		client->v6_route_add_cnt++;
	else if (ret < 0)
		client->v6_route_upd8_cnt++;

	return 0;

stream_failure:
	nexthops_free(re->nexthop);
	XFREE(MTYPE_RE, re);

	return -1;
}

/* Zebra server IPv6 prefix delete function. */
static int zread_ipv6_delete(struct zserv *client, u_short length,
			     struct zebra_vrf *zvrf)
{
	struct stream *s;
	struct zapi_ipv6 api;
	struct prefix p;
	struct prefix_ipv6 src_p, *src_pp;

	s = client->ibuf;

	/* Type, flags, message. */
	STREAM_GETC(s, api.type);
	STREAM_GETW(s, api.instance);
	STREAM_GETL(s, api.flags);
	STREAM_GETC(s, api.message);
	STREAM_GETW(s, api.safi);

	/* IPv4 prefix. */
	memset(&p, 0, sizeof(struct prefix));
	p.family = AF_INET6;
	STREAM_GETC(s, p.prefixlen);
	STREAM_GET(&p.u.prefix6, s, PSIZE(p.prefixlen));

	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX)) {
		memset(&src_p, 0, sizeof(struct prefix_ipv6));
		src_p.family = AF_INET6;
		STREAM_GETC(s, src_p.prefixlen);
		STREAM_GET(&src_p.prefix, s, PSIZE(src_p.prefixlen));
		src_pp = &src_p;
	} else
		src_pp = NULL;

	rib_delete(AFI_IP6, api.safi, zvrf_id(zvrf), api.type, api.instance,
		   api.flags, &p, src_pp, NULL, client->rtm_table, 0, false,
		   NULL);

	client->v6_route_del_cnt++;

stream_failure:
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
	u_char notify;

	STREAM_GETC(client->ibuf, proto);
	STREAM_GETW(client->ibuf, instance);
	STREAM_GETC(client->ibuf, notify);
	if (notify)
		client->notify_owner = true;

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

stream_failure:
	return;
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
			      struct zebra_vrf *zvrf)
{
	struct stream *s;
	enum lsp_types_t type;
	struct prefix prefix;
	enum nexthop_types_t gtype;
	union g_addr gate;
	ifindex_t ifindex;
	mpls_label_t in_label, out_label;
	u_int8_t distance;

	/* Get input stream.  */
	s = client->ibuf;

	/* Get data. */
	STREAM_GETC(s, type);
	STREAM_GETL(s, prefix.family);
	switch (prefix.family) {
	case AF_INET:
		STREAM_GET(&prefix.u.prefix4.s_addr, s, IPV4_MAX_BYTELEN);
		STREAM_GETC(s, prefix.prefixlen);
		if (prefix.prefixlen > IPV4_MAX_BITLEN) {
			zlog_warn("%s: Specified prefix length %d is greater than a v4 address can support",
				  __PRETTY_FUNCTION__,
				  prefix.prefixlen);
			return;
		}
		STREAM_GET(&gate.ipv4.s_addr, s, IPV4_MAX_BYTELEN);
		break;
	case AF_INET6:
		STREAM_GET(&prefix.u.prefix6, s, 16);
		STREAM_GETC(s, prefix.prefixlen);
		if (prefix.prefixlen > IPV6_MAX_BITLEN) {
			zlog_warn("%s: Specified prefix length %d is greater than a v6 address can support",
				  __PRETTY_FUNCTION__,
				  prefix.prefixlen);
			return;
		}
		STREAM_GET(&gate.ipv6, s, 16);
		break;
	default:
		zlog_warn("%s: Specified AF %d is not supported for this call",
			  __PRETTY_FUNCTION__, prefix.family);
		return;
	}
	STREAM_GETL(s, ifindex);
	STREAM_GETC(s, distance);
	STREAM_GETL(s, in_label);
	STREAM_GETL(s, out_label);

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
		mpls_ftn_update(1, zvrf, type, &prefix, gtype, &gate, ifindex,
				distance, out_label);
	} else if (command == ZEBRA_MPLS_LABELS_DELETE) {
		mpls_lsp_uninstall(zvrf, type, in_label, gtype, &gate, ifindex);
		mpls_ftn_update(0, zvrf, type, &prefix, gtype, &gate, ifindex,
				distance, out_label);
	}
stream_failure:
	return;
}
/* Send response to a label manager connect request to client */
static int zsend_label_manager_connect_response(struct zserv *client,
						vrf_id_t vrf_id, u_short result)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_LABEL_MANAGER_CONNECT, vrf_id);

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
	STREAM_GETC(s, proto);
	STREAM_GETW(s, instance);

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

stream_failure:
	return;
}
/* Send response to a get label chunk request to client */
static int zsend_assign_label_chunk_response(struct zserv *client,
					     vrf_id_t vrf_id,
					     struct label_manager_chunk *lmc)
{
	struct stream *s;

	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_GET_LABEL_CHUNK, vrf_id);

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
	STREAM_GETC(s, keep);
	STREAM_GETL(s, size);

	lmc = assign_label_chunk(client->proto, client->instance, keep, size);
	if (!lmc)
		zlog_err("%s: Unable to assign Label Chunk of size %u",
			 __func__, size);
	else
		zlog_debug("Assigned Label Chunk %u - %u to %u", lmc->start,
			   lmc->end, keep);
	/* send response back */
	zsend_assign_label_chunk_response(client, vrf_id, lmc);

stream_failure:
	return;
}

static void zread_release_label_chunk(struct zserv *client)
{
	struct stream *s;
	uint32_t start, end;

	/* Get input stream.  */
	s = client->ibuf;

	/* Get data. */
	STREAM_GETL(s, start);
	STREAM_GETL(s, end);

	release_label_chunk(client->proto, client->instance, start, end);

stream_failure:
	return;
}
static void zread_label_manager_request(int cmd, struct zserv *client,
					struct zebra_vrf *zvrf)
{
	/* to avoid sending other messages like ZERBA_INTERFACE_UP */
	if (cmd == ZEBRA_LABEL_MANAGER_CONNECT)
		client->is_synchronous = 1;

	/* external label manager */
	if (lm_is_external)
		zread_relay_label_manager_request(cmd, client,
						  zvrf_id(zvrf));
	/* this is a label manager */
	else {
		if (cmd == ZEBRA_LABEL_MANAGER_CONNECT)
			zread_label_manager_connect(client,
						    zvrf_id(zvrf));
		else {
			/* Sanity: don't allow 'unidentified' requests */
			if (!client->proto) {
				zlog_err(
					"Got label request from an unidentified client");
				return;
			}
			if (cmd == ZEBRA_GET_LABEL_CHUNK)
				zread_get_label_chunk(client,
						      zvrf_id(zvrf));
			else if (cmd == ZEBRA_RELEASE_LABEL_CHUNK)
				zread_release_label_chunk(client);
		}
	}
}

static int zread_pseudowire(int command, struct zserv *client, u_short length,
			    struct zebra_vrf *zvrf)
{
	struct stream *s;
	char ifname[IF_NAMESIZE];
	ifindex_t ifindex;
	int type;
	int af;
	union g_addr nexthop;
	uint32_t local_label;
	uint32_t remote_label;
	uint8_t flags;
	union pw_protocol_fields data;
	uint8_t protocol;
	struct zebra_pw *pw;

	/* Get input stream.  */
	s = client->ibuf;

	/* Get data. */
	STREAM_GET(ifname, s, IF_NAMESIZE);
	STREAM_GETL(s, ifindex);
	STREAM_GETL(s, type);
	STREAM_GETL(s, af);
	switch (af) {
	case AF_INET:
		STREAM_GET(&nexthop.ipv4.s_addr, s, IPV4_MAX_BYTELEN);
		break;
	case AF_INET6:
		STREAM_GET(&nexthop.ipv6, s, 16);
		break;
	default:
		return -1;
	}
	STREAM_GETL(s, local_label);
	STREAM_GETL(s, remote_label);
	STREAM_GETC(s, flags);
	STREAM_GET(&data, s, sizeof(data));
	protocol = client->proto;

	pw = zebra_pw_find(zvrf, ifname);
	switch (command) {
	case ZEBRA_PW_ADD:
		if (pw) {
			zlog_warn("%s: pseudowire %s already exists [%s]",
				  __func__, ifname,
				  zserv_command_string(command));
			return -1;
		}

		zebra_pw_add(zvrf, ifname, protocol, client);
		break;
	case ZEBRA_PW_DELETE:
		if (!pw) {
			zlog_warn("%s: pseudowire %s not found [%s]", __func__,
				  ifname, zserv_command_string(command));
			return -1;
		}

		zebra_pw_del(zvrf, pw);
		break;
	case ZEBRA_PW_SET:
	case ZEBRA_PW_UNSET:
		if (!pw) {
			zlog_warn("%s: pseudowire %s not found [%s]", __func__,
				  ifname, zserv_command_string(command));
			return -1;
		}

		switch (command) {
		case ZEBRA_PW_SET:
			pw->enabled = 1;
			break;
		case ZEBRA_PW_UNSET:
			pw->enabled = 0;
			break;
		}

		zebra_pw_change(pw, ifindex, type, af, &nexthop, local_label,
				remote_label, flags, &data);
		break;
	}

stream_failure:
	return 0;
}

/* Cleanup registered nexthops (across VRFs) upon client disconnect. */
static void zebra_client_close_cleanup_rnh(struct zserv *client)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
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

/* free zebra client information. */
static void zebra_client_free(struct zserv *client)
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

	/* Remove pseudowires associated with this client */
	zebra_pw_client_close(client);

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

	XFREE(MTYPE_TMP, client);
}

static void zebra_client_close(struct zserv *client)
{
	listnode_delete(zebrad.client_list, client);
	zebra_client_free(client);
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

static int zread_interface_set_master(struct zserv *client,
				      u_short length)
{
	struct interface *master;
	struct interface *slave;
	struct stream *s = client->ibuf;
	int ifindex;
	vrf_id_t vrf_id;

	STREAM_GETL(s, vrf_id);
	STREAM_GETL(s, ifindex);
	master = if_lookup_by_index(ifindex, vrf_id);

	STREAM_GETL(s, vrf_id);
	STREAM_GETL(s, ifindex);
	slave = if_lookup_by_index(ifindex, vrf_id);

	if (!master || !slave)
		return 0;

	kernel_interface_set_master(master, slave);

stream_failure:
	return 1;
}

static inline void zserv_handle_commands(struct zserv *client,
					 uint16_t command,
					 uint16_t length,
					 struct zebra_vrf *zvrf)
{
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
	case ZEBRA_ROUTE_ADD:
		zread_route_add(client, length, zvrf);
		break;
	case ZEBRA_ROUTE_DELETE:
		zread_route_del(client, length, zvrf);
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
		zserv_rnh_register(client, length, RNH_NEXTHOP_TYPE,
				   zvrf);
		break;
	case ZEBRA_NEXTHOP_UNREGISTER:
		zserv_rnh_unregister(client, length, RNH_NEXTHOP_TYPE,
				     zvrf);
		break;
	case ZEBRA_IMPORT_ROUTE_REGISTER:
		zserv_rnh_register(client, length, RNH_IMPORT_CHECK_TYPE,
				   zvrf);
		break;
	case ZEBRA_IMPORT_ROUTE_UNREGISTER:
		zserv_rnh_unregister(client, length,
				     RNH_IMPORT_CHECK_TYPE, zvrf);
		break;
	case ZEBRA_BFD_DEST_UPDATE:
	case ZEBRA_BFD_DEST_REGISTER:
		zebra_ptm_bfd_dst_register(client, length, command, zvrf);
		break;
	case ZEBRA_BFD_DEST_DEREGISTER:
		zebra_ptm_bfd_dst_deregister(client, length, zvrf);
		break;
	case ZEBRA_VRF_UNREGISTER:
		zread_vrf_unregister(client, length, zvrf);
		break;
	case ZEBRA_BFD_CLIENT_REGISTER:
		zebra_ptm_bfd_client_register(client, length);
		break;
	case ZEBRA_INTERFACE_ENABLE_RADV:
#if defined(HAVE_RTADV)
		zebra_interface_radv_set(client, length, zvrf, 1);
#endif
		break;
	case ZEBRA_INTERFACE_DISABLE_RADV:
#if defined(HAVE_RTADV)
		zebra_interface_radv_set(client, length, zvrf, 0);
#endif
		break;
	case ZEBRA_MPLS_LABELS_ADD:
	case ZEBRA_MPLS_LABELS_DELETE:
		zread_mpls_labels(command, client, length, zvrf);
		break;
	case ZEBRA_IPMR_ROUTE_STATS:
		zebra_ipmr_route_stats(client, length, zvrf);
		break;
	case ZEBRA_LABEL_MANAGER_CONNECT:
	case ZEBRA_GET_LABEL_CHUNK:
	case ZEBRA_RELEASE_LABEL_CHUNK:
		zread_label_manager_request(command, client, zvrf);
		break;
	case ZEBRA_FEC_REGISTER:
		zserv_fec_register(client, length);
		break;
	case ZEBRA_FEC_UNREGISTER:
		zserv_fec_unregister(client, length);
		break;
	case ZEBRA_ADVERTISE_DEFAULT_GW:
		zebra_vxlan_advertise_gw_macip(client, length, zvrf);
		break;
	case ZEBRA_ADVERTISE_SUBNET:
		zebra_vxlan_advertise_subnet(client, length, zvrf);
		break;
	case ZEBRA_ADVERTISE_ALL_VNI:
		zebra_vxlan_advertise_all_vni(client, length, zvrf);
		break;
	case ZEBRA_REMOTE_VTEP_ADD:
		zebra_vxlan_remote_vtep_add(client, length, zvrf);
		break;
	case ZEBRA_REMOTE_VTEP_DEL:
		zebra_vxlan_remote_vtep_del(client, length, zvrf);
		break;
	case ZEBRA_REMOTE_MACIP_ADD:
		zebra_vxlan_remote_macip_add(client, length, zvrf);
		break;
	case ZEBRA_REMOTE_MACIP_DEL:
		zebra_vxlan_remote_macip_del(client, length, zvrf);
		break;
	case ZEBRA_INTERFACE_SET_MASTER:
		zread_interface_set_master(client, length);
		break;
	case ZEBRA_PW_ADD:
	case ZEBRA_PW_DELETE:
	case ZEBRA_PW_SET:
	case ZEBRA_PW_UNSET:
		zread_pseudowire(command, client, length, zvrf);
		break;
	default:
		zlog_info("Zebra received unknown command %d", command);
		break;
	}
}

#if defined(HANDLE_ZAPI_FUZZING)
static void zserv_write_incoming(struct stream *orig, uint16_t command)
{
	char fname[MAXPATHLEN];
	struct stream *copy;
	int fd = -1;

	copy = stream_dup(orig);
	stream_set_getp(copy, 0);

	zserv_privs.change(ZPRIVS_RAISE);
	snprintf(fname, MAXPATHLEN, "%s/%u", DAEMON_VTY_DIR, command);
	fd = open(fname, O_CREAT | O_WRONLY | O_EXCL, 0644);
	stream_flush(copy, fd);
	close(fd);
	zserv_privs.change(ZPRIVS_LOWER);
	stream_free(copy);
}
#endif

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
#if defined(HANDLE_ZAPI_FUZZING)
	int packets = 1;
#else
	int packets = zebrad.packets_to_process;
#endif

	/* Get thread data.  Reset reading thread because I'm running. */
	sock = THREAD_FD(thread);
	client = THREAD_ARG(thread);
	client->t_read = NULL;

	if (client->t_suicide) {
		zebra_client_close(client);
		return -1;
	}

	while (packets) {
		/* Read length and command (if we don't have it already). */
		if ((already = stream_get_endp(client->ibuf))
		    < ZEBRA_HEADER_SIZE) {
			ssize_t nbyte;
			if (((nbyte =
			      stream_read_try(client->ibuf, sock,
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
		STREAM_GETW(client->ibuf, length);
		STREAM_GETC(client->ibuf, marker);
		STREAM_GETC(client->ibuf, version);
		STREAM_GETL(client->ibuf, vrf_id);
		STREAM_GETW(client->ibuf, command);

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

#if defined(HANDLE_ZAPI_FUZZING)
		zserv_write_incoming(client->ibuf, command);
#endif
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

		zserv_handle_commands(client, command, length, zvrf);

		if (client->t_suicide) {
			/* No need to wait for thread callback, just kill immediately.
			 */
			zebra_client_close(client);
			return -1;
		}
		packets -= 1;
		stream_reset(client->ibuf);
	}

stream_failure:
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

/* Make zebra server socket, wiping any existing one (see bug #403). */
void zebra_zserv_socket_init(char *path)
{
	int ret;
	int sock;
	mode_t old_mask;
	struct sockaddr_storage sa;
	socklen_t sa_len;

	if (!frr_zclient_addr(&sa, &sa_len, path))
		/* should be caught in zebra main() */
		return;

	/* Set umask */
	old_mask = umask(0077);

	/* Make UNIX domain socket. */
	sock = socket(sa.ss_family, SOCK_STREAM, 0);
	if (sock < 0) {
		zlog_warn("Can't create zserv socket: %s",
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provide full functionality due to above error");
		return;
	}

	if (sa.ss_family != AF_UNIX) {
		sockopt_reuseaddr(sock);
		sockopt_reuseport(sock);
	} else {
		struct sockaddr_un *suna = (struct sockaddr_un *)&sa;
		if (suna->sun_path[0])
			unlink(suna->sun_path);
	}

	zserv_privs.change(ZPRIVS_RAISE);
	setsockopt_so_recvbuf(sock, 1048576);
	setsockopt_so_sendbuf(sock, 1048576);
	zserv_privs.change(ZPRIVS_LOWER);

	if (sa.ss_family != AF_UNIX && zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("Can't raise privileges");

	ret = bind(sock, (struct sockaddr *)&sa, sa_len);
	if (ret < 0) {
		zlog_warn("Can't bind zserv socket on %s: %s", path,
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provide full functionality due to above error");
		close(sock);
		return;
	}
	if (sa.ss_family != AF_UNIX && zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges");

	ret = listen(sock, 5);
	if (ret < 0) {
		zlog_warn("Can't listen to zserv socket %s: %s", path,
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provide full functionality due to above error");
		close(sock);
		return;
	}

	umask(old_mask);

	zebra_event(ZEBRA_SERV, sock, NULL);
}


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
	vty_out(vty, "L3-VNI add notifications: %d\n", client->l3vniadd_cnt);
	vty_out(vty, "L3-VNI delete notifications: %d\n", client->l3vnidel_cnt);
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

struct zserv *zebra_find_client(u_char proto, u_short instance)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	for (ALL_LIST_ELEMENTS(zebrad.client_list, node, nnode, client)) {
		if (client->proto == proto &&
		    client->instance == instance)
			return client;
	}

	return NULL;
}

/* This command is for debugging purpose. */
DEFUN (show_zebra_client,
       show_zebra_client_cmd,
       "show zebra client",
       SHOW_STR
       ZEBRA_STR
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
       ZEBRA_STR
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

#if defined(HANDLE_ZAPI_FUZZING)
void zserv_read_file(char *input)
{
	int fd;
	struct zserv *client = NULL;
	struct thread t;

	zebra_client_create(-1);
	client = zebrad.client_list->head->data;
	t.arg = client;

	fd = open(input, O_RDONLY|O_NONBLOCK);
	t.u.fd = fd;

	zebra_client_read(&t);

	close(fd);
}
#endif

void zserv_init(void)
{
	/* Client list init. */
	zebrad.client_list = list_new();
	zebrad.client_list->del = (void (*)(void *))zebra_client_free;

	install_element(ENABLE_NODE, &show_zebra_client_cmd);
	install_element(ENABLE_NODE, &show_zebra_client_summary_cmd);
}
