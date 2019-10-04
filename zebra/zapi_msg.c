/*
 * Zebra API message creation & consumption.
 * Portions:
 *   Copyright (C) 1997-1999  Kunihiro Ishiguro
 *   Copyright (C) 2015-2018  Cumulus Networks, Inc.
 *   et al.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <libgen.h>

#include "lib/prefix.h"
#include "lib/command.h"
#include "lib/if.h"
#include "lib/thread.h"
#include "lib/stream.h"
#include "lib/memory.h"
#include "lib/table.h"
#include "lib/network.h"
#include "lib/sockunion.h"
#include "lib/log.h"
#include "lib/zclient.h"
#include "lib/privs.h"
#include "lib/network.h"
#include "lib/buffer.h"
#include "lib/nexthop.h"
#include "lib/vrf.h"
#include "lib/libfrr.h"
#include "lib/sockopt.h"

#include "zebra/zebra_router.h"
#include "zebra/rib.h"
#include "zebra/zebra_memory.h"
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
#include "zebra/zebra_vxlan.h"
#include "zebra/rt.h"
#include "zebra/zebra_pbr.h"
#include "zebra/table_manager.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_mlag.h"

/* Encoding helpers -------------------------------------------------------- */

static void zserv_encode_interface(struct stream *s, struct interface *ifp)
{
	/* Interface information. */
	struct zebra_if *zif = ifp->info;

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
	stream_putl(s, zif->link_ifindex);
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
	const char *netns_name = zvrf_ns_name(zvrf);

	data.l.table_id = zvrf->table_id;

	if (netns_name)
		strlcpy(data.l.netns_name, basename((char *)netns_name),
			NS_NAMSIZ);
	else
		memset(data.l.netns_name, 0, NS_NAMSIZ);
	/* Pass the tableid and the netns NAME */
	stream_put(s, &data, sizeof(struct vrf_data));
	/* Interface information. */
	stream_put(s, zvrf_name(zvrf), VRF_NAMSIZ);
	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));
}

static int zserv_encode_nexthop(struct stream *s, struct nexthop *nexthop)
{
	stream_putl(s, nexthop->vrf_id);
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

/* Send handlers ----------------------------------------------------------- */

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
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_INTERFACE_ADD, ifp->vrf_id);
	zserv_encode_interface(s, ifp);

	client->ifadd_cnt++;
	return zserv_send_message(client, s);
}

/* Interface deletion from zebra daemon. */
int zsend_interface_delete(struct zserv *client, struct interface *ifp)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_INTERFACE_DELETE, ifp->vrf_id);
	zserv_encode_interface(s, ifp);

	client->ifdel_cnt++;
	return zserv_send_message(client, s);
}

int zsend_vrf_add(struct zserv *client, struct zebra_vrf *zvrf)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_VRF_ADD, zvrf_id(zvrf));
	zserv_encode_vrf(s, zvrf);

	client->vrfadd_cnt++;
	return zserv_send_message(client, s);
}

/* VRF deletion from zebra daemon. */
int zsend_vrf_delete(struct zserv *client, struct zebra_vrf *zvrf)

{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_VRF_DELETE, zvrf_id(zvrf));
	zserv_encode_vrf(s, zvrf);

	client->vrfdel_cnt++;
	return zserv_send_message(client, s);
}

int zsend_interface_link_params(struct zserv *client, struct interface *ifp)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	if (!ifp->link_params) {
		stream_free(s);
		return 0;
	}

	zclient_create_header(s, ZEBRA_INTERFACE_LINK_PARAMS, ifp->vrf_id);

	/* Add Interface Index */
	stream_putl(s, ifp->ifindex);

	/* Then TE Link Parameters */
	if (zebra_interface_link_params_write(s, ifp) == 0) {
		stream_free(s);
		return 0;
	}

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zserv_send_message(client, s);
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
 *    - for the vty commands "ip address A.B.C.D/M [<label LINE>]"
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
 *     "no ip address A.B.C.D/M"
 *     ["no ipv6 address X:X::X:X/M"]
 *
 */
int zsend_interface_address(int cmd, struct zserv *client,
			    struct interface *ifp, struct connected *ifc)
{
	int blen;
	struct prefix *p;
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

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
	return zserv_send_message(client, s);
}

static int zsend_interface_nbr_address(int cmd, struct zserv *client,
				       struct interface *ifp,
				       struct nbr_connected *ifc)
{
	int blen;
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	struct prefix *p;

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

	return zserv_send_message(client, s);
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

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client))
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

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client))
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
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_INTERFACE_VRF_UPDATE, ifp->vrf_id);

	/* Fill in the name of the interface and its new VRF (id) */
	stream_put(s, ifp->name, INTERFACE_NAMSIZ);
	stream_putl(s, vrf_id);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	client->if_vrfchg_cnt++;
	return zserv_send_message(client, s);
}

/* Add new nbr connected IPv6 address */
void nbr_connected_add_ipv6(struct interface *ifp, struct in6_addr *address)
{
	struct nbr_connected *ifc;
	struct prefix p;

	p.family = AF_INET6;
	IPV6_ADDR_COPY(&p.u.prefix6, address);
	p.prefixlen = IPV6_MAX_PREFIXLEN;

	ifc = listnode_head(ifp->nbr_connected);
	if (!ifc) {
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
	IPV6_ADDR_COPY(&p.u.prefix6, address);
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
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, cmd, ifp->vrf_id);
	zserv_encode_interface(s, ifp);

	if (cmd == ZEBRA_INTERFACE_UP)
		client->ifup_cnt++;
	else
		client->ifdown_cnt++;

	return zserv_send_message(client, s);
}

int zsend_redistribute_route(int cmd, struct zserv *client,
			     const struct prefix *p,
			     const struct prefix *src_p,
			     const struct route_entry *re)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct nexthop *nexthop;
	uint8_t count = 0;
	afi_t afi;
	size_t stream_size =
		MAX(ZEBRA_MAX_PACKET_SIZ, sizeof(struct zapi_route));

	memset(&api, 0, sizeof(api));
	api.vrf_id = re->vrf_id;
	api.type = re->type;
	api.safi = SAFI_UNICAST;
	api.instance = re->instance;
	api.flags = re->flags;

	afi = family2afi(p->family);
	switch (afi) {
	case AFI_IP:
		if (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
			client->redist_v4_add_cnt++;
		else
			client->redist_v4_del_cnt++;
		break;
	case AFI_IP6:
		if (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
			client->redist_v6_add_cnt++;
		else
			client->redist_v6_del_cnt++;
		break;
	default:
		break;
	}

	/* Prefix. */
	api.prefix = *p;
	if (src_p) {
		SET_FLAG(api.message, ZAPI_MESSAGE_SRCPFX);
		memcpy(&api.src_prefix, src_p, sizeof(api.src_prefix));
	}

	for (nexthop = re->ng->nexthop; nexthop; nexthop = nexthop->next) {
		if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
			continue;

		api_nh = &api.nexthops[count];
		api_nh->vrf_id = nexthop->vrf_id;
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

	/* Nexthops. */
	if (count) {
		SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
		api.nexthop_num = count;
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

	struct stream *s = stream_new(stream_size);

	/* Encode route and send. */
	if (zapi_route_encode(cmd, s, &api) < 0) {
		stream_free(s);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_SEND) {
		char buf_prefix[PREFIX_STRLEN];

		prefix2str(&api.prefix, buf_prefix, sizeof(buf_prefix));

		zlog_debug("%s: %s to client %s: type %s, vrf_id %d, p %s",
			   __func__, zserv_command_string(cmd),
			   zebra_route_string(client->proto),
			   zebra_route_string(api.type), api.vrf_id,
			   buf_prefix);
	}
	return zserv_send_message(client, s);
}

/*
 * Modified version of zsend_ipv4_nexthop_lookup(): Query unicast rib if
 * nexthop is not found on mrib. Returns both route metric and protocol
 * distance.
 */
static int zsend_ipv4_nexthop_lookup_mrib(struct zserv *client,
					  struct in_addr addr,
					  struct route_entry *re,
					  struct zebra_vrf *zvrf)
{
	struct stream *s;
	unsigned long nump;
	uint8_t num;
	struct nexthop *nexthop;

	/* Get output stream. */
	s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	stream_reset(s);

	/* Fill in result. */
	zclient_create_header(s, ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB, zvrf_id(zvrf));
	stream_put_in_addr(s, &addr);

	if (re) {
		stream_putc(s, re->distance);
		stream_putl(s, re->metric);
		num = 0;
		/* remember position for nexthop_num */
		nump = stream_get_endp(s);
		/* reserve room for nexthop_num */
		stream_putc(s, 0);
		/*
		 * Only non-recursive routes are elegible to resolve the
		 * nexthop we are looking up. Therefore, we will just iterate
		 * over the top chain of nexthops.
		 */
		for (nexthop = re->ng->nexthop; nexthop;
		     nexthop = nexthop->next)
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
				num += zserv_encode_nexthop(s, nexthop);

		/* store nexthop_num */
		stream_putc_at(s, nump, num);
	} else {
		stream_putc(s, 0); /* distance */
		stream_putl(s, 0); /* metric */
		stream_putc(s, 0); /* nexthop_num */
	}

	stream_putw_at(s, 0, stream_get_endp(s));

	return zserv_send_message(client, s);
}

/*
 * Common utility send route notification, called from a path using a
 * route_entry and from a path using a dataplane context.
 */
static int route_notify_internal(const struct prefix *p, int type,
				 uint16_t instance, vrf_id_t vrf_id,
				 uint32_t table_id,
				 enum zapi_route_notify_owner note)
{
	struct zserv *client;
	struct stream *s;
	uint8_t blen;

	client = zserv_find_client(type, instance);
	if (!client || !client->notify_owner) {
		if (IS_ZEBRA_DEBUG_PACKET) {
			char buff[PREFIX_STRLEN];

			zlog_debug(
				"Not Notifying Owner: %u about prefix %s(%u) %d vrf: %u",
				type, prefix2str(p, buff, sizeof(buff)),
				table_id, note, vrf_id);
		}
		return 0;
	}

	if (IS_ZEBRA_DEBUG_PACKET) {
		char buff[PREFIX_STRLEN];

		zlog_debug("Notifying Owner: %u about prefix %s(%u) %d vrf: %u",
			   type, prefix2str(p, buff, sizeof(buff)),
			   table_id, note, vrf_id);
	}

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	stream_reset(s);

	zclient_create_header(s, ZEBRA_ROUTE_NOTIFY_OWNER, vrf_id);

	stream_put(s, &note, sizeof(note));

	stream_putc(s, p->family);

	blen = prefix_blen(p);
	stream_putc(s, p->prefixlen);
	stream_put(s, &p->u.prefix, blen);

	stream_putl(s, table_id);

	stream_putw_at(s, 0, stream_get_endp(s));

	return zserv_send_message(client, s);
}

int zsend_route_notify_owner(struct route_entry *re, const struct prefix *p,
			     enum zapi_route_notify_owner note)
{
	return (route_notify_internal(p, re->type, re->instance, re->vrf_id,
				      re->table, note));
}

/*
 * Route-owner notification using info from dataplane update context.
 */
int zsend_route_notify_owner_ctx(const struct zebra_dplane_ctx *ctx,
				 enum zapi_route_notify_owner note)
{
	return (route_notify_internal(dplane_ctx_get_dest(ctx),
				      dplane_ctx_get_type(ctx),
				      dplane_ctx_get_instance(ctx),
				      dplane_ctx_get_vrf(ctx),
				      dplane_ctx_get_table(ctx),
				      note));
}

void zsend_rule_notify_owner(struct zebra_pbr_rule *rule,
			     enum zapi_rule_notify_owner note)
{
	struct listnode *node;
	struct zserv *client;
	struct stream *s;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Notifying %u", __PRETTY_FUNCTION__,
			   rule->rule.unique);

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (rule->sock == client->sock)
			break;
	}

	if (!client)
		return;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_RULE_NOTIFY_OWNER, VRF_DEFAULT);
	stream_put(s, &note, sizeof(note));
	stream_putl(s, rule->rule.seq);
	stream_putl(s, rule->rule.priority);
	stream_putl(s, rule->rule.unique);
	stream_putl(s, rule->rule.ifindex);

	stream_putw_at(s, 0, stream_get_endp(s));

	zserv_send_message(client, s);
}

void zsend_ipset_notify_owner(struct zebra_pbr_ipset *ipset,
			      enum zapi_ipset_notify_owner note)
{
	struct listnode *node;
	struct zserv *client;
	struct stream *s;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Notifying %u", __PRETTY_FUNCTION__,
			   ipset->unique);

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (ipset->sock == client->sock)
			break;
	}

	if (!client)
		return;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_IPSET_NOTIFY_OWNER, VRF_DEFAULT);
	stream_put(s, &note, sizeof(note));
	stream_putl(s, ipset->unique);
	stream_put(s, ipset->ipset_name, ZEBRA_IPSET_NAME_SIZE);
	stream_putw_at(s, 0, stream_get_endp(s));

	zserv_send_message(client, s);
}

void zsend_ipset_entry_notify_owner(struct zebra_pbr_ipset_entry *ipset,
				    enum zapi_ipset_entry_notify_owner note)
{
	struct listnode *node;
	struct zserv *client;
	struct stream *s;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Notifying %u", __PRETTY_FUNCTION__,
			   ipset->unique);

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (ipset->sock == client->sock)
			break;
	}

	if (!client)
		return;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_IPSET_ENTRY_NOTIFY_OWNER, VRF_DEFAULT);
	stream_put(s, &note, sizeof(note));
	stream_putl(s, ipset->unique);
	stream_put(s, ipset->backpointer->ipset_name, ZEBRA_IPSET_NAME_SIZE);
	stream_putw_at(s, 0, stream_get_endp(s));

	zserv_send_message(client, s);
}

void zsend_iptable_notify_owner(struct zebra_pbr_iptable *iptable,
				enum zapi_iptable_notify_owner note)
{
	struct listnode *node;
	struct zserv *client;
	struct stream *s;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Notifying %u", __PRETTY_FUNCTION__,
			   iptable->unique);

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (iptable->sock == client->sock)
			break;
	}

	if (!client)
		return;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_IPTABLE_NOTIFY_OWNER, VRF_DEFAULT);
	stream_put(s, &note, sizeof(note));
	stream_putl(s, iptable->unique);
	stream_putw_at(s, 0, stream_get_endp(s));

	zserv_send_message(client, s);
}

/* Router-id is updated. Send ZEBRA_ROUTER_ID_ADD to client. */
int zsend_router_id_update(struct zserv *client, struct prefix *p,
			   vrf_id_t vrf_id)
{
	int blen;

	/* Check this client need interface information. */
	if (!vrf_bitmap_check(client->ridinfo, vrf_id))
		return 0;

	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	/* Message type. */
	zclient_create_header(s, ZEBRA_ROUTER_ID_UPDATE, vrf_id);

	/* Prefix information. */
	stream_putc(s, p->family);
	blen = prefix_blen(p);
	stream_put(s, &p->u.prefix, blen);
	stream_putc(s, p->prefixlen);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zserv_send_message(client, s);
}

/*
 * Function used by Zebra to send a PW status update to LDP daemon
 */
int zsend_pw_update(struct zserv *client, struct zebra_pw *pw)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_PW_STATUS_UPDATE, pw->vrf_id);
	stream_write(s, pw->ifname, IF_NAMESIZE);
	stream_putl(s, pw->ifindex);
	stream_putl(s, pw->status);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zserv_send_message(client, s);
}

/* Send response to a get label chunk request to client */
int zsend_assign_label_chunk_response(struct zserv *client, vrf_id_t vrf_id,
				      uint8_t proto, uint16_t instance,
				      struct label_manager_chunk *lmc)
{
	int ret;
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_GET_LABEL_CHUNK, vrf_id);
	/* proto */
	stream_putc(s, proto);
	/* instance */
	stream_putw(s, instance);

	if (lmc) {
		/* keep */
		stream_putc(s, lmc->keep);
		/* start and end labels */
		stream_putl(s, lmc->start);
		stream_putl(s, lmc->end);
	}

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	ret = writen(client->sock, s->data, stream_get_endp(s));
	stream_free(s);
	return ret;
}

/* Send response to a label manager connect request to client */
int zsend_label_manager_connect_response(struct zserv *client, vrf_id_t vrf_id,
					 unsigned short result)
{
	int ret;
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_LABEL_MANAGER_CONNECT, vrf_id);

	/* proto */
	stream_putc(s, client->proto);

	/* instance */
	stream_putw(s, client->instance);

	/* result */
	stream_putc(s, result);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	ret = writen(client->sock, s->data, stream_get_endp(s));
	stream_free(s);

	return ret;
}

/* Send response to a get table chunk request to client */
static int zsend_assign_table_chunk_response(struct zserv *client,
					     vrf_id_t vrf_id,
					     struct table_manager_chunk *tmc)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_GET_TABLE_CHUNK, vrf_id);

	if (tmc) {
		/* start and end labels */
		stream_putl(s, tmc->start);
		stream_putl(s, tmc->end);
	}

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zserv_send_message(client, s);
}

static int zsend_table_manager_connect_response(struct zserv *client,
						vrf_id_t vrf_id,
						uint16_t result)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_TABLE_MANAGER_CONNECT, vrf_id);

	/* result */
	stream_putc(s, result);

	stream_putw_at(s, 0, stream_get_endp(s));

	return zserv_send_message(client, s);
}

/* Inbound message handling ------------------------------------------------ */

int cmd2type[] = {
	[ZEBRA_NEXTHOP_REGISTER] = RNH_NEXTHOP_TYPE,
	[ZEBRA_NEXTHOP_UNREGISTER] = RNH_NEXTHOP_TYPE,
	[ZEBRA_IMPORT_ROUTE_REGISTER] = RNH_IMPORT_CHECK_TYPE,
	[ZEBRA_IMPORT_ROUTE_UNREGISTER] = RNH_IMPORT_CHECK_TYPE,
};

/* Nexthop register */
static void zread_rnh_register(ZAPI_HANDLER_ARGS)
{
	struct rnh *rnh;
	struct stream *s;
	struct prefix p;
	unsigned short l = 0;
	uint8_t flags = 0;
	uint16_t type = cmd2type[hdr->command];
	bool exist;
	bool flag_changed = false;
	uint8_t orig_flags;

	if (IS_ZEBRA_DEBUG_NHT)
		zlog_debug(
			"rnh_register msg from client %s: hdr->length=%d, type=%s vrf=%u\n",
			zebra_route_string(client->proto), hdr->length,
			(type == RNH_NEXTHOP_TYPE) ? "nexthop" : "route",
			zvrf->vrf->vrf_id);

	s = msg;

	client->nh_reg_time = monotime(NULL);

	while (l < hdr->length) {
		STREAM_GETC(s, flags);
		STREAM_GETW(s, p.family);
		STREAM_GETC(s, p.prefixlen);
		l += 4;
		if (p.family == AF_INET) {
			client->v4_nh_watch_add_cnt++;
			if (p.prefixlen > IPV4_MAX_BITLEN) {
				zlog_debug(
					"%s: Specified prefix hdr->length %d is too large for a v4 address",
					__PRETTY_FUNCTION__, p.prefixlen);
				return;
			}
			STREAM_GET(&p.u.prefix4.s_addr, s, IPV4_MAX_BYTELEN);
			l += IPV4_MAX_BYTELEN;
		} else if (p.family == AF_INET6) {
			client->v6_nh_watch_add_cnt++;
			if (p.prefixlen > IPV6_MAX_BITLEN) {
				zlog_debug(
					"%s: Specified prefix hdr->length %d is to large for a v6 address",
					__PRETTY_FUNCTION__, p.prefixlen);
				return;
			}
			STREAM_GET(&p.u.prefix6, s, IPV6_MAX_BYTELEN);
			l += IPV6_MAX_BYTELEN;
		} else {
			flog_err(
				EC_ZEBRA_UNKNOWN_FAMILY,
				"rnh_register: Received unknown family type %d\n",
				p.family);
			return;
		}
		rnh = zebra_add_rnh(&p, zvrf_id(zvrf), type, &exist);
		if (!rnh)
			return;

		orig_flags = rnh->flags;
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

		if (orig_flags != rnh->flags)
			flag_changed = true;

		/* Anything not AF_INET/INET6 has been filtered out above */
		if (!exist || flag_changed)
			zebra_evaluate_rnh(zvrf, family2afi(p.family), 1, type,
					   &p);

		zebra_add_rnh_client(rnh, client, type, zvrf_id(zvrf));
	}

stream_failure:
	return;
}

/* Nexthop register */
static void zread_rnh_unregister(ZAPI_HANDLER_ARGS)
{
	struct rnh *rnh;
	struct stream *s;
	struct prefix p;
	unsigned short l = 0;
	uint16_t type = cmd2type[hdr->command];

	if (IS_ZEBRA_DEBUG_NHT)
		zlog_debug(
			"rnh_unregister msg from client %s: hdr->length=%d vrf: %u\n",
			zebra_route_string(client->proto), hdr->length,
			zvrf->vrf->vrf_id);

	s = msg;

	while (l < hdr->length) {
		uint8_t flags;

		STREAM_GETC(s, flags);
		if (flags != 0)
			goto stream_failure;

		STREAM_GETW(s, p.family);
		STREAM_GETC(s, p.prefixlen);
		l += 4;
		if (p.family == AF_INET) {
			client->v4_nh_watch_rem_cnt++;
			if (p.prefixlen > IPV4_MAX_BITLEN) {
				zlog_debug(
					"%s: Specified prefix hdr->length %d is to large for a v4 address",
					__PRETTY_FUNCTION__, p.prefixlen);
				return;
			}
			STREAM_GET(&p.u.prefix4.s_addr, s, IPV4_MAX_BYTELEN);
			l += IPV4_MAX_BYTELEN;
		} else if (p.family == AF_INET6) {
			client->v6_nh_watch_rem_cnt++;
			if (p.prefixlen > IPV6_MAX_BITLEN) {
				zlog_debug(
					"%s: Specified prefix hdr->length %d is to large for a v6 address",
					__PRETTY_FUNCTION__, p.prefixlen);
				return;
			}
			STREAM_GET(&p.u.prefix6, s, IPV6_MAX_BYTELEN);
			l += IPV6_MAX_BYTELEN;
		} else {
			flog_err(
				EC_ZEBRA_UNKNOWN_FAMILY,
				"rnh_register: Received unknown family type %d\n",
				p.family);
			return;
		}
		rnh = zebra_lookup_rnh(&p, zvrf_id(zvrf), type);
		if (rnh) {
			client->nh_dereg_time = monotime(NULL);
			zebra_remove_rnh_client(rnh, client, type);
		}
	}
stream_failure:
	return;
}

#define ZEBRA_MIN_FEC_LENGTH 5

/* FEC register */
static void zread_fec_register(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	unsigned short l = 0;
	struct prefix p;
	uint16_t flags;
	uint32_t label = MPLS_INVALID_LABEL;
	uint32_t label_index = MPLS_INVALID_LABEL_INDEX;

	s = msg;
	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (!zvrf)
		return;

	/*
	 * The minimum amount of data that can be sent for one fec
	 * registration
	 */
	if (hdr->length < ZEBRA_MIN_FEC_LENGTH) {
		flog_err(
			EC_ZEBRA_IRDP_LEN_MISMATCH,
			"fec_register: Received a fec register of hdr->length %d, it is of insufficient size to properly decode",
			hdr->length);
		return;
	}

	while (l < hdr->length) {
		STREAM_GETW(s, flags);
		memset(&p, 0, sizeof(p));
		STREAM_GETW(s, p.family);
		if (p.family != AF_INET && p.family != AF_INET6) {
			flog_err(
				EC_ZEBRA_UNKNOWN_FAMILY,
				"fec_register: Received unknown family type %d\n",
				p.family);
			return;
		}
		STREAM_GETC(s, p.prefixlen);
		if ((p.family == AF_INET && p.prefixlen > IPV4_MAX_BITLEN)
		    || (p.family == AF_INET6
			&& p.prefixlen > IPV6_MAX_BITLEN)) {
			zlog_debug(
				"%s: Specified prefix hdr->length: %d is to long for %d",
				__PRETTY_FUNCTION__, p.prefixlen, p.family);
			return;
		}
		l += 5;
		STREAM_GET(&p.u.prefix, s, PSIZE(p.prefixlen));
		l += PSIZE(p.prefixlen);
		if (flags & ZEBRA_FEC_REGISTER_LABEL) {
			STREAM_GETL(s, label);
			l += 4;
		} else if (flags & ZEBRA_FEC_REGISTER_LABEL_INDEX) {
			STREAM_GETL(s, label_index);
			l += 4;
		}

		zebra_mpls_fec_register(zvrf, &p, label, label_index, client);
	}

stream_failure:
	return;
}

/* FEC unregister */
static void zread_fec_unregister(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	unsigned short l = 0;
	struct prefix p;
	uint16_t flags;

	s = msg;
	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (!zvrf)
		return;

	/*
	 * The minimum amount of data that can be sent for one
	 * fec unregistration
	 */
	if (hdr->length < ZEBRA_MIN_FEC_LENGTH) {
		flog_err(
			EC_ZEBRA_IRDP_LEN_MISMATCH,
			"fec_unregister: Received a fec unregister of hdr->length %d, it is of insufficient size to properly decode",
			hdr->length);
		return;
	}

	while (l < hdr->length) {
		STREAM_GETW(s, flags);
		if (flags != 0)
			goto stream_failure;

		memset(&p, 0, sizeof(p));
		STREAM_GETW(s, p.family);
		if (p.family != AF_INET && p.family != AF_INET6) {
			flog_err(
				EC_ZEBRA_UNKNOWN_FAMILY,
				"fec_unregister: Received unknown family type %d\n",
				p.family);
			return;
		}
		STREAM_GETC(s, p.prefixlen);
		if ((p.family == AF_INET && p.prefixlen > IPV4_MAX_BITLEN)
		    || (p.family == AF_INET6
			&& p.prefixlen > IPV6_MAX_BITLEN)) {
			zlog_debug(
				"%s: Received prefix hdr->length %d which is greater than %d can support",
				__PRETTY_FUNCTION__, p.prefixlen, p.family);
			return;
		}
		l += 5;
		STREAM_GET(&p.u.prefix, s, PSIZE(p.prefixlen));
		l += PSIZE(p.prefixlen);
		zebra_mpls_fec_unregister(zvrf, &p, client);
	}

stream_failure:
	return;
}


/*
 * Register zebra server interface information.
 * Send current all interface and address information.
 */
static void zread_interface_add(ZAPI_HANDLER_ARGS)
{
	struct vrf *vrf;
	struct interface *ifp;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			/* Skip pseudo interface. */
			if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE))
				continue;

			zsend_interface_add(client, ifp);
			zsend_interface_link_params(client, ifp);
			zsend_interface_addresses(client, ifp);
		}
	}
}

/* Unregister zebra server interface information. */
static void zread_interface_delete(ZAPI_HANDLER_ARGS)
{
}

/*
 * Handle message requesting interface be set up or down.
 */
static void zread_interface_set_protodown(ZAPI_HANDLER_ARGS)
{
	ifindex_t ifindex;
	struct interface *ifp;
	char down;

	STREAM_GETL(msg, ifindex);
	STREAM_GETC(msg, down);

	/* set ifdown */
	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT), ifindex);

	if (ifp) {
		zlog_info("Setting interface %s (%u): protodown %s", ifp->name,
			  ifindex, down ? "on" : "off");
		zebra_if_set_protodown(ifp, down);
	} else {
		zlog_warn(
			"Cannot set protodown %s for interface %u; does not exist",
			down ? "on" : "off", ifindex);
	}


stream_failure:
	return;
}


void zserv_nexthop_num_warn(const char *caller, const struct prefix *p,
			    const unsigned int nexthop_num)
{
	if (nexthop_num > zrouter.multipath_num) {
		char buff[PREFIX2STR_BUFFER];

		prefix2str(p, buff, sizeof(buff));
		flog_warn(
			EC_ZEBRA_MORE_NH_THAN_MULTIPATH,
			"%s: Prefix %s has %d nexthops, but we can only use the first %d",
			caller, buff, nexthop_num, zrouter.multipath_num);
	}
}

static void zread_route_add(ZAPI_HANDLER_ARGS)
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
	struct ipaddr vtep_ip;

	s = msg;
	if (zapi_route_decode(s, &api) < 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Unable to decode zapi_route sent",
				   __PRETTY_FUNCTION__);
		return;
	}

	if (IS_ZEBRA_DEBUG_RECV) {
		char buf_prefix[PREFIX_STRLEN];

		prefix2str(&api.prefix, buf_prefix, sizeof(buf_prefix));
		zlog_debug("%s: p=%s, ZAPI_MESSAGE_LABEL: %sset, flags=0x%x",
			   __func__, buf_prefix,
			   (CHECK_FLAG(api.message, ZAPI_MESSAGE_LABEL) ? ""
									: "un"),
			   api.flags);
	}

	/* Allocate new route. */
	vrf_id = zvrf_id(zvrf);
	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));
	re->type = api.type;
	re->instance = api.instance;
	re->flags = api.flags;
	re->uptime = monotime(NULL);
	re->vrf_id = vrf_id;
	re->ng = nexthop_group_new();

	if (api.tableid)
		re->table = api.tableid;
	else
		re->table = zvrf->table_id;

	if (!CHECK_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP)
	    || api.nexthop_num == 0) {
		flog_warn(EC_ZEBRA_RX_ROUTE_NO_NEXTHOPS,
			  "%s: received a route without nexthops for prefix %pFX from client %s",
			  __func__, &api.prefix,
			  zebra_route_string(client->proto));

		nexthop_group_delete(&re->ng);
		XFREE(MTYPE_RE, re);
		return;
	}

	/*
	 * TBD should _all_ of the nexthop add operations use
	 * api_nh->vrf_id instead of re->vrf_id ? I only changed
	 * for cases NEXTHOP_TYPE_IPV4 and NEXTHOP_TYPE_IPV6.
	 */
	for (i = 0; i < api.nexthop_num; i++) {
		api_nh = &api.nexthops[i];
		ifindex_t ifindex = 0;

		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("nh type %d", api_nh->type);

		switch (api_nh->type) {
		case NEXTHOP_TYPE_IFINDEX:
			nexthop = route_entry_nexthop_ifindex_add(
				re, api_nh->ifindex, api_nh->vrf_id);
			break;
		case NEXTHOP_TYPE_IPV4:
			if (IS_ZEBRA_DEBUG_RECV) {
				char nhbuf[INET6_ADDRSTRLEN] = {0};

				inet_ntop(AF_INET, &api_nh->gate.ipv4, nhbuf,
					  INET6_ADDRSTRLEN);
				zlog_debug("%s: nh=%s, vrf_id=%d", __func__,
					   nhbuf, api_nh->vrf_id);
			}
			nexthop = route_entry_nexthop_ipv4_add(
				re, &api_nh->gate.ipv4, NULL, api_nh->vrf_id);
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:

			memset(&vtep_ip, 0, sizeof(struct ipaddr));
			ifindex = api_nh->ifindex;
			if (IS_ZEBRA_DEBUG_RECV) {
				char nhbuf[INET6_ADDRSTRLEN] = {0};

				inet_ntop(AF_INET, &api_nh->gate.ipv4, nhbuf,
					  INET6_ADDRSTRLEN);
				zlog_debug(
					"%s: nh=%s, vrf_id=%d (re->vrf_id=%d), ifindex=%d",
					__func__, nhbuf, api_nh->vrf_id,
					re->vrf_id, ifindex);
			}
			nexthop = route_entry_nexthop_ipv4_ifindex_add(
				re, &api_nh->gate.ipv4, NULL, ifindex,
				api_nh->vrf_id);

			/* Special handling for IPv4 routes sourced from EVPN:
			 * the nexthop and associated MAC need to be installed.
			 */
			if (CHECK_FLAG(api.flags, ZEBRA_FLAG_EVPN_ROUTE)) {
				vtep_ip.ipa_type = IPADDR_V4;
				memcpy(&(vtep_ip.ipaddr_v4),
				       &(api_nh->gate.ipv4),
				       sizeof(struct in_addr));
				zebra_vxlan_evpn_vrf_route_add(
					api_nh->vrf_id, &api_nh->rmac,
					&vtep_ip, &api.prefix);
			}
			break;
		case NEXTHOP_TYPE_IPV6:
			nexthop = route_entry_nexthop_ipv6_add(
				re, &api_nh->gate.ipv6, api_nh->vrf_id);
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			memset(&vtep_ip, 0, sizeof(struct ipaddr));
			ifindex = api_nh->ifindex;
			nexthop = route_entry_nexthop_ipv6_ifindex_add(
				re, &api_nh->gate.ipv6, ifindex,
				api_nh->vrf_id);

			/* Special handling for IPv6 routes sourced from EVPN:
			 * the nexthop and associated MAC need to be installed.
			 */
			if (CHECK_FLAG(api.flags, ZEBRA_FLAG_EVPN_ROUTE)) {
				vtep_ip.ipa_type = IPADDR_V6;
				memcpy(&vtep_ip.ipaddr_v6, &(api_nh->gate.ipv6),
				       sizeof(struct in6_addr));
				zebra_vxlan_evpn_vrf_route_add(
					api_nh->vrf_id, &api_nh->rmac,
					&vtep_ip, &api.prefix);
			}
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			nexthop = route_entry_nexthop_blackhole_add(
				re, api_nh->bh_type);
			break;
		}

		if (!nexthop) {
			flog_warn(
				EC_ZEBRA_NEXTHOP_CREATION_FAILED,
				"%s: Nexthops Specified: %d but we failed to properly create one",
				__PRETTY_FUNCTION__, api.nexthop_num);
			nexthop_group_delete(&re->ng);
			XFREE(MTYPE_RE, re);
			return;
		}
		if (api_nh->onlink)
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK);

		/* MPLS labels for BGP-LU or Segment Routing */
		if (CHECK_FLAG(api.message, ZAPI_MESSAGE_LABEL)
		    && api_nh->type != NEXTHOP_TYPE_IFINDEX
		    && api_nh->type != NEXTHOP_TYPE_BLACKHOLE) {
			enum lsp_types_t label_type;

			label_type = lsp_type_from_re_type(client->proto);

			if (IS_ZEBRA_DEBUG_RECV) {
				zlog_debug(
					"%s: adding %d labels of type %d (1st=%u)",
					__func__, api_nh->label_num, label_type,
					api_nh->labels[0]);
			}

			nexthop_add_labels(nexthop, label_type,
					   api_nh->label_num,
					   &api_nh->labels[0]);
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
		flog_warn(EC_ZEBRA_RX_SRCDEST_WRONG_AFI,
			  "%s: Received SRC Prefix but afi is not v6",
			  __PRETTY_FUNCTION__);
		nexthop_group_delete(&re->ng);
		XFREE(MTYPE_RE, re);
		return;
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
}

static void zread_route_del(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct zapi_route api;
	afi_t afi;
	struct prefix_ipv6 *src_p = NULL;
	uint32_t table_id;

	s = msg;
	if (zapi_route_decode(s, &api) < 0)
		return;

	afi = family2afi(api.prefix.family);
	if (afi != AFI_IP6 && CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX)) {
		flog_warn(EC_ZEBRA_RX_SRCDEST_WRONG_AFI,
			  "%s: Received a src prefix while afi is not v6",
			  __PRETTY_FUNCTION__);
		return;
	}
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		src_p = &api.src_prefix;

	if (api.tableid)
		table_id = api.tableid;
	else
		table_id = zvrf->table_id;

	rib_delete(afi, api.safi, zvrf_id(zvrf), api.type, api.instance,
		   api.flags, &api.prefix, src_p, NULL, 0, table_id, api.metric,
		   api.distance, false);

	/* Stats */
	switch (api.prefix.family) {
	case AF_INET:
		client->v4_route_del_cnt++;
		break;
	case AF_INET6:
		client->v6_route_del_cnt++;
		break;
	}
}

/* MRIB Nexthop lookup for IPv4. */
static void zread_ipv4_nexthop_lookup_mrib(ZAPI_HANDLER_ARGS)
{
	struct in_addr addr;
	struct route_entry *re;

	STREAM_GET(&addr.s_addr, msg, IPV4_MAX_BYTELEN);
	re = rib_match_ipv4_multicast(zvrf_id(zvrf), addr, NULL);
	zsend_ipv4_nexthop_lookup_mrib(client, addr, re, zvrf);

stream_failure:
	return;
}

/* Register zebra server router-id information.  Send current router-id */
static void zread_router_id_add(ZAPI_HANDLER_ARGS)
{
	struct prefix p;

	/* Router-id information is needed. */
	vrf_bitmap_set(client->ridinfo, zvrf_id(zvrf));

	router_id_get(&p, zvrf_id(zvrf));

	zsend_router_id_update(client, &p, zvrf_id(zvrf));
}

/* Unregister zebra server router-id information. */
static void zread_router_id_delete(ZAPI_HANDLER_ARGS)
{
	vrf_bitmap_unset(client->ridinfo, zvrf_id(zvrf));
}

static void zsend_capabilities(struct zserv *client, struct zebra_vrf *zvrf)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_CAPABILITIES, zvrf->vrf->vrf_id);
	stream_putl(s, vrf_get_backend());
	stream_putc(s, mpls_enabled);
	stream_putl(s, zrouter.multipath_num);
	stream_putc(s, zebra_mlag_get_role());

	stream_putw_at(s, 0, stream_get_endp(s));
	zserv_send_message(client, s);
}

void zsend_capabilities_all_clients(void)
{
	struct listnode *node, *nnode;
	struct zebra_vrf *zvrf;
	struct zserv *client;

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		zsend_capabilities(client, zvrf);
	}
}

/* Tie up route-type and client->sock */
static void zread_hello(ZAPI_HANDLER_ARGS)
{
	/* type of protocol (lib/zebra.h) */
	uint8_t proto;
	unsigned short instance;
	uint8_t notify;

	STREAM_GETC(msg, proto);
	STREAM_GETW(msg, instance);
	STREAM_GETC(msg, notify);
	if (notify)
		client->notify_owner = true;

	/* accept only dynamic routing protocols */
	if ((proto < ZEBRA_ROUTE_MAX) && (proto > ZEBRA_ROUTE_CONNECT)) {
		zlog_notice(
			"client %d says hello and bids fair to announce only %s routes vrf=%u",
			client->sock, zebra_route_string(proto),
			zvrf->vrf->vrf_id);
		if (instance)
			zlog_notice("client protocol instance %d", instance);

		client->proto = proto;
		client->instance = instance;
	}

	zsend_capabilities(client, zvrf);
	zebra_vrf_update_all(client);
stream_failure:
	return;
}

/* Unregister all information in a VRF. */
static void zread_vrf_unregister(ZAPI_HANDLER_ARGS)
{
	int i;
	afi_t afi;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			vrf_bitmap_unset(client->redist[afi][i], zvrf_id(zvrf));
		vrf_bitmap_unset(client->redist_default[afi], zvrf_id(zvrf));
	}
	vrf_bitmap_unset(client->ridinfo, zvrf_id(zvrf));
}

/*
 * Handle request to create an MPLS LSP.
 *
 * A single message can fully specify an LSP with multiple nexthops.
 *
 * When the optional ZAPI_LABELS_FTN flag is set, the specified FEC (route) is
 * updated to use the received label(s).
 */
static void zread_mpls_labels_add(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct zapi_labels zl;

	/* Get input stream.  */
	s = msg;
	if (zapi_labels_decode(s, &zl) < 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Unable to decode zapi_labels sent",
				   __PRETTY_FUNCTION__);
		return;
	}

	if (!mpls_enabled)
		return;

	for (int i = 0; i < zl.nexthop_num; i++) {
		struct zapi_nexthop_label *znh;

		znh = &zl.nexthops[i];
		mpls_lsp_install(zvrf, zl.type, zl.local_label, znh->label,
				 znh->type, &znh->address, znh->ifindex);

		if (CHECK_FLAG(zl.message, ZAPI_LABELS_FTN))
			mpls_ftn_update(1, zvrf, zl.type, &zl.route.prefix,
					znh->type, &znh->address, znh->ifindex,
					zl.route.type, zl.route.instance,
					znh->label);
	}
}

/*
 * Handle request to delete an MPLS LSP.
 *
 * An LSP is identified by its type and local label. When the received message
 * doesn't contain any nexthop, the whole LSP is deleted. Otherwise, only the
 * listed LSP nexthops (aka NHLFEs) are deleted.
 *
 * When the optional ZAPI_LABELS_FTN flag is set, the labels of the specified
 * FEC (route) nexthops are deleted.
 */
static void zread_mpls_labels_delete(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct zapi_labels zl;

	/* Get input stream.  */
	s = msg;
	if (zapi_labels_decode(s, &zl) < 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Unable to decode zapi_labels sent",
				   __PRETTY_FUNCTION__);
		return;
	}

	if (!mpls_enabled)
		return;

	if (zl.nexthop_num > 0) {
		for (int i = 0; i < zl.nexthop_num; i++) {
			struct zapi_nexthop_label *znh;

			znh = &zl.nexthops[i];
			mpls_lsp_uninstall(zvrf, zl.type, zl.local_label,
					   znh->type, &znh->address,
					   znh->ifindex);

			if (CHECK_FLAG(zl.message, ZAPI_LABELS_FTN))
				mpls_ftn_update(0, zvrf, zl.type,
						&zl.route.prefix, znh->type,
						&znh->address, znh->ifindex,
						zl.route.type,
						zl.route.instance, znh->label);
		}
	} else {
		mpls_lsp_uninstall_all_vrf(zvrf, zl.type, zl.local_label);

		if (CHECK_FLAG(zl.message, ZAPI_LABELS_FTN))
			mpls_ftn_uninstall(zvrf, zl.type, &zl.route.prefix,
					   zl.route.type, zl.route.instance);
	}
}

/*
 * Handle request to add an MPLS LSP or change an existing one.
 *
 * A single message can fully specify an LSP with multiple nexthops.
 *
 * When the optional ZAPI_LABELS_FTN flag is set, the specified FEC (route) is
 * updated to use the received label(s).
 *
 * NOTE: zebra will use route replace semantics (make-before-break) to update
 * the LSP in the forwarding plane if that's supported by the underlying
 * platform.
 */
static void zread_mpls_labels_replace(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct zapi_labels zl;

	/* Get input stream.  */
	s = msg;
	if (zapi_labels_decode(s, &zl) < 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Unable to decode zapi_labels sent",
				   __PRETTY_FUNCTION__);
		return;
	}

	if (!mpls_enabled)
		return;

	mpls_lsp_uninstall_all_vrf(zvrf, zl.type, zl.local_label);
	if (CHECK_FLAG(zl.message, ZAPI_LABELS_FTN))
		mpls_ftn_uninstall(zvrf, zl.type, &zl.route.prefix,
				   zl.route.type, zl.route.instance);

	for (int i = 0; i < zl.nexthop_num; i++) {
		struct zapi_nexthop_label *znh;

		znh = &zl.nexthops[i];
		mpls_lsp_install(zvrf, zl.type, zl.local_label, znh->label,
				 znh->type, &znh->address, znh->ifindex);

		if (CHECK_FLAG(zl.message, ZAPI_LABELS_FTN)) {
			mpls_ftn_update(1, zvrf, zl.type, &zl.route.prefix,
					znh->type, &znh->address, znh->ifindex,
					zl.route.type, zl.route.instance,
					znh->label);
		}
	}
}

/* Send response to a table manager connect request to client */
static void zread_table_manager_connect(struct zserv *client,
					struct stream *msg, vrf_id_t vrf_id)
{
	struct stream *s;
	uint8_t proto;
	uint16_t instance;

	s = msg;

	/* Get data. */
	STREAM_GETC(s, proto);
	STREAM_GETW(s, instance);

	/* accept only dynamic routing protocols */
	if ((proto >= ZEBRA_ROUTE_MAX) || (proto <= ZEBRA_ROUTE_STATIC)) {
		flog_err(EC_ZEBRA_TM_WRONG_PROTO,
			 "client %d has wrong protocol %s", client->sock,
			 zebra_route_string(proto));
		zsend_table_manager_connect_response(client, vrf_id, 1);
		return;
	}
	zlog_notice("client %d with vrf %u instance %u connected as %s",
		    client->sock, vrf_id, instance, zebra_route_string(proto));
	client->proto = proto;
	client->instance = instance;

	/*
	 * Release previous labels of same protocol and instance.
	 * This is done in case it restarted from an unexpected shutdown.
	 */
	release_daemon_table_chunks(client);

	zsend_table_manager_connect_response(client, vrf_id, 0);

stream_failure:
	return;
}

static void zread_label_manager_connect(struct zserv *client,
					struct stream *msg, vrf_id_t vrf_id)
{
	struct stream *s;
	/* type of protocol (lib/zebra.h) */
	uint8_t proto;
	unsigned short instance;

	/* Get input stream.  */
	s = msg;

	/* Get data. */
	STREAM_GETC(s, proto);
	STREAM_GETW(s, instance);

	/* accept only dynamic routing protocols */
	if ((proto >= ZEBRA_ROUTE_MAX) || (proto <= ZEBRA_ROUTE_STATIC)) {
		flog_err(EC_ZEBRA_TM_WRONG_PROTO,
			 "client %d has wrong protocol %s", client->sock,
			 zebra_route_string(proto));
		zsend_label_manager_connect_response(client, vrf_id, 1);
		return;
	}

	/* recall proto and instance in this socket */
	client->proto = proto;
	client->instance = instance;

	/* call hook for connection using wrapper */
	lm_client_connect_call(proto, instance, vrf_id);

stream_failure:
	return;
}

static void zread_get_label_chunk(struct zserv *client, struct stream *msg,
				  vrf_id_t vrf_id)
{
	struct stream *s;
	uint8_t keep;
	uint32_t size, base;
	struct label_manager_chunk *lmc = NULL;
	uint8_t proto;
	unsigned short instance;

	/* Get input stream.  */
	s = msg;

	/* Get data. */
	STREAM_GETC(s, proto);
	STREAM_GETW(s, instance);
	STREAM_GETC(s, keep);
	STREAM_GETL(s, size);
	STREAM_GETL(s, base);

	/* call hook to get a chunk using wrapper */
	lm_get_chunk_call(&lmc, proto, instance, keep, size, base, vrf_id);

	if (!lmc)
		flog_err(
			EC_ZEBRA_LM_CANNOT_ASSIGN_CHUNK,
			"Unable to assign Label Chunk of size %u to %s instance %u",
			size, zebra_route_string(proto), instance);
	else
		if (IS_ZEBRA_DEBUG_PACKET)
			zlog_debug("Assigned Label Chunk %u - %u to %s instance %u",
				   lmc->start, lmc->end,
				   zebra_route_string(proto), instance);

stream_failure:
	return;
}

static void zread_release_label_chunk(struct zserv *client, struct stream *msg)
{
	struct stream *s;
	uint32_t start, end;
	uint8_t proto;
	unsigned short instance;

	/* Get input stream.  */
	s = msg;

	/* Get data. */
	STREAM_GETC(s, proto);
	STREAM_GETW(s, instance);
	STREAM_GETL(s, start);
	STREAM_GETL(s, end);

	/* call hook to release a chunk using wrapper */
	lm_release_chunk_call(proto, instance, start, end);

stream_failure:
	return;
}

static void zread_label_manager_request(ZAPI_HANDLER_ARGS)
{
	if (hdr->command == ZEBRA_LABEL_MANAGER_CONNECT
	    || hdr->command == ZEBRA_LABEL_MANAGER_CONNECT_ASYNC)
		zread_label_manager_connect(client, msg, zvrf_id(zvrf));
	else {
		if (hdr->command == ZEBRA_GET_LABEL_CHUNK)
			zread_get_label_chunk(client, msg, zvrf_id(zvrf));
		else if (hdr->command == ZEBRA_RELEASE_LABEL_CHUNK)
			zread_release_label_chunk(client, msg);
	}
}

static void zread_get_table_chunk(struct zserv *client, struct stream *msg,
				  vrf_id_t vrf_id)
{
	struct stream *s;
	uint32_t size;
	struct table_manager_chunk *tmc;

	/* Get input stream.  */
	s = msg;

	/* Get data. */
	STREAM_GETL(s, size);

	tmc = assign_table_chunk(client->proto, client->instance, size);
	if (!tmc)
		flog_err(EC_ZEBRA_TM_CANNOT_ASSIGN_CHUNK,
			 "%s: Unable to assign Table Chunk of size %u",
			 __func__, size);
	else
		zlog_debug("Assigned Table Chunk %u - %u", tmc->start,
			   tmc->end);
	/* send response back */
	zsend_assign_table_chunk_response(client, vrf_id, tmc);

stream_failure:
	return;
}

static void zread_release_table_chunk(struct zserv *client, struct stream *msg)
{
	struct stream *s;
	uint32_t start, end;

	/* Get input stream.  */
	s = msg;

	/* Get data. */
	STREAM_GETL(s, start);
	STREAM_GETL(s, end);

	release_table_chunk(client->proto, client->instance, start, end);

stream_failure:
	return;
}

static void zread_table_manager_request(ZAPI_HANDLER_ARGS)
{
	/* to avoid sending other messages like ZERBA_INTERFACE_UP */
	if (hdr->command == ZEBRA_TABLE_MANAGER_CONNECT)
		zread_table_manager_connect(client, msg, zvrf_id(zvrf));
	else {
		/* Sanity: don't allow 'unidentified' requests */
		if (!client->proto) {
			flog_err(
				EC_ZEBRA_TM_ALIENS,
				"Got table request from an unidentified client");
			return;
		}
		if (hdr->command == ZEBRA_GET_TABLE_CHUNK)
			zread_get_table_chunk(client, msg, zvrf_id(zvrf));
		else if (hdr->command == ZEBRA_RELEASE_TABLE_CHUNK)
			zread_release_table_chunk(client, msg);
	}
}

static void zread_pseudowire(ZAPI_HANDLER_ARGS)
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
	s = msg;

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
		return;
	}
	STREAM_GETL(s, local_label);
	STREAM_GETL(s, remote_label);
	STREAM_GETC(s, flags);
	STREAM_GET(&data, s, sizeof(data));
	protocol = client->proto;

	pw = zebra_pw_find(zvrf, ifname);
	switch (hdr->command) {
	case ZEBRA_PW_ADD:
		if (pw) {
			flog_warn(EC_ZEBRA_PSEUDOWIRE_EXISTS,
				  "%s: pseudowire %s already exists [%s]",
				  __func__, ifname,
				  zserv_command_string(hdr->command));
			return;
		}

		zebra_pw_add(zvrf, ifname, protocol, client);
		break;
	case ZEBRA_PW_DELETE:
		if (!pw) {
			flog_warn(EC_ZEBRA_PSEUDOWIRE_NONEXISTENT,
				  "%s: pseudowire %s not found [%s]", __func__,
				  ifname, zserv_command_string(hdr->command));
			return;
		}

		zebra_pw_del(zvrf, pw);
		break;
	case ZEBRA_PW_SET:
	case ZEBRA_PW_UNSET:
		if (!pw) {
			flog_warn(EC_ZEBRA_PSEUDOWIRE_NONEXISTENT,
				  "%s: pseudowire %s not found [%s]", __func__,
				  ifname, zserv_command_string(hdr->command));
			return;
		}

		switch (hdr->command) {
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
	return;
}

static void zread_interface_set_master(ZAPI_HANDLER_ARGS)
{
	struct interface *master;
	struct interface *slave;
	struct stream *s = msg;
	int ifindex;
	vrf_id_t vrf_id;

	STREAM_GETL(s, vrf_id);
	STREAM_GETL(s, ifindex);
	master = if_lookup_by_index(ifindex, vrf_id);

	STREAM_GETL(s, vrf_id);
	STREAM_GETL(s, ifindex);
	slave = if_lookup_by_index(ifindex, vrf_id);

	if (!master || !slave)
		return;

	kernel_interface_set_master(master, slave);

stream_failure:
	return;
}


static void zread_vrf_label(ZAPI_HANDLER_ARGS)
{
	struct interface *ifp;
	mpls_label_t nlabel;
	afi_t afi;
	struct stream *s;
	struct zebra_vrf *def_zvrf;
	enum lsp_types_t ltype;

	s = msg;
	STREAM_GETL(s, nlabel);
	STREAM_GETC(s, afi);
	if (nlabel == zvrf->label[afi]) {
		/*
		 * Nothing to do here move along
		 */
		return;
	}

	STREAM_GETC(s, ltype);

	if (zvrf->vrf->vrf_id != VRF_DEFAULT)
		ifp = if_lookup_by_name(zvrf->vrf->name, zvrf->vrf->vrf_id);
	else
		ifp = if_lookup_by_name("lo", VRF_DEFAULT);

	if (!ifp) {
		zlog_debug("Unable to find specified Interface for %s",
			   zvrf->vrf->name);
		return;
	}

	def_zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	if (zvrf->label[afi] != MPLS_LABEL_NONE) {
		afi_t scrubber;
		bool really_remove;

		really_remove = true;
		for (scrubber = AFI_IP; scrubber < AFI_MAX; scrubber++) {
			if (scrubber == afi)
				continue;

			if (zvrf->label[scrubber] == MPLS_LABEL_NONE)
				continue;

			if (zvrf->label[afi] == zvrf->label[scrubber]) {
				really_remove = false;
				break;
			}
		}

		if (really_remove)
			mpls_lsp_uninstall(def_zvrf, ltype, zvrf->label[afi],
					   NEXTHOP_TYPE_IFINDEX, NULL,
					   ifp->ifindex);
	}

	if (nlabel != MPLS_LABEL_NONE)
		mpls_lsp_install(def_zvrf, ltype, nlabel,
				 MPLS_LABEL_IMPLICIT_NULL, NEXTHOP_TYPE_IFINDEX,
				 NULL, ifp->ifindex);

	zvrf->label[afi] = nlabel;
stream_failure:
	return;
}

static inline void zread_rule(ZAPI_HANDLER_ARGS)
{
	struct zebra_pbr_rule zpr;
	struct stream *s;
	uint32_t total, i;

	s = msg;
	STREAM_GETL(s, total);

	for (i = 0; i < total; i++) {
		memset(&zpr, 0, sizeof(zpr));

		zpr.sock = client->sock;
		zpr.rule.vrf_id = hdr->vrf_id;
		STREAM_GETL(s, zpr.rule.seq);
		STREAM_GETL(s, zpr.rule.priority);
		STREAM_GETL(s, zpr.rule.unique);
		STREAM_GETC(s, zpr.rule.filter.src_ip.family);
		STREAM_GETC(s, zpr.rule.filter.src_ip.prefixlen);
		STREAM_GET(&zpr.rule.filter.src_ip.u.prefix, s,
			   prefix_blen(&zpr.rule.filter.src_ip));
		STREAM_GETW(s, zpr.rule.filter.src_port);
		STREAM_GETC(s, zpr.rule.filter.dst_ip.family);
		STREAM_GETC(s, zpr.rule.filter.dst_ip.prefixlen);
		STREAM_GET(&zpr.rule.filter.dst_ip.u.prefix, s,
			   prefix_blen(&zpr.rule.filter.dst_ip));
		STREAM_GETW(s, zpr.rule.filter.dst_port);
		STREAM_GETL(s, zpr.rule.filter.fwmark);
		STREAM_GETL(s, zpr.rule.action.table);
		STREAM_GETL(s, zpr.rule.ifindex);

		if (zpr.rule.ifindex) {
			struct interface *ifp;

			ifp = if_lookup_by_index_per_ns(zvrf->zns,
							zpr.rule.ifindex);
			if (!ifp) {
				zlog_debug("Failed to lookup ifindex: %u",
					   zpr.rule.ifindex);
				return;
			}

			strlcpy(zpr.ifname, ifp->name, sizeof(zpr.ifname));
		}

		if (!is_default_prefix(&zpr.rule.filter.src_ip))
			zpr.rule.filter.filter_bm |= PBR_FILTER_SRC_IP;

		if (!is_default_prefix(&zpr.rule.filter.dst_ip))
			zpr.rule.filter.filter_bm |= PBR_FILTER_DST_IP;

		if (zpr.rule.filter.src_port)
			zpr.rule.filter.filter_bm |= PBR_FILTER_SRC_PORT;

		if (zpr.rule.filter.dst_port)
			zpr.rule.filter.filter_bm |= PBR_FILTER_DST_PORT;

		if (zpr.rule.filter.fwmark)
			zpr.rule.filter.filter_bm |= PBR_FILTER_FWMARK;

		zpr.vrf_id = zvrf->vrf->vrf_id;
		if (hdr->command == ZEBRA_RULE_ADD)
			zebra_pbr_add_rule(&zpr);
		else
			zebra_pbr_del_rule(&zpr);
	}

stream_failure:
	return;
}

static inline void zread_ipset(ZAPI_HANDLER_ARGS)
{
	struct zebra_pbr_ipset zpi;
	struct stream *s;
	uint32_t total, i;

	s = msg;
	STREAM_GETL(s, total);

	for (i = 0; i < total; i++) {
		memset(&zpi, 0, sizeof(zpi));

		zpi.sock = client->sock;
		zpi.vrf_id = zvrf->vrf->vrf_id;
		STREAM_GETL(s, zpi.unique);
		STREAM_GETL(s, zpi.type);
		STREAM_GET(&zpi.ipset_name, s, ZEBRA_IPSET_NAME_SIZE);

		if (hdr->command == ZEBRA_IPSET_CREATE)
			zebra_pbr_create_ipset(&zpi);
		else
			zebra_pbr_destroy_ipset(&zpi);
	}

stream_failure:
	return;
}

static inline void zread_ipset_entry(ZAPI_HANDLER_ARGS)
{
	struct zebra_pbr_ipset_entry zpi;
	struct zebra_pbr_ipset ipset;
	struct stream *s;
	uint32_t total, i;

	s = msg;
	STREAM_GETL(s, total);

	for (i = 0; i < total; i++) {
		memset(&zpi, 0, sizeof(zpi));
		memset(&ipset, 0, sizeof(ipset));

		zpi.sock = client->sock;
		STREAM_GETL(s, zpi.unique);
		STREAM_GET(&ipset.ipset_name, s, ZEBRA_IPSET_NAME_SIZE);
		STREAM_GETC(s, zpi.src.family);
		STREAM_GETC(s, zpi.src.prefixlen);
		STREAM_GET(&zpi.src.u.prefix, s, prefix_blen(&zpi.src));
		STREAM_GETC(s, zpi.dst.family);
		STREAM_GETC(s, zpi.dst.prefixlen);
		STREAM_GET(&zpi.dst.u.prefix, s, prefix_blen(&zpi.dst));

		STREAM_GETW(s, zpi.src_port_min);
		STREAM_GETW(s, zpi.src_port_max);
		STREAM_GETW(s, zpi.dst_port_min);
		STREAM_GETW(s, zpi.dst_port_max);
		STREAM_GETC(s, zpi.proto);
		if (!is_default_prefix(&zpi.src))
			zpi.filter_bm |= PBR_FILTER_SRC_IP;

		if (!is_default_prefix(&zpi.dst))
			zpi.filter_bm |= PBR_FILTER_DST_IP;
		if (zpi.dst_port_min != 0 || zpi.proto == IPPROTO_ICMP)
			zpi.filter_bm |= PBR_FILTER_DST_PORT;
		if (zpi.src_port_min != 0 || zpi.proto == IPPROTO_ICMP)
			zpi.filter_bm |= PBR_FILTER_SRC_PORT;
		if (zpi.dst_port_max != 0)
			zpi.filter_bm |= PBR_FILTER_DST_PORT_RANGE;
		if (zpi.src_port_max != 0)
			zpi.filter_bm |= PBR_FILTER_SRC_PORT_RANGE;
		if (zpi.proto != 0)
			zpi.filter_bm |= PBR_FILTER_PROTO;

		/* calculate backpointer */
		zpi.backpointer =
			zebra_pbr_lookup_ipset_pername(ipset.ipset_name);
		if (hdr->command == ZEBRA_IPSET_ENTRY_ADD)
			zebra_pbr_add_ipset_entry(&zpi);
		else
			zebra_pbr_del_ipset_entry(&zpi);
	}

stream_failure:
	return;
}

static inline void zread_iptable(ZAPI_HANDLER_ARGS)
{
	struct zebra_pbr_iptable zpi;
	struct stream *s;

	s = msg;

	memset(&zpi, 0, sizeof(zpi));

	zpi.interface_name_list = list_new();
	zpi.sock = client->sock;
	zpi.vrf_id = zvrf->vrf->vrf_id;
	STREAM_GETL(s, zpi.unique);
	STREAM_GETL(s, zpi.type);
	STREAM_GETL(s, zpi.filter_bm);
	STREAM_GETL(s, zpi.action);
	STREAM_GETL(s, zpi.fwmark);
	STREAM_GET(&zpi.ipset_name, s, ZEBRA_IPSET_NAME_SIZE);
	STREAM_GETW(s, zpi.pkt_len_min);
	STREAM_GETW(s, zpi.pkt_len_max);
	STREAM_GETW(s, zpi.tcp_flags);
	STREAM_GETW(s, zpi.tcp_mask_flags);
	STREAM_GETC(s, zpi.dscp_value);
	STREAM_GETC(s, zpi.fragment);
	STREAM_GETC(s, zpi.protocol);
	STREAM_GETL(s, zpi.nb_interface);
	zebra_pbr_iptable_update_interfacelist(s, &zpi);

	if (hdr->command == ZEBRA_IPTABLE_ADD)
		zebra_pbr_add_iptable(&zpi);
	else
		zebra_pbr_del_iptable(&zpi);
stream_failure:
	return;
}

void (*zserv_handlers[])(ZAPI_HANDLER_ARGS) = {
	[ZEBRA_ROUTER_ID_ADD] = zread_router_id_add,
	[ZEBRA_ROUTER_ID_DELETE] = zread_router_id_delete,
	[ZEBRA_INTERFACE_ADD] = zread_interface_add,
	[ZEBRA_INTERFACE_DELETE] = zread_interface_delete,
	[ZEBRA_INTERFACE_SET_PROTODOWN] = zread_interface_set_protodown,
	[ZEBRA_ROUTE_ADD] = zread_route_add,
	[ZEBRA_ROUTE_DELETE] = zread_route_del,
	[ZEBRA_REDISTRIBUTE_ADD] = zebra_redistribute_add,
	[ZEBRA_REDISTRIBUTE_DELETE] = zebra_redistribute_delete,
	[ZEBRA_REDISTRIBUTE_DEFAULT_ADD] = zebra_redistribute_default_add,
	[ZEBRA_REDISTRIBUTE_DEFAULT_DELETE] = zebra_redistribute_default_delete,
	[ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB] = zread_ipv4_nexthop_lookup_mrib,
	[ZEBRA_HELLO] = zread_hello,
	[ZEBRA_NEXTHOP_REGISTER] = zread_rnh_register,
	[ZEBRA_NEXTHOP_UNREGISTER] = zread_rnh_unregister,
	[ZEBRA_IMPORT_ROUTE_REGISTER] = zread_rnh_register,
	[ZEBRA_IMPORT_ROUTE_UNREGISTER] = zread_rnh_unregister,
	[ZEBRA_BFD_DEST_UPDATE] = zebra_ptm_bfd_dst_register,
	[ZEBRA_BFD_DEST_REGISTER] = zebra_ptm_bfd_dst_register,
	[ZEBRA_BFD_DEST_DEREGISTER] = zebra_ptm_bfd_dst_deregister,
#if HAVE_BFDD > 0
	[ZEBRA_BFD_DEST_REPLAY] = zebra_ptm_bfd_dst_replay,
#endif /* HAVE_BFDD */
	[ZEBRA_VRF_UNREGISTER] = zread_vrf_unregister,
	[ZEBRA_VRF_LABEL] = zread_vrf_label,
	[ZEBRA_BFD_CLIENT_REGISTER] = zebra_ptm_bfd_client_register,
#if defined(HAVE_RTADV)
	[ZEBRA_INTERFACE_ENABLE_RADV] = zebra_interface_radv_enable,
	[ZEBRA_INTERFACE_DISABLE_RADV] = zebra_interface_radv_disable,
#else
	[ZEBRA_INTERFACE_ENABLE_RADV] = NULL,
	[ZEBRA_INTERFACE_DISABLE_RADV] = NULL,
#endif
	[ZEBRA_MPLS_LABELS_ADD] = zread_mpls_labels_add,
	[ZEBRA_MPLS_LABELS_DELETE] = zread_mpls_labels_delete,
	[ZEBRA_MPLS_LABELS_REPLACE] = zread_mpls_labels_replace,
	[ZEBRA_IPMR_ROUTE_STATS] = zebra_ipmr_route_stats,
	[ZEBRA_LABEL_MANAGER_CONNECT] = zread_label_manager_request,
	[ZEBRA_LABEL_MANAGER_CONNECT_ASYNC] = zread_label_manager_request,
	[ZEBRA_GET_LABEL_CHUNK] = zread_label_manager_request,
	[ZEBRA_RELEASE_LABEL_CHUNK] = zread_label_manager_request,
	[ZEBRA_FEC_REGISTER] = zread_fec_register,
	[ZEBRA_FEC_UNREGISTER] = zread_fec_unregister,
	[ZEBRA_ADVERTISE_DEFAULT_GW] = zebra_vxlan_advertise_gw_macip,
	[ZEBRA_ADVERTISE_SVI_MACIP] = zebra_vxlan_advertise_svi_macip,
	[ZEBRA_ADVERTISE_SUBNET] = zebra_vxlan_advertise_subnet,
	[ZEBRA_ADVERTISE_ALL_VNI] = zebra_vxlan_advertise_all_vni,
	[ZEBRA_REMOTE_VTEP_ADD] = zebra_vxlan_remote_vtep_add,
	[ZEBRA_REMOTE_VTEP_DEL] = zebra_vxlan_remote_vtep_del,
	[ZEBRA_REMOTE_MACIP_ADD] = zebra_vxlan_remote_macip_add,
	[ZEBRA_REMOTE_MACIP_DEL] = zebra_vxlan_remote_macip_del,
	[ZEBRA_DUPLICATE_ADDR_DETECTION] = zebra_vxlan_dup_addr_detection,
	[ZEBRA_INTERFACE_SET_MASTER] = zread_interface_set_master,
	[ZEBRA_PW_ADD] = zread_pseudowire,
	[ZEBRA_PW_DELETE] = zread_pseudowire,
	[ZEBRA_PW_SET] = zread_pseudowire,
	[ZEBRA_PW_UNSET] = zread_pseudowire,
	[ZEBRA_RULE_ADD] = zread_rule,
	[ZEBRA_RULE_DELETE] = zread_rule,
	[ZEBRA_TABLE_MANAGER_CONNECT] = zread_table_manager_request,
	[ZEBRA_GET_TABLE_CHUNK] = zread_table_manager_request,
	[ZEBRA_RELEASE_TABLE_CHUNK] = zread_table_manager_request,
	[ZEBRA_IPSET_CREATE] = zread_ipset,
	[ZEBRA_IPSET_DESTROY] = zread_ipset,
	[ZEBRA_IPSET_ENTRY_ADD] = zread_ipset_entry,
	[ZEBRA_IPSET_ENTRY_DELETE] = zread_ipset_entry,
	[ZEBRA_IPTABLE_ADD] = zread_iptable,
	[ZEBRA_IPTABLE_DELETE] = zread_iptable,
	[ZEBRA_VXLAN_FLOOD_CONTROL] = zebra_vxlan_flood_control,
	[ZEBRA_VXLAN_SG_REPLAY] = zebra_vxlan_sg_replay,
};

#if defined(HANDLE_ZAPI_FUZZING)
extern struct zebra_privs_t zserv_privs;

static void zserv_write_incoming(struct stream *orig, uint16_t command)
{
	char fname[MAXPATHLEN];
	struct stream *copy;
	int fd = -1;

	copy = stream_dup(orig);
	stream_set_getp(copy, 0);

	snprintf(fname, MAXPATHLEN, "%s/%u", frr_vtydir, command);

	frr_with_privs(&zserv_privs) {
		fd = open(fname, O_CREAT | O_WRONLY | O_EXCL, 0644);
	}
	stream_flush(copy, fd);
	close(fd);
	stream_free(copy);
}
#endif

void zserv_handle_commands(struct zserv *client, struct stream *msg)
{
	struct zmsghdr hdr;
	struct zebra_vrf *zvrf;

	zapi_parse_header(msg, &hdr);

	if (IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV)
		zserv_log_message(NULL, msg, &hdr);

#if defined(HANDLE_ZAPI_FUZZING)
	zserv_write_incoming(msg, hdr.command);
#endif

	hdr.length -= ZEBRA_HEADER_SIZE;

	/* lookup vrf */
	zvrf = zebra_vrf_lookup_by_id(hdr.vrf_id);
	if (!zvrf) {
		if (IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV)
			zlog_debug("ZAPI message specifies unknown VRF: %d",
				   hdr.vrf_id);
		return;
	}

	if (hdr.command >= array_size(zserv_handlers)
	    || zserv_handlers[hdr.command] == NULL)
		zlog_info("Zebra received unknown command %d", hdr.command);
	else
		zserv_handlers[hdr.command](client, &hdr, msg, zvrf);
}
