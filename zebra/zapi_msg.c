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
#include "lib/stream.h"
#include "lib/memory.h"
#include "lib/table.h"
#include "lib/network.h"
#include "lib/log.h"
#include "lib/zclient.h"
#include "lib/privs.h"
#include "lib/nexthop.h"
#include "lib/vrf.h"
#include "lib/libfrr.h"
#include "lib/lib_errors.h"

#include "zebra/zebra_router.h"
#include "zebra/rib.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/router-id.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/zebra_rnh.h"
#include "zebra/interface.h"
#include "zebra/zebra_ptm.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_mroute.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/rt.h"
#include "zebra/zebra_pbr.h"
#include "zebra/table_manager.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_mlag.h"
#include "zebra/connected.h"
#include "zebra/zebra_opaque.h"
#include "zebra/zebra_srte.h"

DEFINE_MTYPE_STATIC(ZEBRA, OPAQUE, "Opaque Data");

static int zapi_nhg_decode(struct stream *s, int cmd, struct zapi_nhg *api_nhg);

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

	memset(&data, 0, sizeof(data));
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

/*
 * Zebra error addition adds error type.
 *
 *
 *  0                   1
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      enum zebra_error_types   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
static void zserv_encode_error(struct stream *s, enum zebra_error_types error)
{
	stream_put(s, &error, sizeof(error));

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));
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

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

		zsend_interface_nbr_address(ZEBRA_INTERFACE_NBR_ADDRESS_ADD,
					    client, ifp, ifc);
	}
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

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

		zsend_interface_nbr_address(ZEBRA_INTERFACE_NBR_ADDRESS_DELETE,
					    client, ifp, ifc);
	}
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

	for (nexthop = re->nhe->nhg.nexthop;
	     nexthop; nexthop = nexthop->next) {
		if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
			continue;

		api_nh = &api.nexthops[count];
		api_nh->vrf_id = nexthop->vrf_id;
		api_nh->type = nexthop->type;
		api_nh->weight = nexthop->weight;
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

	if (IS_ZEBRA_DEBUG_SEND)
		zlog_debug("%s: %s to client %s: type %s, vrf_id %d, p %pFX",
			   __func__, zserv_command_string(cmd),
			   zebra_route_string(client->proto),
			   zebra_route_string(api.type), api.vrf_id,
			   &api.prefix);
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
		for (nexthop = re->nhe->nhg.nexthop; nexthop;
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

int zsend_nhg_notify(uint16_t type, uint16_t instance, uint32_t session_id,
		     uint32_t id, enum zapi_nhg_notify_owner note)
{
	struct zserv *client;
	struct stream *s;

	client = zserv_find_client_session(type, instance, session_id);
	if (!client) {
		if (IS_ZEBRA_DEBUG_PACKET) {
			zlog_debug("Not Notifying Owner: %u(%u) about %u(%d)",
				   type, instance, id, note);
		}
		return 0;
	}

	if (IS_ZEBRA_DEBUG_SEND)
		zlog_debug("%s: type %d, id %d, note %s",
			   __func__, type, id, zapi_nhg_notify_owner2str(note));

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	stream_reset(s);

	zclient_create_header(s, ZEBRA_NHG_NOTIFY_OWNER, VRF_DEFAULT);

	stream_put(s, &note, sizeof(note));
	stream_putl(s, id);

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
				 enum zapi_route_notify_owner note,
				 afi_t afi, safi_t safi)
{
	struct zserv *client;
	struct stream *s;
	uint8_t blen;

	client = zserv_find_client(type, instance);
	if (!client || !client->notify_owner) {
		if (IS_ZEBRA_DEBUG_PACKET)
			zlog_debug(
				"Not Notifying Owner: %s about prefix %pFX(%u) %d vrf: %u",
				zebra_route_string(type), p, table_id, note,
				vrf_id);
		return 0;
	}

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug(
			"Notifying Owner: %s about prefix %pFX(%u) %d vrf: %u",
			zebra_route_string(type), p, table_id, note, vrf_id);

	/* We're just allocating a small-ish buffer here, since we only
	 * encode a small amount of data.
	 */
	s = stream_new(ZEBRA_SMALL_PACKET_SIZE);

	stream_reset(s);

	zclient_create_header(s, ZEBRA_ROUTE_NOTIFY_OWNER, vrf_id);

	stream_put(s, &note, sizeof(note));

	stream_putc(s, p->family);

	blen = prefix_blen(p);
	stream_putc(s, p->prefixlen);
	stream_put(s, &p->u.prefix, blen);

	stream_putl(s, table_id);

	/* Encode AFI, SAFI in the message */
	stream_putc(s, afi);
	stream_putc(s, safi);

	stream_putw_at(s, 0, stream_get_endp(s));

	return zserv_send_message(client, s);
}

int zsend_route_notify_owner(struct route_entry *re, const struct prefix *p,
			     enum zapi_route_notify_owner note,
			     afi_t afi, safi_t safi)
{
	return (route_notify_internal(p, re->type, re->instance, re->vrf_id,
				      re->table, note, afi, safi));
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
				      note,
				      dplane_ctx_get_afi(ctx),
				      dplane_ctx_get_safi(ctx)));
}

static void zread_route_notify_request(ZAPI_HANDLER_ARGS)
{
	uint8_t notify;

	STREAM_GETC(msg, notify);
	client->notify_owner = notify;
stream_failure:
	return;
}

void zsend_rule_notify_owner(const struct zebra_dplane_ctx *ctx,
			     enum zapi_rule_notify_owner note)
{
	struct listnode *node;
	struct zserv *client;
	struct stream *s;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Notifying %u", __func__,
			   dplane_ctx_rule_get_unique(ctx));

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (dplane_ctx_rule_get_sock(ctx) == client->sock)
			break;
	}

	if (!client)
		return;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_RULE_NOTIFY_OWNER, VRF_DEFAULT);
	stream_put(s, &note, sizeof(note));
	stream_putl(s, dplane_ctx_rule_get_seq(ctx));
	stream_putl(s, dplane_ctx_rule_get_priority(ctx));
	stream_putl(s, dplane_ctx_rule_get_unique(ctx));
	stream_put(s, dplane_ctx_rule_get_ifname(ctx), INTERFACE_NAMSIZ);

	stream_putw_at(s, 0, stream_get_endp(s));

	zserv_send_message(client, s);
}

void zsend_iptable_notify_owner(const struct zebra_dplane_ctx *ctx,
				uint16_t note)
{
	struct listnode *node;
	struct zserv *client;
	struct stream *s;
	struct zebra_pbr_iptable ipt;
	uint16_t cmd = ZEBRA_IPTABLE_NOTIFY_OWNER;

	if (!dplane_ctx_get_pbr_iptable(ctx, &ipt))
		return;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Notifying %s id %u note %u", __func__,
			   zserv_command_string(cmd), ipt.unique, note);

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (ipt.sock == client->sock)
			break;
	}

	if (!client)
		return;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, cmd, VRF_DEFAULT);
	stream_put(s, &note, sizeof(note));
	stream_putl(s, ipt.unique);
	stream_put(s, ipt.ipset_name, ZEBRA_IPSET_NAME_SIZE);
	stream_putw_at(s, 0, stream_get_endp(s));

	zserv_send_message(client, s);
}

void zsend_ipset_notify_owner(const struct zebra_dplane_ctx *ctx, uint16_t note)
{
	struct listnode *node;
	struct zserv *client;
	struct stream *s;
	struct zebra_pbr_ipset ipset;
	uint16_t cmd = ZEBRA_IPSET_NOTIFY_OWNER;

	if (!dplane_ctx_get_pbr_ipset(ctx, &ipset))
		return;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Notifying %s id %u note %u", __func__,
			   zserv_command_string(cmd), ipset.unique, note);

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (ipset.sock == client->sock)
			break;
	}

	if (!client)
		return;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, cmd, VRF_DEFAULT);
	stream_put(s, &note, sizeof(note));
	stream_putl(s, ipset.unique);
	stream_put(s, ipset.ipset_name, ZEBRA_IPSET_NAME_SIZE);
	stream_putw_at(s, 0, stream_get_endp(s));

	zserv_send_message(client, s);
}

void zsend_ipset_entry_notify_owner(const struct zebra_dplane_ctx *ctx,
				    uint16_t note)
{
	struct listnode *node;
	struct zserv *client;
	struct stream *s;
	struct zebra_pbr_ipset_entry ipent;
	struct zebra_pbr_ipset ipset;
	uint16_t cmd = ZEBRA_IPSET_ENTRY_NOTIFY_OWNER;

	if (!dplane_ctx_get_pbr_ipset_entry(ctx, &ipent))
		return;
	if (!dplane_ctx_get_pbr_ipset(ctx, &ipset))
		return;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Notifying %s id %u note %u", __func__,
			   zserv_command_string(cmd), ipent.unique, note);

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (ipent.sock == client->sock)
			break;
	}

	if (!client)
		return;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, cmd, VRF_DEFAULT);
	stream_put(s, &note, sizeof(note));
	stream_putl(s, ipent.unique);
	stream_put(s, ipset.ipset_name, ZEBRA_IPSET_NAME_SIZE);
	stream_putw_at(s, 0, stream_get_endp(s));

	zserv_send_message(client, s);
}

void zsend_nhrp_neighbor_notify(int cmd, struct interface *ifp,
				struct ipaddr *ipaddr, int ndm_state,
				union sockunion *link_layer_ipv4)
{
	struct stream *s;
	struct listnode *node, *nnode;
	struct zserv *client;
	afi_t afi;
	union sockunion ip;

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s: Notifying Neighbor entry (%u)", __func__, cmd);

	sockunion_family(&ip) = ipaddr_family(ipaddr);
	afi = family2afi(sockunion_family(&ip));
	memcpy((char *)sockunion_get_addr(&ip), &ipaddr->ip.addr,
	       family2addrsize(sockunion_family(&ip)));

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		if (!vrf_bitmap_check(client->nhrp_neighinfo[afi], ifp->vrf_id))
			continue;

		s = stream_new(ZEBRA_MAX_PACKET_SIZ);
		zclient_neigh_ip_encode(s, cmd, &ip, link_layer_ipv4, ifp);
		stream_putw_at(s, 0, stream_get_endp(s));
		zserv_send_message(client, s);
	}
}


/* Router-id is updated. Send ZEBRA_ROUTER_ID_UPDATE to client. */
int zsend_router_id_update(struct zserv *client, afi_t afi, struct prefix *p,
			   vrf_id_t vrf_id)
{
	int blen;
	struct stream *s;

	/* Check this client need interface information. */
	if (!vrf_bitmap_check(client->ridinfo[afi], vrf_id))
		return 0;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

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
				      struct label_manager_chunk *lmc)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_GET_LABEL_CHUNK, vrf_id);
	/* proto */
	stream_putc(s, client->proto);
	/* instance */
	stream_putw(s, client->instance);

	if (lmc) {
		/* keep */
		stream_putc(s, lmc->keep);
		/* start and end labels */
		stream_putl(s, lmc->start);
		stream_putl(s, lmc->end);
	}

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zserv_send_message(client, s);
}

/* Send response to a label manager connect request to client */
int zsend_label_manager_connect_response(struct zserv *client, vrf_id_t vrf_id,
					 unsigned short result)
{
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

	return zserv_send_message(client, s);
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

const int cmd2type[] = {
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
			"rnh_register msg from client %s: hdr->length=%d, type=%s vrf=%u",
			zebra_route_string(client->proto), hdr->length,
			(type == RNH_NEXTHOP_TYPE) ? "nexthop" : "route",
			zvrf->vrf->vrf_id);

	s = msg;

	if (!client->nh_reg_time)
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
					__func__, p.prefixlen);
				return;
			}
			STREAM_GET(&p.u.prefix4.s_addr, s, IPV4_MAX_BYTELEN);
			l += IPV4_MAX_BYTELEN;
		} else if (p.family == AF_INET6) {
			client->v6_nh_watch_add_cnt++;
			if (p.prefixlen > IPV6_MAX_BITLEN) {
				zlog_debug(
					"%s: Specified prefix hdr->length %d is to large for a v6 address",
					__func__, p.prefixlen);
				return;
			}
			STREAM_GET(&p.u.prefix6, s, IPV6_MAX_BYTELEN);
			l += IPV6_MAX_BYTELEN;
		} else {
			flog_err(
				EC_ZEBRA_UNKNOWN_FAMILY,
				"rnh_register: Received unknown family type %d",
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
			"rnh_unregister msg from client %s: hdr->length=%d vrf: %u",
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
					__func__, p.prefixlen);
				return;
			}
			STREAM_GET(&p.u.prefix4.s_addr, s, IPV4_MAX_BYTELEN);
			l += IPV4_MAX_BYTELEN;
		} else if (p.family == AF_INET6) {
			client->v6_nh_watch_rem_cnt++;
			if (p.prefixlen > IPV6_MAX_BITLEN) {
				zlog_debug(
					"%s: Specified prefix hdr->length %d is to large for a v6 address",
					__func__, p.prefixlen);
				return;
			}
			STREAM_GET(&p.u.prefix6, s, IPV6_MAX_BYTELEN);
			l += IPV6_MAX_BYTELEN;
		} else {
			flog_err(
				EC_ZEBRA_UNKNOWN_FAMILY,
				"rnh_register: Received unknown family type %d",
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
				"fec_register: Received unknown family type %d",
				p.family);
			return;
		}
		STREAM_GETC(s, p.prefixlen);
		if ((p.family == AF_INET && p.prefixlen > IPV4_MAX_BITLEN)
		    || (p.family == AF_INET6
			&& p.prefixlen > IPV6_MAX_BITLEN)) {
			zlog_debug(
				"%s: Specified prefix hdr->length: %d is to long for %d",
				__func__, p.prefixlen, p.family);
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
				"fec_unregister: Received unknown family type %d",
				p.family);
			return;
		}
		STREAM_GETC(s, p.prefixlen);
		if ((p.family == AF_INET && p.prefixlen > IPV4_MAX_BITLEN)
		    || (p.family == AF_INET6
			&& p.prefixlen > IPV6_MAX_BITLEN)) {
			zlog_debug(
				"%s: Received prefix hdr->length %d which is greater than %d can support",
				__func__, p.prefixlen, p.family);
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

	vrf_id_t vrf_id = zvrf_id(zvrf);
	if (vrf_id != VRF_DEFAULT && vrf_id != VRF_UNKNOWN) {
		FOR_ALL_INTERFACES (zvrf->vrf, ifp) {
			/* Skip pseudo interface. */
			if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE))
				continue;

			zsend_interface_add(client, ifp);
			zsend_interface_link_params(client, ifp);
			zsend_interface_addresses(client, ifp);
		}
		return;
	}

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

bool zserv_nexthop_num_warn(const char *caller, const struct prefix *p,
			    const unsigned int nexthop_num)
{
	if (nexthop_num > zrouter.multipath_num) {
		char buff[PREFIX2STR_BUFFER];

		if (p)
			prefix2str(p, buff, sizeof(buff));

		flog_warn(
			EC_ZEBRA_MORE_NH_THAN_MULTIPATH,
			"%s: Prefix %s has %d nexthops, but we can only use the first %d",
			caller, (p ? buff : "(NULL)"), nexthop_num,
			zrouter.multipath_num);
		return true;
	}

	return false;
}

/*
 * Create a new nexthop based on a zapi nexthop.
 */
static struct nexthop *nexthop_from_zapi(const struct zapi_nexthop *api_nh,
					 uint32_t flags, struct prefix *p,
					 uint16_t backup_nexthop_num)
{
	struct nexthop *nexthop = NULL;
	struct ipaddr vtep_ip;
	struct interface *ifp;
	int i;
	char nhbuf[INET6_ADDRSTRLEN] = "";

	switch (api_nh->type) {
	case NEXTHOP_TYPE_IFINDEX:
		nexthop = nexthop_from_ifindex(api_nh->ifindex, api_nh->vrf_id);
		break;
	case NEXTHOP_TYPE_IPV4:
		if (IS_ZEBRA_DEBUG_RECV) {
			inet_ntop(AF_INET, &api_nh->gate.ipv4, nhbuf,
				  sizeof(nhbuf));
			zlog_debug("%s: nh=%s, vrf_id=%d", __func__,
				   nhbuf, api_nh->vrf_id);
		}
		nexthop = nexthop_from_ipv4(&api_nh->gate.ipv4, NULL,
					    api_nh->vrf_id);
		break;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		if (IS_ZEBRA_DEBUG_RECV) {
			inet_ntop(AF_INET, &api_nh->gate.ipv4, nhbuf,
				  sizeof(nhbuf));
			zlog_debug("%s: nh=%s, vrf_id=%d, ifindex=%d",
				   __func__, nhbuf, api_nh->vrf_id,
				   api_nh->ifindex);
		}

		nexthop = nexthop_from_ipv4_ifindex(
			&api_nh->gate.ipv4, NULL, api_nh->ifindex,
			api_nh->vrf_id);

		/* Special handling for IPv4 routes sourced from EVPN:
		 * the nexthop and associated MAC need to be installed.
		 */
		if (CHECK_FLAG(flags, ZEBRA_FLAG_EVPN_ROUTE)) {
			memset(&vtep_ip, 0, sizeof(struct ipaddr));
			vtep_ip.ipa_type = IPADDR_V4;
			memcpy(&(vtep_ip.ipaddr_v4), &(api_nh->gate.ipv4),
			       sizeof(struct in_addr));
			zebra_vxlan_evpn_vrf_route_add(
				api_nh->vrf_id, &api_nh->rmac, &vtep_ip, p);
		}
		break;
	case NEXTHOP_TYPE_IPV6:
		if (IS_ZEBRA_DEBUG_RECV) {
			inet_ntop(AF_INET6, &api_nh->gate.ipv6, nhbuf,
				  sizeof(nhbuf));
			zlog_debug("%s: nh=%s, vrf_id=%d", __func__,
				   nhbuf, api_nh->vrf_id);
		}
		nexthop = nexthop_from_ipv6(&api_nh->gate.ipv6, api_nh->vrf_id);
		break;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		if (IS_ZEBRA_DEBUG_RECV) {
			inet_ntop(AF_INET6, &api_nh->gate.ipv6, nhbuf,
				  sizeof(nhbuf));
			zlog_debug("%s: nh=%s, vrf_id=%d, ifindex=%d",
				   __func__, nhbuf, api_nh->vrf_id,
				   api_nh->ifindex);
		}
		nexthop = nexthop_from_ipv6_ifindex(&api_nh->gate.ipv6,
						    api_nh->ifindex,
						    api_nh->vrf_id);

		/* Special handling for IPv6 routes sourced from EVPN:
		 * the nexthop and associated MAC need to be installed.
		 */
		if (CHECK_FLAG(flags, ZEBRA_FLAG_EVPN_ROUTE)) {
			memset(&vtep_ip, 0, sizeof(struct ipaddr));
			vtep_ip.ipa_type = IPADDR_V6;
			memcpy(&vtep_ip.ipaddr_v6, &(api_nh->gate.ipv6),
			       sizeof(struct in6_addr));
			zebra_vxlan_evpn_vrf_route_add(
				api_nh->vrf_id, &api_nh->rmac, &vtep_ip, p);
		}
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: nh blackhole %d",
				   __func__, api_nh->bh_type);

		nexthop = nexthop_from_blackhole(api_nh->bh_type);
		break;
	}

	/* Return early if we couldn't process the zapi nexthop */
	if (nexthop == NULL) {
		goto done;
	}

	/* Mark nexthop as onlink either if client has explicitly told us
	 * to or if the nexthop is on an 'unnumbered' interface.
	 */
	if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_ONLINK))
		SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK);
	else if (api_nh->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
		ifp = if_lookup_by_index(api_nh->ifindex, api_nh->vrf_id);
		if (ifp && connected_is_unnumbered(ifp))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK);
	}

	if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_WEIGHT))
		nexthop->weight = api_nh->weight;

	if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_HAS_BACKUP)) {
		/* Validate count */
		if (api_nh->backup_num > NEXTHOP_MAX_BACKUPS) {
			if (IS_ZEBRA_DEBUG_RECV || IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("%s: invalid backup nh count %d",
					   __func__, api_nh->backup_num);
			nexthop_free(nexthop);
			nexthop = NULL;
			goto done;
		}

		/* Copy backup info */
		SET_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP);
		nexthop->backup_num = api_nh->backup_num;

		for (i = 0; i < api_nh->backup_num; i++) {
			/* Validate backup index */
			if (api_nh->backup_idx[i] < backup_nexthop_num) {
				nexthop->backup_idx[i] = api_nh->backup_idx[i];
			} else {
				if (IS_ZEBRA_DEBUG_RECV || IS_ZEBRA_DEBUG_EVENT)
					zlog_debug("%s: invalid backup nh idx %d",
						   __func__,
						   api_nh->backup_idx[i]);
				nexthop_free(nexthop);
				nexthop = NULL;
				goto done;
			}
		}
	}

done:
	return nexthop;
}

static bool zapi_read_nexthops(struct zserv *client, struct prefix *p,
			       struct zapi_nexthop *nhops, uint32_t flags,
			       uint32_t message, uint16_t nexthop_num,
			       uint16_t backup_nh_num,
			       struct nexthop_group **png,
			       struct nhg_backup_info **pbnhg)
{
	struct nexthop_group *ng = NULL;
	struct nhg_backup_info *bnhg = NULL;
	uint16_t i;
	struct nexthop *last_nh = NULL;

	assert(!(png && pbnhg));

	if (png)
		ng = nexthop_group_new();

	if (pbnhg && backup_nh_num > 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: adding %d backup nexthops", __func__,
				   backup_nh_num);

		bnhg = zebra_nhg_backup_alloc();
	}

	/*
	 * TBD should _all_ of the nexthop add operations use
	 * api_nh->vrf_id instead of re->vrf_id ? I only changed
	 * for cases NEXTHOP_TYPE_IPV4 and NEXTHOP_TYPE_IPV6.
	 */
	for (i = 0; i < nexthop_num; i++) {
		struct nexthop *nexthop;
		enum lsp_types_t label_type;
		char nhbuf[NEXTHOP_STRLEN];
		char labelbuf[MPLS_LABEL_STRLEN];
		struct zapi_nexthop *api_nh = &nhops[i];

		/* Convert zapi nexthop */
		nexthop = nexthop_from_zapi(api_nh, flags, p, backup_nh_num);
		if (!nexthop) {
			flog_warn(
				EC_ZEBRA_NEXTHOP_CREATION_FAILED,
				"%s: Nexthops Specified: %u(%u) but we failed to properly create one",
				__func__, nexthop_num, i);
			if (ng)
				nexthop_group_delete(&ng);
			if (bnhg)
				zebra_nhg_backup_free(&bnhg);
			return false;
		}

		if (bnhg
		    && CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP)) {
			if (IS_ZEBRA_DEBUG_RECV) {
				nexthop2str(nexthop, nhbuf, sizeof(nhbuf));
				zlog_debug("%s: backup nh %s with BACKUP flag!",
					   __func__, nhbuf);
			}
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP);
			nexthop->backup_num = 0;
		}

		if (CHECK_FLAG(message, ZAPI_MESSAGE_SRTE)) {
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_SRTE);
			nexthop->srte_color = api_nh->srte_color;
		}

		/* MPLS labels for BGP-LU or Segment Routing */
		if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_LABEL)
		    && api_nh->type != NEXTHOP_TYPE_IFINDEX
		    && api_nh->type != NEXTHOP_TYPE_BLACKHOLE
		    && api_nh->label_num > 0) {

			label_type = lsp_type_from_re_type(client->proto);
			nexthop_add_labels(nexthop, label_type,
					   api_nh->label_num,
					   &api_nh->labels[0]);
		}

		if (IS_ZEBRA_DEBUG_RECV) {
			labelbuf[0] = '\0';
			nhbuf[0] = '\0';

			nexthop2str(nexthop, nhbuf, sizeof(nhbuf));

			if (nexthop->nh_label &&
			    nexthop->nh_label->num_labels > 0) {
				mpls_label2str(nexthop->nh_label->num_labels,
					       nexthop->nh_label->label,
					       labelbuf, sizeof(labelbuf),
					       false);
			}

			zlog_debug("%s: nh=%s, vrf_id=%d %s",
				   __func__, nhbuf, api_nh->vrf_id, labelbuf);
		}

		if (ng) {
			/* Add new nexthop to temporary list. This list is
			 * canonicalized - sorted - so that it can be hashed
			 * later in route processing. We expect that the sender
			 * has sent the list sorted, and the zapi client api
			 * attempts to enforce that, so this should be
			 * inexpensive - but it is necessary to support shared
			 * nexthop-groups.
			 */
			nexthop_group_add_sorted(ng, nexthop);
		}
		if (bnhg) {
			/* Note that the order of the backup nexthops is
			 * significant, so we don't sort this list as we do the
			 * primary nexthops, we just append.
			 */
			if (last_nh)
				NEXTHOP_APPEND(last_nh, nexthop);
			else
				bnhg->nhe->nhg.nexthop = nexthop;

			last_nh = nexthop;
		}
	}


	/* succesfully read, set caller pointers now */
	if (png)
		*png = ng;

	if (pbnhg)
		*pbnhg = bnhg;

	return true;
}

static int zapi_nhg_decode(struct stream *s, int cmd, struct zapi_nhg *api_nhg)
{
	uint16_t i;
	struct zapi_nexthop *znh;

	STREAM_GETW(s, api_nhg->proto);
	STREAM_GETL(s, api_nhg->id);

	if (cmd == ZEBRA_NHG_DEL)
		goto done;

	/* Nexthops */
	STREAM_GETW(s, api_nhg->nexthop_num);

	if (zserv_nexthop_num_warn(__func__, NULL, api_nhg->nexthop_num))
		return -1;

	if (api_nhg->nexthop_num <= 0) {
		flog_warn(EC_ZEBRA_NEXTHOP_CREATION_FAILED,
			  "%s: No nexthops sent", __func__);
		return -1;
	}

	for (i = 0; i < api_nhg->nexthop_num; i++) {
		znh = &((api_nhg->nexthops)[i]);

		if (zapi_nexthop_decode(s, znh, 0, 0) != 0) {
			flog_warn(EC_ZEBRA_NEXTHOP_CREATION_FAILED,
				  "%s: Nexthop creation failed", __func__);
			return -1;
		}
	}

	/* Backup Nexthops */
	STREAM_GETW(s, api_nhg->backup_nexthop_num);

	if (zserv_nexthop_num_warn(__func__, NULL, api_nhg->backup_nexthop_num))
		return -1;

	for (i = 0; i < api_nhg->backup_nexthop_num; i++) {
		znh = &((api_nhg->backup_nexthops)[i]);

		if (zapi_nexthop_decode(s, znh, 0, 0) != 0) {
			flog_warn(EC_ZEBRA_NEXTHOP_CREATION_FAILED,
				  "%s: Backup Nexthop creation failed",
				  __func__);
			return -1;
		}
	}

done:
	return 0;

stream_failure:
	flog_warn(
		EC_ZEBRA_NEXTHOP_CREATION_FAILED,
		"%s: Nexthop Group decode failed with some sort of stream read failure",
		__func__);
	return -1;
}

static void zread_nhg_del(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct zapi_nhg api_nhg = {};
	struct nhg_hash_entry *nhe;

	s = msg;
	if (zapi_nhg_decode(s, hdr->command, &api_nhg) < 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Unable to decode zapi_nhg sent",
				   __func__);
		return;
	}

	/*
	 * Delete the received nhg id
	 */
	nhe = zebra_nhg_proto_del(api_nhg.id, api_nhg.proto);

	if (nhe) {
		zebra_nhg_decrement_ref(nhe);
		zsend_nhg_notify(api_nhg.proto, client->instance,
				 client->session_id, api_nhg.id,
				 ZAPI_NHG_REMOVED);
	} else
		zsend_nhg_notify(api_nhg.proto, client->instance,
				 client->session_id, api_nhg.id,
				 ZAPI_NHG_REMOVE_FAIL);
}

static void zread_nhg_add(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct zapi_nhg api_nhg = {};
	struct nexthop_group *nhg = NULL;
	struct nhg_backup_info *bnhg = NULL;
	struct nhg_hash_entry *nhe;

	s = msg;
	if (zapi_nhg_decode(s, hdr->command, &api_nhg) < 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Unable to decode zapi_nhg sent",
				   __func__);
		return;
	}

	if ((!zapi_read_nexthops(client, NULL, api_nhg.nexthops, 0, 0,
				 api_nhg.nexthop_num,
				 api_nhg.backup_nexthop_num, &nhg, NULL))
	    || (!zapi_read_nexthops(client, NULL, api_nhg.backup_nexthops, 0, 0,
				    api_nhg.backup_nexthop_num,
				    api_nhg.backup_nexthop_num, NULL, &bnhg))) {

		flog_warn(EC_ZEBRA_NEXTHOP_CREATION_FAILED,
			  "%s: Nexthop Group Creation failed", __func__);
		return;
	}

	/* Create a temporary nhe */
	nhe = zebra_nhg_alloc();
	nhe->id = api_nhg.id;
	nhe->type = api_nhg.proto;
	nhe->zapi_instance = client->instance;
	nhe->zapi_session = client->session_id;

	/* Take over the list(s) of nexthops */
	nhe->nhg.nexthop = nhg->nexthop;
	nhg->nexthop = NULL;

	if (bnhg) {
		nhe->backup_info = bnhg;
		bnhg = NULL;
	}

	/*
	 * TODO:
	 * Assume fully resolved for now and install.
	 * Resolution is going to need some more work.
	 */

	/* Enqueue to workqueue for processing */
	rib_queue_nhe_add(nhe);

	/* Free any local allocations */
	nexthop_group_delete(&nhg);
	zebra_nhg_backup_free(&bnhg);

}

static void zread_route_add(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct zapi_route api;
	afi_t afi;
	struct prefix_ipv6 *src_p = NULL;
	struct route_entry *re;
	struct nexthop_group *ng = NULL;
	struct nhg_backup_info *bnhg = NULL;
	int ret;
	vrf_id_t vrf_id;
	struct nhg_hash_entry nhe;

	s = msg;
	if (zapi_route_decode(s, &api) < 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Unable to decode zapi_route sent",
				   __func__);
		return;
	}

	vrf_id = zvrf_id(zvrf);

	if (IS_ZEBRA_DEBUG_RECV)
		zlog_debug("%s: p=(%u:%u)%pFX, msg flags=0x%x, flags=0x%x",
			   __func__, vrf_id, api.tableid, &api.prefix,
			   (int)api.message, api.flags);

	/* Allocate new route. */
	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));
	re->type = api.type;
	re->instance = api.instance;
	re->flags = api.flags;
	re->uptime = monotime(NULL);
	re->vrf_id = vrf_id;

	if (api.tableid)
		re->table = api.tableid;
	else
		re->table = zvrf->table_id;

	if (!CHECK_FLAG(api.message, ZAPI_MESSAGE_NHG)
	    && (!CHECK_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP)
		|| api.nexthop_num == 0)) {
		flog_warn(
			EC_ZEBRA_RX_ROUTE_NO_NEXTHOPS,
			"%s: received a route without nexthops for prefix %pFX from client %s",
			__func__, &api.prefix,
			zebra_route_string(client->proto));

		XFREE(MTYPE_RE, re);
		return;
	}

	/* Report misuse of the backup flag */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_BACKUP_NEXTHOPS)
	    && api.backup_nexthop_num == 0) {
		if (IS_ZEBRA_DEBUG_RECV || IS_ZEBRA_DEBUG_EVENT)
			zlog_debug(
				"%s: client %s: BACKUP flag set but no backup nexthops, prefix %pFX",
				__func__, zebra_route_string(client->proto),
				&api.prefix);
	}

	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_NHG))
		re->nhe_id = api.nhgid;

	if (!re->nhe_id
	    && (!zapi_read_nexthops(client, &api.prefix, api.nexthops,
				    api.flags, api.message, api.nexthop_num,
				    api.backup_nexthop_num, &ng, NULL)
		|| !zapi_read_nexthops(client, &api.prefix, api.backup_nexthops,
				       api.flags, api.message,
				       api.backup_nexthop_num,
				       api.backup_nexthop_num, NULL, &bnhg))) {

		nexthop_group_delete(&ng);
		zebra_nhg_backup_free(&bnhg);
		XFREE(MTYPE_RE, re);
		return;
	}

	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_DISTANCE))
		re->distance = api.distance;
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_METRIC))
		re->metric = api.metric;
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_TAG))
		re->tag = api.tag;
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_MTU))
		re->mtu = api.mtu;

	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_OPAQUE)) {
		re->opaque = XMALLOC(MTYPE_OPAQUE,
				     sizeof(struct opaque) + api.opaque.length);
		re->opaque->length = api.opaque.length;
		memcpy(re->opaque->data, api.opaque.data, re->opaque->length);
	}

	afi = family2afi(api.prefix.family);
	if (afi != AFI_IP6 && CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX)) {
		flog_warn(EC_ZEBRA_RX_SRCDEST_WRONG_AFI,
			  "%s: Received SRC Prefix but afi is not v6",
			  __func__);
		nexthop_group_delete(&ng);
		zebra_nhg_backup_free(&bnhg);
		XFREE(MTYPE_RE, re);
		return;
	}
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		src_p = &api.src_prefix;

	if (api.safi != SAFI_UNICAST && api.safi != SAFI_MULTICAST) {
		flog_warn(EC_LIB_ZAPI_MISSMATCH,
			  "%s: Received safi: %d but we can only accept UNICAST or MULTICAST",
			  __func__, api.safi);
		nexthop_group_delete(&ng);
		zebra_nhg_backup_free(&bnhg);
		XFREE(MTYPE_RE, re);
		return;
	}

	/*
	 * If we have an ID, this proto owns the NHG it sent along with the
	 * route, so we just send the ID into rib code with it.
	 *
	 * Havent figured out how to handle backup NHs with this yet, so lets
	 * keep that separate.
	 * Include backup info with the route. We use a temporary nhe here;
	 * if this is a new/unknown nhe, a new copy will be allocated
	 * and stored.
	 */
	if (!re->nhe_id) {
		zebra_nhe_init(&nhe, afi, ng->nexthop);
		nhe.nhg.nexthop = ng->nexthop;
		nhe.backup_info = bnhg;
	}
	ret = rib_add_multipath_nhe(afi, api.safi, &api.prefix, src_p,
				    re, &nhe);

	/* At this point, these allocations are not needed: 're' has been
	 * retained or freed, and if 're' still exists, it is using
	 * a reference to a shared group object.
	 */
	nexthop_group_delete(&ng);
	if (bnhg)
		zebra_nhg_backup_free(&bnhg);

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

void zapi_opaque_free(struct opaque *opaque)
{
	XFREE(MTYPE_OPAQUE, opaque);
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
			  __func__);
		return;
	}
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		src_p = &api.src_prefix;

	if (api.tableid)
		table_id = api.tableid;
	else
		table_id = zvrf->table_id;

	if (IS_ZEBRA_DEBUG_RECV)
		zlog_debug("%s: p=(%u:%u)%pFX, msg flags=0x%x, flags=0x%x",
			   __func__, zvrf_id(zvrf), table_id, &api.prefix,
			   (int)api.message, api.flags);

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
	afi_t afi;

	struct prefix p;

	STREAM_GETW(msg, afi);

	if (afi <= AFI_UNSPEC || afi >= AFI_MAX) {
		zlog_warn(
			"Invalid AFI %u while registering for router ID notifications",
			afi);
		goto stream_failure;
	}

	/* Router-id information is needed. */
	vrf_bitmap_set(client->ridinfo[afi], zvrf_id(zvrf));

	router_id_get(afi, &p, zvrf);

	zsend_router_id_update(client, afi, &p, zvrf_id(zvrf));

stream_failure:
	return;
}

/* Unregister zebra server router-id information. */
static void zread_router_id_delete(ZAPI_HANDLER_ARGS)
{
	afi_t afi;

	STREAM_GETW(msg, afi);

	if (afi <= AFI_UNSPEC || afi >= AFI_MAX) {
		zlog_warn(
			"Invalid AFI %u while unregistering from router ID notifications",
			afi);
		goto stream_failure;
	}

	vrf_bitmap_unset(client->ridinfo[afi], zvrf_id(zvrf));

stream_failure:
	return;
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
		/* Do not send unsolicited messages to synchronous clients. */
		if (client->synchronous)
			continue;

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
	uint8_t synchronous;
	uint32_t session_id;

	STREAM_GETC(msg, proto);
	STREAM_GETW(msg, instance);
	STREAM_GETL(msg, session_id);
	STREAM_GETC(msg, notify);
	STREAM_GETC(msg, synchronous);
	if (notify)
		client->notify_owner = true;

	if (synchronous)
		client->synchronous = true;

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
		client->session_id = session_id;

		/* Graceful restart processing for client connect */
		zebra_gr_client_reconnect(client);
	}

	if (!client->synchronous) {
		zsend_capabilities(client, zvrf);
		zebra_vrf_update_all(client);
	}
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
		vrf_bitmap_unset(client->ridinfo[afi], zvrf_id(zvrf));
		vrf_bitmap_unset(client->nhrp_neighinfo[afi], zvrf_id(zvrf));
	}
}

/*
 * Validate incoming zapi mpls lsp / labels message
 */
static int zapi_labels_validate(const struct zapi_labels *zl)
{
	int ret = -1;
	int i, j, idx;
	uint32_t bits[8];
	uint32_t ival;
	const struct zapi_nexthop *znh;

	/* Validate backup info: no duplicates for a single primary */
	if (zl->backup_nexthop_num == 0) {
		ret = 0;
		goto done;
	}

	for (j = 0; j < zl->nexthop_num; j++) {
		znh = &zl->nexthops[j];

		memset(bits, 0, sizeof(bits));

		for (i = 0; i < znh->backup_num; i++) {
			idx = znh->backup_idx[i] / 32;

			ival = 1 << znh->backup_idx[i] % 32;

			/* Check whether value is already used */
			if (ival & bits[idx]) {
				/* Fail */

				if (IS_ZEBRA_DEBUG_RECV)
					zlog_debug("%s: invalid zapi mpls message: duplicate backup nexthop index %d",
						   __func__,
						   znh->backup_idx[i]);
				goto done;
			}

			/* Mark index value */
			bits[idx] |= ival;
		}
	}

	ret = 0;

done:

	return ret;
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
	int ret;

	/* Get input stream.  */
	s = msg;
	if (zapi_labels_decode(s, &zl) < 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Unable to decode zapi_labels sent",
				   __func__);
		return;
	}

	if (!mpls_enabled)
		return;

	/* Validate; will debug on failure */
	if (zapi_labels_validate(&zl) < 0)
		return;

	ret = mpls_zapi_labels_process(true, zvrf, &zl);
	if (ret < 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Error processing zapi request",
				   __func__);
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
	int ret;

	/* Get input stream.  */
	s = msg;
	if (zapi_labels_decode(s, &zl) < 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Unable to decode zapi_labels sent",
				   __func__);
		return;
	}

	if (!mpls_enabled)
		return;

	if (zl.nexthop_num > 0) {
		ret = mpls_zapi_labels_process(false /*delete*/, zvrf, &zl);
		if (ret < 0) {
			if (IS_ZEBRA_DEBUG_RECV)
				zlog_debug("%s: Error processing zapi request",
					   __func__);
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
				   __func__);
		return;
	}

	if (!mpls_enabled)
		return;

	/* Validate; will debug on failure */
	if (zapi_labels_validate(&zl) < 0)
		return;

	/* This removes everything, then re-adds from the client's
	 * zapi message. Since the LSP will be processed later, on this
	 * this same pthread, all of the changes will 'appear' at once.
	 */
	mpls_lsp_uninstall_all_vrf(zvrf, zl.type, zl.local_label);
	if (CHECK_FLAG(zl.message, ZAPI_LABELS_FTN))
		mpls_ftn_uninstall(zvrf, zl.type, &zl.route.prefix,
				   zl.route.type, zl.route.instance);

	mpls_zapi_labels_process(true, zvrf, &zl);
}

static void zread_sr_policy_set(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct zapi_sr_policy zp;
	struct zapi_srte_tunnel *zt;
	struct zebra_sr_policy *policy;

	/* Get input stream.  */
	s = msg;
	if (zapi_sr_policy_decode(s, &zp) < 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Unable to decode zapi_sr_policy sent",
				   __func__);
		return;
	}
	zt = &zp.segment_list;
	if (zt->label_num < 1) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug(
				"%s: SR-TE tunnel must contain at least one label",
				__func__);
		return;
	}

	if (!mpls_enabled)
		return;

	policy = zebra_sr_policy_find(zp.color, &zp.endpoint);
	if (!policy)
		policy = zebra_sr_policy_add(zp.color, &zp.endpoint, zp.name);
	/* TODO: per-VRF list of SR-TE policies. */
	policy->zvrf = zvrf;

	zebra_sr_policy_validate(policy, &zp.segment_list);
}

static void zread_sr_policy_delete(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct zapi_sr_policy zp;
	struct zebra_sr_policy *policy;

	/* Get input stream.  */
	s = msg;
	if (zapi_sr_policy_decode(s, &zp) < 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Unable to decode zapi_sr_policy sent",
				   __func__);
		return;
	}

	if (!mpls_enabled)
		return;

	policy = zebra_sr_policy_find(zp.color, &zp.endpoint);
	if (!policy) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: Unable to find SR-TE policy", __func__);
		return;
	}

	zebra_sr_policy_del(policy);
}

int zsend_sr_policy_notify_status(uint32_t color, struct ipaddr *endpoint,
				  char *name, int status)
{
	struct zserv *client;
	struct stream *s;

	client = zserv_find_client(ZEBRA_ROUTE_SRTE, 0);
	if (!client) {
		if (IS_ZEBRA_DEBUG_PACKET)
			zlog_debug(
				"Not notifying pathd about policy %s"
				" status change to %d",
				name, status);
		return 0;
	}

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug(
			"Notifying pathd about policy %s status change"
			" to %d",
			name, status);

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	stream_reset(s);

	zclient_create_header(s, ZEBRA_SR_POLICY_NOTIFY_STATUS, VRF_DEFAULT);
	stream_putl(s, color);
	stream_put_ipaddr(s, endpoint);
	stream_write(s, name, SRTE_POLICY_NAME_MAX_LENGTH);
	stream_putl(s, status);

	stream_putw_at(s, 0, stream_get_endp(s));

	return zserv_send_message(client, s);
}

/* Send client close notify to client */
int zsend_client_close_notify(struct zserv *client, struct zserv *closed_client)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_CLIENT_CLOSE_NOTIFY, VRF_DEFAULT);

	stream_putc(s, closed_client->proto);
	stream_putw(s, closed_client->instance);
	stream_putl(s, closed_client->session_id);

	stream_putw_at(s, 0, stream_get_endp(s));

	return zserv_send_message(client, s);
}

/* Send response to a table manager connect request to client */
static void zread_table_manager_connect(struct zserv *client,
					struct stream *msg, vrf_id_t vrf_id)
{
	struct stream *s;
	uint8_t proto;
	uint16_t instance;
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);

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
	zlog_notice("client %d with vrf %s(%u) instance %u connected as %s",
		    client->sock, VRF_LOGNAME(vrf), vrf_id, instance,
		    zebra_route_string(proto));
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
	lm_client_connect_call(client, vrf_id);

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

	assert(proto == client->proto && instance == client->instance);

	/* call hook to get a chunk using wrapper */
	lm_get_chunk_call(&lmc, client, keep, size, base, vrf_id);

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

	assert(proto == client->proto && instance == client->instance);

	/* call hook to release a chunk using wrapper */
	lm_release_chunk_call(client, start, end);

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
	ifname[IF_NAMESIZE - 1] = '\0';
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

	if (!(IS_VALID_AFI(afi))) {
		zlog_warn("Invalid AFI for VRF label: %u", afi);
		return;
	}

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
					   ifp->ifindex, false /*backup*/);
	}

	if (nlabel != MPLS_LABEL_NONE) {
		mpls_label_t out_label = MPLS_LABEL_IMPLICIT_NULL;
		mpls_lsp_install(def_zvrf, ltype, nlabel, 1, &out_label,
				 NEXTHOP_TYPE_IFINDEX, NULL, ifp->ifindex);
	}

	zvrf->label[afi] = nlabel;
stream_failure:
	return;
}

static inline void zread_rule(ZAPI_HANDLER_ARGS)
{
	struct zebra_pbr_rule zpr;
	struct stream *s;
	uint32_t total, i;
	char ifname[INTERFACE_NAMSIZ + 1] = {};

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
		STREAM_GETC(s, zpr.rule.filter.dsfield);
		STREAM_GETL(s, zpr.rule.filter.fwmark);
		STREAM_GETL(s, zpr.rule.action.table);
		STREAM_GET(ifname, s, INTERFACE_NAMSIZ);

		strlcpy(zpr.ifname, ifname, sizeof(zpr.ifname));
		strlcpy(zpr.rule.ifname, ifname, sizeof(zpr.rule.ifname));

		if (!is_default_prefix(&zpr.rule.filter.src_ip))
			zpr.rule.filter.filter_bm |= PBR_FILTER_SRC_IP;

		if (!is_default_prefix(&zpr.rule.filter.dst_ip))
			zpr.rule.filter.filter_bm |= PBR_FILTER_DST_IP;

		if (zpr.rule.filter.src_port)
			zpr.rule.filter.filter_bm |= PBR_FILTER_SRC_PORT;

		if (zpr.rule.filter.dst_port)
			zpr.rule.filter.filter_bm |= PBR_FILTER_DST_PORT;

		if (zpr.rule.filter.dsfield)
			zpr.rule.filter.filter_bm |= PBR_FILTER_DSFIELD;

		if (zpr.rule.filter.fwmark)
			zpr.rule.filter.filter_bm |= PBR_FILTER_FWMARK;

		if (!(zpr.rule.filter.src_ip.family == AF_INET
		      || zpr.rule.filter.src_ip.family == AF_INET6)) {
			zlog_warn(
				"Unsupported PBR source IP family: %s (%hhu)",
				family2str(zpr.rule.filter.src_ip.family),
				zpr.rule.filter.src_ip.family);
			return;
		}
		if (!(zpr.rule.filter.dst_ip.family == AF_INET
		      || zpr.rule.filter.dst_ip.family == AF_INET6)) {
			zlog_warn(
				"Unsupported PBR destination IP family: %s (%hhu)",
				family2str(zpr.rule.filter.dst_ip.family),
				zpr.rule.filter.dst_ip.family);
			return;
		}


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
		STREAM_GETC(s, zpi.family);
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
		ipset.ipset_name[ZEBRA_IPSET_NAME_SIZE - 1] = '\0';
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

		if (!(zpi.dst.family == AF_INET
		      || zpi.dst.family == AF_INET6)) {
			zlog_warn(
				"Unsupported PBR destination IP family: %s (%hhu)",
				family2str(zpi.dst.family), zpi.dst.family);
			goto stream_failure;
		}
		if (!(zpi.src.family == AF_INET
		      || zpi.src.family == AF_INET6)) {
			zlog_warn(
				"Unsupported PBR source IP family: %s (%hhu)",
				family2str(zpi.src.family), zpi.src.family);
			goto stream_failure;
		}

		/* calculate backpointer */
		zpi.backpointer =
			zebra_pbr_lookup_ipset_pername(ipset.ipset_name);

		if (!zpi.backpointer) {
			zlog_warn("ipset name specified: %s does not exist",
				  ipset.ipset_name);
			goto stream_failure;
		}

		if (hdr->command == ZEBRA_IPSET_ENTRY_ADD)
			zebra_pbr_add_ipset_entry(&zpi);
		else
			zebra_pbr_del_ipset_entry(&zpi);
	}

stream_failure:
	return;
}


static inline void zebra_neigh_register(ZAPI_HANDLER_ARGS)
{
	afi_t afi;

	STREAM_GETW(msg, afi);
	if (afi <= AFI_UNSPEC || afi >= AFI_MAX) {
		zlog_warn(
			"Invalid AFI %u while registering for neighbors notifications",
			afi);
		goto stream_failure;
	}
	vrf_bitmap_set(client->nhrp_neighinfo[afi], zvrf_id(zvrf));
stream_failure:
	return;
}

static inline void zebra_neigh_unregister(ZAPI_HANDLER_ARGS)
{
	afi_t afi;

	STREAM_GETW(msg, afi);
	if (afi <= AFI_UNSPEC || afi >= AFI_MAX) {
		zlog_warn(
			"Invalid AFI %u while unregistering from neighbor notifications",
			afi);
		goto stream_failure;
	}
	vrf_bitmap_unset(client->nhrp_neighinfo[afi], zvrf_id(zvrf));
stream_failure:
	return;
}

static inline void zebra_gre_get(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	ifindex_t idx;
	struct interface *ifp;
	struct zebra_if *zebra_if = NULL;
	struct zebra_l2info_gre *gre_info;
	struct interface *ifp_link = NULL;
	vrf_id_t vrf_id_link = VRF_UNKNOWN;
	vrf_id_t vrf_id = zvrf->vrf->vrf_id;

	s = msg;
	STREAM_GETL(s, idx);
	ifp  = if_lookup_by_index(idx, vrf_id);

	if (ifp)
		zebra_if = ifp->info;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_GRE_UPDATE, vrf_id);

	if (ifp  && IS_ZEBRA_IF_GRE(ifp) && zebra_if) {
		gre_info = &zebra_if->l2info.gre;

		stream_putl(s, idx);
		stream_putl(s, gre_info->ikey);
		stream_putl(s, gre_info->ikey);
		stream_putl(s, gre_info->ifindex_link);

		ifp_link = if_lookup_by_index_per_ns(
					zebra_ns_lookup(gre_info->link_nsid),
					gre_info->ifindex_link);
		if (ifp_link)
			vrf_id_link = ifp_link->vrf_id;
		stream_putl(s, vrf_id_link);
		stream_putl(s, gre_info->vtep_ip.s_addr);
		stream_putl(s, gre_info->vtep_ip_remote.s_addr);
	} else {
		stream_putl(s, idx);
		stream_putl(s, 0);
		stream_putl(s, 0);
		stream_putl(s, IFINDEX_INTERNAL);
		stream_putl(s, VRF_UNKNOWN);
		stream_putl(s, 0);
	}
	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));
	zserv_send_message(client, s);

	return;
 stream_failure:
	return;
}

static inline void zebra_configure_arp(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	uint8_t fam;
	ifindex_t idx;
	struct interface *ifp;

	s = msg;
	STREAM_GETC(s, fam);
	if (fam != AF_INET && fam != AF_INET6)
		return;
	STREAM_GETL(s, idx);
	ifp = if_lookup_by_index_per_ns(zvrf->zns, idx);
	if (!ifp)
		return;
	dplane_neigh_table_update(ifp, fam, 1, 0, 0);
stream_failure:
	return;
}

static inline void zebra_neigh_ip_add(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct zapi_neigh_ip api = {};
	int ret;
	const struct interface *ifp;

	s = msg;
	ret = zclient_neigh_ip_decode(s, &api);
	if (ret < 0)
		return;
	ifp = if_lookup_by_index(api.index, zvrf_id(zvrf));
	if (!ifp)
		return;
	dplane_neigh_ip_update(DPLANE_OP_NEIGH_IP_INSTALL, ifp, &api.ip_out,
			       &api.ip_in, api.ndm_state, client->proto);
}


static inline void zebra_neigh_ip_del(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct zapi_neigh_ip api = {};
	int ret;
	struct interface *ifp;

	s = msg;
	ret = zclient_neigh_ip_decode(s, &api);
	if (ret < 0)
		return;
	ifp = if_lookup_by_index(api.index, zvrf_id(zvrf));
	if (!ifp)
		return;
	dplane_neigh_ip_update(DPLANE_OP_NEIGH_IP_DELETE, ifp, &api.ip_out,
			       &api.ip_in, api.ndm_state, client->proto);
}


static inline void zread_iptable(ZAPI_HANDLER_ARGS)
{
	struct zebra_pbr_iptable *zpi =
		XCALLOC(MTYPE_TMP, sizeof(struct zebra_pbr_iptable));
	struct stream *s;

	s = msg;

	zpi->interface_name_list = list_new();
	zpi->sock = client->sock;
	zpi->vrf_id = zvrf->vrf->vrf_id;
	STREAM_GETL(s, zpi->unique);
	STREAM_GETL(s, zpi->type);
	STREAM_GETL(s, zpi->filter_bm);
	STREAM_GETL(s, zpi->action);
	STREAM_GETL(s, zpi->fwmark);
	STREAM_GET(&zpi->ipset_name, s, ZEBRA_IPSET_NAME_SIZE);
	STREAM_GETC(s, zpi->family);
	STREAM_GETW(s, zpi->pkt_len_min);
	STREAM_GETW(s, zpi->pkt_len_max);
	STREAM_GETW(s, zpi->tcp_flags);
	STREAM_GETW(s, zpi->tcp_mask_flags);
	STREAM_GETC(s, zpi->dscp_value);
	STREAM_GETC(s, zpi->fragment);
	STREAM_GETC(s, zpi->protocol);
	STREAM_GETW(s, zpi->flow_label);
	STREAM_GETL(s, zpi->nb_interface);
	zebra_pbr_iptable_update_interfacelist(s, zpi);

	if (hdr->command == ZEBRA_IPTABLE_ADD)
		zebra_pbr_add_iptable(zpi);
	else
		zebra_pbr_del_iptable(zpi);

stream_failure:
	zebra_pbr_iptable_free(zpi);
	zpi = NULL;
	return;
}

static inline void zread_neigh_discover(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	ifindex_t ifindex;
	struct interface *ifp;
	struct prefix p;
	struct ipaddr ip;

	s = msg;

	STREAM_GETL(s, ifindex);

	ifp = if_lookup_by_index_per_ns(zvrf->zns, ifindex);
	if (!ifp) {
		zlog_debug("Failed to lookup ifindex: %u", ifindex);
		return;
	}

	STREAM_GETC(s, p.family);
	STREAM_GETC(s, p.prefixlen);
	STREAM_GET(&p.u.prefix, s, prefix_blen(&p));

	if (p.family == AF_INET)
		SET_IPADDR_V4(&ip);
	else
		SET_IPADDR_V6(&ip);

	memcpy(&ip.ip.addr, &p.u.prefix, prefix_blen(&p));

	dplane_neigh_discover(ifp, &ip);

stream_failure:
	return;
}

static inline void zebra_gre_source_set(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	ifindex_t idx, link_idx;
	vrf_id_t link_vrf_id;
	struct interface *ifp;
	struct interface *ifp_link;
	vrf_id_t vrf_id = zvrf->vrf->vrf_id;
	struct zebra_if *zif, *gre_zif;
	struct zebra_l2info_gre *gre_info;
	unsigned int mtu;

	s = msg;
	STREAM_GETL(s, idx);
	ifp  = if_lookup_by_index(idx, vrf_id);
	STREAM_GETL(s, link_idx);
	STREAM_GETL(s, link_vrf_id);
	STREAM_GETL(s, mtu);

	ifp_link  = if_lookup_by_index(link_idx, link_vrf_id);
	if (!ifp_link || !ifp) {
		zlog_warn("GRE (index %u, VRF %u) or GRE link interface (index %u, VRF %u) not found, when setting GRE params",
			  idx, vrf_id, link_idx, link_vrf_id);
		return;
	}

	if (!IS_ZEBRA_IF_GRE(ifp))
		return;

	gre_zif = (struct zebra_if *)ifp->info;
	zif = (struct zebra_if *)ifp_link->info;
	if (!zif || !gre_zif)
		return;

	gre_info = &zif->l2info.gre;
	if (!gre_info)
		return;

	if (!mtu)
		mtu = ifp->mtu;

	/* if gre link already set or mtu did not change, do not set it */
	if (gre_zif->link && gre_zif->link == ifp_link && mtu == ifp->mtu)
		return;

	dplane_gre_set(ifp, ifp_link, mtu, gre_info);

 stream_failure:
	return;
}

static void zsend_error_msg(struct zserv *client, enum zebra_error_types error,
			    struct zmsghdr *bad_hdr)
{

	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_ERROR, bad_hdr->vrf_id);

	zserv_encode_error(s, error);

	client->error_cnt++;
	zserv_send_message(client, s);
}

static void zserv_error_no_vrf(ZAPI_HANDLER_ARGS)
{
	if (IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV)
		zlog_debug("ZAPI message specifies unknown VRF: %d",
			   hdr->vrf_id);

	zsend_error_msg(client, ZEBRA_NO_VRF, hdr);
}

static void zserv_error_invalid_msg_type(ZAPI_HANDLER_ARGS)
{
	zlog_info("Zebra received unknown command %d", hdr->command);

	zsend_error_msg(client, ZEBRA_INVALID_MSG_TYPE, hdr);
}

void (*const zserv_handlers[])(ZAPI_HANDLER_ARGS) = {
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
	[ZEBRA_INTERFACE_ENABLE_RADV] = zebra_interface_radv_enable,
	[ZEBRA_INTERFACE_DISABLE_RADV] = zebra_interface_radv_disable,
	[ZEBRA_SR_POLICY_SET] = zread_sr_policy_set,
	[ZEBRA_SR_POLICY_DELETE] = zread_sr_policy_delete,
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
	[ZEBRA_REMOTE_ES_VTEP_ADD] = zebra_evpn_proc_remote_es,
	[ZEBRA_REMOTE_ES_VTEP_DEL] = zebra_evpn_proc_remote_es,
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
	[ZEBRA_MLAG_CLIENT_REGISTER] = zebra_mlag_client_register,
	[ZEBRA_MLAG_CLIENT_UNREGISTER] = zebra_mlag_client_unregister,
	[ZEBRA_MLAG_FORWARD_MSG] = zebra_mlag_forward_client_msg,
	[ZEBRA_CLIENT_CAPABILITIES] = zread_client_capabilities,
	[ZEBRA_NEIGH_DISCOVER] = zread_neigh_discover,
	[ZEBRA_NHG_ADD] = zread_nhg_add,
	[ZEBRA_NHG_DEL] = zread_nhg_del,
	[ZEBRA_ROUTE_NOTIFY_REQUEST] = zread_route_notify_request,
	[ZEBRA_EVPN_REMOTE_NH_ADD] = zebra_evpn_proc_remote_nh,
	[ZEBRA_EVPN_REMOTE_NH_DEL] = zebra_evpn_proc_remote_nh,
	[ZEBRA_NEIGH_IP_ADD] = zebra_neigh_ip_add,
	[ZEBRA_NEIGH_IP_DEL] = zebra_neigh_ip_del,
	[ZEBRA_NHRP_NEIGH_REGISTER] = zebra_neigh_register,
	[ZEBRA_NHRP_NEIGH_UNREGISTER] = zebra_neigh_unregister,
	[ZEBRA_CONFIGURE_ARP] = zebra_configure_arp,
	[ZEBRA_GRE_GET] = zebra_gre_get,
	[ZEBRA_GRE_SOURCE_SET] = zebra_gre_source_set,
};

/*
 * Process a batch of zapi messages.
 */
void zserv_handle_commands(struct zserv *client, struct stream_fifo *fifo)
{
	struct zmsghdr hdr;
	struct zebra_vrf *zvrf;
	struct stream *msg;
	struct stream_fifo temp_fifo;

	stream_fifo_init(&temp_fifo);

	while (stream_fifo_head(fifo)) {
		msg = stream_fifo_pop(fifo);

		if (STREAM_READABLE(msg) > ZEBRA_MAX_PACKET_SIZ) {
			if (IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV)
				zlog_debug(
					"ZAPI message is %zu bytes long but the maximum packet size is %u; dropping",
					STREAM_READABLE(msg),
					ZEBRA_MAX_PACKET_SIZ);
			goto continue_loop;
		}

		zapi_parse_header(msg, &hdr);

		if (IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV
		    && IS_ZEBRA_DEBUG_DETAIL)
			zserv_log_message(NULL, msg, &hdr);

		hdr.length -= ZEBRA_HEADER_SIZE;

		/* Before checking for a handler function, check for
		 * special messages that are handled in another module;
		 * we'll treat these as opaque.
		 */
		if (zebra_opaque_handles_msgid(hdr.command)) {
			/* Reset message buffer */
			stream_set_getp(msg, 0);

			stream_fifo_push(&temp_fifo, msg);

			/* Continue without freeing the message */
			msg = NULL;
			goto continue_loop;
		}

		/* lookup vrf */
		zvrf = zebra_vrf_lookup_by_id(hdr.vrf_id);
		if (!zvrf) {
			zserv_error_no_vrf(client, &hdr, msg, zvrf);
			goto continue_loop;
		}

		if (hdr.command >= array_size(zserv_handlers)
		    || zserv_handlers[hdr.command] == NULL) {
			zserv_error_invalid_msg_type(client, &hdr, msg, zvrf);
			goto continue_loop;
		}

		zserv_handlers[hdr.command](client, &hdr, msg, zvrf);

continue_loop:
		stream_free(msg);
	}

	/* Dispatch any special messages from the temp fifo */
	if (stream_fifo_head(&temp_fifo) != NULL)
		zebra_opaque_enqueue_batch(&temp_fifo);

	stream_fifo_deinit(&temp_fifo);
}
