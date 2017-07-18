/*
 * Zebra connect library for OSPFd
 * Copyright (C) 1997, 98, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada
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

#include "thread.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"
#include "lib/bfd.h"
#include "nexthop.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_te.h"

DEFINE_HOOK(ospf_if_update, (struct interface * ifp), (ifp))
DEFINE_HOOK(ospf_if_delete, (struct interface * ifp), (ifp))

/* Zebra structure to hold current status. */
struct zclient *zclient = NULL;

/* For registering threads. */
extern struct thread_master *master;
struct in_addr router_id_zebra;

/* Router-id update message from zebra. */
static int ospf_router_id_update_zebra(int command, struct zclient *zclient,
				       zebra_size_t length, vrf_id_t vrf_id)
{
	struct ospf *ospf;
	struct prefix router_id;
	zebra_router_id_update_read(zclient->ibuf, &router_id);

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE)) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(&router_id, buf, sizeof(buf));
		zlog_debug("Zebra rcvd: router id update %s", buf);
	}

	router_id_zebra = router_id.u.prefix4;

	ospf = ospf_lookup();

	if (ospf != NULL)
		ospf_router_id_update(ospf);

	return 0;
}

/* Inteface addition message from zebra. */
static int ospf_interface_add(int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug(
			"Zebra: interface add %s[%u] index %d flags %llx metric %d mtu %d",
			ifp->name, ifp->vrf_id, ifp->ifindex,
			(unsigned long long)ifp->flags, ifp->metric, ifp->mtu);

	assert(ifp->info);

	if (!OSPF_IF_PARAM_CONFIGURED(IF_DEF_PARAMS(ifp), type)) {
		SET_IF_PARAM(IF_DEF_PARAMS(ifp), type);
		IF_DEF_PARAMS(ifp)->type = ospf_default_iftype(ifp);
	}

	ospf_if_update(NULL, ifp);

	hook_call(ospf_if_update, ifp);

	return 0;
}

static int ospf_interface_delete(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct stream *s;
	struct route_node *rn;

	s = zclient->ibuf;
	/* zebra_interface_state_read() updates interface structure in iflist */
	ifp = zebra_interface_state_read(s, vrf_id);

	if (ifp == NULL)
		return 0;

	if (if_is_up(ifp))
		zlog_warn("Zebra: got delete of %s, but interface is still up",
			  ifp->name);

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug(
			"Zebra: interface delete %s[%u] index %d flags %llx metric %d mtu %d",
			ifp->name, ifp->vrf_id, ifp->ifindex,
			(unsigned long long)ifp->flags, ifp->metric, ifp->mtu);

	hook_call(ospf_if_delete, ifp);

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn))
		if (rn->info)
			ospf_if_free((struct ospf_interface *)rn->info);

	ifp->ifindex = IFINDEX_DELETED;
	return 0;
}

static struct interface *zebra_interface_if_lookup(struct stream *s,
						   vrf_id_t vrf_id)
{
	char ifname_tmp[INTERFACE_NAMSIZ];

	/* Read interface name. */
	stream_get(ifname_tmp, s, INTERFACE_NAMSIZ);

	/* And look it up. */
	return if_lookup_by_name_len(
		ifname_tmp, strnlen(ifname_tmp, INTERFACE_NAMSIZ), VRF_DEFAULT);
}

static int ospf_interface_state_up(int command, struct zclient *zclient,
				   zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct ospf_interface *oi;
	struct route_node *rn;

	ifp = zebra_interface_if_lookup(zclient->ibuf, vrf_id);

	if (ifp == NULL)
		return 0;

	/* Interface is already up. */
	if (if_is_operative(ifp)) {
		/* Temporarily keep ifp values. */
		struct interface if_tmp;
		memcpy(&if_tmp, ifp, sizeof(struct interface));

		zebra_interface_if_set_value(zclient->ibuf, ifp);

		if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
			zlog_debug(
				"Zebra: Interface[%s] state update speed %u -> %u, bw  %d -> %d",
				ifp->name, if_tmp.speed, ifp->speed,
				if_tmp.bandwidth, ifp->bandwidth);

		ospf_if_recalculate_output_cost(ifp);

		if (if_tmp.mtu != ifp->mtu) {
			if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
				zlog_debug(
					"Zebra: Interface[%s] MTU change %u -> %u.",
					ifp->name, if_tmp.mtu, ifp->mtu);

			/* Must reset the interface (simulate down/up) when MTU
			 * changes. */
			ospf_if_reset(ifp);
		}
		return 0;
	}

	zebra_interface_if_set_value(zclient->ibuf, ifp);

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug("Zebra: Interface[%s] state change to up.",
			   ifp->name);

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		if ((oi = rn->info) == NULL)
			continue;

		ospf_if_up(oi);
	}

	return 0;
}

static int ospf_interface_state_down(int command, struct zclient *zclient,
				     zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct ospf_interface *oi;
	struct route_node *node;

	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);

	if (ifp == NULL)
		return 0;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug("Zebra: Interface[%s] state change to down.",
			   ifp->name);

	for (node = route_top(IF_OIFS(ifp)); node; node = route_next(node)) {
		if ((oi = node->info) == NULL)
			continue;
		ospf_if_down(oi);
	}

	return 0;
}

static int ospf_interface_address_add(int command, struct zclient *zclient,
				      zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;

	c = zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE)) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(c->address, buf, sizeof(buf));
		zlog_debug("Zebra: interface %s address add %s", c->ifp->name,
			   buf);
	}

	ospf_if_update(NULL, c->ifp);

	hook_call(ospf_if_update, c->ifp);

	return 0;
}

static int ospf_interface_address_delete(int command, struct zclient *zclient,
					 zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;
	struct interface *ifp;
	struct ospf_interface *oi;
	struct route_node *rn;
	struct prefix p;

	c = zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE)) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(c->address, buf, sizeof(buf));
		zlog_debug("Zebra: interface %s address delete %s",
			   c->ifp->name, buf);
	}

	ifp = c->ifp;
	p = *c->address;
	p.prefixlen = IPV4_MAX_PREFIXLEN;

	rn = route_node_lookup(IF_OIFS(ifp), &p);
	if (!rn) {
		connected_free(c);
		return 0;
	}

	assert(rn->info);
	oi = rn->info;
	route_unlock_node(rn);

	/* Call interface hook functions to clean up */
	ospf_if_free(oi);

	hook_call(ospf_if_update, c->ifp);

	connected_free(c);

	return 0;
}

static int ospf_interface_link_params(int command, struct zclient *zclient,
				      zebra_size_t length)
{
	struct interface *ifp;

	ifp = zebra_interface_link_params_read(zclient->ibuf);

	if (ifp == NULL)
		return 0;

	/* Update TE TLV */
	ospf_mpls_te_update_if(ifp);

	return 0;
}


void ospf_zebra_add(struct prefix_ipv4 *p, struct ospf_route * or)
{
	u_char message;
	u_char distance;
	u_int32_t flags;
	int psize;
	struct stream *s;
	struct ospf_path *path;
	struct listnode *node;
	struct ospf *ospf = ospf_lookup();

	if ((ospf->instance
	     && redist_check_instance(
			&zclient->mi_redist[AFI_IP][ZEBRA_ROUTE_OSPF],
			ospf->instance))
	    || vrf_bitmap_check(zclient->redist[AFI_IP][ZEBRA_ROUTE_OSPF],
				VRF_DEFAULT)) {
		message = 0;
		flags = 0;

		/* OSPF pass nexthop and metric */
		SET_FLAG(message, ZAPI_MESSAGE_NEXTHOP);
		SET_FLAG(message, ZAPI_MESSAGE_METRIC);

		/* Distance value. */
		distance = ospf_distance_apply(p, or);
		if (distance)
			SET_FLAG(message, ZAPI_MESSAGE_DISTANCE);

		/* Check if path type is ASE */
		if (((or->path_type == OSPF_PATH_TYPE1_EXTERNAL)
		     || (or->path_type == OSPF_PATH_TYPE2_EXTERNAL))
		    && (or->u.ext.tag > 0) && (or->u.ext.tag <= ROUTE_TAG_MAX))
			SET_FLAG(message, ZAPI_MESSAGE_TAG);

		/* Make packet. */
		s = zclient->obuf;
		stream_reset(s);

		/* Put command, type, flags, message. */
		zclient_create_header(s, ZEBRA_IPV4_ROUTE_ADD, VRF_DEFAULT);
		stream_putc(s, ZEBRA_ROUTE_OSPF);
		stream_putw(s, ospf->instance);
		stream_putl(s, flags);
		stream_putc(s, message);
		stream_putw(s, SAFI_UNICAST);

		/* Put prefix information. */
		psize = PSIZE(p->prefixlen);
		stream_putc(s, p->prefixlen);
		stream_write(s, (u_char *)&p->prefix, psize);

		/* Nexthop count. */
		stream_putc(s, or->paths->count);

		/* Nexthop, ifindex, distance and metric information. */
		for (ALL_LIST_ELEMENTS_RO(or->paths, node, path)) {
#ifdef HAVE_NETLINK
			if (path->unnumbered
			    || (path->nexthop.s_addr != INADDR_ANY
				&& path->ifindex != 0)) {
				stream_putc(s, NEXTHOP_TYPE_IPV4_IFINDEX);
				stream_put_in_addr(s, &path->nexthop);
				stream_putl(s, path->ifindex);
			} else if (path->nexthop.s_addr != INADDR_ANY) {
				stream_putc(s, NEXTHOP_TYPE_IPV4);
				stream_put_in_addr(s, &path->nexthop);
			} else {
				stream_putc(s, NEXTHOP_TYPE_IFINDEX);
				if (path->ifindex)
					stream_putl(s, path->ifindex);
				else
					stream_putl(s, 0);
			}
#else  /* HAVE_NETLINK */
			if (path->nexthop.s_addr != INADDR_ANY
			    && path->ifindex != 0) {
				stream_putc(s, NEXTHOP_TYPE_IPV4_IFINDEX);
				stream_put_in_addr(s, &path->nexthop);
				stream_putl(s, path->ifindex);
			} else if (path->nexthop.s_addr != INADDR_ANY) {
				stream_putc(s, NEXTHOP_TYPE_IPV4);
				stream_put_in_addr(s, &path->nexthop);
			} else {
				stream_putc(s, NEXTHOP_TYPE_IFINDEX);
				if (path->ifindex)
					stream_putl(s, path->ifindex);
				else
					stream_putl(s, 0);
			}
#endif /* HAVE_NETLINK */

			if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE)) {
				char buf[2][INET_ADDRSTRLEN];
				zlog_debug(
					"Zebra: Route add %s/%d nexthop %s, ifindex=%d",
					inet_ntop(AF_INET, &p->prefix, buf[0],
						  sizeof(buf[0])),
					p->prefixlen,
					inet_ntop(AF_INET, &path->nexthop,
						  buf[1], sizeof(buf[1])),
					path->ifindex);
			}
		}

		if (CHECK_FLAG(message, ZAPI_MESSAGE_DISTANCE))
			stream_putc(s, distance);
		if (CHECK_FLAG(message, ZAPI_MESSAGE_METRIC)) {
			if (or->path_type == OSPF_PATH_TYPE1_EXTERNAL)
				stream_putl(s, or->cost + or->u.ext.type2_cost);
			else if (or->path_type == OSPF_PATH_TYPE2_EXTERNAL)
				stream_putl(s, or->u.ext.type2_cost);
			else
				stream_putl(s, or->cost);
		}

		if (CHECK_FLAG(message, ZAPI_MESSAGE_TAG))
			stream_putl(s, or->u.ext.tag);

		stream_putw_at(s, 0, stream_get_endp(s));

		zclient_send_message(zclient);
	}
}

void ospf_zebra_delete(struct prefix_ipv4 *p, struct ospf_route * or)
{
	u_char message;
	u_char distance;
	u_int32_t flags;
	int psize;
	struct stream *s;
	struct ospf_path *path;
	struct listnode *node;
	struct ospf *ospf = ospf_lookup();

	if ((ospf->instance
	     && redist_check_instance(
			&zclient->mi_redist[AFI_IP][ZEBRA_ROUTE_OSPF],
			ospf->instance))
	    || vrf_bitmap_check(zclient->redist[AFI_IP][ZEBRA_ROUTE_OSPF],
				VRF_DEFAULT)) {
		message = 0;
		flags = 0;
		/* Distance value. */
		distance = ospf_distance_apply(p, or);
		/* Make packet. */
		s = zclient->obuf;
		stream_reset(s);

		/* Put command, type, flags, message. */
		zclient_create_header(s, ZEBRA_IPV4_ROUTE_DELETE, VRF_DEFAULT);
		stream_putc(s, ZEBRA_ROUTE_OSPF);
		stream_putw(s, ospf->instance);
		stream_putl(s, flags);
		stream_putc(s, message);
		stream_putw(s, SAFI_UNICAST);

		/* Put prefix information. */
		psize = PSIZE(p->prefixlen);
		stream_putc(s, p->prefixlen);
		stream_write(s, (u_char *)&p->prefix, psize);

		/* Nexthop count. */
		stream_putc(s, or->paths->count);

		/* Nexthop, ifindex, distance and metric information. */
		for (ALL_LIST_ELEMENTS_RO(or->paths, node, path)) {
			if (path->nexthop.s_addr != INADDR_ANY
			    && path->ifindex != 0) {
				stream_putc(s, NEXTHOP_TYPE_IPV4_IFINDEX);
				stream_put_in_addr(s, &path->nexthop);
				stream_putl(s, path->ifindex);
			} else if (path->nexthop.s_addr != INADDR_ANY) {
				stream_putc(s, NEXTHOP_TYPE_IPV4);
				stream_put_in_addr(s, &path->nexthop);
			} else {
				stream_putc(s, NEXTHOP_TYPE_IFINDEX);
				stream_putl(s, path->ifindex);
			}

			if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE)) {
				char buf[2][INET_ADDRSTRLEN];
				zlog_debug(
					"Zebra: Route delete %s/%d nexthop %s",
					inet_ntop(AF_INET, &p->prefix, buf[0],
						  sizeof(buf[0])),
					p->prefixlen,
					inet_ntop(AF_INET, &path->nexthop,
						  buf[1], sizeof(buf[1])));
			}
		}

		if (CHECK_FLAG(message, ZAPI_MESSAGE_DISTANCE))
			stream_putc(s, distance);
		if (CHECK_FLAG(message, ZAPI_MESSAGE_METRIC)) {
			if (or->path_type == OSPF_PATH_TYPE1_EXTERNAL)
				stream_putl(s, or->cost + or->u.ext.type2_cost);
			else if (or->path_type == OSPF_PATH_TYPE2_EXTERNAL)
				stream_putl(s, or->u.ext.type2_cost);
			else
				stream_putl(s, or->cost);
		}

		stream_putw_at(s, 0, stream_get_endp(s));

		zclient_send_message(zclient);
	}
}

void ospf_zebra_add_discard(struct prefix_ipv4 *p)
{
	struct zapi_ipv4 api;
	struct ospf *ospf = ospf_lookup();

	if ((ospf->instance
	     && redist_check_instance(
			&zclient->mi_redist[AFI_IP][ZEBRA_ROUTE_OSPF],
			ospf->instance))
	    || vrf_bitmap_check(zclient->redist[AFI_IP][ZEBRA_ROUTE_OSPF],
				VRF_DEFAULT)) {
		api.vrf_id = VRF_DEFAULT;
		api.type = ZEBRA_ROUTE_OSPF;
		api.instance = ospf->instance;
		api.flags = ZEBRA_FLAG_BLACKHOLE;
		api.message = 0;
		api.safi = SAFI_UNICAST;
		SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
		api.nexthop_num = 0;
		api.ifindex_num = 0;
		api.tag = 0;

		zapi_ipv4_route(ZEBRA_IPV4_ROUTE_ADD, zclient, p, &api);

		if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE))
			zlog_debug("Zebra: Route add discard %s/%d",
				   inet_ntoa(p->prefix), p->prefixlen);
	}
}

void ospf_zebra_delete_discard(struct prefix_ipv4 *p)
{
	struct zapi_ipv4 api;
	struct ospf *ospf = ospf_lookup();

	if ((ospf->instance
	     && redist_check_instance(
			&zclient->mi_redist[AFI_IP][ZEBRA_ROUTE_OSPF],
			ospf->instance))
	    || vrf_bitmap_check(zclient->redist[AFI_IP][ZEBRA_ROUTE_OSPF],
				VRF_DEFAULT)) {
		api.vrf_id = VRF_DEFAULT;
		api.type = ZEBRA_ROUTE_OSPF;
		api.instance = ospf->instance;
		api.flags = ZEBRA_FLAG_BLACKHOLE;
		api.message = 0;
		api.safi = SAFI_UNICAST;
		SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
		api.nexthop_num = 0;
		api.ifindex_num = 0;
		api.tag = 0;

		zapi_ipv4_route(ZEBRA_IPV4_ROUTE_DELETE, zclient, p, &api);

		if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE))
			zlog_debug("Zebra: Route delete discard %s/%d",
				   inet_ntoa(p->prefix), p->prefixlen);
	}
}

struct ospf_external *ospf_external_lookup(u_char type, u_short instance)
{
	struct list *ext_list;
	struct listnode *node;
	struct ospf_external *ext;

	ext_list = om->external[type];
	if (!ext_list)
		return (NULL);

	for (ALL_LIST_ELEMENTS_RO(ext_list, node, ext))
		if (ext->instance == instance)
			return ext;

	return NULL;
}

struct ospf_external *ospf_external_add(u_char type, u_short instance)
{
	struct list *ext_list;
	struct ospf_external *ext;

	ext = ospf_external_lookup(type, instance);
	if (ext)
		return ext;

	if (!om->external[type])
		om->external[type] = list_new();

	ext_list = om->external[type];
	ext = (struct ospf_external *)calloc(1, sizeof(struct ospf_external));
	ext->instance = instance;
	EXTERNAL_INFO(ext) = route_table_init();

	listnode_add(ext_list, ext);

	return ext;
}

void ospf_external_del(u_char type, u_short instance)
{
	struct ospf_external *ext;

	ext = ospf_external_lookup(type, instance);

	if (ext) {
		if (EXTERNAL_INFO(ext))
			route_table_finish(EXTERNAL_INFO(ext));

		listnode_delete(om->external[type], ext);
		if (!om->external[type]->count) {
			list_free(om->external[type]);
			om->external[type] = NULL;
		}
	}
}

struct ospf_redist *ospf_redist_lookup(struct ospf *ospf, u_char type,
				       u_short instance)
{
	struct list *red_list;
	struct listnode *node;
	struct ospf_redist *red;

	red_list = ospf->redist[type];
	if (!red_list)
		return (NULL);

	for (ALL_LIST_ELEMENTS_RO(red_list, node, red))
		if (red->instance == instance)
			return red;

	return NULL;
}

struct ospf_redist *ospf_redist_add(struct ospf *ospf, u_char type,
				    u_short instance)
{
	struct list *red_list;
	struct ospf_redist *red;

	red = ospf_redist_lookup(ospf, type, instance);
	if (red)
		return red;

	if (!ospf->redist[type])
		ospf->redist[type] = list_new();

	red_list = ospf->redist[type];
	red = (struct ospf_redist *)calloc(1, sizeof(struct ospf_redist));
	red->instance = instance;
	red->dmetric.type = -1;
	red->dmetric.value = -1;

	listnode_add(red_list, red);

	return red;
}

void ospf_redist_del(struct ospf *ospf, u_char type, u_short instance)
{
	struct ospf_redist *red;

	red = ospf_redist_lookup(ospf, type, instance);

	if (red) {
		listnode_delete(ospf->redist[type], red);
		if (!ospf->redist[type]->count) {
			list_free(ospf->redist[type]);
			ospf->redist[type] = NULL;
		}
	}
}


int ospf_is_type_redistributed(int type, u_short instance)
{
	return (DEFAULT_ROUTE_TYPE(type)
			? vrf_bitmap_check(zclient->default_information,
					   VRF_DEFAULT)
			: ((instance
			    && redist_check_instance(
				       &zclient->mi_redist[AFI_IP][type],
				       instance))
			   || (!instance
			       && vrf_bitmap_check(
					  zclient->redist[AFI_IP][type],
					  VRF_DEFAULT))));
}

int ospf_redistribute_set(struct ospf *ospf, int type, u_short instance,
			  int mtype, int mvalue)
{
	int force = 0;
	struct ospf_redist *red;

	red = ospf_redist_lookup(ospf, type, instance);
	if (ospf_is_type_redistributed(type, instance)) {
		if (mtype != red->dmetric.type) {
			red->dmetric.type = mtype;
			force = LSA_REFRESH_FORCE;
		}
		if (mvalue != red->dmetric.value) {
			red->dmetric.value = mvalue;
			force = LSA_REFRESH_FORCE;
		}

		ospf_external_lsa_refresh_type(ospf, type, instance, force);

		if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE))
			zlog_debug(
				"Redistribute[%s][%d]: Refresh  Type[%d], Metric[%d]",
				ospf_redist_string(type), instance,
				metric_type(ospf, type, instance),
				metric_value(ospf, type, instance));

		return CMD_SUCCESS;
	}

	red->dmetric.type = mtype;
	red->dmetric.value = mvalue;

	ospf_external_add(type, instance);

	zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP, type,
			     instance, VRF_DEFAULT);

	if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE))
		zlog_debug("Redistribute[%s][%d]: Start  Type[%d], Metric[%d]",
			   ospf_redist_string(type), instance,
			   metric_type(ospf, type, instance),
			   metric_value(ospf, type, instance));

	ospf_asbr_status_update(ospf, ++ospf->redistribute);

	return CMD_SUCCESS;
}

int ospf_redistribute_unset(struct ospf *ospf, int type, u_short instance)
{
	if (type == zclient->redist_default && instance == zclient->instance)
		return CMD_SUCCESS;

	if (!ospf_is_type_redistributed(type, instance))
		return CMD_SUCCESS;

	zclient_redistribute(ZEBRA_REDISTRIBUTE_DELETE, zclient, AFI_IP, type,
			     instance, VRF_DEFAULT);

	if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE))
		zlog_debug("Redistribute[%s][%d]: Stop",
			   ospf_redist_string(type), instance);

	ospf_redist_del(ospf, type, instance);

	/* Remove the routes from OSPF table. */
	ospf_redistribute_withdraw(ospf, type, instance);

	ospf_external_del(type, instance);

	ospf_asbr_status_update(ospf, --ospf->redistribute);

	return CMD_SUCCESS;
}

int ospf_redistribute_default_set(struct ospf *ospf, int originate, int mtype,
				  int mvalue)
{
	struct ospf_redist *red;

	ospf->default_originate = originate;

	red = ospf_redist_add(ospf, DEFAULT_ROUTE, 0);
	red->dmetric.type = mtype;
	red->dmetric.value = mvalue;

	ospf_external_add(DEFAULT_ROUTE, 0);

	if (ospf_is_type_redistributed(DEFAULT_ROUTE, 0)) {
		/* if ospf->default_originate changes value, is calling
		   ospf_external_lsa_refresh_default sufficient to implement
		   the change? */
		ospf_external_lsa_refresh_default(ospf);

		if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE))
			zlog_debug(
				"Redistribute[%s]: Refresh  Type[%d], Metric[%d]",
				ospf_redist_string(DEFAULT_ROUTE),
				metric_type(ospf, DEFAULT_ROUTE, 0),
				metric_value(ospf, DEFAULT_ROUTE, 0));
		return CMD_SUCCESS;
	}

	zclient_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_ADD, zclient,
				     VRF_DEFAULT);

	if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE))
		zlog_debug("Redistribute[DEFAULT]: Start  Type[%d], Metric[%d]",
			   metric_type(ospf, DEFAULT_ROUTE, 0),
			   metric_value(ospf, DEFAULT_ROUTE, 0));

	if (ospf->router_id.s_addr == 0)
		ospf->external_origin |= (1 << DEFAULT_ROUTE);
	else
		thread_add_timer(master, ospf_default_originate_timer, ospf, 1,
				 NULL);

	ospf_asbr_status_update(ospf, ++ospf->redistribute);

	return CMD_SUCCESS;
}

int ospf_redistribute_default_unset(struct ospf *ospf)
{
	if (!ospf_is_type_redistributed(DEFAULT_ROUTE, 0))
		return CMD_SUCCESS;

	ospf->default_originate = DEFAULT_ORIGINATE_NONE;
	ospf_redist_del(ospf, DEFAULT_ROUTE, 0);

	zclient_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_DELETE, zclient,
				     VRF_DEFAULT);

	if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE))
		zlog_debug("Redistribute[DEFAULT]: Stop");

	// Pending: how does the external_info cleanup work in this case?

	ospf_asbr_status_update(ospf, --ospf->redistribute);

	return CMD_SUCCESS;
}

static int ospf_external_lsa_originate_check(struct ospf *ospf,
					     struct external_info *ei)
{
	/* If prefix is multicast, then do not originate LSA. */
	if (IN_MULTICAST(htonl(ei->p.prefix.s_addr))) {
		zlog_info(
			"LSA[Type5:%s]: Not originate AS-external-LSA, "
			"Prefix belongs multicast",
			inet_ntoa(ei->p.prefix));
		return 0;
	}

	/* Take care of default-originate. */
	if (is_prefix_default(&ei->p))
		if (ospf->default_originate == DEFAULT_ORIGINATE_NONE) {
			zlog_info(
				"LSA[Type5:0.0.0.0]: Not originate AS-external-LSA "
				"for default");
			return 0;
		}

	return 1;
}

/* If connected prefix is OSPF enable interface, then do not announce. */
int ospf_distribute_check_connected(struct ospf *ospf, struct external_info *ei)
{
	struct listnode *node;
	struct ospf_interface *oi;


	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi))
		if (prefix_match(oi->address, (struct prefix *)&ei->p))
			return 0;
	return 1;
}

/* return 1 if external LSA must be originated, 0 otherwise */
int ospf_redistribute_check(struct ospf *ospf, struct external_info *ei,
			    int *changed)
{
	struct route_map_set_values save_values;
	struct prefix_ipv4 *p = &ei->p;
	struct ospf_redist *red;
	u_char type = is_prefix_default(&ei->p) ? DEFAULT_ROUTE : ei->type;
	u_short instance = is_prefix_default(&ei->p) ? 0 : ei->instance;

	if (changed)
		*changed = 0;

	if (!ospf_external_lsa_originate_check(ospf, ei))
		return 0;

	/* Take care connected route. */
	if (type == ZEBRA_ROUTE_CONNECT
	    && !ospf_distribute_check_connected(ospf, ei))
		return 0;

	if (!DEFAULT_ROUTE_TYPE(type) && DISTRIBUTE_NAME(ospf, type))
		/* distirbute-list exists, but access-list may not? */
		if (DISTRIBUTE_LIST(ospf, type))
			if (access_list_apply(DISTRIBUTE_LIST(ospf, type), p)
			    == FILTER_DENY) {
				if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE))
					zlog_debug(
						"Redistribute[%s]: %s/%d filtered by ditribute-list.",
						ospf_redist_string(type),
						inet_ntoa(p->prefix),
						p->prefixlen);
				return 0;
			}

	save_values = ei->route_map_set;
	ospf_reset_route_map_set_values(&ei->route_map_set);

	/* apply route-map if needed */
	red = ospf_redist_lookup(ospf, type, instance);
	if (red && ROUTEMAP_NAME(red)) {
		int ret;

		ret = route_map_apply(ROUTEMAP(red), (struct prefix *)p,
				      RMAP_OSPF, ei);

		if (ret == RMAP_DENYMATCH) {
			ei->route_map_set = save_values;
			if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE))
				zlog_debug(
					"Redistribute[%s]: %s/%d filtered by route-map.",
					ospf_redist_string(type),
					inet_ntoa(p->prefix), p->prefixlen);
			return 0;
		}

		/* check if 'route-map set' changed something */
		if (changed)
			*changed = !ospf_route_map_set_compare(
				&ei->route_map_set, &save_values);
	}

	return 1;
}

/* OSPF route-map set for redistribution */
void ospf_routemap_set(struct ospf_redist *red, const char *name)
{
	if (ROUTEMAP_NAME(red))
		free(ROUTEMAP_NAME(red));

	ROUTEMAP_NAME(red) = strdup(name);
	ROUTEMAP(red) = route_map_lookup_by_name(name);
}

void ospf_routemap_unset(struct ospf_redist *red)
{
	if (ROUTEMAP_NAME(red))
		free(ROUTEMAP_NAME(red));

	ROUTEMAP_NAME(red) = NULL;
	ROUTEMAP(red) = NULL;
}

/* Zebra route add and delete treatment. */
static int ospf_zebra_read_ipv4(int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{
	struct stream *s;
	struct zapi_ipv4 api;
	unsigned long ifindex;
	struct in_addr nexthop;
	struct prefix_ipv4 p;
	struct external_info *ei;
	struct ospf *ospf;
	int i;

	s = zclient->ibuf;
	ifindex = 0;
	nexthop.s_addr = 0;

	/* Type, flags, message. */
	api.type = stream_getc(s);
	api.instance = stream_getw(s);
	api.flags = stream_getl(s);
	api.message = stream_getc(s);

	/* IPv4 prefix. */
	memset(&p, 0, sizeof(struct prefix_ipv4));
	p.family = AF_INET;
	p.prefixlen = MIN(IPV4_MAX_PREFIXLEN, stream_getc(s));
	stream_get(&p.prefix, s, PSIZE(p.prefixlen));

	if (IPV4_NET127(ntohl(p.prefix.s_addr)))
		return 0;

	/* Nexthop, ifindex, distance, metric. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP)) {
		api.nexthop_num = stream_getc(s);
		nexthop.s_addr = stream_get_ipv4(s);
	}
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_IFINDEX)) {
		api.ifindex_num = stream_getc(s);
		/* XXX assert(api.ifindex_num == 1); */
		ifindex = stream_getl(s);
	}
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_DISTANCE))
		api.distance = stream_getc(s);
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_METRIC))
		api.metric = stream_getl(s);
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_TAG))
		api.tag = stream_getl(s);
	else
		api.tag = 0;

	ospf = ospf_lookup();
	if (ospf == NULL)
		return 0;

	if (command == ZEBRA_REDISTRIBUTE_IPV4_ADD) {
		/* XXX|HACK|TODO|FIXME:
		 * Maybe we should ignore reject/blackhole routes? Testing shows
		 * that
		 * there is no problems though and this is only way to
		 * "summarize"
		 * routes in ASBR at the moment. Maybe we need just a better
		 * generalised
		 * solution for these types?
		 *
		 * if ( CHECK_FLAG (api.flags, ZEBRA_FLAG_BLACKHOLE)
		 *     || CHECK_FLAG (api.flags, ZEBRA_FLAG_REJECT))
		 * return 0;
		 */

		/* Protocol tag overwrites all other tag value send by zebra */
		if (ospf->dtag[api.type] > 0)
			api.tag = ospf->dtag[api.type];

		/*
		 * Given zebra sends update for a prefix via ADD message, it
		 * should
		 * be considered as an implicit DEL for that prefix with other
		 * source
		 * types.
		 */
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			if (i != api.type)
				ospf_external_info_delete(i, api.instance, p);

		ei = ospf_external_info_add(api.type, api.instance, p, ifindex,
					    nexthop, api.tag);
		if (ei == NULL) {
			/* Nothing has changed, so nothing to do; return */
			return 0;
		}
		if (ospf->router_id.s_addr == 0)
			/* Set flags to generate AS-external-LSA originate event
			   for each redistributed protocols later. */
			ospf->external_origin |= (1 << api.type);
		else {
			if (ei) {
				if (is_prefix_default(&p))
					ospf_external_lsa_refresh_default(ospf);
				else {
					struct ospf_lsa *current;

					current = ospf_external_info_find_lsa(
						ospf, &ei->p);
					if (!current)
						ospf_external_lsa_originate(
							ospf, ei);
					else {
						if (IS_DEBUG_OSPF(
							    zebra,
							    ZEBRA_REDISTRIBUTE))
							zlog_debug(
								"ospf_zebra_read_ipv4() : %s refreshing LSA",
								inet_ntoa(
									p.prefix));
						ospf_external_lsa_refresh(
							ospf, current, ei,
							LSA_REFRESH_FORCE);
					}
				}
			}
		}
	} else /* if (command == ZEBRA_REDISTRIBUTE_IPV4_DEL) */
	{
		ospf_external_info_delete(api.type, api.instance, p);
		if (is_prefix_default(&p))
			ospf_external_lsa_refresh_default(ospf);
		else
			ospf_external_lsa_flush(ospf, api.type, &p,
						ifindex /*, nexthop */);
	}

	return 0;
}


int ospf_distribute_list_out_set(struct ospf *ospf, int type, const char *name)
{
	/* Lookup access-list for distribute-list. */
	DISTRIBUTE_LIST(ospf, type) = access_list_lookup(AFI_IP, name);

	/* Clear previous distribute-name. */
	if (DISTRIBUTE_NAME(ospf, type))
		free(DISTRIBUTE_NAME(ospf, type));

	/* Set distribute-name. */
	DISTRIBUTE_NAME(ospf, type) = strdup(name);

	/* If access-list have been set, schedule update timer. */
	if (DISTRIBUTE_LIST(ospf, type))
		ospf_distribute_list_update(ospf, type, 0);

	return CMD_SUCCESS;
}

int ospf_distribute_list_out_unset(struct ospf *ospf, int type,
				   const char *name)
{
	/* Schedule update timer. */
	if (DISTRIBUTE_LIST(ospf, type))
		ospf_distribute_list_update(ospf, type, 0);

	/* Unset distribute-list. */
	DISTRIBUTE_LIST(ospf, type) = NULL;

	/* Clear distribute-name. */
	if (DISTRIBUTE_NAME(ospf, type))
		free(DISTRIBUTE_NAME(ospf, type));

	DISTRIBUTE_NAME(ospf, type) = NULL;

	return CMD_SUCCESS;
}

/* distribute-list update timer. */
static int ospf_distribute_list_update_timer(struct thread *thread)
{
	struct route_node *rn;
	struct external_info *ei;
	struct route_table *rt;
	struct ospf_lsa *lsa;
	int type, default_refresh = 0;
	struct ospf *ospf;

	ospf = ospf_lookup();
	if (ospf == NULL)
		return 0;

	ospf->t_distribute_update = NULL;

	zlog_info("Zebra[Redistribute]: distribute-list update timer fired!");

	/* foreach all external info. */
	for (type = 0; type <= ZEBRA_ROUTE_MAX; type++) {
		struct list *ext_list;
		struct listnode *node;
		struct ospf_external *ext;

		ext_list = om->external[type];
		if (!ext_list)
			continue;

		for (ALL_LIST_ELEMENTS_RO(ext_list, node, ext)) {
			rt = ext->external_info;
			if (!rt)
				continue;
			for (rn = route_top(rt); rn; rn = route_next(rn))
				if ((ei = rn->info) != NULL) {
					if (is_prefix_default(&ei->p))
						default_refresh = 1;
					else if (
						(lsa = ospf_external_info_find_lsa(
							 ospf, &ei->p)))
						ospf_external_lsa_refresh(
							ospf, lsa, ei,
							LSA_REFRESH_IF_CHANGED);
					else
						ospf_external_lsa_originate(
							ospf, ei);
				}
		}
	}
	if (default_refresh)
		ospf_external_lsa_refresh_default(ospf);
	return 0;
}

/* Update distribute-list and set timer to apply access-list. */
void ospf_distribute_list_update(struct ospf *ospf, uintptr_t type,
				 u_short instance)
{
	struct route_table *rt;
	struct ospf_external *ext;

	/* External info does not exist. */
	ext = ospf_external_lookup(type, instance);
	if (!ext || !(rt = EXTERNAL_INFO(ext)))
		return;

	/* If exists previously invoked thread, then let it continue. */
	if (ospf->t_distribute_update)
		return;

	/* Set timer. */
	ospf->t_distribute_update = NULL;
	thread_add_timer_msec(master, ospf_distribute_list_update_timer,
			      (void *)type, ospf->min_ls_interval,
			      &ospf->t_distribute_update);
}

/* If access-list is updated, apply some check. */
static void ospf_filter_update(struct access_list *access)
{
	struct ospf *ospf;
	int type;
	int abr_inv = 0;
	struct ospf_area *area;
	struct listnode *node;

	/* If OSPF instance does not exist, return right now. */
	ospf = ospf_lookup();
	if (ospf == NULL)
		return;

	/* Update distribute-list, and apply filter. */
	for (type = 0; type <= ZEBRA_ROUTE_MAX; type++) {
		struct list *red_list;
		struct listnode *node;
		struct ospf_redist *red;

		red_list = ospf->redist[type];
		if (red_list)
			for (ALL_LIST_ELEMENTS_RO(red_list, node, red)) {
				if (ROUTEMAP(red)) {
					/* if route-map is not NULL it may be
					 * using this access list */
					ospf_distribute_list_update(
						ospf, type, red->instance);
				}
			}

		/* There is place for route-map for default-information
		 * (ZEBRA_ROUTE_MAX),
		 * but no distribute list. */
		if (type == ZEBRA_ROUTE_MAX)
			break;

		if (DISTRIBUTE_NAME(ospf, type)) {
			/* Keep old access-list for distribute-list. */
			struct access_list *old = DISTRIBUTE_LIST(ospf, type);

			/* Update access-list for distribute-list. */
			DISTRIBUTE_LIST(ospf, type) = access_list_lookup(
				AFI_IP, DISTRIBUTE_NAME(ospf, type));

			/* No update for this distribute type. */
			if (old == NULL && DISTRIBUTE_LIST(ospf, type) == NULL)
				continue;

			/* Schedule distribute-list update timer. */
			if (DISTRIBUTE_LIST(ospf, type) == NULL
			    || strcmp(DISTRIBUTE_NAME(ospf, type), access->name)
				       == 0)
				ospf_distribute_list_update(ospf, type, 0);
		}
	}

	/* Update Area access-list. */
	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (EXPORT_NAME(area)) {
			EXPORT_LIST(area) = NULL;
			abr_inv++;
		}

		if (IMPORT_NAME(area)) {
			IMPORT_LIST(area) = NULL;
			abr_inv++;
		}
	}

	/* Schedule ABR tasks -- this will be changed -- takada. */
	if (IS_OSPF_ABR(ospf) && abr_inv)
		ospf_schedule_abr_task(ospf);
}

/* If prefix-list is updated, do some updates. */
void ospf_prefix_list_update(struct prefix_list *plist)
{
	struct ospf *ospf;
	int type;
	int abr_inv = 0;
	struct ospf_area *area;
	struct listnode *node;

	/* If OSPF instatnce does not exist, return right now. */
	ospf = ospf_lookup();
	if (ospf == NULL)
		return;

	/* Update all route-maps which are used as redistribution filters.
	 * They might use prefix-list.
	 */
	for (type = 0; type <= ZEBRA_ROUTE_MAX; type++) {
		struct list *red_list;
		struct listnode *node;
		struct ospf_redist *red;

		red_list = ospf->redist[type];
		if (red_list)
			for (ALL_LIST_ELEMENTS_RO(red_list, node, red)) {
				if (ROUTEMAP(red)) {
					/* if route-map is not NULL it may be
					 * using this prefix list */
					ospf_distribute_list_update(
						ospf, type, red->instance);
				}
			}
	}

	/* Update area filter-lists. */
	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		/* Update filter-list in. */
		if (PREFIX_NAME_IN(area))
			if (strcmp(PREFIX_NAME_IN(area),
				   prefix_list_name(plist))
			    == 0) {
				PREFIX_LIST_IN(area) = prefix_list_lookup(
					AFI_IP, PREFIX_NAME_IN(area));
				abr_inv++;
			}

		/* Update filter-list out. */
		if (PREFIX_NAME_OUT(area))
			if (strcmp(PREFIX_NAME_OUT(area),
				   prefix_list_name(plist))
			    == 0) {
				PREFIX_LIST_IN(area) = prefix_list_lookup(
					AFI_IP, PREFIX_NAME_OUT(area));
				abr_inv++;
			}
	}

	/* Schedule ABR task. */
	if (IS_OSPF_ABR(ospf) && abr_inv)
		ospf_schedule_abr_task(ospf);
}

static struct ospf_distance *ospf_distance_new(void)
{
	return XCALLOC(MTYPE_OSPF_DISTANCE, sizeof(struct ospf_distance));
}

static void ospf_distance_free(struct ospf_distance *odistance)
{
	XFREE(MTYPE_OSPF_DISTANCE, odistance);
}

int ospf_distance_set(struct vty *vty, struct ospf *ospf,
		      const char *distance_str, const char *ip_str,
		      const char *access_list_str)
{
	int ret;
	struct prefix_ipv4 p;
	u_char distance;
	struct route_node *rn;
	struct ospf_distance *odistance;

	ret = str2prefix_ipv4(ip_str, &p);
	if (ret == 0) {
		vty_out(vty, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	distance = atoi(distance_str);

	/* Get OSPF distance node. */
	rn = route_node_get(ospf->distance_table, (struct prefix *)&p);
	if (rn->info) {
		odistance = rn->info;
		route_unlock_node(rn);
	} else {
		odistance = ospf_distance_new();
		rn->info = odistance;
	}

	/* Set distance value. */
	odistance->distance = distance;

	/* Reset access-list configuration. */
	if (odistance->access_list) {
		free(odistance->access_list);
		odistance->access_list = NULL;
	}
	if (access_list_str)
		odistance->access_list = strdup(access_list_str);

	return CMD_SUCCESS;
}

int ospf_distance_unset(struct vty *vty, struct ospf *ospf,
			const char *distance_str, const char *ip_str,
			char const *access_list_str)
{
	int ret;
	struct prefix_ipv4 p;
	struct route_node *rn;
	struct ospf_distance *odistance;

	ret = str2prefix_ipv4(ip_str, &p);
	if (ret == 0) {
		vty_out(vty, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rn = route_node_lookup(ospf->distance_table, (struct prefix *)&p);
	if (!rn) {
		vty_out(vty, "Can't find specified prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	odistance = rn->info;

	if (odistance->access_list)
		free(odistance->access_list);
	ospf_distance_free(odistance);

	rn->info = NULL;
	route_unlock_node(rn);
	route_unlock_node(rn);

	return CMD_SUCCESS;
}

void ospf_distance_reset(struct ospf *ospf)
{
	struct route_node *rn;
	struct ospf_distance *odistance;

	for (rn = route_top(ospf->distance_table); rn; rn = route_next(rn))
		if ((odistance = rn->info) != NULL) {
			if (odistance->access_list)
				free(odistance->access_list);
			ospf_distance_free(odistance);
			rn->info = NULL;
			route_unlock_node(rn);
		}
}

u_char ospf_distance_apply(struct prefix_ipv4 *p, struct ospf_route * or)
{
	struct ospf *ospf;

	ospf = ospf_lookup();
	if (ospf == NULL)
		return 0;

	if (ospf->distance_intra)
		if (or->path_type == OSPF_PATH_INTRA_AREA)
			return ospf->distance_intra;

	if (ospf->distance_inter)
		if (or->path_type == OSPF_PATH_INTER_AREA)
			return ospf->distance_inter;

	if (ospf->distance_external)
		if (or->path_type == OSPF_PATH_TYPE1_EXTERNAL ||
		    or->path_type == OSPF_PATH_TYPE2_EXTERNAL)
			return ospf->distance_external;

	if (ospf->distance_all)
		return ospf->distance_all;

	return 0;
}

static void ospf_zebra_connected(struct zclient *zclient)
{
	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER);

	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

void ospf_zebra_init(struct thread_master *master, u_short instance)
{
	/* Allocate zebra structure. */
	zclient = zclient_new(master);
	zclient_init(zclient, ZEBRA_ROUTE_OSPF, instance);
	zclient->zebra_connected = ospf_zebra_connected;
	zclient->router_id_update = ospf_router_id_update_zebra;
	zclient->interface_add = ospf_interface_add;
	zclient->interface_delete = ospf_interface_delete;
	zclient->interface_up = ospf_interface_state_up;
	zclient->interface_down = ospf_interface_state_down;
	zclient->interface_address_add = ospf_interface_address_add;
	zclient->interface_address_delete = ospf_interface_address_delete;
	zclient->interface_link_params = ospf_interface_link_params;

	zclient->redistribute_route_ipv4_add = ospf_zebra_read_ipv4;
	zclient->redistribute_route_ipv4_del = ospf_zebra_read_ipv4;

	access_list_add_hook(ospf_filter_update);
	access_list_delete_hook(ospf_filter_update);
	prefix_list_add_hook(ospf_prefix_list_update);
	prefix_list_delete_hook(ospf_prefix_list_update);
}
