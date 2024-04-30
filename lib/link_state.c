// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Link State Database - link_state.c
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2020 Orange http://www.orange.com
 *
 * This file is part of Free Range Routing (FRR).
 */

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "log.h"
#include "command.h"
#include "termtable.h"
#include "memory.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "zclient.h"
#include "stream.h"
#include "sbuf.h"
#include "printfrr.h"
#include <lib/json.h>
#include "link_state.h"
#include "iso.h"

/* Link State Memory allocation */
DEFINE_MTYPE_STATIC(LIB, LS_DB, "Link State Database");

/**
 *  Link State Node management functions
 */
int ls_node_id_same(struct ls_node_id i1, struct ls_node_id i2)
{
	if (i1.origin != i2.origin)
		return 0;

	if (i1.origin == UNKNOWN)
		return 1;

	if (i1.origin == ISIS_L1 || i1.origin == ISIS_L2) {
		if (memcmp(i1.id.iso.sys_id, i2.id.iso.sys_id, ISO_SYS_ID_LEN)
			    != 0
		    || (i1.id.iso.level != i2.id.iso.level))
			return 0;
	} else {
		if (!IPV4_ADDR_SAME(&i1.id.ip.addr, &i2.id.ip.addr)
		    || !IPV4_ADDR_SAME(&i1.id.ip.area_id, &i2.id.ip.area_id))
			return 1;
	}

	return 1;
}

struct ls_node *ls_node_new(struct ls_node_id adv, struct in_addr rid,
			    struct in6_addr rid6)
{
	struct ls_node *new;

	if (adv.origin == UNKNOWN)
		return NULL;

	new = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_node));
	new->adv = adv;
	if (!IPV4_NET0(rid.s_addr)) {
		new->router_id = rid;
		SET_FLAG(new->flags, LS_NODE_ROUTER_ID);
	} else {
		if (adv.origin == OSPFv2 || adv.origin == STATIC
		    || adv.origin == DIRECT) {
			new->router_id = adv.id.ip.addr;
			SET_FLAG(new->flags, LS_NODE_ROUTER_ID);
		}
	}
	if (!IN6_IS_ADDR_UNSPECIFIED(&rid6)) {
		new->router_id6 = rid6;
		SET_FLAG(new->flags, LS_NODE_ROUTER_ID6);
	}
	return new;
}

void ls_node_del(struct ls_node *node)
{
	if (!node)
		return;

	XFREE(MTYPE_LS_DB, node);
}

int ls_node_same(struct ls_node *n1, struct ls_node *n2)
{
	/* First, check pointer */
	if ((n1 && !n2) || (!n1 && n2))
		return 0;

	if (n1 == n2)
		return 1;

	/* Then, verify Flags and Origin */
	if (n1->flags != n2->flags)
		return 0;

	if (!ls_node_id_same(n1->adv, n2->adv))
		return 0;

	/* Finally, check each individual parameters that are valid */
	if (CHECK_FLAG(n1->flags, LS_NODE_NAME)
	    && (strncmp(n1->name, n2->name, MAX_NAME_LENGTH) != 0))
		return 0;
	if (CHECK_FLAG(n1->flags, LS_NODE_ROUTER_ID)
	    && !IPV4_ADDR_SAME(&n1->router_id, &n2->router_id))
		return 0;
	if (CHECK_FLAG(n1->flags, LS_NODE_ROUTER_ID6)
	    && !IPV6_ADDR_SAME(&n1->router_id6, &n2->router_id6))
		return 0;
	if (CHECK_FLAG(n1->flags, LS_NODE_FLAG)
	    && (n1->node_flag != n2->node_flag))
		return 0;
	if (CHECK_FLAG(n1->flags, LS_NODE_TYPE) && (n1->type != n2->type))
		return 0;
	if (CHECK_FLAG(n1->flags, LS_NODE_AS_NUMBER)
	    && (n1->as_number != n2->as_number))
		return 0;
	if (CHECK_FLAG(n1->flags, LS_NODE_SR)) {
		if (n1->srgb.flag != n2->srgb.flag
		    || n1->srgb.lower_bound != n2->srgb.lower_bound
		    || n1->srgb.range_size != n2->srgb.range_size)
			return 0;
		if ((n1->algo[0] != n2->algo[0])
		    || (n1->algo[1] != n2->algo[1]))
			return 0;
		if (CHECK_FLAG(n1->flags, LS_NODE_SRLB)
		    && ((n1->srlb.lower_bound != n2->srlb.lower_bound
			 || n1->srlb.range_size != n2->srlb.range_size)))
			return 0;
		if (CHECK_FLAG(n1->flags, LS_NODE_MSD) && (n1->msd != n2->msd))
			return 0;
	}

	/* OK, n1 & n2 are equal */
	return 1;
}

/**
 *  Link State Attributes management functions
 */
struct ls_attributes *ls_attributes_new(struct ls_node_id adv,
					struct in_addr local,
					struct in6_addr local6,
					uint32_t local_id)
{
	struct ls_attributes *new;

	if (adv.origin == UNKNOWN)
		return NULL;

	new = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_attributes));
	new->adv = adv;
	if (!IPV4_NET0(local.s_addr)) {
		new->standard.local = local;
		SET_FLAG(new->flags, LS_ATTR_LOCAL_ADDR);
	}
	if (!IN6_IS_ADDR_UNSPECIFIED(&local6)) {
		new->standard.local6 = local6;
		SET_FLAG(new->flags, LS_ATTR_LOCAL_ADDR6);
	}
	if (local_id != 0) {
		new->standard.local_id = local_id;
		SET_FLAG(new->flags, LS_ATTR_LOCAL_ID);
	}

	/* Check that almost one identifier is set */
	if (!CHECK_FLAG(new->flags, LS_ATTR_LOCAL_ADDR | LS_ATTR_LOCAL_ADDR6
	    | LS_ATTR_LOCAL_ID)) {
		XFREE(MTYPE_LS_DB, new);
		return NULL;
	}

	admin_group_init(&new->ext_admin_group);

	return new;
}

void ls_attributes_srlg_del(struct ls_attributes *attr)
{
	if (!attr)
		return;

	if (attr->srlgs)
		XFREE(MTYPE_LS_DB, attr->srlgs);

	attr->srlgs = NULL;
	attr->srlg_len = 0;
	UNSET_FLAG(attr->flags, LS_ATTR_SRLG);
}

void ls_attributes_del(struct ls_attributes *attr)
{
	if (!attr)
		return;

	ls_attributes_srlg_del(attr);

	admin_group_term(&attr->ext_admin_group);

	XFREE(MTYPE_LS_DB, attr);
}

int ls_attributes_same(struct ls_attributes *l1, struct ls_attributes *l2)
{
	/* First, check pointer */
	if ((l1 && !l2) || (!l1 && l2))
		return 0;

	if (l1 == l2)
		return 1;

	/* Then, verify Flags and Origin */
	if (l1->flags != l2->flags)
		return 0;

	if (!ls_node_id_same(l1->adv, l2->adv))
		return 0;

	/* Finally, check each individual parameters that are valid */
	if (CHECK_FLAG(l1->flags, LS_ATTR_NAME)
	    && strncmp(l1->name, l2->name, MAX_NAME_LENGTH) != 0)
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_METRIC) && (l1->metric != l2->metric))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_TE_METRIC)
	    && (l1->standard.te_metric != l2->standard.te_metric))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_ADM_GRP)
	    && (l1->standard.admin_group != l2->standard.admin_group))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_EXT_ADM_GRP) &&
	    !admin_group_cmp(&l1->ext_admin_group, &l2->ext_admin_group))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_LOCAL_ADDR)
	    && !IPV4_ADDR_SAME(&l1->standard.local, &l2->standard.local))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_NEIGH_ADDR)
	    && !IPV4_ADDR_SAME(&l1->standard.remote, &l2->standard.remote))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_LOCAL_ADDR6)
	    && !IPV6_ADDR_SAME(&l1->standard.local6, &l2->standard.local6))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_NEIGH_ADDR6)
	    && !IPV6_ADDR_SAME(&l1->standard.remote6, &l2->standard.remote6))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_LOCAL_ID)
	    && (l1->standard.local_id != l2->standard.local_id))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_NEIGH_ID)
	    && (l1->standard.remote_id != l2->standard.remote_id))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_MAX_BW)
	    && (l1->standard.max_bw != l2->standard.max_bw))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_MAX_RSV_BW)
	    && (l1->standard.max_rsv_bw != l2->standard.max_rsv_bw))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_UNRSV_BW)
	    && memcmp(&l1->standard.unrsv_bw, &l2->standard.unrsv_bw, 32) != 0)
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_REMOTE_AS)
	    && (l1->standard.remote_as != l2->standard.remote_as))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_REMOTE_ADDR)
	    && !IPV4_ADDR_SAME(&l1->standard.remote_addr,
			       &l2->standard.remote_addr))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_REMOTE_ADDR6)
	    && !IPV6_ADDR_SAME(&l1->standard.remote_addr6,
			       &l2->standard.remote_addr6))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_DELAY)
	    && (l1->extended.delay != l2->extended.delay))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_MIN_MAX_DELAY)
	    && ((l1->extended.min_delay != l2->extended.min_delay)
		|| (l1->extended.max_delay != l2->extended.max_delay)))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_JITTER)
	    && (l1->extended.jitter != l2->extended.jitter))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_PACKET_LOSS)
	    && (l1->extended.pkt_loss != l2->extended.pkt_loss))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_AVA_BW)
	    && (l1->extended.ava_bw != l2->extended.ava_bw))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_RSV_BW)
	    && (l1->extended.rsv_bw != l2->extended.rsv_bw))
		return 0;
	if (CHECK_FLAG(l1->flags, LS_ATTR_USE_BW)
	    && (l1->extended.used_bw != l2->extended.used_bw))
		return 0;
	for (int i = 0; i < LS_ADJ_MAX; i++) {
		if (!CHECK_FLAG(l1->flags, (LS_ATTR_ADJ_SID << i)))
			continue;
		if ((l1->adj_sid[i].sid != l2->adj_sid[i].sid)
		    || (l1->adj_sid[i].flags != l2->adj_sid[i].flags)
		    || (l1->adj_sid[i].weight != l2->adj_sid[i].weight))
			return 0;
		if (((l1->adv.origin == ISIS_L1) || (l1->adv.origin == ISIS_L2))
		    && (memcmp(&l1->adj_sid[i].neighbor.sysid,
			       &l2->adj_sid[i].neighbor.sysid, ISO_SYS_ID_LEN)
			!= 0))
			return 0;
		if (((l1->adv.origin == OSPFv2) || (l1->adv.origin == STATIC)
		     || (l1->adv.origin == DIRECT))
		    && (i < ADJ_PRI_IPV6)
		    && (!IPV4_ADDR_SAME(&l1->adj_sid[i].neighbor.addr,
					&l2->adj_sid[i].neighbor.addr)))
			return 0;
	}
	if (CHECK_FLAG(l1->flags, LS_ATTR_SRLG)
	    && ((l1->srlg_len != l2->srlg_len)
		|| memcmp(l1->srlgs, l2->srlgs,
			  l1->srlg_len * sizeof(uint32_t))
			   != 0))
		return 0;

	/* OK, l1 & l2 are equal */
	return 1;
}

/**
 *  Link State prefix management functions
 */
struct ls_prefix *ls_prefix_new(struct ls_node_id adv, struct prefix *p)
{
	struct ls_prefix *new;

	if (adv.origin == UNKNOWN)
		return NULL;

	new = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_prefix));
	new->adv = adv;
	new->pref = *p;

	return new;
}

void ls_prefix_del(struct ls_prefix *pref)
{
	if (!pref)
		return;

	XFREE(MTYPE_LS_DB, pref);
}

int ls_prefix_same(struct ls_prefix *p1, struct ls_prefix *p2)
{
	/* First, check pointer */
	if ((p1 && !p2) || (!p1 && p2))
		return 0;

	if (p1 == p2)
		return 1;

	/* Then, verify Flags and Origin */
	if (p1->flags != p2->flags)
		return 0;

	if (!ls_node_id_same(p1->adv, p2->adv))
		return 0;

	/* Finally, check each individual parameters that are valid */
	if (prefix_same(&p1->pref, &p2->pref) == 0)
		return 0;
	if (CHECK_FLAG(p1->flags, LS_PREF_IGP_FLAG)
	    && (p1->igp_flag != p2->igp_flag))
		return 0;
	if (CHECK_FLAG(p1->flags, LS_PREF_ROUTE_TAG)
	    && (p1->route_tag != p2->route_tag))
		return 0;
	if (CHECK_FLAG(p1->flags, LS_PREF_EXTENDED_TAG)
	    && (p1->extended_tag != p2->extended_tag))
		return 0;
	if (CHECK_FLAG(p1->flags, LS_PREF_METRIC) && (p1->metric != p2->metric))
		return 0;
	if (CHECK_FLAG(p1->flags, LS_PREF_SR)) {
		if ((p1->sr.algo != p2->sr.algo) || (p1->sr.sid != p2->sr.sid)
		    || (p1->sr.sid_flag != p2->sr.sid_flag))
			return 0;
	}

	/* OK, p1 & p2 are equal */
	return 1;
}

/**
 *  Link State Vertices management functions
 */
uint64_t sysid_to_key(const uint8_t sysid[ISO_SYS_ID_LEN])
{
	uint64_t key = 0;

#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t *byte = (uint8_t *)&key;

	for (int i = 0; i < ISO_SYS_ID_LEN; i++)
		byte[i] = sysid[ISO_SYS_ID_LEN - i - 1];

	byte[6] = 0;
	byte[7] = 0;
#else
	memcpy(&key, sysid, ISO_SYS_ID_LEN);
#endif

	return key;
}

struct ls_vertex *ls_vertex_add(struct ls_ted *ted, struct ls_node *node)
{
	struct ls_vertex *new;
	uint64_t key = 0;

	if ((ted == NULL) || (node == NULL))
		return NULL;

	/* set Key as the IPv4/Ipv6 Router ID or ISO System ID */
	switch (node->adv.origin) {
	case OSPFv2:
	case STATIC:
	case DIRECT:
		key = ((uint64_t)ntohl(node->adv.id.ip.addr.s_addr))
		      & 0xffffffff;
		break;
	case ISIS_L1:
	case ISIS_L2:
		key = sysid_to_key(node->adv.id.iso.sys_id);
		break;
	case UNKNOWN:
		key = 0;
		break;
	}

	/* Check that key is valid */
	if (key == 0)
		return NULL;

	/* Create Vertex and add it to the TED */
	new = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_vertex));
	if (!new)
		return NULL;

	new->key = key;
	new->node = node;
	new->status = NEW;
	new->type = VERTEX;
	new->incoming_edges = list_new();
	new->incoming_edges->cmp = (int (*)(void *, void *))edge_cmp;
	new->outgoing_edges = list_new();
	new->outgoing_edges->cmp = (int (*)(void *, void *))edge_cmp;
	new->prefixes = list_new();
	new->prefixes->cmp = (int (*)(void *, void *))subnet_cmp;
	vertices_add(&ted->vertices, new);

	return new;
}

void ls_vertex_del(struct ls_ted *ted, struct ls_vertex *vertex)
{
	struct listnode *node, *nnode;
	struct ls_edge *edge;
	struct ls_subnet *subnet;

	if (!ted || !vertex)
		return;

	/* Remove outgoing Edges and list */
	for (ALL_LIST_ELEMENTS(vertex->outgoing_edges, node, nnode, edge))
		ls_edge_del_all(ted, edge);
	list_delete(&vertex->outgoing_edges);

	/* Disconnect incoming Edges and remove list */
	for (ALL_LIST_ELEMENTS(vertex->incoming_edges, node, nnode, edge)) {
		ls_disconnect(vertex, edge, false);
		if (edge->source == NULL)
			ls_edge_del_all(ted, edge);
	}
	list_delete(&vertex->incoming_edges);

	/* Remove subnet and list */
	for (ALL_LIST_ELEMENTS(vertex->prefixes, node, nnode, subnet))
		ls_subnet_del_all(ted, subnet);
	list_delete(&vertex->prefixes);

	/* Then remove Vertex from Link State Data Base and free memory */
	vertices_del(&ted->vertices, vertex);
	XFREE(MTYPE_LS_DB, vertex);
}

void ls_vertex_del_all(struct ls_ted *ted, struct ls_vertex *vertex)
{
	if (!ted || !vertex)
		return;

	/* First remove associated Link State Node */
	ls_node_del(vertex->node);

	/* Then, Vertex itself */
	ls_vertex_del(ted, vertex);
}

struct ls_vertex *ls_vertex_update(struct ls_ted *ted, struct ls_node *node)
{
	struct ls_vertex *old;

	if (node == NULL)
		return NULL;

	old = ls_find_vertex_by_id(ted, node->adv);
	if (old) {
		if (!ls_node_same(old->node, node)) {
			ls_node_del(old->node);
			old->node = node;
		} else
			ls_node_del(node);

		old->status = UPDATE;
		return old;
	}

	return ls_vertex_add(ted, node);
}

struct ls_vertex *ls_find_vertex_by_key(struct ls_ted *ted, const uint64_t key)
{
	struct ls_vertex vertex = {};

	if (key == 0)
		return NULL;

	vertex.key = key;
	return vertices_find(&ted->vertices, &vertex);
}

struct ls_vertex *ls_find_vertex_by_id(struct ls_ted *ted,
				       struct ls_node_id nid)
{
	struct ls_vertex vertex = {};

	vertex.key = 0;
	switch (nid.origin) {
	case OSPFv2:
	case STATIC:
	case DIRECT:
		vertex.key =
			((uint64_t)ntohl(nid.id.ip.addr.s_addr)) & 0xffffffff;
		break;
	case ISIS_L1:
	case ISIS_L2:
		vertex.key = sysid_to_key(nid.id.iso.sys_id);
		break;
	case UNKNOWN:
		return NULL;
	}

	return vertices_find(&ted->vertices, &vertex);
}

int ls_vertex_same(struct ls_vertex *v1, struct ls_vertex *v2)
{
	if ((v1 && !v2) || (!v1 && v2))
		return 0;

	if (!v1 && !v2)
		return 1;

	if (v1->key != v2->key)
		return 0;

	if (v1->node == v2->node)
		return 1;

	return ls_node_same(v1->node, v2->node);
}

void ls_vertex_clean(struct ls_ted *ted, struct ls_vertex *vertex,
		     struct zclient *zclient)
{
	struct listnode *node, *nnode;
	struct ls_edge *edge;
	struct ls_subnet *subnet;
	struct ls_message msg;

	/* Remove Orphan Edge ... */
	for (ALL_LIST_ELEMENTS(vertex->outgoing_edges, node, nnode, edge)) {
		if (edge->status == ORPHAN) {
			if (zclient) {
				edge->status = DELETE;
				ls_edge2msg(&msg, edge);
				ls_send_msg(zclient, &msg, NULL);
			}
			ls_edge_del_all(ted, edge);
		}
	}
	for (ALL_LIST_ELEMENTS(vertex->incoming_edges, node, nnode, edge)) {
		if (edge->status == ORPHAN) {
			if (zclient) {
				edge->status = DELETE;
				ls_edge2msg(&msg, edge);
				ls_send_msg(zclient, &msg, NULL);
			}
			ls_edge_del_all(ted, edge);
		}
	}

	/* ... and Subnet from the Vertex */
	for (ALL_LIST_ELEMENTS(vertex->prefixes, node, nnode, subnet)) {
		if (subnet->status == ORPHAN) {
			if (zclient) {
				subnet->status = DELETE;
				ls_subnet2msg(&msg, subnet);
				ls_send_msg(zclient, &msg, NULL);
			}
			ls_subnet_del_all(ted, subnet);
		}
	}
}

/**
 * Link State Edges management functions
 */

/**
 * This function allows to connect the Edge to the vertices present in the TED.
 * A temporary vertex that corresponds to the source of this Edge i.e. the
 * advertised router, is created if not found in the Data Base. If a Edge that
 * corresponds to the reverse path is found, the Edge is attached to the
 * destination vertex as destination and reverse Edge is attached to the source
 * vertex as source.
 *
 * @param ted	Link State Data Base
 * @param edge	Link State Edge to be attached
 */
static void ls_edge_connect_to(struct ls_ted *ted, struct ls_edge *edge)
{
	struct ls_vertex *vertex = NULL;
	struct ls_node *node;
	struct ls_edge *dst;
	const struct in_addr inaddr_any = {.s_addr = INADDR_ANY};

	/* First, search if there is a Vertex that correspond to the Node ID */
	vertex = ls_find_vertex_by_id(ted, edge->attributes->adv);
	if (vertex == NULL) {
		/* Create a new temporary Node & Vertex if not found */
		node = ls_node_new(edge->attributes->adv, inaddr_any,
				   in6addr_any);
		vertex = ls_vertex_add(ted, node);
	}
	/* and attach the edge as source to the vertex */
	listnode_add_sort_nodup(vertex->outgoing_edges, edge);
	edge->source = vertex;

	/* Then search if there is a reverse Edge */
	dst = ls_find_edge_by_destination(ted, edge->attributes);
	/* attach the destination edge to the vertex */
	if (dst) {
		listnode_add_sort_nodup(vertex->incoming_edges, dst);
		dst->destination = vertex;
		/* and destination vertex to this edge */
		vertex = dst->source;
		listnode_add_sort_nodup(vertex->incoming_edges, edge);
		edge->destination = vertex;
	}
}

static struct ls_edge_key get_edge_key(struct ls_attributes *attr, bool dst)
{
	struct ls_edge_key key = {.family = AF_UNSPEC};
	struct ls_standard *std;

	if (!attr)
		return key;

	std = &attr->standard;

	if (dst) {
		if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR)) {
			/* Key is the IPv4 remote address */
			key.family = AF_INET;
			IPV4_ADDR_COPY(&key.k.addr, &std->remote);
		} else if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR6)) {
			/* or the IPv6 remote address */
			key.family = AF_INET6;
			IPV6_ADDR_COPY(&key.k.addr6, &std->remote6);
		} else if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ID)) {
			/* or Remote identifier if IP addr. are not defined */
			key.family = AF_LOCAL;
			key.k.link_id =
				(((uint64_t)std->remote_id) & 0xffffffff) |
				((uint64_t)std->local_id << 32);
		}
	} else {
		if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR)) {
			/* Key is the IPv4 local address */
			key.family = AF_INET;
			IPV4_ADDR_COPY(&key.k.addr, &std->local);
		} else if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR6)) {
			/* or the 64 bits LSB of IPv6 local address */
			key.family = AF_INET6;
			IPV6_ADDR_COPY(&key.k.addr6, &std->local6);
		} else if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ID)) {
			/* or Remote identifier if IP addr. are not defined */
			key.family = AF_LOCAL;
			key.k.link_id =
				(((uint64_t)std->local_id) & 0xffffffff) |
				((uint64_t)std->remote_id << 32);
		}
	}

	return key;
}

struct ls_edge *ls_edge_add(struct ls_ted *ted,
			    struct ls_attributes *attributes)
{
	struct ls_edge *new;
	struct ls_edge_key key;

	if (attributes == NULL)
		return NULL;

	key = get_edge_key(attributes, false);
	if (key.family == AF_UNSPEC)
		return NULL;

	/* Create Edge and add it to the TED */
	new = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_edge));

	new->attributes = attributes;
	new->key = key;
	new->status = NEW;
	new->type = EDGE;
	edges_add(&ted->edges, new);

	/* Finally, connect Edge to Vertices */
	ls_edge_connect_to(ted, new);

	return new;
}

struct ls_edge *ls_find_edge_by_key(struct ls_ted *ted,
				    const struct ls_edge_key key)
{
	struct ls_edge edge = {};

	if (key.family == AF_UNSPEC)
		return NULL;

	edge.key = key;
	return edges_find(&ted->edges, &edge);
}

struct ls_edge *ls_find_edge_by_source(struct ls_ted *ted,
				       struct ls_attributes *attributes)
{
	struct ls_edge edge = {};

	if (attributes == NULL)
		return NULL;

	edge.key = get_edge_key(attributes, false);
	if (edge.key.family == AF_UNSPEC)
		return NULL;

	return edges_find(&ted->edges, &edge);
}

struct ls_edge *ls_find_edge_by_destination(struct ls_ted *ted,
					    struct ls_attributes *attributes)
{
	struct ls_edge edge = {};

	if (attributes == NULL)
		return NULL;

	edge.key = get_edge_key(attributes, true);
	if (edge.key.family == AF_UNSPEC)
		return NULL;

	return edges_find(&ted->edges, &edge);
}

struct ls_edge *ls_edge_update(struct ls_ted *ted,
			       struct ls_attributes *attributes)
{
	struct ls_edge *old;

	if (attributes == NULL)
		return NULL;

	/* First, search for an existing Edge */
	old = ls_find_edge_by_source(ted, attributes);
	if (old) {
		/* Check if attributes are similar */
		if (!ls_attributes_same(old->attributes, attributes)) {
			ls_attributes_del(old->attributes);
			old->attributes = attributes;
		} else
			ls_attributes_del(attributes);

		old->status = UPDATE;
		return old;
	}

	/* If not found, add new Edge from the attributes */
	return ls_edge_add(ted, attributes);
}

int ls_edge_same(struct ls_edge *e1, struct ls_edge *e2)
{
	if ((e1 && !e2) || (!e1 && e2))
		return 0;

	if (!e1 && !e2)
		return 1;

	if (edge_cmp(e1, e2) != 0)
		return 0;

	if (e1->attributes == e2->attributes)
		return 1;

	return ls_attributes_same(e1->attributes, e2->attributes);
}

void ls_edge_del(struct ls_ted *ted, struct ls_edge *edge)
{
	if (!ted || !edge)
		return;

	/* Fist disconnect Edge from Vertices */
	ls_disconnect_edge(edge);
	/* Then remove it from the Data Base */
	edges_del(&ted->edges, edge);
	XFREE(MTYPE_LS_DB, edge);
}

void ls_edge_del_all(struct ls_ted *ted, struct ls_edge *edge)
{
	if (!ted || !edge)
		return;

	/* Remove associated Link State Attributes */
	ls_attributes_del(edge->attributes);
	/* Then Edge itself */
	ls_edge_del(ted, edge);
}

/**
 * Link State Subnet Management functions.
 */
struct ls_subnet *ls_subnet_add(struct ls_ted *ted,
				struct ls_prefix *ls_pref)
{
	struct ls_subnet *new;
	struct ls_vertex *vertex;
	struct ls_node *node;
	const struct in_addr inaddr_any = {.s_addr = INADDR_ANY};

	if (ls_pref == NULL)
		return NULL;

	new = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_subnet));
	new->ls_pref = ls_pref;
	new->key = ls_pref->pref;
	new->status = NEW;
	new->type = SUBNET;

	/* Find Vertex */
	vertex = ls_find_vertex_by_id(ted, ls_pref->adv);
	if (vertex == NULL) {
		/* Create a new temporary Node & Vertex if not found */
		node = ls_node_new(ls_pref->adv, inaddr_any, in6addr_any);
		vertex = ls_vertex_add(ted, node);
	}
	/* And attach the subnet to the corresponding Vertex */
	new->vertex = vertex;
	listnode_add_sort_nodup(vertex->prefixes, new);

	subnets_add(&ted->subnets, new);

	return new;
}

struct ls_subnet *ls_subnet_update(struct ls_ted *ted, struct ls_prefix *pref)
{
	struct ls_subnet *old;

	if (pref == NULL)
		return NULL;

	old = ls_find_subnet(ted, &pref->pref);
	if (old) {
		if (!ls_prefix_same(old->ls_pref, pref)) {
			ls_prefix_del(old->ls_pref);
			old->ls_pref = pref;
		} else
			ls_prefix_del(pref);

		old->status = UPDATE;
		return old;
	}

	return ls_subnet_add(ted, pref);
}

int ls_subnet_same(struct ls_subnet *s1, struct ls_subnet *s2)
{
	if ((s1 && !s2) || (!s1 && s2))
		return 0;

	if (!s1 && !s2)
		return 1;

	if (!prefix_same(&s1->key, &s2->key))
		return 0;

	if (s1->ls_pref == s2->ls_pref)
		return 1;

	return ls_prefix_same(s1->ls_pref, s2->ls_pref);
}

void ls_subnet_del(struct ls_ted *ted, struct ls_subnet *subnet)
{
	if (!ted || !subnet)
		return;

	/* First, disconnect Subnet from associated Vertex */
	listnode_delete(subnet->vertex->prefixes, subnet);
	/* Then delete Subnet */
	subnets_del(&ted->subnets, subnet);
	XFREE(MTYPE_LS_DB, subnet);
}

void ls_subnet_del_all(struct ls_ted *ted, struct ls_subnet *subnet)
{
	if (!ted || !subnet)
		return;

	/* First, remove associated Link State Subnet */
	ls_prefix_del(subnet->ls_pref);
	/* Then, delete Subnet itself */
	ls_subnet_del(ted, subnet);
}

struct ls_subnet *ls_find_subnet(struct ls_ted *ted,
				 const struct prefix *prefix)
{
	struct ls_subnet subnet = {};

	if (!prefix)
		return NULL;

	prefix_copy(&subnet.key, prefix);
	return subnets_find(&ted->subnets, &subnet);
}

/**
 * Link State TED management functions
 */
struct ls_ted *ls_ted_new(const uint32_t key, const char *name,
			  uint32_t as_number)
{
	struct ls_ted *new;

	new = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_ted));

	/* Set basic information for this ted */
	new->key = key;
	new->as_number = as_number;
	strlcpy(new->name, name, MAX_NAME_LENGTH);

	/* Initialize the various RB tree */
	vertices_init(&new->vertices);
	edges_init(&new->edges);
	subnets_init(&new->subnets);

	return new;
}

void ls_ted_del(struct ls_ted *ted)
{
	if (ted == NULL)
		return;

	/* Check that TED is empty */
	if (vertices_count(&ted->vertices) || edges_count(&ted->edges)
	    || subnets_count(&ted->subnets))
		return;

	/* Release RB Tree */
	vertices_fini(&ted->vertices);
	edges_fini(&ted->edges);
	subnets_fini(&ted->subnets);

	XFREE(MTYPE_LS_DB, ted);
}

void ls_ted_del_all(struct ls_ted **ted)
{
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct ls_subnet *subnet;

	if (*ted == NULL)
		return;

	/* First remove Vertices, Edges and Subnets and associated Link State */
	frr_each_safe (vertices, &(*ted)->vertices, vertex)
		ls_vertex_del_all(*ted, vertex);
	frr_each_safe (edges, &(*ted)->edges, edge)
		ls_edge_del_all(*ted, edge);
	frr_each_safe (subnets, &(*ted)->subnets, subnet)
		ls_subnet_del_all(*ted, subnet);

	/* then remove TED itself */
	ls_ted_del(*ted);
	*ted = NULL;
}

void ls_ted_clean(struct ls_ted *ted)
{
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct ls_subnet *subnet;

	if (ted == NULL)
		return;

	/* First, start with Vertices */
	frr_each_safe (vertices, &ted->vertices, vertex)
		if (vertex->status == ORPHAN)
			ls_vertex_del_all(ted, vertex);

	/* Then Edges */
	frr_each_safe (edges, &ted->edges, edge)
		if (edge->status == ORPHAN)
			ls_edge_del_all(ted, edge);

	/* and Subnets */
	frr_each_safe (subnets, &ted->subnets, subnet)
		if (subnet->status == ORPHAN)
			ls_subnet_del_all(ted, subnet);

}

void ls_connect(struct ls_vertex *vertex, struct ls_edge *edge, bool source)
{
	if (vertex == NULL || edge == NULL)
		return;

	if (source) {
		listnode_add_sort_nodup(vertex->outgoing_edges, edge);
		edge->source = vertex;
	} else {
		listnode_add_sort_nodup(vertex->incoming_edges, edge);
		edge->destination = vertex;
	}
}

void ls_disconnect(struct ls_vertex *vertex, struct ls_edge *edge, bool source)
{

	if (vertex == NULL || edge == NULL)
		return;

	if (source) {
		listnode_delete(vertex->outgoing_edges, edge);
		edge->source = NULL;
	} else {
		listnode_delete(vertex->incoming_edges, edge);
		edge->destination = NULL;
	}
}

void ls_connect_vertices(struct ls_vertex *src, struct ls_vertex *dst,
			 struct ls_edge *edge)
{
	if (edge == NULL)
		return;

	edge->source = src;
	edge->destination = dst;

	if (src != NULL)
		listnode_add_sort_nodup(src->outgoing_edges, edge);

	if (dst != NULL)
		listnode_add_sort_nodup(dst->incoming_edges, edge);
}

void ls_disconnect_edge(struct ls_edge *edge)
{
	if (edge == NULL)
		return;

	ls_disconnect(edge->source, edge, true);
	ls_disconnect(edge->destination, edge, false);

	/* Mark this Edge as ORPHAN for future cleanup */
	edge->status = ORPHAN;
}

/**
 * Link State Message management functions
 */

int ls_register(struct zclient *zclient, bool server)
{
	int rc;

	if (server)
		rc = zclient_register_opaque(zclient, LINK_STATE_SYNC);
	else
		rc = zclient_register_opaque(zclient, LINK_STATE_UPDATE);

	return rc;
}

int ls_unregister(struct zclient *zclient, bool server)
{
	int rc;

	if (server)
		rc = zclient_unregister_opaque(zclient, LINK_STATE_SYNC);
	else
		rc = zclient_unregister_opaque(zclient, LINK_STATE_UPDATE);

	return rc;
}

int ls_request_sync(struct zclient *zclient)
{
	/* Check buffer size */
	if (STREAM_SIZE(zclient->obuf)
	    < (ZEBRA_HEADER_SIZE + 3 * sizeof(uint32_t)))
		return -1;

	/* No data with this message */
	return zclient_send_opaque(zclient, LINK_STATE_SYNC, NULL, 0);
}

static struct ls_node *ls_parse_node(struct stream *s)
{
	struct ls_node *node;
	size_t len;

	node = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_node));

	STREAM_GET(&node->adv, s, sizeof(struct ls_node_id));
	STREAM_GETW(s, node->flags);
	if (CHECK_FLAG(node->flags, LS_NODE_NAME)) {
		STREAM_GETC(s, len);
		STREAM_GET(node->name, s, len);
	}
	if (CHECK_FLAG(node->flags, LS_NODE_ROUTER_ID))
		node->router_id.s_addr = stream_get_ipv4(s);
	if (CHECK_FLAG(node->flags, LS_NODE_ROUTER_ID6))
		STREAM_GET(&node->router_id6, s, IPV6_MAX_BYTELEN);
	if (CHECK_FLAG(node->flags, LS_NODE_FLAG))
		STREAM_GETC(s, node->node_flag);
	if (CHECK_FLAG(node->flags, LS_NODE_TYPE))
		STREAM_GETC(s, node->type);
	if (CHECK_FLAG(node->flags, LS_NODE_AS_NUMBER))
		STREAM_GETL(s, node->as_number);
	if (CHECK_FLAG(node->flags, LS_NODE_SR)) {
		STREAM_GETL(s, node->srgb.lower_bound);
		STREAM_GETL(s, node->srgb.range_size);
		STREAM_GETC(s, node->srgb.flag);
		STREAM_GET(node->algo, s, 2);
	}
	if (CHECK_FLAG(node->flags, LS_NODE_SRLB)) {
		STREAM_GETL(s, node->srlb.lower_bound);
		STREAM_GETL(s, node->srlb.range_size);
	}
	if (CHECK_FLAG(node->flags, LS_NODE_MSD))
		STREAM_GETC(s, node->msd);

	return node;

stream_failure:
	zlog_err("LS(%s): Could not parse Link State Node. Abort!", __func__);
	XFREE(MTYPE_LS_DB, node);
	return NULL;
}

static struct ls_attributes *ls_parse_attributes(struct stream *s)
{
	struct ls_attributes *attr;
	uint8_t nb_ext_adm_grp;
	uint32_t bitmap_data;
	size_t len;

	attr = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_attributes));
	admin_group_init(&attr->ext_admin_group);
	attr->srlgs = NULL;

	STREAM_GET(&attr->adv, s, sizeof(struct ls_node_id));
	STREAM_GETL(s, attr->flags);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NAME)) {
		STREAM_GETC(s, len);
		STREAM_GET(attr->name, s, len);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_METRIC))
		STREAM_GETL(s, attr->metric);
	if (CHECK_FLAG(attr->flags, LS_ATTR_TE_METRIC))
		STREAM_GETL(s, attr->standard.te_metric);
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADM_GRP))
		STREAM_GETL(s, attr->standard.admin_group);
	if (CHECK_FLAG(attr->flags, LS_ATTR_EXT_ADM_GRP)) {
		/* Extended Administrative Group */
		STREAM_GETC(s, nb_ext_adm_grp);
		for (size_t i = 0; i < nb_ext_adm_grp; i++) {
			STREAM_GETL(s, bitmap_data);
			admin_group_bulk_set(&attr->ext_admin_group,
					     bitmap_data, i);
		}
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR))
		attr->standard.local.s_addr = stream_get_ipv4(s);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR))
		attr->standard.remote.s_addr = stream_get_ipv4(s);
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR6))
		STREAM_GET(&attr->standard.local6, s, IPV6_MAX_BYTELEN);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR6))
		STREAM_GET(&attr->standard.remote6, s, IPV6_MAX_BYTELEN);
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ID))
		STREAM_GETL(s, attr->standard.local_id);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ID))
		STREAM_GETL(s, attr->standard.remote_id);
	if (CHECK_FLAG(attr->flags, LS_ATTR_MAX_BW))
		STREAM_GETF(s, attr->standard.max_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_MAX_RSV_BW))
		STREAM_GETF(s, attr->standard.max_rsv_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_UNRSV_BW))
		for (len = 0; len < MAX_CLASS_TYPE; len++)
			STREAM_GETF(s, attr->standard.unrsv_bw[len]);
	if (CHECK_FLAG(attr->flags, LS_ATTR_REMOTE_AS))
		STREAM_GETL(s, attr->standard.remote_as);
	if (CHECK_FLAG(attr->flags, LS_ATTR_REMOTE_ADDR))
		attr->standard.remote_addr.s_addr = stream_get_ipv4(s);
	if (CHECK_FLAG(attr->flags, LS_ATTR_REMOTE_ADDR6))
		STREAM_GET(&attr->standard.remote_addr6, s, IPV6_MAX_BYTELEN);
	if (CHECK_FLAG(attr->flags, LS_ATTR_DELAY))
		STREAM_GETL(s, attr->extended.delay);
	if (CHECK_FLAG(attr->flags, LS_ATTR_MIN_MAX_DELAY)) {
		STREAM_GETL(s, attr->extended.min_delay);
		STREAM_GETL(s, attr->extended.max_delay);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_JITTER))
		STREAM_GETL(s, attr->extended.jitter);
	if (CHECK_FLAG(attr->flags, LS_ATTR_PACKET_LOSS))
		STREAM_GETL(s, attr->extended.pkt_loss);
	if (CHECK_FLAG(attr->flags, LS_ATTR_AVA_BW))
		STREAM_GETF(s, attr->extended.ava_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_RSV_BW))
		STREAM_GETF(s, attr->extended.rsv_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_USE_BW))
		STREAM_GETF(s, attr->extended.used_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADJ_SID)) {
		STREAM_GETL(s, attr->adj_sid[ADJ_PRI_IPV4].sid);
		STREAM_GETC(s, attr->adj_sid[ADJ_PRI_IPV4].flags);
		STREAM_GETC(s, attr->adj_sid[ADJ_PRI_IPV4].weight);
		attr->adj_sid[ADJ_PRI_IPV4].neighbor.addr.s_addr =
			stream_get_ipv4(s);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID)) {
		STREAM_GETL(s, attr->adj_sid[ADJ_BCK_IPV4].sid);
		STREAM_GETC(s, attr->adj_sid[ADJ_BCK_IPV4].flags);
		STREAM_GETC(s, attr->adj_sid[ADJ_BCK_IPV4].weight);
		attr->adj_sid[ADJ_BCK_IPV4].neighbor.addr.s_addr =
			stream_get_ipv4(s);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADJ_SID6)) {
		STREAM_GETL(s, attr->adj_sid[ADJ_PRI_IPV6].sid);
		STREAM_GETC(s, attr->adj_sid[ADJ_PRI_IPV6].flags);
		STREAM_GETC(s, attr->adj_sid[ADJ_PRI_IPV6].weight);
		STREAM_GET(attr->adj_sid[ADJ_PRI_IPV6].neighbor.sysid, s,
			   ISO_SYS_ID_LEN);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID6)) {
		STREAM_GETL(s, attr->adj_sid[ADJ_BCK_IPV6].sid);
		STREAM_GETC(s, attr->adj_sid[ADJ_BCK_IPV6].flags);
		STREAM_GETC(s, attr->adj_sid[ADJ_BCK_IPV6].weight);
		STREAM_GET(attr->adj_sid[ADJ_BCK_IPV6].neighbor.sysid, s,
			   ISO_SYS_ID_LEN);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_SRLG)) {
		STREAM_GETC(s, len);
		attr->srlgs = XCALLOC(MTYPE_LS_DB, len*sizeof(uint32_t));
		attr->srlg_len = len;
		for (len = 0; len < attr->srlg_len; len++)
			STREAM_GETL(s, attr->srlgs[len]);
	}

	return attr;

stream_failure:
	zlog_err("LS(%s): Could not parse Link State Attributes. Abort!",
		 __func__);
	/* Clean memory allocation */
	if (attr->srlgs != NULL)
		XFREE(MTYPE_LS_DB, attr->srlgs);
	XFREE(MTYPE_LS_DB, attr);
	return NULL;

}

static struct ls_prefix *ls_parse_prefix(struct stream *s)
{
	struct ls_prefix *ls_pref;
	size_t len;

	ls_pref = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_prefix));

	STREAM_GET(&ls_pref->adv, s, sizeof(struct ls_node_id));
	STREAM_GETW(s, ls_pref->flags);
	STREAM_GETC(s, ls_pref->pref.family);
	STREAM_GETW(s, ls_pref->pref.prefixlen);
	len = prefix_blen(&ls_pref->pref);
	STREAM_GET(&ls_pref->pref.u.prefix, s, len);
	if (CHECK_FLAG(ls_pref->flags, LS_PREF_IGP_FLAG))
		STREAM_GETC(s, ls_pref->igp_flag);
	if (CHECK_FLAG(ls_pref->flags, LS_PREF_ROUTE_TAG))
		STREAM_GETL(s, ls_pref->route_tag);
	if (CHECK_FLAG(ls_pref->flags, LS_PREF_EXTENDED_TAG))
		STREAM_GETQ(s, ls_pref->extended_tag);
	if (CHECK_FLAG(ls_pref->flags, LS_PREF_METRIC))
		STREAM_GETL(s, ls_pref->metric);
	if (CHECK_FLAG(ls_pref->flags, LS_PREF_SR)) {
		STREAM_GETL(s, ls_pref->sr.sid);
		STREAM_GETC(s, ls_pref->sr.sid_flag);
		STREAM_GETC(s, ls_pref->sr.algo);
	}

	return ls_pref;

stream_failure:
	zlog_err("LS(%s): Could not parse Link State Prefix. Abort!", __func__);
	XFREE(MTYPE_LS_DB, ls_pref);
	return NULL;
}

struct ls_message *ls_parse_msg(struct stream *s)
{
	struct ls_message *msg;

	msg = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_message));

	/* Read LS Message header */
	STREAM_GETC(s, msg->event);
	STREAM_GETC(s, msg->type);

	/* Read Message Payload */
	switch (msg->type) {
	case LS_MSG_TYPE_NODE:
		msg->data.node = ls_parse_node(s);
		break;
	case LS_MSG_TYPE_ATTRIBUTES:
		STREAM_GET(&msg->remote_id, s, sizeof(struct ls_node_id));
		msg->data.attr = ls_parse_attributes(s);
		break;
	case LS_MSG_TYPE_PREFIX:
		msg->data.prefix = ls_parse_prefix(s);
		break;
	default:
		zlog_err("Unsupported Payload");
		goto stream_failure;
	}

	if (msg->data.node == NULL || msg->data.attr == NULL
	    || msg->data.prefix == NULL)
		goto stream_failure;

	return msg;

stream_failure:
	zlog_err("LS(%s): Could not parse LS message. Abort!", __func__);
	XFREE(MTYPE_LS_DB, msg);
	return NULL;
}

static int ls_format_node(struct stream *s, struct ls_node *node)
{
	size_t len;

	/* Push Advertise node information first */
	stream_put(s, &node->adv, sizeof(struct ls_node_id));

	/* Push Flags & Origin then Node information if there are present */
	stream_putw(s, node->flags);
	if (CHECK_FLAG(node->flags, LS_NODE_NAME)) {
		len = strlen(node->name);
		stream_putc(s, len + 1);
		stream_put(s, node->name, len);
		stream_putc(s, '\0');
	}
	if (CHECK_FLAG(node->flags, LS_NODE_ROUTER_ID))
		stream_put_ipv4(s, node->router_id.s_addr);
	if (CHECK_FLAG(node->flags, LS_NODE_ROUTER_ID6))
		stream_put(s, &node->router_id6, IPV6_MAX_BYTELEN);
	if (CHECK_FLAG(node->flags, LS_NODE_FLAG))
		stream_putc(s, node->node_flag);
	if (CHECK_FLAG(node->flags, LS_NODE_TYPE))
		stream_putc(s, node->type);
	if (CHECK_FLAG(node->flags, LS_NODE_AS_NUMBER))
		stream_putl(s, node->as_number);
	if (CHECK_FLAG(node->flags, LS_NODE_SR)) {
		stream_putl(s, node->srgb.lower_bound);
		stream_putl(s, node->srgb.range_size);
		stream_putc(s, node->srgb.flag);
		stream_put(s, node->algo, 2);
	}
	if (CHECK_FLAG(node->flags, LS_NODE_SRLB)) {
		stream_putl(s, node->srlb.lower_bound);
		stream_putl(s, node->srlb.range_size);
	}
	if (CHECK_FLAG(node->flags, LS_NODE_MSD))
		stream_putc(s, node->msd);

	return 0;
}

static int ls_format_attributes(struct stream *s, struct ls_attributes *attr)
{
	size_t len, nb_ext_adm_grp;

	/* Push Advertise node information first */
	stream_put(s, &attr->adv, sizeof(struct ls_node_id));

	/* Push Flags & Origin then LS attributes if there are present */
	stream_putl(s, attr->flags);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NAME)) {
		len = strlen(attr->name);
		stream_putc(s, len + 1);
		stream_put(s, attr->name, len);
		stream_putc(s, '\0');
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_METRIC))
		stream_putl(s, attr->metric);
	if (CHECK_FLAG(attr->flags, LS_ATTR_TE_METRIC))
		stream_putl(s, attr->standard.te_metric);
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADM_GRP))
		stream_putl(s, attr->standard.admin_group);
	if (CHECK_FLAG(attr->flags, LS_ATTR_EXT_ADM_GRP)) {
		/* Extended Administrative Group */
		nb_ext_adm_grp = admin_group_nb_words(&attr->ext_admin_group);
		stream_putc(s, nb_ext_adm_grp);
		for (size_t i = 0; i < nb_ext_adm_grp; i++)
			stream_putl(s, admin_group_get_offset(
					       &attr->ext_admin_group, i));
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR))
		stream_put_ipv4(s, attr->standard.local.s_addr);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR))
		stream_put_ipv4(s, attr->standard.remote.s_addr);
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR6))
		stream_put(s, &attr->standard.local6, IPV6_MAX_BYTELEN);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR6))
		stream_put(s, &attr->standard.remote6, IPV6_MAX_BYTELEN);
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ID))
		stream_putl(s, attr->standard.local_id);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ID))
		stream_putl(s, attr->standard.remote_id);
	if (CHECK_FLAG(attr->flags, LS_ATTR_MAX_BW))
		stream_putf(s, attr->standard.max_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_MAX_RSV_BW))
		stream_putf(s, attr->standard.max_rsv_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_UNRSV_BW))
		for (len = 0; len < MAX_CLASS_TYPE; len++)
			stream_putf(s, attr->standard.unrsv_bw[len]);
	if (CHECK_FLAG(attr->flags, LS_ATTR_REMOTE_AS))
		stream_putl(s, attr->standard.remote_as);
	if (CHECK_FLAG(attr->flags, LS_ATTR_REMOTE_ADDR))
		stream_put_ipv4(s, attr->standard.remote_addr.s_addr);
	if (CHECK_FLAG(attr->flags, LS_ATTR_REMOTE_ADDR6))
		stream_put(s, &attr->standard.remote_addr6, IPV6_MAX_BYTELEN);
	if (CHECK_FLAG(attr->flags, LS_ATTR_DELAY))
		stream_putl(s, attr->extended.delay);
	if (CHECK_FLAG(attr->flags, LS_ATTR_MIN_MAX_DELAY)) {
		stream_putl(s, attr->extended.min_delay);
		stream_putl(s, attr->extended.max_delay);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_JITTER))
		stream_putl(s, attr->extended.jitter);
	if (CHECK_FLAG(attr->flags, LS_ATTR_PACKET_LOSS))
		stream_putl(s, attr->extended.pkt_loss);
	if (CHECK_FLAG(attr->flags, LS_ATTR_AVA_BW))
		stream_putf(s, attr->extended.ava_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_RSV_BW))
		stream_putf(s, attr->extended.rsv_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_USE_BW))
		stream_putf(s, attr->extended.used_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADJ_SID)) {
		stream_putl(s, attr->adj_sid[ADJ_PRI_IPV4].sid);
		stream_putc(s, attr->adj_sid[ADJ_PRI_IPV4].flags);
		stream_putc(s, attr->adj_sid[ADJ_PRI_IPV4].weight);
		stream_put_ipv4(
			s, attr->adj_sid[ADJ_PRI_IPV4].neighbor.addr.s_addr);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID)) {
		stream_putl(s, attr->adj_sid[ADJ_BCK_IPV4].sid);
		stream_putc(s, attr->adj_sid[ADJ_BCK_IPV4].flags);
		stream_putc(s, attr->adj_sid[ADJ_BCK_IPV4].weight);
		stream_put_ipv4(
			s, attr->adj_sid[ADJ_BCK_IPV4].neighbor.addr.s_addr);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADJ_SID6)) {
		stream_putl(s, attr->adj_sid[ADJ_PRI_IPV6].sid);
		stream_putc(s, attr->adj_sid[ADJ_PRI_IPV6].flags);
		stream_putc(s, attr->adj_sid[ADJ_PRI_IPV6].weight);
		stream_put(s, attr->adj_sid[ADJ_PRI_IPV6].neighbor.sysid,
			   ISO_SYS_ID_LEN);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID6)) {
		stream_putl(s, attr->adj_sid[ADJ_BCK_IPV6].sid);
		stream_putc(s, attr->adj_sid[ADJ_BCK_IPV6].flags);
		stream_putc(s, attr->adj_sid[ADJ_BCK_IPV6].weight);
		stream_put(s, attr->adj_sid[ADJ_BCK_IPV6].neighbor.sysid,
			   ISO_SYS_ID_LEN);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_SRLG)) {
		stream_putc(s, attr->srlg_len);
		for (len = 0; len < attr->srlg_len; len++)
			stream_putl(s, attr->srlgs[len]);
	}

	return 0;
}

static int ls_format_prefix(struct stream *s, struct ls_prefix *ls_pref)
{
	size_t len;

	/* Push Advertise node information first */
	stream_put(s, &ls_pref->adv, sizeof(struct ls_node_id));

	/* Push Flags, Origin & Prefix then information if there are present */
	stream_putw(s, ls_pref->flags);
	stream_putc(s, ls_pref->pref.family);
	stream_putw(s, ls_pref->pref.prefixlen);
	len = prefix_blen(&ls_pref->pref);
	stream_put(s, &ls_pref->pref.u.prefix, len);
	if (CHECK_FLAG(ls_pref->flags, LS_PREF_IGP_FLAG))
		stream_putc(s, ls_pref->igp_flag);
	if (CHECK_FLAG(ls_pref->flags, LS_PREF_ROUTE_TAG))
		stream_putl(s, ls_pref->route_tag);
	if (CHECK_FLAG(ls_pref->flags, LS_PREF_EXTENDED_TAG))
		stream_putq(s, ls_pref->extended_tag);
	if (CHECK_FLAG(ls_pref->flags, LS_PREF_METRIC))
		stream_putl(s, ls_pref->metric);
	if (CHECK_FLAG(ls_pref->flags, LS_PREF_SR)) {
		stream_putl(s, ls_pref->sr.sid);
		stream_putc(s, ls_pref->sr.sid_flag);
		stream_putc(s, ls_pref->sr.algo);
	}

	return 0;
}

static int ls_format_msg(struct stream *s, struct ls_message *msg)
{

	/* Prepare Link State header */
	stream_putc(s, msg->event);
	stream_putc(s, msg->type);

	/* Add Message Payload */
	switch (msg->type) {
	case LS_MSG_TYPE_NODE:
		return ls_format_node(s, msg->data.node);
	case LS_MSG_TYPE_ATTRIBUTES:
		/* Add remote node first */
		stream_put(s, &msg->remote_id, sizeof(struct ls_node_id));
		return ls_format_attributes(s, msg->data.attr);
	case LS_MSG_TYPE_PREFIX:
		return ls_format_prefix(s, msg->data.prefix);
	default:
		zlog_warn("Unsupported Payload");
		break;
	}

	return -1;
}

int ls_send_msg(struct zclient *zclient, struct ls_message *msg,
		struct zapi_opaque_reg_info *dst)
{
	struct stream *s;
	uint16_t flags = 0;

	/* Check if we have a valid message */
	if (msg->event == LS_MSG_EVENT_UNDEF)
		return -1;

	/* Check buffer size */
	if (STREAM_SIZE(zclient->obuf) <
	    (ZEBRA_HEADER_SIZE + sizeof(uint32_t) + sizeof(msg)))
		return -1;

	/* Init the message, then encode the data inline. */
	if (dst == NULL)
		zapi_opaque_init(zclient, LINK_STATE_UPDATE, flags);
	else
		zapi_opaque_unicast_init(zclient, LINK_STATE_UPDATE, flags,
					 dst->proto, dst->instance,
					 dst->session_id);

	s = zclient->obuf;

	/* Format Link State message */
	if (ls_format_msg(s, msg) < 0) {
		stream_reset(s);
		return -1;
	}

	/* Put length into the header at the start of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}
struct ls_message *ls_vertex2msg(struct ls_message *msg,
				 struct ls_vertex *vertex)
{
	/* Allocate space if needed */
	if (msg == NULL)
		msg = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_message));
	else
		memset(msg, 0, sizeof(*msg));

	msg->type = LS_MSG_TYPE_NODE;
	switch (vertex->status) {
	case NEW:
		msg->event = LS_MSG_EVENT_ADD;
		break;
	case UPDATE:
		msg->event = LS_MSG_EVENT_UPDATE;
		break;
	case DELETE:
		msg->event = LS_MSG_EVENT_DELETE;
		break;
	case SYNC:
		msg->event = LS_MSG_EVENT_SYNC;
		break;
	case UNSET:
	case ORPHAN:
		msg->event = LS_MSG_EVENT_UNDEF;
		break;
	}
	msg->data.node = vertex->node;
	msg->remote_id.origin = UNKNOWN;

	return msg;
}

struct ls_message *ls_edge2msg(struct ls_message *msg, struct ls_edge *edge)
{
	/* Allocate space if needed */
	if (msg == NULL)
		msg = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_message));
	else
		memset(msg, 0, sizeof(*msg));

	msg->type = LS_MSG_TYPE_ATTRIBUTES;
	switch (edge->status) {
	case NEW:
		msg->event = LS_MSG_EVENT_ADD;
		break;
	case UPDATE:
		msg->event = LS_MSG_EVENT_UPDATE;
		break;
	case DELETE:
		msg->event = LS_MSG_EVENT_DELETE;
		break;
	case SYNC:
		msg->event = LS_MSG_EVENT_SYNC;
		break;
	case UNSET:
	case ORPHAN:
		msg->event = LS_MSG_EVENT_UNDEF;
		break;
	}
	msg->data.attr = edge->attributes;
	if (edge->destination != NULL)
		msg->remote_id = edge->destination->node->adv;
	else
		msg->remote_id.origin = UNKNOWN;

	return msg;
}

struct ls_message *ls_subnet2msg(struct ls_message *msg,
				 struct ls_subnet *subnet)
{
	/* Allocate space if needed */
	if (msg == NULL)
		msg = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_message));
	else
		memset(msg, 0, sizeof(*msg));

	msg->type = LS_MSG_TYPE_PREFIX;
	switch (subnet->status) {
	case NEW:
		msg->event = LS_MSG_EVENT_ADD;
		break;
	case UPDATE:
		msg->event = LS_MSG_EVENT_UPDATE;
		break;
	case DELETE:
		msg->event = LS_MSG_EVENT_DELETE;
		break;
	case SYNC:
		msg->event = LS_MSG_EVENT_SYNC;
		break;
	case UNSET:
	case ORPHAN:
		msg->event = LS_MSG_EVENT_UNDEF;
		break;
	}
	msg->data.prefix = subnet->ls_pref;
	msg->remote_id.origin = UNKNOWN;

	return msg;
}

struct ls_vertex *ls_msg2vertex(struct ls_ted *ted, struct ls_message *msg,
				bool delete)
{
	struct ls_node *node = msg->data.node;
	struct ls_vertex *vertex = NULL;

	switch (msg->event) {
	case LS_MSG_EVENT_SYNC:
		vertex = ls_vertex_add(ted, node);
		if (vertex)
			vertex->status = SYNC;
		break;
	case LS_MSG_EVENT_ADD:
		vertex = ls_vertex_add(ted, node);
		if (vertex)
			vertex->status = NEW;
		break;
	case LS_MSG_EVENT_UPDATE:
		vertex = ls_vertex_update(ted, node);
		if (vertex)
			vertex->status = UPDATE;
		break;
	case LS_MSG_EVENT_DELETE:
		vertex = ls_find_vertex_by_id(ted, node->adv);
		if (vertex) {
			if (delete) {
				ls_vertex_del_all(ted, vertex);
				vertex = NULL;
			} else
				vertex->status = DELETE;
		}
		break;
	default:
		vertex = NULL;
		break;
	}

	return vertex;
}

struct ls_edge *ls_msg2edge(struct ls_ted *ted, struct ls_message *msg,
			    bool delete)
{
	struct ls_attributes *attr = msg->data.attr;
	struct ls_edge *edge = NULL;

	switch (msg->event) {
	case LS_MSG_EVENT_SYNC:
		edge = ls_edge_add(ted, attr);
		if (edge)
			edge->status = SYNC;
		break;
	case LS_MSG_EVENT_ADD:
		edge = ls_edge_add(ted, attr);
		if (edge)
			edge->status = NEW;
		break;
	case LS_MSG_EVENT_UPDATE:
		edge = ls_edge_update(ted, attr);
		if (edge)
			edge->status = UPDATE;
		break;
	case LS_MSG_EVENT_DELETE:
		edge = ls_find_edge_by_source(ted, attr);
		if (edge) {
			if (delete) {
				ls_edge_del_all(ted, edge);
				edge = NULL;
			} else
				edge->status = DELETE;
		}
		break;
	default:
		edge = NULL;
		break;
	}

	return edge;
}

struct ls_subnet *ls_msg2subnet(struct ls_ted *ted, struct ls_message *msg,
				bool delete)
{
	struct ls_prefix *pref = msg->data.prefix;
	struct ls_subnet *subnet = NULL;

	switch (msg->event) {
	case LS_MSG_EVENT_SYNC:
		subnet = ls_subnet_add(ted, pref);
		if (subnet)
			subnet->status = SYNC;
		break;
	case LS_MSG_EVENT_ADD:
		subnet = ls_subnet_add(ted, pref);
		if (subnet)
			subnet->status = NEW;
		break;
	case LS_MSG_EVENT_UPDATE:
		subnet = ls_subnet_update(ted, pref);
		if (subnet)
			subnet->status = UPDATE;
		break;
	case LS_MSG_EVENT_DELETE:
		subnet = ls_find_subnet(ted, &pref->pref);
		if (subnet) {
			if (delete) {
				ls_subnet_del_all(ted, subnet);
				subnet = NULL;
			} else
				subnet->status = DELETE;
		}
		break;
	default:
		subnet = NULL;
		break;
	}

	return subnet;
}

struct ls_element *ls_msg2ted(struct ls_ted *ted, struct ls_message *msg,
			       bool delete)
{
	struct ls_element *lse = NULL;

	switch (msg->type) {
	case LS_MSG_TYPE_NODE:
		lse = (struct ls_element *)ls_msg2vertex(ted, msg, delete);
		break;
	case LS_MSG_TYPE_ATTRIBUTES:
		lse = (struct ls_element *)ls_msg2edge(ted, msg, delete);
		break;
	case LS_MSG_TYPE_PREFIX:
		lse = (struct ls_element *)ls_msg2subnet(ted, msg, delete);
		break;
	default:
		lse = NULL;
		break;
	}

	return lse;
}

struct ls_element *ls_stream2ted(struct ls_ted *ted, struct stream *s,
				  bool delete)
{
	struct ls_message *msg;
	struct ls_element *lse = NULL;

	msg = ls_parse_msg(s);
	if (msg) {
		lse = ls_msg2ted(ted, msg, delete);
		ls_delete_msg(msg);
	}

	return lse;
}

void ls_delete_msg(struct ls_message *msg)
{
	if (msg == NULL)
		return;

	if (msg->event == LS_MSG_EVENT_DELETE) {
		switch (msg->type) {
		case LS_MSG_TYPE_NODE:
			ls_node_del(msg->data.node);
			break;
		case LS_MSG_TYPE_ATTRIBUTES:
			ls_attributes_del(msg->data.attr);
			break;
		case LS_MSG_TYPE_PREFIX:
			ls_prefix_del(msg->data.prefix);
			break;
		}
	}

	XFREE(MTYPE_LS_DB, msg);
}

int ls_sync_ted(struct ls_ted *ted, struct zclient *zclient,
		struct zapi_opaque_reg_info *dst)
{
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct ls_subnet *subnet;
	struct ls_message msg;

	/* Loop TED, start sending Node, then Attributes and finally Prefix */
	frr_each(vertices, &ted->vertices, vertex) {
		ls_vertex2msg(&msg, vertex);
		ls_send_msg(zclient, &msg, dst);
	}
	frr_each(edges, &ted->edges, edge) {
		ls_edge2msg(&msg, edge);
		ls_send_msg(zclient, &msg, dst);
	}
	frr_each(subnets, &ted->subnets, subnet) {
		ls_subnet2msg(&msg, subnet);
		ls_send_msg(zclient, &msg, dst);
	}
	return 0;
}

/**
 *  Link State Show functions
 */
static const char *const origin2txt[] = {
	"Unknown",
	"ISIS_L1",
	"ISIS_L2",
	"OSPFv2",
	"Direct",
	"Static"
};

static const char *const type2txt[] = {
	"Unknown",
	"Standard",
	"ABR",
	"ASBR",
	"Remote ASBR",
	"Pseudo"
};

static const char *const status2txt[] = {
	"Unknown",
	"New",
	"Update",
	"Delete",
	"Sync",
	"Orphan"
};

static const char *ls_node_id_to_text(struct ls_node_id lnid, char *str,
				      size_t size)
{
	if (lnid.origin == ISIS_L1 || lnid.origin == ISIS_L2)
		snprintfrr(str, size, "%pSY", lnid.id.iso.sys_id);
	else
		snprintfrr(str, size, "%pI4", &lnid.id.ip.addr);

	return str;
}

static void ls_show_vertex_vty(struct ls_vertex *vertex, struct vty *vty,
			       bool verbose)
{
	struct listnode *node;
	struct ls_node *lsn;
	struct ls_edge *edge;
	struct ls_attributes *attr;
	struct ls_subnet *subnet;
	struct sbuf sbuf;
	uint32_t upper;

	/* Sanity Check */
	if (!vertex)
		return;

	lsn = vertex->node;

	sbuf_init(&sbuf, NULL, 0);

	sbuf_push(&sbuf, 2, "Vertex (%" PRIu64 "): %s", vertex->key, lsn->name);
	sbuf_push(&sbuf, 0, "\tRouter Id: %pI4", &lsn->router_id);
	sbuf_push(&sbuf, 0, "\tOrigin: %s", origin2txt[lsn->adv.origin]);
	sbuf_push(&sbuf, 0, "\tStatus: %s\n", status2txt[vertex->status]);
	if (!verbose) {
		sbuf_push(
			&sbuf, 0,
			"\t%d Outgoing Edges, %d Incoming Edges, %d Subnets\n",
			listcount(vertex->outgoing_edges),
			listcount(vertex->incoming_edges),
			listcount(vertex->prefixes));
		goto end;
	}

	if (CHECK_FLAG(lsn->flags, LS_NODE_TYPE))
		sbuf_push(&sbuf, 4, "Type: %s\n", type2txt[lsn->type]);
	if (CHECK_FLAG(lsn->flags, LS_NODE_AS_NUMBER))
		sbuf_push(&sbuf, 4, "AS number: %u\n", lsn->as_number);
	if (CHECK_FLAG(lsn->flags, LS_NODE_SR)) {
		sbuf_push(&sbuf, 4, "Segment Routing Capabilities:\n");
		upper = lsn->srgb.lower_bound + lsn->srgb.range_size - 1;
		sbuf_push(&sbuf, 8, "SRGB: [%d/%d]", lsn->srgb.lower_bound,
			  upper);
		if (CHECK_FLAG(lsn->flags, LS_NODE_SRLB)) {
			upper = lsn->srlb.lower_bound + lsn->srlb.range_size
				- 1;
			sbuf_push(&sbuf, 0, "\tSRLB: [%d/%d]",
				  lsn->srlb.lower_bound, upper);
		}
		sbuf_push(&sbuf, 0, "\tAlgo: ");
		for (int i = 0; i < 2; i++) {
			if (lsn->algo[i] == 255)
				continue;

			sbuf_push(&sbuf, 0,
				  lsn->algo[i] == 0 ? "SPF " : "S-SPF ");
		}
		if (CHECK_FLAG(lsn->flags, LS_NODE_MSD))
			sbuf_push(&sbuf, 0, "\tMSD: %d", lsn->msd);
		sbuf_push(&sbuf, 0, "\n");
	}

	sbuf_push(&sbuf, 4, "Outgoing Edges: %d\n",
		  listcount(vertex->outgoing_edges));
	for (ALL_LIST_ELEMENTS_RO(vertex->outgoing_edges, node, edge)) {
		if (edge->destination) {
			lsn = edge->destination->node;
			sbuf_push(&sbuf, 6, "To:\t%s(%pI4)", lsn->name,
				  &lsn->router_id);
		} else {
			sbuf_push(&sbuf, 6, "To:\t- (0.0.0.0)");
		}
		attr = edge->attributes;
		if ((CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR)))
			sbuf_push(&sbuf, 0, "\tLocal:  %pI4\tRemote: %pI4\n",
				  &attr->standard.local,
				  &attr->standard.remote);
		else if ((CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR6)))
			sbuf_push(&sbuf, 0, "\tLocal:  %pI6\tRemote: %pI6\n",
				  &attr->standard.local6,
				  &attr->standard.remote6);
	}

	sbuf_push(&sbuf, 4, "Incoming Edges: %d\n",
		  listcount(vertex->incoming_edges));
	for (ALL_LIST_ELEMENTS_RO(vertex->incoming_edges, node, edge)) {
		if (edge->source) {
			lsn = edge->source->node;
			sbuf_push(&sbuf, 6, "From:\t%s(%pI4)", lsn->name,
				  &lsn->router_id);
		} else {
			sbuf_push(&sbuf, 6, "From:\t- (0.0.0.0)");
		}
		attr = edge->attributes;
		if ((CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR)))
			sbuf_push(&sbuf, 0, "\tLocal:  %pI4\tRemote: %pI4\n",
				  &attr->standard.local,
				  &attr->standard.remote);
		else if ((CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR6)))
			sbuf_push(&sbuf, 0, "\tLocal:  %pI6\tRemote: %pI6\n",
				  &attr->standard.local6,
				  &attr->standard.remote6);
	}

	sbuf_push(&sbuf, 4, "Subnets: %d\n", listcount(vertex->prefixes));
	for (ALL_LIST_ELEMENTS_RO(vertex->prefixes, node, subnet))
		sbuf_push(&sbuf, 6, "Prefix:\t%pFX\n", &subnet->key);

end:
	vty_out(vty, "%s\n", sbuf_buf(&sbuf));
	sbuf_free(&sbuf);
}

static void ls_show_vertex_json(struct ls_vertex *vertex,
				struct json_object *json)
{
	struct ls_node *lsn;
	json_object *jsr, *jalgo, *jobj;
	char buf[INET6_BUFSIZ];

	/* Sanity Check */
	if (!vertex)
		return;

	lsn = vertex->node;

	json_object_int_add(json, "vertex-id", vertex->key);
	json_object_string_add(json, "status", status2txt[vertex->status]);
	json_object_string_add(json, "origin", origin2txt[lsn->adv.origin]);
	if (CHECK_FLAG(lsn->flags, LS_NODE_NAME))
		json_object_string_add(json, "name", lsn->name);
	if (CHECK_FLAG(lsn->flags, LS_NODE_ROUTER_ID)) {
		snprintfrr(buf, INET6_BUFSIZ, "%pI4", &lsn->router_id);
		json_object_string_add(json, "router-id", buf);
	}
	if (CHECK_FLAG(lsn->flags, LS_NODE_ROUTER_ID6)) {
		snprintfrr(buf, INET6_BUFSIZ, "%pI6", &lsn->router_id6);
		json_object_string_add(json, "router-id-v6", buf);
	}
	if (CHECK_FLAG(lsn->flags, LS_NODE_TYPE))
		json_object_string_add(json, "vertex-type",
				       type2txt[lsn->type]);
	if (CHECK_FLAG(lsn->flags, LS_NODE_AS_NUMBER))
		json_object_int_add(json, "asn", lsn->as_number);
	if (CHECK_FLAG(lsn->flags, LS_NODE_SR)) {
		jsr = json_object_new_object();
		json_object_object_add(json, "segment-routing", jsr);
		json_object_int_add(jsr, "srgb-size", lsn->srgb.range_size);
		json_object_int_add(jsr, "srgb-lower", lsn->srgb.lower_bound);
		jalgo = json_object_new_array();
		json_object_object_add(jsr, "algorithms", jalgo);
		for (int i = 0; i < 2; i++) {
			if (lsn->algo[i] == 255)
				continue;
			jobj = json_object_new_object();

			snprintfrr(buf, 2, "%u", i);
			json_object_string_add(
				jobj, buf, lsn->algo[i] == 0 ? "SPF" : "S-SPF");
			json_object_array_add(jalgo, jobj);
		}
		if (CHECK_FLAG(lsn->flags, LS_NODE_SRLB)) {
			json_object_int_add(jsr, "srlb-size",
					    lsn->srlb.range_size);
			json_object_int_add(jsr, "srlb-lower",
					    lsn->srlb.lower_bound);
		}
		if (CHECK_FLAG(lsn->flags, LS_NODE_MSD))
			json_object_int_add(jsr, "msd", lsn->msd);
	}
}

void ls_show_vertex(struct ls_vertex *vertex, struct vty *vty,
		    struct json_object *json, bool verbose)
{
	if (json)
		ls_show_vertex_json(vertex, json);
	else if (vty)
		ls_show_vertex_vty(vertex, vty, verbose);
}

void ls_show_vertices(struct ls_ted *ted, struct vty *vty,
		      struct json_object *json, bool verbose)
{
	struct ls_vertex *vertex;
	json_object *jnodes, *jnode;

	if (json) {
		jnodes = json_object_new_array();
		json_object_object_add(json, "vertices", jnodes);
		frr_each (vertices, &ted->vertices, vertex) {
			jnode = json_object_new_object();
			ls_show_vertex(vertex, NULL, jnode, verbose);
			json_object_array_add(jnodes, jnode);
		}
	} else if (vty) {
		frr_each (vertices, &ted->vertices, vertex)
			ls_show_vertex(vertex, vty, NULL, verbose);
	}
}

static const char *edge_key_to_text(struct ls_edge_key key)
{
#define FORMAT_BUF_COUNT 4
	static char buf_ring[FORMAT_BUF_COUNT][INET6_BUFSIZ];
	static size_t cur_buf = 0;
	char *rv;

	rv = buf_ring[cur_buf];
	cur_buf = (cur_buf + 1) % FORMAT_BUF_COUNT;

	switch (key.family) {
	case AF_INET:
		snprintfrr(rv, INET6_BUFSIZ, "%pI4", &key.k.addr);
		break;
	case AF_INET6:
		snprintfrr(rv, INET6_BUFSIZ, "%pI6", &key.k.addr6);
		break;
	case AF_LOCAL:
		snprintfrr(rv, INET6_BUFSIZ, "%" PRIu64, key.k.link_id);
		break;
	default:
		snprintfrr(rv, INET6_BUFSIZ, "(Unknown)");
		break;
	}

	return rv;
}

static void ls_show_edge_vty(struct ls_edge *edge, struct vty *vty,
			     bool verbose)
{
	char admin_group_buf[ADMIN_GROUP_PRINT_MAX_SIZE];
	struct ls_attributes *attr;
	struct sbuf sbuf;
	char buf[INET6_BUFSIZ];
	int indent;

	attr = edge->attributes;
	sbuf_init(&sbuf, NULL, 0);

	sbuf_push(&sbuf, 2, "Edge (%s): ", edge_key_to_text(edge->key));
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR))
		sbuf_push(&sbuf, 0, "%pI4", &attr->standard.local);
	else if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR6))
		sbuf_push(&sbuf, 0, "%pI6", &attr->standard.local6);
	else
		sbuf_push(&sbuf, 0, "%u/%u", attr->standard.local_id,
			  attr->standard.remote_id);
	ls_node_id_to_text(attr->adv, buf, INET6_BUFSIZ);
	sbuf_push(&sbuf, 0, "\tAdv. Vertex: %s", buf);
	sbuf_push(&sbuf, 0, "\tMetric: %u", attr->metric);
	sbuf_push(&sbuf, 0, "\tStatus: %s\n", status2txt[edge->status]);

	if (!verbose)
		goto end;

	sbuf_push(&sbuf, 4, "Origin: %s\n", origin2txt[attr->adv.origin]);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NAME))
		sbuf_push(&sbuf, 4, "Name: %s\n", attr->name);
	if (CHECK_FLAG(attr->flags, LS_ATTR_TE_METRIC))
		sbuf_push(&sbuf, 4, "TE Metric: %u\n",
			  attr->standard.te_metric);
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADM_GRP))
		sbuf_push(&sbuf, 4, "Admin Group: 0x%x\n",
			  attr->standard.admin_group);
	if (CHECK_FLAG(attr->flags, LS_ATTR_EXT_ADM_GRP) &&
	    admin_group_nb_words(&attr->ext_admin_group) != 0) {
		indent = 4;
		sbuf_push(&sbuf, indent, "Ext Admin Group: %s\n",
			  admin_group_string(
				  admin_group_buf, ADMIN_GROUP_PRINT_MAX_SIZE,
				  indent + strlen("Ext Admin Group: "),
				  &attr->ext_admin_group));
		if (admin_group_buf[0] != '\0' &&
		    (sbuf.pos + strlen(admin_group_buf) +
		     SBUF_DEFAULT_SIZE / 2) < sbuf.size)
			sbuf_push(&sbuf, indent + 2, "Bit positions: %s\n",
				  admin_group_buf);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR))
		sbuf_push(&sbuf, 4, "Local IPv4 address: %pI4\n",
			  &attr->standard.local);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR))
		sbuf_push(&sbuf, 4, "Remote IPv4 address: %pI4\n",
			  &attr->standard.remote);
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR6))
		sbuf_push(&sbuf, 4, "Local IPv6 address: %pI6\n",
			  &attr->standard.local6);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR6))
		sbuf_push(&sbuf, 4, "Remote IPv6 address: %pI6\n",
			  &attr->standard.remote6);
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ID))
		sbuf_push(&sbuf, 4, "Local Identifier: %u\n",
			  attr->standard.local_id);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ID))
		sbuf_push(&sbuf, 4, "Remote Identifier: %u\n",
			  attr->standard.remote_id);
	if (CHECK_FLAG(attr->flags, LS_ATTR_MAX_BW))
		sbuf_push(&sbuf, 4, "Maximum Bandwidth: %g (Bytes/s)\n",
			  attr->standard.max_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_MAX_RSV_BW))
		sbuf_push(&sbuf, 4,
			  "Maximum Reservable Bandwidth: %g (Bytes/s)\n",
			  attr->standard.max_rsv_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_UNRSV_BW)) {
		sbuf_push(&sbuf, 4, "Unreserved Bandwidth per Class Type\n");
		for (int i = 0; i < MAX_CLASS_TYPE; i += 2)
			sbuf_push(&sbuf, 8,
				  "[%d]: %g (Bytes/sec)\t[%d]: %g (Bytes/s)\n",
				  i, attr->standard.unrsv_bw[i], i + 1,
				  attr->standard.unrsv_bw[i + 1]);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_REMOTE_AS))
		sbuf_push(&sbuf, 4, "Remote AS: %u\n",
			  attr->standard.remote_as);
	if (CHECK_FLAG(attr->flags, LS_ATTR_REMOTE_ADDR))
		sbuf_push(&sbuf, 4, "Remote ASBR IPv4 address: %pI4\n",
			  &attr->standard.remote_addr);
	if (CHECK_FLAG(attr->flags, LS_ATTR_REMOTE_ADDR6))
		sbuf_push(&sbuf, 4, "Remote ASBR IPv6 address: %pI6\n",
			  &attr->standard.remote_addr6);
	if (CHECK_FLAG(attr->flags, LS_ATTR_DELAY))
		sbuf_push(&sbuf, 4, "Average Link Delay: %d (micro-sec)\n",
			  attr->extended.delay);
	if (CHECK_FLAG(attr->flags, LS_ATTR_MIN_MAX_DELAY))
		sbuf_push(&sbuf, 4, "Min/Max Link Delay: %d/%d (micro-sec)\n",
			  attr->extended.min_delay, attr->extended.max_delay);
	if (CHECK_FLAG(attr->flags, LS_ATTR_JITTER))
		sbuf_push(&sbuf, 4, "Delay Variation: %d (micro-sec)\n",
			  attr->extended.jitter);
	if (CHECK_FLAG(attr->flags, LS_ATTR_PACKET_LOSS))
		sbuf_push(&sbuf, 4, "Link Loss: %g (%%)\n",
			  (float)(attr->extended.pkt_loss * LOSS_PRECISION));
	if (CHECK_FLAG(attr->flags, LS_ATTR_AVA_BW))
		sbuf_push(&sbuf, 4, "Available Bandwidth: %g (Bytes/s)\n",
			  attr->extended.ava_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_RSV_BW))
		sbuf_push(&sbuf, 4, "Residual Bandwidth: %g (Bytes/s)\n",
			  attr->extended.rsv_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_USE_BW))
		sbuf_push(&sbuf, 4, "Utilized Bandwidth: %g (Bytes/s)\n",
			  attr->extended.used_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADJ_SID)) {
		sbuf_push(&sbuf, 4, "IPv4 Adjacency-SID: %u",
			  attr->adj_sid[ADJ_PRI_IPV4].sid);
		sbuf_push(&sbuf, 0, "\tFlags: 0x%x\tWeight: 0x%x\n",
			  attr->adj_sid[ADJ_PRI_IPV4].flags,
			  attr->adj_sid[ADJ_PRI_IPV4].weight);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID)) {
		sbuf_push(&sbuf, 4, "IPv4 Bck. Adjacency-SID: %u",
			  attr->adj_sid[ADJ_BCK_IPV4].sid);
		sbuf_push(&sbuf, 0, "\tFlags: 0x%x\tWeight: 0x%x\n",
			  attr->adj_sid[ADJ_BCK_IPV4].flags,
			  attr->adj_sid[ADJ_BCK_IPV4].weight);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADJ_SID6)) {
		sbuf_push(&sbuf, 4, "IPv6 Adjacency-SID: %u",
			  attr->adj_sid[ADJ_PRI_IPV6].sid);
		sbuf_push(&sbuf, 0, "\tFlags: 0x%x\tWeight: 0x%x\n",
			  attr->adj_sid[ADJ_PRI_IPV6].flags,
			  attr->adj_sid[ADJ_PRI_IPV6].weight);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID6)) {
		sbuf_push(&sbuf, 4, "IPv6 Bck. Adjacency-SID: %u",
			  attr->adj_sid[ADJ_BCK_IPV6].sid);
		sbuf_push(&sbuf, 0, "\tFlags: 0x%x\tWeight: 0x%x\n",
			  attr->adj_sid[ADJ_BCK_IPV6].flags,
			  attr->adj_sid[ADJ_BCK_IPV6].weight);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_SRLG)) {
		sbuf_push(&sbuf, 4, "SRLGs: %d", attr->srlg_len);
		for (int i = 1; i < attr->srlg_len; i++) {
			if (i % 8)
				sbuf_push(&sbuf, 8, "\n%u", attr->srlgs[i]);
			else
				sbuf_push(&sbuf, 8, ", %u", attr->srlgs[i]);
		}
		sbuf_push(&sbuf, 0, "\n");
	}

end:
	vty_out(vty, "%s\n", sbuf_buf(&sbuf));
	sbuf_free(&sbuf);
}

static void ls_show_edge_json(struct ls_edge *edge, struct json_object *json)
{
	struct ls_attributes *attr;
	struct json_object *jte, *jbw, *jobj, *jsr = NULL, *jsrlg, *js_ext_ag,
					      *js_ext_ag_arr_word,
					      *js_ext_ag_arr_bit;
	char buf[INET6_BUFSIZ];
	char buf_ag[strlen("0xffffffff") + 1];
	uint32_t bitmap;
	size_t i;

	attr = edge->attributes;

	json_object_string_add(json, "edge-id", edge_key_to_text(edge->key));
	json_object_string_add(json, "status", status2txt[edge->status]);
	json_object_string_add(json, "origin", origin2txt[attr->adv.origin]);
	ls_node_id_to_text(attr->adv, buf, INET6_BUFSIZ);
	json_object_string_add(json, "advertised-router", buf);
	if (edge->source)
		json_object_int_add(json, "local-vertex-id", edge->source->key);
	if (edge->destination)
		json_object_int_add(json, "remote-vertex-id",
				    edge->destination->key);
	json_object_int_add(json, "metric", attr->metric);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NAME))
		json_object_string_add(json, "name", attr->name);
	jte = json_object_new_object();
	json_object_object_add(json, "edge-attributes", jte);
	if (CHECK_FLAG(attr->flags, LS_ATTR_TE_METRIC))
		json_object_int_add(jte, "te-metric", attr->standard.te_metric);
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADM_GRP))
		json_object_int_add(jte, "admin-group",
				    attr->standard.admin_group);
	if (CHECK_FLAG(attr->flags, LS_ATTR_EXT_ADM_GRP)) {
		js_ext_ag = json_object_new_object();
		json_object_object_add(jte, "extAdminGroup", js_ext_ag);
		js_ext_ag_arr_word = json_object_new_array();
		json_object_object_add(js_ext_ag, "words", js_ext_ag_arr_word);
		js_ext_ag_arr_bit = json_object_new_array();
		json_object_object_add(js_ext_ag, "bitPositions",
				       js_ext_ag_arr_bit);
		for (i = 0; i < admin_group_nb_words(&attr->ext_admin_group);
		     i++) {
			bitmap = admin_group_get_offset(&attr->ext_admin_group,
							i);
			snprintf(buf_ag, sizeof(buf_ag), "0x%08x", bitmap);
			json_object_array_add(js_ext_ag_arr_word,
					      json_object_new_string(buf_ag));
		}
		for (i = 0;
		     i < (admin_group_size(&attr->ext_admin_group) * WORD_SIZE);
		     i++) {
			if (admin_group_get(&attr->ext_admin_group, i))
				json_object_array_add(js_ext_ag_arr_bit,
						      json_object_new_int(i));
		}
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR)) {
		snprintfrr(buf, INET6_BUFSIZ, "%pI4", &attr->standard.local);
		json_object_string_add(jte, "local-address", buf);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR)) {
		snprintfrr(buf, INET6_BUFSIZ, "%pI4", &attr->standard.remote);
		json_object_string_add(jte, "remote-address", buf);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR6)) {
		snprintfrr(buf, INET6_BUFSIZ, "%pI6", &attr->standard.local6);
		json_object_string_add(jte, "local-address-v6", buf);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR6)) {
		snprintfrr(buf, INET6_BUFSIZ, "%pI6", &attr->standard.remote6);
		json_object_string_add(jte, "remote-address-v6", buf);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ID))
		json_object_int_add(jte, "local-identifier",
				    attr->standard.local_id);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NEIGH_ID))
		json_object_int_add(jte, "remote-identifier",
				    attr->standard.remote_id);
	if (CHECK_FLAG(attr->flags, LS_ATTR_MAX_BW))
		json_object_double_add(jte, "max-link-bandwidth",
				       attr->standard.max_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_MAX_RSV_BW))
		json_object_double_add(jte, "max-resv-link-bandwidth",
				       attr->standard.max_rsv_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_UNRSV_BW)) {
		jbw = json_object_new_array();
		json_object_object_add(jte, "unreserved-bandwidth", jbw);
		for (int i = 0; i < MAX_CLASS_TYPE; i++) {
			jobj = json_object_new_object();
			snprintfrr(buf, 13, "class-type-%u", i);
			json_object_double_add(jobj, buf,
					       attr->standard.unrsv_bw[i]);
			json_object_array_add(jbw, jobj);
		}
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_REMOTE_AS))
		json_object_int_add(jte, "remote-asn",
				    attr->standard.remote_as);
	if (CHECK_FLAG(attr->flags, LS_ATTR_REMOTE_ADDR)) {
		snprintfrr(buf, INET6_BUFSIZ, "%pI4",
			   &attr->standard.remote_addr);
		json_object_string_add(jte, "remote-as-address", buf);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_REMOTE_ADDR6)) {
		snprintfrr(buf, INET6_BUFSIZ, "%pI6",
			   &attr->standard.remote_addr6);
		json_object_string_add(jte, "remote-as-address-v6", buf);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_DELAY))
		json_object_int_add(jte, "delay", attr->extended.delay);
	if (CHECK_FLAG(attr->flags, LS_ATTR_MIN_MAX_DELAY)) {
		json_object_int_add(jte, "min-delay", attr->extended.min_delay);
		json_object_int_add(jte, "max-delay", attr->extended.max_delay);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_JITTER))
		json_object_int_add(jte, "jitter", attr->extended.jitter);
	if (CHECK_FLAG(attr->flags, LS_ATTR_PACKET_LOSS))
		json_object_double_add(
			jte, "loss", attr->extended.pkt_loss * LOSS_PRECISION);
	if (CHECK_FLAG(attr->flags, LS_ATTR_AVA_BW))
		json_object_double_add(jte, "available-bandwidth",
				       attr->extended.ava_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_RSV_BW))
		json_object_double_add(jte, "residual-bandwidth",
				       attr->extended.rsv_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_USE_BW))
		json_object_double_add(jte, "utilized-bandwidth",
				       attr->extended.used_bw);
	if (CHECK_FLAG(attr->flags, LS_ATTR_SRLG)) {
		jsrlg = json_object_new_array();
		json_object_object_add(jte, "srlgs", jsrlg);
		for (int i = 1; i < attr->srlg_len; i++) {
			jobj = json_object_new_object();
			json_object_int_add(jobj, "srlg", attr->srlgs[i]);
			json_object_array_add(jsrlg, jobj);
		}
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADJ_SID)) {
		jsr = json_object_new_array();
		json_object_object_add(json, "segment-routing", jsr);
		jobj = json_object_new_object();
		json_object_int_add(jobj, "adj-sid",
				    attr->adj_sid[ADJ_PRI_IPV4].sid);
		snprintfrr(buf, 6, "0x%x", attr->adj_sid[ADJ_PRI_IPV4].flags);
		json_object_string_add(jobj, "flags", buf);
		json_object_int_add(jobj, "weight",
				    attr->adj_sid[ADJ_PRI_IPV4].weight);
		json_object_array_add(jsr, jobj);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID)) {
		if (!jsr) {
			jsr = json_object_new_array();
			json_object_object_add(json, "segment-routing", jsr);
		}
		jobj = json_object_new_object();
		json_object_int_add(jobj, "adj-sid",
				    attr->adj_sid[ADJ_BCK_IPV4].sid);
		snprintfrr(buf, 6, "0x%x", attr->adj_sid[ADJ_BCK_IPV4].flags);
		json_object_string_add(jobj, "flags", buf);
		json_object_int_add(jobj, "weight",
				    attr->adj_sid[ADJ_BCK_IPV4].weight);
		json_object_array_add(jsr, jobj);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADJ_SID6)) {
		jsr = json_object_new_array();
		json_object_object_add(json, "segment-routing", jsr);
		jobj = json_object_new_object();
		json_object_int_add(jobj, "adj-sid",
				    attr->adj_sid[ADJ_PRI_IPV6].sid);
		snprintfrr(buf, 6, "0x%x", attr->adj_sid[ADJ_PRI_IPV6].flags);
		json_object_string_add(jobj, "flags", buf);
		json_object_int_add(jobj, "weight",
				    attr->adj_sid[ADJ_PRI_IPV6].weight);
		json_object_array_add(jsr, jobj);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID6)) {
		if (!jsr) {
			jsr = json_object_new_array();
			json_object_object_add(json, "segment-routing", jsr);
		}
		jobj = json_object_new_object();
		json_object_int_add(jobj, "adj-sid",
				    attr->adj_sid[ADJ_BCK_IPV6].sid);
		snprintfrr(buf, 6, "0x%x", attr->adj_sid[ADJ_BCK_IPV6].flags);
		json_object_string_add(jobj, "flags", buf);
		json_object_int_add(jobj, "weight",
				    attr->adj_sid[ADJ_BCK_IPV6].weight);
		json_object_array_add(jsr, jobj);
	}
}

void ls_show_edge(struct ls_edge *edge, struct vty *vty,
		  struct json_object *json, bool verbose)
{
	/* Sanity Check */
	if (!edge)
		return;

	if (json)
		ls_show_edge_json(edge, json);
	else if (vty)
		ls_show_edge_vty(edge, vty, verbose);
}

void ls_show_edges(struct ls_ted *ted, struct vty *vty,
		   struct json_object *json, bool verbose)
{
	struct ls_edge *edge;
	json_object *jedges, *jedge;

	if (json) {
		jedges = json_object_new_array();
		json_object_object_add(json, "edges", jedges);
		frr_each (edges, &ted->edges, edge) {
			jedge = json_object_new_object();
			ls_show_edge(edge, NULL, jedge, verbose);
			json_object_array_add(jedges, jedge);
		}
	} else if (vty) {
		frr_each (edges, &ted->edges, edge)
			ls_show_edge(edge, vty, NULL, verbose);
	}
}

static void ls_show_subnet_vty(struct ls_subnet *subnet, struct vty *vty,
			       bool verbose)
{
	struct ls_prefix *pref;
	struct sbuf sbuf;
	char buf[INET6_BUFSIZ];

	pref = subnet->ls_pref;
	sbuf_init(&sbuf, NULL, 0);

	sbuf_push(&sbuf, 2, "Subnet: %pFX", &subnet->key);
	ls_node_id_to_text(pref->adv, buf, INET6_BUFSIZ);
	sbuf_push(&sbuf, 0, "\tAdv. Vertex: %s", buf);
	sbuf_push(&sbuf, 0, "\tMetric: %d", pref->metric);
	sbuf_push(&sbuf, 0, "\tStatus: %s\n", status2txt[subnet->status]);

	if (!verbose)
		goto end;

	sbuf_push(&sbuf, 4, "Origin: %s\n", origin2txt[pref->adv.origin]);
	if (CHECK_FLAG(pref->flags, LS_PREF_IGP_FLAG))
		sbuf_push(&sbuf, 4, "Flags: %d\n", pref->igp_flag);

	if (CHECK_FLAG(pref->flags, LS_PREF_ROUTE_TAG))
		sbuf_push(&sbuf, 4, "Tag: %d\n", pref->route_tag);

	if (CHECK_FLAG(pref->flags, LS_PREF_EXTENDED_TAG))
		sbuf_push(&sbuf, 4, "Extended Tag: %" PRIu64 "\n",
			  pref->extended_tag);

	if (CHECK_FLAG(pref->flags, LS_PREF_SR))
		sbuf_push(&sbuf, 4, "SID: %d\tAlgorithm: %d\tFlags: 0x%x\n",
			  pref->sr.sid, pref->sr.algo, pref->sr.sid_flag);

end:
	vty_out(vty, "%s\n", sbuf_buf(&sbuf));
	sbuf_free(&sbuf);
}

static void ls_show_subnet_json(struct ls_subnet *subnet,
				struct json_object *json)
{
	struct ls_prefix *pref;
	json_object *jsr;
	char buf[INET6_BUFSIZ];

	pref = subnet->ls_pref;

	snprintfrr(buf, INET6_BUFSIZ, "%pFX", &subnet->key);
	json_object_string_add(json, "subnet-id", buf);
	json_object_string_add(json, "status", status2txt[subnet->status]);
	json_object_string_add(json, "origin", origin2txt[pref->adv.origin]);
	ls_node_id_to_text(pref->adv, buf, INET6_BUFSIZ);
	json_object_string_add(json, "advertised-router", buf);
	if (subnet->vertex)
		json_object_int_add(json, "vertex-id", subnet->vertex->key);
	json_object_int_add(json, "metric", pref->metric);
	if (CHECK_FLAG(pref->flags, LS_PREF_IGP_FLAG)) {
		snprintfrr(buf, INET6_BUFSIZ, "0x%x", pref->igp_flag);
		json_object_string_add(json, "flags", buf);
	}
	if (CHECK_FLAG(pref->flags, LS_PREF_ROUTE_TAG))
		json_object_int_add(json, "tag", pref->route_tag);
	if (CHECK_FLAG(pref->flags, LS_PREF_EXTENDED_TAG))
		json_object_int_add(json, "extended-tag", pref->extended_tag);
	if (CHECK_FLAG(pref->flags, LS_PREF_SR)) {
		jsr = json_object_new_object();
		json_object_object_add(json, "segment-routing", jsr);
		json_object_int_add(jsr, "pref-sid", pref->sr.sid);
		json_object_int_add(jsr, "algo", pref->sr.algo);
		snprintfrr(buf, INET6_BUFSIZ, "0x%x", pref->sr.sid_flag);
		json_object_string_add(jsr, "flags", buf);
	}
}

void ls_show_subnet(struct ls_subnet *subnet, struct vty *vty,
		    struct json_object *json, bool verbose)
{
	/* Sanity Check */
	if (!subnet)
		return;

	if (json)
		ls_show_subnet_json(subnet, json);
	else if (vty)
		ls_show_subnet_vty(subnet, vty, verbose);
}

void ls_show_subnets(struct ls_ted *ted, struct vty *vty,
		     struct json_object *json, bool verbose)
{
	struct ls_subnet *subnet;
	json_object *jsubs, *jsub;

	if (json) {
		jsubs = json_object_new_array();
		json_object_object_add(json, "subnets", jsubs);
		frr_each (subnets, &ted->subnets, subnet) {
			jsub = json_object_new_object();
			ls_show_subnet(subnet, NULL, jsub, verbose);
			json_object_array_add(jsubs, jsub);
		}
	} else if (vty) {
		frr_each (subnets, &ted->subnets, subnet)
			ls_show_subnet(subnet, vty, NULL, verbose);
	}
}

void ls_show_ted(struct ls_ted *ted, struct vty *vty, struct json_object *json,
		 bool verbose)
{
	json_object *jted;

	if (json) {
		jted = json_object_new_object();
		json_object_object_add(json, "ted", jted);
		json_object_string_add(jted, "name", ted->name);
		json_object_int_add(jted, "key", ted->key);
		json_object_int_add(jted, "verticesCount",
				    vertices_count(&ted->vertices));
		json_object_int_add(jted, "edgesCount",
				    edges_count(&ted->edges));
		json_object_int_add(jted, "subnetsCount",
				    subnets_count(&ted->subnets));
		ls_show_vertices(ted, NULL, jted, verbose);
		ls_show_edges(ted, NULL, jted, verbose);
		ls_show_subnets(ted, NULL, jted, verbose);
		return;
	}

	if (vty) {
		vty_out(vty,
			"\n\tTraffic Engineering Database: %s (key: %d)\n\n",
			ted->name, ted->key);
		ls_show_vertices(ted, vty, NULL, verbose);
		ls_show_edges(ted, vty, NULL, verbose);
		ls_show_subnets(ted, vty, NULL, verbose);
		vty_out(vty,
			"\n\tTotal: %zu Vertices, %zu Edges, %zu Subnets\n\n",
			vertices_count(&ted->vertices),
			edges_count(&ted->edges), subnets_count(&ted->subnets));
	}
}

void ls_dump_ted(struct ls_ted *ted)
{
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct ls_subnet *subnet;
	const struct in_addr inaddr_any = {.s_addr = INADDR_ANY};

	zlog_debug("(%s) Ted init", __func__);

	/* Loop TED, start printing Node, then Attributes and finally Prefix */
	frr_each (vertices, &ted->vertices, vertex) {
		zlog_debug("    Ted node (%s %pI4 %s)",
			   vertex->node->name[0] ? vertex->node->name
						 : "no name node",
			   &vertex->node->router_id,
			   origin2txt[vertex->node->adv.origin]);
		struct listnode *lst_node;
		struct ls_edge *vertex_edge;

		for (ALL_LIST_ELEMENTS_RO(vertex->incoming_edges, lst_node,
					  vertex_edge)) {
			zlog_debug(
				"        inc edge key:%s attr key:%pI4 loc:(%pI4) rmt:(%pI4)",
				edge_key_to_text(vertex_edge->key),
				&vertex_edge->attributes->adv.id.ip.addr,
				&vertex_edge->attributes->standard.local,
				&vertex_edge->attributes->standard.remote);
		}
		for (ALL_LIST_ELEMENTS_RO(vertex->outgoing_edges, lst_node,
					  vertex_edge)) {
			zlog_debug(
				"        out edge key:%s attr key:%pI4  loc:(%pI4) rmt:(%pI4)",
				edge_key_to_text(vertex_edge->key),
				&vertex_edge->attributes->adv.id.ip.addr,
				&vertex_edge->attributes->standard.local,
				&vertex_edge->attributes->standard.remote);
		}
	}
	frr_each (edges, &ted->edges, edge) {
		zlog_debug("    Ted edge key:%s src:%pI4 dst:%pI4",
			   edge_key_to_text(edge->key),
			   edge->source ? &edge->source->node->router_id
					: &inaddr_any,
			   edge->destination
				   ? &edge->destination->node->router_id
				   : &inaddr_any);
	}
	frr_each (subnets, &ted->subnets, subnet) {
		zlog_debug("    Ted subnet key:%pFX vertex:%pI4",
			   &subnet->ls_pref->pref,
			   &subnet->vertex->node->adv.id.ip.addr);
	}
	zlog_debug("(%s) Ted end", __func__);
}
