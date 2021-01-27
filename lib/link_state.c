/*
 * Link State Database - link_state.c
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2020 Orange http://www.orange.com
 *
 * This file is part of Free Range Routing (FRR).
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
#include "link_state.h"

/* Link State Memory allocation */
DEFINE_MTYPE_STATIC(LIB, LS_DB, "Link State Database")

/**
 *  Link State Node management functions
 */
struct ls_node *ls_node_new(struct ls_node_id adv, struct in_addr rid,
			    struct in6_addr rid6)
{
	struct ls_node *new;

	if (adv.origin == NONE)
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
		new->router6_id = rid6;
		SET_FLAG(new->flags, LS_NODE_ROUTER_ID6);
	}
	return new;
}

void ls_node_del(struct ls_node *node)
{
	XFREE(MTYPE_LS_DB, node);
	node = NULL;
}

int ls_node_same(struct ls_node *n1, struct ls_node *n2)
{
	if ((n1 && !n2) || (!n1 && n2))
		return 0;

	if (n1 == n2)
		return 1;

	if (n1->flags != n2->flags)
		return 0;

	if (n1->adv.origin != n2->adv.origin)
		return 0;

	if (!memcmp(&n1->adv.id, &n2->adv.id, sizeof(struct ls_node_id)))
		return 0;

	/* Do we need to test individually each field, instead performing a
	 * global memcmp? There is a risk that an old value that is bit masked
	 * i.e. corresponding flag = 0, will result into a false negative
	 */
	if (!memcmp(n1, n2, sizeof(struct ls_node)))
		return 0;
	else
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

	if (adv.origin == NONE)
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

	return new;
}

void ls_attributes_del(struct ls_attributes *attr)
{
	if (!attr)
		return;

	if (attr->srlgs)
		XFREE(MTYPE_LS_DB, attr->srlgs);

	XFREE(MTYPE_LS_DB, attr);
	attr = NULL;
}

int ls_attributes_same(struct ls_attributes *l1, struct ls_attributes *l2)
{
	if ((l1 && !l2) || (!l1 && l2))
		return 0;

	if (l1 == l2)
		return 1;

	if (l1->flags != l2->flags)
		return 0;

	if (l1->adv.origin != l2->adv.origin)
		return 0;

	if (!memcmp(&l1->adv.id, &l2->adv.id, sizeof(struct ls_node_id)))
		return 0;

	/* Do we need to test individually each field, instead performing a
	 * global memcmp? There is a risk that an old value that is bit masked
	 * i.e. corresponding flag = 0, will result into a false negative
	 */
	if (!memcmp(l1, l2, sizeof(struct ls_attributes)))
		return 0;
	else
		return 1;
}

/**
 *  Link State Vertices management functions
 */
struct ls_vertex *ls_vertex_new(struct ls_node *node)
{
	struct ls_vertex *new;

	if (node == NULL)
		return NULL;

	new = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_vertex));
	new->node = node;
	new->incoming_edges = list_new();
	new->outgoing_edges = list_new();
	new->prefixes = list_new();

	return new;
}

void ls_vertex_del(struct ls_vertex *vertex)
{
	if (vertex == NULL)
		return;

	list_delete_all_node(vertex->incoming_edges);
	list_delete_all_node(vertex->outgoing_edges);
	list_delete_all_node(vertex->prefixes);
	XFREE(MTYPE_LS_DB, vertex);
	vertex = NULL;
}

struct ls_vertex *ls_vertex_add(struct ls_ted *ted, struct ls_node *node)
{
	struct ls_vertex *new;

	if ((ted == NULL) || (node == NULL))
		return NULL;

	new = ls_vertex_new(node);
	if (!new)
		return NULL;

	/* set Key as the IPv4/Ipv6 Router ID or ISO System ID */
	switch (node->adv.origin) {
	case OSPFv2:
	case STATIC:
	case DIRECT:
		memcpy(&new->key, &node->adv.id.ip.addr, IPV4_MAX_BYTELEN);
		break;
	case ISIS_L1:
	case ISIS_L2:
		memcpy(&new->key, &node->adv.id.iso.sys_id, ISO_SYS_ID_LEN);
		break;
	default:
		new->key = 0;
		break;
	}

	/* Remove Vertex if key is not set */
	if (new->key == 0) {
		ls_vertex_del(new);
		return NULL;
	}

	/* Add Vertex to TED */
	vertices_add(&ted->vertices, new);

	return new;
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
		}
		return old;
	}

	return ls_vertex_add(ted, node);
}

void ls_vertex_remove(struct ls_ted *ted, struct ls_vertex *vertex)
{
	vertices_del(&ted->vertices, vertex);
	ls_vertex_del(vertex);
}

struct ls_vertex *ls_find_vertex_by_key(struct ls_ted *ted, const uint64_t key)
{
	struct ls_vertex node = {};

	if (key == 0)
		return NULL;

	node.key = key;
	return vertices_find(&ted->vertices, &node);
}

struct ls_vertex *ls_find_vertex_by_id(struct ls_ted *ted,
				       struct ls_node_id nid)
{
	struct ls_vertex node = {};

	switch (nid.origin) {
	case OSPFv2:
	case STATIC:
	case DIRECT:
		memcpy(&node.key, &nid.id.ip.addr, IPV4_MAX_BYTELEN);
		break;
	case ISIS_L1:
	case ISIS_L2:
		memcpy(&node.key, &nid.id.iso.sys_id, ISO_SYS_ID_LEN);
		break;
	default:
		return NULL;
	}

	return vertices_find(&ted->vertices, &node);
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
	listnode_add(vertex->outgoing_edges, edge);
	edge->source = vertex;

	/* Then search if there is a reverse Edge */
	dst = ls_find_edge_by_destination(ted, edge->attributes);
	/* attach the destination edge to the vertex */
	if (dst) {
		listnode_add(vertex->incoming_edges, dst);
		dst->destination = vertex;
		/* and destination vertex to this edge */
		vertex = dst->source;
		listnode_add(vertex->incoming_edges, edge);
		edge->destination = vertex;
	}
}

struct ls_edge *ls_edge_add(struct ls_ted *ted,
			    struct ls_attributes *attributes)
{
	struct ls_edge *new;

	if (attributes == NULL)
		return NULL;

	new = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_edge));
	new->attributes = attributes;
	/* Key is the IPv4 local address */
	if (!IPV4_NET0(attributes->standard.local.s_addr))
		new->key = ((uint64_t)attributes->standard.local.s_addr)
			   & 0xffffffff;
	/* or the IPv6 local address if IPv4 is not defined */
	else if (!IN6_IS_ADDR_UNSPECIFIED(&attributes->standard.local6))
		new->key = (uint64_t)(attributes->standard.local6.s6_addr32[0]
				      & 0xffffffff)
			   | ((uint64_t)attributes->standard.local6.s6_addr32[1]
			      << 32);
	/* of local identifier if no IP addresses are defined */
	else if (attributes->standard.local_id != 0)
		new->key = (uint64_t)(
			(attributes->standard.local_id & 0xffffffff)
			| ((uint64_t)attributes->standard.remote_id << 32));

	/* Remove Edge if key is not known */
	if (new->key == 0) {
		XFREE(MTYPE_LS_DB, new);
		return NULL;
	}

	edges_add(&ted->edges, new);

	/* Finally, connect edge to vertices */
	ls_edge_connect_to(ted, new);

	return new;
}

struct ls_edge *ls_find_edge_by_key(struct ls_ted *ted, const uint64_t key)
{
	struct ls_edge edge = {};

	if (key == 0)
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

	/* Key is the IPv4 local address */
	if (!IPV4_NET0(attributes->standard.local.s_addr))
		edge.key = ((uint64_t)attributes->standard.local.s_addr)
			   & 0xffffffff;
	/* or the IPv6 local address if IPv4 is not defined */
	else if (!IN6_IS_ADDR_UNSPECIFIED(&attributes->standard.local6))
		edge.key = (uint64_t)(attributes->standard.local6.s6_addr32[0]
				      & 0xffffffff)
			   | ((uint64_t)attributes->standard.local6.s6_addr32[1]
			      << 32);
	/* of local identifier if no IP addresses are defined */
	else if (attributes->standard.local_id != 0)
		edge.key = (uint64_t)(
			(attributes->standard.local_id & 0xffffffff)
			| ((uint64_t)attributes->standard.remote_id << 32));

	if (edge.key == 0)
		return NULL;

	return edges_find(&ted->edges, &edge);
}

struct ls_edge *ls_find_edge_by_destination(struct ls_ted *ted,
					    struct ls_attributes *attributes)
{
	struct ls_edge edge = {};

	if (attributes == NULL)
		return NULL;

	/* Key is the IPv4 local address */
	if (!IPV4_NET0(attributes->standard.remote.s_addr))
		edge.key = ((uint64_t)attributes->standard.remote.s_addr)
			   & 0xffffffff;
	/* or the IPv6 local address if IPv4 is not defined */
	else if (!IN6_IS_ADDR_UNSPECIFIED(&attributes->standard.remote6))
		edge.key =
			(uint64_t)(attributes->standard.remote6.s6_addr32[0]
				   & 0xffffffff)
			| ((uint64_t)attributes->standard.remote6.s6_addr32[1]
			   << 32);
	/* of local identifier if no IP addresses are defined */
	else if (attributes->standard.remote_id != 0)
		edge.key = (uint64_t)(
			(attributes->standard.remote_id & 0xffffffff)
			| ((uint64_t)attributes->standard.local_id << 32));

	if (edge.key == 0)
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
		}
		return old;
	}

	/* If not found, add new Edge from the attributes */
	return ls_edge_add(ted, attributes);
}

void ls_edge_del(struct ls_ted *ted, struct ls_edge *edge)
{
	/* Fist disconnect Edge */
	ls_disconnect_edge(edge);
	/* Then remove it from the Data Base */
	edges_del(&ted->edges, edge);
	XFREE(MTYPE_LS_DB, edge);
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

	/* Find Vertex */
	vertex = ls_find_vertex_by_id(ted, ls_pref->adv);
	if (vertex == NULL) {
		/* Create a new temporary Node & Vertex if not found */
		node = ls_node_new(ls_pref->adv, inaddr_any, in6addr_any);
		vertex = ls_vertex_add(ted, node);
	}
	/* And attach the subnet to the corresponding Vertex */
	new->vertex = vertex;
	listnode_add(vertex->prefixes, new);

	subnets_add(&ted->subnets, new);

	return new;
}

void ls_subnet_del(struct ls_ted *ted, struct ls_subnet *subnet)
{
	subnets_del(&ted->subnets, subnet);
	XFREE(MTYPE_LS_DB, subnet);
}

struct ls_subnet *ls_find_subnet(struct ls_ted *ted, const struct prefix prefix)
{
	struct ls_subnet subnet = {};

	subnet.key = prefix;
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
	if (new == NULL)
		return new;

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

	/* Release RB Tree */
	vertices_fini(&ted->vertices);
	edges_fini(&ted->edges);
	subnets_fini(&ted->subnets);

	XFREE(MTYPE_LS_DB, ted);
	ted = NULL;
}

void ls_connect(struct ls_vertex *vertex, struct ls_edge *edge, bool source)
{
	if (vertex == NULL || edge == NULL)
		return;

	if (source) {
		listnode_add(vertex->outgoing_edges, edge);
		edge->source = vertex;
	} else {
		listnode_add(vertex->incoming_edges, edge);
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
		listnode_add(src->outgoing_edges, edge);

	if (dst != NULL)
		listnode_add(dst->incoming_edges, edge);

}

void ls_disconnect_edge(struct ls_edge *edge)
{
	if (edge == NULL)
		return;

	ls_disconnect(edge->source, edge, true);
	ls_disconnect(edge->destination, edge, false);
}

/**
 * Link State Message management functions
 */

static struct ls_node *ls_parse_node(struct stream *s)
{
	struct ls_node *node;
	size_t len;

	node = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_node));
	if (node == NULL)
		return NULL;

	STREAM_GET(&node->adv, s, sizeof(struct ls_node_id));
	STREAM_GETW(s, node->flags);
	if (CHECK_FLAG(node->flags, LS_NODE_NAME)) {
		STREAM_GETC(s, len);
		STREAM_GET(node->name, s, len);
	}
	if (CHECK_FLAG(node->flags, LS_NODE_ROUTER_ID))
		node->router_id.s_addr = stream_get_ipv4(s);
	if (CHECK_FLAG(node->flags, LS_NODE_ROUTER_ID6))
		STREAM_GET(&node->router6_id, s, IPV6_MAX_BYTELEN);
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
	size_t len;

	attr = XCALLOC(MTYPE_LS_DB, sizeof(struct ls_attributes));
	if (attr == NULL)
		return NULL;
	attr->srlgs = NULL;

	STREAM_GET(&attr->adv, s, sizeof(struct ls_node_id));
	STREAM_GETL(s, attr->flags);
	if (CHECK_FLAG(attr->flags, LS_ATTR_NAME)) {
		STREAM_GETC(s, len);
		STREAM_GET(attr->name, s, len);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_METRIC))
		STREAM_GETL(s, attr->standard.metric);
	if (CHECK_FLAG(attr->flags, LS_ATTR_TE_METRIC))
		STREAM_GETL(s, attr->standard.te_metric);
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADM_GRP))
		STREAM_GETL(s, attr->standard.admin_group);
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
		STREAM_GETL(s, attr->adj_sid[0].sid);
		STREAM_GETC(s, attr->adj_sid[0].flags);
		STREAM_GETC(s, attr->adj_sid[0].weight);
		if (attr->adv.origin == ISIS_L1 || attr->adv.origin == ISIS_L2)
			STREAM_GET(attr->adj_sid[0].neighbor.sysid, s,
				   ISO_SYS_ID_LEN);
		else if (attr->adv.origin == OSPFv2)
			attr->adj_sid[0].neighbor.addr.s_addr =
				stream_get_ipv4(s);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID)) {
		STREAM_GETL(s, attr->adj_sid[1].sid);
		STREAM_GETC(s, attr->adj_sid[1].flags);
		STREAM_GETC(s, attr->adj_sid[1].weight);
		if (attr->adv.origin == ISIS_L1 || attr->adv.origin == ISIS_L2)
			STREAM_GET(attr->adj_sid[1].neighbor.sysid, s,
				   ISO_SYS_ID_LEN);
		else if (attr->adv.origin == OSPFv2)
			attr->adj_sid[1].neighbor.addr.s_addr =
				stream_get_ipv4(s);
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
	/* Clean memeory allocation */
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
	if (ls_pref == NULL)
		return NULL;

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
	if (msg == NULL)
		return NULL;

	/* Read LS Message header */
	STREAM_GETC(s, msg->event);
	STREAM_GETC(s, msg->type);
	STREAM_GET(&msg->remote_id, s, sizeof(struct ls_node_id));

	/* Read Message Payload */
	switch (msg->type) {
	case LS_MSG_TYPE_NODE:
		msg->data.node = ls_parse_node(s);
		break;
	case LS_MSG_TYPE_ATTRIBUTES:
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
		stream_put(s, &node->router6_id, IPV6_MAX_BYTELEN);
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
	size_t len;

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
		stream_putl(s, attr->standard.metric);
	if (CHECK_FLAG(attr->flags, LS_ATTR_TE_METRIC))
		stream_putl(s, attr->standard.te_metric);
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADM_GRP))
		stream_putl(s, attr->standard.admin_group);
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
		stream_putl(s, attr->adj_sid[0].sid);
		stream_putc(s, attr->adj_sid[0].flags);
		stream_putc(s, attr->adj_sid[0].weight);
		if (attr->adv.origin == ISIS_L1 || attr->adv.origin == ISIS_L2)
			stream_put(s, attr->adj_sid[0].neighbor.sysid,
				   ISO_SYS_ID_LEN);
		else if (attr->adv.origin == OSPFv2)
			stream_put_ipv4(s,
					attr->adj_sid[0].neighbor.addr.s_addr);
	}
	if (CHECK_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID)) {
		stream_putl(s, attr->adj_sid[1].sid);
		stream_putc(s, attr->adj_sid[1].flags);
		stream_putc(s, attr->adj_sid[1].weight);
		if (attr->adv.origin == ISIS_L1 || attr->adv.origin == ISIS_L2)
			stream_put(s, attr->adj_sid[1].neighbor.sysid,
				   ISO_SYS_ID_LEN);
		else if (attr->adv.origin == OSPFv2)
			stream_put_ipv4(s,
					attr->adj_sid[1].neighbor.addr.s_addr);
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
	stream_put(s, &msg->remote_id, sizeof(struct ls_node_id));

	/* Add Message Payload */
	switch (msg->type) {
	case LS_MSG_TYPE_NODE:
		return ls_format_node(s, msg->data.node);
	case LS_MSG_TYPE_ATTRIBUTES:
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

	/* Check buffer size */
	if (STREAM_SIZE(zclient->obuf) <
	    (ZEBRA_HEADER_SIZE + sizeof(uint32_t) + sizeof(msg)))
		return -1;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_OPAQUE_MESSAGE, VRF_DEFAULT);

	/* Send sub-type, flags and destination for unicast message */
	stream_putl(s, LINK_STATE_UPDATE);
	if (dst != NULL) {
		SET_FLAG(flags, ZAPI_OPAQUE_FLAG_UNICAST);
		stream_putw(s, flags);
		/* Send destination client info */
		stream_putc(s, dst->proto);
		stream_putw(s, dst->instance);
		stream_putl(s, dst->session_id);
	} else
		stream_putw(s, flags);

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
	msg->data.node = vertex->node;
	msg->remote_id.origin = NONE;

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
	msg->data.attr = edge->attributes;
	if (edge->destination != NULL)
		msg->remote_id = edge->destination->node->adv;
	else
		msg->remote_id.origin = NONE;

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
	msg->data.prefix = subnet->ls_pref;
	msg->remote_id.origin = NONE;

	return msg;
}

void ls_delete_msg(struct ls_message *msg)
{
	if (msg == NULL)
		return;

	switch (msg->type) {
	case LS_MSG_TYPE_NODE:
		if (msg->data.node)
			XFREE(MTYPE_LS_DB, msg->data.node);
		break;
	case LS_MSG_TYPE_ATTRIBUTES:
		if (msg->data.attr)
			XFREE(MTYPE_LS_DB, msg->data.attr);
		break;
	case LS_MSG_TYPE_PREFIX:
		if (msg->data.prefix)
			XFREE(MTYPE_LS_DB, msg->data.prefix);
		break;
	default:
		break;
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

	/* Prepare message */
	msg.event = LS_MSG_EVENT_SYNC;

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

void ls_dump_ted(struct ls_ted *ted)
{
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct ls_subnet *subnet;
	struct ls_message msg;

	zlog_debug("(%s) Ted init", __func__);
	/* Prepare message */
	msg.event = LS_MSG_EVENT_SYNC;

	/* Loop TED, start printing Node, then Attributes and finally Prefix */
	frr_each(vertices, &ted->vertices, vertex) {
		ls_vertex2msg(&msg, vertex);
		zlog_debug("\tTed node (%s %pI4 %s)",
			   vertex->node->name[0] ? vertex->node->name
						 : "no name node",
			   &vertex->node->router_id,
			   vertex->node->adv.origin == DIRECT ? "DIRECT"
							      : "NO DIRECT");
		struct listnode *lst_node;
		struct ls_edge *vertex_edge;

		for (ALL_LIST_ELEMENTS_RO(vertex->incoming_edges, lst_node,
					  vertex_edge)) {
			zlog_debug(
				"\t\tinc edge key:%lldn attr key:%pI4 loc:(%pI4) rmt:(%pI4)",
				vertex_edge->key,
				&vertex_edge->attributes->adv.id.ip.addr,
				&vertex_edge->attributes->standard.local,
				&vertex_edge->attributes->standard.remote);
		}
		for (ALL_LIST_ELEMENTS_RO(vertex->outgoing_edges, lst_node,
					  vertex_edge)) {
			zlog_debug(
				"\t\tout edge key:%lld  attr key:%pI4  loc:(%pI4) rmt:(%pI4)",
				vertex_edge->key,
				&vertex_edge->attributes->adv.id.ip.addr,
				&vertex_edge->attributes->standard.local,
				&vertex_edge->attributes->standard.remote);
		}
	}
	frr_each(edges, &ted->edges, edge) {
		ls_edge2msg(&msg, edge);
		zlog_debug("\tTed edge key:%lld src:%s dst:%s", edge->key,
			   edge->source ? edge->source->node->name
					: "no_source",
			   edge->destination ? edge->destination->node->name
					     : "no_dest");
	}
	frr_each(subnets, &ted->subnets, subnet) {
		ls_subnet2msg(&msg, subnet);
		zlog_debug(
			"\tTed subnet key:%pFX vertex:%pI4 pfx:%pFX",
			&subnet->key,
			&subnet->vertex->node->adv.id.ip.addr,
			&subnet->ls_pref->pref);
	}
	zlog_debug("(%s) Ted end", __func__);
}
