// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Link State Database definition - ted.h
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2020 Orange http://www.orange.com
 *
 * This file is part of Free Range Routing (FRR).
 */

#ifndef _FRR_LINK_STATE_H_
#define _FRR_LINK_STATE_H_

#include "admin_group.h"
#include "typesafe.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This file defines the model used to implement a Link State Database
 * suitable to be used by various protocol like RSVP-TE, BGP-LS, PCEP ...
 * This database is normally fulfill by the link state routing protocol,
 * commonly OSPF or ISIS, carrying Traffic Engineering information within
 * Link State Attributes. See, RFC3630.(OSPF-TE) and RFC5305 (ISIS-TE).
 *
 * At least, 3 types of Link State structure are defined:
 *  - Link State Node that groups all information related to a node
 *  - Link State Attributes that groups all information related to a link
 *  - Link State Prefix that groups all information related to a prefix
 *
 * These 3 types of structures are those handled by BGP-LS (see RFC7752).
 *
 * Each structure, in addition to the specific parameters, embed the node
 * identifier which advertises the Link State and a bit mask as flags to
 * indicates which parameters are valid i.e. for which the value corresponds
 * to a Link State information convey by the routing protocol.
 * Node identifier is composed of the route id as IPv4 address plus the area
 * id for OSPF and the ISO System id plus the IS-IS level for IS-IS.
 */

/* external reference */
struct zapi_opaque_reg_info;
struct zclient;

/* Link State Common definitions */
#define MAX_NAME_LENGTH		256
#define ISO_SYS_ID_LEN		6

/* Type of Node */
enum ls_node_type {
	NONE = 0,	/* Unknown */
	STANDARD,	/* a P or PE node */
	ABR,		/* an Array Border Node */
	ASBR,		/* an Autonomous System Border Node */
	RMT_ASBR,	/* Remote ASBR */
	PSEUDO		/* a Pseudo Node */
};

/* Origin of the Link State information */
enum ls_origin { UNKNOWN = 0, ISIS_L1, ISIS_L2, OSPFv2, DIRECT, STATIC };

/**
 * Link State Node Identifier as:
 *  - IPv4 address + Area ID for OSPF
 *  - ISO System ID + ISIS Level for ISIS
 */
struct ls_node_id {
	enum ls_origin origin;		/* Origin of the LS information */
	union {
		struct {
			struct in_addr addr;		/* OSPF Router IS */
			struct in_addr area_id;		/* OSPF Area ID */
		} ip;
		struct {
			uint8_t sys_id[ISO_SYS_ID_LEN];	/* ISIS System ID */
			uint8_t level;			/* ISIS Level */
			uint8_t padding;
		} iso;
	} id;
};

/**
 * Check if two Link State Node IDs are equal. Note that this routine has the
 * same return value sense as '==' (which is different from a comparison).
 *
 * @param i1	First Link State Node Identifier
 * @param i2	Second Link State Node Identifier
 * @return	1 if equal, 0 otherwise
 */
extern int ls_node_id_same(struct ls_node_id i1, struct ls_node_id i2);

/* Supported number of algorithm by the link-state library */
#define LIB_LS_SR_ALGO_COUNT 2

/* Link State flags to indicate which Node parameters are valid */
#define LS_NODE_UNSET		0x0000
#define LS_NODE_NAME		0x0001
#define LS_NODE_ROUTER_ID	0x0002
#define LS_NODE_ROUTER_ID6	0x0004
#define LS_NODE_FLAG		0x0008
#define LS_NODE_TYPE		0x0010
#define LS_NODE_AS_NUMBER	0x0020
#define LS_NODE_SR		0x0040
#define LS_NODE_SRLB		0x0080
#define LS_NODE_MSD		0x0100
#define LS_NODE_SRV6		0x0200

/* Link State Node structure */
struct ls_node {
	uint16_t flags;			/* Flag for parameters validity */
	struct ls_node_id adv;		/* Adv. Router of this Link State */
	char name[MAX_NAME_LENGTH];	/* Name of the Node (IS-IS only) */
	struct in_addr router_id;	/* IPv4 Router ID */
	struct in6_addr router_id6;	/* IPv6 Router ID */
	uint8_t node_flag;		/* IS-IS or OSPF Node flag */
	enum ls_node_type type;		/* Type of Node */
	uint32_t as_number;		/* Local or neighbor AS number */
	struct ls_srgb {		/* Segment Routing Global Block */
		uint32_t lower_bound;		/* MPLS label lower bound */
		uint32_t range_size;		/* MPLS label range size */
		uint8_t flag;			/* IS-IS SRGB flags */
	} srgb;
	struct ls_srlb {		/* Segment Routing Local Block */
		uint32_t lower_bound;		/* MPLS label lower bound */
		uint32_t range_size;		/* MPLS label range size */
	} srlb;
	uint8_t algo[LIB_LS_SR_ALGO_COUNT]; /* Segment Routing Algorithms */
	uint8_t msd;			/* Maximum Stack Depth */

	uint16_t srv6_cap_flags; /* draft-ietf-idr-bgpls-srv6-ext, 3.1., flags field */
	struct ls_srv6_msd { /* draft-ietf-idr-bgpls-srv6-ext, 3.2. */
		uint8_t max_seg_left_msd;
		uint8_t max_end_pop_msd;
		uint8_t max_h_encaps_msd;
		uint8_t max_end_d_msd;
	} srv6_msd;
};

/* Link State flags to indicate which Attribute parameters are valid */
#define LS_ATTR_UNSET		0x00000000
#define LS_ATTR_NAME		0x00000001
#define LS_ATTR_METRIC		0x00000002
#define LS_ATTR_TE_METRIC	0x00000004
#define LS_ATTR_ADM_GRP		0x00000008
#define LS_ATTR_LOCAL_ADDR	0x00000010
#define LS_ATTR_NEIGH_ADDR	0x00000020
#define LS_ATTR_LOCAL_ADDR6	0x00000040
#define LS_ATTR_NEIGH_ADDR6	0x00000080
#define LS_ATTR_LOCAL_ID	0x00000100
#define LS_ATTR_NEIGH_ID	0x00000200
#define LS_ATTR_MAX_BW		0x00000400
#define LS_ATTR_MAX_RSV_BW	0x00000800
#define LS_ATTR_UNRSV_BW	0x00001000
#define LS_ATTR_REMOTE_AS	0x00002000
#define LS_ATTR_REMOTE_ADDR	0x00004000
#define LS_ATTR_REMOTE_ADDR6	0x00008000
#define LS_ATTR_DELAY		0x00010000
#define LS_ATTR_MIN_MAX_DELAY	0x00020000
#define LS_ATTR_JITTER		0x00040000
#define LS_ATTR_PACKET_LOSS	0x00080000
#define LS_ATTR_AVA_BW		0x00100000
#define LS_ATTR_RSV_BW		0x00200000
#define LS_ATTR_USE_BW		0x00400000
#define LS_ATTR_ADJ_SID		0x01000000
#define LS_ATTR_BCK_ADJ_SID	0x02000000
#define LS_ATTR_ADJ_SID6	0x04000000
#define LS_ATTR_BCK_ADJ_SID6	0x08000000
#define LS_ATTR_SRLG		0x10000000
#define LS_ATTR_EXT_ADM_GRP 0x20000000
#define LS_ATTR_ADJ_SRV6SID	0x40000000
#define LS_ATTR_BCK_ADJ_SRV6SID 0x80000000

/* Link State Attributes */
struct ls_attributes {
	uint32_t flags;			/* Flag for parameters validity */
	struct ls_node_id adv;		/* Adv. Router of this Link State */
	char name[MAX_NAME_LENGTH];	/* Name of the Edge. Could be null */
	uint32_t metric;		/* IGP standard metric */
	struct ls_standard {		/* Standard TE metrics */
		uint32_t te_metric;		/* Traffic Engineering metric */
		uint32_t admin_group;		/* Administrative Group */
		struct in_addr local;		/* Local IPv4 address */
		struct in_addr remote;		/* Remote IPv4 address */
		struct in6_addr local6;		/* Local IPv6 address */
		struct in6_addr remote6;	/* Remote IPv6 address */
		uint32_t local_id;		/* Local Identifier */
		uint32_t remote_id;		/* Remote Identifier */
		float max_bw;			/* Maximum Link Bandwidth */
		float max_rsv_bw;		/* Maximum Reservable BW */
		float unrsv_bw[8];		/* Unreserved BW per CT (8) */
		uint32_t remote_as;		/* Remote AS number */
		struct in_addr remote_addr;	/* Remote IPv4 address */
		struct in6_addr remote_addr6;	/* Remote IPv6 address */
	} standard;
	struct ls_extended {		/* Extended TE Metrics */
		uint32_t delay;		/* Unidirectional average delay */
		uint32_t min_delay;	/* Unidirectional minimum delay */
		uint32_t max_delay;	/* Unidirectional maximum delay */
		uint32_t jitter;	/* Unidirectional delay variation */
		uint32_t pkt_loss;	/* Unidirectional packet loss */
		float ava_bw;		/* Available Bandwidth */
		float rsv_bw;		/* Reserved Bandwidth */
		float used_bw;		/* Utilized Bandwidth */
	} extended;
	struct admin_group ext_admin_group; /* Extended Admin. Group */
#define ADJ_PRI_IPV4	0
#define ADJ_BCK_IPV4	1
#define ADJ_PRI_IPV6	2
#define ADJ_BCK_IPV6	3
#define LS_ADJ_MAX	4
	struct ls_adjacency {		/* (LAN)-Adjacency SID for OSPF */
		uint32_t sid;		/* SID as MPLS label or index */
		uint8_t flags;		/* Flags */
		uint8_t weight;		/* Administrative weight */
		union {
			struct in_addr addr;	/* Neighbor @IP for OSPF */
			uint8_t sysid[ISO_SYS_ID_LEN]; /* or Sys-ID for ISIS */
		} neighbor;
	} adj_sid[4];		/* IPv4/IPv6 & Primary/Backup (LAN)-Adj. SID */
#define ADJ_SRV6_PRI_IPV6 0
#define ADJ_SRV6_BCK_IPV6 1
#define ADJ_SRV6_MAX	  2
	struct ls_srv6_adjacency {	    /* Adjacency SID for IS-IS */
		struct in6_addr sid;	    /* SID as IPv6 address */
		uint8_t flags;		    /* Flags */
		uint8_t weight;		    /* Administrative weight */
		uint16_t endpoint_behavior; /* Endpoint Behavior */
		union {
			uint8_t sysid[ISO_SYS_ID_LEN]; /* Sys-ID for ISIS */
		} neighbor;
	} adj_srv6_sid[2];
	uint32_t *srlgs;	/* List of Shared Risk Link Group */
	uint8_t srlg_len;	/* number of SRLG in the list */
};

/* Link State flags to indicate which Prefix parameters are valid */
#define LS_PREF_UNSET		0x00
#define LS_PREF_IGP_FLAG	0x01
#define LS_PREF_ROUTE_TAG	0x02
#define LS_PREF_EXTENDED_TAG	0x04
#define LS_PREF_METRIC		0x08
#define LS_PREF_SR		0x10

/* Link State Prefix */
struct ls_prefix {
	uint8_t flags;			/* Flag for parameters validity */
	struct ls_node_id adv;		/* Adv. Router of this Link State */
	struct prefix pref;		/* IPv4 or IPv6 prefix */
	uint8_t igp_flag;		/* IGP Flags associated to the prefix */
	uint32_t route_tag;		/* IGP Route Tag */
	uint64_t extended_tag;		/* IGP Extended Route Tag */
	uint32_t metric;		/* Route metric for this prefix */
	struct ls_sid {
		uint32_t sid;		/* Segment Routing ID */
		uint8_t sid_flag;	/* Segment Routing Flags */
		uint8_t algo;		/* Algorithm for Segment Routing */
	} sr;
};

/**
 * Create a new Link State Node. Structure is dynamically allocated.
 *
 * @param adv	Mandatory Link State Node ID i.e. advertise router information
 * @param rid	Router ID as IPv4 address
 * @param rid6	Router ID as IPv6 address
 *
 * @return	New Link State Node
 */
extern struct ls_node *ls_node_new(struct ls_node_id adv, struct in_addr rid,
				   struct in6_addr rid6);

/**
 * Remove Link State Node. Data structure is freed.
 *
 * @param node	      Pointer to a valid Link State Node structure
 */
extern void ls_node_del(struct ls_node *node);

/**
 * Check if two Link State Nodes are equal. Note that this routine has the same
 * return value sense as '==' (which is different from a comparison).
 *
 * @param n1	First Link State Node to be compare
 * @param n2	Second Link State Node to be compare
 *
 * @return	1 if equal, 0 otherwise
 */
extern int ls_node_same(struct ls_node *n1, struct ls_node *n2);

/**
 * Create a new Link State Attributes. Structure is dynamically allocated.
 * At least one of parameters MUST be valid and not equal to 0.
 *
 * @param adv		Mandatory Link State Node ID i.e. advertise router ID
 * @param local		Local IPv4 address
 * @param local6	Local Ipv6 address
 * @param local_id	Local Identifier
 *
 * @return		New Link State Attributes
 */
extern struct ls_attributes *ls_attributes_new(struct ls_node_id adv,
					       struct in_addr local,
					       struct in6_addr local6,
					       uint32_t local_id);

/**
 * Remove SRLGs from Link State Attributes if defined.
 *
 * @param attr	Pointer to a valid Link State Attribute structure
 */
extern void ls_attributes_srlg_del(struct ls_attributes *attr);

/**
 * Remove Link State Attributes. Data structure is freed.
 *
 * @param attr	Pointer to a valid Link State Attribute structure
 */
extern void ls_attributes_del(struct ls_attributes *attr);

/**
 * Check if two Link State Attributes are equal. Note that this routine has the
 * same return value sense as '==' (which is different from a comparison).
 *
 * @param a1	First Link State Attributes to be compare
 * @param a2	Second Link State Attributes to be compare
 *
 * @return	1 if equal, 0 otherwise
 */
extern int ls_attributes_same(struct ls_attributes *a1,
			      struct ls_attributes *a2);

/**
 * Create a new Link State Prefix. Structure is dynamically allocated.
 *
 * @param adv	Mandatory Link State Node ID i.e. advertise router ID
 * @param p	Mandatory Prefix
 *
 * @return	New Link State Prefix
 */
extern struct ls_prefix *ls_prefix_new(struct ls_node_id adv, struct prefix *p);

/**
 * Remove Link State Prefix. Data Structure is freed.
 *
 * @param pref	Pointer to a valid Link State Attribute Prefix.
 */
extern void ls_prefix_del(struct ls_prefix *pref);

/**
 * Check if two Link State Prefix are equal. Note that this routine has the
 * same return value sense as '==' (which is different from a comparison).
 *
 * @param p1	First Link State Prefix to be compare
 * @param p2	Second Link State Prefix to be compare
 *
 * @return	1 if equal, 0 otherwise
 */
extern int ls_prefix_same(struct ls_prefix *p1, struct ls_prefix *p2);

/**
 * In addition a Graph model is defined as an overlay on top of link state
 * database in order to ease Path Computation algorithm implementation.
 * Denoted G(V, E), a graph is composed by a list of Vertices (V) which
 * represents the network Node and a list of Edges (E) which represents node
 * Link. An additional list of prefixes (P) is also added.
 * A prefix (P) is also attached to the Vertex (V) which advertise it.
 *
 * Vertex (V) contains the list of outgoing Edges (E) that connect this Vertex
 * with its direct neighbors and the list of incoming Edges (E) that connect
 * the direct neighbors to this Vertex. Indeed, the Edge (E) is unidirectional,
 * thus, it is necessary to add 2 Edges to model a bidirectional relation
 * between 2 Vertices.
 *
 * Edge (E) contains the source and destination Vertex that this Edge
 * is connecting.
 *
 * A unique Key is used to identify both Vertices and Edges within the Graph.
 * An easy way to build this key is to used the IP address: i.e. loopback
 * address for Vertices and link IP address for Edges.
 *
 *      --------------     ---------------------------    --------------
 *      | Connected  |---->| Connected Edge Va to Vb |--->| Connected  |
 *  --->|  Vertex    |     ---------------------------    |  Vertex    |---->
 *      |            |                                    |            |
 *      | - Key (Va) |                                    | - Key (Vb) |
 *  <---| - Vertex   |     ---------------------------    | - Vertex   |<----
 *      |            |<----| Connected Edge Vb to Va |<---|            |
 *      --------------     ---------------------------    --------------
 *
 */

enum ls_status { UNSET = 0, NEW, UPDATE, DELETE, SYNC, ORPHAN };
enum ls_type { GENERIC = 0, VERTEX, EDGE, SUBNET };

/* Link State Vertex structure */
PREDECL_RBTREE_UNIQ(vertices);
struct ls_vertex {
	enum ls_type type;		/* Link State Type */
	enum ls_status status;		/* Status of the Vertex in the TED */
	struct vertices_item entry;	/* Entry in RB Tree */
	uint64_t key;			/* Unique Key identifier */
	struct ls_node *node;		/* Link State Node */
	struct list *incoming_edges;	/* List of incoming Link State links */
	struct list *outgoing_edges;	/* List of outgoing Link State links */
	struct list *prefixes;		/* List of advertised prefix */
};

/* Link State Edge Key structure */
struct ls_edge_key {
	uint8_t family;
	union {
		struct in_addr addr;
		struct in6_addr addr6;
		uint64_t link_id;
	} k;
};

/* Link State Edge structure */
PREDECL_RBTREE_UNIQ(edges);
struct ls_edge {
	enum ls_type type;		/* Link State Type */
	enum ls_status status;		/* Status of the Edge in the TED */
	struct edges_item entry;	/* Entry in RB tree */
	struct ls_edge_key key;		/* Unique Key identifier */
	struct ls_attributes *attributes;	/* Link State attributes */
	struct ls_vertex *source;	/* Pointer to the source Vertex */
	struct ls_vertex *destination;	/* Pointer to the destination Vertex */
};

/* Link State Subnet structure */
PREDECL_RBTREE_UNIQ(subnets);
struct ls_subnet {
	enum ls_type type;		/* Link State Type */
	enum ls_status status;		/* Status of the Subnet in the TED */
	struct subnets_item entry;	/* Entry in RB tree */
	struct prefix key;		/* Unique Key identifier */
	struct ls_prefix *ls_pref;	/* Link State Prefix */
	struct ls_vertex *vertex;	/* Back pointer to the Vertex owner */
};

/* Declaration of Vertices, Edges and Prefixes RB Trees */
macro_inline int vertex_cmp(const struct ls_vertex *node1,
			    const struct ls_vertex *node2)
{
	return numcmp(node1->key, node2->key);
}
DECLARE_RBTREE_UNIQ(vertices, struct ls_vertex, entry, vertex_cmp);

macro_inline int edge_cmp(const struct ls_edge *edge1,
			  const struct ls_edge *edge2)
{
	if (edge1->key.family != edge2->key.family)
		return numcmp(edge1->key.family, edge2->key.family);

	switch (edge1->key.family) {
	case AF_INET:
		return memcmp(&edge1->key.k.addr, &edge2->key.k.addr, 4);
	case AF_INET6:
		return memcmp(&edge1->key.k.addr6, &edge2->key.k.addr6, 16);
	case AF_LOCAL:
		return numcmp(edge1->key.k.link_id, edge2->key.k.link_id);
	default:
		return 0;
	}
}
DECLARE_RBTREE_UNIQ(edges, struct ls_edge, entry, edge_cmp);

/*
 * Prefix comparison are done to the host part so, 10.0.0.1/24
 * and 10.0.0.2/24 are considered different
 */
macro_inline int subnet_cmp(const struct ls_subnet *a,
			    const struct ls_subnet *b)
{
	if (a->key.family != b->key.family)
		return numcmp(a->key.family, b->key.family);

	if (a->key.prefixlen != b->key.prefixlen)
		return numcmp(a->key.prefixlen, b->key.prefixlen);

	if (a->key.family == AF_INET)
		return memcmp(&a->key.u.val, &b->key.u.val, 4);

	return memcmp(&a->key.u.val, &b->key.u.val, 16);
}
DECLARE_RBTREE_UNIQ(subnets, struct ls_subnet, entry, subnet_cmp);

/* Link State TED Structure */
struct ls_ted {
	uint32_t key;			/* Unique identifier */
	char name[MAX_NAME_LENGTH];	/* Name of this graph. Could be null */
	uint32_t as_number;		/* AS number of the modeled network */
	struct ls_vertex *self;		/* Vertex of the FRR instance */
	struct vertices_head vertices;	/* List of Vertices */
	struct edges_head edges;	/* List of Edges */
	struct subnets_head subnets;	/* List of Subnets */
};

/* Generic Link State Element */
struct ls_element {
	enum ls_type type;		/* Link State Element Type */
	enum ls_status status;		/* Link State Status in the TED */
	void *data;			/* Link State payload */
};

/**
 * Add new vertex to the Link State DB. Vertex is created from the Link State
 * Node. Vertex data structure is dynamically allocated.
 *
 * @param ted	Traffic Engineering Database structure
 * @param node	Link State Node
 *
 * @return	New Vertex or NULL in case of error
 */
extern struct ls_vertex *ls_vertex_add(struct ls_ted *ted,
				       struct ls_node *node);

/**
 * Delete Link State Vertex. This function clean internal Vertex lists (incoming
 * and outgoing Link State Edge and Link State Subnet). Vertex Data structure
 * is freed but not the Link State Node. Link State DB is not modified if Vertex
 * is NULL or not found in the Data Base. Note that referenced to Link State
 * Edges & SubNets are not removed as they could be connected to other Vertices.
 *
 * @param ted		Traffic Engineering Database structure
 * @param vertex	Link State Vertex to be removed
 */
extern void ls_vertex_del(struct ls_ted *ted, struct ls_vertex *vertex);

/**
 * Delete Link State Vertex as ls_vertex_del() but also removed associated
 * Link State Node.
 *
 * @param ted		Traffic Engineering Database structure
 * @param vertex	Link State Vertex to be removed
 */
extern void ls_vertex_del_all(struct ls_ted *ted, struct ls_vertex *vertex);

/**
 * Update Vertex with the Link State Node. A new vertex is created if no one
 * corresponds to the Link State Node.
 *
 * @param ted	Link State Data Base
 * @param node	Link State Node to be updated
 *
 * @return	Updated Link State Vertex or Null in case of error
 */
extern struct ls_vertex *ls_vertex_update(struct ls_ted *ted,
					  struct ls_node *node);

/**
 * Clean Vertex structure by removing all Edges and Subnets marked as ORPHAN
 * from this vertex. Link State Update message is sent if zclient is not NULL.
 *
 * @param ted		Link State Data Base
 * @param vertex	Link State Vertex to be cleaned
 * @param zclient	Reference to Zebra Client
 */
extern void ls_vertex_clean(struct ls_ted *ted, struct ls_vertex *vertex,
			    struct zclient *zclient);

/**
 * This function convert the ISIS ISO system ID into a 64 bits unsigned integer
 * following the architecture dependent byte order.
 *
 * @param sysid The ISO system ID
 * @return	Key as 64 bits unsigned integer
 */
extern uint64_t sysid_to_key(const uint8_t sysid[ISO_SYS_ID_LEN]);

/**
 * Find Vertex in the Link State DB by its unique key.
 *
 * @param ted	Link State Data Base
 * @param key	Vertex Key different from 0
 *
 * @return	Vertex if found, NULL otherwise
 */
extern struct ls_vertex *ls_find_vertex_by_key(struct ls_ted *ted,
					       const uint64_t key);

/**
 * Find Vertex in the Link State DB by its Link State Node.
 *
 * @param ted	Link State Data Base
 * @param nid	Link State Node ID
 *
 * @return	Vertex if found, NULL otherwise
 */
extern struct ls_vertex *ls_find_vertex_by_id(struct ls_ted *ted,
					      struct ls_node_id nid);

/**
 * Check if two Vertices are equal. Note that this routine has the same return
 * value sense as '==' (which is different from a comparison).
 *
 * @param v1	First vertex to compare
 * @param v2	Second vertex to compare
 *
 * @return	1 if equal, 0 otherwise
 */
extern int ls_vertex_same(struct ls_vertex *v1, struct ls_vertex *v2);

/**
 * Add new Edge to the Link State DB. Edge is created from the Link State
 * Attributes. Edge data structure is dynamically allocated.
 *
 * @param ted		Link State Data Base
 * @param attributes	Link State attributes
 *
 * @return		New Edge or NULL in case of error
 */
extern struct ls_edge *ls_edge_add(struct ls_ted *ted,
				   struct ls_attributes *attributes);

/**
 * Update the Link State Attributes information of an existing Edge. If there is
 * no corresponding Edge in the Link State Data Base, a new Edge is created.
 *
 * @param ted		Link State Data Base
 * @param attributes	Link State Attributes
 *
 * @return		Updated Link State Edge, or NULL in case of error
 */
extern struct ls_edge *ls_edge_update(struct ls_ted *ted,
				      struct ls_attributes *attributes);

/**
 * Check if two Edges are equal. Note that this routine has the same return
 * value sense as '==' (which is different from a comparison).
 *
 * @param e1	First edge to compare
 * @param e2	Second edge to compare
 *
 * @return	1 if equal, 0 otherwise
 */
extern int ls_edge_same(struct ls_edge *e1, struct ls_edge *e2);

/**
 * Remove Edge from the Link State DB. Edge data structure is freed but not the
 * Link State Attributes data structure. Link State DB is not modified if Edge
 * is NULL or not found in the Data Base.
 *
 * @param ted	Link State Data Base
 * @param edge	Edge to be removed
 */
extern void ls_edge_del(struct ls_ted *ted, struct ls_edge *edge);

/**
 * Remove Edge and associated Link State Attributes from the Link State DB.
 * Link State DB is not modified if Edge is NULL or not found.
 *
 * @param ted	Link State Data Base
 * @param edge	Edge to be removed
 */
extern void ls_edge_del_all(struct ls_ted *ted, struct ls_edge *edge);

/**
 * Find Edge in the Link State Data Base by Edge key.
 *
 * @param ted	Link State Data Base
 * @param key	Edge key
 *
 * @return	Edge if found, NULL otherwise
 */
extern struct ls_edge *ls_find_edge_by_key(struct ls_ted *ted,
					   const struct ls_edge_key key);

/**
 * Find Edge in the Link State Data Base by the source (local IPv4 or IPv6
 * address or local ID) informations of the Link State Attributes
 *
 * @param ted		Link State Data Base
 * @param attributes	Link State Attributes
 *
 * @return		Edge if found, NULL otherwise
 */
extern struct ls_edge *
ls_find_edge_by_source(struct ls_ted *ted, struct ls_attributes *attributes);

/**
 * Find Edge in the Link State Data Base by the destination (remote IPv4 or IPv6
 * address of remote ID) information of the Link State Attributes
 *
 * @param ted		Link State Data Base
 * @param attributes	Link State Attributes
 *
 * @return		Edge if found, NULL otherwise
 */
extern struct ls_edge *
ls_find_edge_by_destination(struct ls_ted *ted,
			    struct ls_attributes *attributes);

/**
 * Add new Subnet to the Link State DB. Subnet is created from the Link State
 * prefix. Subnet data structure is dynamically allocated.
 *
 * @param ted	Link State Data Base
 * @param pref	Link State Prefix
 *
 * @return	New Subnet
 */
extern struct ls_subnet *ls_subnet_add(struct ls_ted *ted,
				       struct ls_prefix *pref);

/**
 * Update the Link State Prefix information of an existing Subnet. If there is
 * no corresponding Subnet in the Link State Data Base, a new Subnet is created.
 *
 * @param ted	Link State Data Base
 * @param pref	Link State Prefix
 *
 * @return	Updated Link State Subnet, or NULL in case of error
 */
extern struct ls_subnet *ls_subnet_update(struct ls_ted *ted,
					  struct ls_prefix *pref);

/**
 * Check if two Subnets are equal. Note that this routine has the same return
 * value sense as '==' (which is different from a comparison).
 *
 * @param s1	First subnet to compare
 * @param s2	Second subnet to compare
 *
 * @return	1 if equal, 0 otherwise
 */
extern int ls_subnet_same(struct ls_subnet *s1, struct ls_subnet *s2);

/**
 * Remove Subnet from the Link State DB. Subnet data structure is freed but
 * not the Link State prefix data structure. Link State DB is not modified
 * if Subnet is NULL or not found in the Data Base.
 *
 * @param ted		Link State Data Base
 * @param subnet	Subnet to be removed
 */
extern void ls_subnet_del(struct ls_ted *ted, struct ls_subnet *subnet);

/**
 * Remove Subnet and the associated Link State Prefix from the Link State DB.
 * Link State DB is not modified if Subnet is NULL or not found.
 *
 * @param ted		Link State Data Base
 * @param subnet	Subnet to be removed
 */
extern void ls_subnet_del_all(struct ls_ted *ted, struct ls_subnet *subnet);

/**
 * Find Subnet in the Link State Data Base by prefix.
 *
 * @param ted		Link State Data Base
 * @param prefix	Link State Prefix
 *
 * @return		Subnet if found, NULL otherwise
 */
extern struct ls_subnet *ls_find_subnet(struct ls_ted *ted,
					const struct prefix *prefix);

/**
 * Create a new Link State Data Base.
 *
 * @param key	Unique key of the data base. Must be different from 0
 * @param name	Name of the data base (may be NULL)
 * @param asn	AS Number for this data base. 0 if unknown
 *
 * @return	New Link State Database or NULL in case of error
 */
extern struct ls_ted *ls_ted_new(const uint32_t key, const char *name,
				 uint32_t asn);

/**
 * Delete existing Link State Data Base. Vertices, Edges, and Subnets are not
 * removed.
 *
 * @param ted	Link State Data Base
 */
extern void ls_ted_del(struct ls_ted *ted);

/**
 * Delete all Link State Vertices, Edges and SubNets and the Link State DB.
 *
 * @param ted	Link State Data Base
 */
extern void ls_ted_del_all(struct ls_ted **ted);

/**
 * Clean Link State Data Base by removing all Vertices, Edges and SubNets marked
 * as ORPHAN.
 *
 * @param ted	Link State Data Base
 */
extern void ls_ted_clean(struct ls_ted *ted);

/**
 * Connect Source and Destination Vertices by given Edge. Only non NULL source
 * and destination vertices are connected.
 *
 * @param src	Link State Source Vertex
 * @param dst	Link State Destination Vertex
 * @param edge	Link State Edge. Must not be NULL
 */
extern void ls_connect_vertices(struct ls_vertex *src, struct ls_vertex *dst,
				struct ls_edge *edge);

/**
 * Connect Link State Edge to the Link State Vertex which could be a Source or
 * a Destination Vertex.
 *
 * @param vertex	Link State Vertex to be connected. Must not be NULL
 * @param edge		Link State Edge connection. Must not be NULL
 * @param source	True for a Source, false for a Destination Vertex
 */
extern void ls_connect(struct ls_vertex *vertex, struct ls_edge *edge,
		       bool source);

/**
 * Disconnect Link State Edge from the Link State Vertex which could be a
 * Source or a Destination Vertex.
 *
 * @param vertex	Link State Vertex to be connected. Must not be NULL
 * @param edge		Link State Edge connection. Must not be NULL
 * @param source	True for a Source, false for a Destination Vertex
 */
extern void ls_disconnect(struct ls_vertex *vertex, struct ls_edge *edge,
			  bool source);

/**
 * Disconnect Link State Edge from both Source and Destination Vertex.
 *
 * @param edge		Link State Edge to be disconnected
 */
extern void ls_disconnect_edge(struct ls_edge *edge);


/**
 * The Link State Message is defined to convey Link State parameters from
 * the routing protocol (OSPF or IS-IS) to other daemons e.g. BGP.
 *
 * The structure is composed of:
 *  - Event of the message:
 *    - Sync: Send the whole LS DB following a request
 *    - Add: Send the a new Link State element
 *    -  Update: Send an update of an existing Link State element
 *    - Delete: Indicate that the given Link State element is removed
 *  - Type of Link State element: Node, Attribute or Prefix
 *  - Remote node id when known
 *  - Data: Node, Attributes or Prefix
 *
 * A Link State Message can carry only one Link State Element (Node, Attributes
 * of Prefix) at once, and only one Link State Message is sent through ZAPI
 * Opaque Link State type at once.
 */

/* ZAPI Opaque Link State Message Event */
#define LS_MSG_EVENT_UNDEF	0
#define LS_MSG_EVENT_SYNC	1
#define LS_MSG_EVENT_ADD	2
#define LS_MSG_EVENT_UPDATE	3
#define LS_MSG_EVENT_DELETE	4

/* ZAPI Opaque Link State Message sub-Type */
#define LS_MSG_TYPE_NODE	1
#define LS_MSG_TYPE_ATTRIBUTES	2
#define LS_MSG_TYPE_PREFIX	3

/* Link State Message */
struct ls_message {
	uint8_t event;		/* Message Event: Sync, Add, Update, Delete */
	uint8_t type;		/* Message Data Type: Node, Attribute, Prefix */
	struct ls_node_id remote_id;	/* Remote Link State Node ID */
	union {
		struct ls_node *node;		/* Link State Node */
		struct ls_attributes *attr;	/* Link State Attributes */
		struct ls_prefix *prefix;	/* Link State Prefix */
	} data;
};

/**
 * Register Link State daemon as a server or client for Zebra OPAQUE API.
 *
 * @param zclient  Zebra client structure
 * @param server   Register daemon as a server (true) or as a client (false)
 *
 * @return	   0 if success, -1 otherwise
 */
extern int ls_register(struct zclient *zclient, bool server);

/**
 * Unregister Link State daemon as a server or client for Zebra OPAQUE API.
 *
 * @param zclient  Zebra client structure
 * @param server   Unregister daemon as a server (true) or as a client (false)
 *
 * @return	   0 if success, -1 otherwise
 */
extern int ls_unregister(struct zclient *zclient, bool server);

/**
 * Send Link State SYNC message to request the complete Link State Database.
 *
 * @param zclient	Zebra client
 *
 * @return		0 if success, -1 otherwise
 */
extern int ls_request_sync(struct zclient *zclient);

/**
 * Parse Link State Message from stream. Used this function once receiving a
 * new ZAPI Opaque message of type Link State.
 *
 * @param s	Stream buffer. Must not be NULL.
 *
 * @return	New Link State Message or NULL in case of error
 */
extern struct ls_message *ls_parse_msg(struct stream *s);

/**
 * Delete existing message. Data structure is freed.
 *
 * @param msg	Link state message to be deleted
 */
extern void ls_delete_msg(struct ls_message *msg);

/**
 * Send Link State Message as new ZAPI Opaque message of type Link State.
 * If destination is not NULL, message is sent as Unicast otherwise it is
 * broadcast to all registered daemon.
 *
 * @param zclient	Zebra Client
 * @param msg		Link State Message to be sent
 * @param dst		Destination daemon for unicast message,
 *			NULL for broadcast message
 *
 * @return		0 on success, -1 otherwise
 */
extern int ls_send_msg(struct zclient *zclient, struct ls_message *msg,
		       struct zapi_opaque_reg_info *dst);

/**
 * Create a new Link State Message from a Link State Vertex. If Link State
 * Message is NULL, a new data structure is dynamically allocated.
 *
 * @param msg		Link State Message to be filled or NULL
 * @param vertex	Link State Vertex. Must not be NULL
 *
 * @return		New Link State Message msg parameter is NULL or pointer
 *			to the provided Link State Message
 */
extern struct ls_message *ls_vertex2msg(struct ls_message *msg,
					struct ls_vertex *vertex);

/**
 * Create a new Link State Message from a Link State Edge. If Link State
 * Message is NULL, a new data structure is dynamically allocated.
 *
 * @param msg		Link State Message to be filled or NULL
 * @param edge		Link State Edge. Must not be NULL
 *
 * @return		New Link State Message msg parameter is NULL or pointer
 *			to the provided Link State Message
 */
extern struct ls_message *ls_edge2msg(struct ls_message *msg,
				      struct ls_edge *edge);

/**
 * Create a new Link State Message from a Link State Subnet. If Link State
 * Message is NULL, a new data structure is dynamically allocated.
 *
 * @param msg		Link State Message to be filled or NULL
 * @param subnet	Link State Subnet. Must not be NULL
 *
 * @return		New Link State Message msg parameter is NULL or pointer
 *			to the provided Link State Message
 */
extern struct ls_message *ls_subnet2msg(struct ls_message *msg,
					struct ls_subnet *subnet);

/**
 * Convert Link State Message into Vertex and update TED accordingly to
 * the message event: SYNC, ADD, UPDATE or DELETE.
 *
 * @param ted		Link State Database
 * @param msg		Link State Message
 * @param delete	True to delete the Link State Vertex from the Database,
 *                      False otherwise. If true, return value is NULL in case
 *                      of deletion.
 *
 * @return	Vertex if success, NULL otherwise or if Vertex is removed
 */
extern struct ls_vertex *ls_msg2vertex(struct ls_ted *ted,
				       struct ls_message *msg, bool delete);

/**
 * Convert Link State Message into Edge and update TED accordingly to
 * the message event: SYNC, ADD, UPDATE or DELETE.
 *
 * @param ted		Link State Database
 * @param msg		Link State Message
 * @param delete	True to delete the Link State Edge from the Database,
 *                      False otherwise. If true, return value is NULL in case
 *                      of deletion.
 *
 * @return	Edge if success, NULL otherwise or if Edge is removed
 */
extern struct ls_edge *ls_msg2edge(struct ls_ted *ted, struct ls_message *msg,
				   bool delete);

/**
 * Convert Link State Message into Subnet and update TED accordingly to
 * the message event: SYNC, ADD, UPDATE or DELETE.
 *
 * @param ted		Link State Database
 * @param msg		Link State Message
 * @param delete	True to delete the Link State Subnet from the Database,
 *                      False otherwise. If true, return value is NULL in case
 *                      of deletion.
 *
 * @return	Subnet if success, NULL otherwise or if Subnet is removed
 */
extern struct ls_subnet *ls_msg2subnet(struct ls_ted *ted,
				       struct ls_message *msg, bool delete);

/**
 * Convert Link State Message into Link State element (Vertex, Edge or Subnet)
 * and update TED accordingly to the message event: SYNC, ADD, UPDATE or DELETE.
 *
 * @param ted		Link State Database
 * @param msg		Link State Message
 * @param delete	True to delete the Link State Element from the Database,
 *                      False otherwise. If true, return value is NULL in case
 *                      of deletion.
 *
 * @return	Element if success, NULL otherwise or if Element is removed
 */
extern struct ls_element *ls_msg2ted(struct ls_ted *ted, struct ls_message *msg,
				     bool delete);

/**
 * Convert stream buffer into Link State element (Vertex, Edge or Subnet) and
 * update TED accordingly to the message event: SYNC, ADD, UPDATE or DELETE.
 *
 * @param ted		Link State Database
 * @param s		Stream buffer
 * @param delete	True to delete the Link State Element from the Database,
 *                      False otherwise. If true, return value is NULL in case
 *                      of deletion.
 *
 * @return	Element if success, NULL otherwise or if Element is removed
 */
extern struct ls_element *ls_stream2ted(struct ls_ted *ted, struct stream *s,
					bool delete);

/**
 * Send all the content of the Link State Data Base to the given destination.
 * Link State content is sent is this order: Vertices, Edges, Subnet.
 * This function must be used when a daemon request a Link State Data Base
 * Synchronization.
 *
 * @param ted		Link State Data Base. Must not be NULL
 * @param zclient	Zebra Client. Must not be NULL
 * @param dst		Destination FRR daemon. Must not be NULL
 *
 * @return		0 on success, -1 otherwise
 */
extern int ls_sync_ted(struct ls_ted *ted, struct zclient *zclient,
		       struct zapi_opaque_reg_info *dst);

struct json_object;
struct vty;
/**
 * Show Link State Vertex information. If both vty and json are specified,
 * Json format output supersedes standard vty output.
 *
 * @param vertex	Link State Vertex to show. Must not be NULL
 * @param vty		Pointer to vty output, could be NULL
 * @param json		Pointer to json output, could be NULL
 * @param verbose	Set to true for more detail
 */
extern void ls_show_vertex(struct ls_vertex *vertex, struct vty *vty,
			   struct json_object *json, bool verbose);

/**
 * Show all Link State Vertices information. If both vty and json are specified,
 * Json format output supersedes standard vty output.
 *
 * @param ted		Link State Data Base. Must not be NULL
 * @param vty		Pointer to vty output, could be NULL
 * @param json		Pointer to json output, could be NULL
 * @param verbose	Set to true for more detail
 */
extern void ls_show_vertices(struct ls_ted *ted, struct vty *vty,
			     struct json_object *json, bool verbose);

/**
 * Show Link State Edge information. If both vty and json are specified,
 * Json format output supersedes standard vty output.
 *
 * @param edge		Link State Edge to show. Must not be NULL
 * @param vty		Pointer to vty output, could be NULL
 * @param json		Pointer to json output, could be NULL
 * @param verbose	Set to true for more detail
 */
extern void ls_show_edge(struct ls_edge *edge, struct vty *vty,
			 struct json_object *json, bool verbose);

/**
 * Show all Link State Edges information. If both vty and json are specified,
 * Json format output supersedes standard vty output.
 *
 * @param ted		Link State Data Base. Must not be NULL
 * @param vty		Pointer to vty output, could be NULL
 * @param json		Pointer to json output, could be NULL
 * @param verbose	Set to true for more detail
 */
extern void ls_show_edges(struct ls_ted *ted, struct vty *vty,
			  struct json_object *json, bool verbose);

/**
 * Show Link State Subnets information. If both vty and json are specified,
 * Json format output supersedes standard vty output.
 *
 * @param subnet	Link State Subnet to show. Must not be NULL
 * @param vty		Pointer to vty output, could be NULL
 * @param json		Pointer to json output, could be NULL
 * @param verbose	Set to true for more detail
 */
extern void ls_show_subnet(struct ls_subnet *subnet, struct vty *vty,
			   struct json_object *json, bool verbose);

/**
 * Show all Link State Subnet information. If both vty and json are specified,
 * Json format output supersedes standard vty output.
 *
 * @param ted		Link State Data Base. Must not be NULL
 * @param vty		Pointer to vty output, could be NULL
 * @param json		Pointer to json output, could be NULL
 * @param verbose	Set to true for more detail
 */
extern void ls_show_subnets(struct ls_ted *ted, struct vty *vty,
			    struct json_object *json, bool verbose);

/**
 * Show Link State Data Base information. If both vty and json are specified,
 * Json format output supersedes standard vty output.
 *
 * @param ted		Link State Data Base to show. Must not be NULL
 * @param vty		Pointer to vty output, could be NULL
 * @param json		Pointer to json output, could be NULL
 * @param verbose	Set to true for more detail
 */
extern void ls_show_ted(struct ls_ted *ted, struct vty *vty,
			struct json_object *json, bool verbose);

/**
 * Dump all Link State Data Base elements for debugging purposes
 *
 * @param ted	Link State Data Base. Must not be NULL
 *
 */
extern void ls_dump_ted(struct ls_ted *ted);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_LINK_STATE_H_ */
