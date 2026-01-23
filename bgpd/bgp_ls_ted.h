// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Link-State Traffic Engineering Database (RFC 9552)
 * Copyright (C) 2025 Carmine Scarpitta
 *
 * This file implements the BGP-LS TED management functions for storing
 * topology information learned from BGP-LS routes. The TED provides a
 * graph-based view of the network for applications (PCE, SDN controllers).
 */

#ifndef _FRR_BGP_LS_TED_H
#define _FRR_BGP_LS_TED_H

#define UNKNOWN LS_UNKNOWN
#include "lib/link_state.h"
#undef UNKNOWN

/* Forward declarations */
struct bgp;
struct bgp_ls_nlri;

/*
 * Populate BGP-LS Node Attributes from Link State Node
 *
 * @param ls_node Link State node from TED
 * @param attr BGP-LS node attribute structure to populate
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_populate_node_attr(struct ls_node *ls_node, struct bgp_ls_node_attr *attr);

/*
 * Populate BGP-LS Link Attributes from Link State Attributes
 *
 * @param ls_attr Link State attributes from TED
 * @param attr BGP-LS link attribute structure to populate
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_populate_link_attr(struct ls_attributes *ls_attr, struct bgp_ls_link_attr *attr);

/*
 * Populate BGP-LS Prefix Attributes from Link State Prefix
 *
 * @param ls_prefix Link State prefix from TED
 * @param attr BGP-LS prefix attribute structure to populate
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_populate_prefix_attr(struct ls_prefix *ls_prefix,
				       struct bgp_ls_prefix_attr *attr);

/*
 * ===========================================================================
 * IGP Origination Functions
 * ===========================================================================
 */

/*
 * Originate Node NLRI from IGP router information
 *
 * Creates a BGP-LS Node NLRI from IGP router advertisements
 * (ISIS LSP or OSPF Router-LSA) and installs it in the RIB.
 *
 * @param bgp - BGP instance
 * @param protocol_id - IGP protocol (ISIS/OSPF)
 * @param router_id - IGP router ID
 * @param router_id_len - Length of router ID
 * @param area_id - IGP area/level identifier
 * @param vertex - Link State vertex (for attribute population)
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_originate_node(struct bgp *bgp, uint8_t protocol_id, uint8_t *router_id,
				 uint16_t router_id_len, uint32_t area_id,
				 struct ls_vertex *vertex);

/*
 * Originate Link NLRI from IGP adjacency information
 *
 * Creates a BGP-LS Link NLRI from IGP adjacency advertisements
 * (ISIS IS Reachability or OSPF Link-LSA) and installs it in the RIB.
 *
 * @param bgp - BGP instance
 * @param protocol_id - IGP protocol (ISIS/OSPF)
 * @param local_router_id - Local router IGP ID
 * @param local_router_id_len - Length of local router ID
 * @param remote_router_id - Remote router IGP ID
 * @param remote_router_id_len - Length of remote router ID
 * @param area_id - IGP area/level identifier
 * @param edge - Link State edge (for attribute population)
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_originate_link(struct bgp *bgp, uint8_t protocol_id, uint8_t *local_router_id,
				 uint16_t local_router_id_len, uint8_t *remote_router_id,
				 uint16_t remote_router_id_len, uint32_t area_id,
				 struct ls_edge *edge);

/*
 * Originate Prefix NLRI from IGP prefix information
 *
 * Creates a BGP-LS Prefix NLRI from IGP prefix advertisements
 * (ISIS IP Reachability or OSPF Summary-LSA) and installs it in the RIB.
 *
 * @param bgp - BGP instance
 * @param protocol_id - IGP protocol (ISIS/OSPF)
 * @param router_id - Advertising router IGP ID
 * @param router_id_len - Length of router ID
 * @param prefix - IP prefix
 * @param area_id - IGP area/level identifier
 * @param subnet - Link State subnet (for attribute population)
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_originate_prefix(struct bgp *bgp, uint8_t protocol_id, uint8_t *router_id,
				   uint16_t router_id_len, struct prefix *prefix, uint32_t area_id,
				   struct ls_subnet *subnet);

/*
 * ===========================================================================
 * Link State Message Processing
 * ===========================================================================
 */

/*
 * Process Link State vertex (node) and originate BGP-LS Node NLRI
 *
 * Extracts IGP router information from ls_vertex and calls
 * bgp_ls_originate_node() to create and install BGP-LS route.
 *
 * @param bgp - BGP instance
 * @param vertex - Link State vertex from ls_msg2vertex()
 * @param event - LS_MSG_EVENT_ADD, UPDATE, or DELETE
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_process_vertex(struct bgp *bgp, struct ls_vertex *vertex, uint8_t event);

/*
 * Process Link State edge (link) and originate BGP-LS Link NLRI
 *
 * Extracts IGP adjacency information from ls_edge and calls
 * bgp_ls_originate_link() to create and install BGP-LS route.
 *
 * @param bgp - BGP instance
 * @param edge - Link State edge from ls_msg2edge()
 * @param event - LS_MSG_EVENT_ADD, UPDATE, or DELETE
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_process_edge(struct bgp *bgp, struct ls_edge *edge, uint8_t event);

/*
 * Process Link State subnet (prefix) and originate BGP-LS Prefix NLRI
 *
 * Extracts IGP prefix information from ls_subnet and calls
 * bgp_ls_originate_prefix() to create and install BGP-LS route.
 *
 * @param bgp - BGP instance
 * @param subnet - Link State subnet from ls_msg2subnet()
 * @param event - LS_MSG_EVENT_ADD, UPDATE, or DELETE
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_process_subnet(struct bgp *bgp, struct ls_subnet *subnet, uint8_t event);

/*
 * Withdraw Node NLRI from BGP-LS RIB
 *
 * Removes a BGP-LS Node NLRI from the RIB when the IGP router is removed.
 *
 * @param bgp - BGP instance
 * @param protocol_id - IGP protocol (ISIS/OSPF)
 * @param router_id - IGP router ID
 * @param router_id_len - Length of router ID
 * @param area_id - IGP area/level identifier
 * @return 0 on success, -1 on error
 */
int bgp_ls_withdraw_node(struct bgp *bgp, uint8_t protocol_id, uint8_t *router_id,
			 uint16_t router_id_len, uint32_t area_id, struct ls_vertex *vertex);

int bgp_ls_withdraw_link(struct bgp *bgp, uint8_t protocol_id, uint8_t *local_router_id,
			 uint16_t local_router_id_len, uint8_t *remote_router_id,
			 uint16_t remote_router_id_len, uint32_t area_id, struct ls_edge *edge);

int bgp_ls_withdraw_prefix(struct bgp *bgp, uint8_t protocol_id, uint8_t *router_id,
			   uint16_t router_id_len, struct prefix *prefix, uint32_t area_id,
			   struct ls_subnet *subnet);

/*
 * ===========================================================================
 * Link-State Message Processing
 * ===========================================================================
 */

/*
 * Process link-state message from zebra
 *
 * Handles link-state SYNC/UPDATE messages received from zebra.
 * Parses the message and delegates to bgp_ls_process_message().
 *
 * @param s - Stream containing the message
 * @param msg_type - Message type (LINK_STATE_UPDATE or LINK_STATE_SYNC)
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_process_linkstate_message(struct stream *s, uint8_t msg_type);

/*
 * Process link-state message and update TED
 *
 * Converts message to TED structure (vertex/edge/subnet) and triggers
 * BGP-LS route origination.
 *
 * @param bgp - BGP instance
 * @param msg - Link-state message to process
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_process_message(struct bgp *bgp, struct ls_message *msg);

#endif /* _FRR_BGP_LS_TED_H */
