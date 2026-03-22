// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Link-State Traffic Engineering Database (RFC 9552)
 * Copyright (C) 2025 Carmine Scarpitta
 */

#include <zebra.h>

#include "lib/memory.h"
#include "lib/log.h"
#include "lib/prefix.h"
#include "lib/stream.h"
#define UNKNOWN LS_UNKNOWN
#include "lib/link_state.h"
#undef UNKNOWN

#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_ls.h"
#include "bgpd/bgp_ls_nlri.h"
#include "bgpd/bgp_ls_ted.h"
#include "bgpd/bgp_route.h"

/*
 * ===========================================================================
 * Node Attribute Population
 * ===========================================================================
 */

/*
 * Populate BGP-LS Attributes from Link State Node
 */
int bgp_ls_populate_node_attr(struct ls_node *ls_node, struct bgp_ls_attr *attr)
{
	if (!ls_node || !attr)
		return -1;

	/* Node Flag Bits (TLV 1024) */
	if (CHECK_FLAG(ls_node->flags, LS_NODE_FLAG)) {
		attr->node_flags = ls_node->node_flag;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_NODE_FLAGS_BIT);
	}

	/* Node Name (TLV 1026) */
	if (CHECK_FLAG(ls_node->flags, LS_NODE_NAME) && ls_node->name[0] != '\0') {
		size_t name_len = strlen(ls_node->name);

		attr->node_name = XCALLOC(MTYPE_BGP_LS_ATTR, name_len + 1);
		memcpy(attr->node_name, ls_node->name, name_len + 1);
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_NODE_NAME_BIT);
	}

	/* IPv4 Router-ID (TLV 1028) */
	if (CHECK_FLAG(ls_node->flags, LS_NODE_ROUTER_ID)) {
		attr->ipv4_router_id_local = ls_node->router_id;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_IPV4_ROUTER_ID_LOCAL_BIT);
	}

	/* IPv6 Router-ID (TLV 1029) */
	if (CHECK_FLAG(ls_node->flags, LS_NODE_ROUTER_ID6)) {
		attr->ipv6_router_id_local = ls_node->router_id6;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_IPV6_ROUTER_ID_LOCAL_BIT);
	}

	return 0;
}

/*
 * ===========================================================================
 * Link Attribute Population
 * ===========================================================================
 */

/*
 * Populate BGP-LS Attributes from Link State Attributes
 */
int bgp_ls_populate_link_attr(struct ls_attributes *ls_attr, struct bgp_ls_attr *attr)
{
	if (!ls_attr || !attr)
		return -1;

	/* Administrative Group (TLV 1088) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_ADM_GRP)) {
		attr->admin_group = ls_attr->standard.admin_group;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_ADMIN_GROUP_BIT);
	}

	/* Maximum Link Bandwidth (TLV 1089) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_MAX_BW)) {
		attr->max_link_bw = ls_attr->standard.max_bw;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_MAX_LINK_BW_BIT);
	}

	/* Maximum Reservable Bandwidth (TLV 1090) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_MAX_RSV_BW)) {
		attr->max_resv_bw = ls_attr->standard.max_rsv_bw;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_MAX_RESV_BW_BIT);
	}

	/* Unreserved Bandwidth (TLV 1091) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_UNRSV_BW)) {
		for (int i = 0; i < BGP_LS_MAX_UNRESV_BW; i++)
			attr->unreserved_bw[i] = ls_attr->standard.unrsv_bw[i];
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_UNRESV_BW_BIT);
	}

	/* TE Default Metric (TLV 1092) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_TE_METRIC)) {
		attr->te_metric = ls_attr->standard.te_metric;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_TE_METRIC_BIT);
	}

	/* IGP Metric (TLV 1095) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_METRIC)) {
		/* IGP metric can be 1, 2, or 3 bytes */
		if (ls_attr->metric <= 0xFF)
			attr->igp_metric_len = 1;
		else if (ls_attr->metric <= 0xFFFF)
			attr->igp_metric_len = 2;
		else
			attr->igp_metric_len = 3;
		attr->igp_metric = ls_attr->metric;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_IGP_METRIC_BIT);
	}

	/* Shared Risk Link Group (TLV 1096) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_SRLG) && ls_attr->srlg_len > 0) {
		uint8_t count = ls_attr->srlg_len;

		if (count > BGP_LS_MAX_SRLG)
			count = BGP_LS_MAX_SRLG;

		attr->srlg_count = count;
		attr->srlg_values = XCALLOC(MTYPE_BGP_LS_ATTR, count * sizeof(uint32_t));
		for (uint8_t i = 0; i < count; i++)
			attr->srlg_values[i] = ls_attr->srlgs[i];
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_SRLG_BIT);
	}

	/* Link Name (TLV 1098) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_NAME) && ls_attr->name[0] != '\0') {
		size_t name_len = strlen(ls_attr->name);

		attr->link_name = XCALLOC(MTYPE_BGP_LS_ATTR, name_len + 1);
		memcpy(attr->link_name, ls_attr->name, name_len + 1);
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_LINK_NAME_BIT);
	}

	/* Remote IPv4 Router-ID (TLV 1030) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_REMOTE_ADDR)) {
		attr->ipv4_router_id_remote = ls_attr->standard.remote_addr;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_IPV4_ROUTER_ID_REMOTE_BIT);
	}

	/* Remote IPv6 Router-ID (TLV 1031) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_REMOTE_ADDR6)) {
		attr->ipv6_router_id_remote = ls_attr->standard.remote_addr6;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_IPV6_ROUTER_ID_REMOTE_BIT);
	}

	/* Extended Admin Group (TLV 1093) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_EXT_ADM_GRP)) {
		admin_group_copy(&attr->ext_admin_group, &ls_attr->ext_admin_group);
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_EXT_ADMIN_GROUP_BIT);
	}

	/* Unidirectional Link Delay (TLV 1114) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_DELAY)) {
		attr->delay = ls_attr->extended.delay;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_DELAY_BIT);
	}

	/* Min/Max Unidirectional Link Delay (TLV 1115) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_MIN_MAX_DELAY)) {
		attr->min_delay = ls_attr->extended.min_delay;
		attr->max_delay = ls_attr->extended.max_delay;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_MIN_MAX_DELAY_BIT);
	}

	/* Unidirectional Delay Variation (TLV 1116) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_JITTER)) {
		attr->jitter = ls_attr->extended.jitter;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_JITTER_BIT);
	}

	/* Unidirectional Packet Loss (TLV 1117) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_PACKET_LOSS)) {
		attr->pkt_loss = ls_attr->extended.pkt_loss;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_PKT_LOSS_BIT);
	}

	/* Unidirectional Residual Bandwidth (TLV 1118) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_RSV_BW)) {
		attr->residual_bw = ls_attr->extended.rsv_bw;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_RESIDUAL_BW_BIT);
	}

	/* Unidirectional Available Bandwidth (TLV 1119) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_AVA_BW)) {
		attr->available_bw = ls_attr->extended.ava_bw;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_AVAILABLE_BW_BIT);
	}

	/* Unidirectional Utilized Bandwidth (TLV 1120) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_USE_BW)) {
		attr->utilized_bw = ls_attr->extended.used_bw;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_UTILIZED_BW_BIT);
	}

	return 0;
}

/*
 * ===========================================================================
 * Prefix Attribute Population
 * ===========================================================================
 */

/*
 * Populate BGP-LS Attributes from Link State Prefix
 */
int bgp_ls_populate_prefix_attr(struct ls_prefix *ls_prefix, struct bgp_ls_attr *attr)
{
	if (!ls_prefix || !attr)
		return -1;

	/* IGP Flags (TLV 1152) */
	if (CHECK_FLAG(ls_prefix->flags, LS_PREF_IGP_FLAG)) {
		attr->igp_flags = ls_prefix->igp_flag;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_IGP_FLAGS_BIT);
	}

	/* Route Tags (TLV 1153) - single tag */
	if (CHECK_FLAG(ls_prefix->flags, LS_PREF_ROUTE_TAG)) {
		attr->route_tag_count = 1;
		attr->route_tags = XCALLOC(MTYPE_BGP_LS_ATTR, sizeof(uint32_t));
		attr->route_tags[0] = ls_prefix->route_tag;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_ROUTE_TAG_BIT);
	}

	/* Extended Tags (TLV 1154) - single extended tag */
	if (CHECK_FLAG(ls_prefix->flags, LS_PREF_EXTENDED_TAG)) {
		attr->extended_tag_count = 1;
		attr->extended_tags = XCALLOC(MTYPE_BGP_LS_ATTR, sizeof(uint64_t));
		attr->extended_tags[0] = ls_prefix->extended_tag;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_EXTENDED_TAG_BIT);
	}

	/* Prefix Metric (TLV 1155) */
	if (CHECK_FLAG(ls_prefix->flags, LS_PREF_METRIC)) {
		attr->prefix_metric = ls_prefix->metric;
		attr->present_tlvs |= (1ULL << BGP_LS_ATTR_PREFIX_METRIC_BIT);
	}

	/* Prefix-SID (TLV 1158) */
	if (CHECK_FLAG(ls_prefix->flags, LS_PREF_SR)) {
		if (bgp_ls_attr_prefix_sid_len(ls_prefix->sr.sid_flag) == -1) {
			zlog_warn("BGP-LS: %s TED contains wrong combination of V-Flag and L-Flag for Prefix SID",
				  __func__);
		} else {
			attr->prefix_sid.sid = ls_prefix->sr.sid;
			attr->prefix_sid.sid_flag = ls_prefix->sr.sid_flag;
			attr->prefix_sid.algo = ls_prefix->sr.algo;
			attr->present_tlvs |= (1ULL << BGP_LS_ATTR_PREFIX_SID_BIT);
		}
	}

	return 0;
}

/*
 * ===========================================================================
 * IGP Origination Functions
 * ===========================================================================
 */

static bool bgp_ls_link_valid(struct ls_edge *edge)
{
	if ((CHECK_FLAG(edge->attributes->flags, LS_ATTR_LOCAL_ID) &&
	     CHECK_FLAG(edge->attributes->flags, LS_ATTR_NEIGH_ID)))
		return true;

	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_LOCAL_ADDR) &&
	    CHECK_FLAG(edge->attributes->flags, LS_ATTR_NEIGH_ADDR))
		return true;

	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_LOCAL_ADDR6) &&
	    CHECK_FLAG(edge->attributes->flags, LS_ATTR_NEIGH_ADDR6) &&
	    !IN6_IS_ADDR_LINKLOCAL(&edge->attributes->standard.local6) &&
	    !IN6_IS_ADDR_LINKLOCAL(&edge->attributes->standard.remote6))
		return true;

	return false;
}

/*
 * Originate Node NLRI from IGP router information
 *
 * This function creates a BGP-LS Node NLRI from IGP router data
 * and installs it in the RIB for advertisement to BGP-LS peers.
 */
int bgp_ls_originate_node(struct bgp *bgp, uint8_t protocol_id, uint8_t *router_id,
			  uint16_t router_id_len, uint32_t area_id, struct ls_vertex *vertex)
{
	struct bgp_ls_nlri nlri;
	struct bgp_ls_attr *ls_attr = NULL;
	int ret;

	if (!bgp || !router_id)
		return -1;

	if (!vertex || !vertex->node)
		return -1;

	/* Validate router ID length */
	if (router_id_len < BGP_LS_IGP_ROUTER_ID_MIN_SIZE ||
	    router_id_len > BGP_LS_IGP_ROUTER_ID_MAX_SIZE) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Invalid router ID length %u", router_id_len);
		return -1;
	}

	/* Clear NLRI structure */
	memset(&nlri, 0, sizeof(nlri));

	/* Build Node NLRI */
	nlri.nlri_type = BGP_LS_NLRI_TYPE_NODE;
	nlri.nlri_data.node.protocol_id = protocol_id;
	nlri.nlri_data.node.identifier = 0; /* Instance ID, use 0 for default */

	/* Set Local Node Descriptor */
	nlri.nlri_data.node.local_node.igp_router_id_len = router_id_len;
	memcpy(nlri.nlri_data.node.local_node.igp_router_id, router_id, router_id_len);
	BGP_LS_TLV_SET(nlri.nlri_data.node.local_node.present_tlvs,
		       BGP_LS_NODE_DESC_IGP_ROUTER_BIT);

	/* Set AS Number if available */
	if (CHECK_FLAG(vertex->node->flags, LS_NODE_AS_NUMBER)) {
		nlri.nlri_data.node.local_node.asn = vertex->node->as_number;
		BGP_LS_TLV_SET(nlri.nlri_data.node.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_AS_BIT);
	}

	/* Set OSPF Area ID if OSPF */
	if (protocol_id == BGP_LS_PROTO_OSPFV2 || protocol_id == BGP_LS_PROTO_OSPFV3) {
		nlri.nlri_data.node.local_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.node.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
	}

	/* Populate BGP-LS attributes from Link State vertex */
	ls_attr = bgp_ls_attr_alloc();
	if (bgp_ls_populate_node_attr(vertex->node, ls_attr) < 0) {
		zlog_warn("BGP-LS: Failed to populate Node attributes");
		bgp_ls_attr_free(ls_attr);
		return -1;
	}

	/* Install in RIB */
	ret = bgp_ls_update(bgp, &nlri, ls_attr);
	if (ret < 0) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Failed to originate Node NLRI");
		bgp_ls_attr_free(ls_attr);
		return -1;
	}

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Originated Node NLRI for protocol %u", protocol_id);

	bgp_ls_attr_free(ls_attr);

	return 0;
}


int bgp_ls_withdraw_node(struct bgp *bgp, uint8_t protocol_id, uint8_t *router_id,
			 uint16_t router_id_len, uint32_t area_id, struct ls_vertex *vertex)
{
	struct bgp_ls_nlri nlri;
	int ret;

	if (!bgp || !router_id)
		return -1;

	if (!vertex || !vertex->node)
		return -1;

	/* Validate router ID length */
	if (router_id_len < BGP_LS_IGP_ROUTER_ID_MIN_SIZE ||
	    router_id_len > BGP_LS_IGP_ROUTER_ID_MAX_SIZE) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Invalid router ID length %u", router_id_len);
		return -1;
	}

	/* Clear NLRI structure */
	memset(&nlri, 0, sizeof(nlri));

	/* Build Node NLRI */
	nlri.nlri_type = BGP_LS_NLRI_TYPE_NODE;
	nlri.nlri_data.node.protocol_id = protocol_id;
	nlri.nlri_data.node.identifier = 0; /* Instance ID, use 0 for default */

	/* Set Local Node Descriptor */
	nlri.nlri_data.node.local_node.igp_router_id_len = router_id_len;
	memcpy(nlri.nlri_data.node.local_node.igp_router_id, router_id, router_id_len);
	BGP_LS_TLV_SET(nlri.nlri_data.node.local_node.present_tlvs,
		       BGP_LS_NODE_DESC_IGP_ROUTER_BIT);

	/* Set AS Number if available */
	if (CHECK_FLAG(vertex->node->flags, LS_NODE_AS_NUMBER)) {
		nlri.nlri_data.node.local_node.asn = vertex->node->as_number;
		BGP_LS_TLV_SET(nlri.nlri_data.node.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_AS_BIT);
	}

	/* Set OSPF Area ID if OSPF */
	if (protocol_id == BGP_LS_PROTO_OSPFV2 || protocol_id == BGP_LS_PROTO_OSPFV3) {
		nlri.nlri_data.node.local_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.node.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
	}

	/* Withdraw from RIB */
	ret = bgp_ls_withdraw(bgp, &nlri);
	if (ret < 0) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Failed to withdraw Node NLRI");
		return -1;
	}

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Withdrawn Node NLRI for protocol %u", protocol_id);

	return 0;
}


/*
 * Originate Link NLRI from IGP adjacency information
 *
 * This function creates a BGP-LS Link NLRI from IGP adjacency data
 * and installs it in the RIB for advertisement to BGP-LS peers.
 */
int bgp_ls_originate_link(struct bgp *bgp, uint8_t protocol_id, uint8_t *local_router_id,
			  uint16_t local_router_id_len, uint8_t *remote_router_id,
			  uint16_t remote_router_id_len, uint32_t area_id, struct ls_edge *edge)
{
	struct bgp_ls_nlri nlri;
	struct bgp_ls_attr *ls_attr = NULL;
	int ret;

	if (!bgp || !local_router_id || !remote_router_id)
		return -1;

	if (!edge || !edge->attributes)
		return -1;

	/* Validate router ID lengths */
	if (local_router_id_len < BGP_LS_IGP_ROUTER_ID_MIN_SIZE ||
	    local_router_id_len > BGP_LS_IGP_ROUTER_ID_MAX_SIZE ||
	    remote_router_id_len < BGP_LS_IGP_ROUTER_ID_MIN_SIZE ||
	    remote_router_id_len > BGP_LS_IGP_ROUTER_ID_MAX_SIZE) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Invalid router ID lengths");
		return -1;
	}

	/* Clear NLRI structure */
	memset(&nlri, 0, sizeof(nlri));

	/* Build Link NLRI */
	nlri.nlri_type = BGP_LS_NLRI_TYPE_LINK;
	nlri.nlri_data.link.protocol_id = protocol_id;
	nlri.nlri_data.link.identifier = 0; /* Instance ID, use 0 for default */

	/* Set Local Node Descriptor */
	nlri.nlri_data.link.local_node.igp_router_id_len = local_router_id_len;
	memcpy(nlri.nlri_data.link.local_node.igp_router_id, local_router_id, local_router_id_len);
	BGP_LS_TLV_SET(nlri.nlri_data.link.local_node.present_tlvs,
		       BGP_LS_NODE_DESC_IGP_ROUTER_BIT);

	/* Set AS Number for Local Node if available */
	if (edge->source && edge->source->node &&
	    CHECK_FLAG(edge->source->node->flags, LS_NODE_AS_NUMBER)) {
		nlri.nlri_data.link.local_node.asn = edge->source->node->as_number;
		BGP_LS_TLV_SET(nlri.nlri_data.link.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_AS_BIT);
	}

	/* Set Remote Node Descriptor */
	nlri.nlri_data.link.remote_node.igp_router_id_len = remote_router_id_len;
	memcpy(nlri.nlri_data.link.remote_node.igp_router_id, remote_router_id,
	       remote_router_id_len);
	BGP_LS_TLV_SET(nlri.nlri_data.link.remote_node.present_tlvs,
		       BGP_LS_NODE_DESC_IGP_ROUTER_BIT);

	/* Set AS Number for Remote Node if available */
	if (edge->destination && edge->destination->node &&
	    CHECK_FLAG(edge->destination->node->flags, LS_NODE_AS_NUMBER)) {
		nlri.nlri_data.link.remote_node.asn = edge->destination->node->as_number;
		BGP_LS_TLV_SET(nlri.nlri_data.link.remote_node.present_tlvs,
			       BGP_LS_NODE_DESC_AS_BIT);
	}

	/* Set OSPF Area ID if OSPF */
	if (protocol_id == BGP_LS_PROTO_OSPFV2 || protocol_id == BGP_LS_PROTO_OSPFV3) {
		nlri.nlri_data.link.local_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.link.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
		nlri.nlri_data.link.remote_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.link.remote_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
	}

	/* Populate Link Descriptor from Link State edge attributes */
	/* Link Local/Remote Identifiers (TLV 258) */
	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_LOCAL_ID)) {
		nlri.nlri_data.link.link_desc.link_local_id = edge->attributes->standard.local_id;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_LINK_ID_BIT);
	}

	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_NEIGH_ID)) {
		nlri.nlri_data.link.link_desc.link_remote_id = edge->attributes->standard.remote_id;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_LINK_ID_BIT);
	}

	/* IPv4 Interface Address (TLV 259) */
	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_LOCAL_ADDR)) {
		nlri.nlri_data.link.link_desc.ipv4_intf_addr = edge->attributes->standard.local;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_IPV4_INTF_BIT);
	}

	/* IPv4 Neighbor Address (TLV 260) */
	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_NEIGH_ADDR)) {
		nlri.nlri_data.link.link_desc.ipv4_neigh_addr = edge->attributes->standard.remote;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_IPV4_NEIGH_BIT);
	}

	/* IPv6 Interface Address (TLV 261) */
	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_LOCAL_ADDR6)) {
		nlri.nlri_data.link.link_desc.ipv6_intf_addr = edge->attributes->standard.local6;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_IPV6_INTF_BIT);
	}

	/* IPv6 Neighbor Address (TLV 262) */
	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_NEIGH_ADDR6)) {
		nlri.nlri_data.link.link_desc.ipv6_neigh_addr = edge->attributes->standard.remote6;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_IPV6_NEIGH_BIT);
	}

	/* Remote AS Number (TLV 264) */
	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_REMOTE_AS)) {
		nlri.nlri_data.link.link_desc.remote_asn = edge->attributes->standard.remote_as;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_REMOTE_AS_BIT);
	}

	/* Populate BGP-LS attributes from Link State edge */
	ls_attr = bgp_ls_attr_alloc();
	if (bgp_ls_populate_link_attr(edge->attributes, ls_attr) < 0) {
		zlog_warn("BGP-LS: Failed to populate Link attributes");
		bgp_ls_attr_free(ls_attr);
		return -1;
	}

	/* Install in RIB */
	ret = bgp_ls_update(bgp, &nlri, ls_attr);
	if (ret < 0) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Failed to originate Link NLRI");
		bgp_ls_attr_free(ls_attr);
		return -1;
	}

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Originated Link NLRI for protocol %u", protocol_id);

	bgp_ls_attr_free(ls_attr);

	return 0;
}


int bgp_ls_withdraw_link(struct bgp *bgp, uint8_t protocol_id, uint8_t *local_router_id,
			 uint16_t local_router_id_len, uint8_t *remote_router_id,
			 uint16_t remote_router_id_len, uint32_t area_id, struct ls_edge *edge)
{
	struct bgp_ls_nlri nlri;
	int ret;

	if (!bgp || !local_router_id || !remote_router_id)
		return -1;

	if (!edge || !edge->attributes)
		return -1;

	/* Validate router ID lengths */
	if (local_router_id_len < BGP_LS_IGP_ROUTER_ID_MIN_SIZE ||
	    local_router_id_len > BGP_LS_IGP_ROUTER_ID_MAX_SIZE ||
	    remote_router_id_len < BGP_LS_IGP_ROUTER_ID_MIN_SIZE ||
	    remote_router_id_len > BGP_LS_IGP_ROUTER_ID_MAX_SIZE) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Invalid router ID lengths");
		return -1;
	}

	/* Clear NLRI structure */
	memset(&nlri, 0, sizeof(nlri));

	/* Build Link NLRI */
	nlri.nlri_type = BGP_LS_NLRI_TYPE_LINK;
	nlri.nlri_data.link.protocol_id = protocol_id;
	nlri.nlri_data.link.identifier = 0; /* Instance ID, use 0 for default */

	/* Set Local Node Descriptor */
	nlri.nlri_data.link.local_node.igp_router_id_len = local_router_id_len;
	memcpy(nlri.nlri_data.link.local_node.igp_router_id, local_router_id, local_router_id_len);
	BGP_LS_TLV_SET(nlri.nlri_data.link.local_node.present_tlvs,
		       BGP_LS_NODE_DESC_IGP_ROUTER_BIT);

	/* Set AS Number for Local Node if available */
	if (edge->source && edge->source->node &&
	    CHECK_FLAG(edge->source->node->flags, LS_NODE_AS_NUMBER)) {
		nlri.nlri_data.link.local_node.asn = edge->source->node->as_number;
		BGP_LS_TLV_SET(nlri.nlri_data.link.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_AS_BIT);
	}

	/* Set Remote Node Descriptor */
	nlri.nlri_data.link.remote_node.igp_router_id_len = remote_router_id_len;
	memcpy(nlri.nlri_data.link.remote_node.igp_router_id, remote_router_id,
	       remote_router_id_len);
	BGP_LS_TLV_SET(nlri.nlri_data.link.remote_node.present_tlvs,
		       BGP_LS_NODE_DESC_IGP_ROUTER_BIT);

	/* Set AS Number for Remote Node if available */
	if (edge->destination && edge->destination->node &&
	    CHECK_FLAG(edge->destination->node->flags, LS_NODE_AS_NUMBER)) {
		nlri.nlri_data.link.remote_node.asn = edge->destination->node->as_number;
		BGP_LS_TLV_SET(nlri.nlri_data.link.remote_node.present_tlvs,
			       BGP_LS_NODE_DESC_AS_BIT);
	}

	/* Set OSPF Area ID if OSPF */
	if (protocol_id == BGP_LS_PROTO_OSPFV2 || protocol_id == BGP_LS_PROTO_OSPFV3) {
		nlri.nlri_data.link.local_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.link.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
		nlri.nlri_data.link.remote_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.link.remote_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
	}

	/* Populate Link Descriptor from Link State edge attributes */
	/* Link Local/Remote Identifiers (TLV 258) */
	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_LOCAL_ID)) {
		nlri.nlri_data.link.link_desc.link_local_id = edge->attributes->standard.local_id;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_LINK_ID_BIT);
	}

	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_NEIGH_ID)) {
		nlri.nlri_data.link.link_desc.link_remote_id = edge->attributes->standard.remote_id;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_LINK_ID_BIT);
	}

	/* IPv4 Interface Address (TLV 259) */
	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_LOCAL_ADDR)) {
		nlri.nlri_data.link.link_desc.ipv4_intf_addr = edge->attributes->standard.local;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_IPV4_INTF_BIT);
	}

	/* IPv4 Neighbor Address (TLV 260) */
	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_NEIGH_ADDR)) {
		nlri.nlri_data.link.link_desc.ipv4_neigh_addr = edge->attributes->standard.remote;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_IPV4_NEIGH_BIT);
	}

	/* IPv6 Interface Address (TLV 261) */
	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_LOCAL_ADDR6)) {
		nlri.nlri_data.link.link_desc.ipv6_intf_addr = edge->attributes->standard.local6;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_IPV6_INTF_BIT);
	}

	/* IPv6 Neighbor Address (TLV 262) */
	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_NEIGH_ADDR6)) {
		nlri.nlri_data.link.link_desc.ipv6_neigh_addr = edge->attributes->standard.remote6;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_IPV6_NEIGH_BIT);
	}

	/* Remote AS Number (TLV 264) */
	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_REMOTE_AS)) {
		nlri.nlri_data.link.link_desc.remote_asn = edge->attributes->standard.remote_as;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_REMOTE_AS_BIT);
	}

	/* Withdraw from RIB */
	ret = bgp_ls_withdraw(bgp, &nlri);
	if (ret < 0) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Failed to withdraw Link NLRI");
		return -1;
	}

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Withdrawn Link NLRI for protocol %u", protocol_id);

	return 0;
}


/*
 * Originate Prefix NLRI from IGP prefix information
 *
 * This function creates a BGP-LS Prefix NLRI from IGP prefix data
 * and installs it in the RIB for advertisement to BGP-LS peers.
 */
int bgp_ls_originate_prefix(struct bgp *bgp, uint8_t protocol_id, uint8_t *router_id,
			    uint16_t router_id_len, struct prefix *prefix, uint32_t area_id,
			    struct ls_subnet *subnet)
{
	struct bgp_ls_nlri nlri;
	struct bgp_ls_attr *ls_attr = NULL;
	int ret;

	if (!bgp || !router_id || !prefix)
		return -1;

	if (!subnet || !subnet->ls_pref)
		return -1;

	/* Validate router ID length */
	if (router_id_len < BGP_LS_IGP_ROUTER_ID_MIN_SIZE ||
	    router_id_len > BGP_LS_IGP_ROUTER_ID_MAX_SIZE) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Invalid router ID length %u", router_id_len);
		return -1;
	}

	/* Clear NLRI structure */
	memset(&nlri, 0, sizeof(nlri));

	/* Determine NLRI type based on prefix family */
	if (prefix->family == AF_INET)
		nlri.nlri_type = BGP_LS_NLRI_TYPE_IPV4_PREFIX;
	else if (prefix->family == AF_INET6)
		nlri.nlri_type = BGP_LS_NLRI_TYPE_IPV6_PREFIX;
	else {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Unsupported prefix family %u", prefix->family);
		return -1;
	}

	/* Build Prefix NLRI */
	nlri.nlri_data.prefix.protocol_id = protocol_id;
	nlri.nlri_data.prefix.identifier = 0; /* Instance ID, use 0 for default */

	/* Set Local Node Descriptor */
	nlri.nlri_data.prefix.local_node.igp_router_id_len = router_id_len;
	memcpy(nlri.nlri_data.prefix.local_node.igp_router_id, router_id, router_id_len);
	BGP_LS_TLV_SET(nlri.nlri_data.prefix.local_node.present_tlvs,
		       BGP_LS_NODE_DESC_IGP_ROUTER_BIT);

	/* Set AS Number if available */
	if (subnet->vertex && subnet->vertex->node &&
	    CHECK_FLAG(subnet->vertex->node->flags, LS_NODE_AS_NUMBER)) {
		nlri.nlri_data.prefix.local_node.asn = subnet->vertex->node->as_number;
		BGP_LS_TLV_SET(nlri.nlri_data.prefix.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_AS_BIT);
	}

	/* Set OSPF Area ID if OSPF */
	if (protocol_id == BGP_LS_PROTO_OSPFV2 || protocol_id == BGP_LS_PROTO_OSPFV3) {
		nlri.nlri_data.prefix.local_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.prefix.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
	}

	/* Set Prefix Descriptor */
	nlri.nlri_data.prefix.prefix_desc.prefix = *prefix;
	apply_mask(&nlri.nlri_data.prefix.prefix_desc.prefix);
	BGP_LS_TLV_SET(nlri.nlri_data.prefix.prefix_desc.present_tlvs,
		       BGP_LS_PREFIX_DESC_IP_REACH_BIT);

	/* Populate BGP-LS attributes from Link State subnet */
	ls_attr = bgp_ls_attr_alloc();
	if (bgp_ls_populate_prefix_attr(subnet->ls_pref, ls_attr) < 0) {
		zlog_warn("BGP-LS: Failed to populate Prefix attributes");
		bgp_ls_attr_free(ls_attr);
		return -1;
	}

	/* Install in RIB */
	ret = bgp_ls_update(bgp, &nlri, ls_attr);
	if (ret < 0) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Failed to originate Prefix NLRI");
		bgp_ls_attr_free(ls_attr);
		return -1;
	}

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Originated Prefix NLRI %pFX for protocol %u", prefix,
			   protocol_id);

	bgp_ls_attr_free(ls_attr);

	return 0;
}


int bgp_ls_withdraw_prefix(struct bgp *bgp, uint8_t protocol_id, uint8_t *router_id,
			   uint16_t router_id_len, struct prefix *prefix, uint32_t area_id,
			   struct ls_subnet *subnet)
{
	struct bgp_ls_nlri nlri;
	int ret;

	if (!bgp || !router_id || !prefix)
		return -1;

	if (!subnet || !subnet->ls_pref)
		return -1;

	/* Validate router ID length */
	if (router_id_len < BGP_LS_IGP_ROUTER_ID_MIN_SIZE ||
	    router_id_len > BGP_LS_IGP_ROUTER_ID_MAX_SIZE) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Invalid router ID length %u", router_id_len);
		return -1;
	}

	/* Clear NLRI structure */
	memset(&nlri, 0, sizeof(nlri));

	/* Determine NLRI type based on prefix family */
	if (prefix->family == AF_INET)
		nlri.nlri_type = BGP_LS_NLRI_TYPE_IPV4_PREFIX;
	else if (prefix->family == AF_INET6)
		nlri.nlri_type = BGP_LS_NLRI_TYPE_IPV6_PREFIX;
	else {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Unsupported prefix family %u", prefix->family);
		return -1;
	}

	/* Build Prefix NLRI */
	nlri.nlri_data.prefix.protocol_id = protocol_id;
	nlri.nlri_data.prefix.identifier = 0; /* Instance ID, use 0 for default */

	/* Set Local Node Descriptor */
	nlri.nlri_data.prefix.local_node.igp_router_id_len = router_id_len;
	memcpy(nlri.nlri_data.prefix.local_node.igp_router_id, router_id, router_id_len);
	BGP_LS_TLV_SET(nlri.nlri_data.prefix.local_node.present_tlvs,
		       BGP_LS_NODE_DESC_IGP_ROUTER_BIT);

	/* Set AS Number if available */
	if (subnet->vertex && subnet->vertex->node &&
	    CHECK_FLAG(subnet->vertex->node->flags, LS_NODE_AS_NUMBER)) {
		nlri.nlri_data.prefix.local_node.asn = subnet->vertex->node->as_number;
		BGP_LS_TLV_SET(nlri.nlri_data.prefix.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_AS_BIT);
	}

	/* Set OSPF Area ID if OSPF */
	if (protocol_id == BGP_LS_PROTO_OSPFV2 || protocol_id == BGP_LS_PROTO_OSPFV3) {
		nlri.nlri_data.prefix.local_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.prefix.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
	}

	/* Set Prefix Descriptor */
	nlri.nlri_data.prefix.prefix_desc.prefix = *prefix;
	BGP_LS_TLV_SET(nlri.nlri_data.prefix.prefix_desc.present_tlvs,
		       BGP_LS_PREFIX_DESC_IP_REACH_BIT);

	/* Withdraw from RIB */
	ret = bgp_ls_withdraw(bgp, &nlri);
	if (ret < 0) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Failed to withdraw Prefix NLRI");
		return -1;
	}

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Withdrawn Prefix NLRI %pFX for protocol %u", prefix,
			   protocol_id);

	return 0;
}

/*
 * ===========================================================================
 * Link State Message Processing
 * ===========================================================================
 */

/*
 * Map Link State origin to BGP-LS Protocol-ID
 */
static enum bgp_ls_protocol_id ls_origin_to_protocol_id(enum ls_origin origin)
{
	switch (origin) {
	case ISIS_L1:
		return BGP_LS_PROTO_ISIS_L1;
	case ISIS_L2:
		return BGP_LS_PROTO_ISIS_L2;
	case OSPFv2:
		return BGP_LS_PROTO_OSPFV2;
	case DIRECT:
		return BGP_LS_PROTO_DIRECT;
	case STATIC:
		return BGP_LS_PROTO_STATIC;
	case LS_UNKNOWN:
	default:
		return BGP_LS_PROTO_RESERVED;
	}
}

/*
 * Process Link State vertex and originate/withdraw BGP-LS Node NLRI
 */
int bgp_ls_process_vertex(struct bgp *bgp, struct ls_vertex *vertex, uint8_t event)
{
	enum bgp_ls_protocol_id protocol_id;
	uint8_t router_id[BGP_LS_IGP_ROUTER_ID_MAX_SIZE];
	uint16_t router_id_len = 0;
	uint32_t area_id = 0;

	if (!bgp || !vertex || !vertex->node)
		return -1;

	protocol_id = ls_origin_to_protocol_id(vertex->node->adv.origin);

	switch (protocol_id) {
	case BGP_LS_PROTO_OSPFV2:
		/* OSPF uses 4-byte IPv4 router ID */
		memcpy(router_id, &vertex->node->adv.id.ip.addr.s_addr, 4);
		router_id_len = 4;
		area_id = ntohl(vertex->node->adv.id.ip.area_id.s_addr);
		break;
	case BGP_LS_PROTO_ISIS_L1:
	case BGP_LS_PROTO_ISIS_L2:
		/* IS-IS uses 6-byte System ID + 1 byte pseudonode ID = 7 bytes */
		memcpy(router_id, vertex->node->adv.id.iso.sys_id, ISO_SYS_ID_LEN);
		// router_id[6] = 0; /* Pseudonode ID = 0 for router */
		// router_id_len = 7;
		router_id_len = 6;
		break;
	case BGP_LS_PROTO_DIRECT:
	case BGP_LS_PROTO_STATIC:
	case BGP_LS_PROTO_OSPFV3:
	case BGP_LS_PROTO_BGP:
	case BGP_LS_PROTO_RESERVED:
		zlog_err("BGP-LS: Unsupported protocol %u", protocol_id);
		return -1;
	}

	switch (event) {
	case LS_MSG_EVENT_SYNC:
	case LS_MSG_EVENT_ADD:
	case LS_MSG_EVENT_UPDATE:
		return bgp_ls_originate_node(bgp, protocol_id, router_id, router_id_len, area_id,
					     vertex);

	case LS_MSG_EVENT_DELETE:
		return bgp_ls_withdraw_node(bgp, protocol_id, router_id, router_id_len, area_id,
					    vertex);

	default:
		zlog_warn("BGP-LS: Unknown event type %u for vertex", event);
		return -1;
	}
}

/*
 * Process Link State edge and originate/withdraw BGP-LS Link NLRI
 */
int bgp_ls_process_edge(struct bgp *bgp, struct ls_edge *edge, uint8_t event)
{
	uint8_t protocol_id;
	uint8_t local_router_id[BGP_LS_IGP_ROUTER_ID_MAX_SIZE];
	uint8_t remote_router_id[BGP_LS_IGP_ROUTER_ID_MAX_SIZE];
	uint16_t local_router_id_len = 0;
	uint16_t remote_router_id_len = 0;
	uint32_t area_id = 0;

	if (!bgp || !edge || !edge->attributes)
		return -1;

	/* Map origin to protocol ID */
	protocol_id = ls_origin_to_protocol_id(edge->attributes->adv.origin);

	/* Extract router IDs from source and destination vertices */
	if (!edge->source || !edge->destination) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Edge missing source or destination vertex");
		return -1;
	}

	if (!bgp_ls_link_valid(edge))
		return -1;

	switch (protocol_id) {
	case BGP_LS_PROTO_OSPFV2:
		/* OSPF uses 4-byte IPv4 router ID */
		memcpy(local_router_id, &edge->source->node->adv.id.ip.addr.s_addr, 4);
		local_router_id_len = 4;

		memcpy(remote_router_id, &edge->destination->node->adv.id.ip.addr.s_addr, 4);
		remote_router_id_len = 4;

		area_id = ntohl(edge->attributes->adv.id.ip.area_id.s_addr);
		break;
	case BGP_LS_PROTO_ISIS_L1:
	case BGP_LS_PROTO_ISIS_L2:
		/* IS-IS non-pseudonode uses 6-byte System ID */
		memcpy(local_router_id, edge->source->node->adv.id.iso.sys_id, ISO_SYS_ID_LEN);
		local_router_id_len = 6;

		memcpy(remote_router_id, edge->destination->node->adv.id.iso.sys_id,
		       ISO_SYS_ID_LEN);
		remote_router_id_len = 6;
		break;
	case BGP_LS_PROTO_DIRECT:
	case BGP_LS_PROTO_STATIC:
	case BGP_LS_PROTO_OSPFV3:
	case BGP_LS_PROTO_BGP:
	case BGP_LS_PROTO_RESERVED:
		zlog_err("BGP-LS: Unsupported protocol %u", protocol_id);
		return -1;
	}

	switch (event) {
	case LS_MSG_EVENT_SYNC:
	case LS_MSG_EVENT_ADD:
	case LS_MSG_EVENT_UPDATE:
		return bgp_ls_originate_link(bgp, protocol_id, local_router_id,
					     local_router_id_len, remote_router_id,
					     remote_router_id_len, area_id, edge);

	case LS_MSG_EVENT_DELETE:
		return bgp_ls_withdraw_link(bgp, protocol_id, local_router_id, local_router_id_len,
					    remote_router_id, remote_router_id_len, area_id, edge);

	default:
		zlog_warn("BGP-LS: Unknown event type %u for edge", event);
		return -1;
	}
}

/*
 * Process Link State subnet and originate/withdraw BGP-LS Prefix NLRI
 */
int bgp_ls_process_subnet(struct bgp *bgp, struct ls_subnet *subnet, uint8_t event)
{
	uint8_t protocol_id;
	uint8_t router_id[BGP_LS_IGP_ROUTER_ID_MAX_SIZE];
	uint16_t router_id_len = 0;
	uint32_t area_id = 0;

	if (!bgp || !subnet || !subnet->ls_pref)
		return -1;

	protocol_id = ls_origin_to_protocol_id(subnet->ls_pref->adv.origin);

	/* Extract router ID from advertising vertex */
	if (!subnet->vertex) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Subnet missing advertising vertex");
		return -1;
	}

	switch (protocol_id) {
	case BGP_LS_PROTO_OSPFV2:
		/* OSPF uses 4-byte IPv4 router ID */
		memcpy(router_id, &subnet->vertex->node->adv.id.ip.addr.s_addr, 4);
		router_id_len = 4;
		area_id = ntohl(subnet->ls_pref->adv.id.ip.area_id.s_addr);
		break;
	case BGP_LS_PROTO_ISIS_L1:
	case BGP_LS_PROTO_ISIS_L2:
		/* IS-IS uses 6-byte System ID + 1 byte pseudonode ID = 7 bytes */
		memcpy(router_id, subnet->vertex->node->adv.id.iso.sys_id, ISO_SYS_ID_LEN);
		// router_id[6] = 0; /* Pseudonode ID = 0 for router */
		// router_id_len = 7;
		router_id_len = 6;
		break;
	case BGP_LS_PROTO_DIRECT:
	case BGP_LS_PROTO_STATIC:
	case BGP_LS_PROTO_OSPFV3:
	case BGP_LS_PROTO_BGP:
	case BGP_LS_PROTO_RESERVED:
		zlog_err("BGP-LS: Unsupported protocol %u", protocol_id);
		return -1;
	}

	switch (event) {
	case LS_MSG_EVENT_SYNC:
	case LS_MSG_EVENT_ADD:
	case LS_MSG_EVENT_UPDATE:
		return bgp_ls_originate_prefix(bgp, protocol_id, router_id, router_id_len,
					       &subnet->key, area_id, subnet);

	case LS_MSG_EVENT_DELETE:
		return bgp_ls_withdraw_prefix(bgp, protocol_id, router_id, router_id_len,
					      &subnet->key, area_id, subnet);

	default:
		zlog_warn("BGP-LS: Unknown event type %u for subnet", event);
		return -1;
	}
}

/*
 * ===========================================================================
 * Link-State Message Processing from Zebra
 * ===========================================================================
 */

/*
 * Process link-state message and update TED
 *
 * Converts message to TED structure (vertex/edge/subnet) and triggers
 * BGP-LS route origination.
 */
int bgp_ls_process_message(struct bgp *bgp, struct ls_message *msg)
{
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct ls_edge *reverse_edge = NULL;
	bool reverse_edge_dst_updated = false;
	struct ls_subnet *subnet;

	if (!bgp || !bgp->ls_info || !bgp->ls_info->ted || !msg)
		return -1;

	if (BGP_DEBUG(zebra, ZEBRA) || BGP_DEBUG(linkstate, LINKSTATE)) {
		const char *type_str = msg->type == LS_MSG_TYPE_NODE	     ? "NODE"
				       : msg->type == LS_MSG_TYPE_ATTRIBUTES ? "ATTR"
									     : "PREFIX";
		const char *event_str = msg->event == LS_MSG_EVENT_ADD	    ? "ADD"
					: msg->event == LS_MSG_EVENT_UPDATE ? "UPDATE"
									    : "DELETE";
		zlog_debug("%s: Processing %s %s", __func__, type_str, event_str);
	}

	switch (msg->type) {
	case LS_MSG_TYPE_NODE:
		vertex = ls_msg2vertex(bgp->ls_info->ted, msg, false);
		if (!vertex) {
			zlog_err("%s: Failed to convert message to vertex", __func__);
			return -1;
		}

		if (BGP_DEBUG(zebra, ZEBRA) || BGP_DEBUG(linkstate, LINKSTATE))
			zlog_debug("%s: Node vertex key=%" PRIu64, __func__, vertex->key);

		bgp_ls_process_vertex(bgp, vertex, msg->event);

		if (msg->event == LS_MSG_EVENT_DELETE)
			ls_vertex_del_all(bgp->ls_info->ted, vertex);

		break;

	case LS_MSG_TYPE_ATTRIBUTES:
		edge = ls_msg2edge(bgp->ls_info->ted, msg, false);
		if (!edge) {
			zlog_err("%s: Failed to convert message to edge", __func__);
			return -1;
		}

		if (BGP_DEBUG(zebra, ZEBRA) || BGP_DEBUG(linkstate, LINKSTATE))
			zlog_debug("%s: Link edge", __func__);

		if (msg->event == LS_MSG_EVENT_SYNC || msg->event == LS_MSG_EVENT_ADD ||
		    msg->event == LS_MSG_EVENT_UPDATE) {
			/* Search for the reverse edge and link both directions. */
			reverse_edge = ls_find_edge_by_destination(bgp->ls_info->ted,
								   edge->attributes);
			if (reverse_edge) {
				/* Attach destination to reverse edge if missing. */
				if (reverse_edge->destination == NULL && edge->source) {
					vertex = edge->source;
					listnode_add_sort_nodup(vertex->incoming_edges,
								reverse_edge);
					reverse_edge->destination = vertex;
					reverse_edge_dst_updated = true;
				}
				/* Attach destination to this edge if missing. */
				if (edge->destination == NULL && reverse_edge->source) {
					vertex = reverse_edge->source;
					listnode_add_sort_nodup(vertex->incoming_edges, edge);
					edge->destination = vertex;
				}
			}

			if (!edge->destination) {
				/*
				 * An ADD for edge A->B may arrive before the reverse edge B->A
				 * exists in TED. In that case edge->destination is NULL, so we
				 * cannot originate the link yet and skip it for now. When B->A is
				 * later added, its ADD/UPDATE processing will also look up and
				 * process A->B.
				 */
				if (BGP_DEBUG(zebra, ZEBRA) || BGP_DEBUG(linkstate, LINKSTATE))
					zlog_debug("%s: Skip edge add/update without destination",
						   __func__);
				break;
			}

			bgp_ls_process_edge(bgp, edge, msg->event);

			/*
			 * After we process edge A->B, check whether reverse edge B->A is
			 * already in TED and process it. This originates the Link NLRI for
			 * the direction that was previously skipped when A->B lacked a
			 * destination.
			 */
			if (reverse_edge &&
			    (msg->event == LS_MSG_EVENT_SYNC || msg->event == LS_MSG_EVENT_ADD ||
			     reverse_edge_dst_updated)) {
				uint8_t reverse_event = msg->event;

				if (msg->event == LS_MSG_EVENT_UPDATE && reverse_edge_dst_updated)
					reverse_event = LS_MSG_EVENT_ADD;

				bgp_ls_process_edge(bgp, reverse_edge, reverse_event);
			} else if (!reverse_edge &&
				   (BGP_DEBUG(zebra, ZEBRA) || BGP_DEBUG(linkstate, LINKSTATE)))
				zlog_debug("%s: Reverse edge not yet in TED, will be processed on arrival",
					   __func__);

		} else if (msg->event == LS_MSG_EVENT_DELETE) {
			bgp_ls_process_edge(bgp, edge, msg->event);
			ls_edge_del_all(bgp->ls_info->ted, edge);
		} else {
			if (BGP_DEBUG(zebra, ZEBRA) || BGP_DEBUG(linkstate, LINKSTATE))
				zlog_debug("%s: Unknown event type %u for edge", __func__,
					   msg->event);
		}

		break;

	case LS_MSG_TYPE_PREFIX:
		subnet = ls_msg2subnet(bgp->ls_info->ted, msg, false);
		if (!subnet) {
			zlog_err("%s: Failed to convert message to subnet", __func__);
			return -1;
		}

		if (BGP_DEBUG(zebra, ZEBRA) || BGP_DEBUG(linkstate, LINKSTATE)) {
			char buf[PREFIX2STR_BUFFER];

			prefix2str(&subnet->key, buf, sizeof(buf));
			zlog_debug("%s: Prefix %s", __func__, buf);
		}

		bgp_ls_process_subnet(bgp, subnet, msg->event);

		if (msg->event == LS_MSG_EVENT_DELETE)
			ls_subnet_del_all(bgp->ls_info->ted, subnet);

		break;

	default:
		zlog_warn("%s: Unknown message type %d", __func__, msg->type);
		return -1;
	}

	return 0;
}

/*
 * Remove all entries from the TED.
 */
static void bgp_ls_ted_clear(struct ls_ted *ted)
{
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct ls_subnet *subnet;

	frr_each_safe (vertices, &ted->vertices, vertex)
		ls_vertex_del_all(ted, vertex);
	frr_each_safe (edges, &ted->edges, edge)
		ls_edge_del_all(ted, edge);
	frr_each_safe (subnets, &ted->subnets, subnet)
		ls_subnet_del_all(ted, subnet);
}

/*
 * Withdraw all locally originated BGP-LS routes and reset the TED.
 *
 * Called when the last BGP-LS peer is deactivated: performs a single bulk
 * walk of the BGP-LS RIB via bgp_clear_route() to remove all self-originated
 * paths at once, then clears all TED entries.
 *
 * @param bgp - BGP instance
 */
void bgp_ls_withdraw_ted(struct bgp *bgp)
{
	if (!bgp || !bgp->ls_info || !bgp->ls_info->ted)
		return;

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Withdrawing all locally originated routes and resetting TED");

	/* Remove all self-originated BGP-LS paths from the RIB */
	bgp_clear_route(bgp->peer_self, AFI_BGP_LS, SAFI_BGP_LS);

	/* Clear all TED entries */
	bgp_ls_ted_clear(bgp->ls_info->ted);

	zlog_info("BGP-LS: All locally originated BGP-LS routes withdrawn and TED reset");
}

/*
 * Handle link-state SYNC/UPDATE messages from zebra
 */
int bgp_ls_process_linkstate_message(struct stream *s, uint8_t msg_type)
{
	struct ls_message *msg;
	struct bgp *bgp;
	int ret;

	bgp = bgp_get_default();
	if (!bgp || !bgp->ls_info || !bgp->ls_info->ted) {
		zlog_warn("%s: TED not initialized, ignoring link-state message", __func__);
		return 0;
	}

	msg = ls_parse_msg(s);
	if (!msg) {
		zlog_err("%s: Failed to parse link-state message", __func__);
		return -1;
	}

	if (BGP_DEBUG(zebra, ZEBRA) || BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("%s: Received link-state %s message", __func__,
			   msg_type == LINK_STATE_UPDATE ? "UPDATE" : "SYNC");

	ret = bgp_ls_process_message(bgp, msg);
	ls_delete_msg(msg);

	return ret;
}
