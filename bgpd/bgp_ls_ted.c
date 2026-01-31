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

/*
 * ===========================================================================
 * Node Attribute Population
 * ===========================================================================
 */

/*
 * Populate BGP-LS Node Attributes from Link State Node
 */
int bgp_ls_populate_node_attr(struct ls_node *ls_node, struct bgp_ls_node_attr *attr)
{
	if (!ls_node || !attr)
		return -1;

	bgp_ls_attr_node_init(attr);

	/* Node Flag Bits (TLV 1024) */
	if (CHECK_FLAG(ls_node->flags, LS_NODE_FLAG)) {
		attr->node_flags = ls_node->node_flag;
		attr->present_tlvs |= (1 << BGP_LS_NODE_ATTR_NODE_FLAGS_BIT);
	}

	/* Node Name (TLV 1026) */
	if (CHECK_FLAG(ls_node->flags, LS_NODE_NAME) && ls_node->name[0] != '\0') {
		size_t name_len = strlen(ls_node->name);

		attr->node_name = XCALLOC(MTYPE_BGP_LS_ATTR_DATA, name_len + 1);
		memcpy(attr->node_name, ls_node->name, name_len + 1);
		attr->present_tlvs |= (1 << BGP_LS_NODE_ATTR_NODE_NAME_BIT);
	}

	/* IPv4 Router-ID (TLV 1028) */
	if (CHECK_FLAG(ls_node->flags, LS_NODE_ROUTER_ID)) {
		attr->ipv4_router_id = ls_node->router_id;
		attr->present_tlvs |= (1 << BGP_LS_NODE_ATTR_IPV4_ROUTER_ID_BIT);
	}

	/* IPv6 Router-ID (TLV 1029) */
	if (CHECK_FLAG(ls_node->flags, LS_NODE_ROUTER_ID6)) {
		attr->ipv6_router_id = ls_node->router_id6;
		attr->present_tlvs |= (1 << BGP_LS_NODE_ATTR_IPV6_ROUTER_ID_BIT);
	}

	return 0;
}

/*
 * ===========================================================================
 * Link Attribute Population
 * ===========================================================================
 */

/*
 * Populate BGP-LS Link Attributes from Link State Attributes
 */
int bgp_ls_populate_link_attr(struct ls_attributes *ls_attr, struct bgp_ls_link_attr *attr)
{
	if (!ls_attr || !attr)
		return -1;

	bgp_ls_attr_link_init(attr);

	/* Administrative Group (TLV 1088) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_ADM_GRP)) {
		attr->admin_group = ls_attr->standard.admin_group;
		attr->present_tlvs |= (1 << BGP_LS_LINK_ATTR_ADMIN_GROUP_BIT);
	}

	/* Maximum Link Bandwidth (TLV 1089) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_MAX_BW)) {
		attr->max_link_bw = ls_attr->standard.max_bw;
		attr->present_tlvs |= (1 << BGP_LS_LINK_ATTR_MAX_LINK_BW_BIT);
	}

	/* Maximum Reservable Bandwidth (TLV 1090) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_MAX_RSV_BW)) {
		attr->max_resv_bw = ls_attr->standard.max_rsv_bw;
		attr->present_tlvs |= (1 << BGP_LS_LINK_ATTR_MAX_RESV_BW_BIT);
	}

	/* Unreserved Bandwidth (TLV 1091) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_UNRSV_BW)) {
		for (int i = 0; i < BGP_LS_MAX_UNRESV_BW; i++)
			attr->unreserved_bw[i] = ls_attr->standard.unrsv_bw[i];
		attr->present_tlvs |= (1 << BGP_LS_LINK_ATTR_UNRESV_BW_BIT);
	}

	/* TE Default Metric (TLV 1092) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_TE_METRIC)) {
		attr->te_metric = ls_attr->standard.te_metric;
		attr->present_tlvs |= (1 << BGP_LS_LINK_ATTR_TE_METRIC_BIT);
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
		attr->present_tlvs |= (1 << BGP_LS_LINK_ATTR_IGP_METRIC_BIT);
	}

	/* Shared Risk Link Group (TLV 1096) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_SRLG) && ls_attr->srlg_len > 0) {
		uint8_t count = ls_attr->srlg_len;

		if (count > BGP_LS_MAX_SRLG)
			count = BGP_LS_MAX_SRLG;

		attr->srlg_count = count;
		attr->srlg_values = XCALLOC(MTYPE_BGP_LS_ATTR_DATA, count * sizeof(uint32_t));
		for (uint8_t i = 0; i < count; i++)
			attr->srlg_values[i] = ls_attr->srlgs[i];
		attr->present_tlvs |= (1 << BGP_LS_LINK_ATTR_SRLG_BIT);
	}

	/* Link Name (TLV 1098) */
	if (CHECK_FLAG(ls_attr->flags, LS_ATTR_NAME) && ls_attr->name[0] != '\0') {
		size_t name_len = strlen(ls_attr->name);

		attr->link_name = XCALLOC(MTYPE_BGP_LS_ATTR_DATA, name_len + 1);
		memcpy(attr->link_name, ls_attr->name, name_len + 1);
		attr->present_tlvs |= (1 << BGP_LS_LINK_ATTR_LINK_NAME_BIT);
	}

	return 0;
}

/*
 * ===========================================================================
 * Prefix Attribute Population
 * ===========================================================================
 */

/*
 * Populate BGP-LS Prefix Attributes from Link State Prefix
 */
int bgp_ls_populate_prefix_attr(struct ls_prefix *ls_prefix, struct bgp_ls_prefix_attr *attr)
{
	if (!ls_prefix || !attr)
		return -1;

	bgp_ls_attr_prefix_init(attr);

	/* IGP Flags (TLV 1152) */
	if (CHECK_FLAG(ls_prefix->flags, LS_PREF_IGP_FLAG)) {
		attr->igp_flags = ls_prefix->igp_flag;
		attr->present_tlvs |= (1 << BGP_LS_PREFIX_ATTR_IGP_FLAGS_BIT);
	}

	/* Route Tags (TLV 1153) - single tag */
	if (CHECK_FLAG(ls_prefix->flags, LS_PREF_ROUTE_TAG)) {
		attr->route_tag_count = 1;
		attr->route_tags = XCALLOC(MTYPE_BGP_LS_ATTR_DATA, sizeof(uint32_t));
		attr->route_tags[0] = ls_prefix->route_tag;
		attr->present_tlvs |= (1 << BGP_LS_PREFIX_ATTR_ROUTE_TAG_BIT);
	}

	/* Extended Tags (TLV 1154) - single extended tag */
	if (CHECK_FLAG(ls_prefix->flags, LS_PREF_EXTENDED_TAG)) {
		attr->extended_tag_count = 1;
		attr->extended_tags = XCALLOC(MTYPE_BGP_LS_ATTR_DATA, sizeof(uint64_t));
		attr->extended_tags[0] = ls_prefix->extended_tag;
		attr->present_tlvs |= (1 << BGP_LS_PREFIX_ATTR_EXTENDED_TAG_BIT);
	}

	/* Prefix Metric (TLV 1155) */
	if (CHECK_FLAG(ls_prefix->flags, LS_PREF_METRIC)) {
		attr->prefix_metric = ls_prefix->metric;
		attr->present_tlvs |= (1 << BGP_LS_PREFIX_ATTR_PREFIX_METRIC_BIT);
	}

	return 0;
}

/*
 * ===========================================================================
 * IGP Origination Functions
 * ===========================================================================
 */

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
	int ret;

	if (!bgp || !router_id)
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

	/* Set OSPF Area ID if OSPF */
	if (protocol_id == BGP_LS_PROTO_OSPFV2 || protocol_id == BGP_LS_PROTO_OSPFV3) {
		nlri.nlri_data.node.local_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.node.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
	}

	/* Populate BGP-LS attributes from Link State vertex */
	if (vertex && vertex->node) {
		nlri.nlri_data.node.attr = XCALLOC(MTYPE_BGP_LS_NODE_ATTR,
						   sizeof(struct bgp_ls_node_attr));
		if (bgp_ls_populate_node_attr(vertex->node, nlri.nlri_data.node.attr) < 0) {
			zlog_warn("BGP-LS: Failed to populate Node attributes");
			bgp_ls_attr_node_free(&nlri.nlri_data.node.attr);
		}
	}

	/* Install in RIB */
	ret = bgp_ls_update(bgp, &nlri);

	if (ret < 0) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Failed to originate Node NLRI");
		bgp_ls_attr_node_free(&nlri.nlri_data.node.attr);
		return -1;
	}

	/*
	 * Note: Ownership of nlri.nlri_data.node.attr has been transferred to the route table.
	 * Set to NULL to avoid double-free. It will be freed by bgp_ls_nlri_free() when route is removed.
	 */
	if (nlri.nlri_data.node.attr)
		XFREE(MTYPE_BGP_LS_ATTR_DATA, nlri.nlri_data.node.attr->node_name);
	XFREE(MTYPE_BGP_LS_NODE_ATTR, nlri.nlri_data.node.attr);
	nlri.nlri_data.node.attr = NULL;

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Originated Node NLRI for protocol %u", protocol_id);

	return 0;
}


int bgp_ls_withdraw_node(struct bgp *bgp, uint8_t protocol_id, uint8_t *router_id,
			 uint16_t router_id_len, uint32_t area_id, struct ls_vertex *vertex)
{
	struct bgp_ls_nlri nlri;
	int ret;

	if (!bgp || !router_id)
		return -1;

	/* Validate router ID length */
	if (router_id_len < BGP_LS_IGP_ROUTER_ID_MIN_SIZE ||
	    router_id_len > BGP_LS_IGP_ROUTER_ID_MAX_SIZE) {
		zlog_err("BGP-LS: Invalid router ID length %u", router_id_len);
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

	/* Set OSPF Area ID if OSPF */
	if (protocol_id == BGP_LS_PROTO_OSPFV2 || protocol_id == BGP_LS_PROTO_OSPFV3) {
		nlri.nlri_data.node.local_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.node.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
	}

	/* Populate BGP-LS attributes from Link State vertex */
	if (vertex && vertex->node) {
		nlri.nlri_data.node.attr = XCALLOC(MTYPE_BGP_LS_NODE_ATTR,
						   sizeof(struct bgp_ls_node_attr));
		if (bgp_ls_populate_node_attr(vertex->node, nlri.nlri_data.node.attr) < 0) {
			zlog_warn("BGP-LS: Failed to populate Node attributes");
			XFREE(MTYPE_BGP_LS_NODE_ATTR, nlri.nlri_data.node.attr);
			nlri.nlri_data.node.attr = NULL;
		}
	}

	/* Withdraw from RIB */
	ret = bgp_ls_withdraw(bgp, &nlri);

	if (ret < 0) {
		zlog_err("BGP-LS: Failed to withdraw Node NLRI");
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Failed to withdraw Node NLRI");
		bgp_ls_attr_node_free(&nlri.nlri_data.node.attr);
		return -1;
	}

	/*
	 * Note: Ownership of nlri.nlri_data.node.attr has been transferred to the route table.
	 * Set to NULL to avoid double-free. It will be freed by bgp_ls_nlri_free() when route is removed.
	 */
	if (nlri.nlri_data.node.attr)
		XFREE(MTYPE_BGP_LS_ATTR_DATA, nlri.nlri_data.node.attr->node_name);
	XFREE(MTYPE_BGP_LS_NODE_ATTR, nlri.nlri_data.node.attr);
	nlri.nlri_data.node.attr = NULL;

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
	int ret;

	if (!bgp || !local_router_id || !remote_router_id)
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

	/* Set Remote Node Descriptor */
	nlri.nlri_data.link.remote_node.igp_router_id_len = remote_router_id_len;
	memcpy(nlri.nlri_data.link.remote_node.igp_router_id, remote_router_id,
	       remote_router_id_len);
	BGP_LS_TLV_SET(nlri.nlri_data.link.remote_node.present_tlvs,
		       BGP_LS_NODE_DESC_IGP_ROUTER_BIT);

	/* Set OSPF Area ID if OSPF */
	if (protocol_id == BGP_LS_PROTO_OSPFV2 || protocol_id == BGP_LS_PROTO_OSPFV3) {
		nlri.nlri_data.link.local_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.link.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
		nlri.nlri_data.link.remote_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.link.remote_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
	}

	/* Link Descriptor is empty for Phase 1 (no interface IDs yet) */

	/* Populate BGP-LS attributes from Link State edge */
	if (edge && edge->attributes) {
		nlri.nlri_data.link.attr = XCALLOC(MTYPE_BGP_LS_LINK_ATTR,
						   sizeof(struct bgp_ls_link_attr));
		if (bgp_ls_populate_link_attr(edge->attributes, nlri.nlri_data.link.attr) < 0) {
			zlog_warn("BGP-LS: Failed to populate Link attributes");
			XFREE(MTYPE_BGP_LS_LINK_ATTR, nlri.nlri_data.link.attr);
			nlri.nlri_data.link.attr = NULL;
		}
	}

	/* Install in RIB */
	ret = bgp_ls_update(bgp, &nlri);

	if (ret < 0) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Failed to originate Link NLRI");
		bgp_ls_attr_link_free(&nlri.nlri_data.link.attr);
		return -1;
	}

	/*
	 * Note: Ownership of nlri.nlri_data.link.attr has been transferred to the route table.
	 * Set to NULL to avoid double-free. It will be freed by bgp_ls_nlri_free() when route is removed.
	 */
	XFREE(MTYPE_BGP_LS_LINK_ATTR, nlri.nlri_data.link.attr);
	nlri.nlri_data.link.attr = NULL;

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Originated Link NLRI for protocol %u", protocol_id);

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

	/* Set Remote Node Descriptor */
	nlri.nlri_data.link.remote_node.igp_router_id_len = remote_router_id_len;
	memcpy(nlri.nlri_data.link.remote_node.igp_router_id, remote_router_id,
	       remote_router_id_len);
	BGP_LS_TLV_SET(nlri.nlri_data.link.remote_node.present_tlvs,
		       BGP_LS_NODE_DESC_IGP_ROUTER_BIT);

	/* Set OSPF Area ID if OSPF */
	if (protocol_id == BGP_LS_PROTO_OSPFV2 || protocol_id == BGP_LS_PROTO_OSPFV3) {
		nlri.nlri_data.link.local_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.link.local_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
		nlri.nlri_data.link.remote_node.ospf_area_id = area_id;
		BGP_LS_TLV_SET(nlri.nlri_data.link.remote_node.present_tlvs,
			       BGP_LS_NODE_DESC_OSPF_AREA_BIT);
	}

	/* Link Descriptor is empty for Phase 1 (no interface IDs yet) */

	/* Populate BGP-LS attributes from Link State edge */
	if (edge && edge->attributes) {
		nlri.nlri_data.link.attr = XCALLOC(MTYPE_BGP_LS_LINK_ATTR,
						   sizeof(struct bgp_ls_link_attr));
		if (bgp_ls_populate_link_attr(edge->attributes, nlri.nlri_data.link.attr) < 0) {
			zlog_warn("BGP-LS: Failed to populate Link attributes");
			XFREE(MTYPE_BGP_LS_LINK_ATTR, nlri.nlri_data.link.attr);
			nlri.nlri_data.link.attr = NULL;
		}
	}

	/* Withdraw from RIB */
	ret = bgp_ls_withdraw(bgp, &nlri);

	if (ret < 0) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Failed to withdraw Link NLRI");
		bgp_ls_attr_link_free(&nlri.nlri_data.link.attr);
		return -1;
	}

	/*
	 * Note: Ownership of nlri.nlri_data.link.attr has been transferred to the route table.
	 * Set to NULL to avoid double-free. It will be freed by bgp_ls_nlri_free() when route is removed.
	 */
	XFREE(MTYPE_BGP_LS_LINK_ATTR, nlri.nlri_data.link.attr);
	nlri.nlri_data.link.attr = NULL;

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
	int ret;

	if (!bgp || !router_id || !prefix)
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
	if (subnet && subnet->ls_pref) {
		nlri.nlri_data.prefix.attr = XCALLOC(MTYPE_BGP_LS_PREFIX_ATTR,
						     sizeof(struct bgp_ls_prefix_attr));
		if (bgp_ls_populate_prefix_attr(subnet->ls_pref, nlri.nlri_data.prefix.attr) < 0) {
			zlog_warn("BGP-LS: Failed to populate Prefix attributes");
			XFREE(MTYPE_BGP_LS_PREFIX_ATTR, nlri.nlri_data.prefix.attr);
			nlri.nlri_data.prefix.attr = NULL;
		}
	}

	/* Install in RIB */
	ret = bgp_ls_update(bgp, &nlri);

	if (ret < 0) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Failed to originate Prefix NLRI");
		bgp_ls_attr_prefix_free(&nlri.nlri_data.prefix.attr);
		return -1;
	}

	/*
	 * Note: Ownership of nlri.nlri_data.prefix.attr has been transferred to the route table.
	 * Set to NULL to avoid double-free. It will be freed by bgp_ls_nlri_free() when route is removed.
	 */
	XFREE(MTYPE_BGP_LS_PREFIX_ATTR, nlri.nlri_data.prefix.attr);
	nlri.nlri_data.prefix.attr = NULL;

	if (BGP_DEBUG(linkstate, LINKSTATE)) {
		char buf[PREFIX2STR_BUFFER];

		prefix2str(prefix, buf, sizeof(buf));
		zlog_debug("BGP-LS: Originated Prefix NLRI %s for protocol %u", buf, protocol_id);
	}

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

	/* Populate BGP-LS attributes from Link State subnet */
	if (subnet && subnet->ls_pref) {
		nlri.nlri_data.prefix.attr = XCALLOC(MTYPE_BGP_LS_PREFIX_ATTR,
						     sizeof(struct bgp_ls_prefix_attr));
		if (bgp_ls_populate_prefix_attr(subnet->ls_pref, nlri.nlri_data.prefix.attr) < 0) {
			zlog_warn("BGP-LS: Failed to populate Prefix attributes");
			XFREE(MTYPE_BGP_LS_PREFIX_ATTR, nlri.nlri_data.prefix.attr);
			nlri.nlri_data.prefix.attr = NULL;
		}
	}

	/* Withdraw from RIB */
	ret = bgp_ls_withdraw(bgp, &nlri);

	if (ret < 0) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Failed to withdraw Prefix NLRI");
		bgp_ls_attr_prefix_free(&nlri.nlri_data.prefix.attr);
		return -1;
	}

	/*
	 * Note: Ownership of nlri.nlri_data.prefix.attr has been transferred to the route table.
	 * Set to NULL to avoid double-free. It will be freed by bgp_ls_nlri_free() when route is removed.
	 */
	XFREE(MTYPE_BGP_LS_PREFIX_ATTR, nlri.nlri_data.prefix.attr);
	nlri.nlri_data.prefix.attr = NULL;

	if (BGP_DEBUG(linkstate, LINKSTATE)) {
		char buf[PREFIX2STR_BUFFER];

		prefix2str(prefix, buf, sizeof(buf));
		zlog_debug("BGP-LS: Withdrawn Prefix NLRI %s for protocol %u", buf, protocol_id);
	}

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

	switch (protocol_id) {
	case BGP_LS_PROTO_OSPFV2:
		/* OSPF uses 4-byte IPv4 router ID */
		memcpy(local_router_id, &edge->source->node->adv.id.ip.addr.s_addr, 4);
		local_router_id_len = 4;
		area_id = ntohl(edge->attributes->adv.id.ip.area_id.s_addr);
		break;
	case BGP_LS_PROTO_ISIS_L1:
	case BGP_LS_PROTO_ISIS_L2:
		/* IS-IS uses 6-byte System ID + 1 byte pseudonode ID = 7 bytes */
		memcpy(local_router_id, edge->source->node->adv.id.iso.sys_id, ISO_SYS_ID_LEN);
		// router_id[6] = 0; /* Pseudonode ID = 0 for router */
		// router_id_len = 7;
		local_router_id_len = 6;
		break;
	case BGP_LS_PROTO_DIRECT:
	case BGP_LS_PROTO_STATIC:
	case BGP_LS_PROTO_OSPFV3:
	case BGP_LS_PROTO_BGP:
	case BGP_LS_PROTO_RESERVED:
		zlog_err("BGP-LS: Unsupported protocol %u", protocol_id);
		return -1;
	}


	switch (protocol_id) {
	case BGP_LS_PROTO_OSPFV2:
		/* OSPF uses 4-byte IPv4 router ID */
		memcpy(remote_router_id, &edge->destination->node->adv.id.ip.addr.s_addr, 4);
		remote_router_id_len = 4;
		area_id = ntohl(edge->attributes->adv.id.ip.area_id.s_addr);
		break;
	case BGP_LS_PROTO_ISIS_L1:
	case BGP_LS_PROTO_ISIS_L2:
		/* IS-IS uses 6-byte System ID + 1 byte pseudonode ID = 7 bytes */
		memcpy(remote_router_id, edge->destination->node->adv.id.iso.sys_id,
		       ISO_SYS_ID_LEN);
		// router_id[6] = 0; /* Pseudonode ID = 0 for router */
		// router_id_len = 7;
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
	struct ls_subnet *subnet;
	bool is_delete;

	if (!bgp || !bgp->ls_info || !bgp->ls_info->ted || !msg)
		return -1;

	is_delete = msg->event == LS_MSG_EVENT_DELETE;

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
		vertex = ls_msg2vertex(bgp->ls_info->ted, msg, !is_delete);
		if (!vertex) {
			zlog_err("%s: Failed to convert message to vertex", __func__);
			return -1;
		}

		if (BGP_DEBUG(zebra, ZEBRA) || BGP_DEBUG(linkstate, LINKSTATE))
			zlog_debug("%s: Node vertex key=%" PRIu64, __func__, vertex->key);

		bgp_ls_process_vertex(bgp, vertex, msg->event);
		break;

	case LS_MSG_TYPE_ATTRIBUTES:
		edge = ls_msg2edge(bgp->ls_info->ted, msg, !is_delete);
		if (!edge) {
			zlog_err("%s: Failed to convert message to edge", __func__);
			return -1;
		}

		if (BGP_DEBUG(zebra, ZEBRA) || BGP_DEBUG(linkstate, LINKSTATE))
			zlog_debug("%s: Link edge", __func__);

		bgp_ls_process_edge(bgp, edge, msg->event);
		break;

	case LS_MSG_TYPE_PREFIX:
		subnet = ls_msg2subnet(bgp->ls_info->ted, msg, !is_delete);
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
		break;

	default:
		zlog_warn("%s: Unknown message type %d", __func__, msg->type);
		return -1;
	}

	return 0;
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
