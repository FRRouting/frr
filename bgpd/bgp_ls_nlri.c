// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Link-State NLRI (RFC 9552)
 * Copyright (C) 2025 Carmine Scarpitta
 */

#include <zebra.h>

#include "bgpd/bgp_ls_nlri.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_LS_NLRI, "BGP-LS NLRI");
DEFINE_MTYPE(BGPD, BGP_LS_ATTR, "BGP-LS Attribute");

/*
 * ===========================================================================
 * Node Descriptor Functions
 * ===========================================================================
 */

/*
 * Compare two node descriptors for equality
 * Returns 0 if equal, non-zero otherwise
 */
int bgp_ls_node_descriptor_cmp(const struct bgp_ls_node_descriptor *d1,
			       const struct bgp_ls_node_descriptor *d2)
{
	int ret;

	/* Must have same TLVs present */
	if (d1->present_tlvs != d2->present_tlvs)
		return d1->present_tlvs - d2->present_tlvs;

	/* Compare AS Number if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_NODE_DESC_AS_BIT)) {
		if (d1->asn != d2->asn)
			return d1->asn - d2->asn;
	}

	/* Compare BGP-LS ID if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_NODE_DESC_BGP_LS_ID_BIT)) {
		if (d1->bgp_ls_id != d2->bgp_ls_id)
			return d1->bgp_ls_id - d2->bgp_ls_id;
	}

	/* Compare OSPF Area ID if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_NODE_DESC_OSPF_AREA_BIT)) {
		if (d1->ospf_area_id != d2->ospf_area_id)
			return d1->ospf_area_id - d2->ospf_area_id;
	}

	/* Compare IGP Router ID if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT)) {
		if (d1->igp_router_id_len != d2->igp_router_id_len)
			return d1->igp_router_id_len - d2->igp_router_id_len;
		ret = memcmp(d1->igp_router_id, d2->igp_router_id, d1->igp_router_id_len);
		if (ret != 0)
			return ret;
	}

	return 0;
}

/*
 * ===========================================================================
 * Link Descriptor Functions
 * ===========================================================================
 */

/*
 * Compare two link descriptors for equality
 * Returns 0 if equal, non-zero otherwise
 */
int bgp_ls_link_descriptor_cmp(const struct bgp_ls_link_descriptor *d1,
			       const struct bgp_ls_link_descriptor *d2)
{
	int ret;

	/* Must have same TLVs present */
	if (d1->present_tlvs != d2->present_tlvs)
		return d1->present_tlvs - d2->present_tlvs;

	/* Compare Link IDs if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_LINK_DESC_LINK_ID_BIT)) {
		if (d1->link_local_id != d2->link_local_id)
			return d1->link_local_id - d2->link_local_id;
		if (d1->link_remote_id != d2->link_remote_id)
			return d1->link_remote_id - d2->link_remote_id;
	}

	/* Compare IPv4 Interface Address if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_LINK_DESC_IPV4_INTF_BIT)) {
		ret = IPV4_ADDR_CMP(&d1->ipv4_intf_addr, &d2->ipv4_intf_addr);
		if (ret != 0)
			return ret;
	}

	/* Compare IPv4 Neighbor Address if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_LINK_DESC_IPV4_NEIGH_BIT)) {
		ret = IPV4_ADDR_CMP(&d1->ipv4_neigh_addr, &d2->ipv4_neigh_addr);
		if (ret != 0)
			return ret;
	}

	/* Compare IPv6 Interface Address if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_LINK_DESC_IPV6_INTF_BIT)) {
		ret = IPV6_ADDR_CMP(&d1->ipv6_intf_addr, &d2->ipv6_intf_addr);
		if (ret != 0)
			return ret;
	}

	/* Compare IPv6 Neighbor Address if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_LINK_DESC_IPV6_NEIGH_BIT)) {
		ret = IPV6_ADDR_CMP(&d1->ipv6_neigh_addr, &d2->ipv6_neigh_addr);
		if (ret != 0)
			return ret;
	}

	/* Compare Multi-Topology IDs if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_LINK_DESC_MT_ID_BIT)) {
		if (d1->mt_id_count != d2->mt_id_count)
			return d1->mt_id_count - d2->mt_id_count;
		for (int i = 0; i < d1->mt_id_count; i++) {
			if (d1->mt_id[i] != d2->mt_id[i])
				return d1->mt_id[i] - d2->mt_id[i];
		}
	}

	return 0;
}

/*
 * ===========================================================================
 * Prefix Descriptor Functions
 * ===========================================================================
 */

/*
 * Compare two prefix descriptors for equality
 * Returns 0 if equal, non-zero otherwise
 */
int bgp_ls_prefix_descriptor_cmp(const struct bgp_ls_prefix_descriptor *d1,
				 const struct bgp_ls_prefix_descriptor *d2)
{
	int ret;

	/* Must have same TLVs present */
	if (d1->present_tlvs != d2->present_tlvs)
		return d1->present_tlvs - d2->present_tlvs;

	/* Compare prefix */
	ret = prefix_cmp(&d1->prefix, &d2->prefix);
	if (ret != 0)
		return ret;

	/* Compare OSPF Route Type if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_PREFIX_DESC_OSPF_ROUTE_BIT)) {
		if (d1->ospf_route_type != d2->ospf_route_type)
			return d1->ospf_route_type - d2->ospf_route_type;
	}

	/* Compare Multi-Topology IDs if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_PREFIX_DESC_MT_ID_BIT)) {
		if (d1->mt_id_count != d2->mt_id_count)
			return d1->mt_id_count - d2->mt_id_count;
		for (int i = 0; i < d1->mt_id_count; i++) {
			if (d1->mt_id[i] != d2->mt_id[i])
				return d1->mt_id[i] - d2->mt_id[i];
		}
	}

	return 0;
}

/*
 * ===========================================================================
 * NLRI Comparison Functions
 * ===========================================================================
 */

/*
 * Compare two NLRIs for equality
 * Returns 0 if equal, non-zero otherwise
 */
int bgp_ls_nlri_cmp(const struct bgp_ls_nlri *nlri1, const struct bgp_ls_nlri *nlri2)
{
	int ret;

	/* Different types are never equal */
	if (nlri1->nlri_type != nlri2->nlri_type)
		return nlri1->nlri_type - nlri2->nlri_type;

	/* Type-specific comparison */
	switch (nlri1->nlri_type) {
	case BGP_LS_NLRI_TYPE_NODE: {
		const struct bgp_ls_node_nlri *n1 = &nlri1->nlri_data.node;
		const struct bgp_ls_node_nlri *n2 = &nlri2->nlri_data.node;

		/* Compare protocol ID */
		if (n1->protocol_id != n2->protocol_id)
			return n1->protocol_id - n2->protocol_id;

		/* Compare identifier */
		if (n1->identifier != n2->identifier)
			return n1->identifier - n2->identifier;

		/* Compare local node descriptor */
		return bgp_ls_node_descriptor_cmp(&n1->local_node, &n2->local_node);
	}

	case BGP_LS_NLRI_TYPE_LINK: {
		const struct bgp_ls_link_nlri *l1 = &nlri1->nlri_data.link;
		const struct bgp_ls_link_nlri *l2 = &nlri2->nlri_data.link;

		/* Compare protocol ID */
		if (l1->protocol_id != l2->protocol_id)
			return l1->protocol_id - l2->protocol_id;

		/* Compare identifier */
		if (l1->identifier != l2->identifier)
			return l1->identifier - l2->identifier;

		/* Compare local node descriptor */
		ret = bgp_ls_node_descriptor_cmp(&l1->local_node, &l2->local_node);
		if (ret != 0)
			return ret;

		/* Compare remote node descriptor */
		ret = bgp_ls_node_descriptor_cmp(&l1->remote_node, &l2->remote_node);
		if (ret != 0)
			return ret;

		/* Compare link descriptor */
		return bgp_ls_link_descriptor_cmp(&l1->link_desc, &l2->link_desc);
	}

	case BGP_LS_NLRI_TYPE_IPV4_PREFIX:
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX: {
		const struct bgp_ls_prefix_nlri *p1 = &nlri1->nlri_data.prefix;
		const struct bgp_ls_prefix_nlri *p2 = &nlri2->nlri_data.prefix;

		/* Compare protocol ID */
		if (p1->protocol_id != p2->protocol_id)
			return p1->protocol_id - p2->protocol_id;

		/* Compare identifier */
		if (p1->identifier != p2->identifier)
			return p1->identifier - p2->identifier;

		/* Compare local node descriptor */
		ret = bgp_ls_node_descriptor_cmp(&p1->local_node, &p2->local_node);
		if (ret != 0)
			return ret;

		/* Compare prefix descriptor */
		return bgp_ls_prefix_descriptor_cmp(&p1->prefix_desc, &p2->prefix_desc);
	}

	case BGP_LS_NLRI_TYPE_RESERVED:
		/* Reserved type should never be compared */
		return 0;
	}

	return 0;
}

/*
 * Compare two BGP-LS attributes for equality
 * Returns 0 if equal, non-zero otherwise
 */
int bgp_ls_attr_cmp(const struct bgp_ls_attr *attr1, const struct bgp_ls_attr *attr2)
{
	int ret;

	if (attr1->present_tlvs != attr2->present_tlvs)
		return attr1->present_tlvs - attr2->present_tlvs;

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_NODE_FLAGS_BIT)) {
		if (attr1->node_flags != attr2->node_flags)
			return attr1->node_flags - attr2->node_flags;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_NODE_NAME_BIT)) {
		ret = strcmp(attr1->node_name, attr2->node_name);
		if (ret != 0)
			return ret;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_ISIS_AREA_BIT)) {
		if (attr1->isis_area_id_len != attr2->isis_area_id_len)
			return attr1->isis_area_id_len - attr2->isis_area_id_len;
		ret = memcmp(attr1->isis_area_id, attr2->isis_area_id, attr1->isis_area_id_len);
		if (ret != 0)
			return ret;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_IPV4_ROUTER_ID_LOCAL_BIT)) {
		ret = IPV4_ADDR_CMP(&attr1->ipv4_router_id_local, &attr2->ipv4_router_id_local);
		if (ret != 0)
			return ret;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_IPV6_ROUTER_ID_LOCAL_BIT)) {
		ret = IPV6_ADDR_CMP(&attr1->ipv6_router_id_local, &attr2->ipv6_router_id_local);
		if (ret != 0)
			return ret;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_IPV4_ROUTER_ID_REMOTE_BIT)) {
		ret = IPV4_ADDR_CMP(&attr1->ipv4_router_id_remote, &attr2->ipv4_router_id_remote);
		if (ret != 0)
			return ret;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_IPV6_ROUTER_ID_REMOTE_BIT)) {
		ret = IPV6_ADDR_CMP(&attr1->ipv6_router_id_remote, &attr2->ipv6_router_id_remote);
		if (ret != 0)
			return ret;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_ADMIN_GROUP_BIT)) {
		if (attr1->admin_group != attr2->admin_group)
			return attr1->admin_group - attr2->admin_group;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_MAX_LINK_BW_BIT)) {
		if (attr1->max_link_bw < attr2->max_link_bw)
			return -1;
		if (attr1->max_link_bw > attr2->max_link_bw)
			return 1;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_MAX_RESV_BW_BIT)) {
		if (attr1->max_resv_bw < attr2->max_resv_bw)
			return -1;
		if (attr1->max_resv_bw > attr2->max_resv_bw)
			return 1;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_UNRESV_BW_BIT)) {
		for (int i = 0; i < BGP_LS_MAX_UNRESV_BW; i++) {
			if (attr1->unreserved_bw[i] < attr2->unreserved_bw[i])
				return -1;
			if (attr1->unreserved_bw[i] > attr2->unreserved_bw[i])
				return 1;
		}
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_TE_METRIC_BIT)) {
		if (attr1->te_metric != attr2->te_metric)
			return attr1->te_metric - attr2->te_metric;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_LINK_PROTECTION_BIT)) {
		if (attr1->link_protection != attr2->link_protection)
			return attr1->link_protection - attr2->link_protection;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_MPLS_PROTOCOL_BIT)) {
		if (attr1->mpls_protocol_mask != attr2->mpls_protocol_mask)
			return attr1->mpls_protocol_mask - attr2->mpls_protocol_mask;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_IGP_METRIC_BIT)) {
		if (attr1->igp_metric_len != attr2->igp_metric_len)
			return attr1->igp_metric_len - attr2->igp_metric_len;
		if (attr1->igp_metric != attr2->igp_metric)
			return attr1->igp_metric - attr2->igp_metric;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_SRLG_BIT)) {
		if (attr1->srlg_count != attr2->srlg_count)
			return attr1->srlg_count - attr2->srlg_count;
		for (int i = 0; i < attr1->srlg_count; i++) {
			if (attr1->srlg_values[i] != attr2->srlg_values[i])
				return attr1->srlg_values[i] - attr2->srlg_values[i];
		}
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_LINK_NAME_BIT)) {
		ret = strcmp(attr1->link_name, attr2->link_name);
		if (ret != 0)
			return ret;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_IGP_FLAGS_BIT)) {
		if (attr1->igp_flags != attr2->igp_flags)
			return attr1->igp_flags - attr2->igp_flags;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_ROUTE_TAG_BIT)) {
		if (attr1->route_tag_count != attr2->route_tag_count)
			return attr1->route_tag_count - attr2->route_tag_count;
		for (int i = 0; i < attr1->route_tag_count; i++) {
			if (attr1->route_tags[i] != attr2->route_tags[i])
				return attr1->route_tags[i] - attr2->route_tags[i];
		}
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_EXTENDED_TAG_BIT)) {
		if (attr1->extended_tag_count != attr2->extended_tag_count)
			return attr1->extended_tag_count - attr2->extended_tag_count;
		for (int i = 0; i < attr1->extended_tag_count; i++) {
			if (attr1->extended_tags[i] != attr2->extended_tags[i])
				return attr1->extended_tags[i] - attr2->extended_tags[i];
		}
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_PREFIX_METRIC_BIT)) {
		if (attr1->prefix_metric != attr2->prefix_metric)
			return attr1->prefix_metric - attr2->prefix_metric;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_OSPF_FWD_ADDR_BIT)) {
		ret = IPV4_ADDR_CMP(&attr1->ospf_fwd_addr, &attr2->ospf_fwd_addr);
		if (ret != 0)
			return ret;
		ret = IPV6_ADDR_CMP(&attr1->ospf_fwd_addr6, &attr2->ospf_fwd_addr6);
		if (ret != 0)
			return ret;
	}

	if (attr1->opaque_len != attr2->opaque_len)
		return attr1->opaque_len - attr2->opaque_len;
	if (attr1->opaque_len > 0) {
		ret = memcmp(attr1->opaque_data, attr2->opaque_data, attr1->opaque_len);
		if (ret != 0)
			return ret;
	}

	if (attr1->mt_id_count != attr2->mt_id_count)
		return attr1->mt_id_count - attr2->mt_id_count;
	for (int i = 0; i < attr1->mt_id_count; i++) {
		if (attr1->mt_id[i] != attr2->mt_id[i])
			return attr1->mt_id[i] - attr2->mt_id[i];
	}

	return 0;
}

bool bgp_ls_attr_same(const struct bgp_ls_attr *attr1, const struct bgp_ls_attr *attr2)
{
	if (attr1 == attr2)
		return true;

	if (!attr1 || !attr2)
		return false;

	return bgp_ls_attr_cmp(attr1, attr2) == 0;
}

/*
 * ===========================================================================
 * NLRI Memory Management Functions
 * ===========================================================================
 */

struct bgp_ls_nlri *bgp_ls_nlri_alloc(void)
{
	struct bgp_ls_nlri *nlri;

	nlri = XCALLOC(MTYPE_BGP_LS_NLRI, sizeof(struct bgp_ls_nlri));
	return nlri;
}

void bgp_ls_nlri_free(struct bgp_ls_nlri *nlri)
{
	if (!nlri)
		return;

	switch (nlri->nlri_type) {
	case BGP_LS_NLRI_TYPE_NODE:
		break;

	case BGP_LS_NLRI_TYPE_LINK:
		XFREE(MTYPE_BGP_LS_NLRI, nlri->nlri_data.link.link_desc.mt_id);
		break;

	case BGP_LS_NLRI_TYPE_IPV4_PREFIX:
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX:
		XFREE(MTYPE_BGP_LS_NLRI, nlri->nlri_data.prefix.prefix_desc.mt_id);
		break;

	case BGP_LS_NLRI_TYPE_RESERVED:
		break;
	}

	XFREE(MTYPE_BGP_LS_NLRI, nlri);
}

struct bgp_ls_attr *bgp_ls_attr_alloc(void)
{
	struct bgp_ls_attr *attr;

	attr = XCALLOC(MTYPE_BGP_LS_ATTR, sizeof(struct bgp_ls_attr));
	return attr;
}

void bgp_ls_attr_free(struct bgp_ls_attr *attr)
{
	if (!attr)
		return;

	XFREE(MTYPE_BGP_LS_ATTR, attr->node_name);
	XFREE(MTYPE_BGP_LS_ATTR, attr->isis_area_id);
	XFREE(MTYPE_BGP_LS_ATTR, attr->mt_id);
	XFREE(MTYPE_BGP_LS_ATTR, attr->srlg_values);
	XFREE(MTYPE_BGP_LS_ATTR, attr->link_name);
	XFREE(MTYPE_BGP_LS_ATTR, attr->route_tags);
	XFREE(MTYPE_BGP_LS_ATTR, attr->extended_tags);
	XFREE(MTYPE_BGP_LS_ATTR, attr->opaque_data);

	XFREE(MTYPE_BGP_LS_ATTR, attr);
}

/*
 * ===========================================================================
 * NLRI Validation Functions
 * ===========================================================================
 */

/*
 * Validate IGP Router-ID length based on protocol (RFC 9552 Section 5.2.1.4)
 *
 * Valid lengths:
 *   4 octets  - OSPFv2/v3 non-pseudonode, Direct/Static IPv4
 *   6 octets  - IS-IS non-pseudonode
 *   7 octets  - IS-IS pseudonode
 *   8 octets  - OSPFv2/v3 pseudonode
 *   16 octets - Direct/Static IPv6, BGP IPv6
 */
static bool bgp_ls_igp_router_id_len_valid(enum bgp_ls_protocol_id proto_id, uint8_t len)
{
	switch (proto_id) {
	case BGP_LS_PROTO_ISIS_L1:
	case BGP_LS_PROTO_ISIS_L2:
		/* IS-IS: 6 octets (non-pseudonode) or 7 octets (pseudonode) */
		return (len == BGP_LS_IGP_ROUTER_ID_ISIS_LEN ||
			len == BGP_LS_IGP_ROUTER_ID_ISIS_PSEUDO_LEN);

	case BGP_LS_PROTO_OSPFV2:
	case BGP_LS_PROTO_OSPFV3:
		/* OSPF: 4 octets (non-pseudonode) or 8 octets (pseudonode) */
		return (len == BGP_LS_IGP_ROUTER_ID_OSPF_LEN ||
			len == BGP_LS_IGP_ROUTER_ID_OSPF_PSEUDO_LEN);

	case BGP_LS_PROTO_DIRECT:
	case BGP_LS_PROTO_STATIC:
		/* Direct/Static: Accept IPv4 (4) or IPv6 (16), or IGP formats if IGP is running */
		return (len == BGP_LS_IGP_ROUTER_ID_DIRECT_IPV4_LEN ||
			len == BGP_LS_IGP_ROUTER_ID_DIRECT_IPV6_LEN ||
			len == BGP_LS_IGP_ROUTER_ID_OSPF_LEN ||
			len == BGP_LS_IGP_ROUTER_ID_ISIS_LEN ||
			len == BGP_LS_IGP_ROUTER_ID_ISIS_PSEUDO_LEN ||
			len == BGP_LS_IGP_ROUTER_ID_OSPF_PSEUDO_LEN);

	case BGP_LS_PROTO_BGP:
		/* BGP: Typically uses IPv4 (4) or IPv6 (16) Router-ID */
		return (len == BGP_LS_IGP_ROUTER_ID_DIRECT_IPV4_LEN ||
			len == BGP_LS_IGP_ROUTER_ID_DIRECT_IPV6_LEN);

	case BGP_LS_PROTO_RESERVED:
		return false;
	}

	return false;
}

bool bgp_ls_nlri_validate(const struct bgp_ls_nlri *nlri)
{
	if (!nlri)
		return false;

	switch (nlri->nlri_type) {
	case BGP_LS_NLRI_TYPE_NODE: {
		const struct bgp_ls_node_nlri *n = &nlri->nlri_data.node;

		if (n->protocol_id == BGP_LS_PROTO_RESERVED)
			return false;

		/* IGP Router ID is mandatory (RFC 9552 Section 5.2.1.4) */
		if (!BGP_LS_TLV_CHECK(n->local_node.present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT))
			return false;

		if (!bgp_ls_igp_router_id_len_valid(n->protocol_id,
						    n->local_node.igp_router_id_len))
			return false;

		return true;
	}

	case BGP_LS_NLRI_TYPE_LINK: {
		const struct bgp_ls_link_nlri *l = &nlri->nlri_data.link;

		if (l->protocol_id == BGP_LS_PROTO_RESERVED)
			return false;

		/* Local node IGP Router ID is mandatory */
		if (!BGP_LS_TLV_CHECK(l->local_node.present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT))
			return false;

		/* Remote node IGP Router ID is mandatory */
		if (!BGP_LS_TLV_CHECK(l->remote_node.present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT))
			return false;

		if (!bgp_ls_igp_router_id_len_valid(l->protocol_id,
						    l->local_node.igp_router_id_len) ||
		    !bgp_ls_igp_router_id_len_valid(l->protocol_id,
						    l->remote_node.igp_router_id_len))
			return false;

		return true;
	}

	case BGP_LS_NLRI_TYPE_IPV4_PREFIX: {
		const struct bgp_ls_prefix_nlri *p = &nlri->nlri_data.prefix;

		if (p->protocol_id == BGP_LS_PROTO_RESERVED)
			return false;

		/* Local node IGP Router ID is mandatory */
		if (!BGP_LS_TLV_CHECK(p->local_node.present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT))
			return false;

		if (!bgp_ls_igp_router_id_len_valid(p->protocol_id,
						    p->local_node.igp_router_id_len))
			return false;

		/* Prefix family must be IPv4 */
		if (p->prefix_desc.prefix.family != AF_INET)
			return false;

		return true;
	}

	case BGP_LS_NLRI_TYPE_IPV6_PREFIX: {
		const struct bgp_ls_prefix_nlri *p = &nlri->nlri_data.prefix;

		if (p->protocol_id == BGP_LS_PROTO_RESERVED)
			return false;

		/* Local node IGP Router ID is mandatory */
		if (!BGP_LS_TLV_CHECK(p->local_node.present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT))
			return false;

		if (!bgp_ls_igp_router_id_len_valid(p->protocol_id,
						    p->local_node.igp_router_id_len))
			return false;

		/* Prefix family must be IPv6 */
		if (p->prefix_desc.prefix.family != AF_INET6)
			return false;

		return true;
	}

	case BGP_LS_NLRI_TYPE_RESERVED:
		/* Reserved type is invalid */
		return false;
	}

	return false;
}
