// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Link-State NLRI (RFC 9552)
 * Copyright (C) 2025 Carmine Scarpitta
 */

#include <zebra.h>

#include "bgpd/bgp_ls_nlri.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_LS_NLRI, "BGP-LS NLRI");
DEFINE_MTYPE(BGPD, BGP_LS_NODE_ATTR, "BGP-LS Node Attribute");
DEFINE_MTYPE(BGPD, BGP_LS_LINK_ATTR, "BGP-LS Link Attribute");
DEFINE_MTYPE(BGPD, BGP_LS_PREFIX_ATTR, "BGP-LS Prefix Attribute");
DEFINE_MTYPE(BGPD, BGP_LS_ATTR_DATA, "BGP-LS Attribute Data");

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
 * ===========================================================================
 * NLRI Memory Management Functions
 * ===========================================================================
 */

void bgp_ls_attr_node_init(struct bgp_ls_node_attr *attr)
{
	if (!attr)
		return;

	memset(attr, 0, sizeof(struct bgp_ls_node_attr));
	attr->node_name = NULL;
	attr->isis_area_id = NULL;
	attr->mt_id = NULL;
	attr->opaque_data = NULL;
}

void bgp_ls_attr_node_free(struct bgp_ls_node_attr **pattr)
{
	struct bgp_ls_node_attr *attr;

	if (!pattr || !*pattr)
		return;

	attr = *pattr;

	if (attr->node_name)
		XFREE(MTYPE_BGP_LS_ATTR_DATA, attr->node_name);

	if (attr->isis_area_id)
		XFREE(MTYPE_BGP_LS_ATTR_DATA, attr->isis_area_id);

	if (attr->mt_id)
		XFREE(MTYPE_BGP_LS_ATTR_DATA, attr->mt_id);

	if (attr->opaque_data)
		XFREE(MTYPE_BGP_LS_ATTR_DATA, attr->opaque_data);

	XFREE(MTYPE_BGP_LS_NODE_ATTR, *pattr);
}

void bgp_ls_attr_link_init(struct bgp_ls_link_attr *attr)
{
	if (!attr)
		return;

	memset(attr, 0, sizeof(struct bgp_ls_link_attr));
	attr->srlg_values = NULL;
	attr->link_name = NULL;
	attr->opaque_data = NULL;
}

void bgp_ls_attr_link_free(struct bgp_ls_link_attr **pattr)
{
	struct bgp_ls_link_attr *attr;

	if (!pattr || !*pattr)
		return;

	attr = *pattr;

	if (attr->srlg_values)
		XFREE(MTYPE_BGP_LS_ATTR_DATA, attr->srlg_values);

	if (attr->link_name)
		XFREE(MTYPE_BGP_LS_ATTR_DATA, attr->link_name);

	if (attr->opaque_data)
		XFREE(MTYPE_BGP_LS_ATTR_DATA, attr->opaque_data);

	XFREE(MTYPE_BGP_LS_LINK_ATTR, *pattr);
}

void bgp_ls_attr_prefix_init(struct bgp_ls_prefix_attr *attr)
{
	if (!attr)
		return;

	memset(attr, 0, sizeof(struct bgp_ls_prefix_attr));
	attr->route_tags = NULL;
	attr->extended_tags = NULL;
	attr->opaque_data = NULL;
}

void bgp_ls_attr_prefix_free(struct bgp_ls_prefix_attr **pattr)
{
	struct bgp_ls_prefix_attr *attr;

	if (!pattr || !*pattr)
		return;

	attr = *pattr;

	if (attr->route_tags)
		XFREE(MTYPE_BGP_LS_ATTR_DATA, attr->route_tags);

	if (attr->extended_tags)
		XFREE(MTYPE_BGP_LS_ATTR_DATA, attr->extended_tags);

	if (attr->opaque_data)
		XFREE(MTYPE_BGP_LS_ATTR_DATA, attr->opaque_data);

	XFREE(MTYPE_BGP_LS_PREFIX_ATTR, *pattr);
}

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
		bgp_ls_attr_node_free(&nlri->nlri_data.node.attr);
		break;

	case BGP_LS_NLRI_TYPE_LINK:
		bgp_ls_attr_link_free(&nlri->nlri_data.link.attr);
		XFREE(MTYPE_BGP_LS_NLRI, nlri->nlri_data.link.link_desc.mt_id);
		break;

	case BGP_LS_NLRI_TYPE_IPV4_PREFIX:
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX:
		bgp_ls_attr_prefix_free(&nlri->nlri_data.prefix.attr);
		XFREE(MTYPE_BGP_LS_NLRI, nlri->nlri_data.prefix.prefix_desc.mt_id);
		break;

	case BGP_LS_NLRI_TYPE_RESERVED:
		break;
	}

	XFREE(MTYPE_BGP_LS_NLRI, nlri);
}
