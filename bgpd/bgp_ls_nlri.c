// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Link-State NLRI (RFC 9552)
 * Copyright (C) 2025 Carmine Scarpitta
 */

#include <zebra.h>

#include "bgpd/bgp_ls.h"
#include "bgpd/bgp_ls_nlri.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_debug.h"

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
		return numcmp(d1->present_tlvs, d2->present_tlvs);

	/* Compare AS Number if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_NODE_DESC_AS_BIT)) {
		if (d1->asn != d2->asn)
			return numcmp(d1->asn, d2->asn);
	}

	/* Compare BGP-LS ID if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_NODE_DESC_BGP_LS_ID_BIT)) {
		if (d1->bgp_ls_id != d2->bgp_ls_id)
			return numcmp(d1->bgp_ls_id, d2->bgp_ls_id);
	}

	/* Compare OSPF Area ID if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_NODE_DESC_OSPF_AREA_BIT)) {
		if (d1->ospf_area_id != d2->ospf_area_id)
			return numcmp(d1->ospf_area_id, d2->ospf_area_id);
	}

	/* Compare IGP Router ID if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT)) {
		if (d1->igp_router_id_len != d2->igp_router_id_len)
			return numcmp(d1->igp_router_id_len, d2->igp_router_id_len);
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
		return numcmp(d1->present_tlvs, d2->present_tlvs);

	/* Compare Link IDs if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_LINK_DESC_LINK_ID_BIT)) {
		if (d1->link_local_id != d2->link_local_id)
			return numcmp(d1->link_local_id, d2->link_local_id);
		if (d1->link_remote_id != d2->link_remote_id)
			return numcmp(d1->link_remote_id, d2->link_remote_id);
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
			return numcmp(d1->mt_id_count, d2->mt_id_count);
		for (int i = 0; i < d1->mt_id_count; i++) {
			if (d1->mt_id[i] != d2->mt_id[i])
				return numcmp(d1->mt_id[i], d2->mt_id[i]);
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
		return numcmp(d1->present_tlvs, d2->present_tlvs);

	/* Compare prefix */
	ret = prefix_cmp(&d1->prefix, &d2->prefix);
	if (ret != 0)
		return ret;

	/* Compare OSPF Route Type if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_PREFIX_DESC_OSPF_ROUTE_BIT)) {
		if (d1->ospf_route_type != d2->ospf_route_type)
			return numcmp(d1->ospf_route_type, d2->ospf_route_type);
	}

	/* Compare Multi-Topology IDs if present */
	if (BGP_LS_TLV_CHECK(d1->present_tlvs, BGP_LS_PREFIX_DESC_MT_ID_BIT)) {
		if (d1->mt_id_count != d2->mt_id_count)
			return numcmp(d1->mt_id_count, d2->mt_id_count);
		for (int i = 0; i < d1->mt_id_count; i++) {
			if (d1->mt_id[i] != d2->mt_id[i])
				return numcmp(d1->mt_id[i], d2->mt_id[i]);
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
		return numcmp(nlri1->nlri_type, nlri2->nlri_type);

	/* Type-specific comparison */
	switch (nlri1->nlri_type) {
	case BGP_LS_NLRI_TYPE_NODE: {
		const struct bgp_ls_node_nlri *n1 = &nlri1->nlri_data.node;
		const struct bgp_ls_node_nlri *n2 = &nlri2->nlri_data.node;

		/* Compare protocol ID */
		if (n1->protocol_id != n2->protocol_id)
			return numcmp(n1->protocol_id, n2->protocol_id);

		/* Compare identifier */
		if (n1->identifier != n2->identifier)
			return numcmp(n1->identifier, n2->identifier);

		/* Compare local node descriptor */
		return bgp_ls_node_descriptor_cmp(&n1->local_node, &n2->local_node);
	}

	case BGP_LS_NLRI_TYPE_LINK: {
		const struct bgp_ls_link_nlri *l1 = &nlri1->nlri_data.link;
		const struct bgp_ls_link_nlri *l2 = &nlri2->nlri_data.link;

		/* Compare protocol ID */
		if (l1->protocol_id != l2->protocol_id)
			return numcmp(l1->protocol_id, l2->protocol_id);

		/* Compare identifier */
		if (l1->identifier != l2->identifier)
			return numcmp(l1->identifier, l2->identifier);

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
			return numcmp(p1->protocol_id, p2->protocol_id);

		/* Compare identifier */
		if (p1->identifier != p2->identifier)
			return numcmp(p1->identifier, p2->identifier);

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
		return numcmp(attr1->present_tlvs, attr2->present_tlvs);

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_NODE_FLAGS_BIT)) {
		if (attr1->node_flags != attr2->node_flags)
			return numcmp(attr1->node_flags, attr2->node_flags);
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_NODE_NAME_BIT)) {
		ret = strcmp(attr1->node_name, attr2->node_name);
		if (ret != 0)
			return ret;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_ISIS_AREA_BIT)) {
		if (attr1->isis_area_id_len != attr2->isis_area_id_len)
			return numcmp(attr1->isis_area_id_len, attr2->isis_area_id_len);
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
			return numcmp(attr1->admin_group, attr2->admin_group);
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
			return numcmp(attr1->te_metric, attr2->te_metric);
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_LINK_PROTECTION_BIT)) {
		if (attr1->link_protection != attr2->link_protection)
			return numcmp(attr1->link_protection, attr2->link_protection);
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_MPLS_PROTOCOL_BIT)) {
		if (attr1->mpls_protocol_mask != attr2->mpls_protocol_mask)
			return numcmp(attr1->mpls_protocol_mask, attr2->mpls_protocol_mask);
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_IGP_METRIC_BIT)) {
		if (attr1->igp_metric_len != attr2->igp_metric_len)
			return numcmp(attr1->igp_metric_len, attr2->igp_metric_len);
		if (attr1->igp_metric != attr2->igp_metric)
			return numcmp(attr1->igp_metric, attr2->igp_metric);
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_SRLG_BIT)) {
		if (attr1->srlg_count != attr2->srlg_count)
			return numcmp(attr1->srlg_count, attr2->srlg_count);
		for (int i = 0; i < attr1->srlg_count; i++) {
			if (attr1->srlg_values[i] != attr2->srlg_values[i])
				return numcmp(attr1->srlg_values[i], attr2->srlg_values[i]);
		}
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_LINK_NAME_BIT)) {
		ret = strcmp(attr1->link_name, attr2->link_name);
		if (ret != 0)
			return ret;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_IGP_FLAGS_BIT)) {
		if (attr1->igp_flags != attr2->igp_flags)
			return numcmp(attr1->igp_flags, attr2->igp_flags);
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_ROUTE_TAG_BIT)) {
		if (attr1->route_tag_count != attr2->route_tag_count)
			return numcmp(attr1->route_tag_count, attr2->route_tag_count);
		for (int i = 0; i < attr1->route_tag_count; i++) {
			if (attr1->route_tags[i] != attr2->route_tags[i])
				return numcmp(attr1->route_tags[i], attr2->route_tags[i]);
		}
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_EXTENDED_TAG_BIT)) {
		if (attr1->extended_tag_count != attr2->extended_tag_count)
			return numcmp(attr1->extended_tag_count, attr2->extended_tag_count);
		for (int i = 0; i < attr1->extended_tag_count; i++) {
			if (attr1->extended_tags[i] != attr2->extended_tags[i])
				return numcmp(attr1->extended_tags[i], attr2->extended_tags[i]);
		}
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_PREFIX_METRIC_BIT)) {
		if (attr1->prefix_metric != attr2->prefix_metric)
			return numcmp(attr1->prefix_metric, attr2->prefix_metric);
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_OSPF_FWD_ADDR_BIT)) {
		ret = IPV4_ADDR_CMP(&attr1->ospf_fwd_addr, &attr2->ospf_fwd_addr);
		if (ret != 0)
			return ret;
		ret = IPV6_ADDR_CMP(&attr1->ospf_fwd_addr6, &attr2->ospf_fwd_addr6);
		if (ret != 0)
			return ret;
	}

	if (BGP_LS_TLV_CHECK(attr1->present_tlvs, BGP_LS_ATTR_PREFIX_SID_BIT)) {
		if (attr1->prefix_sid.sid != attr2->prefix_sid.sid)
			return numcmp(attr1->prefix_sid.sid, attr2->prefix_sid.sid);
		if (attr1->prefix_sid.sid_flag != attr2->prefix_sid.sid_flag)
			return numcmp(attr1->prefix_sid.sid_flag, attr2->prefix_sid.sid_flag);
		if (attr1->prefix_sid.algo != attr2->prefix_sid.algo)
			return numcmp(attr1->prefix_sid.algo, attr2->prefix_sid.algo);
	}

	if (attr1->opaque_len != attr2->opaque_len)
		return numcmp(attr1->opaque_len, attr2->opaque_len);
	if (attr1->opaque_len > 0) {
		ret = memcmp(attr1->opaque_data, attr2->opaque_data, attr1->opaque_len);
		if (ret != 0)
			return ret;
	}

	if (attr1->mt_id_count != attr2->mt_id_count)
		return numcmp(attr1->mt_id_count, attr2->mt_id_count);
	for (int i = 0; i < attr1->mt_id_count; i++) {
		if (attr1->mt_id[i] != attr2->mt_id[i])
			return numcmp(attr1->mt_id[i], attr2->mt_id[i]);
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
	admin_group_init(&attr->ext_admin_group);
	return attr;
}

void bgp_ls_attr_free(struct bgp_ls_attr *attr)
{
	if (!attr)
		return;

	admin_group_term(&attr->ext_admin_group);

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

/* Deep copy BGP-LS NLRI (including dynamic fields) */
struct bgp_ls_nlri *bgp_ls_nlri_copy(const struct bgp_ls_nlri *nlri)
{
	struct bgp_ls_nlri *nlri_copy;

	if (!nlri)
		return NULL;

	/* Allocate and copy NLRI */
	nlri_copy = XCALLOC(MTYPE_BGP_LS_NLRI, sizeof(*nlri_copy));
	memcpy(nlri_copy, nlri, sizeof(*nlri_copy));
	nlri_copy->refcnt = 0;

	/* Copy type-specific dynamically allocated fields */
	switch (nlri->nlri_type) {
	case BGP_LS_NLRI_TYPE_NODE:
		break;

	case BGP_LS_NLRI_TYPE_LINK:
		/* Copy link descriptor mt_id */
		if (nlri->nlri_data.link.link_desc.mt_id) {
			size_t mt_size = nlri->nlri_data.link.link_desc.mt_id_count *
					 sizeof(uint16_t);
			nlri_copy->nlri_data.link.link_desc.mt_id = XCALLOC(MTYPE_BGP_LS_NLRI,
									    mt_size);
			memcpy(nlri_copy->nlri_data.link.link_desc.mt_id,
			       nlri->nlri_data.link.link_desc.mt_id, mt_size);
		}
		break;

	case BGP_LS_NLRI_TYPE_IPV4_PREFIX:
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX:
		/* Copy prefix descriptor mt_id */
		if (nlri->nlri_data.prefix.prefix_desc.mt_id) {
			size_t mt_size = nlri->nlri_data.prefix.prefix_desc.mt_id_count *
					 sizeof(uint16_t);
			nlri_copy->nlri_data.prefix.prefix_desc.mt_id = XCALLOC(MTYPE_BGP_LS_NLRI,
										mt_size);
			memcpy(nlri_copy->nlri_data.prefix.prefix_desc.mt_id,
			       nlri->nlri_data.prefix.prefix_desc.mt_id, mt_size);
		}
		break;

	case BGP_LS_NLRI_TYPE_RESERVED:
		break;
	}

	return nlri_copy;
}

struct bgp_ls_attr *bgp_ls_attr_copy(const struct bgp_ls_attr *src)
{
	struct bgp_ls_attr *dst;
	size_t mt_size;
	size_t srlg_size;
	size_t tag_size;

	if (!src)
		return NULL;

	dst = XCALLOC(MTYPE_BGP_LS_ATTR, sizeof(*dst));
	memcpy(dst, src, sizeof(*dst));

	/* Must deep-copy some struct members */

	/* Reset and properly copy admin_group */
	memset(&dst->ext_admin_group, 0, sizeof(dst->ext_admin_group));
	admin_group_copy(&dst->ext_admin_group, &src->ext_admin_group);

	if (src->node_name)
		dst->node_name = XSTRDUP(MTYPE_BGP_LS_ATTR, src->node_name);

	if (src->isis_area_id) {
		dst->isis_area_id = XCALLOC(MTYPE_BGP_LS_ATTR, src->isis_area_id_len);
		memcpy(dst->isis_area_id, src->isis_area_id, src->isis_area_id_len);
	}

	if (src->mt_id) {
		mt_size = src->mt_id_count * sizeof(uint16_t);
		dst->mt_id = XCALLOC(MTYPE_BGP_LS_ATTR, mt_size);
		memcpy(dst->mt_id, src->mt_id, mt_size);
	}

	if (src->srlg_values) {
		srlg_size = src->srlg_count * sizeof(uint32_t);
		dst->srlg_values = XCALLOC(MTYPE_BGP_LS_ATTR, srlg_size);
		memcpy(dst->srlg_values, src->srlg_values, srlg_size);
	}

	if (src->link_name)
		dst->link_name = XSTRDUP(MTYPE_BGP_LS_ATTR, src->link_name);

	if (src->route_tags) {
		tag_size = src->route_tag_count * sizeof(uint32_t);
		dst->route_tags = XCALLOC(MTYPE_BGP_LS_ATTR, tag_size);
		memcpy(dst->route_tags, src->route_tags, tag_size);
	}

	if (src->extended_tags) {
		tag_size = src->extended_tag_count * sizeof(uint64_t);
		dst->extended_tags = XCALLOC(MTYPE_BGP_LS_ATTR, tag_size);
		memcpy(dst->extended_tags, src->extended_tags, tag_size);
	}

	if (src->opaque_data) {
		dst->opaque_data = XCALLOC(MTYPE_BGP_LS_ATTR, src->opaque_len);
		memcpy(dst->opaque_data, src->opaque_data, src->opaque_len);
	}

	return dst;
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

/*
 * ===========================================================================
 * NLRI Size Calculation Functions
 * ===========================================================================
 */

/* Calculate size of node descriptor TLV */
static size_t bgp_ls_node_descriptor_size(const struct bgp_ls_node_descriptor *desc)
{
	size_t size = BGP_LS_TLV_HDR_SIZE; /* Descriptor TLV header */

	/* AS Number TLV */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_AS_BIT))
		size += BGP_LS_TLV_HDR_SIZE + BGP_LS_AS_NUMBER_SIZE;
	/* BGP-LS ID TLV */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_BGP_LS_ID_BIT))
		size += BGP_LS_TLV_HDR_SIZE + BGP_LS_BGP_LS_ID_SIZE;
	/* OSPF Area ID TLV */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_OSPF_AREA_BIT))
		size += BGP_LS_TLV_HDR_SIZE + BGP_LS_OSPF_AREA_ID_SIZE;
	/* IGP Router ID TLV */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT))
		size += BGP_LS_TLV_HDR_SIZE + desc->igp_router_id_len;

	return size;
}

/* Calculate wire format size of NLRI */
size_t bgp_ls_nlri_size(const struct bgp_ls_nlri *nlri)
{
	size_t size = 0;

	if (!nlri)
		return 0;

	/* Common NLRI header: Protocol-ID + Identifier */
	size += BGP_LS_NLRI_HDR_SIZE;

	switch (nlri->nlri_type) {
	case BGP_LS_NLRI_TYPE_NODE: {
		const struct bgp_ls_node_nlri *n = &nlri->nlri_data.node;

		/* Local Node Descriptor */
		size += bgp_ls_node_descriptor_size(&n->local_node);

		break;
	}

	case BGP_LS_NLRI_TYPE_LINK: {
		const struct bgp_ls_link_nlri *l = &nlri->nlri_data.link;

		/* Local Node Descriptor */
		size += bgp_ls_node_descriptor_size(&l->local_node);

		/* Remote Node Descriptor */
		size += bgp_ls_node_descriptor_size(&l->remote_node);

		/* Link Descriptor */
		if (BGP_LS_TLV_CHECK(l->link_desc.present_tlvs, BGP_LS_LINK_DESC_LINK_ID_BIT))
			size += BGP_LS_TLV_HDR_SIZE + BGP_LS_LINK_ID_SIZE;
		if (BGP_LS_TLV_CHECK(l->link_desc.present_tlvs, BGP_LS_LINK_DESC_IPV4_INTF_BIT))
			size += BGP_LS_TLV_HDR_SIZE + BGP_LS_IPV4_ADDR_SIZE;
		if (BGP_LS_TLV_CHECK(l->link_desc.present_tlvs, BGP_LS_LINK_DESC_IPV4_NEIGH_BIT))
			size += BGP_LS_TLV_HDR_SIZE + BGP_LS_IPV4_ADDR_SIZE;
		if (BGP_LS_TLV_CHECK(l->link_desc.present_tlvs, BGP_LS_LINK_DESC_IPV6_INTF_BIT))
			size += BGP_LS_TLV_HDR_SIZE + BGP_LS_IPV6_ADDR_SIZE;
		if (BGP_LS_TLV_CHECK(l->link_desc.present_tlvs, BGP_LS_LINK_DESC_IPV6_NEIGH_BIT))
			size += BGP_LS_TLV_HDR_SIZE + BGP_LS_IPV6_ADDR_SIZE;
		if (BGP_LS_TLV_CHECK(l->link_desc.present_tlvs, BGP_LS_LINK_DESC_MT_ID_BIT))
			size += BGP_LS_TLV_HDR_SIZE +
				(l->link_desc.mt_id_count * BGP_LS_MT_ID_SIZE);

		break;
	}

	case BGP_LS_NLRI_TYPE_IPV4_PREFIX:
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX: {
		const struct bgp_ls_prefix_nlri *p = &nlri->nlri_data.prefix;

		/* Local Node Descriptor */
		size += bgp_ls_node_descriptor_size(&p->local_node);

		/* Prefix Descriptor */
		if (BGP_LS_TLV_CHECK(p->prefix_desc.present_tlvs, BGP_LS_PREFIX_DESC_MT_ID_BIT))
			size += BGP_LS_TLV_HDR_SIZE +
				(p->prefix_desc.mt_id_count * BGP_LS_MT_ID_SIZE);
		if (BGP_LS_TLV_CHECK(p->prefix_desc.present_tlvs,
				     BGP_LS_PREFIX_DESC_OSPF_ROUTE_BIT))
			size += BGP_LS_TLV_HDR_SIZE + BGP_LS_OSPF_ROUTE_TYPE_SIZE;

		/* IP Reachability Info TLV */
		if (nlri->nlri_type == BGP_LS_NLRI_TYPE_IPV4_PREFIX)
			size += BGP_LS_TLV_HDR_SIZE + BGP_LS_PREFIX_LEN_SIZE +
				BGP_LS_IPV4_ADDR_SIZE;
		else
			size += BGP_LS_TLV_HDR_SIZE + BGP_LS_PREFIX_LEN_SIZE +
				BGP_LS_IPV6_ADDR_SIZE;

		break;
	}

	case BGP_LS_NLRI_TYPE_RESERVED:
		return 0;
	}

	return size;
}

/*
 * ===========================================================================
 * String Conversion Functions
 * ===========================================================================
 */

const char *bgp_ls_protocol_id_str(enum bgp_ls_protocol_id proto_id)
{
	switch (proto_id) {
	case BGP_LS_PROTO_RESERVED:
		return "Reserved";
	case BGP_LS_PROTO_ISIS_L1:
		return "IS-IS Level 1";
	case BGP_LS_PROTO_ISIS_L2:
		return "IS-IS Level 2";
	case BGP_LS_PROTO_OSPFV2:
		return "OSPFv2";
	case BGP_LS_PROTO_DIRECT:
		return "Direct";
	case BGP_LS_PROTO_STATIC:
		return "Static";
	case BGP_LS_PROTO_OSPFV3:
		return "OSPFv3";
	case BGP_LS_PROTO_BGP:
		return "BGP";
	}

	return "Unknown";
}

const char *bgp_ls_nlri_type_str(enum bgp_ls_nlri_type nlri_type)
{
	switch (nlri_type) {
	case BGP_LS_NLRI_TYPE_RESERVED:
		return "Reserved";
	case BGP_LS_NLRI_TYPE_NODE:
		return "Node";
	case BGP_LS_NLRI_TYPE_LINK:
		return "Link";
	case BGP_LS_NLRI_TYPE_IPV4_PREFIX:
		return "IPv4 Prefix";
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX:
		return "IPv6 Prefix";
	}

	return "Unknown";
}

const char *bgp_ls_node_descriptor_tlv_str(enum bgp_ls_node_descriptor_tlv tlv_type)
{
	switch (tlv_type) {
	case BGP_LS_TLV_LOCAL_NODE_DESC:
		return "Local Node Descriptors";
	case BGP_LS_TLV_REMOTE_NODE_DESC:
		return "Remote Node Descriptors";
	case BGP_LS_TLV_AS_NUMBER:
		return "Autonomous System";
	case BGP_LS_TLV_BGP_LS_ID:
		return "BGP-LS Identifier";
	case BGP_LS_TLV_OSPF_AREA_ID:
		return "OSPF Area-ID";
	case BGP_LS_TLV_IGP_ROUTER_ID:
		return "IGP Router-ID";
	}

	return "Unknown";
}

const char *bgp_ls_link_descriptor_tlv_str(enum bgp_ls_link_descriptor_tlv tlv_type)
{
	switch (tlv_type) {
	case BGP_LS_TLV_LINK_ID:
		return "Link Local/Remote Identifiers";
	case BGP_LS_TLV_IPV4_INTF_ADDR:
		return "IPv4 Interface Address";
	case BGP_LS_TLV_IPV4_NEIGH_ADDR:
		return "IPv4 Neighbor Address";
	case BGP_LS_TLV_IPV6_INTF_ADDR:
		return "IPv6 Interface Address";
	case BGP_LS_TLV_IPV6_NEIGH_ADDR:
		return "IPv6 Neighbor Address";
	case BGP_LS_TLV_MT_ID:
		return "Multi-Topology Identifier";
	case BGP_LS_TLV_REMOTE_AS_NUMBER:
		return "Remote AS Number";
	}

	return "Unknown";
}

const char *bgp_ls_prefix_descriptor_tlv_str(enum bgp_ls_prefix_descriptor_tlv tlv_type)
{
	switch (tlv_type) {
	case BGP_LS_TLV_OSPF_ROUTE_TYPE:
		return "OSPF Route Type";
	case BGP_LS_TLV_IP_REACH_INFO:
		return "IP Reachability Information";
	}

	return "Unknown";
}

const char *bgp_ls_ospf_route_type_str(enum bgp_ls_ospf_route_type route_type)
{
	switch (route_type) {
	case BGP_LS_OSPF_RT_INTRA_AREA:
		return "Intra-Area";
	case BGP_LS_OSPF_RT_INTER_AREA:
		return "Inter-Area";
	case BGP_LS_OSPF_RT_EXTERNAL_1:
		return "External Type 1";
	case BGP_LS_OSPF_RT_EXTERNAL_2:
		return "External Type 2";
	case BGP_LS_OSPF_RT_NSSA_1:
		return "NSSA Type 1";
	case BGP_LS_OSPF_RT_NSSA_2:
		return "NSSA Type 2";
	}

	return "Unknown";
}

const char *bgp_ls_ospf_route_type_str_json(enum bgp_ls_ospf_route_type route_type)
{
	switch (route_type) {
	case BGP_LS_OSPF_RT_INTRA_AREA:
		return "intraArea";
	case BGP_LS_OSPF_RT_INTER_AREA:
		return "interArea";
	case BGP_LS_OSPF_RT_EXTERNAL_1:
		return "externalType1";
	case BGP_LS_OSPF_RT_EXTERNAL_2:
		return "externalType2";
	case BGP_LS_OSPF_RT_NSSA_1:
		return "nssaType1";
	case BGP_LS_OSPF_RT_NSSA_2:
		return "nssaType2";
	}

	return "Unknown";
}

/*
 * ===========================================================================
 * Hash Key Functions
 * ===========================================================================
 */

/* Hash a node descriptor */
static unsigned int bgp_ls_node_descriptor_hash(const struct bgp_ls_node_descriptor *desc,
						uint32_t key)
{
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_AS_BIT))
		key = jhash_1word(desc->asn, key);

	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_BGP_LS_ID_BIT))
		key = jhash_1word(desc->bgp_ls_id, key);

	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_OSPF_AREA_BIT))
		key = jhash_1word(desc->ospf_area_id, key);

	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT))
		key = jhash(desc->igp_router_id, desc->igp_router_id_len, key);

	return key;
}

/* Hash key generation for Node NLRI */
static unsigned int bgp_ls_node_hash_key_internal(const struct bgp_ls_nlri *nlri)
{
	const struct bgp_ls_node_nlri *node = &nlri->nlri_data.node;
	uint32_t key = 0;

	/* Hash protocol_id and identifier */
	key = jhash_2words(node->protocol_id, (uint32_t)(node->identifier >> 32), key);
	key = jhash_1word((uint32_t)node->identifier, key);

	/* Hash node descriptor */
	key = bgp_ls_node_descriptor_hash(&node->local_node, key);

	return key;
}

/* Hash key generation for Link NLRI */
static unsigned int bgp_ls_link_hash_key_internal(const struct bgp_ls_nlri *nlri)
{
	const struct bgp_ls_link_nlri *link = &nlri->nlri_data.link;
	uint32_t key = 0;

	/* Hash protocol_id and identifier */
	key = jhash_2words(link->protocol_id, (uint32_t)(link->identifier >> 32), key);
	key = jhash_1word((uint32_t)link->identifier, key);

	/* Hash local and remote node descriptors */
	key = bgp_ls_node_descriptor_hash(&link->local_node, key);
	key = bgp_ls_node_descriptor_hash(&link->remote_node, key);

	/* Hash link descriptor */
	if (BGP_LS_TLV_CHECK(link->link_desc.present_tlvs, BGP_LS_LINK_DESC_LINK_ID_BIT))
		key = jhash_2words(link->link_desc.link_local_id, link->link_desc.link_remote_id,
				   key);

	if (BGP_LS_TLV_CHECK(link->link_desc.present_tlvs, BGP_LS_LINK_DESC_IPV4_INTF_BIT))
		key = jhash_1word(link->link_desc.ipv4_intf_addr.s_addr, key);

	if (BGP_LS_TLV_CHECK(link->link_desc.present_tlvs, BGP_LS_LINK_DESC_IPV4_NEIGH_BIT))
		key = jhash_1word(link->link_desc.ipv4_neigh_addr.s_addr, key);

	if (BGP_LS_TLV_CHECK(link->link_desc.present_tlvs, BGP_LS_LINK_DESC_IPV6_INTF_BIT))
		key = jhash(&link->link_desc.ipv6_intf_addr, sizeof(struct in6_addr), key);

	if (BGP_LS_TLV_CHECK(link->link_desc.present_tlvs, BGP_LS_LINK_DESC_IPV6_NEIGH_BIT))
		key = jhash(&link->link_desc.ipv6_neigh_addr, sizeof(struct in6_addr), key);

	return key;
}

/* Hash key generation for Prefix NLRI (IPv4 and IPv6) */
static unsigned int bgp_ls_prefix_hash_key_internal(const struct bgp_ls_nlri *nlri)
{
	const struct bgp_ls_prefix_nlri *prefix = &nlri->nlri_data.prefix;
	uint32_t key = 0;

	/* Hash protocol_id and identifier */
	key = jhash_2words(prefix->protocol_id, (uint32_t)(prefix->identifier >> 32), key);
	key = jhash_1word((uint32_t)prefix->identifier, key);

	/* Hash local node descriptor */
	key = bgp_ls_node_descriptor_hash(&prefix->local_node, key);

	/* Hash prefix descriptor */
	key = jhash_1word(prefix->prefix_desc.prefix.prefixlen, key);

	if (prefix->prefix_desc.prefix.family == AF_INET)
		key = jhash_1word(prefix->prefix_desc.prefix.u.prefix4.s_addr, key);
	else if (prefix->prefix_desc.prefix.family == AF_INET6)
		key = jhash(&prefix->prefix_desc.prefix.u.prefix6, sizeof(struct in6_addr), key);

	/* Hash OSPF route type if present */
	if (BGP_LS_TLV_CHECK(prefix->prefix_desc.present_tlvs, BGP_LS_PREFIX_DESC_OSPF_ROUTE_BIT))
		key = jhash_1word(prefix->prefix_desc.ospf_route_type, key);

	return key;
}

/* Hash key generation for BGP-LS NLRI */
unsigned int bgp_ls_nlri_hash_key(const struct bgp_ls_nlri *nlri)
{
	/* Include NLRI type in hash to ensure different types don't collide */
	uint32_t key = jhash_1word(nlri->nlri_type, 0);

	switch (nlri->nlri_type) {
	case BGP_LS_NLRI_TYPE_NODE:
		return key ^ bgp_ls_node_hash_key_internal(nlri);
	case BGP_LS_NLRI_TYPE_LINK:
		return key ^ bgp_ls_link_hash_key_internal(nlri);
	case BGP_LS_NLRI_TYPE_IPV4_PREFIX:
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX:
		return key ^ bgp_ls_prefix_hash_key_internal(nlri);
	case BGP_LS_NLRI_TYPE_RESERVED:
		return key;
	}

	return key;
}

/*
 * Generate hash key for BGP-LS attribute
 * This hashes all fields present in the attribute based on present_tlvs bitmask
 */
unsigned int bgp_ls_attr_hash_key(const struct bgp_ls_attr *attr)
{
	uint32_t key = 0;

	if (!attr)
		return 0;

	/* Hash the present_tlvs bitmask first */
	key = jhash_1word((uint32_t)(attr->present_tlvs >> 32), key);
	key = jhash_1word((uint32_t)attr->present_tlvs, key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_NODE_FLAGS_BIT))
		key = jhash_1word(attr->node_flags, key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_NODE_NAME_BIT))
		key = jhash(attr->node_name, strlen(attr->node_name), key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_ISIS_AREA_BIT))
		key = jhash(attr->isis_area_id, attr->isis_area_id_len, key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IPV4_ROUTER_ID_LOCAL_BIT))
		key = jhash_1word(attr->ipv4_router_id_local.s_addr, key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IPV6_ROUTER_ID_LOCAL_BIT))
		key = jhash(&attr->ipv6_router_id_local, sizeof(struct in6_addr), key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IPV4_ROUTER_ID_REMOTE_BIT))
		key = jhash_1word(attr->ipv4_router_id_remote.s_addr, key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IPV6_ROUTER_ID_REMOTE_BIT))
		key = jhash(&attr->ipv6_router_id_remote, sizeof(struct in6_addr), key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_ADMIN_GROUP_BIT))
		key = jhash_1word(attr->admin_group, key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_MAX_LINK_BW_BIT)) {
		uint32_t bw;

		memcpy(&bw, &attr->max_link_bw, sizeof(uint32_t));
		key = jhash_1word(bw, key);
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_MAX_RESV_BW_BIT)) {
		uint32_t bw;

		memcpy(&bw, &attr->max_resv_bw, sizeof(uint32_t));
		key = jhash_1word(bw, key);
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_UNRESV_BW_BIT))
		key = jhash(attr->unreserved_bw, sizeof(attr->unreserved_bw), key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_TE_METRIC_BIT))
		key = jhash_1word(attr->te_metric, key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_LINK_PROTECTION_BIT))
		key = jhash_1word(attr->link_protection, key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_MPLS_PROTOCOL_BIT))
		key = jhash_1word(attr->mpls_protocol_mask, key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IGP_METRIC_BIT))
		key = jhash_1word(attr->igp_metric, key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_SRLG_BIT)) {
		for (int i = 0; i < attr->srlg_count; i++)
			key = jhash_1word(attr->srlg_values[i], key);
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_LINK_NAME_BIT))
		key = jhash(attr->link_name, strlen(attr->link_name), key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IGP_FLAGS_BIT))
		key = jhash_1word(attr->igp_flags, key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_ROUTE_TAG_BIT)) {
		for (int i = 0; i < attr->route_tag_count; i++)
			key = jhash_1word(attr->route_tags[i], key);
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_EXTENDED_TAG_BIT)) {
		for (int i = 0; i < attr->extended_tag_count; i++) {
			key = jhash_1word((uint32_t)(attr->extended_tags[i] >> 32), key);
			key = jhash_1word((uint32_t)attr->extended_tags[i], key);
		}
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_PREFIX_METRIC_BIT))
		key = jhash_1word(attr->prefix_metric, key);

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_OSPF_FWD_ADDR_BIT)) {
		key = jhash_1word(attr->ospf_fwd_addr.s_addr, key);
		key = jhash(&attr->ospf_fwd_addr6, sizeof(struct in6_addr), key);
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_PREFIX_SID_BIT))
		key = jhash(&attr->prefix_sid, sizeof(attr->prefix_sid), key);

	if (attr->opaque_len > 0)
		key = jhash(attr->opaque_data, attr->opaque_len, key);

	for (int i = 0; i < attr->mt_id_count; i++)
		key = jhash_1word(attr->mt_id[i], key);

	return key;
}

/*
 * ===========================================================================
 * Hash Comparison Functions
 * ===========================================================================
 */

/*
 * Hash table comparison function for BGP-LS NLRI
 * Returns 0 if equal, non-zero if not equal
 */
int bgp_ls_nlri_hash_cmp(const struct bgp_ls_nlri *n1, const struct bgp_ls_nlri *n2)
{
	return bgp_ls_nlri_cmp(n1, n2);
}

/*
 * Hash table comparison function for BGP-LS attributes
 * Returns 0 if equal, non-zero if not equal
 */
int bgp_ls_attr_hash_cmp(const struct bgp_ls_attr *a1, const struct bgp_ls_attr *a2)
{
	return bgp_ls_attr_cmp(a1, a2);
}

/*
 * ===========================================================================
 * BGP-LS NLRI Hash Table Management Functions
 * ===========================================================================
 */

/* Insert or lookup NLRI in hash table */
struct bgp_ls_nlri *bgp_ls_nlri_get(struct bgp_ls_nlri_hash_head *hash, struct bgp *bgp,
				    struct bgp_ls_nlri *nlri)
{
	struct bgp_ls_nlri *ls_nlri;

	ls_nlri = bgp_ls_nlri_lookup(hash, nlri);
	if (!ls_nlri) {
		ls_nlri = bgp_ls_nlri_copy(nlri);
		ls_nlri->id = idalloc_allocate(bgp->ls_info->allocator);

		bgp_ls_nlri_hash_add(hash, ls_nlri);
	}

	ls_nlri->refcnt++;
	return ls_nlri;
}

/* Lookup NLRI in BGP-LS NLRI hash table */
struct bgp_ls_nlri *bgp_ls_nlri_lookup(struct bgp_ls_nlri_hash_head *hash, struct bgp_ls_nlri *nlri)
{
	struct bgp_ls_nlri lookup;

	if (!hash)
		return NULL;

	memset(&lookup, 0, sizeof(lookup));
	lookup.nlri_type = nlri->nlri_type;
	lookup.nlri_data = nlri->nlri_data;

	return bgp_ls_nlri_hash_find(hash, &lookup);
}

/* Insert or lookup BGP-LS attribute in hash table */
struct bgp_ls_attr *bgp_ls_attr_get(struct bgp_ls_attr_hash_head *hash, struct bgp *bgp,
				    struct bgp_ls_attr *attr)
{
	struct bgp_ls_attr *ls_attr;

	ls_attr = bgp_ls_attr_lookup(hash, attr);
	if (!ls_attr) {
		ls_attr = bgp_ls_attr_copy(attr);

		bgp_ls_attr_hash_add(hash, ls_attr);
	}

	ls_attr->refcnt++;
	return ls_attr;
}

/*
 * Lookup BGP-LS attribute in hash table
 *
 * Parameters:
 *   hash - Hash table head
 *   attr - Attribute to look up
 *
 * Returns:
 *   Pointer to matching attribute if found, NULL otherwise
 */
struct bgp_ls_attr *bgp_ls_attr_lookup(struct bgp_ls_attr_hash_head *hash,
				       const struct bgp_ls_attr *attr)
{
	struct bgp_ls_attr lookup;

	if (!hash || !attr)
		return NULL;

	/* Set up lookup key - copy the attribute for comparison */
	memcpy(&lookup, attr, sizeof(lookup));

	return bgp_ls_attr_hash_find(hash, &lookup);
}

/*
 * ===========================================================================
 * NLRI Interning (Lookup + Lock/Unlock)
 * ===========================================================================
 */

/*
 * Intern BGP-LS NLRI (lookup and lock)
 *
 * Looks up an existing NLRI in the hash table and increments its reference count.
 * Returns the NLRI if found, NULL otherwise.
 */
struct bgp_ls_nlri *bgp_ls_nlri_intern(struct bgp_ls_nlri *ls_nlri)
{
	struct bgp *bgp = bgp_get_default();

	if (!bgp || !bgp->ls_info || !ls_nlri)
		return NULL;

	return bgp_ls_nlri_get(&bgp->ls_info->nlri_hash, bgp, ls_nlri);
}

/*
 * Unintern BGP-LS NLRI (unlock and potentially free)
 *
 * Decrements the reference count and frees the NLRI if it reaches zero.
 */
void bgp_ls_nlri_unintern(struct bgp_ls_nlri **pls_nlri)
{
	struct bgp_ls_nlri *ls_nlri = *pls_nlri;
	struct bgp *bgp = bgp_get_default();

	if (!bgp || !bgp->ls_info || !ls_nlri)
		return;

	ls_nlri->refcnt--;

	if (ls_nlri->refcnt == 0) {
		bgp_ls_nlri_hash_del(&bgp->ls_info->nlri_hash, ls_nlri);
		bgp_ls_nlri_free(ls_nlri);
		*pls_nlri = NULL;
	}
}

/*
 * Intern BGP-LS attribute (lookup and lock)
 *
 * Looks up an existing BGP-LS attribute in the hash table and increments its reference count.
 * Returns the BGP-LS attribute if found, NULL otherwise.
 */
struct bgp_ls_attr *bgp_ls_attr_intern(struct bgp_ls_attr *ls_attr)
{
	struct bgp *bgp = bgp_get_default();

	if (!bgp || !bgp->ls_info || !ls_attr)
		return NULL;

	return bgp_ls_attr_get(&bgp->ls_info->ls_attr_hash, bgp, ls_attr);
}

/*
 * Unintern BGP-LS attribute (unlock and potentially free)
 *
 * Decrements the reference count and frees the BGP-LS attribute if it reaches zero.
 */
void bgp_ls_attr_unintern(struct bgp_ls_attr **pls_attr)
{
	struct bgp_ls_attr *ls_attr = *pls_attr;
	struct bgp *bgp = bgp_get_default();

	if (!bgp || !bgp->ls_info || !ls_attr)
		return;

	ls_attr->refcnt--;

	if (ls_attr->refcnt == 0) {
		bgp_ls_attr_hash_del(&bgp->ls_info->ls_attr_hash, ls_attr);
		bgp_ls_attr_free(ls_attr);
		*pls_attr = NULL;
	}
}

/*
 * ===========================================================================
 * NLRI Encoding Functions
 * ===========================================================================
 */

/*
 * Write TLV header (Type + Length) to stream
 *
 * Wire format (RFC 9552 Section 3.1):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Type             |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Returns number of bytes written, or -1 on error
 */
static inline int stream_put_tlv_hdr(struct stream *s, uint16_t type, uint16_t length)
{
	if (STREAM_WRITEABLE(s) < BGP_LS_TLV_HDR_SIZE)
		return -1;

	stream_putw(s, type);
	stream_putw(s, length);
	return BGP_LS_TLV_HDR_SIZE;
}

/*
 * Put a complete TLV (Type + Length + Value) into stream
 * Returns 0 on success, -1 on error
 */
static inline int stream_put_tlv(struct stream *s, uint16_t type, uint16_t length,
				 const void *value)
{
	if (stream_put_tlv_hdr(s, type, length) < 0)
		return -1;

	if (length > 0) {
		if (STREAM_WRITEABLE(s) < length)
			return -1;
		stream_put(s, value, length);
	}

	return 0;
}

static inline int stream_putf_tlv(struct stream *s, uint16_t type, const float value)
{
	if (stream_put_tlv_hdr(s, type, 4) < 0)
		return -1;

	if (STREAM_WRITEABLE(s) < 4)
		return -1;

	stream_putf(s, value);

	return 0;
}

/*
 * Encode Node Descriptor to wire format (RFC 9552 Section 5.2.1)
 *
 * Wire format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Descriptor Type       |      Descriptor Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //              Node Descriptor Sub-TLVs (variable)            //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Node Descriptor Sub-TLVs (RFC 9552 Section 5.2.1.4):
 *   - TLV 512: Autonomous System (4 bytes)
 *   - TLV 513: BGP-LS Identifier (4 bytes, deprecated)
 *   - TLV 514: OSPF Area-ID (4 bytes)
 *   - TLV 515: IGP Router-ID (4-16 bytes, MANDATORY)
 *
 * tlv_type: BGP_LS_TLV_LOCAL_NODE_DESC or BGP_LS_TLV_REMOTE_NODE_DESC
 *
 * Returns: Number of bytes written, or -1 on error
 */
int bgp_ls_encode_node_descriptor(struct stream *s, const struct bgp_ls_node_descriptor *desc,
				  uint16_t tlv_type)
{
	size_t len_pos, sub_tlv_start;
	int written = 0;
	int ret;

	if (!s || !desc)
		return -1;

	if (STREAM_WRITEABLE(s) < BGP_LS_TLV_HDR_SIZE)
		return -1;

	/* Write TLV type and reserve space for length */
	stream_putw(s, tlv_type);
	len_pos = stream_get_endp(s);
	stream_putw(s, 0); /* Placeholder for length */
	written += BGP_LS_TLV_HDR_SIZE;

	sub_tlv_start = stream_get_endp(s);

	/* AS Number (TLV 512) */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_AS_BIT)) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_AS_NUMBER, BGP_LS_AS_NUMBER_SIZE);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < BGP_LS_AS_NUMBER_SIZE)
			return -1;
		stream_putl(s, desc->asn);
		written += BGP_LS_AS_NUMBER_SIZE;
	}

	/* BGP-LS Identifier (TLV 513) - deprecated but may be present */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_BGP_LS_ID_BIT)) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_BGP_LS_ID, BGP_LS_BGP_LS_ID_SIZE);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < BGP_LS_BGP_LS_ID_SIZE)
			return -1;
		stream_putl(s, desc->bgp_ls_id);
		written += BGP_LS_BGP_LS_ID_SIZE;
	}

	/* OSPF Area ID (TLV 514) */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_OSPF_AREA_BIT)) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_OSPF_AREA_ID, BGP_LS_OSPF_AREA_ID_SIZE);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < BGP_LS_OSPF_AREA_ID_SIZE)
			return -1;
		stream_putl(s, desc->ospf_area_id);
		written += BGP_LS_OSPF_AREA_ID_SIZE;
	}

	/* IGP Router ID (TLV 515) - MANDATORY */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT)) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_IGP_ROUTER_ID, desc->igp_router_id_len);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < desc->igp_router_id_len)
			return -1;
		stream_put(s, desc->igp_router_id, desc->igp_router_id_len);
		written += desc->igp_router_id_len;
	}

	/* Update length field */
	uint16_t sub_tlv_len = stream_get_endp(s) - sub_tlv_start;

	stream_putw_at(s, len_pos, sub_tlv_len);

	return written;
}

/*
 * Encode Link Descriptor to wire format (RFC 9552 Section 5.2.2)
 *
 * Wire format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //                Link Descriptor TLVs (variable)              //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Link Descriptor TLVs (RFC 9552 Section 5.2.2):
 *   - TLV 258: Link Local/Remote Identifiers (8 bytes)
 *   - TLV 259: IPv4 Interface Address (4 bytes)
 *   - TLV 260: IPv4 Neighbor Address (4 bytes)
 *   - TLV 261: IPv6 Interface Address (16 bytes)
 *   - TLV 262: IPv6 Neighbor Address (16 bytes)
 *   - TLV 263: Multi-Topology ID (2 bytes per MT-ID)
 *
 * Returns: Number of bytes written, or -1 on error
 */
int bgp_ls_encode_link_descriptor(struct stream *s, const struct bgp_ls_link_descriptor *desc)
{
	int written = 0;
	int ret;
	uint16_t i;

	if (!s || !desc)
		return -1;

	/* Link Local/Remote Identifiers (TLV 258) */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_LINK_ID_BIT)) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_LINK_ID, BGP_LS_LINK_ID_SIZE);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < BGP_LS_LINK_ID_SIZE)
			return -1;
		stream_putl(s, desc->link_local_id);
		stream_putl(s, desc->link_remote_id);
		written += BGP_LS_LINK_ID_SIZE;
	}

	/* IPv4 Interface Address (TLV 259) */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_INTF_BIT)) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_IPV4_INTF_ADDR, BGP_LS_IPV4_ADDR_SIZE);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < BGP_LS_IPV4_ADDR_SIZE)
			return -1;
		stream_put_ipv4(s, desc->ipv4_intf_addr.s_addr);
		written += BGP_LS_IPV4_ADDR_SIZE;
	}

	/* IPv4 Neighbor Address (TLV 260) */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_NEIGH_BIT)) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_IPV4_NEIGH_ADDR, BGP_LS_IPV4_ADDR_SIZE);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < BGP_LS_IPV4_ADDR_SIZE)
			return -1;
		stream_put_ipv4(s, desc->ipv4_neigh_addr.s_addr);
		written += BGP_LS_IPV4_ADDR_SIZE;
	}

	/* IPv6 Interface Address (TLV 261) */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_INTF_BIT)) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_IPV6_INTF_ADDR, BGP_LS_IPV6_ADDR_SIZE);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < BGP_LS_IPV6_ADDR_SIZE)
			return -1;
		stream_put(s, &desc->ipv6_intf_addr, BGP_LS_IPV6_ADDR_SIZE);
		written += BGP_LS_IPV6_ADDR_SIZE;
	}

	/* IPv6 Neighbor Address (TLV 262) */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_NEIGH_BIT)) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_IPV6_NEIGH_ADDR, BGP_LS_IPV6_ADDR_SIZE);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < BGP_LS_IPV6_ADDR_SIZE)
			return -1;
		stream_put(s, &desc->ipv6_neigh_addr, BGP_LS_IPV6_ADDR_SIZE);
		written += BGP_LS_IPV6_ADDR_SIZE;
	}

	/* Multi-Topology ID (TLV 263) */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_MT_ID_BIT) &&
	    desc->mt_id_count > 0) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_MT_ID,
					 desc->mt_id_count * BGP_LS_MT_ID_SIZE);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < (size_t)desc->mt_id_count * BGP_LS_MT_ID_SIZE)
			return -1;
		for (i = 0; i < desc->mt_id_count; i++)
			stream_putw(s, desc->mt_id[i]);
		written += desc->mt_id_count * BGP_LS_MT_ID_SIZE;
	}

	/* Remote AS Number (TLV 264) */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_REMOTE_AS_BIT)) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_REMOTE_AS_NUMBER, 4);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < 4)
			return -1;
		stream_putl(s, desc->remote_asn);
		written += 4;
	}

	return written;
}

/*
 * Encode Prefix Descriptor to wire format (RFC 9552 Section 5.2.3)
 *
 * Wire format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //               Prefix Descriptor TLVs (variable)             //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Prefix Descriptor TLVs (RFC 9552 Section 5.2.3):
 *   - TLV 263: Multi-Topology ID (2 bytes per MT-ID)
 *   - TLV 264: OSPF Route Type (1 byte)
 *   - TLV 265: IP Reachability Information (1 + prefix bytes, MANDATORY)
 *
 * Returns: Number of bytes written, or -1 on error
 */
int bgp_ls_encode_prefix_descriptor(struct stream *s, const struct bgp_ls_prefix_descriptor *desc)
{
	int written = 0;
	int ret;
	uint16_t i;
	uint8_t prefix_len_bytes;

	if (!s || !desc)
		return -1;

	/* Multi-Topology ID (TLV 263) */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_PREFIX_DESC_MT_ID_BIT) &&
	    desc->mt_id_count > 0) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_MT_ID,
					 desc->mt_id_count * BGP_LS_MT_ID_SIZE);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < (size_t)desc->mt_id_count * BGP_LS_MT_ID_SIZE)
			return -1;
		for (i = 0; i < desc->mt_id_count; i++)
			stream_putw(s, desc->mt_id[i]);
		written += desc->mt_id_count * BGP_LS_MT_ID_SIZE;
	}

	/* OSPF Route Type (TLV 264) */
	if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_PREFIX_DESC_OSPF_ROUTE_BIT)) {
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_OSPF_ROUTE_TYPE,
					 BGP_LS_OSPF_ROUTE_TYPE_SIZE);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < BGP_LS_OSPF_ROUTE_TYPE_SIZE)
			return -1;
		stream_putc(s, desc->ospf_route_type);
		written += BGP_LS_OSPF_ROUTE_TYPE_SIZE;
	}

	/* IP Reachability Information (TLV 265) - MANDATORY */
	if (desc->prefix.family == AF_INET) {
		prefix_len_bytes = (desc->prefix.prefixlen + 7) / 8;
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_IP_REACH_INFO,
					 BGP_LS_PREFIX_LEN_SIZE + prefix_len_bytes);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < (size_t)BGP_LS_PREFIX_LEN_SIZE + prefix_len_bytes)
			return -1;
		stream_putc(s, desc->prefix.prefixlen);
		stream_put(s, &desc->prefix.u.prefix4, prefix_len_bytes);
		written += BGP_LS_PREFIX_LEN_SIZE + prefix_len_bytes;
	} else if (desc->prefix.family == AF_INET6) {
		prefix_len_bytes = (desc->prefix.prefixlen + 7) / 8;
		ret = stream_put_tlv_hdr(s, BGP_LS_TLV_IP_REACH_INFO,
					 BGP_LS_PREFIX_LEN_SIZE + prefix_len_bytes);
		if (ret < 0)
			return -1;
		written += ret;

		if (STREAM_WRITEABLE(s) < (size_t)BGP_LS_PREFIX_LEN_SIZE + prefix_len_bytes)
			return -1;
		stream_putc(s, desc->prefix.prefixlen);
		stream_put(s, &desc->prefix.u.prefix6, prefix_len_bytes);
		written += BGP_LS_PREFIX_LEN_SIZE + prefix_len_bytes;
	}

	return written;
}

/*
 * Encode Node NLRI to wire format (RFC 9552 Section 5.2)
 *
 * Wire format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+
 * |  Protocol-ID  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Identifier                          |
 * |                            (64 bits)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //               Local Node Descriptors (variable)             //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Returns: Number of bytes written, or -1 on error
 */
int bgp_ls_encode_node_nlri(struct stream *s, const struct bgp_ls_node_nlri *nlri)
{
	int written = 0;
	int ret;

	if (!s || !nlri)
		return -1;

	/* Protocol-ID (1 byte) */
	if (STREAM_WRITEABLE(s) < BGP_LS_PROTOCOL_ID_SIZE)
		return -1;
	stream_putc(s, nlri->protocol_id);
	written += BGP_LS_PROTOCOL_ID_SIZE;

	/* Identifier (8 bytes) */
	if (STREAM_WRITEABLE(s) < BGP_LS_IDENTIFIER_SIZE)
		return -1;
	stream_putq(s, nlri->identifier);
	written += BGP_LS_IDENTIFIER_SIZE;

	/* Local Node Descriptors */
	ret = bgp_ls_encode_node_descriptor(s, &nlri->local_node, BGP_LS_TLV_LOCAL_NODE_DESC);
	if (ret < 0)
		return -1;
	written += ret;

	return written;
}

/*
 * Encode Link NLRI to wire format (RFC 9552 Section 5.2)
 *
 * Wire format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+
 * |  Protocol-ID  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Identifier                          |
 * |                            (64 bits)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //               Local Node Descriptors (variable)             //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //               Remote Node Descriptors (variable)            //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //                  Link Descriptors (variable)                //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Returns: Number of bytes written, or -1 on error
 */
int bgp_ls_encode_link_nlri(struct stream *s, const struct bgp_ls_link_nlri *nlri)
{
	int written = 0;
	int ret;

	if (!s || !nlri)
		return -1;

	/* Protocol-ID (1 byte) */
	if (STREAM_WRITEABLE(s) < BGP_LS_PROTOCOL_ID_SIZE)
		return -1;
	stream_putc(s, nlri->protocol_id);
	written += BGP_LS_PROTOCOL_ID_SIZE;

	/* Identifier (8 bytes) */
	if (STREAM_WRITEABLE(s) < BGP_LS_IDENTIFIER_SIZE)
		return -1;
	stream_putq(s, nlri->identifier);
	written += BGP_LS_IDENTIFIER_SIZE;

	/* Local Node Descriptors */
	ret = bgp_ls_encode_node_descriptor(s, &nlri->local_node, BGP_LS_TLV_LOCAL_NODE_DESC);
	if (ret < 0)
		return -1;
	written += ret;

	/* Remote Node Descriptors */
	ret = bgp_ls_encode_node_descriptor(s, &nlri->remote_node, BGP_LS_TLV_REMOTE_NODE_DESC);
	if (ret < 0)
		return -1;
	written += ret;

	/* Link Descriptors */
	ret = bgp_ls_encode_link_descriptor(s, &nlri->link_desc);
	if (ret < 0)
		return -1;
	written += ret;

	return written;
}

/*
 * Encode Prefix NLRI to wire format (RFC 9552 Section 5.2)
 *
 * Wire format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+
 * |  Protocol-ID  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Identifier                          |
 * |                            (64 bits)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //               Local Node Descriptors (variable)             //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //                Prefix Descriptors (variable)                //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Note: Same structure for both IPv4 (Type 3) and IPv6 (Type 4)
 *
 * nlri_type: BGP_LS_NLRI_TYPE_IPV4_PREFIX or BGP_LS_NLRI_TYPE_IPV6_PREFIX
 *
 * Returns: Number of bytes written, or -1 on error
 */
int bgp_ls_encode_prefix_nlri(struct stream *s, const struct bgp_ls_prefix_nlri *nlri,
			      enum bgp_ls_nlri_type nlri_type)
{
	int written = 0;
	int ret;

	if (!s || !nlri)
		return -1;

	/* Validate prefix family matches NLRI type */
	if ((nlri_type == BGP_LS_NLRI_TYPE_IPV4_PREFIX &&
	     nlri->prefix_desc.prefix.family != AF_INET) ||
	    (nlri_type == BGP_LS_NLRI_TYPE_IPV6_PREFIX &&
	     nlri->prefix_desc.prefix.family != AF_INET6))
		return -1;

	/* Protocol-ID (1 byte) */
	if (STREAM_WRITEABLE(s) < BGP_LS_PROTOCOL_ID_SIZE)
		return -1;
	stream_putc(s, nlri->protocol_id);
	written += BGP_LS_PROTOCOL_ID_SIZE;

	/* Identifier (8 bytes) */
	if (STREAM_WRITEABLE(s) < BGP_LS_IDENTIFIER_SIZE)
		return -1;
	stream_putq(s, nlri->identifier);
	written += BGP_LS_IDENTIFIER_SIZE;

	/* Local Node Descriptors */
	ret = bgp_ls_encode_node_descriptor(s, &nlri->local_node, BGP_LS_TLV_LOCAL_NODE_DESC);
	if (ret < 0)
		return -1;
	written += ret;

	/* Prefix Descriptors */
	ret = bgp_ls_encode_prefix_descriptor(s, &nlri->prefix_desc);
	if (ret < 0)
		return -1;
	written += ret;

	return written;
}

/*
 * Encode complete NLRI with Type-Length-Value header
 *
 * Wire format (RFC 9552 Section 5.2):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Type             |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * //                   NLRI Value (variable)                     //
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Where:
 *   Type   = NLRI Type (1=Node, 2=Link, 3=IPv4 Prefix, 4=IPv6 Prefix)
 *   Length = Length of NLRI Value in octets
 *   Value  = Type-specific NLRI data (Protocol-ID + Identifier + Descriptors)
 *
 * This is the top-level encoding used in MP_REACH/MP_UNREACH attributes.
 *
 * Returns: Number of bytes written, or -1 on error
 */
int bgp_ls_encode_nlri(struct stream *s, const struct bgp_ls_nlri *nlri)
{
	size_t len_pos, value_start;
	int written = 0;
	int ret = 0;

	if (!s || !nlri)
		return -1;

	/* Validate NLRI */
	if (!bgp_ls_nlri_validate(nlri))
		return -1;

	/* NLRI Type (2 bytes) */
	if (STREAM_WRITEABLE(s) < BGP_LS_NLRI_TYPE_SIZE)
		return -1;
	stream_putw(s, nlri->nlri_type);
	written += BGP_LS_NLRI_TYPE_SIZE;

	/* Reserve space for NLRI Length */
	if (STREAM_WRITEABLE(s) < BGP_LS_NLRI_LENGTH_SIZE)
		return -1;
	len_pos = stream_get_endp(s);
	stream_putw(s, 0); /* Placeholder */
	written += BGP_LS_NLRI_LENGTH_SIZE;

	value_start = stream_get_endp(s);

	/* Encode NLRI Value based on type */
	switch (nlri->nlri_type) {
	case BGP_LS_NLRI_TYPE_NODE:
		ret = bgp_ls_encode_node_nlri(s, &nlri->nlri_data.node);
		break;

	case BGP_LS_NLRI_TYPE_LINK:
		ret = bgp_ls_encode_link_nlri(s, &nlri->nlri_data.link);
		break;

	case BGP_LS_NLRI_TYPE_IPV4_PREFIX:
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX:
		ret = bgp_ls_encode_prefix_nlri(s, &nlri->nlri_data.prefix, nlri->nlri_type);
		break;

	case BGP_LS_NLRI_TYPE_RESERVED:
		return -1;
	}

	if (ret < 0)
		return -1;

	written += ret;

	/* Update NLRI Length field */
	uint16_t nlri_len = stream_get_endp(s) - value_start;

	stream_putw_at(s, len_pos, nlri_len);

	return written;
}

/*
 * Encode BGP-LS Attributes (BGP-LS Attribute Type 29)
 * RFC 9552 Section 4.3.1
 *
 * Returns number of bytes written, or -1 on error
 */
int bgp_ls_encode_attr(struct stream *s, const struct bgp_ls_attr *attr)
{
	size_t start_pos;

	if (!s || !attr)
		return -1;

	start_pos = stream_get_endp(s);

	/* Node Flag Bits (TLV 1024) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_NODE_FLAGS_BIT)) {
		if (stream_put_tlv(s, BGP_LS_ATTR_NODE_FLAG_BITS, 1, &attr->node_flags) < 0)
			return -1;
	}

	/* Node Name (TLV 1026) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_NODE_NAME_BIT)) {
		if (attr->node_name) {
			uint16_t len = strlen(attr->node_name);

			if (stream_put_tlv(s, BGP_LS_ATTR_NODE_NAME, len, attr->node_name) < 0)
				return -1;
		}
	}

	/* IS-IS Area Identifier (TLV 1027) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_ISIS_AREA_BIT)) {
		if (attr->isis_area_id && attr->isis_area_id_len > 0) {
			if (stream_put_tlv(s, BGP_LS_ATTR_ISIS_AREA_ID, attr->isis_area_id_len,
					   attr->isis_area_id) < 0)
				return -1;
		}
	}

	/* IPv4 Router-ID of Local Node (TLV 1028) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IPV4_ROUTER_ID_LOCAL_BIT)) {
		if (stream_put_tlv(s, BGP_LS_ATTR_IPV4_ROUTER_ID_LOCAL, 4,
				   &attr->ipv4_router_id_local) < 0)
			return -1;
	}

	/* IPv6 Router-ID of Local Node (TLV 1029) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IPV6_ROUTER_ID_LOCAL_BIT)) {
		if (stream_put_tlv(s, BGP_LS_ATTR_IPV6_ROUTER_ID_LOCAL, 16,
				   &attr->ipv6_router_id_local) < 0)
			return -1;
	}

	/* IPv4 Router-ID of Remote Node (TLV 1030) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IPV4_ROUTER_ID_REMOTE_BIT)) {
		if (stream_put_tlv(s, BGP_LS_ATTR_IPV4_ROUTER_ID_REMOTE, 4,
				   &attr->ipv4_router_id_remote) < 0)
			return -1;
	}

	/* IPv6 Router-ID of Remote Node (TLV 1031) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IPV6_ROUTER_ID_REMOTE_BIT)) {
		if (stream_put_tlv(s, BGP_LS_ATTR_IPV6_ROUTER_ID_REMOTE, 16,
				   &attr->ipv6_router_id_remote) < 0)
			return -1;
	}

	/* Administrative Group (TLV 1088) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_ADMIN_GROUP_BIT)) {
		uint32_t admin_group_be = htonl(attr->admin_group);

		if (stream_put_tlv(s, BGP_LS_ATTR_ADMIN_GROUP, 4, &admin_group_be) < 0)
			return -1;
	}

	/* Maximum Link Bandwidth (TLV 1089) - IEEE 754 floating point */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_MAX_LINK_BW_BIT)) {
		if (stream_putf_tlv(s, BGP_LS_ATTR_MAX_LINK_BW, attr->max_link_bw) < 0)
			return -1;
	}

	/* Maximum Reservable Bandwidth (TLV 1090) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_MAX_RESV_BW_BIT)) {
		if (stream_putf_tlv(s, BGP_LS_ATTR_MAX_RESV_BW, attr->max_resv_bw) < 0)
			return -1;
	}

	/* Unreserved Bandwidth (TLV 1091) - 8 priority levels */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_UNRESV_BW_BIT)) {
		if (stream_put_tlv_hdr(s, BGP_LS_ATTR_UNRESV_BW, 32) < 0)
			return -1;
		for (int i = 0; i < BGP_LS_MAX_UNRESV_BW; i++) {
			if (STREAM_WRITEABLE(s) < 4)
				return -1;
			stream_putf(s, attr->unreserved_bw[i]);
		}
	}

	/* TE Default Metric (TLV 1092) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_TE_METRIC_BIT)) {
		uint32_t te_metric_be = htonl(attr->te_metric);

		if (stream_put_tlv(s, BGP_LS_ATTR_TE_DEFAULT_METRIC, 4, &te_metric_be) < 0)
			return -1;
	}

	/* Link Protection Type (TLV 1093) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_LINK_PROTECTION_BIT)) {
		uint16_t protection_be = htons(attr->link_protection);

		if (stream_put_tlv(s, BGP_LS_ATTR_LINK_PROTECTION_TYPE, 2, &protection_be) < 0)
			return -1;
	}

	/* MPLS Protocol Mask (TLV 1094) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_MPLS_PROTOCOL_BIT)) {
		if (stream_put_tlv(s, BGP_LS_ATTR_MPLS_PROTOCOL_MASK, 1,
				   &attr->mpls_protocol_mask) < 0)
			return -1;
	}

	/* IGP Metric (TLV 1095) - Variable length 1-3 bytes */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IGP_METRIC_BIT)) {
		uint8_t metric_buf[3];
		uint8_t len = attr->igp_metric_len;

		if (len > 0 && len <= BGP_LS_IGP_METRIC_MAX_LEN) {
			/* Encode metric in big-endian */
			if (len == 1) {
				metric_buf[0] = attr->igp_metric & 0xFF;
			} else if (len == 2) {
				metric_buf[0] = (attr->igp_metric >> 8) & 0xFF;
				metric_buf[1] = attr->igp_metric & 0xFF;
			} else { /* len == 3 */
				metric_buf[0] = (attr->igp_metric >> 16) & 0xFF;
				metric_buf[1] = (attr->igp_metric >> 8) & 0xFF;
				metric_buf[2] = attr->igp_metric & 0xFF;
			}
			if (stream_put_tlv(s, BGP_LS_ATTR_IGP_METRIC, len, metric_buf) < 0)
				return -1;
		}
	}

	/* Shared Risk Link Group (TLV 1096) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_SRLG_BIT)) {
		if (attr->srlg_values && attr->srlg_count > 0) {
			uint16_t srlg_len = attr->srlg_count * 4;

			if (stream_put_tlv_hdr(s, BGP_LS_ATTR_SRLG, srlg_len) < 0)
				return -1;
			for (int i = 0; i < attr->srlg_count; i++) {
				uint32_t srlg_be = htonl(attr->srlg_values[i]);

				if (STREAM_WRITEABLE(s) < 4)
					return -1;
				stream_put(s, &srlg_be, 4);
			}
		}
	}

	/* Link Name (TLV 1098) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_LINK_NAME_BIT)) {
		if (attr->link_name) {
			uint16_t len = strlen(attr->link_name);

			if (stream_put_tlv(s, BGP_LS_ATTR_LINK_NAME, len, attr->link_name) < 0)
				return -1;
		}
	}

	/* Extended Admin Group (TLV 1173) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_EXT_ADMIN_GROUP_BIT)) {
		size_t nb_words = admin_group_nb_words(&attr->ext_admin_group);

		if (nb_words > 0) {
			uint16_t ag_len = nb_words * 4; /* Each word is 4 bytes */

			if (stream_put_tlv_hdr(s, BGP_LS_ATTR_EXTENDED_ADMIN_GROUP, ag_len) < 0)
				return -1;

			/* Encode each 32-bit word */
			for (size_t i = 0; i < nb_words; i++) {
				uint32_t word = admin_group_get_offset(&attr->ext_admin_group, i);
				uint32_t word_be = htonl(word);

				if (STREAM_WRITEABLE(s) < 4)
					return -1;
				stream_put(s, &word_be, 4);
			}
		}
	}

	/* Unidirectional Link Delay (TLV 1114) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_DELAY_BIT)) {
		uint32_t delay_be = htonl(attr->delay);

		if (stream_put_tlv(s, BGP_LS_ATTR_UNIDIRECTIONAL_LINK_DELAY, 4, &delay_be) < 0)
			return -1;
	}

	/* Min/Max Unidirectional Link Delay (TLV 1115) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_MIN_MAX_DELAY_BIT)) {
		uint32_t min_delay_be = htonl(attr->min_delay);
		uint32_t max_delay_be = htonl(attr->max_delay);

		if (stream_put_tlv_hdr(s, BGP_LS_ATTR_MIN_MAX_UNIDIRECTIONAL_LINK_DELAY, 8) < 0)
			return -1;

		if (STREAM_WRITEABLE(s) < 8)
			return -1;
		stream_put(s, &min_delay_be, 4);
		stream_put(s, &max_delay_be, 4);
	}

	/* Unidirectional Delay Variation (TLV 1116) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_JITTER_BIT)) {
		uint32_t jitter_be = htonl(attr->jitter);

		if (stream_put_tlv(s, BGP_LS_ATTR_UNIDIRECTIONAL_DELAY_VARIATION, 4, &jitter_be) <
		    0)
			return -1;
	}

	/* Unidirectional Packet Loss (TLV 1117) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_PKT_LOSS_BIT)) {
		uint32_t pkt_loss_be = htonl(attr->pkt_loss);

		if (stream_put_tlv(s, BGP_LS_ATTR_UNIDIRECTIONAL_LINK_LOSS, 4, &pkt_loss_be) < 0)
			return -1;
	}

	/* Unidirectional Residual Bandwidth (TLV 1118) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_RESIDUAL_BW_BIT)) {
		if (stream_putf_tlv(s, BGP_LS_ATTR_UNIDIRECTIONAL_RESIDUAL_BANDWIDTH,
				    attr->residual_bw) < 0)
			return -1;
	}

	/* Unidirectional Available Bandwidth (TLV 1119) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_AVAILABLE_BW_BIT)) {
		if (stream_putf_tlv(s, BGP_LS_ATTR_UNIDIRECTIONAL_AVAILABLE_BANDWIDTH,
				    attr->available_bw) < 0)
			return -1;
	}

	/* Unidirectional Utilized Bandwidth (TLV 1120) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_UTILIZED_BW_BIT)) {
		if (stream_putf_tlv(s, BGP_LS_ATTR_UNIDIRECTIONAL_UTILIZED_BANDWIDTH,
				    attr->utilized_bw) < 0)
			return -1;
	}

	/* IGP Flags (TLV 1152) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IGP_FLAGS_BIT)) {
		if (stream_put_tlv(s, BGP_LS_ATTR_IGP_FLAGS, 1, &attr->igp_flags) < 0)
			return -1;
	}

	/* Route Tags (TLV 1153) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_ROUTE_TAG_BIT)) {
		if (attr->route_tags && attr->route_tag_count > 0) {
			uint16_t tag_len = attr->route_tag_count * 4;

			if (stream_put_tlv_hdr(s, BGP_LS_ATTR_ROUTE_TAG, tag_len) < 0)
				return -1;
			for (int i = 0; i < attr->route_tag_count; i++) {
				uint32_t tag_be = htonl(attr->route_tags[i]);

				if (STREAM_WRITEABLE(s) < 4)
					return -1;
				stream_put(s, &tag_be, 4);
			}
		}
	}

	/* Extended Tags (TLV 1154) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_EXTENDED_TAG_BIT)) {
		if (attr->extended_tags && attr->extended_tag_count > 0) {
			uint16_t tag_len = attr->extended_tag_count * 8;

			if (stream_put_tlv_hdr(s, BGP_LS_ATTR_EXTENDED_TAG, tag_len) < 0)
				return -1;
			for (int i = 0; i < attr->extended_tag_count; i++) {
				uint64_t tag_be = htonll(attr->extended_tags[i]);

				if (STREAM_WRITEABLE(s) < 8)
					return -1;
				stream_put(s, &tag_be, 8);
			}
		}
	}

	/* Prefix Metric (TLV 1155) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_PREFIX_METRIC_BIT)) {
		uint32_t metric_be = htonl(attr->prefix_metric);

		if (stream_put_tlv(s, BGP_LS_ATTR_PREFIX_METRIC, 4, &metric_be) < 0)
			return -1;
	}

	/* OSPF Forwarding Address (TLV 1156) - IPv4 or IPv6 */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_OSPF_FWD_ADDR_BIT)) {
		/* Check which address family is present */
		if (attr->ospf_fwd_addr.s_addr != 0) {
			/* IPv4 forwarding address */
			if (stream_put_tlv(s, BGP_LS_ATTR_OSPF_FWD_ADDR, 4, &attr->ospf_fwd_addr) <
			    0)
				return -1;
		} else if (!IN6_IS_ADDR_UNSPECIFIED(&attr->ospf_fwd_addr6)) {
			/* IPv6 forwarding address */
			if (stream_put_tlv(s, BGP_LS_ATTR_OSPF_FWD_ADDR, 16,
					   &attr->ospf_fwd_addr6) < 0)
				return -1;
		}
	}

	/* Prefix SID (TLV 1158) */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_PREFIX_SID_BIT)) {
		int sid_len = bgp_ls_attr_prefix_sid_len(attr->prefix_sid.sid_flag);

		if (sid_len == -1) {
			/* Should be impossible here */
			flog_warn(EC_BGP_LS_PACKET,
				  "BGP-LS: %s wrong combination of V-Flag and L-Flag for Prefix SID",
				  __func__);
		} else {
			if (stream_put_tlv_hdr(s, BGP_LS_ATTR_PREFIX_SID, 4 + sid_len) < 0)
				return -1;
			if (STREAM_WRITEABLE(s) < (size_t)4 + sid_len)
				return -1;
			stream_putc(s, attr->prefix_sid.sid_flag);
			stream_putc(s, attr->prefix_sid.algo);
			stream_putw(s, 0); /* Reserved = 0 */
			/* SID Label/Index - three or four bytes */
			if (sid_len == 3)
				stream_put3(s, attr->prefix_sid.sid);
			else if (sid_len == 4)
				stream_putl(s, attr->prefix_sid.sid);
		}
	}

	return stream_get_endp(s) - start_pos;
}

/*
 * Get Prefix-SID attribute SID length by flags
 *
 * @return 3 or 4 in normal case, -1 in error case
 */
int bgp_ls_attr_prefix_sid_len(uint8_t flags)
{
	/*
	 * IS-IS: RFC 8667, 2.1.1; OSPFv2: RFC8665, 5; OSPFv3: RFC8666, 6:
	 *
	 * All other combinations of V-Flag and L-Flag [all other = V-Flag!=L-Flag]
	 * are invalid and any SID Advertisement received with an invalid setting
	 * for V- and L-Flags MUST be ignored.
	 */
	if (CHECK_FLAG(flags, BGP_LS_PREFIX_SID_FLAG_VALUE) !=
	    CHECK_FLAG(flags, BGP_LS_PREFIX_SID_FLAG_LOCAL))
		return -1;

	return CHECK_FLAG(flags, BGP_LS_PREFIX_SID_FLAG_VALUE) ? 3 : 4;
}

/*
 * ===========================================================================
 * NLRI Decoding Functions
 * ===========================================================================
 */

/*
 * Read TLV header (Type + Length) from stream
 *
 * Wire format (RFC 9552 Section 5.1):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Type             |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Returns 0 on success, -1 on error
 */
static inline int stream_get_tlv_hdr(struct stream *s, uint16_t *type, uint16_t *length)
{
	if (STREAM_READABLE(s) < BGP_LS_TLV_HDR_SIZE) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Not enough data for TLV header");
		return -1;
	}

	*type = stream_getw(s);
	*length = stream_getw(s);

	/* Check if stream has enough data for TLV value */
	if (STREAM_READABLE(s) < *length) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: TLV type=%u length=%u exceeds available data",
			  *type, *length);
		return -1;
	}

	return 0;
}

/*
 * Skip unknown TLV in stream (RFC 9552 Section 5.1)
 * Unknown TLVs must be preserved and propagated
 */
static inline void stream_skip_tlv(struct stream *s, uint16_t length)
{
	stream_forward_getp(s, length);
}

/*
 * Decode Node Descriptor from wire format (RFC 9552 Section 5.2.1)
 *
 * Wire format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Descriptor Type       |      Descriptor Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //              Node Descriptor Sub-TLVs (variable)            //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Node Descriptor Sub-TLVs (RFC 9552 Section 5.2.1.4):
 *   - TLV 512: Autonomous System (4 bytes, OPTIONAL)
 *   - TLV 513: BGP-LS Identifier (4 bytes, deprecated, OPTIONAL)
 *   - TLV 514: OSPF Area-ID (4 bytes, CONDITIONAL)
 *   - TLV 515: IGP Router-ID (variable, MANDATORY)
 *
 * Returns: 0 on success, -1 on error
 */
int bgp_ls_decode_node_descriptor(struct stream *s, struct bgp_ls_node_descriptor *desc,
				  uint16_t desc_length)
{
	size_t end_pos;
	uint16_t sub_type, sub_len;
	bool has_igp_router_id = false;

	if (!s || !desc)
		return -1;

	/* Clear descriptor */
	memset(desc, 0, sizeof(*desc));

	/* Save end position for bounds checking */
	end_pos = stream_get_getp(s) + desc_length;

	/* Parse sub-TLVs */
	while (stream_get_getp(s) < end_pos) {
		if (stream_get_tlv_hdr(s, &sub_type, &sub_len) < 0)
			return -1;

		switch (sub_type) {
		case BGP_LS_TLV_AS_NUMBER:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_AS_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate AS Number TLV in node descriptor");
				return -1;
			}
			if (sub_len != BGP_LS_AS_NUMBER_SIZE) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: Invalid AS Number TLV length %u (expected %u)",
					  sub_len, BGP_LS_AS_NUMBER_SIZE);
				return -1;
			}
			desc->asn = stream_getl(s);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_NODE_DESC_AS_BIT);
			break;

		case BGP_LS_TLV_BGP_LS_ID:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_BGP_LS_ID_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate BGP-LS ID TLV in node descriptor");
				return -1;
			}
			if (sub_len != BGP_LS_BGP_LS_ID_SIZE) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: Invalid BGP-LS ID TLV length %u (expected %u)",
					  sub_len, BGP_LS_BGP_LS_ID_SIZE);
				return -1;
			}
			desc->bgp_ls_id = stream_getl(s);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_NODE_DESC_BGP_LS_ID_BIT);
			break;

		case BGP_LS_TLV_OSPF_AREA_ID:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_OSPF_AREA_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate OSPF Area ID TLV in node descriptor");
				return -1;
			}
			if (sub_len != BGP_LS_OSPF_AREA_ID_SIZE) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: Invalid OSPF Area ID TLV length %u (expected %u)",
					  sub_len, BGP_LS_OSPF_AREA_ID_SIZE);
				return -1;
			}
			desc->ospf_area_id = stream_getl(s);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_NODE_DESC_OSPF_AREA_BIT);
			break;

		case BGP_LS_TLV_IGP_ROUTER_ID:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate IGP Router-ID TLV in node descriptor");
				return -1;
			}
			/* Variable length: 4 to 16 bytes */
			if (sub_len < BGP_LS_IGP_ROUTER_ID_MIN_SIZE ||
			    sub_len > BGP_LS_IGP_ROUTER_ID_MAX_SIZE) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: Invalid IGP Router-ID TLV length %u", sub_len);
				return -1;
			}
			desc->igp_router_id_len = sub_len;
			stream_get(desc->igp_router_id, s, sub_len);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT);
			has_igp_router_id = true;
			break;

		default:
			/* Unknown TLV - skip but preserve (RFC 9552 Section 5.1) */
			flog_warn(EC_BGP_LS_PACKET,
				  "BGP-LS: Unknown Node Descriptor sub-TLV %u, length %u (skipping)",
				  sub_type, sub_len);
			stream_skip_tlv(s, sub_len);
			break;
		}
	}

	/* Verify mandatory TLV present */
	if (!has_igp_router_id) {
		flog_warn(EC_BGP_LS_PACKET,
			  "BGP-LS: Mandatory IGP Router-ID TLV missing from Node Descriptor");
		return -1;
	}

	/* Check we consumed exactly desc_length bytes */
	if (stream_get_getp(s) != end_pos) {
		flog_warn(EC_BGP_LS_PACKET,
			  "BGP-LS: Node Descriptor length mismatch (consumed %zu, expected %u)",
			  stream_get_getp(s) - (end_pos - desc_length), desc_length);
		return -1;
	}

	return 0;
}

/*
 * Decode Link Descriptor from wire format (RFC 9552 Section 5.2.2)
 *
 * Wire format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //                Link Descriptor TLVs (variable)              //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Link Descriptor TLVs (RFC 9552 Section 5.2.2):
 *   - TLV 258: Link Local/Remote Identifiers (8 bytes)
 *   - TLV 259: IPv4 Interface Address (4 bytes)
 *   - TLV 260: IPv4 Neighbor Address (4 bytes)
 *   - TLV 261: IPv6 Interface Address (16 bytes)
 *   - TLV 262: IPv6 Neighbor Address (16 bytes)
 *   - TLV 263: Multi-Topology ID (variable, 2 bytes per MT-ID)
 *
 * Returns: 0 on success, -1 on error
 */
int bgp_ls_decode_link_descriptor(struct stream *s, struct bgp_ls_link_descriptor *desc,
				  size_t total_length)
{
	size_t end_pos;
	uint16_t tlv_type, tlv_len;

	if (!s || !desc)
		return -1;

	/* Clear descriptor */
	memset(desc, 0, sizeof(*desc));

	/* Save end position for bounds checking */
	end_pos = stream_get_getp(s) + total_length;

	/* Parse TLVs */
	while (stream_get_getp(s) < end_pos) {
		if (stream_get_tlv_hdr(s, &tlv_type, &tlv_len) < 0)
			goto error;

		switch (tlv_type) {
		case BGP_LS_TLV_LINK_ID:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_LINK_ID_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate Link ID TLV in link descriptor");
				goto error;
			}
			if (tlv_len != BGP_LS_LINK_ID_SIZE) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: Invalid Link ID TLV length %u (expected %u)",
					  tlv_len, BGP_LS_LINK_ID_SIZE);
				goto error;
			}
			desc->link_local_id = stream_getl(s);
			desc->link_remote_id = stream_getl(s);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_LINK_DESC_LINK_ID_BIT);
			break;

		case BGP_LS_TLV_IPV4_INTF_ADDR:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_INTF_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate IPv4 Interface Address TLV in link descriptor");
				goto error;
			}
			if (tlv_len != BGP_LS_IPV4_ADDR_SIZE) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: Invalid IPv4 Interface Address TLV length %u",
					  tlv_len);
				goto error;
			}
			stream_get(&desc->ipv4_intf_addr.s_addr, s, BGP_LS_IPV4_ADDR_SIZE);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_INTF_BIT);
			break;

		case BGP_LS_TLV_IPV4_NEIGH_ADDR:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_NEIGH_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate IPv4 Neighbor Address TLV in link descriptor");
				goto error;
			}
			if (tlv_len != BGP_LS_IPV4_ADDR_SIZE) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: Invalid IPv4 Neighbor Address TLV length %u",
					  tlv_len);
				goto error;
			}
			stream_get(&desc->ipv4_neigh_addr.s_addr, s, BGP_LS_IPV4_ADDR_SIZE);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_NEIGH_BIT);
			break;

		case BGP_LS_TLV_IPV6_INTF_ADDR:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_INTF_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate IPv6 Interface Address TLV in link descriptor");
				goto error;
			}
			if (tlv_len != BGP_LS_IPV6_ADDR_SIZE) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: Invalid IPv6 Interface Address TLV length %u",
					  tlv_len);
				goto error;
			}
			stream_get(&desc->ipv6_intf_addr.s6_addr, s, BGP_LS_IPV6_ADDR_SIZE);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_INTF_BIT);
			break;

		case BGP_LS_TLV_IPV6_NEIGH_ADDR:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_NEIGH_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate IPv6 Neighbor Address TLV in link descriptor");
				goto error;
			}
			if (tlv_len != BGP_LS_IPV6_ADDR_SIZE) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: Invalid IPv6 Neighbor Address TLV length %u",
					  tlv_len);
				goto error;
			}
			stream_get(&desc->ipv6_neigh_addr.s6_addr, s, BGP_LS_IPV6_ADDR_SIZE);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_NEIGH_BIT);
			break;

		case BGP_LS_TLV_MT_ID:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_MT_ID_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate MT-ID TLV in link descriptor");
				goto error;
			}
			/* Variable length: 2*n bytes where n is number of MT-IDs */
			if (tlv_len % 2 != 0 || tlv_len > BGP_LS_MAX_MT_ID * 2) {
				flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Invalid MT-ID TLV length %u",
					  tlv_len);
				goto error;
			}
			desc->mt_id_count = tlv_len / 2;
			desc->mt_id = XCALLOC(MTYPE_BGP_LS_NLRI, tlv_len);
			for (uint16_t i = 0; i < desc->mt_id_count; i++)
				desc->mt_id[i] = stream_getw(s);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_LINK_DESC_MT_ID_BIT);
			break;

		case BGP_LS_TLV_REMOTE_AS_NUMBER:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_LINK_DESC_REMOTE_AS_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate Remote AS Number TLV in link descriptor");
				goto error;
			}
			if (tlv_len != 4) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: Invalid Remote AS Number TLV length %u (expected 4)",
					  tlv_len);
				goto error;
			}
			desc->remote_asn = stream_getl(s);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_LINK_DESC_REMOTE_AS_BIT);
			break;

		default:
			/* Unknown TLV - skip but preserve (RFC 9552 Section 5.1) */
			flog_warn(EC_BGP_LS_PACKET,
				  "BGP-LS: Unknown Link Descriptor TLV %u, length %u (skipping)",
				  tlv_type, tlv_len);
			stream_skip_tlv(s, tlv_len);
			break;
		}
	}

	/* Check we consumed exactly total_length bytes */
	if (stream_get_getp(s) != end_pos) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Link Descriptor length mismatch");
		goto error;
	}

	return 0;

error:
	XFREE(MTYPE_BGP_LS_NLRI, desc->mt_id);
	desc->mt_id = NULL;
	desc->mt_id_count = 0;
	return -1;
}

/*
 * Decode Prefix Descriptor from wire format (RFC 9552 Section 5.2.3)
 *
 * Wire format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //             Prefix Descriptor TLVs (variable)               //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Prefix Descriptor TLVs (RFC 9552 Section 5.2.3):
 *   - TLV 263: Multi-Topology ID (2 bytes, CONDITIONAL)
 *   - TLV 264: OSPF Route Type (1 byte, CONDITIONAL)
 *   - TLV 265: IP Reachability Information (variable, MANDATORY)
 *
 * Returns: 0 on success, -1 on error
 */
int bgp_ls_decode_prefix_descriptor(struct stream *s, struct bgp_ls_prefix_descriptor *desc,
				    size_t total_length, bool is_ipv6)
{
	size_t end_pos;
	uint16_t tlv_type, tlv_len;
	bool has_ip_reach = false;

	if (!s || !desc)
		return -1;

	/* Clear descriptor */
	memset(desc, 0, sizeof(*desc));

	/* Save end position for bounds checking */
	end_pos = stream_get_getp(s) + total_length;

	/* Parse TLVs */
	while (stream_get_getp(s) < end_pos) {
		if (stream_get_tlv_hdr(s, &tlv_type, &tlv_len) < 0)
			goto error;

		switch (tlv_type) {
		case BGP_LS_TLV_MT_ID:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_PREFIX_DESC_MT_ID_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate MT-ID TLV in prefix descriptor");
				goto error;
			}
			/* Variable length: 2*n bytes where n is number of MT-IDs */
			if (tlv_len % 2 != 0 || tlv_len > BGP_LS_MAX_MT_ID * 2) {
				flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Invalid MT-ID TLV length %u",
					  tlv_len);
				goto error;
			}
			desc->mt_id_count = tlv_len / 2;
			desc->mt_id = XCALLOC(MTYPE_BGP_LS_NLRI, tlv_len);
			for (uint16_t i = 0; i < desc->mt_id_count; i++)
				desc->mt_id[i] = stream_getw(s);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_PREFIX_DESC_MT_ID_BIT);
			break;

		case BGP_LS_TLV_OSPF_ROUTE_TYPE:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs,
					     BGP_LS_PREFIX_DESC_OSPF_ROUTE_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate OSPF Route Type TLV in prefix descriptor");
				goto error;
			}
			if (tlv_len != BGP_LS_OSPF_ROUTE_TYPE_SIZE) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: Invalid OSPF Route Type TLV length %u", tlv_len);
				goto error;
			}
			desc->ospf_route_type = stream_getc(s);
			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_PREFIX_DESC_OSPF_ROUTE_BIT);
			break;

		case BGP_LS_TLV_IP_REACH_INFO:
			if (BGP_LS_TLV_CHECK(desc->present_tlvs, BGP_LS_PREFIX_DESC_IP_REACH_BIT)) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: duplicate IP Reachability Info TLV in prefix descriptor");
				goto error;
			}
			/* Variable length: prefix_len + ceil(prefix_len/8) */
			if (tlv_len < 1) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: Invalid IP Reach Info TLV length %u", tlv_len);
				goto error;
			}
			/* First byte is prefix length */
			desc->prefix.prefixlen = stream_getc(s);

			/* Calculate expected bytes for this prefix length */
			uint16_t expected_bytes = (desc->prefix.prefixlen + 7) / 8;

			if (tlv_len != 1 + expected_bytes) {
				flog_warn(EC_BGP_LS_PACKET,
					  "BGP-LS: IP Reach Info TLV length %u mismatch (prefix len %u requires %u bytes)",
					  tlv_len, desc->prefix.prefixlen, 1 + expected_bytes);
				goto error;
			}

			/*
			 * Read prefix bytes
			 */
			if (is_ipv6) {
				desc->prefix.family = AF_INET6;
				/* Validate prefix length is valid for IPv6 */
				if (desc->prefix.prefixlen > IPV6_MAX_BITLEN) {
					flog_warn(EC_BGP_LS_PACKET,
						  "BGP-LS: Invalid IPv6 prefix length %u (max 128)",
						  desc->prefix.prefixlen);
					goto error;
				}
				if (expected_bytes > 0)
					stream_get(&desc->prefix.u.prefix6.s6_addr, s,
						   expected_bytes);
			} else {
				desc->prefix.family = AF_INET;
				/* Validate prefix length is valid for IPv4 */
				if (desc->prefix.prefixlen > IPV4_MAX_BITLEN) {
					flog_warn(EC_BGP_LS_PACKET,
						  "BGP-LS: Invalid IPv4 prefix length %u (max 32)",
						  desc->prefix.prefixlen);
					goto error;
				}
				if (expected_bytes > 0)
					stream_get(&desc->prefix.u.prefix4.s_addr, s,
						   expected_bytes);
			}

			BGP_LS_TLV_SET(desc->present_tlvs, BGP_LS_PREFIX_DESC_IP_REACH_BIT);
			has_ip_reach = true;
			break;

		default:
			/* Unknown TLV - skip but preserve (RFC 9552 Section 5.1) */
			flog_warn(EC_BGP_LS_PACKET,
				  "BGP-LS: Unknown Prefix Descriptor TLV %u, length %u (skipping)",
				  tlv_type, tlv_len);
			stream_skip_tlv(s, tlv_len);
			break;
		}
	}

	/* Verify mandatory TLV present */
	if (!has_ip_reach) {
		flog_warn(EC_BGP_LS_PACKET,
			  "BGP-LS: Mandatory IP Reachability Info TLV missing from Prefix Descriptor");
		goto error;
	}

	/* Check we consumed exactly total_length bytes */
	if (stream_get_getp(s) != end_pos) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Prefix Descriptor length mismatch");
		goto error;
	}

	return 0;

error:
	XFREE(MTYPE_BGP_LS_NLRI, desc->mt_id);
	desc->mt_id = NULL;
	desc->mt_id_count = 0;
	return -1;
}

/*
 * Decode Node NLRI from wire format (RFC 9552 Section 5.2)
 *
 * Wire format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        NLRI Type = 1          |       Total NLRI Length       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Protocol-ID   |
 * +-+-+-+-+-+-+-+-+
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Identifier                             |
 * |                          (8 octets)                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Local Node Descriptors TLV Type     |      Length           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //              Local Node Descriptor Sub-TLVs                 //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Returns: 0 on success, -1 on error
 */
int bgp_ls_decode_node_nlri(struct stream *s, struct bgp_ls_nlri *nlri, uint16_t nlri_length)
{
	uint16_t desc_type, desc_len;
	size_t start_pos;

	if (!s || !nlri)
		return -1;

	/* Save start position for length validation */
	start_pos = stream_get_getp(s);

	/* Check minimum length */
	if (nlri_length < BGP_LS_NLRI_MIN_LENGTH) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Node NLRI length %u too short (minimum %u)",
			  nlri_length, BGP_LS_NLRI_MIN_LENGTH);
		return -1;
	}

	/* Allocate NLRI structure */
	nlri->nlri_type = BGP_LS_NLRI_TYPE_NODE;

	/* Read Protocol-ID (1 byte) */
	nlri->nlri_data.node.protocol_id = stream_getc(s);

	/* Validate Protocol-ID */
	if (nlri->nlri_data.node.protocol_id == BGP_LS_PROTO_RESERVED ||
	    nlri->nlri_data.node.protocol_id > BGP_LS_PROTO_BGP) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Invalid Protocol-ID %u",
			  nlri->nlri_data.node.protocol_id);
		return -1;
	}

	/* Read Identifier (8 bytes) */
	nlri->nlri_data.node.identifier = stream_getq(s);

	/* Read Local Node Descriptor TLV */
	if (stream_get_tlv_hdr(s, &desc_type, &desc_len) < 0)
		return -1;

	if (desc_type != BGP_LS_TLV_LOCAL_NODE_DESC) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Expected Local Node Descriptor TLV %u, got %u",
			  BGP_LS_TLV_LOCAL_NODE_DESC, desc_type);
		return -1;
	}

	if (bgp_ls_decode_node_descriptor(s, &nlri->nlri_data.node.local_node, desc_len) < 0)
		return -1;

	/* Verify we consumed exactly nlri_length bytes */
	if (stream_get_getp(s) - start_pos != nlri_length) {
		flog_warn(EC_BGP_LS_PACKET,
			  "BGP-LS: Node NLRI length mismatch (consumed %zu, expected %u)",
			  stream_get_getp(s) - start_pos, nlri_length);
		return -1;
	}

	return 0;
}

/*
 * Decode Link NLRI from wire format (RFC 9552 Section 5.2)
 *
 * Wire format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        NLRI Type = 2          |       Total NLRI Length       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Protocol-ID   |
 * +-+-+-+-+-+-+-+-+
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Identifier                             |
 * |                          (8 octets)                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Local Node Descriptors TLV Type     |      Length           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //              Local Node Descriptor Sub-TLVs                 //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Remote Node Descriptors TLV Type    |      Length           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //              Remote Node Descriptor Sub-TLVs                //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //                Link Descriptor TLVs                         //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Returns: 0 on success, -1 on error
 */
int bgp_ls_decode_link_nlri(struct stream *s, struct bgp_ls_nlri *nlri, uint16_t nlri_length)
{
	uint16_t desc_type, desc_len;
	size_t start_pos, link_desc_start;
	size_t consumed = 0;

	if (!s || !nlri)
		return -1;

	/* Save start position for length validation */
	start_pos = stream_get_getp(s);

	/* Check minimum length */
	if (nlri_length < BGP_LS_NLRI_MIN_LENGTH) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Link NLRI length %u too short (minimum %u)",
			  nlri_length, BGP_LS_NLRI_MIN_LENGTH);
		return -1;
	}

	/* Allocate NLRI structure */
	nlri->nlri_type = BGP_LS_NLRI_TYPE_LINK;

	/* Read Protocol-ID (1 byte) */
	nlri->nlri_data.link.protocol_id = stream_getc(s);

	/* Validate Protocol-ID */
	if (nlri->nlri_data.link.protocol_id == BGP_LS_PROTO_RESERVED ||
	    nlri->nlri_data.link.protocol_id > BGP_LS_PROTO_BGP) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Invalid Protocol-ID %u",
			  nlri->nlri_data.link.protocol_id);
		return -1;
	}

	/* Read Identifier (8 bytes) */
	nlri->nlri_data.link.identifier = stream_getq(s);

	/* Read Local Node Descriptor TLV */
	if (stream_get_tlv_hdr(s, &desc_type, &desc_len) < 0)
		return -1;

	if (desc_type != BGP_LS_TLV_LOCAL_NODE_DESC) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Expected Local Node Descriptor TLV %u, got %u",
			  BGP_LS_TLV_LOCAL_NODE_DESC, desc_type);
		return -1;
	}

	consumed = stream_get_getp(s) - start_pos;
	if (consumed > nlri_length || desc_len > nlri_length - consumed) {
		flog_warn(EC_BGP_LS_PACKET,
			  "BGP-LS: Local Node Descriptor TLV length %u exceeds NLRI boundary",
			  desc_len);
		return -1;
	}

	if (bgp_ls_decode_node_descriptor(s, &nlri->nlri_data.link.local_node, desc_len) < 0)
		return -1;

	/* Read Remote Node Descriptor TLV */
	if (stream_get_tlv_hdr(s, &desc_type, &desc_len) < 0)
		return -1;

	if (desc_type != BGP_LS_TLV_REMOTE_NODE_DESC) {
		flog_warn(EC_BGP_LS_PACKET,
			  "BGP-LS: Expected Remote Node Descriptor TLV %u, got %u",
			  BGP_LS_TLV_REMOTE_NODE_DESC, desc_type);
		return -1;
	}

	consumed = stream_get_getp(s) - start_pos;
	if (consumed > nlri_length || desc_len > nlri_length - consumed) {
		flog_warn(EC_BGP_LS_PACKET,
			  "BGP-LS: Remote Node Descriptor TLV length %u exceeds NLRI boundary",
			  desc_len);
		return -1;
	}

	if (bgp_ls_decode_node_descriptor(s, &nlri->nlri_data.link.remote_node, desc_len) < 0)
		return -1;

	/* Link Descriptors are remaining bytes */
	link_desc_start = stream_get_getp(s);
	size_t link_desc_len = nlri_length - (link_desc_start - start_pos);

	if (link_desc_len > 0) {
		if (bgp_ls_decode_link_descriptor(s, &nlri->nlri_data.link.link_desc,
						  link_desc_len) < 0)
			return -1;
	}

	/* Verify we consumed exactly nlri_length bytes */
	if (stream_get_getp(s) - start_pos != nlri_length) {
		flog_warn(EC_BGP_LS_PACKET,
			  "BGP-LS: Link NLRI length mismatch (consumed %zu, expected %u)",
			  stream_get_getp(s) - start_pos, nlri_length);
		return -1;
	}

	return 0;
}

/*
 * Decode Prefix NLRI from wire format (RFC 9552 Section 5.2)
 *
 * Wire format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      NLRI Type = 3/4          |       Total NLRI Length       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Protocol-ID   |
 * +-+-+-+-+-+-+-+-+
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Identifier                             |
 * |                          (8 octets)                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Local Node Descriptors TLV Type     |      Length           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //              Local Node Descriptor Sub-TLVs                 //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //               Prefix Descriptor TLVs                        //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Returns: 0 on success, -1 on error
 */
int bgp_ls_decode_prefix_nlri(struct stream *s, struct bgp_ls_nlri *nlri, uint16_t nlri_type,
			      uint16_t nlri_length)
{
	uint16_t desc_type, desc_len;
	size_t start_pos, prefix_desc_start;
	size_t consumed = 0;

	if (!s || !nlri)
		return -1;

	/* Validate NLRI type */
	if (nlri_type != BGP_LS_NLRI_TYPE_IPV4_PREFIX && nlri_type != BGP_LS_NLRI_TYPE_IPV6_PREFIX) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Invalid Prefix NLRI type %u", nlri_type);
		return -1;
	}

	/* Save start position for length validation */
	start_pos = stream_get_getp(s);

	/* Check minimum length */
	if (nlri_length < BGP_LS_NLRI_MIN_LENGTH) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Prefix NLRI length %u too short (minimum %u)",
			  nlri_length, BGP_LS_NLRI_MIN_LENGTH);
		return -1;
	}

	/* Allocate NLRI structure */
	nlri->nlri_type = nlri_type;

	/* Read Protocol-ID (1 byte) */
	nlri->nlri_data.prefix.protocol_id = stream_getc(s);

	/* Validate Protocol-ID */
	if (nlri->nlri_data.prefix.protocol_id == BGP_LS_PROTO_RESERVED ||
	    nlri->nlri_data.prefix.protocol_id > BGP_LS_PROTO_BGP) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Invalid Protocol-ID %u",
			  nlri->nlri_data.prefix.protocol_id);
		return -1;
	}

	/* Read Identifier (8 bytes) */
	nlri->nlri_data.prefix.identifier = stream_getq(s);

	/* Read Local Node Descriptor TLV */
	if (stream_get_tlv_hdr(s, &desc_type, &desc_len) < 0)
		return -1;

	if (desc_type != BGP_LS_TLV_LOCAL_NODE_DESC) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Expected Local Node Descriptor TLV %u, got %u",
			  BGP_LS_TLV_LOCAL_NODE_DESC, desc_type);
		return -1;
	}

	consumed = stream_get_getp(s) - start_pos;
	if (consumed > nlri_length || desc_len > nlri_length - consumed) {
		flog_warn(EC_BGP_LS_PACKET,
			  "BGP-LS: Local Node Descriptor TLV length %u exceeds NLRI boundary",
			  desc_len);
		return -1;
	}

	if (bgp_ls_decode_node_descriptor(s, &nlri->nlri_data.prefix.local_node, desc_len) < 0)
		return -1;

	/* Prefix Descriptors are remaining bytes */
	prefix_desc_start = stream_get_getp(s);
	size_t prefix_desc_len = nlri_length - (prefix_desc_start - start_pos);

	if (prefix_desc_len > 0) {
		/* Determine if IPv6 based on NLRI type (RFC 9552 Section 3.2) */
		bool is_ipv6 = (nlri_type == BGP_LS_NLRI_TYPE_IPV6_PREFIX);

		if (bgp_ls_decode_prefix_descriptor(s, &nlri->nlri_data.prefix.prefix_desc,
						    prefix_desc_len, is_ipv6) < 0)
			return -1;
	} else {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Prefix NLRI has no Prefix Descriptor TLVs");
		return -1;
	}

	/* Verify we consumed exactly nlri_length bytes */
	if (stream_get_getp(s) - start_pos != nlri_length) {
		flog_warn(EC_BGP_LS_PACKET,
			  "BGP-LS: Prefix NLRI length mismatch (consumed %zu, expected %u)",
			  stream_get_getp(s) - start_pos, nlri_length);
		return -1;
	}

	return 0;
}

/*
 * Decode complete BGP-LS NLRI from UPDATE message (RFC 9552 Section 5.2)
 *
 * This is the main entry point for decoding NLRIs from MP_REACH_NLRI
 * or MP_UNREACH_NLRI attributes.
 *
 * Returns: 0 on success, -1 on error
 */
int bgp_ls_decode_nlri(struct stream *s, struct bgp_ls_nlri *nlri)
{
	uint16_t nlri_type, nlri_length;

	if (!s || !nlri)
		return -1;

	/* Read NLRI Type (2 bytes) */
	if (STREAM_READABLE(s) < 2) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Not enough data for NLRI type");
		return -1;
	}
	nlri_type = stream_getw(s);

	/* Read NLRI Length (2 bytes) */
	if (STREAM_READABLE(s) < 2) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Not enough data for NLRI length");
		return -1;
	}
	nlri_length = stream_getw(s);

	/* Check if stream has enough data for NLRI */
	if (STREAM_READABLE(s) < nlri_length) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: NLRI type=%u length=%u exceeds available data",
			  nlri_type, nlri_length);
		return -1;
	}

	/* Decode based on NLRI type */
	switch (nlri_type) {
	case BGP_LS_NLRI_TYPE_NODE:
		return bgp_ls_decode_node_nlri(s, nlri, nlri_length);

	case BGP_LS_NLRI_TYPE_LINK:
		return bgp_ls_decode_link_nlri(s, nlri, nlri_length);

	case BGP_LS_NLRI_TYPE_IPV4_PREFIX:
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX:
		return bgp_ls_decode_prefix_nlri(s, nlri, nlri_type, nlri_length);

	default:
		/* Unknown NLRI type - preserve and propagate (RFC 9552 Section 5.2) */
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Unknown NLRI type %u, length %u (skipping)",
			  nlri_type, nlri_length);
		stream_forward_getp(s, nlri_length);
		return -1;
	}
}

/*
 * Parse Node Flag Bits TLV (TLV 1024)
 * RFC 9552 Section 5.3.1.1
 */
static int parse_node_flags(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length < 1) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Node Flags TLV too short (%u bytes)", length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_NODE_FLAGS_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Node Flags TLV");
		return -1;
	}

	attr->node_flags = stream_getc(s);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_NODE_FLAGS_BIT);

	/* Skip any extra bytes */
	if (length > 1)
		stream_forward_getp(s, length - 1);

	return 0;
}

/*
 * Parse Node Name TLV (TLV 1026)
 * RFC 9552 Section 5.3.1.3
 */
static int parse_node_name(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length == 0)
		return 0;

	if (length > BGP_LS_MAX_NODE_NAME_LEN) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Node Name TLV length %u exceeds maximum %u, skipping TLV",
			  length, BGP_LS_MAX_NODE_NAME_LEN);
		stream_forward_getp(s, length);
		return 0;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_NODE_NAME_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Node Name TLV");
		return -1;
	}

	/* Allocate space for node name (null-terminated) */
	attr->node_name = XCALLOC(MTYPE_BGP_LS_ATTR, length + 1);
	stream_get(attr->node_name, s, length);
	attr->node_name[length] = '\0';
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_NODE_NAME_BIT);

	return 0;
}

/*
 * Parse IS-IS Area ID TLV (TLV 1027)
 * RFC 9552 Section 5.3.1.4
 */
static int parse_isis_area_id(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length == 0 || length > 13) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid ISIS Area ID length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_ISIS_AREA_BIT)) {
		/*
		 * RFC 9552 Section 5.3.1.4 allows multiple IS-IS Area-ID TLVs
		 * to encode synonymous area addresses. We currently support
		 * only one IS-IS Area-ID TLV; skip any additional ones.
		 */
		if (BGP_DEBUG(linkstate, LINKSTATE))
			flog_warn(EC_BGP_UPDATE_RCV,
				  "BGP-LS: multiple IS-IS Area-ID TLVs not supported, skipping duplicate");
		stream_forward_getp(s, length);
		return 0;
	}

	attr->isis_area_id = XCALLOC(MTYPE_BGP_LS_ATTR, length);
	stream_get(attr->isis_area_id, s, length);
	attr->isis_area_id_len = length;
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_ISIS_AREA_BIT);

	return 0;
}

/*
 * Parse Administrative Group TLV (TLV 1088)
 * RFC 5305 Section 3.1
 */
static int parse_admin_group(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Admin Group length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_ADMIN_GROUP_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Admin Group TLV");
		return -1;
	}

	attr->admin_group = stream_getl(s);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_ADMIN_GROUP_BIT);

	return 0;
}

/*
 * Parse Maximum Link Bandwidth TLV (TLV 1089)
 * RFC 5305 Section 3.4
 */
static int parse_max_link_bw(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	uint32_t bw_bits;

	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Max Link BW length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_MAX_LINK_BW_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Maximum Link Bandwidth TLV");
		return -1;
	}

	/* Read as 32-bit IEEE floating point */
	bw_bits = stream_getl(s);
	memcpy(&attr->max_link_bw, &bw_bits, 4);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_MAX_LINK_BW_BIT);

	return 0;
}

/*
 * Parse Maximum Reservable Bandwidth TLV (TLV 1090)
 * RFC 5305 Section 3.5
 */
static int parse_max_resv_bw(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	uint32_t bw_bits;

	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Max Resv BW length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_MAX_RESV_BW_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Maximum Reservable Bandwidth TLV");
		return -1;
	}

	bw_bits = stream_getl(s);
	memcpy(&attr->max_resv_bw, &bw_bits, 4);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_MAX_RESV_BW_BIT);

	return 0;
}

/*
 * Parse Unreserved Bandwidth TLV (TLV 1091)
 * RFC 5305 Section 3.6
 */
static int parse_unresv_bw(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	uint32_t bw_bits;
	int i;

	if (length != 32) { /* 8 priorities * 4 bytes each */
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Unreserved BW length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_UNRESV_BW_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Unreserved Bandwidth TLV");
		return -1;
	}

	for (i = 0; i < BGP_LS_MAX_UNRESV_BW; i++) {
		bw_bits = stream_getl(s);
		memcpy(&attr->unreserved_bw[i], &bw_bits, 4);
	}
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_UNRESV_BW_BIT);

	return 0;
}

/*
 * Parse TE Default Metric TLV (TLV 1092)
 * RFC 9552 Section 5.3.2.3
 */
static int parse_te_metric(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid TE Metric length (%u bytes)", length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_TE_METRIC_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate TE Default Metric TLV");
		return -1;
	}

	attr->te_metric = stream_getl(s);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_TE_METRIC_BIT);

	return 0;
}

/*
 * Parse IGP Metric TLV (TLV 1095)
 * RFC 9552 Section 5.3.2.4
 */
static int parse_igp_metric(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length < 1 || length > BGP_LS_IGP_METRIC_MAX_LEN) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid IGP Metric length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IGP_METRIC_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate IGP Metric TLV");
		return -1;
	}

	attr->igp_metric = 0;
	for (int i = 0; i < length; i++)
		attr->igp_metric = (attr->igp_metric << 8) | stream_getc(s);
	attr->igp_metric_len = length;
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_IGP_METRIC_BIT);

	return 0;
}

/*
 * Parse SRLG TLV (TLV 1096)
 * RFC 9552 Section 5.3.2.5
 */
static int parse_srlg(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	uint16_t count;
	int i;

	if (length % 4 != 0) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid SRLG length (%u bytes)", length);
		return -1;
	}

	count = length / 4;
	if (count > BGP_LS_MAX_SRLG) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Too many SRLGs (%u, max %u)", count,
			  BGP_LS_MAX_SRLG);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_SRLG_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate SRLG TLV");
		return -1;
	}

	attr->srlg_values = XMALLOC(MTYPE_BGP_LS_ATTR, count * sizeof(uint32_t));
	for (i = 0; i < count; i++)
		attr->srlg_values[i] = stream_getl(s);
	attr->srlg_count = count;
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_SRLG_BIT);

	return 0;
}

/*
 * Parse Link Name TLV (TLV 1098)
 * RFC 9552 Section 5.3.2.7
 */
static int parse_link_name(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length == 0)
		return 0;

	if (length > BGP_LS_MAX_LINK_NAME_LEN) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Link Name TLV length %u exceeds maximum %u, skipping TLV",
			  length, BGP_LS_MAX_LINK_NAME_LEN);
		stream_forward_getp(s, length);
		return 0;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_LINK_NAME_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Link Name TLV");
		return -1;
	}

	attr->link_name = XCALLOC(MTYPE_BGP_LS_ATTR, length + 1);
	stream_get(attr->link_name, s, length);
	attr->link_name[length] = '\0';
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_LINK_NAME_BIT);

	return 0;
}

/*
 * Parse Extended Admin Group TLV (TLV 1173)
 */
static int parse_ext_admin_group(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	size_t nb_words;

	/* Length must be multiple of 4 (each word is 32 bits) */
	if (length % 4 != 0) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Invalid Extended Admin Group TLV length %u (must be multiple of 4)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_EXT_ADMIN_GROUP_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Extended Admin Group TLV");
		return -1;
	}

	nb_words = length / 4;
	if (nb_words > BGP_LS_MAX_EXT_ADMIN_GROUPS) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Extended Admin Group TLV too large (%zu words, max %zu)",
			  nb_words, (size_t)BGP_LS_MAX_EXT_ADMIN_GROUPS);
		return -1;
	}

	/* Decode each 32-bit word */
	for (size_t i = 0; i < nb_words; i++)
		admin_group_bulk_set(&attr->ext_admin_group, stream_getl(s), i);

	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_EXT_ADMIN_GROUP_BIT);

	return 0;
}

/*
 * Parse Unidirectional Link Delay TLV (TLV 1114)
 */
static int parse_link_delay(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Link Delay length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_DELAY_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Unidirectional Link Delay TLV");
		return -1;
	}

	attr->delay = stream_getl(s);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_DELAY_BIT);

	return 0;
}

/*
 * Parse Min/Max Unidirectional Link Delay TLV (TLV 1115)
 */
static int parse_min_max_delay(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 8) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Min/Max Delay length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_MIN_MAX_DELAY_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: duplicate Min/Max Unidirectional Link Delay TLV");
		return -1;
	}

	attr->min_delay = stream_getl(s);
	attr->max_delay = stream_getl(s);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_MIN_MAX_DELAY_BIT);

	return 0;
}

/*
 * Parse Unidirectional Delay Variation TLV (TLV 1116)
 */
static int parse_link_jitter(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Link Jitter length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_JITTER_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: duplicate Unidirectional Delay Variation TLV");
		return -1;
	}

	attr->jitter = stream_getl(s);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_JITTER_BIT);

	return 0;
}

/*
 * Parse Unidirectional Packet Loss TLV (TLV 1117)
 */
static int parse_packet_loss(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Packet Loss length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_PKT_LOSS_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Unidirectional Link Loss TLV");
		return -1;
	}

	attr->pkt_loss = stream_getl(s);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_PKT_LOSS_BIT);

	return 0;
}

/*
 * Parse Unidirectional Residual Bandwidth TLV (TLV 1118)
 */
static int parse_residual_bw(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Residual BW length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_RESIDUAL_BW_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Residual Bandwidth TLV");
		return -1;
	}

	stream_get(&attr->residual_bw, s, 4);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_RESIDUAL_BW_BIT);

	return 0;
}

/*
 * Parse Unidirectional Available Bandwidth TLV (TLV 1119)
 */
static int parse_available_bw(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Available BW length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_AVAILABLE_BW_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Available Bandwidth TLV");
		return -1;
	}

	stream_get(&attr->available_bw, s, 4);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_AVAILABLE_BW_BIT);

	return 0;
}

/*
 * Parse Unidirectional Utilized Bandwidth TLV (TLV 1120)
 */
static int parse_utilized_bw(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Utilized BW length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_UTILIZED_BW_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Utilized Bandwidth TLV");
		return -1;
	}

	stream_get(&attr->utilized_bw, s, 4);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_UTILIZED_BW_BIT);

	return 0;
}

/*
 * Parse IGP Flags TLV (TLV 1152)
 * RFC 9552 Section 5.3.3.1
 */
static int parse_igp_flags(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length < 1) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: IGP Flags TLV too short (%u bytes)", length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IGP_FLAGS_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate IGP Flags TLV");
		return -1;
	}

	attr->igp_flags = stream_getc(s);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_IGP_FLAGS_BIT);

	if (length > 1)
		stream_forward_getp(s, length - 1);

	return 0;
}

/*
 * Parse Route Tag TLV (TLV 1153)
 * RFC 9552 Section 5.3.3.2
 */
static int parse_route_tag(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	uint16_t count;
	int i;

	if (length % 4 != 0) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Route Tag length (%u bytes)", length);
		return -1;
	}

	count = length / 4;
	if (count > BGP_LS_MAX_ROUTE_TAGS) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Too many Route Tags (%u, max %u)", count,
			  BGP_LS_MAX_ROUTE_TAGS);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_ROUTE_TAG_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Route Tag TLV");
		return -1;
	}

	attr->route_tags = XMALLOC(MTYPE_BGP_LS_ATTR, count * sizeof(uint32_t));
	for (i = 0; i < count; i++)
		attr->route_tags[i] = stream_getl(s);
	attr->route_tag_count = count;
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_ROUTE_TAG_BIT);

	return 0;
}

/*
 * Parse Prefix Metric TLV (TLV 1155)
 * RFC 9552 Section 5.3.3.4
 */
static int parse_prefix_metric(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid Prefix Metric length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_PREFIX_METRIC_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Prefix Metric TLV");
		return -1;
	}

	attr->prefix_metric = stream_getl(s);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_PREFIX_METRIC_BIT);

	return 0;
}

/*
 * Parse OSPF Forwarding Address TLV (TLV 1156)
 * RFC 9552 Section 5.3.3.5
 */
static int parse_ospf_fwd_addr(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 4 && length != 16) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Invalid OSPF Fwd Addr length (%u bytes)",
			  length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_OSPF_FWD_ADDR_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate OSPF Forwarding Address TLV");
		return -1;
	}
	if (length == 4) {
		/* IPv4 */
		stream_get(&attr->ospf_fwd_addr, s, 4);
	} else {
		/* IPv6 */
		stream_get(&attr->ospf_fwd_addr6, s, 16);
	}

	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_OSPF_FWD_ADDR_BIT);
	return 0;
}

/* Parse IPv4 Router-ID of Local Node (TLV 1028) */
static int parse_ipv4_router_id_local(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Invalid IPv4 Router-ID Local length (%u bytes)", length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IPV4_ROUTER_ID_LOCAL_BIT)) {
		/*
		 * RFC 9552 Section 5.3.1.4 allows multiple IPv4 Local Router-ID TLVs
		 * when a node has more than one auxiliary Router-ID. We currently
		 * support only one; skip any additional ones.
		 */
		if (BGP_DEBUG(linkstate, LINKSTATE))
			flog_warn(EC_BGP_UPDATE_RCV,
				  "BGP-LS: multiple IPv4 Local Router-ID TLVs not supported, skipping duplicate");
		stream_forward_getp(s, length);
		return 0;
	}

	stream_get(&attr->ipv4_router_id_local, s, 4);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_IPV4_ROUTER_ID_LOCAL_BIT);
	return 0;
}

/* Parse IPv6 Router-ID of Local Node (TLV 1029) */
static int parse_ipv6_router_id_local(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 16) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Invalid IPv6 Router-ID Local length (%u bytes)", length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IPV6_ROUTER_ID_LOCAL_BIT)) {
		/*
		 * RFC 9552 Section 5.3.1.4 allows multiple IPv6 Local Router-ID TLVs
		 * when a node has more than one auxiliary Router-ID. We currently
		 * support only one; skip any additional ones.
		 */
		if (BGP_DEBUG(linkstate, LINKSTATE))
			flog_warn(EC_BGP_UPDATE_RCV,
				  "BGP-LS: multiple IPv6 Local Router-ID TLVs not supported, skipping duplicate");
		stream_forward_getp(s, length);
		return 0;
	}

	stream_get(&attr->ipv6_router_id_local, s, 16);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_IPV6_ROUTER_ID_LOCAL_BIT);
	return 0;
}

/* Parse IPv4 Router-ID of Remote Node (TLV 1030) */
static int parse_ipv4_router_id_remote(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 4) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Invalid IPv4 Router-ID Remote length (%u bytes)", length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IPV4_ROUTER_ID_REMOTE_BIT)) {
		/*
		 * RFC 9552 Section 5.3.2.1 allows multiple IPv4 Remote Router-ID TLVs
		 * when a node has more than one auxiliary Router-ID. We currently
		 * support only one; skip any additional ones.
		 */
		if (BGP_DEBUG(linkstate, LINKSTATE))
			flog_warn(EC_BGP_UPDATE_RCV,
				  "BGP-LS: multiple IPv4 Remote Router-ID TLVs not supported, skipping duplicate");
		stream_forward_getp(s, length);
		return 0;
	}

	stream_get(&attr->ipv4_router_id_remote, s, 4);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_IPV4_ROUTER_ID_REMOTE_BIT);
	return 0;
}

/* Parse IPv6 Router-ID of Remote Node (TLV 1031) */
static int parse_ipv6_router_id_remote(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 16) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Invalid IPv6 Router-ID Remote length (%u bytes)", length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_IPV6_ROUTER_ID_REMOTE_BIT)) {
		/*
		 * RFC 9552 Section 5.3.2.1 allows multiple IPv6 Remote Router-ID TLVs
		 * when a node has more than one auxiliary Router-ID. We currently
		 * support only one; skip any additional ones.
		 */
		if (BGP_DEBUG(linkstate, LINKSTATE))
			flog_warn(EC_BGP_UPDATE_RCV,
				  "BGP-LS: multiple IPv6 Remote Router-ID TLVs not supported, skipping duplicate");
		stream_forward_getp(s, length);
		return 0;
	}

	stream_get(&attr->ipv6_router_id_remote, s, 16);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_IPV6_ROUTER_ID_REMOTE_BIT);
	return 0;
}

/* Parse Link Protection Type (TLV 1093) */
static int parse_link_protection(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 2) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Invalid Link Protection Type length (%u bytes)", length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_LINK_PROTECTION_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Link Protection Type TLV");
		return -1;
	}

	attr->link_protection = stream_getw(s);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_LINK_PROTECTION_BIT);
	return 0;
}

/* Parse MPLS Protocol Mask (TLV 1094) */
static int parse_mpls_protocol_mask(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	if (length != 1) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Invalid MPLS Protocol Mask length (%u bytes)", length);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_MPLS_PROTOCOL_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate MPLS Protocol Mask TLV");
		return -1;
	}

	attr->mpls_protocol_mask = stream_getc(s);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_MPLS_PROTOCOL_BIT);
	return 0;
}

/* Parse Extended Tags (TLV 1154) */
static int parse_extended_tag(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	uint16_t count;

	if (length % 8 != 0) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Invalid Extended Tag length (%u bytes, must be multiple of 8)",
			  length);
		return -1;
	}

	count = length / 8;
	if (count > BGP_LS_MAX_ROUTE_TAGS) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: Too many Extended Tags (%u, max %u)", count,
			  BGP_LS_MAX_ROUTE_TAGS);
		return -1;
	}

	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_EXTENDED_TAG_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV, "BGP-LS: duplicate Extended Route Tag TLV");
		return -1;
	}

	attr->extended_tags = XCALLOC(MTYPE_BGP_LS_ATTR, count * sizeof(uint64_t));
	attr->extended_tag_count = count;

	for (uint16_t i = 0; i < count; i++)
		attr->extended_tags[i] = stream_getq(s);

	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_EXTENDED_TAG_BIT);
	return 0;
}

/*
 * Parse Prefix SID (TLV 1158)
 * RFC 9085 Section 2.3.1
 */
static int parse_prefix_sid(struct stream *s, uint16_t length, struct bgp_ls_attr *attr)
{
	int flags;
	int sid_len;

	if (length != 7 && length != 8) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Invalid Prefix SID length (%u bytes, expected 7 or 8)", length);
		return -1;
	}

	/*
	 * IS-IS in RFC8667 2.1 references RFC8402, in section 3.1:
	 *		Multiple SIDs MAY be allocated to the same prefix so long
	 *		as the tuple <prefix, topology, algorithm> is unique.
	 *
	 * RFC8665 (OSPFv2), 5; RFC8666 (OSPFv3), 6:
	 *		It MAY appear more than once in the parent TLV
	 */
	if (BGP_LS_TLV_CHECK(attr->present_tlvs, BGP_LS_ATTR_PREFIX_SID_BIT)) {
		flog_warn(EC_BGP_UPDATE_RCV,
			  "BGP-LS: Only one Prefix SID per prefix is supported, ignoring another one");
		stream_forward_getp(s, length);
		return 0;
	}

	flags = stream_getc(s);
	sid_len = bgp_ls_attr_prefix_sid_len(flags);

	if (sid_len == -1) {
		stream_forward_getp(s, length - 1);
		flog_warn(EC_BGP_LS_PACKET,
			  "BGP-LS: %s wrong combination of V-Flag and L-Flag for Prefix SID, ignoring",
			  __func__);
		return 0;
	}

	if (sid_len + 4 != length) {
		stream_forward_getp(s, length - 1);
		flog_warn(EC_BGP_LS_PACKET,
			  "BGP-LS: %s V-Flag value contradicts length of Prefix SID, ignoring",
			  __func__);
		return 0;
	}

	attr->prefix_sid.sid_flag = flags;
	attr->prefix_sid.algo = stream_getc(s);
	stream_getw(s); /* Reserved, ignore two octets */
	attr->prefix_sid.sid = 0;
	for (int i = 0; i < sid_len; i++)
		attr->prefix_sid.sid = (attr->prefix_sid.sid << 8) | stream_getc(s);
	BGP_LS_TLV_SET(attr->present_tlvs, BGP_LS_ATTR_PREFIX_SID_BIT);

	return 0;
}

/*
 * Parse BGP-LS Attribute TLVs
 * RFC 9552 Section 5.3.1
 */
int bgp_ls_parse_attr(struct stream *s, uint16_t total_length, struct bgp_ls_attr *attr)
{
	uint16_t type, length;
	size_t end_pos = stream_get_getp(s) + total_length;

	if (!attr)
		return -1;

	while (stream_get_getp(s) < end_pos) {
		if (stream_get_tlv_hdr(s, &type, &length) < 0) {
			flog_warn(EC_BGP_UPDATE_RCV,
				  "BGP-LS: Error parsing Node Attribute TLV header");
			return -1;
		}

		switch (type) {
		case BGP_LS_ATTR_NODE_FLAG_BITS:
			if (parse_node_flags(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_NODE_NAME:
			if (parse_node_name(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_ISIS_AREA_ID:
			if (parse_isis_area_id(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_IPV4_ROUTER_ID_LOCAL:
			if (parse_ipv4_router_id_local(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_IPV6_ROUTER_ID_LOCAL:
			if (parse_ipv6_router_id_local(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_IPV4_ROUTER_ID_REMOTE:
			if (parse_ipv4_router_id_remote(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_IPV6_ROUTER_ID_REMOTE:
			if (parse_ipv6_router_id_remote(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_ADMIN_GROUP:
			if (parse_admin_group(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_MAX_LINK_BW:
			if (parse_max_link_bw(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_MAX_RESV_BW:
			if (parse_max_resv_bw(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_UNRESV_BW:
			if (parse_unresv_bw(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_TE_DEFAULT_METRIC:
			if (parse_te_metric(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_LINK_PROTECTION_TYPE:
			if (parse_link_protection(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_MPLS_PROTOCOL_MASK:
			if (parse_mpls_protocol_mask(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_IGP_METRIC:
			if (parse_igp_metric(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_SRLG:
			if (parse_srlg(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_LINK_NAME:
			if (parse_link_name(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_UNIDIRECTIONAL_LINK_DELAY:
			if (parse_link_delay(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_MIN_MAX_UNIDIRECTIONAL_LINK_DELAY:
			if (parse_min_max_delay(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_UNIDIRECTIONAL_DELAY_VARIATION:
			if (parse_link_jitter(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_UNIDIRECTIONAL_LINK_LOSS:
			if (parse_packet_loss(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_UNIDIRECTIONAL_RESIDUAL_BANDWIDTH:
			if (parse_residual_bw(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_UNIDIRECTIONAL_AVAILABLE_BANDWIDTH:
			if (parse_available_bw(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_UNIDIRECTIONAL_UTILIZED_BANDWIDTH:
			if (parse_utilized_bw(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_EXTENDED_ADMIN_GROUP:
			if (parse_ext_admin_group(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_IGP_FLAGS:
			if (parse_igp_flags(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_ROUTE_TAG:
			if (parse_route_tag(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_EXTENDED_TAG:
			if (parse_extended_tag(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_PREFIX_METRIC:
			if (parse_prefix_metric(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_OSPF_FWD_ADDR:
			if (parse_ospf_fwd_addr(s, length, attr) < 0)
				return -1;
			break;

		case BGP_LS_ATTR_PREFIX_SID:
			if (parse_prefix_sid(s, length, attr) < 0)
				return -1;
			break;

		default:
			if (BGP_DEBUG(update, UPDATE_IN))
				zlog_debug("BGP-LS: Skipping unrecognized BGP-LS Attribute TLV %u",
					   type);
			stream_skip_tlv(s, length);
			break;
		}
	}

	if (stream_get_getp(s) != end_pos) {
		flog_warn(EC_BGP_LS_PACKET, "BGP-LS: Attribute length mismatch");
		return -1;
	}

	return 0;
}

/*
 * Convert BGP-LS Attributes to JSON object
 * Used for "show bgp" commands to display link-state topology information in json
 */
struct json_object *bgp_ls_attr_to_json(struct bgp_ls_attr *ls_attr)
{
	json_object *json_ls_attr = json_object_new_object();
	char buf[INET6_BUFSIZ];

	/* Node Name */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_NODE_NAME_BIT))
		json_object_string_add(json_ls_attr, "nodeName",
				       ls_attr->node_name ? ls_attr->node_name : "(null)");

	/* Local TE Router-ID (IPv4) */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_IPV4_ROUTER_ID_LOCAL_BIT)) {
		snprintfrr(buf, INET6_BUFSIZ, "%pI4", &ls_attr->ipv4_router_id_local);
		json_object_string_add(json_ls_attr, "routerIdLocal", buf);
	}

	/* Local TE Router-ID (IPv6) */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_IPV6_ROUTER_ID_LOCAL_BIT)) {
		snprintfrr(buf, INET6_BUFSIZ, "%pI6", &ls_attr->ipv6_router_id_local);
		json_object_string_add(json_ls_attr, "routerIdLocalV6", buf);
	}

	/* Link bandwidth */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_MAX_LINK_BW_BIT))
		json_object_double_add(json_ls_attr, "maxLinkBandwidth", ls_attr->max_link_bw);

	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_MAX_RESV_BW_BIT))
		json_object_double_add(json_ls_attr, "maxResvLinkBandwidth",
				       ls_attr->max_resv_bw);

	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_UNRESV_BW_BIT)) {
		json_object *jbw = json_object_new_array();

		json_object_object_add(json_ls_attr, "unreservedBandwidth", jbw);
		for (int i = 0; i < MAX_CLASS_TYPE; i++) {
			json_object *jobj = json_object_new_object();

			snprintfrr(buf, 13, "classType%u", (unsigned int)i);
			json_object_double_add(jobj, buf, ls_attr->unreserved_bw[i]);
			json_object_array_add(jbw, jobj);
		}
	}

	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_IGP_METRIC_BIT))
		json_object_int_add(json_ls_attr, "igpMetric", ls_attr->igp_metric);

	/* TE Default Metric */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_TE_METRIC_BIT))
		json_object_int_add(json_ls_attr, "teMetric", ls_attr->te_metric);

	/* Administrative Group */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_ADMIN_GROUP_BIT))
		json_object_int_add(json_ls_attr, "adminGroup", ls_attr->admin_group);

	/* Link Protection Type */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_LINK_PROTECTION_BIT))
		json_object_int_add(json_ls_attr, "linkProtection", ls_attr->link_protection);

	/* MPLS Protocol Mask */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_MPLS_PROTOCOL_BIT))
		json_object_int_add(json_ls_attr, "mplsProtocolMask",
				    ls_attr->mpls_protocol_mask);

	/* SRLG */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_SRLG_BIT)) {
		struct json_object *jsrlg = json_object_new_array();

		json_object_object_add(json_ls_attr, "srlgs", jsrlg);
		for (int i = 0; i < ls_attr->srlg_count; i++) {
			json_object *jobj = json_object_new_object();

			json_object_int_add(jobj, "srlg", ls_attr->srlg_values[i]);
			json_object_array_add(jsrlg, jobj);
		}
	}

	/* Link Name */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_LINK_NAME_BIT))
		json_object_string_add(json_ls_attr, "linkName", ls_attr->link_name);

	/* Performance Metrics - Link Delay */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_DELAY_BIT))
		json_object_int_add(json_ls_attr, "delay", ls_attr->delay);

	/* Min/Max Delay */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_MIN_MAX_DELAY_BIT)) {
		json_object_int_add(json_ls_attr, "minDelay", ls_attr->min_delay);
		json_object_int_add(json_ls_attr, "maxDelay", ls_attr->max_delay);
	}

	/* Delay Variation */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_JITTER_BIT))
		json_object_int_add(json_ls_attr, "jitter", ls_attr->jitter);

	/* Packet Loss */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_PKT_LOSS_BIT))
		json_object_double_add(json_ls_attr, "loss", ls_attr->pkt_loss * LOSS_PRECISION);

	/* Residual Bandwidth */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_RESIDUAL_BW_BIT))
		json_object_double_add(json_ls_attr, "residualBandwidth", ls_attr->residual_bw);

	/* Available Bandwidth */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_AVAILABLE_BW_BIT))
		json_object_double_add(json_ls_attr, "availableBandwidth", ls_attr->available_bw);

	/* Utilized Bandwidth */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_UTILIZED_BW_BIT))
		json_object_double_add(json_ls_attr, "utilizedBandwidth", ls_attr->utilized_bw);

	/* IGP Flags (for prefixes) */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_IGP_FLAGS_BIT)) {
		snprintfrr(buf, INET6_BUFSIZ, "0x%x", ls_attr->igp_flags);
		json_object_string_add(json_ls_attr, "flags", buf);
	}

	/* Route Tags */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_ROUTE_TAG_BIT)) {
		struct json_object *jtags = json_object_new_array();

		json_object_object_add(json_ls_attr, "tags", jtags);
		for (int i = 0; i < ls_attr->route_tag_count; i++) {
			json_object *jobj = json_object_new_object();

			json_object_int_add(jobj, "tag", ls_attr->route_tags[i]);
			json_object_array_add(jtags, jobj);
		}
	}

	/* Extended Tags */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_EXTENDED_TAG_BIT)) {
		struct json_object *jtags = json_object_new_array();

		json_object_object_add(json_ls_attr, "extendedTags", jtags);
		for (int i = 0; i < ls_attr->extended_tag_count; i++) {
			json_object *jobj = json_object_new_object();

			json_object_int_add(jobj, "tag", ls_attr->extended_tags[i]);
			json_object_array_add(jtags, jobj);
		}
	}

	/* Prefix Metric */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_PREFIX_METRIC_BIT))
		json_object_int_add(json_ls_attr, "prefixMetric", ls_attr->prefix_metric);

	/* OSPF Forwarding Address (IPv4) */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_OSPF_FWD_ADDR_BIT)) {
		if (ls_attr->ospf_fwd_addr.s_addr != INADDR_ANY) {
			snprintfrr(buf, INET6_BUFSIZ, "%pI4", &ls_attr->ospf_fwd_addr);
			json_object_string_add(json_ls_attr, "forwardingAddr", buf);
		} else if (!IN6_IS_ADDR_UNSPECIFIED(&ls_attr->ospf_fwd_addr6)) {
			snprintfrr(buf, INET6_BUFSIZ, "%pI6", &ls_attr->ospf_fwd_addr6);
			json_object_string_add(json_ls_attr, "forwardingAddrV6", buf);
		}
	}

	/* Prefix SID */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_PREFIX_SID_BIT)) {
		json_object *jpref = json_object_new_object();

		json_object_object_add(json_ls_attr, "prefixSid", jpref);
		json_object_int_add(jpref, "sid", ls_attr->prefix_sid.sid);
		snprintfrr(buf, INET6_BUFSIZ, "0x%x", ls_attr->prefix_sid.sid_flag);
		json_object_string_add(jpref, "flags", buf);
		json_object_int_add(jpref, "algo", ls_attr->prefix_sid.algo);
	}

	return json_ls_attr;
}

/*
 * Display BGP-LS Attributes to VTY output
 * Used for "show bgp" commands to display link-state topology information
 */
void bgp_ls_attr_display(struct vty *vty, struct bgp_ls_attr *ls_attr)
{
	int col = 0;
	bool first_attr = true;

#define COL_WIDTH   50
#define INIT_INDENT "      Link-state: "
#define CONT_INDENT "                   "
#define CHECK_WRAP()                                                                              \
	do {                                                                                      \
		if (col > COL_WIDTH) {                                                            \
			vty_out(vty, "\n" CONT_INDENT);                                           \
			col = strlen(CONT_INDENT);                                                \
		} else if (!first_attr) {                                                         \
			vty_out(vty, ", ");                                                       \
			col += 2;                                                                 \
		}                                                                                 \
		first_attr = false;                                                               \
	} while (0)

	vty_out(vty, INIT_INDENT);
	col = strlen(INIT_INDENT);

	/* Node Name */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_NODE_NAME_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Node Name: %s",
			       ls_attr->node_name ? ls_attr->node_name : "(null)");
	}

	/* Local TE Router-ID (IPv4) */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_IPV4_ROUTER_ID_LOCAL_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Local TE Router-ID: %pI4", &ls_attr->ipv4_router_id_local);
	}

	/* Local TE Router-ID (IPv6) */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_IPV6_ROUTER_ID_LOCAL_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Local TE Router-ID: %pI6", &ls_attr->ipv6_router_id_local);
	}

	/* Link bandwidth */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_MAX_LINK_BW_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Maximum Link BW (kbits/sec): %.0f",
			       ls_attr->max_link_bw / 1000.0);
	}

	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_MAX_RESV_BW_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Maximum Reserv Link BW (kbits/sec): %.0f",
			       ls_attr->max_resv_bw / 1000.0);
	}

	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_UNRESV_BW_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Maximum Unreserv Link BW (kbits/sec):");
		for (int j = 0; j < 8; j++)
			col += vty_out(vty, " %.0f", ls_attr->unreserved_bw[j] / 1000.0);
	}

	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_IGP_METRIC_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "metric: %u", ls_attr->igp_metric);
	}

	/* TE Default Metric */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_TE_METRIC_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "TE Default Metric: %u", ls_attr->te_metric);
	}

	/* Administrative Group */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_ADMIN_GROUP_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Administrative Group: 0x%08x", ls_attr->admin_group);
	}

	/* Link Protection Type */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_LINK_PROTECTION_BIT)) {
		CHECK_WRAP();
		vty_out(vty, "Link Protection Type: 0x%04x", ls_attr->link_protection);
	}

	/* MPLS Protocol Mask */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_MPLS_PROTOCOL_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "MPLS Protocol Mask: 0x%02x", ls_attr->mpls_protocol_mask);
	}

	/* SRLG */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_SRLG_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "SRLG:");
		col += 5;
		for (int j = 0; j < ls_attr->srlg_count; j++)
			col += vty_out(vty, " %u", ls_attr->srlg_values[j]);
	}

	/* Link Name */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_LINK_NAME_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Link Name: %s", ls_attr->link_name);
	}

	/* Performance Metrics - Link Delay */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_DELAY_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Link Delay: %u us", ls_attr->delay);
	}

	/* Min/Max Delay */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_MIN_MAX_DELAY_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Min Delay: %u us Max Delay: %u us", ls_attr->min_delay,
			       ls_attr->max_delay);
	}

	/* Delay Variation */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_JITTER_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Delay Variation: %u us", ls_attr->jitter);
	}

	/* Packet Loss */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_PKT_LOSS_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Packet Loss: %g (%%)",
			       (float)(ls_attr->pkt_loss * LOSS_PRECISION));
	}

	/* Residual Bandwidth */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_RESIDUAL_BW_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Residual BW (kbits/sec): %.0f", ls_attr->residual_bw / 1000.0);
	}

	/* Available Bandwidth */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_AVAILABLE_BW_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Available BW (kbits/sec): %.0f",
			       ls_attr->available_bw / 1000.0);
	}

	/* Utilized Bandwidth */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_UTILIZED_BW_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Utilized BW (kbits/sec): %.0f", ls_attr->utilized_bw / 1000.0);
	}

	/* IGP Flags (for prefixes) */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_IGP_FLAGS_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "IGP flags: 0x%02x", ls_attr->igp_flags);
	}

	/* Route Tags */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_ROUTE_TAG_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Route tag:");
		for (int j = 0; j < ls_attr->route_tag_count; j++)
			col += vty_out(vty, " %u", ls_attr->route_tags[j]);
	}

	/* Extended Tags */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_EXTENDED_TAG_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Extended tag:");
		for (int j = 0; j < ls_attr->extended_tag_count; j++)
			col += vty_out(vty, " %" PRIu64, ls_attr->extended_tags[j]);
	}

	/* Prefix Metric */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_PREFIX_METRIC_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Metric: %u", ls_attr->prefix_metric);
	}

	/* OSPF Forwarding Address (IPv4) */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_OSPF_FWD_ADDR_BIT)) {
		if (ls_attr->ospf_fwd_addr.s_addr != INADDR_ANY) {
			CHECK_WRAP();
			col += vty_out(vty, "Forwarding addr: %pI4", &ls_attr->ospf_fwd_addr);
		} else if (!IN6_IS_ADDR_UNSPECIFIED(&ls_attr->ospf_fwd_addr6)) {
			CHECK_WRAP();
			col += vty_out(vty, "Forwarding addr: %pI6", &ls_attr->ospf_fwd_addr6);
		}
	}

	/* Prefix SID */
	if (BGP_LS_TLV_CHECK(ls_attr->present_tlvs, BGP_LS_ATTR_PREFIX_SID_BIT)) {
		CHECK_WRAP();
		col += vty_out(vty, "Prefix-SID: %u Flags 0x%x algo %hhu", ls_attr->prefix_sid.sid,
			       ls_attr->prefix_sid.sid_flag, ls_attr->prefix_sid.algo);
	}

	(void)col; /* Don't complain about last 'col +=' */
#undef CHECK_WRAP
#undef COL_WIDTH
#undef INIT_INDENT
#undef CONT_INDENT

	vty_out(vty, "\n");
}

/*
 * Display BGP-LS NLRI to VTY output
 * Used for "show bgp" commands to display link-state NLRI details
 */
void bgp_ls_nlri_display(struct vty *vty, struct bgp_ls_nlri *nlri)
{
	const char *nlri_type_str = NULL;
	const char *protocol_str = NULL;

	if (!nlri)
		return;

	/* Determine NLRI type string */
	switch (nlri->nlri_type) {
	case BGP_LS_NLRI_TYPE_NODE:
		nlri_type_str = "Node";
		break;
	case BGP_LS_NLRI_TYPE_LINK:
		nlri_type_str = "Link";
		break;
	case BGP_LS_NLRI_TYPE_IPV4_PREFIX:
		nlri_type_str = "Prefix";
		break;
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX:
		nlri_type_str = "Prefix";
		break;
	case BGP_LS_NLRI_TYPE_RESERVED:
		nlri_type_str = "Unknown";
		break;
	}

	/* Determine protocol string */
	switch (nlri->nlri_data.node.protocol_id) {
	case BGP_LS_PROTO_ISIS_L1:
		protocol_str = "ISIS L1";
		break;
	case BGP_LS_PROTO_ISIS_L2:
		protocol_str = "ISIS L2";
		break;
	case BGP_LS_PROTO_OSPFV2:
		protocol_str = "OSPFv2";
		break;
	case BGP_LS_PROTO_OSPFV3:
		protocol_str = "OSPFv3";
		break;
	case BGP_LS_PROTO_BGP:
		protocol_str = "BGP";
		break;
	case BGP_LS_PROTO_DIRECT:
		protocol_str = "Direct";
		break;
	case BGP_LS_PROTO_STATIC:
		protocol_str = "Static";
		break;
	case BGP_LS_PROTO_RESERVED:
		protocol_str = "Unknown";
		break;
	}

	vty_out(vty, "NLRI Type: %s\n", nlri_type_str);
	vty_out(vty, "Protocol: %s\n", protocol_str);
	vty_out(vty, "Identifier: 0x%" PRIx64 "\n", nlri->nlri_data.node.identifier);

	/* Display Local Node Descriptor */
	vty_out(vty, "Local Node Descriptor:\n");
	struct bgp_ls_node_descriptor *local_node = NULL;

	if (nlri->nlri_type == BGP_LS_NLRI_TYPE_NODE) {
		local_node = &nlri->nlri_data.node.local_node;
	} else if (nlri->nlri_type == BGP_LS_NLRI_TYPE_LINK) {
		local_node = &nlri->nlri_data.link.local_node;
	} else if (nlri->nlri_type == BGP_LS_NLRI_TYPE_IPV4_PREFIX ||
		   nlri->nlri_type == BGP_LS_NLRI_TYPE_IPV6_PREFIX) {
		local_node = &nlri->nlri_data.prefix.local_node;
	}

	if (local_node) {
		if (BGP_LS_TLV_CHECK(local_node->present_tlvs, BGP_LS_NODE_DESC_AS_BIT))
			vty_out(vty, "\tAS Number: %u\n", local_node->asn);
		if (BGP_LS_TLV_CHECK(local_node->present_tlvs, BGP_LS_NODE_DESC_OSPF_AREA_BIT))
			vty_out(vty, "\tArea ID: %pI4\n", (in_addr_t *)&local_node->ospf_area_id);
		if (BGP_LS_TLV_CHECK(local_node->present_tlvs, BGP_LS_NODE_DESC_BGP_LS_ID_BIT))
			vty_out(vty, "\tBGP Identifier: %u\n", local_node->bgp_ls_id);
		if (BGP_LS_TLV_CHECK(local_node->present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT)) {
			if (local_node->igp_router_id_len == 4) {
				vty_out(vty, "\tRouter ID IPv4: %pI4\n",
					(struct in_addr *)local_node->igp_router_id);
			} else if (local_node->igp_router_id_len == 6 ||
				   local_node->igp_router_id_len == 7) {
				vty_out(vty, "\tISO Node ID: %02x%02x.%02x%02x.%02x%02x.%02x\n",
					local_node->igp_router_id[0], local_node->igp_router_id[1],
					local_node->igp_router_id[2], local_node->igp_router_id[3],
					local_node->igp_router_id[4], local_node->igp_router_id[5],
					local_node->igp_router_id[6] >> 1);
			} else if (local_node->igp_router_id_len == 16)
				vty_out(vty, "\tRouter ID IPv6: %pI6\n",
					(struct in6_addr *)local_node->igp_router_id);
		}
	}

	/* Display Remote Node Descriptor for Link NLRI */
	if (nlri->nlri_type == BGP_LS_NLRI_TYPE_LINK) {
		struct bgp_ls_node_descriptor *remote_node = &nlri->nlri_data.link.remote_node;

		vty_out(vty, "Remote Node Descriptor:\n");

		if (BGP_LS_TLV_CHECK(remote_node->present_tlvs, BGP_LS_NODE_DESC_AS_BIT))
			vty_out(vty, "\tAS Number: %u\n", remote_node->asn);
		if (BGP_LS_TLV_CHECK(remote_node->present_tlvs, BGP_LS_NODE_DESC_OSPF_AREA_BIT))
			vty_out(vty, "\tArea ID: %pI4\n", (in_addr_t *)&remote_node->ospf_area_id);
		if (BGP_LS_TLV_CHECK(remote_node->present_tlvs, BGP_LS_NODE_DESC_BGP_LS_ID_BIT))
			vty_out(vty, "\tBGP Identifier: %u\n", remote_node->bgp_ls_id);
		if (BGP_LS_TLV_CHECK(remote_node->present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT)) {
			if (remote_node->igp_router_id_len == 4) {
				vty_out(vty, "\tRouter ID IPv4: %pI4\n",
					(struct in_addr *)remote_node->igp_router_id);
			} else if (remote_node->igp_router_id_len == 6 ||
				   remote_node->igp_router_id_len == 7) {
				vty_out(vty, "\tISO Node ID: %02x%02x.%02x%02x.%02x%02x.%02x\n",
					remote_node->igp_router_id[0],
					remote_node->igp_router_id[1],
					remote_node->igp_router_id[2],
					remote_node->igp_router_id[3],
					remote_node->igp_router_id[4],
					remote_node->igp_router_id[5],
					remote_node->igp_router_id[6] >> 1);
			} else if (remote_node->igp_router_id_len == 16)
				vty_out(vty, "\tRouter ID IPv6: %pI6\n",
					(struct in6_addr *)remote_node->igp_router_id);
		}

		/* Display Link Descriptor */
		struct bgp_ls_link_descriptor *link_desc = &nlri->nlri_data.link.link_desc;

		vty_out(vty, "Link Descriptor:\n");

		if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_LINK_ID_BIT)) {
			vty_out(vty, "\tLink ID: %u.%u\n", link_desc->link_local_id,
				link_desc->link_remote_id);
		}

		if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_INTF_BIT))
			vty_out(vty, "\tLocal Interface Address IPv4: %pI4\n",
				&link_desc->ipv4_intf_addr);
		if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_NEIGH_BIT))
			vty_out(vty, "\tNeighbor Interface Address IPv4: %pI4\n",
				&link_desc->ipv4_neigh_addr);
		if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_INTF_BIT))
			vty_out(vty, "\tLocal Interface Address IPv6: %pI6\n",
				&link_desc->ipv6_intf_addr);
		if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_NEIGH_BIT))
			vty_out(vty, "\tNeighbor Interface Address IPv6: %pI6\n",
				&link_desc->ipv6_neigh_addr);

		/* Display Link Descriptor Multi-Topology info */
		if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_MT_ID_BIT)) {
			vty_out(vty, "Multi-Topology:\n");
			for (uint8_t i = 0; i < link_desc->mt_id_count; i++)
				vty_out(vty, "\tMT-ID: %u\n", link_desc->mt_id[i]);
		}
	}

	/* Display Prefix Descriptor for Prefix NLRI */
	if (nlri->nlri_type == BGP_LS_NLRI_TYPE_IPV4_PREFIX ||
	    nlri->nlri_type == BGP_LS_NLRI_TYPE_IPV6_PREFIX) {
		struct bgp_ls_prefix_descriptor *prefix_desc = &nlri->nlri_data.prefix.prefix_desc;

		vty_out(vty, "Prefix Descriptor:\n");

		char prefix_str[BUFSIZ];

		prefix2str(&prefix_desc->prefix, prefix_str, sizeof(prefix_str));
		vty_out(vty, "\tPrefix: %s\n", prefix_str);

		/* OSPF Route Type */
		if (BGP_LS_TLV_CHECK(prefix_desc->present_tlvs, BGP_LS_PREFIX_DESC_OSPF_ROUTE_BIT)) {
			const char *ospf_rt_str = NULL;

			switch (prefix_desc->ospf_route_type) {
			case BGP_LS_OSPF_RT_INTRA_AREA:
				ospf_rt_str = "Intra-Area";
				break;
			case BGP_LS_OSPF_RT_INTER_AREA:
				ospf_rt_str = "Inter-Area";
				break;
			case BGP_LS_OSPF_RT_EXTERNAL_1:
				ospf_rt_str = "External Type 1";
				break;
			case BGP_LS_OSPF_RT_EXTERNAL_2:
				ospf_rt_str = "External Type 2";
				break;
			case BGP_LS_OSPF_RT_NSSA_1:
				ospf_rt_str = "NSSA Type 1";
				break;
			case BGP_LS_OSPF_RT_NSSA_2:
				ospf_rt_str = "NSSA Type 2";
				break;
			default:
				ospf_rt_str = "Unknown";
				break;
			}
			vty_out(vty, "\tOSPF Route Type: %s\n", ospf_rt_str);
		}

		/* Multi-Topology */
		if (BGP_LS_TLV_CHECK(prefix_desc->present_tlvs, BGP_LS_PREFIX_DESC_MT_ID_BIT)) {
			vty_out(vty, "Multi-Topology:\n");
			for (uint8_t i = 0; i < prefix_desc->mt_id_count; i++)
				vty_out(vty, "\tMT-ID: %u\n", prefix_desc->mt_id[i]);
		}
	}
}
