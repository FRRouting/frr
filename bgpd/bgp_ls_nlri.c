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
