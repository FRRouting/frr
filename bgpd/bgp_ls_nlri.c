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