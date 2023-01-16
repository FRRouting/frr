// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Link-State TLV Serializer/Deserializer
 * Copyright 2023 6WIND S.A.
 */

#include <zebra.h>

#include "iso.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_linkstate.h"
#include "bgpd/bgp_linkstate_tlv.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_LS_TYPE_NODE, "BGP-LS Type Node");
DEFINE_MTYPE_STATIC(BGPD, BGP_LS_TYPE_LINK, "BGP-LS Type Link");
DEFINE_MTYPE_STATIC(BGPD, BGP_LS_TYPE_PREFIX4, "BGP-LS Type Prefix IPv4");
DEFINE_MTYPE_STATIC(BGPD, BGP_LS_TYPE_PREFIX6, "BGP-LS Type Prefix IPv6");

struct bgp_linkstate_tlv_info {
	const char *descr;
	uint8_t min_size;
	uint16_t max_size;
	uint8_t multiple;
};

#define MAX_SZ 0xFFFF
#define UNDEF_MULTPL 1

struct bgp_linkstate_tlv_info bgp_linkstate_tlv_infos[BGP_LS_TLV_MAX] = {
		/* NLRI TLV */
		[BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS] = {"Local Node Descriptors", 1, MAX_SZ, UNDEF_MULTPL},
		[BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS] = {"Remote Node Descriptors", 1, MAX_SZ, UNDEF_MULTPL},
		[BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS] = {"Link Local/Remote Identifiers", 2, 2, UNDEF_MULTPL},
		[BGP_LS_TLV_IPV4_INTERFACE_ADDRESS] = {"IPv4 interface address", 4, 4, UNDEF_MULTPL},
		[BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS] = {"IPv4 neighbor address", 4, 4, UNDEF_MULTPL},
		[BGP_LS_TLV_IPV6_INTERFACE_ADDRESS] = {"IPv6 interface address", 16, 16, UNDEF_MULTPL},
		[BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS] = {"IPv6 neighbor address", 16, 16, UNDEF_MULTPL},
		[BGP_LS_TLV_OSPF_ROUTE_TYPE] = {"OSPF Route Type", 1, 1, UNDEF_MULTPL},
		[BGP_LS_TLV_IP_REACHABILITY_INFORMATION] = {"IP Reachability Information", 2, 17, UNDEF_MULTPL},
		[BGP_LS_TLV_AUTONOMOUS_SYSTEM] = {"Autonomous System", 4, 4, UNDEF_MULTPL},
		[BGP_LS_TLV_BGP_LS_IDENTIFIER] = {"BGP-LS Identifier", 4, 4, UNDEF_MULTPL},
		[BGP_LS_TLV_OSPF_AREA_ID] = {"OSPF Area-ID", 4, 4, UNDEF_MULTPL},
		[BGP_LS_TLV_IGP_ROUTER_ID] = {"IGP Router-ID", 4, 8, UNDEF_MULTPL},
		/* NRLI & BGP-LS Attributes */
		[BGP_LS_TLV_MULTI_TOPOLOGY_ID] = {"Multi-Topology ID", 2, MAX_SZ, 2},
};

/* Return the TLV length is valid for the TLV type */
static bool bgp_ls_tlv_check_size(enum bgp_linkstate_tlv type, size_t length)
{
	if (type > BGP_LS_TLV_MAX ||
	    bgp_linkstate_tlv_infos[type].descr == NULL)
		/* TLV type is not defined. Cannot check size */
		return false;

	if (bgp_linkstate_tlv_infos[type].min_size > length)
		return false;
	if (bgp_linkstate_tlv_infos[type].max_size < length)
		return false;
	if (length % bgp_linkstate_tlv_infos[type].multiple != 0)
		return false;

	return true;
}

static uint8_t pnt_decode8(uint8_t **pnt)
{
	uint8_t data;

	data = **pnt;
	*pnt += 1;
	return data;
}

static uint16_t pnt_decode16(uint8_t **pnt)
{
	uint16_t data;

	*pnt = ptr_get_be16(*pnt, &data);

	return data;
}

static uint32_t pnt_decode32(uint8_t **pnt)
{
	uint32_t data;

	*pnt = (uint8_t *)ptr_get_be32(*pnt, &data);

	return data;
}

static uint64_t pnt_decode64(uint8_t **pnt)
{
	uint64_t data;

	*pnt = (uint8_t *)ptr_get_be64(*pnt, &data);

	return data;
}

static const char *bgp_ls_print_nlri_proto(enum bgp_ls_nlri_proto proto)
{
	switch (proto) {
	case BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_1:
		return "ISIS-L1";
	case BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_2:
		return "ISIS-L2";
	case BGP_LS_NLRI_PROTO_ID_OSPF:
		return "OSPFv2";
	case BGP_LS_NLRI_PROTO_ID_DIRECT:
		return "Direct";
	case BGP_LS_NLRI_PROTO_ID_STATIC:
		return "Static";
	case BGP_LS_NLRI_PROTO_ID_OSPFv3:
		return "OSPFv3";
	case BGP_LS_NLRI_PROTO_ID_UNKNOWN:
		return "Unknown";
	}
	return "Unknown";
}

static int bgp_linkstate_nlri_node_descriptor_decode(
	struct bgp_ls_nlri_node_descr_tlv *node_descr, uint8_t *pnt,
	uint16_t len)
{
	uint8_t *lim = pnt + len;
	uint16_t type, length;

	while (pnt < lim) {
		type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);

		if (!bgp_ls_tlv_check_size(type, length))
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;

		switch (type) {
		case BGP_LS_TLV_AUTONOMOUS_SYSTEM:
			if (CHECK_FLAG(
				    node_descr->flags,
				    BGP_NLRI_TLV_NODE_DESCR_AUTONOMOUS_SYSTEM))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(node_descr->flags,
				 BGP_NLRI_TLV_NODE_DESCR_AUTONOMOUS_SYSTEM);
			node_descr->autonomous_system = pnt_decode32(&pnt);
			break;
		case BGP_LS_TLV_BGP_LS_IDENTIFIER:
			if (CHECK_FLAG(node_descr->flags,
				       BGP_NLRI_TLV_NODE_DESCR_BGP_LS_ID))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(node_descr->flags,
				 BGP_NLRI_TLV_NODE_DESCR_BGP_LS_ID);
			node_descr->bgp_ls_id = pnt_decode32(&pnt);
			break;
		case BGP_LS_TLV_OSPF_AREA_ID:
			if (CHECK_FLAG(node_descr->flags,
				       BGP_NLRI_TLV_NODE_DESCR_AREA_ID))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(node_descr->flags,
				 BGP_NLRI_TLV_NODE_DESCR_AREA_ID);
			node_descr->area_id = pnt_decode32(&pnt);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID:
			if (CHECK_FLAG(node_descr->flags,
				       BGP_NLRI_TLV_NODE_DESCR_IGP_ROUTER_ID))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			switch (length) {
			case BGP_LS_TLV_IGP_ROUTER_ID_ISIS_NON_PSEUDOWIRE_SIZE:
			case BGP_LS_TLV_IGP_ROUTER_ID_ISIS_PSEUDOWIRE_SIZE:
			case BGP_LS_TLV_IGP_ROUTER_ID_OSPF_NON_PSEUDOWIRE_SIZE:
			case BGP_LS_TLV_IGP_ROUTER_ID_OSPF_PSEUDOWIRE_SIZE:
				SET_FLAG(node_descr->flags,
					 BGP_NLRI_TLV_NODE_DESCR_IGP_ROUTER_ID);
				memcpy(&node_descr->igp_router_id, pnt, length);
				node_descr->igp_router_id_size = length;
				pnt += length;
				break;
			default:
				zlog_err(
					"%s: received invalid IGP Router-ID length %hu",
					__func__, length);
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			}
			break;
		default:
			zlog_err(
				"%s: received an unexpected node descriptor TLV %hu",
				__func__, type);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		}
	}

	return BGP_NLRI_PARSE_OK;
}

static size_t bgp_linkstate_nlri_node_descriptor_display(
	struct bgp_ls_nlri_node_descr_tlv *node_descr, char *buf, size_t size,
	bool multiline)
{
	bool first = true;

	if (CHECK_FLAG(node_descr->flags, BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE))
		snprintf(buf, size, "%sLocal%s", multiline ? "\n" : " ",
			 multiline ? "  " : "{");
	else if (CHECK_FLAG(node_descr->flags,
			    BGP_NLRI_TLV_NODE_DESCR_REMOTE_NODE))
		snprintf(buf, size, "%sRemote%s", multiline ? "\n" : " ",
			 multiline ? " " : "{");
	size -= strlen(buf);
	buf += strlen(buf);

	if (CHECK_FLAG(node_descr->flags,
		       BGP_NLRI_TLV_NODE_DESCR_AUTONOMOUS_SYSTEM)) {
		snprintf(buf, size, "%sAS:%u", first ? "" : " ",
			 node_descr->autonomous_system);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(node_descr->flags, BGP_NLRI_TLV_NODE_DESCR_BGP_LS_ID)) {
		snprintf(buf, size, "%sID:%u", first ? "" : " ",
			 node_descr->bgp_ls_id);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(node_descr->flags, BGP_NLRI_TLV_NODE_DESCR_AREA_ID)) {
		snprintf(buf, size, "%sArea:%u", first ? "" : " ",
			 node_descr->area_id);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(node_descr->flags,
		       BGP_NLRI_TLV_NODE_DESCR_IGP_ROUTER_ID)) {
		switch (node_descr->igp_router_id_size) {
		case BGP_LS_TLV_IGP_ROUTER_ID_ISIS_NON_PSEUDOWIRE_SIZE:
			snprintfrr(buf, size, "%sRtr:%pSY", first ? "" : " ",
				   (uint8_t *)&node_descr->igp_router_id);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID_ISIS_PSEUDOWIRE_SIZE:
			snprintfrr(buf, size, "%sRtr:%pPN", first ? "" : " ",
				   (uint8_t *)&node_descr->igp_router_id);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID_OSPF_NON_PSEUDOWIRE_SIZE:
			snprintfrr(buf, size, "%sRtr:%pI4", first ? "" : " ",
				   (in_addr_t *)&node_descr->igp_router_id);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID_OSPF_PSEUDOWIRE_SIZE:
			snprintfrr(
				buf, size, "%sRtr:%pI4:%pI4", first ? "" : " ",
				(in_addr_t *)&node_descr->igp_router_id,
				((in_addr_t *)&node_descr->igp_router_id + 1));
			break;
		}

		size -= strlen(buf);
		buf += strlen(buf);
	}

	if (!multiline) {
		snprintf(buf, size, "}");
		size -= strlen(buf);
	}

	return size;
}

static uint16_t
bgp_linkstate_nlri_node_prefixlen(struct bgp_linkstate_type_node *p_node)
{
	return sizeof(struct bgp_linkstate_type_node);
}

static int bgp_linkstate_nlri_node_decode(struct bgp_linkstate_type_node **pp,
					  uint8_t *pnt, uint16_t len)
{
	int ret = BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
	struct bgp_linkstate_type_node *p_node = *pp;
	uint8_t *lim = pnt + len;
	uint16_t type, length;

	p_node->proto = pnt_decode8(&pnt);
	p_node->identifier = pnt_decode64(&pnt);

	while (pnt < lim) {
		type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);
		switch (type) {
		case BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS:
			if (p_node->local_node_descr.flags != 0)
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_node->local_node_descr.flags,
				 BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE);
			ret = bgp_linkstate_nlri_node_descriptor_decode(
				&p_node->local_node_descr, pnt, length);
			break;
		default:
			zlog_err("%s: received an unexpected TLV type %hu",
				 __func__, type);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		}
		if (ret != BGP_NLRI_PARSE_OK)
			return ret;
		pnt += length;
	}

	return ret;
}

static void
bgp_linkstate_nlri_node_display(char *buf, size_t size,
				struct bgp_linkstate_type_node *p_node,
				bool multiline)
{
	snprintfrr(buf, size, " %s ID:0x%" PRIx64,
		   bgp_ls_print_nlri_proto(p_node->proto), p_node->identifier);
	size -= strlen(buf);
	buf += strlen(buf);

	bgp_linkstate_nlri_node_descriptor_display(&p_node->local_node_descr,
						   buf, size, multiline);
}

static int bgp_linkstate_nlri_link_descriptor_decode(
	struct bgp_ls_nlri_link_descr_tlv *link_descr, uint8_t *pnt,
	uint16_t type, uint16_t length)
{
	switch (type) {
	case BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS:
		if (CHECK_FLAG(link_descr->flags,
			       BGP_NLRI_TLV_LINK_DESCR_LOCAL_REMOTE_ID))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(link_descr->flags,
			 BGP_NLRI_TLV_LINK_DESCR_LOCAL_REMOTE_ID);
		link_descr->local_remote_id = pnt_decode16(&pnt);
		break;
	case BGP_LS_TLV_IPV4_INTERFACE_ADDRESS:
		if (CHECK_FLAG(link_descr->flags,
			       BGP_NLRI_TLV_LINK_DESCR_INTERFACE4))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_INTERFACE4);
		memcpy(&link_descr->interface4, pnt, length);
		*pnt += length;
		break;
	case BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS:
		if (CHECK_FLAG(link_descr->flags,
			       BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR4))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR4);
		memcpy(&link_descr->neighbor4, pnt, length);
		*pnt += length;
		break;
	case BGP_LS_TLV_IPV6_INTERFACE_ADDRESS:
		if (CHECK_FLAG(link_descr->flags,
			       BGP_NLRI_TLV_LINK_DESCR_INTERFACE6))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_INTERFACE6);
		memcpy(&link_descr->interface6, pnt, length);
		*pnt += length;
		break;
	case BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS:
		if (CHECK_FLAG(link_descr->flags,
			       BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR6))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR6);
		memcpy(&link_descr->neighbor6, pnt, length);
		*pnt += length;
		break;
	default:
		assert(!"NLRI link descriptor decode cannot be used for this TLV type!");
		break;
	}

	return BGP_NLRI_PARSE_OK;
}

static size_t
bgp_linkstate_nlri_mtid_display(struct bgp_ls_tlv_generic *mtid_tlv, char *buf,
				size_t size, bool first)
{
	uint16_t *mtid;

	mtid = (uint16_t *)&mtid_tlv->data;
	for (int i = 0; i < (mtid_tlv->length / 2); i++) {
		if (i == 0)
			snprintf(buf, size, "%sMT:%hu", first ? "" : " ",
				 mtid[i]);
		else
			snprintf(buf, size, ",%hu", mtid[i]);
		size -= strlen(buf);
		buf += strlen(buf);
	}
	return size;
}

static size_t bgp_linkstate_nlri_link_descriptor_display(
	struct bgp_ls_nlri_link_descr_tlv *link_descr, char *buf, size_t size,
	bool multiline)
{
	bool first = true;

	if (link_descr->flags == 0)
		return size;

	snprintf(buf, size, "%sLink%s", multiline ? "\n" : " ",
		 multiline ? "   " : "{");
	size -= strlen(buf);
	buf += strlen(buf);

	if (CHECK_FLAG(link_descr->flags,
		       BGP_NLRI_TLV_LINK_DESCR_LOCAL_REMOTE_ID)) {
		snprintf(buf, size, "%sLocal/remote:%hu", first ? "" : " ",
			 link_descr->local_remote_id);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_INTERFACE4)) {
		snprintfrr(buf, size, "%sIPv4:%pI4", first ? "" : " ",
			   &link_descr->interface4);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR4)) {
		snprintfrr(buf, size, "%sNeigh-IPv4:%pI4", first ? "" : " ",
			   &link_descr->neighbor4);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_INTERFACE6)) {
		snprintfrr(buf, size, "%sIPv6:%pI6", first ? "" : " ",
			   &link_descr->interface6);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR6)) {
		snprintfrr(buf, size, "%sNeigh-IPv6:%pI6", first ? "" : " ",
			   &link_descr->neighbor6);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(link_descr->flags, BGP_NLRI_TLV_LINK_DESCR_MT_ID)) {
		size = bgp_linkstate_nlri_mtid_display(&link_descr->mtid, buf,
						       size, first);
		buf += strlen(buf);
	}

	if (!multiline) {
		snprintf(buf, size, "}");
		size -= strlen(buf);
	}

	return size;
}

static uint16_t
bgp_linkstate_nlri_link_prefixlen(struct bgp_linkstate_type_link *p_link)
{
	return sizeof(struct bgp_linkstate_type_link) +
	       p_link->link_descr.mtid.length;
}

static int bgp_linkstate_nlri_link_decode(struct bgp_linkstate_type_link **pp,
					  uint8_t *pnt, uint16_t len)
{
	int ret = BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
	struct bgp_linkstate_type_link *p_link = *pp;
	uint8_t *lim = pnt + len;
	uint16_t type, length, *dst, *src;

	p_link->proto = pnt_decode8(&pnt);
	p_link->identifier = pnt_decode64(&pnt);

	while (pnt < lim) {
		type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);

		if (!bgp_ls_tlv_check_size(type, length))
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;

		switch (type) {
		case BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS:
			if (p_link->local_node_descr.flags != 0)
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_link->local_node_descr.flags,
				 BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE);
			ret = bgp_linkstate_nlri_node_descriptor_decode(
				&p_link->local_node_descr, pnt, length);
			break;
		case BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS:
			if (p_link->remote_node_descr.flags != 0)
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_link->remote_node_descr.flags,
				 BGP_NLRI_TLV_NODE_DESCR_REMOTE_NODE);
			ret = bgp_linkstate_nlri_node_descriptor_decode(
				&p_link->remote_node_descr, pnt, length);
			break;
		case BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS:
		case BGP_LS_TLV_IPV4_INTERFACE_ADDRESS:
		case BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS:
		case BGP_LS_TLV_IPV6_INTERFACE_ADDRESS:
		case BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS:
			bgp_linkstate_nlri_link_descriptor_decode(
				&p_link->link_descr, pnt, type, length);
			break;
		case BGP_LS_TLV_MULTI_TOPOLOGY_ID:
			if (CHECK_FLAG(p_link->link_descr.flags,
				       BGP_NLRI_TLV_PREFIX_DESCR_MT_ID))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			if ((length % 2) != 0)
				/* Length must be a multiple of 2 */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_link->link_descr.flags,
				 BGP_NLRI_TLV_LINK_DESCR_MT_ID);
			*pp = XREALLOC(MTYPE_BGP_LS_TYPE_LINK, *pp,
				       sizeof(struct bgp_linkstate_type_link) +
					       length);
			p_link = *pp;
			p_link->link_descr.mtid.length = length;
			dst = (uint16_t *)&p_link->link_descr.mtid.data;
			src = (uint16_t *)pnt;
			for (int i = 0; i < (length / 2); i++)
				dst[i] = ntohs(src[i]);
			break;
		default:
			zlog_err("%s: received an unexpected TLV type %hu",
				 __func__, type);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		}
		if (ret != BGP_NLRI_PARSE_OK)
			return ret;
		pnt += length;
	}

	if (p_link->local_node_descr.flags == 0 ||
	    p_link->remote_node_descr.flags == 0)
		/* Local and remote nodes are mandatory */
		return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;

	return ret;
}

static void
bgp_linkstate_nlri_link_display(char *buf, size_t size,
				struct bgp_linkstate_type_link *p_link,
				bool multiline)
{
	snprintfrr(buf, size, " %s ID:0x%" PRIx64,
		   bgp_ls_print_nlri_proto(p_link->proto), p_link->identifier);
	size -= strlen(buf);
	buf += strlen(buf);

	size = bgp_linkstate_nlri_node_descriptor_display(
		&p_link->local_node_descr, buf, size, multiline);
	buf += strlen(buf);

	size = bgp_linkstate_nlri_node_descriptor_display(
		&p_link->remote_node_descr, buf, size, multiline);
	buf += strlen(buf);

	bgp_linkstate_nlri_link_descriptor_display(&p_link->link_descr, buf,
						   size, multiline);
}

static int bgp_linkstate_nlri_prefix4_descriptor_decode(
	struct bgp_ls_nlri_prefix4_descr_tlv *prefix4_descr, uint8_t *pnt,
	uint16_t type, uint16_t length)
{
	switch (type) {
	case BGP_LS_TLV_OSPF_ROUTE_TYPE:
		if (CHECK_FLAG(prefix4_descr->flags,
			       BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(prefix4_descr->flags,
			 BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE);
		prefix4_descr->ospf_route_type = pnt_decode8(&pnt);
		break;
	case BGP_LS_TLV_IP_REACHABILITY_INFORMATION:
		if (CHECK_FLAG(prefix4_descr->flags,
			       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(prefix4_descr->flags,
			 BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY);
		prefix4_descr->ip_reachability_prefixlen = pnt_decode8(&pnt);
		memcpy(&prefix4_descr->ip_reachability_prefix.s_addr, pnt,
		       length - sizeof(prefix4_descr
					       ->ip_reachability_prefixlen));
		break;
	default:
		assert(!"NLRI prefix4 descriptor decode cannot be used for this TLV type!");
		break;
	}

	return BGP_NLRI_PARSE_OK;
}

static size_t bgp_linkstate_nlri_prefix4_descriptor_display(
	struct bgp_ls_nlri_prefix4_descr_tlv *prefix4_descr, char *buf,
	size_t size, bool multiline)
{
	bool first = true;

	if (prefix4_descr->flags == 0)
		return size;

	snprintf(buf, size, "%sPrefix%s", multiline ? "\n" : " ",
		 multiline ? " " : "{");
	size -= strlen(buf);
	buf += strlen(buf);

	if (CHECK_FLAG(prefix4_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE)) {
		snprintf(buf, size, "%sOSPF-Route-Type:%u", first ? "" : " ",
			 prefix4_descr->ospf_route_type);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(prefix4_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY)) {
		snprintfrr(buf, size, "%sIPv4:%pI4/%u", first ? "" : " ",
			   &prefix4_descr->ip_reachability_prefix,
			   prefix4_descr->ip_reachability_prefixlen);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(prefix4_descr->flags, BGP_NLRI_TLV_PREFIX_DESCR_MT_ID)) {
		size = bgp_linkstate_nlri_mtid_display(&prefix4_descr->mtid,
						       buf, size, first);
		buf += strlen(buf);
	}

	if (!multiline) {
		snprintf(buf, size, "}");
		size -= strlen(buf);
	}

	return size;
}

static uint16_t bgp_linkstate_nlri_prefix4_prefixlen(
	struct bgp_linkstate_type_prefix4 *p_prefix4)
{
	return sizeof(struct bgp_linkstate_type_prefix4) +
	       p_prefix4->prefix_descr.mtid.length;
}

static int
bgp_linkstate_nlri_prefix4_decode(struct bgp_linkstate_type_prefix4 **pp,
				  uint8_t *pnt, uint16_t len)
{
	struct bgp_linkstate_type_prefix4 *p_prefix4 = *pp;
	int ret = BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
	uint8_t *lim = pnt + len;
	uint16_t type, length;
	uint16_t *dst, *src;

	p_prefix4->proto = pnt_decode8(&pnt);
	p_prefix4->identifier = pnt_decode64(&pnt);

	while (pnt < lim) {
		type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);

		if (!bgp_ls_tlv_check_size(type, length))
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;

		switch (type) {
		case BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS:
			if (p_prefix4->local_node_descr.flags != 0)
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_prefix4->local_node_descr.flags,
				 BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE);
			ret = bgp_linkstate_nlri_node_descriptor_decode(
				&p_prefix4->local_node_descr, pnt, length);
			break;
		case BGP_LS_TLV_OSPF_ROUTE_TYPE:
		case BGP_LS_TLV_IP_REACHABILITY_INFORMATION:
			ret = bgp_linkstate_nlri_prefix4_descriptor_decode(
				&p_prefix4->prefix_descr, pnt, type, length);
			break;
		case BGP_LS_TLV_MULTI_TOPOLOGY_ID:
			if (CHECK_FLAG(p_prefix4->prefix_descr.flags,
				       BGP_NLRI_TLV_PREFIX_DESCR_MT_ID))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			if ((length % 2) != 0)
				/* Length must be a multiple of 2 */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_prefix4->prefix_descr.flags,
				 BGP_NLRI_TLV_PREFIX_DESCR_MT_ID);
			*pp = XREALLOC(
				MTYPE_BGP_LS_TYPE_PREFIX4, *pp,
				sizeof(struct bgp_linkstate_type_prefix4) +
					length);
			p_prefix4 = *pp;
			p_prefix4->prefix_descr.mtid.length = length;
			dst = (uint16_t *)&p_prefix4->prefix_descr.mtid.data;
			src = (uint16_t *)pnt;
			for (int i = 0; i < (length / 2); i++)
				dst[i] = ntohs(src[i]);
			break;
		default:
			zlog_err("%s: received an unexpected TLV type %hu",
				 __func__, type);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		}
		if (ret != BGP_NLRI_PARSE_OK)
			return ret;
		pnt += length;
	}

	if (p_prefix4->local_node_descr.flags == 0 ||
	    p_prefix4->prefix_descr.flags == 0)
		/* Local node and prefix info are mandatory */
		return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;

	return ret;
}

static void
bgp_linkstate_nlri_prefix4_display(char *buf, size_t size,
				   struct bgp_linkstate_type_prefix4 *p_prefix4,
				   bool multiline)
{
	snprintfrr(buf, size, " %s ID:0x%" PRIx64,
		   bgp_ls_print_nlri_proto(p_prefix4->proto),
		   p_prefix4->identifier);
	size -= strlen(buf);
	buf += strlen(buf);

	size = bgp_linkstate_nlri_node_descriptor_display(
		&p_prefix4->local_node_descr, buf, size, multiline);
	buf += strlen(buf);

	bgp_linkstate_nlri_prefix4_descriptor_display(&p_prefix4->prefix_descr,
						      buf, size, multiline);
}

static int bgp_linkstate_nlri_prefix6_descriptor_decode(
	struct bgp_ls_nlri_prefix6_descr_tlv *prefix6_descr, uint8_t *pnt,
	uint16_t type, uint16_t length)
{
	switch (type) {
	case BGP_LS_TLV_OSPF_ROUTE_TYPE:
		if (CHECK_FLAG(prefix6_descr->flags,
			       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(prefix6_descr->flags,
			 BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE);
		prefix6_descr->ospf_route_type = pnt_decode8(&pnt);
		break;
	case BGP_LS_TLV_IP_REACHABILITY_INFORMATION:
		if (CHECK_FLAG(prefix6_descr->flags,
			       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY))
			/* TLV must be present only once */
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		SET_FLAG(prefix6_descr->flags,
			 BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY);
		prefix6_descr->ip_reachability_prefixlen = pnt_decode8(&pnt);
		memcpy(&prefix6_descr->ip_reachability_prefix, pnt,
		       length - sizeof(prefix6_descr
					       ->ip_reachability_prefixlen));
		break;
	default:
		assert(!"NLRI prefix6 descriptor decode cannot be used for this TLV type!");
		break;
	}

	return BGP_NLRI_PARSE_OK;
}

static size_t bgp_linkstate_nlri_prefix6_descriptor_display(
	struct bgp_ls_nlri_prefix6_descr_tlv *prefix6_descr, char *buf,
	size_t size, bool multiline)
{
	bool first = true;

	if (prefix6_descr->flags == 0)
		return size;

	snprintf(buf, size, "%sPrefix%s", multiline ? "\n" : " ",
		 multiline ? " " : "{");
	size -= strlen(buf);
	buf += strlen(buf);

	if (CHECK_FLAG(prefix6_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE)) {
		snprintf(buf, size, "%sOSPF-Route-Type:%u", first ? "" : " ",
			 prefix6_descr->ospf_route_type);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(prefix6_descr->flags,
		       BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY)) {
		snprintfrr(buf, size, "%sIPv6:%pI6/%u", first ? "" : " ",
			   &prefix6_descr->ip_reachability_prefix,
			   prefix6_descr->ip_reachability_prefixlen);
		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}
	if (CHECK_FLAG(prefix6_descr->flags, BGP_NLRI_TLV_PREFIX_DESCR_MT_ID)) {
		size = bgp_linkstate_nlri_mtid_display(&prefix6_descr->mtid,
						       buf, size, first);
		buf += strlen(buf);
	}

	if (!multiline) {
		snprintf(buf, size, "}");
		size -= strlen(buf);
	}

	return size;
}

static uint16_t bgp_linkstate_nlri_prefix6_prefixlen(
	struct bgp_linkstate_type_prefix6 *p_prefix6)
{
	return sizeof(struct bgp_linkstate_type_prefix6) +
	       p_prefix6->prefix_descr.mtid.length;
}

static int
bgp_linkstate_nlri_prefix6_decode(struct bgp_linkstate_type_prefix6 **pp,
				  uint8_t *pnt, uint16_t len)
{
	int ret = BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
	struct bgp_linkstate_type_prefix6 *p_prefix6 = *pp;
	uint8_t *lim = pnt + len;
	uint16_t type, length;
	uint16_t *dst, *src;

	p_prefix6->proto = pnt_decode8(&pnt);
	p_prefix6->identifier = pnt_decode64(&pnt);

	while (pnt < lim) {
		type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);
		switch (type) {
		case BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS:
			if (p_prefix6->local_node_descr.flags != 0)
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_prefix6->local_node_descr.flags,
				 BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE);
			ret = bgp_linkstate_nlri_node_descriptor_decode(
				&p_prefix6->local_node_descr, pnt, length);
			break;
		case BGP_LS_TLV_OSPF_ROUTE_TYPE:
		case BGP_LS_TLV_IP_REACHABILITY_INFORMATION:
			ret = bgp_linkstate_nlri_prefix6_descriptor_decode(
				&p_prefix6->prefix_descr, pnt, type, length);
			break;
		case BGP_LS_TLV_MULTI_TOPOLOGY_ID:
			if (CHECK_FLAG(p_prefix6->prefix_descr.flags,
				       BGP_NLRI_TLV_PREFIX_DESCR_MT_ID))
				/* TLV must be present only once */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			if ((length % 2) != 0)
				/* Length must be a multiple of 2 */
				return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
			SET_FLAG(p_prefix6->prefix_descr.flags,
				 BGP_NLRI_TLV_PREFIX_DESCR_MT_ID);
			*pp = XREALLOC(
				MTYPE_BGP_LS_TYPE_PREFIX6, *pp,
				sizeof(struct bgp_linkstate_type_prefix6) +
					length);
			p_prefix6 = *pp;
			p_prefix6->prefix_descr.mtid.length = length;
			dst = (uint16_t *)&p_prefix6->prefix_descr.mtid.data;
			src = (uint16_t *)pnt;
			for (int i = 0; i < (length / 2); i++)
				dst[i] = ntohs(src[i]);
			break;
		default:
			zlog_err("%s: received an unexpected TLV type %hu",
				 __func__, type);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;
		}
		if (ret != BGP_NLRI_PARSE_OK)
			return ret;
		pnt += length;
	}

	if (p_prefix6->local_node_descr.flags == 0 ||
	    p_prefix6->prefix_descr.flags == 0)
		/* Local node and prefix info are mandatory */
		return BGP_NLRI_PARSE_ERROR_PREFIX_LINKSTATE;

	return ret;
}

static void
bgp_linkstate_nlri_prefix6_display(char *buf, size_t size,
				   struct bgp_linkstate_type_prefix6 *p_prefix6,
				   bool multiline)
{
	snprintfrr(buf, size, " %s ID:0x%" PRIx64,
		   bgp_ls_print_nlri_proto(p_prefix6->proto),
		   p_prefix6->identifier);
	size -= strlen(buf);
	buf += strlen(buf);

	size = bgp_linkstate_nlri_node_descriptor_display(
		&p_prefix6->local_node_descr, buf, size, multiline);
	buf += strlen(buf);

	bgp_linkstate_nlri_prefix6_descriptor_display(&p_prefix6->prefix_descr,
						      buf, size, multiline);
}

int bgp_nlri_parse_linkstate(struct peer *peer, struct attr *attr,
			     struct bgp_nlri *packet, int withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	uint16_t psize = 0;
	struct prefix p;
	struct bgp_linkstate_type_node *p_node = NULL;
	struct bgp_linkstate_type_link *p_link = NULL;
	struct bgp_linkstate_type_prefix4 *p_prefix4 = NULL;
	struct bgp_linkstate_type_prefix6 *p_prefix6 = NULL;
	int ret;

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;

	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		/* All linkstate NLRI begin with NRLI type and length. */
		if (pnt + 4 > lim)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		p.u.prefix_linkstate.nlri_type = pnt_decode16(&pnt);
		psize = pnt_decode16(&pnt);
		/* When packet overflow occur return immediately. */
		if (pnt + psize > lim) {
			flog_err(
				EC_BGP_LINKSTATE_PACKET,
				"Link-State NLRI length inconsistent (size %u seen)",
				psize);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}
		p.family = AF_LINKSTATE;

		switch (p.u.prefix_linkstate.nlri_type) {
		case BGP_LINKSTATE_NODE:
			p_node =
				XCALLOC(MTYPE_BGP_LS_TYPE_NODE,
					sizeof(struct bgp_linkstate_type_node));
			ret = bgp_linkstate_nlri_node_decode(&p_node, pnt,
							     psize);
			if (ret != BGP_NLRI_PARSE_OK) {
				XFREE(MTYPE_BGP_LS_TYPE_NODE, p_node);
				return ret;
			}
			p.u.prefix_linkstate.ptr = (uintptr_t)p_node;
			p.prefixlen = bgp_linkstate_nlri_node_prefixlen(p_node);
			break;
		case BGP_LINKSTATE_LINK:
			p_link =
				XCALLOC(MTYPE_BGP_LS_TYPE_LINK,
					sizeof(struct bgp_linkstate_type_link));
			ret = bgp_linkstate_nlri_link_decode(&p_link, pnt,
							     psize);
			if (ret != BGP_NLRI_PARSE_OK) {
				XFREE(MTYPE_BGP_LS_TYPE_LINK, p_link);
				return ret;
			}
			p.u.prefix_linkstate.ptr = (uintptr_t)p_link;
			p.prefixlen = bgp_linkstate_nlri_link_prefixlen(p_link);
			break;
		case BGP_LINKSTATE_PREFIX4:
			p_prefix4 = XCALLOC(
				MTYPE_BGP_LS_TYPE_PREFIX4,
				sizeof(struct bgp_linkstate_type_prefix4));
			ret = bgp_linkstate_nlri_prefix4_decode(&p_prefix4, pnt,
								psize);
			if (ret != BGP_NLRI_PARSE_OK) {
				XFREE(MTYPE_BGP_LS_TYPE_PREFIX4, p_prefix4);
				return ret;
			}
			p.u.prefix_linkstate.ptr = (uintptr_t)p_prefix4;
			p.prefixlen =
				bgp_linkstate_nlri_prefix4_prefixlen(p_prefix4);
			break;
		case BGP_LINKSTATE_PREFIX6:
			p_prefix6 = XCALLOC(
				MTYPE_BGP_LS_TYPE_PREFIX6,
				sizeof(struct bgp_linkstate_type_prefix6));
			ret = bgp_linkstate_nlri_prefix6_decode(&p_prefix6, pnt,
								psize);
			if (ret != BGP_NLRI_PARSE_OK) {
				XFREE(MTYPE_BGP_LS_TYPE_PREFIX6, p_prefix6);
				return ret;
			}
			p.u.prefix_linkstate.ptr = (uintptr_t)p_prefix6;
			p.prefixlen =
				bgp_linkstate_nlri_prefix6_prefixlen(p_prefix6);
			break;
		}

		/* Process the route. */
		if (withdraw)
			bgp_withdraw(peer, &p, 0, afi, safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0, NULL);
		else
			bgp_update(peer, &p, 0, attr, afi, safi,
				   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL,
				   NULL, 0, 0, NULL);

		switch (p.u.prefix_linkstate.nlri_type) {
		case BGP_LINKSTATE_NODE:
			XFREE(MTYPE_BGP_LS_TYPE_NODE, p_node);
			break;
		case BGP_LINKSTATE_LINK:
			XFREE(MTYPE_BGP_LS_TYPE_LINK, p_link);
			break;
		case BGP_LINKSTATE_PREFIX4:
			XFREE(MTYPE_BGP_LS_TYPE_PREFIX4, p_prefix4);
			break;
		case BGP_LINKSTATE_PREFIX6:
			XFREE(MTYPE_BGP_LS_TYPE_PREFIX6, p_prefix6);
			break;
		}
	}
	return BGP_NLRI_PARSE_OK;
}

char *bgp_linkstate_nlri_prefix_display(char *buf, size_t size,
					uint16_t nlri_type, void *prefix)
{
	char *cbuf = buf;

	snprintf(buf, size, "%s", bgp_linkstate_nlri_type_2str(nlri_type));
	size -= strlen(buf);
	buf += strlen(buf);

	switch (nlri_type) {
	case BGP_LINKSTATE_NODE:
		bgp_linkstate_nlri_node_display(buf, size, prefix, false);
		break;
	case BGP_LINKSTATE_LINK:
		bgp_linkstate_nlri_link_display(buf, size, prefix, false);
		break;
	case BGP_LINKSTATE_PREFIX4:
		bgp_linkstate_nlri_prefix4_display(buf, size, prefix, false);
		break;
	case BGP_LINKSTATE_PREFIX6:
		bgp_linkstate_nlri_prefix6_display(buf, size, prefix, false);
		break;
	}

	return cbuf;
}
