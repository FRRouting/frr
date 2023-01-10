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
#include "bgpd/bgp_linkstate_tlv.h"


static bool bgp_linkstate_nlri_value_display(char *buf, size_t size,
					     uint8_t *pnt, uint16_t nlri_type,
					     uint16_t type, uint16_t length,
					     bool first, json_object *json);

struct bgp_linkstate_tlv_info {
	const char *descr;
	uint8_t min_size;
	uint16_t max_size;
	uint8_t multiple;
};

#define UNDEF_MIN_SZ 0xFF
#define MAX_SZ 0xFFFF
#define UNDEF_MULTPL 1

/* clang-format off */
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
/* clang-format on */

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

int bgp_nlri_parse_linkstate(struct peer *peer, struct attr *attr,
			     struct bgp_nlri *packet, int withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	uint16_t length = 0;
	struct prefix p;

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;

	for (; pnt < lim; pnt += length) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		/* All linkstate NLRI begin with NRLI type and length. */
		if (pnt + 4 > lim)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		p.u.prefix_linkstate.nlri_type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);
		/* When packet overflow occur return immediately. */
		if (pnt + length > lim) {
			flog_err(
				EC_BGP_LINKSTATE_PACKET,
				"Link-State NLRI length inconsistent (size %u seen)",
				length);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}
		p.family = AF_LINKSTATE;

		p.u.prefix_linkstate.ptr = (uintptr_t)pnt;
		p.prefixlen = length;

		if (BGP_DEBUG(linkstate, LINKSTATE)) {
			zlog_debug("LS Rx %s %s %pFX",
				   withdraw ? "Withdraw" : "Update",
				   afi2str(afi), &p);
		}

		/* Process the route. */
		if (withdraw)
			bgp_withdraw(peer, &p, 0, afi, safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0, NULL);
		else
			bgp_update(peer, &p, 0, attr, afi, safi,
				   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL,
				   NULL, 0, 0, NULL);
	}
	return BGP_NLRI_PARSE_OK;
}

/*
 * Encode Link-State prefix in Update (MP_REACH)
 */
void bgp_nlri_encode_linkstate(struct stream *s, const struct prefix *p)
{
	/* NLRI type */
	stream_putw(s, p->u.prefix_linkstate.nlri_type);

	/* Size */
	stream_putw(s, p->prefixlen);

	stream_put(s, (const void *)p->u.prefix_linkstate.ptr, p->prefixlen);
}

static size_t bgp_linkstate_nlri_hexa_display(char *buf, size_t size,
					      uint8_t *pnt, uint16_t type,
					      uint16_t length, bool first,
					      json_object *json)
{
	json_object *json_array = NULL;
	uint8_t *lim = pnt + length;
	char json_buf[19];
	int i;

	if (json) {
		snprintf(json_buf, sizeof(json_buf), "%u", type);
		json_array = json_object_new_array();
		json_object_object_add(json, json_buf, json_array);
		for (i = 0; pnt < lim; pnt++, i++) {
			if (i % 8 == 0) {
				if (i != 0)
					json_object_array_add(
						json_array,
						json_object_new_string(
							json_buf));
				snprintf(json_buf, sizeof(buf), "0x");
			}
			snprintf(json_buf + strlen(json_buf),
				 sizeof(json_buf) - strlen(json_buf), "%02x",
				 *pnt);
		}
		if (strlen(json_buf) > 2) /* do not only contain 0x */
			json_object_array_add(json_array,
					      json_object_new_string(json_buf));

		return size;
	}

	snprintf(buf, size, "%s%u:", first ? "" : " ", type);
	size -= strlen(buf);
	buf += strlen(buf);

	snprintf(buf, size, "0x");
	size -= strlen(buf);
	buf += strlen(buf);

	for (i = 0; pnt < lim; pnt++, i++) {
		snprintf(buf, size, "%02x", *pnt);
		size -= strlen(buf);
		buf += strlen(buf);
	}

	return size;
}

static void bgp_linkstate_nlri_mtid_display(char *buf, size_t size,
					    uint8_t *pnt, uint16_t type,
					    uint16_t length, bool first,
					    json_object *json)
{
	json_object *json_array = NULL;

	if (json) {
		json_array = json_object_new_array();
		json_object_object_add(json, "mtID", json_array);
		for (int i = 0; i < (length / 2); i++) {
			json_object_array_add(
				json_array,
				json_object_new_int(pnt_decode16(&pnt)));
		}
		return;
	}

	for (int i = 0; i < (length / 2); i++) {
		if (i == 0)
			snprintf(buf, size, "%sMT:%hu", first ? "" : " ",
				 pnt_decode16(&pnt));
		else
			snprintf(buf, size, ",%hu", pnt_decode16(&pnt));
		size -= strlen(buf);
		buf += strlen(buf);
	}
}

static bool bgp_linkstate_nlri_node_descriptor_display(
	char *buf, size_t size, uint8_t *pnt, uint16_t nlri_type, uint16_t type,
	uint16_t length, bool first, json_object *json)
{
	json_object *json_node = NULL;
	bool sub_first = true;
	uint8_t *lim = pnt + length;
	uint16_t sub_type, sub_length;

	if (json) {
		json_node = json_object_new_object();
		if (type == BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS)
			json_object_object_add(json, "localNode", json_node);
		else
			json_object_object_add(json, "remoteNode", json_node);
	} else {
		if (type == BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS)
			snprintf(buf, size, "%sLocal {", first ? "" : " ");
		else
			snprintf(buf, size, "%sRemote {", first ? "" : " ");
		size -= strlen(buf);
		buf += strlen(buf);
	}

	for (; pnt < lim; pnt += sub_length) {
		sub_type = pnt_decode16(&pnt);
		sub_length = pnt_decode16(&pnt);

		if (pnt + sub_length > lim)
			/* bad length */
			return false;

		bgp_linkstate_nlri_value_display(buf, size, pnt, nlri_type,
						 sub_type, sub_length,
						 sub_first, json_node);

		if (!json) {
			size -= strlen(buf);
			buf += strlen(buf);
			sub_first = false;
		}
	}

	if (!json)
		snprintf(buf, size, "}");

	return true;
}

static bool bgp_linkstate_nlri_value_display(char *buf, size_t size,
					     uint8_t *pnt, uint16_t nlri_type,
					     uint16_t type, uint16_t length,
					     bool first, json_object *json)
{
	struct in_addr ipv4 = {0};
	struct in6_addr ipv6 = {0};
	uint8_t mask_length;

	if (!bgp_ls_tlv_check_size(type, length) && !json) {
		bgp_linkstate_nlri_hexa_display(buf, size, pnt, type, length,
						first, json);
		return true;
	}

	switch (type) {
	case BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS:
	case BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS:
		return bgp_linkstate_nlri_node_descriptor_display(
			buf, size, pnt, nlri_type, type, length, first, json);
	case BGP_LS_TLV_AUTONOMOUS_SYSTEM:
		if (json)
			json_object_int_add(json, "as", pnt_decode32(&pnt));
		else
			snprintf(buf, size, "%sAS:%u", first ? "" : " ",
				 pnt_decode32(&pnt));
		break;
	case BGP_LS_TLV_BGP_LS_IDENTIFIER:
		if (json)
			json_object_int_add(json, "identifier",
					    pnt_decode32(&pnt));
		else
			snprintf(buf, size, "%sID:%u", first ? "" : " ",
				 pnt_decode32(&pnt));
		break;
	case BGP_LS_TLV_OSPF_AREA_ID:
		if (json)
			json_object_int_add(json, "area", pnt_decode32(&pnt));
		else
			snprintf(buf, size, "%sArea:%u", first ? "" : " ",
				 pnt_decode32(&pnt));
		break;
	case BGP_LS_TLV_IGP_ROUTER_ID:
		switch (length) {
		case BGP_LS_TLV_IGP_ROUTER_ID_ISIS_NON_PSEUDOWIRE_SIZE:
			if (json)
				json_object_string_addf(json, "routerID",
							"%pSY", pnt);
			else
				snprintfrr(buf, size, "%sRtr:%pSY",
					   first ? "" : " ", pnt);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID_ISIS_PSEUDOWIRE_SIZE:
			if (json)
				json_object_string_addf(json, "routerID",
							"%pPN", pnt);
			else
				snprintfrr(buf, size, "%sRtr:%pPN",
					   first ? "" : " ", pnt);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID_OSPF_NON_PSEUDOWIRE_SIZE:
			if (json)
				json_object_string_addf(json, "routerID",
							"%pI4",
							(in_addr_t *)pnt);
			else
				snprintfrr(buf, size, "%sRtr:%pI4",
					   first ? "" : " ", (in_addr_t *)pnt);
			break;
		case BGP_LS_TLV_IGP_ROUTER_ID_OSPF_PSEUDOWIRE_SIZE:
			if (json)
				json_object_string_addf(json, "routerID",
							"%pI4:%pI4",
							(in_addr_t *)pnt,
							((in_addr_t *)pnt + 1));
			else
				snprintfrr(buf, size, "%sRtr:%pI4:%pI4",
					   first ? "" : " ", (in_addr_t *)pnt,
					   ((in_addr_t *)pnt + 1));
			break;
		default:
			bgp_linkstate_nlri_hexa_display(buf, size, pnt, type,
							length, first, json);
		}
		break;
	case BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS:
		if (json)
			json_object_int_add(json, "localRemoteID",
					    pnt_decode16(&pnt));
		else
			snprintf(buf, size, "%sLocal/remote:%hu",
				 first ? "" : " ", pnt_decode16(&pnt));
		break;
	case BGP_LS_TLV_IPV4_INTERFACE_ADDRESS:
		if (json)
			json_object_string_addf(json, "interfaceIPv4", "%pI4",
						(in_addr_t *)pnt);
		else
			snprintfrr(buf, size, "%sIPv4:%pI4", first ? "" : " ",
				   (in_addr_t *)pnt);
		break;
	case BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS:
		if (json)
			json_object_string_addf(json, "neighborIPv4", "%pI4",
						(in_addr_t *)pnt);
		else
			snprintfrr(buf, size, "%sNeigh-IPv4:%pI4",
				   first ? "" : " ", (in_addr_t *)pnt);
		break;
	case BGP_LS_TLV_IPV6_INTERFACE_ADDRESS:
		if (json)
			json_object_string_addf(json, "interfaceIPv6", "%pI6",
						(struct in6_addr *)pnt);
		else
			snprintfrr(buf, size, "%sIPv6:%pI6", first ? "" : " ",
				   (struct in6_addr *)pnt);
		break;
	case BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS:
		if (json)
			json_object_string_addf(json, "neighborIPv6", "%pI6",
						(struct in6_addr *)pnt);
		else
			snprintfrr(buf, size, "%sNeigh-IPv6:%pI6",
				   first ? "" : " ", (struct in6_addr *)pnt);
		break;
	case BGP_LS_TLV_MULTI_TOPOLOGY_ID:
		bgp_linkstate_nlri_mtid_display(buf, size, pnt, type, length,
						first, json);
		break;
	case BGP_LS_TLV_OSPF_ROUTE_TYPE:
		if (json)
			json_object_int_add(json, "ospfRouteType",
					    pnt_decode8(&pnt));
		else
			snprintf(buf, size, "%sOSPF-Route-Type:%u",
				 first ? "" : " ", pnt_decode8(&pnt));
		break;
	case BGP_LS_TLV_IP_REACHABILITY_INFORMATION:
		mask_length = pnt_decode8(&pnt);
		if (nlri_type == BGP_LINKSTATE_PREFIX4) {
			memcpy(&ipv4.s_addr, pnt, length - sizeof(mask_length));
			if (json)
				json_object_string_addf(json, "ipReachability",
							"%pI4/%u", &ipv4,
							mask_length);
			else
				snprintfrr(buf, size, "%sIPv4:%pI4/%u",
					   first ? "" : " ", &ipv4,
					   mask_length);
		} else if (nlri_type == BGP_LINKSTATE_PREFIX6) {
			memcpy(&ipv6, pnt, length - sizeof(mask_length));
			if (json)
				json_object_string_addf(json, "ipReachability",
							"%pI6/%u", &ipv6,
							mask_length);
			else
				snprintfrr(buf, size, "%sIPv6:%pI6/%u",
					   first ? "" : " ", &ipv6,
					   mask_length);
		} else
			bgp_linkstate_nlri_hexa_display(buf, size, pnt, type,
							length, first, json);

		break;
	default:
		bgp_linkstate_nlri_hexa_display(buf, size, pnt, type, length,
						first, json);
	}

	return true;
}

char *bgp_linkstate_nlri_prefix_display(char *buf, size_t size,
					uint16_t nlri_type, uintptr_t ptr,
					uint16_t len)
{
	uint8_t *pnt = (uint8_t *)ptr;
	uint8_t *lim = pnt + len;
	uint16_t type, length;
	char *cbuf = buf, *cbuf2;
	uint8_t proto;
	bool ret;
	bool first = true;

	proto = pnt_decode8(&pnt);

	snprintfrr(buf, size, "%s %s ID:0x%" PRIx64 " {",
		   bgp_linkstate_nlri_type_2str(nlri_type),
		   bgp_ls_print_nlri_proto(proto), pnt_decode64(&pnt));
	size -= strlen(buf);
	buf += strlen(buf);

	cbuf2 = buf;

	for (; pnt < lim; pnt += length) {
		type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);

		if (pnt + length > lim) {
			/* bad length */
			snprintf(cbuf2, size, "Bad format}");
			return cbuf;
		}

		ret = bgp_linkstate_nlri_value_display(
			buf, size, pnt, nlri_type, type, length, first, NULL);

		if (!ret) {
			/* bad length */
			snprintf(cbuf2, size, "Bad format}");
			return cbuf;
		}

		size -= strlen(buf);
		buf += strlen(buf);
		first = false;
	}

	snprintf(buf, size, "}");

	return cbuf;
}

void bgp_linkstate_nlri_prefix_json(json_object *json, uint16_t nlri_type,
				    uintptr_t ptr, uint16_t len)
{
	json_object *json_nlri = json_object_new_object();
	uint8_t *pnt = (uint8_t *)ptr;
	uint8_t *lim = pnt + len;
	uint16_t type, length;
	uint8_t proto;
	bool ret;

	proto = pnt_decode8(&pnt);

	json_object_object_add(json, "linkStateNLRI", json_nlri);
	json_object_string_add(json_nlri, "nlriType",
			       bgp_linkstate_nlri_type_2str(nlri_type));
	json_object_string_add(json_nlri, "protocol",
			       bgp_ls_print_nlri_proto(proto));
	json_object_string_addf(json_nlri, "identifier", "0x%" PRIx64,
				pnt_decode64(&pnt));

	for (; pnt < lim; pnt += length) {
		type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);

		if (pnt + length > lim)
			/* bad length */
			return;

		ret = bgp_linkstate_nlri_value_display(NULL, 0, pnt, nlri_type,
						       type, length, false,
						       json_nlri);

		if (!ret)
			/* bad length */
			return;
	}
}
