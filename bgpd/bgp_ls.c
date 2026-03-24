// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Link-State (RFC 9552) - Core Implementation
 * Copyright (C) 2025 Carmine Scarpitta
 */

#include <zebra.h>

#include "lib/json.h"

#include "stream.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_ls.h"
#include "bgpd/bgp_ls_nlri.h"
#include "bgpd/bgp_ls_ted.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_zebra.h"
#define UNKNOWN LS_UNKNOWN
#include "lib/link_state.h"
#undef UNKNOWN

DEFINE_MTYPE_STATIC(BGPD, BGP_LS, "BGP-LS instance");

/*
 * Helper Functions for NLRI Formatting
 */

/* Convert node descriptor to JSON */
static json_object *node_desc_to_json(struct bgp_ls_node_descriptor *node)
{
	json_object *json_node = json_object_new_object();

	if (BGP_LS_TLV_CHECK(node->present_tlvs, BGP_LS_NODE_DESC_AS_BIT))
		json_object_int_add(json_node, "asn", node->asn);

	if (BGP_LS_TLV_CHECK(node->present_tlvs, BGP_LS_NODE_DESC_BGP_LS_ID_BIT))
		json_object_int_add(json_node, "bgplsId", node->bgp_ls_id);

	if (BGP_LS_TLV_CHECK(node->present_tlvs, BGP_LS_NODE_DESC_OSPF_AREA_BIT))
		json_object_string_addf(json_node, "ospfAreaId", "%pI4",
					(in_addr_t *)&node->ospf_area_id);

	if (BGP_LS_TLV_CHECK(node->present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT)) {
		char igp_router_id[256];
		char *p = igp_router_id;

		for (int i = 0; i < node->igp_router_id_len; i++) {
			p += snprintfrr(p, sizeof(igp_router_id) - (p - igp_router_id), "%02x",
					node->igp_router_id[i]);
			if (i < node->igp_router_id_len - 1 && (i + 1) % 2 == 0) {
				p += snprintfrr(p, sizeof(igp_router_id) - (p - igp_router_id),
						".");
			}
		}
		json_object_string_add(json_node, "igpRouterId", igp_router_id);
	}

	if (BGP_LS_TLV_CHECK(node->present_tlvs, BGP_LS_NODE_DESC_BGP_ROUTER_ID_BIT))
		json_object_string_addf(json_node, "bgpRouterId", "%pI4", &node->bgp_router_id);

	return json_node;
}

/* Convert link descriptor to JSON */
static json_object *link_desc_to_json(struct bgp_ls_link_descriptor *link_desc)
{
	json_object *json_link = json_object_new_object();

	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_LINK_ID_BIT)) {
		json_object_int_add(json_link, "linkLocalId", link_desc->link_local_id);
		json_object_int_add(json_link, "linkRemoteId", link_desc->link_remote_id);
	}

	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_INTF_BIT))
		json_object_string_addf(json_link, "ipv4InterfaceAddress", "%pI4",
					&link_desc->ipv4_intf_addr);

	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_NEIGH_BIT))
		json_object_string_addf(json_link, "ipv4NeighborAddress", "%pI4",
					&link_desc->ipv4_neigh_addr);

	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_INTF_BIT))
		json_object_string_addf(json_link, "ipv6InterfaceAddress", "%pI6",
					&link_desc->ipv6_intf_addr);

	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_NEIGH_BIT))
		json_object_string_addf(json_link, "ipv6NeighborAddress", "%pI6",
					&link_desc->ipv6_neigh_addr);

	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_MT_ID_BIT) &&
	    link_desc->mt_id_count > 0)
		json_object_int_add(json_link, "mtId", link_desc->mt_id[0]);

	return json_link;
}

/* Convert prefix descriptor to JSON */
static json_object *prefix_desc_to_json(struct bgp_ls_prefix_descriptor *prefix_desc,
					enum bgp_ls_nlri_type nlri_type)
{
	json_object *json_prefix = json_object_new_object();

	/* IP Reachability Information */
	json_object_string_addf(json_prefix, "ipReachabilityInformation", "%pFX",
				&prefix_desc->prefix);

	/* OSPF Route Type */
	if (BGP_LS_TLV_CHECK(prefix_desc->present_tlvs, BGP_LS_PREFIX_DESC_OSPF_ROUTE_BIT))
		json_object_string_addf(json_prefix, "ospfRouteType", "%s",
					bgp_ls_ospf_route_type_str_json(
						prefix_desc->ospf_route_type));

	/* BGP Route Type */
	if (BGP_LS_TLV_CHECK(prefix_desc->present_tlvs, BGP_LS_PREFIX_DESC_BGP_ROUTE_TYPE_BIT))
		json_object_string_addf(json_prefix, "bgpRouteType", "%s",
					bgp_ls_bgp_route_type_str_json(prefix_desc->bgp_route_type));

	return json_prefix;
}

/* Convert NLRI to JSON */
json_object *bgp_ls_nlri_to_json(struct bgp_ls_nlri *nlri)
{
	json_object *json_nlri = json_object_new_object();
	const char *nlri_type_str = NULL;
	enum bgp_ls_protocol_id protocol_id = 0;
	uint64_t identifier = 0;

	/* NLRI Type */
	switch (nlri->nlri_type) {
	case BGP_LS_NLRI_TYPE_NODE:
		nlri_type_str = "node";
		protocol_id = nlri->nlri_data.node.protocol_id;
		identifier = nlri->nlri_data.node.identifier;
		break;
	case BGP_LS_NLRI_TYPE_LINK:
		nlri_type_str = "link";
		protocol_id = nlri->nlri_data.link.protocol_id;
		identifier = nlri->nlri_data.link.identifier;
		break;
	case BGP_LS_NLRI_TYPE_IPV4_PREFIX:
		nlri_type_str = "ipv4Prefix";
		protocol_id = nlri->nlri_data.prefix.protocol_id;
		identifier = nlri->nlri_data.prefix.identifier;
		break;
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX:
		nlri_type_str = "ipv6Prefix";
		protocol_id = nlri->nlri_data.prefix.protocol_id;
		identifier = nlri->nlri_data.prefix.identifier;
		break;
	case BGP_LS_NLRI_TYPE_RESERVED:
		nlri_type_str = "unknown";
		break;
	}
	json_object_string_add(json_nlri, "nlriType", nlri_type_str);

	/* Protocol ID */
	json_object_int_add(json_nlri, "protocolId", protocol_id);

	/* Identifier */
	json_object_int_add(json_nlri, "identifier", identifier);

	/* Type-specific descriptors */
	if (nlri->nlri_type == BGP_LS_NLRI_TYPE_NODE) {
		json_object *json_local = node_desc_to_json(&nlri->nlri_data.node.local_node);

		json_object_object_add(json_nlri, "localNodeDescriptors", json_local);
	} else if (nlri->nlri_type == BGP_LS_NLRI_TYPE_LINK) {
		json_object *json_local = node_desc_to_json(&nlri->nlri_data.link.local_node);
		json_object *json_remote = node_desc_to_json(&nlri->nlri_data.link.remote_node);
		json_object *json_link = link_desc_to_json(&nlri->nlri_data.link.link_desc);

		json_object_object_add(json_nlri, "localNodeDescriptors", json_local);
		json_object_object_add(json_nlri, "remoteNodeDescriptors", json_remote);
		json_object_object_add(json_nlri, "linkDescriptors", json_link);
	} else if (nlri->nlri_type == BGP_LS_NLRI_TYPE_IPV4_PREFIX ||
		   nlri->nlri_type == BGP_LS_NLRI_TYPE_IPV6_PREFIX) {
		json_object *json_local = node_desc_to_json(&nlri->nlri_data.prefix.local_node);
		json_object *json_prefix = prefix_desc_to_json(&nlri->nlri_data.prefix.prefix_desc,
							       nlri->nlri_type);
		json_object_object_add(json_nlri, "localNodeDescriptors", json_local);
		json_object_object_add(json_nlri, "prefixDescriptors", json_prefix);
	}

	return json_nlri;
}

/* Format node descriptor to string */
static void format_node_desc(char **p, size_t *remain, struct bgp_ls_node_descriptor *node,
			     const char *prefix_str)
{
	int len;

	len = snprintfrr(*p, *remain, "[%s", prefix_str);
	*p += len;
	*remain -= len;

	/* AS Number */
	if (BGP_LS_TLV_CHECK(node->present_tlvs, BGP_LS_NODE_DESC_AS_BIT)) {
		len = snprintfrr(*p, *remain, "[c%u]", node->asn);
		*p += len;
		*remain -= len;
	}

	/* BGP-LS Identifier (deprecated but still used) */
	if (BGP_LS_TLV_CHECK(node->present_tlvs, BGP_LS_NODE_DESC_BGP_LS_ID_BIT)) {
		len = snprintfrr(*p, *remain, "[b%u.%u.%u.%u]", (node->bgp_ls_id >> 24) & 0xFF,
				 (node->bgp_ls_id >> 16) & 0xFF, (node->bgp_ls_id >> 8) & 0xFF,
				 node->bgp_ls_id & 0xFF);
		*p += len;
		*remain -= len;
	}

	/* IGP Router ID */
	if (BGP_LS_TLV_CHECK(node->present_tlvs, BGP_LS_NODE_DESC_IGP_ROUTER_BIT)) {
		len = snprintfrr(*p, *remain, "[s");
		*p += len;
		*remain -= len;
		for (int i = 0; i < node->igp_router_id_len; i++) {
			len = snprintfrr(*p, *remain, "%02x", node->igp_router_id[i]);
			*p += len;
			*remain -= len;
			if (i < node->igp_router_id_len - 1 && (i + 1) % 2 == 0) {
				len = snprintfrr(*p, *remain, ".");
				*p += len;
				*remain -= len;
			}
		}
		len = snprintfrr(*p, *remain, "]");
		*p += len;
		*remain -= len;
	}

	/* BGP Router ID (TLV 516) */
	if (BGP_LS_TLV_CHECK(node->present_tlvs, BGP_LS_NODE_DESC_BGP_ROUTER_ID_BIT)) {
		len = snprintfrr(*p, *remain, "[q%pI4]", &node->bgp_router_id);
		*p += len;
		*remain -= len;
	}

	len = snprintfrr(*p, *remain, "]");
	*p += len;
	*remain -= len;
}

/* Format link descriptor to string */
static void format_link_desc(char **p, size_t *remain, struct bgp_ls_link_descriptor *link_desc)
{
	int len;

	len = snprintfrr(*p, *remain, "[L");
	*p += len;
	*remain -= len;

	/* Link Local/Remote Identifiers (TLV 258) */
	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_LINK_ID_BIT)) {
		len = snprintfrr(*p, *remain, "[l%u/%u]", link_desc->link_local_id,
				 link_desc->link_remote_id);
		*p += len;
		*remain -= len;
	}

	/* IPv4 Interface Address (TLV 259) */
	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_INTF_BIT)) {
		len = snprintfrr(*p, *remain, "[i%pI4]", &link_desc->ipv4_intf_addr);
		*p += len;
		*remain -= len;
	}

	/* IPv4 Neighbor Address (TLV 260) */
	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_NEIGH_BIT)) {
		len = snprintfrr(*p, *remain, "[n%pI4]", &link_desc->ipv4_neigh_addr);
		*p += len;
		*remain -= len;
	}

	/* IPv6 Interface Address (TLV 261) */
	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_INTF_BIT)) {
		len = snprintfrr(*p, *remain, "[i%pI6]", &link_desc->ipv6_intf_addr);
		*p += len;
		*remain -= len;
	}

	/* IPv6 Neighbor Address (TLV 262) */
	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_NEIGH_BIT)) {
		len = snprintfrr(*p, *remain, "[n%pI6]", &link_desc->ipv6_neigh_addr);
		*p += len;
		*remain -= len;
	}

	len = snprintfrr(*p, *remain, "]");
	*p += len;
	*remain -= len;
}

void bgp_ls_nlri_format(struct bgp_ls_nlri *nlri, char *buf, size_t buf_len)
{
	char tmp[512];
	char *p = buf;
	size_t remain = buf_len;
	int len;

	if (!nlri || !buf || buf_len == 0)
		return;

	/* NLRI Type prefix */
	switch (nlri->nlri_type) {
	case BGP_LS_NLRI_TYPE_RESERVED:
		len = snprintfrr(p, remain, "[R]");
		break;
	case BGP_LS_NLRI_TYPE_NODE:
		len = snprintfrr(p, remain, "[V]");
		break;
	case BGP_LS_NLRI_TYPE_LINK:
		len = snprintfrr(p, remain, "[E]");
		break;
	case BGP_LS_NLRI_TYPE_IPV4_PREFIX:
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX:
		len = snprintfrr(p, remain, "[T]");
		break;
	default:
		len = snprintfrr(p, remain, "[U]");
		break;
	}
	p += len;
	remain -= len;

	/* Protocol ID and Instance ID - directly from NLRI structures */
	const char *proto_str = NULL;
	uint64_t instance_id = 0;
	enum bgp_ls_protocol_id protocol_id = 0;

	if (nlri->nlri_type == BGP_LS_NLRI_TYPE_NODE) {
		protocol_id = nlri->nlri_data.node.protocol_id;
		instance_id = nlri->nlri_data.node.identifier;
	} else if (nlri->nlri_type == BGP_LS_NLRI_TYPE_LINK) {
		protocol_id = nlri->nlri_data.link.protocol_id;
		instance_id = nlri->nlri_data.link.identifier;
	} else if (nlri->nlri_type == BGP_LS_NLRI_TYPE_IPV4_PREFIX ||
		   nlri->nlri_type == BGP_LS_NLRI_TYPE_IPV6_PREFIX) {
		protocol_id = nlri->nlri_data.prefix.protocol_id;
		instance_id = nlri->nlri_data.prefix.identifier;
	}

	switch (protocol_id) {
	case BGP_LS_PROTO_ISIS_L1:
		proto_str = "L1";
		break;
	case BGP_LS_PROTO_ISIS_L2:
		proto_str = "L2";
		break;
	case BGP_LS_PROTO_OSPFV2:
		proto_str = "O";
		break;
	case BGP_LS_PROTO_OSPFV3:
		proto_str = "O3";
		break;
	case BGP_LS_PROTO_DIRECT:
		proto_str = "D";
		break;
	case BGP_LS_PROTO_STATIC:
		proto_str = "S";
		break;
	case BGP_LS_PROTO_BGP:
		proto_str = "B";
		break;
	case BGP_LS_PROTO_RESERVED:
		proto_str = "U";
		break;
	}
	len = snprintfrr(p, remain, "[%s][I0x%llx]", proto_str, (unsigned long long)instance_id);
	p += len;
	remain -= len;

	/* Add NLRI type-specific descriptors */
	if (nlri->nlri_type == BGP_LS_NLRI_TYPE_NODE) {
		format_node_desc(&p, &remain, &nlri->nlri_data.node.local_node, "N");
	} else if (nlri->nlri_type == BGP_LS_NLRI_TYPE_LINK) {
		format_node_desc(&p, &remain, &nlri->nlri_data.link.local_node, "N");
		format_node_desc(&p, &remain, &nlri->nlri_data.link.remote_node, "R");
		format_link_desc(&p, &remain, &nlri->nlri_data.link.link_desc);
	} else if (nlri->nlri_type == BGP_LS_NLRI_TYPE_IPV4_PREFIX ||
		   nlri->nlri_type == BGP_LS_NLRI_TYPE_IPV6_PREFIX) {
		format_node_desc(&p, &remain, &nlri->nlri_data.prefix.local_node, "N");

		/* Format prefix */
		len = snprintfrr(p, remain, "[P[p");
		p += len;
		remain -= len;

		if (nlri->nlri_type == BGP_LS_NLRI_TYPE_IPV4_PREFIX) {
			inet_ntop(AF_INET, &nlri->nlri_data.prefix.prefix_desc.prefix.u.prefix4,
				  tmp, sizeof(tmp));
		} else {
			inet_ntop(AF_INET6, &nlri->nlri_data.prefix.prefix_desc.prefix.u.prefix6,
				  tmp, sizeof(tmp));
		}
		len = snprintfrr(p, remain, "%s/%u", tmp,
				 nlri->nlri_data.prefix.prefix_desc.prefix.prefixlen);
		p += len;
		remain -= len;

		len = snprintfrr(p, remain, "]]");
		p += len;
		remain -= len;

		/* Format BGP Route Type if present */
		if (BGP_LS_TLV_CHECK(nlri->nlri_data.prefix.prefix_desc.present_tlvs,
				     BGP_LS_PREFIX_DESC_BGP_ROUTE_TYPE_BIT)) {
			len = snprintfrr(p, remain, "[br0x%02x]",
					 nlri->nlri_data.prefix.prefix_desc.bgp_route_type);
			p += len;
			remain -= len;
		}
	}
}

/*
 * Helper function to lookup BGP-LS NLRI by string representation
 */
struct bgp_dest *bgp_ls_lookup_nlri_by_str(struct bgp *bgp, const char *nlri_str)
{
	struct bgp_table *table;
	struct bgp_dest *dest;
	char formatted_nlri[1024];
	struct bgp_ls_nlri *entry;

	if (!bgp || !bgp->ls_info)
		return NULL;

	table = bgp->rib[AFI_BGP_LS][SAFI_BGP_LS];
	if (!table)
		return NULL;

	/* Iterate through the table and match formatted NLRI string */
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		entry = dest->ls_nlri;
		if (!entry)
			continue;
		bgp_ls_nlri_format(entry, formatted_nlri, sizeof(formatted_nlri));
		if (strcmp(formatted_nlri, nlri_str) == 0)
			return dest;
	}

	return NULL;
}

/*
 * ===========================================================================
 * BGP-LS NLRI Parsing
 * ===========================================================================
 */

/*
 * Parse BGP-LS NLRI from UPDATE/WITHDRAW messages
 *
 * Called from bgp_nlri_parse() for SAFI_BGP_LS packets.
 * Decodes NLRIs from MP_REACH_NLRI or MP_UNREACH_NLRI and processes them.
 *
 * @param peer   - BGP peer sending the NLRI
 * @param attr   - BGP path attributes (NULL for withdrawals)
 * @param packet - NLRI packet containing AFI/SAFI and NLRI data
 * @return BGP_NLRI_PARSE_OK on success, error code otherwise
 */
int bgp_nlri_parse_ls(struct peer *peer, struct attr *attr, struct bgp_nlri *packet)
{
	struct stream *s;
	struct bgp_ls_nlri nlri;
	struct prefix p;
	struct bgp_ls_nlri *ls_entry;
	struct bgp_dest *dest;
	int ret = BGP_NLRI_PARSE_OK;

	s = stream_new(packet->length);
	stream_put(s, packet->nlri, packet->length);
	stream_set_getp(s, 0);

	while (STREAM_READABLE(s) > 0) {
		memset(&nlri, 0, sizeof(nlri));
		ret = bgp_ls_decode_nlri(s, &nlri);

		if (ret < 0) {
			flog_warn(EC_BGP_LS_PACKET, "%s [Error] Failed to decode BGP-LS NLRI",
				  peer->host);
			ret = BGP_NLRI_PARSE_ERROR;
			goto done;
		}

		ls_entry = bgp_ls_nlri_get(&peer->bgp->ls_info->nlri_hash, peer->bgp, &nlri);

		memset(&p, 0, sizeof(p));
		p.family = AF_UNSPEC;
		p.prefixlen = 32;
		p.u.val32[0] = ls_entry->id;

		if (attr) {
			dest = bgp_afi_node_get(bgp_get_default()->rib[AFI_BGP_LS][SAFI_BGP_LS],
						AFI_BGP_LS, SAFI_BGP_LS, &p, NULL);
			dest->ls_nlri = ls_entry;

			bgp_update(peer, &p, 0, attr, packet->afi, packet->safi, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, NULL, NULL, 0, 0, NULL);

			bgp_dest_unlock_node(dest);
		} else
			bgp_withdraw(peer, &p, 0, packet->afi, packet->safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0);

		if (BGP_DEBUG(linkstate, LINKSTATE))
			zlog_debug("%s processed BGP-LS %s NLRI type=%u", peer->host,
				   attr ? "UPDATE" : "WITHDRAW", nlri.nlri_type);
	}

done:
	stream_free(s);
	return ret;
}

/*
 * ===========================================================================
 * RIB Operations
 * ===========================================================================
 */

/*
 * Install or update BGP-LS route in RIB (RFC 9552 Section 6)
 *
 * This function handles locally originated BGP-LS routes from IGP.
 * It creates a synthetic prefix in the standard BGP RIB using AF_UNSPEC
 * and stores the full NLRI in bgp_path_info_extra->ls_nlri.
 *
 * The function uses a dual-storage approach:
 * 1. BGP-LS hash table - for fast NLRI lookups and ID allocation
 * 2. Standard BGP RIB - for integration with existing BGP processing
 *
 * @param bgp - BGP instance
 * @param nlri - BGP-LS NLRI to install
 * @return 0 on success, -1 on error
 */
int bgp_ls_update(struct bgp *bgp, struct bgp_ls_nlri *nlri, struct bgp_ls_attr *ls_attr)
{
	struct bgp_path_info *bpi;
	struct bgp_path_info *new;
	struct attr attr;
	struct attr *attr_new;
	struct bgp_dest *dest;
	struct bgp_ls_nlri *ls_nlri;
	struct prefix p;

	if (!bgp || !nlri) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Invalid parameters to %s", __func__);
		return -1;
	}

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS) || bgp->peer_self == NULL)
		return 0;

	if (!bgp->ls_info) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: ls_info not initialized");
		return -1;
	}

	/* Lookup or insert NLRI in hash table */
	ls_nlri = bgp_ls_nlri_intern(nlri);

	/* Make BGP-LS NLRI prefix */
	memset(&p, 0, sizeof(p));
	p.family = AF_UNSPEC;
	p.prefixlen = 32;
	p.u.val32[0] = ls_nlri->id;

	dest = bgp_afi_node_get(bgp->rib[AFI_BGP_LS][SAFI_BGP_LS], AFI_BGP_LS, SAFI_BGP_LS, &p,
				NULL);

	/*
	 * Unintern any existing NLRI reference before installing the new one
	 * to avoid leaking the previous interned pointer.
	 */
	if (dest->ls_nlri)
		bgp_ls_nlri_unintern(&dest->ls_nlri);

	dest->ls_nlri = ls_nlri;

	/* Make default attribute. */
	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_INCOMPLETE);

	attr.ls_attr = ls_attr;

	attr_new = bgp_attr_intern(&attr);

	for (bpi = bgp_dest_get_bgp_path_info(dest); bpi; bpi = bpi->next)
		if (bpi->peer == bgp->peer_self)
			break;

	if (bpi) {
		if (!CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED) && attrhash_cmp(bpi->attr, attr_new)) {
			/* The attribute is not changed. */
			bgp_attr_unintern(&attr_new);
			aspath_unintern(&attr.aspath);
			bgp_dest_unlock_node(dest);
		} else {
			/* The attribute is changed. */
			bgp_path_info_set_flag(dest, bpi, BGP_PATH_ATTR_CHANGED);

			UNSET_FLAG(bpi->flags, BGP_PATH_REMOVED);
			/* unset of previous already took care of pcount */
			SET_FLAG(bpi->flags, BGP_PATH_VALID);

			bgp_attr_unintern(&bpi->attr);
			bpi->attr = attr_new;
			bpi->uptime = monotime(NULL);

			/* Process change. */
			bgp_process(bgp, dest, bpi, AFI_BGP_LS, SAFI_BGP_LS);
			bgp_dest_unlock_node(dest);
			aspath_unintern(&attr.aspath);
		}

		return 0;
	}

	/* Make new BGP info. */
	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_REDISTRIBUTE, 0, bgp->peer_self, attr_new, dest);
	SET_FLAG(new->flags, BGP_PATH_VALID);

	/* Register new BGP information. */
	bgp_path_info_add(dest, new);

	/* Process change */
	bgp_process(bgp, dest, new, AFI_BGP_LS, SAFI_BGP_LS);

	/* Unlock node from bgp_afi_node_get */
	bgp_dest_unlock_node(dest);

	/* Unintern original */
	aspath_unintern(&attr.aspath);

	return 0;
}


/*
 * Remove BGP-LS route from RIB (RFC 9552 Section 6)
 *
 * This function handles withdrawal of locally originated BGP-LS routes.
 * It marks the route as removed and triggers BGP processing for
 * withdrawal advertisement to peers.
 *
 * @param bgp - BGP instance
 * @param nlri - BGP-LS NLRI to withdraw
 * @return 0 on success, -1 on error
 */
int bgp_ls_withdraw(struct bgp *bgp, struct bgp_ls_nlri *nlri)
{
	struct bgp_path_info *bpi;
	struct bgp_dest *dest;
	struct prefix p;
	struct bgp_ls_nlri *ls_nlri;

	if (!bgp || !nlri) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Invalid parameters to %s", __func__);
		return -1;
	}

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS) || bgp->peer_self == NULL)
		return 0;

	if (!bgp->ls_info) {
		if (BGP_DEBUG(linkstate, LINKSTATE))
			zlog_debug("%s: No BGP-LS info exists for withdraw", __func__);

		return 0;
	}

	/* Lookup NLRI in hash table */
	ls_nlri = bgp_ls_nlri_lookup(&bgp->ls_info->nlri_hash, nlri);
	if (!ls_nlri) {
		if (BGP_DEBUG(linkstate, LINKSTATE)) {
			zlog_debug("%s: BGP-LS WITHDRAW for non-existent NLRI type=%u", __func__,
				   nlri->nlri_type);
		}
		return 0; /* Not an error - may have been withdrawn already */
	}

	/* Make synthetic prefix using hash table ID */
	memset(&p, 0, sizeof(p));
	p.family = AF_UNSPEC;
	p.prefixlen = 32;
	p.u.val32[0] = ls_nlri->id;

	dest = bgp_node_lookup(bgp->rib[AFI_BGP_LS][SAFI_BGP_LS], &p);
	if (!dest) {
		if (BGP_DEBUG(linkstate, LINKSTATE))
			zlog_debug("%s: No RIB entry found for NLRI type=%u", __func__,
				   nlri->nlri_type);
		return 0;
	}

	/* Find path from local peer */
	for (bpi = bgp_dest_get_bgp_path_info(dest); bpi; bpi = bpi->next)
		if (bpi->peer == bgp->peer_self)
			break;

	if (bpi) {
		if (BGP_DEBUG(linkstate, LINKSTATE)) {
			zlog_debug("%s: Withdrawing BGP-LS route type=%u", __func__,
				   nlri->nlri_type);
		}

		/* Mark for deletion */
		SET_FLAG(bpi->flags, BGP_PATH_REMOVED);
		UNSET_FLAG(bpi->flags, BGP_PATH_VALID);

		/* Process change - triggers withdrawal to peers */
		bgp_process(bgp, dest, bpi, AFI_BGP_LS, SAFI_BGP_LS);
	} else {
		if (BGP_DEBUG(linkstate, LINKSTATE))
			zlog_debug("%s: No path found for NLRI type=%u", __func__, nlri->nlri_type);
	}

	/* Unlock node from bgp_node_lookup */
	bgp_dest_unlock_node(dest);

	return 0;
}

/*
 * ===========================================================================
 * BGP-LS Link State Database Registration
 * ===========================================================================
 */

/*
 * Register BGP with zebra link-state database to receive updates from IGPs
 *
 * @return true on success, false on failure
 */
bool bgp_ls_register(struct bgp *bgp)
{
	if (!bgp->ls_info)
		return false;

	/* Already registered */
	if (bgp_ls_is_registered(bgp))
		return true;

	if (ls_register(bgp_zclient, false) != 0) {
		zlog_err("BGP-LS: Failed to register with Link State database");
		return false;
	}

	bgp->ls_info->registered_ls_db = true;

	zlog_info("BGP-LS: Registered with Link State database for BGP instance %s",
		  bgp->name_pretty);
	return true;
}

/*
 * Unregister BGP from zebra link-state database
 *
 * @return true on success, false on failure
 */
bool bgp_ls_unregister(struct bgp *bgp)
{
	if (!bgp->ls_info)
		return false;

	/* Not registered */
	if (!bgp_ls_is_registered(bgp))
		return true;

	/*
	 * Clear the local registration flag *before* the zebra call.
	 *
	 * If ls_unregister() fails, BGP has lost sync with zebra.  Leaving
	 * registered_ls_db set to true in that case would make
	 * bgp_ls_is_registered() report "still registered", preventing any
	 * subsequent bgp_ls_register() call from attempting re-registration
	 * and leaving BGP permanently unable to receive link-state updates.
	 *
	 * By clearing the flag eagerly, bgp_ls_register() will see
	 * registered_ls_db=false and attempt re-registration, giving the
	 * system a chance to recover.
	 */
	bgp->ls_info->registered_ls_db = false;

	if (ls_unregister(bgp_zclient, false) != 0) {
		zlog_err("BGP-LS: Failed to unregister from Link State database");
		return false;
	}

	zlog_info("BGP-LS: Unregistered from Link State database for BGP instance %s",
		  bgp->name_pretty);
	return true;
}

/*
 * Check if BGP is registered with zebra link-state database
 * Returns true if registered, false otherwise
 */
bool bgp_ls_is_registered(struct bgp *bgp)
{
	if (!bgp || !bgp->ls_info)
		return false;

	return bgp->ls_info->registered_ls_db;
}

/*
 * ===========================================================================
 * Module Initialization and Cleanup
 * ===========================================================================
 */

/*
 * Initialize BGP-LS module for a BGP instance
 * Called from bgp_create() for the default BGP instance only
 */
void bgp_ls_init(struct bgp *bgp)
{
	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return;

	bgp->ls_info = XCALLOC(MTYPE_BGP_LS, sizeof(struct bgp_ls));
	bgp->ls_info->bgp = bgp;
	bgp->ls_info->allocator = idalloc_new("BGP-LS NLRI ID Allocator");
	bgp_ls_nlri_hash_init(&bgp->ls_info->nlri_hash);
	bgp_ls_attr_hash_init(&bgp->ls_info->ls_attr_hash);

	bgp->ls_info->ted = ls_ted_new(bgp->as, "BGP-LS TED", bgp->as);

	zlog_info("BGP-LS: Module initialized for instance %s", bgp->name_pretty);
}

/*
 * Cleanup BGP-LS module for a BGP instance
 * Called from bgp_free() for the default BGP instance only
 */
void bgp_ls_cleanup(struct bgp *bgp)
{
	struct bgp_ls_nlri *entry;
	struct bgp_ls_attr *ls_attr;

	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return;

	if (!bgp->ls_info)
		return;

	bgp_ls_unregister(bgp);

	frr_each_safe (bgp_ls_nlri_hash, &bgp->ls_info->nlri_hash, entry) {
		bgp_ls_nlri_hash_del(&bgp->ls_info->nlri_hash, entry);
		bgp_ls_nlri_free(entry);
	}
	bgp_ls_nlri_hash_fini(&bgp->ls_info->nlri_hash);

	frr_each_safe (bgp_ls_attr_hash, &bgp->ls_info->ls_attr_hash, ls_attr) {
		bgp_ls_attr_hash_del(&bgp->ls_info->ls_attr_hash, ls_attr);
		bgp_ls_attr_free(ls_attr);
	}
	bgp_ls_attr_hash_fini(&bgp->ls_info->ls_attr_hash);

	ls_ted_del_all(&bgp->ls_info->ted);

	idalloc_destroy(bgp->ls_info->allocator);

	XFREE(MTYPE_BGP_LS, bgp->ls_info);

	zlog_info("BGP-LS: Module terminated for instance %s", bgp->name_pretty);
}

/*
 * ===========================================================================
 * BGP Topology Export (BGP-only fabrics)
 * ===========================================================================
 */

/*
 * Originate Node NLRI for local BGP router
 *
 * Reference: draft-ietf-idr-bgp-ls-bgp-only-fabric Section 3
 *
 * Generates a Node NLRI for the local BGP router with:
 * - Protocol-ID = BGP_LS_PROTO_BGP (7)
 * - Autonomous System Number (TLV 512) - local BGP ASN
 * - BGP Router-ID (TLV 516) - local BGP Identifier
 *
 * This function should be called once per BGP instance when
 * 'distribute link-state' is configured.
 */
int bgp_ls_originate_bgp_node(struct bgp *bgp)
{
	struct bgp_ls_nlri nlri;
	struct attr *attr = NULL;
	struct peer *peer;
	int ret;

	if (!bgp || !bgp->ls_info || !bgp->ls_info->enable_distribution)
		return 0;

	if (!bgp) {
		zlog_err("BGP-LS: Cannot originate BGP node without BGP instance");
		return -1;
	}

	/* Get local peer for route origination */
	peer = bgp->peer_self;
	if (!peer) {
		zlog_err("BGP-LS: No local peer for BGP node origination");
		return -1;
	}

	zlog_info("bgp_ls_originate_node bgp->peer_self->host %s su %pSU su_local %pSU su_remote %pSU",
		  bgp->peer_self->host, &bgp->peer_self->connection->su,
		  bgp->peer_self->connection->su_local, bgp->peer_self->connection->su_remote);
	zlog_info("bgp_ls_originate_node peer->host %s su %pSU su_local %pSU su_remote %pSU",
		  peer->host, &peer->connection->su, peer->connection->su_local,
		  peer->connection->su_remote);

	/* Initialize NLRI structure */
	memset(&nlri, 0, sizeof(nlri));

	/* Set NLRI type and protocol */
	nlri.nlri_type = BGP_LS_NLRI_TYPE_NODE;
	nlri.nlri_data.node.protocol_id = BGP_LS_PROTO_BGP; /* Protocol-ID = 7 for BGP */
	nlri.nlri_data.node.identifier = 0;		    /* Instance ID, use 0 for default */

	/* TLV 512: Autonomous System Number (local ASN) */
	nlri.nlri_data.node.local_node.asn = bgp->as;
	BGP_LS_TLV_SET(nlri.nlri_data.node.local_node.present_tlvs, BGP_LS_NODE_DESC_AS_BIT);

	/* TLV 516: BGP Router-ID (local BGP Identifier) */
	nlri.nlri_data.node.local_node.bgp_router_id = bgp->router_id;
	BGP_LS_TLV_SET(nlri.nlri_data.node.local_node.present_tlvs,
		       BGP_LS_NODE_DESC_BGP_ROUTER_ID_BIT);

	// /* No Node attributes for BGP-only fabrics in initial implementation */
	// nlri.nlri_data.node.attr = NULL;

	/* Insert into BGP-LS RIB */
	ret = bgp_ls_update(peer->bgp, &nlri, NULL);
	if (ret != 0) {
		zlog_err("BGP-LS: Failed to insert BGP node NLRI into RIB");
		bgp_attr_unintern(&attr);
		return -1;
	}

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Originated BGP Node NLRI for AS %u, Router-ID %pI4", bgp->as,
			   &bgp->router_id);

	return 0;
}

/*
 * Originate BGP Link NLRI for a BGP session
 *
 * This generates a Link NLRI representing a BGP session from the local
 * router to a peer. Per draft-ietf-idr-bgp-ls-bgp-only-fabric:
 * - Local Node Descriptor: Local BGP router (ASN + BGP Router-ID)
 * - Remote Node Descriptor: Peer BGP router (ASN + BGP Router-ID)
 * - Link Descriptor: IPv4/IPv6 interface and neighbor addresses
 * - Protocol-ID: BGP (7)
 *
 * @param bgp  - BGP instance
 * @param peer - BGP peer (remote endpoint of the session)
 * @return 0 on success, -1 on error
 */
int bgp_ls_originate_bgp_link(struct bgp *bgp, struct peer *peer)
{
	struct bgp_ls_nlri nlri;
	struct attr *attr;
	struct peer *local_peer;
	int ret;

	if (!bgp || !bgp->ls_info || !bgp->ls_info->enable_distribution)
		return 0;

	if (!bgp || !peer) {
		zlog_err("BGP-LS: Cannot originate BGP link without BGP instance or peer");
		return -1;
	}

	/* Get local peer for route origination */
	local_peer = bgp->peer_self;
	if (!local_peer) {
		zlog_err("BGP-LS: No local peer for BGP link origination");
		return -1;
	}

	/* Initialize NLRI structure */
	memset(&nlri, 0, sizeof(nlri));

	/* Set NLRI type and protocol */
	nlri.nlri_type = BGP_LS_NLRI_TYPE_LINK;
	nlri.nlri_data.link.protocol_id = BGP_LS_PROTO_BGP; /* Protocol-ID = 7 for BGP */
	nlri.nlri_data.link.identifier = 0;		    /* Instance ID, use 0 for default */

	/* Local Node Descriptor (this router) */
	nlri.nlri_data.link.local_node.asn = bgp->as;
	BGP_LS_TLV_SET(nlri.nlri_data.link.local_node.present_tlvs, BGP_LS_NODE_DESC_AS_BIT);

	nlri.nlri_data.link.local_node.bgp_router_id = bgp->router_id;
	BGP_LS_TLV_SET(nlri.nlri_data.link.local_node.present_tlvs,
		       BGP_LS_NODE_DESC_BGP_ROUTER_ID_BIT);

	/* Remote Node Descriptor (peer router) */
	nlri.nlri_data.link.remote_node.asn = peer->as;
	BGP_LS_TLV_SET(nlri.nlri_data.link.remote_node.present_tlvs, BGP_LS_NODE_DESC_AS_BIT);

	nlri.nlri_data.link.remote_node.bgp_router_id = peer->remote_id;
	BGP_LS_TLV_SET(nlri.nlri_data.link.remote_node.present_tlvs,
		       BGP_LS_NODE_DESC_BGP_ROUTER_ID_BIT);

	/* Link Descriptor: Link identifiers */
	if (peer->ifp) {
		/* Set link_local_id to interface index */
		nlri.nlri_data.link.link_desc.link_local_id = peer->ifp->ifindex;
		nlri.nlri_data.link.link_desc.link_remote_id = 0; /* Not known */
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_LINK_ID_BIT);
	}

	/* Link Descriptor: Interface addresses */
	if (peer->connection->su.sa.sa_family == AF_INET) {
		/* IPv4 BGP session */
		nlri.nlri_data.link.link_desc.ipv4_intf_addr =
			peer->connection->su_local->sin.sin_addr;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_IPV4_INTF_BIT);

		nlri.nlri_data.link.link_desc.ipv4_neigh_addr = peer->connection->su.sin.sin_addr;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_IPV4_NEIGH_BIT);
	} else if (peer->connection->su.sa.sa_family == AF_INET6) {
		/* IPv6 BGP session */
		nlri.nlri_data.link.link_desc.ipv6_intf_addr =
			peer->connection->su_local->sin6.sin6_addr;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_IPV6_INTF_BIT);

		nlri.nlri_data.link.link_desc.ipv6_neigh_addr = peer->connection->su.sin6.sin6_addr;
		BGP_LS_TLV_SET(nlri.nlri_data.link.link_desc.present_tlvs,
			       BGP_LS_LINK_DESC_IPV6_NEIGH_BIT);
	}

	// /* No Link attributes for BGP-only fabrics in initial implementation */
	// nlri.nlri_data.link.attr = NULL;

	/* Insert into BGP-LS RIB */
	ret = bgp_ls_update(local_peer->bgp, &nlri, NULL);
	if (ret != 0) {
		zlog_err("BGP-LS: Failed to insert BGP link NLRI into RIB");
		bgp_attr_unintern(&attr);
		return -1;
	}

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Originated BGP Link NLRI: Local AS %u Router-ID %pI4 -> Peer AS %u Router-ID %pI4",
			   bgp->as, &bgp->router_id, peer->as, &peer->remote_id);

	return 0;
}

/*
 * Originate BGP Prefix NLRI
 *
 * Reference: draft-ietf-idr-bgp-ls-bgp-only-fabric
 *
 * Generates a BGP-LS Prefix NLRI for a locally advertised BGP route.
 * Only generates NLRIs for routes originated by this router (from bgp->peer_self).
 *
 * @param bgp - BGP instance
 * @param afi - Address family (AFI_IP or AFI_IP6)
 * @param safi - Subsequent address family (SAFI_UNICAST, etc.)
 * @param dest - BGP destination (route)
 * @param path - BGP path info (must be from peer_self)
 * @return 0 on success, -1 on failure
 */
int bgp_ls_originate_bgp_prefix(struct bgp *bgp, afi_t afi, safi_t safi, struct bgp_dest *dest,
				struct bgp_path_info *path)
{
	struct bgp_ls_nlri nlri;
	struct attr *attr = NULL;
	struct peer *peer;
	const struct prefix *p;
	int ret;

	if (!bgp || !bgp->ls_info || !bgp->ls_info->enable_distribution)
		return 0;

	if (!bgp || !dest || !path) {
		zlog_err("BGP-LS: Invalid parameters for BGP prefix origination");
		return -1;
	}

	if (safi != SAFI_UNICAST) {
		zlog_info("%s supports only SAFI_UNICAST", __func__);
		return 0;
	}

	// /* Only advertise locally originated routes */
	// if (path->peer != bgp->peer_self) {
	//	/* This is not our route, skip it */
	//	return 0;
	// }

	/* Get local peer for route origination */
	peer = bgp->peer_self;
	if (!peer) {
		zlog_err("BGP-LS: Cannot originate prefix NLRI without local peer");
		return -1;
	}

	/* Get the prefix */
	p = bgp_dest_get_prefix(dest);
	if (!p) {
		zlog_err("BGP-LS: Cannot get prefix from destination");
		return -1;
	}

	/* Initialize NLRI structure */
	memset(&nlri, 0, sizeof(nlri));

	/* Set NLRI type based on address family */
	if (afi == AFI_IP)
		nlri.nlri_type = BGP_LS_NLRI_TYPE_IPV4_PREFIX;
	else if (afi == AFI_IP6)
		nlri.nlri_type = BGP_LS_NLRI_TYPE_IPV6_PREFIX;
	else {
		zlog_err("BGP-LS: Unsupported AFI %d for BGP prefix", afi);
		return -1;
	}

	nlri.nlri_data.prefix.protocol_id = BGP_LS_PROTO_BGP; /* Protocol-ID = 7 for BGP */
	nlri.nlri_data.prefix.identifier = 0;		      /* Instance ID, use 0 for default */

	/* Local Node Descriptor (this router) */
	/* TLV 512: Autonomous System Number */
	nlri.nlri_data.prefix.local_node.asn = bgp->as;
	BGP_LS_TLV_SET(nlri.nlri_data.prefix.local_node.present_tlvs, BGP_LS_NODE_DESC_AS_BIT);

	/* TLV 516: BGP Router-ID */
	nlri.nlri_data.prefix.local_node.bgp_router_id = bgp->router_id;
	BGP_LS_TLV_SET(nlri.nlri_data.prefix.local_node.present_tlvs,
		       BGP_LS_NODE_DESC_BGP_ROUTER_ID_BIT);

	/* Prefix Descriptor */
	/* TLV 267: BGP Route Type (new TLV from draft) */
	/* Determine route type based on path attributes */
	// if (path->peer == bgp->peer_self) {
	zlog_info("BGP-LS: Determining BGP route type for prefix %pFX", p);
	zlog_info("BGP-LS: Path type = %d, peer type = %d", path->type, path->peer->sort);
	if (path->type == ZEBRA_ROUTE_LOCAL ||
	    (p->family == AF_INET6 && if_address_is_local(&p->u.prefix6, AF_INET6, VRF_DEFAULT)) ||
	    (p->family == AF_INET && if_address_is_local(&p->u.prefix4, AF_INET, VRF_DEFAULT)))
		nlri.nlri_data.prefix.prefix_desc.bgp_route_type = BGP_LS_BGP_RT_LOCAL;
	else if (path->type == ZEBRA_ROUTE_CONNECT)
		nlri.nlri_data.prefix.prefix_desc.bgp_route_type = BGP_LS_BGP_RT_ATTACHED;
	else if (path->type == ZEBRA_ROUTE_BGP && path->peer->sort == BGP_PEER_EBGP)
		nlri.nlri_data.prefix.prefix_desc.bgp_route_type = BGP_LS_BGP_RT_EXTERNAL_BGP;
	else if (path->type == ZEBRA_ROUTE_BGP && path->peer->sort == BGP_PEER_IBGP)
		nlri.nlri_data.prefix.prefix_desc.bgp_route_type = BGP_LS_BGP_RT_INTERNAL_BGP;
	else // if (path->type >= ZEBRA_ROUTE_STATIC && path->type <= ZEBRA_ROUTE_TABLE_DIRECT)
		nlri.nlri_data.prefix.prefix_desc.bgp_route_type = BGP_LS_BGP_RT_REDISTRIBUTED;
	/* Locally originated route */
	// if (path->sub_type == BGP_ROUTE_STATIC)
	//	nlri.nlri_data.prefix.prefix_desc.bgp_route_type =
	//		BGP_LS_BGP_ROUTE_TYPE_STATIC;
	// else if (path->sub_type == BGP_ROUTE_AGGREGATE)
	//	nlri.nlri_data.prefix.prefix_desc.bgp_route_type =
	//		BGP_LS_BGP_ROUTE_TYPE_AGGREGATE;
	// else if (path->sub_type == BGP_ROUTE_REDISTRIBUTE)
	//	nlri.nlri_data.prefix.prefix_desc.bgp_route_type =
	//		BGP_LS_BGP_ROUTE_TYPE_REDISTRIBUTED;
	// else
	//	nlri.nlri_data.prefix.prefix_desc.bgp_route_type =
	//		BGP_LS_BGP_ROUTE_TYPE_LOCAL;
	// } else {
	//	/* Should not happen since we checked peer == peer_self above */
	//	nlri.nlri_data.prefix.prefix_desc.bgp_route_type =
	//		BGP_LS_BGP_ROUTE_TYPE_EXTERNAL_BGP;
	// }
	BGP_LS_TLV_SET(nlri.nlri_data.prefix.prefix_desc.present_tlvs,
		       BGP_LS_PREFIX_DESC_BGP_ROUTE_TYPE_BIT);

	/* TLV 265: IP Reachability Information */
	nlri.nlri_data.prefix.prefix_desc.prefix = *p;
	BGP_LS_TLV_SET(nlri.nlri_data.prefix.prefix_desc.present_tlvs,
		       BGP_LS_PREFIX_DESC_IP_REACH_BIT);

	// /* No Prefix attributes for now (can be added later) */
	// nlri.nlri_data.prefix.attr = NULL;

	/* Insert into BGP-LS RIB */
	ret = bgp_ls_update(peer->bgp, &nlri, NULL);
	if (ret != 0) {
		zlog_err("BGP-LS: Failed to insert BGP prefix NLRI into RIB");
		bgp_attr_unintern(&attr);
		return -1;
	}

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Originated BGP Prefix NLRI for %pFX", p);

	return 0;
}

/*
 * Export BGP topology as BGP-LS NLRIs
 *
 * This function generates BGP-LS NLRIs representing the local BGP router's
 * topology. Per draft-ietf-idr-bgp-ls-bgp-only-fabric, each BGP router
 * advertises information about itself only:
 * - Its own Node NLRI (local router)
 * - Its own Link NLRIs (BGP sessions to peers)
 * - Its own Prefix NLRIs (locally advertised BGP routes)
 *
 * Note: We do NOT advertise Node NLRIs for peers. Each peer advertises
 * its own Node NLRI independently.
 *
 * Called when:
 * - 'distribute link-state' is configured and neighbors are activated
 * - A new neighbor is activated with 'distribute link-state' already configured
 *
 * Implementation Plan:
 * - Generate Node NLRI for local router (once)
 * - Iterate through all established BGP peers
 * - Generate Link NLRI for each peer session (local -> peer)
 * - Generate Prefix NLRI for each locally advertised BGP route
 */
int bgp_ls_export_bgp_topology(struct bgp *bgp)
{
	struct listnode *node;
	struct peer *peer;
	int count = 0;

	if (!bgp) {
		zlog_err("BGP-LS: Cannot export BGP topology without BGP instance");
		return -1;
	}

	if (!bgp || !bgp->ls_info || !bgp->ls_info->enable_distribution) {
		zlog_err("BGP-LS: BGP topology distribution not enabled");
		return -1;
	}

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Exporting BGP topology for instance %s", bgp->name_pretty);

	/* Generate Node NLRI for local BGP router (once) */
	if (bgp_ls_originate_bgp_node(bgp) != 0) {
		zlog_warn("BGP-LS: Failed to originate local BGP node NLRI");
		/* Continue anyway to generate Link NLRIs */
	}

	/* Iterate through all peers to generate Link NLRIs */
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		/* Only process established peers */
		if (peer->connection->status != Established)
			continue;

		/* Skip peer groups (only process actual peers) */
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
			continue;

		/* Generate Link NLRI for BGP session (local -> peer) */
		if (bgp_ls_originate_bgp_link(bgp, peer) != 0) {
			zlog_warn("BGP-LS: Failed to originate link NLRI for peer %s", peer->host);
			/* Continue to process remaining peers */
		}

		count++;
	}

	/* Export locally advertised BGP prefixes as Prefix NLRIs */
	/* Iterate through BGP RIB for IPv4 and IPv6 unicast */
	afi_t afis[] = { AFI_IP, AFI_IP6 };

	for (int i = 0; i < 2; i++) {
		afi_t afi = afis[i];
		struct bgp_dest *dest;
		struct bgp_path_info *path;

		/* Check if RIB exists for this AFI/SAFI */
		if (!bgp->rib[afi][SAFI_UNICAST])
			continue;

		/* Iterate through all routes in the RIB */
		for (dest = bgp_table_top(bgp->rib[afi][SAFI_UNICAST]); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix *prefix = bgp_dest_get_prefix(dest);

			zlog_debug("BGP-LS: Processing BGP route %pFX for Prefix NLRI origination",
				   prefix);
			/* Iterate through all paths for this destination */
			for (path = bgp_dest_get_bgp_path_info(dest); path; path = path->next) {
				zlog_debug("BGP-LS: Processing path info for route %pFX for Prefix NLRI origination",
					   prefix);
				/* Only process best paths that are locally originated */
				// if (!CHECK_FLAG(path->flags, BGP_PATH_SELECTED))
				//	continue;

				// if (path->peer != bgp->peer_self)
				//	continue;

				/* Generate Prefix NLRI for this route */
				if (bgp_ls_originate_bgp_prefix(bgp, afi, SAFI_UNICAST, dest,
								path) != 0) {
					const struct prefix *p = bgp_dest_get_prefix(dest);

					zlog_warn("BGP-LS: Failed to originate prefix NLRI for %pFX",
						  p);
					/* Continue to process remaining prefixes */
				}
			}
		}
	}

	if (BGP_DEBUG(linkstate, LINKSTATE))
		zlog_debug("BGP-LS: Exported BGP topology with %d peer sessions", count);

	return 0;
}

/* Withdraw specified route type's route. */
void bgp_ls_withdraw_all(struct bgp *bgp)
{
	struct bgp_dest *dest;
	struct bgp_table *table;

	table = bgp->rib[AFI_BGP_LS][SAFI_BGP_LS];

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest))
		bgp_ls_withdraw(bgp, dest->ls_nlri);
}

int bgp_ls_withdraw_bgp_link(struct bgp *bgp, struct peer *peer)
{
	struct bgp_dest *dest;
	struct bgp_table *table;

	if (!bgp || !peer) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Invalid parameters to %s", __func__);
		return -1;
	}

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS) || bgp->peer_self == NULL)
		return 0;

	if (!bgp->ls_info) {
		if (BGP_DEBUG(linkstate, LINKSTATE))
			zlog_debug("%s: No BGP-LS info exists for withdraw", __func__);

		return 0;
	}

	table = bgp->rib[AFI_BGP_LS][SAFI_BGP_LS];

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		if (dest->ls_nlri->nlri_type != BGP_LS_NLRI_TYPE_LINK)
			continue;
		if (dest->ls_nlri->nlri_data.link.protocol_id != BGP_LS_PROTO_BGP)
			continue;

		if (dest->ls_nlri->nlri_data.link.local_node.asn != bgp->as)
			continue;

		if (dest->ls_nlri->nlri_data.link.remote_node.asn != peer->as)
			continue;

		if (!IPV4_ADDR_SAME(&dest->ls_nlri->nlri_data.link.local_node.bgp_router_id,
				    &bgp->router_id))
			continue;

		if (!IPV4_ADDR_SAME(&dest->ls_nlri->nlri_data.link.remote_node.bgp_router_id,
				    &peer->remote_id))
			continue;

		bgp_ls_withdraw(bgp, dest->ls_nlri);
		break;
	}

	return 0;
}

int bgp_ls_withdraw_bgp_prefix(struct bgp *bgp, afi_t afi, safi_t safi, struct bgp_dest *dest,
			       struct bgp_path_info *path)
{
	const struct prefix *p;
	struct bgp_table *table;
	enum bgp_ls_bgp_route_type route_type;
	struct bgp_dest *bn;

	if (!bgp || !dest || !path) {
		zlog_err("BGP-LS: Invalid parameters for BGP prefix origination");
		return -1;
	}

	/* Get the prefix */
	p = bgp_dest_get_prefix(dest);
	if (!p) {
		zlog_err("BGP-LS: Cannot get prefix from destination");
		return -1;
	}

	if (path->type == ZEBRA_ROUTE_LOCAL ||
	    (p->family == AF_INET6 && if_address_is_local(&p->u.prefix6, AF_INET6, VRF_DEFAULT)) ||
	    (p->family == AF_INET && if_address_is_local(&p->u.prefix4, AF_INET, VRF_DEFAULT)))
		route_type = BGP_LS_BGP_RT_LOCAL;
	else if (path->type == ZEBRA_ROUTE_CONNECT)
		route_type = BGP_LS_BGP_RT_ATTACHED;
	else if (path->type == ZEBRA_ROUTE_BGP && path->peer->sort == BGP_PEER_EBGP)
		route_type = BGP_LS_BGP_RT_EXTERNAL_BGP;
	else if (path->type == ZEBRA_ROUTE_BGP && path->peer->sort == BGP_PEER_IBGP)
		route_type = BGP_LS_BGP_RT_INTERNAL_BGP;
	else // if (path->type >= ZEBRA_ROUTE_STATIC && path->type <= ZEBRA_ROUTE_TABLE_DIRECT)
		route_type = BGP_LS_BGP_RT_REDISTRIBUTED;

	zlog_info("route type %u", route_type);

	table = bgp->rib[AFI_BGP_LS][SAFI_BGP_LS];

	for (bn = bgp_table_top(table); bn; bn = bgp_route_next(bn)) {
		if (bn->ls_nlri->nlri_data.prefix.protocol_id != BGP_LS_PROTO_BGP)
			continue;

		if (p->family == AF_INET && bn->ls_nlri->nlri_type != BGP_LS_NLRI_TYPE_IPV4_PREFIX)
			continue;

		if (p->family == AF_INET6 && bn->ls_nlri->nlri_type != BGP_LS_NLRI_TYPE_IPV6_PREFIX)
			continue;

		if (bn->ls_nlri->nlri_data.prefix.local_node.asn != bgp->as)
			continue;

		if (!IPV4_ADDR_SAME(&bn->ls_nlri->nlri_data.prefix.local_node.bgp_router_id,
				    &bgp->router_id))
			continue;

		if ((route_type != BGP_LS_BGP_RT_ATTACHED) &&
		    bn->ls_nlri->nlri_data.prefix.prefix_desc.bgp_route_type != route_type)
			continue;

		if (!prefix_same(&bn->ls_nlri->nlri_data.prefix.prefix_desc.prefix, p))
			continue;

		bgp_ls_withdraw(bgp, bn->ls_nlri);
		break;
	}

	return 0;
}
