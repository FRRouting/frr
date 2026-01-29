// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Link-State VTY commands (RFC 9552)
 * Copyright (C) 2025 Carmine Scarpitta
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/vty.h"
#include "lib/json.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_ls.h"
#include "bgpd/bgp_ls_nlri.h"
#include "bgpd/bgp_ls_ted.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"

/* External functions from bgp_vty.c */
extern struct peer *peer_and_group_lookup_vty(struct vty *vty, const char *peer_str);

/*
 * Helper Functions for NLRI Formatting
 */

/* Convert node descriptor to JSON */
static json_object *node_desc_to_json(struct bgp_ls_node_descriptor *node)
{
	json_object *json_node = json_object_new_object();

	if (BGP_LS_TLV_CHECK(node->present_tlvs, BGP_LS_NODE_DESC_AS_BIT))
		json_object_int_add(json_node, "asn", node->asn);

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

	return json_node;
}

/* Convert link descriptor to JSON */
static json_object *link_desc_to_json(struct bgp_ls_link_descriptor *link_desc)
{
	json_object *json_link = json_object_new_object();
	char addr_str[INET6_ADDRSTRLEN];

	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_LINK_ID_BIT)) {
		json_object_int_add(json_link, "linkLocalId", link_desc->link_local_id);
		json_object_int_add(json_link, "linkRemoteId", link_desc->link_remote_id);
	}

	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_INTF_BIT)) {
		inet_ntop(AF_INET, &link_desc->ipv4_intf_addr, addr_str, sizeof(addr_str));
		json_object_string_add(json_link, "ipv4InterfaceAddress", addr_str);
	}

	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV4_NEIGH_BIT)) {
		inet_ntop(AF_INET, &link_desc->ipv4_neigh_addr, addr_str, sizeof(addr_str));
		json_object_string_add(json_link, "ipv4NeighborAddress", addr_str);
	}

	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_INTF_BIT)) {
		inet_ntop(AF_INET6, &link_desc->ipv6_intf_addr, addr_str, sizeof(addr_str));
		json_object_string_add(json_link, "ipv6InterfaceAddress", addr_str);
	}

	if (BGP_LS_TLV_CHECK(link_desc->present_tlvs, BGP_LS_LINK_DESC_IPV6_NEIGH_BIT)) {
		inet_ntop(AF_INET6, &link_desc->ipv6_neigh_addr, addr_str, sizeof(addr_str));
		json_object_string_add(json_link, "ipv6NeighborAddress", addr_str);
	}

	return json_link;
}

/* Convert prefix descriptor to JSON */
static json_object *prefix_desc_to_json(struct bgp_ls_prefix_descriptor *prefix_desc,
					enum bgp_ls_nlri_type nlri_type)
{
	json_object *json_prefix = json_object_new_object();
	char prefix_str[INET6_ADDRSTRLEN + 4];
	char addr_str[INET_ADDRSTRLEN];

	/* IP Reachability Information */
	if (nlri_type == BGP_LS_NLRI_TYPE_IPV4_PREFIX) {
		inet_ntop(AF_INET, &prefix_desc->prefix.u.prefix4, addr_str, sizeof(addr_str));
		snprintfrr(prefix_str, sizeof(prefix_str), "%s/%u", addr_str,
			   prefix_desc->prefix.prefixlen);
	} else if (nlri_type == BGP_LS_NLRI_TYPE_IPV6_PREFIX) {
		inet_ntop(AF_INET6, &prefix_desc->prefix.u.prefix6, addr_str, sizeof(addr_str));
		snprintfrr(prefix_str, sizeof(prefix_str), "%s/%u", addr_str,
			   prefix_desc->prefix.prefixlen);
	}
	json_object_string_add(json_prefix, "ipReachabilityInformation", prefix_str);

	return json_prefix;
}

/* Convert NLRI to JSON */
static json_object *nlri_to_json(struct bgp_ls_nlri *nlri)
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

/*
 * Helper Functions for NLRI Formatting
 */

/* Format Node Attributes */
static void format_node_attr(struct vty *vty, struct bgp_ls_node_attr *attr, const char *prefix)
{
	if (!attr || !vty)
		return;

	/* Node Name */
	if (attr->present_tlvs & (1 << BGP_LS_NODE_ATTR_NODE_NAME_BIT)) {
		vty_out(vty, "%sNode-name: %s", prefix,
			attr->node_name ? attr->node_name : "(null)");
	}

	/* ISIS Area ID */
	if (attr->present_tlvs & (1 << BGP_LS_NODE_ATTR_ISIS_AREA_BIT)) {
		if (attr->present_tlvs & (1 << BGP_LS_NODE_ATTR_NODE_NAME_BIT))
			vty_out(vty, ", ");
		vty_out(vty, "ISIS area: ");
		for (uint8_t i = 0; i < attr->isis_area_id_len; i++) {
			if (i > 0)
				vty_out(vty, ".");
			vty_out(vty, "%02x", attr->isis_area_id[i]);
		}
	}

	/* IPv4 Router ID */
	if (attr->present_tlvs & (1 << BGP_LS_NODE_ATTR_IPV4_ROUTER_ID_BIT)) {
		if ((attr->present_tlvs & (1 << BGP_LS_NODE_ATTR_NODE_NAME_BIT)) ||
		    (attr->present_tlvs & (1 << BGP_LS_NODE_ATTR_ISIS_AREA_BIT)))
			vty_out(vty, ", ");
		vty_out(vty, "IPv4 Router-ID: %pI4", &attr->ipv4_router_id);
	}

	/* IPv6 Router ID */
	if (attr->present_tlvs & (1 << BGP_LS_NODE_ATTR_IPV6_ROUTER_ID_BIT)) {
		if ((attr->present_tlvs & (1 << BGP_LS_NODE_ATTR_NODE_NAME_BIT)) ||
		    (attr->present_tlvs & (1 << BGP_LS_NODE_ATTR_ISIS_AREA_BIT)) ||
		    (attr->present_tlvs & (1 << BGP_LS_NODE_ATTR_IPV4_ROUTER_ID_BIT)))
			vty_out(vty, ", ");
		vty_out(vty, "IPv6 Router-ID: %pI6", &attr->ipv6_router_id);
	}

	/* Node Flags */
	if (attr->present_tlvs & (1 << BGP_LS_NODE_ATTR_NODE_FLAGS_BIT)) {
		vty_out(vty, "\n%sNode Flags: 0x%02x", prefix, attr->node_flags);
		if (attr->node_flags & BGP_LS_NODE_FLAG_OVERLOAD)
			vty_out(vty, " (Overload)");
		if (attr->node_flags & BGP_LS_NODE_FLAG_ATTACHED)
			vty_out(vty, " (Attached)");
		if (attr->node_flags & BGP_LS_NODE_FLAG_EXTERNAL)
			vty_out(vty, " (External)");
		if (attr->node_flags & BGP_LS_NODE_FLAG_ABR)
			vty_out(vty, " (ABR)");
		if (attr->node_flags & BGP_LS_NODE_FLAG_ROUTER)
			vty_out(vty, " (Router)");
		if (attr->node_flags & BGP_LS_NODE_FLAG_V6)
			vty_out(vty, " (V6)");
	}
}

/* Format Link Attributes */
static void format_link_attr(struct vty *vty, struct bgp_ls_link_attr *attr, const char *prefix)
{
	bool first = true;

	if (!attr || !vty)
		return;

	/* IGP Metric */
	if (attr->present_tlvs & (1 << BGP_LS_LINK_ATTR_IGP_METRIC_BIT)) {
		vty_out(vty, "%sIGP Metric: %u", prefix, attr->igp_metric);
		first = false;
	}

	/* TE Metric */
	if (attr->present_tlvs & (1 << BGP_LS_LINK_ATTR_TE_METRIC_BIT)) {
		if (!first)
			vty_out(vty, ", ");
		else
			vty_out(vty, "%s", prefix);
		vty_out(vty, "TE Metric: %u", attr->te_metric);
		first = false;
	}

	/* Max Link Bandwidth */
	if (attr->present_tlvs & (1 << BGP_LS_LINK_ATTR_MAX_LINK_BW_BIT)) {
		if (!first)
			vty_out(vty, "\n%s", prefix);
		else
			vty_out(vty, "%s", prefix);
		vty_out(vty, "Max Link BW: %.2f Mbps", attr->max_link_bw / 1000000.0);
		first = false;
	}

	/* Max Reservable Bandwidth */
	if (attr->present_tlvs & (1 << BGP_LS_LINK_ATTR_MAX_RESV_BW_BIT)) {
		if (!first)
			vty_out(vty, ", ");
		else
			vty_out(vty, "%s", prefix);
		vty_out(vty, "Max Resv BW: %.2f Mbps", attr->max_resv_bw / 1000000.0);
		first = false;
	}

	/* Unreserved Bandwidth */
	if (attr->present_tlvs & (1 << BGP_LS_LINK_ATTR_UNRESV_BW_BIT)) {
		vty_out(vty, "\n%sUnreserved BW:", prefix);
		for (int i = 0; i < BGP_LS_MAX_UNRESV_BW; i++)
			vty_out(vty, " [%d]=%.2f", i, attr->unreserved_bw[i] / 1000000.0);
		first = false;
	}

	/* Admin Group */
	if (attr->present_tlvs & (1 << BGP_LS_LINK_ATTR_ADMIN_GROUP_BIT)) {
		if (!first)
			vty_out(vty, "\n%s", prefix);
		else
			vty_out(vty, "%s", prefix);
		vty_out(vty, "Admin Group: 0x%08x", attr->admin_group);
		first = false;
	}

	/* SRLG */
	if (attr->present_tlvs & (1 << BGP_LS_LINK_ATTR_SRLG_BIT)) {
		vty_out(vty, "\n%sSRLG: ", prefix);
		for (uint8_t i = 0; i < attr->srlg_count; i++) {
			if (i > 0)
				vty_out(vty, ", ");
			vty_out(vty, "%u", attr->srlg_values[i]);
		}
		first = false;
	}

	/* Link Name */
	if (attr->present_tlvs & (1 << BGP_LS_LINK_ATTR_LINK_NAME_BIT)) {
		if (!first)
			vty_out(vty, "\n%s", prefix);
		else
			vty_out(vty, "%s", prefix);
		vty_out(vty, "Link Name: %s", attr->link_name ? attr->link_name : "(null)");
		first = false;
	}

	/* Link Protection */
	if (attr->present_tlvs & (1 << BGP_LS_LINK_ATTR_LINK_PROTECTION_BIT)) {
		if (!first)
			vty_out(vty, "\n%s", prefix);
		else
			vty_out(vty, "%s", prefix);
		vty_out(vty, "Link Protection: 0x%04x", attr->link_protection);
	}
}

/* Format Prefix Attributes */
static void format_prefix_attr(struct vty *vty, struct bgp_ls_prefix_attr *attr, const char *prefix)
{
	bool first = true;

	if (!attr || !vty)
		return;

	/* IGP Flags */
	if (attr->present_tlvs & (1 << BGP_LS_PREFIX_ATTR_IGP_FLAGS_BIT)) {
		vty_out(vty, "%sIGP Flags: 0x%02x", prefix, attr->igp_flags);
		if (attr->igp_flags & BGP_LS_PREFIX_FLAG_DOWN)
			vty_out(vty, " (Down)");
		if (attr->igp_flags & BGP_LS_PREFIX_FLAG_NO_UNICAST)
			vty_out(vty, " (No-Unicast)");
		if (attr->igp_flags & BGP_LS_PREFIX_FLAG_LOCAL)
			vty_out(vty, " (Local)");
		if (attr->igp_flags & BGP_LS_PREFIX_FLAG_PROPAGATE)
			vty_out(vty, " (Propagate)");
		if (attr->igp_flags & BGP_LS_PREFIX_FLAG_NODE)
			vty_out(vty, " (Node)");
		first = false;
	}

	/* Prefix Metric */
	if (attr->present_tlvs & (1 << BGP_LS_PREFIX_ATTR_PREFIX_METRIC_BIT)) {
		if (!first)
			vty_out(vty, ", ");
		else
			vty_out(vty, "%s", prefix);
		vty_out(vty, "Prefix Metric: %u", attr->prefix_metric);
		first = false;
	}

	/* Route Tags */
	if (attr->present_tlvs & (1 << BGP_LS_PREFIX_ATTR_ROUTE_TAG_BIT)) {
		if (!first)
			vty_out(vty, "\n%s", prefix);
		else
			vty_out(vty, "%s", prefix);
		vty_out(vty, "Route Tags:");
		for (uint8_t i = 0; i < attr->route_tag_count; i++)
			vty_out(vty, " %u", attr->route_tags[i]);
		first = false;
	}

	/* Extended Tags */
	if (attr->present_tlvs & (1 << BGP_LS_PREFIX_ATTR_EXTENDED_TAG_BIT)) {
		if (!first)
			vty_out(vty, "\n%s", prefix);
		else
			vty_out(vty, "%s", prefix);
		vty_out(vty, "Extended Tags:");
		for (uint8_t i = 0; i < attr->extended_tag_count; i++)
			vty_out(vty, " %" PRIu64, attr->extended_tags[i]);
		first = false;
	}

	/* OSPF Forwarding Address */
	if (attr->present_tlvs & (1 << BGP_LS_PREFIX_ATTR_OSPF_FWD_ADDR_BIT)) {
		if (!first)
			vty_out(vty, "\n%s", prefix);
		else
			vty_out(vty, "%s", prefix);
		/* Check if IPv4 or IPv6 */
		if (attr->ospf_fwd_addr.s_addr != 0)
			vty_out(vty, "OSPF Fwd Addr: %pI4", &attr->ospf_fwd_addr);
		else
			vty_out(vty, "OSPF Fwd Addr: %pI6", &attr->ospf_fwd_addr6);
	}
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

/* Format BGP-LS NLRI to string */
static void bgp_ls_nlri_format(struct bgp_ls_nlri *nlri, char *buf, size_t buf_len)
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
		len = snprintfrr(p, remain, "[T4]");
		break;
	case BGP_LS_NLRI_TYPE_IPV6_PREFIX:
		len = snprintfrr(p, remain, "[T6]");
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
	}
}

/*
 * Show Commands
 */

DEFUN(show_bgp_link_state_route,
      show_bgp_link_state_route_cmd,
      "show bgp link-state link-state [json]",
      SHOW_STR
      BGP_STR
      "Link-State information\n"
      "BGP-LS routes\n"
      JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct bgp *bgp = NULL;
	json_object *json_routes = NULL;
	char nlri_str[1024];
	char nexthop_str[INET6_ADDRSTRLEN];
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	bgp = bgp_get_default();
	if (!bgp) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% No BGP instance found\n");
		return CMD_WARNING;
	}

	if (!bgp->ls_info) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% BGP-LS not available\n");
		return CMD_WARNING;
	}

	if (uj) {
		json_routes = json_object_new_array();
	} else {
		vty_out(vty, "BGP table version is 0, local router ID is %pI4\n", &bgp->router_id);
		vty_out(vty,
			"Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,\n");
		vty_out(vty,
			"              r RIB-failure, S Stale, m multipath, b backup-path, f RT-Filter,\n");
		vty_out(vty,
			"              x best-external, a additional-path, c RIB-compressed,\n");
		vty_out(vty, "              t secondary path,\n");
		vty_out(vty, "Origin codes: i - IGP, e - EGP, ? - incomplete\n");
		vty_out(vty, "RPKI validation codes: V valid, I invalid, N Not found\n");
		vty_out(vty,
			"Prefix codes: E link, V node, T4 IPv4 reachable route, T6 IPv6 reachable route, I Identifier,\n");
		vty_out(vty, "              N local node, R remote node, L link, P prefix,\n");
		vty_out(vty,
			"              L1/L2 ISIS level-1/level-2, O OSPF, a area-ID, l link-ID,\n");
		vty_out(vty,
			"              t topology-ID, s ISO-ID, c confed-ID/ASN, b bgp-identifier,\n");
		vty_out(vty,
			"              r router-ID, i if-address, n nbr-address, o OSPF Route-type,\n");
		vty_out(vty,
			"              p IP-prefix, d designated router address, u/U Unknown,\n");
		vty_out(vty, "              x/X Unexpected, m/M Malformed\n\n");
		vty_out(vty,
			"     Network          Next Hop            Metric LocPrf Weight Path\n");
	}

	table = bgp->rib[AFI_BGP_LS][SAFI_BGP_LS];

	unsigned long route_count = 0;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		pi = bgp_dest_get_bgp_path_info(dest);
		if (!pi)
			continue;

		for (; pi; pi = pi->next) {
			struct bgp_ls_nlri *ls_nlri = NULL;

			if (pi->extra && pi->extra->ls_nlri)
				ls_nlri = pi->extra->ls_nlri;

			if (!ls_nlri)
				continue;

			route_count++;

			/* Format NLRI */
			bgp_ls_nlri_format(ls_nlri, nlri_str, sizeof(nlri_str));

			/* Get next hop */
			if (pi->attr && pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4) {
				inet_ntop(AF_INET, &pi->attr->mp_nexthop_global_in, nexthop_str,
					  sizeof(nexthop_str));
			} else if (pi->attr &&
				   pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL) {
				inet_ntop(AF_INET6, &pi->attr->mp_nexthop_global, nexthop_str,
					  sizeof(nexthop_str));
			} else {
				snprintfrr(nexthop_str, sizeof(nexthop_str), "0.0.0.0");
			}

			if (uj) {
				json_object *json_route = json_object_new_object();
				json_object *json_nlri = nlri_to_json(ls_nlri);

				json_object_object_add(json_route, "nlri", json_nlri);
				json_object_string_add(json_route, "nextHop", nexthop_str);
				if (pi->attr) {
					json_object_int_add(json_route, "metric", pi->attr->med);
					json_object_int_add(json_route, "locPrf",
							    pi->attr->local_pref);
					json_object_int_add(json_route, "weight", pi->attr->weight);
				}
				json_object_array_add(json_routes, json_route);
			} else {
				/* Status codes */
				vty_out(vty, " *>  ");

				/* NLRI (Network column) */
				vty_out(vty, " %s\n", nlri_str);

				/* Next hop and metrics on next line */
				vty_out(vty, "                      %-19s %6u %6u %6u ",
					nexthop_str, pi->attr ? pi->attr->med : 0,
					pi->attr ? pi->attr->local_pref : 0,
					pi->attr ? pi->attr->weight : 0);

				/* AS path and origin */
				if (pi->attr && pi->attr->aspath)
					vty_out(vty, "%s", pi->attr->aspath->str);

				vty_out(vty, " i\n");
			}
		}
	}

	if (uj)
		vty_json(vty, json_routes);
	else
		vty_out(vty, "\nDisplayed %lu routes\n", route_count);

	return CMD_SUCCESS;
}

DEFUN(show_bgp_link_state_route_nlri,
      show_bgp_link_state_route_nlri_cmd,
      "show bgp link-state link-state WORD [json]",
      SHOW_STR
      BGP_STR
      "Link-State information\n"
      "BGP-LS routes\n"
      "NLRI string\n"
      JSON_STR)
{
	int idx_nlri = 4;
	bool uj = use_json(argc, argv);
	struct bgp *bgp = NULL;
	struct bgp_ls_nlri *entry = NULL;
	char formatted_nlri[1024];
	bool found = false;
	struct bgp_table *table;

	bgp = bgp_get_default();
	if (!bgp) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% No BGP instance found\n");
		return CMD_WARNING;
	}

	if (!bgp->ls_info) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% BGP-LS not available\n");
		return CMD_WARNING;
	}

	frr_each (bgp_ls_nlri_hash, &bgp->ls_info->nlri_hash, entry) {
		bgp_ls_nlri_format(entry, formatted_nlri, sizeof(formatted_nlri));

		if (strcmp(formatted_nlri, argv[idx_nlri]->arg) == 0) {
			found = true;
			break;
		}
	}

	struct bgp_dest *dest = NULL;

	table = bgp->rib[AFI_BGP_LS][SAFI_BGP_LS];

	if (found) {
		struct prefix match;

		match.family = AF_UNSPEC;
		match.prefixlen = 32;
		match.u.val32[0] = entry->id;

		dest = bgp_node_match(table, &match);
		if (!dest) {
			vty_out(vty, "%% Network not in table\n");
			return CMD_SUCCESS;
		}
	}

	struct bgp_path_info *pi;

	pi = bgp_dest_get_bgp_path_info(dest);
	if (!pi)
		return CMD_SUCCESS;

	for (; pi; pi = pi->next) {
		if (uj) {
			json_object *json = json_object_new_object();

			json_object_string_add(json, "nlri", formatted_nlri);
			if (pi && pi->attr) {
				char nexthop_str[INET6_ADDRSTRLEN];

				if (pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4) {
					inet_ntop(AF_INET, &pi->attr->mp_nexthop_global_in,
						  nexthop_str, sizeof(nexthop_str));
				} else if (pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL) {
					inet_ntop(AF_INET6, &pi->attr->mp_nexthop_global,
						  nexthop_str, sizeof(nexthop_str));
				} else {
					snprintfrr(nexthop_str, sizeof(nexthop_str), "0.0.0.0");
				}
				json_object_string_add(json, "nextHop", nexthop_str);
				json_object_int_add(json, "metric", pi->attr->med);
				json_object_int_add(json, "locPrf", pi->attr->local_pref);
				json_object_int_add(json, "weight", pi->attr->weight);
			}
			vty_json(vty, json);
		} else {
			vty_out(vty, "BGP routing table entry for %s\n", formatted_nlri);

			if (pi) {
				if (pi->peer == bgp->peer_self)
					vty_out(vty, "  Not advertised to any peer\n");

				vty_out(vty, "  Local\n");

				if (pi->attr) {
					char nexthop_str[INET6_ADDRSTRLEN];

					if (pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4) {
						inet_ntop(AF_INET, &pi->attr->mp_nexthop_global_in,
							  nexthop_str, sizeof(nexthop_str));
					} else if (pi->attr->mp_nexthop_len ==
						   BGP_ATTR_NHLEN_IPV6_GLOBAL) {
						inet_ntop(AF_INET6, &pi->attr->mp_nexthop_global,
							  nexthop_str, sizeof(nexthop_str));
					} else {
						snprintfrr(nexthop_str, sizeof(nexthop_str),
							   "0.0.0.0");
					}

					vty_out(vty, "    %s from %s (%pI4)\n", nexthop_str,
						pi->peer->host, &pi->peer->remote_id);
					vty_out(vty,
						"      Origin IGP, metric %u, localpref %u, valid, internal, best\n",
						pi->attr->med, pi->attr->local_pref);

					/* Display BGP-LS Attributes */
					if (entry->nlri_type == BGP_LS_NLRI_TYPE_NODE &&
						entry->nlri_data.node.attr) {
						vty_out(vty, "      LS Attribute: ");
						format_node_attr(vty,
									entry->nlri_data.node.attr,
									"");
						vty_out(vty, "\n");
					} else if (entry->nlri_type ==
								BGP_LS_NLRI_TYPE_LINK &&
							entry->nlri_data.link.attr) {
						vty_out(vty, "      LS Attribute:\n");
						format_link_attr(vty,
									entry->nlri_data.link.attr,
									"        ");
						vty_out(vty, "\n");
					} else if ((entry->nlri_type ==
								BGP_LS_NLRI_TYPE_IPV4_PREFIX ||
							entry->nlri_type ==
								BGP_LS_NLRI_TYPE_IPV6_PREFIX) &&
							entry->nlri_data.prefix.attr) {
						vty_out(vty, "      LS Attribute: ");
						format_prefix_attr(vty,
									entry->nlri_data.prefix
										.attr,
									"");
						vty_out(vty, "\n");
					}

					vty_out(vty, "      rx pathid: 0, tx pathid: 0x0\n");
				}
			}
		}
	}

	if (!found && !uj)
		vty_out(vty, "%% Network not in table\n");

	return CMD_SUCCESS;
}

/*
 * Initialization
 */

void bgp_ls_vty_init(void)
{
	/* Show commands */
	install_element(VIEW_NODE, &show_bgp_link_state_route_cmd);
	install_element(VIEW_NODE, &show_bgp_link_state_route_nlri_cmd);
}
