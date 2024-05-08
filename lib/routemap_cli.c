// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Route map northbound CLI implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/northbound_cli.h"
#include "lib/routemap.h"

#include "lib/routemap_cli_clippy.c"

#define ROUTE_MAP_CMD_STR \
	"Create route-map or enter route-map command mode\n" \
	"Route map tag\n"
#define ROUTE_MAP_OP_CMD_STR \
	"Route map denies set operations\n" \
	"Route map permits set operations\n"
#define ROUTE_MAP_SEQUENCE_CMD_STR \
	"Sequence to insert to/delete from existing route-map entry\n"

DEFPY_YANG_NOSH(
	route_map, route_map_cmd,
	"route-map RMAP_NAME$name <deny|permit>$action (1-65535)$sequence",
	ROUTE_MAP_CMD_STR
	ROUTE_MAP_OP_CMD_STR
	ROUTE_MAP_SEQUENCE_CMD_STR)
{
	char xpath_action[XPATH_MAXLEN + 64];
	char xpath_index[XPATH_MAXLEN + 32];
	char xpath[XPATH_MAXLEN];
	int rv;

	snprintf(xpath, sizeof(xpath),
		 "/frr-route-map:lib/route-map[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_index, sizeof(xpath_index), "%s/entry[sequence='%lu']",
		 xpath, sequence);
	nb_cli_enqueue_change(vty, xpath_index, NB_OP_CREATE, NULL);

	snprintf(xpath_action, sizeof(xpath_action), "%s/action", xpath_index);
	nb_cli_enqueue_change(vty, xpath_action, NB_OP_MODIFY, action);

	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(RMAP_NODE, xpath_index);

	return rv;
}

DEFPY_YANG(
	no_route_map_all, no_route_map_all_cmd,
	"no route-map RMAP_NAME$name",
	NO_STR
	ROUTE_MAP_CMD_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-route-map:lib/route-map[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_route_map, no_route_map_cmd,
	"no route-map RMAP_NAME$name <deny|permit>$action (1-65535)$sequence",
	NO_STR
	ROUTE_MAP_CMD_STR
	ROUTE_MAP_OP_CMD_STR
	ROUTE_MAP_SEQUENCE_CMD_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-route-map:lib/route-map[name='%s']/entry[sequence='%lu']",
		 name, sequence);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

int route_map_instance_cmp(const struct lyd_node *dnode1,
			   const struct lyd_node *dnode2)
{
	uint16_t seq1 = yang_dnode_get_uint16(dnode1, "sequence");
	uint16_t seq2 = yang_dnode_get_uint16(dnode2, "sequence");

	return seq1 - seq2;
}

void route_map_instance_show(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "../name");
	const char *action = yang_dnode_get_string(dnode, "action");
	const char *sequence = yang_dnode_get_string(dnode, "sequence");

	vty_out(vty, "route-map %s %s %s\n", name, action, sequence);

}

void route_map_instance_show_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");
}

DEFPY_YANG(
	match_interface, match_interface_cmd,
	"match interface IFNAME",
	MATCH_STR
	"Match first hop interface of route\n"
	INTERFACE_STR)
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:interface']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/interface", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, ifname);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_interface, no_match_interface_cmd,
	"no match interface [IFNAME]",
	NO_STR
	MATCH_STR
	"Match first hop interface of route\n"
	INTERFACE_STR)
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:interface']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_ip_address, match_ip_address_cmd,
	"match ip address ACCESSLIST4_NAME$name",
	MATCH_STR
	IP_STR
	"Match address of route\n"
	"IP Access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv4-address-list']";
	char xpath_value[XPATH_MAXLEN + 32];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_ip_address, no_match_ip_address_cmd,
	"no match ip address [ACCESSLIST4_NAME]",
	NO_STR
	MATCH_STR
	IP_STR
	"Match address of route\n"
	"IP Access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv4-address-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_ip_address_prefix_list,
	match_ip_address_prefix_list_cmd,
	"match ip address prefix-list PREFIXLIST4_NAME$name",
	MATCH_STR
	IP_STR
	"Match address of route\n"
	"Match entries of prefix-lists\n"
	"IP prefix-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv4-prefix-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_ip_address_prefix_list, no_match_ip_address_prefix_list_cmd,
	"no match ip address prefix-list [PREFIXLIST4_NAME]",
	NO_STR
	MATCH_STR
	IP_STR
	"Match address of route\n"
	"Match entries of prefix-lists\n"
	"IP prefix-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv4-prefix-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_ip_next_hop, match_ip_next_hop_cmd,
	"match ip next-hop ACCESSLIST4_NAME$name",
	MATCH_STR
	IP_STR
	"Match next-hop address of route\n"
	"IP Access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv4-next-hop-list']";
	char xpath_value[XPATH_MAXLEN + 32];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_ip_next_hop, no_match_ip_next_hop_cmd,
	"no match ip next-hop [ACCESSLIST4_NAME]",
	NO_STR
	MATCH_STR
	IP_STR
	"Match address of route\n"
	"IP Access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv4-next-hop-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_ip_next_hop_prefix_list,
	match_ip_next_hop_prefix_list_cmd,
	"match ip next-hop prefix-list PREFIXLIST4_NAME$name",
	MATCH_STR
	IP_STR
	"Match next-hop address of route\n"
	"Match entries of prefix-lists\n"
	"IP prefix-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv4-next-hop-prefix-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_ip_next_hop_prefix_list,
	no_match_ip_next_hop_prefix_list_cmd,
	"no match ip next-hop prefix-list [PREFIXLIST4_NAME]",
	NO_STR
	MATCH_STR
	IP_STR
	"Match next-hop address of route\n"
	"Match entries of prefix-lists\n"
	"IP prefix-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv4-next-hop-prefix-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_ip_next_hop_type, match_ip_next_hop_type_cmd,
	"match ip next-hop type <blackhole>$type",
	MATCH_STR
	IP_STR
	"Match next-hop address of route\n"
	"Match entries by type\n"
	"Blackhole\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv4-next-hop-type']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/ipv4-next-hop-type", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, type);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_ip_next_hop_type, no_match_ip_next_hop_type_cmd,
	"no match ip next-hop type [<blackhole>]",
	NO_STR MATCH_STR IP_STR
	"Match next-hop address of route\n"
	"Match entries by type\n"
	"Blackhole\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv4-next-hop-type']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_ipv6_address, match_ipv6_address_cmd,
	"match ipv6 address ACCESSLIST6_NAME$name",
	MATCH_STR
	IPV6_STR
	"Match IPv6 address of route\n"
	"IPv6 access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv6-address-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_ipv6_address, no_match_ipv6_address_cmd,
	"no match ipv6 address [ACCESSLIST6_NAME]",
	NO_STR
	MATCH_STR
	IPV6_STR
	"Match IPv6 address of route\n"
	"IPv6 access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv6-address-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_ipv6_address_prefix_list, match_ipv6_address_prefix_list_cmd,
	"match ipv6 address prefix-list PREFIXLIST6_NAME$name",
	MATCH_STR
	IPV6_STR
	"Match address of route\n"
	"Match entries of prefix-lists\n"
	"IP prefix-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv6-prefix-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_ipv6_address_prefix_list,
	no_match_ipv6_address_prefix_list_cmd,
	"no match ipv6 address prefix-list [PREFIXLIST6_NAME]",
	NO_STR
	MATCH_STR
	IPV6_STR
	"Match address of route\n"
	"Match entries of prefix-lists\n"
	"IP prefix-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv6-prefix-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_ipv6_next_hop_type, match_ipv6_next_hop_type_cmd,
	"match ipv6 next-hop type <blackhole>$type",
	MATCH_STR IPV6_STR
	"Match next-hop address of route\n"
	"Match entries by type\n"
	"Blackhole\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv6-next-hop-type']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/ipv6-next-hop-type", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, type);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_ipv6_next_hop_type, no_match_ipv6_next_hop_type_cmd,
	"no match ipv6 next-hop type [<blackhole>]",
	NO_STR MATCH_STR IPV6_STR
	"Match address of route\n"
	"Match entries by type\n"
	"Blackhole\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv6-next-hop-type']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_metric, match_metric_cmd,
	"match metric (0-4294967295)$metric",
	MATCH_STR
	"Match metric of route\n"
	"Metric value\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:match-metric']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/metric", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, metric_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_metric, no_match_metric_cmd,
	"no match metric [(0-4294967295)]",
	NO_STR
	MATCH_STR
	"Match metric of route\n"
	"Metric value\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:match-metric']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_tag, match_tag_cmd,
	"match tag <untagged$untagged|(1-4294967295)$tagged>",
	MATCH_STR
	"Match tag of route\n"
	"Untagged route\n"
	"Tag value\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:match-tag']";
	char xpath_value[XPATH_MAXLEN];
	char value[64];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/tag", xpath);
	snprintf(value, sizeof(value), "%lu", tagged ? tagged : 0);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_tag, no_match_tag_cmd,
	"no match tag [<untagged|(1-4294967295)>]",
	NO_STR
	MATCH_STR
	"Match tag of route\n"
	"Untagged route\n"
	"Tag value\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:match-tag']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void route_map_condition_show(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults)
{
	const char *condition = yang_dnode_get_string(dnode, "condition");
	const struct lyd_node *ln;
	const char *acl;

	if (IS_MATCH_INTERFACE(condition)) {
		vty_out(vty, " match interface %s\n",
			yang_dnode_get_string(
				dnode, "./rmap-match-condition/interface"));
	} else if (IS_MATCH_IPv4_ADDRESS_LIST(condition)) {
		vty_out(vty, " match ip address %s\n",
			yang_dnode_get_string(
				dnode, "./rmap-match-condition/list-name"));
	} else if (IS_MATCH_IPv4_NEXTHOP_LIST(condition)) {
		vty_out(vty, " match ip next-hop %s\n",
			yang_dnode_get_string(
				dnode, "./rmap-match-condition/list-name"));
	} else if (IS_MATCH_IPv6_NEXTHOP_LIST(condition)) {
		vty_out(vty, " match ipv6 next-hop %s\n",
			yang_dnode_get_string(
				dnode, "./rmap-match-condition/list-name"));
	} else if (IS_MATCH_IPv4_PREFIX_LIST(condition)) {
		vty_out(vty, " match ip address prefix-list %s\n",
			yang_dnode_get_string(
				dnode, "./rmap-match-condition/list-name"));
	} else if (IS_MATCH_IPv4_NEXTHOP_PREFIX_LIST(condition)) {
		vty_out(vty, " match ip next-hop prefix-list %s\n",
			yang_dnode_get_string(
				dnode, "./rmap-match-condition/list-name"));
	} else if (IS_MATCH_IPv6_NEXTHOP_PREFIX_LIST(condition)) {
		vty_out(vty, " match ipv6 next-hop prefix-list %s\n",
			yang_dnode_get_string(
				dnode, "./rmap-match-condition/list-name"));
	} else if (IS_MATCH_IPv6_ADDRESS_LIST(condition)) {
		vty_out(vty, " match ipv6 address %s\n",
			yang_dnode_get_string(
				dnode, "./rmap-match-condition/list-name"));
	} else if (IS_MATCH_IPv6_PREFIX_LIST(condition)) {
		vty_out(vty, " match ipv6 address prefix-list %s\n",
			yang_dnode_get_string(
				dnode, "./rmap-match-condition/list-name"));
	} else if (IS_MATCH_IPv4_NEXTHOP_TYPE(condition)) {
		vty_out(vty, " match ip next-hop type %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/ipv4-next-hop-type"));
	} else if (IS_MATCH_IPv6_NEXTHOP_TYPE(condition)) {
		vty_out(vty, " match ipv6 next-hop type %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/ipv6-next-hop-type"));
	} else if (IS_MATCH_METRIC(condition)) {
		vty_out(vty, " match metric %s\n",
			yang_dnode_get_string(dnode,
					      "./rmap-match-condition/metric"));
	} else if (IS_MATCH_TAG(condition)) {
		uint32_t tag =
			strtoul(yang_dnode_get_string(dnode,
						      "./rmap-match-condition/tag"),
				NULL, 10);

		if (!tag)
			vty_out(vty, " match tag untagged\n");
		else
			vty_out(vty, " match tag %u\n", tag);
	} else if (IS_MATCH_IPv4_PREFIX_LEN(condition)) {
		vty_out(vty, " match ip address prefix-len %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-zebra-route-map:ipv4-prefix-length"));
	} else if (IS_MATCH_IPv6_PREFIX_LEN(condition)) {
		vty_out(vty, " match ipv6 address prefix-len %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-zebra-route-map:ipv6-prefix-length"));
	} else if (IS_MATCH_IPv4_NH_PREFIX_LEN(condition)) {
		vty_out(vty, " match ip next-hop prefix-len %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-zebra-route-map:ipv4-prefix-length"));
	} else if (IS_MATCH_SRC_PROTO(condition) ||
		   IS_MATCH_BGP_SRC_PROTO(condition)) {
		vty_out(vty, " match source-protocol %s\n",
			yang_dnode_get_string(
				dnode,
				IS_MATCH_SRC_PROTO(condition)
					? "./rmap-match-condition/frr-zebra-route-map:source-protocol"
					: "./rmap-match-condition/frr-bgp-route-map:source-protocol"));
	} else if (IS_MATCH_SRC_INSTANCE(condition)) {
		vty_out(vty, " match source-instance %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-zebra-route-map:source-instance"));
	} else if (IS_MATCH_LOCAL_PREF(condition)) {
		vty_out(vty, " match local-preference %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:local-preference"));
	} else if (IS_MATCH_ALIAS(condition)) {
		vty_out(vty, " match alias %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:alias"));
	} else if (IS_MATCH_SCRIPT(condition)) {
		vty_out(vty, " match script %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:script"));
	} else if (IS_MATCH_ORIGIN(condition)) {
		vty_out(vty, " match origin %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:origin"));
	} else if (IS_MATCH_RPKI(condition)) {
		vty_out(vty, " match rpki %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:rpki"));
	} else if (IS_MATCH_RPKI_EXTCOMMUNITY(condition)) {
		vty_out(vty, " match rpki-extcommunity %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:rpki-extcommunity"));
	} else if (IS_MATCH_PROBABILITY(condition)) {
		vty_out(vty, " match probability %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:probability"));
	} else if (IS_MATCH_SRC_VRF(condition)) {
		vty_out(vty, " match source-vrf %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:source-vrf"));
	} else if (IS_MATCH_PEER(condition)) {
		acl = NULL;
		if ((ln = yang_dnode_get(
			     dnode,
			     "./rmap-match-condition/frr-bgp-route-map:peer-ipv4-address"))
		    != NULL)
			acl = yang_dnode_get_string(ln, NULL);
		else if (
			(ln = yang_dnode_get(
				 dnode,
				 "./rmap-match-condition/frr-bgp-route-map:peer-ipv6-address"))
			!= NULL)
			acl = yang_dnode_get_string(ln, NULL);
		else if (
			(ln = yang_dnode_get(
				 dnode,
				 "./rmap-match-condition/frr-bgp-route-map:peer-interface"))
			!= NULL)
			acl = yang_dnode_get_string(ln, NULL);
		else if (yang_dnode_get(
				 dnode,
				 "./rmap-match-condition/frr-bgp-route-map:peer-local")
			!= NULL)
			acl = "local";

		vty_out(vty, " match peer %s\n", acl);
	} else if (IS_MATCH_AS_LIST(condition)) {
		vty_out(vty, " match as-path %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:list-name"));
	} else if (IS_MATCH_EVPN_ROUTE_TYPE(condition)) {
		vty_out(vty, " match evpn route-type %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:evpn-route-type"));
	} else if (IS_MATCH_EVPN_DEFAULT_ROUTE(condition)) {
		vty_out(vty, " match evpn default-route\n");
	} else if (IS_MATCH_EVPN_VNI(condition)) {
		vty_out(vty, " match evpn vni %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:evpn-vni"));
	} else if (IS_MATCH_EVPN_DEFAULT_ROUTE(condition)) {
		vty_out(vty, " match evpn default-route %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:evpn-default-route"));
	} else if (IS_MATCH_EVPN_RD(condition)) {
		vty_out(vty, " match evpn rd %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:route-distinguisher"));
	} else if (IS_MATCH_MAC_LIST(condition)) {
		vty_out(vty, " match mac address %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:list-name"));
	} else if (IS_MATCH_ROUTE_SRC(condition)) {
		vty_out(vty, " match ip route-source %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:list-name"));
	} else if (IS_MATCH_ROUTE_SRC_PL(condition)) {
		vty_out(vty, " match ip route-source prefix-list %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:list-name"));
	} else if (IS_MATCH_COMMUNITY(condition)) {
		vty_out(vty, " match community %s",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name"));
		if (yang_dnode_get_bool(
			    dnode,
			    "./rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-exact-match"))
			vty_out(vty, " exact-match");
		if (yang_dnode_get_bool(
			    dnode,
			    "./rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-any"))
			vty_out(vty, " any");
		vty_out(vty, "\n");
	} else if (IS_MATCH_LCOMMUNITY(condition)) {
		vty_out(vty, " match large-community %s",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name"));
		if (yang_dnode_get_bool(
			    dnode,
			    "./rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-exact-match"))
			vty_out(vty, " exact-match");
		if (yang_dnode_get_bool(
			    dnode,
			    "./rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-any"))
			vty_out(vty, " any");
		vty_out(vty, "\n");
	} else if (IS_MATCH_EXTCOMMUNITY(condition)) {
		vty_out(vty, " match extcommunity %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name"));
	} else if (IS_MATCH_IPV4_NH(condition)) {
		vty_out(vty, " match ip next-hop address %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:ipv4-address"));
	} else if (IS_MATCH_IPV6_NH(condition)) {
		vty_out(vty, " match ipv6 next-hop address %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-match-condition/frr-bgp-route-map:ipv6-address"));
	}
}

DEFPY_YANG(
	set_ip_nexthop, set_ip_nexthop_cmd,
	"set ip next-hop A.B.C.D$addr",
	SET_STR
	IP_STR
	"Next hop address\n"
	"IP address of next hop\n")
{
	const char *xpath =
		"./set-action[action='frr-route-map:ipv4-next-hop']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/ipv4-address", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, addr_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_set_ip_nexthop, no_set_ip_nexthop_cmd,
	"no set ip next-hop [A.B.C.D]",
	NO_STR
	SET_STR
	IP_STR
	"Next hop address\n"
	"IP address of next hop\n")
{
	const char *xpath =
		"./set-action[action='frr-route-map:ipv4-next-hop']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	set_ipv6_nexthop_local, set_ipv6_nexthop_local_cmd,
	"set ipv6 next-hop local X:X::X:X$addr",
	SET_STR
	IPV6_STR
	"IPv6 next-hop address\n"
	"IPv6 local address\n"
	"IPv6 address of next hop\n")
{
	const char *xpath =
		"./set-action[action='frr-route-map:ipv6-next-hop']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/ipv6-address", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, addr_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_set_ipv6_nexthop_local, no_set_ipv6_nexthop_local_cmd,
	"no set ipv6 next-hop local [X:X::X:X]",
	NO_STR
	SET_STR
	IPV6_STR
	"IPv6 next-hop address\n"
	"IPv6 local address\n"
	"IPv6 address of next hop\n")
{
	const char *xpath =
		"./set-action[action='frr-route-map:ipv6-next-hop']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	set_metric, set_metric_cmd,
	"set metric <(-4294967295-4294967295)$metric|rtt$rtt|+rtt$artt|-rtt$srtt>",
	SET_STR
	"Metric value for destination routing protocol\n"
	"Metric value (use +/- for additions or subtractions)\n"
	"Assign round trip time\n"
	"Add round trip time\n"
	"Subtract round trip time\n")
{
	const char *xpath = "./set-action[action='frr-route-map:set-metric']";
	char xpath_value[XPATH_MAXLEN];
	char value[64];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (rtt) {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/use-round-trip-time", xpath);
		snprintf(value, sizeof(value), "true");
	} else if (artt) {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/add-round-trip-time", xpath);
		snprintf(value, sizeof(value), "true");
	} else if (srtt) {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/subtract-round-trip-time", xpath);
		snprintf(value, sizeof(value), "true");
	} else if (metric_str && metric_str[0] == '+') {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/add-metric", xpath);
		snprintf(value, sizeof(value), "%s", ++metric_str);
	} else if (metric_str && metric_str[0] == '-') {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/subtract-metric", xpath);
		snprintf(value, sizeof(value), "%s", ++metric_str);
	} else {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/value", xpath);
		snprintf(value, sizeof(value), "%s", metric_str);
	}
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_set_metric, no_set_metric_cmd,
	"no set metric [OPTVAL]",
	NO_STR
	SET_STR
	"Metric value for destination routing protocol\n"
	"Metric value\n")
{
	const char *xpath = "./set-action[action='frr-route-map:set-metric']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(set_min_metric, set_min_metric_cmd,
	   "set min-metric <(0-4294967295)$metric>",
	   SET_STR
	   "Minimum metric value for destination routing protocol\n"
	   "Minimum metric value\n")
{
	const char *xpath =
		"./set-action[action='frr-route-map:set-min-metric']";
	char xpath_value[XPATH_MAXLEN];
	char value[64];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/min-metric", xpath);
	snprintf(value, sizeof(value), "%s", metric_str);

	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_set_min_metric, no_set_min_metric_cmd,
	   "no set min-metric [(0-4294967295)]",
	   NO_STR SET_STR
	   "Minimum metric value for destination routing protocol\n"
	   "Minumum metric value\n")
{
	const char *xpath =
		"./set-action[action='frr-route-map:set-min-metric']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(set_max_metric, set_max_metric_cmd,
	   "set max-metric <(0-4294967295)$metric>",
	   SET_STR
	   "Maximum metric value for destination routing protocol\n"
	   "Miximum metric value\n")
{
	const char *xpath =
		"./set-action[action='frr-route-map:set-max-metric']";
	char xpath_value[XPATH_MAXLEN];
	char value[64];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/max-metric", xpath);
	snprintf(value, sizeof(value), "%s", metric_str);

	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_set_max_metric, no_set_max_metric_cmd,
	   "no set max-metric [(0-4294967295)]",
	   NO_STR SET_STR
	   "Maximum Metric value for destination routing protocol\n"
	   "Maximum metric value\n")
{
	const char *xpath =
		"./set-action[action='frr-route-map:set-max-metric']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	set_tag, set_tag_cmd,
	"set tag <untagged$untagged|(1-4294967295)$tagged>",
	SET_STR
	"Tag value for routing protocol\n"
	"Untagged route\n"
	"Tag value\n")
{
	const char *xpath = "./set-action[action='frr-route-map:set-tag']";
	char xpath_value[XPATH_MAXLEN];
	char value[64];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/rmap-set-action/tag",
		 xpath);
	snprintf(value, sizeof(value), "%lu", tagged ? tagged : 0);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_set_tag, no_set_tag_cmd,
	"no set tag [<untagged|(1-4294967295)>]",
	NO_STR
	SET_STR
	"Tag value for routing protocol\n"
	"Untagged route\n"
	"Tag value\n")
{
	const char *xpath = "./set-action[action='frr-route-map:set-tag']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_srte_color,
	    set_srte_color_cmd,
	    "set sr-te color (1-4294967295)",
	    SET_STR
	    SRTE_STR
	    SRTE_COLOR_STR
	    "Color of the SR-TE Policies to match with\n")
{
	const char *xpath =
		"./set-action[action='frr-route-map:set-sr-te-color']";
	char xpath_value[XPATH_MAXLEN];
	int idx = 0;

	char *arg = argv_find(argv, argc, "(1-4294967295)", &idx)
		? argv[idx]->arg
		: NULL;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/policy", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_srte_color,
	    no_set_srte_color_cmd,
	    "no set sr-te color [(1-4294967295)]",
	    NO_STR
	    SET_STR
	    SRTE_STR
	    SRTE_COLOR_STR
	    "Color of the SR-TE Policies to match with\n")
{
	const char *xpath =
		"./set-action[action='frr-route-map:set-sr-te-color']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}


void route_map_action_show(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	const char *action = yang_dnode_get_string(dnode, "action");
	const struct lyd_node *ln;
	const char *acl;

	if (IS_SET_IPv4_NH(action)) {
		vty_out(vty, " set ip next-hop %s\n",
			yang_dnode_get_string(
				dnode, "./rmap-set-action/ipv4-address"));
	} else if (IS_SET_IPv6_NH(action)) {
		vty_out(vty, " set ipv6 next-hop local %s\n",
			yang_dnode_get_string(
				dnode, "./rmap-set-action/ipv6-address"));
	} else if (IS_SET_METRIC(action)) {
		if (yang_dnode_get(dnode,
				   "./rmap-set-action/use-round-trip-time")) {
			vty_out(vty, " set metric rtt\n");
		} else if (yang_dnode_get(
				   dnode,
				   "./rmap-set-action/add-round-trip-time")) {
			vty_out(vty, " set metric +rtt\n");
		} else if (
			yang_dnode_get(
				dnode,
				"./rmap-set-action/subtract-round-trip-time")) {
			vty_out(vty, " set metric -rtt\n");
		} else if (yang_dnode_get(dnode,
					  "./rmap-set-action/add-metric")) {
			vty_out(vty, " set metric +%s\n",
				yang_dnode_get_string(
					dnode, "./rmap-set-action/add-metric"));
		} else if (yang_dnode_get(
				   dnode,
				   "./rmap-set-action/subtract-metric")) {
			vty_out(vty, " set metric -%s\n",
				yang_dnode_get_string(
					dnode,
					"./rmap-set-action/subtract-metric"));
		} else {
			vty_out(vty, " set metric %s\n",
				yang_dnode_get_string(
					dnode, "./rmap-set-action/value"));
		}
	} else if (IS_SET_MIN_METRIC(action)) {
		vty_out(vty, " set min-metric %s\n",
			yang_dnode_get_string(dnode,
					      "./rmap-set-action/min-metric"));
	} else if (IS_SET_MAX_METRIC(action)) {
		vty_out(vty, " set max-metric %s\n",
			yang_dnode_get_string(dnode,
					      "./rmap-set-action/max-metric"));
	} else if (IS_SET_TAG(action)) {
		uint32_t tag =
			strtoul(yang_dnode_get_string(dnode,
						      "rmap-set-action/tag"),
				NULL, 10);

		if (!tag)
			vty_out(vty, " set tag untagged\n");
		else
			vty_out(vty, " set tag %u\n", tag);
	} else if (IS_SET_SR_TE_COLOR(action)) {
		vty_out(vty, " set sr-te color %s\n",
			yang_dnode_get_string(dnode,
					      "./rmap-set-action/policy"));
	} else if (IS_SET_SRC(action)) {
		if (yang_dnode_exists(
			    dnode,
			    "./rmap-set-action/frr-zebra-route-map:ipv4-src-address"))
			vty_out(vty, " set src %s\n",
				yang_dnode_get_string(
					dnode,
					"./rmap-set-action/frr-zebra-route-map:ipv4-src-address"));
		else
			vty_out(vty, " set src %s\n",
				yang_dnode_get_string(
					dnode,
					"./rmap-set-action/frr-zebra-route-map:ipv6-src-address"));
	} else if (IS_SET_METRIC_TYPE(action)) {
		vty_out(vty, " set metric-type %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-ospf-route-map:metric-type"));
	} else if (IS_SET_FORWARDING_ADDR(action)) {
		vty_out(vty, " set forwarding-address %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-ospf6-route-map:ipv6-address"));
	} else if (IS_SET_WEIGHT(action)) {
		vty_out(vty, " set weight %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:weight"));
	} else if (IS_SET_TABLE(action)) {
		vty_out(vty, " set table %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:table"));
	} else if (IS_SET_LOCAL_PREF(action)) {
		vty_out(vty, " set local-preference %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:local-pref"));
	} else if (IS_SET_LABEL_INDEX(action)) {
		vty_out(vty, " set label-index %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:label-index"));
	} else if (IS_SET_DISTANCE(action)) {
		vty_out(vty, " set distance %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:distance"));
	} else if (IS_SET_ORIGIN(action)) {
		vty_out(vty, " set origin %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:origin"));
	} else if (IS_SET_ATOMIC_AGGREGATE(action)) {
		vty_out(vty, " set atomic-aggregate\n");
	} else if (IS_SET_AIGP_METRIC(action)) {
		vty_out(vty, " set aigp-metric %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:aigp-metric"));
	} else if (IS_SET_ORIGINATOR_ID(action)) {
		vty_out(vty, " set originator-id %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:originator-id"));
	} else if (IS_SET_COMM_LIST_DEL(action)) {
		acl = NULL;
		if ((ln = yang_dnode_get(
				 dnode,
				 "./rmap-set-action/frr-bgp-route-map:comm-list-name"))
			!= NULL)
			acl = yang_dnode_get_string(ln, NULL);

		assert(acl);

		vty_out(vty, " set comm-list %s delete\n", acl);
	} else if (IS_SET_LCOMM_LIST_DEL(action)) {
		acl = NULL;
		if ((ln = yang_dnode_get(
				 dnode,
				 "./rmap-set-action/frr-bgp-route-map:comm-list-name"))
			!= NULL)
			acl = yang_dnode_get_string(ln, NULL);

		assert(acl);

		vty_out(vty, " set large-comm-list %s delete\n", acl);
	} else if (IS_SET_EXTCOMM_LIST_DEL(action)) {
		acl = NULL;
		ln = yang_dnode_get(dnode, "rmap-set-action/frr-bgp-route-map:comm-list-name");

		if (ln)
			acl = yang_dnode_get_string(ln, NULL);

		assert(acl);

		vty_out(vty, " set extended-comm-list %s delete\n", acl);
	} else if (IS_SET_LCOMMUNITY(action)) {
		if (yang_dnode_exists(
			    dnode,
			    "./rmap-set-action/frr-bgp-route-map:large-community-string"))
			vty_out(vty, " set large-community %s\n",
				yang_dnode_get_string(
					dnode,
					"./rmap-set-action/frr-bgp-route-map:large-community-string"));
		else {
			if (true
			    == yang_dnode_get_bool(
				    dnode,
				    "./rmap-set-action/frr-bgp-route-map:large-community-none"))
				vty_out(vty, " set large-community none\n");
		}
	} else if (IS_SET_COMMUNITY(action)) {
		if (yang_dnode_exists(
			    dnode,
			    "./rmap-set-action/frr-bgp-route-map:community-string"))
			vty_out(vty, " set community %s\n",
				yang_dnode_get_string(
					dnode,
					"./rmap-set-action/frr-bgp-route-map:community-string"));
		else {
			if (true
			    == yang_dnode_get_bool(
				    dnode,
				    "./rmap-set-action/frr-bgp-route-map:community-none"))
				vty_out(vty, " set community none\n");
		}
	} else if (IS_SET_EXTCOMMUNITY_RT(action)) {
		vty_out(vty, " set extcommunity rt %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:extcommunity-rt"));
	} else if (IS_SET_EXTCOMMUNITY_NT(action)) {
		vty_out(vty, " set extcommunity nt %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:extcommunity-nt"));
	} else if (IS_SET_EXTCOMMUNITY_SOO(action)) {
		vty_out(vty, " set extcommunity soo %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:extcommunity-soo"));
	} else if (IS_SET_EXTCOMMUNITY_LB(action)) {
		enum ecommunity_lb_type lb_type;
		char str[VTY_BUFSIZ];
		uint32_t bandwidth;

		lb_type = yang_dnode_get_enum(
			dnode,
			"./rmap-set-action/frr-bgp-route-map:extcommunity-lb/lb-type");
		switch (lb_type) {
		case EXPLICIT_BANDWIDTH:
			bandwidth = yang_dnode_get_uint32(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:extcommunity-lb/bandwidth");
			snprintf(str, sizeof(str), "%d", bandwidth);
			break;
		case CUMULATIVE_BANDWIDTH:
			snprintf(str, sizeof(str), "%s", "cumulative");
			break;
		case COMPUTED_BANDWIDTH:
			snprintf(str, sizeof(str), "%s", "num-multipaths");
		}

		if (yang_dnode_get_bool(
			    dnode,
			    "./rmap-set-action/frr-bgp-route-map:extcommunity-lb/two-octet-as-specific"))
			strlcat(str, " non-transitive", sizeof(str));

		vty_out(vty, " set extcommunity bandwidth %s\n", str);
	} else if (IS_SET_EXTCOMMUNITY_COLOR(action)) {
		vty_out(vty, " set extcommunity color %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:extcommunity-color"));
	} else if (IS_SET_EXTCOMMUNITY_NONE(action)) {
		if (yang_dnode_get_bool(
			    dnode,
			    "./rmap-set-action/frr-bgp-route-map:extcommunity-none"))
			vty_out(vty, " set extcommunity none\n");
	} else if (IS_SET_AGGREGATOR(action)) {
		vty_out(vty, " set aggregator as %s %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:aggregator/aggregator-asn"),
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:aggregator/aggregator-address"));
	} else if (IS_SET_AS_EXCLUDE(action)) {
		vty_out(vty, " set as-path exclude %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:exclude-as-path"));
	} else if (IS_SET_AS_REPLACE(action)) {
		vty_out(vty, " set as-path replace %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:replace-as-path"));
	} else if (IS_SET_AS_PREPEND(action)) {
		if (yang_dnode_exists(
			    dnode,
			    "./rmap-set-action/frr-bgp-route-map:prepend-as-path"))
			vty_out(vty, " set as-path prepend %s\n",
				yang_dnode_get_string(
					dnode,
					"./rmap-set-action/frr-bgp-route-map:prepend-as-path"));
		else {
			vty_out(vty, " set as-path prepend last-as %u\n",
				yang_dnode_get_uint8(
					dnode,
					"./rmap-set-action/frr-bgp-route-map:last-as"));
		}
	} else if (IS_SET_IPV6_NH_GLOBAL(action)) {
		vty_out(vty, " set ipv6 next-hop global %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:ipv6-address"));
	} else if (IS_SET_IPV6_VPN_NH(action)) {
		vty_out(vty, " set ipv6 vpn next-hop %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:ipv6-address"));
	} else if (IS_SET_IPV6_PEER_ADDR(action)) {
		if (true
		    == yang_dnode_get_bool(
			    dnode,
			    "./rmap-set-action/frr-bgp-route-map:preference"))
			vty_out(vty, " set ipv6 next-hop peer-address\n");
	} else if (IS_SET_IPV6_PREFER_GLOBAL(action)) {
		if (true
		    == yang_dnode_get_bool(
			    dnode,
			    "./rmap-set-action/frr-bgp-route-map:preference"))
			vty_out(vty, " set ipv6 next-hop prefer-global\n");
	} else if (IS_SET_IPV4_VPN_NH(action)) {
		vty_out(vty, " set ipv4 vpn next-hop %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:ipv4-address"));
	} else if (IS_SET_BGP_IPV4_NH(action)) {
		vty_out(vty, " set ip next-hop %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:ipv4-nexthop"));
	} else if (IS_SET_BGP_EVPN_GATEWAY_IP_IPV4(action)) {
		vty_out(vty, " set evpn gateway-ip ipv4 %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:evpn-gateway-ip-ipv4"));
	} else if (IS_SET_BGP_EVPN_GATEWAY_IP_IPV6(action)) {
		vty_out(vty, " set evpn gateway-ip ipv6 %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:evpn-gateway-ip-ipv6"));
	} else if (IS_SET_BGP_L3VPN_NEXTHOP_ENCAPSULATION(action)) {
		vty_out(vty, " set l3vpn next-hop encapsulation %s\n",
			yang_dnode_get_string(
				dnode,
				"./rmap-set-action/frr-bgp-route-map:l3vpn-nexthop-encapsulation"));
	}
}

DEFPY_YANG(
	rmap_onmatch_next, rmap_onmatch_next_cmd,
	"on-match next",
	"Exit policy on matches\n"
	"Next clause\n")
{
	nb_cli_enqueue_change(vty, "./exit-policy", NB_OP_MODIFY, "next");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_rmap_onmatch_next,
	no_rmap_onmatch_next_cmd,
	"no on-match next",
	NO_STR
	"Exit policy on matches\n"
	"Next clause\n")
{
	nb_cli_enqueue_change(vty, "./exit-policy", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	rmap_onmatch_goto, rmap_onmatch_goto_cmd,
	"on-match goto (1-65535)$rm_num",
	"Exit policy on matches\n"
	"Goto Clause number\n"
	"Number\n")
{
	nb_cli_enqueue_change(vty, "./exit-policy", NB_OP_MODIFY, "goto");
	nb_cli_enqueue_change(vty, "./goto-value", NB_OP_MODIFY, rm_num_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_rmap_onmatch_goto, no_rmap_onmatch_goto_cmd,
	"no on-match goto",
	NO_STR
	"Exit policy on matches\n"
	"Goto Clause number\n")
{
	nb_cli_enqueue_change(vty, "./exit-policy", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* Cisco/GNU Zebra compatibility aliases */
ALIAS_YANG(
	rmap_onmatch_goto, rmap_continue_cmd,
	"continue (1-65535)$rm_num",
	"Continue on a different entry within the route-map\n"
	"Route-map entry sequence number\n")

ALIAS_YANG(
	no_rmap_onmatch_goto, no_rmap_continue_cmd,
	"no continue [(1-65535)]",
	NO_STR
	"Continue on a different entry within the route-map\n"
	"Route-map entry sequence number\n")

void route_map_exit_policy_show(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	int exit_policy = yang_dnode_get_enum(dnode, NULL);

	switch (exit_policy) {
	case 0: /* permit-or-deny */
		/* NOTHING: default option. */
		break;
	case 1: /* next */
		vty_out(vty, " on-match next\n");
		break;
	case 2: /* goto */
		vty_out(vty, " on-match goto %s\n",
			yang_dnode_get_string(dnode, "../goto-value"));
		break;
	}
}

DEFPY_YANG(
	rmap_call, rmap_call_cmd,
	"call WORD$name",
	"Jump to another Route-Map after match+set\n"
	"Target route-map name\n")
{
	nb_cli_enqueue_change(vty, "./call", NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_rmap_call, no_rmap_call_cmd,
	"no call [NAME]",
	NO_STR
	"Jump to another Route-Map after match+set\n"
	"Target route-map name\n")
{
	nb_cli_enqueue_change(vty, "./call", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void route_map_call_show(struct vty *vty, const struct lyd_node *dnode,
			 bool show_defaults)
{
	vty_out(vty, " call %s\n", yang_dnode_get_string(dnode, NULL));
}

DEFPY_YANG(
	rmap_description, rmap_description_cmd,
	"description LINE...",
	"Route-map comment\n"
	"Comment describing this route-map rule\n")
{
	char *desc;
	int rv;

	desc = argv_concat(argv, argc, 1);
	nb_cli_enqueue_change(vty, "./description", NB_OP_MODIFY, desc);
	rv = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, desc);

	return rv;
}

DEFUN_YANG (no_rmap_description,
       no_rmap_description_cmd,
       "no description",
       NO_STR
       "Route-map comment\n")
{
	nb_cli_enqueue_change(vty, "./description", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void route_map_description_show(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, " description %s\n", yang_dnode_get_string(dnode, NULL));
}

DEFPY_YANG(
	route_map_optimization, route_map_optimization_cmd,
	"[no] route-map RMAP_NAME$name optimization",
	NO_STR
	ROUTE_MAP_CMD_STR
	"Configure route-map optimization\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-route-map:lib/route-map[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(
		xpath, sizeof(xpath),
		"/frr-route-map:lib/route-map[name='%s']/optimization-disabled",
		name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, no ? "true" : "false");

	return nb_cli_apply_changes(vty, NULL);
}

void route_map_optimization_disabled_show(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "../name");
	const bool disabled = yang_dnode_get_bool(dnode, NULL);

	vty_out(vty, "%sroute-map %s optimization\n", disabled ? "no " : "",
		name);
}

static int route_map_config_write(struct vty *vty)
{
	const struct lyd_node *dnode;
	int written = 0;

	dnode = yang_dnode_get(running_config->dnode,
			       "/frr-route-map:lib");
	if (dnode) {
		nb_cli_show_dnode_cmds(vty, dnode, false);
		written = 1;
	}

	return written;
}

/* Route map node structure. */
static int route_map_config_write(struct vty *vty);
static struct cmd_node rmap_node = {
	.name = "routemap",
	.node = RMAP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-route-map)# ",
	.config_write = route_map_config_write,
};

static void rmap_autocomplete(vector comps, struct cmd_token *token)
{
	struct route_map *map;

	for (map = route_map_master.head; map; map = map->next)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, map->name));
}

static const struct cmd_variable_handler rmap_var_handlers[] = {
	{.varname = "route_map", .completions = rmap_autocomplete},
	{.tokenname = "ROUTEMAP_NAME", .completions = rmap_autocomplete},
	{.tokenname = "RMAP_NAME", .completions = rmap_autocomplete},
	{.completions = NULL}
};

void route_map_cli_init(void)
{
	/* Auto complete handler. */
	cmd_variable_handler_register(rmap_var_handlers);

	/* CLI commands. */
	install_node(&rmap_node);
	install_default(RMAP_NODE);
	install_element(CONFIG_NODE, &route_map_cmd);
	install_element(CONFIG_NODE, &no_route_map_cmd);
	install_element(CONFIG_NODE, &no_route_map_all_cmd);
	install_element(CONFIG_NODE, &route_map_optimization_cmd);

	/* Install the on-match stuff */
	install_element(RMAP_NODE, &rmap_onmatch_next_cmd);
	install_element(RMAP_NODE, &no_rmap_onmatch_next_cmd);
	install_element(RMAP_NODE, &rmap_onmatch_goto_cmd);
	install_element(RMAP_NODE, &no_rmap_onmatch_goto_cmd);
	install_element(RMAP_NODE, &rmap_continue_cmd);
	install_element(RMAP_NODE, &no_rmap_continue_cmd);

	/* Install the call stuff. */
	install_element(RMAP_NODE, &rmap_call_cmd);
	install_element(RMAP_NODE, &no_rmap_call_cmd);

	/* Install description commands. */
	install_element(RMAP_NODE, &rmap_description_cmd);
	install_element(RMAP_NODE, &no_rmap_description_cmd);

	/* Install 'match' commands. */
	install_element(RMAP_NODE, &match_interface_cmd);
	install_element(RMAP_NODE, &no_match_interface_cmd);

	install_element(RMAP_NODE, &match_ip_address_cmd);
	install_element(RMAP_NODE, &no_match_ip_address_cmd);

	install_element(RMAP_NODE, &match_ip_address_prefix_list_cmd);
	install_element(RMAP_NODE, &no_match_ip_address_prefix_list_cmd);

	install_element(RMAP_NODE, &match_ip_next_hop_cmd);
	install_element(RMAP_NODE, &no_match_ip_next_hop_cmd);

	install_element(RMAP_NODE, &match_ip_next_hop_prefix_list_cmd);
	install_element(RMAP_NODE, &no_match_ip_next_hop_prefix_list_cmd);

	install_element(RMAP_NODE, &match_ip_next_hop_type_cmd);
	install_element(RMAP_NODE, &no_match_ip_next_hop_type_cmd);

	install_element(RMAP_NODE, &match_ipv6_address_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_address_cmd);

	install_element(RMAP_NODE, &match_ipv6_address_prefix_list_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_address_prefix_list_cmd);

	install_element(RMAP_NODE, &match_ipv6_next_hop_type_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_next_hop_type_cmd);

	install_element(RMAP_NODE, &match_metric_cmd);
	install_element(RMAP_NODE, &no_match_metric_cmd);

	install_element(RMAP_NODE, &match_tag_cmd);
	install_element(RMAP_NODE, &no_match_tag_cmd);

	/* Install 'set' commands. */
	install_element(RMAP_NODE, &set_ip_nexthop_cmd);
	install_element(RMAP_NODE, &no_set_ip_nexthop_cmd);

	install_element(RMAP_NODE, &set_ipv6_nexthop_local_cmd);
	install_element(RMAP_NODE, &no_set_ipv6_nexthop_local_cmd);

	install_element(RMAP_NODE, &set_metric_cmd);
	install_element(RMAP_NODE, &no_set_metric_cmd);

	install_element(RMAP_NODE, &set_min_metric_cmd);
	install_element(RMAP_NODE, &no_set_min_metric_cmd);

	install_element(RMAP_NODE, &set_max_metric_cmd);
	install_element(RMAP_NODE, &no_set_max_metric_cmd);

	install_element(RMAP_NODE, &set_tag_cmd);
	install_element(RMAP_NODE, &no_set_tag_cmd);

	install_element(RMAP_NODE, &set_srte_color_cmd);
	install_element(RMAP_NODE, &no_set_srte_color_cmd);
}
