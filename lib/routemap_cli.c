/*
 * Route map northbound CLI implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/northbound_cli.h"
#include "lib/routemap.h"

#ifndef VTYSH_EXTRACT_PL
#include "lib/routemap_cli_clippy.c"
#endif /* VTYSH_EXTRACT_PL */

#define ROUTE_MAP_CMD_STR \
	"Create route-map or enter route-map command mode\n" \
	"Route map tag\n"
#define ROUTE_MAP_OP_CMD_STR \
	"Route map denies set operations\n" \
	"Route map permits set operations\n"
#define ROUTE_MAP_SEQUENCE_CMD_STR \
	"Sequence to insert to/delete from existing route-map entry\n"

DEFPY_NOSH(
	route_map, route_map_cmd,
	"route-map WORD$name <deny|permit>$action (1-65535)$sequence",
	ROUTE_MAP_CMD_STR
	ROUTE_MAP_OP_CMD_STR
	ROUTE_MAP_SEQUENCE_CMD_STR)
{
	struct route_map_index *rmi;
	struct route_map *rm;
	int action_type;
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
	if (rv == CMD_SUCCESS) {
		VTY_PUSH_XPATH(RMAP_NODE, xpath_index);

		/* Add support for non-migrated route map users. */
		rm = route_map_get(name);
		action_type = (action[0] == 'p') ? RMAP_PERMIT : RMAP_DENY;
		rmi = route_map_index_get(rm, action_type, sequence);
		VTY_PUSH_CONTEXT(RMAP_NODE, rmi);
	}

	return rv;
}

DEFPY(
	no_route_map_all, no_route_map_all_cmd,
	"no route-map WORD$name",
	NO_STR
	ROUTE_MAP_CMD_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-route-map:lib/route-map[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_route_map, no_route_map_cmd,
	"no route-map WORD$name <deny|permit>$action (1-65535)$sequence",
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

void route_map_instance_show(struct vty *vty, struct lyd_node *dnode,
			     bool show_defaults)
{
	const struct route_map_rule *rmr;
	const struct route_map_index *rmi;
	const char *name = yang_dnode_get_string(dnode, "../name");
	const char *action = yang_dnode_get_string(dnode, "./action");
	const char *sequence = yang_dnode_get_string(dnode, "./sequence");

	vty_out(vty, "route-map %s %s %s\n", name, action, sequence);

	rmi = nb_running_get_entry(dnode, NULL, false);
	if (rmi == NULL) {
		/*
		 * We can't have outdated rules if route map hasn't
		 * been created yet.
		 */
		return;
	}

#define SKIP_RULE(name) if (strcmp((name), rmr->cmd->str) == 0) continue

	/* Print route map `match` for old CLI users. */
	for (rmr = rmi->match_list.head; rmr; rmr = rmr->next) {
		/* Skip all matches implemented by northbound. */
		SKIP_RULE("interface");
		SKIP_RULE("ip address");
		SKIP_RULE("ip address prefix-list");
		SKIP_RULE("ip next-hop");
		SKIP_RULE("ip next-hop prefix-list");
		SKIP_RULE("ip next-hop type");
		SKIP_RULE("ipv6 address");
		SKIP_RULE("ipv6 address prefix-list");
		SKIP_RULE("ipv6 next-hop type");
		SKIP_RULE("metric");
		SKIP_RULE("tag");
		/* Zebra specific match conditions. */
		SKIP_RULE("ip address prefix-len");
		SKIP_RULE("ipv6 address prefix-len");
		SKIP_RULE("ip next-hop prefix-len");
		SKIP_RULE("source-protocol");
		SKIP_RULE("source-instance");

		vty_out(vty, " match %s %s\n", rmr->cmd->str,
			rmr->rule_str ? rmr->rule_str : "");
	}

	/* Print route map `set` for old CLI users. */
	for (rmr = rmi->set_list.head; rmr; rmr = rmr->next) {
		/* Skip all sets implemented by northbound. */
		SKIP_RULE("metric");
		SKIP_RULE("tag");
		/* Zebra specific set actions. */
		SKIP_RULE("src");

		vty_out(vty, " set %s %s\n", rmr->cmd->str,
			rmr->rule_str ? rmr->rule_str : "");
	}

#undef SKIP_RULE
}

void route_map_instance_show_end(struct vty *vty, struct lyd_node *dnode)
{
	vty_out(vty, "!\n");
}

DEFPY(
	match_interface, match_interface_cmd,
	"match interface IFNAME",
	MATCH_STR
	"Match first hop interface of route\n"
	INTERFACE_STR)
{
	const char *xpath = "./match-condition[condition='interface']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/interface", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, ifname);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_match_interface, no_match_interface_cmd,
	"no match interface [IFNAME]",
	NO_STR
	MATCH_STR
	"Match first hop interface of route\n"
	INTERFACE_STR)
{
	const char *xpath = "./match-condition[condition='interface']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	match_ip_address, match_ip_address_cmd,
	"match ip address <(1-199)$acll|(1300-2699)$aclh|WORD$name>",
	MATCH_STR
	IP_STR
	"Match address of route\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP Access-list name\n")
{
	const char *xpath = "./match-condition[condition='ipv4-address-list']";
	char xpath_value[XPATH_MAXLEN + 32];
	int acln = acll ? acll : aclh;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (name) {
		snprintf(xpath_value, sizeof(xpath_value), "%s/list-name",
			 xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);
	} else /* if (acll || aclh) */ {
		if ((acln >= 1 && acln <= 99)
		    || (acln >= 1300 && acln <= 1999)) {
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/access-list-num", xpath);
		} else {
			/*
			 * if ((acln >= 100 && acln <= 199)
			 *     || (acln >= 2000 && acln <= 2699))
			 */
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/access-list-num-extended", xpath);
		}
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      acll_str ? acll_str : aclh_str);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_match_ip_address, no_match_ip_address_cmd,
	"no match ip address [<(1-199)|(1300-2699)|WORD>]",
	NO_STR
	MATCH_STR
	IP_STR
	"Match address of route\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP Access-list name\n")
{
	const char *xpath = "./match-condition[condition='ipv4-address-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	match_ip_address_prefix_list,
	match_ip_address_prefix_list_cmd,
	"match ip address prefix-list WORD$name",
	MATCH_STR
	IP_STR
	"Match address of route\n"
	"Match entries of prefix-lists\n"
	"IP prefix-list name\n")
{
	const char *xpath = "./match-condition[condition='ipv4-prefix-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_match_ip_address_prefix_list, no_match_ip_address_prefix_list_cmd,
	"no match ip address prefix-list [WORD]",
	NO_STR
	MATCH_STR
	IP_STR
	"Match address of route\n"
	"Match entries of prefix-lists\n"
	"IP prefix-list name\n")
{
	const char *xpath = "./match-condition[condition='ipv4-prefix-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	match_ip_next_hop, match_ip_next_hop_cmd,
	"match ip next-hop <(1-199)$acll|(1300-2699)$aclh|WORD$name>",
	MATCH_STR
	IP_STR
	"Match next-hop address of route\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP Access-list name\n")
{
	const char *xpath = "./match-condition[condition='ipv4-next-hop-list']";
	char xpath_value[XPATH_MAXLEN + 32];
	int acln = acll ? acll : aclh;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (name) {
		snprintf(xpath_value, sizeof(xpath_value), "%s/list-name",
			 xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);
	} else /* if (acll || aclh) */ {
		if ((acln >= 1 && acln <= 99)
		    || (acln >= 1300 && acln <= 1999)) {
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/access-list-num", xpath);
		} else {
			/*
			 * if ((acln >= 100 && acln <= 199)
			 *     || (acln >= 2000 && acln <= 2699))
			 */
			snprintf(xpath_value, sizeof(xpath_value),
				 "%s/access-list-num-extended", xpath);
		}
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      acll_str ? acll_str : aclh_str);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_match_ip_next_hop, no_match_ip_next_hop_cmd,
	"no match ip next-hop [<(1-199)|(1300-2699)|WORD>]",
	NO_STR
	MATCH_STR
	IP_STR
	"Match address of route\n"
	"IP access-list number\n"
	"IP access-list number (expanded range)\n"
	"IP Access-list name\n")
{
	const char *xpath = "./match-condition[condition='ipv4-next-hop-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	match_ip_next_hop_prefix_list,
	match_ip_next_hop_prefix_list_cmd,
	"match ip next-hop prefix-list WORD$name",
	MATCH_STR
	IP_STR
	"Match next-hop address of route\n"
	"Match entries of prefix-lists\n"
	"IP prefix-list name\n")
{
	const char *xpath =
		"./match-condition[condition='ipv4-next-hop-prefix-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_match_ip_next_hop_prefix_list,
	no_match_ip_next_hop_prefix_list_cmd,
	"no match ip next-hop prefix-list [WORD]",
	NO_STR
	MATCH_STR
	IP_STR
	"Match next-hop address of route\n"
	"Match entries of prefix-lists\n"
	"IP prefix-list name\n")
{
	const char *xpath =
		"./match-condition[condition='ipv4-next-hop-prefix-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	match_ip_next_hop_type, match_ip_next_hop_type_cmd,
	"match ip next-hop type <blackhole>$type",
	MATCH_STR
	IP_STR
	"Match next-hop address of route\n"
	"Match entries by type\n"
	"Blackhole\n")
{
	const char *xpath = "./match-condition[condition='ipv4-next-hop-type']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/ipv4-next-hop-type",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, type);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_match_ip_next_hop_type, no_match_ip_next_hop_type_cmd,
	"no match ip next-hop type [<blackhole>]",
	NO_STR MATCH_STR IP_STR
	"Match next-hop address of route\n"
	"Match entries by type\n"
	"Blackhole\n")
{
	const char *xpath = "./match-condition[condition='ipv4-next-hop-type']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	match_ipv6_address, match_ipv6_address_cmd,
	"match ipv6 address WORD$name",
	MATCH_STR
	IPV6_STR
	"Match IPv6 address of route\n"
	"IPv6 access-list name\n")
{
	const char *xpath = "./match-condition[condition='ipv6-address-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_match_ipv6_address, no_match_ipv6_address_cmd,
	"no match ipv6 address [WORD]",
	NO_STR
	MATCH_STR
	IPV6_STR
	"Match IPv6 address of route\n"
	"IPv6 access-list name\n")
{
	const char *xpath = "./match-condition[condition='ipv6-address-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	match_ipv6_address_prefix_list, match_ipv6_address_prefix_list_cmd,
	"match ipv6 address prefix-list WORD$name",
	MATCH_STR
	IPV6_STR
	"Match address of route\n"
	"Match entries of prefix-lists\n"
	"IP prefix-list name\n")
{
	const char *xpath = "./match-condition[condition='ipv6-prefix-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_match_ipv6_address_prefix_list,
	no_match_ipv6_address_prefix_list_cmd,
	"no match ipv6 address prefix-list [WORD]",
	NO_STR
	MATCH_STR
	IPV6_STR
	"Match address of route\n"
	"Match entries of prefix-lists\n"
	"IP prefix-list name\n")
{
	const char *xpath = "./match-condition[condition='ipv6-prefix-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	match_ipv6_next_hop_type, match_ipv6_next_hop_type_cmd,
	"match ipv6 next-hop type <blackhole>$type",
	MATCH_STR IPV6_STR
	"Match next-hop address of route\n"
	"Match entries by type\n"
	"Blackhole\n")
{
	const char *xpath = "./match-condition[condition='ipv6-next-hop-type']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/ipv6-next-hop-type",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, type);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_match_ipv6_next_hop_type, no_match_ipv6_next_hop_type_cmd,
	"no match ipv6 next-hop type [<blackhole>]",
	NO_STR MATCH_STR IPV6_STR
	"Match address of route\n"
	"Match entries by type\n"
	"Blackhole\n")
{
	const char *xpath = "./match-condition[condition='ipv6-next-hop-type']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	match_metric, match_metric_cmd,
	"match metric (0-4294967295)$metric",
	MATCH_STR
	"Match metric of route\n"
	"Metric value\n")
{
	const char *xpath = "./match-condition[condition='metric']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/metric", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, metric_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_match_metric, no_match_metric_cmd,
	"no match metric [(0-4294967295)]",
	NO_STR
	MATCH_STR
	"Match metric of route\n"
	"Metric value\n")
{
	const char *xpath = "./match-condition[condition='metric']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	match_tag, match_tag_cmd,
	"match tag (1-4294967295)$tag",
	MATCH_STR
	"Match tag of route\n"
	"Tag value\n")
{
	const char *xpath = "./match-condition[condition='tag']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/tag", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, tag_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_match_tag, no_match_tag_cmd,
	"no match tag [(1-4294967295)]",
	NO_STR
	MATCH_STR
	"Match tag of route\n"
	"Tag value\n")
{
	const char *xpath = "./match-condition[condition='tag']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void route_map_condition_show(struct vty *vty, struct lyd_node *dnode,
			      bool show_defaults)
{
	int condition = yang_dnode_get_enum(dnode, "./condition");
	struct lyd_node *ln;
	const char *acl;

	switch (condition) {
	case 0: /* interface */
		vty_out(vty, " match interface %s\n",
			yang_dnode_get_string(dnode, "./interface"));
		break;
	case 1: /* ipv4-address-list */
	case 3: /* ipv4-next-hop-list */
		acl = NULL;
		if ((ln = yang_dnode_get(dnode, "./list-name")) != NULL)
			acl = yang_dnode_get_string(ln, NULL);
		else if ((ln = yang_dnode_get(dnode, "./access-list-num"))
			 != NULL)
			acl = yang_dnode_get_string(ln, NULL);
		else if ((ln = yang_dnode_get(dnode,
					      "./access-list-num-extended"))
			 != NULL)
			acl = yang_dnode_get_string(ln, NULL);

		assert(acl);

		switch (condition) {
		case 1:
			vty_out(vty, " match ip address %s\n", acl);
			break;
		case 3:
			vty_out(vty, " match ip next-hop %s\n", acl);
			break;
		}
		break;
	case 2: /* ipv4-prefix-list */
		vty_out(vty, " match ip address prefix-list %s\n",
			yang_dnode_get_string(dnode, "./list-name"));
		break;
	case 4: /* ipv4-next-hop-prefix-list */
		vty_out(vty, " match ip next-hop prefix-list %s\n",
			yang_dnode_get_string(dnode, "./list-name"));
		break;
	case 5: /* ipv4-next-hop-type */
		vty_out(vty, " match ip next-hop type %s\n",
			yang_dnode_get_string(dnode, "./ipv4-next-hop-type"));
		break;
	case 6: /* ipv6-address-list */
		vty_out(vty, " match ipv6 address %s\n",
			yang_dnode_get_string(dnode, "./list-name"));
		break;
	case 7: /* ipv6-prefix-list */
		vty_out(vty, " match ipv6 address prefix-list %s\n",
			yang_dnode_get_string(dnode, "./list-name"));
		break;
	case 8: /* ipv6-next-hop-type */
		vty_out(vty, " match ipv6 next-hop type %s\n",
			yang_dnode_get_string(dnode, "./ipv6-next-hop-type"));
		break;
	case 9: /* metric */
		vty_out(vty, " match metric %s\n",
			yang_dnode_get_string(dnode, "./metric"));
		break;
	case 10: /* tag */
		vty_out(vty, " match tag %s\n",
			yang_dnode_get_string(dnode, "./tag"));
		break;
	case 100: /* ipv4-prefix-length */
		vty_out(vty, " match ip address prefix-len %s\n",
			yang_dnode_get_string(dnode,"./frr-zebra:ipv4-prefix-length"));
		break;
	case 101: /* ipv6-prefix-length */
		vty_out(vty, " match ipv6 address prefix-len %s\n",
			yang_dnode_get_string(dnode, "./frr-zebra:ipv6-prefix-length"));
		break;
	case 102: /* ipv4-next-hop-prefix-length */
		vty_out(vty, " match ip next-hop prefix-len %s\n",
			yang_dnode_get_string(dnode, "./frr-zebra:ipv4-prefix-length"));
		break;
	case 103: /* source-protocol */
		vty_out(vty, " match source-protocol %s\n",
			yang_dnode_get_string(dnode, "./frr-zebra:source-protocol"));
		break;
	case 104: /* source-instance */
		vty_out(vty, " match source-instance %s\n",
			yang_dnode_get_string(dnode, "./frr-zebra:source-instance"));
		break;
	}
}

DEFPY(
	set_ip_nexthop, set_ip_nexthop_cmd,
	"set ip next-hop A.B.C.D$addr",
	SET_STR
	IP_STR
	"Next hop address\n"
	"IP address of next hop\n")
{
	const char *xpath = "./set-action[action='ipv4-next-hop']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/ipv4-address", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, addr_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_set_ip_nexthop, no_set_ip_nexthop_cmd,
	"no set ip next-hop [A.B.C.D]",
	NO_STR
	SET_STR
	IP_STR
	"Next hop address\n"
	"IP address of next hop\n")
{
	const char *xpath = "./set-action[action='ipv4-next-hop']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	set_ipv6_nexthop_local, set_ipv6_nexthop_local_cmd,
	"set ipv6 next-hop local X:X::X:X$addr",
	SET_STR
	IPV6_STR
	"IPv6 next-hop address\n"
	"IPv6 local address\n"
	"IPv6 address of next hop\n")
{
	const char *xpath = "./set-action[action='ipv6-next-hop']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/ipv6-address", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, addr_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_set_ipv6_nexthop_local, no_set_ipv6_nexthop_local_cmd,
	"no set ipv6 next-hop local [X:X::X:X]",
	NO_STR
	SET_STR
	IPV6_STR
	"IPv6 next-hop address\n"
	"IPv6 local address\n"
	"IPv6 address of next hop\n")
{
	const char *xpath = "./set-action[action='ipv6-next-hop']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	set_metric, set_metric_cmd,
	"set metric <(0-4294967295)$metric|rtt$rtt|+rtt$artt|-rtt$srtt|+metric$ametric|-metric$smetric>",
	SET_STR
	"Metric value for destination routing protocol\n"
	"Metric value\n"
	"Assign round trip time\n"
	"Add round trip time\n"
	"Subtract round trip time\n"
	"Add metric\n"
	"Subtract metric\n")
{
	const char *xpath = "./set-action[action='metric']";
	char xpath_value[XPATH_MAXLEN];
	char value[64];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (rtt) {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/use-round-trip-time", xpath);
		snprintf(value, sizeof(value), "true");
	} else if (artt) {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/add-round-trip-time", xpath);
		snprintf(value, sizeof(value), "true");
	} else if (srtt) {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/subtract-round-trip-time", xpath);
		snprintf(value, sizeof(value), "true");
	} else if (ametric) {
		snprintf(xpath_value, sizeof(xpath_value), "%s/add-metric",
			 xpath);
		snprintf(value, sizeof(value), "true");
	} else if (smetric) {
		snprintf(xpath_value, sizeof(xpath_value), "%s/subtract-metric",
			 xpath);
		snprintf(value, sizeof(value), "true");
	} else {
		snprintf(xpath_value, sizeof(xpath_value), "%s/value", xpath);
		snprintf(value, sizeof(value), "%lu", metric);
	}
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_set_metric, no_set_metric_cmd,
	"no set metric [(0-4294967295)]",
	NO_STR
	SET_STR
	"Metric value for destination routing protocol\n"
	"Metric value\n")
{
	const char *xpath = "./set-action[action='metric']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	set_tag, set_tag_cmd,
	"set tag (1-4294967295)$tag",
	SET_STR
	"Tag value for routing protocol\n"
	"Tag value\n")
{
	const char *xpath = "./set-action[action='tag']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value), "%s/tag", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, tag_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_set_tag, no_set_tag_cmd,
	"no set tag [(1-4294967295)]",
	NO_STR
	SET_STR
	"Tag value for routing protocol\n"
	"Tag value\n")
{
	const char *xpath = "./set-action[action='tag']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void route_map_action_show(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	int action = yang_dnode_get_enum(dnode, "./action");

	switch (action) {
	case 0: /* ipv4-next-hop */
		vty_out(vty, " set ip next-hop %s\n",
			yang_dnode_get_string(dnode, "./ipv4-address"));
		break;
	case 1: /* ipv6-next-hop */
		vty_out(vty, " set ipv6 next-hop local %s\n",
			yang_dnode_get_string(dnode, "./ipv6-address"));
		break;
	case 2: /* metric */
		if (yang_dnode_get(dnode, "./use-round-trip-time")) {
			vty_out(vty, " set metric rtt\n");
		} else if (yang_dnode_get(dnode, "./add-round-trip-time")) {
			vty_out(vty, " set metric +rtt\n");
		} else if (yang_dnode_get(dnode, "./subtract-round-trip-time")) {
			vty_out(vty, " set metric -rtt\n");
		} else if (yang_dnode_get(dnode, "./add-metric")) {
			vty_out(vty, " set metric +metric\n");
		} else if (yang_dnode_get(dnode, "./subtract-metric")) {
			vty_out(vty, " set metric -metric\n");
		} else {
			vty_out(vty, " set metric %s\n",
				yang_dnode_get_string(dnode, "./value"));
		}
		break;
	case 3: /* tag */
		vty_out(vty, " set tag %s\n",
			yang_dnode_get_string(dnode, "./tag"));
		break;
	case 100: /* source */
		if (yang_dnode_exists(dnode, "./frr-zebra:source-v4"))
			vty_out(vty, " set src %s\n",
				yang_dnode_get_string(dnode, "./frr-zebra:source-v4"));
		else
			vty_out(vty, " set src %s\n",
				yang_dnode_get_string(dnode, "./frr-zebra:source-v6"));
		break;
	}
}

DEFPY(
	rmap_onmatch_next, rmap_onmatch_next_cmd,
	"on-match next",
	"Exit policy on matches\n"
	"Next clause\n")
{
	nb_cli_enqueue_change(vty, "./exit-policy", NB_OP_MODIFY, "next");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
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

DEFPY(
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

DEFPY(
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
ALIAS(
	rmap_onmatch_goto, rmap_continue_cmd,
	"continue (1-65535)$rm_num",
	"Continue on a different entry within the route-map\n"
	"Route-map entry sequence number\n")

ALIAS(
	no_rmap_onmatch_goto, no_rmap_continue_cmd,
	"no continue [(1-65535)]",
	NO_STR
	"Continue on a different entry within the route-map\n"
	"Route-map entry sequence number\n")

void route_map_exit_policy_show(struct vty *vty, struct lyd_node *dnode,
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

DEFPY(
	rmap_call, rmap_call_cmd,
	"call WORD$name",
	"Jump to another Route-Map after match+set\n"
	"Target route-map name\n")
{
	nb_cli_enqueue_change(vty, "./call", NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_rmap_call, no_rmap_call_cmd,
	"no call",
	NO_STR
	"Jump to another Route-Map after match+set\n")
{
	nb_cli_enqueue_change(vty, "./call", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void route_map_call_show(struct vty *vty, struct lyd_node *dnode,
			 bool show_defaults)
{
	vty_out(vty, " call %s\n", yang_dnode_get_string(dnode, NULL));
}

DEFPY(
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

DEFUN (no_rmap_description,
       no_rmap_description_cmd,
       "no description",
       NO_STR
       "Route-map comment\n")
{
	nb_cli_enqueue_change(vty, "./description", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void route_map_description_show(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, " description %s\n", yang_dnode_get_string(dnode, NULL));
}

static int route_map_config_write(struct vty *vty)
{
	struct lyd_node *dnode;
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
static struct cmd_node rmap_node = {
	.node = RMAP_NODE,
	.prompt = "%s(config-route-map)# ",
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
	install_node(&rmap_node, route_map_config_write);
	install_default(RMAP_NODE);
	install_element(CONFIG_NODE, &route_map_cmd);
	install_element(CONFIG_NODE, &no_route_map_cmd);
	install_element(CONFIG_NODE, &no_route_map_all_cmd);

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

	install_element(RMAP_NODE, &set_tag_cmd);
	install_element(RMAP_NODE, &no_set_tag_cmd);
}
