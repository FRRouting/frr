/* zebra routemap.
 * Copyright (C) 2006 IBM Corporation
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "memory.h"
#include "zebra_memory.h"
#include "prefix.h"
#include "rib.h"
#include "vty.h"
#include "routemap.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "nexthop.h"
#include "vrf.h"

#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_routemap.h"

static u_int32_t zebra_rmap_update_timer = ZEBRA_RMAP_DEFAULT_UPDATE_TIMER;
static struct thread *zebra_t_rmap_update = NULL;
char *proto_rm[AFI_MAX][ZEBRA_ROUTE_MAX + 1]; /* "any" == ZEBRA_ROUTE_MAX */
/* NH Tracking route map */
char *nht_rm[AFI_MAX][ZEBRA_ROUTE_MAX + 1]; /* "any" == ZEBRA_ROUTE_MAX */
char *zebra_import_table_routemap[AFI_MAX][ZEBRA_KERNEL_TABLE_MAX];

struct nh_rmap_obj {
	struct nexthop *nexthop;
	vrf_id_t vrf_id;
	u_int32_t source_protocol;
	int metric;
	route_tag_t tag;
};

static void zebra_route_map_set_delay_timer(u_int32_t value);


/* Add zebra route map rule */
static int zebra_route_match_add(struct vty *vty, const char *command,
				 const char *arg, route_map_event_t type)
{
	VTY_DECLVAR_CONTEXT(route_map_index, index);
	int ret;
	int retval = CMD_SUCCESS;

	ret = route_map_add_match(index, command, arg);
	switch (ret) {
	case RMAP_RULE_MISSING:
		vty_out(vty, "%% Zebra Can't find rule.\n");
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_ERROR:
		vty_out(vty, "%% Zebra Argument is malformed.\n");
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_SUCCESS:
		if (type != RMAP_EVENT_MATCH_ADDED) {
			route_map_upd8_dependency(type, arg, index->map->name);
		}
		break;
	}

	return retval;
}

/* Delete zebra route map rule. */
static int zebra_route_match_delete(struct vty *vty, const char *command,
				    const char *arg, route_map_event_t type)
{
	VTY_DECLVAR_CONTEXT(route_map_index, index);
	int ret;
	int retval = CMD_SUCCESS;
	char *dep_name = NULL;
	const char *tmpstr;
	char *rmap_name = NULL;

	if (type != RMAP_EVENT_MATCH_DELETED) {
		/* ignore the mundane, the types without any dependency */
		if (arg == NULL) {
			if ((tmpstr = route_map_get_match_arg(index, command))
			    != NULL)
				dep_name =
					XSTRDUP(MTYPE_ROUTE_MAP_RULE, tmpstr);
		} else {
			dep_name = XSTRDUP(MTYPE_ROUTE_MAP_RULE, arg);
		}
		rmap_name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, index->map->name);
	}

	ret = route_map_delete_match(index, command, arg);
	switch (ret) {
	case RMAP_RULE_MISSING:
		vty_out(vty, "%% Zebra Can't find rule.\n");
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_ERROR:
		vty_out(vty, "%% Zebra Argument is malformed.\n");
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_SUCCESS:
		if (type != RMAP_EVENT_MATCH_DELETED && dep_name)
			route_map_upd8_dependency(type, dep_name, rmap_name);
		break;
	}

	if (dep_name)
		XFREE(MTYPE_ROUTE_MAP_RULE, dep_name);
	if (rmap_name)
		XFREE(MTYPE_ROUTE_MAP_NAME, rmap_name);

	return retval;
}

/* 'match tag TAG'
 * Match function return 1 if match is success else return 0
 */
static route_map_result_t route_match_tag(void *rule, struct prefix *prefix,
					  route_map_object_t type, void *object)
{
	route_tag_t *tag;
	struct nh_rmap_obj *nh_data;

	if (type == RMAP_ZEBRA) {
		tag = rule;
		nh_data = object;

		if (nh_data->tag == *tag)
			return RMAP_MATCH;
	}
	return RMAP_NOMATCH;
}

/* Route map commands for tag matching */
static struct route_map_rule_cmd route_match_tag_cmd = {
	"tag", route_match_tag, route_map_rule_tag_compile,
	route_map_rule_tag_free,
};


/* `match interface IFNAME' */
/* Match function return 1 if match is success else return zero. */
static route_map_result_t route_match_interface(void *rule,
						struct prefix *prefix,
						route_map_object_t type,
						void *object)
{
	struct nh_rmap_obj *nh_data;
	char *ifname = rule;
	ifindex_t ifindex;

	if (type == RMAP_ZEBRA) {
		if (strcasecmp(ifname, "any") == 0)
			return RMAP_MATCH;
		nh_data = object;
		if (!nh_data || !nh_data->nexthop)
			return RMAP_NOMATCH;
		ifindex = ifname2ifindex(ifname, nh_data->vrf_id);
		if (ifindex == 0)
			return RMAP_NOMATCH;
		if (nh_data->nexthop->ifindex == ifindex)
			return RMAP_MATCH;
	}
	return RMAP_NOMATCH;
}

/* Route map `match interface' match statement. `arg' is IFNAME value */
static void *route_match_interface_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `match interface' value. */
static void route_match_interface_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for interface matching */
struct route_map_rule_cmd route_match_interface_cmd = {
	"interface", route_match_interface, route_match_interface_compile,
	route_match_interface_free};

DEFUN (match_ip_address_prefix_len,
       match_ip_address_prefix_len_cmd,
       "match ip address prefix-len (0-32)",
       MATCH_STR
       IP_STR
       "Match prefix length of ip address\n"
       "Match prefix length of ip address\n"
       "Prefix length\n")
{
	return zebra_route_match_add(vty, "ip address prefix-len", argv[4]->arg,
				     RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_ip_address_prefix_len,
       no_match_ip_address_prefix_len_cmd,
       "no match ip address prefix-len [(0-32)]",
       NO_STR
       MATCH_STR
       IP_STR
       "Match prefix length of ip address\n"
       "Match prefix length of ip address\n"
       "Prefix length\n")
{
	char *plen = (argc == 6) ? argv[5]->arg : NULL;
	return zebra_route_match_delete(vty, "ip address prefix-len", plen,
					RMAP_EVENT_MATCH_DELETED);
}

DEFUN (match_ipv6_address_prefix_len,
       match_ipv6_address_prefix_len_cmd,
       "match ipv6 address prefix-len (0-128)",
       MATCH_STR
       IPV6_STR
       "Match prefix length of ipv6 address\n"
       "Match prefix length of ipv6 address\n"
       "Prefix length\n")
{
	return zebra_route_match_add(vty, "ipv6 address prefix-len", argv[4]->arg,
				     RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_ipv6_address_prefix_len,
       no_match_ipv6_address_prefix_len_cmd,
       "no match ipv6 address prefix-len [(0-128)]",
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match prefix length of ip address\n"
       "Match prefix length of ip address\n"
       "Prefix length\n")
{
	char *plen = (argc == 6) ? argv[5]->arg : NULL;
	return zebra_route_match_delete(vty, "ipv6 address prefix-len", plen,
					RMAP_EVENT_MATCH_DELETED);
}

DEFUN (match_ip_nexthop_prefix_len,
       match_ip_nexthop_prefix_len_cmd,
       "match ip next-hop prefix-len (0-32)",
       MATCH_STR
       IP_STR
       "Match prefixlen of nexthop ip address\n"
       "Match prefixlen of given nexthop\n"
       "Prefix length\n")
{
	return zebra_route_match_add(vty, "ip next-hop prefix-len",
				     argv[4]->arg, RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_ip_nexthop_prefix_len,
       no_match_ip_nexthop_prefix_len_cmd,
       "no match ip next-hop prefix-len [(0-32)]",
       NO_STR
       MATCH_STR
       IP_STR
       "Match prefixlen of nexthop ip address\n"
       "Match prefix length of nexthop\n"
       "Prefix length\n")
{
	char *plen = (argc == 6) ? argv[5]->arg : NULL;
	return zebra_route_match_delete(vty, "ip next-hop prefix-len", plen,
					RMAP_EVENT_MATCH_DELETED);
}

DEFUN (match_source_protocol,
       match_source_protocol_cmd,
       "match source-protocol <bgp|ospf|rip|ripng|isis|ospf6|pim|nhrp|eigrp|babel|connected|system|kernel|static>",
       MATCH_STR
       "Match protocol via which the route was learnt\n"
       "BGP protocol\n"
       "OSPF protocol\n"
       "RIP protocol\n"
       "RIPNG protocol\n"
       "ISIS protocol\n"
       "OSPF6 protocol\n"
       "PIM protocol\n"
       "NHRP protocol\n"
       "EIGRP protocol\n"
       "BABEL protocol\n"
       "Routes from directly connected peer\n"
       "Routes from system configuration\n"
       "Routes from kernel\n"
       "Statically configured routes\n")
{
	char *proto = argv[2]->text;
	int i;

	i = proto_name2num(proto);
	if (i < 0) {
		vty_out(vty, "invalid protocol name \"%s\"\n", proto);
		return CMD_WARNING_CONFIG_FAILED;
	}
	return zebra_route_match_add(vty, "source-protocol", proto,
				     RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_source_protocol,
       no_match_source_protocol_cmd,
       "no match source-protocol [<bgp|ospf|rip|ripng|isis|ospf6|pim|nhrp|eigrp|babel|connected|system|kernel|static>]",
       NO_STR
       MATCH_STR
       "No match protocol via which the route was learnt\n"
       "BGP protocol\n"
       "OSPF protocol\n"
       "RIP protocol\n"
       "RIPNG protocol\n"
       "ISIS protocol\n"
       "OSPF6 protocol\n"
       "PIM protocol\n"
       "NHRP protocol\n"
       "EIGRP protocol\n"
       "BABEL protocol\n"
       "Routes from directly connected peer\n"
       "Routes from system configuration\n"
       "Routes from kernel\n"
       "Statically configured routes\n")
{
	char *proto = (argc == 4) ? argv[3]->text : NULL;
	return zebra_route_match_delete(vty, "source-protocol", proto,
					RMAP_EVENT_MATCH_DELETED);
}

/* set functions */

DEFUN (set_src,
       set_src_cmd,
       "set src <A.B.C.D|X:X::X:X>",
       SET_STR
       "src address for route\n"
       "IPv4 src address\n"
       "IPv6 src address\n")
{
	int idx_ip = 2;
	union g_addr src;
	struct interface *pif = NULL;
	int family;
	struct prefix p;
	struct vrf *vrf;

	if (inet_pton(AF_INET, argv[idx_ip]->arg, &src.ipv4) != 1) {
		if (inet_pton(AF_INET6, argv[idx_ip]->arg, &src.ipv6) != 1) {
			vty_out(vty, "%% not a valid IPv4/v6 address\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		p.family = family = AF_INET6;
		p.u.prefix6 = src.ipv6;
		p.prefixlen = IPV6_MAX_BITLEN;
	} else {
		p.family = family = AF_INET;
		p.u.prefix4 = src.ipv4;
		p.prefixlen = IPV4_MAX_BITLEN;
	}

	if (!zebra_check_addr(&p)) {
		vty_out(vty, "%% not a valid source IPv4/v6 address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		if (family == AF_INET)
			pif = if_lookup_exact_address((void *)&src.ipv4,
						      AF_INET, vrf->vrf_id);
		else if (family == AF_INET6)
			pif = if_lookup_exact_address((void *)&src.ipv6,
						      AF_INET6, vrf->vrf_id);

		if (pif != NULL)
			break;
	}

	if (!pif) {
		vty_out(vty, "%% not a local address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	VTY_DECLVAR_CONTEXT(route_map_index, index);
	return generic_set_add(vty, index, "src", argv[idx_ip]->arg);
}

DEFUN (no_set_src,
       no_set_src_cmd,
       "no set src [<A.B.C.D|X:X::X:X>]",
       NO_STR
       SET_STR
       "Source address for route\n"
       "IPv4 address\n"
       "IPv6 address\n")
{
	char *ip = (argc == 4) ? argv[3]->arg : NULL;
	VTY_DECLVAR_CONTEXT(route_map_index, index);
	return generic_set_delete(vty, index, "src", ip);
}

DEFUN (zebra_route_map_timer,
       zebra_route_map_timer_cmd,
       "zebra route-map delay-timer (0-600)",
       ZEBRA_STR
       "Set route-map parameters\n"
       "Time to wait before route-map updates are processed\n"
       "0 means event-driven updates are disabled\n")
{
	int idx_number = 3;
	u_int32_t rmap_delay_timer;

	rmap_delay_timer = strtoul(argv[idx_number]->arg, NULL, 10);
	zebra_route_map_set_delay_timer(rmap_delay_timer);

	return (CMD_SUCCESS);
}

DEFUN (no_zebra_route_map_timer,
       no_zebra_route_map_timer_cmd,
       "no zebra route-map delay-timer [(0-600)]",
       NO_STR
       ZEBRA_STR
       "Set route-map parameters\n"
       "Reset delay-timer to default value, 30 secs\n"
       "0 means event-driven updates are disabled\n")
{
	zebra_route_map_set_delay_timer(ZEBRA_RMAP_DEFAULT_UPDATE_TIMER);

	return (CMD_SUCCESS);
}


DEFUN (ip_protocol,
       ip_protocol_cmd,
       "ip protocol " FRR_IP_PROTOCOL_MAP_STR_ZEBRA " route-map ROUTE-MAP",
       IP_STR
       "Filter routing info exchanged between zebra and protocol\n"
       FRR_IP_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Specify route-map\n"
       "Route map name\n")
{
	char *proto = argv[2]->text;
	char *rmap = argv[4]->arg;
	int i;

	if (strcasecmp(proto, "any") == 0)
		i = ZEBRA_ROUTE_MAX;
	else
		i = proto_name2num(proto);
	if (i < 0) {
		vty_out(vty, "invalid protocol name \"%s\"\n", proto);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (proto_rm[AFI_IP][i]) {
		if (strcmp(proto_rm[AFI_IP][i], rmap) == 0)
			return CMD_SUCCESS;

		XFREE(MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP][i]);
	}
	proto_rm[AFI_IP][i] = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug(
			"%u: IPv4 Routemap config for protocol %s, scheduling RIB processing",
			VRF_DEFAULT, proto);

	rib_update(VRF_DEFAULT, RIB_UPDATE_RMAP_CHANGE);
	return CMD_SUCCESS;
}

DEFUN (no_ip_protocol,
       no_ip_protocol_cmd,
       "no ip protocol " FRR_IP_PROTOCOL_MAP_STR_ZEBRA " [route-map ROUTE-MAP]",
       NO_STR
       IP_STR
       "Stop filtering routing info between zebra and protocol\n"
       FRR_IP_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Specify route map\n"
       "Route map name\n")
{
	char *proto = argv[3]->text;
	char *rmap = (argc == 6) ? argv[5]->arg : NULL;
	int i;

	if (strcasecmp(proto, "any") == 0)
		i = ZEBRA_ROUTE_MAX;
	else
		i = proto_name2num(proto);

	if (i < 0) {
		vty_out(vty, "invalid protocol name \"%s\"\n", proto);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!proto_rm[AFI_IP][i])
		return CMD_SUCCESS;

	if (!rmap || strcmp(rmap, proto_rm[AFI_IP][i]) == 0) {
		XFREE(MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP][i]);
		proto_rm[AFI_IP][i] = NULL;

		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug(
				"%u: IPv4 Routemap unconfig for protocol %s, scheduling RIB processing",
				VRF_DEFAULT, proto);
		rib_update(VRF_DEFAULT, RIB_UPDATE_RMAP_CHANGE);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_protocol,
       show_ip_protocol_cmd,
       "show ip protocol",
        SHOW_STR
        IP_STR
       "IP protocol filtering status\n")
{
	int i;

	vty_out(vty, "Protocol    : route-map \n");
	vty_out(vty, "------------------------\n");
	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (proto_rm[AFI_IP][i])
			vty_out(vty, "%-10s  : %-10s\n", zebra_route_string(i),
				proto_rm[AFI_IP][i]);
		else
			vty_out(vty, "%-10s  : none\n", zebra_route_string(i));
	}
	if (proto_rm[AFI_IP][i])
		vty_out(vty, "%-10s  : %-10s\n", "any", proto_rm[AFI_IP][i]);
	else
		vty_out(vty, "%-10s  : none\n", "any");

	return CMD_SUCCESS;
}

DEFUN (ipv6_protocol,
       ipv6_protocol_cmd,
       "ipv6 protocol " FRR_IP6_PROTOCOL_MAP_STR_ZEBRA " route-map ROUTE-MAP",
       IP6_STR
       "Filter IPv6 routing info exchanged between zebra and protocol\n"
       FRR_IP6_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Specify route map\n"
       "Route map name\n")
{
	char *proto = argv[2]->text;
	char *rmap = argv[4]->arg;
	int i;

	if (strcasecmp(proto, "any") == 0)
		i = ZEBRA_ROUTE_MAX;
	else
		i = proto_name2num(proto);
	if (i < 0) {
		vty_out(vty, "invalid protocol name \"%s\"\n", proto);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (proto_rm[AFI_IP6][i]) {
		if (strcmp(proto_rm[AFI_IP6][i], rmap) == 0)
			return CMD_SUCCESS;

		XFREE(MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP6][i]);
	}
	proto_rm[AFI_IP6][i] = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug(
			"%u: IPv6 Routemap config for protocol %s, scheduling RIB processing",
			VRF_DEFAULT, proto);

	rib_update(VRF_DEFAULT, RIB_UPDATE_RMAP_CHANGE);
	return CMD_SUCCESS;
}

DEFUN (no_ipv6_protocol,
       no_ipv6_protocol_cmd,
       "no ipv6 protocol " FRR_IP6_PROTOCOL_MAP_STR_ZEBRA " [route-map ROUTE-MAP]",
       NO_STR
       IP6_STR
       "Stop filtering IPv6 routing info between zebra and protocol\n"
       FRR_IP6_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Specify route map\n"
       "Route map name\n")
{
	const char *proto = argv[3]->text;
	const char *rmap = (argc == 6) ? argv[5]->arg : NULL;
	int i;

	if (strcasecmp(proto, "any") == 0)
		i = ZEBRA_ROUTE_MAX;
	else
		i = proto_name2num(proto);
	if (i < 0) {
		vty_out(vty, "invalid protocol name \"%s\"\n", proto);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!proto_rm[AFI_IP6][i])
		return CMD_SUCCESS;

	if (!rmap || strcmp(rmap, proto_rm[AFI_IP6][i]) == 0) {
		XFREE(MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP6][i]);
		proto_rm[AFI_IP6][i] = NULL;

		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug(
				"%u: IPv6 Routemap unconfig for protocol %s, scheduling RIB processing",
				VRF_DEFAULT, proto);

		rib_update(VRF_DEFAULT, RIB_UPDATE_RMAP_CHANGE);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ipv6_protocol,
       show_ipv6_protocol_cmd,
       "show ipv6 protocol",
        SHOW_STR
        IP6_STR
       "IPv6 protocol filtering status\n")
{
	int i;

	vty_out(vty, "Protocol    : route-map \n");
	vty_out(vty, "------------------------\n");
	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (proto_rm[AFI_IP6][i])
			vty_out(vty, "%-10s  : %-10s\n", zebra_route_string(i),
				proto_rm[AFI_IP6][i]);
		else
			vty_out(vty, "%-10s  : none\n", zebra_route_string(i));
	}
	if (proto_rm[AFI_IP6][i])
		vty_out(vty, "%-10s  : %-10s\n", "any", proto_rm[AFI_IP6][i]);
	else
		vty_out(vty, "%-10s  : none\n", "any");

	return CMD_SUCCESS;
}

DEFUN (ip_protocol_nht_rmap,
       ip_protocol_nht_rmap_cmd,
       "ip nht " FRR_IP_PROTOCOL_MAP_STR_ZEBRA " route-map ROUTE-MAP",
       IP_STR
       "Filter Next Hop tracking route resolution\n"
       FRR_IP_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Specify route map\n"
       "Route map name\n")
{
	char *proto = argv[2]->text;
	char *rmap = argv[4]->arg;
	int i;

	if (strcasecmp(proto, "any") == 0)
		i = ZEBRA_ROUTE_MAX;
	else
		i = proto_name2num(proto);
	if (i < 0) {
		vty_out(vty, "invalid protocol name \"%s\"\n", proto);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (nht_rm[AFI_IP][i]) {
		if (strcmp(nht_rm[AFI_IP][i], rmap) == 0)
			return CMD_SUCCESS;

		XFREE(MTYPE_ROUTE_MAP_NAME, nht_rm[AFI_IP][i]);
	}

	nht_rm[AFI_IP][i] = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
	zebra_evaluate_rnh(0, AF_INET, 1, RNH_NEXTHOP_TYPE, NULL);

	return CMD_SUCCESS;
}

DEFUN (no_ip_protocol_nht_rmap,
       no_ip_protocol_nht_rmap_cmd,
       "no ip nht " FRR_IP_PROTOCOL_MAP_STR_ZEBRA " [route-map ROUTE-MAP]",
       NO_STR
       IP_STR
       "Filter Next Hop tracking route resolution\n"
       FRR_IP_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Specify route map\n"
       "Route map name\n")
{
	int idx = 0;
	char *proto = argv[3]->text;
	char *rmap = argv_find(argv, argc, "ROUTE-MAP", &idx) ? argv[idx]->arg
							      : NULL;

	int i = strmatch(proto, "any") ? ZEBRA_ROUTE_MAX
				       : proto_name2num(proto);

	if (i < 0) {
		vty_out(vty, "invalid protocol name \"%s\"\n", proto);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!nht_rm[AFI_IP][i])
		return CMD_SUCCESS;

	if (!rmap || strcmp(rmap, nht_rm[AFI_IP][i]) == 0) {
		XFREE(MTYPE_ROUTE_MAP_NAME, nht_rm[AFI_IP][i]);
		nht_rm[AFI_IP][i] = NULL;
		zebra_evaluate_rnh(0, AF_INET, 1, RNH_NEXTHOP_TYPE, NULL);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_protocol_nht,
       show_ip_protocol_nht_cmd,
       "show ip nht route-map",
       SHOW_STR
       IP_STR
       "IP nexthop tracking table\n"
       "IP Next Hop tracking filtering status\n")
{
	int i;

	vty_out(vty, "Protocol    : route-map \n");
	vty_out(vty, "------------------------\n");
	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (nht_rm[AFI_IP][i])
			vty_out(vty, "%-10s  : %-10s\n", zebra_route_string(i),
				nht_rm[AFI_IP][i]);
		else
			vty_out(vty, "%-10s  : none\n", zebra_route_string(i));
	}
	if (nht_rm[AFI_IP][i])
		vty_out(vty, "%-10s  : %-10s\n", "any", nht_rm[AFI_IP][i]);
	else
		vty_out(vty, "%-10s  : none\n", "any");

	return CMD_SUCCESS;
}

DEFUN (ipv6_protocol_nht_rmap,
       ipv6_protocol_nht_rmap_cmd,
       "ipv6 nht " FRR_IP6_PROTOCOL_MAP_STR_ZEBRA " route-map ROUTE-MAP",
       IP6_STR
       "Filter Next Hop tracking route resolution\n"
       FRR_IP6_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Specify route map\n"
       "Route map name\n")
{
	char *proto = argv[2]->text;
	char *rmap = argv[4]->arg;
	int i;

	if (strcasecmp(proto, "any") == 0)
		i = ZEBRA_ROUTE_MAX;
	else
		i = proto_name2num(proto);
	if (i < 0) {
		vty_out(vty, "invalid protocol name \"%s\"\n", proto);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (nht_rm[AFI_IP6][i])
		XFREE(MTYPE_ROUTE_MAP_NAME, nht_rm[AFI_IP6][i]);
	nht_rm[AFI_IP6][i] = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
	zebra_evaluate_rnh(0, AF_INET6, 1, RNH_NEXTHOP_TYPE, NULL);

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_protocol_nht_rmap,
       no_ipv6_protocol_nht_rmap_cmd,
       "no ipv6 nht " FRR_IP6_PROTOCOL_MAP_STR_ZEBRA " [route-map ROUTE-MAP]",
       NO_STR
       IP6_STR
       "Filter Next Hop tracking route resolution\n"
       FRR_IP6_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Specify route map\n"
       "Route map name\n")
{
	char *proto = argv[3]->text;
	char *rmap = (argc == 6) ? argv[5]->arg : NULL;
	int i;

	if (strcasecmp(proto, "any") == 0)
		i = ZEBRA_ROUTE_MAX;
	else
		i = proto_name2num(proto);
	if (i < 0) {
		vty_out(vty, "invalid protocol name \"%s\"\n", proto);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nht_rm[AFI_IP6][i] && rmap && strcmp(rmap, nht_rm[AFI_IP6][i])) {
		vty_out(vty, "invalid route-map \"%s\"\n", rmap);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nht_rm[AFI_IP6][i]) {
		XFREE(MTYPE_ROUTE_MAP_NAME, nht_rm[AFI_IP6][i]);
		nht_rm[AFI_IP6][i] = NULL;
	}

	zebra_evaluate_rnh(0, AF_INET6, 1, RNH_NEXTHOP_TYPE, NULL);

	return CMD_SUCCESS;
}

DEFUN (show_ipv6_protocol_nht,
       show_ipv6_protocol_nht_cmd,
       "show ipv6 nht route-map",
       SHOW_STR
       IP6_STR
       "Next Hop filtering status\n"
       "Route-map\n")
{
	int i;

	vty_out(vty, "Protocol    : route-map \n");
	vty_out(vty, "------------------------\n");
	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (nht_rm[AFI_IP6][i])
			vty_out(vty, "%-10s  : %-10s\n", zebra_route_string(i),
				nht_rm[AFI_IP6][i]);
		else
			vty_out(vty, "%-10s  : none\n", zebra_route_string(i));
	}
	if (nht_rm[AFI_IP][i])
		vty_out(vty, "%-10s  : %-10s\n", "any", nht_rm[AFI_IP6][i]);
	else
		vty_out(vty, "%-10s  : none\n", "any");

	return CMD_SUCCESS;
}

/*XXXXXXXXXXXXXXXXXXXXXXXXXXXX*/

/* `match ip next-hop IP_ACCESS_LIST' */

/* Match function return 1 if match is success else return zero. */
static route_map_result_t route_match_ip_next_hop(void *rule,
						  struct prefix *prefix,
						  route_map_object_t type,
						  void *object)
{
	struct access_list *alist;
	struct nh_rmap_obj *nh_data;
	struct prefix_ipv4 p;

	if (type == RMAP_ZEBRA) {
		nh_data = object;
		if (!nh_data)
			return RMAP_DENYMATCH;

		switch (nh_data->nexthop->type) {
		case NEXTHOP_TYPE_IFINDEX:
			/* Interface routes can't match ip next-hop */
			return RMAP_NOMATCH;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV4:
			p.family = AF_INET;
			p.prefix = nh_data->nexthop->gate.ipv4;
			p.prefixlen = IPV4_MAX_BITLEN;
			break;
		default:
			return RMAP_NOMATCH;
		}
		alist = access_list_lookup(AFI_IP, (char *)rule);
		if (alist == NULL)
			return RMAP_NOMATCH;

		return (access_list_apply(alist, &p) == FILTER_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

/* Route map `ip next-hop' match statement.  `arg' should be
   access-list name. */
static void *route_match_ip_next_hop_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `. */
static void route_match_ip_next_hop_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip next-hop matching. */
static struct route_map_rule_cmd route_match_ip_next_hop_cmd = {
	"ip next-hop", route_match_ip_next_hop, route_match_ip_next_hop_compile,
	route_match_ip_next_hop_free};

/* `match ip next-hop prefix-list PREFIX_LIST' */

static route_map_result_t
route_match_ip_next_hop_prefix_list(void *rule, struct prefix *prefix,
				    route_map_object_t type, void *object)
{
	struct prefix_list *plist;
	struct nh_rmap_obj *nh_data;
	struct prefix_ipv4 p;

	if (type == RMAP_ZEBRA) {
		nh_data = (struct nh_rmap_obj *)object;
		if (!nh_data)
			return RMAP_DENYMATCH;

		switch (nh_data->nexthop->type) {
		case NEXTHOP_TYPE_IFINDEX:
			/* Interface routes can't match ip next-hop */
			return RMAP_NOMATCH;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV4:
			p.family = AF_INET;
			p.prefix = nh_data->nexthop->gate.ipv4;
			p.prefixlen = IPV4_MAX_BITLEN;
			break;
		default:
			return RMAP_NOMATCH;
		}
		plist = prefix_list_lookup(AFI_IP, (char *)rule);
		if (plist == NULL)
			return RMAP_NOMATCH;

		return (prefix_list_apply(plist, &p) == PREFIX_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

static void *route_match_ip_next_hop_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ip_next_hop_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_match_ip_next_hop_prefix_list_cmd = {
	"ip next-hop prefix-list", route_match_ip_next_hop_prefix_list,
	route_match_ip_next_hop_prefix_list_compile,
	route_match_ip_next_hop_prefix_list_free};

/* `match ip address IP_ACCESS_LIST' */

/* Match function should return 1 if match is success else return
   zero. */
static route_map_result_t route_match_ip_address(void *rule,
						 struct prefix *prefix,
						 route_map_object_t type,
						 void *object)
{
	struct access_list *alist;

	if (type == RMAP_ZEBRA) {
		alist = access_list_lookup(AFI_IP, (char *)rule);
		if (alist == NULL)
			return RMAP_NOMATCH;

		return (access_list_apply(alist, prefix) == FILTER_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

/* Route map `ip address' match statement.  `arg' should be
   access-list name. */
static void *route_match_ip_address_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
static void route_match_ip_address_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
static struct route_map_rule_cmd route_match_ip_address_cmd = {
	"ip address", route_match_ip_address, route_match_ip_address_compile,
	route_match_ip_address_free};

/* `match ip address prefix-list PREFIX_LIST' */

static route_map_result_t
route_match_ip_address_prefix_list(void *rule, struct prefix *prefix,
				   route_map_object_t type, void *object)
{
	struct prefix_list *plist;

	if (type == RMAP_ZEBRA) {
		plist = prefix_list_lookup(AFI_IP, (char *)rule);
		if (plist == NULL)
			return RMAP_NOMATCH;

		return (prefix_list_apply(plist, prefix) == PREFIX_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

static void *route_match_ip_address_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ip_address_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_match_ip_address_prefix_list_cmd = {
	"ip address prefix-list", route_match_ip_address_prefix_list,
	route_match_ip_address_prefix_list_compile,
	route_match_ip_address_prefix_list_free};


/* `match ip address prefix-len PREFIXLEN' */

static route_map_result_t
route_match_address_prefix_len(void *rule, struct prefix *prefix,
			       route_map_object_t type, void *object)
{
	u_int32_t *prefixlen = (u_int32_t *)rule;

	if (type == RMAP_ZEBRA) {
		return ((prefix->prefixlen == *prefixlen) ? RMAP_MATCH
							  : RMAP_NOMATCH);
	}
	return RMAP_NOMATCH;
}

static void *route_match_address_prefix_len_compile(const char *arg)
{
	u_int32_t *prefix_len;
	char *endptr = NULL;
	unsigned long tmpval;

	/* prefix len value shoud be integer. */
	if (!all_digit(arg))
		return NULL;

	errno = 0;
	tmpval = strtoul(arg, &endptr, 10);
	if (*endptr != '\0' || errno || tmpval > UINT32_MAX)
		return NULL;

	prefix_len = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(u_int32_t));

	if (!prefix_len)
		return prefix_len;

	*prefix_len = tmpval;
	return prefix_len;
}

static void route_match_address_prefix_len_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_match_ip_address_prefix_len_cmd = {
	"ip address prefix-len", route_match_address_prefix_len,
	route_match_address_prefix_len_compile,
	route_match_address_prefix_len_free};

static struct route_map_rule_cmd route_match_ipv6_address_prefix_len_cmd = {
	"ipv6 address prefix-len", route_match_address_prefix_len,
	route_match_address_prefix_len_compile,
	route_match_address_prefix_len_free};

/* `match ip nexthop prefix-len PREFIXLEN' */

static route_map_result_t
route_match_ip_nexthop_prefix_len(void *rule, struct prefix *prefix,
				  route_map_object_t type, void *object)
{
	u_int32_t *prefixlen = (u_int32_t *)rule;
	struct nh_rmap_obj *nh_data;
	struct prefix_ipv4 p;

	if (type == RMAP_ZEBRA) {
		nh_data = (struct nh_rmap_obj *)object;
		if (!nh_data || !nh_data->nexthop)
			return RMAP_DENYMATCH;

		switch (nh_data->nexthop->type) {
		case NEXTHOP_TYPE_IFINDEX:
			/* Interface routes can't match ip next-hop */
			return RMAP_NOMATCH;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV4:
			p.family = AF_INET;
			p.prefix = nh_data->nexthop->gate.ipv4;
			p.prefixlen = IPV4_MAX_BITLEN;
			break;
		default:
			return RMAP_NOMATCH;
		}
		return ((p.prefixlen == *prefixlen) ? RMAP_MATCH
						    : RMAP_NOMATCH);
	}
	return RMAP_NOMATCH;
}

static struct route_map_rule_cmd route_match_ip_nexthop_prefix_len_cmd = {
	"ip next-hop prefix-len", route_match_ip_nexthop_prefix_len,
	route_match_address_prefix_len_compile, /* reuse */
	route_match_address_prefix_len_free     /* reuse */
};

/* `match source-protocol PROTOCOL' */

static route_map_result_t route_match_source_protocol(void *rule,
						      struct prefix *prefix,
						      route_map_object_t type,
						      void *object)
{
	u_int32_t *rib_type = (u_int32_t *)rule;
	struct nh_rmap_obj *nh_data;

	if (type == RMAP_ZEBRA) {
		nh_data = (struct nh_rmap_obj *)object;
		if (!nh_data)
			return RMAP_DENYMATCH;

		return ((nh_data->source_protocol == *rib_type) ? RMAP_MATCH
								: RMAP_NOMATCH);
	}
	return RMAP_NOMATCH;
}

static void *route_match_source_protocol_compile(const char *arg)
{
	u_int32_t *rib_type;
	int i;

	i = proto_name2num(arg);
	rib_type = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(u_int32_t));

	*rib_type = i;

	return rib_type;
}

static void route_match_source_protocol_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_match_source_protocol_cmd = {
	"source-protocol", route_match_source_protocol,
	route_match_source_protocol_compile, route_match_source_protocol_free};

/* `set src A.B.C.D' */

/* Set src. */
static route_map_result_t route_set_src(void *rule, struct prefix *prefix,
					route_map_object_t type, void *object)
{
	struct nh_rmap_obj *nh_data;

	if (type == RMAP_ZEBRA) {
		nh_data = (struct nh_rmap_obj *)object;
		nh_data->nexthop->rmap_src = *(union g_addr *)rule;
	}
	return RMAP_OKAY;
}

/* set src compilation. */
static void *route_set_src_compile(const char *arg)
{
	union g_addr src, *psrc;

	if ((inet_pton(AF_INET6, arg, &src.ipv6) == 1)
	    || (inet_pton(AF_INET, arg, &src.ipv4) == 1)) {
		psrc = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(union g_addr));
		*psrc = src;
		return psrc;
	}
	return NULL;
}

/* Free route map's compiled `set src' value. */
static void route_set_src_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set src rule structure. */
static struct route_map_rule_cmd route_set_src_cmd = {
	"src", route_set_src, route_set_src_compile, route_set_src_free,
};

static int zebra_route_map_update_timer(struct thread *thread)
{
	zebra_t_rmap_update = NULL;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("Event driven route-map update triggered");

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug(
			"%u: Routemap update-timer fired, scheduling RIB processing",
			VRF_DEFAULT);

	zebra_import_table_rm_update();
	rib_update(VRF_DEFAULT, RIB_UPDATE_RMAP_CHANGE);
	zebra_evaluate_rnh(0, AF_INET, 1, RNH_NEXTHOP_TYPE, NULL);
	zebra_evaluate_rnh(0, AF_INET6, 1, RNH_NEXTHOP_TYPE, NULL);

	return (0);
}

static void zebra_route_map_set_delay_timer(u_int32_t value)
{
	zebra_rmap_update_timer = value;
	if (!value && zebra_t_rmap_update) {
		/* Event driven route map updates is being disabled */
		/* But there's a pending timer. Fire it off now */
		thread_cancel(zebra_t_rmap_update);
		zebra_route_map_update_timer(zebra_t_rmap_update);
	}
}

void zebra_route_map_write_delay_timer(struct vty *vty)
{
	if (vty && (zebra_rmap_update_timer != ZEBRA_RMAP_DEFAULT_UPDATE_TIMER))
		vty_out(vty, "zebra route-map delay-timer %d\n",
			zebra_rmap_update_timer);
	return;
}

route_map_result_t zebra_route_map_check(int family, int rib_type,
					 struct prefix *p,
					 struct nexthop *nexthop,
					 vrf_id_t vrf_id, route_tag_t tag)
{
	struct route_map *rmap = NULL;
	route_map_result_t ret = RMAP_MATCH;
	struct nh_rmap_obj nh_obj;

	nh_obj.nexthop = nexthop;
	nh_obj.vrf_id = vrf_id;
	nh_obj.source_protocol = rib_type;
	nh_obj.metric = 0;
	nh_obj.tag = tag;

	if (rib_type >= 0 && rib_type < ZEBRA_ROUTE_MAX)
		rmap = route_map_lookup_by_name(proto_rm[family][rib_type]);
	if (!rmap && proto_rm[family][ZEBRA_ROUTE_MAX])
		rmap = route_map_lookup_by_name(
			proto_rm[family][ZEBRA_ROUTE_MAX]);
	if (rmap) {
		ret = route_map_apply(rmap, p, RMAP_ZEBRA, &nh_obj);
	}

	return (ret);
}

char *zebra_get_import_table_route_map(afi_t afi, uint32_t table)
{
	return zebra_import_table_routemap[afi][table];
}

void zebra_add_import_table_route_map(afi_t afi, const char *rmap_name,
				      uint32_t table)
{
	zebra_import_table_routemap[afi][table] =
		XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_name);
}

void zebra_del_import_table_route_map(afi_t afi, uint32_t table)
{
	XFREE(MTYPE_ROUTE_MAP_NAME, zebra_import_table_routemap[afi][table]);
}

route_map_result_t
zebra_import_table_route_map_check(int family, int re_type, struct prefix *p,
				   struct nexthop *nexthop, vrf_id_t vrf_id,
				   route_tag_t tag, const char *rmap_name)
{
	struct route_map *rmap = NULL;
	route_map_result_t ret = RMAP_DENYMATCH;
	struct nh_rmap_obj nh_obj;

	nh_obj.nexthop = nexthop;
	nh_obj.vrf_id = vrf_id;
	nh_obj.source_protocol = re_type;
	nh_obj.metric = 0;
	nh_obj.tag = tag;

	if (re_type >= 0 && re_type < ZEBRA_ROUTE_MAX)
		rmap = route_map_lookup_by_name(rmap_name);
	if (rmap) {
		ret = route_map_apply(rmap, p, RMAP_ZEBRA, &nh_obj);
	}

	return (ret);
}

route_map_result_t zebra_nht_route_map_check(int family, int client_proto,
					     struct prefix *p,
					     struct route_entry *re,
					     struct nexthop *nexthop)
{
	struct route_map *rmap = NULL;
	route_map_result_t ret = RMAP_MATCH;
	struct nh_rmap_obj nh_obj;

	nh_obj.nexthop = nexthop;
	nh_obj.vrf_id = re->nh_vrf_id;
	nh_obj.source_protocol = re->type;
	nh_obj.metric = re->metric;
	nh_obj.tag = re->tag;

	if (client_proto >= 0 && client_proto < ZEBRA_ROUTE_MAX)
		rmap = route_map_lookup_by_name(nht_rm[family][client_proto]);
	if (!rmap && nht_rm[family][ZEBRA_ROUTE_MAX])
		rmap = route_map_lookup_by_name(
			nht_rm[family][ZEBRA_ROUTE_MAX]);
	if (rmap) {
		ret = route_map_apply(rmap, p, RMAP_ZEBRA, &nh_obj);
	}

	return (ret);
}

static void zebra_route_map_mark_update(const char *rmap_name)
{
	/* rmap_update_timer of 0 means don't do route updates */
	if (zebra_rmap_update_timer && !zebra_t_rmap_update) {
		zebra_t_rmap_update = NULL;
		thread_add_timer(zebrad.master, zebra_route_map_update_timer,
				 NULL, zebra_rmap_update_timer,
				 &zebra_t_rmap_update);
	}
}

static void zebra_route_map_add(const char *rmap_name)
{
	zebra_route_map_mark_update(rmap_name);
	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

static void zebra_route_map_delete(const char *rmap_name)
{
	zebra_route_map_mark_update(rmap_name);
	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_DELETED);
}

static void zebra_route_map_event(route_map_event_t event,
				  const char *rmap_name)
{
	zebra_route_map_mark_update(rmap_name);
	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

/* ip protocol configuration write function */
void zebra_routemap_config_write_protocol(struct vty *vty)
{
	int i;

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (proto_rm[AFI_IP][i])
			vty_out(vty, "ip protocol %s route-map %s\n",
				zebra_route_string(i), proto_rm[AFI_IP][i]);

		if (proto_rm[AFI_IP6][i])
			vty_out(vty, "ipv6 protocol %s route-map %s\n",
				zebra_route_string(i), proto_rm[AFI_IP6][i]);

		if (nht_rm[AFI_IP][i])
			vty_out(vty, "ip nht %s route-map %s\n",
				zebra_route_string(i), nht_rm[AFI_IP][i]);

		if (nht_rm[AFI_IP6][i])
			vty_out(vty, "ipv6 nht %s route-map %s\n",
				zebra_route_string(i), nht_rm[AFI_IP6][i]);
	}

	if (proto_rm[AFI_IP][ZEBRA_ROUTE_MAX])
		vty_out(vty, "ip protocol %s route-map %s\n", "any",
			proto_rm[AFI_IP][ZEBRA_ROUTE_MAX]);

	if (proto_rm[AFI_IP6][ZEBRA_ROUTE_MAX])
		vty_out(vty, "ipv6 protocol %s route-map %s\n", "any",
			proto_rm[AFI_IP6][ZEBRA_ROUTE_MAX]);

	if (nht_rm[AFI_IP][ZEBRA_ROUTE_MAX])
		vty_out(vty, "ip nht %s route-map %s\n", "any",
			nht_rm[AFI_IP][ZEBRA_ROUTE_MAX]);

	if (nht_rm[AFI_IP6][ZEBRA_ROUTE_MAX])
		vty_out(vty, "ipv6 nht %s route-map %s\n", "any",
			nht_rm[AFI_IP6][ZEBRA_ROUTE_MAX]);

	if (zebra_rmap_update_timer != ZEBRA_RMAP_DEFAULT_UPDATE_TIMER)
		vty_out(vty, "zebra route-map delay-timer %d\n",
			zebra_rmap_update_timer);
}

void zebra_route_map_init()
{
	install_element(CONFIG_NODE, &ip_protocol_cmd);
	install_element(CONFIG_NODE, &no_ip_protocol_cmd);
	install_element(VIEW_NODE, &show_ip_protocol_cmd);
	install_element(CONFIG_NODE, &ipv6_protocol_cmd);
	install_element(CONFIG_NODE, &no_ipv6_protocol_cmd);
	install_element(VIEW_NODE, &show_ipv6_protocol_cmd);
	install_element(CONFIG_NODE, &ip_protocol_nht_rmap_cmd);
	install_element(CONFIG_NODE, &no_ip_protocol_nht_rmap_cmd);
	install_element(VIEW_NODE, &show_ip_protocol_nht_cmd);
	install_element(CONFIG_NODE, &ipv6_protocol_nht_rmap_cmd);
	install_element(CONFIG_NODE, &no_ipv6_protocol_nht_rmap_cmd);
	install_element(VIEW_NODE, &show_ipv6_protocol_nht_cmd);
	install_element(CONFIG_NODE, &zebra_route_map_timer_cmd);
	install_element(CONFIG_NODE, &no_zebra_route_map_timer_cmd);

	route_map_init();

	route_map_add_hook(zebra_route_map_add);
	route_map_delete_hook(zebra_route_map_delete);
	route_map_event_hook(zebra_route_map_event);

	route_map_match_interface_hook(generic_match_add);
	route_map_no_match_interface_hook(generic_match_delete);

	route_map_match_ip_address_hook(generic_match_add);
	route_map_no_match_ip_address_hook(generic_match_delete);

	route_map_match_ip_address_prefix_list_hook(generic_match_add);
	route_map_no_match_ip_address_prefix_list_hook(generic_match_delete);

	route_map_match_ip_next_hop_hook(generic_match_add);
	route_map_no_match_ip_next_hop_hook(generic_match_delete);

	route_map_match_ip_next_hop_prefix_list_hook(generic_match_add);
	route_map_no_match_ip_next_hop_prefix_list_hook(generic_match_delete);

	route_map_match_tag_hook(generic_match_add);
	route_map_no_match_tag_hook(generic_match_delete);

	route_map_install_match(&route_match_tag_cmd);
	route_map_install_match(&route_match_interface_cmd);
	route_map_install_match(&route_match_ip_next_hop_cmd);
	route_map_install_match(&route_match_ip_next_hop_prefix_list_cmd);
	route_map_install_match(&route_match_ip_address_cmd);
	route_map_install_match(&route_match_ip_address_prefix_list_cmd);
	route_map_install_match(&route_match_ip_address_prefix_len_cmd);
	route_map_install_match(&route_match_ipv6_address_prefix_len_cmd);
	route_map_install_match(&route_match_ip_nexthop_prefix_len_cmd);
	route_map_install_match(&route_match_source_protocol_cmd);
	/* */
	route_map_install_set(&route_set_src_cmd);
	/* */
	install_element(RMAP_NODE, &match_ip_nexthop_prefix_len_cmd);
	install_element(RMAP_NODE, &no_match_ip_nexthop_prefix_len_cmd);
	install_element(RMAP_NODE, &match_ip_address_prefix_len_cmd);
	install_element(RMAP_NODE, &match_ipv6_address_prefix_len_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_address_prefix_len_cmd);
	install_element(RMAP_NODE, &no_match_ip_address_prefix_len_cmd);
	install_element(RMAP_NODE, &match_source_protocol_cmd);
	install_element(RMAP_NODE, &no_match_source_protocol_cmd);
	/* */
	install_element(RMAP_NODE, &set_src_cmd);
	install_element(RMAP_NODE, &no_set_src_cmd);
}
