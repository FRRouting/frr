// SPDX-License-Identifier: GPL-2.0-or-later
/* PIM Route-map Code
 * Copyright (C) 2016 Cumulus Networks <sharpd@cumulusnetworks.com>
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of Quagga
 */
#include <zebra.h>

#include "if.h"
#include "vty.h"
#include "routemap.h"
#include "lib/command.h"
#include "lib/northbound_cli.h"
#include "pimd/pim_nb.h"

#include "pimd.h"

#define MULTICAST_IPV4_SOURCE	   "multicast-source"
#define MULTICAST_IPV4_SOURCE_LIST "multicast-source prefix-list"
#define MULTICAST_IPV6_SOURCE	   "multicast-source-v6"
#define MULTICAST_IPV6_SOURCE_LIST "multicast-source-v6 prefix-list"
#define MULTICAST_IPV4_GROUP	   "multicast-group"
#define MULTICAST_IPV4_GROUP_LIST  "multicast-group prefix-list"
#define MULTICAST_IPV6_GROUP	   "multicast-group-v6"
#define MULTICAST_IPV6_GROUP_LIST  "multicast-group-v6 prefix-list"
#define MULTICAST_INTERFACE	   "multicast-interface"

/*
 * CLI
 */
#include "pimd/pim_routemap_clippy.c"

DEFPY_YANG(route_map_match_address, route_map_match_address_cmd,
           "[no] match ip <multicast-source$do_src A.B.C.D$addr|multicast-group$do_grp A.B.C.D$addr>",
           NO_STR
           MATCH_STR
           IP_STR
           "Multicast source address\n"
           "Multicast source address\n"
           "Multicast group address\n"
           "Multicast group address\n")
{
	const char *xpath, *xpval;
	char xpath_value[XPATH_MAXLEN];

	if (do_src) {
		xpath = "./match-condition[condition='frr-pim-route-map:ipv4-multicast-source']";
		xpval = "/rmap-match-condition/frr-pim-route-map:ipv4-multicast-source-address";
	} else {
		xpath = "./match-condition[condition='frr-pim-route-map:ipv4-multicast-group']";
		xpval = "/rmap-match-condition/frr-pim-route-map:ipv4-multicast-group-address";
	}

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value), "%s%s", xpath, xpval);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, addr_str);
	}

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG(route_map_match_address, no_route_map_match_address_cmd,
           "no match ip <multicast-source$do_src|multicast-group$do_grp>",
           NO_STR
           MATCH_STR
           IP_STR
           "Multicast source address\n"
           "Multicast group address\n")

DEFPY_YANG(route_map_match_address_v6, route_map_match_address_v6_cmd,
           "[no] match ipv6 <multicast-source$do_src X:X::X:X$addr|multicast-group$do_grp X:X::X:X$addr>",
           NO_STR
           MATCH_STR
           IPV6_STR
           "Multicast source address\n"
           "Multicast source address\n"
           "Multicast group address\n"
           "Multicast group address\n")
{
	const char *xpath, *xpval;
	char xpath_value[XPATH_MAXLEN];

	if (do_src) {
		xpath = "./match-condition[condition='frr-pim-route-map:ipv6-multicast-source']";
		xpval = "/rmap-match-condition/frr-pim-route-map:ipv6-multicast-source-address";
	} else {
		xpath = "./match-condition[condition='frr-pim-route-map:ipv6-multicast-group']";
		xpval = "/rmap-match-condition/frr-pim-route-map:ipv6-multicast-group-address";
	}

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value), "%s%s", xpath, xpval);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, addr_str);
	}

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG(route_map_match_address_v6, no_route_map_match_address_v6_cmd,
           "no match ipv6 <multicast-source$do_src|multicast-group$do_grp>",
           NO_STR
           MATCH_STR
           IPV6_STR
           "Multicast source address\n"
           "Multicast group address\n")

DEFPY_YANG(route_map_match_prefix_list,
           route_map_match_prefix_list_cmd,
           "[no] match ip <multicast-source$do_src|multicast-group$do_grp> prefix-list PREFIXLIST4_NAME$prefix_list",
           NO_STR
           MATCH_STR
           IP_STR
           "Multicast source address\n"
           "Multicast group address\n"
           "Match against IPv4 prefix list\n"
           "Prefix list name\n")
{
	const char *xpath, *xpval;
	char xpath_value[XPATH_MAXLEN];

	if (do_src)
		xpath = "./match-condition[condition='frr-pim-route-map:ipv4-multicast-source-prefix-list']";
	else
		xpath = "./match-condition[condition='frr-pim-route-map:ipv4-multicast-group-prefix-list']";

	xpval = "/rmap-match-condition/frr-pim-route-map:list-name";

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value), "%s%s", xpath, xpval);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, prefix_list);
	}

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG(route_map_match_prefix_list,
           no_route_map_match_prefix_list_cmd,
           "no match ip <multicast-source$do_src|multicast-group$do_grp> prefix-list",
           NO_STR
           MATCH_STR
           IP_STR
           "Multicast source address\n"
           "Multicast group address\n"
           "Match against IPv4 prefix list\n")

DEFPY_YANG(route_map_match_prefix_list_v6,
           route_map_match_prefix_list_v6_cmd,
           "[no] match ipv6 <multicast-source$do_src|multicast-group$do_grp> prefix-list PREFIXLIST6_NAME$prefix_list",
           NO_STR
           MATCH_STR
           IPV6_STR
           "Multicast source address\n"
           "Multicast group address\n"
           "Match against IPv6 prefix list\n"
           "Prefix list name\n")
{
	const char *xpath, *xpval;
	char xpath_value[XPATH_MAXLEN];

	if (do_src)
		xpath = "./match-condition[condition='frr-pim-route-map:ipv6-multicast-source-prefix-list']";
	else
		xpath = "./match-condition[condition='frr-pim-route-map:ipv6-multicast-group-prefix-list']";

	xpval = "/rmap-match-condition/frr-pim-route-map:list-name";

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value), "%s%s", xpath, xpval);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, prefix_list);
	}

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG(route_map_match_prefix_list_v6,
           no_route_map_match_prefix_list_v6_cmd,
           "no match ipv6 <multicast-source$do_src|multicast-group$do_grp> prefix-list",
           NO_STR
           MATCH_STR
           IPV6_STR
           "Multicast source address\n"
           "Multicast group address\n"
           "Match against IPv6 prefix list\n")

DEFPY_YANG(route_map_match_interface,
           route_map_match_interface_cmd,
           "[no] match multicast-interface IFNAME",
           NO_STR
           MATCH_STR
           "Multicast data interface\n"
           "Interface name\n")
{
	const char *xpath, *xpval;
	char xpath_value[XPATH_MAXLEN];

	xpath = "./match-condition[condition='frr-pim-route-map:multicast-interface']";
	xpval = "/rmap-match-condition/frr-pim-route-map:multicast-interface";

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value), "%s%s", xpath, xpval);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, ifname);
	}

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG(route_map_match_interface,
           no_route_map_match_interface_cmd,
           "no match multicast-interface",
           NO_STR
           MATCH_STR
           "Multicast data interface\n")


/*
 * PIM route map
 */
#include "pim_util.h"

static void *route_map_rule_str_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_map_rule_str_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static enum route_map_cmd_result_t route_match_source(void *rule, const struct prefix *prefix,
						      void *object)
{
	struct pim_rmap_info *info = object;
	struct in_addr addr;
	int ret;

	ret = inet_pton(AF_INET, rule, &addr);
	if (ret != 1)
		return RMAP_NOMATCH;

	if (addr.s_addr != info->sg->src.ipaddr_v4.s_addr)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static const struct route_map_rule_cmd route_match_source_cmd = {
	MULTICAST_IPV4_SOURCE,
	route_match_source,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static enum route_map_cmd_result_t route_match_source_v6(void *rule, const struct prefix *prefix,
							 void *object)
{
	struct pim_rmap_info *info = object;
	struct in6_addr addr;
	int ret;

	ret = inet_pton(AF_INET6, rule, &addr);
	if (ret != 1)
		return RMAP_NOMATCH;

	if (memcmp(&addr, &info->sg->src.ipaddr_v6, sizeof(addr)) != 0)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static const struct route_map_rule_cmd route_match_source_v6_cmd = {
	MULTICAST_IPV6_SOURCE,
	route_match_source_v6,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static enum route_map_cmd_result_t route_match_group(void *rule, const struct prefix *prefix,
						     void *object)
{
	struct pim_rmap_info *info = object;
	struct in_addr addr;
	int ret;

	ret = inet_pton(AF_INET, rule, &addr);
	if (ret != 1)
		return RMAP_NOMATCH;

	if (addr.s_addr != info->sg->grp.ipaddr_v4.s_addr)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static const struct route_map_rule_cmd route_match_group_cmd = {
	MULTICAST_IPV4_GROUP,
	route_match_group,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static enum route_map_cmd_result_t route_match_group_v6(void *rule, const struct prefix *prefix,
							void *object)
{
	struct pim_rmap_info *info = object;
	struct in6_addr addr;
	int ret;

	ret = inet_pton(AF_INET6, rule, &addr);
	if (ret != 1)
		return RMAP_NOMATCH;

	if (memcmp(&addr, &info->sg->grp.ipaddr_v6, sizeof(addr)) != 0)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static const struct route_map_rule_cmd route_match_group_v6_cmd = {
	MULTICAST_IPV6_GROUP,
	route_match_group_v6,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static enum route_map_cmd_result_t
route_match_source_prefix_list(void *rule, const struct prefix *prefix, void *object)
{
	struct pim_rmap_info *info = object;
	struct prefix_list *plist;
	struct prefix_ipv4 p;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.prefix = info->sg->src.ipaddr_v4;

	plist = prefix_list_lookup(AFI_IP, (char *)rule);
	if (!plist)
		return RMAP_NOMATCH;

	if (prefix_list_apply_ext(plist, NULL, &p, true) != PREFIX_PERMIT)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static const struct route_map_rule_cmd route_match_source_prefix_list_cmd = {
	MULTICAST_IPV4_SOURCE_LIST,
	route_match_source_prefix_list,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static enum route_map_cmd_result_t
route_match_source_v6_prefix_list(void *rule, const struct prefix *prefix, void *object)
{
	struct pim_rmap_info *info = object;
	struct prefix_list *plist;
	struct prefix_ipv6 p;

	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	p.prefix = info->sg->src.ipaddr_v6;

	plist = prefix_list_lookup(AFI_IP6, (char *)rule);
	if (!plist)
		return RMAP_NOMATCH;

	if (prefix_list_apply_ext(plist, NULL, &p, true) != PREFIX_PERMIT)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static const struct route_map_rule_cmd route_match_source_v6_prefix_list_cmd = {
	MULTICAST_IPV6_SOURCE_LIST,
	route_match_source_v6_prefix_list,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static enum route_map_cmd_result_t
route_match_group_prefix_list(void *rule, const struct prefix *prefix, void *object)
{
	struct pim_rmap_info *info = object;
	struct prefix_list *plist;
	struct prefix_ipv4 p;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.prefix = info->sg->grp.ipaddr_v4;

	plist = prefix_list_lookup(AFI_IP, (char *)rule);
	if (!plist)
		return RMAP_NOMATCH;

	if (prefix_list_apply_ext(plist, NULL, &p, true) != PREFIX_PERMIT)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static const struct route_map_rule_cmd route_match_group_prefix_list_cmd = {
	MULTICAST_IPV4_GROUP_LIST,
	route_match_group_prefix_list,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static enum route_map_cmd_result_t
route_match_group_v6_prefix_list(void *rule, const struct prefix *prefix, void *object)
{
	struct pim_rmap_info *info = object;
	struct prefix_list *plist;
	struct prefix_ipv6 p;

	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	p.prefix = info->sg->grp.ipaddr_v6;

	plist = prefix_list_lookup(AFI_IP6, (char *)rule);
	if (!plist)
		return RMAP_NOMATCH;

	if (prefix_list_apply_ext(plist, NULL, &p, true) != PREFIX_PERMIT)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static const struct route_map_rule_cmd route_match_group_v6_prefix_list_cmd = {
	MULTICAST_IPV6_GROUP_LIST,
	route_match_group_v6_prefix_list,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static enum route_map_cmd_result_t route_match_interface(void *rule, const struct prefix *prefix,
							 void *object)
{
	struct pim_rmap_info *info = object;
	struct interface *ifp = NULL;
	struct vrf *vrf;

	if (!info->interface)
		return RMAP_NOMATCH;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_name(rule, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL || ifp != info->interface)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static const struct route_map_rule_cmd route_match_interface_cmd = {
	MULTICAST_INTERFACE,
	route_match_interface,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};


static void pim_route_map_add(const char *rmap_name)
{
	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

static void pim_route_map_delete(const char *rmap_name)
{
	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_DELETED);
}

static void pim_route_map_event(const char *rmap_name)
{
	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

void pim_route_map_init(void)
{
	route_map_init();

	route_map_add_hook(pim_route_map_add);
	route_map_delete_hook(pim_route_map_delete);
	route_map_event_hook(pim_route_map_event);

	route_map_match_interface_hook(generic_match_add);
	route_map_no_match_interface_hook(generic_match_delete);

	route_map_install_match(&route_match_source_cmd);
	route_map_install_match(&route_match_source_v6_cmd);
	route_map_install_match(&route_match_group_cmd);
	route_map_install_match(&route_match_group_v6_cmd);
	route_map_install_match(&route_match_source_prefix_list_cmd);
	route_map_install_match(&route_match_source_v6_prefix_list_cmd);
	route_map_install_match(&route_match_group_prefix_list_cmd);
	route_map_install_match(&route_match_group_v6_prefix_list_cmd);
	route_map_install_match(&route_match_interface_cmd);

	install_element(RMAP_NODE, &route_map_match_address_cmd);
	install_element(RMAP_NODE, &no_route_map_match_address_cmd);
	install_element(RMAP_NODE, &route_map_match_address_v6_cmd);
	install_element(RMAP_NODE, &no_route_map_match_address_v6_cmd);
	install_element(RMAP_NODE, &route_map_match_prefix_list_cmd);
	install_element(RMAP_NODE, &no_route_map_match_prefix_list_cmd);
	install_element(RMAP_NODE, &route_map_match_prefix_list_v6_cmd);
	install_element(RMAP_NODE, &no_route_map_match_prefix_list_v6_cmd);
	install_element(RMAP_NODE, &route_map_match_interface_cmd);
	install_element(RMAP_NODE, &no_route_map_match_interface_cmd);
}

void pim_route_map_terminate(void)
{
	route_map_finish();
}


/*
 * Northbound
 */
static int pim_route_map_match_item_modify(struct nb_cb_modify_args *args, const char *rulename)
{
	struct routemap_hook_context *rhc;
	const char *addr;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	addr = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = generic_match_delete;
	rhc->rhc_rule = rulename;
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = generic_match_add(rhc->rhc_rmi, rhc->rhc_rule, addr, RMAP_EVENT_MATCH_ADDED,
			       args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int pim_route_map_match_source_modify(struct nb_cb_modify_args *args)
{
	return pim_route_map_match_item_modify(args, MULTICAST_IPV4_SOURCE);
}

int pim_route_map_match_source_v6_modify(struct nb_cb_modify_args *args)
{
	return pim_route_map_match_item_modify(args, MULTICAST_IPV6_SOURCE);
}

int pim_route_map_match_group_modify(struct nb_cb_modify_args *args)
{
	return pim_route_map_match_item_modify(args, MULTICAST_IPV4_GROUP);
}

int pim_route_map_match_group_v6_modify(struct nb_cb_modify_args *args)
{
	return pim_route_map_match_item_modify(args, MULTICAST_IPV6_GROUP);
}

int pim_route_map_match_interface_modify(struct nb_cb_modify_args *args)
{
	return pim_route_map_match_item_modify(args, MULTICAST_INTERFACE);
}

int pim_route_map_match_list_name_modify(struct nb_cb_modify_args *args)
{
	const char *condition = yang_dnode_get_string(args->dnode, "../../condition");

	if (IS_MATCH_IPV4_MULTICAST_SOURCE_PREFIX_LIST(condition))
		return pim_route_map_match_item_modify(args, MULTICAST_IPV4_SOURCE_LIST);
	else if (IS_MATCH_IPV6_MULTICAST_SOURCE_PREFIX_LIST(condition))
		return pim_route_map_match_item_modify(args, MULTICAST_IPV6_SOURCE_LIST);
	else if (IS_MATCH_IPV4_MULTICAST_GROUP_PREFIX_LIST(condition))
		return pim_route_map_match_item_modify(args, MULTICAST_IPV4_GROUP_LIST);
	else if (IS_MATCH_IPV6_MULTICAST_GROUP_PREFIX_LIST(condition))
		return pim_route_map_match_item_modify(args, MULTICAST_IPV6_GROUP_LIST);

	assertf(0, "unknown YANG condition %s", condition);
}
