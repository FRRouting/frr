// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 1998 Kunihiro Ishiguro
 * Copyright (C) 2018 NetDEF, Inc.
 *                    Renato Westphal
 */

#include <zebra.h>

#include "if.h"
#include "if_rmap.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "northbound_cli.h"
#include "libfrr.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_nb.h"
#include "ripngd/ripng_cli_clippy.c"

/*
 * XPath: /frr-ripngd:ripngd/instance
 */
DEFPY_YANG_NOSH (router_ripng,
       router_ripng_cmd,
       "router ripng [vrf NAME]",
       "Enable a routing process\n"
       "Make RIPng instance command\n"
       VRF_CMD_HELP_STR)
{
	char xpath[XPATH_MAXLEN];
	int ret;

	/* Build RIPng instance XPath. */
	if (!vrf)
		vrf = VRF_DEFAULT_NAME;
	snprintf(xpath, sizeof(xpath), "/frr-ripngd:ripngd/instance[vrf='%s']",
		 vrf);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(RIPNG_NODE, xpath);

	return ret;
}

DEFPY_YANG (no_router_ripng,
       no_router_ripng_cmd,
       "no router ripng [vrf NAME]",
       NO_STR
       "Enable a routing process\n"
       "Make RIPng instance command\n"
       VRF_CMD_HELP_STR)
{
	char xpath[XPATH_MAXLEN];

	/* Build RIPng instance XPath. */
	if (!vrf)
		vrf = VRF_DEFAULT_NAME;
	snprintf(xpath, sizeof(xpath), "/frr-ripngd:ripngd/instance[vrf='%s']",
		 vrf);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes_clear_pending(vty, NULL);
}

void cli_show_router_ripng(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	const char *vrf_name;

	vrf_name = yang_dnode_get_string(dnode, "vrf");

	vty_out(vty, "!\n");
	vty_out(vty, "router ripng");
	if (!strmatch(vrf_name, VRF_DEFAULT_NAME))
		vty_out(vty, " vrf %s", vrf_name);
	vty_out(vty, "\n");
}

void cli_show_end_router_ripng(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
}

/*
 * XPath: /frr-ripngd:ripngd/instance/allow-ecmp
 */
DEFUN_YANG (ripng_allow_ecmp,
            ripng_allow_ecmp_cmd,
            "allow-ecmp [" CMD_RANGE_STR(1, MULTIPATH_NUM) "]",
            "Allow Equal Cost MultiPath\n"
            "Number of paths\n")
{
	int idx_number = 0;
	char mpaths[3] = {};
	uint32_t paths = MULTIPATH_NUM;

    if (argv_find(argv, argc, CMD_RANGE_STR(1, MULTIPATH_NUM), &idx_number))
		paths = strtol(argv[idx_number]->arg, NULL, 10);
	snprintf(mpaths, sizeof(mpaths), "%u", paths);

	nb_cli_enqueue_change(vty, "./allow-ecmp", NB_OP_MODIFY, mpaths);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_ripng_allow_ecmp,
            no_ripng_allow_ecmp_cmd,
            "no allow-ecmp [" CMD_RANGE_STR(1, MULTIPATH_NUM) "]", NO_STR
            "Allow Equal Cost MultiPath\n"
            "Number of paths\n")
{
	nb_cli_enqueue_change(vty, "./allow-ecmp", NB_OP_MODIFY, 0);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_allow_ecmp(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults)
{
	uint8_t paths;

	paths = yang_dnode_get_uint8(dnode, NULL);

	if (!paths)
		vty_out(vty, " no allow-ecmp\n");
	else
		vty_out(vty, " allow-ecmp %d\n", paths);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/default-information-originate
 */
DEFPY_YANG (ripng_default_information_originate,
       ripng_default_information_originate_cmd,
       "[no] default-information originate",
       NO_STR
       "Default route information\n"
       "Distribute default route\n")
{
	nb_cli_enqueue_change(vty, "./default-information-originate",
			      NB_OP_MODIFY, no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_default_information_originate(struct vty *vty,
						  const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " default-information originate\n");
}

/*
 * XPath: /frr-ripngd:ripngd/instance/default-metric
 */
DEFPY_YANG (ripng_default_metric,
       ripng_default_metric_cmd,
       "default-metric (1-16)",
       "Set a metric of redistribute routes\n"
       "Default metric\n")
{
	nb_cli_enqueue_change(vty, "./default-metric", NB_OP_MODIFY,
			      default_metric_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_ripng_default_metric,
       no_ripng_default_metric_cmd,
       "no default-metric [(1-16)]",
       NO_STR
       "Set a metric of redistribute routes\n"
       "Default metric\n")
{
	nb_cli_enqueue_change(vty, "./default-metric", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_default_metric(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	vty_out(vty, " default-metric %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/network
 */
DEFPY_YANG (ripng_network_prefix,
       ripng_network_prefix_cmd,
       "[no] network X:X::X:X/M",
       NO_STR
       "RIPng enable on specified interface or network.\n"
       "IPv6 network\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./network[.='%s']", network_str);

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_network_prefix(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	vty_out(vty, " network %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/interface
 */
DEFPY_YANG (ripng_network_if,
       ripng_network_if_cmd,
       "[no] network WORD",
       NO_STR
       "RIPng enable on specified interface or network.\n"
       "Interface name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./interface[.='%s']", network);

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_network_interface(struct vty *vty,
				      const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " network %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/offset-list
 */
DEFPY_YANG (ripng_offset_list,
       ripng_offset_list_cmd,
       "[no] offset-list ACCESSLIST6_NAME$acl <in|out>$direction (0-16)$metric [IFNAME]",
       NO_STR
       "Modify RIPng metric\n"
       "Access-list name\n"
       "For incoming updates\n"
       "For outgoing updates\n"
       "Metric value\n"
       "Interface to match\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./access-list", NB_OP_MODIFY, acl);
		nb_cli_enqueue_change(vty, "./metric", NB_OP_MODIFY,
				      metric_str);
	} else
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(
		vty, "./offset-list[interface='%s'][direction='%s']",
		ifname ? ifname : "*", direction);
}

void cli_show_ripng_offset_list(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	const char *interface;

	interface = yang_dnode_get_string(dnode, "interface");

	vty_out(vty, " offset-list %s %s %s",
		yang_dnode_get_string(dnode, "access-list"),
		yang_dnode_get_string(dnode, "direction"),
		yang_dnode_get_string(dnode, "metric"));
	if (!strmatch(interface, "*"))
		vty_out(vty, " %s", interface);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ripngd:ripngd/instance/passive-interface
 */
DEFPY_YANG (ripng_passive_interface,
       ripng_passive_interface_cmd,
       "[no] passive-interface IFNAME",
       NO_STR
       "Suppress routing updates on an interface\n"
       "Interface name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./passive-interface[.='%s']", ifname);

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE,
			      ifname);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_passive_interface(struct vty *vty,
				      const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " passive-interface %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute
 */
DEFPY_YANG (ripng_redistribute,
       ripng_redistribute_cmd,
       "[no] redistribute " FRR_REDIST_STR_RIPNGD "$protocol [{metric (0-16)|route-map RMAP_NAME$route_map}]",
       NO_STR
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPNGD
       "Metric\n"
       "Metric value\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./route-map",
				      route_map ? NB_OP_MODIFY : NB_OP_DESTROY,
				      route_map);
		nb_cli_enqueue_change(vty, "./metric",
				      metric_str ? NB_OP_MODIFY : NB_OP_DESTROY,
				      metric_str);
	} else
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./redistribute[protocol='%s']",
				    protocol);
}

void cli_show_ripng_redistribute(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, " redistribute %s",
		yang_dnode_get_string(dnode, "protocol"));
	if (yang_dnode_exists(dnode, "metric"))
		vty_out(vty, " metric %s",
			yang_dnode_get_string(dnode, "metric"));
	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s",
			yang_dnode_get_string(dnode, "route-map"));
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ripngd:ripngd/instance/static-route
 */
DEFPY_YANG (ripng_route,
       ripng_route_cmd,
       "[no] route X:X::X:X/M",
       NO_STR
       "Static route setup\n"
       "Set static RIPng route announcement\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./static-route[.='%s']", route_str);

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_route(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults)
{
	vty_out(vty, " route %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/aggregate-addres
 */
DEFPY_YANG (ripng_aggregate_address,
       ripng_aggregate_address_cmd,
       "[no] aggregate-address X:X::X:X/M",
       NO_STR
       "Set aggregate RIPng route announcement\n"
       "Aggregate network\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./aggregate-address[.='%s']",
		 aggregate_address_str);

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_aggregate_address(struct vty *vty,
				      const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " aggregate-address %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers
 */
DEFPY_YANG (ripng_timers,
       ripng_timers_cmd,
       "timers basic (1-65535)$update (1-65535)$timeout (1-65535)$garbage",
       "RIPng timers setup\n"
       "Basic timer\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")
{
	nb_cli_enqueue_change(vty, "./update-interval", NB_OP_MODIFY,
			      update_str);
	nb_cli_enqueue_change(vty, "./holddown-interval", NB_OP_MODIFY,
			      timeout_str);
	nb_cli_enqueue_change(vty, "./flush-interval", NB_OP_MODIFY,
			      garbage_str);

	return nb_cli_apply_changes(vty, "./timers");
}

DEFPY_YANG (no_ripng_timers,
       no_ripng_timers_cmd,
       "no timers basic [(1-65535) (1-65535) (1-65535)]",
       NO_STR
       "RIPng timers setup\n"
       "Basic timer\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")
{
	nb_cli_enqueue_change(vty, "./update-interval", NB_OP_MODIFY, NULL);
	nb_cli_enqueue_change(vty, "./holddown-interval", NB_OP_MODIFY, NULL);
	nb_cli_enqueue_change(vty, "./flush-interval", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, "./timers");
}

void cli_show_ripng_timers(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " timers basic %s %s %s\n",
		yang_dnode_get_string(dnode, "update-interval"),
		yang_dnode_get_string(dnode, "holddown-interval"),
		yang_dnode_get_string(dnode, "flush-interval"));
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripngd:ripng/split-horizon
 */
DEFPY_YANG (ipv6_ripng_split_horizon,
       ipv6_ripng_split_horizon_cmd,
       "[no] ipv6 ripng split-horizon [poisoned-reverse$poisoned_reverse]",
       NO_STR
       IPV6_STR
       "Routing Information Protocol\n"
       "Perform split horizon\n"
       "With poisoned-reverse\n")
{
	const char *value;

	if (no)
		value = "disabled";
	else if (poisoned_reverse)
		value = "poison-reverse";
	else
		value = "simple";

	nb_cli_enqueue_change(vty, "./split-horizon", NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, "./frr-ripngd:ripng");
}

void cli_show_ipv6_ripng_split_horizon(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults)
{
	int value;

	value = yang_dnode_get_enum(dnode, NULL);
	switch (value) {
	case RIPNG_NO_SPLIT_HORIZON:
		vty_out(vty, " no ipv6 ripng split-horizon\n");
		break;
	case RIPNG_SPLIT_HORIZON:
		vty_out(vty, " ipv6 ripng split-horizon\n");
		break;
	case RIPNG_SPLIT_HORIZON_POISONED_REVERSE:
		vty_out(vty, " ipv6 ripng split-horizon poisoned-reverse\n");
		break;
	}
}

DEFPY_YANG(
	ripng_ipv6_distribute_list, ripng_ipv6_distribute_list_cmd,
	"ipv6 distribute-list ACCESSLIST6_NAME$name <in|out>$dir [WORD$ifname]",
	"IPv6\n"
	"Filter networks in routing updates\n"
	"Access-list name\n"
	"Filter incoming routing updates\n"
	"Filter outgoing routing updates\n"
	"Interface name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "./distribute-list[interface='%s']/%s/access-list",
		 ifname ? ifname : "", dir);
	/* nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL); */
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, name);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	ripng_ipv6_distribute_list_prefix, ripng_ipv6_distribute_list_prefix_cmd,
	"ipv6 distribute-list prefix PREFIXLIST6_NAME$name <in|out>$dir [WORD$ifname]",
	"IPv6\n"
	"Filter networks in routing updates\n"
	"Specify a prefix list\n"
	"Prefix-list name\n"
	"Filter incoming routing updates\n"
	"Filter outgoing routing updates\n"
	"Interface name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "./distribute-list[interface='%s']/%s/prefix-list",
		 ifname ? ifname : "", dir);
	/* nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL); */
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, name);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_ripng_ipv6_distribute_list,
	   no_ripng_ipv6_distribute_list_cmd,
	   "no ipv6 distribute-list [ACCESSLIST6_NAME$name] <in|out>$dir [WORD$ifname]",
	   NO_STR
	   "IPv6\n"
	   "Filter networks in routing updates\n"
	   "Access-list name\n"
	   "Filter incoming routing updates\n"
	   "Filter outgoing routing updates\n"
	   "Interface name\n")
{
	const struct lyd_node *value_node;
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "./distribute-list[interface='%s']/%s/access-list",
		 ifname ? ifname : "", dir);
	/*
	 * See if the user has specified specific list so check it exists.
	 *
	 * NOTE: Other FRR CLI commands do not do this sort of verification and
	 * there may be an official decision not to.
	 */
	if (name) {
		value_node = yang_dnode_getf(vty->candidate_config->dnode, "%s/%s",
					     VTY_CURR_XPATH, xpath);
		if (!value_node || strcmp(name, lyd_get_value(value_node))) {
			vty_out(vty, "distribute list doesn't exist\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_ripng_ipv6_distribute_list_prefix,
	   no_ripng_ipv6_distribute_list_prefix_cmd,
	   "no ipv6 distribute-list prefix [PREFIXLIST6_NAME$name] <in|out>$dir [WORD$ifname]",
	   NO_STR
	   "IPv6\n"
	   "Filter networks in routing updates\n"
	   "Specify a prefix list\n"
	   "Prefix-list name\n"
	   "Filter incoming routing updates\n"
	   "Filter outgoing routing updates\n"
	   "Interface name\n")
{
	const struct lyd_node *value_node;
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "./distribute-list[interface='%s']/%s/prefix-list",
		 ifname ? ifname : "", dir);
	/*
	 * See if the user has specified specific list so check it exists.
	 *
	 * NOTE: Other FRR CLI commands do not do this sort of verification and
	 * there may be an official decision not to.
	 */
	if (name) {
		value_node = yang_dnode_getf(vty->candidate_config->dnode, "%s/%s",
					     VTY_CURR_XPATH, xpath);
		if (!value_node || strcmp(name, lyd_get_value(value_node))) {
			vty_out(vty, "distribute list doesn't exist\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* RIPng node structure. */
static struct cmd_node cmd_ripng_node = {
	.name = "ripng",
	.node = RIPNG_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
};

void ripng_cli_init(void)
{
	/* Install RIPNG_NODE. */
	install_node(&cmd_ripng_node);
	install_default(RIPNG_NODE);

	install_element(CONFIG_NODE, &router_ripng_cmd);
	install_element(CONFIG_NODE, &no_router_ripng_cmd);

	install_element(RIPNG_NODE, &ripng_ipv6_distribute_list_cmd);
	install_element(RIPNG_NODE, &ripng_ipv6_distribute_list_prefix_cmd);
	install_element(RIPNG_NODE, &no_ripng_ipv6_distribute_list_cmd);
	install_element(RIPNG_NODE, &no_ripng_ipv6_distribute_list_prefix_cmd);

	install_element(RIPNG_NODE, &ripng_allow_ecmp_cmd);
	install_element(RIPNG_NODE, &no_ripng_allow_ecmp_cmd);
	install_element(RIPNG_NODE, &ripng_default_information_originate_cmd);
	install_element(RIPNG_NODE, &ripng_default_metric_cmd);
	install_element(RIPNG_NODE, &no_ripng_default_metric_cmd);
	install_element(RIPNG_NODE, &ripng_network_prefix_cmd);
	install_element(RIPNG_NODE, &ripng_network_if_cmd);
	install_element(RIPNG_NODE, &ripng_offset_list_cmd);
	install_element(RIPNG_NODE, &ripng_passive_interface_cmd);
	install_element(RIPNG_NODE, &ripng_redistribute_cmd);
	install_element(RIPNG_NODE, &ripng_route_cmd);
	install_element(RIPNG_NODE, &ripng_aggregate_address_cmd);
	install_element(RIPNG_NODE, &ripng_timers_cmd);
	install_element(RIPNG_NODE, &no_ripng_timers_cmd);

	install_element(INTERFACE_NODE, &ipv6_ripng_split_horizon_cmd);

	if_rmap_init(RIPNG_NODE);
}

/* clang-format off */
const struct frr_yang_module_info frr_ripngd_cli_info = {
	.name = "frr-ripngd",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-ripngd:ripngd/instance",
			.cbs.cli_show = cli_show_router_ripng,
			.cbs.cli_show_end = cli_show_end_router_ripng,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/allow-ecmp",
			.cbs.cli_show = cli_show_ripng_allow_ecmp,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/default-information-originate",
			.cbs.cli_show = cli_show_ripng_default_information_originate,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/default-metric",
			.cbs.cli_show = cli_show_ripng_default_metric,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/network",
			.cbs.cli_show = cli_show_ripng_network_prefix,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/interface",
			.cbs.cli_show = cli_show_ripng_network_interface,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/offset-list",
			.cbs.cli_show = cli_show_ripng_offset_list,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/passive-interface",
			.cbs.cli_show = cli_show_ripng_passive_interface,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/distribute-list/in/access-list",
			.cbs.cli_show = group_distribute_list_ipv6_cli_show,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/distribute-list/out/access-list",
			.cbs.cli_show = group_distribute_list_ipv6_cli_show,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/distribute-list/in/prefix-list",
			.cbs.cli_show = group_distribute_list_ipv6_cli_show,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/distribute-list/out/prefix-list",
			.cbs.cli_show = group_distribute_list_ipv6_cli_show,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/redistribute",
			.cbs.cli_show = cli_show_ripng_redistribute,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/if-route-maps/if-route-map",
			.cbs.cli_show = cli_show_if_route_map,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/static-route",
			.cbs.cli_show = cli_show_ripng_route,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/aggregate-address",
			.cbs.cli_show = cli_show_ripng_aggregate_address,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/timers",
			.cbs.cli_show = cli_show_ripng_timers,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripngd:ripng/split-horizon",
			.cbs = {
				.cli_show = cli_show_ipv6_ripng_split_horizon,
			},
		},
		{
			.xpath = NULL,
		},
	}
};
