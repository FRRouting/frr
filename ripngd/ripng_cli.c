/*
 * Copyright (C) 1998 Kunihiro Ishiguro
 * Copyright (C) 2018 NetDEF, Inc.
 *                    Renato Westphal
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "northbound_cli.h"
#include "libfrr.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_nb.h"
#ifndef VTYSH_EXTRACT_PL
#include "ripngd/ripng_cli_clippy.c"
#endif

/*
 * XPath: /frr-ripngd:ripngd/instance
 */
DEFPY_NOSH (router_ripng,
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

DEFPY (no_router_ripng,
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

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_router_ripng(struct vty *vty, struct lyd_node *dnode,
			 bool show_defaults)
{
	const char *vrf_name;

	vrf_name = yang_dnode_get_string(dnode, "./vrf");

	vty_out(vty, "!\n");
	vty_out(vty, "router ripng");
	if (!strmatch(vrf_name, VRF_DEFAULT_NAME))
		vty_out(vty, " vrf %s", vrf_name);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ripngd:ripngd/instance/allow-ecmp
 */
DEFPY (ripng_allow_ecmp,
       ripng_allow_ecmp_cmd,
       "[no] allow-ecmp",
       NO_STR
       "Allow Equal Cost MultiPath\n")
{
	nb_cli_enqueue_change(vty, "./allow-ecmp", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_allow_ecmp(struct vty *vty, struct lyd_node *dnode,
			       bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " allow-ecmp\n");
}

/*
 * XPath: /frr-ripngd:ripngd/instance/default-information-originate
 */
DEFPY (ripng_default_information_originate,
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
						  struct lyd_node *dnode,
						  bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " default-information originate\n");
}

/*
 * XPath: /frr-ripngd:ripngd/instance/default-metric
 */
DEFPY (ripng_default_metric,
       ripng_default_metric_cmd,
       "default-metric (1-16)",
       "Set a metric of redistribute routes\n"
       "Default metric\n")
{
	nb_cli_enqueue_change(vty, "./default-metric", NB_OP_MODIFY,
			      default_metric_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY (no_ripng_default_metric,
       no_ripng_default_metric_cmd,
       "no default-metric [(1-16)]",
       NO_STR
       "Set a metric of redistribute routes\n"
       "Default metric\n")
{
	nb_cli_enqueue_change(vty, "./default-metric", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_default_metric(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults)
{
	vty_out(vty, " default-metric %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/network
 */
DEFPY (ripng_network_prefix,
       ripng_network_prefix_cmd,
       "[no] network X:X::X:X/M",
       NO_STR
       "RIPng enable on specified interface or network.\n"
       "IPv6 network\n")
{
	nb_cli_enqueue_change(vty, "./network",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, network_str);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_network_prefix(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults)
{
	vty_out(vty, " network %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/interface
 */
DEFPY (ripng_network_if,
       ripng_network_if_cmd,
       "[no] network WORD",
       NO_STR
       "RIPng enable on specified interface or network.\n"
       "Interface name\n")
{
	nb_cli_enqueue_change(vty, "./interface",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, network);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_network_interface(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " network %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/offset-list
 */
DEFPY (ripng_offset_list,
       ripng_offset_list_cmd,
       "[no] offset-list WORD$acl <in|out>$direction (0-16)$metric [IFNAME]",
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

void cli_show_ripng_offset_list(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	const char *interface;

	interface = yang_dnode_get_string(dnode, "./interface");

	vty_out(vty, " offset-list %s %s %s",
		yang_dnode_get_string(dnode, "./access-list"),
		yang_dnode_get_string(dnode, "./direction"),
		yang_dnode_get_string(dnode, "./metric"));
	if (!strmatch(interface, "*"))
		vty_out(vty, " %s", interface);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ripngd:ripngd/instance/passive-interface
 */
DEFPY (ripng_passive_interface,
       ripng_passive_interface_cmd,
       "[no] passive-interface IFNAME",
       NO_STR
       "Suppress routing updates on an interface\n"
       "Interface name\n")
{
	nb_cli_enqueue_change(vty, "./passive-interface",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, ifname);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_passive_interface(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " passive-interface %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute
 */
DEFPY (ripng_redistribute,
       ripng_redistribute_cmd,
       "[no] redistribute " FRR_REDIST_STR_RIPNGD "$protocol [{metric (0-16)|route-map WORD}]",
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

void cli_show_ripng_redistribute(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, " redistribute %s",
		yang_dnode_get_string(dnode, "./protocol"));
	if (yang_dnode_exists(dnode, "./metric"))
		vty_out(vty, " metric %s",
			yang_dnode_get_string(dnode, "./metric"));
	if (yang_dnode_exists(dnode, "./route-map"))
		vty_out(vty, " route-map %s",
			yang_dnode_get_string(dnode, "./route-map"));
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ripngd:ripngd/instance/static-route
 */
DEFPY (ripng_route,
       ripng_route_cmd,
       "[no] route X:X::X:X/M",
       NO_STR
       "Static route setup\n"
       "Set static RIPng route announcement\n")
{
	nb_cli_enqueue_change(vty, "./static-route",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, route_str);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_route(struct vty *vty, struct lyd_node *dnode,
			  bool show_defaults)
{
	vty_out(vty, " route %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/aggregate-addres
 */
DEFPY (ripng_aggregate_address,
       ripng_aggregate_address_cmd,
       "[no] aggregate-address X:X::X:X/M",
       NO_STR
       "Set aggregate RIPng route announcement\n"
       "Aggregate network\n")
{
	nb_cli_enqueue_change(vty, "./aggregate-address",
			      no ? NB_OP_DESTROY : NB_OP_CREATE,
			      aggregate_address_str);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripng_aggregate_address(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " aggregate-address %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers
 */
DEFPY (ripng_timers,
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

DEFPY (no_ripng_timers,
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

void cli_show_ripng_timers(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " timers basic %s %s %s\n",
		yang_dnode_get_string(dnode, "./update-interval"),
		yang_dnode_get_string(dnode, "./holddown-interval"),
		yang_dnode_get_string(dnode, "./flush-interval"));
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripngd:ripng/split-horizon
 */
DEFPY (ipv6_ripng_split_horizon,
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

void cli_show_ipv6_ripng_split_horizon(struct vty *vty, struct lyd_node *dnode,
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

/*
 * XPath: /frr-ripngd:clear-ripng-route
 */
DEFPY (clear_ipv6_rip,
       clear_ipv6_rip_cmd,
       "clear ipv6 ripng [vrf WORD]",
       CLEAR_STR
       IPV6_STR
       "Clear IPv6 RIP database\n"
       VRF_CMD_HELP_STR)
{
	struct list *input;

	input = list_new();
	if (vrf) {
		struct yang_data *yang_vrf;

		yang_vrf = yang_data_new(
			"/frr-ripngd:clear-ripng-route/input/vrf", vrf);
		listnode_add(input, yang_vrf);
	}

	return nb_cli_rpc("/frr-ripngd:clear-ripng-route", input, NULL);
}

void ripng_cli_init(void)
{
	install_element(CONFIG_NODE, &router_ripng_cmd);
	install_element(CONFIG_NODE, &no_router_ripng_cmd);

	install_element(RIPNG_NODE, &ripng_allow_ecmp_cmd);
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

	install_element(ENABLE_NODE, &clear_ipv6_rip_cmd);
}
