/*
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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

#include "ripd/ripd.h"
#include "ripd/rip_cli.h"
#ifndef VTYSH_EXTRACT_PL
#include "ripd/rip_cli_clippy.c"
#endif

/*
 * XPath: /frr-ripd:ripd/instance
 */
DEFPY_NOSH (router_rip,
       router_rip_cmd,
       "router rip",
       "Enable a routing process\n"
       "Routing Information Protocol (RIP)\n")
{
	int ret;

	struct cli_config_change changes[] = {
		{
			.xpath = "/frr-ripd:ripd/instance",
			.operation = NB_OP_CREATE,
			.value = NULL,
		},
	};

	ret = nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(RIP_NODE, changes[0].xpath);

	return ret;
}

DEFPY (no_router_rip,
       no_router_rip_cmd,
       "no router rip",
       NO_STR
       "Enable a routing process\n"
       "Routing Information Protocol (RIP)\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "/frr-ripd:ripd/instance",
			.operation = NB_OP_DELETE,
			.value = NULL,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_router_rip(struct vty *vty, struct lyd_node *dnode,
			 bool show_defaults)
{
	vty_out(vty, "!\n");
	vty_out(vty, "router rip\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/allow-ecmp
 */
DEFPY (rip_allow_ecmp,
       rip_allow_ecmp_cmd,
       "[no] allow-ecmp",
       NO_STR
       "Allow Equal Cost MultiPath\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./allow-ecmp",
			.operation = NB_OP_MODIFY,
			.value = no ? "false" : "true",
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_rip_allow_ecmp(struct vty *vty, struct lyd_node *dnode,
			     bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " allow-ecmp\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/default-information-originate
 */
DEFPY (rip_default_information_originate,
       rip_default_information_originate_cmd,
       "[no] default-information originate",
       NO_STR
       "Control distribution of default route\n"
       "Distribute a default route\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./default-information-originate",
			.operation = NB_OP_MODIFY,
			.value = no ? "false" : "true",
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_rip_default_information_originate(struct vty *vty,
						struct lyd_node *dnode,
						bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " default-information originate\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/default-metric
 */
DEFPY (rip_default_metric,
       rip_default_metric_cmd,
       "default-metric (1-16)",
       "Set a metric of redistribute routes\n"
       "Default metric\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./default-metric",
			.operation = NB_OP_MODIFY,
			.value = default_metric_str,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

DEFPY (no_rip_default_metric,
       no_rip_default_metric_cmd,
       "no default-metric [(1-16)]",
       NO_STR
       "Set a metric of redistribute routes\n"
       "Default metric\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./default-metric",
			.operation = NB_OP_MODIFY,
			.value = NULL,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_rip_default_metric(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, " default-metric %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/default
 */
DEFPY (rip_distance,
       rip_distance_cmd,
       "distance (1-255)",
       "Administrative distance\n"
       "Distance value\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./distance/default",
			.operation = NB_OP_MODIFY,
			.value = distance_str,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

DEFPY (no_rip_distance,
       no_rip_distance_cmd,
       "no distance [(1-255)]",
       NO_STR
       "Administrative distance\n"
       "Distance value\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./distance/default",
			.operation = NB_OP_MODIFY,
			.value = NULL,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_rip_distance(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " distance %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/source
 */
DEFPY (rip_distance_source,
       rip_distance_source_cmd,
       "distance (1-255) A.B.C.D/M$prefix [WORD$acl]",
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n"
       "Access list name\n")
{
	char xpath_list[XPATH_MAXLEN];
	struct cli_config_change changes[] = {
		{
			.xpath = ".",
			.operation = NB_OP_CREATE,
		},
		{
			.xpath = "./distance",
			.operation = NB_OP_MODIFY,
			.value = distance_str,
		},
		{
			.xpath = "./access-list",
			.operation = acl ? NB_OP_MODIFY : NB_OP_DELETE,
			.value = acl,
		},
	};

	snprintf(xpath_list, sizeof(xpath_list),
		 "./distance/source[prefix='%s']", prefix_str);

	return nb_cli_cfg_change(vty, xpath_list, changes, array_size(changes));
}

DEFPY (no_rip_distance_source,
       no_rip_distance_source_cmd,
       "no distance (1-255) A.B.C.D/M$prefix [WORD$acl]",
       NO_STR
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n"
       "Access list name\n")
{
	char xpath_list[XPATH_MAXLEN];
	struct cli_config_change changes[] = {
		{
			.xpath = ".",
			.operation = NB_OP_DELETE,
		},
	};

	snprintf(xpath_list, sizeof(xpath_list),
		 "./distance/source[prefix='%s']", prefix_str);

	return nb_cli_cfg_change(vty, xpath_list, changes, 1);
}

void cli_show_rip_distance_source(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults)
{
	vty_out(vty, " distance %s %s",
		yang_dnode_get_string(dnode, "./distance"),
		yang_dnode_get_string(dnode, "./prefix"));
	if (yang_dnode_exists(dnode, "./access-list"))
		vty_out(vty, " %s",
			yang_dnode_get_string(dnode, "./access-list"));
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/explicit-neighbor
 */
DEFPY (rip_neighbor,
       rip_neighbor_cmd,
       "[no] neighbor A.B.C.D",
       NO_STR
       "Specify a neighbor router\n"
       "Neighbor address\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./explicit-neighbor",
			.operation = no ? NB_OP_DELETE : NB_OP_CREATE,
			.value = neighbor_str,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_rip_neighbor(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " neighbor %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/network
 */
DEFPY (rip_network_prefix,
       rip_network_prefix_cmd,
       "[no] network A.B.C.D/M",
       NO_STR
       "Enable routing on an IP network\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./network",
			.operation = no ? NB_OP_DELETE : NB_OP_CREATE,
			.value = network_str,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_rip_network_prefix(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, " network %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/interface
 */
DEFPY (rip_network_if,
       rip_network_if_cmd,
       "[no] network WORD",
       NO_STR
       "Enable routing on an IP network\n"
       "Interface name\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./interface",
			.operation = no ? NB_OP_DELETE : NB_OP_CREATE,
			.value = network,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_rip_network_interface(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, " network %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/offset-list
 */
DEFPY (rip_offset_list,
       rip_offset_list_cmd,
       "offset-list WORD$acl <in|out>$direction (0-16)$metric [IFNAME]",
       "Modify RIP metric\n"
       "Access-list name\n"
       "For incoming updates\n"
       "For outgoing updates\n"
       "Metric value\n"
       "Interface to match\n")
{
	char xpath_list[XPATH_MAXLEN];
	struct cli_config_change changes[] = {
		{
			.xpath = ".",
			.operation = NB_OP_CREATE,
		},
		{
			.xpath = "./access-list",
			.operation = NB_OP_MODIFY,
			.value = acl,
		},
		{
			.xpath = "./metric",
			.operation = NB_OP_MODIFY,
			.value = metric_str,
		},
	};

	snprintf(xpath_list, sizeof(xpath_list),
		 "./offset-list[interface='%s'][direction='%s']",
		 ifname ? ifname : "*", direction);

	return nb_cli_cfg_change(vty, xpath_list, changes, array_size(changes));
}

DEFPY (no_rip_offset_list,
       no_rip_offset_list_cmd,
       "no offset-list WORD$acl <in|out>$direction (0-16)$metric [IFNAME]",
       NO_STR
       "Modify RIP metric\n"
       "Access-list name\n"
       "For incoming updates\n"
       "For outgoing updates\n"
       "Metric value\n"
       "Interface to match\n")
{
	char xpath_list[XPATH_MAXLEN];
	struct cli_config_change changes[] = {
		{
			.xpath = ".",
			.operation = NB_OP_DELETE,
		},
	};

	snprintf(xpath_list, sizeof(xpath_list),
		 "./offset-list[interface='%s'][direction='%s']",
		 ifname ? ifname : "*", direction);

	return nb_cli_cfg_change(vty, xpath_list, changes, array_size(changes));
}

void cli_show_rip_offset_list(struct vty *vty, struct lyd_node *dnode,
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
 * XPath: /frr-ripd:ripd/instance/passive-default
 */
DEFPY (rip_passive_default,
       rip_passive_default_cmd,
       "[no] passive-interface default",
       NO_STR
       "Suppress routing updates on an interface\n"
       "default for all interfaces\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./passive-default",
			.operation = NB_OP_MODIFY,
			.value = no ? "false" : "true",
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_rip_passive_default(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " passive-interface default\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/passive-interface
 *        /frr-ripd:ripd/instance/non-passive-interface
 */
DEFPY (rip_passive_interface,
       rip_passive_interface_cmd,
       "[no] passive-interface IFNAME",
       NO_STR
       "Suppress routing updates on an interface\n"
       "Interface name\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./passive-interface",
			.operation = no ? NB_OP_DELETE : NB_OP_CREATE,
			.value = ifname,
		},
		{
			.xpath = "./non-passive-interface",
			.operation = no ? NB_OP_CREATE : NB_OP_DELETE,
			.value = ifname,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_rip_passive_interface(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, " passive-interface %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void cli_show_rip_non_passive_interface(struct vty *vty, struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, " no passive-interface %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/redistribute
 */
DEFPY (rip_redistribute,
       rip_redistribute_cmd,
       "redistribute " FRR_REDIST_STR_RIPD "$protocol [{metric (0-16)|route-map WORD}]",
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPD
       "Metric\n"
       "Metric value\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	char xpath_list[XPATH_MAXLEN];
	struct cli_config_change changes[] = {
		{
			.xpath = ".",
			.operation = NB_OP_CREATE,
		},
		{
			.xpath = "./route-map",
			.operation = route_map ? NB_OP_MODIFY : NB_OP_DELETE,
			.value = route_map,
		},
		{
			.xpath = "./metric",
			.operation = metric_str ? NB_OP_MODIFY : NB_OP_DELETE,
			.value = metric_str,
		},
	};

	snprintf(xpath_list, sizeof(xpath_list),
		 "./redistribute[protocol='%s']", protocol);

	return nb_cli_cfg_change(vty, xpath_list, changes, array_size(changes));
}

DEFPY (no_rip_redistribute,
       no_rip_redistribute_cmd,
       "no redistribute " FRR_REDIST_STR_RIPD "$protocol [{metric (0-16)|route-map WORD}]",
       NO_STR
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPD
       "Metric\n"
       "Metric value\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	char xpath_list[XPATH_MAXLEN];
	struct cli_config_change changes[] = {
		{
			.xpath = ".",
			.operation = NB_OP_DELETE,
		},
	};

	snprintf(xpath_list, sizeof(xpath_list),
		 "./redistribute[protocol='%s']", protocol);

	return nb_cli_cfg_change(vty, xpath_list, changes, array_size(changes));
}

void cli_show_rip_redistribute(struct vty *vty, struct lyd_node *dnode,
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
 * XPath: /frr-ripd:ripd/instance/static-route
 */
DEFPY (rip_route,
       rip_route_cmd,
       "[no] route A.B.C.D/M",
       NO_STR
       "RIP static route configuration\n"
       "IP prefix <network>/<length>\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./static-route",
			.operation = no ? NB_OP_DELETE : NB_OP_CREATE,
			.value = route_str,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_rip_route(struct vty *vty, struct lyd_node *dnode,
			bool show_defaults)
{
	vty_out(vty, " route %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/timers
 */
DEFPY (rip_timers,
       rip_timers_cmd,
       "timers basic (5-2147483647)$update (5-2147483647)$timeout (5-2147483647)$garbage",
       "Adjust routing timers\n"
       "Basic routing protocol update timers\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./timers/update-interval",
			.operation = NB_OP_MODIFY,
			.value = update_str,
		},
		{
			.xpath = "./timers/holddown-interval",
			.operation = NB_OP_MODIFY,
			.value = timeout_str,
		},
		{
			.xpath = "./timers/flush-interval",
			.operation = NB_OP_MODIFY,
			.value = garbage_str,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

DEFPY (no_rip_timers,
       no_rip_timers_cmd,
       "no timers basic [(5-2147483647) (5-2147483647) (5-2147483647)]",
       NO_STR
       "Adjust routing timers\n"
       "Basic routing protocol update timers\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./timers/update-interval",
			.operation = NB_OP_MODIFY,
			.value =  NULL,
		},
		{
			.xpath = "./timers/holddown-interval",
			.operation = NB_OP_MODIFY,
			.value =  NULL,
		},
		{
			.xpath = "./timers/flush-interval",
			.operation = NB_OP_MODIFY,
			.value =  NULL,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_rip_timers(struct vty *vty, struct lyd_node *dnode,
			 bool show_defaults)
{
	vty_out(vty, " timers basic %s %s %s\n",
		yang_dnode_get_string(dnode, "./update-interval"),
		yang_dnode_get_string(dnode, "./holddown-interval"),
		yang_dnode_get_string(dnode, "./flush-interval"));
}

/*
 * XPath: /frr-ripd:ripd/instance/version
 */
DEFPY (rip_version,
       rip_version_cmd,
       "version (1-2)",
       "Set routing protocol version\n"
       "version\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./version/receive",
			.operation = NB_OP_MODIFY,
			.value = version_str,
		},
		{
			.xpath = "./version/send",
			.operation = NB_OP_MODIFY,
			.value = version_str,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

DEFPY (no_rip_version,
       no_rip_version_cmd,
       "no version [(1-2)]",
       NO_STR
       "Set routing protocol version\n"
       "version\n")
{
	struct cli_config_change changes[] = {
		{
			.xpath = "./version/receive",
			.operation = NB_OP_MODIFY,
		},
		{
			.xpath = "./version/send",
			.operation = NB_OP_MODIFY,
		},
	};

	return nb_cli_cfg_change(vty, NULL, changes, array_size(changes));
}

void cli_show_rip_version(struct vty *vty, struct lyd_node *dnode,
			  bool show_defaults)
{
	/*
	 * We have only one "version" command and three possible combinations of
	 * send/receive values.
	 */
	switch (yang_dnode_get_enum(dnode, "./receive")) {
	case RI_RIP_VERSION_1:
		vty_out(vty, " version 1\n");
		break;
	case RI_RIP_VERSION_2:
		vty_out(vty, " version 2\n");
		break;
	case RI_RIP_VERSION_1_AND_2:
		vty_out(vty, " no version\n");
		break;
	}
}

void rip_cli_init(void)
{
	install_element(CONFIG_NODE, &router_rip_cmd);
	install_element(CONFIG_NODE, &no_router_rip_cmd);

	install_element(RIP_NODE, &rip_allow_ecmp_cmd);
	install_element(RIP_NODE, &rip_default_information_originate_cmd);
	install_element(RIP_NODE, &rip_default_metric_cmd);
	install_element(RIP_NODE, &no_rip_default_metric_cmd);
	install_element(RIP_NODE, &rip_distance_cmd);
	install_element(RIP_NODE, &no_rip_distance_cmd);
	install_element(RIP_NODE, &rip_distance_source_cmd);
	install_element(RIP_NODE, &no_rip_distance_source_cmd);
	install_element(RIP_NODE, &rip_neighbor_cmd);
	install_element(RIP_NODE, &rip_network_prefix_cmd);
	install_element(RIP_NODE, &rip_network_if_cmd);
	install_element(RIP_NODE, &rip_offset_list_cmd);
	install_element(RIP_NODE, &no_rip_offset_list_cmd);
	install_element(RIP_NODE, &rip_passive_default_cmd);
	install_element(RIP_NODE, &rip_passive_interface_cmd);
	install_element(RIP_NODE, &rip_redistribute_cmd);
	install_element(RIP_NODE, &no_rip_redistribute_cmd);
	install_element(RIP_NODE, &rip_route_cmd);
	install_element(RIP_NODE, &rip_timers_cmd);
	install_element(RIP_NODE, &no_rip_timers_cmd);
	install_element(RIP_NODE, &rip_version_cmd);
	install_element(RIP_NODE, &no_rip_version_cmd);
}
