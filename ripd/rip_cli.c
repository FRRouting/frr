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
}
