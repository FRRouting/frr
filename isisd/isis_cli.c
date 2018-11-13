/*
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2018        Volta Networks
 *                           Emanuele Di Pascale
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
#include "yang.h"
#include "lib/linklist.h"
#include "isisd/isisd.h"
#include "isisd/isis_cli.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_csm.h"

#ifndef VTYSH_EXTRACT_PL
#include "isisd/isis_cli_clippy.c"
#endif

#ifndef FABRICD

/*
 * XPath: /frr-isisd:isis/instance
 */
DEFPY_NOSH(router_isis, router_isis_cmd, "router isis WORD$tag",
	   ROUTER_STR
	   "ISO IS-IS\n"
	   "ISO Routing area tag\n")
{
	int ret;
	char base_xpath[XPATH_MAXLEN];

	snprintf(base_xpath, XPATH_MAXLEN,
		 "/frr-isisd:isis/instance[area-tag='%s']", tag);
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
	/* default value in yang for is-type is level-1, but in FRR
	 * the first instance is assigned is-type level-1-2. We
	 * need to make sure to set it in the yang model so that it
	 * is consistent with what FRR sees.
	 */
	if (listcount(isis->area_list) == 0)
		nb_cli_enqueue_change(vty, "./is-type", NB_OP_MODIFY,
				      "level-1-2");
	ret = nb_cli_apply_changes(vty, base_xpath);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(ISIS_NODE, base_xpath);

	return ret;
}

DEFPY(no_router_isis, no_router_isis_cmd, "no router isis WORD$tag",
      NO_STR ROUTER_STR
      "ISO IS-IS\n"
      "ISO Routing area tag\n")
{
	char temp_xpath[XPATH_MAXLEN];
	struct listnode *node, *nnode;
	struct isis_circuit *circuit = NULL;
	struct isis_area *area = NULL;

	area = isis_area_lookup(tag);
	if (!area) {
		vty_out(vty, "ISIS area %s not found.\n", tag);
		return CMD_ERR_NOTHING_TODO;
	}

	nb_cli_enqueue_change(vty, ".", NB_OP_DELETE, NULL);
	if (area->circuit_list && listcount(area->circuit_list)) {
		for (ALL_LIST_ELEMENTS(area->circuit_list, node, nnode,
				       circuit)) {
			/* add callbacks to delete each of the circuits listed
			 */
			const char *vrf_name =
				vrf_lookup_by_id(circuit->interface->vrf_id)
					->name;
			snprintf(
				temp_xpath, XPATH_MAXLEN,
				"/frr-interface:lib/interface[name='%s'][vrf='%s']/frr-isisd:isis",
				circuit->interface->name, vrf_name);
			nb_cli_enqueue_change(vty, temp_xpath, NB_OP_DELETE,
					      NULL);
		}
	}

	return nb_cli_apply_changes(
		vty, "/frr-isisd:isis/instance[area-tag='%s']", tag);
}

void cli_show_router_isis(struct vty *vty, struct lyd_node *dnode,
			  bool show_defaults)
{
	vty_out(vty, "!\n");
	vty_out(vty, "router isis %s\n",
		yang_dnode_get_string(dnode, "./area-tag"));
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv4-routing
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv6-routing
 * XPath: /frr-isisd:isis/instance
 */
DEFPY(ip_router_isis, ip_router_isis_cmd, "ip router isis WORD$tag",
      "Interface Internet Protocol config commands\n"
      "IP router interface commands\n"
      "IS-IS routing protocol\n"
      "Routing process tag\n")
{
	char temp_xpath[XPATH_MAXLEN];
	const char *circ_type;
	struct isis_area *area;

	/* area will be created if it is not present. make sure the yang model
	 * is synced with FRR and call the appropriate NB cb.
	 */
	area = isis_area_lookup(tag);
	if (!area) {
		snprintf(temp_xpath, XPATH_MAXLEN,
			 "/frr-isisd:isis/instance[area-tag='%s']", tag);
		nb_cli_enqueue_change(vty, temp_xpath, NB_OP_CREATE, tag);
		snprintf(temp_xpath, XPATH_MAXLEN,
			 "/frr-isisd:isis/instance[area-tag='%s']/is-type",
			 tag);
		nb_cli_enqueue_change(
			vty, temp_xpath, NB_OP_MODIFY,
			listcount(isis->area_list) == 0 ? "level-1-2" : NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis", NB_OP_CREATE,
				      NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/area-tag",
				      NB_OP_MODIFY, tag);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/ipv4-routing",
				      NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(
			vty, "./frr-isisd:isis/circuit-type", NB_OP_MODIFY,
			listcount(isis->area_list) == 0 ? "level-1-2"
							: "level-1");
	} else {
		/* area exists, circuit type defaults to its area's is_type */
		switch (area->is_type) {
		case IS_LEVEL_1:
			circ_type = "level-1";
			break;
		case IS_LEVEL_2:
			circ_type = "level-2";
			break;
		case IS_LEVEL_1_AND_2:
			circ_type = "level-1-2";
			break;
		}
		nb_cli_enqueue_change(vty, "./frr-isisd:isis", NB_OP_CREATE,
				      NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/area-tag",
				      NB_OP_MODIFY, tag);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/ipv4-routing",
				      NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/circuit-type",
				      NB_OP_MODIFY, circ_type);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(ip6_router_isis, ip6_router_isis_cmd, "ipv6 router isis WORD$tag",
      "Interface Internet Protocol config commands\n"
      "IP router interface commands\n"
      "IS-IS routing protocol\n"
      "Routing process tag\n")
{
	char temp_xpath[XPATH_MAXLEN];
	const char *circ_type;
	struct isis_area *area;

	/* area will be created if it is not present. make sure the yang model
	 * is synced with FRR and call the appropriate NB cb.
	 */
	area = isis_area_lookup(tag);
	if (!area) {
		snprintf(temp_xpath, XPATH_MAXLEN,
			 "/frr-isisd:isis/instance[area-tag='%s']", tag);
		nb_cli_enqueue_change(vty, temp_xpath, NB_OP_CREATE, tag);
		snprintf(temp_xpath, XPATH_MAXLEN,
			 "/frr-isisd:isis/instance[area-tag='%s']/is-type",
			 tag);
		nb_cli_enqueue_change(
			vty, temp_xpath, NB_OP_MODIFY,
			listcount(isis->area_list) == 0 ? "level-1-2" : NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis", NB_OP_CREATE,
				      NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/area-tag",
				      NB_OP_MODIFY, tag);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/ipv6-routing",
				      NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(
			vty, "./frr-isisd:isis/circuit-type", NB_OP_MODIFY,
			listcount(isis->area_list) == 0 ? "level-1-2"
							: "level-1");
	} else {
		/* area exists, circuit type defaults to its area's is_type */
		switch (area->is_type) {
		case IS_LEVEL_1:
			circ_type = "level-1";
			break;
		case IS_LEVEL_2:
			circ_type = "level-2";
			break;
		case IS_LEVEL_1_AND_2:
			circ_type = "level-1-2";
			break;
		}
		nb_cli_enqueue_change(vty, "./frr-isisd:isis", NB_OP_CREATE,
				      NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/area-tag",
				      NB_OP_MODIFY, tag);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/ipv6-routing",
				      NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/circuit-type",
				      NB_OP_MODIFY, circ_type);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_ip_router_isis, no_ip_router_isis_cmd,
      "no <ip|ipv6>$ip router isis [WORD]$tag",
      NO_STR
      "Interface Internet Protocol config commands\n"
      "IP router interface commands\n"
      "IP router interface commands\n"
      "IS-IS routing protocol\n"
      "Routing process tag\n")
{
	const struct lyd_node *dnode =
		yang_dnode_get(running_config->dnode, VTY_CURR_XPATH);
	struct interface *ifp;
	struct isis_circuit *circuit = NULL;

	/* check for the existance of a circuit */
	if (dnode) {
		ifp = yang_dnode_get_entry(dnode, false);
		if (ifp)
			circuit = circuit_scan_by_ifp(ifp);
	}

	/* if both ipv4 and ipv6 are off delete the interface isis container too
	 */
	if (!strncmp(ip, "ipv6", strlen("ipv6"))) {
		if (circuit && !circuit->ip_router)
			nb_cli_enqueue_change(vty, "./frr-isisd:isis",
					      NB_OP_DELETE, NULL);
		else
			nb_cli_enqueue_change(vty,
					      "./frr-isisd:isis/ipv6-routing",
					      NB_OP_DELETE, NULL);
	} else { /* no ipv4  */
		if (circuit && !circuit->ipv6_router)
			nb_cli_enqueue_change(vty, "./frr-isisd:isis",
					      NB_OP_DELETE, NULL);
		else
			nb_cli_enqueue_change(vty,
					      "./frr-isisd:isis/ipv4-routing",
					      NB_OP_DELETE, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_ipv4(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " ip router isis %s\n",
		yang_dnode_get_string(dnode, "../area-tag"));
}

void cli_show_ip_isis_ipv6(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " ipv6 router isis %s\n",
		yang_dnode_get_string(dnode, "../area-tag"));
}

void isis_cli_init(void)
{
	install_element(CONFIG_NODE, &router_isis_cmd);
	install_element(CONFIG_NODE, &no_router_isis_cmd);

	install_element(INTERFACE_NODE, &ip_router_isis_cmd);
	install_element(INTERFACE_NODE, &ip6_router_isis_cmd);
	install_element(INTERFACE_NODE, &no_ip_router_isis_cmd);
}

#endif /* ifndef FABRICD */
