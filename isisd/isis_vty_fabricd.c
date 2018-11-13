/*
 * IS-IS Rout(e)ing protocol - isis_vty_fabricd.c
 *
 * This file contains the CLI that is specific to OpenFabric
 *
 * Copyright (C) 2018        Christian Franke, for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "command.h"

#include "isisd/isisd.h"
#include "isisd/isis_vty_common.h"
#include "isisd/fabricd.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_circuit.h"

DEFUN (fabric_tier,
       fabric_tier_cmd,
       "fabric-tier (0-14)",
       "Statically configure the tier to advertise\n"
       "Tier to advertise\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	uint8_t tier = atoi(argv[1]->arg);

	fabricd_configure_tier(area, tier);
	return CMD_SUCCESS;
}

DEFUN (no_fabric_tier,
       no_fabric_tier_cmd,
       "no fabric-tier [(0-14)]",
       NO_STR
       "Statically configure the tier to advertise\n"
       "Tier to advertise\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	fabricd_configure_tier(area, ISIS_TIER_UNDEFINED);
	return CMD_SUCCESS;
}

DEFUN (triggered_csnp,
       triggered_csnp_cmd,
       "triggered-csnp-delay (100-10000) [always]",
       "Configure the delay for triggered CSNPs\n"
       "Delay in milliseconds\n"
       "Trigger CSNP for all LSPs, not only circuit-scoped\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	int csnp_delay = atoi(argv[1]->arg);
	bool always_send_csnp = (argc == 3);

	fabricd_configure_triggered_csnp(area, csnp_delay, always_send_csnp);
	return CMD_SUCCESS;
}

DEFUN (no_triggered_csnp,
       no_triggered_csnp_cmd,
       "no triggered-csnp-delay [(100-10000) [always]]",
       NO_STR
       "Configure the delay for triggered CSNPs\n"
       "Delay in milliseconds\n"
       "Trigger CSNP for all LSPs, not only circuit-scoped\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	fabricd_configure_triggered_csnp(area, FABRICD_DEFAULT_CSNP_DELAY,
					 false);
	return CMD_SUCCESS;
}

static void lsp_print_flooding(struct vty *vty, struct isis_lsp *lsp)
{
	char lspid[255];

	lspid_print(lsp->hdr.lsp_id, lspid, true, true);
	vty_out(vty, "Flooding information for %s\n", lspid);

	if (!lsp->flooding_neighbors[TX_LSP_NORMAL]) {
		vty_out(vty, "    Never received.\n");
		return;
	}

	vty_out(vty, "    Last received on: %s (",
		lsp->flooding_interface ?
		lsp->flooding_interface : "(null)");

	time_t uptime = time(NULL) - lsp->flooding_time;
	struct tm *tm = gmtime(&uptime);

	if (uptime < ONE_DAY_SECOND)
		vty_out(vty, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min,
			tm->tm_sec);
	else if (uptime < ONE_WEEK_SECOND)
		vty_out(vty, "%dd%02dh%02dm", tm->tm_yday, tm->tm_hour,
			tm->tm_min);
	else
		vty_out(vty, "%02dw%dd%02dh", tm->tm_yday / 7,
			tm->tm_yday - ((tm->tm_yday / 7) * 7),
			tm->tm_hour);
	vty_out(vty, " ago)\n");

	if (lsp->flooding_circuit_scoped) {
		vty_out(vty, "    Received as circuit-scoped LSP, so not "
			"flooded.\n");
		return;
	}

	for (enum isis_tx_type type = TX_LSP_NORMAL;
	     type <= TX_LSP_CIRCUIT_SCOPED; type++) {
		struct listnode *node;
		uint8_t *neighbor_id;

		vty_out(vty, "    %s:\n",
			(type == TX_LSP_NORMAL) ? "RF" : "DNR");
		for (ALL_LIST_ELEMENTS_RO(lsp->flooding_neighbors[type],
					  node, neighbor_id)) {
			vty_out(vty, "        %s\n",
				print_sys_hostname(neighbor_id));
		}
	}
}

DEFUN (show_lsp_flooding,
       show_lsp_flooding_cmd,
       "show openfabric flooding [WORD]",
       SHOW_STR
       PROTO_HELP
       "Flooding information\n"
       "LSP ID\n")
{
	const char *lspid = NULL;

	if (argc == 4)
		lspid = argv[3]->arg;

	struct listnode *node;
	struct isis_area *area;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		dict_t *lspdb = area->lspdb[ISIS_LEVEL2 - 1];

		vty_out(vty, "Area %s:\n", area->area_tag ?
			area->area_tag : "null");

		if (lspid) {
			struct isis_lsp *lsp = lsp_for_arg(lspid, lspdb);

			if (lsp)
				lsp_print_flooding(vty, lsp);

			continue;
		}

		for (dnode_t *dnode = dict_first(lspdb); dnode;
		     dnode = dict_next(lspdb, dnode)) {
			lsp_print_flooding(vty, dnode_get(dnode));
			vty_out(vty, "\n");
		}
	}

	return CMD_SUCCESS;
}

DEFUN (ip_router_isis,
       ip_router_isis_cmd,
       "ip router " PROTO_NAME " WORD",
       "Interface Internet Protocol config commands\n"
       "IP router interface commands\n"
       PROTO_HELP
       "Routing process tag\n")
{
	int idx_afi = 0;
	int idx_word = 3;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct isis_circuit *circuit;
	struct isis_area *area;
	const char *af = argv[idx_afi]->arg;
	const char *area_tag = argv[idx_word]->arg;

	/* Prevent more than one area per circuit */
	circuit = circuit_scan_by_ifp(ifp);
	if (circuit && circuit->area) {
		if (strcmp(circuit->area->area_tag, area_tag)) {
			vty_out(vty, "ISIS circuit is already defined on %s\n",
				circuit->area->area_tag);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	area = isis_area_lookup(area_tag);
	if (!area)
		area = isis_area_create(area_tag);

	if (!circuit || !circuit->area) {
		circuit = isis_circuit_create(area, ifp);

		if (circuit->state != C_STATE_CONF
		    && circuit->state != C_STATE_UP) {
			vty_out(vty,
				"Couldn't bring up interface, please check log.\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	bool ip = circuit->ip_router, ipv6 = circuit->ipv6_router;
	if (af[2] != '\0')
		ipv6 = true;
	else
		ip = true;

	isis_circuit_af_set(circuit, ip, ipv6);
	return CMD_SUCCESS;
}

DEFUN (ip6_router_isis,
       ip6_router_isis_cmd,
       "ipv6 router " PROTO_NAME " WORD",
       "Interface Internet Protocol config commands\n"
       "IP router interface commands\n"
       PROTO_HELP
       "Routing process tag\n")
{
	return ip_router_isis(self, vty, argc, argv);
}

DEFUN (no_ip_router_isis,
       no_ip_router_isis_cmd,
       "no <ip|ipv6> router " PROTO_NAME " WORD",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "IP router interface commands\n"
       "IP router interface commands\n"
       PROTO_HELP
       "Routing process tag\n")
{
	int idx_afi = 1;
	int idx_word = 4;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct isis_area *area;
	struct isis_circuit *circuit;
	const char *af = argv[idx_afi]->arg;
	const char *area_tag = argv[idx_word]->arg;

	area = isis_area_lookup(area_tag);
	if (!area) {
		vty_out(vty, "Can't find ISIS instance %s\n",
			area_tag);
		return CMD_ERR_NO_MATCH;
	}

	circuit = circuit_lookup_by_ifp(ifp, area->circuit_list);
	if (!circuit) {
		vty_out(vty, "ISIS is not enabled on circuit %s\n", ifp->name);
		return CMD_ERR_NO_MATCH;
	}

	bool ip = circuit->ip_router, ipv6 = circuit->ipv6_router;
	if (af[2] != '\0')
		ipv6 = false;
	else
		ip = false;

	isis_circuit_af_set(circuit, ip, ipv6);
	return CMD_SUCCESS;
}

void isis_vty_daemon_init(void)
{
	install_element(ROUTER_NODE, &fabric_tier_cmd);
	install_element(ROUTER_NODE, &no_fabric_tier_cmd);
	install_element(ROUTER_NODE, &triggered_csnp_cmd);
	install_element(ROUTER_NODE, &no_triggered_csnp_cmd);

	install_element(ENABLE_NODE, &show_lsp_flooding_cmd);

	install_element(INTERFACE_NODE, &ip_router_isis_cmd);
	install_element(INTERFACE_NODE, &ip6_router_isis_cmd);
	install_element(INTERFACE_NODE, &no_ip_router_isis_cmd);
}
