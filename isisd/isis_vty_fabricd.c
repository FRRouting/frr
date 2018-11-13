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

DEFUN (set_overload_bit,
       set_overload_bit_cmd,
       "set-overload-bit",
       "Set overload bit to avoid any transit traffic\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	isis_area_overload_bit_set(area, true);
	return CMD_SUCCESS;
}

DEFUN (no_set_overload_bit,
       no_set_overload_bit_cmd,
       "no set-overload-bit",
       "Reset overload bit to accept transit traffic\n"
       "Reset overload bit\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	isis_area_overload_bit_set(area, false);
	return CMD_SUCCESS;
}

static int isis_vty_password_set(struct vty *vty, int argc,
			  struct cmd_token *argv[], int level)
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	int idx_algo = 1;
	int idx_password = 2;
	int idx_snp_auth = 5;
	uint8_t snp_auth = 0;

	const char *passwd = argv[idx_password]->arg;
	if (strlen(passwd) > 254) {
		vty_out(vty, "Too long area password (>254)\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argc > idx_snp_auth) {
		snp_auth = SNP_AUTH_SEND;
		if (strmatch(argv[idx_snp_auth]->text, "validate"))
			snp_auth |= SNP_AUTH_RECV;
	}

	if (strmatch(argv[idx_algo]->text, "clear")) {
		return isis_area_passwd_cleartext_set(area, level,
						      passwd, snp_auth);
	} else if (strmatch(argv[idx_algo]->text, "md5")) {
		return isis_area_passwd_hmac_md5_set(area, level,
						     passwd, snp_auth);
	}

	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (domain_passwd,
       domain_passwd_cmd,
       "domain-password <clear|md5> WORD [authenticate snp <send-only|validate>]",
       "Set the authentication password for a routing domain\n"
       "Authentication type\n"
       "Authentication type\n"
       "Level-wide password\n"
       "Authentication\n"
       "SNP PDUs\n"
       "Send but do not check PDUs on receiving\n"
       "Send and check PDUs on receiving\n")
{
	return isis_vty_password_set(vty, argc, argv, IS_LEVEL_2);
}

DEFUN (no_domain_passwd,
       no_domain_passwd_cmd,
       "no domain-password",
       NO_STR
       "Set the authentication password for a routing domain\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	return isis_area_passwd_unset(area, IS_LEVEL_2);
}

static int
isis_vty_lsp_gen_interval_set(struct vty *vty, int level, uint16_t interval)
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int lvl;

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; ++lvl) {
		if (!(lvl & level))
			continue;

		if (interval >= area->lsp_refresh[lvl - 1]) {
			vty_out(vty,
				"LSP gen interval %us must be less than "
				"the LSP refresh interval %us\n",
				interval, area->lsp_refresh[lvl - 1]);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; ++lvl) {
		if (!(lvl & level))
			continue;
		area->lsp_gen_interval[lvl - 1] = interval;
	}

	return CMD_SUCCESS;
}

DEFUN (lsp_gen_interval,
       lsp_gen_interval_cmd,
       "lsp-gen-interval (1-120)",
       "Minimum interval between regenerating same LSP\n"
       "Minimum interval in seconds\n")
{
	uint16_t interval = atoi(argv[1]->arg);

	return isis_vty_lsp_gen_interval_set(vty, IS_LEVEL_1_AND_2, interval);
}

DEFUN (no_lsp_gen_interval,
       no_lsp_gen_interval_cmd,
       "no lsp-gen-interval [(1-120)]",
       NO_STR
       "Minimum interval between regenerating same LSP\n"
       "Minimum interval in seconds\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	return isis_vty_lsp_gen_interval_set(vty, IS_LEVEL_1_AND_2,
					     DEFAULT_MIN_LSP_GEN_INTERVAL);
}

static int
isis_vty_lsp_refresh_set(struct vty *vty, int level, uint16_t interval)
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int lvl;

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; ++lvl) {
		if (!(lvl & level))
			continue;
		if (interval <= area->lsp_gen_interval[lvl - 1]) {
			vty_out(vty,
				"LSP refresh interval %us must be greater than "
				"the configured LSP gen interval %us\n",
				interval, area->lsp_gen_interval[lvl - 1]);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (interval > (area->max_lsp_lifetime[lvl - 1] - 300)) {
			vty_out(vty,
				"LSP refresh interval %us must be less than "
				"the configured LSP lifetime %us less 300\n",
				interval, area->max_lsp_lifetime[lvl - 1]);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; ++lvl) {
		if (!(lvl & level))
			continue;
		isis_area_lsp_refresh_set(area, lvl, interval);
	}

	return CMD_SUCCESS;
}

DEFUN (lsp_refresh_interval,
       lsp_refresh_interval_cmd,
       "lsp-refresh-interval (1-65235)",
       "LSP refresh interval\n"
       "LSP refresh interval in seconds\n")
{
	unsigned int interval = atoi(argv[1]->arg);
	return isis_vty_lsp_refresh_set(vty, IS_LEVEL_1_AND_2, interval);
}

DEFUN (no_lsp_refresh_interval,
       no_lsp_refresh_interval_cmd,
       "no lsp-refresh-interval [(1-65235)]",
       NO_STR
       "LSP refresh interval\n"
       "LSP refresh interval in seconds\n")
{
	return isis_vty_lsp_refresh_set(vty, IS_LEVEL_1_AND_2,
					DEFAULT_MAX_LSP_GEN_INTERVAL);
}

static int
isis_vty_max_lsp_lifetime_set(struct vty *vty, int level, uint16_t interval)
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int lvl;
	uint16_t refresh_interval = interval - 300;
	int set_refresh_interval[ISIS_LEVELS] = {0, 0};

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; lvl++) {
		if (!(lvl & level))
			continue;

		if (refresh_interval < area->lsp_refresh[lvl - 1]) {
			vty_out(vty,
				"Level %d Max LSP lifetime %us must be 300s greater than "
				"the configured LSP refresh interval %us\n",
				lvl, interval, area->lsp_refresh[lvl - 1]);
			vty_out(vty,
				"Automatically reducing level %d LSP refresh interval "
				"to %us\n",
				lvl, refresh_interval);
			set_refresh_interval[lvl - 1] = 1;

			if (refresh_interval
			    <= area->lsp_gen_interval[lvl - 1]) {
				vty_out(vty,
					"LSP refresh interval %us must be greater than "
					"the configured LSP gen interval %us\n",
					refresh_interval,
					area->lsp_gen_interval[lvl - 1]);
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
	}

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; lvl++) {
		if (!(lvl & level))
			continue;
		isis_area_max_lsp_lifetime_set(area, lvl, interval);
		if (set_refresh_interval[lvl - 1])
			isis_area_lsp_refresh_set(area, lvl, refresh_interval);
	}

	return CMD_SUCCESS;
}

DEFUN (max_lsp_lifetime,
       max_lsp_lifetime_cmd,
       "max-lsp-lifetime (350-65535)",
       "Maximum LSP lifetime\n"
       "LSP lifetime in seconds\n")
{
	int lifetime = atoi(argv[1]->arg);

	return isis_vty_max_lsp_lifetime_set(vty, IS_LEVEL_1_AND_2, lifetime);
}


DEFUN (no_max_lsp_lifetime,
       no_max_lsp_lifetime_cmd,
       "no max-lsp-lifetime [(350-65535)]",
       NO_STR
       "Maximum LSP lifetime\n"
       "LSP lifetime in seconds\n")
{
	return isis_vty_max_lsp_lifetime_set(vty, IS_LEVEL_1_AND_2,
					     DEFAULT_LSP_LIFETIME);
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

	install_element(ROUTER_NODE, &set_overload_bit_cmd);
	install_element(ROUTER_NODE, &no_set_overload_bit_cmd);

	install_element(ROUTER_NODE, &domain_passwd_cmd);
	install_element(ROUTER_NODE, &no_domain_passwd_cmd);

	install_element(ROUTER_NODE, &lsp_gen_interval_cmd);
	install_element(ROUTER_NODE, &no_lsp_gen_interval_cmd);

	install_element(ROUTER_NODE, &lsp_refresh_interval_cmd);
	install_element(ROUTER_NODE, &no_lsp_refresh_interval_cmd);

	install_element(ROUTER_NODE, &max_lsp_lifetime_cmd);
	install_element(ROUTER_NODE, &no_max_lsp_lifetime_cmd);
}
