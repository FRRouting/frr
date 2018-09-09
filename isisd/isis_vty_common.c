/*
 * IS-IS Rout(e)ing protocol - isis_vty_common.c
 *
 * This file contains the CLI that is shared between OpenFabric and IS-IS
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2016        David Lamparter, for NetDEF, Inc.
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
#include "spf_backoff.h"

#include "isis_circuit.h"
#include "isis_csm.h"
#include "isis_misc.h"
#include "isis_mt.h"
#include "isisd.h"
#include "isis_vty_common.h"

struct isis_circuit *isis_circuit_lookup(struct vty *vty)
{
	struct interface *ifp = VTY_GET_CONTEXT(interface);
	struct isis_circuit *circuit;

	if (!ifp) {
		vty_out(vty, "Invalid interface \n");
		return NULL;
	}

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit) {
		vty_out(vty, "ISIS is not enabled on circuit %s\n", ifp->name);
		return NULL;
	}

	return circuit;
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

DEFUN (isis_passive,
       isis_passive_cmd,
       PROTO_NAME " passive",
       PROTO_HELP
       "Configure the passive mode for interface\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	CMD_FERR_RETURN(isis_circuit_passive_set(circuit, 1),
			"Cannot set passive: $ERR");
	return CMD_SUCCESS;
}

DEFUN (no_isis_passive,
       no_isis_passive_cmd,
       "no " PROTO_NAME " passive",
       NO_STR
       PROTO_HELP
       "Configure the passive mode for interface\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	CMD_FERR_RETURN(isis_circuit_passive_set(circuit, 0),
			"Cannot set no passive: $ERR");
	return CMD_SUCCESS;
}

DEFUN (isis_passwd,
       isis_passwd_cmd,
       PROTO_NAME " password <md5|clear> WORD",
       PROTO_HELP
       "Configure the authentication password for a circuit\n"
       "HMAC-MD5 authentication\n"
       "Cleartext password\n"
       "Circuit password\n")
{
	int idx_encryption = 2;
	int idx_word = 3;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	ferr_r rv;

	if (!circuit)
		return CMD_ERR_NO_MATCH;

	if (argv[idx_encryption]->arg[0] == 'm')
		rv = isis_circuit_passwd_hmac_md5_set(circuit,
						      argv[idx_word]->arg);
	else
		rv = isis_circuit_passwd_cleartext_set(circuit,
						       argv[idx_word]->arg);

	CMD_FERR_RETURN(rv, "Failed to set circuit password: $ERR");
	return CMD_SUCCESS;
}

DEFUN (no_isis_passwd,
       no_isis_passwd_cmd,
       "no " PROTO_NAME " password [<md5|clear> WORD]",
       NO_STR
       PROTO_HELP
       "Configure the authentication password for a circuit\n"
       "HMAC-MD5 authentication\n"
       "Cleartext password\n"
       "Circuit password\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	CMD_FERR_RETURN(isis_circuit_passwd_unset(circuit),
			"Failed to unset circuit password: $ERR");
	return CMD_SUCCESS;
}

DEFUN (isis_metric,
       isis_metric_cmd,
       PROTO_NAME " metric (0-16777215)",
       PROTO_HELP
       "Set default metric for circuit\n"
       "Default metric value\n")
{
	int idx_number = 2;
	int met;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	met = atoi(argv[idx_number]->arg);

	/* RFC3787 section 5.1 */
	if (circuit->area && circuit->area->oldmetric == 1
	    && met > MAX_NARROW_LINK_METRIC) {
		vty_out(vty,
			"Invalid metric %d - should be <0-63> "
			"when narrow metric type enabled\n",
			met);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* RFC4444 */
	if (circuit->area && circuit->area->newmetric == 1
	    && met > MAX_WIDE_LINK_METRIC) {
		vty_out(vty,
			"Invalid metric %d - should be <0-16777215> "
			"when wide metric type enabled\n",
			met);
		return CMD_WARNING_CONFIG_FAILED;
	}

	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, IS_LEVEL_1, met),
			"Failed to set L1 metric: $ERR");
	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, IS_LEVEL_2, met),
			"Failed to set L2 metric: $ERR");
	return CMD_SUCCESS;
}

DEFUN (no_isis_metric,
       no_isis_metric_cmd,
       "no " PROTO_NAME " metric [(0-16777215)]",
       NO_STR
       PROTO_HELP
       "Set default metric for circuit\n"
       "Default metric value\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, IS_LEVEL_1,
						DEFAULT_CIRCUIT_METRIC),
			"Failed to set L1 metric: $ERR");
	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, IS_LEVEL_2,
						DEFAULT_CIRCUIT_METRIC),
			"Failed to set L2 metric: $ERR");
	return CMD_SUCCESS;
}

DEFUN (isis_hello_interval,
       isis_hello_interval_cmd,
       PROTO_NAME " hello-interval (1-600)",
       PROTO_HELP
       "Set Hello interval\n"
       "Holdtime 1 seconds, interval depends on multiplier\n")
{
	uint32_t interval = atoi(argv[2]->arg);
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_interval[0] = interval;
	circuit->hello_interval[1] = interval;

	return CMD_SUCCESS;
}

DEFUN (no_isis_hello_interval,
       no_isis_hello_interval_cmd,
       "no " PROTO_NAME " hello-interval [(1-600)]",
       NO_STR
       PROTO_HELP
       "Set Hello interval\n"
       "Holdtime 1 second, interval depends on multiplier\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_interval[0] = DEFAULT_HELLO_INTERVAL;
	circuit->hello_interval[1] = DEFAULT_HELLO_INTERVAL;

	return CMD_SUCCESS;
}

DEFUN (isis_hello_multiplier,
       isis_hello_multiplier_cmd,
       PROTO_NAME " hello-multiplier (2-100)",
       PROTO_HELP
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n")
{
	uint16_t mult = atoi(argv[2]->arg);
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_multiplier[0] = mult;
	circuit->hello_multiplier[1] = mult;

	return CMD_SUCCESS;
}

DEFUN (no_isis_hello_multiplier,
       no_isis_hello_multiplier_cmd,
       "no " PROTO_NAME " hello-multiplier [(2-100)]",
       NO_STR
       PROTO_HELP
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_multiplier[0] = DEFAULT_HELLO_MULTIPLIER;
	circuit->hello_multiplier[1] = DEFAULT_HELLO_MULTIPLIER;

	return CMD_SUCCESS;
}

DEFUN (csnp_interval,
       csnp_interval_cmd,
       PROTO_NAME " csnp-interval (1-600)",
       PROTO_HELP
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n")
{
	uint16_t interval = atoi(argv[2]->arg);
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->csnp_interval[0] = interval;
	circuit->csnp_interval[1] = interval;

	return CMD_SUCCESS;
}

DEFUN (no_csnp_interval,
       no_csnp_interval_cmd,
       "no " PROTO_NAME " csnp-interval [(1-600)]",
       NO_STR
       PROTO_HELP
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->csnp_interval[0] = DEFAULT_CSNP_INTERVAL;
	circuit->csnp_interval[1] = DEFAULT_CSNP_INTERVAL;

	return CMD_SUCCESS;
}

DEFUN (psnp_interval,
       psnp_interval_cmd,
       PROTO_NAME " psnp-interval (1-120)",
       PROTO_HELP
       "Set PSNP interval in seconds\n"
       "PSNP interval value\n")
{
	uint16_t interval = atoi(argv[2]->arg);
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->psnp_interval[0] = interval;
	circuit->psnp_interval[1] = interval;

	return CMD_SUCCESS;
}

DEFUN (no_psnp_interval,
       no_psnp_interval_cmd,
       "no " PROTO_NAME " psnp-interval [(1-120)]",
       NO_STR
       PROTO_HELP
       "Set PSNP interval in seconds\n"
       "PSNP interval value\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->psnp_interval[0] = DEFAULT_PSNP_INTERVAL;
	circuit->psnp_interval[1] = DEFAULT_PSNP_INTERVAL;

	return CMD_SUCCESS;
}

DEFUN (circuit_topology,
       circuit_topology_cmd,
       PROTO_NAME " topology " ISIS_MT_NAMES,
       PROTO_HELP
       "Configure interface IS-IS topologies\n"
       ISIS_MT_DESCRIPTIONS)
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;
	const char *arg = argv[2]->arg;
	uint16_t mtid = isis_str2mtid(arg);

	if (circuit->area && circuit->area->oldmetric) {
		vty_out(vty,
			"Multi topology IS-IS can only be used with wide metrics\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (mtid == (uint16_t)-1) {
		vty_out(vty, "Don't know topology '%s'\n", arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return isis_circuit_mt_enabled_set(circuit, mtid, true);
}

DEFUN (no_circuit_topology,
       no_circuit_topology_cmd,
       "no " PROTO_NAME " topology " ISIS_MT_NAMES,
       NO_STR
       PROTO_HELP
       "Configure interface IS-IS topologies\n"
       ISIS_MT_DESCRIPTIONS)
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;
	const char *arg = argv[3]->arg;
	uint16_t mtid = isis_str2mtid(arg);

	if (circuit->area && circuit->area->oldmetric) {
		vty_out(vty,
			"Multi topology IS-IS can only be used with wide metrics\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (mtid == (uint16_t)-1) {
		vty_out(vty, "Don't know topology '%s'\n", arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return isis_circuit_mt_enabled_set(circuit, mtid, false);
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

static int isis_vty_lsp_mtu_set(struct vty *vty, unsigned int lsp_mtu)
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	struct listnode *node;
	struct isis_circuit *circuit;

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		if (circuit->state != C_STATE_INIT
		    && circuit->state != C_STATE_UP)
			continue;
		if (lsp_mtu > isis_circuit_pdu_size(circuit)) {
			vty_out(vty,
				"ISIS area contains circuit %s, which has a maximum PDU size of %zu.\n",
				circuit->interface->name,
				isis_circuit_pdu_size(circuit));
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	isis_area_lsp_mtu_set(area, lsp_mtu);
	return CMD_SUCCESS;
}

DEFUN (area_lsp_mtu,
       area_lsp_mtu_cmd,
       "lsp-mtu (128-4352)",
       "Configure the maximum size of generated LSPs\n"
       "Maximum size of generated LSPs\n")
{
	int idx_number = 1;
	unsigned int lsp_mtu;

	lsp_mtu = strtoul(argv[idx_number]->arg, NULL, 10);

	return isis_vty_lsp_mtu_set(vty, lsp_mtu);
}

DEFUN (no_area_lsp_mtu,
       no_area_lsp_mtu_cmd,
       "no lsp-mtu [(128-4352)]",
       NO_STR
       "Configure the maximum size of generated LSPs\n"
       "Maximum size of generated LSPs\n")
{
	return isis_vty_lsp_mtu_set(vty, DEFAULT_LSP_MTU);
}

DEFUN (area_purge_originator,
       area_purge_originator_cmd,
       "[no] purge-originator",
       NO_STR
       "Use the RFC 6232 purge-originator\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	area->purge_originator = !!strcmp(argv[0]->text, "no");
	return CMD_SUCCESS;
}

int isis_vty_lsp_gen_interval_set(struct vty *vty, int level, uint16_t interval)
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

DEFUN (spf_interval,
       spf_interval_cmd,
       "spf-interval (1-120)",
       "Minimum interval between SPF calculations\n"
       "Minimum interval between consecutive SPFs in seconds\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	uint16_t interval = atoi(argv[1]->arg);

	area->min_spf_interval[0] = interval;
	area->min_spf_interval[1] = interval;

	return CMD_SUCCESS;
}

DEFUN (no_spf_interval,
       no_spf_interval_cmd,
       "no spf-interval [(1-120)]",
       NO_STR
       "Minimum interval between SPF calculations\n"
       "Minimum interval between consecutive SPFs in seconds\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	area->min_spf_interval[0] = MINIMUM_SPF_INTERVAL;
	area->min_spf_interval[1] = MINIMUM_SPF_INTERVAL;

	return CMD_SUCCESS;
}

DEFUN (no_spf_delay_ietf,
       no_spf_delay_ietf_cmd,
       "no spf-delay-ietf",
       NO_STR
       "IETF SPF delay algorithm\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	spf_backoff_free(area->spf_delay_ietf[0]);
	spf_backoff_free(area->spf_delay_ietf[1]);
	area->spf_delay_ietf[0] = NULL;
	area->spf_delay_ietf[1] = NULL;

	return CMD_SUCCESS;
}

DEFUN (spf_delay_ietf,
       spf_delay_ietf_cmd,
       "spf-delay-ietf init-delay (0-60000) short-delay (0-60000) long-delay (0-60000) holddown (0-60000) time-to-learn (0-60000)",
       "IETF SPF delay algorithm\n"
       "Delay used while in QUIET state\n"
       "Delay used while in QUIET state in milliseconds\n"
       "Delay used while in SHORT_WAIT state\n"
       "Delay used while in SHORT_WAIT state in milliseconds\n"
       "Delay used while in LONG_WAIT\n"
       "Delay used while in LONG_WAIT state in milliseconds\n"
       "Time with no received IGP events before considering IGP stable\n"
       "Time with no received IGP events before considering IGP stable (in milliseconds)\n"
       "Maximum duration needed to learn all the events related to a single failure\n"
       "Maximum duration needed to learn all the events related to a single failure (in milliseconds)\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	long init_delay = atol(argv[2]->arg);
	long short_delay = atol(argv[4]->arg);
	long long_delay = atol(argv[6]->arg);
	long holddown = atol(argv[8]->arg);
	long timetolearn = atol(argv[10]->arg);

	size_t bufsiz = strlen(area->area_tag) + sizeof("IS-IS  Lx");
	char *buf = XCALLOC(MTYPE_TMP, bufsiz);

	snprintf(buf, bufsiz, "IS-IS %s L1", area->area_tag);
	spf_backoff_free(area->spf_delay_ietf[0]);
	area->spf_delay_ietf[0] =
		spf_backoff_new(master, buf, init_delay, short_delay,
				long_delay, holddown, timetolearn);

	snprintf(buf, bufsiz, "IS-IS %s L2", area->area_tag);
	spf_backoff_free(area->spf_delay_ietf[1]);
	area->spf_delay_ietf[1] =
		spf_backoff_new(master, buf, init_delay, short_delay,
				long_delay, holddown, timetolearn);

	XFREE(MTYPE_TMP, buf);
	return CMD_SUCCESS;
}

int isis_vty_max_lsp_lifetime_set(struct vty *vty, int level, uint16_t interval)
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

int isis_vty_lsp_refresh_set(struct vty *vty, int level, uint16_t interval)
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

int isis_vty_password_set(struct vty *vty, int argc,
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

void isis_vty_init(void)
{
	install_element(INTERFACE_NODE, &ip_router_isis_cmd);
	install_element(INTERFACE_NODE, &ip6_router_isis_cmd);
	install_element(INTERFACE_NODE, &no_ip_router_isis_cmd);

	install_element(INTERFACE_NODE, &isis_passive_cmd);
	install_element(INTERFACE_NODE, &no_isis_passive_cmd);

	install_element(INTERFACE_NODE, &isis_passwd_cmd);
	install_element(INTERFACE_NODE, &no_isis_passwd_cmd);

	install_element(INTERFACE_NODE, &isis_metric_cmd);
	install_element(INTERFACE_NODE, &no_isis_metric_cmd);

	install_element(INTERFACE_NODE, &isis_hello_interval_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_interval_cmd);

	install_element(INTERFACE_NODE, &isis_hello_multiplier_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_multiplier_cmd);

	install_element(INTERFACE_NODE, &csnp_interval_cmd);
	install_element(INTERFACE_NODE, &no_csnp_interval_cmd);

	install_element(INTERFACE_NODE, &psnp_interval_cmd);
	install_element(INTERFACE_NODE, &no_psnp_interval_cmd);

	install_element(INTERFACE_NODE, &circuit_topology_cmd);
	install_element(INTERFACE_NODE, &no_circuit_topology_cmd);

	install_element(ROUTER_NODE, &set_overload_bit_cmd);
	install_element(ROUTER_NODE, &no_set_overload_bit_cmd);

	install_element(ROUTER_NODE, &area_lsp_mtu_cmd);
	install_element(ROUTER_NODE, &no_area_lsp_mtu_cmd);

	install_element(ROUTER_NODE, &area_purge_originator_cmd);

	install_element(ROUTER_NODE, &lsp_gen_interval_cmd);
	install_element(ROUTER_NODE, &no_lsp_gen_interval_cmd);

	install_element(ROUTER_NODE, &spf_interval_cmd);
	install_element(ROUTER_NODE, &no_spf_interval_cmd);

	install_element(ROUTER_NODE, &max_lsp_lifetime_cmd);
	install_element(ROUTER_NODE, &no_max_lsp_lifetime_cmd);

	install_element(ROUTER_NODE, &lsp_refresh_interval_cmd);
	install_element(ROUTER_NODE, &no_lsp_refresh_interval_cmd);

	install_element(ROUTER_NODE, &domain_passwd_cmd);
	install_element(ROUTER_NODE, &no_domain_passwd_cmd);

	install_element(ROUTER_NODE, &spf_delay_ietf_cmd);
	install_element(ROUTER_NODE, &no_spf_delay_ietf_cmd);

	isis_vty_daemon_init();
}
