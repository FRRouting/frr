/*
 * IS-IS Rout(e)ing protocol - isis_vty_isisd.c
 *
 * This file contains the CLI that is specific to IS-IS
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

#include "isis_circuit.h"
#include "isis_csm.h"
#include "isis_misc.h"
#include "isis_mt.h"
#include "isisd.h"
#include "isis_vty_common.h"

static int level_for_arg(const char *arg)
{
	if (!strcmp(arg, "level-1"))
		return IS_LEVEL_1;
	else
		return IS_LEVEL_2;
}

DEFUN (isis_circuit_type,
       isis_circuit_type_cmd,
       "isis circuit-type <level-1|level-1-2|level-2-only>",
       "IS-IS routing protocol\n"
       "Configure circuit type for interface\n"
       "Level-1 only adjacencies are formed\n"
       "Level-1-2 adjacencies are formed\n"
       "Level-2 only adjacencies are formed\n")
{
	int idx_level = 2;
	int is_type;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	is_type = string2circuit_t(argv[idx_level]->arg);
	if (!is_type) {
		vty_out(vty, "Unknown circuit-type \n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (circuit->state == C_STATE_UP
	    && circuit->area->is_type != IS_LEVEL_1_AND_2
	    && circuit->area->is_type != is_type) {
		vty_out(vty, "Invalid circuit level for area %s.\n",
			circuit->area->area_tag);
		return CMD_WARNING_CONFIG_FAILED;
	}
	isis_circuit_is_type_set(circuit, is_type);

	return CMD_SUCCESS;
}

DEFUN (no_isis_circuit_type,
       no_isis_circuit_type_cmd,
       "no isis circuit-type <level-1|level-1-2|level-2-only>",
       NO_STR
       "IS-IS routing protocol\n"
       "Configure circuit type for interface\n"
       "Level-1 only adjacencies are formed\n"
       "Level-1-2 adjacencies are formed\n"
       "Level-2 only adjacencies are formed\n")
{
	int is_type;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	/*
	 * Set the circuits level to its default value
	 */
	if (circuit->state == C_STATE_UP)
		is_type = circuit->area->is_type;
	else
		is_type = IS_LEVEL_1_AND_2;
	isis_circuit_is_type_set(circuit, is_type);

	return CMD_SUCCESS;
}

DEFUN (isis_network,
       isis_network_cmd,
       "isis network point-to-point",
       "IS-IS routing protocol\n"
       "Set network type\n"
       "point-to-point network type\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	if (isis_circuit_circ_type_set(circuit, CIRCUIT_T_P2P)) {
		vty_out(vty,
			"isis network point-to-point is valid only on broadcast interfaces\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_isis_network,
       no_isis_network_cmd,
       "no isis network point-to-point",
       NO_STR
       "IS-IS routing protocol\n"
       "Set network type for circuit\n"
       "point-to-point network type\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	if (isis_circuit_circ_type_set(circuit, CIRCUIT_T_BROADCAST)) {
		vty_out(vty,
			"isis network point-to-point is valid only on broadcast interfaces\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (isis_priority,
       isis_priority_cmd,
       "isis priority (0-127)",
       "IS-IS routing protocol\n"
       "Set priority for Designated Router election\n"
       "Priority value\n")
{
	uint8_t prio = atoi(argv[2]->arg);
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->priority[0] = prio;
	circuit->priority[1] = prio;

	return CMD_SUCCESS;
}

DEFUN (no_isis_priority,
       no_isis_priority_cmd,
       "no isis priority [(0-127)]",
       NO_STR
       "IS-IS routing protocol\n"
       "Set priority for Designated Router election\n"
       "Priority value\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->priority[0] = DEFAULT_PRIORITY;
	circuit->priority[1] = DEFAULT_PRIORITY;

	return CMD_SUCCESS;
}

DEFUN (isis_priority_level,
       isis_priority_level_cmd,
       "isis priority (0-127) <level-1|level-2>",
       "IS-IS routing protocol\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-1 routing\n"
       "Specify priority for level-2 routing\n")
{
	uint8_t prio = atoi(argv[2]->arg);
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->priority[level_for_arg(argv[3]->text)] = prio;

	return CMD_SUCCESS;
}

DEFUN (no_isis_priority_level,
       no_isis_priority_level_cmd,
       "no isis priority [(0-127)] <level-1|level-2>",
       NO_STR
       "IS-IS routing protocol\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-1 routing\n"
       "Specify priority for level-2 routing\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	int level = level_for_arg(argv[argc - 1]->text);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->priority[level] = DEFAULT_PRIORITY;

	return CMD_SUCCESS;
}

DEFUN (isis_metric_level,
       isis_metric_level_cmd,
       "isis metric (0-16777215) <level-1|level-2>",
       "IS-IS routing protocol\n"
       "Set default metric for circuit\n"
       "Default metric value\n"
       "Specify metric for level-1 routing\n"
       "Specify metric for level-2 routing\n")
{
	uint32_t met = atoi(argv[2]->arg);
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	CMD_FERR_RETURN(isis_circuit_metric_set(circuit,
						level_for_arg(argv[3]->text),
						met),
			"Failed to set metric: $ERR");
	return CMD_SUCCESS;
}

DEFUN (no_isis_metric_level,
       no_isis_metric_level_cmd,
       "no isis metric [(0-16777215)] <level-1|level-2>",
       NO_STR
       "IS-IS routing protocol\n"
       "Set default metric for circuit\n"
       "Default metric value\n"
       "Specify metric for level-1 routing\n"
       "Specify metric for level-2 routing\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	int level = level_for_arg(argv[argc - 1]->text);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, level,
						DEFAULT_CIRCUIT_METRIC),
			"Failed to set L1 metric: $ERR");
	return CMD_SUCCESS;
}

DEFUN (isis_hello_interval_level,
       isis_hello_interval_level_cmd,
       "isis hello-interval (1-600) <level-1|level-2>",
       "IS-IS routing protocol\n"
       "Set Hello interval\n"
       "Holdtime 1 second, interval depends on multiplier\n"
       "Specify hello-interval for level-1 IIHs\n"
       "Specify hello-interval for level-2 IIHs\n")
{
	uint32_t interval = atoi(argv[2]->arg);
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_interval[level_for_arg(argv[3]->text)] = interval;

	return CMD_SUCCESS;
}

DEFUN (no_isis_hello_interval_level,
       no_isis_hello_interval_level_cmd,
       "no isis hello-interval [(1-600)] <level-1|level-2>",
       NO_STR
       "IS-IS routing protocol\n"
       "Set Hello interval\n"
       "Holdtime 1 second, interval depends on multiplier\n"
       "Specify hello-interval for level-1 IIHs\n"
       "Specify hello-interval for level-2 IIHs\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	int level = level_for_arg(argv[argc - 1]->text);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_interval[level] = DEFAULT_HELLO_INTERVAL;

	return CMD_SUCCESS;
}

DEFUN (isis_hello_multiplier_level,
       isis_hello_multiplier_level_cmd,
       "isis hello-multiplier (2-100) <level-1|level-2>",
       "IS-IS routing protocol\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n"
       "Specify hello multiplier for level-1 IIHs\n"
       "Specify hello multiplier for level-2 IIHs\n")
{
	uint16_t mult = atoi(argv[2]->arg);
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_multiplier[level_for_arg(argv[3]->text)] = mult;

	return CMD_SUCCESS;
}

DEFUN (no_isis_hello_multiplier_level,
       no_isis_hello_multiplier_level_cmd,
       "no isis hello-multiplier [(2-100)] <level-1|level-2>",
       NO_STR
       "IS-IS routing protocol\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n"
       "Specify hello multiplier for level-1 IIHs\n"
       "Specify hello multiplier for level-2 IIHs\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	int level = level_for_arg(argv[argc - 1]->text);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_multiplier[level] = DEFAULT_HELLO_MULTIPLIER;

	return CMD_SUCCESS;
}

DEFUN (isis_threeway_adj,
       isis_threeway_adj_cmd,
       "[no] isis three-way-handshake",
       NO_STR
       "IS-IS commands\n"
       "Enable/Disable three-way handshake\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->disable_threeway_adj = !strcmp(argv[0]->text, "no");
	return CMD_SUCCESS;
}

DEFUN (isis_hello_padding,
       isis_hello_padding_cmd,
       "isis hello padding",
       "IS-IS routing protocol\n"
       "Add padding to IS-IS hello packets\n"
       "Pad hello packets\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->pad_hellos = 1;

	return CMD_SUCCESS;
}

DEFUN (no_isis_hello_padding,
       no_isis_hello_padding_cmd,
       "no isis hello padding",
       NO_STR
       "IS-IS routing protocol\n"
       "Add padding to IS-IS hello packets\n"
       "Pad hello packets\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->pad_hellos = 0;

	return CMD_SUCCESS;
}

DEFUN (csnp_interval_level,
       csnp_interval_level_cmd,
       "isis csnp-interval (1-600) <level-1|level-2>",
       "IS-IS routing protocol\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n"
       "Specify interval for level-1 CSNPs\n"
       "Specify interval for level-2 CSNPs\n")
{
	uint16_t interval = atoi(argv[2]->arg);
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->csnp_interval[level_for_arg(argv[3]->text)] = interval;

	return CMD_SUCCESS;
}

DEFUN (no_csnp_interval_level,
       no_csnp_interval_level_cmd,
       "no isis csnp-interval [(1-600)] <level-1|level-2>",
       NO_STR
       "IS-IS routing protocol\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n"
       "Specify interval for level-1 CSNPs\n"
       "Specify interval for level-2 CSNPs\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	int level = level_for_arg(argv[argc - 1]->text);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->csnp_interval[level] = DEFAULT_CSNP_INTERVAL;

	return CMD_SUCCESS;
}

DEFUN (psnp_interval_level,
       psnp_interval_level_cmd,
       "isis psnp-interval (1-120) <level-1|level-2>",
       "IS-IS routing protocol\n"
       "Set PSNP interval in seconds\n"
       "PSNP interval value\n"
       "Specify interval for level-1 PSNPs\n"
       "Specify interval for level-2 PSNPs\n")
{
	uint16_t interval = atoi(argv[2]->arg);
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->psnp_interval[level_for_arg(argv[3]->text)] = (uint16_t)interval;

	return CMD_SUCCESS;
}

DEFUN (no_psnp_interval_level,
       no_psnp_interval_level_cmd,
       "no isis psnp-interval [(1-120)] <level-1|level-2>",
       NO_STR
       "IS-IS routing protocol\n"
       "Set PSNP interval in seconds\n"
       "PSNP interval value\n"
       "Specify interval for level-1 PSNPs\n"
       "Specify interval for level-2 PSNPs\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	int level = level_for_arg(argv[argc - 1]->text);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->psnp_interval[level] = DEFAULT_PSNP_INTERVAL;

	return CMD_SUCCESS;
}

static int validate_metric_style_narrow(struct vty *vty, struct isis_area *area)
{
	struct isis_circuit *circuit;
	struct listnode *node;

	if (!vty)
		return CMD_WARNING_CONFIG_FAILED;

	if (!area) {
		vty_out(vty, "ISIS area is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		if ((area->is_type & IS_LEVEL_1)
		    && (circuit->is_type & IS_LEVEL_1)
		    && (circuit->te_metric[0] > MAX_NARROW_LINK_METRIC)) {
			vty_out(vty, "ISIS circuit %s metric is invalid\n",
				circuit->interface->name);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if ((area->is_type & IS_LEVEL_2)
		    && (circuit->is_type & IS_LEVEL_2)
		    && (circuit->te_metric[1] > MAX_NARROW_LINK_METRIC)) {
			vty_out(vty, "ISIS circuit %s metric is invalid\n",
				circuit->interface->name);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	return CMD_SUCCESS;
}

DEFUN (metric_style,
       metric_style_cmd,
       "metric-style <narrow|transition|wide>",
       "Use old-style (ISO 10589) or new-style packet formats\n"
       "Use old style of TLVs with narrow metric\n"
       "Send and accept both styles of TLVs during transition\n"
       "Use new style of TLVs to carry wider metric\n")
{
	int idx_metric_style = 1;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int ret;

	if (strncmp(argv[idx_metric_style]->arg, "w", 1) == 0) {
		isis_area_metricstyle_set(area, false, true);
		return CMD_SUCCESS;
	}

	if (area_is_mt(area)) {
		vty_out(vty,
			"Narrow metrics cannot be used while multi topology IS-IS is active\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = validate_metric_style_narrow(vty, area);
	if (ret != CMD_SUCCESS)
		return ret;

	if (strncmp(argv[idx_metric_style]->arg, "t", 1) == 0)
		isis_area_metricstyle_set(area, true, true);
	else if (strncmp(argv[idx_metric_style]->arg, "n", 1) == 0)
		isis_area_metricstyle_set(area, true, false);
	return CMD_SUCCESS;

	return CMD_SUCCESS;
}

DEFUN (no_metric_style,
       no_metric_style_cmd,
       "no metric-style",
       NO_STR
       "Use old-style (ISO 10589) or new-style packet formats\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int ret;

	if (area_is_mt(area)) {
		vty_out(vty,
			"Narrow metrics cannot be used while multi topology IS-IS is active\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = validate_metric_style_narrow(vty, area);
	if (ret != CMD_SUCCESS)
		return ret;

	isis_area_metricstyle_set(area, true, false);
	return CMD_SUCCESS;
}

DEFUN (set_attached_bit,
       set_attached_bit_cmd,
       "set-attached-bit",
       "Set attached bit to identify as L1/L2 router for inter-area traffic\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	isis_area_attached_bit_set(area, true);
	return CMD_SUCCESS;
}

DEFUN (no_set_attached_bit,
       no_set_attached_bit_cmd,
       "no set-attached-bit",
       NO_STR
       "Reset attached bit\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	isis_area_attached_bit_set(area, false);
	return CMD_SUCCESS;
}

DEFUN (dynamic_hostname,
       dynamic_hostname_cmd,
       "hostname dynamic",
       "Dynamic hostname for IS-IS\n"
       "Dynamic hostname\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	isis_area_dynhostname_set(area, true);
	return CMD_SUCCESS;
}

DEFUN (no_dynamic_hostname,
       no_dynamic_hostname_cmd,
       "no hostname dynamic",
       NO_STR
       "Dynamic hostname for IS-IS\n"
       "Dynamic hostname\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	isis_area_dynhostname_set(area, false);
	return CMD_SUCCESS;
}

DEFUN (is_type,
       is_type_cmd,
       "is-type <level-1|level-1-2|level-2-only>",
       "IS Level for this routing process (OSI only)\n"
       "Act as a station router only\n"
       "Act as both a station router and an area router\n"
       "Act as an area router only\n")
{
	int idx_level = 1;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int type;

	type = string2circuit_t(argv[idx_level]->arg);
	if (!type) {
		vty_out(vty, "Unknown IS level \n");
		return CMD_SUCCESS;
	}

	isis_area_is_type_set(area, type);

	return CMD_SUCCESS;
}

DEFUN (no_is_type,
       no_is_type_cmd,
       "no is-type <level-1|level-1-2|level-2-only>",
       NO_STR
       "IS Level for this routing process (OSI only)\n"
       "Act as a station router only\n"
       "Act as both a station router and an area router\n"
       "Act as an area router only\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int type;

	/*
	 * Put the is-type back to defaults:
	 * - level-1-2 on first area
	 * - level-1 for the rest
	 */
	if (listgetdata(listhead(isis->area_list)) == area)
		type = IS_LEVEL_1_AND_2;
	else
		type = IS_LEVEL_1;

	isis_area_is_type_set(area, type);

	return CMD_SUCCESS;
}

DEFUN (lsp_gen_interval_level,
       lsp_gen_interval_level_cmd,
       "lsp-gen-interval <level-1|level-2> (1-120)",
       "Minimum interval between regenerating same LSP\n"
       "Set interval for level 1 only\n"
       "Set interval for level 2 only\n"
       "Minimum interval in seconds\n")
{
	uint16_t interval = atoi(argv[2]->arg);

	return isis_vty_lsp_gen_interval_set(vty, level_for_arg(argv[1]->text),
					     interval);
}

DEFUN (no_lsp_gen_interval_level,
       no_lsp_gen_interval_level_cmd,
       "no lsp-gen-interval <level-1|level-2> [(1-120)]",
       NO_STR
       "Minimum interval between regenerating same LSP\n"
       "Set interval for level 1 only\n"
       "Set interval for level 2 only\n"
       "Minimum interval in seconds\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	return isis_vty_lsp_gen_interval_set(vty, level_for_arg(argv[2]->text),
					     DEFAULT_MIN_LSP_GEN_INTERVAL);
}

DEFUN (max_lsp_lifetime_level,
       max_lsp_lifetime_level_cmd,
       "max-lsp-lifetime <level-1|level-2> (350-65535)",
       "Maximum LSP lifetime\n"
       "Maximum LSP lifetime for Level 1 only\n"
       "Maximum LSP lifetime for Level 2 only\n"
       "LSP lifetime in seconds\n")
{
	uint16_t lifetime = atoi(argv[2]->arg);

	return isis_vty_max_lsp_lifetime_set(vty, level_for_arg(argv[1]->text),
					     lifetime);
}

DEFUN (no_max_lsp_lifetime_level,
       no_max_lsp_lifetime_level_cmd,
       "no max-lsp-lifetime <level-1|level-2> [(350-65535)]",
       NO_STR
       "Maximum LSP lifetime\n"
       "Maximum LSP lifetime for Level 1 only\n"
       "Maximum LSP lifetime for Level 2 only\n"
       "LSP lifetime in seconds\n")
{
	return isis_vty_max_lsp_lifetime_set(vty, level_for_arg(argv[1]->text),
					     DEFAULT_LSP_LIFETIME);
}

DEFUN (spf_interval_level,
       spf_interval_level_cmd,
       "spf-interval <level-1|level-2> (1-120)",
       "Minimum interval between SPF calculations\n"
       "Set interval for level 1 only\n"
       "Set interval for level 2 only\n"
       "Minimum interval between consecutive SPFs in seconds\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	uint16_t interval = atoi(argv[2]->arg);

	area->min_spf_interval[level_for_arg(argv[1]->text)] = interval;

	return CMD_SUCCESS;
}

DEFUN (no_spf_interval_level,
       no_spf_interval_level_cmd,
       "no spf-interval <level-1|level-2> [(1-120)]",
       NO_STR
       "Minimum interval between SPF calculations\n"
       "Set interval for level 1 only\n"
       "Set interval for level 2 only\n"
       "Minimum interval between consecutive SPFs in seconds\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int level = level_for_arg(argv[1]->text);

	area->min_spf_interval[level] = MINIMUM_SPF_INTERVAL;

	return CMD_SUCCESS;
}

DEFUN (lsp_refresh_interval_level,
       lsp_refresh_interval_level_cmd,
       "lsp-refresh-interval <level-1|level-2> (1-65235)",
       "LSP refresh interval\n"
       "LSP refresh interval for Level 1 only\n"
       "LSP refresh interval for Level 2 only\n"
       "LSP refresh interval in seconds\n")
{
	uint16_t interval = atoi(argv[2]->arg);
	return isis_vty_lsp_refresh_set(vty, level_for_arg(argv[1]->text),
					interval);
}

DEFUN (no_lsp_refresh_interval_level,
       no_lsp_refresh_interval_level_cmd,
       "no lsp-refresh-interval <level-1|level-2> [(1-65235)]",
       NO_STR
       "LSP refresh interval\n"
       "LSP refresh interval for Level 1 only\n"
       "LSP refresh interval for Level 2 only\n"
       "LSP refresh interval in seconds\n")
{
	return isis_vty_lsp_refresh_set(vty, level_for_arg(argv[2]->text),
					DEFAULT_MAX_LSP_GEN_INTERVAL);
}

DEFUN (area_passwd,
       area_passwd_cmd,
       "area-password <clear|md5> WORD [authenticate snp <send-only|validate>]",
       "Configure the authentication password for an area\n"
       "Authentication type\n"
       "Authentication type\n"
       "Area password\n"
       "Authentication\n"
       "SNP PDUs\n"
       "Send but do not check PDUs on receiving\n"
       "Send and check PDUs on receiving\n")
{
	return isis_vty_password_set(vty, argc, argv, IS_LEVEL_1);
}

DEFUN (no_area_passwd,
       no_area_passwd_cmd,
       "no area-password",
       NO_STR
       "Configure the authentication password for an area\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	return isis_area_passwd_unset(area, IS_LEVEL_1);
}

void isis_vty_daemon_init(void)
{
	install_element(INTERFACE_NODE, &isis_circuit_type_cmd);
	install_element(INTERFACE_NODE, &no_isis_circuit_type_cmd);

	install_element(INTERFACE_NODE, &isis_network_cmd);
	install_element(INTERFACE_NODE, &no_isis_network_cmd);

	install_element(INTERFACE_NODE, &isis_priority_cmd);
	install_element(INTERFACE_NODE, &no_isis_priority_cmd);
	install_element(INTERFACE_NODE, &isis_priority_level_cmd);
	install_element(INTERFACE_NODE, &no_isis_priority_level_cmd);

	install_element(INTERFACE_NODE, &isis_metric_level_cmd);
	install_element(INTERFACE_NODE, &no_isis_metric_level_cmd);

	install_element(INTERFACE_NODE, &isis_hello_interval_level_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_interval_level_cmd);

	install_element(INTERFACE_NODE, &isis_hello_multiplier_level_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_multiplier_level_cmd);

	install_element(INTERFACE_NODE, &isis_threeway_adj_cmd);

	install_element(INTERFACE_NODE, &isis_hello_padding_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_padding_cmd);

	install_element(INTERFACE_NODE, &csnp_interval_level_cmd);
	install_element(INTERFACE_NODE, &no_csnp_interval_level_cmd);

	install_element(INTERFACE_NODE, &psnp_interval_level_cmd);
	install_element(INTERFACE_NODE, &no_psnp_interval_level_cmd);

	install_element(ROUTER_NODE, &metric_style_cmd);
	install_element(ROUTER_NODE, &no_metric_style_cmd);

	install_element(ROUTER_NODE, &set_attached_bit_cmd);
	install_element(ROUTER_NODE, &no_set_attached_bit_cmd);

	install_element(ROUTER_NODE, &dynamic_hostname_cmd);
	install_element(ROUTER_NODE, &no_dynamic_hostname_cmd);

	install_element(ROUTER_NODE, &is_type_cmd);
	install_element(ROUTER_NODE, &no_is_type_cmd);

	install_element(ROUTER_NODE, &lsp_gen_interval_level_cmd);
	install_element(ROUTER_NODE, &no_lsp_gen_interval_level_cmd);

	install_element(ROUTER_NODE, &max_lsp_lifetime_level_cmd);
	install_element(ROUTER_NODE, &no_max_lsp_lifetime_level_cmd);

	install_element(ROUTER_NODE, &spf_interval_level_cmd);
	install_element(ROUTER_NODE, &no_spf_interval_level_cmd);

	install_element(ROUTER_NODE, &lsp_refresh_interval_level_cmd);
	install_element(ROUTER_NODE, &no_lsp_refresh_interval_level_cmd);

	install_element(ROUTER_NODE, &area_passwd_cmd);
	install_element(ROUTER_NODE, &no_area_passwd_cmd);
}
