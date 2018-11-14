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
}
