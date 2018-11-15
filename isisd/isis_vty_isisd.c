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

void isis_vty_daemon_init(void)
{
	install_element(INTERFACE_NODE, &isis_network_cmd);
	install_element(INTERFACE_NODE, &no_isis_network_cmd);

	install_element(INTERFACE_NODE, &isis_priority_cmd);
	install_element(INTERFACE_NODE, &no_isis_priority_cmd);
	install_element(INTERFACE_NODE, &isis_priority_level_cmd);
	install_element(INTERFACE_NODE, &no_isis_priority_level_cmd);
}
