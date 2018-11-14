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
#include "bfd.h"

#include "isis_circuit.h"
#include "isis_csm.h"
#include "isis_misc.h"
#include "isis_mt.h"
#include "isisd.h"
#include "isis_bfd.h"
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

DEFUN (isis_bfd,
       isis_bfd_cmd,
       PROTO_NAME " bfd",
       PROTO_HELP
       "Enable BFD support\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);

	if (!circuit)
		return CMD_ERR_NO_MATCH;

	if (circuit->bfd_info
	    && CHECK_FLAG(circuit->bfd_info->flags, BFD_FLAG_PARAM_CFG)) {
		return CMD_SUCCESS;
	}

	isis_bfd_circuit_param_set(circuit, BFD_DEF_MIN_RX,
				   BFD_DEF_MIN_TX, BFD_DEF_DETECT_MULT, true);

	return CMD_SUCCESS;
}

DEFUN (no_isis_bfd,
       no_isis_bfd_cmd,
       "no " PROTO_NAME " bfd",
       NO_STR
       PROTO_HELP
       "Disables BFD support\n"
)
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);

	if (!circuit)
		return CMD_ERR_NO_MATCH;

	if (!circuit->bfd_info)
		return CMD_SUCCESS;

	isis_bfd_circuit_cmd(circuit, ZEBRA_BFD_DEST_DEREGISTER);
	bfd_info_free(&circuit->bfd_info);
	return CMD_SUCCESS;
}

void isis_vty_init(void)
{
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

	install_element(INTERFACE_NODE, &isis_bfd_cmd);
	install_element(INTERFACE_NODE, &no_isis_bfd_cmd);

	isis_vty_daemon_init();
}
