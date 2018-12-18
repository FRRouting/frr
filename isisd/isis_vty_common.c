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
	install_element(INTERFACE_NODE, &isis_bfd_cmd);
	install_element(INTERFACE_NODE, &no_isis_bfd_cmd);

#ifdef FABRICD
	isis_vty_daemon_init();
#endif /* ifdef FABRICD */
}
