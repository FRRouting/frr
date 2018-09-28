/*
 * IS-IS Rout(e)ing protocol - BFD support
 *
 * Copyright (C) 2018 Christian Franke
 *
 * This file is part of FreeRangeRouting (FRR)
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "zclient.h"
#include "bfd.h"

#include "isisd/isis_bfd.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_common.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/fabricd.h"

static int isis_bfd_interface_dest_update(int command, struct zclient *zclient,
					  zebra_size_t length, vrf_id_t vrf_id)
{
	return 0;
}

static int isis_bfd_nbr_replay(int command, struct zclient *zclient,
			       zebra_size_t length, vrf_id_t vrf_id)
{
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER);
	return 0;
}

static void (*orig_zebra_connected)(struct zclient *);
static void isis_bfd_zebra_connected(struct zclient *zclient)
{
	if (orig_zebra_connected)
		orig_zebra_connected(zclient);

	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER);
}

void isis_bfd_circuit_cmd(struct isis_circuit *circuit, int command)
{
	return;
}

void isis_bfd_circuit_param_set(struct isis_circuit *circuit,
				uint32_t min_rx, uint32_t min_tx,
				uint32_t detect_mult, int defaults)
{
	int command = 0;

	bfd_set_param(&circuit->bfd_info, min_rx,
		      min_tx, detect_mult, defaults, &command);

	if (command)
		isis_bfd_circuit_cmd(circuit, command);
}

static int bfd_circuit_write_settings(struct isis_circuit *circuit,
				      struct vty *vty)
{
	struct bfd_info *bfd_info = circuit->bfd_info;

	if (!bfd_info)
		return 0;

#if HAVE_BFDD == 0
	if (CHECK_FLAG(bfd_info->flags, BFD_FLAG_PARAM_CFG)) {
		vty_out(vty, " %s bfd %" PRIu8 " %" PRIu32 " %" PRIu32 "\n",
			PROTO_NAME, bfd_info->detect_mult,
			bfd_info->required_min_rx, bfd_info->desired_min_tx);
	} else
#endif
		vty_out(vty, " %s bfd\n", PROTO_NAME);
	return 1;
}

void isis_bfd_init(void)
{
	bfd_gbl_init();

	orig_zebra_connected = zclient->zebra_connected;
	zclient->zebra_connected = isis_bfd_zebra_connected;
	zclient->interface_bfd_dest_update = isis_bfd_interface_dest_update;
	zclient->bfd_dest_replay = isis_bfd_nbr_replay;
	hook_register(isis_circuit_config_write,
		      bfd_circuit_write_settings);
}
