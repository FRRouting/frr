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

void isis_bfd_init(void)
{
	bfd_gbl_init();

	orig_zebra_connected = zclient->zebra_connected;
	zclient->zebra_connected = isis_bfd_zebra_connected;
	zclient->interface_bfd_dest_update = isis_bfd_interface_dest_update;
	zclient->bfd_dest_replay = isis_bfd_nbr_replay;
}
