/*
 * isis_errors - code for error messages that may occur in the
 *              isis process
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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

#include "isis_errors.h"

static struct ferr_ref ferr_isis_err[] = {
	{
		.code = ISIS_ERR_PACKET,
		.title = "ISIS Packet Error",
		.description = "Isis has detected an error with a packet from a peer",
		.suggestion = "Gather log information and open an issue then restart FRR"
	},
	{
		.code = ISIS_ERR_CONFIG,
		.title = "ISIS Configuration Error",
		.description = "Isis has detected an error within configuration for the router",
		.suggestion = "Ensure configuration is correct"
	},
	{
		.code = END_FERR,
	}
};

void isis_error_init(void)
{
	ferr_ref_init();

	ferr_ref_add(ferr_isis_err);
}
