/*
 * eigrp_errors - code for error messages that may occur in the
 *              eigrp process
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

#include "eigrp_errors.h"

static struct ferr_ref ferr_eigrp_err[] = {
	{
		.code = EIGRP_ERR_PACKET,
		.title = "EIGRP Packet Error",
		.description = "EIGRP has a packet that does not correctly decode or encode",
		.suggestion = "Gather log files from both sides of the neighbor relationship and open an issue"
	},
	{
		.code = EIGRP_ERR_CONFIG,
		.title = "EIGRP Configuration Error",
		.description = "EIGRP has detected a configuration error",
		.suggestion = "Correct the configuration issue, if it still persists open an Issue"
	},
	{
		.code = END_FERR,
	}
};

void eigrp_error_init(void)
{
	ferr_ref_init();

	ferr_ref_add(ferr_eigrp_err);
}
