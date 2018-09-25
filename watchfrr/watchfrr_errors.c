/*
 * Watchfrr-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "lib/ferr.h"
#include "watchfrr_errors.h"

/* clang-format off */
static struct log_ref ferr_watchfrr_err[] = {
	{
		.code = EC_WATCHFRR_CONNECTION,
		.title = "WATCHFRR Connection Error",
		.description = "WATCHFRR has detected a connectivity issue with one of the FRR daemons",
		.suggestion = "Ensure that FRR is still running and if not please open an Issue"
	},
	{
		.code = EC_WATCHFRR_UNEXPECTED_DAEMONS,
		.title = "WATCHFRR wrong daemons to watch",
		.description = "As part of WATCHFRR startup you must specify 1 or more daemons to monitor",
		.suggestion = "Update your startup scripts to include zebra and any other daemon you would like to monitor",
	},
	{
		.code = END_FERR,
	}
};
/* clang-format on */

void watchfrr_error_init(void)
{
	log_ref_add(ferr_watchfrr_err);
}
