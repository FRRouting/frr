/*
 * babel_errors - code for error messages that may occur in the
 *              babel process
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

#include "babel_errors.h"

static struct ferr_ref ferr_babel_err[] = {
	{
		.code = BABEL_ERR_MEMORY,
		.title = "BABEL Memory Errors",
		.description = "Babel has failed to allocate memory, the system is about to run out of memory",
		.suggestion = "Find the process that is causing memory shortages and remediate that process\nRestart FRR"
	},
	{
		.code = BABEL_ERR_PACKET,
		.title = "BABEL Packet Error",
		.description = "Babel has detected a packet encode/decode problem",
		.suggestion = "Collect relevant log files and file an Issue"
	},
	{
		.code = BABEL_ERR_CONFIG,
		.title = "BABEL Configuration Error",
		.description = "Babel has detected a configuration error of some sort",
		.suggestion = "Ensure that the configuration is correct"
	},
	{
		.code = BABEL_ERR_ROUTE,
		.title = "BABEL Route Error",
		.description = "Babel has detected a routing error and has an inconsistent state",
		.suggestion = "Gather data for filing an Issue and then restart FRR"
	},
	{
		.code = END_FERR,
	}
};

void babel_error_init(void)
{
	ferr_ref_init();

	ferr_ref_add(ferr_babel_err);
}
