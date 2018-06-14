/*
 * Library-specific error messages.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Donald Sharp
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
#include <lib_errors.h>

static struct ferr_ref ferr_lib_err[] = {
	{
		.code = LIB_ERR_PRIVILEGES,
		.title = "Failure to raise or lower privileges",
		.description = "FRR attempted to raise or lower it's privileges and was unable to do so",
		.suggestion = "Ensure that you are running FRR as the frr user and that the user has\nSufficient privileges to properly access root privileges"
	},
	{
		.code = LIB_ERR_VRF_START,
		.title = "VRF Failure on Start",
		.description = "Upon startup FRR failed to properly initialize and startup the VRF subsystem",
		.suggestion = "Ensure that there is sufficient memory to start processes and restart FRR",
	},
	{
		.code = LIB_ERR_VRF_SOCKET,
		.title = "VRF Socket Error",
		.description = "When attempting to access a socket for the VRF specified, we\nwere unable to properly complete the request",
		.suggestion = "Ensure that there is sufficient system resources available and\nensure that the frr user has sufficient permisions to work",
	},
	{
		.code = END_FERR
	}
};

void lib_error_init(void)
{
	ferr_ref_init();
	ferr_ref_add(ferr_lib_err);
}
