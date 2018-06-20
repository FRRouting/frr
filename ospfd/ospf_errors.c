/*
 * OSPF-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *		Chirag Shah
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
#include "ospf_errors.h"

static struct ferr_ref ferr_ospf_err[] = {
	{
		.code = OSPF_ERR_PKT_PROCESS,
		.title = "Failure to process a packet",
		.description = "OSPF attempted to process a received packet but could not",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = OSPF_ERR_ROUTER_LSA_MISMATCH,
		.title = "Failure to process Router LSA",
		.description = "OSPF attempted to process a Router LSA but Advertising ID mismtach with link id",
		.suggestion = "Check OSPF network config for any config issue, If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = OSPF_ERR_DOMAIN_CORRUPT,
		.title = "OSPF Domain Corruption",
		.description = "OSPF attempted to process a Router LSA but Advertising ID mismtach with link id",
		.suggestion = "Check OSPF network Database for corrupted LSA, If the problem persists, shutdown ospf domain and report the problem for troubleshooting"
	},
	{
		.code = OSPF_ERR_INIT_FAIL,
		.title = "OSPF Initialization failure",
		.description = "OSPF failed to initialized ospf default insance",
		.suggestion = "Ensure there is adequate memory on the device. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = OSPF_ERR_SR_INVALID_DB,
		.title = "OSPF SR Invalid DB",
		.description = "OSPF Segment Routing Database is invalid",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = OSPF_ERR_SR_NODE_CREATE,
		.title = "OSPF SR hash node creation failed",
		.description = "OSPF Segment Routing node creation failed",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = OSPF_ERR_SR_INVALID_LSA_ID,
		.title = "OSPF SR Invalid lsa id",
		.description = "OSPF Segment Routing invalid lsa id",
		.suggestion = "Restart ospf instance, If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = OSPF_ERR_SR_INVALID_ALGORITHM,
		.title = "OSPF SR Invalid Algorithm",
		.description = "OSPF Segment Routing invalid Algorithm",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},

	{
		.code = END_FERR,
	}
};

void ospf_error_init(void)
{
	ferr_ref_add(ferr_ospf_err);
}
