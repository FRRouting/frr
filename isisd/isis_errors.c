// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ISIS-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */

#include <zebra.h>

#include "lib/ferr.h"
#include "isis_errors.h"

/* clang-format off */
static struct log_ref ferr_isis_err[] = {
	{
		.code = EC_ISIS_PACKET,
		.title = "ISIS Packet Error",
		.description = "Isis has detected an error with a packet from a peer",
		.suggestion = "Gather log information and open an issue then restart FRR"
	},
	{
		.code = EC_ISIS_CONFIG,
		.title = "ISIS Configuration Error",
		.description = "Isis has detected an error within configuration for the router",
		.suggestion = "Ensure configuration is correct"
	},
	{
		.code = EC_ISIS_SID_OVERFLOW,
		.title = "SID index overflow",
		.description = "Isis has detected that a SID index falls outside of its associated SRGB range",
		.suggestion = "Configure a larger SRGB"
	},
	{
		.code = EC_ISIS_SID_COLLISION,
		.title = "SID collision",
		.description = "Isis has detected that two different prefixes share the same SID index",
		.suggestion = "Identify the routers that are advertising the same SID index and fix the collision accordingly"
	},
	{
		.code = END_FERR,
	}
};
/* clang-format on */

void isis_error_init(void)
{
	log_ref_add(ferr_isis_err);
}
