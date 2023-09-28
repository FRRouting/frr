// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */

#include <zebra.h>

#include "lib/ferr.h"
#include "pim_errors.h"

/* clang-format off */
static struct log_ref ferr_pim_err[] = {
	{
		.code = EC_PIM_MSDP_PACKET,
		.title = "PIM MSDP Packet Error",
		.description = "PIM has received a packet from a peer that does not correctly decode",
		.suggestion = "Check MSDP peer and ensure it is correctly working"
	},
	{
		.code = EC_PIM_CONFIG,
		.title = "PIM Configuration Error",
		.description = "PIM has detected a configuration error",
		.suggestion = "Ensure the configuration is correct and apply correct configuration"
	},
	{
		.code = END_FERR,
	}
};
/* clang-format on */

void pim_error_init(void)
{
	log_ref_add(ferr_pim_err);
}
