// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EIGRP-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */

#include <zebra.h>

#include "lib/ferr.h"
#include "eigrp_errors.h"

/* clang-format off */
static struct log_ref ferr_eigrp_err[] = {
	{
		.code = EC_EIGRP_PACKET,
		.title = "EIGRP Packet Error",
		.description = "EIGRP has a packet that does not correctly decode or encode",
		.suggestion = "Gather log files from both sides of the neighbor relationship and open an issue"
	},
	{
		.code = EC_EIGRP_CONFIG,
		.title = "EIGRP Configuration Error",
		.description = "EIGRP has detected a configuration error",
		.suggestion = "Correct the configuration issue, if it still persists open an Issue"
	},
	{
		.code = END_FERR,
	}
};
/* clang-format on */

void eigrp_error_init(void)
{
	log_ref_add(ferr_eigrp_err);
}
