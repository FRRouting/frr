// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Watchfrr-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
