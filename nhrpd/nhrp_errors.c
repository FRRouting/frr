// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NHRP-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */

#include <zebra.h>

#include "lib/ferr.h"
#include "nhrp_errors.h"

/* clang-format off */
static struct log_ref ferr_nhrp_err[] = {
	{
		.code = EC_NHRP_SWAN,
		.title = "NHRP Strong Swan Error",
		.description = "NHRP has detected a error with the Strongswan code",
		.suggestion = "Ensure that StrongSwan is configured correctly.  Restart StrongSwan and FRR"
	},
	{
		.code = END_FERR,
	}
};
/* clang-format on */

void nhrp_error_init(void)
{
	log_ref_add(ferr_nhrp_err);
}
