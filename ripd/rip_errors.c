// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RIP-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */

#include <zebra.h>

#include "lib/ferr.h"
#include "rip_errors.h"

static struct log_ref ferr_rip_err[] = {
	{.code = EC_RIP_PACKET,
	 .title = "RIP Packet Error",
	 .description = "RIP has detected a packet encode/decode issue",
	 .suggestion = "Gather log files from both sides and open a Issue"},
	{
		.code = END_FERR,
	}};

void rip_error_init(void)
{
	log_ref_add(ferr_rip_err);
}
