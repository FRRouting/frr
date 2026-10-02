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
		.code = EC_PIM_KERNEL_MAXVIFS_MISMATCH,
		.title = "PIM Kernel MAXVIFS Mismatch",
		.description = "pimd was compiled against a <linux/mroute.h> whose MAXVIFS differs from the one the running kernel was built with, so struct mfcctl has a different size on each side and the kernel rejects every multicast route pimd tries to install (MRT_ADD_MFC fails with EINVAL)",
		.suggestion = "Rebuild pimd against the kernel headers (linux-libc-headers) that match the running kernel's MAXVIFS, or run a kernel built with the MAXVIFS value pimd was compiled with"
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
