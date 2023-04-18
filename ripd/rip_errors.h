// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RIP-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */

#ifndef __RIP_ERRORS_H__
#define __RIP_ERRORS_H__

#include "lib/ferr.h"

enum rip_log_refs {
	EC_RIP_PACKET = RIP_FERR_START,
	RIP_ERR_CONFIG,
};

extern void rip_error_init(void);

#endif
