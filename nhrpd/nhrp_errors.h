// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NHRP-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */

#ifndef __NHRP_ERRORS_H__
#define __NHRP_ERRORS_H__

#include "lib/ferr.h"

enum nhrp_log_refs {
	EC_NHRP_SWAN = NHRP_FERR_START,
};

extern void nhrp_error_init(void);

#endif
