// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Watchfrr-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */

#ifndef __WATCHFRR_ERRORS_H__
#define __WATCHFRR_ERRORS_H__

#include "lib/ferr.h"

enum watchfrr_log_refs {
	EC_WATCHFRR_CONNECTION = WATCHFRR_FERR_START,
	EC_WATCHFRR_UNEXPECTED_DAEMONS,
};

extern void watchfrr_error_init(void);

#endif
