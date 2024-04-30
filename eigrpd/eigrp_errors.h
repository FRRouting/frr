// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EIGRP-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */

#ifndef __EIGRP_ERRORS_H__
#define __EIGRP_ERRORS_H__

#include "lib/ferr.h"

enum eigrp_log_refs {
	EC_EIGRP_PACKET = EIGRP_FERR_START,
	EC_EIGRP_CONFIG,
};

extern void eigrp_error_init(void);

#endif
