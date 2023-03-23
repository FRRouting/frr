// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ISIS-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */

#ifndef __ISIS_ERRORS_H__
#define __ISIS_ERRORS_H__

#include "lib/ferr.h"

enum isis_log_refs {
	EC_ISIS_PACKET = ISIS_FERR_START,
	EC_ISIS_CONFIG,
	EC_ISIS_SID_OVERFLOW,
	EC_ISIS_SID_COLLISION,
};

extern void isis_error_init(void);

#endif
